import CryptoKit
import Foundation

/// Sends one HTTP request. URLSession in production; a fake server in tests.
public protocol HTTPTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct URLSessionTransport: HTTPTransport {
    let session: URLSession

    public init(session: URLSession = .shared) { self.session = session }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw DeliveryError.http(status: 0, body: "not HTTP") }
        return (data, http)
    }
}

/// The request-signing contract shared with the backend
/// (docs/schema/signature-vector.json).
public enum RequestSigning {
    public static func canonicalString(method: String, pathAndQuery: String, timestamp: Int64, body: Data) -> String {
        let digest = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
        return ["ALTIWARD-SIG-V1", method, pathAndQuery, String(timestamp), digest].joined(separator: "\n")
    }

    static func sign(_ request: inout URLRequest, deviceID: String, key: P256.Signing.PrivateKey, timestamp: Int64) throws {
        guard let url = request.url, let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw DeliveryError.http(status: 0, body: "request has no URL")
        }
        var target = components.percentEncodedPath
        if let query = components.percentEncodedQuery { target += "?" + query }
        let canonical = canonicalString(
            method: request.httpMethod ?? "GET", pathAndQuery: target, timestamp: timestamp, body: request.httpBody ?? Data())
        let signature = try key.signature(for: Data(canonical.utf8))
        request.setValue("AltiwardDevice \(deviceID)", forHTTPHeaderField: "Authorization")
        request.setValue(String(timestamp), forHTTPHeaderField: "X-Altiward-Timestamp")
        request.setValue(signature.derRepresentation.base64EncodedString(), forHTTPHeaderField: "X-Altiward-Signature")
    }
}

/// Holds this Mac's device credential and signs agent requests with it.
///
/// The key is stored before the enrollment request is sent, so a retry after a lost
/// response enrolls the same key and the server returns the same credential. The key
/// lives in the agent store, inside the root-only data directory.
public actor DeviceAuthenticator {
    private struct Credential: Codable {
        var serverURL: String
        var privateKey: Data  // P256 raw representation
        var deviceID: String?
    }

    private static let storeKey = "device_credential"

    private let store: AgentStore
    private let serverURL: URL
    private let enrollmentToken: String
    private let device: @Sendable () -> DeviceInfo
    private let transport: any HTTPTransport
    private let now: @Sendable () -> Date
    /// Server time minus local time, learned from a `clock_skew` response.
    private var clockOffset: TimeInterval = 0

    public init(
        store: AgentStore, serverURL: URL, enrollmentToken: String, device: @escaping @Sendable () -> DeviceInfo,
        transport: any HTTPTransport = URLSessionTransport(), now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.store = store
        self.serverURL = serverURL
        self.enrollmentToken = enrollmentToken
        self.device = device
        self.transport = transport
        self.now = now
    }

    /// The enrolled device ID for the configured server, if any.
    public var deviceID: String? {
        guard let c = try? load(), c.serverURL == serverURL.absoluteString else { return nil }
        return c.deviceID
    }

    /// Enrolls if needed, then sends a signed request to `path` (relative to the server
    /// URL, optionally with a query), giving up after `timeout` seconds. Throws
    /// ``DeliveryError/credentialInvalid`` (the credential was discarded, unless another
    /// process had already replaced it; the next call enrolls again or uses the
    /// replacement) or ``DeliveryError/enrollmentPending``; any other response is returned
    /// for the caller to judge.
    public func send(
        method: String, path: String, body: Data, timeout: TimeInterval = 30
    ) async throws -> (Data, HTTPURLResponse) {
        let credential = try await enrolled()
        var (data, response) = try await signedSend(credential, method: method, path: path, body: body, timeout: timeout)
        if response.statusCode == 401, Self.code(data) == "clock_skew",
            let serverDate = response.value(forHTTPHeaderField: "Date").flatMap(Self.parseHTTPDate)
        {
            clockOffset = serverDate.timeIntervalSince(now())
            (data, response) = try await signedSend(
                credential, method: method, path: path, body: body, timeout: timeout)
        }
        switch (response.statusCode, Self.code(data)) {
        case (401, "credential_invalid"):
            try discard(credential)
            throw DeliveryError.credentialInvalid
        case (403, "enrollment_pending"):
            throw DeliveryError.enrollmentPending
        default:
            return (data, response)
        }
    }

    private func signedSend(
        _ c: Credential, method: String, path: String, body: Data, timeout: TimeInterval
    ) async throws -> (Data, HTTPURLResponse) {
        // appendingPathComponent would escape a "?", so the query goes on separately.
        let parts = path.split(separator: "?", maxSplits: 1)
        var url = serverURL.appendingPathComponent(String(parts[0]))
        if parts.count == 2, var components = URLComponents(url: url, resolvingAgainstBaseURL: false) {
            components.percentEncodedQuery = String(parts[1])
            url = components.url ?? url
        }
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = method
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("altiward-agent/\(AgentVersion.current)", forHTTPHeaderField: "User-Agent")
        let key = try P256.Signing.PrivateKey(rawRepresentation: c.privateKey)
        let timestamp = Int64(now().addingTimeInterval(clockOffset).timeIntervalSince1970)
        try RequestSigning.sign(&request, deviceID: c.deviceID!, key: key, timestamp: timestamp)
        return try await transport.send(request)
    }

    private func enrolled() async throws -> Credential {
        var c: Credential
        if let stored = try load(), stored.serverURL == serverURL.absoluteString {
            c = stored
        } else {
            c = Credential(serverURL: serverURL.absoluteString, privateKey: P256.Signing.PrivateKey().rawRepresentation)
            try save(c)
        }
        if c.deviceID != nil { return c }

        let key = try P256.Signing.PrivateKey(rawRepresentation: c.privateKey)
        let info = device()
        var request = URLRequest(url: serverURL.appendingPathComponent("v1/agent/enroll"), timeoutInterval: 30)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(enrollmentToken)", forHTTPHeaderField: "Authorization")
        request.setValue("altiward-agent/\(AgentVersion.current)", forHTTPHeaderField: "User-Agent")
        request.httpBody = try JSONEncoder().encode([
            "serial": info.serial, "hardware_uuid": info.hardwareUUID,
            "public_key": key.publicKey.derRepresentation.base64EncodedString(),
        ])
        let (data, response) = try await transport.send(request)
        guard response.statusCode == 200 || response.statusCode == 201 else {
            throw DeliveryError.http(status: response.statusCode, body: String(decoding: data, as: UTF8.self))
        }
        struct Enrolled: Decodable {
            let device_id: String
            let status: String
        }
        let enrolled = try JSONDecoder().decode(Enrolled.self, from: data)
        if enrolled.status == "revoked" {
            // This key was revoked earlier; start over with a new one.
            try discard(c)
            throw DeliveryError.credentialInvalid
        }
        c.deviceID = enrolled.device_id
        try save(c)
        return c
    }

    private func load() throws -> Credential? {
        try store.value(forKey: Self.storeKey).map { try JSONDecoder().decode(Credential.self, from: Data($0.utf8)) }
    }

    private func save(_ c: Credential) throws {
        try store.setValue(String(decoding: try JSONEncoder().encode(c), as: UTF8.self), forKey: Self.storeKey)
    }

    /// Drops the stored credential if it still holds `c`'s key. Another process sharing the
    /// store may have enrolled a new key since `c` was loaded; that one stays.
    private func discard(_ c: Credential) throws {
        try store.transaction {
            if try load()?.privateKey == c.privateKey {
                try store.setValue(nil, forKey: Self.storeKey)
            }
        }
    }

    private static func code(_ data: Data) -> String? {
        struct Body: Decodable { let code: String? }
        return (try? JSONDecoder().decode(Body.self, from: data))?.code
    }

    private static func parseHTTPDate(_ s: String) -> Date? {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "GMT")
        f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return f.date(from: s)
    }
}
