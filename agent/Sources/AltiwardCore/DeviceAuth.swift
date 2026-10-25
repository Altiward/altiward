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

    /// Signs `request`; `sign` returns the DER ECDSA P-256 signature of its argument.
    static func sign(
        _ request: inout URLRequest, deviceID: String, timestamp: Int64, with sign: (Data) throws -> Data
    ) throws {
        guard let url = request.url, let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw DeliveryError.http(status: 0, body: "request has no URL")
        }
        var target = components.percentEncodedPath
        if let query = components.percentEncodedQuery { target += "?" + query }
        let canonical = canonicalString(
            method: request.httpMethod ?? "GET", pathAndQuery: target, timestamp: timestamp, body: request.httpBody ?? Data())
        let signature = try sign(Data(canonical.utf8))
        request.setValue("AltiwardDevice \(deviceID)", forHTTPHeaderField: "Authorization")
        request.setValue(String(timestamp), forHTTPHeaderField: "X-Altiward-Timestamp")
        request.setValue(signature.base64EncodedString(), forHTTPHeaderField: "X-Altiward-Signature")
    }
}

/// Where this Mac's device key is kept. The agent reports it when it enrolls.
public enum KeyStorage: String, Sendable {
    /// In the Secure Enclave: the agent stores an opaque handle that only this Mac's
    /// Secure Enclave can use, so a copy is no use anywhere else.
    case secureEnclave = "secure_enclave"
    /// The raw key, in the root-only agent store. Macs without a Secure Enclave, and
    /// Macs that enrolled before agent 0.2.0.
    case software
}

/// Makes and uses device keys. A key is opaque `Data`: the raw P-256 key for
/// ``KeyStorage/software``, the Secure Enclave's `dataRepresentation` otherwise.
public protocol DeviceKeys: Sendable {
    var secureEnclaveAvailable: Bool { get }
    func makeKey(_ storage: KeyStorage) throws -> Data
    /// The key's public half as SubjectPublicKeyInfo DER.
    func publicKey(_ key: Data, _ storage: KeyStorage) throws -> Data
    /// A DER ECDSA P-256 signature of `message`.
    func sign(_ message: Data, key: Data, _ storage: KeyStorage) throws -> Data
}

public struct SystemDeviceKeys: DeviceKeys {
    public init() {}

    public var secureEnclaveAvailable: Bool { SecureEnclave.isAvailable }

    public func makeKey(_ storage: KeyStorage) throws -> Data {
        switch storage {
        case .software:
            return P256.Signing.PrivateKey().rawRepresentation
        case .secureEnclave:
            // Usable after the first unlock since boot, on this Mac only, with no user
            // presence: CryptoKit's default, written out so it can't change under us. On a
            // test Mac a root LaunchDaemon made and used such keys at the login window with
            // nobody signed in, while locked, across fast user switching, sleep and logout,
            // and after the app was rebuilt and re-signed (issue #75).
            var error: Unmanaged<CFError>?
            guard
                let access = SecAccessControlCreateWithFlags(
                    nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [], &error)
            else { throw error!.takeRetainedValue() as Error }
            return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access).dataRepresentation
        }
    }

    public func publicKey(_ key: Data, _ storage: KeyStorage) throws -> Data {
        switch storage {
        case .software: try P256.Signing.PrivateKey(rawRepresentation: key).publicKey.derRepresentation
        case .secureEnclave: try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: key).publicKey.derRepresentation
        }
    }

    public func sign(_ message: Data, key: Data, _ storage: KeyStorage) throws -> Data {
        switch storage {
        case .software:
            try P256.Signing.PrivateKey(rawRepresentation: key).signature(for: message).derRepresentation
        case .secureEnclave:
            try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: key).signature(for: message).derRepresentation
        }
    }
}

/// A device key this process can't use. Not a ``DeliveryError``: the server refused nothing.
public enum DeviceKeyError: Error, Equatable, CustomStringConvertible {
    /// The Secure Enclave couldn't sign just now; the key stays and the send is retried.
    case secureEnclaveUnavailable(String)
    /// The key is in the Secure Enclave, where only the agent daemon can use it.
    case heldByDaemon
    /// This Mac has a Secure Enclave and hasn't enrolled; the agent daemon enrolls it.
    case notEnrolled

    public var description: String {
        switch self {
        case .secureEnclaveUnavailable(let error): "the Secure Enclave couldn't sign (\(error)); will retry"
        case .heldByDaemon: "this Mac's key is in the Secure Enclave, where only the agent daemon can use it; the daemon sends within a minute"
        case .notEnrolled: "not enrolled yet; the agent daemon enrolls this Mac when it starts"
        }
    }
}

private extension DeviceInfo {
    /// Whether the Mac said which it is, rather than ``DeviceIdentity/unreadable``.
    var isReadable: Bool { serial != DeviceIdentity.unreadable && hardwareUUID != DeviceIdentity.unreadable }
}

/// Holds this Mac's device credential and signs agent requests with it.
///
/// The key is stored before the enrollment request is sent, so a retry after a lost
/// response enrolls the same key and the server returns the same credential. A new key
/// goes in the Secure Enclave when the Mac has one; a Mac that enrolled with a file key
/// keeps it until it enrolls again.
///
/// The two kinds live in separate records of the agent store, inside the root-only data
/// directory. A file key keeps the record and format agent 0.1 reads, and a Secure
/// Enclave key has its own record, so an older agent installed over this one finds no
/// key it can't use: it enrolls again with a file key instead of failing every send.
public actor DeviceAuthenticator {
    /// Which process this is. A Secure Enclave key works only in the session that made
    /// it: one the daemon made can't sign from `sudo altiward-agent` in a Terminal, nor
    /// the other way round.
    public enum Role: Sendable {
        /// Makes keys and uses every key: the daemon, or a command with its own data
        /// directory (development), where no daemon shares the store.
        case daemon
        /// A command run beside the daemon. It uses a file key, leaves a Secure Enclave
        /// key to the daemon, and on a Mac with a Secure Enclave leaves enrolling to the
        /// daemon too, so the Mac doesn't end up with a file key.
        case command
    }

    private struct Credential: Codable {
        var serverURL: String
        var privateKey: Data  // the raw P256 key, or the Secure Enclave's handle
        var deviceID: String?
        /// The Mac the key was made on. A store copied to another Mac (Migration Assistant,
        /// a clone, a restore) keeps a file key that works there, so without these the
        /// copy would go on signing as the first Mac. Nil in a record from before agent
        /// 0.8.0, or made while the Mac wouldn't say, which is given this Mac's the first
        /// time it is used and the Mac can say.
        var serial: String?
        var hardwareUUID: String?
    }

    /// A credential and the record it came from.
    private struct Stored {
        var credential: Credential
        var storage: KeyStorage
    }

    private static func storeKey(_ storage: KeyStorage) -> String {
        switch storage {
        case .software: "device_credential"
        case .secureEnclave: "device_credential_se"
        }
    }

    private let store: AgentStore
    private let serverURL: URL
    private let enrollmentToken: String
    private let device: @Sendable () -> DeviceInfo
    private let transport: any HTTPTransport
    private let keys: any DeviceKeys
    private let role: Role
    private let now: @Sendable () -> Date
    private let log: @Sendable (String) -> Void
    /// Server time minus local time, learned from a `clock_skew` response.
    private var clockOffset: TimeInterval = 0

    public init(
        store: AgentStore, serverURL: URL, enrollmentToken: String, device: @escaping @Sendable () -> DeviceInfo,
        transport: any HTTPTransport = URLSessionTransport(), keys: any DeviceKeys = SystemDeviceKeys(),
        role: Role = .daemon, now: @escaping @Sendable () -> Date = { Date() },
        log: @escaping @Sendable (String) -> Void = { _ in }
    ) {
        self.store = store
        self.serverURL = serverURL
        self.enrollmentToken = enrollmentToken
        self.device = device
        self.transport = transport
        self.keys = keys
        self.role = role
        self.now = now
        self.log = log
    }

    /// The enrolled device ID for the configured server, if any.
    public var deviceID: String? {
        (try? load())?.credential.deviceID
    }

    /// The serial the Mac reports now, which is ``DeviceIdentity/unreadable`` when it
    /// won't say.
    public var currentSerial: String {
        device().serial
    }

    /// Where the key for the configured server is kept, if there is one. Reads the store
    /// only; it never asks the Secure Enclave.
    public var keyStorage: KeyStorage? {
        (try? load())?.storage
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
        _ c: Stored, method: String, path: String, body: Data, timeout: TimeInterval
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
        let timestamp = Int64(now().addingTimeInterval(clockOffset).timeIntervalSince1970)
        try RequestSigning.sign(&request, deviceID: c.credential.deviceID!, timestamp: timestamp) { message in
            try withKey(c) { try keys.sign(message, key: $0, c.storage) }
        }
        return try await transport.send(request)
    }

    private func enrolled() async throws -> Stored {
        let info = device()
        var c = try boundToThisMac(info) ?? makeCredential(info)
        if role == .command, c.storage == .secureEnclave { throw DeviceKeyError.heldByDaemon }
        if c.credential.deviceID != nil { return c }

        let publicKey = try withKey(c) { try keys.publicKey($0, c.storage) }
        var request = URLRequest(url: serverURL.appendingPathComponent("v1/agent/enroll"), timeoutInterval: 30)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(enrollmentToken)", forHTTPHeaderField: "Authorization")
        request.setValue("altiward-agent/\(AgentVersion.current)", forHTTPHeaderField: "User-Agent")
        request.httpBody = try JSONEncoder().encode([
            "serial": info.serial, "hardware_uuid": info.hardwareUUID,
            "public_key": publicKey.base64EncodedString(), "key_storage": c.storage.rawValue,
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
        c.credential.deviceID = enrolled.device_id
        try store.transaction {
            // Unless another process has replaced the key meanwhile.
            if try record(c.storage)?.privateKey == c.credential.privateKey { try save(c) }
        }
        return c
    }

    /// Makes a key for the configured server and stores it, unless another process
    /// sharing the store stored one first. The key is made outside the transaction:
    /// the Secure Enclave can take seconds while someone signs in, and the store
    /// mustn't wait on it.
    private func makeCredential(_ info: DeviceInfo) throws -> Stored {
        var storage = KeyStorage.software
        if keys.secureEnclaveAvailable {
            guard role == .daemon else { throw DeviceKeyError.notEnrolled }
            storage = .secureEnclave
        }
        var key: Data
        do {
            key = try keys.makeKey(storage)
        } catch where storage == .secureEnclave {
            // A file key the console shows as one beats a Mac that never enrolls.
            log("couldn't make a key in the Secure Enclave, so this Mac's key is a file: \(error)")
            storage = .software
            key = try keys.makeKey(storage)
        }
        return try store.transaction {
            if let stored = try load() { return stored }
            let fresh = Stored(
                credential: Credential(
                    serverURL: serverURL.absoluteString, privateKey: key, serial: info.isReadable ? info.serial : nil,
                    hardwareUUID: info.isReadable ? info.hardwareUUID : nil),
                storage: storage)
            try save(fresh)
            // Neither record is for this server, so the other one is for an old one.
            try store.setValue(nil, forKey: Self.storeKey(storage == .software ? .secureEnclave : .software))
            return fresh
        }
    }

    /// The credential for the configured server that was made on this Mac, if any. One
    /// made on another Mac is dropped, so the Mac enrolls its own key; one from before
    /// agent 0.8.0 has no Mac recorded, so it gets this Mac's and stays enrolled, rather
    /// than sending every upgraded Mac to approval. Checks both records, since a downgrade
    /// and upgrade can leave a Secure Enclave key and a file key. When the Mac won't say
    /// which it is, it can't tell a copy from the original, so the stored key stays as it
    /// is and a later run checks it.
    private func boundToThisMac(_ info: DeviceInfo) throws -> Stored? {
        guard info.isReadable else {
            let stored = try load()
            if stored != nil { log("couldn't read this Mac's serial or hardware UUID; keeping the stored key") }
            return stored
        }
        while var c = try load() {
            guard let serial = c.credential.serial, let hardwareUUID = c.credential.hardwareUUID else {
                c.credential.serial = info.serial
                c.credential.hardwareUUID = info.hardwareUUID
                try store.transaction {
                    // Unless another process has replaced the key meanwhile.
                    if var current = try record(c.storage), current.privateKey == c.credential.privateKey {
                        current.serial = info.serial
                        current.hardwareUUID = info.hardwareUUID
                        try save(Stored(credential: current, storage: c.storage))
                    }
                }
                return c
            }
            if serial == info.serial, hardwareUUID == info.hardwareUUID { return c }
            log("this Mac's stored key was made on another Mac (serial \(serial)); enrolling again")
            try discard(c)
        }
        return nil
    }

    /// Runs `body` with `c`'s key. When the Secure Enclave can't use a key it holds, a
    /// throwaway key tells why: if that one signs, the Secure Enclave works and the stored
    /// key isn't one of its own (the store came from another Mac or a backup), so it's
    /// dropped for a fresh enrollment; if not, the Secure Enclave is unavailable for now
    /// and the key stays. Only the daemon gets here with a Secure Enclave key.
    private func withKey<T>(_ c: Stored, _ body: (Data) throws -> T) throws -> T {
        do {
            return try body(c.credential.privateKey)
        } catch where c.storage == .secureEnclave {
            let probe = Data("altiward-key-check".utf8)
            guard (try? keys.sign(probe, key: keys.makeKey(.secureEnclave), .secureEnclave)) != nil else {
                throw DeviceKeyError.secureEnclaveUnavailable(String(describing: error))
            }
            log("the Secure Enclave can't use this Mac's stored key (\(error)); enrolling again")
            try discard(c)
            throw DeliveryError.credentialInvalid
        }
    }

    /// The credential for the configured server: the Secure Enclave record's, else the
    /// file record's. Both can be there after a downgrade and upgrade; the file key stays
    /// in case it's the one the server ends up keeping.
    private func load() throws -> Stored? {
        for storage in [KeyStorage.secureEnclave, .software] {
            if let c = try record(storage), c.serverURL == serverURL.absoluteString {
                return Stored(credential: c, storage: storage)
            }
        }
        return nil
    }

    private func record(_ storage: KeyStorage) throws -> Credential? {
        try store.value(forKey: Self.storeKey(storage)).map {
            try JSONDecoder().decode(Credential.self, from: Data($0.utf8))
        }
    }

    private func save(_ c: Stored) throws {
        try store.setValue(
            String(decoding: try JSONEncoder().encode(c.credential), as: UTF8.self), forKey: Self.storeKey(c.storage))
    }

    /// Drops `c`'s record if it still holds `c`'s key. Another process sharing the store
    /// may have enrolled a new key since `c` was loaded; that one stays.
    private func discard(_ c: Stored) throws {
        try store.transaction {
            if try record(c.storage)?.privateKey == c.credential.privateKey {
                try store.setValue(nil, forKey: Self.storeKey(c.storage))
            }
        }
    }

    /// Drops the stored credential that has `deviceID`, so the next send enrolls with a new
    /// key. For when the server says that key belongs to another Mac. Does nothing if no
    /// record has that ID, as when another process sharing the store has already replaced
    /// the credential that was signed with.
    public func discardCredential(ifDeviceID deviceID: String) throws {
        let discarded = try store.transaction {
            var found = false
            for storage in [KeyStorage.secureEnclave, .software] where try record(storage)?.deviceID == deviceID {
                try store.setValue(nil, forKey: Self.storeKey(storage))
                found = true
            }
            return found
        }
        if discarded { log("the server says this key belongs to another Mac; enrolling again") }
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
