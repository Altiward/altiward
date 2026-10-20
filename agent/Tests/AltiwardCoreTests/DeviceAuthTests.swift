import CryptoKit
import Foundation
import Testing
import os

@testable import AltiwardCore

/// A stand-in for the API's enrollment and signature checks. It verifies real
/// signatures, so the tests prove the agent signs what the backend expects.
final class FakeServer: HTTPTransport, Sendable {
    struct Request: Sendable {
        let method: String
        let path: String
        var query: String? = nil
        let headers: [String: String]
        let body: Data
        var timeout: TimeInterval = 0
    }

    private struct State {
        var requests: [Request] = []
        var keys: [String: P256.Signing.PublicKey] = [:]  // device ID → key
        var enrollStatus = "active"
        var dropNextEnrollResponse = false
        var revoked: Set<String> = []
        var pending: Set<String> = []
        var commands: [AgentCommand] = []
        var results: [String: CommandResult] = [:]
        var failResults = 0
    }

    let clock: TestClock
    let serverOffset: TimeInterval
    private let state = OSAllocatedUnfairLock(initialState: State())

    init(clock: TestClock, serverOffset: TimeInterval = 0) {
        self.clock = clock
        self.serverOffset = serverOffset
    }

    var requests: [Request] { state.withLock { $0.requests } }
    var enrollments: [Request] { requests.filter { $0.path == "/v1/agent/enroll" } }
    func setEnrollStatus(_ s: String) { state.withLock { $0.enrollStatus = s } }
    func dropNextEnrollResponse() { state.withLock { $0.dropNextEnrollResponse = true } }
    func revoke(_ id: String) { state.withLock { _ = $0.revoked.insert(id) } }
    func queueCommand(_ c: AgentCommand) { state.withLock { $0.commands.append(c) } }
    func failResults(times: Int) { state.withLock { $0.failResults = times } }
    var results: [String: CommandResult] { state.withLock { $0.results } }

    struct Dropped: Error {}

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let url = try #require(request.url)
        let r = Request(
            method: request.httpMethod ?? "GET", path: url.path, query: url.query(percentEncoded: true),
            headers: request.allHTTPHeaderFields ?? [:], body: request.httpBody ?? Data(),
            timeout: request.timeoutInterval)
        let (status, headers, body) = try state.withLock { s -> (Int, [String: String], Data) in
            s.requests.append(r)
            return try handle(r, &s)
        }
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        return (body, response)
    }

    private func handle(_ r: Request, _ s: inout State) throws -> (Int, [String: String], Data) {
        let serverNow = clock.now.addingTimeInterval(serverOffset)
        if r.path == "/v1/agent/enroll" {
            guard r.headers["Authorization"] == "Bearer enroll-token-0001" else { return (401, [:], Data()) }
            let body = try JSONSerialization.jsonObject(with: r.body) as! [String: String]
            let key = try P256.Signing.PublicKey(derRepresentation: Data(base64Encoded: body["public_key"]!)!)
            let id =
                s.keys.first { $0.value.derRepresentation == key.derRepresentation }?.key
                ?? UUID().uuidString.lowercased()
            s.keys[id] = key
            if s.enrollStatus == "pending" { s.pending.insert(id) }
            if s.dropNextEnrollResponse {
                s.dropNextEnrollResponse = false
                throw Dropped()
            }
            return (201, [:], Data(#"{"device_id":"\#(id)","status":"\#(s.enrollStatus)"}"#.utf8))
        }

        func coded(_ status: Int, _ code: String, _ headers: [String: String] = [:]) -> (Int, [String: String], Data) {
            (status, headers, Data(#"{"error":"no","code":"\#(code)"}"#.utf8))
        }
        guard let auth = r.headers["Authorization"], auth.hasPrefix("AltiwardDevice "),
            let ts = r.headers["X-Altiward-Timestamp"].flatMap(Int64.init),
            let sig = r.headers["X-Altiward-Signature"].flatMap({ Data(base64Encoded: $0) })
        else { return coded(401, "credential_invalid") }
        let id = String(auth.dropFirst("AltiwardDevice ".count))
        let canonical = RequestSigning.canonicalString(
            method: r.method, pathAndQuery: r.path + (r.query.map { "?" + $0 } ?? ""), timestamp: ts, body: r.body)
        guard let key = s.keys[id], !s.revoked.contains(id),
            key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: sig), for: Data(canonical.utf8))
        else { return coded(401, "credential_invalid") }
        if abs(Double(ts) - serverNow.timeIntervalSince1970) > 300 {
            return coded(401, "clock_skew", ["Date": httpDate(serverNow)])
        }
        if s.pending.contains(id) { return coded(403, "enrollment_pending") }
        if r.method == "GET", r.path == "/v1/agent/commands" {
            // Like the API: every command still waiting for a result.
            let waiting = s.commands.filter { s.results[$0.commandID] == nil }
            return (200, [:], try AltiwardJSON.encoder().encode(AgentCommandList(commands: waiting)))
        }
        if r.method == "POST", r.path.hasPrefix("/v1/agent/commands/"), r.path.hasSuffix("/result") {
            if s.failResults > 0 {
                s.failResults -= 1
                return (503, [:], Data(#"{"error":"try later"}"#.utf8))
            }
            let commandID = r.path.split(separator: "/")[3]
            let result = try AltiwardJSON.decoder().decode(CommandResult.self, from: r.body)
            if s.results[String(commandID)] == nil { s.results[String(commandID)] = result }
            return (200, [:], Data(#"{"status":"\#(result.status.rawValue)"}"#.utf8))
        }
        return (200, [:], Data(#"{"accepted":[],"duplicate":[],"rejected":[]}"#.utf8))
    }
}

func httpDate(_ date: Date) -> String {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = TimeZone(identifier: "GMT")
    f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
    return f.string(from: date)
}

/// Forwards to a ``FakeServer``, first running work queued with ``beforeNextRequest(_:)``
/// once: what another process does while this request is in flight.
final class InterleavingTransport: HTTPTransport, Sendable {
    typealias Work = @Sendable () async throws -> Void
    let server: FakeServer
    private let next = OSAllocatedUnfairLock<Work?>(initialState: nil)

    init(server: FakeServer) { self.server = server }

    func beforeNextRequest(_ work: @escaping Work) { next.withLock { $0 = work } }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        if let work = next.withLock({ w -> Work? in defer { w = nil }; return w }) {
            try await work()
        }
        return try await server.send(request)
    }
}

struct SignatureVector: Decodable {
    let deviceID, method, path, body, canonical, publicKeySPKI, signature: String
    let timestamp: Int64

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id", method, path, body, canonical, timestamp
        case publicKeySPKI = "public_key_spki", signature
    }

    static func load() throws -> SignatureVector {
        try JSONDecoder().decode(
            SignatureVector.self, from: Data(contentsOf: repoFile("docs/schema/signature-vector.json")))
    }
}

struct RequestSigningTests {
    @Test func canonicalStringMatchesContract() throws {
        let v = try SignatureVector.load()
        let got = RequestSigning.canonicalString(
            method: v.method, pathAndQuery: v.path, timestamp: v.timestamp, body: Data(v.body.utf8))
        #expect(got == v.canonical)
    }

    @Test func verifiesBackendSignatureFromContract() throws {
        let v = try SignatureVector.load()
        let key = try P256.Signing.PublicKey(derRepresentation: Data(base64Encoded: v.publicKeySPKI)!)
        let sig = try P256.Signing.ECDSASignature(derRepresentation: Data(base64Encoded: v.signature)!)
        #expect(key.isValidSignature(sig, for: Data(v.canonical.utf8)))
        #expect(!key.isValidSignature(sig, for: Data(v.canonical.replacingOccurrences(of: "POST", with: "GET").utf8)))
    }
}

struct DeviceAuthenticatorTests {
    let clock = TestClock()
    let serverURL = URL(string: "https://api.altiward.test")!

    func authenticator(_ store: AgentStore, _ server: FakeServer, url: URL? = nil) -> DeviceAuthenticator {
        DeviceAuthenticator(
            store: store, serverURL: url ?? serverURL, enrollmentToken: "enroll-token-0001", device: { testDevice },
            transport: server, now: { clock.now })
    }

    func postEvents(_ auth: DeviceAuthenticator) async throws -> Int {
        let (_, response) = try await auth.send(method: "POST", path: "v1/agent/events", body: Data(#"{"events":[]}"#.utf8))
        return response.statusCode
    }

    func enrolledKey(_ r: FakeServer.Request) throws -> String {
        let body = try JSONSerialization.jsonObject(with: r.body) as! [String: String]
        return try #require(body["public_key"])
    }

    @Test func enrollsOnceThenSignsRequests() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(store, server)) == 200)

        let enroll = try #require(server.enrollments.first)
        let body = try JSONSerialization.jsonObject(with: enroll.body) as! [String: String]
        #expect(body["serial"] == testDevice.serial)
        #expect(body["hardware_uuid"] == testDevice.hardwareUUID)
        let events = try #require(server.requests.last)
        #expect(events.path == "/v1/agent/events")
        #expect(events.headers["X-Altiward-Timestamp"] == String(Int64(clock.now.timeIntervalSince1970)))
        #expect(events.headers["Authorization"]?.hasPrefix("AltiwardDevice ") == true)

        // A restarted agent reuses the stored credential.
        #expect(try await postEvents(authenticator(store, server)) == 200)
        #expect(server.enrollments.count == 1)
    }

    @Test func retryAfterLostEnrollResponseReusesKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        server.dropNextEnrollResponse()
        let auth = authenticator(store, server)
        await #expect(throws: (any Error).self) { try await postEvents(auth) }
        #expect(try await postEvents(auth) == 200)
        let enrollments = server.enrollments
        #expect(enrollments.count == 2)
        #expect(try enrolledKey(enrollments[0]) == enrolledKey(enrollments[1]))
    }

    @Test func invalidCredentialLeadsToFreshEnrollment() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        let firstID = try #require(await auth.deviceID)
        server.revoke(firstID)

        await #expect(throws: DeliveryError.credentialInvalid) { try await postEvents(auth) }
        #expect(try await postEvents(auth) == 200)
        let enrollments = server.enrollments
        #expect(enrollments.count == 2)
        #expect(try enrolledKey(enrollments[0]) != enrolledKey(enrollments[1]))
        #expect(await auth.deviceID != firstID)
    }

    /// Two agent processes share the store (the daemon and a CLI command). If one enrolls a
    /// new key while the other's request is in flight, the server rejects that request's
    /// old key; dropping the stored credential then would throw away the new one too, and
    /// the next enrollment would revoke it in turn.
    @Test func rejectedOldKeyDoesNotDiscardANewerCredential() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let other = try makeStore()
        let transport = InterleavingTransport(server: server)
        let auth = DeviceAuthenticator(
            store: store, serverURL: serverURL, enrollmentToken: "enroll-token-0001", device: { testDevice },
            transport: transport, now: { clock.now })
        #expect(try await postEvents(auth) == 200)
        let firstID = try #require(await auth.deviceID)

        transport.beforeNextRequest {
            // The other process enrolls a new key, which revokes the old one, and saves it.
            #expect(try await postEvents(authenticator(other, server)) == 200)
            server.revoke(firstID)
            try store.setValue(other.value(forKey: "device_credential"), forKey: "device_credential")
        }
        await #expect(throws: DeliveryError.credentialInvalid) { try await postEvents(auth) }

        let newerID = try #require(await authenticator(other, server).deviceID)
        #expect(await auth.deviceID == newerID)
        #expect(try await postEvents(auth) == 200)
        #expect(server.enrollments.count == 2)
    }

    @Test func pendingEnrollmentKeepsCredentialAndWaits() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        server.setEnrollStatus("pending")
        let auth = authenticator(store, server)
        await #expect(throws: DeliveryError.enrollmentPending) { try await postEvents(auth) }
        await #expect(throws: DeliveryError.enrollmentPending) { try await postEvents(auth) }
        #expect(server.enrollments.count == 1)
    }

    @Test func correctsClockFromServerDate() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock, serverOffset: 600)  // the Mac's clock is 10 minutes slow
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        let last = try #require(server.requests.last)
        #expect(last.headers["X-Altiward-Timestamp"] == String(Int64(clock.now.timeIntervalSince1970) + 600))
    }

    @Test func changingServerURLReenrolls() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(store, server)) == 200)
        #expect(try await postEvents(authenticator(store, server, url: URL(string: "https://eu.altiward.test")!)) == 200)
        #expect(server.enrollments.count == 2)
    }
}
