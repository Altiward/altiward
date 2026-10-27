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
        var enrollRefusal: (status: Int, headers: [String: String])?
        var dropNextEnrollResponse = false
        var revoked: Set<String> = []
        var pending: Set<String> = []
        var commands: [AgentCommand] = []
        var results: [String: CommandResult] = [:]
        var failResults = 0
        var eventRejections: [String: IngestResponse.Rejection] = [:]  // event ID → answer once
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
    /// Answers every enrolment with `status` and `headers` until ``acceptEnrollments()``.
    func refuseEnrollments(status: Int, headers: [String: String] = [:]) {
        state.withLock { $0.enrollRefusal = (status, headers) }
    }
    func acceptEnrollments() { state.withLock { $0.enrollRefusal = nil } }
    func dropNextEnrollResponse() { state.withLock { $0.dropNextEnrollResponse = true } }
    func revoke(_ id: String) { state.withLock { _ = $0.revoked.insert(id) } }
    func approve(_ id: String) { state.withLock { _ = $0.pending.remove(id) } }
    func queueCommand(_ c: AgentCommand) { state.withLock { $0.commands.append(c) } }
    func failResults(times: Int) { state.withLock { $0.failResults = times } }
    /// Rejects the event with this ID the next time it is posted; any other event is accepted.
    func rejectEvent(_ id: String, error: String, code: String? = nil) {
        state.withLock { $0.eventRejections[id] = IngestResponse.Rejection(eventID: id, error: error, code: code) }
    }
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
            if let (status, headers) = s.enrollRefusal {
                return (status, headers, Data(#"{"error":"try again later","code":"enrollment_rate_limited"}"#.utf8))
            }
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
        if r.method == "POST", r.path == "/v1/agent/events" {
            struct Posted: Decodable {
                struct Event: Decodable { let event_id: String }
                let events: [Event]
            }
            var verdicts = IngestResponse()
            for event in try JSONDecoder().decode(Posted.self, from: r.body).events {
                if let rejection = s.eventRejections.removeValue(forKey: event.event_id) {
                    verdicts.rejected.append(rejection)
                } else {
                    verdicts.accepted.append(event.event_id)
                }
            }
            return (200, [:], try JSONEncoder().encode(verdicts))
        }
        return (200, [:], Data(#"{"accepted":[],"duplicate":[],"rejected":[]}"#.utf8))
    }
}

/// Device keys for tests. Its "Secure Enclave" keys are software keys behind a prefix,
/// so they aren't 32 bytes and a file-key loader can't take them for its own.
final class FakeKeys: DeviceKeys, Sendable {
    private struct State {
        var available = true
        var failCreate = false
        var busy = false
        var made: [Data] = []
        var dead: Set<Data> = []
        var beforeMake: (@Sendable () throws -> Void)?
    }

    struct Failed: Error {}
    static let prefix = Data("SE:".utf8)
    private let state = OSAllocatedUnfairLock(initialState: State())

    init(secureEnclave: Bool = true) { state.withLock { $0.available = secureEnclave } }

    var secureEnclaveAvailable: Bool { state.withLock { $0.available } }
    func failCreate(_ fail: Bool) { state.withLock { $0.failCreate = fail } }
    func busy(_ busy: Bool) { state.withLock { $0.busy = busy } }
    /// Makes every Secure Enclave key so far unusable, as on another Mac.
    func killExistingKeys() { state.withLock { $0.dead = Set($0.made) } }
    /// Runs once, before the next key is made: what another process does meanwhile.
    func beforeNextMake(_ work: @escaping @Sendable () throws -> Void) { state.withLock { $0.beforeMake = work } }

    func makeKey(_ storage: KeyStorage) throws -> Data {
        if let work = state.withLock({ s -> (@Sendable () throws -> Void)? in defer { s.beforeMake = nil }; return s.beforeMake }) {
            try work()
        }
        let raw = P256.Signing.PrivateKey().rawRepresentation
        guard storage == .secureEnclave else { return raw }
        return try state.withLock { s in
            guard s.available, !s.failCreate, !s.busy else { throw Failed() }
            let key = Self.prefix + raw
            s.made.append(key)
            return key
        }
    }

    func publicKey(_ key: Data, _ storage: KeyStorage) throws -> Data {
        try privateKey(key, storage).publicKey.derRepresentation
    }

    func sign(_ message: Data, key: Data, _ storage: KeyStorage) throws -> Data {
        try privateKey(key, storage).signature(for: message).derRepresentation
    }

    private func privateKey(_ key: Data, _ storage: KeyStorage) throws -> P256.Signing.PrivateKey {
        guard storage == .secureEnclave else { return try P256.Signing.PrivateKey(rawRepresentation: key) }
        try state.withLock { s in
            guard s.available, !s.busy, !s.dead.contains(key), key.starts(with: Self.prefix) else { throw Failed() }
        }
        return try P256.Signing.PrivateKey(rawRepresentation: key.dropFirst(Self.prefix.count))
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

struct RotationVector: Decodable {
    let deviceID, newPublicKey, statement, proof: String

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id", newPublicKey = "new_public_key", statement, proof
    }

    static func load() throws -> RotationVector {
        try JSONDecoder().decode(
            RotationVector.self, from: Data(contentsOf: repoFile("docs/schema/rotation-vector.json")))
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

    @Test func rotationStatementMatchesContract() throws {
        let v = try RotationVector.load()
        let got = RotationProof.statement(deviceID: v.deviceID, newPublicKey: Data(base64Encoded: v.newPublicKey)!)
        #expect(got == v.statement)
    }

    @Test func verifiesBackendRotationProofFromContract() throws {
        let v = try RotationVector.load()
        let key = try P256.Signing.PublicKey(derRepresentation: Data(base64Encoded: v.newPublicKey)!)
        let proof = try P256.Signing.ECDSASignature(derRepresentation: Data(base64Encoded: v.proof)!)
        #expect(key.isValidSignature(proof, for: Data(v.statement.utf8)))
        let other = RotationProof.statement(deviceID: "00000000-0000-4000-8000-000000000000", newPublicKey: key.derRepresentation)
        #expect(!key.isValidSignature(proof, for: Data(other.utf8)))
    }
}

struct DeviceAuthenticatorTests {
    let clock = TestClock()
    let serverURL = URL(string: "https://api.altiward.test")!
    let keys = FakeKeys()

    func authenticator(
        _ store: AgentStore, _ server: FakeServer, url: URL? = nil, keys: FakeKeys? = nil,
        role: DeviceAuthenticator.Role = .daemon, device: DeviceInfo = testDevice,
        log: @escaping @Sendable (String) -> Void = { _ in }
    ) -> DeviceAuthenticator {
        DeviceAuthenticator(
            store: store, serverURL: url ?? serverURL, enrollmentToken: "enroll-token-0001", device: { device },
            transport: server, keys: keys ?? self.keys, role: role, now: { clock.now }, log: log)
    }

    /// This test's Mac, with another serial and hardware UUID.
    func mac(_ serial: String, _ hardwareUUID: String) -> DeviceInfo {
        var d = testDevice
        d.serial = serial
        d.hardwareUUID = hardwareUUID
        return d
    }

    func enrolledStorage(_ r: FakeServer.Request) throws -> String? {
        let body = try JSONSerialization.jsonObject(with: r.body) as! [String: String]
        return body["key_storage"]
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
            transport: transport, keys: keys, now: { clock.now })
        #expect(try await postEvents(auth) == 200)
        let firstID = try #require(await auth.deviceID)

        transport.beforeNextRequest {
            // The other process enrolls a new key, which revokes the old one, and saves it.
            #expect(try await postEvents(authenticator(other, server)) == 200)
            server.revoke(firstID)
            try store.setValue(other.value(forKey: "device_credential_se"), forKey: "device_credential_se")
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

    /// A Mac the server's enrolment limits refuse waits as long as the server says before
    /// it asks again, rather than on every poll and heartbeat.
    @Test func aRefusedEnrolmentWaitsForRetryAfter() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        server.refuseEnrollments(status: 429, headers: ["Retry-After": "3600"])
        let auth = authenticator(store, server)
        let until = clock.now.addingTimeInterval(3600)
        await #expect(throws: DeliveryError.enrollmentRateLimited(until: until)) { try await postEvents(auth) }
        #expect(server.enrollments.count == 1)

        server.acceptEnrollments()
        await #expect(throws: DeliveryError.enrollmentRateLimited(until: until)) { try await postEvents(auth) }
        clock.advance(3599)
        await #expect(throws: DeliveryError.enrollmentRateLimited(until: until)) { try await postEvents(auth) }
        #expect(server.requests.count == 1)

        clock.advance(2)
        #expect(try await postEvents(auth) == 200)
        #expect(server.enrollments.count == 2)
        #expect(try enrolledKey(server.enrollments[0]) == enrolledKey(server.enrollments[1]))
    }

    @Test(arguments: [nil, "soon", "-60"] as [String?])
    func aRefusedEnrolmentWithoutRetryAfterWaitsAnHour(_ retryAfter: String?) async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        server.refuseEnrollments(status: 429, headers: retryAfter.map { ["Retry-After": $0] } ?? [:])
        let auth = authenticator(store, server)
        let until = clock.now.addingTimeInterval(3600)
        await #expect(throws: DeliveryError.enrollmentRateLimited(until: until)) { try await postEvents(auth) }

        server.acceptEnrollments()
        clock.advance(3599)
        await #expect(throws: DeliveryError.enrollmentRateLimited(until: until)) { try await postEvents(auth) }
        #expect(server.enrollments.count == 1)
        clock.advance(2)
        #expect(try await postEvents(auth) == 200)
    }

    /// Retry-After can be a date, by the server's clock, and the agent waits at most a day.
    @Test func aRefusedEnrolmentReadsADateAndWaitsAtMostADay() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        server.refuseEnrollments(status: 429, headers: ["Retry-After": httpDate(clock.now.addingTimeInterval(7200))])
        let auth = authenticator(store, server)
        await #expect(throws: DeliveryError.enrollmentRateLimited(until: clock.now.addingTimeInterval(7200))) {
            try await postEvents(auth)
        }

        clock.advance(7201)
        server.refuseEnrollments(status: 429, headers: ["Retry-After": "604800"])
        await #expect(throws: DeliveryError.enrollmentRateLimited(until: clock.now.addingTimeInterval(86400))) {
            try await postEvents(auth)
        }
        #expect(server.enrollments.count == 2)
    }

    /// Only a 429 means "wait": another refusal is tried again on the next send, as before.
    @Test func anotherEnrolmentRefusalDoesNotWait() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        server.refuseEnrollments(status: 503, headers: ["Retry-After": "3600"])
        let auth = authenticator(store, server)
        await #expect(throws: (any Error).self) { try await postEvents(auth) }
        server.acceptEnrollments()
        #expect(try await postEvents(auth) == 200)
        #expect(server.enrollments.count == 2)
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

    // MARK: Where the key is kept

    /// The credential as agent 0.1 reads it from "device_credential".
    struct V01Credential: Decodable {
        var serverURL: String
        var privateKey: Data
        var deviceID: String?
    }

    @Test func newKeyGoesInSecureEnclave() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        #expect(try enrolledStorage(#require(server.enrollments.first)) == "secure_enclave")
        #expect(try store.value(forKey: "device_credential_se") != nil)
        #expect(try store.value(forKey: "device_credential") == nil)
        #expect(await auth.keyStorage == .secureEnclave)
    }

    @Test func withoutSecureEnclaveAFileKeyKeepsTheOldFormat() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let auth = authenticator(store, server, keys: FakeKeys(secureEnclave: false))
        #expect(try await postEvents(auth) == 200)
        #expect(try enrolledStorage(#require(server.enrollments.first)) == "software")
        #expect(await auth.keyStorage == .software)

        // An older agent installed over this one can still sign with it.
        let json = try #require(try store.value(forKey: "device_credential"))
        let old = try JSONDecoder().decode(V01Credential.self, from: Data(json.utf8))
        #expect(old.deviceID == (await auth.deviceID))
        _ = try P256.Signing.PrivateKey(rawRepresentation: old.privateKey)
        #expect(try store.value(forKey: "device_credential_se") == nil)
    }

    @Test func failingToMakeASecureEnclaveKeyFallsBackToAFile() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        keys.failCreate(true)
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        #expect(try enrolledStorage(#require(server.enrollments.first)) == "software")
        #expect(await auth.keyStorage == .software)
    }

    @Test func anEnrolledFileKeyStays() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(store, server, keys: FakeKeys(secureEnclave: false))) == 200)

        // Upgraded on a Mac with a Secure Enclave: it keeps signing with the file key.
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        #expect(server.enrollments.count == 1)
        #expect(await auth.keyStorage == .software)
    }

    @Test func aRevokedFileKeyMovesToTheSecureEnclave() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(store, server, keys: FakeKeys(secureEnclave: false))) == 200)
        let auth = authenticator(store, server)
        server.revoke(try #require(await auth.deviceID))

        await #expect(throws: DeliveryError.credentialInvalid) { try await postEvents(auth) }
        #expect(try await postEvents(auth) == 200)
        #expect(try enrolledStorage(server.enrollments[1]) == "secure_enclave")
        #expect(try store.value(forKey: "device_credential") == nil)
        #expect(await auth.keyStorage == .secureEnclave)
    }

    /// Agent 0.1 installed over this one ignores the Secure Enclave record and enrolls a
    /// file key, which with approval off revokes the Secure Enclave key. Upgraded again,
    /// the agent finds the Secure Enclave key refused and goes on with the file key.
    @Test func downgradeAndUpgradeWithApprovalOff() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        let enclaveID = try #require(await auth.deviceID)

        let fileID = try await enrollAsAgent01(store, server)
        server.revoke(enclaveID)

        await #expect(throws: DeliveryError.credentialInvalid) { try await postEvents(auth) }
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == fileID)
        #expect(await auth.keyStorage == .software)
        #expect(server.enrollments.count == 2)
    }

    /// With approval on, the downgraded agent's file key waits for approval while the
    /// Secure Enclave key keeps working. The agent keeps both, so approving the file key
    /// later still leaves it a key that works.
    @Test func downgradeAndUpgradeWithApprovalOn() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        let enclaveID = try #require(await auth.deviceID)

        server.setEnrollStatus("pending")
        let fileID = try await enrollAsAgent01(store, server)
        server.setEnrollStatus("active")

        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == enclaveID)
        #expect(try store.value(forKey: "device_credential") != nil)

        server.approve(fileID)
        server.revoke(enclaveID)
        await #expect(throws: DeliveryError.credentialInvalid) { try await postEvents(auth) }
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == fileID)
    }

    /// What agent 0.1 does on a store whose only key is in the Secure Enclave record: it
    /// finds no credential, so it enrolls a file key and saves it in its own record.
    func enrollAsAgent01(_ store: AgentStore, _ server: FakeServer) async throws -> String {
        let key = P256.Signing.PrivateKey()
        var request = URLRequest(url: serverURL.appendingPathComponent("v1/agent/enroll"))
        request.httpMethod = "POST"
        request.setValue("Bearer enroll-token-0001", forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONEncoder().encode([
            "serial": testDevice.serial, "hardware_uuid": testDevice.hardwareUUID,
            "public_key": key.publicKey.derRepresentation.base64EncodedString(),
        ])
        struct Enrolled: Decodable { let device_id: String }
        let id = try JSONDecoder().decode(Enrolled.self, from: await server.send(request).0).device_id
        let json = #"{"serverURL":"\#(serverURL.absoluteString)","privateKey":"\#(key.rawRepresentation.base64EncodedString())","deviceID":"\#(id)"}"#
        try store.setValue(json, forKey: "device_credential")
        return id
    }

    @Test func aKeyFromAnotherMacEnrollsAgain() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)

        keys.killExistingKeys()
        await #expect(throws: DeliveryError.credentialInvalid) { try await postEvents(auth) }
        #expect(try await postEvents(auth) == 200)
        #expect(server.enrollments.count == 2)
        #expect(try enrolledStorage(server.enrollments[1]) == "secure_enclave")
    }

    // MARK: Which Mac the key was made on

    /// The parts of a stored credential that say which Mac it belongs to.
    struct StoredIdentity: Decodable {
        var privateKey: Data
        var serial: String?
        var hardwareUUID: String?
    }

    func storedIdentity(_ store: AgentStore, _ key: String) throws -> StoredIdentity? {
        try store.value(forKey: key).map { try JSONDecoder().decode(StoredIdentity.self, from: Data($0.utf8)) }
    }

    /// A store copied to another Mac (Migration Assistant, a clone, a restore) that holds a
    /// file key: the copy would otherwise go on signing as the first Mac.
    @Test func aCredentialMadeOnAnotherMacEnrollsAgain() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(store, server, device: mac("C02AAA", "U1"))) == 200)
        let first = try #require(try storedIdentity(store, "device_credential_se"))
        #expect(first.serial == "C02AAA")
        #expect(first.hardwareUUID == "U1")

        let copy = authenticator(store, server, device: mac("C02BBB", "U2"))
        #expect(try await postEvents(copy) == 200)
        let enrollments = server.enrollments
        try #require(enrollments.count == 2)
        let body = try JSONSerialization.jsonObject(with: enrollments[1].body) as! [String: String]
        #expect(body["serial"] == "C02BBB")
        #expect(try enrolledKey(enrollments[0]) != enrolledKey(enrollments[1]))

        // Only the new key is left, and it is bound to this Mac.
        let second = try #require(try storedIdentity(store, "device_credential_se"))
        #expect(second.privateKey != first.privateKey)
        #expect(second.serial == "C02BBB")
        #expect(second.hardwareUUID == "U2")
        #expect(try keys.publicKey(second.privateKey, .secureEnclave).base64EncodedString() == enrolledKey(enrollments[1]))
        #expect(try store.value(forKey: "device_credential") == nil)
    }

    @Test func aChangedHardwareUUIDEnrollsAgain() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(store, server, device: mac("C02AAA", "U1"))) == 200)
        #expect(try await postEvents(authenticator(store, server, device: mac("C02AAA", "U2"))) == 200)
        #expect(server.enrollments.count == 2)
    }

    /// After a downgrade and upgrade the store holds a Secure Enclave key and a file key.
    /// Dropping the first must not leave the Mac signing with the second.
    @Test func everyKeyMadeOnAnotherMacIsDropped() async throws {
        let store = try makeStore()
        let other = try makeStore()
        let server = FakeServer(clock: clock)
        let first = mac("C02AAA", "U1")
        #expect(try await postEvents(authenticator(store, server, device: first)) == 200)
        #expect(try await postEvents(authenticator(other, server, keys: FakeKeys(secureEnclave: false), device: first)) == 200)
        try store.setValue(other.value(forKey: "device_credential"), forKey: "device_credential")

        let copy = authenticator(store, server, device: mac("C02BBB", "U2"))
        #expect(try await postEvents(copy) == 200)
        #expect(server.enrollments.count == 3)
        #expect(try store.value(forKey: "device_credential") == nil)
        #expect(await copy.keyStorage == .secureEnclave)
    }

    /// When the Mac won't say which it is (IOKit failed), the agent can't tell a copy from
    /// the original, so it keeps signing with the key it has and checks on a later run.
    @Test func anUnreadableIdentityKeepsTheKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let first = mac("C02AAA", "U1")
        #expect(try await postEvents(authenticator(store, server, device: first)) == 200)
        let before = try store.value(forKey: "device_credential_se")

        let logged = OSAllocatedUnfairLock(initialState: [String]())
        let unreadable = authenticator(
            store, server, device: mac(DeviceIdentity.unreadable, "U1"), log: { line in logged.withLock { $0.append(line) } })
        #expect(try await postEvents(unreadable) == 200)
        #expect(server.enrollments.count == 1)
        #expect(try store.value(forKey: "device_credential_se") == before)
        #expect(logged.withLock { $0 } == ["couldn't read this Mac's serial or hardware UUID; keeping the stored key"])

        // Once the Mac can say, the check goes on as usual.
        #expect(try await postEvents(authenticator(store, server, device: first)) == 200)
        #expect(server.enrollments.count == 1)
        #expect(try await postEvents(authenticator(store, server, device: mac("C02BBB", "U2"))) == 200)
        #expect(server.enrollments.count == 2)
    }

    @Test func anUnreadableIdentityDoesNotBindAnOldRecord() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        _ = try await enrollAsAgent01(store, server)
        let before = try store.value(forKey: "device_credential")

        let auth = authenticator(store, server, device: mac(DeviceIdentity.unreadable, DeviceIdentity.unreadable))
        #expect(try await postEvents(auth) == 200)
        #expect(server.enrollments.count == 1)
        #expect(try store.value(forKey: "device_credential") == before)
        let after = try #require(try storedIdentity(store, "device_credential"))
        #expect(after.serial == nil)
        #expect(after.hardwareUUID == nil)
    }

    /// A key made while the Mac won't say which it is records no Mac, rather than "unknown",
    /// and takes the Mac's identity on the first run that can read it.
    @Test func aKeyMadeWhileTheIdentityIsUnreadableIsBoundLater() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(store, server, device: mac(DeviceIdentity.unreadable, "U1"))) == 200)
        let made = try #require(try storedIdentity(store, "device_credential_se"))
        #expect(made.serial == nil)
        #expect(made.hardwareUUID == nil)

        #expect(try await postEvents(authenticator(store, server, device: mac("C02AAA", "U1"))) == 200)
        #expect(server.enrollments.count == 1)
        let bound = try #require(try storedIdentity(store, "device_credential_se"))
        #expect(bound.privateKey == made.privateKey)
        #expect(bound.serial == "C02AAA")
        #expect(bound.hardwareUUID == "U1")
    }

    /// A credential stored by an earlier agent has no serial. Re-enrolling it would send
    /// every upgraded Mac to console approval, so it is bound to the Mac it is on.
    @Test func aCredentialFromBeforeThisVersionIsBoundToThisMac() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let id = try await enrollAsAgent01(store, server)
        let before = try #require(try storedIdentity(store, "device_credential"))
        #expect(before.serial == nil)
        #expect(before.hardwareUUID == nil)

        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        #expect(server.enrollments.count == 1)
        #expect(await auth.deviceID == id)
        let after = try #require(try storedIdentity(store, "device_credential"))
        #expect(after.privateKey == before.privateKey)
        #expect(after.serial == testDevice.serial)
        #expect(after.hardwareUUID == testDevice.hardwareUUID)
    }

    @Test func aBusySecureEnclaveKeepsTheKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        let id = await auth.deviceID

        keys.busy(true)
        await #expect(throws: DeviceKeyError.self) { try await postEvents(auth) }
        keys.busy(false)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == id)
        #expect(server.enrollments.count == 1)
    }

    @Test func aCommandLeavesTheSecureEnclaveKeyToTheDaemon() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(store, server)) == 200)

        let command = authenticator(store, server, role: .command)
        await #expect(throws: DeviceKeyError.heldByDaemon) { try await postEvents(command) }
        #expect(await command.deviceID != nil)
        #expect(await command.keyStorage == .secureEnclave)
        #expect(server.enrollments.count == 1)
    }

    @Test func aCommandLeavesEnrollingToTheDaemonOnAMacWithASecureEnclave() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        await #expect(throws: DeviceKeyError.notEnrolled) {
            try await postEvents(authenticator(store, server, role: .command))
        }
        #expect(server.enrollments.isEmpty)

        // Without a Secure Enclave both processes can use a file key, as before.
        let noEnclave = FakeKeys(secureEnclave: false)
        #expect(try await postEvents(authenticator(store, server, keys: noEnclave, role: .command)) == 200)
        #expect(try await postEvents(authenticator(store, server, keys: noEnclave)) == 200)
        #expect(server.enrollments.count == 1)
    }

    /// The daemon and a command share the store; if the other one stores a key while
    /// this one makes its own, the stored key wins and only one is enrolled.
    @Test func aKeyStoredMeanwhileByAnotherProcessWins() async throws {
        let store = try makeStore()
        let other = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(other, server, keys: FakeKeys())) == 200)
        let otherID = try #require(await authenticator(other, server, keys: FakeKeys()).deviceID)

        keys.beforeNextMake {
            try store.setValue(other.value(forKey: "device_credential_se"), forKey: "device_credential_se")
        }
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == otherID)
        #expect(server.enrollments.count == 1)
    }

    /// The real Secure Enclave, on Macs that have one (not CI's virtual machines).
    @Test(.enabled(if: SecureEnclave.isAvailable)) func signsWithTheRealSecureEnclave() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let auth = DeviceAuthenticator(
            store: store, serverURL: serverURL, enrollmentToken: "enroll-token-0001", device: { testDevice },
            transport: server, keys: SystemDeviceKeys(), now: { clock.now })
        #expect(try await postEvents(auth) == 200)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.keyStorage == .secureEnclave)
        #expect(server.enrollments.count == 1)
    }
}

struct HTTPEventSinkTests {
    let clock = TestClock()
    let serverURL = URL(string: "https://api.altiward.test")!
    let mismatch = "device.serial does not match the sending device"
    let logged = OSAllocatedUnfairLock(initialState: [String]())

    func sink(_ store: AgentStore, _ server: FakeServer, device: DeviceInfo = testDevice) -> (HTTPEventSink, DeviceAuthenticator) {
        let auth = DeviceAuthenticator(
            store: store, serverURL: serverURL, enrollmentToken: "enroll-token-0001", device: { device },
            transport: server, keys: FakeKeys(), now: { clock.now }, log: { line in logged.withLock { $0.append(line) } })
        return (HTTPEventSink(authenticator: auth), auth)
    }

    /// An event naming `serial`, which the test's Mac sends when it is the Mac's own.
    func event(serial: String = testDevice.serial) -> AltiwardEvent {
        var e = sampleEvent()
        e.device.serial = serial
        return e
    }

    func enrolledKey(_ r: FakeServer.Request) throws -> String {
        let body = try JSONSerialization.jsonObject(with: r.body) as! [String: String]
        return try #require(body["public_key"])
    }

    /// The server says the key belongs to another Mac, but these events name this one: the
    /// key is what is wrong, so the events stay queued and the next send enrols a new key.
    @Test func aMismatchForThisMacsEventsKeepsThemAndEnrollsAgain() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (sink, auth) = sink(store, server)
        let own = event()
        server.rejectEvent(own.eventID, error: mismatch, code: "device_mismatch")

        let response = try await sink.send([own])
        #expect(response.rejected.isEmpty)
        #expect(response.accepted.isEmpty)
        #expect(server.enrollments.count == 1)
        #expect(await auth.deviceID == nil)
        #expect(logged.withLock { $0 } == ["the server says this key belongs to another Mac; enrolling again"])

        let retry = try await sink.send([own])
        #expect(retry.accepted == [own.eventID])
        let enrollments = server.enrollments
        try #require(enrollments.count == 2)
        #expect(try enrolledKey(enrollments[0]) != enrolledKey(enrollments[1]))
    }

    /// Events naming another Mac are stale copies of its queue. That Mac delivers its own,
    /// so these are dropped, and this Mac's key is fine.
    @Test func aMismatchForAnotherMacsEventsDropsThem() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (sink, auth) = sink(store, server)
        let stale = event(serial: "OTHER")
        server.rejectEvent(stale.eventID, error: mismatch, code: "device_mismatch")

        let response = try await sink.send([stale])
        #expect(response.rejected.map(\.eventID) == [stale.eventID])
        #expect(response.rejected.first?.code == "device_mismatch")
        let id = try #require(await auth.deviceID)

        #expect(try await sink.send([event()]).accepted.count == 1)
        #expect(server.enrollments.count == 1)
        #expect(await auth.deviceID == id)
        #expect(logged.withLock { $0 }.isEmpty)
    }

    @Test func aMixedBatchDropsStaleEventsAndKeepsOwn() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (sink, auth) = sink(store, server)
        _ = try await sink.send([])  // enrols, so the sink knows the ID it signs with
        let firstID = try #require(await auth.deviceID)

        let own = event()
        let stale = event(serial: "OTHER")
        server.rejectEvent(own.eventID, error: mismatch, code: "device_mismatch")
        server.rejectEvent(stale.eventID, error: mismatch, code: "device_mismatch")

        let response = try await sink.send([own, stale])
        #expect(response.rejected.map(\.eventID) == [stale.eventID])
        #expect(server.enrollments.count == 1)
        #expect(await auth.deviceID == nil)

        let retry = try await sink.send([own])
        #expect(retry.accepted == [own.eventID])
        #expect(retry.rejected.isEmpty)
        #expect(server.enrollments.count == 2)
        #expect(await auth.deviceID != firstID)
    }

    /// A rejection that names no code is about the event itself, whoever sent it.
    @Test func aRejectionWithoutTheCodeKeepsTheKeyAndDropsTheEvent() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (sink, auth) = sink(store, server)
        let bad = event()
        server.rejectEvent(bad.eventID, error: "schema_version must be 1")

        let response = try await sink.send([bad])
        #expect(response.rejected.map(\.eventID) == [bad.eventID])
        #expect(response.rejected.first?.code == nil)
        #expect(await auth.deviceID != nil)
        #expect(server.enrollments.count == 1)
    }

    /// A Mac that won't say which it is can't tell its own events from another's, so it
    /// neither keeps them nor throws its key away.
    @Test func anUnreadableIdentityTakesNoMismatchAsItsOwn() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        var unreadable = testDevice
        unreadable.serial = DeviceIdentity.unreadable
        let (sink, auth) = sink(store, server, device: unreadable)
        var e = sampleEvent()
        e.device = unreadable
        server.rejectEvent(e.eventID, error: mismatch, code: "device_mismatch")

        let response = try await sink.send([e])
        #expect(response.rejected.map(\.eventID) == [e.eventID])
        #expect(await auth.deviceID != nil)
        #expect(server.enrollments.count == 1)
        #expect(logged.withLock { $0 }.isEmpty)
    }

    @Test func discardingAnIDThatIsNotStoredKeepsTheCredential() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (sink, auth) = sink(store, server)
        _ = try await sink.send([])
        let id = try #require(await auth.deviceID)

        // Another process sharing the store has already replaced the key that was signed with.
        try await auth.discardCredential(ifDeviceID: "not-this-one")
        #expect(await auth.deviceID == id)
        #expect(logged.withLock { $0 }.isEmpty)

        try await auth.discardCredential(ifDeviceID: id)
        #expect(await auth.deviceID == nil)
        #expect(await auth.keyStorage == nil)
    }
}
