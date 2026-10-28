import CryptoKit
import Foundation
import Testing
import os

@testable import AltiwardCore

/// A stand-in for the API's enrollment and signature checks. It verifies real
/// signatures, so the tests prove the agent signs what the backend expects. Its rotate
/// handler follows the server's: a retry is answered first, then the key's status, the
/// 24-hour limit and the key's uniqueness. A key that rotation replaced and that signs
/// anything else counts in ``staleKeyUses`` (and revokes the key that replaced it), unless
/// the request was signed before the rotation and arrives within a minute of it.
final class FakeServer: HTTPTransport, Sendable {
    struct Request: Sendable {
        let method: String
        let path: String
        var query: String? = nil
        let headers: [String: String]
        let body: Data
        var timeout: TimeInterval = 0

        /// The device ID that signed it, if it is signed.
        var deviceID: String? {
            headers["Authorization"].flatMap {
                $0.hasPrefix("AltiwardDevice ") ? String($0.dropFirst("AltiwardDevice ".count)) : nil
            }
        }
        var isRotate: Bool { path == "/v1/agent/rotate" }
        /// A rotate request's new public key, base64.
        var rotatedKey: String? {
            (try? JSONSerialization.jsonObject(with: body) as? [String: String])?["public_key"]
        }
    }

    /// An answer the rotate path gives instead of handling the request.
    struct Answer: Sendable {
        let status: Int
        let headers: [String: String]
        let body: Data
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
        var serverOffset: TimeInterval
        var keyStorage: [String: String] = [:]  // device ID → key_storage it enrolled or rotated with
        var activatedAt: [String: Date] = [:]
        var successor: [String: String] = [:]  // device ID → the device ID that replaced it
        var rotationSignedAt: [String: Int64] = [:]  // new device ID → the rotate request's timestamp
        var staleKeyUses = 0
        var dropNextRotateResponse: (any Error & Sendable)?
        var rotateAnswers: [(answer: Answer, times: Int)] = []
        var rotateFailures: [(error: any Error & Sendable, times: Int)] = []
    }

    let clock: TestClock
    private let state: OSAllocatedUnfairLock<State>

    init(clock: TestClock, serverOffset: TimeInterval = 0) {
        self.clock = clock
        state = OSAllocatedUnfairLock(initialState: State(serverOffset: serverOffset))
    }

    /// Requests that reached the server, in the order they arrived.
    var requests: [Request] { state.withLock { $0.requests } }
    var enrollments: [Request] { requests.filter { $0.path == "/v1/agent/enroll" } }
    var rotations: [Request] { requests.filter(\.isRotate) }
    /// Every rotation the server made: the device ID replaced → the one that replaced it.
    var successors: [String: String] { state.withLock { $0.successor } }
    /// Requests signed by a replaced key that the server took for a second holder of it.
    var staleKeyUses: Int { state.withLock { $0.staleKeyUses } }
    func isRevoked(_ id: String) -> Bool { state.withLock { $0.revoked.contains(id) } }
    func setServerOffset(_ offset: TimeInterval) { state.withLock { $0.serverOffset = offset } }
    func setEnrollStatus(_ s: String) { state.withLock { $0.enrollStatus = s } }
    /// Answers every enrolment with `status` and `headers` until ``acceptEnrollments()``.
    func refuseEnrollments(status: Int, headers: [String: String] = [:]) {
        state.withLock { $0.enrollRefusal = (status, headers) }
    }
    func acceptEnrollments() { state.withLock { $0.enrollRefusal = nil } }
    func dropNextEnrollResponse() { state.withLock { $0.dropNextEnrollResponse = true } }
    func revoke(_ id: String) { state.withLock { _ = $0.revoked.insert(id) } }
    func approve(_ id: String) {
        let now = clock.now
        state.withLock { s in
            if s.pending.remove(id) != nil { s.activatedAt[id] = now.addingTimeInterval(s.serverOffset) }
        }
    }
    func queueCommand(_ c: AgentCommand) { state.withLock { $0.commands.append(c) } }
    func failResults(times: Int) { state.withLock { $0.failResults = times } }
    /// Rejects the event with this ID the next time it is posted; any other event is accepted.
    func rejectEvent(_ id: String, error: String, code: String? = nil) {
        state.withLock { $0.eventRejections[id] = IngestResponse.Rejection(eventID: id, error: error, code: code) }
    }
    var results: [String: CommandResult] { state.withLock { $0.results } }

    /// The next rotate request the server handles successfully is committed, and then the
    /// answer is lost: the agent gets `error` instead.
    func dropNextRotateResponse(_ error: any Error & Sendable = Dropped()) {
        state.withLock { $0.dropNextRotateResponse = error }
    }

    /// The next `times` rotate requests arrive but get this answer instead of being handled,
    /// as from a proxy, a captive portal, a server without rotation or one that is failing.
    func answerRotate(
        status: Int, code: String? = nil, retryAfter: Int? = nil, body: Data? = nil, times: Int = .max
    ) {
        let answer = Answer(
            status: status, headers: retryAfter.map { ["Retry-After": String($0)] } ?? [:],
            body: body ?? Data(#"{"error":"no"\#(code.map { #","code":"\#($0)""# } ?? "")}"#.utf8))
        state.withLock { $0.rotateAnswers.append((answer, times)) }
    }

    /// Handles rotate requests again, after ``answerRotate(status:code:retryAfter:body:times:)``.
    func stopAnsweringRotate() { state.withLock { $0.rotateAnswers = [] } }

    /// The next `times` rotate requests fail with `error` before they reach the server.
    func failRotate(_ error: any Error & Sendable, times: Int = 1) {
        state.withLock { $0.rotateFailures.append((error, times)) }
    }

    struct Dropped: Error {}

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let url = try #require(request.url)
        let r = Request(
            method: request.httpMethod ?? "GET", path: url.path, query: url.query(percentEncoded: true),
            headers: request.allHTTPHeaderFields ?? [:], body: request.httpBody ?? Data(),
            timeout: request.timeoutInterval)
        let (status, headers, body) = try state.withLock { s -> (Int, [String: String], Data) in
            if r.isRotate, !s.rotateFailures.isEmpty {
                let error = s.rotateFailures[0].error
                s.rotateFailures[0].times -= 1
                if s.rotateFailures[0].times == 0 { s.rotateFailures.removeFirst() }
                throw error
            }
            s.requests.append(r)
            if r.isRotate, !s.rotateAnswers.isEmpty {
                let answer = s.rotateAnswers[0].answer
                s.rotateAnswers[0].times -= 1
                if s.rotateAnswers[0].times == 0 { s.rotateAnswers.removeFirst() }
                return (answer.status, answer.headers, answer.body)
            }
            let answer = try handle(r, &s)
            if r.isRotate, (200..<300).contains(answer.0), let error = s.dropNextRotateResponse {
                s.dropNextRotateResponse = nil
                throw error
            }
            return answer
        }
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        return (body, response)
    }

    private func handle(_ r: Request, _ s: inout State) throws -> (Int, [String: String], Data) {
        let serverNow = clock.now.addingTimeInterval(s.serverOffset)
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
            s.keyStorage[id] = body["key_storage"]
            if s.enrollStatus == "pending" { s.pending.insert(id) } else { s.activatedAt[id] = s.activatedAt[id] ?? serverNow }
            if s.dropNextEnrollResponse {
                s.dropNextEnrollResponse = false
                throw Dropped()
            }
            return (201, [:], Data(#"{"device_id":"\#(id)","status":"\#(s.enrollStatus)"}"#.utf8))
        }

        func coded(_ status: Int, _ code: String, _ headers: [String: String] = [:]) -> (Int, [String: String], Data) {
            (status, headers, Data(#"{"error":"no","code":"\#(code)"}"#.utf8))
        }
        guard let id = r.deviceID,
            let ts = r.headers["X-Altiward-Timestamp"].flatMap(Int64.init),
            let sig = r.headers["X-Altiward-Signature"].flatMap({ Data(base64Encoded: $0) })
        else { return coded(401, "credential_invalid") }
        let canonical = RequestSigning.canonicalString(
            method: r.method, pathAndQuery: r.path + (r.query.map { "?" + $0 } ?? ""), timestamp: ts, body: r.body)
        guard let key = s.keys[id],
            key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: sig), for: Data(canonical.utf8))
        else { return coded(401, "credential_invalid") }
        if abs(Double(ts) - serverNow.timeIntervalSince1970) > 300 {
            return coded(401, "clock_skew", ["Date": httpDate(serverNow)])
        }
        if r.method == "POST", r.isRotate { return rotate(r, id: id, key: key, signedAt: ts, serverNow, &s) }
        if s.revoked.contains(id) {
            staleUse(id, signedAt: ts, serverNow, inFlightExempt: true, &s)
            return coded(401, "credential_invalid")
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
        return (404, [:], Data(#"{"error":"not found"}"#.utf8))
    }

    /// The server's rotate handler, for a request whose signature and clock checked out.
    private func rotate(
        _ r: Request, id: String, key: P256.Signing.PublicKey, signedAt: Int64, _ serverNow: Date, _ s: inout State
    ) -> (Int, [String: String], Data) {
        func coded(_ status: Int, _ code: String, _ headers: [String: String] = [:]) -> (Int, [String: String], Data) {
            (status, headers, Data(#"{"error":"no","code":"\#(code)"}"#.utf8))
        }
        func answer(_ status: Int, _ deviceID: String, _ state: String) -> (Int, [String: String], Data) {
            (status, [:], Data(#"{"device_id":"\#(deviceID)","status":"\#(state)"}"#.utf8))
        }
        struct Body: Decodable {
            let public_key: String?
            let key_storage: String?
            let proof: String?
        }
        let body = try? JSONDecoder().decode(Body.self, from: r.body)
        var newKey: P256.Signing.PublicKey?
        if let der = body?.public_key.flatMap({ Data(base64Encoded: $0) }),
            let candidate = try? P256.Signing.PublicKey(derRepresentation: der),
            candidate.derRepresentation != key.derRepresentation,
            let proof = body?.proof.flatMap({ Data(base64Encoded: $0) }).flatMap({ try? P256.Signing.ECDSASignature(derRepresentation: $0) }),
            candidate.isValidSignature(proof, for: Data(RotationProof.statement(deviceID: id, newPublicKey: der).utf8))
        {
            newKey = candidate
        }
        guard let newKey else {
            if s.revoked.contains(id) {
                staleUse(id, signedAt: signedAt, serverNow, inFlightExempt: false, &s)
                return coded(401, "credential_invalid")
            }
            return coded(400, "rotation_invalid")
        }
        if s.revoked.contains(id) {
            if let next = s.successor[id], s.keys[next]?.derRepresentation == newKey.derRepresentation {
                // A retry: the rotation it asks for has happened.
                return answer(200, next, s.revoked.contains(next) ? "revoked" : s.pending.contains(next) ? "pending" : "active")
            }
            staleUse(id, signedAt: signedAt, serverNow, inFlightExempt: false, &s)
            return coded(401, "credential_invalid")
        }
        if s.pending.contains(id) { return coded(403, "enrollment_pending") }
        if s.keyStorage[id] == "secure_enclave" { return coded(409, "rotation_not_allowed") }
        if let activated = s.activatedAt[id], serverNow < activated.addingTimeInterval(86400) {
            let left = Int(activated.addingTimeInterval(86400).timeIntervalSince(serverNow).rounded(.up))
            return coded(429, "rotation_rate_limited", ["Retry-After": String(max(1, left))])
        }
        if s.keys.values.contains(where: { $0.derRepresentation == newKey.derRepresentation }) {
            return coded(409, "key_in_use")
        }
        let next = UUID().uuidString.lowercased()
        s.revoked.insert(id)
        s.keys[next] = newKey
        s.keyStorage[next] = body?.key_storage
        s.activatedAt[next] = serverNow
        s.rotationSignedAt[next] = signedAt
        s.successor[id] = next
        return answer(201, next, "active")
    }

    /// A request signed by revoked key `id`. If rotation replaced the key, this is a second
    /// holder of it, unless (for anything but rotate) it was signed no later than the
    /// rotation and arrives within a minute of it. A second holder revokes the lineage's
    /// active key, if the key was replaced within 30 days.
    private func staleUse(_ id: String, signedAt: Int64, _ serverNow: Date, inFlightExempt: Bool, _ s: inout State) {
        guard let next = s.successor[id] else { return }
        if inFlightExempt, let rotationSigned = s.rotationSignedAt[next], let activated = s.activatedAt[next],
            signedAt <= rotationSigned, serverNow <= activated.addingTimeInterval(60)
        {
            return
        }
        s.staleKeyUses += 1
        var active = next
        while let later = s.successor[active] { active = later }
        if let activated = s.activatedAt[next], serverNow < activated.addingTimeInterval(30 * 86400) {
            s.revoked.insert(active)
        }
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
        var madeCount = 0
        var dead: Set<Data> = []
        var beforeMake: (@Sendable () throws -> Void)?
    }

    struct Failed: Error {}
    static let prefix = Data("SE:".utf8)
    private let state = OSAllocatedUnfairLock(initialState: State())

    init(secureEnclave: Bool = true) { state.withLock { $0.available = secureEnclave } }

    var secureEnclaveAvailable: Bool { state.withLock { $0.available } }
    /// How many keys of either kind it has made.
    var madeCount: Int { state.withLock { $0.madeCount } }
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
        guard storage == .secureEnclave else {
            state.withLock { $0.madeCount += 1 }
            return raw
        }
        return try state.withLock { s in
            guard s.available, !s.failCreate, !s.busy else { throw Failed() }
            let key = Self.prefix + raw
            s.made.append(key)
            s.madeCount += 1
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

    /// The console's shortFingerprint gives the same for both keys (format.test.ts).
    @Test func keyFingerprintMatchesTheConsole() throws {
        let v = try SignatureVector.load()
        #expect(DeviceAuthenticator.fingerprint(publicKey: Data(base64Encoded: v.publicKeySPKI)!) == "1A93 E3D5 98CC 0F43")
        #expect(DeviceAuthenticator.fingerprint(publicKey: Data("abc".utf8)) == "BA78 16BF 8F01 CFEA")
    }
}

struct DeviceAuthenticatorTests {
    let clock = TestClock()
    let serverURL = URL(string: "https://api.altiward.test")!
    let keys = FakeKeys()

    func authenticator(
        _ store: AgentStore, _ server: FakeServer, url: URL? = nil, keys: FakeKeys? = nil,
        role: DeviceAuthenticator.Role = .daemon, device: DeviceInfo = testDevice,
        mdmDeviceID: String? = nil, transport: (any HTTPTransport)? = nil,
        log: @escaping @Sendable (String) -> Void = { _ in }
    ) -> DeviceAuthenticator {
        DeviceAuthenticator(
            store: store, serverURL: url ?? serverURL, enrollmentToken: "enroll-token-0001", mdmDeviceID: mdmDeviceID,
            device: { device }, transport: transport ?? server, keys: keys ?? self.keys, role: role, now: { clock.now }, log: log)
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
        let (_, response, _) = try await auth.send(method: "POST", path: "v1/agent/events", body: Data(#"{"events":[]}"#.utf8))
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

    /// `status` shows the key's fingerprint as the console does, read from the store, so a
    /// command shows a Secure Enclave key's without asking the Secure Enclave.
    @Test func theKeyFingerprintIsReadFromTheStore() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let daemon = authenticator(store, server)
        #expect(try await postEvents(daemon) == 200)
        let enrollment = try #require(server.enrollments.first)
        let enrolled = try #require(Data(base64Encoded: try enrolledKey(enrollment)))
        let fingerprint = DeviceAuthenticator.fingerprint(publicKey: enrolled)
        #expect(await daemon.keyStorage == .secureEnclave)
        #expect(await daemon.keyFingerprint == fingerprint)

        let unusable = FakeKeys()
        unusable.busy(true)
        #expect(await authenticator(store, server, keys: unusable, role: .command).keyFingerprint == fingerprint)
    }

    /// Replaces a stored record with one as agent 0.9 wrote it, without the public key.
    func dropRecordedPublicKey(_ store: AgentStore, _ key: String) throws {
        var record = try JSONSerialization.jsonObject(
            with: Data(try #require(try store.value(forKey: key)).utf8)) as! [String: Any]
        #expect(record.removeValue(forKey: "publicKey") != nil)
        try store.setValue(String(decoding: try JSONSerialization.data(withJSONObject: record), as: UTF8.self), forKey: key)
    }

    /// A Secure Enclave record from before agent 1.0.0 has no public key in it: the daemon
    /// adds it the next time it signs a request.
    @Test func theDaemonRecordsAnOldRecordsPublicKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let daemon = authenticator(store, server)
        #expect(try await postEvents(daemon) == 200)
        let fingerprint = try #require(await daemon.keyFingerprint)
        try dropRecordedPublicKey(store, "device_credential_se")
        #expect(await daemon.keyFingerprint == nil)

        #expect(try await postEvents(daemon) == 200)
        #expect(await authenticator(store, server, role: .command).keyFingerprint == fingerprint)
    }

    /// A file key's fingerprint comes from the key itself when the record has no public key.
    @Test func aFileKeysFingerprintNeedsNoRecordedPublicKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let noEnclave = FakeKeys(secureEnclave: false)
        #expect(try await postEvents(authenticator(store, server, keys: noEnclave)) == 200)
        let enrollment = try #require(server.enrollments.first)
        let enrolled = try #require(Data(base64Encoded: try enrolledKey(enrollment)))
        try dropRecordedPublicKey(store, "device_credential")
        #expect(
            await authenticator(store, server, keys: noEnclave, role: .command).keyFingerprint
                == DeviceAuthenticator.fingerprint(publicKey: enrolled))
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

    /// Intune's ID for the Mac goes to the server once, in the enrol body.
    @Test func enrolSendsTheMDMDeviceID() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let id = "77e8b11e-8a43-4e15-938a-0af400040863"
        #expect(try await postEvents(authenticator(store, server, mdmDeviceID: id)) == 200)
        let body = try JSONSerialization.jsonObject(with: #require(server.enrollments.first).body) as! [String: String]
        #expect(body["mdm_device_id"] == id)
    }

    @Test func enrolLeavesOutAMissingMDMDeviceID() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(store, server)) == 200)
        let body = try JSONSerialization.jsonObject(with: #require(server.enrollments.first).body) as! [String: String]
        #expect(body["mdm_device_id"] == nil)
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

    @Test func anEnrolledFileKeyStaysUntilItRotates() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(store, server, keys: FakeKeys(secureEnclave: false))) == 200)

        // Upgraded on a Mac with a Secure Enclave: it keeps signing with the file key.
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        #expect(server.enrollments.count == 1)
        #expect(await auth.keyStorage == .software)

        // Until it rotates, without enrolling again.
        clock.advance(86400)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.rotate(reason: "move into the Secure Enclave") == .rotated(.secureEnclave))
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.keyStorage == .secureEnclave)
        #expect(server.enrollments.count == 1)
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

    /// The real Secure Enclave, on Macs that have one. CI's `macos-latest` runners have one
    /// (as a user session, not as the daemon), and CI sets ALTIWARD_REQUIRE_SECURE_ENCLAVE
    /// so that these fail there rather than skip.
    @Test(.enabled(if: SecureEnclave.isAvailable || requireSecureEnclave))
    func signsWithTheRealSecureEnclave() async throws {
        try #require(SecureEnclave.isAvailable, "ALTIWARD_REQUIRE_SECURE_ENCLAVE is set, but this Mac has no Secure Enclave")
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

// MARK: Rotating the key

/// Rotation. Unless a test says otherwise, each one checks that the server saw no second
/// holder of a replaced key (`staleKeyUses`), and that nothing but the rotate request was
/// signed with the old key once rotation began.
extension DeviceAuthenticatorTests {
    /// The credential as agent 0.9 reads it.
    struct V09Credential: Decodable {
        var serverURL: String
        var privateKey: Data
        var deviceID: String?
        var serial: String?
        var hardwareUUID: String?
    }

    /// What agent 0.9's `load()` returns: the Secure Enclave record's credential for the
    /// server, else the file record's.
    func loadAsAgent09(_ store: AgentStore) throws -> V09Credential? {
        for key in ["device_credential_se", "device_credential"] {
            if let json = try store.value(forKey: key) {
                let c = try JSONDecoder().decode(V09Credential.self, from: Data(json.utf8))
                if c.serverURL == serverURL.absoluteString { return c }
            }
        }
        return nil
    }

    func nextRecord(_ store: AgentStore) throws -> PendingRotation? {
        try store.value(forKey: "device_credential_next").map {
            try JSONDecoder().decode(PendingRotation.self, from: Data($0.utf8))
        }
    }

    /// A Mac that enrolled a file key `age` ago, then started (on the Mac `keys` describes)
    /// and has signed a request since, so it may rotate. Returns it and the file key's ID.
    func readyToRotate(
        _ store: AgentStore, _ server: FakeServer, keys: FakeKeys? = nil, age: TimeInterval = 86400,
        mdmDeviceID: String? = nil, transport: (any HTTPTransport)? = nil,
        log: @escaping @Sendable (String) -> Void = { _ in }
    ) async throws -> (DeviceAuthenticator, String) {
        let first = authenticator(store, server, keys: FakeKeys(secureEnclave: false), mdmDeviceID: mdmDeviceID)
        #expect(try await postEvents(first) == 200)
        let id = try #require(await first.deviceID)
        clock.advance(age)
        let auth = authenticator(store, server, keys: keys, mdmDeviceID: mdmDeviceID, transport: transport, log: log)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.lastSignedSuccess?.deviceID == id)
        return (auth, id)
    }

    /// Requests other than rotate that arrived signed by `id`, after the first `start`.
    func oldKeyRequests(_ server: FakeServer, _ id: String, after start: Int) -> [FakeServer.Request] {
        server.requests.dropFirst(start).filter { $0.deviceID == id && !$0.isRotate }
    }

    /// Saves a next record as the daemon does just before it sends the rotate request.
    func saveNextRecord(
        _ store: AgentStore, from id: String, fromKey: Data? = nil, url: URL? = nil, mac: DeviceInfo = testDevice
    ) throws -> PendingRotation {
        let fromKey = try fromKey ?? #require(try storedIdentity(store, "device_credential")).privateKey
        let pending = PendingRotation(
            serverURL: (url ?? serverURL).absoluteString, fromDeviceID: id, fromPrivateKey: fromKey,
            serial: mac.serial, hardwareUUID: mac.hardwareUUID, privateKey: try keys.makeKey(.secureEnclave),
            storage: .secureEnclave, madeAt: clock.now)
        try store.setValue(
            String(decoding: try JSONEncoder().encode(pending), as: UTF8.self), forKey: "device_credential_next")
        return pending
    }

    func logLines() -> (OSAllocatedUnfairLock<[String]>, @Sendable (String) -> Void) {
        let logged = OSAllocatedUnfairLock(initialState: [String]())
        return (logged, { line in logged.withLock { $0.append(line) } })
    }

    @Test(.timeLimit(.minutes(1))) func aFileKeyRotatesIntoTheSecureEnclave() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (logged, log) = logLines()
        let (auth, oldID) = try await readyToRotate(store, server, log: log)
        let start = server.requests.count

        #expect(await auth.rotate(reason: "move into the Secure Enclave") == .rotated(.secureEnclave))
        let newID = try #require(server.successors[oldID])
        #expect(try store.value(forKey: "device_credential") == nil)
        #expect(try store.value(forKey: "device_credential_next") == nil)
        #expect(logged.withLock { $0 }.contains("rotated this Mac's key into the Secure Enclave"))

        // Agent 0.9 reads the new record, so a downgrade keeps the new key.
        let json = try #require(try store.value(forKey: "device_credential_se"))
        let saved = try JSONDecoder().decode(V09Credential.self, from: Data(json.utf8))
        #expect(saved.deviceID == newID)
        #expect(saved.serverURL == serverURL.absoluteString)
        #expect(saved.serial == testDevice.serial)
        #expect(saved.hardwareUUID == testDevice.hardwareUUID)
        #expect(try loadAsAgent09(store)?.deviceID == newID)
        let rotation = try #require(server.rotations.first)
        #expect(rotation.rotatedKey == (try keys.publicKey(saved.privateKey, .secureEnclave).base64EncodedString()))
        let rotatedKey = try #require(rotation.rotatedKey.flatMap { Data(base64Encoded: $0) })
        #expect(await auth.keyFingerprint == DeviceAuthenticator.fingerprint(publicKey: rotatedKey))

        #expect(try await postEvents(auth) == 200)
        #expect(server.requests.last?.deviceID == newID)
        #expect(await auth.keyStorage == .secureEnclave)
        #expect(server.enrollments.count == 1)
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    /// The MDM's ID is for enrolling only: a rotation names the Mac by its signature.
    @Test(.timeLimit(.minutes(1))) func rotateNeverSendsTheMDMDeviceID() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, _) = try await readyToRotate(store, server, mdmDeviceID: "ABC")
        #expect(await auth.rotate(reason: "move into the Secure Enclave") == .rotated(.secureEnclave))
        let rotation = try #require(server.requests.last { $0.isRotate })
        #expect(!String(decoding: rotation.body, as: UTF8.self).contains("mdm_device_id"))
    }

    @Test(.timeLimit(.minutes(1))) func aLostResponseSendsNoOldKeyRequest() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        let delivery = DeliveryLoop(store: store, sink: HTTPEventSink(authenticator: auth), now: { clock.now })
        let start = server.requests.count

        server.dropNextRotateResponse()
        #expect(await auth.rotate(reason: "test") == .unknown)
        #expect(try nextRecord(store) != nil)
        server.answerRotate(status: 503, times: 1)
        server.failRotate(URLError(.timedOut))

        // Three batches queue while the answer is unknown; each delivery retries the rotation.
        var ids: [String] = []
        for wait in [15.0, 15, 30] {
            let event = sampleEvent(at: clock.now)
            ids.append(event.eventID)
            try store.enqueue(event, now: clock.now)
            clock.advance(wait)
            let result = await delivery.flush()
            #expect(result.delivered == (ids.count == 3 ? 3 : 0))
        }
        #expect(try store.pendingCount() == 0)

        let newID = try #require(server.successors[oldID])
        #expect(server.successors.count == 1)
        #expect(server.rotations.count == 3)
        #expect(Set(server.rotations.map(\.rotatedKey)).count == 1)
        let posted = server.requests.filter { $0.path == "/v1/agent/events" && $0.deviceID == newID }
        #expect(posted.count == 1)
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    /// The daemon stopped after saving the next record and before sending it.
    @Test(.timeLimit(.minutes(1))) func aRotationSavedButNotSentFinishesWithTheSameKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (_, oldID) = try await readyToRotate(store, server)
        let pending = try saveNextRecord(store, from: oldID)
        let start = server.requests.count

        let restarted = authenticator(store, server)
        #expect(try await postEvents(restarted) == 200)
        let rotation = try #require(server.rotations.first)
        #expect(server.rotations.count == 1)
        #expect(rotation.rotatedKey == (try keys.publicKey(pending.privateKey, .secureEnclave).base64EncodedString()))
        #expect(try nextRecord(store) == nil)
        let newID = try #require(server.successors[oldID])
        #expect(await restarted.deviceID == newID)
        #expect(server.requests.last?.deviceID == newID)
        #expect(server.enrollments.count == 1)
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    @Test(.timeLimit(.minutes(1))) func aRotationInterruptedByARestartFinishesLater() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        let start = server.requests.count
        server.dropNextRotateResponse()
        #expect(await auth.rotate(reason: "test") == .unknown)
        let newID = try #require(server.successors[oldID])

        clock.advance(10 * 86400)
        let restarted = authenticator(store, server)
        #expect(try await postEvents(restarted) == 200)
        #expect(await restarted.deviceID == newID)
        #expect(server.requests.last?.deviceID == newID)
        #expect(server.rotations.count == 2)
        #expect(server.successors.count == 1)
        #expect(server.enrollments.count == 1)
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    @Test(.timeLimit(.minutes(1))) func aRefusedRotationEnrollsAgainOnce() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        server.revoke(oldID)

        #expect(await auth.rotate(reason: "test") == .enrolAgain)
        #expect(try nextRecord(store) == nil)
        #expect(try store.value(forKey: "device_credential") == nil)
        #expect(try await postEvents(auth) == 200)
        #expect(try await postEvents(auth) == 200)
        try #require(server.enrollments.count == 2)
        #expect(try enrolledStorage(server.enrollments[1]) == "secure_enclave")
        #expect(server.staleKeyUses == 0)
    }

    @Test(.timeLimit(.minutes(1))) func aServerWithoutRotationKeepsTheKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (logged, log) = logLines()
        let (auth, oldID) = try await readyToRotate(store, server, log: log)
        server.answerRotate(status: 404, body: Data("404 page not found\n".utf8))

        #expect(await auth.rotate(reason: "test") == .deferred(until: clock.now.addingTimeInterval(86400)))
        #expect(try nextRecord(store) == nil)
        #expect(logged.withLock { $0 }.contains("the server does not support key rotation yet; keeping the current key"))
        #expect(try await postEvents(auth) == 200)
        #expect(server.requests.last?.deviceID == oldID)
        #expect(await auth.keyStorage == .software)
        #expect(server.staleKeyUses == 0)
    }

    @Test(.timeLimit(.minutes(1))) func aRateLimitedRotationDropsTheNextKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server, age: 3600)

        // The server's limit: a key rotates at most once a day.
        #expect(await auth.rotate(reason: "test") == .deferred(until: clock.now.addingTimeInterval(82800)))
        #expect(server.rotations.count == 1)
        #expect(try nextRecord(store) == nil)
        #expect(try await postEvents(auth) == 200)
        #expect(server.requests.last?.deviceID == oldID)
        #expect(server.staleKeyUses == 0)
    }

    @Test(.timeLimit(.minutes(1))) func aSecureEnclaveFailureKeepsTheFileKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)

        keys.failCreate(true)
        for failures in 1...3 {
            #expect(await auth.rotate(reason: "test") == .deferred(until: clock.now.addingTimeInterval(86400)))
            #expect(await auth.secureEnclaveFailures == failures)
        }
        #expect(server.rotations.isEmpty)
        #expect(try nextRecord(store) == nil)
        #expect(try await postEvents(auth) == 200)
        #expect(server.requests.last?.deviceID == oldID)
        #expect(await auth.keyStorage == .software)

        // After three in a row the Mac counts as having no Secure Enclave: a new file key.
        #expect(await auth.rotate(reason: "test") == .rotated(.software))
        #expect(server.staleKeyUses == 0)

        // A Secure Enclave rotation that works starts the count again.
        let other = try makeStore()
        let (again, _) = try await readyToRotate(other, server)
        #expect(await again.rotate(reason: "test") == .deferred(until: clock.now.addingTimeInterval(86400)))
        keys.failCreate(false)
        #expect(await again.rotate(reason: "test") == .rotated(.secureEnclave))
        #expect(await again.secureEnclaveFailures == 0)
    }

    @Test(.timeLimit(.minutes(1)), arguments: [true, false])
    func aCommandLeavesARotatingKeyAlone(_ secureEnclave: Bool) async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let mac = FakeKeys(secureEnclave: secureEnclave)
        let (auth, oldID) = try await readyToRotate(store, server, keys: mac)
        server.dropNextRotateResponse()
        #expect(await auth.rotate(reason: "test") == .unknown)
        let pending = try #require(try nextRecord(store))
        let records = try ["device_credential", "device_credential_se", "device_credential_next"].map(store.value)
        let arrived = server.requests.count

        let command = authenticator(store, server, keys: mac, role: .command)
        let refusal = DeviceKeyError.rotationInProgress(since: pending.madeAt)
        await #expect(throws: refusal) { try await postEvents(command) }
        await #expect(throws: refusal) { try await command.discardCredential(ifDeviceID: oldID) }
        #expect(await command.rotate(reason: "test") == .notDue)
        #expect(await command.rotationPendingSince == pending.madeAt)
        #expect(server.requests.count == arrived)
        #expect(try ["device_credential", "device_credential_se", "device_credential_next"].map(store.value) == records)

        // The daemon finishes it.
        clock.advance(15)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == server.successors[oldID])
        #expect(server.enrollments.count == 1)
        #expect(server.staleKeyUses == 0)
    }

    @Test(.timeLimit(.minutes(1))) func nothingIsInFlightAtTheRotateRequest() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let transport = HoldingTransport(server: server, holding: false)
        let (auth, oldID) = try await readyToRotate(store, server, transport: transport)
        let sentBefore = transport.sent.count
        let start = server.requests.count

        transport.setHolding(true)
        let longPoll = Task {
            try await auth.send(method: "GET", path: "v1/agent/commands?wait=50", body: Data(), timeout: 70).1.statusCode
        }
        let first = Task { try await postEvents(auth) }
        let second = Task { try await postEvents(auth) }
        try await transport.waitUntilSent(sentBefore + 3)

        let rotation = Task { await auth.rotate(reason: "test") }
        try await Task.sleep(for: .milliseconds(200))
        #expect(transport.sent.count == sentBefore + 3)  // the rotation waits for them

        transport.releaseAll()
        try await transport.waitUntilSent(sentBefore + 4)
        #expect(transport.sent.last?.path == "/v1/agent/rotate")
        let fourth = Task { try await postEvents(auth) }
        try await Task.sleep(for: .milliseconds(200))
        #expect(transport.sent.count == sentBefore + 4)  // held back until the rotation settles

        transport.setHolding(false)
        #expect(await rotation.value == .rotated(.secureEnclave))
        for task in [longPoll, first, second, fourth] { #expect(try await task.value == 200) }

        let newID = try #require(server.successors[oldID])
        let arrival = try #require(transport.arrivals.first { $0.path == "/v1/agent/rotate" })
        #expect(arrival.othersInFlight == 0)
        let afterRotate = transport.sent.drop { $0.path != "/v1/agent/rotate" }.dropFirst()
        #expect(afterRotate.count == 1)
        #expect(afterRotate.allSatisfy { $0.deviceID == newID })
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).count == 3)  // the three sent before it
    }

    @Test(.timeLimit(.minutes(1))) func aClockSkewedRetryCorrectsItsClock() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        let start = server.requests.count
        server.dropNextRotateResponse()
        #expect(await auth.rotate(reason: "test") == .unknown)

        // Restarted, with the Mac's clock now 10 minutes slow.
        server.setServerOffset(600)
        let restarted = authenticator(store, server)
        #expect(try await postEvents(restarted) == 200)
        let rotations = server.rotations
        #expect(rotations.count == 3)
        #expect(rotations.last?.headers["X-Altiward-Timestamp"] == String(Int64(clock.now.timeIntervalSince1970) + 600))
        #expect(try store.value(forKey: "server_clock_offset").flatMap(Double.init) == 600)
        #expect(await restarted.deviceID == server.successors[oldID])
        #expect(server.enrollments.count == 1)
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    @Test(.timeLimit(.minutes(1))) func aRefusedRotationRequestDropsTheNextKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)

        server.answerRotate(status: 400, code: "rotation_invalid", times: 1)
        #expect(await auth.rotate(reason: "test") == .deferred(until: clock.now.addingTimeInterval(86400)))
        #expect(try nextRecord(store) == nil)
        #expect(try await postEvents(auth) == 200)
        #expect(server.requests.last?.deviceID == oldID)

        clock.advance(86400)
        server.answerRotate(status: 409, code: "key_in_use", times: 1)
        #expect(await auth.rotate(reason: "test") == .deferred(until: clock.now.addingTimeInterval(86400)))
        #expect(try nextRecord(store) == nil)
        let rotations = server.rotations
        try #require(rotations.count == 2)
        #expect(rotations[0].rotatedKey != rotations[1].rotatedKey)
        #expect(try await postEvents(auth) == 200)
        #expect(server.requests.last?.deviceID == oldID)
        #expect(server.staleKeyUses == 0)
    }

    @Test(.timeLimit(.minutes(1))) func aDayOfServerErrorsHoldsWithoutTheOldKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (logged, log) = logLines()
        let (auth, oldID) = try await readyToRotate(store, server, log: log)
        let start = server.requests.count
        server.dropNextRotateResponse(URLError(.networkConnectionLost))
        #expect(await auth.rotate(reason: "test") == .unknown)
        let pending = try #require(try nextRecord(store))
        server.answerRotate(status: 503, body: Data("upstream unavailable".utf8))

        for _ in 0..<(24 * 4) {
            clock.advance(900)
            await #expect(throws: DeviceKeyError.rotationOutcomeUnknown) { try await postEvents(auth) }
            #expect(await auth.rotationPendingSince == pending.madeAt)
        }
        #expect(try nextRecord(store)?.privateKey == pending.privateKey)
        #expect(server.rotations.count == 1 + 24 * 4)
        let holding = logged.withLock { $0 }.filter { $0.hasPrefix("the rotation's outcome is not known yet") }
        #expect((24...25).contains(holding.count))  // once an hour
        // Something on the way may be what keeps the request from the server, so each says
        // what to check.
        let advice = "If this goes on, check that the whole of /v1/agent/ reaches the server"
        #expect(holding.allSatisfy { $0.contains(advice) })

        // altiward-agent status, a command, shows the last answer the daemon logged.
        let status = authenticator(store, server, role: .command)
        let last = try #require(await status.rotationLastAnswer)
        #expect(last.answer == "HTTP 503: upstream unavailable. \(advice)")
        #expect(last.at <= clock.now && clock.now.timeIntervalSince(last.at) < 3600)
        #expect(try nextRecord(store)?.sent == true)

        server.stopAnsweringRotate()
        clock.advance(900)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.rotationPendingSince == nil)
        #expect(await status.rotationLastAnswer == nil)
        let newID = try #require(server.successors[oldID])
        #expect(server.requests.last?.deviceID == newID)
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    /// The last answer a rotation waits on is shown on one line, without the control
    /// characters of whatever sent it; a hold caused on the Mac gives no network advice.
    @Test(.timeLimit(.minutes(1))) func aHeldRotationsLastAnswerIsPrintable() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (logged, log) = logLines()
        let (auth, _) = try await readyToRotate(store, server, log: log)
        server.dropNextRotateResponse()  // not a URLError: as if signing failed on the Mac
        #expect(await auth.rotate(reason: "test") == .unknown)
        #expect(logged.withLock { $0 }.allSatisfy { !$0.contains("/v1/agent/") })

        server.answerRotate(status: 502, body: Data("<h1>Bad\nGateway</h1>\u{1B}[2J\u{07}".utf8))
        clock.advance(3600)
        await #expect(throws: DeviceKeyError.rotationOutcomeUnknown) { try await postEvents(auth) }
        let last = try #require(await auth.rotationLastAnswer)
        #expect(last.answer.hasPrefix("HTTP 502: <h1>Bad Gateway</h1> [2J . If this goes on"))

        server.stopAnsweringRotate()
        server.answerRotate(status: 504, body: Data())
        clock.advance(3600)
        await #expect(throws: DeviceKeyError.rotationOutcomeUnknown) { try await postEvents(auth) }
        #expect(try #require(await auth.rotationLastAnswer).answer.hasPrefix("HTTP 504. If this goes on"))
    }

    @Test(.timeLimit(.minutes(1))) func aRotationCopiedToAnotherMacIsDropped() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        server.failRotate(URLError(.notConnectedToInternet))
        #expect(await auth.rotate(reason: "test") == .unknown)
        #expect(try nextRecord(store) != nil)
        let start = server.requests.count

        let copy = authenticator(store, server, device: mac("C02BBB", "U2"))
        #expect(try await postEvents(copy) == 200)
        #expect(server.rotations.isEmpty)
        #expect(try nextRecord(store) == nil)
        try #require(server.enrollments.count == 2)
        let body = try JSONSerialization.jsonObject(with: server.enrollments[1].body) as! [String: String]
        #expect(body["serial"] == "C02BBB")
        #expect(try storedIdentity(store, "device_credential_se")?.serial == "C02BBB")
        #expect(try store.value(forKey: "device_credential") == nil)
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    @Test(.timeLimit(.minutes(1))) func aNextRecordForAnotherCredentialIsDropped() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)

        _ = try saveNextRecord(store, from: "another-device", fromKey: P256.Signing.PrivateKey().rawRepresentation)
        #expect(try await postEvents(auth) == 200)
        #expect(try nextRecord(store) == nil)
        #expect(server.requests.last?.deviceID == oldID)

        // One for another server is dropped too.
        _ = try saveNextRecord(store, from: oldID, url: URL(string: "https://eu.altiward.test")!)
        #expect(try await postEvents(auth) == 200)
        #expect(try nextRecord(store) == nil)
        #expect(server.requests.last?.deviceID == oldID)
        #expect(server.rotations.isEmpty)
        #expect(server.staleKeyUses == 0)
    }

    /// A command's request, signed just before the daemon began rotating, is refused because
    /// the rotation has committed by the time it arrives. The command leaves the key alone,
    /// and the daemon's lost answer is retried.
    @Test(.timeLimit(.minutes(1))) func aCommandRefusalThenALostResponseStillCommits() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let mac = FakeKeys(secureEnclave: false)
        let (daemon, oldID) = try await readyToRotate(store, server, keys: mac)
        let held = HoldingTransport(server: server)
        let command = authenticator(store, server, keys: mac, role: .command, transport: held)
        let request = Task { try await postEvents(command) }
        try await held.waitUntilSent(1)

        server.dropNextRotateResponse()
        #expect(await daemon.rotate(reason: "test") == .unknown)
        let pending = try #require(try nextRecord(store))
        held.setHolding(false)
        await #expect(throws: DeviceKeyError.rotationInProgress(since: pending.madeAt)) { try await request.value }
        #expect(try storedIdentity(store, "device_credential")?.privateKey == pending.fromPrivateKey)

        clock.advance(15)
        #expect(try await postEvents(daemon) == 200)
        let newID = try #require(server.successors[oldID])
        #expect(await daemon.deviceID == newID)
        #expect(!server.isRevoked(newID))
        #expect(server.enrollments.count == 1)
        #expect(server.staleKeyUses == 0)
    }

    @Test(.timeLimit(.minutes(1))) func aPendingKeyDoesNotRotate() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        server.setEnrollStatus("pending")
        let auth = authenticator(store, server, keys: FakeKeys(secureEnclave: false))
        await #expect(throws: DeliveryError.enrollmentPending) { try await postEvents(auth) }
        clock.advance(86400)
        #expect(await auth.lastSignedSuccess == nil)
        #expect(await auth.rotate(reason: "test") == .notDue)

        // Success was recorded for a key another process has since replaced.
        server.setEnrollStatus("active")
        let replaced = try makeStore()
        let (stale, firstID) = try await readyToRotate(replaced, server)
        let other = try makeStore()
        #expect(try await postEvents(authenticator(other, server, keys: FakeKeys(secureEnclave: false))) == 200)
        try replaced.setValue(other.value(forKey: "device_credential"), forKey: "device_credential")
        #expect(await stale.lastSignedSuccess?.deviceID == firstID)
        #expect(await stale.deviceID != firstID)
        #expect(await stale.rotate(reason: "test") == .notDue)
        #expect(server.rotations.isEmpty)
        #expect(try nextRecord(store) == nil)
        #expect(try nextRecord(replaced) == nil)
    }

    @Test(.timeLimit(.minutes(1))) func aZeroNineDecoderIgnoresTheNextRecord() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        server.failRotate(URLError(.notConnectedToInternet))
        #expect(await auth.rotate(reason: "test") == .unknown)
        let pending = try #require(try nextRecord(store))

        let old = try #require(try loadAsAgent09(store))
        #expect(old.deviceID == oldID)
        #expect(old.privateKey == pending.fromPrivateKey)
    }

    @Test(.timeLimit(.minutes(1))) func aRetryWithTheNetworkDownKeepsTheNextRecord() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        let start = server.requests.count
        server.dropNextRotateResponse(URLError(.networkConnectionLost))
        #expect(await auth.rotate(reason: "test") == .unknown)
        let pending = try #require(try nextRecord(store))

        server.failRotate(URLError(.notConnectedToInternet), times: 2)
        for _ in 0..<2 {
            clock.advance(15)
            await #expect(throws: DeviceKeyError.rotationOutcomeUnknown) { try await postEvents(auth) }
            #expect(try nextRecord(store)?.privateKey == pending.privateKey)
        }
        clock.advance(15)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == server.successors[oldID])
        #expect(server.rotations.count == 2)
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    @Test(.timeLimit(.minutes(1))) func overlappingRotationsMakeOneKey() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        let made = keys.madeCount
        server.dropNextRotateResponse()

        async let afterPoll = auth.rotate(reason: "after a long poll")
        async let hourly = auth.rotate(reason: "hourly")
        let (first, second) = await (afterPoll, hourly)
        #expect(first == .unknown)
        #expect(second == first)
        #expect(keys.madeCount == made + 1)

        clock.advance(15)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == server.successors[oldID])
        #expect(Set(server.rotations.map(\.rotatedKey)).count == 1)
        #expect(server.staleKeyUses == 0)
    }

    @Test(.timeLimit(.minutes(1))) func aCommandUsesTheSharedClockOffset() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock, serverOffset: 600)  // the Mac's clock is 10 minutes slow
        let mac = FakeKeys(secureEnclave: false)
        let (daemon, oldID) = try await readyToRotate(store, server, keys: mac)
        #expect(try store.value(forKey: "server_clock_offset").flatMap(Double.init) == 600)

        let held = HoldingTransport(server: server)
        let command = authenticator(store, server, keys: mac, role: .command, transport: held)
        let request = Task { try await postEvents(command) }
        try await held.waitUntilSent(1)
        #expect(held.sent.first?.timestamp == String(Int64(clock.now.timeIntervalSince1970) + 600))

        // The daemon rotates while the command's request is on its way.
        #expect(await daemon.rotate(reason: "test") == .rotated(.software))
        held.setHolding(false)
        await #expect(throws: DeliveryError.credentialInvalid) { try await request.value }
        #expect(held.sent.count == 1)
        let newID = try #require(server.successors[oldID])
        #expect(!server.isRevoked(newID))
        #expect(await daemon.deviceID == newID)
        #expect(try await postEvents(daemon) == 200)
        #expect(server.staleKeyUses == 0)
    }

    @Test(.timeLimit(.minutes(1))) func anUnreadableNextRecordEnrollsAfresh() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        let start = server.requests.count
        try store.setValue(#"{"serverURL":"https://api.altiward.test","fromDeviceID":"#, forKey: "device_credential_next")

        #expect(try await postEvents(auth) == 200)
        #expect(try store.value(forKey: "device_credential_next") == nil)
        #expect(try store.value(forKey: "device_credential") == nil)
        let enrollments = server.enrollments
        try #require(enrollments.count == 2)
        #expect(try enrolledKey(enrollments[0]) != enrolledKey(enrollments[1]))
        #expect(await auth.deviceID != oldID)
        #expect(server.rotations.isEmpty)
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    /// The lid closes while the rotate request is in flight; on wake the first retry times
    /// out before the network is back.
    @Test(.timeLimit(.minutes(1))) func aRotationInterruptedBySleepRetriesOnWake() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        let start = server.requests.count
        server.dropNextRotateResponse(URLError(.networkConnectionLost))
        #expect(await auth.rotate(reason: "test") == .unknown)

        clock.advance(8 * 3600)
        server.failRotate(URLError(.timedOut))
        await #expect(throws: DeviceKeyError.rotationOutcomeUnknown) { try await postEvents(auth) }
        #expect(try nextRecord(store) != nil)
        clock.advance(15)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == server.successors[oldID])
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    /// A captive portal or a proxy answers 200 with a page of its own.
    @Test(.timeLimit(.minutes(1))) func aCaptivePortalAnswerIsUnknown() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        let start = server.requests.count
        server.answerRotate(status: 200, body: Data("<html><body>Sign in to use the Wi-Fi</body></html>".utf8), times: 1)
        server.answerRotate(status: 200, body: Data("{}".utf8), times: 1)
        server.answerRotate(status: 201, body: Data(#"{"device_id":"","status":"active"}"#.utf8), times: 1)
        server.answerRotate(status: 200, body: Data(#"{"device_id":"\#(oldID)","status":"active"}"#.utf8), times: 1)

        #expect(await auth.rotate(reason: "test") == .unknown)
        for _ in 0..<3 {
            clock.advance(15)
            await #expect(throws: DeviceKeyError.rotationOutcomeUnknown) { try await postEvents(auth) }
            #expect(try nextRecord(store) != nil)
            #expect(await auth.deviceID == oldID)
            #expect(try store.value(forKey: "device_credential_se") == nil)
        }
        clock.advance(15)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == server.successors[oldID])
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    /// The rotation commits but its answer is lost, and a proxy answers the retry with a
    /// block page of its own. Only the server's refusal, with its code, says the rotation
    /// didn't happen, so the new key stays saved and the old one unused.
    @Test(.timeLimit(.minutes(1))) func aProxyRefusingARetryLeavesTheRotationUnknown() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        let start = server.requests.count

        server.dropNextRotateResponse()
        #expect(await auth.rotate(reason: "test") == .unknown)
        let pending = try #require(try nextRecord(store))
        server.answerRotate(
            status: 403, body: Data("<html><body>Blocked by your organisation's web policy</body></html>".utf8), times: 1)
        clock.advance(15)
        #expect(await auth.rotate(reason: "test") == .unknown)
        #expect(try nextRecord(store)?.privateKey == pending.privateKey)
        #expect(await auth.deviceID == oldID)
        #expect(server.staleKeyUses == 0)

        clock.advance(15)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == server.successors[oldID])
        #expect(try nextRecord(store) == nil)
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    /// A load balancer throttles a retry without the server's code: that is no refusal of
    /// the rotation, so the agent holds and asks again.
    @Test(.timeLimit(.minutes(1))) func anUncodedRateLimitOfARetryLeavesTheRotationUnknown() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        let start = server.requests.count

        server.failRotate(URLError(.timedOut))
        #expect(await auth.rotate(reason: "test") == .unknown)
        server.answerRotate(status: 429, retryAfter: 60, body: Data("Too Many Requests".utf8), times: 1)
        clock.advance(15)
        #expect(await auth.rotate(reason: "test") == .unknown)
        #expect(try nextRecord(store) != nil)
        #expect(server.successors[oldID] == nil)

        clock.advance(15)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == server.successors[oldID])
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    /// On a retry, a 4xx whose code belongs to another refusal is no refusal of the
    /// rotation either.
    @Test(.timeLimit(.minutes(1))) func aMismatchedRefusalCodeOnARetryLeavesTheRotationUnknown() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)

        server.failRotate(URLError(.networkConnectionLost))
        #expect(await auth.rotate(reason: "test") == .unknown)
        server.answerRotate(status: 409, code: "rotation_rate_limited", times: 1)
        clock.advance(15)
        #expect(await auth.rotate(reason: "test") == .unknown)
        #expect(try nextRecord(store) != nil)
        clock.advance(15)
        #expect(await auth.rotate(reason: "test") == .rotated(.secureEnclave))
        #expect(server.successors[oldID] != nil)
        #expect(server.staleKeyUses == 0)
    }

    /// A proxy or firewall refuses the very first rotate request with a page of its own.
    /// Nothing can have committed, so the rotation is dropped for a day and the Mac keeps
    /// reporting with its key, rather than holding everything behind a path it can't use.
    @Test(.timeLimit(.minutes(1))) func aProxyRefusingTheFirstRequestDefersTheRotation() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (logged, log) = logLines()
        let (auth, oldID) = try await readyToRotate(store, server, log: log)

        server.answerRotate(
            status: 403, body: Data("<html><body>Blocked by your organisation's web policy</body></html>".utf8))
        #expect(await auth.rotate(reason: "test") == .deferred(until: clock.now.addingTimeInterval(86400)))
        #expect(try nextRecord(store) == nil)
        #expect(logged.withLock { $0 }.contains { $0.contains("Check that the whole of /v1/agent/ reaches the server") })
        #expect(try await postEvents(auth) == 200)
        #expect(server.requests.last?.deviceID == oldID)
        #expect(await auth.keyStorage == .software)
        #expect(server.successors.isEmpty)
        #expect(server.staleKeyUses == 0)

        // The same for an uncoded throttle, which waits a day whatever Retry-After says.
        clock.advance(86400)
        server.stopAnsweringRotate()
        server.answerRotate(status: 429, retryAfter: 60, body: Data("Too Many Requests".utf8))
        #expect(await auth.rotate(reason: "test") == .deferred(until: clock.now.addingTimeInterval(86400)))
        #expect(try nextRecord(store) == nil)
        #expect(server.staleKeyUses == 0)
    }

    /// A saved rotation from before the agent recorded whether it was sent counts as sent:
    /// a proxy's refusal of it holds, since an earlier attempt may have committed.
    @Test(.timeLimit(.minutes(1))) func aSavedRotationThatDoesNotSayCountsAsSent() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (_, oldID) = try await readyToRotate(store, server)
        _ = try saveNextRecord(store, from: oldID)
        var record = try JSONSerialization.jsonObject(
            with: Data(try #require(try store.value(forKey: "device_credential_next")).utf8)) as! [String: Any]
        #expect(record.removeValue(forKey: "sent") != nil)
        try store.setValue(
            String(decoding: try JSONSerialization.data(withJSONObject: record), as: UTF8.self),
            forKey: "device_credential_next")
        #expect(try nextRecord(store)?.sent == true)

        let restarted = authenticator(store, server)
        server.answerRotate(status: 403, body: Data("<html>Blocked</html>".utf8), times: 1)
        #expect(await restarted.rotate(reason: "test") == .unknown)
        #expect(try nextRecord(store) != nil)
        #expect(server.staleKeyUses == 0)
    }

    /// The server commits, but saving the new key fails: another connection holds the
    /// store's write lock past its 5-second busy timeout.
    @Test(.timeLimit(.minutes(1))) func aFailedLocalCommitIsRetried() async throws {
        let (store, other) = try makeSharedStores()
        let server = FakeServer(clock: clock)
        let transport = InterleavingTransport(server: server)
        let (logged, log) = logLines()
        let (auth, oldID) = try await readyToRotate(store, server, transport: transport, log: log)
        let start = server.requests.count

        let holding = OSAllocatedUnfairLock(initialState: 0)  // 1 while held, 2 once released
        transport.beforeNextRequest {
            Thread {
                try? other.transaction {
                    holding.withLock { $0 = 1 }
                    Thread.sleep(forTimeInterval: 9)
                }
                holding.withLock { $0 = 2 }
            }.start()
            while holding.withLock({ $0 }) == 0 { try await Task.sleep(for: .milliseconds(5)) }
        }
        #expect(await auth.rotate(reason: "test") == .unknown)
        let newID = try #require(server.successors[oldID])
        #expect(try nextRecord(store) != nil)
        #expect(await auth.deviceID == oldID)
        #expect(logged.withLock { $0 }.contains { $0.hasPrefix("couldn't save the rotated key") })

        while holding.withLock({ $0 }) != 2 { try await Task.sleep(for: .milliseconds(20)) }
        clock.advance(15)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.deviceID == newID)
        #expect(try nextRecord(store) == nil)
        #expect(server.enrollments.count == 1)
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    /// Hook events recorded while the outcome is unknown stay queued, and go out signed by
    /// the new key as soon as another request finds the rotation settled.
    @Test(.timeLimit(.minutes(1))) func eventsRecordedDuringARotationAreDeliveredAfterIt() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        let delivery = DeliveryLoop(store: store, sink: HTTPEventSink(authenticator: auth), now: { clock.now })
        let start = server.requests.count
        server.dropNextRotateResponse()
        #expect(await auth.rotate(reason: "test") == .unknown)

        let events = (0..<3).map { _ in sampleEvent(at: clock.now) }
        for event in events {
            try store.enqueue(event, now: clock.now)
            _ = await delivery.flush()
        }
        #expect(try store.pendingCount() == 3)

        // The long poll's next request settles the rotation; the backoff it left ends at once.
        clock.advance(15)
        #expect(try await auth.send(method: "GET", path: "v1/agent/commands", body: Data()).1.statusCode == 200)
        await delivery.serverAnswered()
        #expect(try store.pendingCount() == 0)

        let newID = try #require(server.successors[oldID])
        struct Posted: Decodable {
            struct Event: Decodable { let event_id: String }
            let events: [Event]
        }
        let delivered = try server.requests.filter { $0.path == "/v1/agent/events" && $0.deviceID == newID }
            .flatMap { try JSONDecoder().decode(Posted.self, from: $0.body).events.map(\.event_id) }
        #expect(Set(delivered) == Set(events.map(\.eventID)))
        #expect(server.staleKeyUses == 0)
        #expect(oldKeyRequests(server, oldID, after: start).isEmpty)
    }

    // MARK: When to rotate

    /// The file record's `madeAt`, as the store holds it: nil when it has none.
    func storedMadeAt(_ store: AgentStore) throws -> Date? {
        let json = try #require(try store.value(forKey: "device_credential"))
        let object = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        return (object["madeAt"] as? Double).map { Date(timeIntervalSinceReferenceDate: $0) }
    }

    /// Rewrites the file record's `madeAt`: removes it for nil.
    func setStoredMadeAt(_ store: AgentStore, _ date: Date?) throws {
        let json = try #require(try store.value(forKey: "device_credential"))
        var object = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        object["madeAt"] = date?.timeIntervalSinceReferenceDate
        let data = try JSONSerialization.data(withJSONObject: object)
        try store.setValue(String(decoding: data, as: UTF8.self), forKey: "device_credential")
    }

    var thirtyDays: TimeInterval { DeviceAuthenticator.fileKeyLifetime }

    @Test(.timeLimit(.minutes(1))) func theFileKeyLifetimeIsThirtyDays() {
        #expect(DeviceAuthenticator.fileKeyLifetime == 30 * 86400)
    }

    @Test(.timeLimit(.minutes(1))) func aFileKeyWithTheSecureEnclaveIsDue() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, _) = try await readyToRotate(store, server)
        #expect(try await auth.rotationDue(now: clock.now) == "move into the Secure Enclave")
        #expect(await auth.rotate(reason: "move into the Secure Enclave") == .rotated(.secureEnclave))
        #expect(try await auth.rotationDue(now: clock.now) == nil)
    }

    @Test(.timeLimit(.minutes(1))) func aFileKeyWithoutTheSecureEnclaveIsDueAfterThirtyDays() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, _) = try await readyToRotate(store, server, keys: FakeKeys(secureEnclave: false), age: 86400)
        let madeAt = try #require(try storedMadeAt(store))
        #expect(try await auth.rotationDue(now: clock.now) == nil)

        // 29 days 23 hours after the key was made, then 30 days.
        clock.advance(madeAt.addingTimeInterval(thirtyDays - 3600).timeIntervalSince(clock.now))
        #expect(try await auth.rotationDue(now: clock.now) == nil)
        clock.advance(3600)
        #expect(try await auth.rotationDue(now: clock.now) != nil)
        #expect(await auth.rotate(reason: "test") == .rotated(.software))
        let rotated = try #require(try storedMadeAt(store))
        #expect(rotated == clock.now)
        #expect(try await auth.rotationDue(now: clock.now) == nil)
    }

    @Test(.timeLimit(.minutes(1))) func aRecordWithoutMadeAtStartsItsClockNow() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, _) = try await readyToRotate(store, server, keys: FakeKeys(secureEnclave: false), age: 90 * 86400)
        try setStoredMadeAt(store, nil)
        #expect(try storedMadeAt(store) == nil)

        // Not due, however old the key is: the clock starts now.
        #expect(try await auth.rotationDue(now: clock.now) == nil)
        #expect(try storedMadeAt(store) == clock.now)
        let started = clock.now
        clock.advance(thirtyDays - 1)
        #expect(try await auth.rotationDue(now: clock.now) == nil)
        #expect(try storedMadeAt(store) == started)
        clock.advance(1)
        #expect(try await auth.rotationDue(now: clock.now) != nil)
    }

    @Test(.timeLimit(.minutes(1))) func aFutureMadeAtCountsAsNow() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, _) = try await readyToRotate(store, server, keys: FakeKeys(secureEnclave: false))
        try setStoredMadeAt(store, clock.now.addingTimeInterval(400 * 86400))

        #expect(try await auth.rotationDue(now: clock.now) == nil)
        #expect(try storedMadeAt(store) == clock.now)
        clock.advance(thirtyDays - 1)
        #expect(try await auth.rotationDue(now: clock.now) == nil)
        clock.advance(1)
        #expect(try await auth.rotationDue(now: clock.now) != nil)
    }

    @Test(.timeLimit(.minutes(1))) func aSecureEnclaveKeyIsNeverDue() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let auth = authenticator(store, server)
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.keyStorage == .secureEnclave)
        #expect(try await auth.rotationDue(now: clock.now) == nil)
        #expect(try await auth.rotationDue(now: clock.now.addingTimeInterval(400 * 86400)) == nil)
    }

    @Test(.timeLimit(.minutes(1))) func threeSecureEnclaveFailuresUseTheThirtyDaySchedule() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, _) = try await readyToRotate(store, server)
        let madeAt = try #require(try storedMadeAt(store))

        keys.failCreate(true)
        for _ in 1...2 {
            #expect(await auth.rotate(reason: "test") != .notDue)
            #expect(try await auth.rotationDue(now: clock.now) == "move into the Secure Enclave")
        }
        #expect(await auth.rotate(reason: "test") != .notDue)
        #expect(await auth.secureEnclaveFailures == 3)

        // As if the Mac had no Secure Enclave: due thirty days after the key was made.
        #expect(try await auth.rotationDue(now: clock.now) == nil)
        clock.advance(madeAt.addingTimeInterval(thirtyDays - 1).timeIntervalSince(clock.now))
        #expect(try await auth.rotationDue(now: clock.now) == nil)
        clock.advance(1)
        #expect(try await auth.rotationDue(now: clock.now) != nil)
    }

    /// Failing to use a saved Secure Enclave key counts like failing to make one.
    @Test(.timeLimit(.minutes(1))) func failingToUseASavedSecureEnclaveKeyCounts() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, oldID) = try await readyToRotate(store, server)
        _ = try saveNextRecord(store, from: oldID)

        keys.busy(true)
        for failures in 1...3 {
            clock.advance(15)
            #expect(await auth.rotate(reason: "test") == .unknown)
            #expect(await auth.secureEnclaveFailures == failures)
        }
        #expect(try nextRecord(store) != nil)
        #expect(server.rotations.isEmpty)

        keys.busy(false)
        clock.advance(15)
        #expect(await auth.rotate(reason: "test") == .rotated(.secureEnclave))
        #expect(await auth.secureEnclaveFailures == 0)
        #expect(server.staleKeyUses == 0)
    }

    @Test(.timeLimit(.minutes(1))) func aCommandIsNeverDue() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (_, _) = try await readyToRotate(store, server, keys: FakeKeys(secureEnclave: false))
        let command = authenticator(store, server, keys: FakeKeys(secureEnclave: false), role: .command)
        #expect(try await postEvents(command) == 200)
        #expect(await command.lastSignedSuccess != nil)
        let madeAt = try #require(try storedMadeAt(store))
        #expect(try await command.rotationDue(now: madeAt.addingTimeInterval(400 * 86400)) == nil)
        #expect(try storedMadeAt(store) == madeAt)

        // Even where the daemon would move the key into the Secure Enclave.
        let withEnclave = authenticator(store, server, role: .command)
        #expect(try await postEvents(withEnclave) == 200)
        #expect(try await withEnclave.rotationDue(now: clock.now) == nil)
    }

    @Test(.timeLimit(.minutes(1))) func aPendingRotationOrAnotherKeysSuccessIsNotDue() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let (auth, _) = try await readyToRotate(store, server)
        server.dropNextRotateResponse()
        #expect(await auth.rotate(reason: "test") == .unknown)
        clock.advance(400 * 86400)
        #expect(try await auth.rotationDue(now: clock.now) == nil)

        // Before it has signed a request successfully in this run.
        let fresh = authenticator(store, server, keys: FakeKeys(secureEnclave: false))
        #expect(await fresh.lastSignedSuccess == nil)
        #expect(try await fresh.rotationDue(now: clock.now) == nil)

        // Success recorded for a key another process has since replaced.
        let replaced = try makeStore()
        let (stale, firstID) = try await readyToRotate(replaced, server)
        let other = try makeStore()
        #expect(try await postEvents(authenticator(other, server, keys: FakeKeys(secureEnclave: false))) == 200)
        try replaced.setValue(other.value(forKey: "device_credential"), forKey: "device_credential")
        #expect(await stale.lastSignedSuccess?.deviceID == firstID)
        #expect(await stale.deviceID != firstID)
        #expect(try await stale.rotationDue(now: clock.now) == nil)
    }

    @Test(.timeLimit(.minutes(1))) func onlyTheProcessLaunchdStartedIsTheDaemon() {
        let launchd = ["XPC_SERVICE_NAME": "com.altiward.agent", "PATH": "/usr/bin"]
        let other = ["XPC_SERVICE_NAME": "com.apple.Terminal", "PATH": "/usr/bin"]
        let standard = AgentConfiguration.defaultDataDirectory
        let own = URL(fileURLWithPath: "/tmp/altiward-dev")

        #expect(DeviceAuthenticator.Role.forProcess(environment: launchd, dataDirectory: standard) == .daemon)
        #expect(DeviceAuthenticator.Role.forProcess(environment: [:], dataDirectory: standard) == .command)
        #expect(DeviceAuthenticator.Role.forProcess(environment: other, dataDirectory: standard) == .command)
        #expect(DeviceAuthenticator.Role.forProcess(environment: ["XPC_SERVICE_NAME": "0"], dataDirectory: standard) == .command)
        #expect(DeviceAuthenticator.Role.forProcess(environment: [:], dataDirectory: own) == .daemon)
        #expect(DeviceAuthenticator.Role.forProcess(environment: other, dataDirectory: own) == .daemon)
    }

    /// A call to rotate that waits behind a send finishing the saved rotation doesn't try
    /// the request again the moment that send gives up.
    @Test(.timeLimit(.minutes(1))) func aRotateParkedBehindARetryHonoursTheRetryInterval() async throws {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let transport = HoldingTransport(server: server, holding: false)
        let (auth, _) = try await readyToRotate(store, server, transport: transport)
        server.dropNextRotateResponse()
        #expect(await auth.rotate(reason: "test") == .unknown)
        let rotateRequests = transport.sent.filter { $0.path == "/v1/agent/rotate" }.count
        #expect(rotateRequests == 1)

        // A send finds the saved rotation and retries it; the retry is held, and so is its
        // answer, which is lost again.
        clock.advance(15)
        server.dropNextRotateResponse()
        transport.setHolding(true)
        let sent = transport.sent.count
        let send = Task { try await postEvents(auth) }
        try await transport.waitUntilSent(sent + 1)
        #expect(transport.sent.last?.path == "/v1/agent/rotate")

        let rotation = Task { await auth.rotate(reason: "test") }
        try await Task.sleep(for: .milliseconds(200))  // it waits for the gate
        transport.setHolding(false)
        await #expect(throws: DeviceKeyError.rotationOutcomeUnknown) { try await send.value }
        #expect(await rotation.value == .unknown)
        #expect(transport.sent.filter { $0.path == "/v1/agent/rotate" }.count == rotateRequests + 1)

        // Once the interval has passed, a call tries again.
        clock.advance(15)
        #expect(await auth.rotate(reason: "test") == .rotated(.secureEnclave))
        #expect(server.staleKeyUses == 0)
    }

    /// The real Secure Enclave, as in ``signsWithTheRealSecureEnclave()``.
    @Test(.timeLimit(.minutes(1)), .enabled(if: SecureEnclave.isAvailable || requireSecureEnclave))
    func rotatesIntoTheRealSecureEnclave() async throws {
        try #require(SecureEnclave.isAvailable, "ALTIWARD_REQUIRE_SECURE_ENCLAVE is set, but this Mac has no Secure Enclave")
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        #expect(try await postEvents(authenticator(store, server, keys: FakeKeys(secureEnclave: false))) == 200)
        clock.advance(86400)
        let auth = DeviceAuthenticator(
            store: store, serverURL: serverURL, enrollmentToken: "enroll-token-0001", device: { testDevice },
            transport: server, keys: SystemDeviceKeys(), now: { clock.now })
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.rotate(reason: "move into the Secure Enclave") == .rotated(.secureEnclave))
        #expect(try await postEvents(auth) == 200)
        #expect(await auth.keyStorage == .secureEnclave)
        #expect(server.enrollments.count == 1)
        #expect(server.staleKeyUses == 0)
    }
}
