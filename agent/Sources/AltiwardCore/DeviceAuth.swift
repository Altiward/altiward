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

/// The key-rotation proof contract shared with the backend
/// (docs/schema/rotation-vector.json).
public enum RotationProof {
    /// The text a new device key signs to prove possession: version, the device_id it succeeds
    /// and the lowercase hex SHA-256 of its own SubjectPublicKeyInfo DER, one per line, with no
    /// trailing newline. Its first line keeps it apart from a request signature.
    public static func statement(deviceID: String, newPublicKey: Data) -> String {
        let digest = SHA256.hash(data: newPublicKey).map { String(format: "%02x", $0) }.joined()
        return ["ALTIWARD-ROTATE-V1", deviceID, digest].joined(separator: "\n")
    }
}

/// Where this Mac's device key is kept. The agent reports it when it enrolls.
public enum KeyStorage: String, Sendable, Codable {
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
    /// The agent daemon is replacing this Mac's key, and began at `since`. Until it has
    /// finished, another process sends, discards and enrols nothing.
    case rotationInProgress(since: Date)
    /// The daemon asked the server to replace this Mac's key and hasn't heard whether it
    /// did. Nothing is sent until it has; the request is retried like a network failure.
    case rotationOutcomeUnknown

    public var description: String {
        switch self {
        case .secureEnclaveUnavailable(let error): "the Secure Enclave couldn't sign (\(error)); will retry"
        case .heldByDaemon: "this Mac's key is in the Secure Enclave, where only the agent daemon can use it; the daemon sends within a minute"
        case .notEnrolled: "not enrolled yet; the agent daemon enrolls this Mac when it starts"
        case .rotationInProgress(let since):
            "the agent daemon has been replacing this Mac's key since \(since.formatted(.iso8601)); try again once it has finished"
        case .rotationOutcomeUnknown:
            "the rotation's outcome is not known yet; holding requests until the server answers"
        }
    }
}

/// What a call to ``DeviceAuthenticator/rotate(reason:)`` came to.
public enum RotationOutcome: Sendable, Equatable {
    /// Nothing to rotate: no enrolled file key that has signed successfully in this run, a
    /// key that changed meanwhile, or a process other than the daemon.
    case notDue
    /// The server replaced the key, and this Mac now signs with the new one.
    case rotated(KeyStorage)
    /// Not now: the current key stays, and a rotation is worth trying again after `until`.
    case deferred(until: Date)
    /// The server hasn't said whether it replaced the key. The replacement is kept, and
    /// every request retries it before anything else is sent.
    case unknown
    /// The server no longer accepts the current key, so both keys were dropped, and the
    /// next send enrols a new one.
    case enrolAgain
}

/// A replacement for this Mac's file key, kept in the agent store from just before the
/// rotate request is sent until the server's answer settles it. It carries the old key too,
/// so a retry never depends on the old credential's record. Agent 0.9 and earlier ignore it.
struct PendingRotation: Codable {
    static let storeKey = "device_credential_next"

    var serverURL: String
    var fromDeviceID: String
    /// Always a file key: a Secure Enclave key is never rotated.
    var fromPrivateKey: Data
    /// The Mac the old credential was bound to; the new one keeps it.
    var serial: String
    var hardwareUUID: String
    var privateKey: Data
    var storage: KeyStorage
    var madeAt: Date
    /// Whether the rotate request may have left the Mac. Set, and saved, before the first
    /// send, so a refusal of a request never sent before can't hide an earlier commit.
    /// Read leniently, and true when missing: a record that doesn't say is treated as sent.
    var sent = true
    /// What last kept the rotation waiting, and when, for `altiward-agent status`. Saved
    /// when the daemon logs it, so at most an hour old. Agent 1.0.0 ignores them.
    var lastAnswer: String?
    var lastAnswerAt: Date?
}

extension PendingRotation {
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        serverURL = try c.decode(String.self, forKey: .serverURL)
        fromDeviceID = try c.decode(String.self, forKey: .fromDeviceID)
        fromPrivateKey = try c.decode(Data.self, forKey: .fromPrivateKey)
        serial = try c.decode(String.self, forKey: .serial)
        hardwareUUID = try c.decode(String.self, forKey: .hardwareUUID)
        privateKey = try c.decode(Data.self, forKey: .privateKey)
        storage = try c.decode(KeyStorage.self, forKey: .storage)
        madeAt = try c.decode(Date.self, forKey: .madeAt)
        sent = (try? c.decodeIfPresent(Bool.self, forKey: .sent)) ?? true
        lastAnswer = try? c.decodeIfPresent(String.self, forKey: .lastAnswer)
        lastAnswerAt = try? c.decodeIfPresent(Date.self, forKey: .lastAnswerAt)
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
/// goes in the Secure Enclave when the Mac has one. A Mac that enrolled with a file key
/// keeps it until it rotates (``rotate(reason:)``): into the Secure Enclave when it has one.
///
/// The two kinds live in separate records of the agent store, inside the root-only data
/// directory. A file key keeps the record and format agent 0.1 reads, and a Secure
/// Enclave key has its own record, so an older agent installed over this one finds no
/// key it can't use: it enrolls again with a file key instead of failing every send.
///
/// While a rotation's outcome is unknown, no request signed by the old key may reach the
/// server except the rotation's own retry: once the server has replaced a key, any other
/// use of it looks like a second holder, and the server revokes the Mac's new key. So
/// every send passes a gate. A rotation closes it to new sends, waits for those in flight,
/// and only then saves the replacement and asks the server. While a replacement is saved,
/// the daemon retries it before admitting anything, and any other process refuses.
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
        /// daemon too, so the Mac doesn't end up with a file key. It never rotates, and
        /// while the daemon is rotating it sends, discards and enrols nothing.
        case command

        /// The role of a process: the daemon when launchd started it (it sets
        /// `XPC_SERVICE_NAME` to the job's label) or when it has a data directory of its own
        /// (development), where no daemon shares the store; otherwise a command. A
        /// `sudo altiward-agent run` beside the daemon is a command too, so it never rotates the key
        /// the daemon is using.
        public static func forProcess(environment: [String: String], dataDirectory: URL) -> Role {
            environment["XPC_SERVICE_NAME"] == "com.altiward.agent"
                || dataDirectory != AgentConfiguration.defaultDataDirectory ? .daemon : .command
        }
    }

    private struct Credential: Codable {
        var serverURL: String
        var privateKey: Data  // the raw P256 key, or the Secure Enclave's handle
        var deviceID: String?
        /// The Mac the key was made on. A store copied to another Mac (Migration Assistant,
        /// a clone, a restore) keeps a file key that works there, so without these the
        /// copy would go on signing as the first Mac. Nil in a record from before agent
        /// 0.8.0, or in one made while the Mac couldn't report its identity; such a record
        /// gets this Mac's identity the first time the Mac can report it.
        var serial: String?
        var hardwareUUID: String?
        /// When the key was made. Nil in a record from before agent 1.0.0, and read
        /// leniently, so a value this agent can't read never costs it the key.
        var madeAt: Date?
        /// The key's public half as SubjectPublicKeyInfo DER, so a command can show its
        /// fingerprint without asking the Secure Enclave, which only the daemon may. Nil in
        /// a record from before agent 1.0.0 until the daemon next signs with the key, and
        /// read leniently like `madeAt`.
        var publicKey: Data?

        init(
            serverURL: String, privateKey: Data, deviceID: String? = nil, serial: String?, hardwareUUID: String?,
            madeAt: Date?, publicKey: Data? = nil
        ) {
            self.serverURL = serverURL
            self.privateKey = privateKey
            self.deviceID = deviceID
            self.serial = serial
            self.hardwareUUID = hardwareUUID
            self.madeAt = madeAt
            self.publicKey = publicKey
        }

        init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            serverURL = try c.decode(String.self, forKey: .serverURL)
            privateKey = try c.decode(Data.self, forKey: .privateKey)
            deviceID = try c.decodeIfPresent(String.self, forKey: .deviceID)
            serial = try c.decodeIfPresent(String.self, forKey: .serial)
            hardwareUUID = try c.decodeIfPresent(String.self, forKey: .hardwareUUID)
            madeAt = try? c.decodeIfPresent(Date.self, forKey: .madeAt)
            publicKey = try? c.decodeIfPresent(Data.self, forKey: .publicKey)
        }
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

    /// Server time minus local time in seconds, learnt from a `clock_skew` answer. In the
    /// store, so the daemon and commands sign with the same corrected time.
    static let clockOffsetKey = "server_clock_offset"
    /// How often a rotation whose outcome is unknown is retried.
    static let rotationRetryInterval: TimeInterval = 15
    /// How long a refused rotation, or one the Secure Enclave failed, waits.
    static let rotationDeferral: TimeInterval = 86400
    /// How long a file key lasts on a Mac that can't move it into the Secure Enclave.
    public static let fileKeyLifetime: TimeInterval = 30 * 86400
    /// Failures in a row to make or use a Secure Enclave key, after which the Mac counts as
    /// having none for ``fileKeyLifetime``.
    static let secureEnclaveFailureLimit = 3

    private let store: AgentStore
    private let serverURL: URL
    private let enrollmentToken: String
    private let device: @Sendable () -> DeviceInfo
    private let transport: any HTTPTransport
    private let keys: any DeviceKeys
    private let role: Role
    private let now: @Sendable () -> Date
    private let log: @Sendable (String) -> Void
    /// The clock offset last learnt here, for when the store can't be read.
    private var learntClockOffset: TimeInterval = 0
    /// After the server's enrolment limits refused this Mac (429), when it may ask again.
    /// In memory only: a restarted agent asks once more.
    private var enrollNotBefore: Date?

    // The send gate. One holder at a time, which a rotation takes: it closes the gate to
    // new sends first, then waits for those in flight, so steady traffic can't starve it.
    /// Sends admitted and not yet answered.
    private var inFlight = 0
    /// A holder has closed the gate.
    private var exclusive = false
    /// Sends and would-be holders waiting for the gate to open.
    private var parked: [CheckedContinuation<Void, Never>] = []
    /// The holder, waiting for the sends in flight to finish.
    private var drained: [CheckedContinuation<Void, Never>] = []

    /// The rotation running now, which an overlapping call waits for.
    private var rotation: Task<RotationOutcome, Never>?
    /// When the rotate request was last tried while its outcome stays unknown.
    private var lastRotationAttempt: Date?
    private var lastHoldingLog: Date?
    /// Secure Enclave failures in a row while rotating: making, or using, a key there. In
    /// memory, so a restart tries the Secure Enclave again.
    private(set) var secureEnclaveFailures = 0

    /// The last request signed by this Mac's key that the server answered with success in
    /// this run, and the device ID that signed it. A key rotates only once it has.
    public private(set) var lastSignedSuccess: (deviceID: String, at: Date)?

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

    /// The fingerprint of the key for the configured server, as the console shows it, if
    /// the store says. Reads the store only; it never asks the Secure Enclave, so a Secure
    /// Enclave key enrolled before agent 1.0.0 has none until the daemon next signs with it.
    public var keyFingerprint: String? {
        guard let c = try? load() else { return nil }
        guard let publicKey = c.credential.publicKey
            ?? (c.storage == .software ? try? keys.publicKey(c.credential.privateKey, .software) : nil)
        else { return nil }
        return Self.fingerprint(publicKey: publicKey)
    }

    /// The first 64 bits of the SHA-256 of a key's SubjectPublicKeyInfo DER, in upper-case
    /// hex in groups of four digits: how the console shows a key, so an admin can tell
    /// which pending key is this Mac's.
    public static func fingerprint(publicKey: Data) -> String {
        let hex = SHA256.hash(data: publicKey).prefix(8).map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 4).map { start in
            let from = hex.index(hex.startIndex, offsetBy: start)
            return String(hex[from..<hex.index(from, offsetBy: 4)])
        }.joined(separator: " ")
    }

    /// When the rotation the daemon hasn't finished yet began, if there is one.
    public var rotationPendingSince: Date? {
        try? pendingSince()
    }

    /// What last kept the unfinished rotation waiting, and when, once the daemon has logged
    /// it.
    public var rotationLastAnswer: (at: Date, answer: String)? {
        guard let raw = try? store.value(forKey: PendingRotation.storeKey),
            let pending = try? JSONDecoder().decode(PendingRotation.self, from: Data(raw.utf8)),
            let answer = pending.lastAnswer, let at = pending.lastAnswerAt
        else { return nil }
        return (at, answer)
    }

    // MARK: Sending

    /// Enrolls if needed, then sends a signed request to `path` (relative to the server
    /// URL, optionally with a query), giving up after `timeout` seconds. Returns the answer
    /// and the device ID that signed the request. Throws
    /// ``DeliveryError/credentialInvalid`` (the credential was discarded, unless another
    /// process had already replaced it; the next call enrolls again or uses the
    /// replacement), ``DeliveryError/enrollmentPending``, or
    /// ``DeliveryError/enrollmentRateLimited(until:)`` without sending anything while the
    /// server's enrolment limits make this Mac wait; any other response is returned for the
    /// caller to judge. While a rotation's outcome is unknown it throws
    /// ``DeviceKeyError/rotationOutcomeUnknown`` (the daemon) or
    /// ``DeviceKeyError/rotationInProgress(since:)`` (a command) and sends nothing else.
    public func send(
        method: String, path: String, body: Data, timeout: TimeInterval = 30
    ) async throws -> (Data, HTTPURLResponse, signedWith: String) {
        try await admit()
        defer { leave() }
        let credential = try await enrolled()
        var (data, response, used) = try await signedSend(
            credential, method: method, path: path, body: body, timeout: timeout)
        if response.statusCode == 401, Self.code(data) == "clock_skew",
            let serverDate = response.value(forHTTPHeaderField: "Date").flatMap(Self.parseHTTPDate)
        {
            learnClockOffset(serverDate.timeIntervalSince(now()))
            (data, response, used) = try await signedSend(
                credential, method: method, path: path, body: body, timeout: timeout)
        }
        let signedWith = used.credential.deviceID ?? ""
        switch (response.statusCode, Self.code(data)) {
        case (401, "credential_invalid"):
            try discard(used)
            throw DeliveryError.credentialInvalid
        case (403, "enrollment_pending"):
            throw DeliveryError.enrollmentPending
        default:
            if (200..<300).contains(response.statusCode) {
                lastSignedSuccess = (signedWith, now())
                recordPublicKey(used)
            }
            return (data, response, signedWith)
        }
    }

    /// Signs and sends one request with `c`'s key, and returns the answer and the
    /// credential that signed it.
    ///
    /// A command reads the key, checks that no rotation is pending and signs in one store
    /// transaction. The daemon saves a rotation's replacement in a transaction too, so a
    /// command's signature always comes before the rotate request's, and carries no later
    /// time (both read the clock offset from the store). The daemon signs outside it: its
    /// own gate keeps rotations out, and a Secure Enclave signature can take seconds.
    private func signedSend(
        _ c: Stored, method: String, path: String, body: Data, timeout: TimeInterval
    ) async throws -> (Data, HTTPURLResponse, Stored) {
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
        var used = c
        if role == .command {
            used = try store.transaction {
                try refuseWhileRotating()
                // The daemon may have rotated or dropped the key since it was read.
                guard let current = try load(), current.credential.deviceID != nil else {
                    throw DeliveryError.credentialInvalid
                }
                guard current.storage == .software else { throw DeviceKeyError.heldByDaemon }
                try RequestSigning.sign(&request, deviceID: current.credential.deviceID!, timestamp: signingTime()) {
                    try keys.sign($0, key: current.credential.privateKey, .software)
                }
                return current
            }
        } else {
            try RequestSigning.sign(&request, deviceID: c.credential.deviceID!, timestamp: signingTime()) { message in
                try withKey(c) { try keys.sign(message, key: $0, c.storage) }
            }
        }
        let (data, response) = try await transport.send(request)
        return (data, response, used)
    }

    /// Now by the server's clock, as far as any process sharing the store has learnt it.
    private func serverNow() -> Date {
        let stored = (try? store.value(forKey: Self.clockOffsetKey)).flatMap { $0.flatMap(TimeInterval.init) }
        return now().addingTimeInterval(stored ?? learntClockOffset)
    }

    private func signingTime() -> Int64 { Int64(serverNow().timeIntervalSince1970) }

    private func learnClockOffset(_ offset: TimeInterval) {
        learntClockOffset = offset
        do {
            try store.setValue(String(offset), forKey: Self.clockOffsetKey)
        } catch {
            log("couldn't save the server's clock offset (\(error)); using it in this process only")
        }
    }

    // MARK: The send gate

    /// Lets a send in, once no holder has the gate closed and no rotation is pending. A
    /// pending rotation is finished first, holding the gate: the daemon retries it (at most
    /// once every 15 seconds) and throws while its outcome stays unknown; a command throws.
    private func admit() async throws {
        while true {
            if exclusive {
                await withCheckedContinuation { parked.append($0) }
                continue
            }
            guard let since = try pendingSince() else {
                inFlight += 1
                return
            }
            guard role == .daemon else { throw DeviceKeyError.rotationInProgress(since: since) }
            if rotationAttemptedRecently() { throw DeviceKeyError.rotationOutcomeUnknown }
            await acquireExclusive()
            let outcome = await finishPendingRotation()
            releaseExclusive()
            if outcome == .unknown { throw DeviceKeyError.rotationOutcomeUnknown }
        }
    }

    /// Whether the rotate request was tried less than ``rotationRetryInterval`` ago, and its
    /// outcome is still unknown.
    private func rotationAttemptedRecently() -> Bool {
        guard let last = lastRotationAttempt else { return false }
        let elapsed = now().timeIntervalSince(last)
        return elapsed >= 0 && elapsed < Self.rotationRetryInterval
    }

    private func leave() {
        inFlight -= 1
        if inFlight == 0 {
            let waiting = drained
            drained = []
            for c in waiting { c.resume() }
        }
    }

    /// Closes the gate to new sends, then waits for those in flight to finish.
    private func acquireExclusive() async {
        while exclusive { await withCheckedContinuation { parked.append($0) } }
        exclusive = true
        if inFlight > 0 { await withCheckedContinuation { drained.append($0) } }
    }

    private func releaseExclusive() {
        exclusive = false
        let waiting = parked
        parked = []
        for c in waiting { c.resume() }
    }

    // MARK: Rotating

    /// Replaces this Mac's file key with a new one, in the Secure Enclave when the Mac has
    /// one that works, and the server agrees. Only the daemon rotates, and only a file key
    /// that has signed a request successfully in this run. A pending rotation is finished
    /// instead of starting another, and a call made while one runs gets its outcome.
    /// `reason` is for the log. It waits for sends in flight, so call it between sends,
    /// never from inside one.
    public func rotate(reason: String) async -> RotationOutcome {
        if let running = rotation { return await running.value }
        let task = Task { await self.rotateOnce(reason: reason) }
        rotation = task
        let outcome = await task.value
        if rotation == task { rotation = nil }
        return outcome
    }

    private func rotateOnce(reason: String) async -> RotationOutcome {
        guard role == .daemon else { return .notDue }
        if (try? pendingSince()) != nil {
            await acquireExclusive()
            defer { releaseExclusive() }
            // Parked behind a holder that has just tried the request and heard nothing: the
            // retry interval applies to this call too.
            if rotationAttemptedRecently() { return .unknown }
            return await finishPendingRotation()
        }
        guard let candidate = try? rotationCandidate() else { return .notDue }
        let (current, fromDeviceID, serial, hardwareUUID) = (
            candidate.current, candidate.deviceID, candidate.serial, candidate.hardwareUUID
        )

        // Made before the gate closes and outside any transaction: the Secure Enclave can
        // take seconds while someone signs in. The proof is signed with the new key itself,
        // never through withKey, which would drop the current credential on a failure.
        let storage: KeyStorage = movesIntoSecureEnclave ? .secureEnclave : .software
        let key: Data
        let proven: Proven
        do {
            key = try await Self.makeKey(keys, storage)
            proven = try await Self.prove(keys, key: key, storage: storage, deviceID: fromDeviceID)
        } catch {
            if storage == .secureEnclave { secureEnclaveFailures += 1 }
            let until = now().addingTimeInterval(Self.rotationDeferral)
            log("couldn't make a new key to rotate to (\(error)); keeping the current key until \(until.formatted(.iso8601))")
            return .deferred(until: until)
        }

        await acquireExclusive()
        defer { releaseExclusive() }
        enum Saved {
            case saved(PendingRotation)
            /// Another call saved one first; that one is finished and this key thrown away.
            case pending
            case changed
        }
        let saved: Saved
        do {
            saved = try store.transaction {
                if try store.value(forKey: PendingRotation.storeKey) != nil { return .pending }
                guard let latest = try load(), latest.storage == .software, latest.credential.deviceID == fromDeviceID,
                    latest.credential.privateKey == current.credential.privateKey
                else { return .changed }
                let pending = PendingRotation(
                    serverURL: serverURL.absoluteString, fromDeviceID: fromDeviceID,
                    fromPrivateKey: current.credential.privateKey, serial: serial, hardwareUUID: hardwareUUID,
                    privateKey: key, storage: storage, madeAt: now(), sent: false)
                try store.setValue(Self.encode(pending), forKey: PendingRotation.storeKey)
                return .saved(pending)
            }
        } catch {
            let until = now().addingTimeInterval(3600)
            log("couldn't save the new key to rotate to (\(error)); keeping the current key until \(until.formatted(.iso8601))")
            return .deferred(until: until)
        }
        switch saved {
        case .pending: return await finishPendingRotation()
        case .changed: return .notDue
        case .saved(let pending):
            log("rotating this Mac's key (\(reason))")
            return await requestRotation(pending, proven)
        }
    }

    /// A file key this process may rotate: the daemon's, enrolled, bound to this Mac, and
    /// the one that has signed a request successfully in this run.
    private struct RotationCandidate {
        var current: Stored
        var deviceID: String
        var serial: String
        var hardwareUUID: String
    }

    private func rotationCandidate() throws -> RotationCandidate? {
        guard role == .daemon, let current = try load(), current.storage == .software,
            let deviceID = current.credential.deviceID, lastSignedSuccess?.deviceID == deviceID,
            let serial = current.credential.serial, let hardwareUUID = current.credential.hardwareUUID
        else { return nil }
        return RotationCandidate(current: current, deviceID: deviceID, serial: serial, hardwareUUID: hardwareUUID)
    }

    /// Whether a file key goes into the Secure Enclave: the Mac has one, and making or using
    /// a key there hasn't failed ``secureEnclaveFailureLimit`` times in a row.
    private var movesIntoSecureEnclave: Bool {
        keys.secureEnclaveAvailable && secureEnclaveFailures < Self.secureEnclaveFailureLimit
    }

    /// Why this Mac's key should be replaced at `now`, or nil when it shouldn't. The daemon
    /// asks, then calls ``rotate(reason:)``.
    ///
    /// Due when a file key can go into the Secure Enclave, or when it is
    /// ``fileKeyLifetime`` old. Never for a Secure Enclave key, for a process other than the
    /// daemon, while a rotation is pending, or before the key has signed a request
    /// successfully in this run: the same conditions under which `rotate` does nothing. A
    /// record without a creation time, or with one in the future, starts its clock now, so an
    /// upgrade doesn't rotate every Mac at once.
    public func rotationDue(now: Date) throws -> String? {
        guard try pendingSince() == nil, let candidate = try rotationCandidate() else { return nil }
        if movesIntoSecureEnclave { return "move into the Secure Enclave" }
        let key = candidate.current.credential
        guard let madeAt = key.madeAt, madeAt <= now else {
            try store.transaction {
                // Unless another process has replaced the key, or set its time, meanwhile.
                if var latest = try record(.software), latest.privateKey == key.privateKey,
                    latest.madeAt == key.madeAt
                {
                    latest.madeAt = now
                    try save(Stored(credential: latest, storage: .software))
                }
            }
            return nil
        }
        return now.timeIntervalSince(madeAt) >= Self.fileKeyLifetime ? "the file key is 30 days old" : nil
    }

    /// Finishes the saved rotation, holding the gate: the checks that it is still this
    /// Mac's and this credential's, then the rotate request again. A rotate retry is the
    /// one question the server answers before anything else, so the old key asks nothing
    /// else.
    private func finishPendingRotation() async -> RotationOutcome {
        let pending: PendingRotation
        do {
            guard let raw = try store.value(forKey: PendingRotation.storeKey) else { return .notDue }
            do {
                pending = try JSONDecoder().decode(PendingRotation.self, from: Data(raw.utf8))
            } catch {
                // Its key is unreadable, so it can't be retried, and the old key may already
                // be replaced. Starting afresh never signs with the old key.
                log("couldn't read the saved key rotation (\(error)); enrolling again with a new key")
                try store.transaction {
                    for key in [PendingRotation.storeKey, Self.storeKey(.software), Self.storeKey(.secureEnclave)] {
                        try store.setValue(nil, forKey: key)
                    }
                }
                return settled(.enrolAgain)
            }
        } catch {
            return holding("couldn't read the saved key rotation: \(error)")
        }

        let info = device()
        if info.isReadable, pending.serial != info.serial || pending.hardwareUUID != info.hardwareUUID {
            log("this Mac's key rotation was saved on another Mac (serial \(pending.serial)); enrolling again")
            return dropRotation(pending, alsoTheOldKey: true, .enrolAgain)
        }
        let current: Stored?
        do { current = try load() } catch { return holding("couldn't read this Mac's key: \(error)", pending) }
        if pending.serverURL != serverURL.absoluteString
            || (current != nil && current?.credential.deviceID != pending.fromDeviceID)
        {
            log("dropping a saved key rotation for another key or server")
            return dropRotation(pending, alsoTheOldKey: false, .notDue)
        }

        lastRotationAttempt = now()
        let proven: Proven
        do {
            proven = try await Self.prove(keys, key: pending.privateKey, storage: pending.storage, deviceID: pending.fromDeviceID)
        } catch {
            if pending.storage == .secureEnclave, await Self.secureEnclaveWorks(keys) {
                // The Secure Enclave works but can't use this key, as after an erase and
                // restore: it can never be retried.
                log("the Secure Enclave can't use the key this Mac was rotating to (\(error)); enrolling again with a new key")
                return dropRotation(pending, alsoTheOldKey: true, .enrolAgain)
            }
            // Counts like a failure to make one: once the saved rotation settles, a Mac whose
            // Secure Enclave keeps failing rotates on the 30-day schedule instead.
            if pending.storage == .secureEnclave { secureEnclaveFailures += 1 }
            return holding("couldn't sign with the new key: \(error)", pending)
        }
        return await requestRotation(pending, proven)
    }

    /// The rotate request for `pending`, signed by the old key, with one `clock_skew`
    /// retry, and what its answer means. Holding the gate.
    private func requestRotation(_ pending: PendingRotation, _ proven: Proven) async -> RotationOutcome {
        lastRotationAttempt = now()
        // A request that has never left the Mac can't have committed, so any refusal of
        // its first send is final. That it went is saved before it goes, so a restart after
        // sending never takes a retry for a first send.
        let firstSend = !pending.sent
        if firstSend {
            do {
                guard try markSent(pending) else { return settled(.notDue) }
            } catch {
                return holding("couldn't save that the rotation is being sent: \(error)", pending)
            }
        }
        let old = Stored(
            credential: Credential(
                serverURL: pending.serverURL, privateKey: pending.fromPrivateKey, deviceID: pending.fromDeviceID,
                serial: pending.serial, hardwareUUID: pending.hardwareUUID, madeAt: nil),
            storage: .software)
        let data: Data
        let response: HTTPURLResponse
        do {
            let body = try JSONEncoder().encode([
                "public_key": proven.publicKey.base64EncodedString(), "key_storage": pending.storage.rawValue,
                "proof": proven.proof.base64EncodedString(),
            ])
            var (answer, http, _) = try await signedSend(old, method: "POST", path: "v1/agent/rotate", body: body, timeout: 30)
            if http.statusCode == 401, Self.code(answer) == "clock_skew",
                let serverDate = http.value(forHTTPHeaderField: "Date").flatMap(Self.parseHTTPDate)
            {
                learnClockOffset(serverDate.timeIntervalSince(now()))
                (answer, http, _) = try await signedSend(old, method: "POST", path: "v1/agent/rotate", body: body, timeout: 30)
            }
            (data, response) = (answer, http)
        } catch {
            // Whether or not it left the Mac, an earlier attempt may have reached the server. A
            // URLError is the network's; anything else failed on the Mac, such as signing.
            return holding("\(error)", pending, onTheWay: error is URLError)
        }

        struct Answer: Decodable {
            let device_id: String?
            let status: String?
        }
        let status = response.statusCode
        switch status {
        case 200, 201:
            guard let answer = try? JSONDecoder().decode(Answer.self, from: data), let id = answer.device_id,
                !id.isEmpty, id != pending.fromDeviceID
            else { return holding("HTTP \(status) without a key: \(Self.excerpt(data))", pending, onTheWay: true) }
            switch answer.status {
            case "active": return commit(pending, deviceID: id, publicKey: proven.publicKey)
            case "revoked":
                log("the server revoked this Mac's new key; enrolling again")
                return dropRotation(pending, alsoTheOldKey: true, .enrolAgain)
            default: return holding("HTTP \(status) with status \(answer.status ?? "none")", pending, onTheWay: true)
            }
        case 401 where Self.code(data) == "credential_invalid":
            log("the server no longer accepts this Mac's key; enrolling again")
            return dropRotation(pending, alsoTheOldKey: true, .enrolAgain)
        case 400, 403, 404, 405, 409, 429:
            // Not done, now or on any earlier attempt: the server answers a retry before
            // anything else. The current key stays. But on a retry only Altiward's own
            // refusal, with its code, says so: a proxy's block page or throttle says nothing
            // about an earlier attempt, which may have committed. A server without rotation
            // has no code to send with its 404 or 405.
            let coded = Self.refusesRotation(status, code: Self.code(data))
            guard status == 404 || status == 405 || coded || firstSend else {
                return holding(
                    "HTTP \(status) without the server's refusal code: \(Self.excerpt(data))", pending, onTheWay: true)
            }
            let wait = status == 429 && coded
                ? retryDelay(response.value(forHTTPHeaderField: "Retry-After")) : Self.rotationDeferral
            let until = now().addingTimeInterval(wait)
            if status == 404 || status == 405 {
                log("the server does not support key rotation yet; keeping the current key")
            } else if !coded {
                log("something other than the server refused the request to rotate this Mac's key (HTTP \(status): "
                    + "\(Self.excerpt(data))); keeping the current key until \(until.formatted(.iso8601)). "
                    + "Check that the whole of /v1/agent/ reaches the server")
            } else {
                log("the server refused to rotate this Mac's key (HTTP \(status): \(Self.excerpt(data))); "
                    + "keeping the current key until \(until.formatted(.iso8601))")
            }
            return dropRotation(pending, alsoTheOldKey: false, .deferred(until: until))
        default:
            let body = Self.excerpt(data)
            return holding(body.isEmpty ? "HTTP \(status)" : "HTTP \(status): \(body)", pending, onTheWay: true)
        }
    }

    /// The server replaced the key: the new one becomes this Mac's credential, in the
    /// record for its kind, unless the saved rotation changed meanwhile. If the store
    /// can't be written, the rotation stays saved and the retry, answered with the same
    /// key, commits it.
    private func commit(_ pending: PendingRotation, deviceID: String, publicKey: Data) -> RotationOutcome {
        do {
            let committed = try store.transaction { () -> Bool in
                guard let raw = try store.value(forKey: PendingRotation.storeKey),
                    let saved = try? JSONDecoder().decode(PendingRotation.self, from: Data(raw.utf8)),
                    saved.privateKey == pending.privateKey
                else { return false }
                try save(
                    Stored(
                        credential: Credential(
                            serverURL: pending.serverURL, privateKey: pending.privateKey, deviceID: deviceID,
                            serial: pending.serial, hardwareUUID: pending.hardwareUUID, madeAt: pending.madeAt,
                            publicKey: publicKey),
                        storage: pending.storage))
                try store.setValue(nil, forKey: Self.storeKey(pending.storage == .software ? .secureEnclave : .software))
                try store.setValue(nil, forKey: PendingRotation.storeKey)
                return true
            }
            guard committed else { return settled(.notDue) }
        } catch {
            log("couldn't save the rotated key (\(error)); keeping it to try again")
            return holding("couldn't save the rotated key: \(error)", pending)
        }
        if pending.storage == .secureEnclave {
            secureEnclaveFailures = 0
            log("rotated this Mac's key into the Secure Enclave")
        } else {
            log("rotated this Mac's key")
        }
        return settled(.rotated(pending.storage))
    }

    /// Saves that `pending`'s rotate request is about to leave the Mac, if the saved rotation
    /// still holds its key. False when it doesn't, and nothing is to be sent.
    private func markSent(_ pending: PendingRotation) throws -> Bool {
        try store.transaction {
            guard let raw = try store.value(forKey: PendingRotation.storeKey),
                var saved = try? JSONDecoder().decode(PendingRotation.self, from: Data(raw.utf8)),
                saved.privateKey == pending.privateKey
            else { return false }
            saved.sent = true
            try store.setValue(Self.encode(saved), forKey: PendingRotation.storeKey)
            return true
        }
    }

    /// Drops the saved rotation if it still holds `pending`'s key, and with
    /// `alsoTheOldKey` the credential it replaces, so the next send enrols afresh.
    private func dropRotation(
        _ pending: PendingRotation, alsoTheOldKey: Bool, _ outcome: RotationOutcome
    ) -> RotationOutcome {
        do {
            try store.transaction {
                if let raw = try store.value(forKey: PendingRotation.storeKey),
                    (try? JSONDecoder().decode(PendingRotation.self, from: Data(raw.utf8)))?.privateKey == pending.privateKey
                {
                    try store.setValue(nil, forKey: PendingRotation.storeKey)
                }
                guard alsoTheOldKey else { return }
                for storage in [KeyStorage.secureEnclave, .software]
                where (try? record(storage))?.privateKey == pending.fromPrivateKey {
                    try store.setValue(nil, forKey: Self.storeKey(storage))
                }
            }
        } catch {
            return holding("couldn't drop the saved key rotation: \(error)", pending)
        }
        return settled(outcome)
    }

    private func settled(_ outcome: RotationOutcome) -> RotationOutcome {
        lastRotationAttempt = nil
        lastHoldingLog = nil
        return outcome
    }

    /// The outcome is unknown: the saved rotation stays, and so does the hold on sends.
    /// Logged once an hour, and saved with `pending` then, for `altiward-agent status`. An
    /// answer that came back `onTheWay`, from the network or something on it, adds advice:
    /// a proxy or firewall that keeps the rotate request from the server holds the Mac's
    /// reports until it lets it through.
    private func holding(
        _ detail: String, _ pending: PendingRotation? = nil, onTheWay: Bool = false
    ) -> RotationOutcome {
        let t = now()
        if lastHoldingLog.map({ t.timeIntervalSince($0) >= 3600 || t < $0 }) ?? true {
            lastHoldingLog = t
            let advice = "If this goes on, check that the whole of /v1/agent/ reaches the server"
            let answer = onTheWay ? "\(detail)\(detail.hasSuffix(".") ? "" : ".") \(advice)" : detail
            log("the rotation's outcome is not known yet; holding requests until the server answers (\(answer))")
            if let pending { noteAnswer(pending, answer, at: t) }
        }
        return .unknown
    }

    /// Saves `answer` with the saved rotation, if it still holds `pending`'s key. Only for
    /// `altiward-agent status`, so a failure changes nothing.
    private func noteAnswer(_ pending: PendingRotation, _ answer: String, at: Date) {
        try? store.transaction {
            guard let raw = try store.value(forKey: PendingRotation.storeKey),
                var saved = try? JSONDecoder().decode(PendingRotation.self, from: Data(raw.utf8)),
                saved.privateKey == pending.privateKey
            else { return }
            // Whatever answered wrote part of it, and `status` prints it to a terminal.
            saved.lastAnswer = String(
                String.UnicodeScalarView(answer.unicodeScalars.map { $0.properties.generalCategory == .control ? " " : $0 }))
            saved.lastAnswerAt = at
            try store.setValue(Self.encode(saved), forKey: PendingRotation.storeKey)
        }
    }

    private struct Proven: Sendable {
        let publicKey: Data
        let proof: Data
    }

    // Static and async, so the Secure Enclave's calls run off the actor.
    private static func makeKey(_ keys: any DeviceKeys, _ storage: KeyStorage) async throws -> Data {
        try keys.makeKey(storage)
    }

    private static func prove(
        _ keys: any DeviceKeys, key: Data, storage: KeyStorage, deviceID: String
    ) async throws -> Proven {
        let publicKey = try keys.publicKey(key, storage)
        let statement = RotationProof.statement(deviceID: deviceID, newPublicKey: publicKey)
        return Proven(publicKey: publicKey, proof: try keys.sign(Data(statement.utf8), key: key, storage))
    }

    private static func secureEnclaveWorks(_ keys: any DeviceKeys) async -> Bool {
        (try? keys.sign(Data("altiward-key-check".utf8), key: keys.makeKey(.secureEnclave), .secureEnclave)) != nil
    }

    private static func encode(_ pending: PendingRotation) throws -> String {
        String(decoding: try JSONEncoder().encode(pending), as: UTF8.self)
    }

    private static func excerpt(_ data: Data) -> String {
        String(String(decoding: data, as: UTF8.self).prefix(200))
    }

    /// When the saved rotation began (when its key was made), if there is one. A record
    /// that doesn't decode still counts, from now.
    private func pendingSince() throws -> Date? {
        guard let raw = try store.value(forKey: PendingRotation.storeKey) else { return nil }
        return (try? JSONDecoder().decode(PendingRotation.self, from: Data(raw.utf8)))?.madeAt ?? now()
    }

    /// Throws while a rotation is saved: nothing may sign with, discard or replace the
    /// key it is replacing. Called inside store transactions.
    private func refuseWhileRotating() throws {
        if let since = try pendingSince() { throw DeviceKeyError.rotationInProgress(since: since) }
    }

    // MARK: Enrolling

    private func enrolled() async throws -> Stored {
        if role == .command, let since = try pendingSince() { throw DeviceKeyError.rotationInProgress(since: since) }
        let info = device()
        var c = try boundToThisMac(info) ?? makeCredential(info)
        if role == .command, c.storage == .secureEnclave { throw DeviceKeyError.heldByDaemon }
        if c.credential.deviceID != nil { return c }
        if let until = enrollNotBefore, now() < until { throw DeliveryError.enrollmentRateLimited(until: until) }

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
        if response.statusCode == 429 {
            let until = now().addingTimeInterval(retryDelay(response.value(forHTTPHeaderField: "Retry-After")))
            enrollNotBefore = until
            log("the server's enrolment limits refused this Mac (\(String(decoding: data, as: UTF8.self).prefix(200))); "
                + "trying again after \(until.formatted(.iso8601))")
            throw DeliveryError.enrollmentRateLimited(until: until)
        }
        guard response.statusCode == 200 || response.statusCode == 201 else {
            throw DeliveryError.http(status: response.statusCode, body: String(decoding: data, as: UTF8.self))
        }
        enrollNotBefore = nil
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
        c.credential.publicKey = publicKey
        try store.transaction {
            // Unless another process has replaced the key meanwhile.
            if try record(c.storage)?.privateKey == c.credential.privateKey { try save(c) }
        }
        return c
    }

    /// How long a refused enrolment waits: `Retry-After` in seconds or as a date by the
    /// server's clock, an hour when it's missing or unreadable, and at most a day.
    private func retryDelay(_ retryAfter: String?) -> TimeInterval {
        let value = retryAfter?.trimmingCharacters(in: .whitespaces) ?? ""
        var delay: TimeInterval = 3600
        if !value.isEmpty, value.allSatisfy({ ("0"..."9").contains($0) }), let seconds = TimeInterval(value) {
            delay = seconds
        } else if let date = Self.parseHTTPDate(value) {
            delay = date.timeIntervalSince(serverNow())
        }
        return min(max(delay, 0), 86400)
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
            try refuseWhileRotating()
            let fresh = Stored(
                credential: Credential(
                    serverURL: serverURL.absoluteString, privateKey: key, serial: info.isReadable ? info.serial : nil,
                    hardwareUUID: info.isReadable ? info.hardwareUUID : nil, madeAt: now()),
                storage: storage)
            try save(fresh)
            // Neither record is for this server, so the other one is for an old one.
            try store.setValue(nil, forKey: Self.storeKey(storage == .software ? .secureEnclave : .software))
            return fresh
        }
    }

    /// The credential for the configured server that was made on this Mac, if any. One
    /// made on another Mac is dropped, so the Mac enrols its own key; one from before
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

    /// Saves the public half of a Secure Enclave key in its record, when a record from
    /// before agent 1.0.0 lacks it, so `status` can show the key's fingerprint. In the
    /// daemon, the only process that can use the key. A file key's needs no record: a
    /// command works it out from the key.
    private func recordPublicKey(_ c: Stored) {
        guard role == .daemon, c.storage == .secureEnclave, c.credential.publicKey == nil,
            let publicKey = try? keys.publicKey(c.credential.privateKey, c.storage)
        else { return }
        do {
            try store.transaction {
                // Unless another process has replaced the key meanwhile.
                guard var current = try record(c.storage), current.privateKey == c.credential.privateKey,
                    current.publicKey == nil
                else { return }
                current.publicKey = publicKey
                try save(Stored(credential: current, storage: c.storage))
            }
        } catch {
            log("couldn't record this Mac's public key (\(error)); trying again after the next report")
        }
    }

    /// Drops `c`'s record if it still holds `c`'s key. Another process sharing the store
    /// may have enrolled a new key since `c` was loaded; that one stays. Refuses while a
    /// rotation is saved, since its retry needs the old key's identity to stay.
    private func discard(_ c: Stored) throws {
        try store.transaction {
            try refuseWhileRotating()
            if try record(c.storage)?.privateKey == c.credential.privateKey {
                try store.setValue(nil, forKey: Self.storeKey(c.storage))
            }
        }
    }

    /// Drops the stored credential that has `deviceID`, so the next send enrols with a new
    /// key. For when the server says that key belongs to another Mac. Does nothing if no
    /// record has that ID, as when another process sharing the store has already replaced
    /// the credential that was signed with. Waits for a rotation in progress, and refuses
    /// while one is saved.
    public func discardCredential(ifDeviceID deviceID: String) async throws {
        try await admit()
        defer { leave() }
        let discarded = try store.transaction {
            try refuseWhileRotating()
            var found = false
            for storage in [KeyStorage.secureEnclave, .software] where try record(storage)?.deviceID == deviceID {
                try store.setValue(nil, forKey: Self.storeKey(storage))
                found = true
            }
            return found
        }
        if discarded { log("the server says this key belongs to another Mac; enrolling again") }
    }

    /// Whether `code` is the one the server sends when it refuses a rotation with `status`.
    private static func refusesRotation(_ status: Int, code: String?) -> Bool {
        switch (status, code) {
        case (400, "rotation_invalid"), (403, "enrollment_pending"), (409, "key_in_use"),
            (409, "rotation_not_allowed"), (429, "rotation_rate_limited"):
            return true
        default:
            return false
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
