import CryptoKit
import Darwin
import Foundation

/// Persistence detection: what an elevation window left behind. The daemon snapshots the places where
/// admin rights are used to stay on a Mac, and reports what is new or changed since the
/// last snapshot as `persistence.detected`. None of it needs Endpoint Security.
/// The raw values are the wire names in `detail.findings[].kind`.
public enum PersistenceKind: String, Codable, Sendable, Comparable {
    case launchDaemon = "launch_daemon"
    case launchAgent = "launch_agent"
    case sudoers
    case sshAuthorizedKey = "ssh_authorized_key"
    case localAccount = "local_account"
    case remoteAccess = "remote_access"

    public static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
}

/// One thing in a snapshot.
public struct PersistenceItem: Codable, Sendable, Equatable {
    public var kind: PersistenceKind
    /// Unique within its kind: a path, an account name, a service, or a path and key.
    public var id: String
    /// Where it was read from. When that place can't be read, the last snapshot's items
    /// from it are kept rather than treated as gone.
    public var location: String
    /// Changes whenever the item does.
    public var digest: String
    /// What a finding reports about it.
    public var fields: [String: JSONValue]
    /// A sudoers file's rules, so a finding can report only the lines that are new.
    public var lines: [String]?

    public init(
        kind: PersistenceKind, id: String, location: String, digest: String, fields: [String: JSONValue],
        lines: [String]? = nil
    ) {
        self.kind = kind
        self.id = id
        self.location = location
        self.digest = digest
        self.fields = fields
        self.lines = lines
    }

    var key: String { "\(kind.rawValue):\(id)" }
}

public struct PersistenceSnapshot: Sendable, Equatable {
    public var items: [PersistenceItem]
    /// Places that exist but couldn't be read, such as a home folder privacy protection
    /// covers. Reported in `agent.health` as `persistence_unreadable`.
    public var unreadable: [String]

    public init(items: [PersistenceItem], unreadable: [String] = []) {
        self.items = items
        self.unreadable = unreadable
    }
}

/// A local account, as the directory reports it.
public struct LocalAccount: Sendable, Equatable {
    public var name: String
    public var uid: UInt32
    public var home: String
    /// Whether it is in the `admin` group, or nil when that wasn't checked.
    public var admin: Bool?

    public init(name: String, uid: UInt32, home: String, admin: Bool? = nil) {
        self.name = name
        self.uid = uid
        self.home = home
        self.admin = admin
    }
}

/// Reads the persistence locations. Paths are resolved under `root`, so tests can use a
/// temporary folder; item ids and findings always carry the real absolute path.
public struct PersistenceSources: Sendable {
    public var root: URL
    public var accounts: @Sendable () -> [LocalAccount]
    /// The remote access services switched on (`remote_login`, `screen_sharing`), or nil
    /// when launchd couldn't be asked.
    public var remoteAccess: @Sendable () -> Set<String>?

    public init(
        root: URL, accounts: @escaping @Sendable () -> [LocalAccount],
        remoteAccess: @escaping @Sendable () -> Set<String>?
    ) {
        self.root = root
        self.accounts = accounts
        self.remoteAccess = remoteAccess
    }

    public static func live() -> PersistenceSources {
        PersistenceSources(
            root: URL(fileURLWithPath: "/"),
            accounts: {
                let admins = SystemAdminGroup()
                return Self.localAccounts().map { account in
                    var account = account
                    account.admin = admins.isAdmin(user: account.name)
                    return account
                }
            },
            remoteAccess: { Self.launchdRemoteAccess() })
    }

    /// Caps that keep one finding small: a launch item's arguments and a sudoers file's
    /// rules are reported, but not without limit.
    static let maxText = 512
    static let maxFileBytes = 1 << 20
    static let maxList = 16
    static let remoteAccessLocation = "launchctl print-disabled system"

    public func snapshot() -> PersistenceSnapshot {
        var items: [PersistenceItem] = []
        var unreadable: [String] = []
        let accounts = accounts()

        for account in accounts {
            // Admin membership is reported but not part of the digest: someone given admin
            // rights is an elevation, not a changed account.
            var fields: [String: JSONValue] = ["name": .string(account.name), "uid": .number(Double(account.uid))]
            if let admin = account.admin { fields["admin"] = .bool(admin) }
            items.append(
                PersistenceItem(
                    kind: .localAccount, id: account.name, location: "accounts", digest: String(account.uid),
                    fields: fields))
        }

        launchItems(.launchDaemon, in: "/Library/LaunchDaemons", user: nil, into: &items, unreadable: &unreadable)
        launchItems(.launchAgent, in: "/Library/LaunchAgents", user: nil, into: &items, unreadable: &unreadable)
        // Root's home and every human account's: their LaunchAgents and SSH keys.
        for account in accounts where account.uid == 0 || (account.uid >= 500 && !account.name.hasPrefix("_")) {
            guard account.home.hasPrefix("/"), account.home != "/var/empty" else { continue }
            launchItems(
                .launchAgent, in: account.home + "/Library/LaunchAgents", user: account.name, into: &items,
                unreadable: &unreadable)
            for file in ["authorized_keys", "authorized_keys2"] {
                sshKeys(at: account.home + "/.ssh/" + file, user: account.name, into: &items, unreadable: &unreadable)
            }
        }

        sudoers(at: "/etc/sudoers", into: &items, unreadable: &unreadable)
        if let names = list("/etc/sudoers.d", unreadable: &unreadable) {
            for name in names { sudoers(at: "/etc/sudoers.d/" + name, into: &items, unreadable: &unreadable) }
        }

        if let services = remoteAccess() {
            for service in services.sorted() {
                items.append(
                    PersistenceItem(
                        kind: .remoteAccess, id: service, location: Self.remoteAccessLocation, digest: "on",
                        fields: ["service": .string(service)]))
            }
        } else {
            unreadable.append(Self.remoteAccessLocation)
        }
        return PersistenceSnapshot(items: items, unreadable: unreadable)
    }

    private func url(_ path: String) -> URL { root.appendingPathComponent(path) }

    /// The names in a folder, sorted, or nil when it's missing or unreadable.
    private func list(_ dir: String, unreadable: inout [String]) -> [String]? {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url(dir).path, isDirectory: &isDir), isDir.boolValue else {
            return nil
        }
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: url(dir).path) else {
            unreadable.append(dir)
            return nil
        }
        return names.filter { !$0.hasPrefix(".") }.sorted()
    }

    /// A file's contents, or nil when it's missing or unreadable. Some are in users' home
    /// folders, so a pipe or device there counts as unreadable rather than being read.
    private func read(_ path: String, unreadable: inout [String]) -> Data? {
        switch UntrustedFile.read(url(path).path, maxBytes: Self.maxFileBytes) {
        case .missing: return nil
        case .unreadable:
            unreadable.append(path)
            return nil
        case .data(let data): return data
        }
    }

    private func launchItems(
        _ kind: PersistenceKind, in dir: String, user: String?, into items: inout [PersistenceItem],
        unreadable: inout [String]
    ) {
        guard let names = list(dir, unreadable: &unreadable) else { return }
        for name in names where name.hasSuffix(".plist") {
            let path = dir + "/" + name
            guard let data = read(path, unreadable: &unreadable) else { continue }
            let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
            let arguments = (plist?["ProgramArguments"] as? [String]) ?? []
            var fields: [String: JSONValue] = [
                "path": .string(path),
                "label": .optional((plist?["Label"] as? String).map(Self.clip)),
                "program": .optional(((plist?["Program"] as? String) ?? arguments.first).map(Self.clip)),
                "arguments": .strings(arguments.prefix(Self.maxList).map(Self.clip)),
            ]
            if let user { fields["user"] = .string(user) }
            items.append(
                PersistenceItem(kind: kind, id: path, location: dir, digest: Self.sha256(data), fields: fields))
        }
    }

    private func sshKeys(
        at path: String, user: String, into items: inout [PersistenceItem], unreadable: inout [String]
    ) {
        guard let data = read(path, unreadable: &unreadable) else { return }
        var seen = Set<String>()
        for line in String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline) {
            guard let key = Self.publicKey(in: String(line)), seen.insert(key.fingerprint).inserted else { continue }
            items.append(
                PersistenceItem(
                    kind: .sshAuthorizedKey, id: path + "#" + key.fingerprint, location: path,
                    digest: key.fingerprint,
                    fields: [
                        "path": .string(path), "user": .string(user), "key_type": .string(key.type),
                        "fingerprint": .string(key.fingerprint),
                    ]))
        }
    }

    private func sudoers(at path: String, into items: inout [PersistenceItem], unreadable: inout [String]) {
        guard let data = read(path, unreadable: &unreadable) else { return }
        items.append(
            PersistenceItem(
                kind: .sudoers, id: path, location: path, digest: Self.sha256(data), fields: ["path": .string(path)],
                lines: Self.sudoersRules(String(decoding: data, as: UTF8.self))))
    }

    /// The lines sudo acts on: everything but blanks and comments. `#include` and
    /// `#includedir` look like comments but are directives, so they count.
    static func sudoersRules(_ text: String) -> [String] {
        text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && (!$0.hasPrefix("#") || $0.hasPrefix("#include")) }
    }

    /// The type and OpenSSH-style SHA-256 fingerprint of the key on an authorized_keys
    /// line. Options before the key are skipped; the comment after it is not read.
    static func publicKey(in line: String) -> (type: String, fingerprint: String)? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }
        let tokens = trimmed.split(whereSeparator: \.isWhitespace).map(String.init)
        for (i, token) in tokens.enumerated().dropLast()
        where token.hasPrefix("ssh-") || token.hasPrefix("ecdsa-sha2-") || token.hasPrefix("sk-") {
            guard let blob = Data(base64Encoded: tokens[i + 1]) else { continue }
            let digest = Data(SHA256.hash(data: blob)).base64EncodedString()
            return (token, "SHA256:" + digest.replacingOccurrences(of: "=", with: ""))
        }
        return nil
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func clip(_ s: String) -> String {
        s.count <= maxText ? s : String(s.prefix(maxText)) + "…"
    }

    /// Every account in the directory, system ones included: a new hidden account is
    /// as much a way back in as a new admin.
    static func localAccounts() -> [LocalAccount] {
        var accounts: [LocalAccount] = []
        // getpwent is not thread-safe; share the admin group reader's lock.
        directoryLock.lock()
        defer { directoryLock.unlock() }
        setpwent()
        while let pw = getpwent() {
            accounts.append(
                LocalAccount(
                    name: String(cString: pw.pointee.pw_name), uid: pw.pointee.pw_uid,
                    home: String(cString: pw.pointee.pw_dir)))
        }
        endpwent()
        return accounts
    }

    /// Remote Login and Screen Sharing are switched on and off with launchd overrides.
    static func launchdRemoteAccess() -> Set<String>? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print-disabled", "system"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return nil
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        return remoteAccess(fromPrintDisabled: String(decoding: data, as: UTF8.self))
    }

    static let remoteAccessServices = ["com.openssh.sshd": "remote_login", "com.apple.screensharing": "screen_sharing"]

    /// Parses `launchctl print-disabled system`: `"label" => enabled` or `=> disabled`, and
    /// on older macOS `=> false` (not disabled) or `=> true`. A service with no override is
    /// off, which is the default for both.
    static func remoteAccess(fromPrintDisabled output: String) -> Set<String> {
        var on = Set<String>()
        for line in output.split(whereSeparator: \.isNewline) {
            let parts = line.components(separatedBy: "=>")
            guard parts.count == 2 else { continue }
            let label = parts[0].trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            let state = parts[1].trimmingCharacters(in: .whitespaces)
            if let service = remoteAccessServices[label], state == "enabled" || state == "false" { on.insert(service) }
        }
        return on
    }
}

/// The last snapshot, kept in the agent store: what it saw, and which sessions were open
/// when it was taken. Changes found at the next check happened while those sessions were
/// open, so they are reported on them.
struct PersistenceBaseline: Codable {
    struct SessionRef: Codable, Equatable {
        var user: String
        var sessionID: String
        var source: ElevationSource
    }

    var takenAt: Date
    var items: [PersistenceItem]
    var sessions: [SessionRef]
    var unreadable: [String]
}

extension ElevationTracker {
    static let persistenceKey = "persistence_baseline"
    /// Findings beyond this many bytes are counted in `truncated` instead of sent, so an
    /// event stays well inside the API's 64 KiB limit for `detail`.
    static let findingsBudget = 32 << 10

    /// Takes a snapshot and reports what changed since the last one on every session that
    /// was open in between: the ones open at the last snapshot, and out-of-band sessions
    /// found since, whose rights were there before the heartbeat saw them. Changes while no
    /// session was open are taken in silently, so software the MDM installs isn't reported.
    ///
    /// Run it after anything that opens or closes a session, and on the heartbeat. Run
    /// right after an open, it gives the new session a clean start; after a close, it gives
    /// the ended session the changes up to its end. The baseline survives a restart, so a
    /// session that ended while the daemon wasn't running still gets its changes, with
    /// `since` saying how wide the window was.
    @discardableResult
    public func checkPersistence() throws -> [AltiwardEvent] {
        guard let read = env.persistence else { return [] }
        // One check at a time: an older snapshot must never overwrite a newer baseline.
        persistenceLock.lock()
        defer { persistenceLock.unlock() }
        let snapshot = read()
        let now = env.now()
        let device = env.device()

        return try store.transaction {
            let open = try store.openSessions()
            let baseline = try store.value(forKey: Self.persistenceKey)
                .flatMap { try? AltiwardJSON.decoder().decode(PersistenceBaseline.self, from: Data($0.utf8)) }

            var items = snapshot.items
            if let baseline {
                // Keep what an unreadable place held last time, so it isn't reported again
                // once that place can be read.
                let unreadable = Set(snapshot.unreadable)
                items += baseline.items.filter { unreadable.contains($0.location) }
            }

            var events: [AltiwardEvent] = []
            if let baseline {
                let (findings, truncated) = Self.persistenceFindings(from: baseline.items, to: items)
                if !findings.isEmpty {
                    let known = Set(baseline.sessions.map(\.sessionID))
                    let sessions =
                        baseline.sessions
                        + open.filter { $0.source == .outOfBand && !known.contains($0.sessionID) }.map(Self.ref)
                    for session in sessions {
                        events.append(
                            AltiwardEvent(
                                type: .persistenceDetected, sessionID: session.sessionID, timestamp: now,
                                device: device,
                                user: UserInfo(localName: session.user, upn: env.config.upn(for: session.user)),
                                elevation: ElevationInfo(source: session.source),
                                detail: [
                                    "findings": .array(findings), "since": .date(baseline.takenAt),
                                    "truncated": .number(Double(truncated)),
                                ]))
                    }
                }
            }

            let next = PersistenceBaseline(
                takenAt: now, items: items, sessions: open.map(Self.ref), unreadable: snapshot.unreadable)
            try store.setValue(
                String(decoding: try AltiwardJSON.encoder().encode(next), as: UTF8.self), forKey: Self.persistenceKey)
            for event in events { try store.enqueue(event, now: now) }
            return events
        }
    }

    /// The places the last check couldn't read, for `agent.health`; nil before the first.
    func persistenceUnreadable() throws -> [String]? {
        guard env.persistence != nil else { return nil }
        return try lastPersistenceCheck()?.unreadable
    }

    /// When the last snapshot was taken and what it couldn't read, for `status`.
    public func lastPersistenceCheck() throws -> (takenAt: Date, unreadable: [String])? {
        try store.value(forKey: Self.persistenceKey)
            .flatMap { try? AltiwardJSON.decoder().decode(PersistenceBaseline.self, from: Data($0.utf8)) }
            .map { ($0.takenAt, $0.unreadable) }
    }

    private static func ref(_ s: OpenSession) -> PersistenceBaseline.SessionRef {
        .init(user: s.user, sessionID: s.sessionID, source: s.source)
    }

    /// What is new or changed in `current`, in a stable order, within ``findingsBudget``.
    /// Removals are not findings: taking something away doesn't keep anyone in. A sudoers
    /// file that only lost lines isn't one either.
    static func persistenceFindings(from baseline: [PersistenceItem], to current: [PersistenceItem]) -> (
        findings: [JSONValue], truncated: Int
    ) {
        let before = Dictionary(baseline.map { ($0.key, $0) }, uniquingKeysWith: { _, last in last })
        var all: [JSONValue] = []
        for item in current.sorted(by: { ($0.kind, $0.id) < ($1.kind, $1.id) }) {
            let old = before[item.key]
            guard old?.digest != item.digest else { continue }
            var finding = item.fields
            finding["kind"] = .string(item.kind.rawValue)
            finding["change"] = old == nil ? "added" : "modified"
            if let lines = item.lines {
                let had = Set(old?.lines ?? [])
                let added = lines.filter { !had.contains($0) }
                guard !added.isEmpty else { continue }
                finding["added_lines"] = .strings(
                    added.prefix(PersistenceSources.maxList).map(PersistenceSources.clip))
            }
            all.append(.object(finding))
        }

        let encoder = AltiwardJSON.encoder()
        var kept: [JSONValue] = []
        var bytes = 0
        for finding in all {
            bytes += (try? encoder.encode(finding).count) ?? PersistenceSources.maxText
            guard bytes <= findingsBudget else { break }
            kept.append(finding)
        }
        return (kept, all.count - kept.count)
    }
}
