import Foundation
import OSLog

/// What SAP Privileges' system extension writes to the unified log (Privileges 2.6+, with
/// `EnableSystemExtension` on macOS 14+): each change to the `admin` group, by any process,
/// and each attempt on Privileges it blocked, with the process responsible. Altiward reads it
/// to say who made admin rights nobody granted, and to report blocked tampering, which
/// Privileges keeps on the Mac. Only read: without the extension there is nothing to read,
/// and everything else works as before.
public struct PrivilegesAuditRecord: Sendable, Equatable {
    /// `ADMIN_ADD` and `ADMIN_REMOVE` for the admin group; `DELETE`, `RENAME`, `CLONE`,
    /// `CREATE` and `EXEC` (unloading its launchd items) for attempts it blocked.
    public var eventType: String
    /// The account or group for an admin change; the item's path for a blocked attempt.
    public var subject: String
    /// When the extension logged it.
    public var date: Date
    /// The process that made the change or the attempt; nil when Endpoint Security didn't
    /// say.
    public var process: Instigator?
    /// The pid of the process that wrote the log entry (the extension, if the entry is
    /// genuine), as the log reports it; 0 when unknown. Evidence checks it against the
    /// extension's code signature, so a forged entry from another process doesn't count.
    public var loggerPID: Int32

    public struct Instigator: Sendable, Equatable {
        public var executable: String
        public var signingID: String
        public var teamID: String
        public var platformBinary: Bool
        public var pid: Int
        public var ppid: Int
        public var tty: String

        /// As it goes in an event's detail.
        public var json: JSONValue {
            [
                "executable": .string(executable), "signing_id": .string(signingID), "team_id": .string(teamID),
                "platform_binary": .bool(platformBinary), "pid": .number(Double(pid)), "ppid": .number(Double(ppid)),
                "tty": .string(tty),
            ]
        }
    }

    public var isAdminAdd: Bool { eventType == "ADMIN_ADD" }
    public var isBlocked: Bool { Self.blockedTypes.contains(eventType) }

    static let blockedTypes: Set<String> = ["DELETE", "RENAME", "CLONE", "CREATE", "EXEC"]

    public init(eventType: String, subject: String, date: Date, process: Instigator?, loggerPID: Int32 = 0) {
        self.eventType = eventType
        self.subject = subject
        self.date = date
        self.process = process
        self.loggerPID = loggerPID
    }

    /// One of the extension's JSON log messages, or nil for anything else (each change is
    /// also logged as a sentence, which this skips). An admin change names the account in
    /// `privileges.id`; a blocked attempt names the item in `privileges.subject`.
    public static func parse(message: String, date: Date) -> PrivilegesAuditRecord? {
        guard message.hasPrefix("{"),
            let root = try? JSONSerialization.jsonObject(with: Data(message.utf8)) as? [String: Any],
            let privileges = root["privileges"] as? [String: Any],
            let eventType = privileges["event_type"] as? String, !eventType.isEmpty
        else { return nil }
        let subject =
            eventType.hasPrefix("ADMIN_")
            ? privileges["id"] as? String : privileges["subject"] as? String
        guard let subject, !subject.isEmpty else { return nil }

        var instigator: Instigator?
        if let process = (root["esf"] as? [String: Any])?["process"] as? [String: Any],
            let executable = process["executable"] as? String, !executable.isEmpty
        {
            instigator = Instigator(
                executable: executable,
                signingID: process["signing_id"] as? String ?? "",
                teamID: process["team_id"] as? String ?? "",
                platformBinary: process["is_platform_binary"] as? Bool ?? false,
                pid: process["pid"] as? Int ?? 0,
                ppid: process["ppid"] as? Int ?? 0,
                tty: process["tty"] as? String ?? "")
        }
        return PrivilegesAuditRecord(eventType: eventType, subject: subject, date: date, process: instigator)
    }

    /// Words for a blocked attempt, as in Privileges' own log ("Prevented deletion of…").
    var blockedAction: String {
        switch eventType {
        case "DELETE": return "delete"
        case "RENAME": return "rename"
        case "CLONE": return "clone"
        case "CREATE": return "create an item in"
        case "EXEC": return "unload"
        default: return eventType.lowercased()
        }
    }
}

/// Reads the extension's records from the unified log, as Privileges' own helper does for
/// `PrivilegesCLI --history`. Needs root, which the daemon has; the JSON records carry no
/// time of their own, so the log entry's date is used.
public enum PrivilegesAuditLog {
    static let process = "corp.sap.privileges.extension"
    static let subsystem = "com.apple.defaults"
    static let category = "audit"

    /// Records logged since `since`, oldest first. Empty when the log can't be read or the
    /// extension wrote nothing.
    public static func records(since: Date) -> [PrivilegesAuditRecord] {
        guard let store = try? OSLogStore(scope: .system) else { return [] }
        let predicate = NSPredicate(
            format: "process == %@ AND subsystem == %@ AND category == %@", process, subsystem, category)
        guard
            let entries = try? store.getEntries(
                at: store.position(date: since), matching: predicate)
        else { return [] }
        return entries.compactMap { entry -> PrivilegesAuditRecord? in
            // The position is approximate: it can start a little before `since`.
            guard entry.date >= since,
                var record = PrivilegesAuditRecord.parse(message: entry.composedMessage, date: entry.date)
            else { return nil }
            record.loggerPID = (entry as? OSLogEntryFromProcess)?.processIdentifier ?? 0
            return record
        }
    }
}

/// Reads what `PrivilegesDaemon` logged about the changes it made (``PrivilegesDaemonLine``),
/// from the same audit category of the unified log. Needs root, which the daemon has.
public enum PrivilegesDaemonLog {
    static let process = "PrivilegesDaemon"

    /// Lines logged since `since`, oldest first, each with the pid that logged it. Empty when
    /// the log can't be read or the daemon logged nothing. A log store is a snapshot of the
    /// log when it is opened, so each call opens a new one.
    public static func lines(since: Date) -> [PrivilegesDaemonLine] {
        guard let store = try? OSLogStore(scope: .system) else { return [] }
        let predicate = NSPredicate(
            format: "process == %@ AND subsystem == %@ AND category == %@", process, PrivilegesAuditLog.subsystem,
            PrivilegesAuditLog.category)
        guard
            let entries = try? store.getEntries(
                at: store.position(date: since), matching: predicate)
        else { return [] }
        return entries.compactMap { entry -> PrivilegesDaemonLine? in
            // The position is approximate: it can start a little before `since`.
            guard entry.date >= since else { return nil }
            let pid = (entry as? OSLogEntryFromProcess)?.processIdentifier ?? 0
            return PrivilegesDaemonLine.parse(message: entry.composedMessage, date: entry.date, pid: pid)
        }
    }
}

/// Reading the extension's records: the process behind rights nobody granted, and
/// `agent.tamper` for each attempt it blocked.
extension ElevationTracker {
    static let auditCursorKey = "privileges_audit_reported_until"
    /// Blocked attempts reported per heartbeat, one event for each attempt by the same
    /// process on the same item; any more are counted in the last event's `truncated`.
    static let maxBlockedEvents = 20

    /// How far back to look for the change that made someone admin: further than a
    /// heartbeat, so rights the heartbeat finds can still be attributed.
    var auditLookback: TimeInterval { env.config.heartbeatInterval + 10 * 60 }

    /// Where the heartbeat starts reading: from where the last one stopped, so attempts made
    /// while the daemon was stopped are still reported, but never more than a day back, and
    /// always far enough back to attribute admin rights.
    func auditStart(now: Date) throws -> Date {
        try cursorStart(key: Self.auditCursorKey, lookback: auditLookback, now: now)
    }

    /// Where a heartbeat's read of a log starts: `lookback` before `now` when there is no
    /// cursor under `key`, otherwise the earlier of the cursor and that, but never more than
    /// a day back.
    func cursorStart(key: String, lookback: TimeInterval, now: Date) throws -> Date {
        let from = now.addingTimeInterval(-lookback)
        guard let reported = try store.value(forKey: key).flatMap(AltiwardJSON.parse) else { return from }
        return max(now.addingTimeInterval(-86_400), min(reported, from))
    }

    /// The process that most recently added `user` to the admin group, with when the
    /// extension logged it, or nil when the records don't say.
    /// `extension_verified` says whether the record came from the real extension
    /// (``isVerified(_:among:)``); the record counts either way.
    func instigator(of user: String, in records: [PrivilegesAuditRecord]) throws -> JSONValue? {
        guard let add = records.last(where: { $0.isAdminAdd && $0.subject == user }),
            case .object(var fields) = add.process?.json
        else { return nil }
        fields["logged_at"] = .date(add.date)
        fields["extension_verified"] = .bool(Self.isVerified(add, among: try extensionInstances()))
        return .object(fields)
    }

    static let extensionInstancesKey = "privileges_extension_instances"
    /// How many verified extension instances are remembered. The extension restarts rarely,
    /// and a heartbeat reads back at most a day.
    static let maxExtensionInstances = 20

    /// One run of the extension: a pid is reused, so the pid alone doesn't name a process.
    struct ExtensionInstance: Codable, Equatable {
        var pid: Int32
        var startedAt: Date

        enum CodingKeys: String, CodingKey {
            case pid
            case startedAt = "started_at"
        }
    }

    /// The pid and start time of the running extension when it is SAP's: signed by SAP with
    /// the extension's signing ID, and running as root. Nil when none is running or it isn't.
    /// Looks at the process table and its code signature, so call it outside a transaction.
    func verifiedExtensionInstance() -> ExtensionInstance? {
        guard let pid = env.privilegesExtensionPID(), let identity = env.processIdentity(pid),
            identity.isPrivilegesExtension
        else { return nil }
        // Rounded down to the millisecond, as the stored copy is kept to the millisecond: the
        // running process and the remembered instance then compare equal, and a record logged
        // in the same millisecond as the start still follows it.
        let started = (identity.startedAt.timeIntervalSince1970 * 1000).rounded(.down) / 1000
        return ExtensionInstance(pid: pid, startedAt: Date(timeIntervalSince1970: started))
    }

    /// The verified instances seen so far, oldest first; empty when there are none or the
    /// stored list can't be read.
    func extensionInstances() throws -> [ExtensionInstance] {
        guard let raw = try store.value(forKey: Self.extensionInstancesKey),
            let instances = try? AltiwardJSON.decoder().decode([ExtensionInstance].self, from: Data(raw.utf8))
        else { return [] }
        return instances
    }

    /// Remembers `instance`, once, keeping the last ``maxExtensionInstances``. Heartbeat
    /// reads reach back across extension restarts, so an old record is checked against the
    /// instance that wrote it, not only the one running now.
    func noteExtensionInstance(_ instance: ExtensionInstance?) throws {
        guard let instance else { return }
        var instances = try extensionInstances()
        // Compared by the millisecond they are stored to, so the same instance read back
        // from the store is not a new one by a rounding error.
        func millis(_ date: Date) -> Int64 { Int64((date.timeIntervalSince1970 * 1000).rounded()) }
        guard !instances.contains(where: { $0.pid == instance.pid && millis($0.startedAt) == millis(instance.startedAt) })
        else { return }
        instances.append(instance)
        let kept = instances.suffix(Self.maxExtensionInstances)
        let data = try AltiwardJSON.encoder().encode(Array(kept))
        try store.setValue(String(decoding: data, as: UTF8.self), forKey: Self.extensionInstancesKey)
    }

    /// Whether a known extension instance has the record's logger pid and had started by
    /// the time the record was logged. A forged entry from another process, or from a
    /// process that later reused the extension's pid, doesn't match.
    static func isVerified(_ record: PrivilegesAuditRecord, among instances: [ExtensionInstance]) -> Bool {
        instances.contains { $0.pid == record.loggerPID && $0.startedAt <= record.date }
    }

    /// Runs inside the heartbeat's transaction. Reports the attempts logged after the last
    /// heartbeat's `now` and up to this one's, so each is reported once; anything logged
    /// after `now` waits for the next heartbeat.
    func blockedEvents(_ records: [PrivilegesAuditRecord], now: Date, device: DeviceInfo) throws -> [AltiwardEvent] {
        let reported = try store.value(forKey: Self.auditCursorKey).flatMap(AltiwardJSON.parse)
        try store.setValue(AltiwardJSON.format(now), forKey: Self.auditCursorKey)

        let instances = try extensionInstances()
        var groups: [(first: PrivilegesAuditRecord, last: Date, count: Int, verified: Bool)] = []
        for record in records where record.isBlocked && record.date <= now && reported.map({ record.date > $0 }) ?? true {
            if let i = groups.firstIndex(where: {
                $0.first.eventType == record.eventType && $0.first.subject == record.subject
                    && $0.first.process?.executable == record.process?.executable
            }) {
                groups[i].last = record.date
                groups[i].count += 1
                groups[i].verified = groups[i].verified && Self.isVerified(record, among: instances)
            } else {
                groups.append((record, record.date, 1, Self.isVerified(record, among: instances)))
            }
        }

        let listed = groups.prefix(Self.maxBlockedEvents)
        return listed.enumerated().map { index, group in
            let record = group.first
            var problem =
                record.process.map { "SAP Privileges blocked \($0.executable) from trying to \(record.blockedAction) \(record.subject)" }
                ?? "SAP Privileges blocked an attempt to \(record.blockedAction) \(record.subject)"
            if group.count > 1 { problem += " (\(group.count) attempts)" }
            var extra: [String: JSONValue] = [
                "blocked_action": .string(record.eventType), "item": .string(record.subject),
                "instigator": record.process?.json ?? .null, "attempts": .number(Double(group.count)),
                "first_attempt": .date(record.date), "last_attempt": .date(group.last),
                "extension_verified": .bool(group.verified),
            ]
            if index == listed.count - 1, groups.count > listed.count {
                extra["truncated"] = .number(Double(groups.count - listed.count))
            }
            return tamper(
                IntegrityCheck.privilegesBlocked.rawValue, .detected, problem: problem, extra: extra, now: now,
                device: device)
        }
    }
}
