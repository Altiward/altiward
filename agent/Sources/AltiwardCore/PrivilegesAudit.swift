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

    public init(eventType: String, subject: String, date: Date, process: Instigator?) {
        self.eventType = eventType
        self.subject = subject
        self.date = date
        self.process = process
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
        return entries.compactMap { entry in
            // The position is approximate: it can start a little before `since`.
            guard entry.date >= since else { return nil }
            return PrivilegesAuditRecord.parse(message: entry.composedMessage, date: entry.date)
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
    func instigator(of user: String, in records: [PrivilegesAuditRecord]) -> JSONValue? {
        guard let add = records.last(where: { $0.isAdminAdd && $0.subject == user }),
            case .object(var fields) = add.process?.json
        else { return nil }
        fields["logged_at"] = .date(add.date)
        return .object(fields)
    }

    /// Runs inside the heartbeat's transaction. Reports the attempts logged after the last
    /// heartbeat's `now` and up to this one's, so each is reported once; anything logged
    /// after `now` waits for the next heartbeat.
    func blockedEvents(_ records: [PrivilegesAuditRecord], now: Date, device: DeviceInfo) throws -> [AltiwardEvent] {
        let reported = try store.value(forKey: Self.auditCursorKey).flatMap(AltiwardJSON.parse)
        try store.setValue(AltiwardJSON.format(now), forKey: Self.auditCursorKey)

        var groups: [(first: PrivilegesAuditRecord, last: Date, count: Int)] = []
        for record in records where record.isBlocked && record.date <= now && reported.map({ record.date > $0 }) ?? true {
            if let i = groups.firstIndex(where: {
                $0.first.eventType == record.eventType && $0.first.subject == record.subject
                    && $0.first.process?.executable == record.process?.executable
            }) {
                groups[i].last = record.date
                groups[i].count += 1
            } else {
                groups.append((record, record.date, 1))
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
