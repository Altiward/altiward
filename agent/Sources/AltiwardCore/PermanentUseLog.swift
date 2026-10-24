import Foundation
import OSLog

/// A use of a permanent admin account that only the unified log shows: a password typed into
/// an authorisation prompt, or `sudo` or `su` by the account. Read from the log's entries, which an
/// admin can't change but the log can age out, so this is corroboration, as utmpx is.
///
/// A sudo record holds the terminal and the user it ran as, never the command or the working
/// directory: those can hold secrets, and aren't fields on this type.
public struct PermanentUseLogRecord: Sendable, Equatable {
    /// `prompt`, `sudo` or `su`.
    public var method: PermanentUseMethod
    /// The permanent admin account: the one whose password was typed, or that sudo or su ran as
    /// or became.
    public var account: String
    /// When the log entry was written.
    public var date: Date
    /// The user whose session it was, for a prompt and `su`; nil when the log doesn't say.
    public var onSessionOf: String?
    /// The authorisation right a prompt asked for.
    public var right: String?
    /// The app a prompt was for, when the log names it.
    public var client: String?
    public var tty: String?
    /// The user sudo ran the command as.
    public var runAs: String?
    /// The address of a remote client, for the methods that have one; none of the shipped
    /// sources do.
    public var remoteHost: String?

    public init(
        method: PermanentUseMethod, account: String, date: Date, onSessionOf: String? = nil, right: String? = nil,
        client: String? = nil, tty: String? = nil, runAs: String? = nil, remoteHost: String? = nil
    ) {
        self.method = method
        self.account = account
        self.date = date
        self.onSessionOf = onSessionOf
        self.right = right
        self.client = client
        self.tty = tty
        self.runAs = runAs
        self.remoteHost = remoteHost
    }

    // MARK: Parsing

    /// authd's line for a password accepted at a prompt: `UID 501 authenticated as user
    /// breakglass (UID 502) for right 'com.apple.ServiceManagement.daemons.modify'`. The
    /// account is the one named; the session is the first UID's user.
    ///
    /// Nil for any other line, for an account approving its own prompt (the sign-in already
    /// covers it) and for the `system.login.*` rights, which the login window and the screen
    /// saver's unlock use.
    public static func parseAuthd(message: String, date: Date, userName: (UInt32) -> String?)
        -> PermanentUseLogRecord?
    {
        guard message.hasPrefix("UID "),
            let middle = message.range(of: " authenticated as user ")
        else { return nil }
        let from = message.index(message.startIndex, offsetBy: 4)
        guard let session = UInt32(message[from..<middle.lowerBound]) else { return nil }
        let afterUser = message[middle.upperBound...]
        guard let uidMark = afterUser.range(of: " (UID ") else { return nil }
        let account = String(afterUser[..<uidMark.lowerBound])
        let afterUID = afterUser[uidMark.upperBound...]
        guard let rightMark = afterUID.range(of: ") for right '"),
            let approver = UInt32(afterUID[..<rightMark.lowerBound])
        else { return nil }
        let afterRight = afterUID[rightMark.upperBound...]
        guard let quote = afterRight.firstIndex(of: "'") else { return nil }
        let right = String(afterRight[..<quote])
        guard !account.isEmpty, !right.isEmpty, session != approver, !right.hasPrefix("system.login.") else {
            return nil
        }
        return PermanentUseLogRecord(
            method: .prompt, account: account, date: date, onSessionOf: userName(session), right: right)
    }

    /// sudo's line for a command it allowed: `breakglass : TTY=ttys003 ; PWD=… ; USER=root ;
    /// COMMAND=…`. Keeps the account, terminal and `USER=`; the rest is dropped as it is read.
    ///
    /// Nil for a refusal (`user NOT in sudoers`, `incorrect password attempts`, `command not
    /// allowed`) and for any other line.
    public static func parseSudo(message: String, date: Date) -> PermanentUseLogRecord? {
        // A refusal puts its reason before TTY= (`user NOT in sudoers ; TTY=…`), so a line
        // that doesn't start with TTY= is skipped. The text isn't searched for the reason: a
        // command could hold it, to keep its own record out.
        let line = message.trimmingCharacters(in: .whitespaces)
        guard let colon = line.range(of: " : ") else { return nil }
        let account = String(line[..<colon.lowerBound])
        guard !account.isEmpty, !account.contains(" ") else { return nil }
        let fields = line[colon.upperBound...]
        guard fields.hasPrefix("TTY=") else { return nil }
        let afterTTY = fields.dropFirst(4)
        guard let ttyEnd = afterTTY.range(of: " ; PWD="), !afterTTY[..<ttyEnd.lowerBound].isEmpty else { return nil }
        let tty = String(afterTTY[..<ttyEnd.lowerBound])
        // USER= follows PWD=; a directory or command can hold the same text, so only the
        // first USER= after PWD= is used and it must look like a name.
        let afterPWD = afterTTY[ttyEnd.upperBound...]
        guard let userMark = afterPWD.range(of: " ; USER=") else { return nil }
        let afterUser = afterPWD[userMark.upperBound...]
        let runAs = String(afterUser[..<(afterUser.range(of: " ; COMMAND=")?.lowerBound ?? afterUser.endIndex)])
        guard !runAs.isEmpty, !runAs.contains(" "), !runAs.contains(";") else { return nil }
        return PermanentUseLogRecord(method: .sudo, account: account, date: date, tty: tty, runAs: runAs)
    }

    /// BSD `su`'s line: `alex to breakglass on /dev/ttys002`. The account is the one
    /// switched to; the session is the caller's. Nil for anything else, such as `BAD SU …`.
    public static func parseSu(message: String, date: Date) -> PermanentUseLogRecord? {
        let words = message.split(separator: " ", omittingEmptySubsequences: true)
        guard words.count == 5, words[1] == "to", words[3] == "on", words[4].hasPrefix("/dev/"),
            words[4].count > 5
        else { return nil }
        return PermanentUseLogRecord(
            method: .su, account: String(words[2]), date: date, onSessionOf: String(words[0]),
            tty: String(words[4].dropFirst(5)))
    }

    /// How long after a prompt's line authd may log the line that names the app.
    static let clientWindow: TimeInterval = 5

    /// authd's lines in the order logged, as (date, message), turned into prompt records. Each
    /// record's `client` comes from the first `Succeeded authorizing right '<right>' by client
    /// '<path>' …` line for the same right, from the prompt's own time to ``clientWindow`` after
    /// it; nil when there isn't one.
    public static func prompts(
        from authd: [(date: Date, message: String)], userName: (UInt32) -> String?
    ) -> [PermanentUseLogRecord] {
        authd.compactMap { entry in
            guard var record = parseAuthd(message: entry.message, date: entry.date, userName: userName),
                let right = record.right
            else { return nil }
            let deadline = entry.date.addingTimeInterval(clientWindow)
            record.client =
                authd.lazy
                .filter { $0.date >= entry.date && $0.date <= deadline }
                .compactMap { authorizedClient($0.message, right: right) }.first
            return record
        }
    }

    /// The path in `Succeeded authorizing right 'system.preferences' by client
    /// '/Applications/Foo.app' [2650] for authorization created by …`, when it is for `right`.
    static func authorizedClient(_ message: String, right: String) -> String? {
        let head = "Succeeded authorizing right '\(right)' by client '"
        guard message.hasPrefix(head) else { return nil }
        let rest = message.dropFirst(head.count)
        // The path can hold spaces; the next field is its pid in brackets.
        guard let end = rest.range(of: "' [")?.lowerBound ?? rest.firstIndex(of: "'") else { return nil }
        let path = String(rest[..<end])
        return path.isEmpty ? nil : path
    }

    /// Whether `other` differs from this record in nothing but its time.
    func sameUse(as other: PermanentUseLogRecord) -> Bool {
        var same = other
        same.date = date
        return self == same
    }

    /// One line as `altiward-agent permanent-uses` prints it.
    public var summary: String {
        var parts = ["\(AltiwardJSON.format(date))", method.rawValue, account]
        if let tty { parts.append("tty=\(tty)") }
        if let runAs { parts.append("as=\(runAs)") }
        if let onSessionOf { parts.append("session of \(onSessionOf)") }
        if let right { parts.append("right=\(right)") }
        if let client { parts.append("for \(client)") }
        return parts.joined(separator: "  ")
    }
}

/// Reads the records from the unified log, one query for the three processes. Needs root,
/// which the daemon has. Without it, or on a Mac whose log keeps no sudo or su lines, it
/// returns what it finds, which can be nothing.
public enum PermanentUseLog {
    static let processes = ["authd", "sudo", "su"]

    /// Records logged since `since`, oldest first. Empty when the log can't be read.
    public static func records(since: Date) -> [PermanentUseLogRecord] {
        guard let store = try? OSLogStore(scope: .system) else { return [] }
        let predicate = NSPredicate(format: "process IN %@", processes)
        guard
            let entries = try? store.getEntries(at: store.position(date: since), matching: predicate)
        else { return [] }

        var authd: [(date: Date, message: String)] = []
        var records: [PermanentUseLogRecord] = []
        for case let entry as OSLogEntryLog in entries {
            // The position is approximate: it can start a little before `since`.
            guard entry.date >= since else { continue }
            switch entry.process {
            case "authd": authd.append((entry.date, entry.composedMessage))
            case "sudo":
                if let r = PermanentUseLogRecord.parseSudo(message: entry.composedMessage, date: entry.date) {
                    records.append(r)
                }
            case "su":
                if let r = PermanentUseLogRecord.parseSu(message: entry.composedMessage, date: entry.date) {
                    records.append(r)
                }
            default: break
            }
        }
        records += PermanentUseLogRecord.prompts(from: authd, userName: localUserName)
        return records.sorted { $0.date < $1.date }
    }

    /// The short name of a UID, from the directory.
    static func localUserName(_ uid: UInt32) -> String? {
        var entry = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 4096)
        guard getpwuid_r(uid, &entry, &buffer, buffer.count, &result) == 0, result != nil else { return nil }
        return String(cString: entry.pw_name)
    }
}

/// Reading the log in the heartbeat: one `admin.permanent_use` event for each group of uses
/// since the last heartbeat.
extension ElevationTracker {
    static let permanentUseLogCursorKey = "permanent_use_log_reported_until"
    /// Uses reported per heartbeat, one event for each account, method and so on; any more
    /// are counted in the last event's `truncated`.
    static let maxPermanentUseLogEvents = 20

    /// How far back before the last heartbeat the read starts, so a record logged as the last
    /// one ended isn't missed; the cursor stops it being reported twice.
    var permanentUseLogLookback: TimeInterval { env.config.heartbeatInterval + 60 }

    /// Where the heartbeat starts reading the log: from where the last one stopped, so uses
    /// while the daemon was stopped are still reported, but never more than a day back.
    func permanentUseLogStart(now: Date) throws -> Date {
        try cursorStart(key: Self.permanentUseLogCursorKey, lookback: permanentUseLogLookback, now: now)
    }

    /// Runs inside the heartbeat's transaction. Reports the permanent admins' uses logged
    /// after the last heartbeat's `now` and up to this one's, so each is reported once;
    /// anything logged after `now` waits for the next heartbeat.
    func permanentUseLogEvents(_ records: [PermanentUseLogRecord], now: Date, device: DeviceInfo) throws
        -> [AltiwardEvent]
    {
        let reported = try store.value(forKey: Self.permanentUseLogCursorKey).flatMap(AltiwardJSON.parse)
        try store.setValue(AltiwardJSON.format(now), forKey: Self.permanentUseLogCursorKey)

        // Uses that differ in nothing but their time are one group: a script running sudo
        // hundreds of times sends one event.
        struct Group {
            var first: PermanentUseLogRecord
            var last: Date
            var count: Int
        }
        var groups: [Group] = []
        let fresh = records.filter { record in
            record.date <= now && (reported.map { record.date > $0 } ?? true)
                && env.config.permanentAdmins.contains(record.account)
        }
        for record in fresh.sorted(by: { $0.date < $1.date }) {
            if let i = groups.firstIndex(where: { $0.first.sameUse(as: record) }) {
                groups[i].last = record.date
                groups[i].count += 1
            } else {
                groups.append(Group(first: record, last: record.date, count: 1))
            }
        }

        let listed = groups.prefix(Self.maxPermanentUseLogEvents)
        return listed.enumerated().map { index, group in
            let r = group.first
            var detail: [String: JSONValue] = [
                "use_id": .string(newID()), "method": .string(r.method.rawValue), "state": "single",
                "source": "unified_log", "started": .date(r.date), "count": .number(Double(group.count)),
                "last": .date(group.last),
            ]
            switch r.method {
            case .prompt:
                detail["on_session_of"] = .optional(r.onSessionOf)
                detail["right"] = .optional(r.right)
                detail["client"] = .optional(r.client)
            case .sudo:
                detail["tty"] = .optional(r.tty)
                detail["run_as"] = .optional(r.runAs)
            case .su:
                detail["tty"] = .optional(r.tty)
                detail["on_session_of"] = .optional(r.onSessionOf)
            case .ssh, .screenSharing:
                detail["remote_host"] = .optional(r.remoteHost)
            case .console, .terminal:
                break
            }
            if index == listed.count - 1, groups.count > listed.count {
                detail["truncated"] = .number(Double(groups.count - listed.count))
            }
            return permanentUseEvent(r.account, detail: detail, now: now, device: device)
        }
    }
}
