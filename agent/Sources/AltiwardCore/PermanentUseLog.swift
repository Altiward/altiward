import Foundation
import OSLog

/// A use of a permanent admin account that only the unified log shows: a password typed into
/// an authorisation prompt, or a screen sharing sign-in. Read from the log's entries, which an
/// admin can't change but the log can age out, so this is corroboration, as utmpx is.
///
/// macOS keeps no log line for `sudo` or `su`, or for an SSH file copy or one-off command, so
/// none of them can be read here: they need Endpoint Security.
public struct PermanentUseLogRecord: Sendable, Equatable {
    /// `prompt` or `screen_sharing`.
    public var method: PermanentUseMethod
    /// The permanent admin account: the one whose password was typed. For screen sharing it is
    /// the name the viewer typed, a short name or a full name, until ``resolved(admins:fullName:accountExists:)``
    /// turns it into the short name.
    public var account: String
    /// When the log entry was written.
    public var date: Date
    /// The user whose session it was, for a prompt; nil when the log doesn't say.
    public var onSessionOf: String?
    /// The authorisation right a prompt asked for.
    public var right: String?
    /// The app a prompt was for, when the log names it.
    public var client: String?
    /// The viewer's address, for screen sharing; nil when the log doesn't give one.
    public var remoteHost: String?

    public init(
        method: PermanentUseMethod, account: String, date: Date, onSessionOf: String? = nil, right: String? = nil,
        client: String? = nil, remoteHost: String? = nil
    ) {
        self.method = method
        self.account = account
        self.date = date
        self.onSessionOf = onSessionOf
        self.right = right
        self.client = client
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

    /// screensharingd's line for a viewer that signed in, kept at Default level:
    /// `Authentication: SUCCEEDED :: User Name: breakglass :: Viewer Address: fe80::67:3da0:bab9:1a8e
    /// :: Type: DH`. The account is the User Name, which is what the viewer typed (a short name
    /// or a full name, and not checked here); `remoteHost` is the Viewer Address.
    ///
    /// The line is written when the connection starts for "Log In as Yourself" and when it
    /// closes for "Ask to Share Screen", so its time is the use's, and no end is read.
    ///
    /// Nil for a `FAILED` line, which isn't a use, and for any other line. The address is nil
    /// when it is empty or `<private>`.
    public static func parseScreenSharing(message: String, date: Date) -> PermanentUseLogRecord? {
        let prefix = "Authentication: SUCCEEDED :: User Name: "
        let line = message.trimmingCharacters(in: .whitespaces)
        guard line.hasPrefix(prefix) else { return nil }
        let rest = line.dropFirst(prefix.count)
        // The name is typed by the viewer, so it can hold any text, ` :: ` and a forged
        // `Viewer Address:` included. The address is system text that follows it, so the last
        // marker is the real one and everything before it is the name.
        // No trailing space: the line is trimmed, so an empty address leaves none.
        let marker = " :: Viewer Address:"
        guard let found = rest.range(of: marker, options: .backwards) else { return nil }
        let account = rest[..<found.lowerBound].trimmingCharacters(in: .whitespaces)
        let afterMarker = rest[found.upperBound...]
        let address = String(afterMarker[..<(afterMarker.range(of: " :: ")?.lowerBound ?? afterMarker.endIndex)])
            .trimmingCharacters(in: .whitespaces)
        guard !account.isEmpty else { return nil }
        return PermanentUseLogRecord(
            method: .screenSharing, account: account, date: date,
            remoteHost: address.isEmpty || address == "<private>" ? nil : address)
    }

    /// This record with its account as a permanent admin's short name, or nil when it is none of
    /// them. A prompt names the account exactly. A screen sharing viewer types a short name or
    /// the account's full name, in any case, so it is matched against each admin's short name
    /// first, then its full name (`fullName` gives the directory's), but only when the typed
    /// name isn't the short name of an account (`accountExists`): a non-admin `admin` who signs
    /// in is not the permanent admin whose full name is "Admin".
    public func resolved(
        admins: Set<String>, fullName: (String) -> String?, accountExists: (String) -> Bool
    ) -> PermanentUseLogRecord? {
        guard method == .screenSharing else { return admins.contains(account) ? self : nil }
        let typed = account.lowercased()
        let sorted = admins.sorted()
        guard
            let short = sorted.first(where: { $0.lowercased() == typed })
                ?? (accountExists(account)
                    ? nil
                    : sorted.first(where: {
                        fullName($0)?.trimmingCharacters(in: .whitespaces).lowercased() == typed
                    }))
        else { return nil }
        var record = self
        record.account = short
        return record
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
        if let remoteHost { parts.append("from \(remoteHost)") }
        if let onSessionOf { parts.append("session of \(onSessionOf)") }
        if let right { parts.append("right=\(right)") }
        if let client { parts.append("for \(client)") }
        return parts.joined(separator: "  ")
    }
}

/// Reads the records from the unified log, one query for both processes. Needs root, which
/// the daemon has. Without it it returns what it finds, which can be nothing.
public enum PermanentUseLog {
    static let processes = ["authd", "screensharingd"]

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
            case "screensharingd":
                if let r = PermanentUseLogRecord.parseScreenSharing(message: entry.composedMessage, date: entry.date) {
                    records.append(r)
                }
            default: break
            }
        }
        records += PermanentUseLogRecord.prompts(from: authd, userName: localUserName)
        return records.sorted { $0.date < $1.date }
    }

    /// An account's full name from the directory (`pw_gecos`), nil when it has none.
    public static func fullName(of shortName: String) -> String? {
        var entry = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 4096)
        guard getpwnam_r(shortName, &entry, &buffer, buffer.count, &result) == 0, result != nil,
            let gecos = entry.pw_gecos
        else { return nil }
        let name = String(cString: gecos).trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? nil : name
    }

    /// Whether the directory has an account with this short name.
    public static func accountExists(_ shortName: String) -> Bool {
        var entry = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 4096)
        return getpwnam_r(shortName, &entry, &buffer, buffer.count, &result) == 0 && result != nil
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

        // Uses that differ in nothing but their time are one group: a script that approves
        // hundreds of prompts sends one event.
        struct Group {
            var first: PermanentUseLogRecord
            var last: Date
            var count: Int
        }
        var groups: [Group] = []
        // Screen sharing names the account as the viewer typed it, so it is matched to a
        // permanent admin's short name here, which is also what the event's user is.
        let fresh = records.compactMap { record -> PermanentUseLogRecord? in
            guard record.date <= now, reported.map({ record.date > $0 }) ?? true else { return nil }
            return record.resolved(
                admins: env.config.permanentAdmins, fullName: env.fullName, accountExists: env.accountExists)
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
            case .ssh, .screenSharing:
                detail["remote_host"] = .optional(r.remoteHost)
            case .console, .terminal, .sudo, .su:
                // Sign-ins come from utmpx; the log has no line for sudo or su.
                break
            }
            if index == listed.count - 1, groups.count > listed.count {
                detail["truncated"] = .number(Double(groups.count - listed.count))
            }
            return permanentUseEvent(r.account, detail: detail, now: now, device: device)
        }
    }
}
