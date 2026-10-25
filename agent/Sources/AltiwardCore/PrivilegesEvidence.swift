import Foundation

/// A line `PrivilegesDaemon` wrote to the unified log about a change it made: "SAPCorp: User
/// jdoe now has administrator privileges for the following reason: ..." or "... now has
/// standard user privileges (...)". Only the daemon, which does the change as root, writes
/// them, so a verified one backs a claim that Privileges granted the rights.
public struct PrivilegesDaemonLine: Sendable, Equatable {
    public enum Change: Sendable { case granted, revoked }

    public var user: String
    public var change: Change
    /// When the log entry was written.
    public var date: Date
    /// The pid of the process that wrote it, to verify before the line counts.
    public var loggerPID: Int32

    public init(user: String, change: Change, date: Date, loggerPID: Int32) {
        self.user = user
        self.change = change
        self.date = date
        self.loggerPID = loggerPID
    }

    static let prefix = "SAPCorp: User "
    static let grantedText = " now has administrator privileges"
    static let revokedText = " now has standard user privileges"

    /// The line's user and change, or nil for any other message. Anchored: the message must
    /// start with the prefix, the name is the next run of non-space characters, and the
    /// words after it must follow at once. The reason a user typed comes later in the same
    /// line, so a reason such as "User mallory now has administrator privileges" can never
    /// be read as a line about mallory.
    public static func parse(message: String, date: Date, pid: Int32) -> PrivilegesDaemonLine? {
        guard message.hasPrefix(prefix) else { return nil }
        let rest = message.dropFirst(prefix.count)
        let name = rest.prefix { !$0.isWhitespace }
        guard !name.isEmpty else { return nil }
        let after = rest.dropFirst(name.count)
        let change: Change
        if after.hasPrefix(grantedText) {
            change = .granted
        } else if after.hasPrefix(revokedText) {
            change = .revoked
        } else {
            return nil
        }
        return PrivilegesDaemonLine(user: String(name), change: change, date: date, loggerPID: pid)
    }
}

/// A running process, as the agent verified it: its code signature, when it started, and
/// the user it runs as.
public struct ProcessIdentity: Sendable, Equatable {
    public var signingID: String
    public var teamID: String
    public var startedAt: Date
    /// The uid the process runs as (its effective uid). A process keeps its pid and start
    /// time when it execs another binary, so a user's process could log a forged line and
    /// then exec SAP's genuine one; it can't become root that way, and SAP's daemon and
    /// extension run as root.
    public var uid: UInt32

    public init(signingID: String, teamID: String, startedAt: Date, uid: UInt32) {
        self.signingID = signingID
        self.teamID = teamID
        self.startedAt = startedAt
        self.uid = uid
    }

    /// Whether this is SAP Privileges' system extension: its signing ID, SAP's team, and
    /// running as root.
    public var isPrivilegesExtension: Bool {
        signingID == PrivilegesSigning.systemExtension && teamID == PrivilegesSigning.teamID && uid == 0
    }
}

/// The signing identities of SAP Privileges' processes, pinned one by one: never "any
/// SAP-signed process", because root can run any genuine SAP binary, old helpers included.
public enum PrivilegesSigning {
    static let teamID = "7R5ZEU67FQ"
    static let daemon = "corp.sap.privileges.daemon"
    static let systemExtension = "corp.sap.privileges.extension"
    /// The processes whose `ADMIN_ADD` is a Privileges grant.
    static let grantInstigators: Set<String> = ["corp.sap.privileges.daemon"]
}

/// What backed a grant claim in SAP's own log.
public struct GrantEvidence: Sendable, Equatable {
    public enum Source: String, Sendable {
        case daemon
        case systemExtension = "extension"
    }

    /// When the earliest line used was logged.
    public var date: Date
    public var sources: Set<Source>
    /// One key for each line used (`"<whole milliseconds since 1970>|<logger pid>"`), so a
    /// claim that used them can mark each consumed. Rounded to the millisecond so that the
    /// same entry gives the same key when the log is read again.
    public var keys: Set<String>

    public init(date: Date, sources: Set<Source>, keys: Set<String>) {
        self.date = date
        self.sources = sources
        self.keys = keys
    }
}

/// The rules for what confirms a Privileges grant claim. The hook that makes a claim can be
/// run by hand by any user, so a claim counts only when SAP's own log backs it.
public enum ClaimEvidence {
    /// How far apart a daemon line and an extension record can be and still be one grant.
    static let combineWithin: TimeInterval = 5
    /// How long before a claim arrived its grant's lines may have been logged. Longer than
    /// the confirmation window after it: the agent was seen taking up to 45 s to handle the
    /// hook's call (Altiward/altiward#91), so a real claim can arrive well after its grant.
    static let lookBack: TimeInterval = 120

    /// The earliest evidence that Privileges granted `user` admin rights around `claimedAt`
    /// (from `lookBack` before it to `window` after it, and not after `now`), or nil when
    /// nothing confirms it.
    ///
    /// - A daemon line counts when it says "granted" for exactly `user` and its logger is
    ///   the Privileges daemon (`identity` gives a verified pid's signature, start time and
    ///   uid; the logger of a line or record must run as root and have started before it).
    /// - An extension record counts when it is an `ADMIN_ADD` for `user`, its logger is the
    ///   Privileges extension, and the process that made the change is on the allowlist.
    ///   A record whose logger can't be verified counts for nothing, not even against it.
    /// - A verified `ADMIN_REMOVE` for `user`, or a verified daemon "revoked" line, voids
    ///   every grant before it.
    /// - If the extension logged any verified admin change for `user` in the window, the
    ///   latest must be an allowlisted add, whatever the daemon line says.
    /// - Both of those look only at changes made at or before `claimedAt`: the claim is about
    ///   the rights when it arrived, so a real grant given back seconds later still backs it.
    /// - A line or record whose key is in `consumed` is spent and counts for nothing; the
    ///   evidence returned carries a key for each line it used.
    static func find(
        user: String, claimedAt: Date, now: Date, daemonLines: [PrivilegesDaemonLine],
        records: [PrivilegesAuditRecord], identity: (Int32) -> ProcessIdentity?, consumed: Set<String>,
        lookBack: TimeInterval, window: TimeInterval
    ) -> GrantEvidence? {
        var identities: [Int32: ProcessIdentity?] = [:]
        func verified(_ pid: Int32, _ signingID: String, at date: Date) -> Bool {
            let found: ProcessIdentity?
            if let cached = identities[pid] {
                found = cached
            } else {
                found = identity(pid)
                identities[pid] = .some(found)
            }
            guard let found else { return false }
            return found.signingID == signingID && found.teamID == PrivilegesSigning.teamID && found.uid == 0
                && found.startedAt <= date
        }
        func inWindow(_ date: Date) -> Bool {
            date >= claimedAt.addingTimeInterval(-lookBack) && date <= claimedAt.addingTimeInterval(window) && date <= now
        }

        struct Piece {
            var date: Date
            var source: GrantEvidence.Source
            var key: String
        }
        func key(_ date: Date, _ pid: Int32) -> String { "\(Int64((date.timeIntervalSince1970 * 1000).rounded()))|\(pid)" }

        var pieces: [Piece] = []
        var voids: [Date] = []
        for line in daemonLines where line.user == user && line.date <= now {
            guard verified(line.loggerPID, PrivilegesSigning.daemon, at: line.date) else { continue }
            switch line.change {
            case .revoked:
                if line.date <= claimedAt { voids.append(line.date) }
            case .granted:
                if inWindow(line.date) { pieces.append(Piece(date: line.date, source: .daemon, key: key(line.date, line.loggerPID))) }
            }
        }

        var latestChange: PrivilegesAuditRecord?
        for record in records where record.subject == user && record.eventType.hasPrefix("ADMIN_") && record.date <= now {
            guard verified(record.loggerPID, PrivilegesSigning.systemExtension, at: record.date) else { continue }
            if record.date <= claimedAt {
                if record.eventType == "ADMIN_REMOVE" { voids.append(record.date) }
                if inWindow(record.date), latestChange.map({ record.date >= $0.date }) ?? true { latestChange = record }
            }
            guard record.isAdminAdd, inWindow(record.date), let process = record.process,
                PrivilegesSigning.grantInstigators.contains(process.signingID),
                process.teamID == PrivilegesSigning.teamID
            else { continue }
            pieces.append(Piece(date: record.date, source: .systemExtension, key: key(record.date, record.loggerPID)))
        }

        if let latestChange {
            guard latestChange.isAdminAdd, let process = latestChange.process,
                PrivilegesSigning.grantInstigators.contains(process.signingID),
                process.teamID == PrivilegesSigning.teamID
            else { return nil }
        }

        pieces = pieces.filter { piece in !voids.contains { $0 > piece.date } }
        let live = pieces.filter { !consumed.contains($0.key) }
            .sorted { ($0.date, $0.source.rawValue) < ($1.date, $1.source.rawValue) }
        guard let first = live.first else { return nil }
        var used = [first]
        for other in live where other.source != first.source && abs(other.date.timeIntervalSince(first.date)) <= combineWithin {
            used.append(other)
        }
        return GrantEvidence(date: first.date, sources: Set(used.map(\.source)), keys: Set(used.map(\.key)))
    }
}
