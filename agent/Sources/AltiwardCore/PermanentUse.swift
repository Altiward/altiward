import Foundation

/// How a permanent admin account was used (`detail.method` on `admin.permanent_use`).
public enum PermanentUseMethod: String, Sendable {
    /// Signed in at the Mac: the login window or fast user switching.
    case console
    /// Signed in on a terminal with no remote host, such as `login` in Terminal.
    case terminal
    case ssh
    case screenSharing = "screen_sharing"
    /// Typed into an authorisation prompt.
    case prompt
    case sudo
    case su

    /// A sign-in's method, from where utmpx says it is.
    static func of(_ r: LoginRecord) -> PermanentUseMethod {
        if r.tty == "console" { return .console }
        if !r.host.isEmpty { return .ssh }
        return .terminal
    }
}

/// `admin.permanent_use` for sign-ins by accounts in `PermanentAdmins`, from utmpx and wtmp.
///
/// Each sign-in is a row in the store from its first report until a day after it ended, and
/// every event is enqueued in the transaction that writes its row, so a sign-in gets one
/// `started` and one `ended` however often the agent restarts:
/// - ``checkPermanentUses()`` sends `started` for a sign-in utmpx shows with no row, and
///   `ended` for an open row utmpx no longer shows;
/// - ``catchUpPermanentUses()``, at startup, sends `ended` for a sign-in that began and ended
///   while the agent wasn't running;
/// - the heartbeat does the same for one that began and ended between two checks, then moves
///   the cursor both read from and prunes old rows.
extension ElevationTracker {
    static let permanentUseCursorKey = "permanent_use_logins_until"
    /// How far back the catch-up reads at most, and how long ended rows are kept.
    static let permanentUseLookback: TimeInterval = 86_400

    /// Compares utmpx with the open rows. Run it every few seconds.
    public func checkPermanentUses() throws -> [AltiwardEvent] {
        let now = env.now()
        let device = env.device()
        return try store.transaction {
            var events: [AltiwardEvent] = []
            var signedIn = Set<String>()
            // macOS can leave a sign-in in utmpx after its process has gone, with no logout in
            // wtmp. That isn't a sign-in now: its row ends, as noticed.
            for record in env.logins() where env.processExists(record.pid) {
                let id = useID(record, device: device)
                // Every account's, so a row outlives its account leaving PermanentAdmins.
                signedIn.insert(id)
                guard env.config.permanentAdmins.contains(record.user), !(try store.hasPermanentUse(id: id))
                else { continue }
                let row = PermanentUseRow(
                    useID: id, user: record.user, method: .of(record), tty: record.tty, host: record.host,
                    pid: record.pid, startedAt: record.started, endedAt: nil)
                try store.insertPermanentUse(row)
                events.append(signInEvent(row, now: now, device: device))
            }

            let gone = try store.openPermanentUses().filter { !signedIn.contains($0.useID) }
            if let earliest = gone.map(\.startedAt).min() {
                let history = env.loginHistory(earliest)
                for row in gone {
                    // wtmp's end for the same sign-in: its logout, or the shutdown or boot.
                    let logged = history.first { useID($0, device: device) == row.useID }?.ended
                    var ended = row
                    ended.endedAt = logged ?? now
                    try store.endPermanentUse(id: row.useID, at: logged ?? now)
                    events.append(signInEvent(ended, basis: logged == nil ? "noticed" : "logged", now: now, device: device))
                }
            }

            for event in events { try store.enqueue(event, now: now) }
            return events
        }
    }

    /// Reports sign-ins that began and ended while the agent wasn't running: those wtmp says
    /// ended since the last heartbeat, at most a day back, with no row. Run it once, at
    /// startup, before the checks.
    public func catchUpPermanentUses() throws -> [AltiwardEvent] {
        let now = env.now()
        let device = env.device()
        let start = try permanentUseHistoryStart(now: now)
        return try store.transaction {
            let events = try completedUseEvents(env.loginHistory(start), since: start, now: now, device: device)
            for event in events { try store.enqueue(event, now: now) }
            return events
        }
    }

    /// Where the catch-up and the heartbeat read wtmp from: the last heartbeat, at most a day
    /// back.
    func permanentUseHistoryStart(now: Date) throws -> Date {
        let cursor = try store.value(forKey: Self.permanentUseCursorKey).flatMap(AltiwardJSON.parse)
        return max(now.addingTimeInterval(-Self.permanentUseLookback), cursor ?? .distantPast)
    }

    /// Runs inside the caller's transaction. Inserts an ended row for each permanent admin's
    /// sign-in in `history` that ended at or after `since` and has no row, and returns its
    /// `ended` event for the caller to enqueue.
    func completedUseEvents(_ history: [LoginRecord], since: Date, now: Date, device: DeviceInfo) throws
        -> [AltiwardEvent]
    {
        var events: [AltiwardEvent] = []
        for record in history {
            guard let ended = record.ended, ended >= since, env.config.permanentAdmins.contains(record.user)
            else { continue }
            let id = useID(record, device: device)
            // Open rows are left for the check, which ends them.
            guard !(try store.hasPermanentUse(id: id)) else { continue }
            let row = PermanentUseRow(
                useID: id, user: record.user, method: .of(record), tty: record.tty, host: record.host,
                pid: record.pid, startedAt: record.started, endedAt: ended)
            try store.insertPermanentUse(row)
            events.append(signInEvent(row, basis: "logged", now: now, device: device))
        }
        return events
    }

    /// The same for a sign-in seen in utmpx and in wtmp, before and after a restart.
    func useID(_ record: LoginRecord, device: DeviceInfo) -> String {
        let millis = Int64((record.started.timeIntervalSince1970 * 1000).rounded())
        return nameBasedID("altiward:permanent_use:\(device.serial):\(record.tty):\(record.pid):\(millis)")
    }

    /// `started` for an open row; `ended` for an ended one, with how its end is known.
    private func signInEvent(_ row: PermanentUseRow, basis: String? = nil, now: Date, device: DeviceInfo)
        -> AltiwardEvent
    {
        var detail: [String: JSONValue] = [
            "use_id": .string(row.useID), "method": .string(row.method.rawValue),
            "state": row.endedAt == nil ? "started" : "ended", "source": "utmpx", "started": .date(row.startedAt),
            "tty": .string(row.tty),
        ]
        if row.method == .ssh { detail["remote_host"] = .string(row.host) }
        if let ended = row.endedAt {
            detail["ended"] = .date(ended)
            detail["end_basis"] = basis.map(JSONValue.string) ?? .null
        }
        return permanentUseEvent(row.user, detail: detail, now: now, device: device)
    }

    /// An `admin.permanent_use` event for `user`: outside any elevation session.
    func permanentUseEvent(_ user: String, detail: [String: JSONValue], now: Date, device: DeviceInfo)
        -> AltiwardEvent
    {
        AltiwardEvent(
            type: .adminPermanentUse, sessionID: nil, timestamp: now, device: device,
            user: UserInfo(localName: user, upn: env.config.upn(for: user)), elevation: nil, detail: detail)
    }
}
