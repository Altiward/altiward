import Foundation
import os

/// The outside world the tracker reads from, injectable for tests.
public struct AgentEnvironment: Sendable {
    public var device: @Sendable () -> DeviceInfo
    public var privileges: @Sendable () -> PrivilegesSettings
    public var admins: any AdminMembershipReading
    public var adminEditor: any AdminGroupEditing
    public var config: AgentConfiguration
    public var now: @Sendable () -> Date
    /// The tamper checks that look at the installed system; see ``SystemIntegrity``.
    public var integrity: @Sendable () -> [IntegrityCheck: IntegrityResult]
    /// Snapshots the persistence locations; see ``checkPersistence()``. Nil turns
    /// the check off.
    public var persistence: (@Sendable () -> PersistenceSnapshot)?
    /// Pauses before membership is read again after an admin-group change, because
    /// membership reads can lag the directory for a moment after `dseditgroup` returns.
    public var waitForDirectory: @Sendable () -> Void
    /// The expiry Privileges set for a user's grant made at the given time, when Privileges
    /// recorded one (``PrivilegesTimer``).
    public var privilegesTimer: @Sendable (_ user: String, _ grantedAt: Date) -> Date?
    /// Whether the user's Privileges agent, which runs their timer, is running; nil when
    /// they aren't logged in (``PrivilegesAgentProcess``).
    public var privilegesAgentRunning: @Sendable (_ user: String) -> Bool?
    /// What Privileges' system extension logged since the given time, oldest first
    /// (``PrivilegesAuditLog``).
    public var privilegesAudit: @Sendable (_ since: Date) -> [PrivilegesAuditRecord]

    public init(
        device: @escaping @Sendable () -> DeviceInfo,
        privileges: @escaping @Sendable () -> PrivilegesSettings,
        admins: any AdminMembershipReading,
        adminEditor: any AdminGroupEditing,
        config: AgentConfiguration,
        now: @escaping @Sendable () -> Date = { Date() },
        integrity: @escaping @Sendable () -> [IntegrityCheck: IntegrityResult] = { [:] },
        persistence: (@Sendable () -> PersistenceSnapshot)? = nil,
        waitForDirectory: @escaping @Sendable () -> Void = {},
        privilegesTimer: @escaping @Sendable (_ user: String, _ grantedAt: Date) -> Date? = { _, _ in nil },
        privilegesAgentRunning: @escaping @Sendable (_ user: String) -> Bool? = { _ in nil },
        privilegesAudit: @escaping @Sendable (_ since: Date) -> [PrivilegesAuditRecord] = { _ in [] }
    ) {
        self.device = device
        self.privileges = privileges
        self.admins = admins
        self.adminEditor = adminEditor
        self.config = config
        self.now = now
        self.integrity = integrity
        self.persistence = persistence
        self.waitForDirectory = waitForDirectory
        self.privilegesTimer = privilegesTimer
        self.privilegesAgentRunning = privilegesAgentRunning
        self.privilegesAudit = privilegesAudit
    }

    /// The real system.
    public static func live(config: AgentConfiguration) -> AgentEnvironment {
        let system = SystemIntegrity.live()
        let sources = PersistenceSources.live()
        return AgentEnvironment(
            device: { DeviceIdentity.current() },
            privileges: { PrivilegesSettings.current() },
            admins: SystemAdminGroup(),
            adminEditor: SystemAdminGroup(),
            config: config,
            integrity: { system.run() },
            persistence: { sources.snapshot() },
            waitForDirectory: { Thread.sleep(forTimeInterval: 0.5) },
            privilegesTimer: { PrivilegesTimer.wait(user: $0, grantedAt: $1) },
            privilegesAgentRunning: { PrivilegesAgentProcess.running(user: $0) },
            privilegesAudit: { PrivilegesAuditLog.records(since: $0) })
    }
}

/// Turns Privileges hook calls and periodic admin-group readings into events,
/// keeping the ledger of open sessions in step. Every change is written to the outbox in
/// the same transaction as the ledger update, so a crash cannot split them.
public final class ElevationTracker: Sendable {
    let store: AgentStore
    let env: AgentEnvironment
    let persistenceLock = NSLock()
    /// Admins with no open session, and when ``checkUntrackedAdmins()`` first saw them so.
    let untrackedSince = OSAllocatedUnfairLock<[String: Date]>(initialState: [:])

    public init(store: AgentStore, environment: AgentEnvironment) {
        self.store = store
        self.env = environment
    }

    /// Records a grant or revoke reported by the hook.
    ///
    /// The hook runs as the user, so its claim is only a claim: the event carries what the
    /// daemon observed in the `admin` group and whether the two agree (`detail.verified`).
    ///
    /// Membership is read inside the transaction, so a grant can't commit between the read
    /// and the decision.
    @discardableResult
    public func record(_ invocation: HookInvocation, callerUID: UInt32? = nil) throws -> AltiwardEvent {
        let device = env.device()
        let user = UserInfo(localName: invocation.user, upn: env.config.upn(for: invocation.user))
        // Read before the transaction: it can wait a moment for Privileges to write it. A
        // fixed ExpirationInterval decides the expiry without it.
        let timer =
            invocation.state == .admin && env.privileges().expirationIntervalMinutes == nil
            ? env.privilegesTimer(invocation.user, invocation.invokedAt) : nil

        return try store.transaction {
            let observedAdmin = env.admins.isAdmin(user: invocation.user)
            var detail: [String: JSONValue] = [
                "trigger": "hook",
                "claimed_state": .string(invocation.state.rawValue),
                "observed_admin": .bool(observedAdmin),
                "verified": .bool(observedAdmin == (invocation.state == .admin)),
            ]
            if let callerUID { detail["caller_uid"] = .number(Double(callerUID)) }

            let existing = try store.openSession(user: invocation.user)
            let event: AltiwardEvent
            switch invocation.state {
            case .admin:
                // A grant while a Privileges session is open renews that session.
                let renewing = existing?.source == .privileges ? existing : nil
                let sessionID = renewing?.sessionID ?? newID()
                let limit = env.privileges().expiry(grantedAt: invocation.invokedAt, timer: timer)
                let expiresAt = limit?.date
                detail["renewed"] = .bool(renewing != nil)
                if let limit { detail["expires_basis"] = .string(limit.basis) }
                // A grant replaces an out-of-band session: end it first, or it stays open on
                // the server with its finding. The grant says so, since the claim closes it.
                if let replaced = existing, replaced.source == .outOfBand {
                    detail["replaced_out_of_band"] = true
                    try store.enqueue(
                        AltiwardEvent(
                            type: .elevationRevoked, sessionID: replaced.sessionID,
                            timestamp: invocation.invokedAt, device: device, user: user,
                            elevation: ElevationInfo(source: .outOfBand),
                            detail: [
                                "trigger": "privileges_grant", "observed_admin": .bool(observedAdmin),
                                "verified": .bool(observedAdmin),
                            ]))
                }
                // The overdue report is re-armed only when the expiry moves.
                let unchanged = renewing.map { $0.expiresAt == expiresAt } ?? false
                try store.upsertOpenSession(
                    OpenSession(
                        user: invocation.user, sessionID: sessionID, source: .privileges,
                        startedAt: renewing?.startedAt ?? invocation.invokedAt, expiresAt: expiresAt,
                        overdueReported: unchanged && renewing?.overdueReported == true))
                event = AltiwardEvent(
                    type: .elevationGranted, sessionID: sessionID, timestamp: invocation.invokedAt,
                    device: device, user: user,
                    elevation: ElevationInfo(reason: invocation.reason, expires: expiresAt, source: .privileges),
                    detail: detail)
            case .user:
                if existing == nil { detail["orphan"] = true }
                try store.closeSession(user: invocation.user)
                event = AltiwardEvent(
                    type: .elevationRevoked, sessionID: existing?.sessionID ?? newID(),
                    timestamp: invocation.invokedAt, device: device, user: user,
                    elevation: ElevationInfo(reason: invocation.reason, source: existing?.source ?? .privileges),
                    detail: detail)
            }
            try store.enqueue(event)
            return event
        }
    }

    /// Reads real admin-group membership and reconciles it with the ledger:
    /// - an open session whose user is no longer admin is closed (`trigger: heartbeat`),
    ///   covering revokes the hook never reported;
    /// - an admin with no open session who is not a permanent admin opens an
    ///   out-of-band session and raises `admin.out_of_band`, once; that session ends
    ///   (`trigger: permanent_admin`) if the user later becomes a permanent admin;
    /// - Privileges rights that outlive their expiry are reported or removed
    ///   (``enforceExpiry``);
    /// - an `agent.health` event reports who is admin now and the result of each tamper
    ///   check.
    ///
    /// Membership is read inside the transaction, so a grant or an expiry can't commit
    /// between the read and the reconciliation.
    @discardableResult
    public func heartbeat() throws -> [AltiwardEvent] {
        let now = env.now()
        let device = env.device()
        let settings = env.privileges()
        // Read outside the transaction: it checks the bundle's signature.
        var integrity = env.integrity()
        // So is the unified log, which can take a moment.
        let audit = env.privilegesAudit(try auditStart(now: now))

        return try store.transaction {
            let admins = env.admins.adminMembers()
            var events: [AltiwardEvent] = []
            let open = try store.openSessions()

            for session in open where !admins.contains(session.user) {
                try store.closeSession(user: session.user)
                events.append(
                    AltiwardEvent(
                        type: .elevationRevoked, sessionID: session.sessionID, timestamp: now, device: device,
                        user: UserInfo(localName: session.user, upn: env.config.upn(for: session.user)),
                        elevation: ElevationInfo(source: session.source),
                        detail: [
                            "trigger": "heartbeat", "observed_admin": false, "verified": true,
                            "inferred": true,
                        ]))
            }

            // An out-of-band session whose user is now a permanent admin: the rights are
            // standing now, not unexplained, so the session ends while they stay. Left open,
            // it would last as long as the rights. Privileges grants run their course.
            for session in open
            where session.source == .outOfBand && admins.contains(session.user)
                && env.config.permanentAdmins.contains(session.user)
            {
                try store.closeSession(user: session.user)
                events.append(
                    AltiwardEvent(
                        type: .elevationRevoked, sessionID: session.sessionID, timestamp: now, device: device,
                        user: UserInfo(localName: session.user, upn: env.config.upn(for: session.user)),
                        elevation: ElevationInfo(source: session.source),
                        detail: ["trigger": "permanent_admin", "observed_admin": true, "verified": true]))
            }

            let (expiryEvents, demoted) = try enforceExpiry(
                open.filter { admins.contains($0.user) }, now: now, device: device)
            events += expiryEvents

            for user in untracked(admins: admins, open: open).sorted() {
                events.append(try openOutOfBand(user, now: now, device: device, audit: audit))
            }

            if device.privilegesVersion != nil {
                integrity[.privilegesTimer] = privilegesTimerCheck(open, admins: admins.subtracting(demoted))
            }
            events += try tamperEvents(integrity, now: now, device: device)
            events += try blockedEvents(audit, now: now, device: device)

            var privileges = settings.healthDetail
            if case .object(var fields) = privileges {
                fields["installed"] = .bool(device.privilegesVersion != nil)
                privileges = .object(fields)
            }
            let openNow = try store.openSessions()
            var health: [String: JSONValue] = [
                "admin_members": .strings(admins.subtracting(demoted).sorted()),
                "permanent_admins": .strings(env.config.permanentAdmins.sorted()),
                "open_sessions": .array(
                    openNow.map {
                        [
                            "user": .string($0.user), "session_id": .string($0.sessionID),
                            "source": .string($0.source.rawValue),
                        ]
                    }),
                // Depth before this batch is enqueued: what was still waiting.
                "queue_depth": .number(Double(try store.pendingCount())),
                "privileges": privileges,
                "integrity": .object(
                    Dictionary(uniqueKeysWithValues: integrity.map { ($0.key.rawValue, JSONValue.bool($0.value.ok)) })),
            ]
            if let unreadable = try persistenceUnreadable() { health["persistence_unreadable"] = .strings(unreadable) }
            events.append(
                AltiwardEvent(
                    type: .agentHealth, sessionID: nil, timestamp: now, device: device, user: nil, elevation: nil,
                    detail: health))

            for event in events { try store.enqueue(event, now: now) }
            return events
        }
    }

    /// Fails while someone logged in holds rights from a Privileges grant and their
    /// Privileges agent, which runs the timer that would remove them, isn't running: they
    /// may have stopped it to keep the rights. Users not logged in, permanent admins and
    /// rights Privileges didn't grant are left out; ``enforceExpiry`` still covers them.
    private func privilegesTimerCheck(_ open: [OpenSession], admins: Set<String>) -> IntegrityResult {
        let stopped = open.filter {
            $0.source == .privileges && admins.contains($0.user)
                && !env.config.permanentAdmins.contains($0.user)
        }
        .map(\.user).filter { env.privilegesAgentRunning($0) == false }.sorted()
        guard !stopped.isEmpty else { return .ok }
        let verb = stopped.count == 1 ? "holds" : "hold"
        return .failed(
            "Privileges' timer isn't running for \(stopped.joined(separator: ", ")), who \(verb) admin rights it granted")
    }

    /// Expiry enforcement. For each open Privileges session whose user is still admin past
    /// expiry plus the grace period: in `enforce` mode remove the rights, end the session
    /// and raise `elevation.expired_enforced`; otherwise, or when removal fails, raise
    /// `elevation.overdue` once per expiry. Removal is retried on every heartbeat.
    ///
    /// Acts on the `admin` group directly, never through Privileges, so expiry works
    /// without Privileges installed. Permanent admins and out-of-band sessions, which have
    /// no expiry, are left alone.
    private func enforceExpiry(_ sessions: [OpenSession], now: Date, device: DeviceInfo) throws -> (
        events: [AltiwardEvent], demoted: Set<String>
    ) {
        let mode = env.config.expiryEnforcement
        let grace = env.config.expiryGracePeriod
        guard mode != .off else { return ([], []) }

        var events: [AltiwardEvent] = []
        var demoted = Set<String>()
        for session in sessions
        where session.source == .privileges && !env.config.permanentAdmins.contains(session.user)
        {
            guard let expiresAt = session.expiresAt, now >= expiresAt.addingTimeInterval(grace) else { continue }
            let user = UserInfo(localName: session.user, upn: env.config.upn(for: session.user))
            let elevation = ElevationInfo(expires: expiresAt, source: session.source)
            var detail: [String: JSONValue] = [
                "trigger": "heartbeat", "expired_at": .date(expiresAt), "grace_seconds": .number(grace),
            ]

            var failure: String?
            if mode == .enforce {
                failure = removeFromAdminGroup(session.user)
                if failure == nil {
                    try store.closeSession(user: session.user)
                    demoted.insert(session.user)
                    detail["observed_admin"] = false
                    detail["verified"] = true
                    events.append(
                        AltiwardEvent(
                            type: .elevationExpiredEnforced, sessionID: session.sessionID, timestamp: now,
                            device: device, user: user, elevation: elevation, detail: detail))
                    continue
                }
            }

            guard !session.overdueReported else { continue }
            try store.markOverdueReported(user: session.user)
            detail["observed_admin"] = true
            detail["enforcement"] = .string(mode.rawValue)
            detail["enforcement_failed"] = .bool(failure != nil)
            if let failure { detail["error"] = .string(failure) }
            events.append(
                AltiwardEvent(
                    type: .elevationOverdue, sessionID: session.sessionID, timestamp: now,
                    device: device, user: user, elevation: elevation, detail: detail))
        }
        return (events, demoted)
    }

    /// How long an admin goes without an open session before ``checkUntrackedAdmins()``
    /// raises it: longer than a Privileges hook can take to report a grant, including its
    /// wait for Privileges' timer (``PrivilegesTimer/wait(user:grantedAt:attempts:pause:)``,
    /// about 18 s at worst).
    static let untrackedGrace: TimeInterval = 30

    /// Raises `admin.out_of_band` between heartbeats for an admin who has had no open
    /// session for ``untrackedGrace``, so rights nobody granted show within a minute instead
    /// of a heartbeat, while a grant whose hook is still on its way isn't reported as one.
    /// Run it every few seconds; the heartbeat still raises anything it misses.
    public func checkUntrackedAdmins() throws -> [AltiwardEvent] {
        let now = env.now()
        let device = env.device()
        return try store.transaction {
            let untracked = untracked(admins: env.admins.adminMembers(), open: try store.openSessions())
            let confirmed = untrackedSince.withLock { since in
                since = Dictionary(uniqueKeysWithValues: untracked.map { ($0, since[$0] ?? now) })
                return Set(since.filter { now.timeIntervalSince($0.value) >= Self.untrackedGrace }.keys)
            }
            var events: [AltiwardEvent] = []
            // Rare, so the log is read here, only when there is something to attribute.
            let audit = confirmed.isEmpty ? [] : env.privilegesAudit(now.addingTimeInterval(-auditLookback))
            for user in confirmed.sorted() {
                let event = try openOutOfBand(user, now: now, device: device, audit: audit)
                try store.enqueue(event, now: now)
                events.append(event)
            }
            return events
        }
    }

    /// Admins with no open session who aren't permanent admins.
    private func untracked(admins: Set<String>, open: [OpenSession]) -> Set<String> {
        admins.subtracting(open.map(\.user)).subtracting(env.config.permanentAdmins)
    }

    /// Opens an out-of-band session for `user` and returns its `admin.out_of_band` event,
    /// for the caller to enqueue. `audit` says which process added them, when Privileges'
    /// system extension logged it.
    private func openOutOfBand(_ user: String, now: Date, device: DeviceInfo, audit: [PrivilegesAuditRecord])
        throws -> AltiwardEvent
    {
        let sessionID = newID()
        try store.upsertOpenSession(
            OpenSession(user: user, sessionID: sessionID, source: .outOfBand, startedAt: now, expiresAt: nil))
        var detail: [String: JSONValue] = ["first_observed": .date(now)]
        if let instigator = instigator(of: user, in: audit) { detail["instigator"] = instigator }
        return AltiwardEvent(
            type: .adminOutOfBand, sessionID: sessionID, timestamp: now, device: device,
            user: UserInfo(localName: user, upn: env.config.upn(for: user)),
            elevation: ElevationInfo(source: .outOfBand),
            detail: detail)
    }

    static let stillAdmin = "still an admin after removal from the admin group (nested group membership?)"
    /// How many times a removal `dseditgroup` reported as done is re-read before it counts
    /// as failed, with ``AgentEnvironment/waitForDirectory`` between reads (about 3 s live).
    static let membershipRechecks = 6

    /// Removes `user` from `admin` and confirms it by reading membership, since a call that
    /// threw may still have taken effect. A removal that reported success is re-read a few
    /// times, because membership reads can briefly lag the change. Returns why it did not
    /// take, or nil.
    func removeFromAdminGroup(_ user: String) -> String? {
        var removeError: String?
        do {
            try env.adminEditor.removeAdmin(user: user)
        } catch {
            removeError = String(describing: error)
        }
        var stillAdmin = env.admins.isAdmin(user: user)
        var rechecks = 0
        while stillAdmin, removeError == nil, rechecks < Self.membershipRechecks {
            env.waitForDirectory()
            rechecks += 1
            stillAdmin = env.admins.isAdmin(user: user)
        }
        return stillAdmin ? removeError ?? Self.stillAdmin : nil
    }

    /// Runs a remote command exactly once. The result is stored in the same
    /// transaction as the ledger changes and events it produced; a redelivered command
    /// returns that stored result without acting again.
    public func execute(_ command: AgentCommand) throws -> CommandResult {
        try store.transaction {
            if let done = try store.commandResult(id: command.commandID) { return done }
            let now = env.now()
            let result =
                command.type == "revoke_admin"
                ? try revoke(command, now: now)
                : CommandResult(status: .failed, error: "unsupported command type \(command.type)", completedAt: now)
            try store.saveCommandResult(id: command.commandID, result: result, at: now)
            return result
        }
    }

    /// Removes admin rights directly from the `admin` group, never through Privileges, so
    /// revoke works without it. Permanent admins are never touched, and a command bound to
    /// a session leaves any newer session alone.
    private func revoke(_ command: AgentCommand, now: Date) throws -> CommandResult {
        var result = CommandResult(status: .skipped, completedAt: now)
        let device = env.device()
        let targets = command.user.map { [$0] } ?? env.admins.adminMembers().sorted()
        for user in targets {
            if env.config.permanentAdmins.contains(user) {
                result.skipped.append(.init(user: user, reason: .permanentAdmin))
                continue
            }
            let open = try store.openSession(user: user)
            if let wanted = command.sessionID, open?.sessionID != wanted {
                result.skipped.append(.init(user: user, reason: .sessionEnded))
                continue
            }
            guard env.admins.isAdmin(user: user) else {
                result.skipped.append(.init(user: user, reason: .notAdmin))
                continue
            }
            if let failure = removeFromAdminGroup(user) {
                result.failed.append(.init(user: user, error: failure))
                continue
            }
            try store.closeSession(user: user)
            result.revoked.append(user)
            var detail: [String: JSONValue] = [
                "trigger": "command", "command_id": .string(command.commandID), "observed_admin": false, "verified": true,
            ]
            if open == nil { detail["orphan"] = true }
            try store.enqueue(
                AltiwardEvent(
                    type: .elevationRevoked, sessionID: open?.sessionID ?? newID(), timestamp: now, device: device,
                    user: UserInfo(localName: user, upn: env.config.upn(for: user)),
                    elevation: ElevationInfo(source: open?.source ?? .outOfBand), detail: detail),
                now: now)
        }
        result.status = !result.failed.isEmpty ? .failed : !result.revoked.isEmpty ? .completed : .skipped
        return result
    }
}
