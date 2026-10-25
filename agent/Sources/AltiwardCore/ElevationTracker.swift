import Foundation
import os

private let log = Logger(subsystem: "com.altiward.agent", category: "tracker")

/// Whether the agent can read SAP's own log of what Privileges did, which is what confirms a
/// grant claim. Unavailable carries why, for the logs and the tamper event.
public enum PrivilegesLogAvailability: Sendable, Equatable {
    case available
    case unavailable(String)
}

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
    /// Who is signed in now, from utmpx (``LoginRecords``).
    public var logins: @Sendable () -> [LoginRecord]
    /// Whether a process with this id still exists (``LoginRecords/processExists(_:)``). utmpx
    /// can keep a sign-in whose process has gone, so a current sign-in without one doesn't count.
    public var processExists: @Sendable (_ pid: Int32) -> Bool
    /// Sign-ins from wtmp that ended at or after the given time or haven't ended, each with
    /// its end when wtmp has one (``LoginRecords``).
    public var loginHistory: @Sendable (_ since: Date) -> [LoginRecord]
    /// Prompts and screen sharing by accounts the log names, since the given time, oldest first
    /// (``PermanentUseLog``).
    public var permanentUseLog: @Sendable (_ since: Date) -> [PermanentUseLogRecord]
    /// An account's full name, as the directory holds it; nil when it has none.
    public var fullName: @Sendable (_ shortName: String) -> String?
    /// Whether the directory has an account with this short name.
    public var accountExists: @Sendable (_ shortName: String) -> Bool
    /// Whether Privileges' log can be read now (``PrivilegesLogAvailability``). While it can,
    /// a grant claim is held until the log confirms it; while it can't, claims are recorded
    /// as they arrive.
    public var privilegesLogAvailability: @Sendable () -> PrivilegesLogAvailability
    /// What `PrivilegesDaemon` logged about changes it made since the given time, oldest first
    /// (``PrivilegesDaemonLine``).
    public var privilegesDaemonLines: @Sendable (_ since: Date) -> [PrivilegesDaemonLine]
    /// The code signature and start time of a running process; nil when it is gone or can't
    /// be verified (``ProcessIdentity``).
    public var processIdentity: @Sendable (_ pid: Int32) -> ProcessIdentity?
    /// The pid of SAP Privileges' running system extension; nil when none is running
    /// (``PrivilegesExtensionProcess/pid()``). Whether it is SAP's is for ``processIdentity`` to say.
    public var privilegesExtensionPID: @Sendable () -> Int32?
    /// The uid of the account with this short name; nil when there is none.
    public var userID: @Sendable (_ shortName: String) -> UInt32?
    /// Renewals SAP Privileges' per-user agent logged since the given time, oldest first
    /// (``PrivilegesAgentLog``).
    public var privilegesRenewals: @Sendable (_ since: Date) -> [PrivilegesRenewalLine]
    /// The UUIDs of SAP's agent executable on disk, one for each architecture.
    public var privilegesAgentImageUUIDs: @Sendable () -> Set<String>

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
        privilegesAudit: @escaping @Sendable (_ since: Date) -> [PrivilegesAuditRecord] = { _ in [] },
        logins: @escaping @Sendable () -> [LoginRecord] = { [] },
        processExists: @escaping @Sendable (_ pid: Int32) -> Bool = { _ in true },
        loginHistory: @escaping @Sendable (_ since: Date) -> [LoginRecord] = { _ in [] },
        permanentUseLog: @escaping @Sendable (_ since: Date) -> [PermanentUseLogRecord] = { _ in [] },
        fullName: @escaping @Sendable (_ shortName: String) -> String? = { _ in nil },
        accountExists: @escaping @Sendable (_ shortName: String) -> Bool = { _ in false },
        privilegesLogAvailability: @escaping @Sendable () -> PrivilegesLogAvailability = {
            .unavailable("not checked")
        },
        privilegesDaemonLines: @escaping @Sendable (_ since: Date) -> [PrivilegesDaemonLine] = { _ in [] },
        processIdentity: @escaping @Sendable (_ pid: Int32) -> ProcessIdentity? = { _ in nil },
        privilegesExtensionPID: @escaping @Sendable () -> Int32? = { nil },
        userID: @escaping @Sendable (_ shortName: String) -> UInt32? = { _ in nil },
        privilegesRenewals: @escaping @Sendable (_ since: Date) -> [PrivilegesRenewalLine] = { _ in [] },
        privilegesAgentImageUUIDs: @escaping @Sendable () -> Set<String> = { [] }
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
        self.logins = logins
        self.processExists = processExists
        self.loginHistory = loginHistory
        self.permanentUseLog = permanentUseLog
        self.fullName = fullName
        self.accountExists = accountExists
        self.privilegesLogAvailability = privilegesLogAvailability
        self.privilegesDaemonLines = privilegesDaemonLines
        self.processIdentity = processIdentity
        self.privilegesExtensionPID = privilegesExtensionPID
        self.userID = userID
        self.privilegesRenewals = privilegesRenewals
        self.privilegesAgentImageUUIDs = privilegesAgentImageUUIDs
    }

    /// The real system.
    public static func live(config: AgentConfiguration) -> AgentEnvironment {
        let system = SystemIntegrity.live(config: config)
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
            privilegesAudit: { PrivilegesAuditLog.records(since: $0) },
            logins: { LoginRecords.current() },
            processExists: { LoginRecords.processExists($0) },
            loginHistory: { LoginRecords.history(since: $0) },
            permanentUseLog: { PermanentUseLog.records(since: $0) },
            fullName: { PermanentUseLog.fullName(of: $0) },
            accountExists: { PermanentUseLog.accountExists($0) },
            privilegesLogAvailability: { .current() },
            privilegesDaemonLines: { PrivilegesDaemonLog.lines(since: $0) },
            processIdentity: { ProcessIdentity.of(pid: $0) },
            privilegesExtensionPID: { PrivilegesExtensionProcess.pid() },
            userID: { ProcessIdentity.uid(of: $0) },
            privilegesRenewals: { PrivilegesAgentLog.renewals(since: $0) },
            privilegesAgentImageUUIDs: { MachOImage.uuids(atPath: PrivilegesAgentLog.executable) })
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
    /// When each caller's recent grant claims arrived, by uid (``submit(_:callerUID:)``).
    let recentClaims = OSAllocatedUnfairLock<[UInt32: [Date]]>(initialState: [:])
    /// When each caller's recent give-back claims arrived, by uid, counted apart from grants.
    let recentGiveBacks = OSAllocatedUnfairLock<[UInt32: [Date]]>(initialState: [:])

    public init(store: AgentStore, environment: AgentEnvironment) {
        self.store = store
        self.env = environment
    }

    /// How long after Altiward raised rights nobody granted a Privileges grant may still claim
    /// them, in `OutOfBandEnforcement` `enforce` mode. The only real case is a heartbeat that
    /// runs between Privileges changing the group and its hook arriving, which reports within
    /// about 25 s of the grant (up to about 18 s waiting for Privileges' timer, see
    /// ``untrackedGrace``, then a 5 s XPC timeout) and never retries. A later claim is someone
    /// running the hook by hand to keep rights nobody granted.
    static let grantReplacementWindow: TimeInterval = 60

    /// Why a hook claim was refused. In `OutOfBandEnforcement` `enforce` mode no grant
    /// claim counts without SAP Privileges, or after ``grantReplacementWindow`` for rights
    /// nobody granted. In every mode a give-back cannot end an open session while the
    /// user is still an admin.
    public struct ClaimRefused: Error, CustomStringConvertible {
        public enum Reason: Sendable, Equatable {
            /// A grant claim, this many seconds after Altiward raised the rights.
            case late(seconds: Int)
            /// A grant claim on a Mac without SAP Privileges.
            case privilegesNotInstalled
            /// A give-back claim while the daemon still sees the user in `admin`.
            case stillAdmin
            /// A grant claim, or a renewal when `renewal`, that Privileges' log doesn't confirm.
            case notConfirmed(renewal: Bool)
            /// A claim for a user sent by a process of another user, who isn't root.
            case callerMismatch(callerUID: UInt32)
            /// The untrusted claim has no authenticated caller UID.
            case unknownCaller
            /// More grant claims from one caller in a minute than ``ElevationTracker/maxClaimsPerMinute``.
            case tooManyClaims
            /// A give-back that wouldn't end a session, from a caller that has sent more than
            /// ``ElevationTracker/maxGiveBacksPerMinute`` give-back claims in a minute.
            case tooManyGiveBacks
            /// A grant or renewal claim recorded without Privileges' log on a Mac where the
            /// agent has read that log before. Losing the log is how a hand-run claim would
            /// get past the check, so it is reported.
            case privilegesLogLost
        }
        public let user: String
        public let reason: Reason

        public var description: String {
            switch reason {
            case .late(let seconds):
                "a Privileges grant claimed for \(user) \(seconds) s after Altiward raised rights nobody granted; OutOfBandEnforcement keeps them out of band"
            case .privilegesNotInstalled:
                "a Privileges grant claimed for \(user) on a Mac without SAP Privileges; OutOfBandEnforcement accepts no grant claim without it"
            case .stillAdmin:
                "a give-back claimed for \(user), who is still an admin; the session stays open until membership loss is confirmed"
            case .notConfirmed(let renewal):
                "a Privileges \(renewal ? "renewal" : "grant") claimed for \(user), which Privileges' own log does not confirm"
            case .callerMismatch(let callerUID):
                "a claim for \(user) sent by a process of user ID \(callerUID), who is neither \(user) nor root"
            case .unknownCaller:
                "a claim for \(user) with no authenticated caller user ID"
            case .tooManyClaims:
                "more than \(ElevationTracker.maxClaimsPerMinute) grant claims in a minute from one caller; this one for \(user) was ignored"
            case .tooManyGiveBacks:
                "more than \(ElevationTracker.maxGiveBacksPerMinute) give-back claims in a minute from one caller; this one for \(user) would end no session, so it was ignored"
            case .privilegesLogLost:
                "Privileges' log was available on this Mac before and isn't now"
            }
        }
    }

    /// Records a grant or revoke reported by the hook.
    ///
    /// The hook runs as the user, so its claim is only a claim: the event carries what the
    /// daemon observed in the `admin` group and whether the two agree (`detail.verified`).
    /// In `OutOfBandEnforcement` `enforce` mode a claim throws ``ClaimRefused`` and records
    /// nothing when it is a grant on a Mac without SAP Privileges, a grant that would replace
    /// an out-of-band session too late. In every mode a give-back that would end an open
    /// session while the user is still an admin is refused, preserving its expiry until
    /// a later claim or heartbeat confirms membership loss.
    ///
    /// Membership is read inside the transaction, so a grant can't commit between the read
    /// and the decision.
    @discardableResult
    public func record(_ invocation: HookInvocation, callerUID: UInt32? = nil) throws -> AltiwardEvent {
        try record(invocation, callerUID: callerUID, grantDetail: [:]) { _ in nil }
    }

    /// ``record(_:callerUID:)``, with `grantDetail` added to a grant's event. When
    /// `alsoQueue` makes an event from the one recorded, it is queued after it in the same
    /// transaction. With `endingOnly`, a give-back is recorded only when it ends an open
    /// session, and otherwise throws `tooManyGiveBacks`, even where it would be refused.
    func record(
        _ invocation: HookInvocation, callerUID: UInt32?, grantDetail: [String: JSONValue],
        endingOnly: Bool = false, alsoQueue: (AltiwardEvent) -> AltiwardEvent?
    ) throws -> AltiwardEvent {
        let device = env.device()
        let user = UserInfo(localName: invocation.user, upn: env.config.upn(for: invocation.user))
        // Read before the transaction: it can wait a moment for Privileges to write it. A
        // fixed ExpirationInterval decides the expiry without it.
        let timer =
            invocation.state == .admin && env.privileges().expirationIntervalMinutes == nil
            ? env.privilegesTimer(invocation.user, invocation.invokedAt) : nil

        return try store.transaction {
            let event: AltiwardEvent
            switch invocation.state {
            case .admin:
                let granted = try applyGrant(
                    invocation, callerUID: callerUID, grantedAt: invocation.invokedAt, timer: timer,
                    extraDetail: grantDetail, skipLateCheck: false, device: device)
                if let replaced = granted.replaced { try store.enqueue(replaced) }
                event = granted.event
            case .user:
                let observedAdmin = env.admins.isAdmin(user: invocation.user)
                var detail = hookDetail(invocation, observedAdmin: observedAdmin, callerUID: callerUID)
                let existing = try store.openSession(user: invocation.user)
                // A claim cannot discard an open session or its expiry while real membership
                // contradicts it. The next heartbeat retries membership confirmation.
                let stillAdmin = existing != nil && observedAdmin
                if endingOnly, existing == nil || stillAdmin {
                    throw ClaimRefused(user: invocation.user, reason: .tooManyGiveBacks)
                }
                if stillAdmin {
                    throw ClaimRefused(user: invocation.user, reason: .stillAdmin)
                }
                if existing == nil { detail["orphan"] = true }
                try store.closeSession(user: invocation.user)
                event = AltiwardEvent(
                    type: .elevationRevoked, sessionID: existing?.sessionID ?? newID(),
                    timestamp: invocation.invokedAt, device: device, user: user,
                    elevation: ElevationInfo(reason: invocation.reason, source: existing?.source ?? .privileges),
                    detail: detail)
            }
            try store.enqueue(event)
            if let also = alsoQueue(event) { try store.enqueue(also) }
            return event
        }
    }

    /// What every hook claim's event says: what was claimed, what the daemon observed, and
    /// whether the two agree.
    private func hookDetail(_ invocation: HookInvocation, observedAdmin: Bool, callerUID: UInt32?)
        -> [String: JSONValue]
    {
        var detail: [String: JSONValue] = [
            "trigger": "hook",
            "claimed_state": .string(invocation.state.rawValue),
            "observed_admin": .bool(observedAdmin),
            "verified": .bool(observedAdmin == (invocation.state == .admin)),
        ]
        if let callerUID { detail["caller_uid"] = .number(Double(callerUID)) }
        return detail
    }

    /// Opens or renews the Privileges session a grant claim asks for, replacing an
    /// out-of-band session where there is one. Runs inside the caller's transaction, which
    /// queues what it returns: the `elevation.granted`, and before it the `elevation.revoked`
    /// that ends the out-of-band session it replaced, if any.
    ///
    /// The expiry counts from `grantedAt`, when the grant was made: the claim's arrival, or
    /// the time of the log lines that confirmed it. `timer` is Privileges' timer, read before
    /// the transaction. The events carry the claim's arrival (`invokedAt`). `extraDetail` is
    /// added to the grant's detail. `skipLateCheck` is for a grant Privileges' log confirmed,
    /// which replaces an out-of-band session however long it has been open; a grant on a Mac
    /// without SAP Privileges is still refused in `enforce` mode.
    func applyGrant(
        _ invocation: HookInvocation, callerUID: UInt32?, grantedAt: Date, timer: Date?,
        extraDetail: [String: JSONValue], skipLateCheck: Bool, device: DeviceInfo
    ) throws -> (event: AltiwardEvent, replaced: AltiwardEvent?) {
        let user = UserInfo(localName: invocation.user, upn: env.config.upn(for: invocation.user))
        // Read inside the transaction, so a grant can't commit between the read and the decision.
        let observedAdmin = env.admins.isAdmin(user: invocation.user)
        var detail = hookDetail(invocation, observedAdmin: observedAdmin, callerUID: callerUID)
        let existing = try store.openSession(user: invocation.user)
        // Before any write, so a refusal leaves the ledger and the outbox as they were.
        try checkGrant(invocation, existing: existing, skipLateCheck: skipLateCheck, device: device)
        // A grant while a Privileges session is open renews that session.
        let renewing = existing?.source == .privileges ? existing : nil
        let sessionID = renewing?.sessionID ?? newID()
        let limit = env.privileges().expiry(grantedAt: grantedAt, timer: timer)
        let expiresAt = limit?.date
        detail["renewed"] = .bool(renewing != nil)
        if let limit { detail["expires_basis"] = .string(limit.basis) }
        // A grant replaces an out-of-band session: end it first, or it stays open on
        // the server with its finding. The grant says so, since the claim closes it.
        var replacedEvent: AltiwardEvent?
        if let replaced = existing, replaced.source == .outOfBand {
            detail["replaced_out_of_band"] = true
            replacedEvent = AltiwardEvent(
                type: .elevationRevoked, sessionID: replaced.sessionID,
                timestamp: invocation.invokedAt, device: device, user: user,
                elevation: ElevationInfo(source: .outOfBand),
                detail: [
                    "trigger": "privileges_grant", "observed_admin": .bool(observedAdmin),
                    "verified": .bool(observedAdmin),
                ])
        }
        detail.merge(extraDetail) { $1 }
        // The overdue report is re-armed only when the expiry moves.
        let unchanged = renewing.map { $0.expiresAt == expiresAt } ?? false
        try store.upsertOpenSession(
            OpenSession(
                user: invocation.user, sessionID: sessionID, source: .privileges,
                startedAt: renewing?.startedAt ?? invocation.invokedAt, expiresAt: expiresAt,
                overdueReported: unchanged && renewing?.overdueReported == true))
        let event = AltiwardEvent(
            type: .elevationGranted, sessionID: sessionID, timestamp: invocation.invokedAt,
            device: device, user: user,
            elevation: ElevationInfo(reason: invocation.reason, expires: expiresAt, source: .privileges),
            detail: detail)
        return (event, replacedEvent)
    }

    /// Throws ``ClaimRefused`` when, in `enforce` mode, a grant claim may not be recorded: on
    /// a Mac without SAP Privileges, whatever the user's session, or (unless `skipLateCheck`)
    /// when it would replace an out-of-band session later than ``grantReplacementWindow``.
    /// Times are the daemon's: the session's start and the claim's `invokedAt`, which the XPC
    /// handler sets on arrival.
    private func checkGrant(
        _ invocation: HookInvocation, existing: OpenSession?, skipLateCheck: Bool, device: DeviceInfo
    ) throws {
        guard env.config.outOfBandEnforcement == .enforce else { return }
        if device.privilegesVersion == nil {
            throw ClaimRefused(user: invocation.user, reason: .privilegesNotInstalled)
        }
        guard !skipLateCheck, let replaced = existing, replaced.source == .outOfBand else { return }
        let elapsed = invocation.invokedAt.timeIntervalSince(replaced.startedAt)
        if elapsed > Self.grantReplacementWindow {
            throw ClaimRefused(user: invocation.user, reason: .late(seconds: Int(elapsed.rounded())))
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
    /// - in `OutOfBandEnforcement` `enforce` mode, rights nobody granted that have lasted
    ///   the grace period are removed (``enforceOutOfBand``);
    /// - an `agent.health` event reports who is admin now and the result of each tamper
    ///   check.
    ///
    /// Held grant claims are resolved first (``resolvePendingClaims()``), and their events
    /// come first in what it returns. An admin whose claim is still in its confirmation window
    /// isn't raised out-of-band.
    ///
    /// Membership is read inside the transaction, so a grant or an expiry can't commit
    /// between the read and the reconciliation.
    @discardableResult
    public func heartbeat() throws -> [AltiwardEvent] {
        let resolved = resolveHeldClaims()
        let now = env.now()
        let device = env.device()
        let settings = env.privileges()
        let logAvailability = env.privilegesLogAvailability()
        // Read outside the transaction: it checks the bundle's signature.
        var integrity = env.integrity()
        // So is the unified log, which can take a moment.
        let audit = env.privilegesAudit(try auditStart(now: now))
        // And the extension's process, for which of those records it wrote.
        let extensionInstance = verifiedExtensionInstance()
        // And wtmp: sign-ins by permanent admins too short for the checks to see.
        let loginsFrom = try permanentUseHistoryStart(now: now)
        let loginHistory = env.loginHistory(loginsFrom)
        // And the unified log again, for their prompts and screen sharing. Left unread with no
        // permanent admins, as nothing it holds would be reported.
        let useLogFrom = try permanentUseLogStart(now: now)
        let useLog = env.config.permanentAdmins.isEmpty ? [] : env.permanentUseLog(useLogFrom)
        // And PrivilegesAgent's renewals, which Privileges reports nowhere else.
        let renewals = try renewalsToApply(settings, now: now)

        return try resolved + store.transaction {
            try notePrivilegesLog(logAvailability)
            try noteExtensionInstance(extensionInstance)
            let admins = env.admins.adminMembers()
            // Before expiry is enforced below, so renewed rights keep their new expiry.
            var events = try applyRenewals(renewals, admins: admins, settings: settings, device: device)
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

            var (expiryEvents, demoted) = try enforceExpiry(
                open.filter { admins.contains($0.user) }, now: now, device: device)
            events += expiryEvents

            // Admins with no open session: raised out-of-band below, unless a claim of theirs
            // is waiting for Privileges' log.
            let untrackedAdmins = untracked(admins: admins, open: open).subtracting(try heldUsers(now: now))

            // Sessions closed above are left out: the not-admin ones by `admins`, the
            // permanent-admin ones by name. Expiry only touches Privileges sessions.
            let (outOfBandEvents, removed) = try enforceOutOfBand(
                open.filter {
                    $0.source == .outOfBand && admins.contains($0.user)
                        && !env.config.permanentAdmins.contains($0.user)
                },
                demoted: demoted, integrity: integrity, now: now, device: device)
            events += outOfBandEvents
            // So agent.health's admin_members and the timer check leave them out.
            demoted.formUnion(removed)

            for user in untrackedAdmins.sorted() {
                events.append(try openOutOfBand(user, now: now, device: device, audit: audit))
            }

            if device.privilegesVersion != nil {
                integrity[.privilegesTimer] = privilegesTimerCheck(open, admins: admins.subtracting(demoted))
            }
            integrity[.grantConfirmation] = try grantConfirmationCheck(logAvailability)
            events += try tamperEvents(integrity, now: now, device: device)
            events += try blockedEvents(audit, now: now, device: device)
            // Sign-ins of permanent admins that began and ended between two checks. The next read
            // starts from here, and rows ended over a day ago, before anything a read covers, are
            // no longer needed to dedupe.
            events += try completedUseEvents(loginHistory, since: loginsFrom, now: now, device: device)
            events += try permanentUseLogEvents(useLog, now: now, device: device)
            try store.setValue(AltiwardJSON.format(now), forKey: Self.permanentUseCursorKey)
            try store.prunePermanentUses(endedBefore: now.addingTimeInterval(-Self.permanentUseLookback))

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

    /// Fails while enforcement can't confirm Privileges grants: Privileges' log is unavailable
    /// (the reason is the problem), or the system extension has logged no record of a grant
    /// the daemon's line confirmed (``extensionSilentKey``). Nil, so left out of the report,
    /// unless `OutOfBandEnforcement` or `ExpiryEnforcement` is `enforce` (only enforcement
    /// depends on the confirmation) and SAP Privileges is installed. `availability` is the
    /// heartbeat's reading of the log.
    func grantConfirmationCheck(_ availability: PrivilegesLogAvailability? = nil) throws -> IntegrityResult? {
        guard env.config.outOfBandEnforcement == .enforce || env.config.expiryEnforcement == .enforce,
            env.device().privilegesVersion != nil
        else { return nil }
        if case .unavailable(let reason) = availability ?? env.privilegesLogAvailability() {
            return .failed(reason)
        }
        if try store.value(forKey: Self.extensionSilentKey) != nil {
            return .failed("Privileges' system extension logged no record of a Privileges grant")
        }
        return .ok
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
    /// no expiry, are left alone; ``enforceOutOfBand`` handles the latter.
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

    /// Out-of-band enforcement. In `enforce` mode, removes the rights of each out-of-band
    /// session that has lasted the grace period since it was raised (its persisted
    /// `startedAt`, so a restart doesn't reset the count), ends the session and raises
    /// `admin.out_of_band_removed`. `sessions` are open out-of-band sessions whose user is
    /// still admin and not a permanent admin.
    ///
    /// Safeguards:
    /// - while Privileges' hook check fails, nothing is removed: grants it doesn't report
    ///   would look like rights nobody granted;
    /// - a standing admin is kept: a removal that would leave none is skipped. Standing
    ///   admins are permanent admins who are admin now, and out-of-band admins past their
    ///   grace that this pass keeps. Holders of a Privileges session don't count, since
    ///   their rights end too, and nor do out-of-band admins still in their grace period or
    ///   admins with no session yet (raised out-of-band later in this heartbeat): they are
    ///   due for removal as well. Membership is read again here, after ``enforceExpiry``'s
    ///   removals, and the users it removed (`demoted`) are left out in case the read lags.
    ///   Newest first, then by short name, so the admin kept is the one seen longest, or of
    ///   those raised at the same moment the one whose short name sorts last.
    ///
    /// A removal that fails keeps the session and is retried on the next heartbeat; it
    /// doesn't stop older ones. Returns the events and the users removed.
    private func enforceOutOfBand(
        _ sessions: [OpenSession], demoted: Set<String>, integrity: [IntegrityCheck: IntegrityResult], now: Date,
        device: DeviceInfo
    ) throws -> (events: [AltiwardEvent], removed: Set<String>) {
        guard env.config.outOfBandEnforcement == .enforce else { return ([], []) }
        let current = env.admins.adminMembers().subtracting(demoted)
        let grace = env.config.outOfBandGracePeriod
        let isDue = { (s: OpenSession) in now >= s.startedAt.addingTimeInterval(grace) }
        let candidates = sessions.filter(isDue).sorted {
            $0.startedAt != $1.startedAt ? $0.startedAt > $1.startedAt : $0.user < $1.user
        }
        guard !candidates.isEmpty else { return ([], []) }

        if integrity[.privilegesHook]?.ok == false {
            let users = candidates.map(\.user).joined(separator: ", ")
            log.notice(
                "keeping out-of-band admin rights (\(users, privacy: .public)): Privileges' hook check is failing")
            return ([], [])
        }

        let permanent = current.intersection(env.config.permanentAdmins)
        let due = current.intersection(candidates.map(\.user))
        var events: [AltiwardEvent] = []
        var removed = Set<String>()
        for session in candidates {
            let remaining = permanent.union(due.subtracting(removed))
            if remaining.subtracting([session.user]).isEmpty {
                log.notice(
                    "keeping \(session.user, privacy: .public)'s out-of-band admin rights: the only standing admin on this Mac")
                continue
            }
            if let failure = removeFromAdminGroup(session.user) {
                log.notice(
                    "out-of-band removal for \(session.user, privacy: .public) failed: \(failure, privacy: .public)")
                continue
            }
            try store.closeSession(user: session.user)
            removed.insert(session.user)
            events.append(
                AltiwardEvent(
                    type: .adminOutOfBandRemoved, sessionID: session.sessionID, timestamp: now, device: device,
                    user: UserInfo(localName: session.user, upn: env.config.upn(for: session.user)),
                    elevation: ElevationInfo(source: .outOfBand),
                    detail: [
                        "trigger": "heartbeat", "first_observed": .date(session.startedAt),
                        "grace_seconds": .number(grace), "observed_admin": false, "verified": true,
                    ]))
        }
        return (events, removed)
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
    ///
    /// Held grant claims are resolved first (``resolvePendingClaims()``),
    /// and their events come first in what it returns. An admin whose claim is still in its
    /// confirmation window isn't raised, though when they were first seen is still kept: if
    /// the claim is refused, their rights count as out of band from then.
    public func checkUntrackedAdmins() throws -> [AltiwardEvent] {
        let resolved = resolveHeldClaims()
        let now = env.now()
        let device = env.device()
        // Read outside the transaction, and only when someone may be raised: it reads the
        // unified log, and a hook claim waits for the store meanwhile. Only an admin seen by
        // an earlier check can be past the grace period.
        let mayRaise = untrackedSince.withLock { $0.values.contains { now.timeIntervalSince($0) >= Self.untrackedGrace } }
        let audit = mayRaise ? env.privilegesAudit(now.addingTimeInterval(-auditLookback)) : []
        return try resolved + store.transaction {
            let untracked = untracked(admins: env.admins.adminMembers(), open: try store.openSessions())
            let held = try heldUsers(now: now)
            let confirmed = untrackedSince.withLock { since in
                since = Dictionary(uniqueKeysWithValues: untracked.map { ($0, since[$0] ?? now) })
                return Set(since.filter { now.timeIntervalSince($0.value) >= Self.untrackedGrace }.keys)
            }.subtracting(held)
            var events: [AltiwardEvent] = []
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
    /// system extension logged it. The session starts at `startedAt`, when the rights were
    /// first seen, or `now` when that isn't given; the grace period counts from it.
    func openOutOfBand(
        _ user: String, now: Date, startedAt: Date? = nil, device: DeviceInfo, audit: [PrivilegesAuditRecord]
    ) throws -> AltiwardEvent {
        let sessionID = newID()
        let firstObserved = startedAt ?? now
        try store.upsertOpenSession(
            OpenSession(user: user, sessionID: sessionID, source: .outOfBand, startedAt: firstObserved, expiresAt: nil))
        var detail: [String: JSONValue] = ["first_observed": .date(firstObserved)]
        if let instigator = try instigator(of: user, in: audit) { detail["instigator"] = instigator }
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
