import Foundation
import Testing
import os

@testable import AltiwardCore

/// Grant claims while Privileges' log is available: held, not recorded, until the log
/// confirms them. A claim is only a claim: the hook runs as the user.
struct ClaimConfirmationTests {
    let clock = TestClock()
    let admins = FakeAdmins()
    let privilegesLog = FakePrivilegesLog()
    let availability = OSAllocatedUnfairLock<PrivilegesLogAvailability>(initialState: .available)

    func tracker(
        availability: PrivilegesLogAvailability = .available, permanent: Set<String> = ["itadmin"],
        userID: @escaping @Sendable (String) -> UInt32? = { _ in nil }
    ) throws -> (ElevationTracker, AgentStore) {
        let store = try makeStore()
        let env = makeEnvironment(
            admins: admins, clock: clock, config: AgentConfiguration(permanentAdmins: permanent),
            privilegesLogAvailability: { availability }, userID: userID)
        return (ElevationTracker(store: store, environment: env), store)
    }

    func claim(_ user: String = "jdoe", _ state: HookInvocation.State = .admin) -> HookInvocation {
        HookInvocation(user: user, state: state, reason: "testing", invokedAt: clock.now)
    }

    func queued(_ store: AgentStore) throws -> [AltiwardEvent] {
        try store.pending(limit: 100).map(\.event)
    }

    @Test func withoutTheLogAGrantClaimIsRecordedAtOnce() throws {
        let (tracker, store) = try tracker(availability: .unavailable("x"))
        admins.set(["jdoe"])
        guard case .recorded(let event) = try tracker.submit(claim(), callerUID: 501) else {
            Issue.record("expected .recorded")
            return
        }
        #expect(event.type == .elevationGranted)
        #expect(try queued(store).map(\.type) == [.elevationGranted])
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func withTheLogAGrantClaimIsHeld() throws {
        let (tracker, store) = try tracker()
        admins.set(["jdoe"])
        guard case .pending(let id) = try tracker.submit(claim(), callerUID: 501) else {
            Issue.record("expected .pending")
            return
        }
        let held = try store.pendingClaims()
        #expect(held.count == 1)
        #expect(held.first?.claimID == id)
        #expect(held.first?.invocation.user == "jdoe")
        #expect(held.first?.invocation.invokedAt == clock.now)
        #expect(held.first?.callerUID == 501)
        #expect(!(try queued(store).map(\.type)).contains(.elevationGranted))
        #expect(try store.openSession(user: "jdoe") == nil)
    }

    @Test func permanentAdminAndGiveBackClaimsAreNotHeld() throws {
        let (tracker, store) = try tracker()
        admins.set(["itadmin"])
        guard case .recorded = try tracker.submit(claim("itadmin"), callerUID: 501) else {
            Issue.record("a permanent admin's claim should be recorded")
            return
        }
        guard case .recorded = try tracker.submit(claim("jdoe", .user), callerUID: 501) else {
            Issue.record("a give-back claim should be recorded")
            return
        }
        #expect(try store.pendingClaims().isEmpty)
        #expect(try queued(store).map(\.type) == [.elevationGranted, .elevationRevoked])
    }

    @Test func aClaimFromAnotherUsersProcessIsRefusedAndReported() throws {
        let (tracker, store) = try tracker(userID: { $0 == "jdoe" ? 501 : nil })
        #expect {
            try tracker.submit(claim(), callerUID: 502)
        } throws: { error in
            (error as? ElevationTracker.ClaimRefused)?.reason == .callerMismatch(callerUID: 502)
        }
        let events = try queued(store)
        #expect(events.map(\.type) == [.agentTamper])
        #expect(events[0].detail["check"] == .string("grant_claim"))
        #expect(events[0].detail["outcome"] == .string("refused"))
        #expect(events[0].detail["kind"] == .string("grant"))
        #expect(events[0].detail["user"] == .string("jdoe"))
        #expect(events[0].detail["caller_uid"] == .number(502))
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func aGiveBackFromAnotherUsersProcessIsReportedAsGiveBack() throws {
        let (tracker, store) = try tracker(userID: { $0 == "jdoe" ? 501 : nil })
        #expect(throws: ElevationTracker.ClaimRefused.self) {
            try tracker.submit(claim("jdoe", .user), callerUID: 502)
        }
        #expect(try queued(store).first?.detail["kind"] == .string("give_back"))
    }

    @Test func rootMayClaimForAnyone() throws {
        let (tracker, _) = try tracker(userID: { $0 == "jdoe" ? 501 : nil })
        guard case .pending = try tracker.submit(claim(), callerUID: 0) else {
            Issue.record("expected .pending")
            return
        }
    }

    @Test func theSixthClaimInAMinuteIsRefusedUnreported() throws {
        let (tracker, store) = try tracker()
        for _ in 0..<ElevationTracker.maxClaimsPerMinute {
            guard case .pending = try tracker.submit(claim(), callerUID: 501) else {
                Issue.record("expected .pending")
                return
            }
        }
        #expect {
            try tracker.submit(claim(), callerUID: 501)
        } throws: { error in
            (error as? ElevationTracker.ClaimRefused)?.reason == .tooManyClaims
        }
        #expect(try queued(store).isEmpty)
        // Another caller has a count of its own.
        guard case .pending = try tracker.submit(claim(), callerUID: 502) else {
            Issue.record("expected .pending")
            return
        }
        clock.advance(61)
        guard case .pending = try tracker.submit(claim(), callerUID: 501) else {
            Issue.record("expected .pending")
            return
        }
    }

    @Test func giveBackClaimsDoNotCountTowardsTheLimit() throws {
        let (tracker, store) = try tracker()
        for _ in 0..<ElevationTracker.maxClaimsPerMinute {
            guard case .pending = try tracker.submit(claim(), callerUID: 501) else {
                Issue.record("expected .pending")
                return
            }
        }
        // A real give-back after a run of grant claims is still recorded.
        guard case .recorded(let event) = try tracker.submit(claim("jdoe", .user), callerUID: 501) else {
            Issue.record("expected .recorded")
            return
        }
        #expect(event.type == .elevationRevoked)
        #expect(try queued(store).map(\.type) == [.elevationRevoked])
        // The grant limit still holds.
        #expect {
            try tracker.submit(claim(), callerUID: 501)
        } throws: { error in
            (error as? ElevationTracker.ClaimRefused)?.reason == .tooManyClaims
        }

        // Nor do give-backs use up a caller's grant claims.
        for _ in 0..<ElevationTracker.maxClaimsPerMinute {
            _ = try tracker.submit(claim("mallory", .user), callerUID: 502)
        }
        guard case .pending = try tracker.submit(claim("mallory"), callerUID: 502) else {
            Issue.record("expected .pending")
            return
        }
    }

    @Test func pastTheGiveBackAllowanceOnlyAGiveBackThatEndsASessionIsRecorded() throws {
        let (tracker, store) = try tracker(availability: .unavailable("x"))
        admins.set(["jdoe"])
        _ = try tracker.submit(claim(), callerUID: 501)
        for _ in 0..<ElevationTracker.maxGiveBacksPerMinute {
            _ = try tracker.submit(claim("mallory", .user), callerUID: 501)
        }
        let before = try queued(store).count
        #expect {
            try tracker.submit(claim("mallory", .user), callerUID: 501)
        } throws: { error in
            (error as? ElevationTracker.ClaimRefused)?.reason == .tooManyGiveBacks
        }
        #expect(try queued(store).count == before)
        // A real give-back past the allowance still ends the session.
        admins.set([])
        guard case .recorded(let event) = try tracker.submit(claim("jdoe", .user), callerUID: 501) else {
            Issue.record("expected .recorded")
            return
        }
        #expect(event.type == .elevationRevoked)
        #expect(event.detail["orphan"] == nil)
        #expect(try store.openSession(user: "jdoe") == nil)
        // The allowance doesn't touch grant claims, and refills after a minute.
        guard case .recorded = try tracker.submit(claim(), callerUID: 501) else {
            Issue.record("expected .recorded")
            return
        }
        clock.advance(61)
        guard case .recorded = try tracker.submit(claim("mallory", .user), callerUID: 501) else {
            Issue.record("expected .recorded")
            return
        }
    }

    @Test func pastTheGiveBackAllowanceAnotherUsersGiveBackIsNotReported() throws {
        let (tracker, store) = try tracker(userID: { $0 == "jdoe" ? 501 : nil })
        for _ in 0..<ElevationTracker.maxGiveBacksPerMinute {
            #expect(throws: ElevationTracker.ClaimRefused.self) {
                try tracker.submit(claim("jdoe", .user), callerUID: 502)
            }
        }
        #expect(tampers(try queued(store)).count == ElevationTracker.maxGiveBacksPerMinute)
        #expect {
            try tracker.submit(claim("jdoe", .user), callerUID: 502)
        } throws: { error in
            (error as? ElevationTracker.ClaimRefused)?.reason == .tooManyGiveBacks
        }
        #expect(tampers(try queued(store)).count == ElevationTracker.maxGiveBacksPerMinute)
    }
}

/// What Privileges' daemon and system extension logged, as the test writes it.
final class FakePrivilegesLog: Sendable {
    static let daemonPID: Int32 = 400
    static let extensionPID: Int32 = 500

    private let state = OSAllocatedUnfairLock<(lines: [PrivilegesDaemonLine], records: [PrivilegesAuditRecord])>(
        initialState: ([], []))

    var lines: [PrivilegesDaemonLine] { state.withLock { $0.lines } }
    var records: [PrivilegesAuditRecord] { state.withLock { $0.records } }

    /// A Privileges grant for `user` at `date`: the daemon's line, the extension's
    /// `ADMIN_ADD`, or both.
    func grant(_ user: String = "jdoe", at date: Date, daemon: Bool = true, extension: Bool = true) {
        state.withLock { s in
            if daemon {
                s.lines.append(PrivilegesDaemonLine(user: user, change: .granted, date: date, loggerPID: Self.daemonPID))
            }
            if `extension` {
                s.records.append(
                    PrivilegesAuditRecord(
                        eventType: "ADMIN_ADD", subject: user, date: date,
                        process: .init(
                            executable: "/Applications/Privileges.app/Contents/MacOS/PrivilegesDaemon",
                            signingID: PrivilegesSigning.daemon, teamID: PrivilegesSigning.teamID,
                            platformBinary: false, pid: Int(Self.daemonPID), ppid: 1, tty: ""),
                        loggerPID: Self.extensionPID))
            }
        }
    }

    /// A Privileges give-back for `user` at `date`: the daemon's "standard user" line and the
    /// extension's `ADMIN_REMOVE` by the daemon, a moment later.
    func giveBack(_ user: String = "jdoe", at date: Date) {
        state.withLock { s in
            s.lines.append(PrivilegesDaemonLine(user: user, change: .revoked, date: date, loggerPID: Self.daemonPID))
            s.records.append(
                PrivilegesAuditRecord(
                    eventType: "ADMIN_REMOVE", subject: user, date: date.addingTimeInterval(0.2),
                    process: .init(
                        executable: "/Applications/Privileges.app/Contents/MacOS/PrivilegesDaemon",
                        signingID: PrivilegesSigning.daemon, teamID: PrivilegesSigning.teamID,
                        platformBinary: false, pid: Int(Self.daemonPID), ppid: 1, tty: ""),
                    loggerPID: Self.extensionPID))
        }
    }
}

/// Resolving held claims: confirmed by SAP's own log, or after the confirmation window
/// refused (or, in `alert` mode, accepted and flagged).
extension ClaimConfirmationTests {
    func resolving(
        _ mode: OutOfBandEnforcement = .enforce,
        privileges: PrivilegesSettings = PrivilegesSettings(expirationIntervalMinutes: 20),
        store existing: AgentStore? = nil
    ) throws -> (ElevationTracker, AgentStore) {
        let store = try existing ?? makeStore()
        let log = privilegesLog
        let availability = availability
        let started = clock.now.addingTimeInterval(-3600)
        let identities: [Int32: ProcessIdentity] = [
            FakePrivilegesLog.daemonPID: ProcessIdentity(
                signingID: PrivilegesSigning.daemon, teamID: PrivilegesSigning.teamID, startedAt: started, uid: 0),
            FakePrivilegesLog.extensionPID: ProcessIdentity(
                signingID: PrivilegesSigning.systemExtension, teamID: PrivilegesSigning.teamID, startedAt: started,
                uid: 0),
        ]
        let env = makeEnvironment(
            admins: admins, clock: clock, privileges: privileges,
            config: AgentConfiguration(permanentAdmins: ["itadmin"], outOfBandEnforcement: mode),
            privilegesAudit: { since in log.records.filter { $0.date >= since } },
            privilegesLogAvailability: { availability.withLock { $0 } },
            privilegesDaemonLines: { since in log.lines.filter { $0.date >= since } },
            processIdentity: { identities[$0] })
        return (ElevationTracker(store: store, environment: env), store)
    }

    /// Submits a grant claim for `user` now and expects it held.
    @discardableResult
    func hold(_ tracker: ElevationTracker, _ user: String = "jdoe") throws -> HookInvocation {
        let invocation = claim(user)
        guard case .pending = try tracker.submit(invocation, callerUID: 501) else {
            Issue.record("expected .pending")
            return invocation
        }
        return invocation
    }

    func tampers(_ events: [AltiwardEvent]) -> [AltiwardEvent] {
        events.filter { $0.type == .agentTamper && $0.detail["check"] == .string("grant_claim") }
    }

    @Test func aConfirmedClaimOpensAPrivilegesSession() throws {
        let (tracker, store) = try resolving()
        admins.set(["jdoe", "itadmin"])
        privilegesLog.grant(at: clock.now.addingTimeInterval(-0.3))
        try hold(tracker)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.elevationGranted])
        let granted = try #require(events.first)
        #expect(granted.detail["privileges_log"] == .string("confirmed"))
        #expect(granted.detail["evidence"] == .strings(["daemon", "extension"]))
        #expect(granted.detail["confirmed_at"] == .date(clock.now))
        #expect(granted.timestamp == clock.now)
        #expect(try store.openSession(user: "jdoe")?.source == .privileges)
        #expect(try store.pendingClaims().isEmpty)
        #expect(try queued(store).map(\.type) == [.elevationGranted])
        #expect(try store.value(forKey: "extension_silent_since") == nil)
    }

    @Test func evidenceArrivingAfterTheClaimConfirmsIt() throws {
        let (tracker, store) = try resolving()
        admins.set(["jdoe", "itadmin"])
        let invocation = try hold(tracker)
        #expect(try tracker.resolvePendingClaims().isEmpty)
        #expect(try store.pendingClaims().count == 1)
        clock.advance(2)
        privilegesLog.grant(at: clock.now)
        clock.advance(1)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.elevationGranted])
        #expect(events.first?.detail["privileges_log"] == .string("confirmed"))
        #expect(events.first?.timestamp == invocation.invokedAt)
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func aDaemonLineWaitsForTheExtensionsRecord() throws {
        // The extension's record lands a moment after the daemon's line, and either can take
        // up to a second to be readable: a check can see the line alone.
        let (tracker, store) = try resolving()
        admins.set(["jdoe", "itadmin"])
        let daemonAt = clock.now.addingTimeInterval(-0.3)
        privilegesLog.grant(at: daemonAt, extension: false)
        try hold(tracker)
        #expect(try tracker.resolvePendingClaims().isEmpty)
        #expect(try store.pendingClaims().count == 1)
        #expect(try store.value(forKey: ElevationTracker.extensionSilentKey) == nil)

        clock.advance(0.5)
        privilegesLog.grant(at: daemonAt.addingTimeInterval(0.2), daemon: false)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.elevationGranted])
        #expect(events.first?.detail["evidence"] == .strings(["daemon", "extension"]))
        #expect(try store.value(forKey: ElevationTracker.extensionSilentKey) == nil)
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func aGrantUpToTwoMinutesBeforeTheClaimConfirmsIt() throws {
        let (tracker, store) = try resolving()
        admins.set(["jdoe", "itadmin"])
        let grantedAt = clock.now
        privilegesLog.grant(at: grantedAt)
        clock.advance(100)
        try hold(tracker)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.elevationGranted])
        #expect(events.first?.detail["privileges_log"] == .string("confirmed"))
        #expect(try store.openSession(user: "jdoe")?.expiresAt == grantedAt.addingTimeInterval(20 * 60))
    }

    @Test func aGrantMoreThanTwoMinutesBeforeTheClaimDoesNotConfirmIt() throws {
        let (tracker, store) = try resolving(.enforce)
        admins.set(["jdoe", "itadmin"])
        privilegesLog.grant(at: clock.now)
        clock.advance(121)
        try hold(tracker)
        #expect(try tracker.resolvePendingClaims().isEmpty)
        clock.advance(61)
        let events = try tracker.resolvePendingClaims()
        #expect(tampers(events).first?.detail["outcome"] == .string("refused"))
        #expect(!events.map(\.type).contains(.elevationGranted))
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func aQuickGiveBackDoesNotVoidTheGrant() throws {
        // A real grant, given back by Privileges 5 s after its claim arrived and before the
        // claim was resolved: the claim was true, so it is confirmed, not reported.
        let (tracker, store) = try resolving(.enforce)
        admins.set(["jdoe", "itadmin"])
        privilegesLog.grant(at: clock.now.addingTimeInterval(-0.3))
        try hold(tracker)
        clock.advance(5)
        privilegesLog.giveBack(at: clock.now)
        admins.set(["itadmin"])
        clock.advance(1)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.elevationGranted])
        #expect(events.first?.detail["privileges_log"] == .string("confirmed"))
        #expect(events.first?.detail["evidence"] == .strings(["daemon", "extension"]))
        #expect(tampers(events).isEmpty)
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func aGiveBackBeforeTheClaimStillVoidsTheGrant() throws {
        // Grant, give back, then a hand-run claim: the earlier grant backs nothing.
        let (tracker, store) = try resolving(.enforce)
        admins.set(["itadmin"])
        privilegesLog.grant(at: clock.now)
        privilegesLog.giveBack(at: clock.now.addingTimeInterval(5))
        clock.advance(10)
        try hold(tracker)
        clock.advance(61)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.agentTamper])
        #expect(tampers(events).first?.detail["outcome"] == .string("refused"))
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func anUnbackedClaimInEnforceModeIsRefusedAndTheRightsStayOutOfBand() throws {
        let (tracker, store) = try resolving(.enforce)
        admins.set(["jdoe", "itadmin"])
        let invocation = try hold(tracker)
        clock.advance(30)
        #expect(try tracker.resolvePendingClaims().isEmpty)
        clock.advance(31)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.agentTamper, .adminOutOfBand])
        let tamper = try #require(tampers(events).first)
        #expect(tamper.detail["outcome"] == .string("refused"))
        #expect(tamper.detail["kind"] == .string("grant"))
        #expect(tamper.detail["user"] == .string("jdoe"))
        let session = try #require(try store.openSession(user: "jdoe"))
        #expect(session.source == .outOfBand)
        #expect(session.startedAt == invocation.invokedAt)
        #expect(events.last?.detail["first_observed"] == .date(invocation.invokedAt))
        #expect(try store.pendingClaims().isEmpty)
        #expect(!(try queued(store).map(\.type)).contains(.elevationGranted))

        clock.advance(300)
        #expect(try tracker.heartbeat().map(\.type).contains(.adminOutOfBandRemoved))
        #expect(!admins.isAdmin(user: "jdoe"))
    }

    @Test func aRefusedClaimCountsTheRightsFromWhenTheyWereFirstSeen() throws {
        let (tracker, store) = try resolving(.enforce)
        admins.set(["jdoe", "itadmin"])
        let firstSeen = clock.now
        #expect(try tracker.checkUntrackedAdmins().isEmpty)
        clock.advance(20)
        try hold(tracker)
        clock.advance(61)
        _ = try tracker.resolvePendingClaims()
        #expect(try store.openSession(user: "jdoe")?.startedAt == firstSeen)
    }

    @Test func anUnbackedClaimInAlertModeIsAcceptedAndFlagged() throws {
        let (tracker, store) = try resolving(.alert)
        admins.set(["jdoe", "itadmin"])
        let invocation = try hold(tracker)
        clock.advance(61)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.elevationGranted, .agentTamper])
        #expect(events.first?.detail["privileges_log"] == .string("not_confirmed"))
        #expect(events.first?.timestamp == invocation.invokedAt)
        #expect(tampers(events).first?.detail["outcome"] == .string("accepted_unconfirmed"))
        #expect(tampers(events).first?.detail["kind"] == .string("grant"))
        #expect(try store.openSession(user: "jdoe")?.source == .privileges)
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test(arguments: [OutOfBandEnforcement.alert, .enforce])
    func anUnbackedRenewalNeverMovesTheExpiry(_ mode: OutOfBandEnforcement) throws {
        let (tracker, store) = try resolving(mode)
        admins.set(["jdoe", "itadmin"])
        privilegesLog.grant(at: clock.now.addingTimeInterval(-0.3))
        try hold(tracker)
        _ = try tracker.resolvePendingClaims()
        let expiry = try #require(try store.openSession(user: "jdoe")?.expiresAt)

        clock.advance(600)
        try hold(tracker)
        clock.advance(61)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.agentTamper])
        #expect(events.first?.detail["kind"] == .string("renewal"))
        #expect(events.first?.detail["outcome"] == .string("refused"))
        #expect(try store.openSession(user: "jdoe")?.expiresAt == expiry)
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func aPendingClaimHoldsBackTheOutOfBandRaise() throws {
        let (tracker, store) = try resolving(.enforce)
        admins.set(["jdoe", "itadmin"])
        try hold(tracker)
        #expect(try tracker.checkUntrackedAdmins().isEmpty)
        clock.advance(31)
        #expect(try tracker.checkUntrackedAdmins().isEmpty)
        #expect(!(try tracker.heartbeat()).contains { $0.type == .adminOutOfBand && $0.user?.localName == "jdoe" })
        #expect(try store.openSession(user: "jdoe") == nil)
        #expect(try store.pendingClaims().count == 1)
    }

    @Test func theHeartbeatResolvesAClaimWhoseWindowIsOver() throws {
        let (tracker, store) = try resolving(.enforce)
        admins.set(["jdoe", "itadmin"])
        try hold(tracker)
        clock.advance(61)
        let events = try tracker.heartbeat()
        #expect(tampers(events).first?.detail["outcome"] == .string("refused"))
        #expect(events.filter { $0.type == .adminOutOfBand }.count == 1)
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func aConfirmedGrantOverridesTheLateRefusal() throws {
        let (tracker, store) = try resolving(.enforce)
        admins.set(["jdoe", "itadmin"])
        let raised = try #require(try tracker.heartbeat().first { $0.type == .adminOutOfBand })
        clock.advance(120)
        privilegesLog.grant(at: clock.now.addingTimeInterval(-0.3))
        try hold(tracker)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.elevationRevoked, .elevationGranted])
        #expect(events.first?.sessionID == raised.sessionID)
        #expect(events.first?.detail["trigger"] == .string("privileges_grant"))
        #expect(events.last?.detail["replaced_out_of_band"] == true)
        #expect(events.last?.detail["privileges_log"] == .string("confirmed"))
        #expect(try store.openSession(user: "jdoe")?.source == .privileges)
    }

    @Test func theExpiryCountsFromTheEvidence() throws {
        let (tracker, store) = try resolving()
        admins.set(["jdoe", "itadmin"])
        let grantedAt = clock.now
        privilegesLog.grant(at: grantedAt, extension: false)
        clock.advance(5)
        try hold(tracker)
        _ = try tracker.resolvePendingClaims()
        #expect(try store.openSession(user: "jdoe")?.expiresAt == grantedAt.addingTimeInterval(20 * 60))
    }

    @Test func aPendingClaimSurvivesARestart() throws {
        let (first, store) = try resolving()
        admins.set(["jdoe", "itadmin"])
        let invocation = try hold(first)
        let (tracker, _) = try resolving(store: store)
        clock.advance(120)
        privilegesLog.grant(at: invocation.invokedAt)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.elevationGranted])
        #expect(events.first?.detail["privileges_log"] == .string("confirmed"))
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func aDaemonOnlyConfirmationFailsTheExtensionCheckState() throws {
        let (tracker, store) = try resolving()
        admins.set(["jdoe", "itadmin"])
        privilegesLog.grant(at: clock.now.addingTimeInterval(-0.3), extension: false)
        try hold(tracker)
        // Held while the extension's record may still be on its way, then confirmed without it.
        #expect(try tracker.resolvePendingClaims().isEmpty)
        clock.advance(ClaimEvidence.combineWithin)
        let events = try tracker.resolvePendingClaims()
        #expect(events.first?.detail["evidence"] == .strings(["daemon"]))
        #expect(try store.value(forKey: "extension_silent_since") != nil)

        clock.advance(600)
        admins.set(["itadmin"])
        _ = try tracker.heartbeat()
        admins.set(["jdoe", "itadmin"])
        privilegesLog.grant(at: clock.now.addingTimeInterval(-0.3))
        try hold(tracker)
        let second = try tracker.resolvePendingClaims()
        #expect(second.first?.detail["evidence"] == .strings(["daemon", "extension"]))
        #expect(try store.value(forKey: "extension_silent_since") == nil)
    }

    @Test func oneGrantConfirmsOneClaim() throws {
        let (tracker, store) = try resolving(.enforce)
        admins.set(["jdoe", "itadmin"])
        privilegesLog.grant(at: clock.now.addingTimeInterval(-0.3))
        try hold(tracker)
        _ = try tracker.resolvePendingClaims()
        #expect(try store.value(forKey: "grant_evidence_consumed") != nil)
        // A hand-run claim straight after, resolved by a tracker that starts afresh.
        clock.advance(1)
        try hold(tracker)
        let (restarted, _) = try resolving(.enforce, store: store)
        clock.advance(61)
        let events = try restarted.resolvePendingClaims()
        #expect(events.map(\.type) == [.agentTamper])
        #expect(events.first?.detail["kind"] == .string("renewal"))
    }

    @Test func aLateClaimRefusedWithoutTheLogIsReported() throws {
        let (tracker, store) = try resolving(.enforce)
        availability.withLock { $0 = .unavailable("extension not running") }
        admins.set(["jdoe", "itadmin"])
        _ = try tracker.heartbeat()
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
        clock.advance(61)
        let before = try queued(store).count
        #expect {
            try tracker.submit(claim(), callerUID: 501)
        } throws: { error in
            (error as? ElevationTracker.ClaimRefused)?.reason == .late(seconds: 61)
        }
        let added = Array(try queued(store).dropFirst(before))
        #expect(added.map(\.type) == [.agentTamper])
        #expect(added.first?.detail["check"] == .string("grant_claim"))
        #expect(added.first?.detail["outcome"] == .string("refused"))
        #expect(added.first?.detail["kind"] == .string("grant"))
        #expect(added.first?.detail["caller_uid"] == .number(501))
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
    }

    @Test func aGiveBackWhileStillAdminIsReported() throws {
        let (tracker, store) = try resolving(.enforce)
        admins.set(["jdoe", "itadmin"])
        _ = try tracker.heartbeat()
        let before = try queued(store).count
        #expect {
            try tracker.submit(claim("jdoe", .user), callerUID: 501)
        } throws: { error in
            (error as? ElevationTracker.ClaimRefused)?.reason == .stillAdmin
        }
        let added = Array(try queued(store).dropFirst(before))
        #expect(added.map(\.type) == [.agentTamper])
        #expect(added.first?.detail["check"] == .string("grant_claim"))
        #expect(added.first?.detail["outcome"] == .string("refused"))
        #expect(added.first?.detail["kind"] == .string("give_back"))
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
    }

    @Test func pastTheGiveBackAllowanceAGiveBackWhileStillAdminIsNotReported() throws {
        let (tracker, store) = try resolving(.enforce)
        admins.set(["jdoe", "itadmin"])
        _ = try tracker.heartbeat()
        let before = try queued(store).count
        for _ in 0..<ElevationTracker.maxGiveBacksPerMinute {
            #expect(throws: ElevationTracker.ClaimRefused.self) {
                try tracker.submit(claim("jdoe", .user), callerUID: 501)
            }
        }
        let reported = try queued(store).count
        #expect(reported - before == ElevationTracker.maxGiveBacksPerMinute)
        #expect {
            try tracker.submit(claim("jdoe", .user), callerUID: 501)
        } throws: { error in
            (error as? ElevationTracker.ClaimRefused)?.reason == .tooManyGiveBacks
        }
        #expect(try queued(store).count == reported)
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
    }

    @Test func aClaimHeldWhileTheLogWasLostIsAcceptedNotRefused() throws {
        let (tracker, store) = try resolving(.enforce)
        admins.set(["jdoe", "itadmin"])
        try hold(tracker)
        availability.withLock { $0 = .unavailable("extension not running") }
        clock.advance(1)
        // Resolved at once: the window can't bring the evidence now.
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.elevationGranted, .agentTamper])
        #expect(events.first?.detail["privileges_log"] == .string("unavailable"))
        let tamper = try #require(tampers(events).first)
        #expect(tamper.detail["outcome"] == .string("accepted_unconfirmed"))
        #expect(tamper.detail["kind"] == .string("grant"))
        #expect(tamper.detail["reason"] == .string("Privileges' log was available on this Mac before and isn't now"))
        #expect(try store.openSession(user: "jdoe")?.source == .privileges)
        #expect(try store.pendingClaims().isEmpty)

        clock.advance(300)
        let later = try tracker.heartbeat()
        #expect(!later.contains { $0.type == .adminOutOfBand || $0.type == .adminOutOfBandRemoved })
        #expect(admins.isAdmin(user: "jdoe"))
        #expect(admins.removalAttempts == 0)
    }

    @Test func aRenewalHeldWhileTheLogWasLostIsStillRefused() throws {
        let (tracker, store) = try resolving(.alert)
        admins.set(["jdoe", "itadmin"])
        privilegesLog.grant(at: clock.now.addingTimeInterval(-0.3))
        try hold(tracker)
        _ = try tracker.resolvePendingClaims()
        let expiry = try #require(try store.openSession(user: "jdoe")?.expiresAt)
        clock.advance(600)
        try hold(tracker)
        availability.withLock { $0 = .unavailable("extension not running") }
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.agentTamper])
        #expect(events.first?.detail["kind"] == .string("renewal"))
        #expect(events.first?.detail["outcome"] == .string("refused"))
        #expect(try store.openSession(user: "jdoe")?.expiresAt == expiry)
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func losingTheLogAfterSeeingItIsReported() throws {
        let (tracker, store) = try resolving()
        admins.set(["itadmin"])
        _ = try tracker.heartbeat()
        #expect(try store.value(forKey: "privileges_log_seen") != nil)
        availability.withLock { $0 = .unavailable("extension not running") }
        clock.advance(10)
        admins.set(["jdoe", "itadmin"])
        let before = try queued(store).count
        guard case .recorded(let event) = try tracker.submit(claim(), callerUID: 501) else {
            Issue.record("expected .recorded")
            return
        }
        #expect(event.type == .elevationGranted)
        #expect(event.detail["privileges_log"] == .string("unavailable"))
        let added = Array(try queued(store).dropFirst(before))
        #expect(added.map(\.type) == [.elevationGranted, .agentTamper])
        #expect(added.last?.detail["outcome"] == .string("accepted_unconfirmed"))
        #expect(added.last?.detail["kind"] == .string("grant"))
        #expect(added.last?.detail["reason"] == .string("Privileges' log was available on this Mac before and isn't now"))
    }

    @Test func withoutTheLogEverSeenAnUnconfirmedClaimIsOnlyMarked() throws {
        let (tracker, store) = try resolving()
        availability.withLock { $0 = .unavailable("extension not running") }
        admins.set(["jdoe", "itadmin"])
        guard case .recorded(let event) = try tracker.submit(claim(), callerUID: 501) else {
            Issue.record("expected .recorded")
            return
        }
        #expect(event.detail["privileges_log"] == .string("unavailable"))
        #expect(try queued(store).map(\.type) == [.elevationGranted])
        #expect(try store.value(forKey: "privileges_log_seen") == nil)
    }

    // MARK: The grant_confirmation standing check

    /// The `grant_confirmation` entry of the health event's `integrity` map, nil when left out.
    func health(_ events: [AltiwardEvent]) -> JSONValue? {
        guard case .object(let integrity)? = events.first(where: { $0.type == .agentHealth })?.detail["integrity"]
        else { return nil }
        return integrity["grant_confirmation"]
    }

    func checkTampers(_ events: [AltiwardEvent]) -> [JSONValue] {
        events.filter { $0.type == .agentTamper && $0.detail["check"] == .string("grant_confirmation") }
            .map { .object($0.detail) }
    }

    @Test func theCheckIsLeftOutWithoutEnforcement() throws {
        availability.withLock { $0 = .unavailable("extension not running") }
        let (tracker, _) = try resolving(.alert)
        let events = try tracker.heartbeat()
        #expect(health(events) == nil)
        #expect(checkTampers(events).isEmpty)
        #expect(try tracker.grantConfirmationCheck() == nil)
        // Expiry enforcement alone switches the check on.
        let env = makeEnvironment(
            admins: admins, clock: clock,
            config: AgentConfiguration(expiryEnforcement: .enforce),
            privilegesLogAvailability: { .unavailable("extension not running") })
        let expiryOnly = ElevationTracker(store: try makeStore(), environment: env)
        #expect(try expiryOnly.grantConfirmationCheck() == .failed("extension not running"))
    }

    @Test func theCheckIsLeftOutWithoutPrivileges() throws {
        let env = makeEnvironment(
            admins: admins, clock: clock,
            config: AgentConfiguration(outOfBandEnforcement: .enforce),
            device: {
                var d = testDevice
                d.privilegesVersion = nil
                return d
            },
            privilegesLogAvailability: { .unavailable("extension not running") })
        let tracker = ElevationTracker(store: try makeStore(), environment: env)
        let events = try tracker.heartbeat()
        #expect(health(events) == nil)
        #expect(checkTampers(events).isEmpty)
        #expect(try tracker.grantConfirmationCheck() == nil)
    }

    @Test func theCheckFailsWithTheReasonWhenTheLogIsMissing() throws {
        let (tracker, _) = try resolving()
        var events = try tracker.heartbeat()
        #expect(health(events) == .bool(true))
        #expect(checkTampers(events).isEmpty)

        availability.withLock { $0 = .unavailable("Privileges' system extension isn't running") }
        clock.advance(60)
        events = try tracker.heartbeat()
        #expect(health(events) == .bool(false))
        #expect(
            checkTampers(events) == [
                [
                    "check": "grant_confirmation", "state": "failed",
                    "problem": "Privileges' system extension isn't running",
                ]
            ])

        availability.withLock { $0 = .available }
        clock.advance(60)
        events = try tracker.heartbeat()
        #expect(health(events) == .bool(true))
        #expect(checkTampers(events) == [["check": "grant_confirmation", "state": "restored", "problem": .null]])
    }

    @Test func theCheckFailsWhileTheExtensionIsSilent() throws {
        let (tracker, store) = try resolving()
        admins.set(["jdoe", "itadmin"])
        privilegesLog.grant(at: clock.now.addingTimeInterval(-0.3), extension: false)
        try hold(tracker)
        // Nothing fails while the extension's record may still be on its way.
        let early = try tracker.heartbeat()
        #expect(health(early) == .bool(true))
        #expect(checkTampers(early).isEmpty)
        clock.advance(ClaimEvidence.combineWithin)
        let events = try tracker.heartbeat()
        #expect(try store.value(forKey: ElevationTracker.extensionSilentKey) != nil)
        #expect(health(events) == .bool(false))
        #expect(
            checkTampers(events) == [
                [
                    "check": "grant_confirmation", "state": "failed",
                    "problem": "Privileges' system extension logged no record of a Privileges grant",
                ]
            ])

        // A later confirmed grant carries the extension's record: the check recovers.
        clock.advance(600)
        admins.set(["itadmin"])
        _ = try tracker.heartbeat()
        admins.set(["jdoe", "itadmin"])
        privilegesLog.grant(at: clock.now.addingTimeInterval(-0.3))
        try hold(tracker)
        let after = try tracker.heartbeat()
        #expect(try store.value(forKey: ElevationTracker.extensionSilentKey) == nil)
        #expect(health(after) == .bool(true))
        #expect(checkTampers(after) == [["check": "grant_confirmation", "state": "restored", "problem": .null]])
    }

    @Test func theCheckPassesWithTheLog() throws {
        let (tracker, _) = try resolving()
        admins.set(["jdoe", "itadmin"])
        privilegesLog.grant(at: clock.now.addingTimeInterval(-0.3))
        try hold(tracker)
        let events = try tracker.heartbeat()
        #expect(health(events) == .bool(true))
        #expect(checkTampers(events).isEmpty)
    }
}

/// The hook waits only 5 s for its answer, so nothing slow runs inside the call (#91):
/// Privileges' timer is read after it, and the log outside the store's lock.
extension ClaimConfirmationTests {
    /// A tracker whose grants take their expiry from Privileges' timer, which counts its reads.
    func timed(
        availability: PrivilegesLogAvailability, mode: OutOfBandEnforcement = .alert,
        reads: OSAllocatedUnfairLock<Int>, expires: Date
    ) throws -> (ElevationTracker, AgentStore) {
        let store = try makeStore()
        let env = makeEnvironment(
            admins: admins, clock: clock, privileges: PrivilegesSettings(),
            config: AgentConfiguration(permanentAdmins: ["itadmin"], outOfBandEnforcement: mode),
            privilegesTimer: { _, _ in
                reads.withLock { $0 += 1 }
                return expires
            },
            privilegesLogAvailability: { availability })
        return (ElevationTracker(store: store, environment: env), store)
    }

    @Test func withoutTheLogAClaimNeedingPrivilegesTimerIsAnsweredBeforeItIsRead() throws {
        let reads = OSAllocatedUnfairLock(initialState: 0)
        let expires = clock.now.addingTimeInterval(1800)
        let (tracker, store) = try timed(availability: .unavailable("x"), reads: reads, expires: expires)
        admins.set(["jdoe"])
        guard case .pending = try tracker.submit(claim(), callerUID: 501) else {
            Issue.record("expected .pending")
            return
        }
        #expect(reads.withLock { $0 } == 0)
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.elevationGranted])
        #expect(events.first?.detail["privileges_log"] == .string("unavailable"))
        #expect(events.first?.timestamp == clock.now)
        #expect(reads.withLock { $0 } > 0)
        #expect(try store.openSession(user: "jdoe")?.expiresAt == expires)
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func withoutTheLogALateClaimNeedingTheTimerIsStillRefusedAndReported() throws {
        let reads = OSAllocatedUnfairLock(initialState: 0)
        let (tracker, store) = try timed(
            availability: .unavailable("x"), mode: .enforce, reads: reads, expires: clock.now.addingTimeInterval(1800))
        admins.set(["jdoe", "itadmin"])
        _ = try tracker.heartbeat()
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
        clock.advance(61)
        guard case .pending = try tracker.submit(claim(), callerUID: 501) else {
            Issue.record("expected .pending")
            return
        }
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.agentTamper])
        #expect(events.first?.detail["outcome"] == .string("refused"))
        #expect(events.first?.detail["reason"] == .string(
            ElevationTracker.ClaimRefused(user: "jdoe", reason: .late(seconds: 61)).description))
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
    }

    @Test func aPermanentAdminsClaimNeedingTheTimerIsAnsweredBeforeItIsRead() throws {
        let reads = OSAllocatedUnfairLock(initialState: 0)
        let expires = clock.now.addingTimeInterval(1800)
        let (tracker, store) = try timed(availability: .available, reads: reads, expires: expires)
        admins.set(["itadmin"])
        guard case .pending = try tracker.submit(claim("itadmin"), callerUID: 501) else {
            Issue.record("expected .pending")
            return
        }
        #expect(reads.withLock { $0 } == 0)
        // Recorded as before, without waiting for Privileges' log.
        let events = try tracker.resolvePendingClaims()
        #expect(events.map(\.type) == [.elevationGranted])
        #expect(events.first?.detail["privileges_log"] == nil)
        #expect(try store.openSession(user: "itadmin")?.expiresAt == expires)
    }

    @Test func aFixedExpirationIntervalNeedsNoTimerSoTheClaimIsRecordedAtOnce() throws {
        let (tracker, _) = try tracker(availability: .unavailable("x"))
        admins.set(["jdoe"])
        guard case .recorded = try tracker.submit(claim(), callerUID: 501) else {
            Issue.record("expected .recorded")
            return
        }
    }

    @Test func raisingAnAdminReadsTheAuditLogOutsideTheStoresLock() throws {
        let store = try makeStore()
        let heldDuringRead = OSAllocatedUnfairLock(initialState: false)
        let env = makeEnvironment(
            admins: admins, clock: clock,
            privilegesAudit: { _ in
                // Another thread's transaction finishes only if this check isn't holding the lock.
                let done = DispatchSemaphore(value: 0)
                Thread.detachNewThread {
                    _ = try? store.transaction { () }
                    done.signal()
                }
                if done.wait(timeout: .now() + 1) == .timedOut { heldDuringRead.withLock { $0 = true } }
                return []
            })
        let tracker = ElevationTracker(store: store, environment: env)
        admins.set(["jdoe"])
        _ = try tracker.checkUntrackedAdmins()
        clock.advance(31)
        let raised = try tracker.checkUntrackedAdmins()
        #expect(raised.map(\.type) == [.adminOutOfBand])
        #expect(!heldDuringRead.withLock { $0 })
    }
}

struct ClaimStepsTests {
    @Test func aSlowAnswerSaysWhatItWaitedFor() {
        let now = OSAllocatedUnfairLock(initialState: 100.0)
        let steps = ClaimSteps(uptime: { now.withLock { $0 } })
        steps.time("Privileges' log check") { now.withLock { $0 += 0.3 } }
        steps.time("settings") { now.withLock { $0 += 0.1 } }
        now.withLock { $0 += 3 }
        #expect(steps.slowSummary() == "3.4 s (Privileges' log check 0.3 s, settings 0.1 s, recording 3.0 s)")
    }

    @Test func aQuickAnswerIsNotLogged() {
        let now = OSAllocatedUnfairLock(initialState: 100.0)
        let steps = ClaimSteps(uptime: { now.withLock { $0 } })
        steps.time("settings") { now.withLock { $0 += 0.5 } }
        #expect(steps.slowSummary() == nil)
    }
}
