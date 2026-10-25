import Foundation
import os
import Testing

@testable import AltiwardCore

struct ElevationTrackerTests {
    let clock = TestClock()

    func grant(_ user: String = "jdoe", reason: String? = "work") -> HookInvocation {
        HookInvocation(user: user, state: .admin, reason: reason, invokedAt: clock.now)
    }

    func revoke(_ user: String = "jdoe") -> HookInvocation {
        HookInvocation(user: user, state: .user, reason: nil, invokedAt: clock.now)
    }

    @Test func grantThenRevokeShareOneSession() throws {
        let store = try makeStore()
        let admins = FakeAdmins(["jdoe"])
        let tracker = ElevationTracker(store: store, environment: makeEnvironment(admins: admins, clock: clock))

        let granted = try tracker.record(grant(), callerUID: 501)
        #expect(granted.type == .elevationGranted)
        #expect(granted.elevation?.reason == "work")
        #expect(granted.elevation?.expires == clock.now.addingTimeInterval(20 * 60))
        #expect(granted.detail["verified"] == true)
        #expect(granted.detail["expires_basis"] == "ExpirationInterval")
        #expect(granted.detail["caller_uid"] == 501)
        #expect(try store.openSession(user: "jdoe")?.sessionID == granted.sessionID)

        admins.set([])
        clock.advance(600)
        let revoked = try tracker.record(revoke())
        #expect(revoked.type == .elevationRevoked)
        #expect(revoked.sessionID == granted.sessionID)
        #expect(revoked.detail["verified"] == true)
        #expect(revoked.detail["orphan"] == nil)
        #expect(try store.openSession(user: "jdoe") == nil)
        #expect(try store.pending(limit: 10).map(\.event.eventID) == [granted.eventID, revoked.eventID])
    }

    @Test func renewalKeepsSessionAndStart() throws {
        let store = try makeStore()
        let tracker = ElevationTracker(
            store: store, environment: makeEnvironment(admins: FakeAdmins(["jdoe"]), clock: clock))
        let first = try tracker.record(grant())
        let start = clock.now
        clock.advance(900)
        let second = try tracker.record(grant())
        #expect(second.sessionID == first.sessionID)
        #expect(second.detail["renewed"] == true)
        #expect(try store.openSession(user: "jdoe")?.startedAt == start)
    }

    @Test func contradictoryGiveBackKeepsSessionUntilMembershipLoss() throws {
        let store = try makeStore()
        let admins = FakeAdmins(["jdoe"])
        let tracker = ElevationTracker(
            store: store, environment: makeEnvironment(admins: admins, clock: clock))
        let granted = try tracker.record(grant())
        let original = try #require(try store.openSession(user: "jdoe"))

        #expect(throws: ElevationTracker.ClaimRefused.self) { try tracker.record(revoke()) }
        #expect(try store.openSession(user: "jdoe") == original)
        #expect(try store.pending(limit: 10).map(\.event.type) == [.elevationGranted])

        // A directory reading that lags the genuine give-back is retried by the heartbeat.
        admins.set([])
        clock.advance(30)
        let revoked = try #require(try tracker.heartbeat().first { $0.type == .elevationRevoked })
        #expect(revoked.sessionID == granted.sessionID)
        #expect(revoked.detail["verified"] == true)
        #expect(try store.openSession(user: "jdoe") == nil)
    }

    @Test func claimThatContradictsAdminGroupIsUnverified() throws {
        // A user running the hook by hand to fake a revoke while still admin.
        let store = try makeStore()
        let tracker = ElevationTracker(
            store: store, environment: makeEnvironment(admins: FakeAdmins(["jdoe"]), clock: clock))
        let event = try tracker.record(revoke())
        #expect(event.detail["verified"] == false)
        #expect(event.detail["observed_admin"] == true)
        #expect(event.detail["orphan"] == true)
    }

    @Test func noExpiryWhenIntervalIsZero() throws {
        let store = try makeStore()
        let env = makeEnvironment(
            admins: FakeAdmins(["jdoe"]), clock: clock, privileges: PrivilegesSettings(expirationIntervalMinutes: 0))
        let event = try ElevationTracker(store: store, environment: env).record(grant())
        #expect(event.elevation?.expires == nil)
    }

    func expiry(
        privileges: PrivilegesSettings, timer: TimeInterval?
    ) throws -> (expires: Date?, basis: JSONValue?) {
        let store = try makeStore()
        let now = clock.now
        let env = makeEnvironment(
            admins: FakeAdmins(["jdoe"]), clock: clock, privileges: privileges,
            privilegesTimer: { _, _ in timer.map { now.addingTimeInterval($0) } })
        let event = try ElevationTracker(store: store, environment: env).record(grant())
        return (event.elevation?.expires, event.detail["expires_basis"])
    }

    @Test func usesTheDurationTheUserPickedInPrivileges() throws {
        let r = try expiry(privileges: PrivilegesSettings(), timer: 3600)
        #expect(r.expires == clock.now.addingTimeInterval(3600))
        #expect(r.basis == "PrivilegesTimer")
    }

    @Test func managedMaximumCapsThePrivilegesTimer() throws {
        let capped = try expiry(privileges: PrivilegesSettings(expirationIntervalMaxMinutes: 30), timer: 7200)
        #expect(capped.expires == clock.now.addingTimeInterval(1800))
        #expect(capped.basis == "ExpirationIntervalMax")

        let within = try expiry(privileges: PrivilegesSettings(expirationIntervalMaxMinutes: 30), timer: 600)
        #expect(within.expires == clock.now.addingTimeInterval(600))
        #expect(within.basis == "PrivilegesTimer")
    }

    @Test func fixedIntervalWinsOverThePrivilegesTimer() throws {
        let r = try expiry(privileges: PrivilegesSettings(expirationIntervalMinutes: 20), timer: 3600)
        #expect(r.expires == clock.now.addingTimeInterval(1200))
        #expect(r.basis == "ExpirationInterval")
    }

    @Test func ignoresAPrivilegesTimerFromBeforeTheGrant() throws {
        let r = try expiry(privileges: PrivilegesSettings(), timer: -60)
        #expect(r.expires == nil)
        #expect(r.basis == nil)
    }

    @Test func mapsUPN() throws {
        let store = try makeStore()
        let env = makeEnvironment(
            admins: FakeAdmins(["jdoe"]), clock: clock,
            config: AgentConfiguration(userPrincipalNames: ["jdoe": "jane.doe@example.com"]))
        let event = try ElevationTracker(store: store, environment: env).record(grant())
        #expect(event.user?.upn == "jane.doe@example.com")
    }

    @Test func heartbeatReportsWhoIsAdmin() throws {
        let store = try makeStore()
        let env = makeEnvironment(
            admins: FakeAdmins(["itadmin"]), clock: clock, config: AgentConfiguration(permanentAdmins: ["itadmin"]))
        let events = try ElevationTracker(store: store, environment: env).heartbeat()
        #expect(events.map(\.type) == [.agentHealth])
        #expect(events[0].detail["admin_members"] == ["itadmin"])
        #expect(events[0].sessionID == nil)
    }

    @Test func heartbeatRaisesOutOfBandOnce() throws {
        let store = try makeStore()
        let admins = FakeAdmins(["itadmin", "backdoor"])
        let env = makeEnvironment(admins: admins, clock: clock, config: AgentConfiguration(permanentAdmins: ["itadmin"]))
        let tracker = ElevationTracker(store: store, environment: env)

        let first = try tracker.heartbeat()
        let oob = try #require(first.first { $0.type == .adminOutOfBand })
        #expect(oob.user?.localName == "backdoor")
        #expect(oob.elevation?.source == .outOfBand)
        #expect(try store.openSession(user: "backdoor")?.source == .outOfBand)

        clock.advance(300)
        #expect(try tracker.heartbeat().map(\.type) == [.agentHealth])

        // Rights removed: the out-of-band session closes.
        admins.set(["itadmin"])
        clock.advance(300)
        let closed = try #require(try tracker.heartbeat().first { $0.type == .elevationRevoked })
        #expect(closed.sessionID == oob.sessionID)
        #expect(closed.elevation?.source == .outOfBand)
    }

    @Test func outOfBandSessionEndsWhenTheUserBecomesAPermanentAdmin() throws {
        // Found without a grant, then listed in PermanentAdmins: standing rights now, so the
        // session ends while the rights stay. Otherwise it stays open as long as they do.
        let store = try makeStore()
        let admins = FakeAdmins(["breakglass"])
        let before = ElevationTracker(store: store, environment: makeEnvironment(admins: admins, clock: clock))
        let oob = try #require(try before.heartbeat().first { $0.type == .adminOutOfBand })

        clock.advance(300)
        let tracker = ElevationTracker(
            store: store,
            environment: makeEnvironment(
                admins: admins, clock: clock, config: AgentConfiguration(permanentAdmins: ["breakglass"])))
        let events = try tracker.heartbeat()
        #expect(events.map(\.type) == [.elevationRevoked, .agentHealth])
        let ended = events[0]
        #expect(ended.sessionID == oob.sessionID)
        #expect(ended.user?.localName == "breakglass")
        #expect(ended.elevation?.source == .outOfBand)
        #expect(ended.detail["trigger"] == "permanent_admin")
        #expect(ended.detail["observed_admin"] == true)
        #expect(ended.detail["verified"] == true)
        #expect(admins.adminMembers() == ["breakglass"])  // rights untouched
        #expect(try store.openSession(user: "breakglass") == nil)
        #expect(events[1].detail["open_sessions"] == .array([]))

        clock.advance(300)
        #expect(try tracker.heartbeat().map(\.type) == [.agentHealth])
    }

    @Test func privilegesSessionOfAPermanentAdminRunsItsCourse() throws {
        // A permanent admin who was demoted and asked Privileges again holds a real, timed
        // grant; only a session nobody granted ends because of the list.
        let store = try makeStore()
        let admins = FakeAdmins(["itadmin"])
        let env = makeEnvironment(admins: admins, clock: clock, config: AgentConfiguration(permanentAdmins: ["itadmin"]))
        let tracker = ElevationTracker(store: store, environment: env)
        let granted = try tracker.record(grant("itadmin"))

        clock.advance(300)
        #expect(try tracker.heartbeat().map(\.type) == [.agentHealth])
        #expect(try store.openSession(user: "itadmin")?.sessionID == granted.sessionID)
    }

    @Test func privilegesTimerStoppedWhileRightsAreHeldIsTampering() throws {
        // Someone holding rights from Privileges stops its agent, which runs their timer, to
        // keep them: a tamper alert at the next heartbeat, before any expiry.
        let store = try makeStore()
        let admins = FakeAdmins(["jdoe"])
        let running = OSAllocatedUnfairLock<[String: Bool?]>(initialState: ["jdoe": true, "asmith": nil])
        var env = makeEnvironment(admins: admins, clock: clock)
        env.privilegesAgentRunning = { user in running.withLock { $0[user] ?? nil } }
        let tracker = ElevationTracker(store: store, environment: env)
        _ = try tracker.record(grant())

        let health = { (events: [AltiwardEvent]) in events.first { $0.type == .agentHealth }?.detail["integrity"] }
        let tamper = { (events: [AltiwardEvent]) in events.filter { $0.type == .agentTamper }.map(\.detail) }
        var events = try tracker.heartbeat()
        #expect(health(events) == ["privileges_timer": true])
        #expect(tamper(events).isEmpty)

        running.withLock { $0["jdoe"] = false }
        clock.advance(60)
        events = try tracker.heartbeat()
        #expect(health(events) == ["privileges_timer": false])
        #expect(
            tamper(events) == [
                [
                    "check": "privileges_timer", "state": "failed",
                    "problem": "Privileges' timer isn't running for jdoe, who holds admin rights it granted",
                ]
            ])

        // Rights gone, whoever removed them: nothing left for the timer to end.
        admins.set([])
        clock.advance(60)
        events = try tracker.heartbeat()
        #expect(health(events) == ["privileges_timer": true])
        #expect(tamper(events) == [["check": "privileges_timer", "state": "restored", "problem": .null]])
    }

    @Test func privilegesTimerCheckIgnoresWhatItCantJudge() throws {
        let store = try makeStore()
        let admins = FakeAdmins(["jdoe", "breakglass"])
        var env = makeEnvironment(admins: admins, clock: clock, config: AgentConfiguration(permanentAdmins: ["breakglass"]))
        // Nobody logged in has an agent running: jdoe isn't logged in (nil), breakglass
        // is a permanent admin, and the out-of-band admin has no Privileges grant.
        env.privilegesAgentRunning = { $0 == "jdoe" ? nil : false }
        let tracker = ElevationTracker(store: store, environment: env)
        _ = try tracker.record(grant())
        _ = try tracker.record(grant("breakglass"))
        admins.set(["jdoe", "breakglass", "backdoor"])
        let events = try tracker.heartbeat()
        #expect(events.first { $0.type == .agentHealth }?.detail["integrity"] == ["privileges_timer": true])

        // Not without Privileges installed.
        var noPrivileges = makeEnvironment(
            admins: admins, clock: clock,
            device: {
                var d = testDevice
                d.privilegesVersion = nil
                return d
            })
        noPrivileges.privilegesAgentRunning = { _ in false }
        let n = try ElevationTracker(store: try makeStore(), environment: noPrivileges).heartbeat()
        #expect(n.first { $0.type == .agentHealth }?.detail["integrity"] == [:])
    }

    @Test func liveProcessLookupSeesThisProcess() {
        #expect(!PrivilegesAgentProcess.commands(uid: getuid()).isEmpty)
        #expect(PrivilegesAgentProcess.running(user: "altiward-no-such-user") == nil)
    }

    @Test func untrackedAdminIsRaisedOnceItHasGoneUngrantedForTheGracePeriod() throws {
        let store = try makeStore()
        let admins = FakeAdmins(["itadmin"])
        let env = makeEnvironment(admins: admins, clock: clock, config: AgentConfiguration(permanentAdmins: ["itadmin"]))
        let tracker = ElevationTracker(store: store, environment: env)
        #expect(try tracker.checkUntrackedAdmins().isEmpty)

        admins.set(["itadmin", "backdoor"])  // an account added to admin by hand
        #expect(try tracker.checkUntrackedAdmins().isEmpty)
        clock.advance(15)
        #expect(try tracker.checkUntrackedAdmins().isEmpty)
        clock.advance(15)
        let raised = try tracker.checkUntrackedAdmins()
        #expect(raised.map(\.type) == [.adminOutOfBand])
        #expect(raised.first?.user?.localName == "backdoor")
        #expect(raised.first?.detail["first_observed"] == .date(clock.now))
        #expect(try store.pending(limit: 100).map(\.event.type) == [.adminOutOfBand])

        clock.advance(15)
        #expect(try tracker.checkUntrackedAdmins().isEmpty)  // once per session
        clock.advance(300)
        #expect(try tracker.heartbeat().map(\.type) == [.agentHealth])
    }

    @Test func grantWhoseHookArrivesBetweenChecksIsNotOutOfBand() throws {
        let store = try makeStore()
        let admins = FakeAdmins()
        let tracker = ElevationTracker(store: store, environment: makeEnvironment(admins: admins, clock: clock))

        // Privileges changed the group; its hook is still waiting for Privileges' timer.
        admins.set(["jdoe"])
        #expect(try tracker.checkUntrackedAdmins().isEmpty)
        clock.advance(15)
        #expect(try tracker.checkUntrackedAdmins().isEmpty)
        clock.advance(3)
        try tracker.record(grant())
        clock.advance(12)
        #expect(try tracker.checkUntrackedAdmins().isEmpty)

        // Rights gone and back again start the wait over.
        admins.set([])
        try tracker.record(revoke())
        clock.advance(15)
        #expect(try tracker.checkUntrackedAdmins().isEmpty)
        admins.set(["jdoe"])
        clock.advance(15)
        #expect(try tracker.checkUntrackedAdmins().isEmpty)
    }

    @Test func heartbeatClosesSessionWhoseRevokeWasMissed() throws {
        let store = try makeStore()
        let admins = FakeAdmins(["jdoe"])
        let tracker = ElevationTracker(store: store, environment: makeEnvironment(admins: admins, clock: clock))
        let granted = try tracker.record(grant())

        admins.set([])  // Privileges expired the rights but the hook never reached us.
        clock.advance(1200)
        let events = try tracker.heartbeat()
        let revoked = try #require(events.first { $0.type == .elevationRevoked })
        #expect(revoked.sessionID == granted.sessionID)
        #expect(revoked.detail["inferred"] == true)
        #expect(revoked.timestamp == clock.now)
        #expect(try store.openSessions().isEmpty)
    }

    @Test func grantAfterOutOfBandStartsPrivilegesSession() throws {
        let store = try makeStore()
        let admins = FakeAdmins(["jdoe"])
        let tracker = ElevationTracker(store: store, environment: makeEnvironment(admins: admins, clock: clock))
        let oob = try #require(try tracker.heartbeat().first { $0.type == .adminOutOfBand })
        clock.advance(300)
        let granted = try tracker.record(grant())
        #expect(granted.sessionID != oob.sessionID)
        #expect(granted.detail["renewed"] == false)
        #expect(granted.detail["replaced_out_of_band"] == true)

        // The out-of-band session ends ahead of the grant, in the same transaction.
        let pending = try store.pending(limit: 10).map(\.event)
        #expect(pending.map(\.type) == [.adminOutOfBand, .agentHealth, .elevationRevoked, .elevationGranted])
        let ended = pending[2]
        #expect(ended.sessionID == oob.sessionID)
        #expect(ended.timestamp == granted.timestamp)
        #expect(ended.elevation?.source == .outOfBand)
        #expect(ended.detail["trigger"] == "privileges_grant")
        #expect(ended.detail["observed_admin"] == true)
        #expect(ended.detail["verified"] == true)
        #expect(ended.detail["inferred"] == nil)
        #expect(pending[3].eventID == granted.eventID)
        #expect(try store.openSession(user: "jdoe")?.sessionID == granted.sessionID)
    }

    @Test func firstGrantAndRenewalEndNothing() throws {
        let store = try makeStore()
        let tracker = ElevationTracker(
            store: store, environment: makeEnvironment(admins: FakeAdmins(["jdoe"]), clock: clock))
        let first = try tracker.record(grant())
        clock.advance(900)
        let renewed = try tracker.record(grant())
        #expect(first.detail["replaced_out_of_band"] == nil)
        #expect(renewed.detail["replaced_out_of_band"] == nil)
        #expect(try store.pending(limit: 10).map(\.event.eventID) == [first.eventID, renewed.eventID])
    }

    @Test func heartbeatRacingAHookGrantDoesNotCloseIt() throws {
        // Membership is read inside the heartbeat's transaction: a grant that lands between
        // the read and the reconciliation must wait, not be closed as missed.
        let store = try makeStore()
        let admins = FakeAdmins()
        let tracker = ElevationTracker(store: store, environment: makeEnvironment(admins: admins, clock: clock))
        let hookGrant = grant()
        let group = DispatchGroup()
        admins.afterRead = {
            race(in: group) {
                admins.set(["jdoe"])
                _ = try? tracker.record(hookGrant)
            }
        }

        let heartbeat = try tracker.heartbeat()
        group.wait()

        #expect(!heartbeat.contains { $0.type == .elevationRevoked })
        #expect(try store.openSession(user: "jdoe")?.source == .privileges)
        #expect(!(try tracker.heartbeat()).contains { $0.type == .adminOutOfBand })
    }
}
