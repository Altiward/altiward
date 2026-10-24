import Foundation
import Testing
import os

@testable import AltiwardCore

/// Out-of-band enforcement: in `enforce` mode, admin rights nobody granted are removed once
/// they have lasted the grace period, unless that would leave the Mac without an admin.
/// The first heartbeat raises jdoe out-of-band; itadmin is a permanent admin unless a test
/// says otherwise.
struct OutOfBandEnforcementTests {
    let clock = TestClock()
    let admins = FakeAdmins(["jdoe", "itadmin"])

    func tracker(
        _ mode: OutOfBandEnforcement, grace: TimeInterval = 300, permanent: Set<String> = ["itadmin"],
        integrity: @escaping @Sendable () -> [IntegrityCheck: IntegrityResult] = { [:] },
        expiry: ExpiryEnforcement = .alert, store existing: AgentStore? = nil
    ) throws -> (ElevationTracker, AgentStore) {
        let store = try existing ?? makeStore()
        let config = AgentConfiguration(
            permanentAdmins: permanent, expiryEnforcement: expiry, outOfBandEnforcement: mode,
            outOfBandGracePeriod: grace)
        let env = makeEnvironment(admins: admins, clock: clock, config: config, integrity: integrity)
        return (ElevationTracker(store: store, environment: env), store)
    }

    func types(_ events: [AltiwardEvent]) -> [EventType] { events.map(\.type) }

    /// The first heartbeat, which raises jdoe out-of-band.
    func raise(_ tracker: ElevationTracker, _ user: String = "jdoe") throws -> AltiwardEvent {
        try #require(try tracker.heartbeat().first { $0.type == .adminOutOfBand && $0.user?.localName == user })
    }

    @Test func alertModeNeverRemoves() throws {
        let (tracker, store) = try tracker(.alert)
        _ = try raise(tracker)
        for _ in 0..<12 {
            clock.advance(300)
            #expect(!types(try tracker.heartbeat()).contains(.adminOutOfBandRemoved))
        }
        #expect(admins.removalAttempts == 0)
        #expect(admins.isAdmin(user: "jdoe"))
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
    }

    @Test func nothingHappensWithinGracePeriod() throws {
        let (tracker, _) = try tracker(.enforce)
        _ = try raise(tracker)
        clock.advance(299)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.isAdmin(user: "jdoe"))
        #expect(admins.removalAttempts == 0)
    }

    @Test func enforceModeRemovesRightsAndEndsSession() throws {
        let (tracker, store) = try tracker(.enforce)
        let raised = try raise(tracker)
        clock.advance(300)

        let events = try tracker.heartbeat()
        try #require(types(events) == [.adminOutOfBandRemoved, .agentHealth])
        let removed = events[0]
        #expect(removed.sessionID == raised.sessionID)
        #expect(removed.timestamp == clock.now)
        #expect(removed.user?.localName == "jdoe")
        #expect(removed.elevation?.source == .outOfBand)
        #expect(removed.detail["trigger"] == "heartbeat")
        #expect(removed.detail["grace_seconds"] == 300)
        #expect(removed.detail["observed_admin"] == false)
        #expect(removed.detail["verified"] == true)
        #expect(removed.detail["first_observed"] == .date(raised.timestamp))
        #expect(removed.detail["first_observed"] == raised.detail["first_observed"])
        #expect(!admins.isAdmin(user: "jdoe"))
        #expect(try store.openSession(user: "jdoe") == nil)
        #expect(events[1].detail["admin_members"] == .strings(["itadmin"]))

        // Done: the next heartbeat has nothing to do.
        clock.advance(300)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.removalAttempts == 1)
    }

    @Test(arguments: [OutOfBandEnforcement.alert, .enforce])
    func permanentAdminsAreNeverRemoved(_ mode: OutOfBandEnforcement) throws {
        let (tracker, _) = try tracker(mode)
        _ = try raise(tracker)
        for _ in 0..<12 {
            clock.advance(300)
            let events = try tracker.heartbeat()
            #expect(!events.contains { $0.user?.localName == "itadmin" })
        }
        #expect(admins.isAdmin(user: "itadmin"))
        #expect(admins.removalAttempts == (mode == .enforce ? 1 : 0))  // jdoe's
    }

    @Test func anOutOfBandAdminWhoBecomesPermanentIsNotRemoved() throws {
        // Raised before PermanentAdmins listed them, then listed once past the grace period:
        // that heartbeat ends the session for permanent_admin and leaves the rights alone.
        let (before, store) = try tracker(.enforce, permanent: [])
        _ = try raise(before, "itadmin")
        clock.advance(300)
        let (tracker, _) = try tracker(.enforce, permanent: ["itadmin"], store: store)
        // jdoe, raised in the same heartbeat, is removed; itadmin, now permanent, is not.
        let events = try tracker.heartbeat()
        try #require(types(events) == [.elevationRevoked, .adminOutOfBandRemoved, .agentHealth])
        #expect(events[0].user?.localName == "itadmin")
        #expect(events[0].detail["trigger"] == "permanent_admin")
        #expect(events[1].user?.localName == "jdoe")
        #expect(admins.removalAttempts == 1)
        #expect(admins.adminMembers() == ["itadmin"])
        #expect(try store.openSession(user: "itadmin") == nil)
    }

    @Test func lastAdminIsKept() throws {
        admins.set(["jdoe"])
        let (tracker, store) = try tracker(.enforce, permanent: [])
        _ = try raise(tracker)
        clock.advance(300)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        clock.advance(3600)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.removalAttempts == 0)
        #expect(admins.isAdmin(user: "jdoe"))
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
    }

    @Test func keepsTheAdminSeenLongest() throws {
        admins.set(["jdoe"])
        let (tracker, store) = try tracker(.enforce, permanent: [])
        _ = try raise(tracker)
        clock.advance(60)
        admins.set(["jdoe", "backdoor"])
        let backdoor = try raise(tracker, "backdoor")

        clock.advance(300)  // past the grace period for both
        let events = try tracker.heartbeat()
        try #require(types(events) == [.adminOutOfBandRemoved, .agentHealth])
        #expect(events[0].sessionID == backdoor.sessionID)
        #expect(events[0].user?.localName == "backdoor")
        #expect(admins.adminMembers() == ["jdoe"])
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
        #expect(events[1].detail["admin_members"] == .strings(["jdoe"]))
    }

    @Test func keepsTheAdminSeenLongestAcrossHeartbeats() throws {
        // jdoe's grace ends a heartbeat before backdoor's. backdoor, still in its grace, is
        // due for removal too, so it doesn't count as an admin who would remain.
        admins.set(["jdoe"])
        let (tracker, store) = try tracker(.enforce, permanent: [])
        _ = try raise(tracker)
        clock.advance(60)
        admins.set(["jdoe", "backdoor"])
        let backdoor = try raise(tracker, "backdoor")

        clock.advance(240)  // t0+300: jdoe past its grace, backdoor not
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.removalAttempts == 0)
        #expect(admins.adminMembers() == ["jdoe", "backdoor"])

        clock.advance(60)  // t0+360: both past their grace
        let events = try tracker.heartbeat()
        try #require(types(events) == [.adminOutOfBandRemoved, .agentHealth])
        #expect(events[0].sessionID == backdoor.sessionID)
        #expect(admins.adminMembers() == ["jdoe"])
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
    }

    @Test func anAdminWithNoSessionYetDoesNotCountAsRemaining() throws {
        // backdoor joins admin just before the heartbeat that ends jdoe's grace, too soon for
        // a session. It's about to be raised out-of-band, so it doesn't count as remaining.
        admins.set(["jdoe"])
        let (tracker, store) = try tracker(.enforce, permanent: [])
        _ = try raise(tracker)
        clock.advance(300)
        admins.set(["jdoe", "backdoor"])
        let events = try tracker.heartbeat()
        try #require(types(events) == [.adminOutOfBand, .agentHealth])
        #expect(events[0].user?.localName == "backdoor")
        #expect(admins.removalAttempts == 0)
        #expect(admins.adminMembers() == ["jdoe", "backdoor"])
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
        #expect(try store.openSession(user: "backdoor")?.source == .outOfBand)
    }

    @Test func adminRemovedAtExpiryDoesNotCountAsRemaining() throws {
        // alice's Privileges grant expires after 20 minutes and is removed 5 minutes later;
        // jdoe's 25-minute grace ends in that same heartbeat. Without alice, jdoe is the
        // only admin left, so jdoe stays.
        admins.set(["jdoe", "alice"])
        let (tracker, store) = try tracker(.enforce, grace: 25 * 60, permanent: [], expiry: .enforce)
        _ = try tracker.record(HookInvocation(user: "alice", state: .admin, reason: "work", invokedAt: clock.now))
        _ = try raise(tracker)

        clock.advance(25 * 60)
        let events = try tracker.heartbeat()
        #expect(types(events) == [.elevationExpiredEnforced, .agentHealth])
        #expect(events.first?.user?.localName == "alice")
        #expect(admins.adminMembers() == ["jdoe"])
        #expect(admins.removalAttempts == 1)  // alice's
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
    }

    @Test func nothingIsRemovedWhilePrivilegesHookFails() throws {
        let hookOK = OSAllocatedUnfairLock(initialState: false)
        let (tracker, store) = try tracker(
            .enforce,
            integrity: { [.privilegesHook: hookOK.withLock { $0 } ? .ok : .failed("x")] })
        _ = try raise(tracker)
        for _ in 0..<3 {
            clock.advance(300)
            #expect(!types(try tracker.heartbeat()).contains(.adminOutOfBandRemoved))
        }
        #expect(admins.removalAttempts == 0)
        #expect(admins.isAdmin(user: "jdoe"))
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)

        hookOK.withLock { $0 = true }
        clock.advance(300)
        #expect(types(try tracker.heartbeat()).contains(.adminOutOfBandRemoved))
        #expect(!admins.isAdmin(user: "jdoe"))
        #expect(try store.openSession(user: "jdoe") == nil)
    }

    @Test func failedRemovalKeepsTheSessionAndRetries() throws {
        let (tracker, store) = try tracker(.enforce)
        let raised = try raise(tracker)
        admins.failRemovals = true
        clock.advance(300)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.removalAttempts == 1)
        #expect(try store.openSession(user: "jdoe")?.sessionID == raised.sessionID)

        admins.failRemovals = false
        clock.advance(300)
        let events = try tracker.heartbeat()
        #expect(types(events) == [.adminOutOfBandRemoved, .agentHealth])
        #expect(events.first?.sessionID == raised.sessionID)
        #expect(admins.removalAttempts == 2)
        #expect(try store.openSession(user: "jdoe") == nil)
    }

    @Test func removalThatLeavesUserAdminCountsAsFailure() throws {
        // Admin through a nested group: removing direct membership is not enough.
        let (tracker, store) = try tracker(.enforce)
        _ = try raise(tracker)
        admins.removalsHaveNoEffect = true
        clock.advance(300)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.removalAttempts == 1)
        #expect(try store.openSession(user: "jdoe")?.source == .outOfBand)
    }

    @Test func grantWithinGraceReplacesTheSession() throws {
        let (tracker, store) = try tracker(.enforce)
        _ = try raise(tracker)
        clock.advance(10)
        _ = try tracker.record(HookInvocation(user: "jdoe", state: .admin, reason: "work", invokedAt: clock.now))
        clock.advance(290)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.removalAttempts == 0)
        #expect(admins.isAdmin(user: "jdoe"))
        #expect(try store.openSession(user: "jdoe")?.source == .privileges)
    }

    @Test func graceCountsFromWhenTheRightsWereRaisedAcrossRestarts() throws {
        let (before, store) = try tracker(.enforce)
        let raised = try raise(before)
        clock.advance(200)
        // The agent restarts: a new tracker on the same store.
        let (tracker, _) = try tracker(.enforce, store: store)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        clock.advance(100)
        let events = try tracker.heartbeat()
        #expect(types(events) == [.adminOutOfBandRemoved, .agentHealth])
        #expect(events.first?.sessionID == raised.sessionID)
        #expect(!admins.isAdmin(user: "jdoe"))
    }
}
