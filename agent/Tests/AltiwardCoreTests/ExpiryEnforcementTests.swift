import Foundation
import Testing

@testable import AltiwardCore

/// Expiry enforcement: rights that outlive their expiry plus the grace period are reported, and in
/// `enforce` mode removed. The test Privileges config expires grants after 20 minutes.
struct ExpiryEnforcementTests {
    let clock = TestClock()
    let admins = FakeAdmins(["jdoe"])

    func tracker(_ mode: ExpiryEnforcement, grace: TimeInterval = 300, permanent: Set<String> = [], privileges: PrivilegesSettings = PrivilegesSettings(expirationIntervalMinutes: 20)) throws -> (ElevationTracker, AgentStore) {
        let store = try makeStore()
        let config = AgentConfiguration(permanentAdmins: permanent, expiryEnforcement: mode, expiryGracePeriod: grace)
        // Privileges' log is available: these tests don't look at the grant_confirmation check.
        let env = makeEnvironment(
            admins: admins, clock: clock, privileges: privileges, config: config, privilegesLogAvailability: { .available })
        return (ElevationTracker(store: store, environment: env), store)
    }

    func grant(_ tracker: ElevationTracker) throws -> AltiwardEvent {
        try tracker.record(HookInvocation(user: "jdoe", state: .admin, reason: "work", invokedAt: clock.now))
    }

    func types(_ events: [AltiwardEvent]) -> [EventType] { events.map(\.type) }

    @Test func nothingHappensWithinGracePeriod() throws {
        let (tracker, _) = try tracker(.enforce)
        _ = try grant(tracker)
        clock.advance(20 * 60 + 299)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.isAdmin(user: "jdoe"))
        #expect(admins.removalAttempts == 0)
    }

    @Test func alertModeReportsOverdueOnceAndKeepsRights() throws {
        let (tracker, store) = try tracker(.alert)
        let granted = try grant(tracker)
        clock.advance(20 * 60 + 300)

        let overdue = try #require(try tracker.heartbeat().first { $0.type == .elevationOverdue })
        #expect(overdue.sessionID == granted.sessionID)
        #expect(overdue.user?.localName == "jdoe")
        #expect(overdue.elevation?.source == .privileges)
        #expect(overdue.elevation?.expires == granted.elevation?.expires)
        #expect(overdue.detail["enforcement"] == "alert")
        #expect(overdue.detail["enforcement_failed"] == false)
        #expect(overdue.detail["grace_seconds"] == 300)
        #expect(overdue.detail["observed_admin"] == true)
        #expect(admins.isAdmin(user: "jdoe"))
        #expect(admins.removalAttempts == 0)
        #expect(try store.openSession(user: "jdoe") != nil)

        clock.advance(300)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
    }

    @Test func enforceModeRemovesRightsAndEndsSession() throws {
        let (tracker, store) = try tracker(.enforce)
        let granted = try grant(tracker)
        clock.advance(20 * 60 + 300)

        let events = try tracker.heartbeat()
        try #require(types(events) == [.elevationExpiredEnforced, .agentHealth])
        let enforced = events[0]
        #expect(enforced.sessionID == granted.sessionID)
        #expect(enforced.timestamp == clock.now)
        #expect(enforced.elevation?.expires == granted.elevation?.expires)
        #expect(enforced.detail["trigger"] == "heartbeat")
        #expect(enforced.detail["observed_admin"] == false)
        #expect(enforced.detail["grace_seconds"] == 300)
        #expect(!admins.isAdmin(user: "jdoe"))
        #expect(try store.openSession(user: "jdoe") == nil)
        #expect(events[1].detail["admin_members"] == .strings([]))
    }

    @Test func failedRemovalIsReportedOnceAndRetried() throws {
        let (tracker, store) = try tracker(.enforce)
        let granted = try grant(tracker)
        admins.failRemovals = true
        clock.advance(20 * 60 + 300)

        let overdue = try #require(try tracker.heartbeat().first { $0.type == .elevationOverdue })
        #expect(overdue.sessionID == granted.sessionID)
        #expect(overdue.detail["enforcement"] == "enforce")
        #expect(overdue.detail["enforcement_failed"] == true)
        #expect(overdue.detail["error"] != nil)
        #expect(try store.openSession(user: "jdoe") != nil)

        clock.advance(300)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.removalAttempts == 2)

        admins.failRemovals = false
        clock.advance(300)
        #expect(types(try tracker.heartbeat()) == [.elevationExpiredEnforced, .agentHealth])
    }

    @Test func removalThatThrowsButTakesEffectCountsAsEnforced() throws {
        let (tracker, store) = try tracker(.enforce)
        _ = try grant(tracker)
        admins.removalsThrowAfterTakingEffect = true
        clock.advance(20 * 60 + 300)
        #expect(types(try tracker.heartbeat()) == [.elevationExpiredEnforced, .agentHealth])
        #expect(try store.openSession(user: "jdoe") == nil)
    }

    @Test func removalThatLeavesUserAdminCountsAsFailure() throws {
        // Admin through a nested group: removing direct membership is not enough.
        let (tracker, _) = try tracker(.enforce)
        _ = try grant(tracker)
        admins.removalsHaveNoEffect = true
        clock.advance(20 * 60 + 300)
        let overdue = try #require(try tracker.heartbeat().first { $0.type == .elevationOverdue })
        #expect(overdue.detail["enforcement_failed"] == true)
    }

    @Test func permanentAdminsAreNeverDemoted() throws {
        let (tracker, _) = try tracker(.enforce, permanent: ["jdoe"])
        _ = try grant(tracker)
        clock.advance(3 * 3600)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.removalAttempts == 0)
    }

    @Test func offModeDoesNothing() throws {
        let (tracker, _) = try tracker(.off)
        _ = try grant(tracker)
        clock.advance(3 * 3600)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.removalAttempts == 0)
    }

    @Test func sessionsWithoutExpiryAreLeftAlone() throws {
        let (tracker, _) = try tracker(.enforce, privileges: PrivilegesSettings(expirationIntervalMinutes: 0))
        _ = try grant(tracker)
        clock.advance(3 * 3600)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.removalAttempts == 0)
    }

    @Test func outOfBandAdminsAreNotDemoted() throws {
        let (tracker, _) = try tracker(.enforce)
        #expect(types(try tracker.heartbeat()) == [.adminOutOfBand, .agentHealth])
        clock.advance(3 * 3600)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        #expect(admins.removalAttempts == 0)
    }

    @Test func renewalExtendsDeadlineAndRearmsAlert() throws {
        let (tracker, _) = try tracker(.alert)
        _ = try grant(tracker)
        clock.advance(20 * 60 + 300)
        #expect(types(try tracker.heartbeat()) == [.elevationOverdue, .agentHealth])

        _ = try grant(tracker)  // renewed: expires 20 minutes from now
        clock.advance(20 * 60 + 299)
        #expect(types(try tracker.heartbeat()) == [.agentHealth])
        clock.advance(1)
        #expect(types(try tracker.heartbeat()) == [.elevationOverdue, .agentHealth])
    }
}
