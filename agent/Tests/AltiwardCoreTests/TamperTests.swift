import Foundation
import Testing
import os

@testable import AltiwardCore

/// The heartbeat's tamper reporting: edge-triggered agent.tamper events and the
/// integrity map in agent.health.
struct TamperTests {
    let clock = TestClock()
    let store: AgentStore
    let results = OSAllocatedUnfairLock<[IntegrityCheck: IntegrityResult]>(initialState: [:])
    let version = OSAllocatedUnfairLock(initialState: testDevice.agentVersion)
    let privilegesVersion = OSAllocatedUnfairLock<String?>(initialState: testDevice.privilegesVersion)

    init() throws {
        store = try makeStore()
    }

    func tracker() -> ElevationTracker {
        let (results, version, privilegesVersion) = (results, version, privilegesVersion)
        let env = makeEnvironment(
            admins: FakeAdmins([]), clock: clock,
            device: {
                var d = testDevice
                d.agentVersion = version.withLock { $0 }
                d.privilegesVersion = privilegesVersion.withLock { $0 }
                return d
            },
            integrity: { results.withLock { $0 } })
        return ElevationTracker(store: store, environment: env)
    }

    func tamper(_ t: ElevationTracker) throws -> [AltiwardEvent] {
        try t.heartbeat().filter { $0.type == .agentTamper }
    }

    @Test func passingChecksSayNothing() throws {
        results.withLock { $0 = [.launchDaemon: .ok, .codeSignature: .ok] }
        #expect(try tamper(tracker()).isEmpty)
    }

    @Test func aFailureIsReportedOnceThenItsRecovery() throws {
        let t = tracker()
        results.withLock { $0 = [.launchDaemon: .ok] }
        _ = try tamper(t)

        results.withLock { $0 = [.launchDaemon: .failed("/Library/LaunchDaemons/com.altiward.agent.plist is missing")] }
        let failed = try tamper(t)
        #expect(failed.count == 1)
        #expect(failed[0].detail["check"] == "launch_daemon")
        #expect(failed[0].detail["state"] == "failed")
        #expect(failed[0].detail["problem"] == "/Library/LaunchDaemons/com.altiward.agent.plist is missing")
        #expect(failed[0].sessionID == nil && failed[0].user == nil)

        #expect(try tamper(t).isEmpty)  // still failing: no repeat

        results.withLock { $0 = [.launchDaemon: .ok] }
        let restored = try tamper(t)
        #expect(restored.map { $0.detail["state"] } == ["restored"])
        #expect(restored[0].detail["problem"] == .null)
    }

    @Test func failingOnTheFirstRunIsReported() throws {
        results.withLock { $0 = [.settingsManaged: .failed("set outside MDM: PermanentAdmins")] }
        #expect(try tamper(tracker()).map { $0.detail["check"] } == ["settings_managed"])
    }

    @Test func aRestartDoesNotRepeatTheAlert() throws {
        results.withLock { $0 = [.codeSignature: .failed("bad")] }
        _ = try tamper(tracker())
        // A new tracker on the same store, as after a daemon restart.
        #expect(try tamper(tracker()).isEmpty)
    }

    @Test func removingPrivilegesRetiresItsFailingChecksWithWhy() throws {
        results.withLock {
            $0 = [.privilegesTamperProtection: .failed("off"), .privilegesHook: .failed("not set"), .launchDaemon: .ok]
        }
        _ = try tamper(tracker())

        // Privileges removed: its checks no longer run.
        privilegesVersion.withLock { $0 = nil }
        results.withLock { $0 = [.launchDaemon: .ok] }
        let events = try tamper(tracker())
        #expect(events.map { $0.detail["check"] } == ["privileges_hook", "privileges_tamper_protection"])
        #expect(events.map { $0.detail["state"] } == ["retired", "retired"])
        #expect(
            events.map { $0.detail["problem"] }
                == ["SAP Privileges isn't installed now", "SAP Privileges isn't installed now"])
        #expect(try tamper(tracker()).isEmpty)  // said once
    }

    /// A later release can drop a check. A failing one stored by the release before is
    /// retired, so its alert doesn't stay open for good.
    @Test func failingChecksAltiwardNoLongerRunsAreRetired() throws {
        try store.setValue(#"{"dropped_check_a": false, "dropped_check_b": false}"#, forKey: "integrity_state")
        results.withLock { $0 = [.launchDaemon: .ok] }
        let events = try tamper(tracker())
        try #require(events.count == 2)
        #expect(events.map { $0.detail["check"] } == ["dropped_check_a", "dropped_check_b"])
        #expect(events.map { $0.detail["state"] } == ["retired", "retired"])
        #expect(
            events.map { $0.detail["problem"] }
                == ["Altiward no longer runs this check", "Altiward no longer runs this check"])
        #expect(try tamper(tracker()).isEmpty)  // said once
    }

    @Test func aFailingGrantConfirmationCheckIsRetiredWithWhy() throws {
        // Left out without enforcement, which the test's configuration doesn't set.
        results.withLock { $0 = [.launchDaemon: .ok] }
        try store.setValue(#"{"grant_confirmation": false}"#, forKey: "integrity_state")
        var events = try tamper(tracker())
        #expect(events.map { $0.detail["check"] } == ["grant_confirmation"])
        #expect(events.map { $0.detail["state"] } == ["retired"])
        #expect(events.map { $0.detail["problem"] } == ["neither OutOfBandEnforcement nor ExpiryEnforcement is enforce now"])

        try store.setValue(#"{"grant_confirmation": false}"#, forKey: "integrity_state")
        privilegesVersion.withLock { $0 = nil }
        events = try tamper(tracker())
        #expect(events.map { $0.detail["problem"] } == ["SAP Privileges isn't installed now"])
    }

    @Test func aFailingRenewalCheckIsRetiredWithWhy() throws {
        results.withLock { $0 = [.launchDaemon: .ok] }
        try store.setValue(#"{"privileges_renewal": false}"#, forKey: "integrity_state")
        var events = try tamper(tracker())
        #expect(events.map { $0.detail["problem"] } == ["ExpiryEnforcement isn't enforce now"])

        try store.setValue(#"{"privileges_renewal": false, "privileges_expiry_cap": false}"#, forKey: "integrity_state")
        privilegesVersion.withLock { $0 = nil }
        events = try tamper(tracker())
        #expect(events.map { $0.detail["check"] } == ["privileges_expiry_cap", "privileges_renewal"])
        #expect(
            events.map { $0.detail["problem"] }
                == ["SAP Privileges isn't installed now", "SAP Privileges isn't installed now"])
    }

    @Test func aPassingCheckThatStopsApplyingSaysNothing() throws {
        results.withLock { $0 = [.privilegesHook: .ok, .launchDaemon: .ok] }
        _ = try tamper(tracker())
        privilegesVersion.withLock { $0 = nil }
        results.withLock { $0 = [.launchDaemon: .ok] }
        #expect(try tamper(tracker()).isEmpty)
    }

    @Test func aDowngradeIsDetectedOnce() throws {
        version.withLock { $0 = "1.1.0" }
        #expect(try tamper(tracker()).isEmpty)
        version.withLock { $0 = "1.0.9" }
        let events = try tamper(tracker())
        #expect(events.count == 1)
        #expect(events[0].detail["check"] == "agent_version")
        #expect(events[0].detail["state"] == "detected")
        #expect(events[0].detail["previous_version"] == "1.1.0")
        #expect(events[0].detail["current_version"] == "1.0.9")
        #expect(try tamper(tracker()).isEmpty)
        // An upgrade is not news.
        version.withLock { $0 = "1.10.0" }
        #expect(try tamper(tracker()).isEmpty)
    }

    @Test func healthCarriesEveryCheckResult() throws {
        results.withLock { $0 = [.launchDaemon: .ok, .codeSignature: .failed("bad")] }
        let health = try #require(try tracker().heartbeat().last)
        #expect(health.type == .agentHealth)
        #expect(
            health.detail["integrity"]
                == .object(["launch_daemon": true, "code_signature": false, "privileges_timer": true]))
    }

    @Test func versionsCompareNumerically() {
        #expect(AgentVersion.isOlder("0.9.1", than: "0.10.0"))
        #expect(!AgentVersion.isOlder("0.10.0", than: "0.9.1"))
        #expect(!AgentVersion.isOlder("1.0", than: "1.0.0"))
        #expect(AgentVersion.isOlder("1.0", than: "1.0.1"))
    }
}
