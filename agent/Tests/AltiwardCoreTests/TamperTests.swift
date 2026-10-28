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
    // MARK: Failures that name what fails

    static func settings(_ keys: [String]) -> IntegrityResult {
        IntegrityResult(ok: false, problem: "differs: \(keys.joined(separator: ", "))", findings: keys)
    }

    /// A later forgery mustn't hide behind an earlier one: a failing check that names its keys
    /// is reported again when they change, and not when they don't.
    @Test func aFailingCheckIsReportedAgainWhenWhatFailsChanges() throws {
        let t = tracker()
        results.withLock { $0 = [.settingsManaged: Self.settings(["com.altiward.agent ServerURL"])] }
        #expect(try tamper(t).map { $0.detail["state"] } == ["failed"])
        #expect(try tamper(t).isEmpty)

        results.withLock {
            $0 = [.settingsManaged: Self.settings(["com.altiward.agent ServerURL", "corp.sap.privileges EnableSystemExtension"])]
        }
        // Within 10 minutes of the last report a changed failure waits, so it can't flood the SIEM.
        clock.advance(300)
        #expect(try tamper(t).isEmpty)
        clock.advance(301)
        let again = try tamper(t)
        try #require(again.map { $0.detail["state"] } == ["failed"])
        #expect(again[0].detail["problem"] == "differs: com.altiward.agent ServerURL, corp.sap.privileges EnableSystemExtension")
        // Not after a restart with the same keys.
        #expect(try tamper(tracker()).isEmpty)

        results.withLock { $0 = [.settingsManaged: .ok] }
        #expect(try tamper(t).map { $0.detail["state"] } == ["restored"])
    }

    /// An agent upgraded while the check was failing has no keys stored: the first named set is
    /// reported, once.
    @Test func aFailureFromBeforeKeysWereStoredIsReportedOnceWithThem() throws {
        try store.setValue(#"{"settings_managed": false}"#, forKey: "integrity_state")
        results.withLock { $0 = [.settingsManaged: Self.settings(["com.altiward.agent ServerURL"])] }
        #expect(try tamper(tracker()).map { $0.detail["state"] } == ["failed"])
        #expect(try tamper(tracker()).isEmpty)
    }

    @Test func aHeldCheckKeepsItsState() throws {
        let t = tracker()
        let held = IntegrityResult(ok: true, problem: nil, held: true)
        results.withLock { $0 = [.settingsManaged: Self.settings(["com.altiward.agent ServerURL"])] }
        _ = try tamper(t)
        results.withLock { $0 = [.settingsManaged: held] }
        // Neither restored nor retired, and agent.health still shows it failing.
        let events = try t.heartbeat()
        #expect(events.filter { $0.type == .agentTamper }.isEmpty)
        let health = try #require(events.first { $0.type == .agentHealth })
        guard case .object(let integrity) = health.detail["integrity"] else {
            Issue.record("agent.health has no integrity map")
            return
        }
        #expect(integrity["settings_managed"] == .bool(false))

        // Held before it ever ran: nothing reported, nothing shown.
        try store.setValue(nil, forKey: "integrity_state")
        let first = try t.heartbeat()
        #expect(first.filter { $0.type == .agentTamper }.isEmpty)
        guard case .object(let shown)? = first.first(where: { $0.type == .agentHealth })?.detail["integrity"] else {
            Issue.record("agent.health has no integrity map")
            return
        }
        #expect(shown["settings_managed"] == nil)
    }

    /// Between heartbeats only the settings check runs, and the others keep their state.
    @Test func theSettingsCheckRunsAloneBetweenHeartbeats() throws {
        let check = OSAllocatedUnfairLock(initialState: IntegrityResult.ok)
        var env = makeEnvironment(admins: FakeAdmins([]), clock: clock, integrity: { [results] in results.withLock { $0 } })
        #expect(try ElevationTracker(store: store, environment: env).checkManagedSettings().isEmpty)
        env.settingsCheck = { check.withLock { $0 } }
        let t = ElevationTracker(store: store, environment: env)

        results.withLock { $0 = [.launchDaemon: .failed("missing"), .settingsManaged: .ok] }
        _ = try tamper(t)

        check.withLock { $0 = Self.settings(["corp.sap.privileges EnableSystemExtension"]) }
        let found = try t.checkManagedSettings()
        #expect(found.map { $0.detail["check"] } == ["settings_managed"])
        #expect(found.map { $0.detail["state"] } == ["failed"])
        // launch_daemon was neither retired nor repeated.
        #expect(try t.checkManagedSettings().isEmpty)
        check.withLock { $0 = .ok }
        #expect(try t.checkManagedSettings().map { $0.detail["state"] } == ["restored"])

        // The next heartbeat sees the same states: nothing new.
        results.withLock { $0 = [.launchDaemon: .failed("missing"), .settingsManaged: .ok] }
        #expect(try tamper(t).isEmpty)
    }

    /// A key set that keeps changing is reported at most every 10 minutes, with what fails then.
    @Test func aChangingFailureIsReportedAtMostEveryTenMinutes() throws {
        let t = tracker()
        results.withLock { $0 = [.settingsManaged: Self.settings(["k0"])] }
        _ = try tamper(t)
        var reported = 0
        for i in 1...40 {
            clock.advance(30)
            results.withLock { $0 = [.settingsManaged: Self.settings(["k\(i)"])] }
            reported += try tamper(t).count
        }
        // 20 minutes of changes every 30 s: two more reports.
        #expect(reported == 2)
    }

    /// The heartbeat reads its checks before its transaction; a settings check that ran and
    /// committed in between is newer, and the heartbeat's older result doesn't overwrite it.
    @Test func anOlderSettingsResultDoesNotOverwriteANewerOne() throws {
        let check = OSAllocatedUnfairLock(initialState: IntegrityResult.ok)
        var env = makeEnvironment(admins: FakeAdmins([]), clock: clock, integrity: { [results] in results.withLock { $0 } })
        env.settingsCheck = { check.withLock { $0 } }
        let t = ElevationTracker(store: store, environment: env)
        let early = clock.now
        clock.advance(5)
        check.withLock {
            $0 = IntegrityResult(ok: false, problem: "differs", findings: ["k"], observedAt: clock.now)
        }
        #expect(try t.checkManagedSettings().map { $0.detail["state"] } == ["failed"])
        results.withLock { $0 = [.settingsManaged: IntegrityResult(ok: true, problem: nil, observedAt: early)] }
        let events = try t.heartbeat()
        #expect(events.filter { $0.type == .agentTamper }.isEmpty)
        guard case .object(let integrity)? = events.first(where: { $0.type == .agentHealth })?.detail["integrity"] else {
            Issue.record("agent.health has no integrity map")
            return
        }
        #expect(integrity["settings_managed"] == .bool(false))
        // A newer passing result restores it.
        results.withLock { $0 = [.settingsManaged: IntegrityResult(ok: true, problem: nil, observedAt: clock.now)] }
        #expect(try tamper(t).map { $0.detail["state"] } == ["restored"])
    }

    /// A failure that came and went between two runs is reported, then its recovery.
    @Test func aFailureThatCameAndWentIsReported() throws {
        let t = tracker()
        results.withLock { $0 = [.settingsManaged: .ok] }
        _ = try tamper(t)
        let earlier = EarlierFailure(problem: "differed at a time", findings: ["k"])
        results.withLock { $0 = [.settingsManaged: IntegrityResult(ok: true, problem: nil, earlier: earlier)] }
        let events = try tamper(t)
        #expect(events.map { $0.detail["state"] } == ["failed", "restored"])
        #expect(events.first?.detail["problem"] == "differed at a time")

        // Already failing with those findings: not said again.
        results.withLock { $0 = [.settingsManaged: Self.settings(["k"])] }
        _ = try tamper(t)
        results.withLock {
            $0 = [.settingsManaged: IntegrityResult(ok: false, problem: "x", findings: ["k"], earlier: earlier)]
        }
        #expect(try tamper(t).isEmpty)
    }

    /// The heartbeat's result took what a changed file held, then lost to a newer result the
    /// watcher committed: the failure it carries is still reported, and restored after.
    @Test func aStaleResultStillReportsTheFailureItCarries() throws {
        let check = OSAllocatedUnfairLock(initialState: IntegrityResult.ok)
        var env = makeEnvironment(admins: FakeAdmins([]), clock: clock, integrity: { [results] in results.withLock { $0 } })
        env.settingsCheck = { check.withLock { $0 } }
        let t = ElevationTracker(store: store, environment: env)
        let early = clock.now
        clock.advance(5)
        check.withLock { $0 = IntegrityResult(ok: true, problem: nil, observedAt: clock.now) }
        #expect(try t.checkManagedSettings().isEmpty)

        let earlier = EarlierFailure(problem: "differed at a time", findings: ["k"])
        results.withLock {
            $0 = [.settingsManaged: IntegrityResult(ok: true, problem: nil, observedAt: early, earlier: earlier)]
        }
        let reported = try tamper(t)
        #expect(reported.map { $0.detail["state"] } == ["failed"])
        #expect(reported.first?.detail["problem"] == "differed at a time")

        clock.advance(5)
        check.withLock { $0 = IntegrityResult(ok: true, problem: nil, observedAt: clock.now) }
        #expect(try t.checkManagedSettings().map { $0.detail["state"] } == ["restored"])
    }
}
