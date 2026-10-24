import Foundation
import Testing

@testable import AltiwardCore

struct ConfigurationTests {
    @Test func namesTheSettingsThatChangedWithoutTheirValues() {
        // The agent started before its profile arrived, then the profile installed.
        let before = AgentConfiguration.load(environment: [:], preferences: Preferences(values: [:]))
        let after = AgentConfiguration.load(
            environment: [:],
            preferences: Preferences(values: [
                "ServerURL": "https://agents.example.com", "EnrollmentToken": "secret-token",
                "PermanentAdmins": ["itadmin"],
            ]))
        #expect(before.changedSettings(after) == ["EnrollmentToken", "PermanentAdmins", "ServerURL"])
        #expect(after.changedSettings(after).isEmpty)
        #expect(after.changedSettings(before) == before.changedSettings(after))
    }

    @Test func everySettingCountsAsAChange() {
        // A setting changedSettings forgets would never restart the agent.
        let base = AgentConfiguration()
        var changed: [AgentConfiguration] = []
        func with(_ change: (inout AgentConfiguration) -> Void) {
            var c = base
            change(&c)
            changed.append(c)
        }
        with { $0.serverURL = URL(string: "https://x") }
        with { $0.enrollmentToken = "t" }
        with { $0.dataDirectory = URL(fileURLWithPath: "/tmp/x") }
        with { $0.heartbeatInterval = 31 }
        with { $0.flushInterval = 11 }
        with { $0.permanentAdmins = ["a"] }
        with { $0.userPrincipalNames = ["a": "a@x"] }
        with { $0.hookCodeRequirement = "r" }
        with { $0.expiryEnforcement = .enforce }
        with { $0.expiryGracePeriod = 1 }
        with { $0.outOfBandEnforcement = .enforce }
        with { $0.outOfBandGracePeriod = 1 }
        with { $0.commandPollInterval = 16 }
        for c in changed {
            #expect(c != base)
            #expect(base.changedSettings(c).count == 1)
        }
    }

    @Test func outOfBandEnforcementDefaultsToAlert() {
        let c = AgentConfiguration.load(environment: [:], preferences: Preferences(values: [:], forced: []))
        #expect(c.outOfBandEnforcement == .alert)
        #expect(c.outOfBandGracePeriod == 300)
    }

    @Test func unknownOutOfBandEnforcementKeepsAlert() {
        func mode(_ value: String) -> OutOfBandEnforcement {
            let p = Preferences(values: ["OutOfBandEnforcement": value])
            return AgentConfiguration.load(environment: [:], preferences: p).outOfBandEnforcement
        }
        #expect(mode("off") == .alert)
        #expect(mode("remove") == .alert)
        #expect(mode("enforce") == .enforce)
    }

    @Test func outOfBandGraceHasAOneMinuteFloor() {
        func grace(_ minutes: Int) -> TimeInterval {
            let p = Preferences(values: ["OutOfBandGraceMinutes": minutes])
            return AgentConfiguration.load(environment: [:], preferences: p).outOfBandGracePeriod
        }
        #expect(grace(0) == 60)
        #expect(grace(15) == 900)
    }

    /// Minutes are converted to seconds as a TimeInterval: in Int, a huge value would trap.
    @Test func hugeGraceMinutesDoNotCrash() {
        let p = Preferences(values: ["ExpiryGraceMinutes": Int.max, "OutOfBandGraceMinutes": Int.max])
        let c = AgentConfiguration.load(environment: [:], preferences: p)
        #expect(c.expiryGracePeriod == TimeInterval(Int.max) * 60)
        #expect(c.outOfBandGracePeriod == TimeInterval(Int.max) * 60)
    }

    /// Privileges 2.7's daily budget is read and reported; 0 means off, as in Privileges.
    @Test func adminBudgetIsReadAndZeroMeansOff() {
        let set = PrivilegesSettings.settings(from: Preferences(values: ["AdminBudget": 90]))
        #expect(set.adminBudgetMinutes == 90)
        guard case .object(let fields) = set.healthDetail else { Issue.record("not an object"); return }
        #expect(fields["admin_budget_minutes"] == 90)
        #expect(PrivilegesSettings.settings(from: Preferences(values: ["AdminBudget": 0])).adminBudgetMinutes == nil)
        #expect(PrivilegesSettings.settings(from: Preferences(values: [:])).adminBudgetMinutes == nil)
    }
}
