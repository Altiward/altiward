import Foundation
import Testing
import os

@testable import AltiwardCore

/// The installed agent's view of MDM's payloads: reading, storing the last clean read, and
/// the settings taken from it.
struct ManagedSettingsTests {
    let store: AgentStore
    let clock = TestClock()
    let reads = OSAllocatedUnfairLock<[Result<ProfilesReading, ProfilesReadError>]>(initialState: [])
    let readCount = OSAllocatedUnfairLock(initialState: 0)

    init() throws {
        store = try makeStore()
    }

    /// A reader whose reads give `results` in turn, the last one again once they run out.
    func settings(_ results: [Result<ProfilesReading, ProfilesReadError>]) -> ManagedSettings {
        reads.withLock { $0 = results }
        let (reads, readCount, clock) = (reads, readCount, clock)
        return ManagedSettings(
            store: store,
            readDevice: {
                readCount.withLock { $0 += 1 }
                return reads.withLock { $0.count > 1 ? $0.removeFirst() : $0[0] }
            }, now: { clock.now })
    }

    static let broken = Result<ProfilesReading, ProfilesReadError>.failure(.command("profiles show", .exited(1)))

    func enrolled(_ payloads: [MDMPayload]) -> Result<ProfilesReading, ProfilesReadError> { .success(.enrolled(payloads)) }

    @Test func theAgentsSettingsComeFromMDMsPayloads() throws {
        let m = settings([enrolled(try fixturePayloads())])
        let state = m.refresh()
        let c = try #require(ManagedSettings.configuration(state))
        #expect(c.serverURL == URL(string: "https://altiward-agents.example.com"))
        #expect(c.enrollmentToken == "token-not-shown")
        #expect(c.mdmDeviceID == "00000000-0000-4000-8000-000000000000")
        #expect(c.heartbeatInterval == 60)
        #expect(c.commandPollInterval == 60)
        #expect(c.permanentAdmins == ["breakglass"])
        #expect(c.userPrincipalNames == ["jdoe": "jane.doe@example.com"])
        #expect(c.userPrincipalNamesForced)
        #expect(c.hookCodeRequirement?.hasPrefix("identifier \"com.altiward.hook\"") == true)
        #expect(c.expiryEnforcement == .enforce)
        #expect(c.expiryGracePeriod == 60)
        #expect(c.outOfBandEnforcement == .alert)
        #expect(c.outOfBandGracePeriod == 300)
        #expect(c.dataDirectory == AgentConfiguration.defaultDataDirectory)
        // And Privileges' settings for the agent's own logic.
        let p = m.privilegesSettings()
        #expect(p.systemExtensionEnabled == true)
        #expect(p.allowPrivilegeRenewal == false)
        #expect(p.postChangeActionOnGrantOnly == false)
        #expect(p.expirationIntervalMaxMinutes == 60)
        #expect(p.expiryCapped)
        #expect(p.postChangeExecutableChecksum == "checksum-not-shown")
    }

    /// Every setting the agent reads is taken from the payloads: a payload setting each one
    /// gives a configuration that differs in each.
    @Test func everySettingIsRecordedFromThePayloads() throws {
        let all: [String: PlistValue] = [
            "ServerURL": .string("https://a.example.com"), "EnrollmentToken": .string("t"), "MDMDeviceID": .string("d"),
            "HeartbeatInterval": .integer(120), "FlushInterval": .integer(30), "PermanentAdmins": .array([.string("x")]),
            "UserPrincipalNames": .dictionary(["x": .string("x@example.com")]), "PlatformSSOIdentity": .bool(false),
            "HookCodeRequirement": .string("r"), "ExpiryEnforcement": .string("enforce"), "ExpiryGraceMinutes": .integer(7),
            "OutOfBandEnforcement": .string("enforce"), "OutOfBandGraceMinutes": .integer(9),
            "CommandPollInterval": .integer(45),
        ]
        let set = MDMPayloadSet(
            [MDMPayload(domain: AgentConfiguration.domain, profileUUID: "p", payloadUUID: "u", settings: all)], readAt: Date())
        let c = AgentConfiguration.load(environment: [:], preferences: set.preferences(for: AgentConfiguration.domain))
        #expect(
            Set(c.changedSettings(AgentConfiguration(userPrincipalNamesForced: false)))
                == Set(all.keys))
    }

    @Test func overridesNeverApply() throws {
        let m = settings([enrolled(try fixturePayloads())])
        let state = m.refresh()
        // `configuration` takes no environment: ALTIWARD_* can't reach the installed agent.
        let c = try #require(ManagedSettings.configuration(state))
        #expect(c == AgentConfiguration.load(environment: [:], preferences: state.payloads!.preferences(for: AgentConfiguration.domain)))
    }

    @Test func aCleanReadIsStoredAndUsedWhenProfilesCantBeRead() throws {
        _ = settings([enrolled(try fixturePayloads())]).refresh()

        // A restart with `profiles` broken: the stored set is in use, so nothing waits.
        clock.advance(3600)
        let later = settings([Self.broken])
        let state = later.refresh()
        #expect(!state.mustWait)
        #expect(state.readError == .command("profiles show", .exited(1)))
        #expect(state.payloads?.readAt == Date(timeIntervalSince1970: 1_792_000_000))
        #expect(try ManagedSettings.configuration(state)?.serverURL == URL(string: "https://altiward-agents.example.com"))
    }

    @Test func withNothingStoredAnUnreadableProfilesToolMeansWait() {
        let m = settings([Self.broken])
        let state = m.refresh()
        #expect(state.mustWait)
        #expect(ManagedSettings.configuration(state) == nil)
        // One retry before giving up.
        #expect(readCount.withLock { $0 } == 2)
    }

    @Test func oneFailedReadIsRetried() throws {
        let m = settings([Self.broken, enrolled(try fixturePayloads())])
        let state = m.refresh()
        #expect(state.readError == nil)
        #expect(state.payloads != nil)
        #expect(readCount.withLock { $0 } == 2)
    }

    @Test func withoutMDMTheSettingsComeFromThePreferences() {
        let state = settings([.success(.notEnrolled)]).refresh()
        #expect(state.unmanaged)
        #expect(!state.mustWait)
        #expect(ManagedSettings.configuration(state) != nil)
    }

    /// Once MDM's payloads were read, a Mac that seems to leave MDM keeps them.
    @Test func noEnrolmentAfterAReadKeepsTheStoredSet() throws {
        _ = settings([enrolled(try fixturePayloads())]).refresh()
        let state = settings([.success(.notEnrolled)]).refresh()
        #expect(state.notEnrolled)
        #expect(!state.unmanaged)
        #expect(try ManagedSettings.configuration(state)?.serverURL == URL(string: "https://altiward-agents.example.com"))
    }

    @Test func aReadWithoutAltiwardsPayloadKeepsTheOneInUse() throws {
        let fixture = try fixturePayloads()
        let m = settings([enrolled(fixture), enrolled(fixture.filter { $0.domain != AgentConfiguration.domain })])
        _ = m.refresh()
        let state = m.refresh()
        #expect(state.agentPayloadMissing)
        #expect(state.payloads?.setsAgent == true)
        #expect(try store.mdmPayloads()?.setsAgent == true)
        #expect(m.settledConfiguration() == nil)
    }

    @Test func aNewConfigurationSettlesAfterTwoEqualReads() throws {
        let fixture = try fixturePayloads()
        var changed = fixture
        changed[1].settings["HeartbeatInterval"] = .integer(300)
        let m = settings([enrolled(fixture), enrolled(changed), enrolled(changed), Self.broken])
        #expect(m.refresh().stable == false)
        #expect(m.settledConfiguration() == nil)

        clock.advance(60)
        let first = m.refresh()
        #expect(first.changedAt == clock.now)
        #expect(!first.stable)
        #expect(m.settledConfiguration() == nil)

        let second = m.refresh()
        #expect(second.stable)
        #expect(second.changedAt == clock.now)
        #expect(m.settledConfiguration()?.heartbeatInterval == 300)

        // A failed read doesn't count as agreeing.
        #expect(!m.refresh().stable)
        #expect(m.settledConfiguration() == nil)
    }

    @Test func theSameSetAsTheStoredOneIsNoChange() throws {
        _ = settings([enrolled(try fixturePayloads())]).refresh()
        clock.advance(600)
        #expect(settings([enrolled(try fixturePayloads())]).refresh().changedAt == nil)
    }
}

/// The settings check over a copy of a Mac's /Library/Managed Preferences.
struct ManagedSettingsCheckTests {
    let root: URL
    let clock = TestClock(Date(timeIntervalSince1970: 1_792_003_600))
    let signedIn = OSAllocatedUnfairLock<[String: Date]>(initialState: [:])
    let userProfiles = OSAllocatedUnfairLock<[MDMPayload]>(initialState: [])
    let payloads: MDMPayloadSet

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("managed-\(UUID().uuidString)")
        try FileManager.default.copyItem(at: repoFile("agent/Tests/Fixtures/profiles/managed-preferences"), to: root)
        payloads = MDMPayloadSet(try fixturePayloads(), readAt: Date(timeIntervalSince1970: 1_792_000_000))
    }

    var check: ManagedSettingsCheck {
        let (signedIn, userProfiles) = (signedIn, userProfiles)
        return ManagedSettingsCheck(
            files: ManagedPreferenceFiles(root: root), signedIn: { signedIn.withLock { $0 } },
            userPayloads: { _ in .success(userProfiles.withLock { $0 }) }, now: { [clock] in clock.now })
    }

    func state(_ change: (inout ManagedSettingsState) -> Void = { _ in }) -> ManagedSettingsState {
        var s = ManagedSettingsState(payloads: payloads, stable: true)
        change(&s)
        return s
    }

    func edit(_ relative: String, _ change: (inout [String: Any]) -> Void) throws {
        let url = root.appendingPathComponent(relative)
        var plist = try PropertyListSerialization.propertyList(from: Data(contentsOf: url), format: nil) as! [String: Any]
        change(&plist)
        try PropertyListSerialization.data(fromPropertyList: plist, format: .binary, options: 0).write(to: url)
    }

    var device: String { root.path }

    @Test func filesMatchingMDMsPayloadsPass() {
        #expect(check.result(state()) == .ok)
    }

    @Test func aForgedValueFailsAndNamesTheKeyNotTheValue() throws {
        try edit("com.altiward.agent.plist") { $0["ServerURL"] = "https://attacker.example.net" }
        let r = check.result(state())
        #expect(!r.ok)
        #expect(r.problem == "managed settings differ from MDM's profiles: com.altiward.agent ServerURL (changed) in \(device)")
        #expect(r.findings == ["com.altiward.agent ServerURL"])
        #expect(r.problem?.contains("attacker") == false)
    }

    @Test func aDeletedOrAddedKeyFails() throws {
        try edit("corp.sap.privileges.plist") {
            $0["PostChangeExecutablePath"] = nil
            $0["EnableSystemExtension"] = nil
            $0["ReasonRequired"] = false
        }
        let r = check.result(state())
        #expect(
            r.problem
                == "managed settings differ from MDM's profiles: corp.sap.privileges EnableSystemExtension (removed), "
                + "corp.sap.privileges PostChangeExecutablePath (removed), corp.sap.privileges ReasonRequired (added) in \(device)")
    }

    @Test func aBooleanForgedAsANumberFails() throws {
        try edit("corp.sap.privileges.plist") { $0["EnableSystemExtension"] = 1 }
        #expect(check.result(state()).findings == ["corp.sap.privileges EnableSystemExtension"])
    }

    @Test func aWholeFileForAnUnmanagedDomainOrAHandInstalledProfileFails() throws {
        // As a profile installed by hand leaves it: another PayloadUUID and _manualProfile.
        try edit("com.altiward.agent.plist") {
            $0["PayloadUUID"] = "27F583CC-DCB1-4E4C-91F9-8E569A8255BE"
            $0["_manualProfile"] = true
        }
        let r = check.result(state())
        #expect(r.findings == ["com.altiward.agent PayloadUUID", "com.altiward.agent _manualProfile"])

        // Privileges' settings with no MDM payload for them.
        let noPrivileges = MDMPayloadSet(payloads.payloads(for: AgentConfiguration.domain), readAt: payloads.readAt)
        try edit("com.altiward.agent.plist") {
            $0["PayloadUUID"] = "A34D3A14-3839-4937-AEFD-14C4CB972C36"
            $0["_manualProfile"] = nil
        }
        let added = check.result(state { $0.payloads = noPrivileges })
        #expect(added.findings?.contains("corp.sap.privileges EnableSystemExtension") == true)
        #expect(added.findings?.contains("corp.sap.privileges PayloadUUID") == true)
    }

    @Test func anUnreadableFileFails() throws {
        try Data("not a plist".utf8).write(to: root.appendingPathComponent("com.altiward.agent.plist"))
        #expect(
            check.result(state()).problem
                == "managed settings differ from MDM's profiles: com.altiward.agent file (unreadable) in \(device)")
    }

    @Test func anyPayloadsValuePasses() throws {
        var two = payloads.payloads
        two.append(
            MDMPayload(
                domain: AgentConfiguration.domain, profileUUID: "P2", payloadUUID: "U2",
                settings: ["HeartbeatInterval": .integer(120)]))
        try edit("com.altiward.agent.plist") { $0["HeartbeatInterval"] = 120 }
        #expect(check.result(state { $0.payloads = MDMPayloadSet(two, readAt: payloads.readAt) }) == .ok)
        #expect(!check.result(state()).ok)
    }

    @Test func aSignedInUsersFolderIsCompared() throws {
        try edit("jdoe/corp.sap.privileges.plist") { $0["EnableSystemExtension"] = false }
        // Not signed in: their folder keeps their last sign-in's settings, and isn't compared.
        #expect(check.result(state()) == .ok)
        // Just signed in: ManagedClient may still be writing it.
        signedIn.withLock { $0 = ["jdoe": clock.now.addingTimeInterval(-30)] }
        #expect(check.result(state()) == .ok)

        signedIn.withLock { $0 = ["jdoe": clock.now.addingTimeInterval(-600)] }
        let r = check.result(state())
        #expect(
            r.problem
                == "managed settings differ from MDM's profiles: corp.sap.privileges EnableSystemExtension (changed) in \(device)/jdoe")
    }

    @Test func aSignedInUsersCompleteListIsCompared() throws {
        signedIn.withLock { $0 = ["jdoe": clock.now.addingTimeInterval(-600)] }
        try edit("jdoe/complete.plist") {
            var agent = $0["com.altiward.agent"] as! [String: Any]
            var entry = agent["PermanentAdmins"] as! [String: Any]
            entry["value"] = ["breakglass", "mallory"]
            agent["PermanentAdmins"] = entry
            $0["com.altiward.agent"] = agent
        }
        #expect(
            check.result(state()).problem
                == "managed settings differ from MDM's profiles: com.altiward.agent PermanentAdmins (changed) in \(device)/jdoe/complete.plist")
    }

    @Test func aUsersOwnMDMProfilesExplainTheirFolder() throws {
        signedIn.withLock { $0 = ["jdoe": clock.now.addingTimeInterval(-600)] }
        try edit("jdoe/corp.sap.privileges.plist") { $0["ReasonRequired"] = true }
        try edit("jdoe/complete.plist") {
            var privileges = $0["corp.sap.privileges"] as! [String: Any]
            privileges["ReasonRequired"] = ["mcxdomain": "always", "value": true]
            $0["corp.sap.privileges"] = privileges
        }
        #expect(!check.result(state()).ok)
        userProfiles.withLock {
            $0 = [MDMPayload(domain: "corp.sap.privileges", profileUUID: "P9", payloadUUID: "U9", settings: ["ReasonRequired": .bool(true)])]
        }
        #expect(check.result(state()) == .ok)
    }

    @Test func differencesJustAfterMDMsPayloadsChangeAreHeld() throws {
        try edit("com.altiward.agent.plist") { $0["HeartbeatInterval"] = 300 }
        let held = check.result(state { $0.changedAt = clock.now.addingTimeInterval(-60) })
        #expect(held.held && held.ok)
        // After the grace they count.
        #expect(!check.result(state { $0.changedAt = clock.now.addingTimeInterval(-400) }).ok)
        // And with an unchanged payload set there's no grace.
        #expect(!check.result(state { $0.changedAt = nil }).ok)
    }

    @Test func aStoredSetInUseIsSaidAndStillCompared() throws {
        try edit("com.altiward.agent.plist") { $0["ServerURL"] = "https://attacker.example.net" }
        let r = check.result(state { $0.readError = .command("profiles show", .exited(1)) })
        #expect(
            r.problem
                == "can't read the installed profiles (profiles show exited with status 1), so compared with the MDM "
                + "settings read 2026-10-14T17:46:40.000Z; managed settings differ from MDM's profiles: "
                + "com.altiward.agent ServerURL (changed) in \(device)")
        #expect(r.findings == ["com.altiward.agent ServerURL", "profiles unreadable"])
        // With the files matching, still a failure: the profiles can't be read.
        try edit("com.altiward.agent.plist") { $0["ServerURL"] = "https://altiward-agents.example.com" }
        #expect(check.result(state { $0.readError = .command("profiles show", .exited(1)) }).findings == ["profiles unreadable"])
        #expect(check.result(state { $0.agentPayloadMissing = true }).findings == ["no com.altiward.agent payload"])
        #expect(check.result(state { $0.notEnrolled = true }).findings == ["not enrolled in MDM"])
    }

    @Test func withNoPayloadsTheCheckFails() {
        #expect(
            check.result(ManagedSettingsState(notEnrolled: true)).problem
                == "this Mac isn't enrolled in MDM, so no MDM profile sets Altiward's settings")
        #expect(
            check.result(ManagedSettingsState(readError: .command("profiles list", .timedOut(10)))).problem
                == "can't read the installed profiles (profiles list didn't finish within 10 s), and no MDM settings are stored")
        // Enrolled, but no profile sets Altiward's settings yet.
        let none = check.result(state { $0.payloads = MDMPayloadSet([], readAt: payloads.readAt) })
        #expect(none.findings?.contains("no com.altiward.agent payload") == true)
    }

    @Test func onlyConsoleSignInsWithALiveProcessCount() {
        let at = Date(timeIntervalSince1970: 1_792_000_000)
        let records = [
            LoginRecord(user: "jdoe", tty: "console", host: "", pid: 10, started: at, ended: nil),
            LoginRecord(user: "jdoe", tty: "ttys001", host: "", pid: 11, started: at.addingTimeInterval(-60), ended: nil),
            LoginRecord(user: "asmith", tty: "ttys002", host: "10.0.0.1", pid: 12, started: at, ended: nil),
            LoginRecord(user: "gone", tty: "console", host: "", pid: 13, started: at, ended: nil),
        ]
        #expect(LoginRecords.atLoginWindow(records, processExists: { $0 != 13 }) == ["jdoe": at])
    }
}
