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

    let storePath: String

    init() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-tests-\(UUID().uuidString)")
        store = try AgentStore.open(directory: dir)
        storePath = dir.appendingPathComponent("agent.sqlite").path
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
        #expect(ManagedSettings.configuration(state)?.serverURL == URL(string: "https://altiward-agents.example.com"))
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
        #expect(ManagedSettings.configuration(state)?.serverURL == URL(string: "https://altiward-agents.example.com"))
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

    // MARK: Profile changes and the stored set

    /// Only a change this agent saw between two of its own reads opens the grace: a stored
    /// set anyone with root edited (here, emptied) is replaced at once, with no hold.
    @Test func anEditedStoredSetOpensNoGrace() throws {
        _ = settings([enrolled(try fixturePayloads())]).refresh()
        _ = try SQLiteConnection(path: storePath).execute("DELETE FROM mdm_payloads")
        // A restart: the stored set is empty now, the profiles read as before.
        let restarted = settings([enrolled(try fixturePayloads())])
        #expect(restarted.latest.payloads?.payloads == [])
        let state = restarted.refresh()
        #expect(state.changedAt == nil)
        #expect(state.previous == nil)
        #expect(!state.inProfileChange(at: clock.now))
    }

    @Test func aChangeSeenBetweenTwoReadsKeepsThePayloadsBefore() throws {
        let fixture = try fixturePayloads()
        var changed = fixture
        changed[1].settings["HeartbeatInterval"] = .integer(300)
        let m = settings([enrolled(fixture), Self.broken, Self.broken, enrolled(changed)])
        let first = m.refresh()
        // A failed read in between doesn't hide the change.
        _ = m.refresh()
        clock.advance(60)
        let state = m.refresh()
        #expect(state.changedAt == clock.now)
        #expect(state.previous?.sameSettings(as: first.payloads) == true)
        #expect(state.inProfileChange(at: clock.now))
        #expect(!state.inProfileChange(at: clock.now.addingTimeInterval(ManagedSettingsCheck.profileChangeGrace)))
    }

    @Test func aStoredRowThatIsntOneTheAgentWroteIsUnreadableNotACrash() throws {
        _ = settings([enrolled(try fixturePayloads())]).refresh()
        _ = try SQLiteConnection(path: storePath).execute("UPDATE mdm_payloads SET settings = 'text'")
        #expect(throws: AgentStoreError.unreadableRow("mdm_payloads")) { try store.mdmPayloads() }
        let m = settings([Self.broken])
        #expect(m.latest.payloads == nil)
        #expect(m.latest.storedRefused == "the stored MDM settings can't be read")
        #expect(m.refresh().mustWait)
    }

    @Test func storedSettingsMustMatchTheEnrolment() throws {
        _ = settings([enrolled(try fixturePayloads())]).refresh()
        let real = "https://altiward-agents.example.com"
        let matching = EnrolmentRecord(serverURLs: [real], tokenDigest: EnrolmentRecord.digest("token-not-shown"))
        reads.withLock { $0 = [Self.broken] }
        let (reads, clock) = (reads, clock)
        func reader(_ enrolment: EnrolmentRecord?) -> ManagedSettings {
            ManagedSettings(
                store: store, readDevice: { reads.withLock { $0[0] } }, now: { clock.now }, enrolment: enrolment)
        }
        #expect(!reader(matching).refresh().mustWait)
        #expect(!reader(nil).refresh().mustWait)
        #expect(!reader(EnrolmentRecord(serverURLs: [real], tokenDigest: nil)).refresh().mustWait)

        let otherServer = reader(EnrolmentRecord(serverURLs: ["https://elsewhere.example.net"], tokenDigest: nil))
        #expect(otherServer.latest.storedRefused == "the stored ServerURL isn't the server this Mac enrolled with")
        #expect(otherServer.refresh().mustWait)
        let otherToken = reader(EnrolmentRecord(serverURLs: [real], tokenDigest: EnrolmentRecord.digest("another")))
        #expect(otherToken.latest.storedRefused == "the stored EnrollmentToken isn't the one this Mac enrolled with")
        #expect(otherToken.refresh().mustWait)
        // A clean read is MDM's word, and replaces the refused set.
        reads.withLock { $0 = [.success(.enrolled(try! fixturePayloads()))] }
        let fresh = otherServer.refresh()
        #expect(!fresh.mustWait)
        #expect(fresh.storedRefused == nil)
    }

    @Test func theEnrolmentRecordComesFromTheKeyRecords() throws {
        #expect(DeviceAuthenticator.enrolment(in: store) == nil)
        try store.setValue(
            #"{"serverURL":"https://altiward-agents.example.com","privateKey":""}"#, forKey: "device_credential")
        try store.setValue("abc", forKey: "enrollment_token_digest")
        #expect(
            DeviceAuthenticator.enrolment(in: store)
                == EnrolmentRecord(serverURLs: ["https://altiward-agents.example.com"], tokenDigest: "abc"))
    }

    @Test func aStoredSetIsRewrittenOnlyWhenItChanges() throws {
        let fixture = try fixturePayloads()
        _ = settings([enrolled(fixture)]).refresh()
        let rows = { try SQLiteConnection(path: storePath).query("SELECT seq FROM mdm_payloads").compactMap { $0.int(0) } }
        let before = try rows()
        clock.advance(60)
        _ = settings([enrolled(fixture)]).refresh()
        #expect(try rows() == before)
        #expect(try store.mdmPayloads()?.readAt == clock.now)
        var changed = fixture
        changed[1].settings["HeartbeatInterval"] = .integer(300)
        _ = settings([enrolled(changed)]).refresh()
        #expect(try rows() != before)
        // Read-only, as a command that changes nothing reads it.
        let dir = URL(fileURLWithPath: storePath).deletingLastPathComponent()
        #expect(try AgentStore.storedMDMPayloads(directory: dir)?.sameSettings(as: MDMPayloadSet(changed, readAt: .now)) == true)
    }

    // MARK: Rechecks

    @Test func rechecksRunOnlyWhileTheReadsSettle() throws {
        let set = MDMPayloadSet(try fixturePayloads(), readAt: clock.now)
        let now = clock.now
        let start = now.addingTimeInterval(-10)
        func recheck(_ s: ManagedSettingsState, since: Date = start) -> Bool {
            ManagedSettingsState.needsRecheck(s, since: since, now: now)
        }
        // A clean read not yet confirmed by a second.
        #expect(recheck(ManagedSettingsState(payloads: set, stable: false)))
        // Confirmed, with no change: nothing to wait for.
        #expect(!recheck(ManagedSettingsState(payloads: set, stable: true)))
        // Confirmed, but differences may be held after a change.
        #expect(recheck(ManagedSettingsState(payloads: set, changedAt: now.addingTimeInterval(-60), previous: set, stable: true)))
        // Never for a read that failed, showed no enrolment or lost Altiward's payload.
        #expect(!recheck(ManagedSettingsState(payloads: set, readError: .malformed("x"))))
        #expect(!recheck(ManagedSettingsState(payloads: set, notEnrolled: true)))
        #expect(!recheck(ManagedSettingsState(payloads: set, agentPayloadMissing: true)))
        #expect(!recheck(ManagedSettingsState(notEnrolled: true)))
        // And never longer than the grace after they began.
        #expect(
            !recheck(
                ManagedSettingsState(payloads: set, stable: false),
                since: now.addingTimeInterval(-ManagedSettingsCheck.profileChangeGrace)))
    }

    // MARK: Starting and restarting

    @Test func theDaemonWaitsForSettingsAndACommandDoesnt() async throws {
        // Nothing stored yet: a command gives up.
        let command = settings([Self.broken])
        await #expect(throws: SettingsUnavailable.self) {
            try await ManagedSettings.startupState(command, mayWait: false, sleep: { _ in }, log: { _ in })
        }

        let fixture = try fixturePayloads()
        let m = settings([Self.broken, Self.broken, Self.broken, Self.broken, enrolled(fixture)])
        let slept = OSAllocatedUnfairLock(initialState: [TimeInterval]())
        var logged: [String] = []
        let state = try await ManagedSettings.startupState(
            m, mayWait: true, retry: 30, sleep: { s in slept.withLock { $0.append(s) } }, log: { logged.append($0) })
        #expect(!state.mustWait)
        #expect(slept.withLock { $0 } == [30, 30])
        #expect(logged.count == 2)
        #expect(logged.first?.hasPrefix("can't read MDM's settings from the installed profiles (profiles show exited with status 1)") == true)
    }

    @Test func theRestartDecision() throws {
        let running = AgentConfiguration(serverURL: URL(string: "https://a.example.com"))
        var next = running
        next.heartbeatInterval = 60
        // Installed: only settled payloads count, never the preferences.
        #expect(
            ManagedSettings.restartChanges(running: running, installed: true, settled: nil, preferences: { next }).isEmpty)
        #expect(
            ManagedSettings.restartChanges(running: running, installed: true, settled: next, preferences: { running })
                == ["HeartbeatInterval"])
        // Development: the preferences.
        #expect(
            ManagedSettings.restartChanges(running: running, installed: false, settled: nil, preferences: { next })
                == ["HeartbeatInterval"])
    }

    @Test func statusSaysWhereTheSettingsComeFrom() throws {
        let set = MDMPayloadSet(try fixturePayloads(), readAt: Date(timeIntervalSince1970: 1_792_000_000))
        func say(_ s: ManagedSettingsState?) -> String { ManagedSettingsState.sourceDescription(s) }
        #expect(say(nil) == "com.altiward.agent preferences (development)")
        #expect(say(ManagedSettingsState(notEnrolled: true)) == "com.altiward.agent preferences: this Mac isn't enrolled in MDM")
        #expect(say(ManagedSettingsState(readError: .malformed("x"))) == "none: the installed profiles can't be read, and none are stored")
        #expect(
            say(ManagedSettingsState(readError: .malformed("x"), storedRefused: "the stored ServerURL isn't the server this Mac enrolled with"))
                == "none: the installed profiles can't be read, and the stored ServerURL isn't the server this Mac enrolled with")
        #expect(say(ManagedSettingsState(payloads: set)) == "MDM's profiles, read 2026-10-14T17:46:40.000Z")
        #expect(
            say(ManagedSettingsState(payloads: set, readError: .command("profiles show", .exited(1))))
                == "MDM's profiles as read 2026-10-14T17:46:40.000Z; they can't be read now (profiles show exited with status 1)")
        #expect(say(ManagedSettingsState(payloads: set, notEnrolled: true)).hasSuffix("no MDM enrolment shows now"))
        #expect(say(ManagedSettingsState(payloads: set, agentPayloadMissing: true)).hasSuffix("no MDM profile sets them now"))
    }
}
