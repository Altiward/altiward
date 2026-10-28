import Foundation
import Testing
import os

@testable import AltiwardCore

/// The settings check over a copy of a Mac's /Library/Managed Preferences.
struct ManagedSettingsCheckTests {
    let root: URL
    let clock = TestClock(Date(timeIntervalSince1970: 1_792_003_600))
    let signedIn = OSAllocatedUnfairLock<[String: Date]>(initialState: [:])
    let userProfiles = OSAllocatedUnfairLock<[MDMPayload]>(initialState: [])
    /// What CFPreferences serves, by "domain key"; nil turns the comparison off.
    let served = OSAllocatedUnfairLock<[String: PlistValue]?>(initialState: nil)
    let payloads: MDMPayloadSet
    let memo: ManagedSettings

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("managed-\(UUID().uuidString)")
        try FileManager.default.copyItem(at: repoFile("agent/Tests/Fixtures/profiles/managed-preferences"), to: root)
        payloads = MDMPayloadSet(try fixturePayloads(), readAt: Date(timeIntervalSince1970: 1_792_000_000))
        memo = ManagedSettings(store: try makeStore(), readDevice: { .failure(.malformed("not read in this test")) })
    }

    var check: ManagedSettingsCheck {
        let (signedIn, userProfiles, served) = (signedIn, userProfiles, served)
        var serve: (@Sendable (String, String) -> PlistValue?)?
        if served.withLock({ $0 }) != nil {
            serve = { domain, key in served.withLock { $0?["\(domain) \(key)"] } }
        }
        return ManagedSettingsCheck(
            files: ManagedPreferenceFiles(root: root), signedIn: { signedIn.withLock { $0 } },
            userPayloads: { _ in .success(userProfiles.withLock { $0 }) }, served: serve, now: { [clock] in clock.now },
            memo: memo)
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

    func passes(_ r: IntegrityResult) -> Bool { r.ok && r.problem == nil && !r.held && r.earlier == nil }

    var device: String { root.path }

    @Test func filesMatchingMDMsPayloadsPass() {
        let r = check.result(state())
        #expect(passes(r))
        #expect(r.observedAt == clock.now)
    }

    @Test func aForgedValueFailsAndNamesTheKeyNotTheValue() throws {
        try edit("com.altiward.agent.plist") { $0["ServerURL"] = "https://attacker.example.net" }
        let r = check.result(state())
        #expect(!r.ok)
        #expect(r.problem == "managed settings differ from MDM's profiles: com.altiward.agent \"ServerURL\" (changed) in \(device)")
        #expect(r.findings == ["com.altiward.agent \"ServerURL\""])
        #expect(r.problem?.contains("attacker") == false)
    }

    @Test func aDeletedOrAddedKeyFails() throws {
        try edit("corp.sap.privileges.plist") {
            $0["PostChangeExecutablePath"] = nil
            $0["EnableSystemExtension"] = nil
            $0["ReasonRequired"] = false
        }
        #expect(
            check.result(state()).problem
                == "managed settings differ from MDM's profiles: corp.sap.privileges \"EnableSystemExtension\" (removed), "
                + "corp.sap.privileges \"PostChangeExecutablePath\" (removed), corp.sap.privileges \"ReasonRequired\" (added) in \(device)")
    }

    @Test func aBooleanForgedAsANumberFails() throws {
        try edit("corp.sap.privileges.plist") { $0["EnableSystemExtension"] = 1 }
        #expect(check.result(state()).findings == ["corp.sap.privileges \"EnableSystemExtension\""])
    }

    @Test func aWholeFileForAnUnmanagedDomainOrAHandInstalledProfileFails() throws {
        // As a profile installed by hand leaves it: another PayloadUUID and _manualProfile.
        try edit("com.altiward.agent.plist") {
            $0["PayloadUUID"] = "6A6A6A6A-0006-4000-8000-000000000006"
            $0["_manualProfile"] = true
        }
        #expect(check.result(state()).findings == ["com.altiward.agent \"PayloadUUID\"", "com.altiward.agent \"_manualProfile\""])

        // Privileges' settings with no MDM payload for them.
        let noPrivileges = MDMPayloadSet(payloads.payloads(for: AgentConfiguration.domain), readAt: payloads.readAt)
        try edit("com.altiward.agent.plist") {
            $0["PayloadUUID"] = "4B4B4B4B-0004-4000-8000-000000000004"
            $0["_manualProfile"] = nil
        }
        let added = check.result(state { $0.payloads = noPrivileges })
        #expect(added.findings?.contains("corp.sap.privileges \"EnableSystemExtension\"") == true)
        #expect(added.problem?.contains("corp.sap.privileges \"PayloadUUID\" (added)") == true)
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
        #expect(passes(check.result(state { $0.payloads = MDMPayloadSet(two, readAt: payloads.readAt) })))
        #expect(!check.result(state()).ok)
    }

    /// Key names come from a file anyone elevated can write: quoted, escaped and cut short in
    /// the problem text, and at most 20 listed.
    @Test func keyNamesCantFloodOrPassForMoreText() throws {
        try edit("com.altiward.agent.plist") {
            $0["x\"; set outside MDM: nothing\n"] = 1
            $0[String(repeating: "k", count: 200)] = 1
        }
        let odd = try #require(check.result(state()).problem)
        #expect(odd.contains(#""x\"; set outside MDM: nothing\u{A}" (added)"#))
        #expect(odd.contains("\"" + String(repeating: "k", count: 64) + "…\" (added)"))
        #expect(!odd.contains("\n"))

        try edit("com.altiward.agent.plist") { for i in 0..<30 { $0["Extra\(i)"] = i } }
        let r = check.result(state())
        #expect(r.problem?.hasSuffix("; and 12 more") == true)
        #expect(r.findings?.count == 32)

        try edit("com.altiward.agent.plist") { for i in 0..<200 { $0["Many\(i)"] = i } }
        let many = check.result(state())
        #expect(many.findings?.count == 101)
        #expect(many.findings?.last == "and 132 more")
    }

    @Test func aSignedInUsersFolderIsCompared() throws {
        try edit("jdoe/corp.sap.privileges.plist") { $0["EnableSystemExtension"] = false }
        // Not signed in: their folder keeps their last sign-in's settings, and isn't compared.
        #expect(passes(check.result(state())))
        // Just signed in: ManagedClient may still be writing it, so it is due later.
        signedIn.withLock { $0 = ["jdoe": clock.now.addingTimeInterval(-30)] }
        #expect(passes(check.result(state())))
        #expect(memo.takeFollowUp() == clock.now.addingTimeInterval(90))
        #expect(memo.takeFollowUp() == nil)

        signedIn.withLock { $0 = ["jdoe": clock.now.addingTimeInterval(-600)] }
        #expect(
            check.result(state()).problem
                == "managed settings differ from MDM's profiles: corp.sap.privileges \"EnableSystemExtension\" (changed) in \(device)/jdoe")
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
                == "managed settings differ from MDM's profiles: com.altiward.agent \"PermanentAdmins\" (changed) in \(device)/jdoe/complete.plist")
    }

    /// An entry that isn't forced (`mcxdomain` `always`) isn't what MDM set, whatever its value.
    @Test func aCompleteListEntryThatIsntForcedFails() throws {
        signedIn.withLock { $0 = ["jdoe": clock.now.addingTimeInterval(-600)] }
        try edit("jdoe/complete.plist") {
            var agent = $0["com.altiward.agent"] as! [String: Any]
            var entry = agent["ServerURL"] as! [String: Any]
            entry["mcxdomain"] = "often"
            agent["ServerURL"] = entry
            $0["com.altiward.agent"] = agent
        }
        #expect(check.result(state()).findings == ["com.altiward.agent \"ServerURL\""])
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
        #expect(passes(check.result(state())))
    }

    /// Just after this agent saw MDM's payloads change, a file that still holds the old
    /// payloads' value is macOS not having rewritten it yet: held, for a while. New content
    /// isn't.
    @Test func filesStillHoldingTheOldPayloadsAreHeldAfterAChange() throws {
        var newer = payloads.payloads
        let i = try #require(newer.firstIndex { $0.domain == AgentConfiguration.domain })
        newer[i].settings["HeartbeatInterval"] = .integer(300)
        let changed = MDMPayloadSet(newer, readAt: clock.now)
        let justChanged = state {
            $0.payloads = changed
            $0.previous = payloads
            $0.changedAt = clock.now.addingTimeInterval(-60)
        }
        // The file still says 60, the old value.
        let held = check.result(justChanged)
        #expect(held.held && held.ok)
        // A value neither set: new content, reported.
        try edit("com.altiward.agent.plist") { $0["HeartbeatInterval"] = 999 }
        #expect(check.result(justChanged).findings == ["com.altiward.agent \"HeartbeatInterval\""])
        // Another key forged meanwhile is reported, and the lagging one left out.
        try edit("com.altiward.agent.plist") {
            $0["HeartbeatInterval"] = 60
            $0["ServerURL"] = "https://attacker.example.net"
        }
        #expect(check.result(justChanged).findings == ["com.altiward.agent \"ServerURL\""])
        try edit("com.altiward.agent.plist") { $0["ServerURL"] = "https://altiward-agents.example.com" }
        // After the grace, the old value counts.
        var later = justChanged
        later.changedAt = clock.now.addingTimeInterval(-400)
        #expect(check.result(later).findings == ["com.altiward.agent \"HeartbeatInterval\""])
        // Without a change this agent saw, no grace.
        var unseen = justChanged
        unseen.previous = nil
        #expect(!check.result(unseen).ok)
    }

    @Test func aStoredSetInUseIsSaidAndStillCompared() throws {
        try edit("com.altiward.agent.plist") { $0["ServerURL"] = "https://attacker.example.net" }
        let r = check.result(state { $0.readError = .command("profiles show", .exited(1)) })
        #expect(
            r.problem
                == "can't read the installed profiles (profiles show exited with status 1), so compared with the MDM "
                + "settings read 2026-10-14T17:46:40.000Z; managed settings differ from MDM's profiles: "
                + "com.altiward.agent \"ServerURL\" (changed) in \(device)")
        #expect(r.findings == ["com.altiward.agent \"ServerURL\"", "profiles unreadable"])
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

    // MARK: Between reads

    /// A value forged and put back before the profiles are read again is still reported:
    /// the change is compared with the payloads at once, and judged at the next read.
    @Test func aValueForgedAndPutBackIsReported() throws {
        try edit("com.altiward.agent.plist") { $0["ServerURL"] = "https://attacker.example.net" }
        check.quick(state())
        try edit("com.altiward.agent.plist") { $0["ServerURL"] = "https://altiward-agents.example.com" }
        let r = check.result(state())
        #expect(r.ok)
        #expect(
            r.earlier
                == EarlierFailure(
                    problem: "managed settings differed from MDM's profiles at 2026-10-14T18:46:40.000Z: "
                        + "com.altiward.agent \"ServerURL\" (changed) in \(device)",
                    findings: ["com.altiward.agent \"ServerURL\""]))
        // Judged once.
        #expect(check.result(state()).earlier == nil)
    }

    /// MDM rewriting the files for a new profile isn't a forgery: what the change held matches
    /// the payloads read next.
    @Test func aProfileChangeSeenBeforeTheReadIsntReported() throws {
        try edit("com.altiward.agent.plist") { $0["HeartbeatInterval"] = 300 }
        check.quick(state())
        var newer = payloads.payloads
        let i = try #require(newer.firstIndex { $0.domain == AgentConfiguration.domain })
        newer[i].settings["HeartbeatInterval"] = .integer(300)
        #expect(passes(check.result(state { $0.payloads = MDMPayloadSet(newer, readAt: clock.now) })))
    }

    @Test func aChangeMatchingThePayloadsKeepsNothing() {
        check.quick(state())
        #expect(memo.takeCaptures().isEmpty)
    }

    /// What CFPreferences serves is compared too: it can keep serving a forged value after the
    /// file is put back.
    @Test func whatMacOSServesIsCompared() throws {
        var all: [String: PlistValue] = [:]
        for p in payloads.payloads { for (k, v) in p.settings { all["\(p.domain) \(k)"] = v } }
        let every = all
        served.withLock { $0 = every }
        #expect(passes(check.result(state())))

        served.withLock { $0?["com.altiward.agent ServerURL"] = .string("https://attacker.example.net") }
        #expect(
            check.result(state()).problem
                == "managed settings differ from MDM's profiles: com.altiward.agent \"ServerURL\" (changed) in what macOS serves")
        served.withLock { $0?["com.altiward.agent ServerURL"] = nil }
        #expect(check.result(state()).problem?.contains("\"ServerURL\" (removed) in what macOS serves") == true)

        // Caught between reads too.
        served.withLock { $0?["com.altiward.agent ServerURL"] = .string("https://attacker.example.net") }
        check.quick(state())
        served.withLock { $0?["com.altiward.agent ServerURL"] = .string("https://altiward-agents.example.com") }
        #expect(check.result(state()).earlier?.findings == ["com.altiward.agent \"ServerURL\""])
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
