import Foundation
import Testing
import os

@testable import AltiwardCore

/// The UPN Platform SSO links to a Mac account: how it is read, recorded and reported, what
/// wins, and that a session keeps the one it started with.
struct PlatformSSOTests {
    let clock = TestClock()
    let admins = FakeAdmins()
    /// The links the fake directory holds; nil when it can't be read.
    let links = OSAllocatedUnfairLock<[String: String]?>(initialState: ["jdoe": "jane.doe@example.com"])
    let accounts = OSAllocatedUnfairLock<Set<String>>(initialState: ["jdoe", "asmith"])
    let availability = OSAllocatedUnfairLock<PrivilegesLogAvailability>(initialState: .unavailable("x"))

    func tracker(_ config: AgentConfiguration = AgentConfiguration()) throws -> (ElevationTracker, AgentStore) {
        let store = try makeStore()
        let (links, accounts, availability) = (links, accounts, availability)
        let env = makeEnvironment(
            admins: admins, clock: clock, config: config,
            accountExists: { name in accounts.withLock { $0.contains(name) } },
            privilegesLogAvailability: { availability.withLock { $0 } },
            platformSSOLinks: { links.withLock { $0 } })
        return (ElevationTracker(store: store, environment: env), store)
    }

    /// A tracker whose links are on record, as after the daemon's first check.
    func recorded(_ config: AgentConfiguration = AgentConfiguration()) throws -> (ElevationTracker, AgentStore) {
        let (tracker, store) = try tracker(config)
        #expect(try tracker.checkPlatformSSOLinks().isEmpty)
        return (tracker, store)
    }

    func claim(_ user: String = "jdoe", _ state: HookInvocation.State = .admin) -> HookInvocation {
        HookInvocation(user: user, state: state, reason: "testing", invokedAt: clock.now)
    }

    // MARK: Reading the link

    @Test func theUPNIsThePlatformSSOValue() {
        let values = [
            "X509:<T>CN=Apple Root CA,OU=Apple Certification Authority,O=Apple Inc.,C=US<S>CN=com.apple.idms.appleid.prd.001",
            "PlatformSSO:phil@lab42.cloud",
        ]
        #expect(PlatformSSO.upn(fromAltSecurityIdentities: values) == "phil@lab42.cloud")
        #expect(
            PlatformSSO.upn(fromAltSecurityIdentities: ["PlatformSSO:o'brien+mac@corp-1.example.com"])
                == "o'brien+mac@corp-1.example.com")
    }

    @Test(arguments: [
        [],
        ["X509:<T>CN=Apple Root CA"],
        // Two links, or one that only matches ignoring case: ambiguous.
        ["PlatformSSO:a@example.com", "PlatformSSO:b@example.com"],
        ["PlatformSSO:a@example.com", "platformsso:b@example.com"],
        ["platformsso:a@example.com"],
        // Not a plain ASCII UPN.
        ["PlatformSSO:"],
        ["PlatformSSO:jdoe"],
        ["PlatformSSO:a@b@example.com"],
        ["PlatformSSO:jane doe@example.com"],
        ["PlatformSSO:jane.doe@example.com\n"],
        ["PlatformSSO:jane\u{200B}doe@example.com"],
        ["PlatformSSO:j\u{0430}ne@example.com"],
        ["PlatformSSO:\"jane\"@example.com"],
        ["PlatformSSO:" + String(repeating: "a", count: 65) + "@example.com"],
        // A domain must be dotted labels that don't start or end with a hyphen or dot.
        ["PlatformSSO:bob@corp"],
        ["PlatformSSO:bob@-"],
        ["PlatformSSO:bob@corp.com."],
        ["PlatformSSO:bob@-corp.com"],
        ["PlatformSSO:bob@corp..com"],
    ])
    func anythingElseIsNoLink(values: [String]) {
        #expect(PlatformSSO.upn(fromAltSecurityIdentities: values) == nil)
    }

    /// The live read, against this Mac's directory: it answers, and root isn't linked.
    @Test func theLiveReadAnswers() throws {
        let links = try #require(PlatformSSO.allLinks())
        #expect(links["root"] == nil)
    }

    // MARK: What wins

    @Test func aMapMDMForcesWins() {
        let config = AgentConfiguration(userPrincipalNames: ["jdoe": "a@example.com"], userPrincipalNamesForced: true)
        #expect(config.upn(for: "jdoe") { _ in "b@example.com" } == "a@example.com")
        // An account the map leaves out still gets its link.
        #expect(config.upn(for: "asmith") { _ in "b@example.com" } == "b@example.com")
    }

    /// Anyone elevated could write a map to /Library/Preferences: it counts for nothing.
    @Test func aMapSetOutsideMDMIsIgnored() {
        let config = AgentConfiguration(userPrincipalNames: ["jdoe": "a@example.com"], userPrincipalNamesForced: false)
        #expect(config.upn(for: "jdoe") { _ in "b@example.com" } == "b@example.com")
        #expect(config.upn(for: "jdoe") { _ in nil } == nil)
    }

    @Test func loadingSaysWhetherMDMForcesTheMap() {
        let map = ["UserPrincipalNames": ["jdoe": "a@example.com"]]
        #expect(AgentConfiguration.load(environment: [:], preferences: Preferences(values: map)).userPrincipalNamesForced == false)
        #expect(
            AgentConfiguration.load(environment: [:], preferences: Preferences(values: map, forced: ["UserPrincipalNames"]))
                .userPrincipalNamesForced == true)
    }

    @Test func onlyMDMCanTurnTheReadOff() {
        let off: [String: Any] = ["PlatformSSOIdentity": false]
        #expect(AgentConfiguration.load(environment: [:], preferences: Preferences(values: [:])).platformSSOIdentity)
        #expect(
            !AgentConfiguration.load(environment: [:], preferences: Preferences(values: off, forced: ["PlatformSSOIdentity"]))
                .platformSSOIdentity)
        // Written with defaults by someone elevated: ignored.
        #expect(AgentConfiguration.load(environment: [:], preferences: Preferences(values: off)).platformSSOIdentity)
    }

    @Test func turnedOffNothingIsReadOrKept() throws {
        let reads = OSAllocatedUnfairLock(initialState: 0)
        let store = try makeStore()
        try store.setValue(#"{"jdoe":"jane.doe@example.com"}"#, forKey: ElevationTracker.platformSSOLinksKey)
        let env = makeEnvironment(
            admins: admins, clock: clock,
            config: AgentConfiguration(userPrincipalNames: ["asmith": "a.smith@example.com"], platformSSOIdentity: false),
            platformSSOLinks: {
                reads.withLock { $0 += 1 }
                return ["jdoe": "jane.doe@example.com"]
            })
        let tracker = ElevationTracker(store: store, environment: env)
        // Turned off, no link is kept: only an empty record, so turning it on reports them all.
        #expect(try tracker.checkPlatformSSOLinks().isEmpty)
        let kept = try #require(try store.value(forKey: ElevationTracker.platformSSOLinksKey))
        #expect(try JSONDecoder().decode(PlatformSSORecord.self, from: Data(kept.utf8)) == PlatformSSORecord())
        admins.set(["jdoe"])
        #expect(try tracker.record(claim()).user?.upn == nil)
        #expect(tracker.upn(for: "asmith") == "a.smith@example.com")
        #expect(reads.withLock { $0 } == 0)
    }

    // MARK: Recording and reporting links

    @Test func theFirstReadOnlyRecords() throws {
        let (tracker, _) = try tracker()
        #expect(tracker.upn(for: "jdoe") == nil)
        #expect(try tracker.checkPlatformSSOLinks().isEmpty)
        #expect(tracker.upn(for: "jdoe") == "jane.doe@example.com")
        admins.set(["jdoe"])
        #expect(try tracker.record(claim()).user?.upn == "jane.doe@example.com")
    }

    @Test func aMovedLinkIsReportedBeforeEventsUseIt() throws {
        let (tracker, store) = try recorded()
        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        // Not yet: events use the record until the change is reported.
        #expect(tracker.upn(for: "jdoe") == "jane.doe@example.com")

        let events = try tracker.checkPlatformSSOLinks()
        let event = try #require(events.first)
        #expect(events.count == 1)
        #expect(event.type == .agentTamper)
        #expect(event.detail["check"] == "platform_sso_link_changed")
        #expect(event.detail["state"] == "detected")
        #expect(event.detail["user"] == "jdoe")
        #expect(event.detail["previous_upn"] == "jane.doe@example.com")
        #expect(event.detail["upn"] == "ceo@example.com")
        #expect(event.detail["problem"] == "jdoe's Mac account moved from jane.doe@example.com to ceo@example.com in Platform SSO")
        #expect(try store.pending(limit: 10).map(\.event.eventID) == [event.eventID])

        #expect(tracker.upn(for: "jdoe") == "ceo@example.com")
        #expect(try tracker.checkPlatformSSOLinks().isEmpty)
    }

    @Test func aLinkAddedOrRemovedIsReported() throws {
        let (tracker, _) = try recorded()
        links.withLock { $0 = ["asmith": "a.smith@example.com"] }
        let events = try tracker.checkPlatformSSOLinks()
        #expect(events.map { $0.detail["check"] } == ["platform_sso_link", "platform_sso_link"])
        #expect(events.map { $0.detail["user"] } == ["asmith", "jdoe"])
        #expect(events[0].detail["previous_upn"] == .null)
        #expect(events[0].detail["upn"] == "a.smith@example.com")
        #expect(events[1].detail["previous_upn"] == "jane.doe@example.com")
        #expect(events[1].detail["upn"] == .null)
        #expect(tracker.upn(for: "jdoe") == nil)
    }

    /// Deleting an account and making it again with another link is a changed link.
    @Test func aRecreatedAccountIsComparedWithItsLastLink() throws {
        let (tracker, _) = try recorded()
        accounts.withLock { _ = $0.remove("jdoe") }
        links.withLock { $0 = [:] }
        #expect(try tracker.checkPlatformSSOLinks().isEmpty)
        accounts.withLock { _ = $0.insert("jdoe") }
        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        let event = try #require(try tracker.checkPlatformSSOLinks().first)
        #expect(event.detail["check"] == "platform_sso_link_changed")
        #expect(event.detail["previous_upn"] == "jane.doe@example.com")
        #expect(event.detail["upn"] == "ceo@example.com")
    }

    /// Unlinking and linking again to someone else, across two checks, is still a change.
    @Test func unlinkingThenLinkingToAnotherIsAChange() throws {
        let (tracker, _) = try recorded()
        links.withLock { $0 = [:] }
        #expect(try tracker.checkPlatformSSOLinks().first?.detail["check"] == "platform_sso_link")
        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        let event = try #require(try tracker.checkPlatformSSOLinks().first)
        #expect(event.detail["check"] == "platform_sso_link_changed")
        #expect(event.detail["previous_upn"] == "jane.doe@example.com")
        // Linked again to the same account: a plain link.
        links.withLock { $0 = [:] }
        try tracker.checkPlatformSSOLinks()
        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        #expect(try tracker.checkPlatformSSOLinks().first?.detail["check"] == "platform_sso_link")
    }

    @Test func aLinkAnotherAccountHasIsAChange() throws {
        let (tracker, _) = try recorded()
        links.withLock { $0 = ["jdoe": "jane.doe@example.com", "asmith": "JANE.DOE@example.com"] }
        let event = try #require(try tracker.checkPlatformSSOLinks().first)
        #expect(event.detail["check"] == "platform_sso_link_changed")
        #expect(event.detail["user"] == "asmith")
    }

    @Test func aLinkAddedWhileSomeoneIsElevatedIsAChange() throws {
        let (tracker, _) = try recorded()
        admins.set(["jdoe"])
        try tracker.record(claim())
        links.withLock { $0 = ["jdoe": "jane.doe@example.com", "asmith": "a.smith@example.com"] }
        let event = try #require(try tracker.checkPlatformSSOLinks().first)
        #expect(event.detail["check"] == "platform_sso_link_changed")
        #expect(event.detail["user"] == "asmith")
    }

    /// Turning the read off and on again, or a record that can't be decoded, starts from an
    /// empty record: every link is reported, none taken in silently.
    @Test(arguments: [true, false])
    func noRecordAfterOneExistedReportsEveryLink(viaSetting: Bool) throws {
        let store = try makeStore()
        let links = links
        func tracker(_ on: Bool) -> ElevationTracker {
            ElevationTracker(
                store: store,
                environment: makeEnvironment(
                    admins: admins, clock: clock, config: AgentConfiguration(platformSSOIdentity: on),
                    platformSSOLinks: { links.withLock { $0 } }))
        }
        #expect(try tracker(true).checkPlatformSSOLinks().isEmpty)
        if viaSetting {
            #expect(try tracker(false).checkPlatformSSOLinks().isEmpty)
        } else {
            try store.setValue("not json", forKey: ElevationTracker.platformSSOLinksKey)
        }
        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        let event = try #require(try tracker(true).checkPlatformSSOLinks().first)
        #expect(event.detail["user"] == "jdoe")
        #expect(event.detail["upn"] == "ceo@example.com")
    }

    @Test func anUnreadableDirectoryKeepsTheRecord() throws {
        let (tracker, _) = try recorded()
        links.withLock { $0 = nil }
        #expect(try tracker.checkPlatformSSOLinks().isEmpty)
        #expect(tracker.upn(for: "jdoe") == "jane.doe@example.com")
        links.withLock { $0 = ["jdoe": "jane.doe@example.com"] }
        #expect(try tracker.checkPlatformSSOLinks().isEmpty)
    }

    // MARK: A session keeps its UPN

    @Test func aSessionKeepsTheUPNItStartedWith() throws {
        let (tracker, store) = try recorded()
        admins.set(["jdoe"])
        let granted = try tracker.record(claim())
        #expect(granted.user?.upn == "jane.doe@example.com")
        #expect(try store.openSession(user: "jdoe")?.upn == .read("jane.doe@example.com"))

        // Elevated, they link their account to someone else's: reported, and the session stays.
        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        #expect(try tracker.checkPlatformSSOLinks().count == 1)
        clock.advance(60)
        admins.set([])
        let revoked = try tracker.record(claim("jdoe", .user))
        #expect(revoked.type == .elevationRevoked)
        #expect(revoked.sessionID == granted.sessionID)
        #expect(revoked.user?.upn == "jane.doe@example.com")

        // The next session is theirs to explain: it starts with the reported link.
        clock.advance(60)
        admins.set(["jdoe"])
        #expect(try tracker.record(claim()).user?.upn == "ceo@example.com")
    }

    /// A user with no UPN when the session started keeps none: a link they add while elevated
    /// doesn't move the session onto its owner.
    @Test func aSessionWithNoUPNKeepsNone() throws {
        links.withLock { $0 = [:] }
        let (tracker, store) = try recorded()
        admins.set(["jdoe"])
        let granted = try tracker.record(claim())
        #expect(granted.user?.upn == nil)
        #expect(try store.openSession(user: "jdoe")?.upn == .read(nil))

        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        #expect(try tracker.checkPlatformSSOLinks().first?.detail["check"] == "platform_sso_link_changed")
        admins.set([])
        clock.advance(60)
        let revoked = try #require(try tracker.heartbeat().first { $0.type == .elevationRevoked })
        #expect(revoked.sessionID == granted.sessionID)
        #expect(revoked.user?.upn == nil)
    }

    @Test func aRenewalKeepsTheSessionsUPN() throws {
        let (tracker, _) = try recorded()
        admins.set(["jdoe"])
        let first = try tracker.record(claim())
        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        try tracker.checkPlatformSSOLinks()
        clock.advance(60)
        let renewed = try tracker.record(claim())
        #expect(renewed.sessionID == first.sessionID)
        #expect(renewed.detail["renewed"] == true)
        #expect(renewed.user?.upn == "jane.doe@example.com")
    }

    @Test(arguments: [true, false])
    func aHeldClaimKeepsTheUPNItArrivedWith(linked: Bool) throws {
        if !linked { links.withLock { $0 = [:] } }
        availability.withLock { $0 = .available }
        let (tracker, store) = try recorded()
        admins.set(["jdoe"])
        guard case .pending = try tracker.submit(claim(), callerUID: 501) else {
            Issue.record("expected the claim to be held")
            return
        }
        let expected = linked ? "jane.doe@example.com" : nil
        #expect(try store.pendingClaims().first?.upn == .read(expected))

        // While the claim waits for Privileges' log, the user changes their link.
        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        #expect(try tracker.checkPlatformSSOLinks().count == 1)
        availability.withLock { $0 = .unavailable("log gone") }
        let granted = try #require(try tracker.resolvePendingClaims().first { $0.type == .elevationGranted })
        #expect(granted.user?.upn == expected)
        #expect(try store.openSession(user: "jdoe")?.upn == .read(expected))
    }

    @Test func anOutOfBandSessionKeepsTheUPNItOpenedWith() throws {
        let (tracker, store) = try recorded()
        admins.set(["jdoe"])
        let opened = try #require(try tracker.heartbeat().first { $0.type == .adminOutOfBand })
        #expect(opened.user?.upn == "jane.doe@example.com")
        #expect(try store.openSession(user: "jdoe")?.upn == .read("jane.doe@example.com"))
        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        try tracker.checkPlatformSSOLinks()
        admins.set([])
        clock.advance(60)
        let closed = try #require(try tracker.heartbeat().first { $0.type == .elevationRevoked })
        #expect(closed.user?.upn == "jane.doe@example.com")
    }

    @Test func aSessionFromAnOlderAgentUsesTheRecord() throws {
        let (tracker, store) = try recorded()
        admins.set(["jdoe"])
        try store.upsertOpenSession(
            OpenSession(user: "jdoe", sessionID: newID(), source: .privileges, startedAt: clock.now, expiresAt: nil))
        admins.set([])
        let revoked = try #require(try tracker.heartbeat().first { $0.type == .elevationRevoked })
        #expect(revoked.user?.upn == "jane.doe@example.com")
    }

    @Test func pinsAreStoredApartFromUnknown() {
        #expect(PinnedUPN(column: nil) == .unknown)
        #expect(PinnedUPN(column: "") == .read(nil))
        #expect(PinnedUPN(column: "a@example.com") == .read("a@example.com"))
    }
}
