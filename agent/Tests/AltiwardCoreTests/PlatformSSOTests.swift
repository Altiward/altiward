import Foundation
import Testing
import os

@testable import AltiwardCore

/// The UPN Platform SSO links to a Mac account: where it comes from, what wins, and that a
/// session keeps the one it started with.
struct PlatformSSOTests {
    let clock = TestClock()
    let admins = FakeAdmins()
    /// jdoe's link, as the fake directory reports it.
    let link = OSAllocatedUnfairLock<PlatformSSO.Lookup>(initialState: .linked("jane.doe@example.com"))
    let availability = OSAllocatedUnfairLock<PrivilegesLogAvailability>(initialState: .unavailable("x"))

    func tracker(_ config: AgentConfiguration = AgentConfiguration()) throws -> (ElevationTracker, AgentStore) {
        let store = try makeStore()
        let (link, availability) = (link, availability)
        let env = makeEnvironment(
            admins: admins, clock: clock, config: config,
            privilegesLogAvailability: { availability.withLock { $0 } },
            platformSSO: { $0 == "jdoe" ? link.withLock { $0 } : .notLinked })
        return (ElevationTracker(store: store, environment: env), store)
    }

    func claim(_ state: HookInvocation.State = .admin) -> HookInvocation {
        HookInvocation(user: "jdoe", state: state, reason: "testing", invokedAt: clock.now)
    }

    // MARK: Reading the link

    @Test func theUPNIsThePlatformSSOValue() {
        let values = [
            "X509:<T>CN=Apple Root CA,OU=Apple Certification Authority,O=Apple Inc.,C=US<S>CN=com.apple.idms.appleid.prd.001",
            "PlatformSSO:phil@lab42.cloud",
        ]
        #expect(PlatformSSO.upn(fromAltSecurityIdentities: values) == "phil@lab42.cloud")
        #expect(PlatformSSO.upn(fromAltSecurityIdentities: ["PlatformSSO:o'brien+mac@corp.example.com"]) == "o'brien+mac@corp.example.com")
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
    ])
    func anythingElseIsNoLink(values: [String]) {
        #expect(PlatformSSO.upn(fromAltSecurityIdentities: values) == nil)
    }

    /// The live read, against this Mac's directory: root exists and isn't linked.
    @Test func theLiveReadTellsAccountsApart() {
        #expect(PlatformSSO.lookup("root") == .notLinked)
        #expect(PlatformSSO.lookup("altiward-no-such-user-\(UUID().uuidString.prefix(8))") == .noAccount)
        #expect(PlatformSSO.allLinks()?["root"] == nil)
    }

    // MARK: What wins

    @Test func aMapMDMForcesWins() {
        let config = AgentConfiguration(userPrincipalNames: ["jdoe": "a@example.com"], userPrincipalNamesForced: true)
        #expect(config.upn(for: "jdoe") { _ in "b@example.com" } == "a@example.com")
        // An account the map leaves out still gets its link.
        #expect(config.upn(for: "asmith") { _ in "b@example.com" } == "b@example.com")
    }

    @Test func aLinkBeatsAMapSetOutsideMDM() {
        let config = AgentConfiguration(userPrincipalNames: ["jdoe": "a@example.com"], userPrincipalNamesForced: false)
        #expect(config.upn(for: "jdoe") { _ in "b@example.com" } == "b@example.com")
        #expect(config.upn(for: "jdoe") { _ in nil } == "a@example.com")
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

    @Test func turnedOffNoLinkIsRead() throws {
        let reads = OSAllocatedUnfairLock(initialState: 0)
        let store = try makeStore()
        let env = makeEnvironment(
            admins: admins, clock: clock,
            config: AgentConfiguration(
                userPrincipalNames: ["asmith": "a.smith@example.com"], platformSSOIdentity: false),
            platformSSO: { _ in
                reads.withLock { $0 += 1 }
                return .linked("jane.doe@example.com")
            })
        let tracker = ElevationTracker(store: store, environment: env)
        admins.set(["jdoe"])
        #expect(try tracker.record(claim()).user?.upn == nil)
        #expect(tracker.upn(for: "asmith") == "a.smith@example.com")
        #expect(reads.withLock { $0 } == 0)
    }

    @Test func platformSSOFillsAMissingEntry() throws {
        let (tracker, _) = try tracker()
        admins.set(["jdoe"])
        #expect(try tracker.record(claim()).user?.upn == "jane.doe@example.com")
    }

    @Test func noLinkNoUPN() throws {
        link.withLock { $0 = .unreadable("directory down") }
        let (tracker, _) = try tracker()
        admins.set(["jdoe"])
        let event = try tracker.record(claim())
        #expect(event.user == UserInfo(localName: "jdoe", upn: nil))
    }

    // MARK: A session keeps its UPN

    @Test func aSessionKeepsTheUPNItStartedWith() throws {
        let (tracker, store) = try tracker()
        admins.set(["jdoe"])
        let granted = try tracker.record(claim())
        #expect(granted.user?.upn == "jane.doe@example.com")
        #expect(try store.openSession(user: "jdoe")?.upn == "jane.doe@example.com")

        // Elevated, they link their account to someone else's.
        link.withLock { $0 = .linked("ceo@example.com") }
        clock.advance(60)
        admins.set([])
        let revoked = try tracker.record(claim(.user))
        #expect(revoked.type == .elevationRevoked)
        #expect(revoked.sessionID == granted.sessionID)
        #expect(revoked.user?.upn == "jane.doe@example.com")

        // The next session is theirs to explain: it starts with the link as it is then.
        clock.advance(60)
        admins.set(["jdoe"])
        #expect(try tracker.record(claim()).user?.upn == "ceo@example.com")
    }

    @Test func aRenewalKeepsTheSessionsUPN() throws {
        let (tracker, _) = try tracker()
        admins.set(["jdoe"])
        let first = try tracker.record(claim())
        link.withLock { $0 = .linked("ceo@example.com") }
        clock.advance(60)
        let renewed = try tracker.record(claim())
        #expect(renewed.sessionID == first.sessionID)
        #expect(renewed.detail["renewed"] == true)
        #expect(renewed.user?.upn == "jane.doe@example.com")
    }

    @Test func heartbeatEventsCarryTheSessionsUPN() throws {
        let (tracker, _) = try tracker()
        admins.set(["jdoe"])
        let granted = try tracker.record(claim())
        link.withLock { $0 = .linked("ceo@example.com") }
        admins.set([])
        clock.advance(60)
        let revoked = try #require(try tracker.heartbeat().first { $0.type == .elevationRevoked })
        #expect(revoked.sessionID == granted.sessionID)
        #expect(revoked.user?.upn == "jane.doe@example.com")
    }

    @Test func aHeldClaimKeepsTheUPNItArrivedWith() throws {
        availability.withLock { $0 = .available }
        let (tracker, store) = try tracker()
        admins.set(["jdoe"])
        guard case .pending = try tracker.submit(claim(), callerUID: 501) else {
            Issue.record("expected the claim to be held")
            return
        }
        #expect(try store.pendingClaims().first?.upn == "jane.doe@example.com")

        // While the claim waits for Privileges' log, the user changes their link.
        link.withLock { $0 = .linked("ceo@example.com") }
        availability.withLock { $0 = .unavailable("log gone") }
        let granted = try #require(try tracker.resolvePendingClaims().first { $0.type == .elevationGranted })
        #expect(granted.user?.upn == "jane.doe@example.com")
        #expect(try store.openSession(user: "jdoe")?.upn == "jane.doe@example.com")
    }

    @Test func anOutOfBandSessionKeepsTheUPNItOpenedWith() throws {
        let (tracker, store) = try tracker()
        admins.set(["jdoe"])
        let opened = try #require(try tracker.heartbeat().first { $0.type == .adminOutOfBand })
        #expect(opened.user?.upn == "jane.doe@example.com")
        #expect(try store.openSession(user: "jdoe")?.upn == "jane.doe@example.com")
        link.withLock { $0 = .linked("ceo@example.com") }
        admins.set([])
        clock.advance(60)
        let closed = try #require(try tracker.heartbeat().first { $0.type == .elevationRevoked })
        #expect(closed.user?.upn == "jane.doe@example.com")
    }

    @Test func aSessionFromAnOlderAgentReadsTheUPNNow() throws {
        let (tracker, store) = try tracker()
        admins.set(["jdoe"])
        try store.upsertOpenSession(
            OpenSession(user: "jdoe", sessionID: newID(), source: .privileges, startedAt: clock.now, expiresAt: nil))
        admins.set([])
        let revoked = try #require(try tracker.heartbeat().first { $0.type == .elevationRevoked })
        #expect(revoked.user?.upn == "jane.doe@example.com")
    }
}
