import Foundation
import os
import Testing

@testable import AltiwardCore

/// The agent side of remote commands: wire format, execution on the Mac, and the poll loop.
struct CommandWireTests {
    @Test func decodesAgentCommandsFixture() throws {
        let data = try Data(contentsOf: repoFile("docs/schema/commands/agent-commands.json"))
        let list = try AltiwardJSON.decoder().decode(AgentCommandList.self, from: data)
        #expect(list.commands.count == 2)
        #expect(list.commands[0].type == "revoke_admin")
        #expect(list.commands[0].user == "jdoe")
        #expect(list.commands[0].sessionID == "5d1c2b7a-8e4f-4a6b-9c3d-2e1f0a9b8c7d")
        #expect(list.commands[1].user == nil)
        #expect(list.commands[1].expiresAt == AltiwardJSON.parse("2026-10-17T09:25:00Z"))
    }

    @Test func encodesResultExactlyLikeFixture() throws {
        let data = try Data(contentsOf: repoFile("docs/schema/commands/command-result.json"))
        let result = try AltiwardJSON.decoder().decode(CommandResult.self, from: data)
        #expect(result.status == .failed)
        #expect(result.skipped == [.init(user: "itadmin", reason: .permanentAdmin)])
        let original = try JSONSerialization.jsonObject(with: data) as! NSDictionary
        let reencoded = try JSONSerialization.jsonObject(with: AltiwardJSON.encoder().encode(result)) as! NSDictionary
        #expect(reencoded == original)
    }
}

struct CommandExecutionTests {
    let clock = TestClock()
    let admins = FakeAdmins(["jdoe"])

    func tracker(permanent: Set<String> = []) throws -> (ElevationTracker, AgentStore) {
        let store = try makeStore()
        let env = makeEnvironment(admins: admins, clock: clock, config: AgentConfiguration(permanentAdmins: permanent))
        return (ElevationTracker(store: store, environment: env), store)
    }

    func revoke(user: String? = "jdoe", session: String? = nil, type: String = "revoke_admin") -> AgentCommand {
        AgentCommand(commandID: newID(), type: type, user: user, sessionID: session, expiresAt: clock.now.addingTimeInterval(86400))
    }

    func grant(_ tracker: ElevationTracker, _ user: String = "jdoe") throws -> AltiwardEvent {
        try tracker.record(HookInvocation(user: user, state: .admin, reason: "work", invokedAt: clock.now))
    }

    func queuedEvents(_ store: AgentStore) throws -> [AltiwardEvent] { try store.pending(limit: 100).map(\.event) }

    @Test func revokesSessionAndRecordsEvent() throws {
        let (tracker, store) = try tracker()
        let granted = try grant(tracker)
        let command = revoke(session: granted.sessionID)
        clock.advance(60)

        let result = try tracker.execute(command)
        #expect(result.status == .completed)
        #expect(result.revoked == ["jdoe"])
        #expect(result.completedAt == clock.now)
        #expect(!admins.isAdmin(user: "jdoe"))
        #expect(try store.openSession(user: "jdoe") == nil)

        let revoked = try #require(try queuedEvents(store).last)
        #expect(revoked.type == .elevationRevoked)
        #expect(revoked.sessionID == granted.sessionID)
        #expect(revoked.timestamp == clock.now)
        #expect(revoked.detail["trigger"] == "command")
        #expect(revoked.detail["command_id"] == .string(command.commandID))
        #expect(revoked.detail["observed_admin"] == false)
    }

    @Test func leavesNewerSessionAlone() throws {
        let (tracker, _) = try tracker()
        _ = try grant(tracker)
        let result = try tracker.execute(revoke(session: newID()))  // a session that already ended
        #expect(result.status == .skipped)
        #expect(result.skipped == [.init(user: "jdoe", reason: .sessionEnded)])
        #expect(admins.isAdmin(user: "jdoe"))
    }

    @Test func neverRemovesPermanentAdmins() throws {
        admins.set(["itadmin"])
        let (tracker, _) = try tracker(permanent: ["itadmin"])
        let result = try tracker.execute(revoke(user: "itadmin"))
        #expect(result.skipped == [.init(user: "itadmin", reason: .permanentAdmin)])
        #expect(admins.isAdmin(user: "itadmin"))
        #expect(admins.removalAttempts == 0)
    }

    @Test func wholeDeviceRevokesEveryoneButPermanentAdmins() throws {
        admins.set(["jdoe", "contractor", "itadmin"])
        let (tracker, store) = try tracker(permanent: ["itadmin"])
        _ = try grant(tracker)
        _ = try tracker.heartbeat()  // contractor becomes an out-of-band session

        let result = try tracker.execute(revoke(user: nil))
        #expect(result.status == .completed)
        #expect(result.revoked == ["contractor", "jdoe"])
        #expect(result.skipped == [.init(user: "itadmin", reason: .permanentAdmin)])
        #expect(admins.adminMembers() == ["itadmin"])
        #expect(try store.openSessions().isEmpty)
    }

    @Test func reportsFailedRemoval() throws {
        let (tracker, store) = try tracker()
        _ = try grant(tracker)
        admins.failRemovals = true
        let result = try tracker.execute(revoke())
        #expect(result.status == .failed)
        #expect(result.failed.map(\.user) == ["jdoe"])
        #expect(try store.openSession(user: "jdoe") != nil)
    }

    @Test func removalThatThrowsButTakesEffectCountsAsRevoked() throws {
        let (tracker, store) = try tracker()
        _ = try grant(tracker)
        admins.removalsThrowAfterTakingEffect = true
        let result = try tracker.execute(revoke())
        #expect(result.status == .completed)
        #expect(result.revoked == ["jdoe"])
        #expect(try store.openSession(user: "jdoe") == nil)
    }

    @Test func removalThatMembershipReadsCatchUpWithCountsAsRevoked() throws {
        let store = try makeStore()
        let admins = admins
        let env = makeEnvironment(admins: admins, clock: clock, waitForDirectory: { admins.settle() })
        let tracker = ElevationTracker(store: store, environment: env)
        _ = try grant(tracker)
        admins.removalsTakeEffectLater = true
        let result = try tracker.execute(revoke())
        #expect(result.status == .completed)
        #expect(result.revoked == ["jdoe"])
        #expect(try store.openSession(user: "jdoe") == nil)
    }

    @Test func removalThatNeverTakesEffectFailsAfterBoundedWaits() throws {
        let store = try makeStore()
        let waits = OSAllocatedUnfairLock(initialState: 0)
        let env = makeEnvironment(admins: admins, clock: clock, waitForDirectory: { waits.withLock { $0 += 1 } })
        let tracker = ElevationTracker(store: store, environment: env)
        _ = try grant(tracker)
        admins.removalsHaveNoEffect = true
        let result = try tracker.execute(revoke())
        #expect(result.status == .failed)
        #expect(result.failed == [.init(user: "jdoe", error: ElevationTracker.stillAdmin)])
        #expect(waits.withLock { $0 } == ElevationTracker.membershipRechecks)
        #expect(try store.openSession(user: "jdoe") != nil)
    }

    @Test func skipsUserWhoIsNotAdmin() throws {
        admins.set([])
        let (tracker, _) = try tracker()
        let result = try tracker.execute(revoke())
        #expect(result.status == .skipped)
        #expect(result.skipped == [.init(user: "jdoe", reason: .notAdmin)])
    }

    @Test func redeliveredCommandIsNotRunAgain() throws {
        let (tracker, store) = try tracker()
        _ = try grant(tracker)
        let command = revoke()
        let first = try tracker.execute(command)
        let eventsAfterFirst = try queuedEvents(store).count

        admins.set(["jdoe"])  // granted again since; the old command must not touch it
        clock.advance(600)
        let again = try tracker.execute(command)
        #expect(again == first)
        #expect(admins.isAdmin(user: "jdoe"))
        #expect(admins.removalAttempts == 1)
        #expect(try queuedEvents(store).count == eventsAfterFirst)
    }

    @Test func unsupportedCommandFails() throws {
        let (tracker, _) = try tracker()
        let result = try tracker.execute(revoke(type: "wipe_everything"))
        #expect(result.status == .failed)
        #expect(result.error == "unsupported command type wipe_everything")
        #expect(admins.isAdmin(user: "jdoe"))
    }
}

struct CommandLoopTests {
    let clock = TestClock()
    let admins = FakeAdmins(["jdoe"])

    func setup() throws -> (CommandLoop, FakeServer, AgentStore) {
        let store = try makeStore()
        let server = FakeServer(clock: clock)
        let auth = DeviceAuthenticator(
            store: store, serverURL: URL(string: "https://api.altiward.test")!, enrollmentToken: "enroll-token-0001",
            device: { testDevice }, transport: server, keys: FakeKeys(), now: { clock.now })
        let tracker = ElevationTracker(store: store, environment: makeEnvironment(admins: admins, clock: clock))
        return (CommandLoop(store: store, tracker: tracker, authenticator: auth, now: { clock.now }), server, store)
    }

    func command() -> AgentCommand {
        AgentCommand(commandID: newID(), type: "revoke_admin", user: "jdoe", sessionID: nil, expiresAt: clock.now.addingTimeInterval(86400))
    }

    @Test func runsCommandsAndReportsOnce() async throws {
        let (loop, server, _) = try setup()
        let c = command()
        server.queueCommand(c)
        let summary = await loop.poll()
        #expect(summary == CommandPollSummary(executed: 1, reported: 1, error: nil))
        #expect(!admins.isAdmin(user: "jdoe"))
        let reported = try #require(server.results[c.commandID])
        #expect(reported.status == .completed)

        #expect(await loop.poll() == CommandPollSummary(executed: 0, reported: 0, error: nil))
        #expect(server.results.count == 1)
    }

    @Test func longPollAsksTheServerToHoldTheRequest() async throws {
        let (loop, server, _) = try setup()
        server.queueCommand(command())
        let summary = await loop.poll(wait: 50)
        #expect(summary == CommandPollSummary(executed: 1, reported: 1, error: nil))
        let fetch = try #require(server.requests.last { $0.method == "GET" })
        #expect(fetch.path == "/v1/agent/commands")
        #expect(fetch.query == "wait=50")
        #expect(fetch.timeout > 50)

        _ = await loop.poll()
        #expect(server.requests.last { $0.method == "GET" }?.query == nil)
    }

    @Test(arguments: [
        // A held request came back empty at its deadline: ask again at once.
        (CommandPollSummary(executed: 0, reported: 0, error: nil), 50.2, 0.0),
        // An empty answer straight away: a server that doesn't hold requests.
        (CommandPollSummary(executed: 0, reported: 0, error: nil), 0.1, 60.0),
        // Commands arrived: ask again soon, but not in a tight loop.
        (CommandPollSummary(executed: 1, reported: 1, error: nil), 0.3, 1.0),
        (CommandPollSummary(executed: 1, reported: 0, error: "503"), 0.3, 60.0),
        (CommandPollSummary(executed: 0, reported: 0, error: "offline"), 0.0, 60.0),
    ])
    func pauseAfterLongPoll(summary: CommandPollSummary, elapsed: Double, pause: Double) {
        #expect(CommandLoop.pauseAfterLongPoll(summary, elapsed: elapsed, wait: 50, interval: 60) == pause)
    }

    @Test func unacknowledgedResultIsReportedLaterWithoutRerunning() async throws {
        let (loop, server, _) = try setup()
        let c = command()
        server.queueCommand(c)
        server.failResults(times: 1)  // the server re-sends c until it has a result
        let first = await loop.poll()
        #expect(first.executed == 1)
        #expect(first.reported == 0)
        #expect(server.results[c.commandID] == nil)

        admins.set(["jdoe"])
        let second = await loop.poll()
        #expect(second.reported == 1)
        #expect(server.results[c.commandID]?.revoked == ["jdoe"])
        #expect(admins.isAdmin(user: "jdoe"))  // not removed a second time
        #expect(admins.removalAttempts == 1)
    }
}
