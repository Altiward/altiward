import Foundation
import Testing
import os

@testable import AltiwardCore

/// admin.permanent_use from the unified log: prompts typed with a permanent admin's password,
/// and sudo and su by the account.
struct PermanentUseLogTests {
    let clock = TestClock()
    let store: AgentStore
    let admins = FakeAdmins(["breakglass"])
    /// What the log holds; the fake reader returns the records since a date, as the live one does.
    let logged = OSAllocatedUnfairLock<[PermanentUseLogRecord]>(initialState: [])
    let reads = OSAllocatedUnfairLock<[Date]>(initialState: [])

    init() throws {
        store = try makeStore()
    }

    func tracker(permanent: Set<String> = ["breakglass"], on store: AgentStore? = nil) -> ElevationTracker {
        let (logged, reads) = (logged, reads)
        let config = AgentConfiguration(
            permanentAdmins: permanent, userPrincipalNames: ["breakglass": "breakglass@example.com"])
        let env = makeEnvironment(
            admins: admins, clock: clock, config: config,
            permanentUseLog: { since in
                reads.withLock { $0.append(since) }
                return logged.withLock { $0.filter { $0.date >= since } }
            })
        return ElevationTracker(store: store ?? self.store, environment: env)
    }

    func log(
        _ method: PermanentUseMethod, _ account: String = "breakglass", ago: TimeInterval = 5,
        onSessionOf: String? = nil, right: String? = nil, client: String? = nil, tty: String? = nil,
        runAs: String? = nil
    ) {
        let record = PermanentUseLogRecord(
            method: method, account: account, date: clock.now.addingTimeInterval(-ago), onSessionOf: onSessionOf,
            right: right, client: client, tty: tty, runAs: runAs, remoteHost: nil)
        logged.withLock { $0.append(record) }
    }

    func uses(_ t: ElevationTracker) throws -> [AltiwardEvent] {
        try t.heartbeat().filter { $0.type == .adminPermanentUse && $0.detail["source"] == "unified_log" }
    }

    // MARK: Parsing

    static let users: @Sendable (UInt32) -> String? = { $0 == 501 ? "alex" : $0 == 502 ? "breakglass" : nil }

    /// As authd logged it on a real Mac, with the accounts renamed.
    static let prompt =
        "UID 501 authenticated as user breakglass (UID 502) for right 'com.apple.ServiceManagement.daemons.modify'"
    /// sudo's refusal, as logged on a real Mac.
    static let sudoRefused =
        "philchatham : user NOT in sudoers ; TTY=ttys004 ; PWD=/Users/philchatham ; USER=root ; COMMAND=/usr/bin/true"
    /// sudo's standard format for a command it allowed.
    static let sudoAllowed =
        "breakglass : TTY=ttys003 ; PWD=/Users/breakglass/secret-project ; USER=root ; COMMAND=/usr/sbin/installer -pkg /tmp/x.pkg -target /"

    @Test func parsesPromptApproval() throws {
        let date = Date(timeIntervalSince1970: 1_792_000_000)
        let record = try #require(PermanentUseLogRecord.parseAuthd(message: Self.prompt, date: date, userName: Self.users))
        #expect(record.method == .prompt)
        #expect(record.account == "breakglass")
        #expect(record.onSessionOf == "alex")
        #expect(record.right == "com.apple.ServiceManagement.daemons.modify")
        #expect(record.client == nil)
        #expect(record.date == date)
    }

    @Test func promptByAnUnknownUIDHasNoSession() throws {
        let message = "UID 999 authenticated as user breakglass (UID 502) for right 'system.preferences'"
        let record = try #require(PermanentUseLogRecord.parseAuthd(message: message, date: Date(), userName: Self.users))
        #expect(record.onSessionOf == nil)
    }

    @Test func selfApprovalSkipped() {
        let message = "UID 502 authenticated as user breakglass (UID 502) for right 'system.preferences'"
        #expect(PermanentUseLogRecord.parseAuthd(message: message, date: Date(), userName: Self.users) == nil)
    }

    @Test func systemLoginRightsSkipped() {
        for right in ["system.login.console", "system.login.screensaver"] {
            let message = "UID 501 authenticated as user breakglass (UID 502) for right '\(right)'"
            #expect(PermanentUseLogRecord.parseAuthd(message: message, date: Date(), userName: Self.users) == nil)
        }
    }

    @Test func otherAuthdLinesSkipped() {
        for message in [
            "Succeeded authorizing right 'system.preferences' by client '/Applications/Foo.app' [1] for authorization created by '/Applications/Foo.app' [1] (3,0) (engine 97)",
            "UID 501 authenticated as user breakglass for right 'x'", "", "UID x authenticated as user a (UID 2) for right 'r'",
        ] {
            #expect(PermanentUseLogRecord.parseAuthd(message: message, date: Date(), userName: Self.users) == nil)
        }
    }

    @Test func parsesSudoWithoutCommand() throws {
        let record = try #require(PermanentUseLogRecord.parseSudo(message: Self.sudoAllowed, date: Date()))
        #expect(record.method == .sudo)
        #expect(record.account == "breakglass")
        #expect(record.tty == "ttys003")
        #expect(record.runAs == "root")
        let text = String(describing: record)
        #expect(!text.contains("installer") && !text.contains("/tmp/x.pkg"))
        #expect(!text.contains("secret-project") && !text.contains("COMMAND=") && !text.contains("PWD="))
    }

    @Test func sudoRefusalSkipped() {
        #expect(PermanentUseLogRecord.parseSudo(message: Self.sudoRefused, date: Date()) == nil)
        let wrong = "breakglass : 3 incorrect password attempts ; TTY=ttys003 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
        #expect(PermanentUseLogRecord.parseSudo(message: wrong, date: Date()) == nil)
        let refused = "breakglass : command not allowed ; TTY=ttys003 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
        #expect(PermanentUseLogRecord.parseSudo(message: refused, date: Date()) == nil)
        #expect(PermanentUseLogRecord.parseSudo(message: "pam_opendirectory: authenticated", date: Date()) == nil)
    }

    @Test func sudoRunAsStopsAtTheCommand() throws {
        let message = "breakglass : TTY=ttys003 ; PWD=/ ; USER=alex ; COMMAND=/bin/sh -c echo ; USER=root"
        #expect(try #require(PermanentUseLogRecord.parseSudo(message: message, date: Date())).runAs == "alex")
    }

    @Test func parsesSu() throws {
        let record = try #require(PermanentUseLogRecord.parseSu(message: "alex to breakglass on /dev/ttys002", date: Date()))
        #expect(record.method == .su)
        #expect(record.account == "breakglass")
        #expect(record.onSessionOf == "alex")
        #expect(record.tty == "ttys002")
    }

    @Test func failedSuSkipped() {
        #expect(PermanentUseLogRecord.parseSu(message: "BAD SU alex to breakglass on /dev/ttys002", date: Date()) == nil)
        #expect(PermanentUseLogRecord.parseSu(message: "alex to breakglass", date: Date()) == nil)
    }

    // MARK: The prompt's client

    static let authorized =
        "Succeeded authorizing right 'system.preferences' by client '/Applications/Visual Studio Code.app' [2650] for authorization created by '/Applications/Visual Studio Code.app' [2650] (3,0) (engine 97)"
    static let promptForPreferences = "UID 501 authenticated as user breakglass (UID 502) for right 'system.preferences'"

    func prompts(_ lines: [(TimeInterval, String)]) -> [PermanentUseLogRecord] {
        let start = Date(timeIntervalSince1970: 1_792_000_000)
        return PermanentUseLogRecord.prompts(
            from: lines.map { (start.addingTimeInterval($0.0), $0.1) }, userName: Self.users)
    }

    @Test func promptTakesTheClientFromTheNextAuthorizingLine() throws {
        let records = prompts([(0, Self.promptForPreferences), (0.4, Self.authorized)])
        #expect(try #require(records.first).client == "/Applications/Visual Studio Code.app")
        #expect(records.count == 1)
    }

    @Test func promptIgnoresAClientForAnotherRight() throws {
        let other = Self.authorized.replacingOccurrences(of: "system.preferences", with: "system.privilege.admin")
        #expect(try #require(prompts([(0, Self.promptForPreferences), (1, other)]).first).client == nil)
    }

    @Test func promptIgnoresAClientMoreThanFiveSecondsLater() throws {
        #expect(try #require(prompts([(0, Self.promptForPreferences), (5.5, Self.authorized)]).first).client == nil)
        #expect(try #require(prompts([(0, Self.promptForPreferences), (5, Self.authorized)]).first).client != nil)
    }

    @Test func promptIgnoresAClientBeforeIt() throws {
        #expect(try #require(prompts([(-1, Self.authorized), (0, Self.promptForPreferences)]).first).client == nil)
    }

    @Test func promptTakesTheFirstOfSeveralClients() throws {
        let later = Self.authorized.replacingOccurrences(of: "Visual Studio Code", with: "Other")
        let records = prompts([(0, Self.promptForPreferences), (1, Self.authorized), (2, later)])
        #expect(try #require(records.first).client == "/Applications/Visual Studio Code.app")
    }

    @Test func promptWithNoAuthorizingLineHasNoClient() throws {
        #expect(try #require(prompts([(0, Self.promptForPreferences)]).first).client == nil)
    }

    @Test func promptsKeepTheirOrderAndSkipSelfApprovals() {
        let own = "UID 502 authenticated as user breakglass (UID 502) for right 'system.preferences'"
        let records = prompts([(0, Self.promptForPreferences), (1, own), (2, Self.prompt)])
        #expect(records.map(\.right) == ["system.preferences", "com.apple.ServiceManagement.daemons.modify"])
    }

    // MARK: Heartbeat

    @Test func heartbeatSendsSingleForPrompt() throws {
        log(
            .prompt, onSessionOf: "alex", right: "com.apple.ServiceManagement.daemons.modify",
            client: "/Applications/Foo.app")
        let events = try uses(tracker())
        let event = try #require(events.first)
        #expect(events.count == 1)
        #expect(event.detail["state"] == "single")
        #expect(event.detail["method"] == "prompt")
        #expect(event.detail["count"] == 1)
        #expect(event.detail["on_session_of"] == "alex")
        #expect(event.detail["right"] == "com.apple.ServiceManagement.daemons.modify")
        #expect(event.detail["client"] == "/Applications/Foo.app")
        #expect(event.detail["started"] == .date(clock.now.addingTimeInterval(-5)))
        #expect(event.detail["last"] == .date(clock.now.addingTimeInterval(-5)))
        #expect(event.user?.localName == "breakglass")
        #expect(event.user?.upn == "breakglass@example.com")
        #expect(event.sessionID == nil)
        #expect(event.elevation == nil)
        #expect(event.timestamp == clock.now)
        #expect(event.detail["tty"] == nil && event.detail["run_as"] == nil && event.detail["truncated"] == nil)
        if case .string(let id) = event.detail["use_id"] { #expect(!id.isEmpty) } else { Issue.record("no use_id") }
    }

    @Test func promptWithoutAClientSendsNull() throws {
        log(.prompt, onSessionOf: nil, right: "system.preferences")
        let event = try #require(try uses(tracker()).first)
        #expect(event.detail["client"] == .null)
        #expect(event.detail["on_session_of"] == .null)
    }

    @Test func heartbeatSendsSudoAndSu() throws {
        log(.sudo, ago: 6, tty: "ttys003", runAs: "root")
        log(.su, ago: 3, onSessionOf: "alex", tty: "ttys002")
        let events = try uses(tracker())
        #expect(events.count == 2)
        #expect(events[0].detail["method"] == "sudo")
        #expect(events[0].detail["tty"] == "ttys003")
        #expect(events[0].detail["run_as"] == "root")
        #expect(events[0].detail["on_session_of"] == nil && events[0].detail["right"] == nil)
        #expect(events[1].detail["method"] == "su")
        #expect(events[1].detail["tty"] == "ttys002")
        #expect(events[1].detail["on_session_of"] == "alex")
        #expect(events[1].detail["run_as"] == nil)
    }

    @Test func eventsAreQueuedInTheHeartbeat() throws {
        log(.sudo, tty: "ttys003", runAs: "root")
        let sent = try uses(tracker())
        let pending = try store.pending(limit: 50).map(\.event.eventID)
        #expect(pending.contains(sent[0].eventID))
    }

    @Test func nonPermanentAccountSkipped() throws {
        log(.sudo, "jdoe", tty: "ttys003", runAs: "root")
        log(.prompt, "jdoe", onSessionOf: "alex", right: "system.preferences")
        #expect(try uses(tracker()).isEmpty)
    }

    @Test func reportedOnce() throws {
        log(.sudo, tty: "ttys003", runAs: "root")
        let t = tracker()
        #expect(try uses(t).count == 1)
        clock.advance(300)
        #expect(try uses(t).isEmpty)
        clock.advance(300)
        log(.sudo, ago: 1, tty: "ttys003", runAs: "root")
        #expect(try uses(t).count == 1)
    }

    @Test func recordsAfterNowWaitForTheNextHeartbeat() throws {
        log(.sudo, ago: -10, tty: "ttys003", runAs: "root")
        let t = tracker()
        #expect(try uses(t).isEmpty)
        clock.advance(300)
        #expect(try uses(t).count == 1)
    }

    @Test func usesWhileTheAgentWasStoppedAreStillReported() throws {
        let t = tracker()
        #expect(try uses(t).isEmpty)
        clock.advance(7200)
        log(.sudo, ago: 3600, tty: "ttys003", runAs: "root")
        #expect(try uses(t).count == 1)
    }

    @Test func sudoBurstGrouped() throws {
        for i in 0..<300 { log(.sudo, ago: 200 - Double(i) / 2, tty: "ttys003", runAs: "root") }
        let events = try uses(tracker())
        let event = try #require(events.first)
        #expect(events.count == 1)
        #expect(event.detail["count"] == 300)
        #expect(event.detail["started"] == .date(clock.now.addingTimeInterval(-200)))
        #expect(event.detail["last"] == .date(clock.now.addingTimeInterval(-200 + 299.0 / 2)))
        #expect(event.detail["truncated"] == nil)
    }

    @Test func groupsSplitByTtyAndTarget() throws {
        log(.sudo, ago: 9, tty: "ttys003", runAs: "root")
        log(.sudo, ago: 8, tty: "ttys004", runAs: "root")
        log(.sudo, ago: 7, tty: "ttys003", runAs: "alex")
        log(.sudo, ago: 6, tty: "ttys003", runAs: "root")
        let events = try uses(tracker())
        #expect(events.count == 3)
        #expect(events[0].detail["count"] == 2)
        #expect(events[1].detail["count"] == 1 && events[2].detail["count"] == 1)
    }

    @Test func eachEventHasItsOwnUseID() throws {
        log(.sudo, ago: 9, tty: "ttys003", runAs: "root")
        log(.sudo, ago: 8, tty: "ttys004", runAs: "root")
        let ids = try uses(tracker()).map { $0.detail["use_id"] }
        #expect(ids.count == 2 && ids[0] != ids[1])
    }

    @Test func cappedAtTwentyWithTruncated() throws {
        for i in 0..<27 { log(.sudo, ago: 100 - Double(i), tty: "ttys\(100 + i)", runAs: "root") }
        let events = try uses(tracker())
        #expect(events.count == 20)
        #expect(events.dropLast().allSatisfy { $0.detail["truncated"] == nil })
        #expect(events.last?.detail["truncated"] == 7)
    }

    @Test func exactlyTwentyGroupsAreNotTruncated() throws {
        for i in 0..<20 { log(.sudo, ago: 100 - Double(i), tty: "ttys\(100 + i)", runAs: "root") }
        let events = try uses(tracker())
        #expect(events.count == 20)
        #expect(events.last?.detail["truncated"] == nil)
    }

    @Test func logIsReadFromTheCursorOnward() throws {
        let t = tracker()
        _ = try t.heartbeat()
        let first = clock.now
        clock.advance(300)
        _ = try t.heartbeat()
        let reads = reads.withLock { $0 }
        #expect(reads.count == 2)
        #expect(reads[1] <= first)
        #expect(reads[1] >= clock.now.addingTimeInterval(-86_400))
    }

    @Test func noLogReadWithoutPermanentAdmins() throws {
        log(.sudo, tty: "ttys003", runAs: "root")
        let t = tracker(permanent: [])
        #expect(try uses(t).isEmpty)
        #expect(reads.withLock { $0.isEmpty })
    }

    @Test func logIsReadOutsideTheHeartbeatTransaction() throws {
        // A reader that holds the store's transaction while it waits for the log would make
        // hook calls wait too. Something racing the read finishes only if the read isn't in one.
        let group = DispatchGroup()
        let store = self.store
        let env = makeEnvironment(
            admins: admins, clock: clock, config: AgentConfiguration(permanentAdmins: ["breakglass"]),
            permanentUseLog: { _ in
                race(in: group) { try? store.setValue("raced", forKey: "probe") }
                return []
            })
        _ = try ElevationTracker(store: store, environment: env).heartbeat()
        group.wait()
        #expect(try store.value(forKey: "probe") == "raced")
    }

    @Test func cursorMovesWithTheEnqueue() throws {
        log(.sudo, tty: "ttys003", runAs: "root")
        let t = tracker()
        _ = try t.heartbeat()
        let cursor = try store.value(forKey: "permanent_use_log_reported_until").flatMap(AltiwardJSON.parse)
        #expect(cursor == clock.now)
        #expect(try store.pending(limit: 50).contains { $0.event.type == .adminPermanentUse })
    }
}
