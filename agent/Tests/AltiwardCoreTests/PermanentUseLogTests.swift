import Foundation
import Testing
import os

@testable import AltiwardCore

/// admin.permanent_use from the unified log: prompts typed with a permanent admin's password,
/// and screen sharing sign-ins by the account. macOS keeps no log line for sudo or su.
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

    func tracker(
        permanent: Set<String> = ["breakglass"], on store: AgentStore? = nil,
        fullName: @escaping @Sendable (String) -> String? = { _ in nil },
        accountExists: @escaping @Sendable (String) -> Bool = { _ in false }
    ) -> ElevationTracker {
        let (logged, reads) = (logged, reads)
        let config = AgentConfiguration(
            permanentAdmins: permanent, userPrincipalNames: ["breakglass": "breakglass@example.com"])
        let env = makeEnvironment(
            admins: admins, clock: clock, config: config,
            permanentUseLog: { since in
                reads.withLock { $0.append(since) }
                return logged.withLock { $0.filter { $0.date >= since } }
            }, fullName: fullName, accountExists: accountExists)
        return ElevationTracker(store: store ?? self.store, environment: env)
    }

    func log(
        _ method: PermanentUseMethod, _ account: String = "breakglass", ago: TimeInterval = 5,
        onSessionOf: String? = nil, right: String? = nil, client: String? = nil, remoteHost: String? = nil
    ) {
        let record = PermanentUseLogRecord(
            method: method, account: account, date: clock.now.addingTimeInterval(-ago), onSessionOf: onSessionOf,
            right: right, client: client, remoteHost: remoteHost)
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
    /// screensharingd's lines at Default level, as logged on a real Mac (macOS 27.0.1).
    static let sharingSucceeded =
        "Authentication: SUCCEEDED :: User Name: breakglass :: Viewer Address: fe80::67:3da0:bab9:1a8e :: Type: DH"
    static let sharingFailed =
        "Authentication: FAILED :: User Name: breakglass :: Viewer Address: fe80::67:3da0:bab9:1a8e :: Type: DH"

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

    @Test func parsesScreenSharingSucceeded() throws {
        let date = Date(timeIntervalSince1970: 1_792_000_000)
        let record = try #require(PermanentUseLogRecord.parseScreenSharing(message: Self.sharingSucceeded, date: date))
        #expect(record.method == .screenSharing)
        #expect(record.account == "breakglass")
        #expect(record.remoteHost == "fe80::67:3da0:bab9:1a8e")
        #expect(record.date == date)
        #expect(record.onSessionOf == nil && record.right == nil && record.client == nil)
    }

    @Test func screenSharingFailedIsNotAUse() {
        #expect(PermanentUseLogRecord.parseScreenSharing(message: Self.sharingFailed, date: Date()) == nil)
        for message in [
            "", "Authentication: SUCCEEDED", "SSDaemon_LoginwindowLogoutNotification called pid 412 logout 502",
            "Authentication: SUCCEEDED :: User Name:  :: Viewer Address: 10.0.0.5 :: Type: DH",
        ] {
            #expect(PermanentUseLogRecord.parseScreenSharing(message: message, date: Date()) == nil, "\(message)")
        }
    }

    @Test func screenSharingPrivateAddressIsNil() throws {
        for address in ["<private>", "", "  "] {
            let message =
                "Authentication: SUCCEEDED :: User Name: breakglass :: Viewer Address: \(address) :: Type: DH"
            let record = try #require(PermanentUseLogRecord.parseScreenSharing(message: message, date: Date()))
            #expect(record.account == "breakglass" && record.remoteHost == nil, "\(address)")
        }
    }

    @Test func screenSharingWithoutAddressIsStillAUse() throws {
        for tail in [" :: Viewer Address: ", " :: Viewer Address:", " :: Viewer Address: :: Type: DH"] {
            let message = "Authentication: SUCCEEDED :: User Name: breakglass" + tail
            let record = try #require(PermanentUseLogRecord.parseScreenSharing(message: message, date: Date()), "\(tail)")
            #expect(record.account == "breakglass" && record.remoteHost == nil, "\(tail)")
        }
    }

    @Test func screenSharingNameCannotSmuggleFields() throws {
        let message =
            "Authentication: SUCCEEDED :: User Name: breakglass :: Viewer Address: 1.2.3.4 :: Type: x :: Viewer Address: fe80::1 :: Type: DH"
        let record = try #require(PermanentUseLogRecord.parseScreenSharing(message: message, date: Date()))
        #expect(record.remoteHost == "fe80::1")
        #expect(record.account != "breakglass")
    }

    @Test func screenSharingKeepsATypedFullNameAndTrims() throws {
        let message =
            "Authentication: SUCCEEDED :: User Name:  Break Glass  :: Viewer Address:  10.0.0.5  :: Type: DH"
        let record = try #require(PermanentUseLogRecord.parseScreenSharing(message: message, date: Date()))
        #expect(record.account == "Break Glass" && record.remoteHost == "10.0.0.5")
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
        #expect(event.detail["remote_host"] == nil)
        if case .string(let id) = event.detail["use_id"] { #expect(!id.isEmpty) } else { Issue.record("no use_id") }
    }

    @Test func promptWithoutAClientSendsNull() throws {
        log(.prompt, onSessionOf: nil, right: "system.preferences")
        let event = try #require(try uses(tracker()).first)
        #expect(event.detail["client"] == .null)
        #expect(event.detail["on_session_of"] == .null)
    }

    @Test func heartbeatSendsSingleForScreenSharing() throws {
        log(.screenSharing, remoteHost: "fe80::67:3da0:bab9:1a8e")
        let events = try uses(tracker())
        let event = try #require(events.first)
        #expect(events.count == 1)
        #expect(event.detail["method"] == "screen_sharing")
        #expect(event.detail["source"] == "unified_log")
        #expect(event.detail["state"] == "single")
        #expect(event.detail["remote_host"] == "fe80::67:3da0:bab9:1a8e")
        #expect(event.detail["count"] == 1)
        #expect(event.detail["started"] == .date(clock.now.addingTimeInterval(-5)))
        #expect(event.detail["last"] == .date(clock.now.addingTimeInterval(-5)))
        #expect(event.detail["on_session_of"] == nil && event.detail["right"] == nil && event.detail["ended"] == nil)
        #expect(event.user?.localName == "breakglass")
        if case .string(let id) = event.detail["use_id"] { #expect(!id.isEmpty) } else { Issue.record("no use_id") }
    }

    @Test func screenSharingWithoutAnAddressSendsNull() throws {
        log(.screenSharing)
        #expect(try #require(try uses(tracker()).first).detail["remote_host"] == .null)
    }

    @Test func screenSharingFullNameMatchesPermanentAdmin() throws {
        log(.screenSharing, "Break Glass", ago: 9, remoteHost: "10.0.0.5")
        log(.screenSharing, "BREAKGLASS", ago: 8, remoteHost: "10.0.0.5")
        log(.screenSharing, "break glass", ago: 7, remoteHost: "10.0.0.5")
        let t = tracker(fullName: { $0 == "breakglass" ? "Break Glass" : nil })
        let events = try uses(t)
        // All three are the same account from the same address: one group, under the short name.
        #expect(events.count == 1)
        #expect(events[0].detail["count"] == 3)
        #expect(events[0].user?.localName == "breakglass")
        #expect(events[0].user?.upn == "breakglass@example.com")
    }

    @Test func screenSharingOtherAccountSkipped() throws {
        log(.screenSharing, "Jane Doe", remoteHost: "10.0.0.5")
        log(.screenSharing, "jdoe", remoteHost: "10.0.0.5")
        // A full name is matched only for a permanent admin, and a short name only as typed.
        log(.screenSharing, "Break Glass", remoteHost: "10.0.0.5")
        let t = tracker(fullName: { $0 == "jdoe" ? "Jane Doe" : $0 == "breakglass" ? "Break Glass II" : nil })
        #expect(try uses(t).isEmpty)
    }

    @Test func screenSharingOtherAccountsShortNameNotMatchedByFullName() throws {
        // A non-admin account `admin` signs in; the permanent admin's full name is "Admin".
        log(.screenSharing, "admin", remoteHost: "10.0.0.5")
        let fullName: @Sendable (String) -> String? = { $0 == "breakglass" ? "Admin" : nil }
        #expect(try uses(tracker(fullName: fullName, accountExists: { $0 == "admin" })).isEmpty)
    }

    @Test func screenSharingFullNameIsNotMatchedWithoutALookup() throws {
        log(.screenSharing, "Break Glass", remoteHost: "10.0.0.5")
        #expect(try uses(tracker()).isEmpty)
    }

    @Test func eventsAreQueuedInTheHeartbeat() throws {
        log(.prompt, right: "system.preferences")
        let sent = try uses(tracker())
        let pending = try store.pending(limit: 50).map(\.event.eventID)
        #expect(pending.contains(sent[0].eventID))
    }

    @Test func nonPermanentAccountSkipped() throws {
        log(.prompt, "jdoe", onSessionOf: "alex", right: "system.preferences")
        log(.screenSharing, "jdoe", remoteHost: "10.0.0.5")
        #expect(try uses(tracker()).isEmpty)
    }

    @Test func reportedOnce() throws {
        log(.prompt, right: "system.preferences")
        let t = tracker()
        #expect(try uses(t).count == 1)
        clock.advance(300)
        #expect(try uses(t).isEmpty)
        clock.advance(300)
        log(.prompt, ago: 1, right: "system.preferences")
        #expect(try uses(t).count == 1)
    }

    @Test func recordsAfterNowWaitForTheNextHeartbeat() throws {
        log(.prompt, ago: -10, right: "system.preferences")
        let t = tracker()
        #expect(try uses(t).isEmpty)
        clock.advance(300)
        #expect(try uses(t).count == 1)
    }

    @Test func usesWhileTheAgentWasStoppedAreStillReported() throws {
        let t = tracker()
        #expect(try uses(t).isEmpty)
        clock.advance(7200)
        log(.prompt, ago: 3600, right: "system.preferences")
        #expect(try uses(t).count == 1)
    }

    @Test func promptBurstGrouped() throws {
        for i in 0..<300 { log(.prompt, ago: 200 - Double(i) / 2, onSessionOf: "alex", right: "system.preferences") }
        let events = try uses(tracker())
        let event = try #require(events.first)
        #expect(events.count == 1)
        #expect(event.detail["count"] == 300)
        #expect(event.detail["started"] == .date(clock.now.addingTimeInterval(-200)))
        #expect(event.detail["last"] == .date(clock.now.addingTimeInterval(-200 + 299.0 / 2)))
        #expect(event.detail["truncated"] == nil)
    }

    @Test func groupsSplitByRightAndSession() throws {
        log(.prompt, ago: 9, onSessionOf: "alex", right: "system.preferences")
        log(.prompt, ago: 8, onSessionOf: "alex", right: "system.install.software")
        log(.prompt, ago: 7, onSessionOf: "jdoe", right: "system.preferences")
        log(.prompt, ago: 6, onSessionOf: "alex", right: "system.preferences")
        let events = try uses(tracker())
        #expect(events.count == 3)
        #expect(events[0].detail["count"] == 2)
        #expect(events[1].detail["count"] == 1 && events[2].detail["count"] == 1)
    }

    @Test func screenSharingGroupsSplitByAddress() throws {
        log(.screenSharing, ago: 9, remoteHost: "10.0.0.5")
        log(.screenSharing, ago: 8, remoteHost: "10.0.0.6")
        log(.screenSharing, ago: 7, remoteHost: "10.0.0.5")
        let events = try uses(tracker())
        #expect(events.count == 2)
        #expect(events[0].detail["count"] == 2 && events[1].detail["count"] == 1)
    }

    @Test func eachEventHasItsOwnUseID() throws {
        log(.prompt, ago: 9, right: "system.preferences")
        log(.prompt, ago: 8, right: "system.install.software")
        let ids = try uses(tracker()).map { $0.detail["use_id"] }
        #expect(ids.count == 2 && ids[0] != ids[1])
    }

    @Test func cappedAtTwentyWithTruncated() throws {
        for i in 0..<27 { log(.prompt, ago: 100 - Double(i), right: "system.right.\(i)") }
        let events = try uses(tracker())
        #expect(events.count == 20)
        #expect(events.dropLast().allSatisfy { $0.detail["truncated"] == nil })
        #expect(events.last?.detail["truncated"] == 7)
    }

    @Test func exactlyTwentyGroupsAreNotTruncated() throws {
        for i in 0..<20 { log(.prompt, ago: 100 - Double(i), right: "system.right.\(i)") }
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
        log(.prompt, right: "system.preferences")
        let t = tracker(permanent: [])
        #expect(try uses(t).isEmpty)
        #expect(reads.withLock { $0.isEmpty })
    }

    @Test func logIsReadOutsideTheHeartbeatTransaction() throws {
        // A reader that holds the store's transaction while it waits for the log would make
        // hook calls wait too. Something racing the read finishes only if the read isn't in
        // one, so the flag is checked inside the read, while the heartbeat can't have committed.
        let group = DispatchGroup()
        let store = self.store
        let racerDone = OSAllocatedUnfairLock(initialState: false)
        let doneBeforeReadReturned = OSAllocatedUnfairLock(initialState: false)
        let env = makeEnvironment(
            admins: admins, clock: clock, config: AgentConfiguration(permanentAdmins: ["breakglass"]),
            permanentUseLog: { _ in
                race(in: group) {
                    try? store.setValue("raced", forKey: "probe")
                    racerDone.withLock { $0 = true }
                }
                // race(in:) has waited for the racer: in a transaction it is still blocked.
                doneBeforeReadReturned.withLock { $0 = racerDone.withLock { $0 } }
                return []
            })
        _ = try ElevationTracker(store: store, environment: env).heartbeat()
        group.wait()
        #expect(doneBeforeReadReturned.withLock { $0 })
        #expect(try store.value(forKey: "probe") == "raced")
    }

    @Test func cursorMovesWithTheEnqueue() throws {
        log(.prompt, right: "system.preferences")
        let t = tracker()
        _ = try t.heartbeat()
        let cursor = try store.value(forKey: "permanent_use_log_reported_until").flatMap(AltiwardJSON.parse)
        #expect(cursor == clock.now)
        #expect(try store.pending(limit: 50).contains { $0.event.type == .adminPermanentUse })
    }
}
