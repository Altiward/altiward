import Foundation
import Testing
import os

@testable import AltiwardCore

/// admin.permanent_use from utmpx and wtmp: sign-ins by accounts in PermanentAdmins, at the
/// Mac, in Terminal and over SSH, and their sign-outs.
struct PermanentUseTests {
    let clock = TestClock()
    let store: AgentStore
    let admins = FakeAdmins(["breakglass"])
    /// What utmpx holds now: the sign-ins still open.
    let utmpx = OSAllocatedUnfairLock<[LoginRecord]>(initialState: [])
    /// What wtmp holds, oldest first. The fake history pairs it as the live one does.
    let wtmp = OSAllocatedUnfairLock<[UtmpxEntry]>(initialState: [])

    /// Process ids that no longer exist, as the liveness stub sees them.
    let goneProcesses = OSAllocatedUnfairLock<Set<Int32>>(initialState: [])

    init() throws {
        store = try makeStore()
    }

    func tracker(permanent: Set<String> = ["breakglass"], on store: AgentStore? = nil) -> ElevationTracker {
        let (utmpx, wtmp, gone) = (utmpx, wtmp, goneProcesses)
        let config = AgentConfiguration(
            permanentAdmins: permanent, userPrincipalNames: ["breakglass": "breakglass@example.com"])
        let env = makeEnvironment(
            admins: admins, clock: clock, config: config,
            logins: { utmpx.withLock { $0 } },
            processExists: { pid in !gone.withLock { $0.contains(pid) } },
            loginHistory: { since in
                LoginRecords.paired(wtmp.withLock { $0 }).filter { ($0.ended ?? .distantFuture) >= since }
            })
        return ElevationTracker(store: store ?? self.store, environment: env)
    }

    /// Signs `user` in `ago` seconds before now: utmpx gets the entry and wtmp the login.
    @discardableResult
    func signIn(
        _ user: String = "breakglass", tty: String = "console", host: String = "", pid: Int32 = 501,
        ago: TimeInterval = 60
    ) -> LoginRecord {
        let started = clock.now.addingTimeInterval(-ago)
        let record = LoginRecord(user: user, tty: tty, host: host, pid: pid, started: started, ended: nil)
        utmpx.withLock { $0.append(record) }
        wtmp.withLock { $0.append(UtmpxEntry(kind: .login, user: user, tty: tty, host: host, pid: pid, time: started)) }
        return record
    }

    /// Signs the record out `ago` seconds before now, and returns when.
    @discardableResult
    func signOut(_ record: LoginRecord, ago: TimeInterval = 0) -> Date {
        let ended = clock.now.addingTimeInterval(-ago)
        utmpx.withLock { $0.removeAll { $0 == record } }
        wtmp.withLock {
            $0.append(UtmpxEntry(kind: .logout, user: "", tty: record.tty, host: "", pid: record.pid, time: ended))
        }
        return ended
    }

    /// The record leaves utmpx with nothing written to wtmp.
    func vanish(_ record: LoginRecord) {
        utmpx.withLock { $0.removeAll { $0 == record } }
    }

    /// The record's process ends, but utmpx still lists it and wtmp has no logout.
    func processGoes(_ record: LoginRecord) {
        goneProcesses.withLock { _ = $0.insert(record.pid) }
    }

    func expectUse(
        _ event: AltiwardEvent, state: String, method: String, started: Date, user: String = "breakglass",
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        #expect(event.type == .adminPermanentUse, sourceLocation: sourceLocation)
        #expect(event.detail["state"] == .string(state), sourceLocation: sourceLocation)
        #expect(event.detail["method"] == .string(method), sourceLocation: sourceLocation)
        #expect(event.detail["source"] == "utmpx", sourceLocation: sourceLocation)
        #expect(event.detail["started"] == .date(started), sourceLocation: sourceLocation)
        #expect(event.user?.localName == user, sourceLocation: sourceLocation)
        #expect(event.sessionID == nil, sourceLocation: sourceLocation)
        #expect(event.elevation == nil, sourceLocation: sourceLocation)
        if case .string(let id) = event.detail["use_id"] {
            #expect(!id.isEmpty, sourceLocation: sourceLocation)
        } else {
            Issue.record("no use_id", sourceLocation: sourceLocation)
        }
    }

    // MARK: Sign-ins

    @Test func consoleSignInSendsStarted() throws {
        let record = signIn(ago: 60)
        let events = try tracker().checkPermanentUses()
        try #require(events.count == 1)
        expectUse(events[0], state: "started", method: "console", started: record.started)
        #expect(events[0].detail["tty"] == "console")
        #expect(events[0].detail["ended"] == nil && events[0].detail["end_basis"] == nil)
        #expect(events[0].detail["remote_host"] == nil)
        #expect(events[0].user?.upn == "breakglass@example.com")
        #expect(events[0].timestamp == clock.now)
        #expect(try store.pending(limit: 10).map(\.event) == events)
        #expect(try store.openPermanentUses().count == 1)
    }

    @Test func secondCheckSendsNothing() throws {
        signIn()
        let t = tracker()
        #expect(try t.checkPermanentUses().count == 1)
        clock.advance(15)
        #expect(try t.checkPermanentUses().isEmpty)
        #expect(try store.pendingCount() == 1)
    }

    @Test func signOutSendsEndedWithBothTimes() throws {
        let record = signIn(ago: 60)
        let t = tracker()
        let started = try t.checkPermanentUses()
        clock.advance(600)
        let ended = signOut(record, ago: 10)

        let events = try t.checkPermanentUses()
        try #require(events.count == 1)
        expectUse(events[0], state: "ended", method: "console", started: record.started)
        #expect(events[0].detail["use_id"] == started.first?.detail["use_id"])
        #expect(events[0].detail["ended"] == .date(ended))
        #expect(events[0].detail["end_basis"] == "logged")
        #expect(events[0].detail["tty"] == "console")
        #expect(try store.openPermanentUses().isEmpty)
        #expect(try store.pendingCount() == 2)
        #expect(try t.checkPermanentUses().isEmpty)
    }

    @Test func signOutWithoutRecordIsNoticed() throws {
        let record = signIn(ago: 60)
        let t = tracker()
        _ = try t.checkPermanentUses()
        clock.advance(600)
        vanish(record)

        let events = try t.checkPermanentUses()
        try #require(events.count == 1)
        expectUse(events[0], state: "ended", method: "console", started: record.started)
        #expect(events[0].detail["ended"] == .date(clock.now))
        #expect(events[0].detail["end_basis"] == "noticed")
    }

    @Test func staleSignInWithDeadProcessIsEnded() throws {
        let record = signIn(pid: 2110, ago: 60)
        let t = tracker()
        let started = try t.checkPermanentUses()
        try #require(started.count == 1)
        clock.advance(600)
        processGoes(record)

        let events = try t.checkPermanentUses()
        try #require(events.count == 1)
        expectUse(events[0], state: "ended", method: "console", started: record.started)
        #expect(events[0].detail["use_id"] == started[0].detail["use_id"])
        #expect(events[0].detail["ended"] == .date(clock.now))
        #expect(events[0].detail["end_basis"] == "noticed")
        #expect(try store.openPermanentUses().isEmpty)
        #expect(try t.checkPermanentUses().isEmpty)
    }

    @Test func staleSignInIsNeverStarted() throws {
        let record = signIn(pid: 2110, ago: 3600)
        processGoes(record)
        #expect(try tracker().checkPermanentUses().isEmpty)
        #expect(try store.pendingCount() == 0)
        #expect(try store.openPermanentUses().isEmpty)
    }

    @Test func liveSignInUnaffected() throws {
        let record = signIn(pid: 2110, ago: 60)
        let t = tracker()
        let events = try t.checkPermanentUses()
        try #require(events.count == 1)
        expectUse(events[0], state: "started", method: "console", started: record.started)
        clock.advance(600)
        #expect(try t.checkPermanentUses().isEmpty)
        #expect(try store.openPermanentUses().count == 1)
    }

    @Test func otherAccountsIgnored() throws {
        let record = signIn("jdoe", tty: "ttys002", pid: 700)
        let t = tracker()
        #expect(try t.checkPermanentUses().isEmpty)
        signOut(record)
        #expect(try t.checkPermanentUses().isEmpty)
        #expect(try t.catchUpPermanentUses().isEmpty)
        #expect(try store.pendingCount() == 0)
    }

    @Test func sshAndTerminalClassified() throws {
        let ssh = signIn(tty: "ttys003", host: "10.0.0.5", pid: 900, ago: 30)
        let terminal = signIn(tty: "ttys004", pid: 901, ago: 20)
        #expect(PermanentUseMethod.of(ssh) == .ssh)
        #expect(PermanentUseMethod.of(terminal) == .terminal)

        let events = try tracker().checkPermanentUses()
        try #require(events.count == 2)
        let bySSH = try #require(events.first { $0.detail["method"] == "ssh" })
        let byTerminal = try #require(events.first { $0.detail["method"] == "terminal" })
        expectUse(bySSH, state: "started", method: "ssh", started: ssh.started)
        #expect(bySSH.detail["tty"] == "ttys003")
        #expect(bySSH.detail["remote_host"] == "10.0.0.5")
        expectUse(byTerminal, state: "started", method: "terminal", started: terminal.started)
        #expect(byTerminal.detail["tty"] == "ttys004")
        #expect(byTerminal.detail["remote_host"] == nil)
        #expect(bySSH.detail["use_id"] != byTerminal.detail["use_id"])

        clock.advance(300)
        signOut(ssh)
        let ended = try tracker().checkPermanentUses()
        try #require(ended.count == 1)
        expectUse(ended[0], state: "ended", method: "ssh", started: ssh.started)
        #expect(ended[0].detail["remote_host"] == "10.0.0.5")
    }

    // MARK: Terminal tabs

    /// Each Terminal tab of an account signed in at the Mac gets its own utmpx entry (a tty
    /// with no host). It is part of the console sign-in, which already covers the time.
    @Test func terminalTabsInsideConsoleUseNotRecorded() throws {
        let console = signIn(pid: 501, ago: 600)
        let t = tracker()
        let started = try t.checkPermanentUses()
        try #require(started.count == 1)
        expectUse(started[0], state: "started", method: "console", started: console.started)

        let tabs = (0..<3).map { i in signIn(tty: "ttys00\(i + 1)", pid: 800 + Int32(i), ago: 300 - Double(i) * 60) }
        clock.advance(15)
        #expect(try t.checkPermanentUses().isEmpty)
        clock.advance(120)
        signOut(tabs[0])
        #expect(try t.checkPermanentUses().isEmpty)
        clock.advance(300)
        #expect(try t.heartbeat().filter { $0.type == .adminPermanentUse }.isEmpty)

        // Signing out of the Mac closes the other tabs, whose records can follow a moment
        // later: only the console sign-in ends.
        clock.advance(300)
        let ended = signOut(console)
        clock.advance(1)
        for tab in tabs.dropFirst() { signOut(tab) }
        var events = try t.checkPermanentUses()
        clock.advance(300)
        events += try t.heartbeat().filter { $0.type == .adminPermanentUse }
        try #require(events.count == 1)
        expectUse(events[0], state: "ended", method: "console", started: console.started)
        #expect(events[0].detail["ended"] == .date(ended))
        #expect(try store.pending(limit: 100).filter { $0.event.detail["method"] == "terminal" }.isEmpty)
    }

    /// `login breakglass` in someone else's Terminal, with no console sign-in of its own, is a use.
    @Test func terminalLoginWithoutConsoleUseRecorded() throws {
        // The account signed in at the Mac earlier, and signed out before.
        let earlier = signIn(pid: 500, ago: 7200)
        let t = tracker()
        #expect(try t.checkPermanentUses().count == 1)
        signOut(earlier, ago: 3600)
        #expect(try t.checkPermanentUses().count == 1)

        signIn("jdoe", pid: 502, ago: 1800)
        let login = signIn(tty: "ttys004", pid: 810, ago: 60)
        let events = try t.checkPermanentUses()
        try #require(events.count == 1)
        expectUse(events[0], state: "started", method: "terminal", started: login.started)
        #expect(events[0].detail["tty"] == "ttys004")

        clock.advance(120)
        signOut(login)
        let ended = try t.checkPermanentUses()
        try #require(ended.count == 1)
        expectUse(ended[0], state: "ended", method: "terminal", started: login.started)
    }

    /// The catch-up and the heartbeat's history scan skip tabs inside a console sign-in too.
    @Test func historyTerminalInsideConsoleUseSkipped() throws {
        // While the agent was stopped: a console sign-in with two tabs, all ended.
        let console = signIn(pid: 501, ago: 7200)
        let tab = signIn(tty: "ttys001", pid: 820, ago: 6000)
        let tab2 = signIn(tty: "ttys002", pid: 821, ago: 5000)
        signOut(tab, ago: 4000)
        let ended = signOut(console, ago: 3600)
        signOut(tab2, ago: 3599)  // closed by the sign-out, a moment after it

        let t = tracker()
        let caught = try t.catchUpPermanentUses()
        try #require(caught.count == 1)
        expectUse(caught[0], state: "ended", method: "console", started: console.started)
        #expect(caught[0].detail["ended"] == .date(ended))

        // While it runs: the account signs in at the Mac, and a tab opens and closes
        // between two checks.
        _ = try t.heartbeat()
        let again = signIn(pid: 530, ago: 0)
        #expect(try t.checkPermanentUses().count == 1)
        clock.advance(300)
        let shortStarted = clock.now.addingTimeInterval(-20)
        wtmp.withLock {
            $0.append(UtmpxEntry(kind: .login, user: "breakglass", tty: "ttys003", host: "", pid: 830, time: shortStarted))
            $0.append(UtmpxEntry(kind: .logout, user: "", tty: "", host: "", pid: 830, time: shortStarted.addingTimeInterval(8)))
        }
        #expect(try t.checkPermanentUses().isEmpty)
        #expect(try t.heartbeat().filter { $0.type == .adminPermanentUse }.isEmpty)
        #expect(try tracker().catchUpPermanentUses().isEmpty)
        #expect(try store.openPermanentUses().map(\.startedAt) == [again.started])
    }

    /// A console sign-in macOS still lists after its process has gone doesn't hide a short
    /// Terminal sign-in from the heartbeat's history scan.
    @Test func historyTerminalDuringStaleConsoleIsRecorded() throws {
        let console = signIn(pid: 501, ago: 3600)
        processGoes(console)
        let t = tracker()
        #expect(try t.checkPermanentUses().isEmpty)
        _ = try t.heartbeat()

        clock.advance(300)
        let started = clock.now.addingTimeInterval(-20)
        let ended = started.addingTimeInterval(8)
        wtmp.withLock {
            $0.append(UtmpxEntry(kind: .login, user: "breakglass", tty: "ttys005", host: "", pid: 840, time: started))
            $0.append(UtmpxEntry(kind: .logout, user: "", tty: "", host: "", pid: 840, time: ended))
        }
        #expect(try t.checkPermanentUses().isEmpty)

        let events = try t.heartbeat().filter { $0.type == .adminPermanentUse }
        try #require(events.count == 1)
        expectUse(events[0], state: "ended", method: "terminal", started: started)
        #expect(events[0].detail["ended"] == .date(ended))
        #expect(events[0].detail["end_basis"] == "logged")
    }

    // MARK: Restarts and the catch-up

    @Test func restartDoesNotRepeatStarted() throws {
        signIn()
        #expect(try tracker().checkPermanentUses().count == 1)
        // A new tracker on the same store, as after the daemon restarts.
        let restarted = tracker()
        #expect(try restarted.catchUpPermanentUses().isEmpty)
        #expect(try restarted.checkPermanentUses().isEmpty)
        #expect(try store.pendingCount() == 1)
    }

    @Test func catchUpReportsUseWhileStopped() throws {
        let record = signIn(tty: "ttys005", host: "10.0.0.7", pid: 950, ago: 3600)
        let ended = signOut(record, ago: 1800)

        let t = tracker()
        let events = try t.catchUpPermanentUses()
        try #require(events.count == 1)
        expectUse(events[0], state: "ended", method: "ssh", started: record.started)
        #expect(events[0].detail["ended"] == .date(ended))
        #expect(events[0].detail["end_basis"] == "logged")
        #expect(events[0].detail["tty"] == "ttys005")
        #expect(events[0].detail["remote_host"] == "10.0.0.7")
        #expect(try store.pending(limit: 10).map(\.event) == events)

        #expect(try t.catchUpPermanentUses().isEmpty)
        #expect(try tracker().catchUpPermanentUses().isEmpty)
        #expect(try t.checkPermanentUses().isEmpty)
    }

    /// With no cursor, the catch-up reads back a day; with one, from the last heartbeat.
    @Test func catchUpReadsFromTheLastHeartbeat() throws {
        let old = signIn(tty: "ttys001", pid: 300, ago: 2 * 86_400)
        signOut(old, ago: 86_400 + 60)
        let recent = signIn(tty: "ttys002", pid: 301, ago: 7200)
        signOut(recent, ago: 3600)
        let events = try tracker().catchUpPermanentUses()
        #expect(events.map(\.detail["tty"]) == ["ttys002"])

        // A heartbeat moves the cursor: a use that ended before it isn't read again, even
        // after its row is gone.
        let store2 = try makeStore()
        let t = tracker(on: store2)
        _ = try t.heartbeat()
        clock.advance(600)
        let afterHeartbeat = signIn(tty: "ttys003", pid: 302, ago: 300)
        signOut(afterHeartbeat, ago: 100)
        let caught = try tracker(on: store2).catchUpPermanentUses()
        #expect(caught.map(\.detail["tty"]) == ["ttys003"])
    }

    @Test func catchUpSkipsTrackedUses() throws {
        // Tracked and ended while the daemon ran.
        let first = signIn(tty: "ttys001", pid: 400, ago: 600)
        let t = tracker()
        #expect(try t.checkPermanentUses().count == 1)
        signOut(first, ago: 300)
        #expect(try t.checkPermanentUses().count == 1)

        // Tracked while the daemon ran, signed out while it was stopped.
        let second = signIn(tty: "ttys002", pid: 401, ago: 200)
        #expect(try t.checkPermanentUses().count == 1)
        signOut(second, ago: 100)

        let restarted = tracker()
        #expect(try restarted.catchUpPermanentUses().isEmpty)
        let ended = try restarted.checkPermanentUses()
        try #require(ended.count == 1)
        expectUse(ended[0], state: "ended", method: "terminal", started: second.started)
        #expect(ended[0].detail["end_basis"] == "logged")
        #expect(try store.pendingCount() == 4)
    }

    @Test func useOutlivesRemovalFromPermanentAdmins() throws {
        let record = signIn(ago: 60)
        #expect(try tracker().checkPermanentUses().count == 1)
        // PermanentAdmins changes restart the daemon: the new one no longer lists the account.
        clock.advance(600)
        let ended = signOut(record)
        let events = try tracker(permanent: []).checkPermanentUses()
        try #require(events.count == 1)
        expectUse(events[0], state: "ended", method: "console", started: record.started)
        #expect(events[0].detail["ended"] == .date(ended))
    }

    /// Review focus 1: the Mac restarts while the account is signed in. The sign-in ends at
    /// wtmp's shutdown record, not when the agent next looks after the boot.
    @Test func restartDuringSignInUsesShutdownTime() throws {
        let record = signIn(ago: 3600)
        #expect(try tracker().checkPermanentUses().count == 1)

        let shutdown = clock.now.addingTimeInterval(-1800)
        wtmp.withLock {
            $0.append(UtmpxEntry(kind: .shutdown, user: "", tty: "~", host: "", pid: 0, time: shutdown))
            $0.append(
                UtmpxEntry(kind: .boot, user: "", tty: "~", host: "", pid: 0, time: shutdown.addingTimeInterval(90)))
        }
        // utmpx starts empty after a boot.
        vanish(record)

        // As the daemon's run(): the catch-up first, then the checks.
        let restarted = tracker()
        #expect(try restarted.catchUpPermanentUses().isEmpty)
        let events = try restarted.checkPermanentUses()
        try #require(events.count == 1)
        expectUse(events[0], state: "ended", method: "console", started: record.started)
        #expect(events[0].detail["ended"] == .date(shutdown))
        #expect(events[0].detail["end_basis"] == "logged")
    }

    /// Review focus 2: with fast user switching the account's sign-in stays in utmpx while
    /// someone else is on screen. It is one use until it signs out.
    @Test func fastUserSwitchIsOneUse() throws {
        let record = signIn(pid: 501, ago: 60)
        let t = tracker()
        var events = try t.checkPermanentUses()
        // Someone else switches in, and the account switches back later.
        clock.advance(120)
        let other = signIn("jdoe", pid: 502, ago: 0)
        events += try t.checkPermanentUses()
        clock.advance(120)
        events += try t.checkPermanentUses()
        signOut(other)
        clock.advance(120)
        events += try t.checkPermanentUses()
        let ended = signOut(record)
        events += try t.checkPermanentUses()

        try #require(events.count == 2)
        expectUse(events[0], state: "started", method: "console", started: record.started)
        expectUse(events[1], state: "ended", method: "console", started: record.started)
        #expect(events[0].detail["use_id"] == events[1].detail["use_id"])
        #expect(events[1].detail["ended"] == .date(ended))
    }

    /// Review focus 3: the agent is upgraded from 0.2 while the account is signed in. The
    /// store gains its table, and the sign-in is reported once, from when it really began.
    @Test func upgradeMidSessionReportsRealStart() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-upgrade-\(UUID().uuidString)")
        try writeVersion1Store(in: dir)
        let upgraded = try AgentStore.open(directory: dir)
        let record = signIn(ago: 7200)

        let t = tracker(on: upgraded)
        #expect(try t.catchUpPermanentUses().isEmpty)
        let events = try t.checkPermanentUses()
        try #require(events.count == 1)
        expectUse(events[0], state: "started", method: "console", started: record.started)
        #expect(try t.checkPermanentUses().isEmpty)
    }

    // MARK: The heartbeat

    /// A sign-in that begins and ends between two checks never shows in utmpx when the check
    /// looks: the heartbeat finds it in wtmp.
    @Test func shortSignInReportedByHeartbeat() throws {
        let t = tracker()
        _ = try t.heartbeat()
        clock.advance(300)
        let started = clock.now.addingTimeInterval(-20)
        let ended = clock.now.addingTimeInterval(-12)
        wtmp.withLock {
            $0.append(UtmpxEntry(kind: .login, user: "breakglass", tty: "ttys006", host: "10.0.0.9", pid: 970, time: started))
            $0.append(UtmpxEntry(kind: .logout, user: "", tty: "", host: "", pid: 970, time: ended))
        }
        #expect(try t.checkPermanentUses().isEmpty)

        let events = try t.heartbeat().filter { $0.type == .adminPermanentUse }
        try #require(events.count == 1)
        expectUse(events[0], state: "ended", method: "ssh", started: started)
        #expect(events[0].detail["ended"] == .date(ended))
        #expect(events[0].detail["end_basis"] == "logged")
        #expect(events[0].detail["remote_host"] == "10.0.0.9")
        #expect(try store.pending(limit: 100).filter { $0.event.type == .adminPermanentUse }.map(\.event) == events)

        clock.advance(300)
        #expect(try t.heartbeat().filter { $0.type == .adminPermanentUse }.isEmpty)
        #expect(try t.checkPermanentUses().isEmpty)
        #expect(try tracker().catchUpPermanentUses().isEmpty)
    }

    @Test func heartbeatPrunesRowsEndedOverADayAgo() throws {
        let record = signIn(tty: "ttys001", pid: 600, ago: 60)
        let t = tracker()
        _ = try t.checkPermanentUses()
        signOut(record)
        _ = try t.checkPermanentUses()
        let id = try #require(try store.pending(limit: 10).first?.event.detail["use_id"])
        guard case .string(let useID) = id else { return }

        clock.advance(86_000)
        _ = try t.heartbeat()
        #expect(try store.hasPermanentUse(id: useID))
        clock.advance(1000)
        _ = try t.heartbeat()
        #expect(try !store.hasPermanentUse(id: useID))
        #expect(try store.value(forKey: "permanent_use_logins_until") == AltiwardJSON.format(clock.now))
    }
}
