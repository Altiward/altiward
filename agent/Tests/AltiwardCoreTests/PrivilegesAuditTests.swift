import Foundation
import Testing
import os

@testable import AltiwardCore

/// Reading SAP Privileges' system extension log: the process behind admin rights nobody
/// granted, and agent.tamper for attempts it blocked.
struct PrivilegesAuditTests {
    let clock = TestClock()
    let store: AgentStore
    let admins = FakeAdmins()
    /// What the extension has logged; the fake reader returns the records since a date, as
    /// the live one does.
    let logged = OSAllocatedUnfairLock<[PrivilegesAuditRecord]>(initialState: [])
    let reads = OSAllocatedUnfairLock<[Date]>(initialState: [])
    /// The pid of the running extension, if any, and the identity of each pid; both can change
    /// between heartbeats.
    let extensionPID = OSAllocatedUnfairLock<Int32?>(initialState: nil)
    let identities = OSAllocatedUnfairLock<[Int32: ProcessIdentity]>(initialState: [:])

    init() throws {
        store = try makeStore()
    }

    func tracker() -> ElevationTracker {
        let (logged, reads, extensionPID, identities) = (logged, reads, extensionPID, identities)
        let env = makeEnvironment(
            admins: admins, clock: clock,
            privilegesAudit: { since in
                reads.withLock { $0.append(since) }
                return logged.withLock { $0.filter { $0.date >= since } }
            },
            processIdentity: { pid in identities.withLock { $0[pid] } },
            privilegesExtensionPID: { extensionPID.withLock { $0 } })
        return ElevationTracker(store: store, environment: env)
    }

    func log(_ type: String, _ subject: String, by executable: String? = "/usr/sbin/dseditgroup", ago: TimeInterval = 0, loggerPID: Int32 = 0) {
        let process = executable.map {
            PrivilegesAuditRecord.Instigator(
                executable: $0, signingID: "com.apple.dseditgroup", teamID: "", platformBinary: true, pid: 5165,
                ppid: 606, tty: "")
        }
        let record = PrivilegesAuditRecord(
            eventType: type, subject: subject, date: clock.now.addingTimeInterval(-ago), process: process,
            loggerPID: loggerPID)
        logged.withLock { $0.append(record) }
    }

    /// Makes `pid` the running extension, genuine and started `startedAgo` seconds ago.
    func runExtension(pid: Int32, startedAgo: TimeInterval, signingID: String = PrivilegesSigning.systemExtension) {
        extensionPID.withLock { $0 = pid }
        identities.withLock {
            $0[pid] = ProcessIdentity(
                signingID: signingID, teamID: PrivilegesSigning.teamID,
                startedAt: clock.now.addingTimeInterval(-startedAgo), uid: 0)
        }
    }

    func blocked(_ t: ElevationTracker) throws -> [AltiwardEvent] {
        try t.heartbeat().filter { $0.type == .agentTamper && $0.detail["check"] == "privileges_blocked" }
    }

    // MARK: Parsing

    /// As Privileges 2.6.0 logged it on a real Mac, with the account renamed.
    static let adminAdd = """
        {"esf":{"process":{"cdhash":"08ec90495b826e13a10d54651f0a80f2707b1a0a","tty":"","ppid":606,\
        "start_time":"2026-10-19T09:06:39Z","executable":"/usr/sbin/dseditgroup","is_platform_binary":true,\
        "parent_audit_token":[4294967295,0,0,0,0,606,100019,1554],"audit_token":[4294967295,0,0,0,0,5165,100019,11640],\
        "responsible_audit_token":[4294967295,0,0,0,0,606,100019,1554],"team_id":"","is_es_client":false,\
        "signing_id":"com.apple.dseditgroup","pid":5165}},"privileges":{"subject":"user","event_type":"ADMIN_ADD",\
        "id":"jdoe"}}
        """

    @Test func parsesAnAdminChange() throws {
        let date = Date(timeIntervalSince1970: 1_792_000_000)
        let record = try #require(PrivilegesAuditRecord.parse(message: Self.adminAdd, date: date))
        #expect(record.eventType == "ADMIN_ADD" && record.isAdminAdd && !record.isBlocked)
        #expect(record.subject == "jdoe")
        #expect(record.date == date)
        #expect(
            record.process
                == .init(
                    executable: "/usr/sbin/dseditgroup", signingID: "com.apple.dseditgroup", teamID: "",
                    platformBinary: true, pid: 5165, ppid: 606, tty: ""))
    }

    @Test func parsesABlockedAttemptByItsPath() throws {
        let message = """
            {"esf":{"process":{"executable":"/bin/rm","signing_id":"com.apple.rm","team_id":"","is_platform_binary":true,\
            "pid":812,"ppid":700,"tty":"/dev/ttys001"}},"privileges":{"event_type":"DELETE",\
            "subject":"/Applications/Privileges.app"}}
            """
        let record = try #require(PrivilegesAuditRecord.parse(message: message, date: Date()))
        #expect(record.isBlocked && record.subject == "/Applications/Privileges.app")
        #expect(record.process?.tty == "/dev/ttys001")
    }

    @Test func skipsTheSentenceAndRecordsWithoutASubject() {
        let sentence = "SAPCorp: User jdoe gained administrator privileges instigated by /usr/sbin/dseditgroup"
        #expect(PrivilegesAuditRecord.parse(message: sentence, date: Date()) == nil)
        #expect(PrivilegesAuditRecord.parse(message: #"{"privileges":{"event_type":"ADMIN_ADD"}}"#, date: Date()) == nil)
        #expect(PrivilegesAuditRecord.parse(message: "{not json", date: Date()) == nil)
    }

    @Test func anEmptyProcessHasNoInstigator() throws {
        let message = #"{"esf":{},"privileges":{"subject":"user","event_type":"ADMIN_ADD","id":"jdoe"}}"#
        let record = try #require(PrivilegesAuditRecord.parse(message: message, date: Date()))
        #expect(record.process == nil)
    }

    // MARK: Who made admin rights nobody granted

    @Test func theCheckBetweenHeartbeatsNamesTheProcess() throws {
        let t = tracker()
        admins.set(["backdoor"])
        log("ADMIN_ADD", "backdoor")
        _ = try t.checkUntrackedAdmins()
        clock.advance(30)
        let raised = try t.checkUntrackedAdmins()
        let instigator = try #require(raised.first?.detail["instigator"])
        guard case .object(let fields) = instigator else { Issue.record("not an object"); return }
        #expect(fields["executable"] == "/usr/sbin/dseditgroup")
        #expect(fields["signing_id"] == "com.apple.dseditgroup")
        #expect(fields["logged_at"] == .date(clock.now.addingTimeInterval(-30)))
    }

    @Test func theHeartbeatNamesTheLatestAddForThatUser() throws {
        admins.set(["backdoor"])
        log("ADMIN_ADD", "backdoor", by: "/usr/bin/old", ago: 200)
        log("ADMIN_ADD", "someoneelse", by: "/usr/bin/other", ago: 50)
        log("ADMIN_ADD", "backdoor", by: "/usr/sbin/sysadminctl", ago: 100)
        let raised = try tracker().heartbeat().filter { $0.type == .adminOutOfBand }
        guard case .object(let fields) = raised.first?.detail["instigator"] else {
            Issue.record("no instigator")
            return
        }
        #expect(fields["executable"] == "/usr/sbin/sysadminctl")
    }

    @Test func withoutARecordThereIsNoInstigator() throws {
        admins.set(["backdoor"])
        log("ADMIN_REMOVE", "backdoor")
        log("ADMIN_ADD", "backdoor", by: nil)  // Endpoint Security named no process
        let raised = try tracker().heartbeat().filter { $0.type == .adminOutOfBand }
        #expect(raised.count == 1 && raised[0].detail["instigator"] == nil)
    }

    @Test func theLogIsReadBetweenHeartbeatsOnlyWhenSomethingIsRaised() throws {
        let t = tracker()
        _ = try t.checkUntrackedAdmins()
        clock.advance(30)
        _ = try t.checkUntrackedAdmins()
        #expect(reads.withLock { $0 }.isEmpty)
    }

    // MARK: Attempts Privileges blocked

    @Test func eachBlockedAttemptIsReportedOnce() throws {
        let t = tracker()
        log("DELETE", "/Applications/Privileges.app", by: "/bin/rm")
        let first = try blocked(t)
        #expect(first.count == 1)
        #expect(first[0].detail["state"] == "detected")
        #expect(first[0].detail["blocked_action"] == "DELETE")
        #expect(first[0].detail["item"] == "/Applications/Privileges.app")
        #expect(first[0].detail["attempts"] == 1)
        #expect(
            first[0].detail["problem"] == "SAP Privileges blocked /bin/rm from trying to delete /Applications/Privileges.app")

        clock.advance(300)
        #expect(try blocked(t).isEmpty)
        // A restart reads from where the last heartbeat stopped.
        clock.advance(300)
        #expect(try blocked(tracker()).isEmpty)
    }

    @Test func repeatsBySameProcessOnSameItemAreOneEvent() throws {
        for ago in [30.0, 20, 10] { log("EXEC", "/Library/LaunchDaemons/corp.sap.privileges.daemon.plist", by: "/bin/launchctl", ago: ago) }
        log("RENAME", "/Applications/Privileges.app", by: "/bin/mv", ago: 5)
        let events = try blocked(tracker())
        #expect(events.map { $0.detail["blocked_action"] } == ["EXEC", "RENAME"])
        #expect(events[0].detail["attempts"] == 3)
        #expect(events[0].detail["first_attempt"] == .date(clock.now.addingTimeInterval(-30)))
        #expect(events[0].detail["last_attempt"] == .date(clock.now.addingTimeInterval(-10)))
        #expect(
            events[0].detail["problem"]
                == "SAP Privileges blocked /bin/launchctl from trying to unload /Library/LaunchDaemons/corp.sap.privileges.daemon.plist (3 attempts)")
    }

    @Test func attemptsAfterTheHeartbeatWaitForTheNext() throws {
        let t = tracker()
        log("DELETE", "/Applications/Privileges.app", by: "/bin/rm", ago: -1)  // logged just after this heartbeat began
        #expect(try blocked(t).isEmpty)
        clock.advance(300)
        #expect(try blocked(t).count == 1)
    }

    @Test func attemptsWhileTheDaemonWasStoppedAreStillReported() throws {
        _ = try blocked(tracker())
        clock.advance(3 * 3600)  // longer than the lookback
        log("DELETE", "/Applications/Privileges.app", by: "/bin/rm", ago: 2 * 3600)
        #expect(try blocked(tracker()).count == 1)
    }

    @Test func tooManyDistinctAttemptsAreCounted() throws {
        for i in 0..<25 { log("CREATE", "/Applications/Privileges.app/Contents/x\(i)", by: "/usr/bin/touch") }
        let events = try blocked(tracker())
        #expect(events.count == ElevationTracker.maxBlockedEvents)
        #expect(events.last?.detail["truncated"] == 5)
        #expect(events.first?.detail["truncated"] == nil)
    }

    @Test func anAttemptWithoutAProcessSaysSo() throws {
        log("DELETE", "/Applications/Privileges.app", by: nil)
        let events = try blocked(tracker())
        #expect(events.first?.detail["problem"] == "SAP Privileges blocked an attempt to delete /Applications/Privileges.app")
        #expect(events.first?.detail["instigator"] == .null)
    }

    // MARK: Which records came from the real extension

    func storedInstances() throws -> [[String: Any]] {
        let raw = try #require(try store.value(forKey: "privileges_extension_instances"))
        return try #require(try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [[String: Any]])
    }

    func outOfBandInstigator(_ t: ElevationTracker) throws -> [String: JSONValue]? {
        let raised = try t.heartbeat().filter { $0.type == .adminOutOfBand }
        guard case .object(let fields) = raised.first?.detail["instigator"] else { return nil }
        return fields
    }

    @Test func aRecordFromAKnownInstanceIsVerified() throws {
        runExtension(pid: 700, startedAgo: 1000)
        admins.set(["backdoor"])
        log("ADMIN_ADD", "backdoor", ago: 100, loggerPID: 700)
        log("DELETE", "/Applications/Privileges.app", by: "/bin/rm", ago: 50, loggerPID: 700)
        let t = tracker()
        let events = try t.heartbeat()
        let raised = events.filter { $0.type == .adminOutOfBand }
        guard case .object(let fields) = raised.first?.detail["instigator"] else {
            Issue.record("no instigator")
            return
        }
        #expect(fields["extension_verified"] == .bool(true))
        let tamper = events.filter { $0.type == .agentTamper && $0.detail["check"] == "privileges_blocked" }
        #expect(tamper.first?.detail["extension_verified"] == .bool(true))
    }

    @Test func aRecordFromAnUnknownPidIsMarkedUnverifiedNotDropped() throws {
        runExtension(pid: 700, startedAgo: 1000)
        admins.set(["backdoor"])
        log("ADMIN_ADD", "backdoor", ago: 100, loggerPID: 4242)  // some other process wrote it
        log("DELETE", "/Applications/Privileges.app", by: "/bin/rm", ago: 50, loggerPID: 4242)
        let events = try tracker().heartbeat()
        let raised = events.filter { $0.type == .adminOutOfBand }
        guard case .object(let fields) = raised.first?.detail["instigator"] else {
            Issue.record("no instigator")
            return
        }
        #expect(fields["executable"] == "/usr/sbin/dseditgroup")
        #expect(fields["extension_verified"] == .bool(false))
        let tamper = events.filter { $0.type == .agentTamper && $0.detail["check"] == "privileges_blocked" }
        #expect(tamper.count == 1)
        #expect(tamper.first?.detail["extension_verified"] == .bool(false))
    }

    @Test func aRecordFromBeforeAnInstanceStartedIsUnverified() throws {
        runExtension(pid: 700, startedAgo: 60)
        admins.set(["backdoor"])
        // Logged by the pid, but before the process that has it now began: a reused pid.
        log("ADMIN_ADD", "backdoor", ago: 100, loggerPID: 700)
        let fields = try #require(try outOfBandInstigator(tracker()))
        #expect(fields["extension_verified"] == .bool(false))
    }

    @Test func withoutAnExtensionNothingIsVerifiedAndNothingIsDropped() throws {
        admins.set(["backdoor"])
        log("ADMIN_ADD", "backdoor", ago: 100, loggerPID: 700)
        let fields = try #require(try outOfBandInstigator(tracker()))
        #expect(fields["extension_verified"] == .bool(false))
    }

    @Test func aProcessThatIsNotTheRealExtensionIsNotRemembered() throws {
        runExtension(pid: 700, startedAgo: 1000, signingID: "com.example.imposter")
        admins.set(["backdoor"])
        log("ADMIN_ADD", "backdoor", ago: 100, loggerPID: 700)
        let fields = try #require(try outOfBandInstigator(tracker()))
        #expect(fields["extension_verified"] == .bool(false))
    }

    @Test func anInstanceIsRememberedAfterTheExtensionRestarts() throws {
        let t = tracker()
        runExtension(pid: 700, startedAgo: 1000)
        _ = try t.heartbeat()
        // The extension restarts as a new process; a heartbeat reads back across the restart.
        clock.advance(600)
        runExtension(pid: 810, startedAgo: 100)
        _ = try t.heartbeat()
        admins.set(["backdoor"])
        log("ADMIN_ADD", "backdoor", ago: 500, loggerPID: 700)
        let fields = try #require(try outOfBandInstigator(t))
        #expect(fields["extension_verified"] == .bool(true))
        let remembered = try #require(try store.value(forKey: "privileges_extension_instances"))
        #expect(remembered.contains("700") && remembered.contains("810"))
    }

    @Test func eachInstanceIsKeptOnceAndOnlyTheLastTwentyRemain() throws {
        let t = tracker()
        runExtension(pid: 900, startedAgo: 10)
        _ = try t.heartbeat()
        _ = try t.heartbeat()  // the same instance again
        var stored = try storedInstances()
        #expect(stored.count == 1)
        for pid in Int32(901)...Int32(930) {
            clock.advance(60)
            runExtension(pid: pid, startedAgo: 10)
            _ = try t.heartbeat()
        }
        stored = try storedInstances()
        #expect(stored.count == 20)
        #expect(stored.last?["pid"] as? Int == 930 && stored.first?["pid"] as? Int == 911)
    }

    @Test func aStartTimeBelowTheMillisecondIsStillOneInstance() throws {
        let t = tracker()
        // The live start time has microsecond precision; the store keeps milliseconds.
        runExtension(pid: 700, startedAgo: 100.0004)
        _ = try t.heartbeat()
        clock.advance(60)
        _ = try t.heartbeat()
        #expect(try storedInstances().count == 1)
        // A record logged at the very instant the process started still counts.
        admins.set(["backdoor"])
        log("ADMIN_ADD", "backdoor", ago: 160.0004, loggerPID: 700)
        let fields = try #require(try outOfBandInstigator(t))
        #expect(fields["extension_verified"] == .bool(true))
    }
}
