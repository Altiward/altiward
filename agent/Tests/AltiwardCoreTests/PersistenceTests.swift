import Foundation
import Testing
import os

@testable import AltiwardCore

/// The persistence snapshot, and which sessions its changes are reported on.
struct PersistenceTests {
    static let key =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAlQsOrg+eGOLhOz+C2hAvFQriMw9/BqSYyl18fWQdFL test@example"
    static let fingerprint = "SHA256:MUYXhbzAe2bGtJZ/B7tFqcYUSEvPPdynEap1A9R+Qd4"

    let clock = TestClock()
    let store: AgentStore
    let admins = FakeAdmins([])
    let root: URL
    let remote = OSAllocatedUnfairLock<Set<String>?>(initialState: [])
    let links = OSAllocatedUnfairLock<[String: String]?>(initialState: ["jdoe": "jane.doe@example.com"])
    let accounts = OSAllocatedUnfairLock(initialState: [
        LocalAccount(name: "root", uid: 0, home: "/var/root"),
        LocalAccount(name: "_www", uid: 70, home: "/Library/WebServer"),
        LocalAccount(name: "jdoe", uid: 501, home: "/Users/jdoe"),
    ])

    init() throws {
        store = try makeStore()
        root = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-persistence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try write("/etc/sudoers", "# defaults\nroot ALL = (ALL) ALL\n%admin ALL = (ALL) ALL\n#includedir /private/etc/sudoers.d\n")
    }

    var sources: PersistenceSources {
        let (accounts, remote, links) = (accounts, remote, links)
        return PersistenceSources(
            root: root, accounts: { accounts.withLock { $0 } }, remoteAccess: { remote.withLock { $0 } },
            platformSSOLinks: { links.withLock { $0 } })
    }

    func tracker(snapshot: (@Sendable () -> PersistenceSnapshot)? = nil) -> ElevationTracker {
        var env = makeEnvironment(admins: admins, clock: clock)
        let sources = sources
        env.persistence = snapshot ?? { sources.snapshot() }
        return ElevationTracker(store: store, environment: env)
    }

    func write(_ path: String, _ text: String) throws {
        let url = root.appendingPathComponent(path)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url)
    }

    func launchItem(_ path: String, label: String, arguments: [String]) throws {
        let data = try PropertyListSerialization.data(
            fromPropertyList: ["Label": label, "ProgramArguments": arguments], format: .xml, options: 0)
        try write(path, String(decoding: data, as: UTF8.self))
    }

    func open(_ user: String, source: ElevationSource = .privileges) throws -> String {
        let id = newID()
        try store.upsertOpenSession(
            OpenSession(user: user, sessionID: id, source: source, startedAt: clock.now, expiresAt: nil))
        return id
    }

    func findings(_ event: AltiwardEvent) -> [[String: JSONValue]] {
        guard case .array(let all) = event.detail["findings"] else { return [] }
        return all.compactMap { if case .object(let f) = $0 { return f } else { return nil } }
    }

    // MARK: The snapshot

    @Test func readsEachLocation() throws {
        try launchItem(
            "/Library/LaunchDaemons/com.example.updater.plist", label: "com.example.updater",
            arguments: ["/bin/sh", "-c", "curl -s https://example.com/x | sh"])
        try launchItem("/Users/jdoe/Library/LaunchAgents/com.example.agent.plist", label: "com.example.agent", arguments: ["/usr/bin/true"])
        try write("/Users/jdoe/.ssh/authorized_keys", "# mine\nno-pty,from=\"10.0.0.0/8\" \(Self.key)\nnot a key\n")
        try write("/etc/sudoers.d/jdoe", "jdoe ALL=(ALL) NOPASSWD: ALL\n")
        remote.withLock { $0 = ["remote_login"] }

        let snapshot = sources.snapshot()
        let byKey = Dictionary(uniqueKeysWithValues: snapshot.items.map { ($0.key, $0) })
        #expect(snapshot.unreadable.isEmpty)

        let daemon = try #require(byKey["launch_daemon:/Library/LaunchDaemons/com.example.updater.plist"])
        #expect(daemon.fields["label"] == "com.example.updater")
        #expect(daemon.fields["program"] == "/bin/sh")
        #expect(daemon.fields["arguments"] == ["/bin/sh", "-c", "curl -s https://example.com/x | sh"])

        let agent = try #require(byKey["launch_agent:/Users/jdoe/Library/LaunchAgents/com.example.agent.plist"])
        #expect(agent.fields["user"] == "jdoe")

        let key = try #require(byKey["ssh_authorized_key:/Users/jdoe/.ssh/authorized_keys#\(Self.fingerprint)"])
        #expect(key.fields["key_type"] == "ssh-ed25519")
        #expect(key.fields["fingerprint"] == .string(Self.fingerprint))
        #expect(key.fields["comment"] == nil)
        #expect(snapshot.items.filter { $0.kind == .sshAuthorizedKey }.count == 1)

        let sudoers = try #require(byKey["sudoers:/etc/sudoers"])
        #expect(sudoers.lines == ["root ALL = (ALL) ALL", "%admin ALL = (ALL) ALL", "#includedir /private/etc/sudoers.d"])
        #expect(byKey["sudoers:/etc/sudoers.d/jdoe"]?.lines == ["jdoe ALL=(ALL) NOPASSWD: ALL"])

        #expect(byKey["local_account:_www"]?.fields["uid"] == 70)
        #expect(byKey["remote_access:remote_login"] != nil)
        #expect(byKey["remote_access:screen_sharing"] == nil)
    }

    @Test func remoteAccessReadsBothLaunchctlFormats() {
        let current = """
            disabled services = {
            	"com.openssh.sshd" => enabled
            	"com.apple.screensharing" => disabled
            	"com.apple.ftpd" => enabled
            }
            """
        #expect(PersistenceSources.remoteAccess(fromPrintDisabled: current) == ["remote_login"])
        let older = "\t\"com.openssh.sshd\" => true\n\t\"com.apple.screensharing\" => false\n"
        #expect(PersistenceSources.remoteAccess(fromPrintDisabled: older) == ["screen_sharing"])
    }

    @Test func launchdFailingCountsAsUnreadable() {
        remote.withLock { $0 = nil }
        #expect(sources.snapshot().unreadable == [PersistenceSources.remoteAccessLocation])
    }

    @Test func aPipeInAHomeFolderIsUnreadableNotWaitedOn() throws {
        // A user could put a FIFO where the daemon reads as root, to hang the check.
        let ssh = root.appendingPathComponent("/Users/jdoe/.ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        #expect(mkfifo(ssh.appendingPathComponent("authorized_keys").path, 0o600) == 0)
        #expect(sources.snapshot().unreadable == ["/Users/jdoe/.ssh/authorized_keys"])
    }

    @Test func anEmptyFileIsReadNotUnreadable() throws {
        // Reading an empty file gives nothing, which isn't failing to read it.
        try write("/Users/jdoe/.ssh/authorized_keys", "")
        try write("/Library/LaunchDaemons/com.example.empty.plist", "")
        try write("/etc/sudoers", "")
        let snapshot = sources.snapshot()
        #expect(snapshot.unreadable.isEmpty)
        #expect(snapshot.items.contains { $0.kind == .launchDaemon && $0.id.hasSuffix("com.example.empty.plist") })
        #expect(snapshot.items.contains { $0.kind == .sudoers && $0.id == "/etc/sudoers" })
    }

    // MARK: Which sessions changes are reported on

    @Test func theFirstCheckOnlyTakesABaseline() throws {
        let t = tracker()
        _ = try open("jdoe")
        #expect(try t.checkPersistence().isEmpty)
    }

    @Test func changesWhileNoSessionIsOpenAreTakenInSilently() throws {
        let t = tracker()
        try t.checkPersistence()
        try launchItem("/Library/LaunchDaemons/com.mdm.tool.plist", label: "com.mdm.tool", arguments: ["/usr/local/bin/tool"])
        #expect(try t.checkPersistence().isEmpty)
        // And it isn't reported later, once a session opens.
        _ = try open("jdoe")
        try t.checkPersistence()
        #expect(try t.checkPersistence().isEmpty)
    }

    @Test func aChangeDuringASessionIsReportedOnItOnce() throws {
        let t = tracker()
        let session = try open("jdoe")
        let started = clock.now
        try t.checkPersistence()

        clock.advance(120)
        try write("/Users/jdoe/.ssh/authorized_keys", Self.key + "\n")
        let events = try t.checkPersistence()
        #expect(events.count == 1)
        let event = try #require(events.first)
        #expect(event.type == .persistenceDetected)
        #expect(event.sessionID == session)
        #expect(event.user?.localName == "jdoe")
        #expect(event.elevation?.source == .privileges)
        #expect(event.detail["since"] == .date(started))
        #expect(event.detail["truncated"] == 0)
        #expect(findings(event).count == 1)
        #expect(findings(event).first?["kind"] == "ssh_authorized_key")
        #expect(findings(event).first?["change"] == "added")
        #expect(try store.pending(limit: 10).map(\.event.eventID).contains(event.eventID))

        #expect(try t.checkPersistence().isEmpty)
    }

    @Test func aSessionThatEndedBeforeTheCheckStillGetsItsChanges() throws {
        // The daemon wasn't running when the rights ended: the stored baseline still
        // names the session, so the next check reports on it.
        let t = tracker()
        let session = try open("jdoe")
        try t.checkPersistence()
        try write("/etc/sudoers.d/jdoe", "jdoe ALL=(ALL) NOPASSWD: ALL\n")
        try store.closeSession(user: "jdoe")
        clock.advance(3 * 24 * 3600)

        let restarted = tracker()
        let events = try restarted.checkPersistence()
        #expect(events.map(\.sessionID) == [session])
        #expect(findings(events[0]).first?["added_lines"] == ["jdoe ALL=(ALL) NOPASSWD: ALL"])
        #expect(try restarted.checkPersistence().isEmpty)
    }

    @Test func changesBeforeAGrantArentPutOnIt() throws {
        let t = tracker()
        try t.checkPersistence()
        try launchItem("/Library/LaunchDaemons/com.before.plist", label: "com.before", arguments: ["/usr/bin/true"])
        _ = try open("jdoe")
        // The check that runs right after the grant takes the change in.
        #expect(try t.checkPersistence().isEmpty)
        #expect(try t.checkPersistence().isEmpty)
    }

    @Test func everySessionOpenInTheWindowGetsTheChanges() throws {
        let t = tracker()
        let first = try open("jdoe")
        let second = try open("asmith")
        try t.checkPersistence()
        try write("/etc/sudoers.d/extra", "asmith ALL=(ALL) ALL\n")
        let events = try t.checkPersistence()
        #expect(Set(events.compactMap(\.sessionID)) == [first, second])
        #expect(events.first(where: { $0.sessionID == second })?.elevation?.source == .privileges)
    }

    @Test func anOutOfBandAdminFoundSinceTheLastCheckGetsTheWindow() throws {
        let t = tracker()
        try t.checkPersistence()
        // Rights nobody granted, made before the heartbeat saw them.
        try launchItem("/Library/LaunchDaemons/com.backdoor.plist", label: "com.backdoor", arguments: ["/tmp/b"])
        admins.set(["mallory"])
        try t.heartbeat()
        let session = try #require(try store.openSession(user: "mallory"))
        #expect(session.source == .outOfBand)

        let events = try t.checkPersistence()
        #expect(events.map(\.sessionID) == [session.sessionID])
        #expect(events.first?.elevation?.source == .outOfBand)
    }

    @Test func aModifiedItemIsReportedAndOnlyNewSudoersLinesAreSent() throws {
        try launchItem("/Library/LaunchDaemons/com.vendor.plist", label: "com.vendor", arguments: ["/opt/vendor/run"])
        let t = tracker()
        _ = try open("jdoe")
        try t.checkPersistence()

        try launchItem("/Library/LaunchDaemons/com.vendor.plist", label: "com.vendor", arguments: ["/tmp/evil"])
        try write("/etc/sudoers", "root ALL = (ALL) ALL\n%admin ALL = (ALL) ALL\njdoe ALL=(ALL) NOPASSWD: ALL\n")
        let found = try #require(try t.checkPersistence().first).detail["findings"]
        #expect(
            found == [
                [
                    "kind": "launch_daemon", "change": "modified", "path": "/Library/LaunchDaemons/com.vendor.plist",
                    "label": "com.vendor", "program": "/tmp/evil", "arguments": ["/tmp/evil"],
                ],
                [
                    "kind": "sudoers", "change": "modified", "path": "/etc/sudoers",
                    "added_lines": ["jdoe ALL=(ALL) NOPASSWD: ALL"],
                ],
            ])
    }

    @Test func removalsAreNotFindings() throws {
        try launchItem("/Library/LaunchDaemons/com.vendor.plist", label: "com.vendor", arguments: ["/opt/vendor/run"])
        let t = tracker()
        _ = try open("jdoe")
        try t.checkPersistence()
        try FileManager.default.removeItem(at: root.appendingPathComponent("/Library/LaunchDaemons/com.vendor.plist"))
        try write("/etc/sudoers", "root ALL = (ALL) ALL\n")
        accounts.withLock { $0.removeAll { $0.name == "_www" } }
        #expect(try t.checkPersistence().isEmpty)
    }

    @Test func aNewAccountAndRemoteLoginAreReported() throws {
        let t = tracker()
        _ = try open("jdoe")
        try t.checkPersistence()
        accounts.withLock { $0.append(LocalAccount(name: "support", uid: 499, home: "/var/support", admin: true)) }
        remote.withLock { $0 = ["remote_login"] }
        let found = try #require(try t.checkPersistence().first).detail["findings"]
        #expect(
            found == [
                ["kind": "local_account", "change": "added", "name": "support", "uid": 499, "admin": true],
                ["kind": "remote_access", "change": "added", "service": "remote_login"],
            ])
    }

    @Test func aSnapshotHoldsEachAccountsPlatformSSOLink() {
        let byKey = Dictionary(uniqueKeysWithValues: sources.snapshot().items.map { ($0.key, $0) })
        #expect(byKey["local_account:jdoe"]?.fields["platform_sso"] == "jane.doe@example.com")
        #expect(byKey["local_account:root"]?.fields["platform_sso"] == nil)
    }

    /// Linking an account to someone else's Platform SSO account while elevated would put the
    /// next sessions on their UPN: a link added, changed or removed is a changed account.
    @Test(arguments: [
        ["jdoe": "ceo@example.com"],
        [:],
        ["jdoe": "jane.doe@example.com", "_www": "ceo@example.com"],
    ])
    func aPlatformSSOLinkChangedDuringASessionIsReported(after: [String: String]) throws {
        let t = tracker()
        _ = try open("jdoe")
        try t.checkPersistence()
        links.withLock { $0 = after }
        let event = try #require(try t.checkPersistence().first)
        #expect(event.type == .persistenceDetected)
        #expect(findings(event).count == 1)
        #expect(findings(event).first?["kind"] == "local_account")
        #expect(findings(event).first?["change"] == "modified")
    }

    @Test func aLinkMadeWhileNoSessionIsOpenIsTakenInSilently() throws {
        let t = tracker()
        try t.checkPersistence()
        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        #expect(try t.checkPersistence().isEmpty)
    }

    @Test func unreadableLinksKeepTheLastAccounts() throws {
        let t = tracker()
        _ = try open("jdoe")
        try t.checkPersistence()
        links.withLock { $0 = nil }
        #expect(try t.checkPersistence().isEmpty)
        #expect(sources.snapshot().unreadable == ["accounts"])
        links.withLock { $0 = ["jdoe": "jane.doe@example.com"] }
        #expect(try t.checkPersistence().isEmpty)
    }

    @Test func persistenceFindingsCarryTheSessionsUPN() throws {
        let t = tracker()
        try store.upsertOpenSession(
            OpenSession(
                user: "jdoe", sessionID: newID(), source: .privileges, startedAt: clock.now, expiresAt: nil,
                upn: "jane.doe@example.com"))
        try t.checkPersistence()
        links.withLock { $0 = ["jdoe": "ceo@example.com"] }
        #expect(try #require(try t.checkPersistence().first).user?.upn == "jane.doe@example.com")
    }

    @Test func anAccountMadeAdminIsNotAChangedAccount() throws {
        // Admin rights given to an existing account are an elevation, reported as such.
        let t = tracker()
        _ = try open("jdoe")
        accounts.withLock { $0 = $0.map { var a = $0; a.admin = false; return a } }
        try t.checkPersistence()
        accounts.withLock { $0 = $0.map { var a = $0; a.admin = a.name == "jdoe"; return a } }
        #expect(try t.checkPersistence().isEmpty)
    }

    @Test func whatAnUnreadablePlaceHeldIsKeptAndItShowsInHealth() throws {
        let item = PersistenceItem(
            kind: .sshAuthorizedKey, id: "/Users/jdoe/.ssh/authorized_keys#\(Self.fingerprint)",
            location: "/Users/jdoe/.ssh/authorized_keys", digest: Self.fingerprint, fields: ["path": "x"])
        let readable = OSAllocatedUnfairLock(initialState: true)
        let t = tracker(snapshot: {
            readable.withLock { $0 }
                ? PersistenceSnapshot(items: [item])
                : PersistenceSnapshot(items: [], unreadable: ["/Users/jdoe/.ssh/authorized_keys"])
        })
        _ = try open("jdoe")
        try t.checkPersistence()

        readable.withLock { $0 = false }
        #expect(try t.checkPersistence().isEmpty)
        let health = try #require(try t.heartbeat().first { $0.type == .agentHealth })
        #expect(health.detail["persistence_unreadable"] == ["/Users/jdoe/.ssh/authorized_keys"])

        // Readable again with the same key: nothing new.
        readable.withLock { $0 = true }
        #expect(try t.checkPersistence().isEmpty)
        let healthy = try #require(try t.heartbeat().first { $0.type == .agentHealth })
        #expect(healthy.detail["persistence_unreadable"] == [])
    }

    @Test func healthLeavesTheFieldOutWhenTheCheckIsOff() throws {
        let env = makeEnvironment(admins: admins, clock: clock)
        let health = try #require(
            try ElevationTracker(store: store, environment: env).heartbeat().first { $0.type == .agentHealth })
        #expect(health.detail["persistence_unreadable"] == nil)
    }

    @Test func findingsPastTheBudgetAreCounted() throws {
        let t = tracker()
        _ = try open("jdoe")
        try t.checkPersistence()
        let long = String(repeating: "x", count: 500)
        for i in 0..<200 {
            try launchItem(
                "/Library/LaunchDaemons/com.flood.\(i).plist", label: "com.flood.\(i)",
                arguments: Array(repeating: long, count: 4))
        }
        let event = try #require(try t.checkPersistence().first)
        let kept = findings(event).count
        guard case .number(let truncated) = event.detail["truncated"] else { Issue.record("no truncated count"); return }
        #expect(kept > 0)
        #expect(kept + Int(truncated) == 200)
        #expect(try AltiwardJSON.encoder().encode(event.detail).count < 48 << 10)
    }
}
