import Foundation
import Testing

@testable import AltiwardCore

struct AgentStoreTests {
    @Test func outboxIsOrderedOldestFirst() throws {
        let store = try makeStore()
        let ids = (0..<5).map { _ in newID() }
        for id in ids { try store.enqueue(sampleEvent(id: id)) }
        #expect(try store.pending(limit: 10).map(\.event.eventID) == ids)
        #expect(try store.pending(limit: 2).map(\.event.eventID) == Array(ids.prefix(2)))
    }

    @Test func enqueueIsIdempotentByEventID() throws {
        let store = try makeStore()
        let event = sampleEvent()
        try store.enqueue(event)
        try store.enqueue(event)
        #expect(try store.pendingCount() == 1)
    }

    @Test func removeAndFailureBookkeeping() throws {
        let store = try makeStore()
        try store.enqueue(sampleEvent())
        try store.enqueue(sampleEvent())
        let pending = try store.pending(limit: 10)
        try store.recordFailure(seqs: [pending[1].seq], error: "offline")
        try store.remove(seqs: [pending[0].seq])
        let left = try store.pending(limit: 10)
        #expect(left.count == 1)
        #expect(left[0].attempts == 1)
    }

    @Test func eventsSurviveReopen() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-reopen-\(UUID().uuidString)")
        let event = sampleEvent()
        do {
            let store = try AgentStore.open(directory: dir)
            try store.enqueue(event)
            try store.upsertOpenSession(
                OpenSession(user: "jdoe", sessionID: "s1", source: .privileges, startedAt: Date(), expiresAt: nil))
        }
        let reopened = try AgentStore.open(directory: dir)
        let encoder = AltiwardJSON.encoder()
        #expect(try reopened.pending(limit: 10).map { try encoder.encode($0.event) } == [try encoder.encode(event)])
        #expect(try reopened.openSession(user: "jdoe")?.sessionID == "s1")
    }

    @Test func dataDirectoryIsOwnerOnly() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-perms-\(UUID().uuidString)")
        _ = try AgentStore.open(directory: dir)
        let perms = try FileManager.default.attributesOfItem(atPath: dir.path)[.posixPermissions] as? Int
        #expect(perms == 0o700)
    }

    /// The installed data directory is also Altiward.app's parent, so the package creates it
    /// world-readable. The database holds the device key: its files must be owner-only anyway.
    @Test func storeFilesAreOwnerOnlyInASharedDirectory() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-shared-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        let store = try AgentStore.open(directory: dir)
        try store.setValue("secret", forKey: "device_credential")
        for name in ["agent.sqlite", "agent.sqlite-wal", "agent.sqlite-shm"] {
            let perms = try FileManager.default.attributesOfItem(atPath: dir.appendingPathComponent(name).path)[.posixPermissions] as? Int
            #expect(perms == 0o600, "\(name)")
        }
    }

    /// Macs installed before the fix already have world-readable files: opening repairs them.
    @Test func openingRepairsWorldReadableStoreFiles() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-repair-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        do {
            let store = try AgentStore.open(directory: dir)
            try store.setValue("secret", forKey: "device_credential")
        }
        for name in ["agent.sqlite", "agent.sqlite-wal", "agent.sqlite-shm"] {
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: dir.appendingPathComponent(name).path)
        }
        let reopened = try AgentStore.open(directory: dir)
        #expect(try reopened.value(forKey: "device_credential") == "secret")
        for name in ["agent.sqlite", "agent.sqlite-wal", "agent.sqlite-shm"] {
            let perms = try FileManager.default.attributesOfItem(atPath: dir.appendingPathComponent(name).path)[.posixPermissions] as? Int
            #expect(perms == 0o600, "\(name)")
        }
    }

    @Test func failedTransactionRollsBack() throws {
        struct Boom: Error {}
        let store = try makeStore()
        #expect(throws: Boom.self) {
            try store.transaction {
                try store.enqueue(sampleEvent())
                throw Boom()
            }
        }
        #expect(try store.pendingCount() == 0)
    }

    @Test func overdueReportIsClearedByARenewal() throws {
        let store = try makeStore()
        let start = Date(timeIntervalSince1970: 1_792_000_000)
        try store.upsertOpenSession(
            OpenSession(
                user: "jdoe", sessionID: "s1", source: .privileges, startedAt: start,
                expiresAt: start.addingTimeInterval(1200)))
        #expect(try store.openSession(user: "jdoe")?.overdueReported == false)

        try store.markOverdueReported(user: "jdoe")
        #expect(try store.openSession(user: "jdoe")?.overdueReported == true)

        // A renewal rewrites the session with a new expiry, which re-arms the alert.
        try store.upsertOpenSession(
            OpenSession(user: "jdoe", sessionID: "s1", source: .privileges, startedAt: start, expiresAt: Date()))
        #expect(try store.openSession(user: "jdoe")?.overdueReported == false)
    }

    @Test func freshStoreHasCurrentSchemaVersion() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-fresh-\(UUID().uuidString)")
        _ = try AgentStore.open(directory: dir)
        #expect(try userVersion(of: dir) == 3)
        #expect(AgentStore.schemaVersion == 3)
    }

    /// 0.1.0 wrote no version. Its stores must open with their data and get the current version.
    @Test func upgradesA010Store() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-v010-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let event = sampleEvent()
        let start = Date(timeIntervalSince1970: 1_792_000_000)
        do {
            // The 0.1.0 layout, exactly as agent-v0.1.0 created it.
            let db = try SQLiteConnection(path: dir.appendingPathComponent("agent.sqlite").path)
            try db.execute(
                """
                CREATE TABLE IF NOT EXISTS outbox (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    body BLOB NOT NULL,
                    enqueued_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT
                );
                CREATE TABLE IF NOT EXISTS open_sessions (
                    user TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    expires_at REAL,
                    overdue_reported INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS kv (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS command_results (
                    command_id TEXT PRIMARY KEY,
                    body BLOB NOT NULL,
                    executed_at REAL NOT NULL,
                    reported_at REAL
                );
                """)
            try db.run(
                "INSERT INTO outbox (event_id, body, enqueued_at, attempts, last_error) VALUES (?, ?, ?, 2, 'offline')",
                [.text(event.eventID), .blob(try AltiwardJSON.encoder().encode(event)), .double(start.timeIntervalSince1970)])
            try db.run(
                "INSERT INTO open_sessions (user, session_id, source, started_at, expires_at, overdue_reported) VALUES ('jdoe', 's1', 'privileges', ?, ?, 1)",
                [.double(start.timeIntervalSince1970), .double(start.addingTimeInterval(1200).timeIntervalSince1970)])
            try db.run("INSERT INTO kv (key, value) VALUES ('device_credential', 'secret')")
        }
        #expect(try userVersion(of: dir) == 0)

        let store = try AgentStore.open(directory: dir)
        let pending = try store.pending(limit: 10)
        #expect(pending.map(\.event.eventID) == [event.eventID])
        #expect(pending.first?.attempts == 2)
        #expect(
            try store.openSession(user: "jdoe")
                == OpenSession(
                    user: "jdoe", sessionID: "s1", source: .privileges, startedAt: start,
                    expiresAt: start.addingTimeInterval(1200), overdueReported: true))
        #expect(try store.value(forKey: "device_credential") == "secret")
        #expect(try userVersion(of: dir) == 3)
    }

    /// Agent 0.2's stores are at version 1: they keep their data and gain `permanent_uses`.
    @Test func migratesVersion1StoreToPermanentUses() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-v1-\(UUID().uuidString)")
        try writeVersion1Store(in: dir)
        try SQLiteConnection(path: dir.appendingPathComponent("agent.sqlite").path)
            .execute("INSERT INTO kv (key, value) VALUES ('device_credential', 'secret')")
        #expect(try userVersion(of: dir) == 1)

        let store = try AgentStore.open(directory: dir)
        #expect(AgentStore.schemaVersion == 3)
        #expect(try userVersion(of: dir) == 3)
        #expect(try store.value(forKey: "device_credential") == "secret")
        let tables = try SQLiteConnection(path: dir.appendingPathComponent("agent.sqlite").path)
            .query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'permanent_uses'")
        #expect(tables.count == 1)
        #expect(try store.openPermanentUses().isEmpty)
    }

    @Test func permanentUseRowsLiveUntilPruned() throws {
        let store = try makeStore()
        let start = Date(timeIntervalSince1970: 1_792_000_000)
        let row = PermanentUseRow(
            useID: "u1", user: "breakglass", method: .ssh, tty: "ttys003", host: "10.0.0.5", pid: 900,
            startedAt: start, endedAt: nil)
        try store.insertPermanentUse(row)
        // A second insert of the same use is ignored, not an error.
        try store.insertPermanentUse(
            PermanentUseRow(
                useID: "u1", user: "other", method: .console, tty: "console", host: "", pid: 1, startedAt: start,
                endedAt: nil))
        #expect(try store.openPermanentUses() == [row])
        #expect(try store.hasPermanentUse(id: "u1"))
        #expect(try !store.hasPermanentUse(id: "u2"))

        try store.endPermanentUse(id: "u1", at: start.addingTimeInterval(60))
        #expect(try store.openPermanentUses().isEmpty)
        // Ended rows stay, so a restart or the catch-up doesn't report the use again.
        #expect(try store.hasPermanentUse(id: "u1"))

        try store.prunePermanentUses(endedBefore: start.addingTimeInterval(60))
        #expect(try store.hasPermanentUse(id: "u1"))
        try store.prunePermanentUses(endedBefore: start.addingTimeInterval(61))
        #expect(try !store.hasPermanentUse(id: "u1"))
    }

    /// Agent 0.3's stores are at version 2: they keep their data and gain `pending_claims`.
    @Test func aVersion2StoreUpgradesToVersion3() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-v2-\(UUID().uuidString)")
        try writeVersion2Store(in: dir)
        try SQLiteConnection(path: dir.appendingPathComponent("agent.sqlite").path)
            .execute("INSERT INTO kv (key, value) VALUES ('device_credential', 'secret')")
        #expect(try userVersion(of: dir) == 2)

        let store = try AgentStore.open(directory: dir)
        #expect(AgentStore.schemaVersion == 3)
        #expect(try userVersion(of: dir) == 3)
        #expect(try store.value(forKey: "device_credential") == "secret")
        #expect(try store.pendingClaims().isEmpty)
    }

    @Test func pendingClaimsRoundTrip() throws {
        let store = try makeStore()
        let start = Date(timeIntervalSince1970: 1_792_000_000.5)
        let later = PendingClaim(
            claimID: "c2",
            invocation: HookInvocation(user: "asmith", state: .admin, reason: nil, invokedAt: start.addingTimeInterval(30)),
            callerUID: nil)
        let earlier = PendingClaim(
            claimID: "c1",
            invocation: HookInvocation(user: "jdoe", state: .admin, reason: "probe reason", invokedAt: start),
            callerUID: 501)
        // Added out of order: the oldest invocation still comes first.
        try store.addPendingClaim(later)
        try store.addPendingClaim(earlier)
        #expect(try store.pendingClaims() == [earlier, later])

        try store.removePendingClaim(id: "c1")
        #expect(try store.pendingClaims() == [later])
        // Removing a claim that is already gone is not an error.
        try store.removePendingClaim(id: "c1")
        #expect(try store.pendingClaims() == [later])
    }

    /// Opening a newer agent's store would risk misreading it: refuse, and leave it as it is.
    @Test func refusesANewerSchemaVersion() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-newer-\(UUID().uuidString)")
        do {
            let store = try AgentStore.open(directory: dir)
            try store.setValue("secret", forKey: "device_credential")
        }
        let path = dir.appendingPathComponent("agent.sqlite").path
        try SQLiteConnection(path: path).execute("PRAGMA user_version = 4")

        #expect(throws: AgentStoreError.newerSchema(found: 4, supported: 3)) {
            try AgentStore.open(directory: dir)
        }
        #expect(try userVersion(of: dir) == 4)
        #expect(try SQLiteConnection(path: path).query("SELECT value FROM kv").first?.text(0) == "secret")
    }

    private func userVersion(of dir: URL) throws -> Int64? {
        try SQLiteConnection(path: dir.appendingPathComponent("agent.sqlite").path).query("PRAGMA user_version").first?.int(0)
    }

    @Test func keyValueRoundTrip() throws {
        let store = try makeStore()
        try store.setValue("x", forKey: "k")
        #expect(try store.value(forKey: "k") == "x")
        try store.setValue(nil, forKey: "k")
        #expect(try store.value(forKey: "k") == nil)
    }
}
