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

    @Test func keyValueRoundTrip() throws {
        let store = try makeStore()
        try store.setValue("x", forKey: "k")
        #expect(try store.value(forKey: "k") == "x")
        try store.setValue(nil, forKey: "k")
        #expect(try store.value(forKey: "k") == nil)
    }
}
