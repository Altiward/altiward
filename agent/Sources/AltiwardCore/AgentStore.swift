import Foundation

public enum AgentStoreError: Error, Equatable, CustomStringConvertible {
    /// The store was written by a newer agent, in a layout this build doesn't know.
    case newerSchema(found: Int, supported: Int)

    public var description: String {
        switch self {
        case .newerSchema(let found, let supported):
            "agent store has schema version \(found), newer than this agent's \(supported): "
                + "a newer Altiward agent wrote it, so reinstall that release or later"
        }
    }
}

/// An event waiting in the outbox.
public struct QueuedEvent: Sendable, Equatable {
    public let seq: Int64
    public let event: AltiwardEvent
    public let enqueuedAt: Date
    public let attempts: Int
}

/// An elevation session the agent believes is open on this Mac.
public struct OpenSession: Sendable, Equatable {
    public let user: String
    public let sessionID: String
    public let source: ElevationSource
    public let startedAt: Date
    public let expiresAt: Date?
    /// `elevation.overdue` was already sent for the current expiry.
    public var overdueReported = false
}

/// The agent's on-disk state: a durable, unbounded, ordered outbox plus the
/// ledger of open elevation sessions. One SQLite file, every write fully synced.
///
/// Thread-safe: all access goes through one recursive lock so callers can group
/// several operations in ``transaction(_:)``.
public final class AgentStore: @unchecked Sendable {
    private let db: SQLiteConnection
    private let lock = NSRecursiveLock()
    private let encoder = AltiwardJSON.encoder()
    private let decoder = AltiwardJSON.decoder()
    private var transactionDepth = 0

    public init(path: String) throws {
        db = try SQLiteConnection(path: path)
        try db.execute("PRAGMA journal_mode = WAL")
        // Evidence matters more than throughput: survive power loss, not just a crash.
        try db.execute("PRAGMA synchronous = FULL")
        try migrate()
    }

    /// Opens (creating if needed) the store in `directory`, readable only by its owner.
    ///
    /// Installed, the directory is also Altiward.app's parent and so world-readable; the
    /// files are what protect the device key. SQLite creates its -wal and -shm files with
    /// the database's mode, and opening tightens any of the files whose mode is looser.
    public static func open(directory: URL) throws -> AgentStore {
        let files = FileManager.default
        try files.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let path = directory.appendingPathComponent("agent.sqlite").path
        if !files.fileExists(atPath: path) {
            guard files.createFile(atPath: path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
                throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: path])
            }
        }
        for file in [path, path + "-wal", path + "-shm"] where files.fileExists(atPath: file) {
            try files.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file)
        }
        return try AgentStore(path: path)
    }

    /// The store's layouts, oldest first: `migrations[v]` upgrades a store at
    /// `PRAGMA user_version` v to v + 1. Migrations are forever: a new layout appends a
    /// step, and a shipped step is never edited or reordered.
    ///
    /// 0.1.0 shipped without a version, so its stores read as 0. Step 0 creates the 0.1.0
    /// tables idempotently: a fresh file gets them, and a 0.1.0 store already has them.
    private static let migrations: [String] = [
        // 0 -> 1: the 0.1.0 layout.
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
        """,
    ]

    /// The layout this build writes.
    static let schemaVersion = migrations.count

    /// Brings the store up to ``schemaVersion`` in one transaction, so a failed step
    /// leaves it at the version it had.
    private func migrate() throws {
        try transaction {
            let version = Int(try db.query("PRAGMA user_version").first?.int(0) ?? 0)
            // A newer agent's layout may hold data this build would misread or drop: refuse it.
            guard version <= Self.schemaVersion else {
                throw AgentStoreError.newerSchema(found: version, supported: Self.schemaVersion)
            }
            for step in Self.migrations[version...] {
                try db.execute(step)
            }
            if version < Self.schemaVersion {
                try db.execute("PRAGMA user_version = \(Self.schemaVersion)")
            }
        }
    }

    /// Runs `body` atomically. Nested calls join the outer transaction.
    public func transaction<T>(_ body: () throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        if transactionDepth > 0 {
            transactionDepth += 1
            defer { transactionDepth -= 1 }
            return try body()
        }
        try db.execute("BEGIN IMMEDIATE")
        transactionDepth = 1
        defer { transactionDepth = 0 }
        do {
            let result = try body()
            try db.execute("COMMIT")
            return result
        } catch {
            try? db.execute("ROLLBACK")
            throw error
        }
    }

    @discardableResult
    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    // MARK: Outbox

    /// Appends an event. Re-enqueueing the same `event_id` is a no-op.
    public func enqueue(_ event: AltiwardEvent, now: Date = Date()) throws {
        let body = try encoder.encode(event)
        try locked {
            try db.run(
                "INSERT OR IGNORE INTO outbox (event_id, body, enqueued_at) VALUES (?, ?, ?)",
                [.text(event.eventID), .blob(body), .double(now.timeIntervalSince1970)])
        }
    }

    /// Oldest-first events awaiting delivery.
    public func pending(limit: Int) throws -> [QueuedEvent] {
        try locked {
            try db.query(
                "SELECT seq, body, enqueued_at, attempts FROM outbox ORDER BY seq LIMIT ?",
                [.int(Int64(limit))]
            ).map { row in
                QueuedEvent(
                    seq: row.int(0)!,
                    event: try decoder.decode(AltiwardEvent.self, from: row.blob(1)!),
                    enqueuedAt: Date(timeIntervalSince1970: row.double(2)!),
                    attempts: Int(row.int(3)!))
            }
        }
    }

    public func remove(seqs: [Int64]) throws {
        guard !seqs.isEmpty else { return }
        try transaction {
            for seq in seqs {
                try db.run("DELETE FROM outbox WHERE seq = ?", [.int(seq)])
            }
        }
    }

    public func recordFailure(seqs: [Int64], error: String) throws {
        guard !seqs.isEmpty else { return }
        try transaction {
            for seq in seqs {
                try db.run(
                    "UPDATE outbox SET attempts = attempts + 1, last_error = ? WHERE seq = ?",
                    [.text(error), .int(seq)])
            }
        }
    }

    public func pendingCount() throws -> Int {
        try locked {
            Int(try db.query("SELECT COUNT(*) FROM outbox").first?.int(0) ?? 0)
        }
    }

    // MARK: Session ledger

    public func openSession(user: String) throws -> OpenSession? {
        try locked {
            try db.query(
                "SELECT user, session_id, source, started_at, expires_at, overdue_reported FROM open_sessions WHERE user = ?",
                [.text(user)]
            ).first.map(Self.session(from:))
        }
    }

    public func openSessions() throws -> [OpenSession] {
        try locked {
            try db.query(
                "SELECT user, session_id, source, started_at, expires_at, overdue_reported FROM open_sessions ORDER BY user"
            ).map(Self.session(from:))
        }
    }

    /// Writes `s`; a renewal that changes the expiry is written the same way.
    public func upsertOpenSession(_ s: OpenSession) throws {
        try locked {
            try db.run(
                """
                INSERT INTO open_sessions (user, session_id, source, started_at, expires_at, overdue_reported)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user) DO UPDATE SET session_id = excluded.session_id, source = excluded.source,
                    started_at = excluded.started_at, expires_at = excluded.expires_at,
                    overdue_reported = excluded.overdue_reported
                """,
                [
                    .text(s.user), .text(s.sessionID), .text(s.source.rawValue),
                    .double(s.startedAt.timeIntervalSince1970), .optional(s.expiresAt?.timeIntervalSince1970),
                    .int(s.overdueReported ? 1 : 0),
                ])
        }
    }

    public func markOverdueReported(user: String) throws {
        try locked {
            try db.run("UPDATE open_sessions SET overdue_reported = 1 WHERE user = ?", [.text(user)])
        }
    }

    public func closeSession(user: String) throws {
        try locked {
            try db.run("DELETE FROM open_sessions WHERE user = ?", [.text(user)])
        }
    }

    /// A source this agent doesn't know reads as `privileges`.
    private static func session(from row: SQLiteRow) -> OpenSession {
        OpenSession(
            user: row.text(0)!,
            sessionID: row.text(1)!,
            source: ElevationSource(rawValue: row.text(2)!) ?? .privileges,
            startedAt: Date(timeIntervalSince1970: row.double(3)!),
            expiresAt: row.double(4).map(Date.init(timeIntervalSince1970:)),
            overdueReported: row.int(5) == 1)
    }

    // MARK: Command results

    /// The stored result of a command this Mac already ran.
    public func commandResult(id: String) throws -> CommandResult? {
        try locked {
            try db.query("SELECT body FROM command_results WHERE command_id = ?", [.text(id)]).first
                .map { try decoder.decode(CommandResult.self, from: $0.blob(0)!) }
        }
    }

    public func saveCommandResult(id: String, result: CommandResult, at date: Date) throws {
        let body = try encoder.encode(result)
        try locked {
            try db.run(
                "INSERT INTO command_results (command_id, body, executed_at) VALUES (?, ?, ?)",
                [.text(id), .blob(body), .double(date.timeIntervalSince1970)])
        }
    }

    /// Results the server has not acknowledged, oldest first.
    public func unreportedCommandResults() throws -> [(id: String, result: CommandResult)] {
        try locked {
            try db.query("SELECT command_id, body FROM command_results WHERE reported_at IS NULL ORDER BY executed_at")
                .map { ($0.text(0)!, try decoder.decode(CommandResult.self, from: $0.blob(1)!)) }
        }
    }

    public func markCommandResultReported(id: String, at date: Date) throws {
        try locked {
            try db.run(
                "UPDATE command_results SET reported_at = ? WHERE command_id = ?", [.double(date.timeIntervalSince1970), .text(id)])
        }
    }

    /// Forgets results reported before `date`. The server stops sending a command once it
    /// has its result, so old rows are only kept as a guard against redelivery.
    public func pruneCommandResults(reportedBefore date: Date) throws {
        try locked {
            try db.run("DELETE FROM command_results WHERE reported_at < ?", [.double(date.timeIntervalSince1970)])
        }
    }

    // MARK: Key-value state

    public func value(forKey key: String) throws -> String? {
        try locked {
            try db.query("SELECT value FROM kv WHERE key = ?", [.text(key)]).first?.text(0)
        }
    }

    public func setValue(_ value: String?, forKey key: String) throws {
        try locked {
            if let value {
                try db.run(
                    "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [.text(key), .text(value)])
            } else {
                try db.run("DELETE FROM kv WHERE key = ?", [.text(key)])
            }
        }
    }
}
