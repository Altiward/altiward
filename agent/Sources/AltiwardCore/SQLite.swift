import Foundation
import SQLite3

public struct SQLiteError: Error, CustomStringConvertible {
    public let code: Int32
    public let message: String
    public var description: String { "SQLite error \(code): \(message)" }
}

// SQLITE_TRANSIENT tells SQLite to copy bound buffers before the call returns.
private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// Minimal SQLite wrapper. Not thread-safe; callers serialise access.
final class SQLiteConnection {
    private var db: OpaquePointer?

    /// `readOnly` opens an existing database without changing it.
    init(path: String, readOnly: Bool = false) throws {
        let flags = (readOnly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) | SQLITE_OPEN_FULLMUTEX
        let rc = sqlite3_open_v2(path, &db, flags, nil)
        guard rc == SQLITE_OK else {
            let message = db.map { String(cString: sqlite3_errmsg($0)) } ?? "open failed"
            sqlite3_close(db)
            throw SQLiteError(code: rc, message: message)
        }
        sqlite3_busy_timeout(db, 5_000)
    }

    deinit {
        sqlite3_close(db)
    }

    func execute(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &err)
        if rc != SQLITE_OK {
            let message = err.map { String(cString: $0) } ?? "exec failed"
            sqlite3_free(err)
            throw SQLiteError(code: rc, message: message)
        }
    }

    /// Runs a statement that returns no rows. Returns the number of rows changed.
    @discardableResult
    func run(_ sql: String, _ bindings: [SQLiteValue] = []) throws -> Int {
        let stmt = try prepare(sql, bindings)
        defer { sqlite3_finalize(stmt) }
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE || rc == SQLITE_ROW else { throw lastError(rc) }
        return Int(sqlite3_changes(db))
    }

    func query(_ sql: String, _ bindings: [SQLiteValue] = []) throws -> [SQLiteRow] {
        let stmt = try prepare(sql, bindings)
        defer { sqlite3_finalize(stmt) }
        var rows: [SQLiteRow] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw lastError(rc) }
            rows.append(SQLiteRow(stmt: stmt!))
        }
        return rows
    }

    private func prepare(_ sql: String, _ bindings: [SQLiteValue]) throws -> OpaquePointer? {
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK else { throw lastError(rc) }
        for (i, value) in bindings.enumerated() {
            let idx = Int32(i + 1)
            let brc: Int32
            switch value {
            case .null: brc = sqlite3_bind_null(stmt, idx)
            case .int(let v): brc = sqlite3_bind_int64(stmt, idx, v)
            case .double(let v): brc = sqlite3_bind_double(stmt, idx, v)
            case .text(let v): brc = sqlite3_bind_text(stmt, idx, v, -1, SQLITE_TRANSIENT)
            case .blob(let v):
                brc = v.withUnsafeBytes { buf in
                    sqlite3_bind_blob(stmt, idx, buf.baseAddress, Int32(buf.count), SQLITE_TRANSIENT)
                }
            }
            guard brc == SQLITE_OK else {
                sqlite3_finalize(stmt)
                throw lastError(brc)
            }
        }
        return stmt
    }

    private func lastError(_ rc: Int32) -> SQLiteError {
        SQLiteError(code: rc, message: String(cString: sqlite3_errmsg(db)))
    }
}

enum SQLiteValue {
    case null
    case int(Int64)
    case double(Double)
    case text(String)
    case blob(Data)

    static func optional(_ s: String?) -> SQLiteValue { s.map { .text($0) } ?? .null }
    static func optional(_ d: Double?) -> SQLiteValue { d.map { .double($0) } ?? .null }
}

struct SQLiteRow {
    private let values: [SQLiteValue]

    fileprivate init(stmt: OpaquePointer) {
        values = (0..<sqlite3_column_count(stmt)).map { i in
            switch sqlite3_column_type(stmt, i) {
            case SQLITE_INTEGER: return .int(sqlite3_column_int64(stmt, i))
            case SQLITE_FLOAT: return .double(sqlite3_column_double(stmt, i))
            case SQLITE_TEXT: return .text(String(cString: sqlite3_column_text(stmt, i)))
            case SQLITE_BLOB:
                let n = Int(sqlite3_column_bytes(stmt, i))
                guard n > 0, let p = sqlite3_column_blob(stmt, i) else { return .blob(Data()) }
                return .blob(Data(bytes: p, count: n))
            default: return .null
            }
        }
    }

    func int(_ i: Int) -> Int64? {
        if case .int(let v) = values[i] { return v }
        return nil
    }

    func double(_ i: Int) -> Double? {
        switch values[i] {
        case .double(let v): v
        case .int(let v): Double(v)
        default: nil
        }
    }

    func text(_ i: Int) -> String? {
        if case .text(let v) = values[i] { return v }
        return nil
    }

    func blob(_ i: Int) -> Data? {
        if case .blob(let v) = values[i] { return v }
        return nil
    }
}
