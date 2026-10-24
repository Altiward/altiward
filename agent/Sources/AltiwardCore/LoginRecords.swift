import Darwin
import Foundation

/// One record from utmpx or wtmp, as `last` reads them.
public struct UtmpxEntry: Sendable, Equatable {
    public enum Kind: Sendable, Equatable {
        /// `USER_PROCESS`: someone signed in.
        case login
        /// `DEAD_PROCESS`: the process that held a sign-in ended.
        case logout
        /// `BOOT_TIME`.
        case boot
        /// `SHUTDOWN_TIME`.
        case shutdown
    }

    public var kind: Kind
    /// The account's short name; empty on logout, boot and shutdown records.
    public var user: String
    /// `console` for the login window, `ttys003` for a terminal.
    public var tty: String
    /// The remote address for SSH, as macOS recorded it; empty otherwise.
    public var host: String
    public var pid: Int32
    public var time: Date

    public init(kind: Kind, user: String, tty: String, host: String, pid: Int32, time: Date) {
        self.kind = kind
        self.user = user
        self.tty = tty
        self.host = host
        self.pid = pid
        self.time = time
    }
}

/// A sign-in: a login record with the record that ended it, if any.
public struct LoginRecord: Sendable, Equatable {
    public var user: String
    public var tty: String
    public var host: String
    public var pid: Int32
    public var started: Date
    /// When wtmp says it ended: its logout, or a shutdown or boot. Nil while it's open, or
    /// when wtmp has nothing that ends it.
    public var ended: Date?

    public init(user: String, tty: String, host: String, pid: Int32, started: Date, ended: Date?) {
        self.user = user
        self.tty = tty
        self.host = host
        self.pid = pid
        self.started = started
        self.ended = ended
    }
}

/// Reads sign-ins from utmpx (who is signed in now) and wtmp (the history `last` shows).
/// Both are corroboration an admin can erase. All the C interop is here; the pairing that
/// turns wtmp's records into sign-ins is the pure ``paired(_:)``.
enum LoginRecords {
    /// The `getutxent` family keeps its position in process-wide state.
    private static let lock = NSLock()

    /// Who is signed in now: utmpx's `USER_PROCESS` entries.
    static func current() -> [LoginRecord] {
        lock.withLock {
            setutxent()
            defer { endutxent() }
            var records: [LoginRecord] = []
            while let raw = getutxent() {
                guard let entry = entry(raw.pointee), entry.kind == .login, !entry.user.isEmpty else { continue }
                records.append(
                    LoginRecord(
                        user: entry.user, tty: entry.tty, host: entry.host, pid: entry.pid, started: entry.time,
                        ended: nil))
            }
            return records
        }
    }

    /// Whether a process with this id exists. `EPERM` means it does, under another account.
    public static func processExists(_ pid: Int32) -> Bool {
        kill(pid, 0) == 0 || errno == EPERM
    }

    /// Sign-ins from wtmp still open at `since` or later: those that ended at or after it,
    /// and those that haven't ended. Empty when wtmp can't be read.
    static func history(since: Date) -> [LoginRecord] {
        let entries = lock.withLock {
            setutxent_wtmp(1)  // oldest first
            defer { endutxent_wtmp() }
            var entries: [UtmpxEntry] = []
            while let raw = getutxent_wtmp() {
                if let entry = entry(raw.pointee) { entries.append(entry) }
            }
            return entries
        }
        return paired(entries).filter { ($0.ended ?? .distantFuture) >= since }
    }

    /// Turns records into sign-ins, in the order they began. A login ends at the first later
    /// logout with the same pid (and the same tty, when the logout names one), or at the first
    /// later shutdown or boot, whichever comes first; a restart writes a shutdown before its
    /// boot, so that is when it ends. macOS writes logouts with an empty tty and user, keeping
    /// the pid; a pid can't be reused before its process exits, which writes the logout.
    static func paired(_ entries: [UtmpxEntry]) -> [LoginRecord] {
        // By time, keeping the given order for records at the same moment.
        let ordered = entries.enumerated().sorted {
            $0.element.time != $1.element.time ? $0.element.time < $1.element.time : $0.offset < $1.offset
        }.map(\.element)

        var records: [LoginRecord] = []
        var open: [Int] = []  // indices into `records`
        for entry in ordered {
            switch entry.kind {
            case .login:
                open.append(records.count)
                records.append(
                    LoginRecord(
                        user: entry.user, tty: entry.tty, host: entry.host, pid: entry.pid, started: entry.time,
                        ended: nil))
            case .logout:
                if let i = open.firstIndex(where: {
                    records[$0].pid == entry.pid && (entry.tty.isEmpty || records[$0].tty == entry.tty)
                }) {
                    records[open[i]].ended = entry.time
                    open.remove(at: i)
                }
            case .boot, .shutdown:
                for i in open { records[i].ended = entry.time }
                open = []
            }
        }
        return records
    }

    /// The record's fields, or nil for a kind that isn't a sign-in, sign-out, boot or shutdown.
    private static func entry(_ u: utmpx) -> UtmpxEntry? {
        let kind: UtmpxEntry.Kind
        switch Int32(u.ut_type) {
        case USER_PROCESS: kind = .login
        case DEAD_PROCESS: kind = .logout
        case BOOT_TIME: kind = .boot
        case SHUTDOWN_TIME: kind = .shutdown
        default: return nil
        }
        let time = Date(
            timeIntervalSince1970: TimeInterval(u.ut_tv.tv_sec) + TimeInterval(u.ut_tv.tv_usec) / 1_000_000)
        return UtmpxEntry(
            kind: kind, user: string(u.ut_user), tty: string(u.ut_line), host: string(u.ut_host), pid: u.ut_pid,
            time: time)
    }

    /// A fixed-size C char array: up to its first NUL, or all of it when it has none.
    private static func string<T>(_ field: T) -> String {
        withUnsafeBytes(of: field) { bytes in
            String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
        }
    }
}
