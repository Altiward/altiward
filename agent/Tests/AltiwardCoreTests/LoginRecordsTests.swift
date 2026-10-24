import Foundation
import Testing

@testable import AltiwardCore

/// Pairing wtmp's records into sign-ins, without touching the real files.
struct LoginRecordsTests {
    let t0 = Date(timeIntervalSince1970: 1_792_000_000)

    func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    @Test func logoutMatchesTtyAndPid() {
        let records = LoginRecords.paired([
            UtmpxEntry(kind: .login, user: "breakglass", tty: "ttys001", host: "", pid: 10, time: at(0)),
            UtmpxEntry(kind: .login, user: "jdoe", tty: "ttys002", host: "10.0.0.5", pid: 11, time: at(1)),
            // The same terminal, reused by another process: not this sign-in's end.
            UtmpxEntry(kind: .logout, user: "", tty: "ttys001", host: "", pid: 99, time: at(2)),
            // The same process on another terminal: not its end either.
            UtmpxEntry(kind: .logout, user: "", tty: "ttys009", host: "", pid: 10, time: at(3)),
            UtmpxEntry(kind: .logout, user: "", tty: "ttys001", host: "", pid: 10, time: at(4)),
            // A second logout for the same sign-in changes nothing.
            UtmpxEntry(kind: .logout, user: "", tty: "ttys001", host: "", pid: 10, time: at(5)),
        ])
        #expect(
            records == [
                LoginRecord(user: "breakglass", tty: "ttys001", host: "", pid: 10, started: at(0), ended: at(4)),
                LoginRecord(user: "jdoe", tty: "ttys002", host: "10.0.0.5", pid: 11, started: at(1), ended: nil),
            ])
    }

    /// As macOS writes them: a logout keeps the pid, with an empty tty and user.
    @Test func logoutWithoutTtyMatchesByPid() {
        let records = LoginRecords.paired([
            UtmpxEntry(kind: .login, user: "breakglass", tty: "ttys004", host: "", pid: 2245, time: at(0)),
            UtmpxEntry(kind: .login, user: "breakglass", tty: "ttys005", host: "", pid: 2246, time: at(1)),
            UtmpxEntry(kind: .logout, user: "", tty: "", host: "", pid: 2245, time: at(7)),
        ])
        #expect(
            records == [
                LoginRecord(user: "breakglass", tty: "ttys004", host: "", pid: 2245, started: at(0), ended: at(7)),
                LoginRecord(user: "breakglass", tty: "ttys005", host: "", pid: 2246, started: at(1), ended: nil),
            ])
    }

    /// A restart writes a shutdown record, then a boot record: sign-ins still open end at
    /// the shutdown, not at the next boot. A crash writes no shutdown, so the boot ends them.
    @Test func shutdownEndsOpenLogins() {
        let records = LoginRecords.paired([
            UtmpxEntry(kind: .login, user: "breakglass", tty: "console", host: "", pid: 100, time: at(0)),
            UtmpxEntry(kind: .login, user: "breakglass", tty: "ttys000", host: "", pid: 200, time: at(10)),
            UtmpxEntry(kind: .shutdown, user: "", tty: "~", host: "", pid: 0, time: at(20)),
            UtmpxEntry(kind: .boot, user: "", tty: "~", host: "", pid: 0, time: at(30)),
            UtmpxEntry(kind: .login, user: "breakglass", tty: "console", host: "", pid: 100, time: at(40)),
            UtmpxEntry(kind: .boot, user: "", tty: "~", host: "", pid: 0, time: at(50)),
            UtmpxEntry(kind: .login, user: "breakglass", tty: "console", host: "", pid: 120, time: at(60)),
        ])
        #expect(
            records == [
                LoginRecord(user: "breakglass", tty: "console", host: "", pid: 100, started: at(0), ended: at(20)),
                LoginRecord(user: "breakglass", tty: "ttys000", host: "", pid: 200, started: at(10), ended: at(20)),
                LoginRecord(user: "breakglass", tty: "console", host: "", pid: 100, started: at(40), ended: at(50)),
                LoginRecord(user: "breakglass", tty: "console", host: "", pid: 120, started: at(60), ended: nil),
            ])
    }

    @Test func unmatchedLoginStaysOpen() {
        let records = LoginRecords.paired([
            // A logout from before the sign-in can't end it.
            UtmpxEntry(kind: .logout, user: "", tty: "console", host: "", pid: 100, time: at(0)),
            UtmpxEntry(kind: .login, user: "breakglass", tty: "console", host: "", pid: 100, time: at(10)),
            UtmpxEntry(kind: .logout, user: "", tty: "ttys004", host: "", pid: 300, time: at(20)),
        ])
        #expect(
            records == [
                LoginRecord(user: "breakglass", tty: "console", host: "", pid: 100, started: at(10), ended: nil)
            ])
    }
}
