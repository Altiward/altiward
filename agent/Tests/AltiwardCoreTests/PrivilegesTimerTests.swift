import Foundation
import Testing

@testable import AltiwardCore

struct PrivilegesTimerTests {
    @Test func parsesWhatDefaultsPrints() {
        #expect(PrivilegesTimer.parse("2026-10-17 18:53:30 +0000\n") == Date(timeIntervalSince1970: 1_792_263_210))
    }

    @Test func anythingElseIsNoTimer() {
        #expect(PrivilegesTimer.parse("") == nil)
        #expect(PrivilegesTimer.parse("tomorrow") == nil)
        #expect(PrivilegesTimer.parse("{\n    TimerExpires = 1;\n}") == nil)
    }

    @Test func runReturnsOutputOfASuccessfulCommand() {
        #expect(PrivilegesTimer.run("/bin/echo", ["2026-10-17 18:53:30 +0000"]) == "2026-10-17 18:53:30 +0000\n")
    }

    @Test func runRefusesFailureLargeOutputAndSlowness() {
        #expect(PrivilegesTimer.run("/usr/bin/false", []) == nil)
        #expect(PrivilegesTimer.run("/bin/sh", ["-c", "head -c 4096 /dev/zero"]) == nil)
        // A user's preferences service that never answers can't hold up the grant.
        let start = Date()
        #expect(PrivilegesTimer.run("/bin/sleep", ["10"]) == nil)
        #expect(Date().timeIntervalSince(start) < 5)
    }

    @Test func readsTheCurrentUsersTimerThroughTheirPreferences() {
        // Runs the real command for this user: no timer later than now unless Privileges
        // has an elevation running.
        let user = NSUserName()
        let uid = getuid()
        _ = PrivilegesTimer.read(user: user, uid: uid)
    }
}
