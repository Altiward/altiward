import Foundation
import Testing

@testable import AltiwardCore

/// One at a time: each test blocks its thread while a command runs.
@Suite(.serialized) struct CommandOutputTests {
    @Test func returnsTheOutputOfACommandThatSucceeds() {
        #expect(CommandOutput.run("/bin/echo", ["hello"], timeout: 5, maxBytes: 100) == .success(Data("hello\n".utf8)))
    }

    @Test func saysWhyThereIsNoOutput() {
        #expect(CommandOutput.run("/usr/bin/false", [], timeout: 5, maxBytes: 100) == .failure(.exited(1)))
        #expect(
            CommandOutput.run("/bin/sh", ["-c", "head -c 4096 /dev/zero"], timeout: 5, maxBytes: 100)
                == .failure(.tooLarge(100)))
        let start = Date()
        #expect(CommandOutput.run("/bin/sleep", ["10"], timeout: 1, maxBytes: 100) == .failure(.timedOut(1)))
        #expect(Date().timeIntervalSince(start) < 5)
        guard case .failure(.couldNotStart) = CommandOutput.run("/nonexistent/tool", [], timeout: 1, maxBytes: 100)
        else {
            Issue.record("a missing command should fail to start")
            return
        }
        #expect(CommandFailure.exited(1).description == "exited with status 1")
        #expect(CommandFailure.timedOut(10).description == "didn't finish within 10 s")
    }

    /// Its input is the null device, so a command that reads input ends at once.
    @Test func inputIsTheNullDevice() {
        #expect(CommandOutput.run("/bin/cat", [], timeout: 5, maxBytes: 100) == .success(Data()))
    }

    /// Endless output is cut off at the limit, not read to the end.
    @Test func endlessOutputStopsAtTheLimit() {
        let start = Date()
        #expect(CommandOutput.run("/usr/bin/yes", [], timeout: 10, maxBytes: 1 << 20) == .failure(.tooLarge(1 << 20)))
        #expect(Date().timeIntervalSince(start) < 5)
    }

    /// A command that ignores SIGTERM is killed, and one that closes its output but doesn't
    /// exit still times out.
    @Test func aCommandThatWontStopIsKilled() {
        let start = Date()
        #expect(
            CommandOutput.run("/bin/sh", ["-c", "trap '' TERM; sleep 30"], timeout: 1, maxBytes: 100)
                == .failure(.timedOut(1)))
        #expect(
            CommandOutput.run("/bin/sh", ["-c", "trap '' TERM; exec >&-; sleep 30"], timeout: 1, maxBytes: 100)
                == .failure(.timedOut(1)))
        #expect(Date().timeIntervalSince(start) < 15)
    }
}
