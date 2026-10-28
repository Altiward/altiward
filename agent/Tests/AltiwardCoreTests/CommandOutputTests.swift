import Foundation
import Testing

@testable import AltiwardCore

struct CommandOutputTests {
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
}
