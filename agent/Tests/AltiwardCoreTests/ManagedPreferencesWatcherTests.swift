import Foundation
import Testing
import os

@testable import AltiwardCore

struct ManagedPreferencesWatcherTests {
    /// Waits up to `timeout` for `condition`.
    func wait(_ timeout: TimeInterval, until condition: () -> Bool) -> Bool {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if condition() { return true }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return condition()
    }

    @Test func triggersCloseTogetherRunTheHandlerOnce() {
        let runs = OSAllocatedUnfairLock(initialState: 0)
        let watcher = ManagedPreferencesWatcher { runs.withLock { $0 += 1 } }
        for _ in 0..<3 { watcher.trigger(after: 0.3) }
        #expect(wait(3) { runs.withLock { $0 } == 1 })
        Thread.sleep(forTimeInterval: 0.5)
        #expect(runs.withLock { $0 } == 1)
    }

    /// A change under the folder runs the handler once the writes have stopped for a few seconds.
    @Test func aWriteUnderTheFolderRunsTheHandler() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("watch-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("jdoe"), withIntermediateDirectories: true)
        let runs = OSAllocatedUnfairLock(initialState: 0)
        let watcher = ManagedPreferencesWatcher { runs.withLock { $0 += 1 } }
        #expect(watcher.start(path: dir.path))
        Thread.sleep(forTimeInterval: 0.5)
        try Data("x".utf8).write(to: dir.appendingPathComponent("jdoe/corp.sap.privileges.plist"))
        #expect(wait(ManagedPreferencesWatcher.settle + 5) { runs.withLock { $0 } >= 1 })
    }
}
