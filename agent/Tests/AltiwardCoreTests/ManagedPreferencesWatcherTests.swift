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

    /// Each change is passed on at once, before the handler's wait.
    @Test func eachChangeIsPassedOnAtOnce() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("watch-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let changes = OSAllocatedUnfairLock(initialState: 0)
        let runs = OSAllocatedUnfairLock(initialState: 0)
        let watcher = ManagedPreferencesWatcher(
            onChange: { changes.withLock { $0 += 1 } }, handler: { runs.withLock { $0 += 1 } })
        #expect(watcher.start(path: dir.path))
        Thread.sleep(forTimeInterval: 0.5)
        try Data("x".utf8).write(to: dir.appendingPathComponent("com.altiward.agent.plist"))
        #expect(wait(2) { changes.withLock { $0 } >= 1 })
        #expect(runs.withLock { $0 } == 0)
    }

    /// A scheduled run keeps the earliest date, and isn't put off by a later one.
    @Test func theEarliestScheduledRunStands() {
        let runs = OSAllocatedUnfairLock(initialState: [Date]())
        let watcher = ManagedPreferencesWatcher { runs.withLock { $0.append(Date()) } }
        let start = Date()
        watcher.schedule(at: start.addingTimeInterval(0.3))
        watcher.schedule(at: start.addingTimeInterval(5))
        #expect(wait(2) { runs.withLock { $0.count } == 1 })
        #expect(runs.withLock { $0[0] }.timeIntervalSince(start) < 1.5)
    }
}

extension ManagedPreferencesWatcherTests {
    /// A change is passed on while a slow run of the handler (reading the profiles) is still
    /// going: the two never wait for each other.
    @Test func aChangeIsPassedOnWhileTheHandlerRuns() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("watch-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let changes = OSAllocatedUnfairLock(initialState: 0)
        let running = OSAllocatedUnfairLock(initialState: false)
        let watcher = ManagedPreferencesWatcher(
            onChange: { changes.withLock { $0 += 1 } },
            handler: {
                running.withLock { $0 = true }
                Thread.sleep(forTimeInterval: 4)
                running.withLock { $0 = false }
            })
        #expect(watcher.start(path: dir.path))
        Thread.sleep(forTimeInterval: 0.5)
        watcher.trigger(after: 0)
        #expect(wait(2) { running.withLock { $0 } })
        Thread.sleep(forTimeInterval: 0.3)
        let before = changes.withLock { $0 }
        try Data("x".utf8).write(to: dir.appendingPathComponent("com.altiward.agent.plist"))
        #expect(wait(2) { changes.withLock { $0 } > before })
        #expect(running.withLock { $0 })
    }
}
