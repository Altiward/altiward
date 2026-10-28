import CoreServices
import Foundation
import os

/// Calls `handler` a few seconds after the last change under a folder (FSEvents), and when
/// asked to with ``trigger(after:)``. For `/Library/Managed Preferences`: a setting forged
/// there for one elevation would otherwise be put back before the next heartbeat looked.
public final class ManagedPreferencesWatcher: Sendable {
    /// The quiet time after the last change before the handler runs, so a write in several
    /// steps, or macOS rewriting every file for a new profile, is checked once.
    public static let settle: TimeInterval = 4
    /// The longest a run waits for changes to stop: writes every few seconds can't put the
    /// check off for good.
    public static let longestWait: TimeInterval = 15

    private let queue = DispatchQueue(label: "com.altiward.agent.managed-preferences")
    private let handler: @Sendable () -> Void
    /// Counts triggers, so a scheduled run goes ahead only if no later trigger replaced it, and
    /// when the oldest trigger not yet handled came.
    private let pending = OSAllocatedUnfairLock<(generation: Int, since: Date?)>(initialState: (0, nil))
    private let stream = OSAllocatedUnfairLock<FSEventStreamWrapper?>(initialState: nil)

    public init(handler: @escaping @Sendable () -> Void) {
        self.handler = handler
    }

    /// Starts watching `path` and everything under it. False when FSEvents can't watch it; the
    /// heartbeat still checks.
    @discardableResult
    public func start(path: String = "/Library/Managed Preferences") -> Bool {
        let info = Unmanaged.passUnretained(self).toOpaque()
        var context = FSEventStreamContext(version: 0, info: info, retain: nil, release: nil, copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, _, _, _, _ in
            guard let info else { return }
            Unmanaged<ManagedPreferencesWatcher>.fromOpaque(info).takeUnretainedValue()
                .trigger(after: ManagedPreferencesWatcher.settle)
        }
        let flags = UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagWatchRoot)
        guard
            let created = FSEventStreamCreate(
                nil, callback, &context, [path] as CFArray, FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 0.5,
                flags)
        else { return false }
        FSEventStreamSetDispatchQueue(created, queue)
        guard FSEventStreamStart(created) else {
            FSEventStreamInvalidate(created)
            FSEventStreamRelease(created)
            return false
        }
        let wrapper = FSEventStreamWrapper(created)
        stream.withLock { $0 = wrapper }
        return true
    }

    /// Runs the handler `delay` seconds from now, replacing a run already waiting, unless that
    /// one has waited ``longestWait`` already.
    public func trigger(after delay: TimeInterval) {
        let now = Date()
        let mine: Int? = pending.withLock {
            if let since = $0.since, now.timeIntervalSince(since) >= Self.longestWait { return nil }
            $0.generation += 1
            $0.since = $0.since ?? now
            return $0.generation
        }
        guard let mine else { return }
        queue.asyncAfter(deadline: .now() + delay) { [pending, handler] in
            let current = pending.withLock {
                guard $0.generation == mine else { return false }
                $0.since = nil
                return true
            }
            if current { handler() }
        }
    }

    deinit {
        stream.withLock { $0?.stop() }
    }
}

/// Owns an FSEventStream; only touched under the watcher's lock.
private final class FSEventStreamWrapper: @unchecked Sendable {
    let stream: FSEventStreamRef

    init(_ stream: FSEventStreamRef) { self.stream = stream }

    func stop() {
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
    }
}
