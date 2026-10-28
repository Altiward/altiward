import CoreServices
import Foundation
import os

/// Watches a folder with FSEvents. On every batch of changes it calls `onChange` at once, and
/// `handler` a few seconds after the last change, or when asked to with ``trigger(after:)``
/// and ``schedule(at:)``. For `/Library/Managed Preferences`: `onChange` compares the files
/// as they are now, `handler` reads the profiles too, so a setting forged there for one
/// elevation is seen before it is put back.
public final class ManagedPreferencesWatcher: Sendable {
    /// The quiet time after the last change before the handler runs, so a write in several
    /// steps, or macOS rewriting every file for a new profile, is checked once.
    public static let settle: TimeInterval = 4
    /// The longest a run waits for changes to stop: writes every few seconds can't put the
    /// check off for good.
    public static let longestWait: TimeInterval = 15

    /// FSEvents delivers here, and `onChange` runs here: never behind the handler.
    private let events = DispatchQueue(label: "com.altiward.agent.managed-preferences.events")
    /// The handler runs here, one run at a time; it reads the profiles and writes the store.
    private let work = DispatchQueue(label: "com.altiward.agent.managed-preferences.work")
    private let onChange: @Sendable () -> Void
    private let handler: @Sendable () -> Void
    /// When a scheduled run is due, so the earliest stands.
    private let scheduled = OSAllocatedUnfairLock<Date?>(initialState: nil)
    /// Counts triggers, so a scheduled run goes ahead only if no later trigger replaced it, and
    /// when the oldest trigger not yet handled came.
    private let pending = OSAllocatedUnfairLock<(generation: Int, since: Date?)>(initialState: (0, nil))
    private let stream = OSAllocatedUnfairLock<FSEventStreamWrapper?>(initialState: nil)

    public init(onChange: @escaping @Sendable () -> Void = {}, handler: @escaping @Sendable () -> Void) {
        self.onChange = onChange
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
            let watcher = Unmanaged<ManagedPreferencesWatcher>.fromOpaque(info).takeUnretainedValue()
            watcher.onChange()
            watcher.trigger(after: ManagedPreferencesWatcher.settle)
        }
        // NoDefer: the first change of a quiet spell is passed on at once, not after the latency.
        let flags = UInt32(
            kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagWatchRoot | kFSEventStreamCreateFlagNoDefer)
        guard
            let created = FSEventStreamCreate(
                nil, callback, &context, [path] as CFArray, FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 0.1,
                flags)
        else { return false }
        FSEventStreamSetDispatchQueue(created, events)
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
        work.asyncAfter(deadline: .now() + delay) { [pending, handler] in
            let current = pending.withLock {
                guard $0.generation == mine else { return false }
                $0.since = nil
                return true
            }
            if current { handler() }
        }
    }

    /// Runs the handler at `date`, unless a run is already scheduled for earlier. Separate from
    /// ``trigger(after:)``, so a later date never puts off a run that a change made due.
    public func schedule(at date: Date) {
        let take = scheduled.withLock {
            if let at = $0, at <= date { return false }
            $0 = date
            return true
        }
        guard take else { return }
        work.asyncAfter(deadline: .now() + max(0, date.timeIntervalSinceNow)) { [scheduled, handler] in
            let current = scheduled.withLock {
                guard $0 == date else { return false }
                $0 = nil
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
