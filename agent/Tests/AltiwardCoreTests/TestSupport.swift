import Foundation
import os

@testable import AltiwardCore

func makeStore() throws -> AgentStore {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("altiward-tests-\(UUID().uuidString)")
    return try AgentStore.open(directory: dir)
}

let testDevice = DeviceInfo(
    serial: "C02TEST", hardwareUUID: "HW-UUID", osVersion: "26.1.0", agentVersion: "0.1.0", privilegesVersion: "2.5.3")

/// Admin-group membership the test controls.
final class FakeAdmins: AdminMembershipReading, AdminGroupEditing, Sendable {
    private struct State {
        var members: Set<String> = []
        var removalAttempts = 0
        var failRemovals = false
        var failRemovalsFor: Set<String> = []
        var removalsHaveNoEffect = false
        var removalsThrowAfterTakingEffect = false
        var removalsTakeEffectLater = false
        var pendingRemovals: Set<String> = []
        var afterRead: (@Sendable () -> Void)?
    }

    struct RemovalFailed: Error {}

    private let state = OSAllocatedUnfairLock(initialState: State())

    init(_ initial: Set<String> = []) {
        state.withLock { $0.members = initial }
    }

    func set(_ users: Set<String>) { state.withLock { $0.members = users } }
    func isAdmin(user: String) -> Bool { read { $0.members.contains(user) } }
    func adminMembers() -> Set<String> { read { $0.members } }

    /// Runs once, right after the next membership read and before it returns: whatever it
    /// does happens in the gap between a caller reading membership and acting on it.
    var afterRead: (@Sendable () -> Void)? {
        get { state.withLock { $0.afterRead } }
        set { state.withLock { $0.afterRead = newValue } }
    }

    private func read<T: Sendable>(_ body: @Sendable (State) -> T) -> T {
        let (value, hook) = state.withLock { s in
            defer { s.afterRead = nil }
            return (body(s), s.afterRead)
        }
        hook?()
        return value
    }

    var removalAttempts: Int { state.withLock { $0.removalAttempts } }
    /// Removal throws.
    var failRemovals: Bool {
        get { state.withLock { $0.failRemovals } }
        set { state.withLock { $0.failRemovals = newValue } }
    }
    /// Removal throws for these users only.
    var failRemovalsFor: Set<String> {
        get { state.withLock { $0.failRemovalsFor } }
        set { state.withLock { $0.failRemovalsFor = newValue } }
    }
    /// Removal succeeds but the user stays admin, as with nested-group membership.
    var removalsHaveNoEffect: Bool {
        get { state.withLock { $0.removalsHaveNoEffect } }
        set { state.withLock { $0.removalsHaveNoEffect = newValue } }
    }

    /// Removal takes effect and then throws anyway.
    var removalsThrowAfterTakingEffect: Bool {
        get { state.withLock { $0.removalsThrowAfterTakingEffect } }
        set { state.withLock { $0.removalsThrowAfterTakingEffect = newValue } }
    }

    /// Removal takes effect only at the next ``settle()``, as when membership reads lag
    /// the directory.
    var removalsTakeEffectLater: Bool {
        get { state.withLock { $0.removalsTakeEffectLater } }
        set { state.withLock { $0.removalsTakeEffectLater = newValue } }
    }

    /// Applies removals held back by ``removalsTakeEffectLater``.
    func settle() {
        state.withLock { s in
            s.members.subtract(s.pendingRemovals)
            s.pendingRemovals = []
        }
    }

    func removeAdmin(user: String) throws {
        try state.withLock { s in
            s.removalAttempts += 1
            if s.failRemovals || s.failRemovalsFor.contains(user) { throw RemovalFailed() }
            if s.removalsTakeEffectLater {
                s.pendingRemovals.insert(user)
            } else if !s.removalsHaveNoEffect {
                s.members.remove(user)
            }
            if s.removalsThrowAfterTakingEffect { throw RemovalFailed() }
        }
    }
}

/// A clock the test moves by hand.
final class TestClock: Sendable {
    private let current: OSAllocatedUnfairLock<Date>

    init(_ start: Date = Date(timeIntervalSince1970: 1_792_000_000)) {
        current = OSAllocatedUnfairLock(initialState: start)
    }

    var now: Date { current.withLock { $0 } }
    func advance(_ seconds: TimeInterval) { current.withLock { $0 = $0.addingTimeInterval(seconds) } }
}

func makeEnvironment(
    admins: FakeAdmins,
    clock: TestClock = TestClock(),
    privileges: PrivilegesSettings = PrivilegesSettings(expirationIntervalMinutes: 20),
    config: AgentConfiguration = AgentConfiguration(),
    device: @escaping @Sendable () -> DeviceInfo = { testDevice },
    integrity: @escaping @Sendable () -> [IntegrityCheck: IntegrityResult] = { [:] },
    waitForDirectory: @escaping @Sendable () -> Void = {},
    privilegesTimer: @escaping @Sendable (_ user: String, _ grantedAt: Date) -> Date? = { _, _ in nil },
    privilegesAudit: @escaping @Sendable (_ since: Date) -> [PrivilegesAuditRecord] = { _ in [] }
) -> AgentEnvironment {
    AgentEnvironment(
        device: device,
        privileges: { privileges },
        admins: admins,
        adminEditor: admins,
        config: config,
        now: { clock.now },
        integrity: integrity,
        waitForDirectory: waitForDirectory,
        privilegesTimer: privilegesTimer,
        privilegesAudit: privilegesAudit)
}

// Whole milliseconds: the wire format keeps no more precision than that.
func sampleEvent(id: String = newID(), at date: Date = Date(timeIntervalSince1970: 1_792_000_000.123)) -> AltiwardEvent {
    AltiwardEvent(
        eventID: id, type: .agentHealth, sessionID: nil, timestamp: date, device: testDevice, user: nil,
        elevation: nil)
}

/// Repo-relative path, resolved from this source file.
func repoFile(_ relative: String) -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()  // AltiwardCoreTests
        .deletingLastPathComponent()  // Tests
        .deletingLastPathComponent()  // agent
        .deletingLastPathComponent()  // repo root
        .appendingPathComponent(relative)
}

/// Starts `body` on another thread, as something racing the caller, and waits up to
/// `timeout` for it. Code that holds the store's transaction while it reads makes `body`
/// wait for the commit, as on a real Mac, so the wait times out; code that reads outside
/// its transaction lets `body` finish in the gap. Wait on `group` before asserting.
///
/// `body` gets a thread of its own. Work sent to `DispatchQueue.global()` can wait for a
/// thread forever while the tests calling this block the concurrency pool's threads, as
/// on a three-core CI runner.
func race(in group: DispatchGroup, timeout: TimeInterval = 0.3, _ body: @escaping @Sendable () -> Void) {
    group.enter()
    Thread {
        body()
        group.leave()
    }.start()
    _ = group.wait(timeout: .now() + timeout)
}
