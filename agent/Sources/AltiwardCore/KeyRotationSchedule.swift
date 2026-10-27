import Foundation

/// Decides when the daemon asks whether this Mac's key is due to rotate, and runs the
/// rotation when it is. The daemon calls ``checkIfDue()`` after each long poll returns and
/// from an hourly task, so a check is never more than an hour away and a rotation rarely
/// waits on a long poll. The first check comes a random 5 to 65 minutes after the daemon
/// starts, so a fleet restarted together doesn't rotate together.
public actor KeyRotationSchedule {
    /// How long after it starts the daemon first checks, in seconds.
    public static let firstCheckDelay: ClosedRange<TimeInterval> = 300...3900
    /// The longest the daemon goes between checks.
    public static let checkInterval: TimeInterval = 3600

    private let due: @Sendable (Date) async throws -> String?
    private let rotate: @Sendable (String) async -> RotationOutcome
    private let now: @Sendable () -> Date
    private let log: @Sendable (String) -> Void
    private var notBefore: Date
    /// Where a deferred rotation waits until. In memory, so a restart may try again sooner;
    /// the server's own 24-hour limit still holds.
    private var deferredUntil: Date?

    public init(
        due: @escaping @Sendable (Date) async throws -> String?,
        rotate: @escaping @Sendable (String) async -> RotationOutcome,
        now: @escaping @Sendable () -> Date = { Date() },
        firstCheckAfter: TimeInterval = .random(in: KeyRotationSchedule.firstCheckDelay),
        log: @escaping @Sendable (String) -> Void = { _ in }
    ) {
        self.due = due
        self.rotate = rotate
        self.now = now
        self.log = log
        notBefore = now().addingTimeInterval(firstCheckAfter)
    }

    public init(
        authenticator: DeviceAuthenticator, now: @escaping @Sendable () -> Date = { Date() },
        firstCheckAfter: TimeInterval = .random(in: KeyRotationSchedule.firstCheckDelay),
        log: @escaping @Sendable (String) -> Void = { _ in }
    ) {
        self.init(
            due: { try await authenticator.rotationDue(now: $0) },
            rotate: { await authenticator.rotate(reason: $0) }, now: now, firstCheckAfter: firstCheckAfter, log: log)
    }

    /// Asks whether the key is due, and rotates it if so. Does nothing before the first check
    /// or while a deferral lasts (the wall clock, so a sleeping Mac counts the time it slept).
    /// Returns what the rotation came to, or nil when none was tried.
    @discardableResult
    public func checkIfDue() async -> RotationOutcome? {
        let t = now()
        if t < notBefore { return nil }
        if let until = deferredUntil, t < until { return nil }
        deferredUntil = nil
        let reason: String?
        do {
            reason = try await due(t)
        } catch {
            log("couldn't tell whether this Mac's key is due to rotate: \(error)")
            return nil
        }
        guard let reason else { return nil }
        let outcome = await rotate(reason)
        if case .deferred(let until) = outcome { deferredUntil = until }
        return outcome
    }
}
