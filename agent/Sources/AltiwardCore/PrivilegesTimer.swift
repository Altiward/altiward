import Darwin
import Foundation

/// The expiry SAP Privileges set for a user's current grant. When nothing managed fixes the
/// duration, the user picks it in Privileges, and only Privileges' agent knows it: it keeps
/// it as `TimerExpires` in the user's `corp.sap.privileges.agent` preferences, and removes it
/// when the rights go.
///
/// It is read through the user's own preferences service, as that user with `defaults`:
/// the preferences file on disk can lag the value by several seconds, and the hook runs
/// as soon as Privileges sets it.
///
/// The preference belongs to the user, so its value is only Privileges' claim: a managed
/// `ExpirationIntervalMax` still caps it (``PrivilegesSettings/expiry(grantedAt:timer:)``).
public enum PrivilegesTimer {
    static let domain = "corp.sap.privileges.agent"
    static let key = "TimerExpires"
    static let maxOutput = 256
    static let readTimeout: TimeInterval = 2

    /// Waits briefly for Privileges to record the timer of a grant made at `grantedAt`, in
    /// case the hook runs before Privileges' agent sets it. Nil when no timer later than
    /// `grantedAt` appears.
    public static func wait(
        user: String, grantedAt: Date, attempts: Int = 8, pause: TimeInterval = 0.25
    ) -> Date? {
        guard let uid = uid(of: user) else { return nil }
        for attempt in 0..<attempts {
            if attempt > 0 { Thread.sleep(forTimeInterval: pause) }
            if let expires = read(user: user, uid: uid), expires > grantedAt { return expires }
        }
        return nil
    }

    /// `defaults read` run in the user's session and as the user, so it asks their
    /// preferences service rather than reading root's preferences or a stale file.
    static func read(user: String, uid: uid_t) -> Date? {
        let output = run(
            "/bin/launchctl",
            ["asuser", String(uid), "/usr/bin/sudo", "-n", "-u", user, "/usr/bin/defaults", "read", domain, key])
        return output.flatMap(parse)
    }

    /// The date `defaults read` prints, such as `2026-10-17 18:53:30 +0000`.
    static func parse(_ output: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
        return formatter.date(from: output.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// A command's output when it exits 0 within ``readTimeout`` and prints no more than
    /// ``maxOutput`` bytes. The value is the user's, so a slow or large one counts as none.
    static func run(_ executable: String, _ arguments: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        do {
            try process.run()
        } catch {
            return nil
        }
        guard exited.wait(timeout: .now() + readTimeout) == .success else {
            process.terminate()
            return nil
        }
        guard process.terminationStatus == 0,
            let data = try? output.fileHandleForReading.read(upToCount: maxOutput + 1), data.count <= maxOutput
        else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    static func uid(of user: String) -> uid_t? {
        directoryLock.lock()
        defer { directoryLock.unlock() }
        return getpwnam(user).map { $0.pointee.pw_uid }
    }
}
