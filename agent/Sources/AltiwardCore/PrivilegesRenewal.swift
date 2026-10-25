import Foundation
import os

private let log = Logger(subsystem: "com.altiward.agent", category: "renewals")

/// A renewal that SAP Privileges' per-user agent logged. Privileges sends no hook claim for a
/// renewal (#90), so this line is the only trace of one. `PrivilegesAgent` runs as the user,
/// who could log a line under its name, so a line counts only when the tracker matches it to
/// SAP's genuine agent (``ElevationTracker/verifiedRenewals(_:)``).
public struct PrivilegesRenewalLine: Sendable, Equatable {
    public var date: Date
    public var user: String
    public var minutes: Int
    /// The process that logged it and the uid it ran as.
    public var pid: Int32
    public var uid: UInt32
    /// The UUID of the executable that logged it, as the log recorded it then. A process
    /// keeps its pid when it execs another binary, but a line keeps the image it came from.
    public var imageUUID: String

    public init(date: Date, user: String, minutes: Int, pid: Int32, uid: UInt32, imageUUID: String) {
        self.date = date
        self.user = user
        self.minutes = minutes
        self.pid = pid
        self.uid = uid
        self.imageUUID = imageUUID
    }

    static let prefix = "SAPCorp: Administrator privileges for user "

    /// The user and minutes in `SAPCorp: Administrator privileges for user jdoe have been
    /// renewed (60 minutes)`; nil for any other line.
    static func parse(message: String) -> (user: String, minutes: Int)? {
        guard message.hasPrefix(prefix), message.hasSuffix(" minutes)") else { return nil }
        let rest = message.dropFirst(prefix.count).dropLast(" minutes)".count)
        guard let have = rest.range(of: " have been renewed (") else { return nil }
        let user = String(rest[..<have.lowerBound])
        guard !user.isEmpty, !user.contains(" "), let minutes = Int(rest[have.upperBound...]), minutes > 0 else {
            return nil
        }
        return (user, minutes)
    }
}

/// Reads `PrivilegesAgent`'s renewal lines with `log show`: the log store's API doesn't say
/// which executable logged a line, and only that tells SAP's agent from a user's copy.
public enum PrivilegesAgentLog {
    static let executable = "/Applications/Privileges.app/Contents/MacOS/PrivilegesAgent.app/Contents/MacOS/PrivilegesAgent"
    static let readTimeout: TimeInterval = 30
    static let maxOutput = 4 << 20

    /// Renewal lines logged since `since`, oldest first. Empty when the log can't be read.
    public static func renewals(since: Date) -> [PrivilegesRenewalLine] {
        let start = DateFormatter()
        start.locale = Locale(identifier: "en_US_POSIX")
        start.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let predicate = "process == \"PrivilegesAgent\" AND eventMessage BEGINSWITH \"\(PrivilegesRenewalLine.prefix)\""
        guard
            let output = CommandOutput.run(
                "/usr/bin/log",
                ["show", "--style", "ndjson", "--start", start.string(from: since), "--predicate", predicate],
                timeout: readTimeout, maxBytes: maxOutput)
        else {
            log.error("couldn't read PrivilegesAgent's renewals from the unified log")
            return []
        }
        return parse(ndjson: output).filter { $0.date >= since }
    }

    /// One line per JSON object `log show --style ndjson` printed; anything else is skipped.
    static func parse(ndjson: Data) -> [PrivilegesRenewalLine] {
        let timestamp = DateFormatter()
        timestamp.locale = Locale(identifier: "en_US_POSIX")
        timestamp.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSZ"
        return ndjson.split(separator: UInt8(ascii: "\n")).compactMap { row -> PrivilegesRenewalLine? in
            guard let entry = try? JSONSerialization.jsonObject(with: Data(row)) as? [String: Any],
                let message = entry["eventMessage"] as? String,
                let (user, minutes) = PrivilegesRenewalLine.parse(message: message),
                let time = entry["timestamp"] as? String, let date = timestamp.date(from: time),
                let pid = entry["processID"] as? Int, let uid = entry["userID"] as? Int,
                let image = entry["processImageUUID"] as? String
            else { return nil }
            return PrivilegesRenewalLine(
                date: date, user: user, minutes: minutes, pid: Int32(pid), uid: UInt32(uid), imageUUID: image)
        }
        .sorted { $0.date < $1.date }
    }
}

/// The UUIDs a Mach-O executable carries (`LC_UUID`), one for each architecture of a
/// universal binary, in the form the unified log prints them.
enum MachOImage {
    static func uuids(atPath path: String) -> Set<String> {
        FileManager.default.contents(atPath: path).map(uuids(in:)) ?? []
    }

    static func uuids(in data: Data) -> Set<String> {
        let bytes = [UInt8](data)
        func uint32(_ offset: Int, bigEndian: Bool) -> Int? {
            guard offset >= 0, offset + 4 <= bytes.count else { return nil }
            let b = Array(bytes[offset..<offset + 4])
            return (bigEndian ? b : b.reversed()).reduce(0) { $0 << 8 | Int($1) }
        }
        func uint64(_ offset: Int) -> Int? {
            guard let high = uint32(offset, bigEndian: true), let low = uint32(offset + 4, bigEndian: true) else {
                return nil
            }
            return high << 32 | low
        }
        // One architecture: its load commands, for LC_UUID.
        func slice(_ base: Int) -> String? {
            guard let magic = uint32(base, bigEndian: false), magic == 0xFEED_FACF || magic == 0xFEED_FACE,
                let count = uint32(base + 16, bigEndian: false)
            else { return nil }
            var offset = base + (magic == 0xFEED_FACF ? 32 : 28)
            for _ in 0..<min(count, 10_000) {
                guard let cmd = uint32(offset, bigEndian: false), let size = uint32(offset + 4, bigEndian: false),
                    size >= 8
                else { return nil }
                if cmd == 0x1B, offset + 24 <= bytes.count {  // LC_UUID
                    return NSUUID(uuidBytes: Array(bytes[offset + 8..<offset + 24])).uuidString
                }
                offset += size
            }
            return nil
        }
        switch uint32(0, bigEndian: true) {
        case 0xCAFE_BABE?, 0xCAFE_BABF?:  // universal: fat_arch, or fat_arch_64
            let wide = uint32(0, bigEndian: true) == 0xCAFE_BABF
            let count = min(uint32(4, bigEndian: true) ?? 0, 64)
            return Set(
                (0..<count).compactMap { i in
                    let entry = 8 + i * (wide ? 32 : 20)
                    return (wide ? uint64(entry + 8) : uint32(entry + 8, bigEndian: true)).flatMap(slice)
                })
        default:
            return slice(0).map { [$0] } ?? []
        }
    }
}

/// A command's standard output when it exits 0 within `timeout` and prints no more than
/// `maxBytes`; nil otherwise. The output is read while the command runs, so a large one
/// can't fill the pipe and stall it.
enum CommandOutput {
    static func run(_ executable: String, _ arguments: [String], timeout: TimeInterval, maxBytes: Int) -> Data? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return nil
        }
        let output = OSAllocatedUnfairLock(initialState: Data())
        let read = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            output.withLock { $0 = data }
            read.signal()
        }
        guard read.wait(timeout: .now() + timeout) == .success else {
            process.terminate()
            return nil
        }
        process.waitUntilExit()
        let data = output.withLock { $0 }
        guard process.terminationStatus == 0, data.count <= maxBytes else { return nil }
        return data
    }
}

/// Renewals: a renewal moves a Privileges session's expiry, so expiry enforcement doesn't
/// remove renewed rights at the old one (#90).
extension ElevationTracker {
    static let renewalCursorKey = "privileges_renewals_read_until"
    /// Read again on the next heartbeat, in case the log was still catching up.
    static let renewalOverlap: TimeInterval = 60

    /// Renewal lines for this heartbeat, read outside its transaction. Not read at all while
    /// MDM turns renewals off, as no real renewal can happen then, nor while no Privileges
    /// session is open, as there is nothing to renew. Only lines from SAP's agent are returned.
    func renewalsToApply(_ settings: PrivilegesSettings, now: Date) throws -> [PrivilegesRenewalLine] {
        guard settings.allowPrivilegeRenewal != false || settings.autoRenewalConfigured,
            try store.openSessions().contains(where: { $0.source == .privileges })
        else { return [] }
        let lookback = now.addingTimeInterval(-(env.config.heartbeatInterval + 10 * 60))
        let cursor = try store.value(forKey: Self.renewalCursorKey).flatMap(AltiwardJSON.parse)
        let since = max(lookback, cursor.map { $0.addingTimeInterval(-Self.renewalOverlap) } ?? lookback)
        let lines = env.privilegesRenewals(since)
        try store.setValue(AltiwardJSON.format(now), forKey: Self.renewalCursorKey)
        return verifiedRenewals(lines)
    }

    /// The lines SAP's agent logged about its own user: the logged executable is SAP's on
    /// disk, and the process is SAP's signed agent, running as the user the line names and
    /// started before the line. A line whose process has gone can't be checked, so it is
    /// left out and the session keeps its expiry.
    func verifiedRenewals(_ lines: [PrivilegesRenewalLine]) -> [PrivilegesRenewalLine] {
        guard !lines.isEmpty else { return [] }
        let genuine = env.privilegesAgentImageUUIDs()
        return lines.filter { line in
            let identity = env.processIdentity(line.pid)
            let ok =
                genuine.contains(line.imageUUID) && env.userID(line.user) == line.uid
                && identity?.signingID == PrivilegesSigning.agent && identity?.teamID == PrivilegesSigning.teamID
                && identity?.uid == line.uid && (identity?.startedAt).map { $0 <= line.date } == true
            if !ok {
                log.notice(
                    "ignoring a Privileges renewal for \(line.user, privacy: .public): not logged by SAP's agent, or its process has gone (pid \(line.pid))"
                )
            }
            return ok
        }
    }

    /// Moves the expiry of each renewed Privileges session the user still holds, inside the
    /// heartbeat's transaction and before expiry is enforced, and returns an
    /// `elevation.granted` (`renewed`) for each. The new expiry is the renewal's time plus
    /// its minutes, capped by `ExpirationIntervalMax`. It only ever moves later, so a line
    /// read twice changes nothing.
    func applyRenewals(
        _ lines: [PrivilegesRenewalLine], admins: Set<String>, settings: PrivilegesSettings, device: DeviceInfo
    ) throws -> [AltiwardEvent] {
        var events: [AltiwardEvent] = []
        for line in lines where admins.contains(line.user) {
            guard let open = try store.openSession(user: line.user), open.source == .privileges,
                line.date >= open.startedAt, let current = open.expiresAt
            else { continue }
            var expires = line.date.addingTimeInterval(TimeInterval(line.minutes * 60))
            var basis = "PrivilegesRenewal"
            if let max = settings.expirationIntervalMaxMinutes, max > 0,
                line.date.addingTimeInterval(TimeInterval(max * 60)) < expires
            {
                expires = line.date.addingTimeInterval(TimeInterval(max * 60))
                basis = "ExpirationIntervalMax"
            }
            guard expires > current else { continue }
            try store.upsertOpenSession(
                OpenSession(
                    user: open.user, sessionID: open.sessionID, source: open.source, startedAt: open.startedAt,
                    expiresAt: expires))
            events.append(
                AltiwardEvent(
                    type: .elevationGranted, sessionID: open.sessionID, timestamp: line.date, device: device,
                    user: UserInfo(localName: line.user, upn: env.config.upn(for: line.user)),
                    elevation: ElevationInfo(expires: expires, source: .privileges),
                    detail: [
                        "trigger": "privileges_renewal", "renewed": true, "observed_admin": true, "verified": true,
                        "expires_basis": .string(basis), "renewed_minutes": .number(Double(line.minutes)),
                    ]))
        }
        return events
    }
}
