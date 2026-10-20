import Darwin

/// Whether a user's SAP Privileges agent is running. It runs their admin timer, so someone
/// who stops it (`launchctl bootout gui/<uid>/corp.sap.privileges.agent`) keeps rights
/// Privileges would have removed. Read from the process table, which the daemon sees for
/// every user.
public enum PrivilegesAgentProcess {
    /// Nil when the user isn't logged in (no `loginwindow` of theirs, as the package's
    /// preinstall also tests), so no agent should be running.
    public static func running(user: String) -> Bool? {
        guard let entry = getpwnam(user) else { return nil }
        let names = commands(uid: entry.pointee.pw_uid)
        guard names.contains("loginwindow") else { return nil }
        return names.contains("PrivilegesAgent")
    }

    /// The command names (up to 16 characters) of the processes running as `uid`.
    static func commands(uid: uid_t) -> Set<String> {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_UID, Int32(bitPattern: uid)]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        // Room for processes started between the two calls.
        var processes = [kinfo_proc](repeating: kinfo_proc(), count: size / MemoryLayout<kinfo_proc>.stride + 16)
        size = processes.count * MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, 4, &processes, &size, nil, 0) == 0 else { return [] }
        return Set(
            processes.prefix(size / MemoryLayout<kinfo_proc>.stride).map { process in
                withUnsafeBytes(of: process.kp_proc.p_comm) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
            })
    }
}
