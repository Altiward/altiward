import Darwin
import Foundation
import Security

extension ProcessIdentity {
    /// The running process `pid`, verified: its code signature, checked against the running
    /// code (not only the file on disk) and bound to its Apple-issued certificate, when it
    /// started, and the uid it runs as. Nil when the process has gone, isn't signed by a
    /// team, its signature doesn't validate, or the pid was reused while it was being read
    /// (the start time and uid are read before and after the signature, and must not
    /// change). Needs root for another user's process, which the daemon has.
    public static func of(pid: Int32) -> ProcessIdentity? {
        guard pid > 0, let before = kernelInfo(of: pid) else { return nil }

        var found: SecCode?
        let attributes = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &found) == errSecSuccess, let code = found else {
            return nil
        }
        // A first check of the dynamic code: the running process's signature must be valid.
        guard SecCodeCheckValidity(code, [], nil) == errSecSuccess else { return nil }

        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
            SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
                == errSecSuccess,
            let info = information as? [String: Any],
            let signingID = info[kSecCodeInfoIdentifier as String] as? String,
            let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String,
            let requirement = requirement(signingID: signingID, teamID: teamID)
        else { return nil }

        // The identifier and team just read are claims of the signature itself until a
        // requirement ties them to a certificate Apple issued to that team, checked again
        // against the running code.
        var compiled: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess,
            let compiled, SecCodeCheckValidity(code, [], compiled) == errSecSuccess
        else { return nil }

        guard let after = kernelInfo(of: pid), after == before else { return nil }
        return ProcessIdentity(signingID: signingID, teamID: teamID, startedAt: before.startedAt, uid: before.uid)
    }

    /// A code requirement that holds only for code with this identifier, signed by a
    /// certificate Apple issued to this team; nil when either value can't be written into
    /// one safely.
    static func requirement(signingID: String, teamID: String) -> String? {
        let teamCharacters = CharacterSet.uppercaseLetters.union(.decimalDigits)
        let idCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
        guard !teamID.isEmpty, teamID.unicodeScalars.allSatisfy({ $0.isASCII && teamCharacters.contains($0) }),
            !signingID.isEmpty, signingID.unicodeScalars.allSatisfy({ $0.isASCII && idCharacters.contains($0) })
        else { return nil }
        return #"identifier "\#(signingID)" and anchor apple generic and certificate leaf[subject.OU] = "\#(teamID)""#
    }

    /// When the process started and the uid it runs as (`pbi_uid`), from one read of the
    /// kernel's record of it; nil when it has gone.
    static func kernelInfo(of pid: Int32) -> (startedAt: Date, uid: UInt32)? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        let started = Date(
            timeIntervalSince1970: Double(info.pbi_start_tvsec) + Double(info.pbi_start_tvusec) / 1_000_000)
        return (started, info.pbi_uid)
    }

    /// The uid of the account with this short name, from the directory; nil when there is
    /// none.
    public static func uid(of shortName: String) -> UInt32? {
        guard let entry = getpwnam(shortName) else { return nil }
        return entry.pointee.pw_uid
    }
}

/// Finds SAP Privileges' system extension in the process table.
public enum PrivilegesExtensionProcess {
    static let directory = "/Library/SystemExtensions/"
    static let executableSuffix = "/corp.sap.privileges.extension"

    /// The pid of the running extension, or nil when none is running. macOS runs a system
    /// extension from its own copy under `/Library/SystemExtensions/<UUID>/`, so the
    /// executable's path is matched there. The match only finds the process: whether it is
    /// SAP's is for ``ProcessIdentity/of(pid:)`` to say.
    public static func pid() -> Int32? {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return nil }
        // Room for processes started between the two calls.
        var pids = [pid_t](repeating: 0, count: Int(count) + 32)
        let filled = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        guard filled > 0 else { return nil }
        var path = [UInt8](repeating: 0, count: Int(MAXPATHLEN) * 4)
        for pid in pids.prefix(Int(filled)) where pid > 0 {
            let length = proc_pidpath(pid, &path, UInt32(path.count))
            guard length > 0 else { continue }
            let executable = String(decoding: path.prefix(Int(length)), as: UTF8.self)
            if executable.hasPrefix(directory), executable.hasSuffix(executableSuffix) { return pid }
        }
        return nil
    }

    /// What is wrong with the extension the process table shows, as the end of a sentence
    /// ("isn't running", "isn't signed by SAP"), or nil when SAP's extension is running.
    static func problem(pid: Int32?, identity: (Int32) -> ProcessIdentity?) -> String? {
        guard let pid else { return "isn't running" }
        guard let found = identity(pid), found.isPrivilegesExtension else { return "isn't signed by SAP" }
        return nil
    }

    /// ``problem(pid:identity:)`` for the running system.
    public static func problem() -> String? {
        problem(pid: pid(), identity: ProcessIdentity.of(pid:))
    }
}

extension PrivilegesLogAvailability {
    /// The oldest SAP Privileges whose system extension writes the audit records.
    static let minimumPrivileges = [2, 6, 0]
    /// The oldest macOS Privileges runs its system extension on.
    static let minimumMacOS = 14

    /// Whether Privileges' log can be read on this Mac now.
    public static func current() -> PrivilegesLogAvailability {
        decide(
            privilegesVersion: DeviceIdentity.privilegesVersion(),
            osMajor: ProcessInfo.processInfo.operatingSystemVersion.majorVersion,
            extensionPID: PrivilegesExtensionProcess.pid(), identity: ProcessIdentity.of(pid:))
    }

    /// The log is available with SAP Privileges 2.6.0 or later on macOS 14 or later, while
    /// its system extension runs, as root, and is signed by SAP; otherwise unavailable, with the first
    /// reason that applies. Versions compare numerically by component, so 2.10.0 is later
    /// than 2.6.0.
    public static func decide(
        privilegesVersion: String?, osMajor: Int, extensionPID: Int32?, identity: (Int32) -> ProcessIdentity?
    ) -> PrivilegesLogAvailability {
        guard let privilegesVersion else { return .unavailable("SAP Privileges isn't installed") }
        guard isAtLeast(privilegesVersion, minimumPrivileges) else {
            return .unavailable("SAP Privileges \(privilegesVersion) is older than 2.6.0")
        }
        guard osMajor >= minimumMacOS else { return .unavailable("macOS \(osMajor) is older than \(minimumMacOS)") }
        if let problem = PrivilegesExtensionProcess.problem(pid: extensionPID, identity: identity) {
            return .unavailable("Privileges' system extension \(problem)")
        }
        return .available
    }

    /// Whether `version` is at least `minimum`, comparing each dot-separated component as a
    /// number (its leading digits; a missing component counts as 0). A version with no number
    /// at all isn't.
    static func isAtLeast(_ version: String, _ minimum: [Int]) -> Bool {
        let parts = version.split(separator: ".", omittingEmptySubsequences: false).map { part in
            Int(part.prefix { $0.isASCII && $0.isNumber })
        }
        guard let first = parts.first, first != nil else { return false }
        let numbers = parts.map { $0 ?? 0 }
        for i in 0..<max(numbers.count, minimum.count) {
            let have = i < numbers.count ? numbers[i] : 0
            let need = i < minimum.count ? minimum[i] : 0
            if have != need { return have > need }
        }
        return true
    }
}
