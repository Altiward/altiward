import Darwin
import Darwin.membership
import Foundation

/// Reads who actually holds admin rights, independent of what Privileges reports.
public protocol AdminMembershipReading: Sendable {
    /// Whether `user` is a member of the local `admin` group, including nested groups.
    func isAdmin(user: String) -> Bool
    /// Every human account (UID >= 500, not `_`-prefixed) that is currently an admin.
    func adminMembers() -> Set<String>
}

/// Changes admin-group membership. Only the root daemon can do this.
public protocol AdminGroupEditing: Sendable {
    /// Removes `user`'s direct membership of the local `admin` group.
    func removeAdmin(user: String) throws
}

/// Uses the membership APIs (`mbr_check_membership`), which resolve nested groups
/// the way the system does, rather than just reading `GroupMembership`.
public struct SystemAdminGroup: AdminMembershipReading {
    public init() {}

    public func isAdmin(user: String) -> Bool {
        isMember(user: user, group: "admin")
    }

    /// Whether `user` is a member of the local group `group`, including nested groups.
    /// An unknown user or group is not a member.
    public func isMember(user: String, group: String) -> Bool {
        var userUUID = uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        var groupUUID = userUUID
        guard Self.uuid(type: ID_TYPE_USERNAME, name: user, into: &userUUID),
            Self.uuid(type: ID_TYPE_GROUPNAME, name: group, into: &groupUUID)
        else { return false }
        var member: Int32 = 0
        let rc = withUnsafePointer(to: &userUUID) { u in
            withUnsafePointer(to: &groupUUID) { g in
                u.withMemoryRebound(to: UInt8.self, capacity: 16) { up in
                    g.withMemoryRebound(to: UInt8.self, capacity: 16) { gp in
                        mbr_check_membership(up, gp, &member)
                    }
                }
            }
        }
        return rc == 0 && member != 0
    }

    public func adminMembers() -> Set<String> {
        Set(Self.humanAccounts().filter(isAdmin(user:)))
    }

    private static func uuid(type: Int32, name: String, into out: inout uuid_t) -> Bool {
        name.withCString { cName in
            withUnsafeMutablePointer(to: &out) { p in
                p.withMemoryRebound(to: UInt8.self, capacity: 16) { up in
                    mbr_identifier_to_uuid(type, cName, strlen(cName), up) == 0
                }
            }
        }
    }

    /// Local human accounts plus any direct members listed on the admin group.
    static func humanAccounts() -> Set<String> {
        var names = Set<String>()
        // getpwent/getgrnam are not thread-safe; serialise through a global lock.
        directoryLock.lock()
        defer { directoryLock.unlock() }
        setpwent()
        while let pw = getpwent() {
            let name = String(cString: pw.pointee.pw_name)
            if pw.pointee.pw_uid >= 500, !name.hasPrefix("_") { names.insert(name) }
        }
        endpwent()
        if let gr = getgrnam("admin"), var member = gr.pointee.gr_mem {
            while let m = member.pointee {
                let name = String(cString: m)
                if !name.hasPrefix("_"), name != "root" { names.insert(name) }
                member = member.advanced(by: 1)
            }
        }
        return names
    }
}

let directoryLock = NSLock()

extension SystemAdminGroup: AdminGroupEditing {
    public struct EditFailed: Error, CustomStringConvertible {
        public let status: Int32
        public let output: String
        public var description: String { "dseditgroup exited \(status): \(output)" }
    }

    /// Edits the local directory node with `dseditgroup`, as admins do by hand. The caller
    /// re-reads membership afterwards, more than once, because membership reads can lag
    /// the edit for a moment.
    public func removeAdmin(user: String) throws {
        try editAdminGroup(flag: "-d", user: user)
    }

    private func editAdminGroup(flag: String, user: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/dseditgroup")
        process.arguments = ["-o", "edit", flag, user, "-t", "user", "admin"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw EditFailed(
                status: process.terminationStatus,
                output: String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
}
