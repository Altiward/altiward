import Foundation

/// Mach service the daemon advertises in its LaunchDaemon plist (`MachServices`).
public let altiwardMachServiceName = "com.altiward.agent.xpc"

/// XPC interface between the hook helper and `altiward-agent`.
///
/// The payload is a JSON-encoded ``HookInvocation``. Passing `Data` keeps the
/// interface trivially secure-coding compatible and versionable.
@objc public protocol AltiwardAgentXPC {
    func recordPrivilegeChange(_ payload: Data, withReply reply: @escaping @Sendable (Bool, String?) -> Void)
}
