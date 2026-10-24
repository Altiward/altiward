// altiward-hook: set as SAP Privileges' PostChangeExecutablePath.
//
// Privileges runs it as the logged-in user after every privilege change with
// $1 = user, $2 = admin|user, $3 = reason (when PassReasonToExecutable is on).
// It forwards the change to altiward-agent over XPC and exits. It never blocks
// Privileges for long and never fails loudly: if the daemon is unreachable,
// the daemon's admin-group heartbeat still catches the change.

import AltiwardCore
import Foundation
import os

struct HookFailure: Error {
    let message: String
    // The daemon answered and refused the claim, rather than never answering.
    let refused: Bool
    init(_ message: String, refused: Bool = false) {
        self.message = message
        self.refused = refused
    }
}

let log = Logger(subsystem: "com.altiward.agent", category: "hook")
let timeout: TimeInterval = 5

let invocation: HookInvocation
do {
    invocation = try HookInvocation.parse(arguments: Array(CommandLine.arguments.dropFirst()))
} catch {
    log.error("Ignoring invalid invocation: \(error.description, privacy: .public)")
    exit(EX_USAGE)
}

let payload: Data
do {
    payload = try AltiwardJSON.encoder().encode(invocation)
} catch {
    log.error("Could not encode invocation: \(String(describing: error), privacy: .public)")
    exit(EX_SOFTWARE)
}

let connection = NSXPCConnection(machServiceName: altiwardMachServiceName, options: .privileged)
connection.remoteObjectInterface = NSXPCInterface(with: AltiwardAgentXPC.self)
connection.resume()

let done = DispatchSemaphore(value: 0)
let outcome = OSAllocatedUnfairLock<Result<Void, HookFailure>>(
    initialState: .failure(HookFailure("timed out after \(Int(timeout))s")))

let proxy = connection.remoteObjectProxyWithErrorHandler { error in
    outcome.withLock { $0 = .failure(HookFailure("XPC error: \(error.localizedDescription)")) }
    done.signal()
} as? AltiwardAgentXPC

if let proxy {
    proxy.recordPrivilegeChange(payload) { ok, message in
        outcome.withLock {
            $0 = ok ? .success(()) : .failure(HookFailure(message ?? "no reason given", refused: true))
        }
        done.signal()
    }
    _ = done.wait(timeout: .now() + timeout)
} else {
    outcome.withLock { $0 = .failure(HookFailure("could not create XPC proxy")) }
}
connection.invalidate()

switch outcome.withLock({ $0 }) {
case .success:
    log.info("Recorded \(invocation.state.rawValue, privacy: .public) for \(invocation.user, privacy: .public)")
    exit(EX_OK)
case .failure(let failure) where failure.refused:
    log.error("altiward-agent refused the claim: \(failure.message, privacy: .public)")
    exit(EX_NOPERM)
case .failure(let failure):
    log.error("Could not reach altiward-agent: \(failure.message, privacy: .public)")
    exit(EX_UNAVAILABLE)
}
