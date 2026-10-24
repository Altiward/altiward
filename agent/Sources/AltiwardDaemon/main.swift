// altiward-agent: the Altiward LaunchDaemon.
//
//   altiward-agent [run]          serve XPC, heartbeat and deliver (launchd entry point)
//   altiward-agent heartbeat      take one admin-group reading and persistence snapshot, then deliver
//   altiward-agent flush          deliver queued events once
//   altiward-agent status         print queue depth and open sessions
//   altiward-agent commands       fetch and run remote commands once, then deliver
//   altiward-agent privileges-audit [HOURS]
//                                 print what SAP Privileges' system extension logged in the
//                                 last HOURS (default 24), as the agent reads it (run as root)
//   altiward-agent simulate-hook USER STATE [REASON]
//                                 record a change as if the hook had called (development)
//
// Configuration comes from the com.altiward.agent preference domain (MDM profile) with
// ALTIWARD_SERVER_URL, ALTIWARD_TOKEN, ALTIWARD_DATA_DIR and ALTIWARD_HEARTBEAT_SECONDS
// overrides for local development.

import AltiwardCore
import Foundation

let arguments = Array(CommandLine.arguments.dropFirst())
let command = arguments.first ?? "run"

if command == "privileges-audit" {
    // Needs no configuration and changes nothing.
    let hours = arguments.dropFirst().first.flatMap(Double.init) ?? 24
    let records = PrivilegesAuditLog.records(since: Date().addingTimeInterval(-hours * 3600))
    for r in records {
        let process = r.process.map { "\($0.executable) (\($0.signingID.isEmpty ? "unsigned" : $0.signingID))" } ?? "-"
        print("\(AltiwardJSON.format(r.date))  \(r.eventType)  \(r.subject)  by \(process)")
    }
    if records.isEmpty {
        print("nothing logged: run as root, with SAP Privileges 2.6 or later and its system extension on")
    }
    exit(0)
}

do {
    let configuration = AgentConfiguration.load()
    // A command run beside the daemon can't use a Secure Enclave key the daemon made:
    // such a key works only in the session that made it. With its own data directory
    // (development) no daemon shares the store, so the command holds the key.
    let role: DeviceAuthenticator.Role =
        command == "run" || configuration.dataDirectory != AgentConfiguration.defaultDataDirectory ? .daemon : .command
    let daemon = try Daemon(configuration: configuration, role: role)
    switch command {
    case "run":
        daemon.run()  // never returns
    case "heartbeat":
        try daemon.tracker.heartbeat()
        for event in try daemon.tracker.checkPersistence() {
            print("queued \(event.type.rawValue) \(event.eventID) session \(event.sessionID ?? "-")")
        }
        Daemon.printFlush(await daemon.delivery.flush())
    case "flush":
        Daemon.printFlush(await daemon.delivery.flush())
    case "commands":
        guard let commands = daemon.commands else { throw DeliveryError.notConfigured }
        let s = await commands.poll()
        print("ran \(s.executed), reported \(s.reported)" + (s.error.map { " (\($0))" } ?? ""))
        Daemon.printFlush(await daemon.delivery.flush())
    case "status":
        try await daemon.printStatus()
    case "simulate-hook":
        let invocation = try HookInvocation.parse(arguments: Array(arguments.dropFirst()))
        let event = try daemon.tracker.record(invocation, callerUID: getuid())
        print("queued \(event.type.rawValue) \(event.eventID) session \(event.sessionID ?? "-")")
        try daemon.tracker.checkPersistence()
        Daemon.printFlush(await daemon.delivery.flush())
    default:
        FileHandle.standardError.write(Data("unknown command: \(command)\n".utf8))
        exit(EX_USAGE)
    }
} catch {
    FileHandle.standardError.write(Data("altiward-agent: \(error)\n".utf8))
    exit(EX_SOFTWARE)
}
