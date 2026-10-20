// altiward-agent: the Altiward LaunchDaemon.
//
//   altiward-agent [run]          serve XPC, heartbeat and deliver (launchd entry point)
//   altiward-agent heartbeat      take one admin-group reading and persistence snapshot, then deliver
//   altiward-agent flush          deliver queued events once
//   altiward-agent status         print queue depth and open sessions
//   altiward-agent commands       fetch and run remote commands once, then deliver
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

do {
    let daemon = try Daemon(configuration: .load())
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
