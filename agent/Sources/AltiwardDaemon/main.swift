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
//   altiward-agent permanent-uses [HOURS]
//                                 print the sign-ins, prompts and screen sharing by accounts in
//                                 PermanentAdmins in the last HOURS (default 24), as the agent
//                                 reads them (run as root)
//   altiward-agent simulate-hook USER STATE [REASON]
//                                 send a change as if the hook had called (development); a
//                                 grant is held, as the hook's is, while Privileges' log is
//                                 available
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

if command == "permanent-uses" {
    // Like privileges-audit: no store, no Secure Enclave key, nothing changed.
    let hours = arguments.dropFirst().first.flatMap(Double.init) ?? 24
    let since = Date().addingTimeInterval(-hours * 3600)
    let admins = AgentConfiguration.load().permanentAdmins
    if admins.isEmpty {
        print("PermanentAdmins is empty: no account is watched, so the agent records none of this")
    }

    var lines: [(date: Date, text: String)] = []
    var seen: Set<String> = []
    // Open sign-ins appear in both lists; one line each.
    for r in LoginRecords.history(since: since) + LoginRecords.current() where admins.contains(r.user) {
        guard seen.insert("\(r.tty) \(r.pid) \(r.started.timeIntervalSince1970)").inserted else { continue }
        let host = r.host.isEmpty ? "" : " from \(r.host)"
        let end = r.ended.map { "ended \(AltiwardJSON.format($0))" } ?? "still signed in"
        lines.append((r.started, "\(AltiwardJSON.format(r.started))  sign-in  \(r.user)  tty=\(r.tty)\(host)  \(end)"))
    }
    for case let r? in PermanentUseLog.records(since: since).map({
        $0.resolved(
            admins: admins, fullName: PermanentUseLog.fullName(of:), accountExists: PermanentUseLog.accountExists)
    }) {
        lines.append((r.date, r.summary))
    }
    for line in lines.sorted(by: { $0.date < $1.date }) { print(line.text) }
    if lines.isEmpty {
        print("nothing found: run as root; macOS keeps no log line for sudo, su or SSH file copies, so none is listed")
    }
    exit(0)
}

do {
    let configuration = AgentConfiguration.load()
    // A command run beside the daemon can't use a Secure Enclave key the daemon made:
    // such a key works only in the session that made it, and it must never rotate the key
    // the daemon is using. Only the process launchd started is the daemon. With its own
    // data directory (development) no daemon shares the store, so the command holds the key.
    let role = DeviceAuthenticator.Role.forProcess(
        environment: ProcessInfo.processInfo.environment, dataDirectory: configuration.dataDirectory)
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
        switch try daemon.tracker.submit(invocation, callerUID: getuid()) {
        case .recorded(let event):
            print("queued \(event.type.rawValue) \(event.eventID) session \(event.sessionID ?? "-")")
        case .pending(let claimID):
            print("held claim \(claimID) for Privileges' log")
        }
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
