import AltiwardCore
import Foundation
import Network
import os

let log = Logger(subsystem: "com.altiward.agent", category: "daemon")

/// Wires the store, tracker and delivery loop to XPC, the network monitor and timers.
final class Daemon: Sendable {
    /// How often the daemon looks for admins nobody granted and for changed settings.
    static let checkInterval: Duration = .seconds(15)

    let configuration: AgentConfiguration
    let store: AgentStore
    let tracker: ElevationTracker
    let delivery: DeliveryLoop
    let authenticator: DeviceAuthenticator?
    let commands: CommandLoop?

    /// `role` says whether this process may use a Secure Enclave key (``DeviceAuthenticator/Role``).
    init(configuration: AgentConfiguration, role: DeviceAuthenticator.Role) throws {
        self.configuration = configuration
        store = try AgentStore.open(directory: configuration.dataDirectory)
        tracker = ElevationTracker(store: store, environment: .live(config: configuration))
        if let url = configuration.serverURL, let token = configuration.enrollmentToken {
            authenticator = DeviceAuthenticator(
                store: store, serverURL: url, enrollmentToken: token, device: { DeviceIdentity.current() }, role: role,
                log: { log.error("\($0, privacy: .public)") })
        } else {
            authenticator = nil
        }
        let sink: any EventSink = authenticator.map(HTTPEventSink.init(authenticator:)) ?? UnconfiguredSink()
        delivery = DeliveryLoop(store: store, sink: sink, log: { log.error("\($0, privacy: .public)") })
        commands = authenticator.map { [store, tracker] in
            CommandLoop(store: store, tracker: tracker, authenticator: $0, log: { log.notice("\($0, privacy: .public)") })
        }
    }

    /// Exits when the settings differ from those the daemon started with, for launchd to
    /// restart it with them (KeepAlive). Everything is built from the settings at startup,
    /// so a profile that arrives after the package, as MDMs often send them, or that changes
    /// later would otherwise wait for a reboot, with events queueing meanwhile. Every event
    /// is already in the store, so exiting loses nothing.
    static func restartIfSettingsChanged(from running: AgentConfiguration) {
        CFPreferencesAppSynchronize(AgentConfiguration.domain as CFString)
        let changed = running.changedSettings(.load())
        guard !changed.isEmpty else { return }
        log.notice("settings changed (\(changed.joined(separator: ", "), privacy: .public)); restarting to apply them")
        exit(0)
    }

    func run() -> Never {
        if configuration.serverURL == nil || configuration.enrollmentToken == nil {
            log.warning("ServerURL or EnrollmentToken not configured; events will queue until they are")
        }
        if configuration.hookCodeRequirement == nil {
            log.warning("HookCodeRequirement not configured; accepting XPC from any local process")
        }

        // Sign-ins by permanent admins that began and ended while the daemon wasn't running.
        // Once, before the checks below, which would otherwise end their rows as "noticed".
        do {
            Self.logPermanentUses(try tracker.catchUpPermanentUses())
        } catch {
            log.error("permanent admin catch-up failed: \(String(describing: error), privacy: .public)")
        }

        let listener = NSXPCListener(machServiceName: altiwardMachServiceName)
        let delegate = ListenerDelegate(
            tracker: tracker, requirement: configuration.hookCodeRequirement,
            onRecorded: { [tracker, delivery] in
                Task {
                    Self.checkPersistence(tracker)
                    await delivery.flush()
                }
            },
            onHeld: { [tracker, delivery] in
                // At once rather than at the next check: a claim held only so Privileges'
                // timer is read after the hook's answer is recorded now, and the log may
                // already back a grant.
                Task {
                    do {
                        let events = try tracker.resolvePendingClaims()
                        Self.logTampers(events)
                        if !events.isEmpty {
                            Self.checkPersistence(tracker)
                            await delivery.flush()
                        }
                    } catch {
                        log.error("resolving a held claim failed: \(String(describing: error), privacy: .public)")
                    }
                }
            })
        listener.delegate = delegate
        listener.resume()

        // Resend as soon as the network comes back, not only on the next elevation.
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [delivery, commands] path in
            guard path.status == .satisfied else { return }
            Task {
                await delivery.resetBackoff()
                await delivery.flush()
                await commands?.poll()
            }
        }
        monitor.start(queue: DispatchQueue(label: "com.altiward.agent.network"))

        let heartbeatInterval = configuration.heartbeatInterval
        Task { [tracker, delivery, commands] in
            while true {
                do {
                    let events = try tracker.heartbeat()
                    Self.logTampers(events)
                    // Sign-ins the scan found, and prompts and screen sharing from the log.
                    Self.logPermanentUses(events.filter { $0.type == .adminPermanentUse })
                    for event in events
                    where event.type == .elevationExpiredEnforced || event.type == .elevationOverdue {
                        var detail = ""
                        if case .string(let error) = event.detail["error"] { detail = " (\(error))" }
                        log.notice(
                            "\(event.type.rawValue, privacy: .public) for \(event.user?.localName ?? "-", privacy: .public), session \(event.sessionID ?? "-", privacy: .public)\(detail, privacy: .public)"
                        )
                    }
                } catch {
                    log.error("heartbeat failed: \(String(describing: error), privacy: .public)")
                }
                Self.checkPersistence(tracker)
                await delivery.flush()
                await commands?.poll()
                try? await Task.sleep(for: .seconds(heartbeatInterval))
            }
        }

        // Raises admins nobody granted and records sign-ins by permanent admins without waiting
        // for the heartbeat, and restarts the agent when its settings change.
        Task { [tracker, delivery, configuration] in
            while true {
                do {
                    let raised = try tracker.checkUntrackedAdmins()
                    for event in raised where event.type == .adminOutOfBand {
                        log.notice("admin.out_of_band for \(event.user?.localName ?? "-", privacy: .public)")
                    }
                    // Held grant claims the log didn't confirm, or accepted without it.
                    Self.logTampers(raised)
                    if !raised.isEmpty {
                        Self.checkPersistence(tracker)
                        await delivery.flush()
                    }
                } catch {
                    log.error("admin check failed: \(String(describing: error), privacy: .public)")
                }
                do {
                    let uses = try tracker.checkPermanentUses()
                    Self.logPermanentUses(uses)
                    if !uses.isEmpty { await delivery.flush() }
                } catch {
                    log.error("permanent admin check failed: \(String(describing: error), privacy: .public)")
                }
                Self.restartIfSettingsChanged(from: configuration)
                try? await Task.sleep(for: Self.checkInterval)
            }
        }

        // Long polls back to back, so a console revoke lands within about a second;
        // CommandPollInterval is the pause after an error or with a server that doesn't hold.
        let pollInterval = configuration.commandPollInterval
        // Whether this Mac's key is due to rotate: checked between long polls, so a rotation
        // rarely waits on one, and at least hourly. The first check is 5 to 65 minutes in.
        let rotation = authenticator.map {
            KeyRotationSchedule(authenticator: $0, log: { log.notice("\($0, privacy: .public)") })
        }
        Task { [rotation] in
            while true {
                try? await Task.sleep(for: .seconds(KeyRotationSchedule.checkInterval))
                await rotation?.checkIfDue()
            }
        }
        Task { [commands, tracker, delivery, rotation] in
            guard let commands else { return }
            while true {
                let started = Date()
                let summary = await commands.poll(wait: CommandLoop.longPollWait)
                // The server answered, so events held back because it couldn't be reached go now.
                if summary.error == nil { await delivery.serverAnswered() }
                await rotation?.checkIfDue()
                // A revoke queues elevation.revoked events; send them straight away.
                if summary.executed > 0 {
                    Self.checkPersistence(tracker)
                    await delivery.flush()
                }
                let pause = CommandLoop.pauseAfterLongPoll(
                    summary, elapsed: Date().timeIntervalSince(started), wait: CommandLoop.longPollWait,
                    interval: pollInterval)
                if pause > 0 { try? await Task.sleep(for: .seconds(pause)) }
            }
        }

        let flushInterval = configuration.flushInterval
        Task { [delivery] in
            while true {
                try? await Task.sleep(for: .seconds(flushInterval))
                await delivery.flush()
            }
        }

        log.info("altiward-agent \(AgentVersion.current, privacy: .public) started")
        withExtendedLifetime((listener, delegate, monitor)) {
            dispatchMain()
        }
    }

    /// One line per `agent.tamper` event among `events`, as `tamper: check=… state=… problem=…`.
    static func logTampers(_ events: [AltiwardEvent]) {
        for event in events where event.type == .agentTamper {
            var what = ""
            for key in ["check", "state", "problem"] {
                if case .string(let s) = event.detail[key] { what += " \(key)=\(s)" }
            }
            log.error("tamper:\(what, privacy: .public)")
        }
    }

    /// One line per `admin.permanent_use` event, as `admin.permanent_use started for
    /// breakglass (ssh, ttys003)`.
    static func logPermanentUses(_ events: [AltiwardEvent]) {
        for event in events {
            var what: [String] = []
            for key in ["method", "tty"] {
                if case .string(let s) = event.detail[key] { what.append(s) }
            }
            var state = ""
            if case .string(let s) = event.detail["state"] { state = " \(s)" }
            log.notice(
                "\(event.type.rawValue, privacy: .public)\(state, privacy: .public) for \(event.user?.localName ?? "-", privacy: .public) (\(what.joined(separator: ", "), privacy: .public))"
            )
        }
    }

    /// Checks for persistence: runs after anything that may have opened or closed a
    /// session, and on the heartbeat. Each finding is in the daemon log as well as in the event.
    static func checkPersistence(_ tracker: ElevationTracker) {
        do {
            for event in try tracker.checkPersistence() {
                guard case .array(let findings) = event.detail["findings"] else { continue }
                let what = findings.compactMap { finding -> String? in
                    guard case .object(let f) = finding, case .string(let kind) = f["kind"] else { return nil }
                    var name = ""
                    for key in ["path", "name", "service"] {
                        if case .string(let s) = f[key] { name = " \(s)"; break }
                    }
                    return kind + name
                }
                log.notice(
                    "persistence.detected for \(event.user?.localName ?? "-", privacy: .public), session \(event.sessionID ?? "-", privacy: .public): \(what.joined(separator: ", "), privacy: .public)"
                )
            }
        } catch {
            log.error("persistence check failed: \(String(describing: error), privacy: .public)")
        }
    }

    func printStatus() async throws {
        print("data directory: \(configuration.dataDirectory.path)")
        print("server: \(configuration.serverURL?.absoluteString ?? "(not configured)")")
        let deviceID = await authenticator?.deviceID
        print("device id: \(deviceID ?? "(not enrolled)")")
        if deviceID != nil, let storage = await authenticator?.keyStorage {
            print("device key: \(storage == .secureEnclave ? "Secure Enclave" : "file")")
        }
        if let since = await authenticator?.rotationPendingSince {
            print("key rotation: in progress since \(AltiwardJSON.format(since))")
        }
        print("queued events: \(try store.pendingCount())")
        let sessions = try store.openSessions()
        print("open sessions: \(sessions.count)")
        for s in sessions {
            let expires = s.expiresAt.map { AltiwardJSON.format($0) } ?? "-"
            print("  \(s.user)  \(s.source.rawValue)  \(s.sessionID)  since \(AltiwardJSON.format(s.startedAt))  expires \(expires)")
        }
        if let check = try tracker.lastPersistenceCheck() {
            let unreadable = check.unreadable.isEmpty ? "none" : check.unreadable.joined(separator: ", ")
            print("persistence snapshot: \(AltiwardJSON.format(check.takenAt)), unreadable: \(unreadable)")
        } else {
            print("persistence snapshot: (none yet)")
        }
    }

    static func printFlush(_ r: FlushResult) {
        var line = "delivered \(r.delivered), rejected \(r.rejected), still queued \(r.remaining)"
        if let error = r.error { line += " (\(error))" }
        print(line)
    }
}

struct UnconfiguredSink: EventSink {
    func send(_ events: [AltiwardEvent]) async throws -> IngestResponse {
        throw DeliveryError.notConfigured
    }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate, Sendable {
    let tracker: ElevationTracker
    let requirement: String?
    let onRecorded: @Sendable () -> Void
    let onHeld: @Sendable () -> Void

    init(
        tracker: ElevationTracker, requirement: String?, onRecorded: @escaping @Sendable () -> Void,
        onHeld: @escaping @Sendable () -> Void
    ) {
        self.tracker = tracker
        self.requirement = requirement
        self.onRecorded = onRecorded
        self.onHeld = onHeld
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        if let requirement {
            // The system rejects messages from callers that do not satisfy the requirement.
            connection.setCodeSigningRequirement(requirement)
        }
        connection.exportedInterface = NSXPCInterface(with: AltiwardAgentXPC.self)
        connection.exportedObject = HookHandler(
            tracker: tracker, callerUID: UInt32(connection.effectiveUserIdentifier), onRecorded: onRecorded,
            onHeld: onHeld)
        connection.resume()
        return true
    }
}

final class HookHandler: NSObject, AltiwardAgentXPC, Sendable {
    let tracker: ElevationTracker
    let callerUID: UInt32
    let onRecorded: @Sendable () -> Void
    let onHeld: @Sendable () -> Void

    init(
        tracker: ElevationTracker, callerUID: UInt32, onRecorded: @escaping @Sendable () -> Void,
        onHeld: @escaping @Sendable () -> Void
    ) {
        self.tracker = tracker
        self.callerUID = callerUID
        self.onRecorded = onRecorded
        self.onHeld = onHeld
    }

    func recordPrivilegeChange(_ payload: Data, withReply reply: @escaping @Sendable (Bool, String?) -> Void) {
        do {
            var invocation = try AltiwardJSON.decoder().decode(HookInvocation.self, from: payload)
            // The caller runs as the user; time the event by the daemon's clock, not theirs.
            invocation.invokedAt = Date()
            switch try tracker.submit(invocation, callerUID: callerUID) {
            case .recorded(let event):
                log.info(
                    "\(event.type.rawValue, privacy: .public) for \(invocation.user, privacy: .public) (uid \(self.callerUID)), session \(event.sessionID ?? "-", privacy: .public)"
                )
                reply(true, nil)
                onRecorded()
            case .pending:
                // Nothing is queued yet: it is resolved after the answer, and by the check loop
                // until Privileges' log confirms or refuses it.
                log.info(
                    "grant claim for \(invocation.user, privacy: .public) held"
                )
                reply(true, nil)
                onHeld()
            }
        } catch {
            log.error("rejected hook payload: \(String(describing: error), privacy: .public)")
            reply(false, String(describing: error))
        }
    }
}
