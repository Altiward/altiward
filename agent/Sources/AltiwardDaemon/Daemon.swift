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
    /// MDM's payloads, in the installed agent; nil in development.
    let managed: ManagedSettings?

    /// Whether this is the installed agent: root, running from Altiward.app. Its settings come
    /// from MDM's payloads, never from `ALTIWARD_*` overrides; anything else is development.
    static var installed: Bool {
        getuid() == 0 && Bundle.main.bundleIdentifier == "com.altiward.agent"
    }

    /// `role` says whether this process may use a Secure Enclave key (``DeviceAuthenticator/Role``).
    /// `store` is the one `managed` was built on, when the installed agent opened it already.
    init(
        configuration: AgentConfiguration, role: DeviceAuthenticator.Role, store: AgentStore? = nil,
        managed: ManagedSettings? = nil
    ) throws {
        self.configuration = configuration
        self.managed = managed
        self.store = try store ?? AgentStore.open(directory: configuration.dataDirectory)
        let store = self.store
        tracker = ElevationTracker(store: store, environment: .live(config: configuration, managed: managed))
        if let url = configuration.serverURL, let token = configuration.enrollmentToken {
            authenticator = DeviceAuthenticator(
                store: store, serverURL: url, enrollmentToken: token, mdmDeviceID: configuration.mdmDeviceID,
                device: { DeviceIdentity.current() }, role: role, log: { log.error("\($0, privacy: .public)") })
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
    ///
    /// In the installed agent the settings are MDM's payloads as last read (by the heartbeat or
    /// the watcher; this never runs `profiles`), once two reads in a row agree.
    static func restartIfSettingsChanged(from running: AgentConfiguration, managed: ManagedSettings?) {
        CFPreferencesAppSynchronize(AgentConfiguration.domain as CFString)
        let changed = ManagedSettings.restartChanges(
            running: running, installed: managed != nil, settled: managed?.settledConfiguration(),
            preferences: { .load() })
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

        // Before anything that makes events, so the first ones have the links on record.
        Self.checkPlatformSSOLinks(tracker)

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

        // A managed preferences file changed: compare the files with MDM's payloads at once,
        // and read the profiles again once the writes stop, not at the next heartbeat.
        let watcher = managed.map { managed in
            ManagedPreferencesWatcher.forSettings(
                tracker: tracker, managed: managed, onEvents: { [tracker, delivery] events in
                    Self.logTampers(events)
                    guard !events.isEmpty else { return }
                    Task {
                        Self.checkPersistence(tracker)
                        await delivery.flush()
                    }
                })
        }
        if let watcher, !watcher.start() {
            log.error("can't watch /Library/Managed Preferences; the heartbeat still checks it")
        }
        // A signed-in user's folder the heartbeat left alone, just after their sign-in, is
        // compared when it is due.
        let followUp: @Sendable () -> Void = { [managed] in
            if let watcher, let due = managed?.takeFollowUp() { watcher.schedule(at: due) }
        }

        let heartbeatInterval = configuration.heartbeatInterval
        Task { [tracker, delivery, commands, followUp] in
            while true {
                do {
                    let events = try tracker.heartbeat()
                    followUp()
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
        Task { [tracker, delivery, configuration, managed] in
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
                Self.restartIfSettingsChanged(from: configuration, managed: managed)
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
            // A cancelled sleep ends the loop rather than checking without a pause.
            while (try? await Task.sleep(for: .seconds(KeyRotationSchedule.checkInterval))) != nil {
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
        withExtendedLifetime((listener, delegate, monitor, watcher)) {
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

    /// Records each account's Platform SSO link and reports what changed: alongside each
    /// persistence check, and once at start.
    static func checkPlatformSSOLinks(_ tracker: ElevationTracker) {
        do {
            logTampers(try tracker.checkPlatformSSOLinks())
        } catch {
            log.error("Platform SSO link check failed: \(String(describing: error), privacy: .public)")
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
        checkPlatformSSOLinks(tracker)
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
        print("settings: \(ManagedSettingsState.sourceDescription(managed?.latest))")
        print("server: \(configuration.serverURL?.absoluteString ?? "(not configured)")")
        let deviceID = await authenticator?.deviceID
        print("device id: \(deviceID ?? "(not enrolled)")")
        if deviceID != nil, let storage = await authenticator?.keyStorage {
            print("device key: \(storage == .secureEnclave ? "Secure Enclave" : "file")")
            // As the console shows the key, so an admin can tell which pending key is this Mac's.
            let fingerprint = await authenticator?.keyFingerprint
            print("key fingerprint: \(fingerprint ?? "(not known until the agent next reports)")")
        }
        if let since = await authenticator?.rotationPendingSince {
            print("key rotation: in progress since \(AltiwardJSON.format(since)); reports wait until the server answers")
            if let last = await authenticator?.rotationLastAnswer {
                print("  last logged \(AltiwardJSON.format(last.at)): \(last.answer)")
            }
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

extension ManagedPreferencesWatcher {
    /// How long to wait before reading the profiles again while MDM's payloads are settling.
    static let recheck: TimeInterval = 30

    /// A watcher for the settings check. On each change it compares the files with the
    /// payloads in use at once (``ManagedSettingsCheck/quick(_:)``); a few seconds after the
    /// last change it reads the profiles and runs the full check, passing on its events. While
    /// the payloads settle (``ManagedSettingsState/needsRecheck(_:since:now:)``) it reads them
    /// again every ``recheck`` seconds, and it runs when a signed-in user's folder is due.
    static func forSettings(
        tracker: ElevationTracker, managed: ManagedSettings, onEvents: @escaping @Sendable ([AltiwardEvent]) -> Void
    ) -> ManagedPreferencesWatcher {
        let check = ManagedSettingsCheck.live(managed)
        let me = OSAllocatedUnfairLock<ManagedPreferencesWatcher?>(initialState: nil)
        /// When the current run of rechecks began.
        let rechecking = OSAllocatedUnfairLock<Date?>(initialState: nil)
        let watcher = ManagedPreferencesWatcher(
            onChange: { check.quick(managed.latest) },
            handler: {
                do {
                    onEvents(try tracker.checkManagedSettings())
                } catch {
                    log.error("settings check failed: \(String(describing: error), privacy: .public)")
                }
                let now = Date()
                let since = rechecking.withLock { $0 ?? now }
                let again = ManagedSettingsState.needsRecheck(managed.latest, since: since, now: now)
                rechecking.withLock { $0 = again ? since : nil }
                let watcher = me.withLock { $0 }
                if again { watcher?.schedule(at: now.addingTimeInterval(recheck)) }
                if let due = managed.takeFollowUp() { watcher?.schedule(at: due) }
            })
        me.withLock { $0 = watcher }
        return watcher
    }
}
