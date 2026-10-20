import Foundation

/// The API's per-event verdicts for one batch. Events in any list are done with:
/// accepted and duplicate are stored server-side; rejected ones will never be accepted,
/// so retrying them would block the queue forever.
public struct IngestResponse: Codable, Sendable, Equatable {
    public struct Rejection: Codable, Sendable, Equatable {
        public var eventID: String
        public var error: String

        public init(eventID: String, error: String) {
            self.eventID = eventID
            self.error = error
        }

        enum CodingKeys: String, CodingKey {
            case eventID = "event_id"
            case error
        }
    }

    public var accepted: [String]
    public var duplicate: [String]
    public var rejected: [Rejection]

    public init(accepted: [String] = [], duplicate: [String] = [], rejected: [Rejection] = []) {
        self.accepted = accepted
        self.duplicate = duplicate
        self.rejected = rejected
    }
}

public protocol EventSink: Sendable {
    func send(_ events: [AltiwardEvent]) async throws -> IngestResponse
}

public enum DeliveryError: Error, Equatable, CustomStringConvertible {
    case notConfigured
    case http(status: Int, body: String)
    /// The server no longer accepts this Mac's credential; it was discarded and the
    /// next delivery enrolls again.
    case credentialInvalid
    /// This Mac's re-enrollment is waiting for approval in the console.
    case enrollmentPending

    public var description: String {
        switch self {
        case .notConfigured: "no server URL or enrollment token configured"
        case .http(let status, let body): "HTTP \(status): \(body.prefix(200))"
        case .credentialInvalid: "device credential rejected; will enroll again"
        case .enrollmentPending: "re-enrollment awaiting approval in the console"
        }
    }
}

/// Posts batches to `POST {server}/v1/agent/events`, signed with the device credential.
public struct HTTPEventSink: EventSink {
    private let authenticator: DeviceAuthenticator

    public init(authenticator: DeviceAuthenticator) {
        self.authenticator = authenticator
    }

    public func send(_ events: [AltiwardEvent]) async throws -> IngestResponse {
        let body = try AltiwardJSON.encoder().encode(["events": events])
        let (data, response) = try await authenticator.send(method: "POST", path: "v1/agent/events", body: body)
        let status = response.statusCode
        guard status == 200 else {
            throw DeliveryError.http(status: status, body: String(decoding: data, as: UTF8.self))
        }
        return try AltiwardJSON.decoder().decode(IngestResponse.self, from: data)
    }
}

public struct FlushResult: Sendable, Equatable {
    public var delivered = 0
    public var rejected = 0
    public var remaining = 0
    public var error: String?
}

/// Drains the outbox oldest-first. Triggered on enqueue, on network reachability
/// changes and on a timer; failures back off exponentially but never drop events.
public actor DeliveryLoop {
    private let store: AgentStore
    private let sink: any EventSink
    private let batchSize: Int
    private let delayedThreshold: TimeInterval
    private let now: @Sendable () -> Date
    private let log: @Sendable (String) -> Void

    private var flushing = false
    private var rerun = false
    private var consecutiveFailures = 0
    private var retryNotBefore: Date?

    public init(
        store: AgentStore,
        sink: any EventSink,
        batchSize: Int = 100,
        delayedThreshold: TimeInterval = 60,
        now: @escaping @Sendable () -> Date = { Date() },
        log: @escaping @Sendable (String) -> Void = { _ in }
    ) {
        self.store = store
        self.sink = sink
        self.batchSize = batchSize
        self.delayedThreshold = delayedThreshold
        self.now = now
        self.log = log
    }

    /// Clears any backoff, e.g. when the network comes back.
    public func resetBackoff() {
        consecutiveFailures = 0
        retryNotBefore = nil
    }

    /// Sends until the outbox is empty or a send fails. Concurrent calls coalesce:
    /// a call made while a flush is running schedules one more pass instead of racing it.
    @discardableResult
    public func flush() async -> FlushResult {
        if flushing {
            rerun = true
            return FlushResult(remaining: (try? store.pendingCount()) ?? 0)
        }
        if let notBefore = retryNotBefore, now() < notBefore {
            return FlushResult(remaining: (try? store.pendingCount()) ?? 0, error: "backing off")
        }
        flushing = true
        defer { flushing = false }

        var result = FlushResult()
        repeat {
            rerun = false
            do {
                while true {
                    let batch = try store.pending(limit: batchSize)
                    if batch.isEmpty { break }
                    try await send(batch, into: &result)
                }
                resetBackoff()
            } catch {
                consecutiveFailures += 1
                let delay = min(3600, 15 * pow(2, Double(min(consecutiveFailures - 1, 8))))
                retryNotBefore = now().addingTimeInterval(delay)
                result.error = String(describing: error)
                log("delivery failed (attempt \(consecutiveFailures), retry in \(Int(delay))s): \(error)")
                break
            }
        } while rerun
        result.remaining = (try? store.pendingCount()) ?? 0
        return result
    }

    private func send(_ batch: [QueuedEvent], into result: inout FlushResult) async throws {
        let sentAt = now()
        let events = batch.map { queued -> AltiwardEvent in
            var event = queued.event
            // Mirrors Privileges' `delayed` flag: true when the event sat in the queue.
            event.delayed = event.delayed || sentAt.timeIntervalSince(event.timestamp) > delayedThreshold
            return event
        }
        do {
            let response = try await sink.send(events)
            let done = Set(response.accepted + response.duplicate + response.rejected.map(\.eventID))
            for r in response.rejected {
                log("server rejected event \(r.eventID): \(r.error)")
            }
            let finished = batch.filter { done.contains($0.event.eventID) }.map(\.seq)
            try store.remove(seqs: finished)
            result.delivered += response.accepted.count + response.duplicate.count
            result.rejected += response.rejected.count
            if finished.count < batch.count {
                // The server skipped some events; leave them queued and retry later.
                throw DeliveryError.http(status: 200, body: "server acknowledged \(finished.count) of \(batch.count) events")
            }
        } catch {
            try? store.recordFailure(seqs: batch.map(\.seq), error: String(describing: error))
            throw error
        }
    }
}
