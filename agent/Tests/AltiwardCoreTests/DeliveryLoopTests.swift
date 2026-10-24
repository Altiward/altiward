import Foundation
import Testing
import os

@testable import AltiwardCore

/// Records what it was sent; fails, can't be reached or rejects on request.
final class FakeSink: EventSink, Sendable {
    enum Mode: Sendable { case accept, fail, unreachable, rejectAll, ignoreAll }

    private let state = OSAllocatedUnfairLock<(mode: Mode, batches: [[AltiwardEvent]])>(
        initialState: (.accept, []))

    func setMode(_ mode: Mode) { state.withLock { $0.mode = mode } }
    var batches: [[AltiwardEvent]] { state.withLock { $0.batches } }

    func send(_ events: [AltiwardEvent]) async throws -> IngestResponse {
        let mode = state.withLock { s in
            s.batches.append(events)
            return s.mode
        }
        switch mode {
        case .accept: return IngestResponse(accepted: events.map(\.eventID))
        case .fail: throw DeliveryError.http(status: 503, body: "unavailable")
        case .unreachable: throw URLError(.timedOut)
        case .rejectAll:
            return IngestResponse(rejected: events.map { .init(eventID: $0.eventID, error: "invalid") })
        case .ignoreAll: return IngestResponse()
        }
    }
}

struct DeliveryLoopTests {
    let clock = TestClock()

    @Test func drainsInOrderedBatches() async throws {
        let store = try makeStore()
        let ids = (0..<5).map { _ in newID() }
        for id in ids { try store.enqueue(sampleEvent(id: id, at: clock.now)) }
        let sink = FakeSink()
        let loop = DeliveryLoop(store: store, sink: sink, batchSize: 2, now: { clock.now })

        let result = await loop.flush()
        #expect(result == FlushResult(delivered: 5, rejected: 0, remaining: 0, error: nil))
        #expect(sink.batches.map(\.count) == [2, 2, 1])
        #expect(sink.batches.flatMap { $0 }.map(\.eventID) == ids)
        #expect(try store.pendingCount() == 0)
    }

    @Test func failureKeepsEventsAndBacksOff() async throws {
        let store = try makeStore()
        try store.enqueue(sampleEvent(at: clock.now))
        let sink = FakeSink()
        sink.setMode(.fail)
        let loop = DeliveryLoop(store: store, sink: sink, now: { clock.now })

        let failed = await loop.flush()
        #expect(failed.remaining == 1)
        #expect(failed.error != nil)
        #expect(try store.pending(limit: 1).first?.attempts == 1)

        // Within the backoff window nothing is sent.
        sink.setMode(.accept)
        _ = await loop.flush()
        #expect(sink.batches.count == 1)

        // After the window, it delivers.
        clock.advance(16)
        let ok = await loop.flush()
        #expect(ok.delivered == 1)
        #expect(try store.pendingCount() == 0)
    }

    @Test func networkReturnClearsBackoff() async throws {
        let store = try makeStore()
        try store.enqueue(sampleEvent(at: clock.now))
        let sink = FakeSink()
        sink.setMode(.fail)
        let loop = DeliveryLoop(store: store, sink: sink, now: { clock.now })
        _ = await loop.flush()
        sink.setMode(.accept)
        await loop.resetBackoff()
        #expect(await loop.flush().delivered == 1)
    }

    @Test func serverAnsweringSendsAtOnceAfterItCouldNotBeReached() async throws {
        let store = try makeStore()
        try store.enqueue(sampleEvent(at: clock.now))
        let sink = FakeSink()
        sink.setMode(.unreachable)
        let loop = DeliveryLoop(store: store, sink: sink, now: { clock.now })
        _ = await loop.flush()
        sink.setMode(.accept)

        // The command long poll got an answer: no waiting out the backoff.
        await loop.serverAnswered()
        #expect(sink.batches.count == 2)
        #expect(try store.pendingCount() == 0)
    }

    @Test func serverAnsweringKeepsTheBackoffAfterARefusal() async throws {
        let store = try makeStore()
        try store.enqueue(sampleEvent(at: clock.now))
        let sink = FakeSink()
        sink.setMode(.fail)
        let loop = DeliveryLoop(store: store, sink: sink, now: { clock.now })
        _ = await loop.flush()
        sink.setMode(.accept)

        // A server that answered with an error isn't asked again on every poll.
        await loop.serverAnswered()
        #expect(sink.batches.count == 1)
        #expect(try store.pendingCount() == 1)
    }

    @Test func serverAnsweringSendsNothingExtraWithoutABackoff() async throws {
        let store = try makeStore()
        try store.enqueue(sampleEvent(at: clock.now))
        let sink = FakeSink()
        let loop = DeliveryLoop(store: store, sink: sink, now: { clock.now })

        await loop.serverAnswered()
        #expect(sink.batches.isEmpty)
    }

    @Test func rejectedEventsAreDroppedNotRetried() async throws {
        let store = try makeStore()
        try store.enqueue(sampleEvent(at: clock.now))
        let sink = FakeSink()
        sink.setMode(.rejectAll)
        let result = await DeliveryLoop(store: store, sink: sink, now: { clock.now }).flush()
        #expect(result.rejected == 1)
        #expect(try store.pendingCount() == 0)
    }

    @Test func unacknowledgedEventsStayQueued() async throws {
        let store = try makeStore()
        try store.enqueue(sampleEvent(at: clock.now))
        let sink = FakeSink()
        sink.setMode(.ignoreAll)
        let result = await DeliveryLoop(store: store, sink: sink, now: { clock.now }).flush()
        #expect(result.remaining == 1)
        #expect(result.error != nil)
    }

    @Test func marksOldEventsDelayed() async throws {
        let store = try makeStore()
        try store.enqueue(sampleEvent(at: clock.now))
        clock.advance(3600)
        try store.enqueue(sampleEvent(at: clock.now))
        let sink = FakeSink()
        _ = await DeliveryLoop(store: store, sink: sink, now: { clock.now }).flush()
        #expect(sink.batches.flatMap { $0 }.map(\.delayed) == [true, false])
    }
}
