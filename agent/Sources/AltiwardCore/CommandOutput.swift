import Foundation
import os

/// Why a command gave no output to use.
public enum CommandFailure: Error, Equatable, Sendable, CustomStringConvertible {
    /// It couldn't be started.
    case couldNotStart(String)
    /// It hadn't finished within the time allowed, and was stopped.
    case timedOut(TimeInterval)
    /// It exited with this status, not 0.
    case exited(Int32)
    /// It printed more than this many bytes.
    case tooLarge(Int)

    public var description: String {
        switch self {
        case .couldNotStart(let why): "couldn't be started (\(why))"
        case .timedOut(let seconds): "didn't finish within \(Int(seconds)) s"
        case .exited(let status): "exited with status \(status)"
        case .tooLarge(let limit): "printed more than \(limit) bytes"
        }
    }
}

/// Runs a command for its standard output: the output when it exits 0 within `timeout` and
/// prints no more than `maxBytes`, and otherwise why not. The output is read while the
/// command runs, so a large one can't fill the pipe and stall it.
enum CommandOutput {
    static func run(_ executable: String, _ arguments: [String], timeout: TimeInterval, maxBytes: Int)
        -> Result<Data, CommandFailure>
    {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return .failure(.couldNotStart((error as NSError).localizedDescription))
        }
        let output = OSAllocatedUnfairLock(initialState: Data())
        let read = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            output.withLock { $0 = data }
            read.signal()
        }
        guard read.wait(timeout: .now() + timeout) == .success else {
            process.terminate()
            return .failure(.timedOut(timeout))
        }
        process.waitUntilExit()
        let data = output.withLock { $0 }
        guard process.terminationStatus == 0 else { return .failure(.exited(process.terminationStatus)) }
        guard data.count <= maxBytes else { return .failure(.tooLarge(maxBytes)) }
        return .success(data)
    }
}
