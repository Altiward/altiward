import Darwin
import Foundation

/// Reads a file someone else controls, such as one in a user's home folder, from the
/// daemon running as root. Only a regular file is read, so a named pipe or a device put
/// there can't hang the daemon or fill its memory, and never more than a limit.
enum UntrustedFile {
    enum Contents: Equatable {
        case missing
        /// It exists but isn't a regular file, is too large, or couldn't be read.
        case unreadable
        case data(Data)
    }

    /// With `followSymlinks` false, a symlink at `path` counts as unreadable.
    static func read(_ path: String, maxBytes: Int, followSymlinks: Bool = true) -> Contents {
        let fd = open(path, O_RDONLY | O_NONBLOCK | (followSymlinks ? 0 : O_NOFOLLOW))
        guard fd >= 0 else { return errno == ENOENT ? .missing : .unreadable }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        // read(upToCount:) gives nil for an empty file, which is empty, not unreadable.
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size <= maxBytes,
            let data = try? handle.read(upToCount: maxBytes) ?? Data()
        else { return .unreadable }
        return .data(data)
    }
}
