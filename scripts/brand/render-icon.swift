// Renders an SVG into an .iconset folder: icon_<n>x<n>.png and icon_<n>x<n>@2x.png for
// each point size given. Used by generate.sh.
//
//   swift render-icon.swift <source.svg> <out.iconset> <size>...
import AppKit

let arguments = CommandLine.arguments
guard arguments.count >= 4, let image = NSImage(contentsOfFile: arguments[1]) else {
    FileHandle.standardError.write(Data("usage: render-icon.swift <source.svg> <out.iconset> <size>...\n".utf8))
    exit(1)
}
let output = URL(fileURLWithPath: arguments[2])

for size in arguments.dropFirst(3).compactMap(Int.init) {
    for scale in [1, 2] {
        let pixels = size * scale
        guard
            let bitmap = NSBitmapImageRep(
                bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8,
                samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                bytesPerRow: 0, bitsPerPixel: 0)
        else { exit(1) }
        bitmap.size = NSSize(width: pixels, height: pixels)
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
        NSGraphicsContext.current?.imageInterpolation = .high
        image.draw(in: NSRect(x: 0, y: 0, width: pixels, height: pixels))
        NSGraphicsContext.restoreGraphicsState()

        let name = scale == 1 ? "icon_\(size)x\(size).png" : "icon_\(size)x\(size)@2x.png"
        guard let png = bitmap.representation(using: .png, properties: [:]) else { exit(1) }
        try png.write(to: output.appendingPathComponent(name))
    }
}
