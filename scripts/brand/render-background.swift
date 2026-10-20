// Renders an SVG into the bottom-left corner of a transparent square canvas, as
// <out>.png and <out>@2x.png, for the Installer background. Used by generate.sh.
//
//   swift render-background.swift <source.svg> <out> <canvas points> <image points> <inset points>
import AppKit

let arguments = CommandLine.arguments
guard arguments.count == 6, let image = NSImage(contentsOfFile: arguments[1]),
    let canvas = Int(arguments[3]), let side = Int(arguments[4]), let inset = Int(arguments[5])
else {
    FileHandle.standardError.write(
        Data("usage: render-background.swift <source.svg> <out> <canvas> <image> <inset>\n".utf8))
    exit(1)
}

for scale in [1, 2] {
    let pixels = canvas * scale
    guard
        let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8,
            samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
            bytesPerRow: 0, bitsPerPixel: 0)
    else { exit(1) }
    // The point size is the same at both scales, so Installer draws the 2x one at Retina.
    bitmap.size = NSSize(width: canvas, height: canvas)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
    NSGraphicsContext.current?.imageInterpolation = .high
    image.draw(in: NSRect(x: inset, y: inset, width: side, height: side))
    NSGraphicsContext.restoreGraphicsState()

    guard let png = bitmap.representation(using: .png, properties: [:]) else { exit(1) }
    try png.write(to: URL(fileURLWithPath: arguments[2] + (scale == 1 ? ".png" : "@2x.png")))
}
