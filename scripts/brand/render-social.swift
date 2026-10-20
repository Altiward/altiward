// Renders a GitHub social preview image (1280x640, 1x pixels, opaque) for one of the
// Altiward repositories, or the website's Open Graph image (1200x630), as the brand's
// SocialCard: dark ground, the repository URL or site address, the name and a one-line
// tagline on the left, and the stair as four bars bleeding off the right edge with the
// signal orange on top. GitHub crops these in some views, so the text sits inside an 80 px
// margin.
//
//   swift render-social.swift <out.png> <card>
//
// <card> is altiward, altiward-forwarder, altiward-siem or website (altiward.com's
// og.png, with the site checked out next to this repository). generate.sh renders this
// repository's, docs/brand/social-altiward.png. The other repositories keep theirs as
// docs/brand/social-preview.png; to refresh one, from this repository's root, with the
// sibling checked out next to it:
//
//   swift scripts/brand/render-social.swift ../altiward-forwarder/docs/brand/social-preview.png \
//     altiward-forwarder
//
// The fonts are the console's (Inter and JetBrains Mono), so run
// `make console-install` once first. Upload each image in its repository's Settings, under
// Social preview.
import AppKit

// Brand v4 tokens from console/src/styles.css (Mono, dark: the card is dark only). The top
// bar is the mark's fixed signal orange, not a token.
func hex(_ value: UInt32) -> NSColor {
    NSColor(
        srgbRed: CGFloat((value >> 16) & 0xff) / 255, green: CGFloat((value >> 8) & 0xff) / 255,
        blue: CGFloat(value & 0xff) / 255, alpha: 1)
}
let surface = hex(0x0e0e0e)  // --surface-100
let ink = hex(0xf2f2f2)  // --ink, 17:1 on the surface
let muted = hex(0xa9a9a9)  // --muted, 8.6:1 on the surface
let line = hex(0x7a7a7a)  // --line
let elevated = hex(0xff8a1f)  // the mark's top step

let margin = 80
let cards: [String: (name: String, tagline: String, label: String)] = [
    "altiward": ("Altiward", "Open-source oversight for temporary admin on macOS.", "github.com/Altiward/altiward"),
    "altiward-forwarder": ("altiward-forwarder", "Forward SAP Privileges events to Splunk, Sentinel or syslog.",
        "github.com/Altiward/altiward-forwarder"),
    "altiward-siem": ("altiward-siem", "Detections and hunting queries for Sentinel and Splunk.",
        "github.com/Altiward/altiward-siem"),
    "website": ("Altiward", "Temporary Mac admin.\nLasting accountability.", "altiward.com"),
]

let arguments = CommandLine.arguments
guard arguments.count == 3, let card = cards[arguments[2]] else {
    let repos = cards.keys.sorted().joined(separator: "|")
    FileHandle.standardError.write(Data("usage: render-social.swift <out.png> <\(repos)>\n".utf8))
    exit(1)
}
let output = URL(fileURLWithPath: arguments[1])
let (width, height) = arguments[2] == "website" ? (1200, 630) : (1280, 640)

let here = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let fonts = here.appendingPathComponent("../../console/node_modules/@fontsource").standardized
for file in [
    "inter/files/inter-latin-400-normal.woff2",
    "inter/files/inter-latin-700-normal.woff2",
    "jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff2",
] {
    let url = fonts.appendingPathComponent(file)
    guard CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil) else {
        FileHandle.standardError.write(Data("missing \(url.path): run make console-install\n".utf8))
        exit(1)
    }
}
func font(_ name: String, _ size: CGFloat) -> NSFont {
    guard let font = NSFont(name: name, size: size) else { fatalError("font \(name) not loaded") }
    return font
}

func attributed(_ text: String, font: NSFont, color: NSColor, kern: CGFloat = 0,
    lineHeight: CGFloat? = nil) -> NSAttributedString
{
    let style = NSMutableParagraphStyle()
    style.lineBreakMode = .byWordWrapping
    if let lineHeight { style.minimumLineHeight = lineHeight; style.maximumLineHeight = lineHeight }
    return NSAttributedString(string: text, attributes: [
        .font: font, .foregroundColor: color, .kern: kern, .paragraphStyle: style,
    ])
}

// Typesets text with its bottom-left at (x, y) in Cocoa coordinates; returns its height.
@discardableResult
func draw(_ string: NSAttributedString, x: Int, bottom y: Int, width boxWidth: Int) -> Int {
    let bounds = string.boundingRect(
        with: NSSize(width: boxWidth, height: 400), options: [.usesLineFragmentOrigin])
    let textHeight = Int(ceil(bounds.height))
    string.draw(
        with: NSRect(x: x, y: y, width: boxWidth, height: textHeight),
        options: [.usesLineFragmentOrigin])
    return textHeight
}

guard
    let bitmap = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height, bitsPerSample: 8,
        samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
        bytesPerRow: 0, bitsPerPixel: 0)
else { exit(1) }
// One point per pixel: GitHub wants exactly 1280x640, not a Retina 2560x1280.
bitmap.size = NSSize(width: width, height: height)
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)

surface.setFill()
NSRect(x: 0, y: 0, width: width, height: height).fill()

// The stair: four 80 px bars from 120 px below the top, each 128 wider than the one above
// with 24 between them, flush right. Only the top one is orange.
for (index, color) in [elevated, ink, muted, line].enumerated() {
    let barWidth = (160 + 128 * index) * width / 1280
    color.setFill()
    NSRect(x: width - barWidth, y: height - 120 - 104 * index - 80, width: barWidth, height: 80).fill()
}

// Left column, clear of the bars: tagline at the bottom margin, the name above it, shrunk
// to fit for the longer repository names.
let column = 620
let used = draw(
    attributed(card.tagline, font: font("Inter-Regular", 30), color: muted, lineHeight: 40),
    x: margin, bottom: margin, width: column)
var size: CGFloat = 120
while size > 48,
    attributed(card.name, font: font("Inter-Bold", size), color: ink, kern: -0.03 * size)
        .size().width > CGFloat(column)
{ size -= 2 }
draw(
    attributed(card.name, font: font("Inter-Bold", size), color: ink, kern: -0.03 * size,
        lineHeight: size),
    x: margin, bottom: margin + used + 24, width: column + 40)

draw(
    attributed(card.label, font: font("JetBrainsMono-Regular", 24), color: muted),
    x: margin, bottom: height - 72 - 24, width: width - 2 * margin)
NSGraphicsContext.restoreGraphicsState()

guard let png = bitmap.representation(using: .png, properties: [:]) else { exit(1) }
try png.write(to: output)
