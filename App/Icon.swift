import AppKit
import CoreImage

@main
enum IconMaker {
  static func main() throws {
    let source = URL(fileURLWithPath: CommandLine.arguments[1])
    let destination = URL(fileURLWithPath: CommandLine.arguments[2])
    let mark = try BrandArtwork.image(from: source, ink: "#411126", paper: "#ffd9e9")
    let master = CIImage(cgImage: drawTile(mark: mark))
    let context = CIContext(options: [.useSoftwareRenderer: true])

    for points in [16, 32, 128, 256, 512] {
      for scale in [1, 2] {
        let pixels = points * scale
        let image = master.applyingFilter("CILanczosScaleTransform", parameters: [
          kCIInputScaleKey: Double(pixels) / master.extent.width, kCIInputAspectRatioKey: 1
        ])
        let bounds = CGRect(x: 0, y: 0, width: pixels, height: pixels)
        guard let raster = context.createCGImage(image, from: bounds),
          let png = NSBitmapImageRep(cgImage: raster).representation(using: .png, properties: [:])
        else { throw CocoaError(.fileWriteUnknown) }
        let name = "icon_\(points)x\(points)" + (scale == 2 ? "@2x" : "") + ".png"
        try png.write(to: destination.appendingPathComponent(name))
      }
    }
  }

  private static func drawTile(mark: NSImage) -> CGImage {
    let bitmap = NSBitmapImageRep(
      bitmapDataPlanes: nil, pixelsWide: 1024, pixelsHigh: 1024, bitsPerSample: 8,
      samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
      bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    defer { NSGraphicsContext.restoreGraphicsState() }
    let context = NSGraphicsContext(bitmapImageRep: bitmap)!
    NSGraphicsContext.current = context
    context.imageInterpolation = .high
    let tile = NSBezierPath(
      roundedRect: NSRect(x: 77, y: 77, width: 870, height: 870), xRadius: 202, yRadius: 202)
    NSColor.white.setFill()
    tile.fill()
    let width: CGFloat = 803
    let height = width * mark.size.height / mark.size.width
    mark.draw(in: NSRect(x: (1024 - width) / 2, y: (1024 - height) / 2, width: width, height: height))
    return bitmap.cgImage!
  }
}
