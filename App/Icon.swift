import AppKit

let destination = URL(fileURLWithPath: CommandLine.arguments[1])
for n in [16, 32, 128, 256, 512] {
  for scale in [1, 2] {
    let size = n * scale
    let rep = NSBitmapImageRep(
      bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8,
      samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
      bytesPerRow: 0, bitsPerPixel: 0)!
    let context = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context
    context.cgContext.scaleBy(x: CGFloat(size) / 1024, y: CGFloat(size) / 1024)
    let path = NSBezierPath(
      roundedRect: NSRect(x: 77, y: 77, width: 870, height: 870), xRadius: 202, yRadius: 202)
    let grad = NSGradient(
      starting: NSColor(srgbRed: 0.08, green: 0.51, blue: 0.44, alpha: 1),
      ending: NSColor(srgbRed: 0.025, green: 0.17, blue: 0.18, alpha: 1))!
    grad.draw(in: path, angle: -65)
    let shield = NSBezierPath()
    shield.move(to: NSPoint(x: 512, y: 782))
    shield.curve(
      to: NSPoint(x: 735, y: 698), controlPoint1: NSPoint(x: 565, y: 754),
      controlPoint2: NSPoint(x: 657, y: 713))
    shield.line(to: NSPoint(x: 733, y: 503))
    shield.curve(
      to: NSPoint(x: 512, y: 240), controlPoint1: NSPoint(x: 724, y: 378),
      controlPoint2: NSPoint(x: 608, y: 282))
    shield.curve(
      to: NSPoint(x: 291, y: 503), controlPoint1: NSPoint(x: 416, y: 282),
      controlPoint2: NSPoint(x: 300, y: 378))
    shield.line(to: NSPoint(x: 289, y: 698))
    shield.curve(
      to: NSPoint(x: 512, y: 782), controlPoint1: NSPoint(x: 367, y: 713),
      controlPoint2: NSPoint(x: 459, y: 754))
    shield.close()
    NSColor(white: 1, alpha: 0.93).setStroke()
    shield.lineWidth = 32
    shield.lineJoinStyle = .round
    shield.stroke()
    let route = NSBezierPath()
    route.move(to: NSPoint(x: 401, y: 496))
    route.line(to: NSPoint(x: 492, y: 496))
    route.curve(
      to: NSPoint(x: 529, y: 534), controlPoint1: NSPoint(x: 514, y: 496),
      controlPoint2: NSPoint(x: 529, y: 510))
    route.line(to: NSPoint(x: 529, y: 562))
    route.curve(
      to: NSPoint(x: 558, y: 592), controlPoint1: NSPoint(x: 529, y: 581),
      controlPoint2: NSPoint(x: 539, y: 592))
    route.line(to: NSPoint(x: 622, y: 592))
    route.lineWidth = 30
    route.lineCapStyle = .round
    route.stroke()
    NSColor(srgbRed: 0.57, green: 0.96, blue: 0.76, alpha: 1).setFill()
    for (x, y) in [(401, 496), (622, 592)] {
      NSBezierPath(ovalIn: NSRect(x: x - 24, y: y - 24, width: 48, height: 48)).fill()
    }
    NSGraphicsContext.restoreGraphicsState()
    let name = "icon_\(n)x\(n)" + (scale == 2 ? "@2x" : "") + ".png"
    try rep.representation(using: .png, properties: [:])!.write(
      to: destination.appendingPathComponent(name))
  }
}
