import AppKit

enum BrandArtwork {
  static let resource = "lobotomy-proxy"

  static func image(from url: URL, ink: String, paper: String) throws -> NSImage {
    let source = try String(contentsOf: url, encoding: .utf8)
    let svg = source
      .replacingOccurrences(of: "fill=\"currentColor\"", with: "fill=\"\(ink)\"")
      .replacingOccurrences(of: "fill=\"#ffffff\"", with: "fill=\"\(paper)\"")
    guard let image = NSImage(data: Data(svg.utf8)) else {
      throw CocoaError(.fileReadCorruptFile)
    }
    return image
  }
}
