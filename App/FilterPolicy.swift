import AppKit
import CryptoKit
import Foundation

struct ManagedApp: Codable, Identifiable {
  let id, name, adapter: String
  let port: Int
}
struct FilterPreset: Codable, Identifiable {
  let id, name: String
  let domains: [String]
}
struct FilterCatalog: Codable {
  let presets: [FilterPreset]
  let apps: [ManagedApp]
  static let shared: Self = {
    guard let u = Tools.host.url(forResource: "catalog", withExtension: "json"),
      let data = try? Data(contentsOf: u),
      let catalog = try? JSONDecoder().decode(Self.self, from: data)
    else { return Self(presets: [], apps: []) }
    return catalog
  }()
}
struct ApplicationRule: Codable, Equatable, Identifiable {
  let id: String
  var all: Bool
  var domains: [String]
}
struct FilterPolicy: Codable, Equatable {
  var domains: [String] = []
  var applications: [ApplicationRule] = []
  init(domains: [String] = [], applications: [ApplicationRule] = []) {
    self.domains = domains
    self.applications = applications
  }
  init(from decoder: Decoder) throws {
    let c = try decoder.container(keyedBy: CodingKeys.self)
    domains = try c.decodeIfPresent([String].self, forKey: .domains) ?? []
    applications = try c.decodeIfPresent([ApplicationRule].self, forKey: .applications) ?? []
  }
  func json() throws -> Data {
    let enc = JSONEncoder()
    enc.outputFormatting = [.sortedKeys]
    return try enc.encode(self)
  }
  // The test uses fresh names below this suffix on every visit. Feed the same policy to
  // the split resolver, TLS filter and browser PAC, including on upgrades from older profiles.
  static let diagnosticDomain = "ip.net.coffee"
  var systemRules: Self {
    var p = fullApplications
    p.domains = Set(p.domains + [Self.diagnosticDomain]).sorted()
    return p
  }
  var fullApplications: Self {
    Self(
      domains: domains,
      applications: applications.map { ApplicationRule(id: $0.id, all: true, domains: []) }.sorted {
        $0.id < $1.id
      })
  }
  func normalized() throws -> Self {
    let input = try json()
    guard input.count <= 48 * 1024 else {
      throw GuardError.message("Список правил слишком длинный.")
    }
    let data = try Tools.run(Tools.engine, ["normalize"], input: input)
    return try JSONDecoder().decode(Self.self, from: data)
  }
  static func words(_ text: String) -> [String] {
    text.split(whereSeparator: { $0.isWhitespace || $0 == "," }).map(String.init)
  }
}
enum Profile {
  static let id = "local.proxyguard.browsers"
  static let appDomain = "local.proxyguard.app"
  static func pac(_ policy: FilterPolicy) throws -> String {
    let list = try JSONEncoder().encode(policy.domains + ["route.proxyguard.test"])
    return """
      function FindProxyForURL(url, host) {
        host = host.toLowerCase().replace(/\\.$/, "");
        var domains = \(String(decoding:list,as:UTF8.self));
        for (var i = 0; i < domains.length; i++) {
          var d = domains[i];
          if (host === d || host.slice(-d.length - 1) === "." + d) return "PROXY 127.0.0.1:17687";
        }
        return "DIRECT";
      }
      """
  }
  static func signature(_ policy: FilterPolicy) throws -> String {
    SHA256.hash(data: try policy.json()).map { String(format: "%02x", $0) }.joined()
  }
  static func preferences(_ policy: FilterPolicy) throws -> [String: [String: Any]] {
    let url =
      "data:application/x-ns-proxy-autoconfig;base64,"
      + Data(try pac(policy).utf8).base64EncodedString()
    var result: [String: [String: Any]] = [appDomain: ["ActiveFilterV4": try signature(policy)]]
    for app in FilterCatalog.shared.apps {
      let selected = policy.applications.contains(where: { $0.id == app.id })
      let address = "127.0.0.1:" + String(app.port)
      switch app.adapter {
      case "chromium":
        let proxy: [String: Any] =
          selected
          ? [
            "ProxyMode": "fixed_servers", "ProxyServer": "http://" + address,
            "ProxyBypassList": "<-loopback>",
          ] : ["ProxyMode": "pac_script", "ProxyPacUrl": url, "ProxyPacMandatory": true]
        result[app.id] = [
          "ProxySettings": proxy, "DnsOverHttpsMode": "off", "NetworkPredictionOptions": 2,
          "QuicAllowed": false, "WebRtcIPHandling": "disable_non_proxied_udp",
          "WebRtcIPHandlingUrl": [["url": "*", "handling": "disable_non_proxied_udp"]],
        ]
      case "firefox":
        let proxy: [String: Any] =
          selected
          ? [
            "Mode": "manual", "HTTPProxy": address, "SSLProxy": address,
            "UseHTTPProxyForAllProtocols": true, "Passthrough": "", "Locked": true,
          ] : ["Mode": "autoConfig", "AutoConfigURL": url, "Locked": true]
        var locks: [String: Bool] = [
          "network.proxy.failover_direct": false, "network.dns.disablePrefetch": true,
          "network.prefetch-next": false, "network.http.http3.enable": false,
          "media.peerconnection.ice.proxy_only": true,
        ]
        if selected {
          locks["network.proxy.allow_hijacking_localhost"] = true
          locks["media.peerconnection.enabled"] = false
        }
        result[app.id] = [
          "EnterprisePoliciesEnabled": true, "DNSOverHTTPS": ["Enabled": false, "Locked": true],
          "Proxy": proxy,
          "Preferences": locks.mapValues { ["Value": $0, "Status": "locked"] as [String: Any] },
        ]
      case "desktop" where selected:
        result[app.id] = [
          "egressProxyUrl": "http://" + address, "disableEssentialTelemetry": true,
          "disableNonessentialTelemetry": true,
        ]
      default: break
      }
    }
    return result
  }
  static func legacyApps(domains: [String], report: ProfileReport) -> [ApplicationRule] {
    FilterCatalog.shared.apps.filter {
      $0.adapter == "desktop"
        && report.preferences[$0.id]?["egressProxyUrl"] as? String == "http://127.0.0.1:17687"
    }.map { ApplicationRule(id: $0.id, all: false, domains: domains) }
  }
  static func data(_ policy: FilterPolicy) throws -> Data {
    let prefs = try preferences(policy)
    let payloads: [[String: Any]] = prefs.keys.sorted().map { domain in
      let identifier = id + ".preferences." + domain
      var bytes = Array(SHA256.hash(data: Data(identifier.utf8)).prefix(16))
      bytes[6] = (bytes[6] & 0x0f) | 0x80
      bytes[8] = (bytes[8] & 0x3f) | 0x80
      let uuid = NSUUID(uuidBytes: bytes).uuidString
      return [
        "PayloadType": "com.apple.ManagedClient.preferences", "PayloadIdentifier": identifier,
        "PayloadUUID": uuid, "PayloadVersion": 1, "PayloadDisplayName": "Правила приложения",
        "PayloadContent": [domain: ["Forced": [["mcx_preference_settings": prefs[domain]!]]]],
      ]
    }
    let profile: [String: Any] = [
      "PayloadType": "Configuration", "PayloadIdentifier": id,
      "PayloadUUID": "ED74DD1A-0599-595D-AE6C-AD206E96B626", "PayloadVersion": 1,
      "PayloadScope": "User", "PayloadDisplayName": "Lobotomy Proxy · Фильтр",
      "PayloadDescription": "Маршрутизация по выбранным доменам и приложениям.",
      "PayloadContent": payloads,
    ]
    return try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
  }
  static func open(_ policy: FilterPolicy) throws {
    let folder = BackgroundRelay.folder.appendingPathComponent("Profiles")
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    let path = folder.appendingPathComponent(
      "Filter-" + (try signature(policy).prefix(16)) + ".mobileconfig")
    try data(policy).write(to: path, options: .atomic)
    guard NSWorkspace.shared.open(path) else {
      throw GuardError.message("Не удалось открыть профиль.")
    }
    try openSettings()
  }
  static func openSettings() throws {
    guard
      NSWorkspace.shared.open(
        URL(string: "x-apple.systempreferences:com.apple.Profiles-Settings.extension")!)
    else {
      throw GuardError.message(
        "Профиль загружен. Откройте Настройки системы → Основные → Управление устройством.")
    }
  }
  static func remove() throws {
    let tool = URL(fileURLWithPath: "/usr/bin/profiles")
    let list = try Tools.run(tool, ["list", "-type", "configuration", "-output", "stdout-xml"])
    let obj = try PropertyListSerialization.propertyList(from: list, options: [], format: nil)
    if installed(in: obj) != nil {
      _ = try Tools.run(tool, ["remove", "-type", "configuration", "-identifier", id, "-forced"])
    }
  }
}
