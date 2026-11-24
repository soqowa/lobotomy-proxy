import Foundation

@main enum PolicyFixture {
  static func main() throws {
    for (bundle, binary) in [
      ("Proxy Guard", "Contents/MacOS/ProxyGuard"),
      ("Proxy Guard", "Contents/Library/LoginItems/Proxy Guard Relay.app/Contents/MacOS/ProxyGuardRelay"),
      ("Lobotomy Proxy", "Contents/Library/LoginItems/Lobotomy Proxy Relay.app/Contents/MacOS/LobotomyProxyRelay"),
    ] {
      let host = "/Applications/" + bundle + ".app"
      let path = host + "/" + binary
      precondition(BackgroundRelay.jobHost([path, "--background-relay"])?.path == host)
      precondition(BackgroundRelay.jobHost([path, "--relay-worker"]) == nil)
    }
    precondition(BackgroundRelay.jobHost(["/tmp/Contents/MacOS/ProxyGuard", "--background-relay"]) == nil)
    let presets = FilterCatalog.shared.presets
    precondition(Set(presets.map(\.id)).count == 4)
    let a = FilterPreset(id: "one", name: "One", domains: ["common.example", "one.example"])
    let b = FilterPreset(id: "two", name: "Two", domains: ["common.example", "two.example"])
    var draft = DomainSelection(["manual.example", "one.example"])
    draft.toggle(a)
    draft.toggle(b)
    draft = try JSONDecoder().decode(DomainSelection.self, from: JSONEncoder().encode(draft))
    draft.toggle(a)
    precondition(
      draft.domains == ["common.example", "manual.example", "one.example", "two.example"])
    draft.remove("two.example")
    draft.toggle(b)
    precondition(draft.domains == ["manual.example", "one.example"])
    var legacy = DomainSelection(a.domains + ["custom.example"], migratePresets: [a, b])
    legacy.toggle(a)
    precondition(legacy.domains == ["custom.example"])
    let browser = FilterCatalog.shared.apps.first { $0.adapter == "chromium" }!
    let desktop = FilterCatalog.shared.apps.first { $0.adapter == "desktop" }!
    let p = FilterPolicy(
      domains: ["custom.example"], applications: [.init(id: browser.id, all: true, domains: [])])
    let effective = p.systemRules
    precondition(effective.domains == ["custom.example", "ip.net.coffee"])
    precondition(effective.systemRules == effective && effective.applications == p.applications)
    let effectivePAC = try Profile.pac(effective)
    precondition(effectivePAC.contains(FilterPolicy.diagnosticDomain))
    let data = try Profile.data(p)
    let root = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
    let items = root["PayloadContent"] as! [[String: Any]]
    let values = items.map { $0["PayloadContent"] as! [String: Any] }
    precondition(values.allSatisfy { $0.count == 1 && $0[desktop.id] == nil })
    precondition(Set(items.compactMap { $0["PayloadUUID"] as? String }).count == items.count)
    precondition(root["PayloadDisplayName"] as? String == "Lobotomy Proxy · Фильтр")
    let inventory = [
      "user": [
        [
          "ProfileIdentifier": Profile.id,
          "ProfileItems": items.map { item in
            [
              "PayloadIdentifier": item["PayloadIdentifier"]!,
              "PayloadContent": ["PayloadContentManagedPreferences": item["PayloadContent"]!],
            ]
          },
        ]
      ]
    ]
    func condition(_ obj: Any, _ policy: FilterPolicy?, _ effective: Bool = true) throws
      -> ProfileCondition
    {
      try Profile.evaluate(obj, policy: policy) { _, _ in effective }.condition
    }
    let seen = try [
      condition(inventory, p), condition(inventory, p, false), condition(inventory, FilterPolicy()),
      condition([:], p),
      condition(["user": [["ProfileIdentifier": Profile.id, "ProfileItems": []]]], p),
    ]
    precondition(seen == [.current, .pending, .changed, .missing, .previous])
    let pac = try Profile.pac(p)
    precondition(
      pac.contains("custom.example") && !presets.flatMap(\.domains).contains(where: pac.contains))
    print(
      "PASS multiple presets, manual overlaps, individual removals, legacy migration, profile generation and five installed-profile states"
    )
  }
}
