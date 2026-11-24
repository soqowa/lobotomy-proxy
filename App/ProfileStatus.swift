import AppKit
import Foundation

enum ProfileCondition: String {
  case unknown, missing, previous, changed, pending, current
  var installed: Bool { self != .unknown && self != .missing }
  var label: String {
    switch self {
    case .unknown: return "Список профилей недоступен"
    case .missing: return "Профиль не установлен"
    case .previous: return "Установлен профиль прежней версии"
    case .changed: return "Установлен профиль с другими правилами"
    case .pending: return "Профиль установлен. Настройки приложения ещё не подтверждены"
    case .current: return "Установлен профиль с текущими правилами"
    }
  }
}
struct ProfileReport {
  var condition: ProfileCondition
  var preferences: [String: [String: Any]] = [:]
  var waitingFor: [String] = []
  var detail: String {
    waitingFor.isEmpty
      ? condition.label : condition.label + " (" + waitingFor.joined(separator: ", ") + ")"
  }
}
extension Profile {
  static func installed(in inventory: Any) -> [String: Any]? {
    if let obj = inventory as? [String: Any] {
      if obj["ProfileIdentifier"] as? String == id { return obj }
      return obj.values.lazy.compactMap { installed(in: $0) }.first
    }
    if let array = inventory as? [Any] { return array.lazy.compactMap { installed(in: $0) }.first }
    return nil
  }
  static func report(_ policy: FilterPolicy?) -> ProfileReport {
    do {
      let data = try Tools.run(
        URL(fileURLWithPath: "/usr/bin/profiles"),
        ["list", "-type", "configuration", "-output", "stdout-xml"])
      let inventory = try PropertyListSerialization.propertyList(
        from: data, options: [], format: nil)
      let running = Set(NSWorkspace.shared.runningApplications.compactMap(\.bundleIdentifier))
      return try evaluate(inventory, policy: policy) { domain, values in
        guard domain != appDomain, running.contains(domain) else { return true }
        CFPreferencesAppSynchronize(domain as CFString)
        return values.allSatisfy { key, expected in
          guard CFPreferencesAppValueIsForced(key as CFString, domain as CFString),
            let value = CFPreferencesCopyAppValue(key as CFString, domain as CFString) as? NSObject
          else { return false }
          return value.isEqual(expected)
        }
      }
    } catch { return ProfileReport(condition: .unknown) }
  }
  static func evaluate(
    _ inventory: Any, policy: FilterPolicy?, effective: (String, [String: Any]) -> Bool
  ) throws -> ProfileReport {
    guard let entry = installed(in: inventory) else { return ProfileReport(condition: .missing) }
    var report = ProfileReport(condition: .previous)
    for item in entry["ProfileItems"] as? [[String: Any]] ?? [] {
      guard let identifier = item["PayloadIdentifier"] as? String,
        identifier == id + ".preferences" || identifier.hasPrefix(id + ".preferences."),
        let payload = item["PayloadContent"] as? [String: Any]
      else { continue }
      let domains = payload["PayloadContentManagedPreferences"] as? [String: Any] ?? payload
      for (domain, object) in domains {
        guard let obj = object as? [String: Any], let entries = obj["Forced"] as? [[String: Any]]
        else { continue }
        for setting in entries {
          if let values = setting["mcx_preference_settings"] as? [String: Any] {
            report.preferences[domain, default: [:]].merge(values) { _, new in new }
          }
        }
      }
    }
    guard report.preferences[appDomain]?["ActiveFilterV4"] != nil else { return report }
    report.condition = .changed
    guard let policy, !FilterCatalog.shared.apps.isEmpty else { return report }
    let expected = try preferences(policy)
    guard NSDictionary(dictionary: report.preferences).isEqual(to: expected) else { return report }
    report.waitingFor = expected.filter { !effective($0.key, $0.value) }.map { pair in
      FilterCatalog.shared.apps.first { $0.id == pair.key }?.name ?? pair.key
    }.sorted()
    report.condition = report.waitingFor.isEmpty ? .current : .pending
    return report
  }
}
