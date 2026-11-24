import Foundation

// Each preset owns its own contributions. Removing a preset never removes a manual entry.
struct DomainSelection: Codable, Equatable {
  var manual: Set<String>
  var sources: [String: Set<String>] = [:]

  init(_ domains: [String], migratePresets: [FilterPreset] = []) {
    manual = Set(domains)
    for preset in migratePresets
    where !preset.domains.isEmpty && Set(preset.domains).isSubset(of: Set(domains)) {
      sources[preset.id] = Set(preset.domains)
      manual.subtract(preset.domains)
    }
  }
  var domains: [String] { sources.values.reduce(manual) { $0.union($1) }.sorted() }
  mutating func toggle(_ preset: FilterPreset) {
    if sources.removeValue(forKey: preset.id) == nil { sources[preset.id] = Set(preset.domains) }
  }
  mutating func remove(_ name: String) {
    manual.remove(name)
    for id in Array(sources.keys) { sources[id]?.remove(name) }
  }
}

struct SavedFilterDraft: Codable {
  var policy: FilterPolicy
  var selections: [String: DomainSelection]
}
