import Foundation

enum AppLanguage {
  // macOS normally tries the second preferred language when the first is unsupported.
  // This app uses English in that case, even when Russian appears later in the list.
  static func resolve(_ preferences: [String]) -> String {
    guard let first = preferences.first,
      Locale.Language(identifier: first).languageCode?.identifier == "ru"
    else { return "en" }
    return "ru"
  }

  static let environmentKey = "LOBOTOMY_PROXY_LANGUAGE"
  static let current: String = {
    if let inherited = ProcessInfo.processInfo.environment[environmentKey],
      Bundle.main.bundleIdentifier == "local.proxyguard.relay-agent"
        || CommandLine.arguments.dropFirst().contains("--relay-worker")
    {
      return resolve([inherited])
    }
    return resolve(UserDefaults.standard.stringArray(forKey: "AppleLanguages") ?? Locale.preferredLanguages)
  }()

  static func configureInterface() {
    let defaults = UserDefaults.standard
    var arguments = defaults.volatileDomain(forName: UserDefaults.argumentDomain)
    arguments["AppleLanguages"] = [current]
    defaults.setVolatileDomain(arguments, forName: UserDefaults.argumentDomain)
  }

  static let strings: Bundle? = {
    guard current == "ru",
      let url = Tools.host.url(forResource: "ru", withExtension: "lproj")
    else { return nil }
    return Bundle(url: url)
  }()
}

func localized(_ english: String) -> String {
  AppLanguage.strings?.localizedString(forKey: english, value: english, table: nil) ?? english
}

func localized(_ english: String, _ argument: CVarArg) -> String {
  String(format: localized(english), arguments: [argument])
}
