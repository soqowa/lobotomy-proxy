<p align="center">
  <img src="Brand/readme-icon.png" width="144" height="144" alt="Lobotomy Proxy app icon">
</p>

<h1 align="center">Lobotomy Proxy</h1>

<p align="center">
  Choose which Mac apps and websites connect through your proxy.
</p>

<p align="center">
  <strong><a href="https://github.com/soqowa/lobotomy-proxy/releases/latest">Download for Mac</a></strong>
  &nbsp;·&nbsp; <a href="#quick-start">Quick&nbsp;start</a>
  &nbsp;·&nbsp; <a href="#build-from-source">Build&nbsp;guide</a>
</p>

## Installation

Download the ZIP from the latest release, unzip it, and move **Lobotomy Proxy.app** to Applications. The universal build runs on Apple Silicon and Intel Macs with **macOS 14 or later**. Sign in to GitHub with an account that has access to the repository. Each release lists the signing certificate used for that build.

<details>
<summary>Verify the download</summary>

Save the release’s `SHA256SUMS.txt` alongside the ZIP and run this command in the same directory.

```sh
shasum -a 256 -c SHA256SUMS.txt
```

</details>

<details>
<summary>Upgrade from Proxy Guard</summary>

Place **Lobotomy Proxy.app** next to **Proxy Guard.app** and open the new version. It picks up your settings and points the active background service to the new app. Once the menu bar shield shows a checkmark, you can remove the old copy. The installed configuration profile takes the new name the next time you update it.

</details>

## Quick start

The app follows your Mac’s primary language. Russian selects the Russian interface. Every other language selects English, even if Russian appears later in your preferred languages. Reopen the app after changing the language in System Settings.

1. **Connect your proxy.** In Connection, choose HTTP, HTTPS, or SOCKS5 and enter the host, port, and credentials. Test and save the connection. The app checks the exit IP against two services, tests DNS, and stores the credentials in your macOS Keychain.
2. **Choose what to route.** In Filter, add individual domains or select one or more presets. Each domain includes its subdomains. Add an app to route all of its supported web traffic through the proxy.
3. **Install the profile.** In Filter, update the profile and open System Settings. Under **General → Device Management**, approve the Lobotomy Proxy profile. macOS may ask for administrator privileges to install the local service and DNS rules.
4. **Check the shield.** Forwarding starts automatically once the configuration is verified. A checkmark in the menu bar shield means the route is verified. If a check fails, click the shield to see the reason and open Overview.

<details>
<summary>How filter edits take effect</summary>

Your draft is saved as you edit. Removing a preset keeps manually added domains and domains from other selected presets. Updating a profile from an older version switches its selected apps to all-sites routing. During an update, the relay uses the available system rules and blocks forwarding if it cannot verify the new configuration.

</details>

To change the app’s appearance, open **menu bar shield → Theme** and choose System, Light, or Dark. In the same menu, **Sidebar** switches between **Logo on Top**, with the logo, version and forwarding status above the sections, and **Classic**, with the logo at the bottom.

## DNS and route checks

Protected connections use the configured proxy and local filter rules. The relay verifies the exit through the proxy about every 40 seconds. Two independent HTTPS services must agree on the public IP and country. For an unchanged exit, the relay keeps the verified time zone in memory for up to one hour. A changed exit needs a fresh time zone check. Cloudflare Trace and Country check the IP and country while the cached time zone is valid. IPWho supplies a fresh time zone on startup, after an exit change and when the cached time zone expires. If a service times out or rate-limits requests, the relay tries the remaining services, including ifconfig.co when a fresh zone is needed. Forwarding stays closed unless the checks pass. [Country API](https://country.is/) · [IPWho API](https://ipwhois.io/documentation) · [ifconfig.co](https://ifconfig.co/)

In **Overview → Leak check**, open Net.Coffee in a protected browser to inspect the DNS resolvers, WebRTC/UDP results, and time zone it observes. The profile covers `ip.net.coffee` and its test subdomains, so you can also check DNS in a regular window of a supported default browser. [Open the Net.Coffee test](https://ip.net.coffee/claude/)

For **Berlin · CryptoStorm** DNS mode, enter the proxy host as a numeric IP address. The app sends DNS-over-HTTPS requests through the proxy, connects to the returned IPs, and blocks the request if DNS resolution fails. [CryptoStorm resolver details](https://cryptostorm.is/blog/doh)

## Time zone

Apps in the active filter launch with `TZ` set to the verified proxy time zone, including when opened from Finder or the Dock. If an app is already running without that setting, the service requests a normal quit and relaunches it. Save open documents before applying the profile. The app’s proxy stays closed if it declines to quit, multiple instances are running, or the relaunch cannot be verified. Browsers with their own privacy settings may report a different time zone.

To apply the proxy time zone to the whole Mac, use **Connection → Time zone**. The rollback control restores the saved setting and checks for any change you made manually. The saved system time zone remains available after removing the filter.

## Routing and rollback

Domain rules use split DNS, entries in the hosts file, and TLS hostname checks on port 443. Chrome, Edge, Brave, Arc, Vivaldi, and Firefox receive managed browser settings. A selected app gets a fixed local proxy. Other supported browsers use a proxy auto-configuration (PAC) file for the selected domains. Safari uses system DNS. Desktop clients that support `egressProxyUrl` depend on the client’s operating mode.

Direct sockets, virtual machines, some updaters, third-party DNS-over-HTTPS, and VPNs with their own routes can bypass client settings. A successful leak test describes the browser window and network configuration you tested.

To roll back, open **Filter** and remove the profile using the rollback control. This stops the relay and removes the service, network rules, and configuration profile. Restart the affected apps. Your draft filter and connection settings are kept for reuse.

## Build from source

The build has been tested with Xcode 27.2 and Go 1.25. From the repository root, run

```sh
./build.sh
```

The script writes the universal app to `../Deliverables/Lobotomy Proxy.app`. For distribution through Gatekeeper on other Macs, sign with Developer ID and notarize the build.

<details>
<summary>Run the checks</summary>

- `(cd engine && go test -race ./... && go vet ./...)` checks proxy routing, domain rules, app admission, failure handling, and rollback.
- `python3 Tests/profile.py` checks presets, profile generation, and installed-profile detection.
- `python3 Tests/zone-launch.py` launches a temporary app and checks its managed relaunch, process time zone, and blocking until verification.
- `node Tests/chrome-route.cjs` checks that protected requests to a local test server are blocked when the proxy is down. It requires `playwright-core` and a full Chromium build. Set `PG_TEST_CHROMIUM` to select the browser executable.
- `node Tests/net-coffee.cjs` runs the live browser test through the local test proxy set in `PG_DIAGNOSTIC_PROXY`, using `PG_TEST_ZONE` for the time zone. Set `PG_TEST_DNS_COUNTRY` and `PG_TEST_DNS_CITY` to check every observed resolver. To test the active profile on your Mac, use the check in Overview.

</details>

The sidebar and Dock icon share one SVG. The outline inherits `currentColor` and the `paper` path sets the fill. [Logo source](Brand/lobotomy-proxy.svg)

### Cut a release

GitHub Actions runs the Go race tests, `go vet`, profile checks, and a universal macOS build on pushes and pull requests to `main`.

1. Update `VERSION`, commit and push to `main`, and check the CI result.
2. On a Mac with Xcode, Go, GitHub CLI, and a signing identity, run `./scripts/release.sh`. It builds the app, tags the commit, and publishes the ZIP and SHA-256 checksum. Signing uses the private key in the local Keychain.
3. To publish a ZIP you already tested, pass its path to the script, for example `./scripts/release.sh "../Deliverables/Lobotomy Proxy macOS.zip"`. For a notarized release, supply a notarized build with its ticket stapled. To provide release notes, set `RELEASE_NOTES_FILE` to the path of a Markdown file.

Set `PROXYGUARD_SIGNING_IDENTITY` to choose a signing identity explicitly. By default, the script looks for a Developer ID Application certificate first, then an Apple Development certificate.
