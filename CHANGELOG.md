# Changelog

## 0.5.0 — 2026-10-01

### Interface

- Completely redesigned: dark sidebar navigation with Dashboard, Websites, Categories and Advanced pages, rounded cards, status pills and short notifications.
- Dashboard shows the protection level (6 layers), totals and a quick "Block a website" box.
- **Turn on recommended protection** enables the adult, gambling and malware lists plus strict mode in one step.
- Categories page: one switch per list with domain count and update date.
- Squid keywords are shown as chips; the account, About and Smart IP settings moved to Advanced.
- New sign-in and account dialogs.

### Blocking

- Category lists: Adult content, Gambling, Social media, and Malware/scams/ads (StevenBlack/hosts), refreshed automatically every 7 days by the sync timer.
- Strict mode (on by default) adds:
  - SafeSearch for Google (51 country domains), Bing and DuckDuckGo, and YouTube Restricted Mode.
  - Blocking of DNS-over-HTTPS resolvers by name (DNS) and by address (firewall, ports 443/853), and of all DNS-over-TLS.
  - Firefox's DoH canary domain answered with NXDOMAIN.
  - Firefox and Chromium/Chrome/Brave/Edge enterprise policies.
- A blocked site always wins over its SafeSearch address.
- When NetworkManager's dnsmasq is the resolver, category lists are served by dnsmasq (wildcard, NXDOMAIN) instead of `/etc/hosts`, so name lookups stay fast. The sync timer moves them automatically when the resolver changes.
- Rules entered as `www.example.com` (or a `https://www...` URL) are stored as `example.com`, so every subdomain is blocked.
- Firefox policies are merged into an existing `policies.json` and restored exactly when strict mode is turned off. A broken third-party policy file no longer prevents other layers from applying.

### Installation

- New single-file offline installer (`eduka-block-<version>-offline-<codename>-<arch>.run`) containing every dependency as a local APT repository. It installs without internet and falls back to the internet only when needed.
- `tools/build-offline-bundle.sh` builds it. CI builds it for Debian 13, tests it on a clean minimal system, and attaches it to GitHub releases for `v*` tags.

### Internal

- State schema 4 (category lists, strict mode, DNS mode); older states migrate automatically.
- New helper action `protection-configure`; the 0.4 `adult-*` actions still work.
- Translations regenerated: obsolete strings removed, all new strings translated into Tetum, Portuguese (Portugal/Brazil) and Indonesian.
- The test suite now runs every helper operation inside a temporary root, and includes a headless GTK smoke test.

## 0.4.2 — 2026-09-30

### Fixed

- Firewall updates no longer fail when an IP address lies inside a blocked CIDR range, or when two rules overlap. nftables interval sets reject overlapping elements, which previously rolled back the whole change; overlapping and adjacent addresses are now merged before the ruleset is generated.
- The main menu popover no longer opens by itself when the window appears.
- The empty-list hint no longer stays visible after rules are loaded.
- Debian 13 installs: depend on `pkexec` and `polkitd` (with `policykit-1` as an alternative for older releases); the `policykit-1` transitional package no longer exists in Debian 13.
- The helper lock moved from world-writable `/run/lock` to root-only `/run`, so an unprivileged user can no longer pre-create or hold it to stall protection updates. Waiting for the lock now times out after 90 seconds with a clear message instead of hanging.
- Smart IP synchronisation and adult-list downloads run their slow network work before taking the lock, so the interface is no longer blocked for minutes while the timer runs.
- Adding and removing rules no longer freezes the window; every privileged action now runs in the background, and locking, closing or switching language is held back until it finishes.
- Many error messages that appeared in English are now translated into Tetum, Portuguese (Portugal/Brazil) and Indonesian.
- Styling is scoped to Eduka-Block windows so menus, file choosers and message dialogs keep the native theme.

### Added

- Import rules from a plain list, a previous export, or a hosts-format blocklist (up to 1,000 entries in one authorisation); export all rules to a text file.
- Select and remove several rules at once.
- "Sync IP addresses now" button and last-synchronisation time in the overview.
- Sortable rule columns, a rule counter with search results, and Ctrl+F / Ctrl+L shortcuts.
- A subdomain already covered by a blocked parent domain is reported instead of being added twice.
- Status colours: DNS fallback and stopped Squid are shown as warnings, failed operations as errors.
- Show/hide password buttons, a dedicated "change account" dialog, and remaining sign-in attempts.
- Duplicate Squid keywords are reported before calling the helper; Delete removes the selected keyword.

### Changed

- The version number is defined once in `src/eduka_block_common.py`; `build.sh`, generated files and translations read it from there, and `Installed-Size` is calculated during the build.
- NetworkManager is reloaded before the firewall service during installation so the first apply already uses the DNS plugin.
- systemd services run with `NoNewPrivileges`, `PrivateTmp` and `ProtectHome`.

## 0.4.1 — 2026-09-05

- Refreshed the complete GTK interface with subtle soft-3D depth, small shadows, layered borders, and theme-adaptive colours.
- Added a red `● BLOCKED` status column for every active website, domain, IP, or CIDR rule.
- Added live password matching feedback and two-field confirmation for account creation and account changes.
- Set the requested password minimum to five characters while retaining PBKDF2-SHA256 hashing with 600,000 iterations and a random salt.
- Bound the managed Squid listener to `127.0.0.1:3128`, preserved the non-local-client ACL, and made original `http_port` restoration reversible.
- Changed nftables updates to a validated, single atomic replacement transaction so the old rule table is not cleared before the new table is ready.
- Added a root-only process lock to prevent state races between the GTK UI, boot service, and Smart IP timer.
- Fixed authentication for Unicode parent/teacher usernames.

## 0.4 — 2026-07-21

- Reduced the default and minimum window size for small laptop displays.
- Compacted the header, logo, cards, spacing, controls, and login dialog.
- Moved website/IP rules and Squid Proxy into separate flat notebook tabs.
- Added secure administrator-account changes from the login screen after current-password verification.
- Added optional Squid forward-proxy keyword ACL management with safe literal validation.
- Added default adult-content keywords, keyword add/remove controls, configuration validation, rollback, and service status.
- Added Squid as a Debian dependency so APT installs it automatically.
- Migrated the persistent state to schema 3 while preserving older rules and settings.

## 0.3 — 2026-07-21

- Reworked the GTK interface with a clean flat-design system.
- Removed gradients and heavy shadows for a lighter, clearer appearance.
- Placed headings, descriptions, hints, labels, and status text in consistent visual boxes.
- Standardised card borders, corner radii, padding, and control geometry.
- Kept all colours adaptive to the active Edukasaun Desktop GTK theme.
- Preserved the complete multilingual and multi-layer blocking engine from version 0.2.

## 0.2 — 2026-07-21

- Changed the default interface language to International English.
- Added Tetum, Portuguese (Portugal), Portuguese (Brazil), and Indonesian.
- Replaced the forced dark palette with adaptive GTK theme colours.
- Added NetworkManager/dnsmasq wildcard protection for every subdomain.
- Added periodic smart A/AAAA discovery and nftables IP synchronization.
- Added explicit IPv4/IPv6 CIDR range support with broad-range safeguards.
- Added layered browser-independent DNS, hosts, and firewall protection.
- Added schema 1 to schema 2 migration preserving version 0.1 rules.
- Added systemd sync timer, DNS health state, tracked-IP counts, and coverage details.
- Updated packaging dependencies, documentation, security model, and tests.

## 0.1 — 2026-07-21

- Initial Eduka-Block development release for Edukasaun OS.
- Added parent/teacher setup and login with PBKDF2 password hashing.
- Added GTK3 interface designed for Eduka-Desktop and LXQt.
- Added persistent domain blocking with a managed `/etc/hosts` section.
- Added persistent IPv4/IPv6 blocking with nftables and systemd.
- Added optional StevenBlack/hosts adult category protection.
- Added PolicyKit privilege separation, validation, backup, and rollback handling.
- Added Debian packaging, desktop integration, AppStream metadata, documentation, and tests.
