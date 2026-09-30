# Changelog

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
