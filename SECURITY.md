# Security model — Eduka-Block 0.4.2

Eduka-Block separates its unprivileged GTK interface from a small root helper.

## Trust boundaries

1. The GTK process reads public state and verifies the parent/teacher PBKDF2 password.
2. Every system mutation is sent as bounded JSON over standard input to the fixed helper path.
3. `pkexec` and the installed PolicyKit action require an administrator before the helper runs as root.
4. The helper validates every domain, IP address, category, identifier, download URL, response size, and state schema again.
5. It never executes a shell or incorporates unvalidated input into a command line.
6. A root-only process lock (`/run/eduka-block.lock`, in the root-owned `/run` directory rather than world-writable `/run/lock`) serializes UI, boot-service, and Smart IP timer mutations. Waiting is limited to 90 seconds. Slow DNS lookups and list downloads happen before the lock is taken.

The version 0.2 security engine adds a NetworkManager/dnsmasq wildcard layer and a systemd smart-IP
timer. Both invoke the same validated helper and use fixed file paths.

The application password protects the interface from casual access. PolicyKit and the operating-system administrator account provide the actual privilege boundary. Someone who knows the root/administrator password can always remove or bypass local parental-control software.

Changing the account from the login screen first verifies the current username and password. Writing the replacement credential file additionally requires PolicyKit administrator authorisation.

## Credentials

`/usr/share/Eduka-Block/credentials.txt` is a deliberately human-readable UTF-8 file. It stores only:

- username
- `PBKDF2-SHA256` algorithm name
- 600,000 iteration count
- random 128-bit salt
- derived 256-bit password hash

It never stores the original password. New and changed accounts require two matching password fields and a minimum of five characters. The file is root-owned and mode 0644 so ordinary users can inspect it for transparency but cannot modify it. Five characters is only the accepted minimum; a longer, unique parent/teacher password is strongly recommended because a readable hash can be attacked offline.

## System files

- `/etc/hosts` updates are atomic and keep unrelated lines.
- Marker corruption stops the operation instead of guessing what to delete.
- The first original hosts content is backed up with mode 0600.
- State changes attempt rollback if hosts or firewall application fails.
- The nftables table uses the dedicated name `inet eduka_block` and only an output chain.
- Each nftables update is syntax-checked, then deletes/recreates the dedicated table in one `nft -f` transaction. The previous table remains active if validation fails.
- Overlapping or adjacent addresses and ranges are merged before rendering, because nftables interval sets reject overlapping elements.
- NetworkManager wildcard rules are generated only for validated manual domains.
- Smart DNS resolution reads the real upstream servers exposed by NetworkManager,
  falls back only when none are available, and accepts only public A/AAAA answers.
- Learned IP addresses are refreshed every 15 minutes and old addresses remain
  protected when a temporary DNS lookup fails.
- Explicit CIDR rules reject extremely broad prefixes to limit accidental damage.
- Package removal invokes the helper to remove only Eduka-Block's managed section and table.

Smart IP protection deliberately does not infer whole provider/CDN subnets. Shared
addresses can host unrelated services, so expanding one domain to an entire subnet
would create unsafe collateral blocking. Administrators can add a reviewed CIDR rule
explicitly.

## Import

- Imported files are parsed by the unprivileged interface only to extract candidate targets; the helper validates every entry again with the same rules as a manual addition.
- One import accepts at most 1,000 entries and a 256 KiB request. Duplicates, subdomains already covered by a blocked parent domain, and invalid lines are counted and skipped.
- Imported domains receive smart IP addresses at the next synchronisation instead of resolving hundreds of names while the lock is held.

## Squid Proxy layer

- Squid is an additional forward-proxy layer on `127.0.0.1:3128`. Version 0.4.1 both binds the managed listener to localhost and retains a defense-in-depth ACL that denies non-local clients, preventing a LAN/open proxy. Original active `http_port` directives are preserved as managed comments and restored when Squid protection is disabled.
- User-entered keywords are treated as literal data. They are lower-cased, limited to 2–40 ASCII letters/numbers with spaces or hyphens, deduplicated, and capped at 100.
- The root helper generates the regular expressions and fixed ACL directives. Raw regular expressions and Squid directives are never accepted from the interface.
- The managed include is inserted before the first active allow rule, while Squid's standard safe-port rules remain unchanged.
- `squid -k parse` must succeed before the service is restarted. State and all affected Squid files are restored if parsing or restart fails.
- Eduka-Block does not perform SSL bump, install a local certificate authority, or decrypt HTTPS content. For proxied HTTPS it filters the destination hostname exposed to the forward proxy, not encrypted paths or page bodies.
- Keyword rules can cause false positives. Parents and teachers are responsible for reviewing broad terms such as `sex`.

## Adult blocklist

The optional adult list is fetched only from the hard-coded HTTPS endpoint on `raw.githubusercontent.com`. Redirect destination, maximum byte size, minimum/maximum domain count, UTF-8 decoding, and every domain are validated. Third-party blocklist content can still contain false positives or omissions.

## Reporting

Security issues should be reported privately to the Edukasaun OS maintainers before public disclosure.
