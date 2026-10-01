#!/usr/bin/python3
"""Static protection data for Eduka-Block: category lists, SafeSearch and anti-bypass rules."""

from __future__ import annotations

from pathlib import Path

STEVENBLACK = "https://raw.githubusercontent.com/StevenBlack/hosts/master/"

# Category blocklists. Each is downloaded only when enabled or refreshed, then
# validated (HTTPS host, size, domain count, every domain re-normalised).
BLOCKLISTS: dict[str, dict] = {
    "adult": {"url": STEVENBLACK + "alternates/porn-only/hosts", "min_domains": 1_000},
    "gambling": {"url": STEVENBLACK + "alternates/gambling-only/hosts", "min_domains": 100},
    "social": {"url": STEVENBLACK + "alternates/social-only/hosts", "min_domains": 100},
    "malware": {"url": STEVENBLACK + "hosts", "min_domains": 1_000},
}
# "Recommended protection" in the interface turns these on together with strict mode.
RECOMMENDED_LISTS = ("adult", "gambling", "malware")
MAX_LIST_DOMAINS = 400_000

# SafeSearch: popular search hosts are pinned to the providers' restricted
# endpoints. Their addresses are resolved during sync; the fallbacks below are
# the providers' published, long-lived addresses for offline boots.
GOOGLE_COUNTRY_SUFFIXES = (
    "com", "tl", "co.id", "pt", "com.br", "com.au", "co.uk", "ca", "de", "fr", "es", "it",
    "nl", "be", "ch", "at", "ie", "se", "no", "dk", "fi", "pl", "cz", "gr", "ru", "com.tr",
    "co.jp", "co.kr", "co.in", "com.sg", "com.my", "com.ph", "co.th", "com.vn", "com.hk",
    "com.tw", "co.nz", "co.za", "com.mx", "com.ar", "cl", "com.co", "com.pe", "com.sa",
    "ae", "com.eg", "com.ng", "co.ke", "com.pk", "lk", "com.bd",
)
SAFE_SEARCH: dict[str, dict] = {
    "forcesafesearch.google.com": {
        "fallback": ["216.239.38.120", "2001:4860:4802:32::78"],
        "hosts": [f"www.google.{suffix}" for suffix in GOOGLE_COUNTRY_SUFFIXES]
        + [f"google.{suffix}" for suffix in GOOGLE_COUNTRY_SUFFIXES],
    },
    "restrictmoderate.youtube.com": {
        "fallback": ["216.239.38.119", "2001:4860:4802:32::77"],
        "hosts": [
            "www.youtube.com",
            "m.youtube.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "www.youtube-nocookie.com",
        ],
    },
    "strict.bing.com": {
        "fallback": ["204.79.197.220"],
        "hosts": ["www.bing.com", "bing.com"],
    },
    "safe.duckduckgo.com": {
        "fallback": [],
        "hosts": ["duckduckgo.com", "www.duckduckgo.com"],
    },
}

# Anti-bypass: encrypted DNS lets a browser skip local DNS filtering entirely.
# These hostnames are blocked in DNS and the addresses below are blocked on
# HTTPS (443) and DNS-over-TLS (853) by the firewall. Normal DNS on port 53 to
# these servers keeps working, so a system configured to use them is unaffected.
DOH_HOSTNAMES = (
    "dns.google", "dns.google.com", "dns64.dns.google",
    "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
    "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "family.cloudflare-dns.com",
    "security.cloudflare-dns.com",
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
    "doh.opendns.com", "doh.familyshield.opendns.com",
    "dns.nextdns.io", "doh.cleanbrowsing.org",
    "dns.adguard.com", "dns.adguard-dns.com", "dns-family.adguard.com", "unfiltered.adguard-dns.com",
    "doh.mullvad.net", "dns.mullvad.net", "adblock.dns.mullvad.net",
    "doh.dns.sb", "dns.alidns.com", "doh.pub", "dns.controld.com", "freedns.controld.com",
    "doh.libredns.gr", "dns.switch.ch", "ordns.he.net", "doh.xfinity.com", "dns.twnic.tw",
)
DOH_IPV4 = (
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
    "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",
    "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16",
    "45.90.28.0/24", "45.90.30.0/24",
    "185.228.168.168", "185.228.169.168", "185.228.168.9", "185.228.169.9",
    "76.76.2.0/24", "76.76.10.0/24",
    "194.242.2.2", "185.222.222.222", "45.11.45.11",
)
DOH_IPV6 = (
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112",
    "2606:4700:4700::1002", "2606:4700:4700::1113", "2606:4700:4700::1003",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11", "2620:fe::fe:11",
    "2620:119:35::35", "2620:119:53::53",
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
    "2a07:a8c0::", "2a07:a8c1::",
)
# Firefox disables its automatic DNS-over-HTTPS when this canary name does not resolve.
DOH_CANARY = "use-application-dns.net"

# Browser enterprise policies (the browsers' own supported mechanism).
CHROMIUM_POLICY_DIRS = (
    Path("/etc/chromium/policies/managed"),
    Path("/etc/chromium-browser/policies/managed"),
    Path("/etc/opt/chrome/policies/managed"),
    Path("/etc/brave/policies/managed"),
    Path("/etc/opt/edge/policies/managed"),
)
CHROMIUM_POLICY_NAME = "eduka-block.json"
CHROMIUM_POLICIES = {
    "DnsOverHttpsMode": "off",
    "ForceGoogleSafeSearch": True,
    "ForceYouTubeRestrict": 1,
    "SafeSitesFilterBehavior": 1,
}
FIREFOX_POLICY_PATH = Path("/etc/firefox/policies/policies.json")
FIREFOX_POLICIES = {
    "DNSOverHTTPS": {"Enabled": False, "Locked": True},
}
