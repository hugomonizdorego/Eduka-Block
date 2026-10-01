#!/usr/bin/python3
"""Privileged, narrowly-scoped system helper for Eduka-Block."""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from eduka_block_common import (
    APP_SHARE_DIR,
    DOMAIN_RE,
    APP_VERSION,
    CATEGORIES,
    CREDENTIALS_PATH,
    ValidationError,
    aliases_for_domain,
    create_credentials_text,
    normalize_target,
    read_credentials,
    rule_target,
)
from eduka_block_data import (
    BLOCKLISTS,
    CHROMIUM_POLICIES,
    CHROMIUM_POLICY_DIRS,
    CHROMIUM_POLICY_NAME,
    DOH_CANARY,
    DOH_HOSTNAMES,
    DOH_IPV4,
    DOH_IPV6,
    FIREFOX_POLICIES,
    FIREFOX_POLICY_PATH,
    MAX_LIST_DOMAINS,
    SAFE_SEARCH,
)


STATE_DIR = Path("/var/lib/eduka-block")
STATE_PATH = STATE_DIR / "blocklist.json"
FIREFOX_POLICY_BACKUP_PATH = STATE_DIR / "firefox-policies.original.json"
HOSTS_PATH = Path("/etc/hosts")
HOSTS_BACKUP_PATH = STATE_DIR / "hosts.original-backup"
DNSMASQ_RULES_PATH = Path("/etc/NetworkManager/dnsmasq.d/eduka-block.conf")
DNSMASQ_LISTS_PATH = Path("/etc/NetworkManager/dnsmasq.d/eduka-block-lists.conf")
RESOLV_CONF_PATH = Path("/etc/resolv.conf")
NETWORKMANAGER_CONFIG = Path("/etc/NetworkManager/conf.d/90-eduka-block-dns.conf")
SQUID_MAIN_CONFIG = Path("/etc/squid/squid.conf")
SQUID_CONFIG_PATH = Path("/etc/squid/eduka-block.conf")
SQUID_KEYWORDS_PATH = Path("/etc/squid/eduka-block-keywords.txt")
SQUID_BACKUP_PATH = STATE_DIR / "squid.conf.original-backup"
# /run is root-owned, unlike the world-writable /run/lock directory, so an
# unprivileged user cannot pre-create or hold the lock file.
LOCK_PATH = Path("/run/eduka-block.lock")
LOCK_TIMEOUT_SECONDS = 90
BEGIN_MARKER = "# BEGIN EDUKA-BLOCK MANAGED SECTION"
END_MARKER = "# END EDUKA-BLOCK MANAGED SECTION"
SQUID_BEGIN_MARKER = "# BEGIN EDUKA-BLOCK SQUID INCLUDE"
SQUID_END_MARKER = "# END EDUKA-BLOCK SQUID INCLUDE"
SQUID_ORIGINAL_PORT_PREFIX = "# EDUKA-BLOCK ORIGINAL HTTP_PORT: "
STATE_SCHEMA = 4
MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024
MAX_SMART_DOMAINS = 250
LIST_REFRESH_DAYS = 7
MAX_IMPORT_ITEMS = 1000
MAX_PAYLOAD_BYTES = 256 * 1024
ALLOWED_CATEGORIES = set(CATEGORIES)
MAX_SQUID_KEYWORDS = 100
SQUID_KEYWORD_RE = re.compile(r"^[a-z0-9][a-z0-9 -]{0,38}[a-z0-9]$|^[a-z0-9]{2}$")
DEFAULT_SQUID_KEYWORDS = [
    "adult",
    "hentai",
    "nude",
    "porn",
    "porno",
    "pornography",
    "seks",
    "sex",
    "xnxx",
    "xvideos",
    "xxx",
]


class HelperError(RuntimeError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def default_list_state() -> dict:
    return {"enabled": False, "domain_count": 0, "updated_at": None}


def default_state() -> dict:
    return {
        "schema": STATE_SCHEMA,
        "entries": [],
        "lists": {key: default_list_state() for key in BLOCKLISTS},
        # Strict mode = SafeSearch + anti-bypass. On by default: without it a
        # browser using encrypted DNS skips every DNS rule.
        "strict_mode": {"enabled": True, "safe_ips": {}, "updated_at": None},
        "dns_mode": None,
        "smart_sync": {"last_run": None},
        "squid_proxy": {
            "enabled": False,
            "keywords": list(DEFAULT_SQUID_KEYWORDS),
            "last_applied_at": None,
        },
    }


def migrate_state(data: dict) -> dict:
    schema = data.get("schema")
    if schema not in {1, 2, 3, STATE_SCHEMA} or not isinstance(data.get("entries"), list):
        raise HelperError("err_state_version")
    data["schema"] = STATE_SCHEMA
    for entry in data["entries"]:
        if entry.get("kind") == "domain":
            entry.setdefault("smart", True)
            entry.setdefault("resolved_ips", [])
            entry.setdefault("last_resolved_at", None)
        else:
            entry["smart"] = False
            entry["resolved_ips"] = []
    lists = data.get("lists")
    if not isinstance(lists, dict):
        lists = {}
    # Schema <= 3 had a single adult list; its cache file name is unchanged.
    legacy = data.pop("adult_protection", None)
    if isinstance(legacy, dict) and "adult" not in lists:
        lists["adult"] = {
            "enabled": bool(legacy.get("enabled")),
            "domain_count": int(legacy.get("domain_count") or 0),
            "updated_at": legacy.get("updated_at"),
        }
    for key in BLOCKLISTS:
        current = lists.get(key)
        lists[key] = {**default_list_state(), **(current if isinstance(current, dict) else {})}
    data["lists"] = {key: lists[key] for key in BLOCKLISTS}
    strict = data.get("strict_mode")
    if not isinstance(strict, dict):
        strict = {}
    data["strict_mode"] = {**default_state()["strict_mode"], **strict}
    data.setdefault("dns_mode", None)
    data.setdefault("smart_sync", {"last_run": None})
    squid = data.get("squid_proxy")
    if not isinstance(squid, dict):
        data["squid_proxy"] = default_state()["squid_proxy"]
    else:
        squid.setdefault("enabled", False)
        squid.setdefault("keywords", list(DEFAULT_SQUID_KEYWORDS))
        squid.setdefault("last_applied_at", None)
    return data


def load_state(path: Path | None = None) -> dict:
    path = path or STATE_PATH
    if not path.exists():
        return default_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HelperError("err_state_read") from exc
    return migrate_state(data)


def atomic_write(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


@contextmanager
def exclusive_system_lock():
    """Serialize UI, timer and boot-service mutations of shared system state."""
    require_root()
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(LOCK_PATH, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise HelperError("err_busy")
                time.sleep(0.25)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def normalize_squid_keywords(values: object) -> list[str]:
    if not isinstance(values, list):
        raise HelperError("err_squid_keyword")
    keywords: list[str] = []
    for raw in values:
        keyword = " ".join(str(raw).strip().lower().split())
        if not SQUID_KEYWORD_RE.fullmatch(keyword):
            raise HelperError("err_squid_keyword")
        if keyword not in keywords:
            keywords.append(keyword)
    if not keywords or len(keywords) > MAX_SQUID_KEYWORDS:
        raise HelperError("err_squid_keywords_limit")
    return sorted(keywords)


def squid_keyword_pattern(keyword: str) -> str:
    escaped = re.escape(keyword).replace(r"\ ", "[^a-z0-9]+")
    return escaped


def render_squid_keywords(keywords: list[str], path: Path = SQUID_KEYWORDS_PATH) -> None:
    normalized = normalize_squid_keywords(keywords)
    lines = [f"# Generated by Eduka-Block {APP_VERSION}. Use the application to edit."]
    lines.extend(squid_keyword_pattern(keyword) for keyword in normalized)
    atomic_write(path, "\n".join(lines) + "\n", 0o644)


def render_squid_config(path: Path = SQUID_CONFIG_PATH) -> None:
    content = "\n".join(
        [
            f"# Eduka-Block {APP_VERSION} managed Squid ACL",
            "# Bind the managed proxy socket to this computer only.",
            "http_port 127.0.0.1:3128",
            "# These deny rules are inserted before Squid's allow rules.",
            "acl eduka_block_localhost src 127.0.0.1/32 ::1",
            f'acl eduka_block_url url_regex -i "{SQUID_KEYWORDS_PATH}"',
            f'acl eduka_block_domain dstdom_regex -i "{SQUID_KEYWORDS_PATH}"',
            "http_access deny !eduka_block_localhost",
            "http_access deny eduka_block_url",
            "http_access deny eduka_block_domain",
            "",
        ]
    )
    atomic_write(path, content, 0o644)


def remove_squid_include(content: str) -> str:
    output: list[str] = []
    inside = False
    saw_begin = False
    changed = False
    for line in content.splitlines():
        if line.strip() == SQUID_BEGIN_MARKER:
            if inside or saw_begin:
                raise HelperError("err_squid_config")
            inside = True
            saw_begin = True
            changed = True
            continue
        if line.strip() == SQUID_END_MARKER:
            if not inside:
                raise HelperError("err_squid_config")
            inside = False
            changed = True
            continue
        if not inside:
            stripped = line.lstrip()
            if stripped.startswith(SQUID_ORIGINAL_PORT_PREFIX):
                original = stripped[len(SQUID_ORIGINAL_PORT_PREFIX) :]
                if not re.match(r"^http_port(?:\s+|$)", original):
                    raise HelperError("err_squid_config")
                indentation = line[: len(line) - len(stripped)]
                output.append(indentation + original)
                changed = True
            else:
                output.append(line)
    if inside:
        raise HelperError("err_squid_config")
    return "\n".join(output).rstrip() + "\n" if changed else content


def install_squid_include(
    main_path: Path = SQUID_MAIN_CONFIG,
    backup_path: Path = SQUID_BACKUP_PATH,
) -> None:
    try:
        current = main_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise HelperError("err_squid_config_read") from exc
    if not backup_path.exists():
        atomic_write(backup_path, current, 0o600)
    clean = remove_squid_include(current)
    lines = clean.rstrip().splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"^http_port(?:\s+|$)", stripped):
            indentation = line[: len(line) - len(line.lstrip())]
            lines[index] = indentation + SQUID_ORIGINAL_PORT_PREFIX + stripped
    insertion = len(lines)
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("http_access allow") or stripped == "http_access deny all":
            insertion = index
            break
    managed = [SQUID_BEGIN_MARKER, f"include {SQUID_CONFIG_PATH}", SQUID_END_MARKER]
    lines[insertion:insertion] = managed
    mode = stat.S_IMODE(main_path.stat().st_mode)
    atomic_write(main_path, "\n".join(lines) + "\n", mode)


def remove_squid_files(main_path: Path = SQUID_MAIN_CONFIG) -> None:
    if main_path.exists():
        try:
            current = main_path.read_text(encoding="utf-8")
            clean = remove_squid_include(current)
            if clean != current:
                atomic_write(main_path, clean, stat.S_IMODE(main_path.stat().st_mode))
        except (OSError, UnicodeError, HelperError) as exc:
            raise HelperError("err_squid_config") from exc
    for path in (SQUID_CONFIG_PATH, SQUID_KEYWORDS_PATH):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def save_state(data: dict, path: Path | None = None) -> None:
    path = path or STATE_PATH
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n", 0o644)


def remove_managed_section(content: str) -> str:
    output: list[str] = []
    inside = False
    saw_begin = False
    for line in content.splitlines():
        if line.strip() == BEGIN_MARKER:
            if inside or saw_begin:
                raise HelperError("err_marker")
            inside = True
            saw_begin = True
            continue
        if line.strip() == END_MARKER:
            if not inside:
                raise HelperError("err_marker")
            inside = False
            continue
        if not inside:
            output.append(line)
    if inside:
        raise HelperError("err_marker")
    return "\n".join(output).rstrip() + "\n"


def list_path(key: str, directory: Path | None = None) -> Path:
    directory = directory or STATE_DIR
    # "adult-domains.txt" keeps the file name used by versions up to 0.4.2.
    return directory / f"{key}-domains.txt"


def read_list_domains(path: Path) -> list[str]:
    """Read a cached category list written by this helper (one domain per line)."""
    if not path.exists():
        return []
    domains: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        candidate = line.strip().lower()
        if candidate and DOMAIN_RE.fullmatch(candidate):
            domains.append(candidate)
    return domains


def enabled_list_domains(state: dict, directory: Path | None = None) -> set[str]:
    domains: set[str] = set()
    for key, settings in state.get("lists", {}).items():
        if key in BLOCKLISTS and settings.get("enabled"):
            domains.update(read_list_domains(list_path(key, directory)))
    return domains


def manual_domains(state: dict) -> list[str]:
    return sorted({e["value"] for e in state["entries"] if e.get("kind") == "domain"})


def strict_enabled(state: dict) -> bool:
    return bool(state.get("strict_mode", {}).get("enabled"))


def wildcard_blocked_domains(state: dict) -> set[str]:
    """Domains blocked together with all of their subdomains."""
    domains = set(manual_domains(state))
    if strict_enabled(state):
        domains.update(DOH_HOSTNAMES)
    return domains


def is_covered(name: str, domains: set[str]) -> bool:
    labels = name.split(".")
    return any(".".join(labels[index:]) in domains for index in range(len(labels) - 1))


def safe_search_records(state: dict, blocked: set[str]) -> list[tuple[str, str]]:
    """(address, hostname) pairs pinning search engines to their restricted mode."""
    if not strict_enabled(state):
        return []
    resolved = state.get("strict_mode", {}).get("safe_ips", {})
    records: list[tuple[str, str]] = []
    for endpoint, settings in SAFE_SEARCH.items():
        addresses = resolved.get(endpoint) or settings["fallback"]
        for host in settings["hosts"]:
            # A blocked site stays blocked; SafeSearch must not re-open it.
            if is_covered(host, blocked):
                continue
            records.extend((address, host) for address in addresses)
    return records


def detect_dns_mode(resolv_path: Path | None = None) -> str:
    """"dnsmasq" when NetworkManager's dnsmasq is the system resolver, else "hosts"."""
    resolv_path = resolv_path or RESOLV_CONF_PATH
    if not NETWORKMANAGER_CONFIG.exists():
        return "hosts"
    try:
        content = resolv_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "hosts"
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver" and parts[1] == "127.0.0.1":
            return "dnsmasq"
    return "hosts"


def render_hosts(
    state: dict,
    hosts_path: Path | None = None,
    backup_path: Path | None = None,
    list_domains: set[str] | None = None,
    lists_in_hosts: bool = True,
) -> None:
    hosts_path = hosts_path or HOSTS_PATH
    backup_path = backup_path or HOSTS_BACKUP_PATH
    try:
        current = hosts_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise HelperError("err_hosts_read") from exc
    if not backup_path.exists():
        atomic_write(backup_path, current, 0o600)
    if list_domains is None:
        list_domains = enabled_list_domains(state)

    clean = remove_managed_section(current)
    wildcard = wildcard_blocked_domains(state)
    exact: set[str] = set()
    for domain in wildcard:
        exact.update(aliases_for_domain(domain))
    # Large category lists stay out of /etc/hosts when dnsmasq serves them:
    # every name lookup scans this file from top to bottom.
    listed = sorted(list_domains - exact) if lists_in_hosts else []
    safe = safe_search_records(state, wildcard | list_domains)

    if exact or listed or safe:
        managed = ["", BEGIN_MARKER, "# Generated by Eduka-Block. Use the app to edit."]
        for domain in sorted(exact):
            managed.append(f"0.0.0.0 {domain}")
            managed.append(f":: {domain}")
        if safe:
            managed.append("# SafeSearch")
            managed.extend(f"{address} {host}" for address, host in safe)
        if listed:
            managed.append("# Category lists")
            managed.extend(f"0.0.0.0 {domain}" for domain in listed)
        managed.extend([END_MARKER, ""])
        new_content = clean.rstrip() + "\n" + "\n".join(managed)
    else:
        new_content = clean

    file_stat = hosts_path.stat()
    descriptor, temp_name = tempfile.mkstemp(prefix=".hosts.eduka-block.", dir=str(hosts_path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(file_stat.st_mode))
            try:
                os.fchown(stream.fileno(), file_stat.st_uid, file_stat.st_gid)
            except PermissionError:
                pass
            stream.write(new_content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, hosts_path)
    except OSError as exc:
        raise HelperError("err_hosts_write") from exc
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _write_or_remove(path: Path, lines: list[str]) -> None:
    if lines:
        atomic_write(path, "\n".join(lines) + "\n", 0o644)
    else:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def render_dnsmasq(
    state: dict,
    path: Path | None = None,
    lists_path: Path | None = None,
    list_domains: set[str] | None = None,
    lists_in_dnsmasq: bool = False,
) -> None:
    path = path or DNSMASQ_RULES_PATH
    lists_path = lists_path or DNSMASQ_LISTS_PATH
    lines: list[str] = []
    domains = sorted(wildcard_blocked_domains(state))
    if domains or strict_enabled(state):
        lines = [
            f"# Eduka-Block {APP_VERSION} - generated file",
            "# Blocks each selected domain and every subdomain.",
        ]
        for domain in domains:
            lines.append(f"local=/{domain}/")
            lines.append(f"address=/{domain}/0.0.0.0")
            lines.append(f"address=/{domain}/::")
        if strict_enabled(state):
            lines.append("# Tell Firefox not to switch to DNS-over-HTTPS (answers NXDOMAIN).")
            lines.append(f"address=/{DOH_CANARY}/")
    _write_or_remove(path, lines)

    listed: list[str] = []
    if lists_in_dnsmasq:
        if list_domains is None:
            list_domains = enabled_list_domains(state)
        listed = sorted(list_domains)
    _write_or_remove(
        lists_path,
        ([f"# Eduka-Block {APP_VERSION} - category lists (NXDOMAIN, all subdomains)"]
         + [f"address=/{domain}/" for domain in listed]) if listed else [],
    )


def reload_dns_plugin(full: bool = True) -> bool:
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return False
    command = [nmcli, "general", "reload"]
    if full:
        command.append("dns-full")
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return result.returncode == 0


def squid_binary(required: bool = True) -> str | None:
    binary = shutil.which("squid")
    if not binary and Path("/usr/sbin/squid").is_file():
        binary = "/usr/sbin/squid"
    if not binary and required:
        raise HelperError("err_squid_missing")
    return binary


def squid_running() -> bool:
    if not squid_binary(required=False):
        return False
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return False
    result = subprocess.run(
        [systemctl, "is-active", "--quiet", "squid.service"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def validate_squid_configuration() -> None:
    binary = squid_binary(required=True)
    result = subprocess.run(
        [str(binary), "-k", "parse"],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise HelperError("err_squid_config", (result.stderr or result.stdout).strip())


def reload_squid(start: bool) -> None:
    systemctl = shutil.which("systemctl")
    if systemctl:
        if start:
            enable_result = subprocess.run(
                [systemctl, "enable", "squid.service"],
                text=True,
                capture_output=True,
                check=False,
            )
            if enable_result.returncode != 0:
                raise HelperError("err_squid_service", enable_result.stderr.strip())
            action = "restart"
        elif squid_running():
            action = "reload"
        else:
            return
        result = subprocess.run(
            [systemctl, action, "squid.service"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise HelperError("err_squid_service", result.stderr.strip())
        return
    if start:
        raise HelperError("err_squid_service", "systemd is not available")


def apply_squid_configuration(state: dict) -> None:
    squid = state.get("squid_proxy", {})
    enabled = bool(squid.get("enabled"))
    if enabled:
        keywords = normalize_squid_keywords(squid.get("keywords"))
        squid_binary(required=True)
        render_squid_keywords(keywords)
        render_squid_config()
        install_squid_include()
        validate_squid_configuration()
        reload_squid(start=True)
        return
    remove_squid_files()
    if squid_binary(required=False) and SQUID_MAIN_CONFIG.exists():
        validate_squid_configuration()
        reload_squid(start=False)


def snapshot_files(paths: tuple[Path, ...]) -> dict[Path, tuple[str, int] | None]:
    snapshot: dict[Path, tuple[str, int] | None] = {}
    for path in paths:
        try:
            snapshot[path] = (path.read_text(encoding="utf-8"), stat.S_IMODE(path.stat().st_mode))
        except FileNotFoundError:
            snapshot[path] = None
        except (OSError, UnicodeError) as exc:
            raise HelperError("err_squid_config_read") from exc
    return snapshot


def restore_files(snapshot: dict[Path, tuple[str, int] | None]) -> None:
    for path, saved in snapshot.items():
        if saved is None:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        else:
            content, mode = saved
            atomic_write(path, content, mode)


def nft_binary() -> str:
    binary = shutil.which("nft")
    if not binary:
        raise HelperError("err_nft_missing")
    return binary


def clear_firewall() -> None:
    binary = nft_binary()
    subprocess.run(
        [binary, "delete", "table", "inet", "eduka_block"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def _collapsed(networks: list) -> list[str]:
    """Merge overlapping/adjacent ranges; nft interval sets reject overlaps."""
    output: list[str] = []
    for network in ipaddress.collapse_addresses(networks):
        if network.prefixlen == network.max_prefixlen:
            output.append(network.network_address.compressed)
        else:
            output.append(network.with_prefixlen)
    return output


def firewall_elements(state: dict) -> tuple[list[str], list[str]]:
    ipv4: list = []
    ipv6: list = []
    for entry in state["entries"]:
        kind = entry.get("kind")
        raw_values: list = []
        if kind in {"ipv4", "ipv4_network", "ipv6", "ipv6_network"}:
            raw_values = [entry.get("value")]
        elif kind == "domain" and entry.get("smart"):
            raw_values = list(entry.get("resolved_ips", []))
        for raw in raw_values:
            try:
                network = ipaddress.ip_network(str(raw), strict=False)
            except ValueError:
                continue
            (ipv4 if network.version == 4 else ipv6).append(network)
    return _collapsed(ipv4), _collapsed(ipv6)


def build_ruleset(state: dict, table_exists: bool) -> str:
    """Return the complete nft script replacing the ``inet eduka_block`` table."""
    ipv4, ipv6 = firewall_elements(state)
    strict = strict_enabled(state)
    doh4 = _collapsed([ipaddress.ip_network(value) for value in DOH_IPV4]) if strict else []
    doh6 = _collapsed([ipaddress.ip_network(value) for value in DOH_IPV6]) if strict else []
    lines: list[str] = []
    if table_exists:
        lines.append("delete table inet eduka_block")
    if not (ipv4 or ipv6 or strict):
        return "\n".join(lines) + "\n" if lines else ""

    def add_set(name: str, family: str, elements: list[str]) -> None:
        lines.extend(
            [
                f"  set {name} {{",
                f"    type {family}",
                "    flags interval",
                f"    elements = {{ {', '.join(elements)} }}",
                "  }",
            ]
        )

    lines.append("table inet eduka_block {")
    if ipv4:
        add_set("blocked_ipv4", "ipv4_addr", ipv4)
    if ipv6:
        add_set("blocked_ipv6", "ipv6_addr", ipv6)
    if doh4:
        add_set("doh_ipv4", "ipv4_addr", doh4)
    if doh6:
        add_set("doh_ipv6", "ipv6_addr", doh6)
    lines.extend(["  chain output {", "    type filter hook output priority 0; policy accept;"])
    if ipv4:
        lines.append("    ip daddr @blocked_ipv4 drop")
    if ipv6:
        lines.append("    ip6 daddr @blocked_ipv6 drop")
    if strict:
        # Encrypted DNS would bypass every DNS rule: block DNS-over-TLS
        # everywhere and HTTPS/QUIC to well-known public DoH resolvers.
        lines.append("    meta l4proto { tcp, udp } th dport 853 drop")
        if doh4:
            lines.append("    ip daddr @doh_ipv4 meta l4proto { tcp, udp } th dport 443 drop")
        if doh6:
            lines.append("    ip6 daddr @doh_ipv6 meta l4proto { tcp, udp } th dport 443 drop")
    lines.extend(["  }", "}"])
    return "\n".join(lines) + "\n"


def apply_firewall(state: dict) -> None:
    binary = nft_binary()
    exists = subprocess.run(
        [binary, "list", "table", "inet", "eduka_block"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0
    ruleset = build_ruleset(state, exists)
    if not ruleset:
        return
    checked = subprocess.run(
        [binary, "--check", "-f", "-"],
        input=ruleset,
        text=True,
        capture_output=True,
        check=False,
    )
    if checked.returncode != 0:
        raise HelperError("err_firewall", checked.stderr.strip())
    result = subprocess.run(
        [binary, "-f", "-"], input=ruleset, text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        raise HelperError("err_firewall", result.stderr.strip())


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise HelperError("err_browser_policy", str(path))
    if not isinstance(data, dict):
        raise HelperError("err_browser_policy", str(path))
    return data


def apply_firefox_policy(
    enabled: bool,
    path: Path | None = None,
    backup_path: Path | None = None,
) -> None:
    """Merge Eduka-Block's keys into Firefox policies and undo them precisely.

    The administrator's other policies are kept. The previous value of every
    key we set is saved once, so disabling restores exactly what was there.
    """
    path = path or FIREFOX_POLICY_PATH
    backup_path = backup_path or FIREFOX_POLICY_BACKUP_PATH
    current = _read_json(path)
    if enabled:
        data = current or {}
        policies = data.setdefault("policies", {})
        if not isinstance(policies, dict):
            raise HelperError("err_browser_policy", str(path))
        if not backup_path.exists():
            previous = {key: policies[key] for key in FIREFOX_POLICIES if key in policies}
            atomic_write(
                backup_path,
                json.dumps({"file_existed": current is not None, "previous": previous}, indent=2),
                0o600,
            )
        policies.update(json.loads(json.dumps(FIREFOX_POLICIES)))
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n", 0o644)
        return
    try:
        backup = json.loads(backup_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return  # Nothing of ours to undo.
    if current is not None:
        policies = current.get("policies", {})
        if isinstance(policies, dict):
            for key in FIREFOX_POLICIES:
                policies.pop(key, None)
            policies.update(backup.get("previous", {}))
            if not policies and not backup.get("file_existed") and set(current) <= {"policies"}:
                path.unlink()
            else:
                atomic_write(path, json.dumps(current, indent=2, ensure_ascii=False) + "\n", 0o644)
    backup_path.unlink()


def apply_chromium_policies(enabled: bool, directories: tuple[Path, ...] | None = None) -> None:
    directories = directories or CHROMIUM_POLICY_DIRS
    content = json.dumps(CHROMIUM_POLICIES, indent=2) + "\n"
    for directory in directories:
        path = directory / CHROMIUM_POLICY_NAME
        if enabled:
            directory.mkdir(parents=True, exist_ok=True, mode=0o755)
            atomic_write(path, content, 0o644)
        else:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def apply_browser_policies(state: dict) -> bool:
    """Best effort: a broken third-party policy file must not undo other layers."""
    enabled = strict_enabled(state)
    ok = True
    for apply in (apply_chromium_policies, apply_firefox_policy):
        try:
            apply(enabled)
        except (HelperError, OSError) as exc:
            ok = False
            print(f"eduka-block: browser policy not applied: {exc}", file=sys.stderr)
    return ok


def apply_system(state: dict) -> str:
    """Apply every protection layer; return the DNS mode that was used."""
    mode = detect_dns_mode()
    list_domains = enabled_list_domains(state)
    render_hosts(state, list_domains=list_domains, lists_in_hosts=mode != "dnsmasq")
    render_dnsmasq(state, list_domains=list_domains, lists_in_dnsmasq=mode == "dnsmasq")
    apply_firewall(state)
    apply_browser_policies(state)
    reload_dns_plugin(full=True)
    return mode


def apply_transaction(old_state: dict, new_state: dict) -> None:
    new_state["dns_mode"] = detect_dns_mode()
    save_state(new_state)
    try:
        apply_system(new_state)
    except Exception:
        save_state(old_state)
        try:
            apply_system(old_state)
        except Exception:
            pass
        raise


def parse_resolv_nameservers(paths: list[Path] | None = None) -> list[str]:
    candidates = paths or [Path("/run/NetworkManager/no-stub-resolv.conf"), Path("/etc/resolv.conf")]
    nameservers: list[str] = []
    for path in candidates:
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for line in content.splitlines():
            parts = line.split()
            if len(parts) < 2 or parts[0] != "nameserver":
                continue
            try:
                address = ipaddress.ip_address(parts[1].split("%", 1)[0])
            except ValueError:
                continue
            if address.is_loopback or address.is_unspecified or address.is_multicast:
                continue
            value = address.compressed
            if value not in nameservers:
                nameservers.append(value)
    return nameservers or ["1.1.1.1", "8.8.8.8"]


def resolve_domain_ips(domain: str, nameservers: list[str] | None = None) -> list[str]:
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return []
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = nameservers or parse_resolv_nameservers()
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    addresses: set[str] = set()
    for name in aliases_for_domain(domain):
        for record_type in ("A", "AAAA"):
            try:
                answer = resolver.resolve(name, record_type, search=False, raise_on_no_answer=False)
            except (dns.exception.DNSException, OSError):
                continue
            if answer.rrset is None:
                continue
            for item in answer:
                try:
                    address = ipaddress.ip_address(item.to_text())
                except ValueError:
                    continue
                if address.is_global:
                    addresses.add(address.compressed)
    return sorted(addresses)


def resolve_smart_domains(state: dict) -> dict[str, list[str]]:
    """Resolve smart domains. Runs before the lock so slow DNS never blocks the UI."""
    resolved: dict[str, list[str]] = {}
    nameservers = parse_resolv_nameservers()
    for entry in state["entries"]:
        if entry.get("kind") != "domain" or not entry.get("smart"):
            continue
        if len(resolved) >= MAX_SMART_DOMAINS:
            break
        domain = entry["value"]
        if domain not in resolved:
            resolved[domain] = resolve_domain_ips(domain, nameservers)
    return resolved


def resolve_safe_ips() -> dict[str, list[str]]:
    nameservers = parse_resolv_nameservers()
    resolved: dict[str, list[str]] = {}
    for endpoint in SAFE_SEARCH:
        addresses = resolve_domain_ips(endpoint, nameservers)
        if addresses:
            resolved[endpoint] = addresses
    return resolved


def list_is_stale(settings: dict, max_age_days: int = LIST_REFRESH_DAYS) -> bool:
    updated = settings.get("updated_at")
    if not updated:
        return True
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(str(updated))
    except ValueError:
        return True
    return age.days >= max_age_days


def prepare_sync(state: dict) -> dict:
    """Network work for the timer: DNS answers, SafeSearch IPs, stale lists."""
    refreshed: dict[str, list[str]] = {}
    for key, settings in state.get("lists", {}).items():
        if key in BLOCKLISTS and settings.get("enabled") and list_is_stale(settings):
            try:
                refreshed[key] = download_blocklist(key)
            except HelperError:
                continue  # Keep the cached copy; try again on the next run.
    return {
        "domains": resolve_smart_domains(state),
        "safe_ips": resolve_safe_ips() if strict_enabled(state) else {},
        "lists": refreshed,
    }


def sync_smart_ips(
    resolved: dict[str, list[str]] | None = None,
    safe_ips: dict[str, list[str]] | None = None,
    lists: dict[str, list[str]] | None = None,
) -> None:
    require_root()
    if resolved is None:
        prepared = prepare_sync(load_state())
        resolved, safe_ips, lists = prepared["domains"], prepared["safe_ips"], prepared["lists"]
    # Re-read under the lock: rules may have changed while DNS was queried.
    state = load_state()
    ips_changed = False
    for entry in state["entries"]:
        if entry.get("kind") != "domain" or not entry.get("smart"):
            continue
        addresses = resolved.get(entry["value"])
        if addresses:
            if addresses != entry.get("resolved_ips", []):
                entry["resolved_ips"] = addresses
                ips_changed = True
            entry["last_resolved_at"] = now_iso()
    full_apply = False
    strict = state["strict_mode"]
    if safe_ips and strict.get("enabled") and safe_ips != strict.get("safe_ips"):
        strict["safe_ips"] = safe_ips
        strict["updated_at"] = now_iso()
        full_apply = True
    for key, domains in (lists or {}).items():
        if state["lists"].get(key, {}).get("enabled"):
            atomic_write(list_path(key), "\n".join(domains) + "\n", 0o644)
            state["lists"][key].update(domain_count=len(domains), updated_at=now_iso())
            full_apply = True
    mode = detect_dns_mode()
    if mode != state.get("dns_mode"):
        # NetworkManager switched resolvers since the last apply (e.g. after
        # installation): move category lists between dnsmasq and /etc/hosts.
        full_apply = True
    state["dns_mode"] = mode
    state["smart_sync"] = {"last_run": now_iso(), "processed": len(resolved)}
    save_state(state)
    if full_apply:
        apply_system(state)
    elif ips_changed:
        apply_firewall(state)


def parse_hosts_download(content: str, min_domains: int = 1_000) -> list[str]:
    domains: set[str] = set()
    for line in content.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        mapping_seen = False
        for token in stripped.split():
            if token in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
                mapping_seen = True
                continue
            if not mapping_seen:
                continue
            try:
                normalized, kind = normalize_target(token)
                if kind == "domain":
                    domains.add(normalized)
            except ValidationError:
                continue
    if not min_domains <= len(domains) <= MAX_LIST_DOMAINS:
        raise HelperError("err_list_integrity")
    return sorted(domains)


def download_blocklist(key: str) -> list[str]:
    if key not in BLOCKLISTS:
        raise HelperError("err_request_format")
    source = BLOCKLISTS[key]
    request = urllib.request.Request(
        source["url"],
        headers={"User-Agent": f"Eduka-Block/{APP_VERSION} (+https://edukasaunos.tl)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "raw.githubusercontent.com":
                raise HelperError("err_list_redirect")
            data = response.read(MAX_DOWNLOAD_BYTES + 1)
    except HelperError:
        raise
    except (OSError, urllib.error.URLError) as exc:
        raise HelperError("err_list_download") from exc
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise HelperError("err_list_large")
    try:
        return parse_hosts_download(data.decode("utf-8"), source["min_domains"])
    except UnicodeError as exc:
        raise HelperError("err_list_encoding") from exc


def require_root() -> None:
    if os.geteuid() != 0:
        raise HelperError("err_root")


def read_payload() -> dict:
    raw = sys.stdin.read(MAX_PAYLOAD_BYTES + 1)
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise HelperError("err_request_large")
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HelperError("err_request_format") from exc
    if not isinstance(payload, dict):
        raise HelperError("err_request_format")
    return payload


def credentials_configured() -> bool:
    return CREDENTIALS_PATH.is_file()


def public_status() -> dict:
    state = load_state()
    tracked = {
        raw
        for entry in state["entries"]
        if entry.get("kind") == "domain" and entry.get("smart")
        for raw in entry.get("resolved_ips", [])
    }
    squid = json.loads(json.dumps(state.get("squid_proxy", default_state()["squid_proxy"])))
    squid["installed"] = bool(squid_binary(required=False))
    squid["running"] = squid_running()
    list_total = sum(
        int(settings.get("domain_count") or 0)
        for settings in state["lists"].values()
        if settings.get("enabled")
    )
    dns_mode = detect_dns_mode()
    return {
        "version": APP_VERSION,
        "configured": credentials_configured(),
        "entries": state["entries"],
        "lists": state["lists"],
        "strict_mode": {
            "enabled": strict_enabled(state),
            "updated_at": state["strict_mode"].get("updated_at"),
        },
        "browser_policies": any(
            (directory / CHROMIUM_POLICY_NAME).exists() for directory in CHROMIUM_POLICY_DIRS
        ),
        "squid_proxy": squid,
        "smart_sync": state.get("smart_sync", {}),
        "manual_count": len(state["entries"]),
        "list_domain_count": list_total,
        "tracked_ip_count": len(tracked),
        "total_count": len(state["entries"]) + list_total + len(tracked),
        "dns_mode": dns_mode,
        "dns_engine": dns_mode == "dnsmasq",
    }


def account_info() -> dict:
    """Return the stored parent/teacher username for account recovery.

    Only reachable through pkexec (root): proving the operating-system
    administrator password is what entitles someone to recover the account.
    """
    require_root()
    if not credentials_configured():
        return {"username": ""}
    try:
        return {"username": read_credentials(CREDENTIALS_PATH)["username"]}
    except ValidationError:
        return {"username": ""}  # Damaged file: the account can still be replaced.


def setup_credentials(payload: dict, replace: bool = False) -> None:
    require_root()
    if credentials_configured() and not replace:
        raise HelperError("err_account_exists")
    text = create_credentials_text(str(payload.get("username", "")), str(payload.get("password", "")))
    APP_SHARE_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(CREDENTIALS_PATH, text, 0o644)


def clean_category(raw: object) -> str:
    category = str(raw or "Manual")
    return category if category in ALLOWED_CATEGORIES else "Other"


def covering_domain(domain: str, entries: list[dict]) -> str | None:
    """Return an existing domain rule whose wildcard already covers ``domain``."""
    blocked = {entry.get("value") for entry in entries if entry.get("kind") == "domain"}
    labels = domain.split(".")
    for index in range(1, len(labels) - 1):
        parent = ".".join(labels[index:])
        if parent in blocked:
            return parent
    return None


def new_entry(value: str, kind: str, category: str, smart: bool, resolved_ips: list[str]) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "value": value,
        "kind": kind,
        "category": category,
        "smart": smart,
        "resolved_ips": resolved_ips,
        "last_resolved_at": now_iso() if resolved_ips else None,
        "created_at": now_iso(),
    }


def add_entry(payload: dict) -> None:
    require_root()
    value, kind = rule_target(str(payload.get("target", "")))
    category = clean_category(payload.get("category"))
    old = load_state()
    if any(entry.get("value") == value for entry in old["entries"]):
        raise HelperError("err_duplicate")
    if kind == "domain":
        parent = covering_domain(value, old["entries"])
        if parent:
            raise HelperError("err_covered", parent)
    smart = kind == "domain" and bool(payload.get("smart", True))
    resolved_ips = resolve_domain_ips(value) if smart else []
    new = json.loads(json.dumps(old))
    new["entries"].append(new_entry(value, kind, category, smart, resolved_ips))
    apply_transaction(old, new)


def import_entries(payload: dict) -> dict:
    """Add many rules in one transaction. Smart IPs are learned by the next sync."""
    require_root()
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        raise HelperError("err_import_empty")
    if len(items) > MAX_IMPORT_ITEMS:
        raise HelperError("err_import_large")
    smart_requested = bool(payload.get("smart", True))
    old = load_state()
    new = json.loads(json.dumps(old))
    known = {entry.get("value") for entry in new["entries"]}
    added = skipped = invalid = 0
    for item in items:
        if not isinstance(item, dict):
            invalid += 1
            continue
        try:
            value, kind = rule_target(str(item.get("target", "")))
        except ValidationError:
            invalid += 1
            continue
        if value in known or (kind == "domain" and covering_domain(value, new["entries"])):
            skipped += 1
            continue
        smart = kind == "domain" and smart_requested
        new["entries"].append(new_entry(value, kind, clean_category(item.get("category")), smart, []))
        known.add(value)
        added += 1
    if added:
        apply_transaction(old, new)
    return {"added": added, "skipped": skipped, "invalid": invalid}


def remove_entry(payload: dict) -> None:
    """Remove one rule (``id``) or several rules (``ids``) in one transaction."""
    require_root()
    raw_ids = payload.get("ids")
    if raw_ids is None:
        raw_ids = [payload.get("id", "")]
    if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > MAX_IMPORT_ITEMS:
        raise HelperError("err_request_format")
    entry_ids = {str(value) for value in raw_ids}
    old = load_state()
    new = json.loads(json.dumps(old))
    new["entries"] = [entry for entry in new["entries"] if entry.get("id") not in entry_ids]
    if len(new["entries"]) == len(old["entries"]):
        raise HelperError("err_not_found")
    apply_transaction(old, new)


def prepare_protection(payload: dict) -> dict:
    """Download the lists a protection change needs, before taking the lock."""
    requested = validated_list_request(payload)
    state = load_state()
    refresh = bool(payload.get("refresh"))
    downloads: dict[str, list[str]] = {}
    for key, enabled in requested.items():
        currently = state["lists"][key]
        if enabled and (refresh or not currently.get("enabled") or not list_path(key).exists()):
            downloads[key] = download_blocklist(key)
    if refresh:
        # "Update all" also refreshes lists that stay enabled but were not named.
        for key, settings in state["lists"].items():
            if settings.get("enabled") and key not in requested:
                downloads[key] = download_blocklist(key)
    strict = payload.get("strict", strict_enabled(state))
    return {"lists": downloads, "safe_ips": resolve_safe_ips() if strict else {}}


def validated_list_request(payload: dict) -> dict[str, bool]:
    requested = payload.get("lists", {})
    if not isinstance(requested, dict) or any(key not in BLOCKLISTS for key in requested):
        raise HelperError("err_request_format")
    return {key: bool(value) for key, value in requested.items()}


def configure_protection(payload: dict, prepared: dict | None = None) -> None:
    """Turn category lists and strict mode on/off in one transaction."""
    require_root()
    requested = validated_list_request(payload)
    if prepared is None:
        prepared = prepare_protection(payload)
    old = load_state()
    new = json.loads(json.dumps(old))
    for key, enabled in requested.items():
        new["lists"][key]["enabled"] = enabled
    if "strict" in payload:
        new["strict_mode"]["enabled"] = bool(payload["strict"])
    if prepared.get("safe_ips"):
        new["strict_mode"]["safe_ips"] = prepared["safe_ips"]
        new["strict_mode"]["updated_at"] = now_iso()

    previous: dict[Path, str | None] = {}
    try:
        for key, domains in prepared.get("lists", {}).items():
            path = list_path(key)
            previous[path] = path.read_text(encoding="utf-8") if path.exists() else None
            atomic_write(path, "\n".join(domains) + "\n", 0o644)
            new["lists"][key].update(domain_count=len(domains), updated_at=now_iso())
        for key, settings in new["lists"].items():
            if settings["enabled"] and not list_path(key).exists():
                raise HelperError("err_list_download")
        apply_transaction(old, new)
    except Exception:
        for path, content in previous.items():
            if content is None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            else:
                atomic_write(path, content, 0o644)
        try:
            apply_system(old)
        except Exception:
            pass
        raise


# 0.4.x action names, kept so older scripts and the postinst keep working.
LEGACY_ADULT_ACTIONS = {
    "adult-enable": {"lists": {"adult": True}},
    "adult-update": {"lists": {"adult": True}, "refresh": True},
    "adult-disable": {"lists": {"adult": False}},
}


def configure_squid_proxy(payload: dict) -> None:
    require_root()
    enabled = bool(payload.get("enabled"))
    keywords = normalize_squid_keywords(payload.get("keywords"))
    old = load_state()
    new = json.loads(json.dumps(old))
    new["squid_proxy"] = {
        "enabled": enabled,
        "keywords": keywords,
        "last_applied_at": now_iso(),
    }
    paths = (SQUID_MAIN_CONFIG, SQUID_CONFIG_PATH, SQUID_KEYWORDS_PATH, SQUID_BACKUP_PATH)
    snapshot = snapshot_files(paths)
    save_state(new)
    try:
        apply_squid_configuration(new)
    except Exception:
        save_state(old)
        restore_files(snapshot)
        try:
            if squid_binary(required=False) and SQUID_MAIN_CONFIG.exists():
                validate_squid_configuration()
                reload_squid(start=bool(old.get("squid_proxy", {}).get("enabled")))
        except Exception:
            pass
        raise


def cleanup_system() -> None:
    require_root()
    try:
        current = HOSTS_PATH.read_text(encoding="utf-8")
        cleaned = remove_managed_section(current)
        if cleaned != current:
            file_stat = HOSTS_PATH.stat()
            atomic_write(HOSTS_PATH, cleaned, stat.S_IMODE(file_stat.st_mode))
    except (OSError, UnicodeError, HelperError):
        pass
    for path in (DNSMASQ_RULES_PATH, DNSMASQ_LISTS_PATH):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    apply_browser_policies({"strict_mode": {"enabled": False}})
    try:
        clear_firewall()
    except HelperError:
        pass
    try:
        remove_squid_files()
        if squid_binary(required=False) and SQUID_MAIN_CONFIG.exists():
            validate_squid_configuration()
            reload_squid(start=False)
    except HelperError:
        pass
    reload_dns_plugin(full=True)


def prepare(action: str, payload: dict | None = None) -> object:
    """Slow network work that must not hold the system lock."""
    payload = LEGACY_ADULT_ACTIONS.get(action, payload or {})
    if action == "sync-smart-ips":
        require_root()
        return prepare_sync(load_state())
    if action == "protection-configure" or action in LEGACY_ADULT_ACTIONS:
        require_root()
        return prepare_protection(payload)
    return None


def dispatch(action: str, payload: dict, prepared: object = None) -> dict:
    extra: dict = {}
    if action == "status":
        return public_status()
    if action == "setup":
        setup_credentials(payload, replace=False)
    elif action == "change-credentials":
        setup_credentials(payload, replace=True)
    elif action == "account-info":
        extra["account"] = account_info()
    elif action == "add":
        add_entry(payload)
    elif action == "import":
        extra["import_result"] = import_entries(payload)
    elif action == "remove":
        remove_entry(payload)
    elif action == "protection-configure":
        configure_protection(payload, prepared)
    elif action in LEGACY_ADULT_ACTIONS:
        configure_protection(LEGACY_ADULT_ACTIONS[action], prepared)
    elif action == "squid-configure":
        configure_squid_proxy(payload)
    elif action == "sync-smart-ips":
        sync_smart_ips(prepared["domains"], prepared["safe_ips"], prepared["lists"])
    elif action == "apply-firewall":
        require_root()
        apply_firewall(load_state())
    elif action == "apply-system":
        require_root()
        state = load_state()
        state["dns_mode"] = detect_dns_mode()
        save_state(state)
        apply_system(state)
    elif action == "apply-squid":
        require_root()
        apply_squid_configuration(load_state())
    elif action == "clear-firewall":
        require_root()
        clear_firewall()
    elif action == "cleanup-system":
        cleanup_system()
    else:
        raise HelperError("err_unknown_command")
    result = public_status()
    result.update(extra)
    return result


def main() -> int:
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        payload = read_payload()
        if action == "status":
            result = dispatch(action, payload)
        else:
            prepared = prepare(action, payload)
            with exclusive_system_lock():
                result = dispatch(action, payload, prepared)
        print(json.dumps({"ok": True, "data": result}, ensure_ascii=False))
        return 0
    except (HelperError, ValidationError) as exc:
        code = getattr(exc, "code", "err_internal")
        detail = getattr(exc, "detail", "")
        print(json.dumps({"ok": False, "error_code": code, "detail": detail}, ensure_ascii=False))
        return 1
    except Exception as exc:
        print(
            json.dumps(
                {"ok": False, "error_code": "err_internal", "detail": str(exc)},
                ensure_ascii=False,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
