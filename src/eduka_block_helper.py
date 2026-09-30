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
    APP_VERSION,
    CATEGORIES,
    CREDENTIALS_PATH,
    ValidationError,
    aliases_for_domain,
    create_credentials_text,
    normalize_target,
)


STATE_DIR = Path("/var/lib/eduka-block")
STATE_PATH = STATE_DIR / "blocklist.json"
ADULT_DOMAINS_PATH = STATE_DIR / "adult-domains.txt"
HOSTS_PATH = Path("/etc/hosts")
HOSTS_BACKUP_PATH = STATE_DIR / "hosts.original-backup"
DNSMASQ_RULES_PATH = Path("/etc/NetworkManager/dnsmasq.d/eduka-block.conf")
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
ADULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts"
)
MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024
MAX_SMART_DOMAINS = 250
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


def default_state() -> dict:
    return {
        "schema": 3,
        "entries": [],
        "adult_protection": {
            "enabled": False,
            "domain_count": 0,
            "source": ADULT_SOURCE_URL,
            "updated_at": None,
        },
        "smart_sync": {"last_run": None},
        "squid_proxy": {
            "enabled": False,
            "keywords": list(DEFAULT_SQUID_KEYWORDS),
            "last_applied_at": None,
        },
    }


def migrate_state(data: dict) -> dict:
    schema = data.get("schema")
    if schema not in {1, 2, 3} or not isinstance(data.get("entries"), list):
        raise HelperError("err_state_version")
    data["schema"] = 3
    for entry in data["entries"]:
        if entry.get("kind") == "domain":
            entry.setdefault("smart", True)
            entry.setdefault("resolved_ips", [])
            entry.setdefault("last_resolved_at", None)
        else:
            entry["smart"] = False
            entry["resolved_ips"] = []
    if not isinstance(data.get("adult_protection"), dict):
        data["adult_protection"] = default_state()["adult_protection"]
    data.setdefault("smart_sync", {"last_run": None})
    squid = data.get("squid_proxy")
    if not isinstance(squid, dict):
        data["squid_proxy"] = default_state()["squid_proxy"]
    else:
        squid.setdefault("enabled", False)
        squid.setdefault("keywords", list(DEFAULT_SQUID_KEYWORDS))
        squid.setdefault("last_applied_at", None)
    return data


def load_state(path: Path = STATE_PATH) -> dict:
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


def save_state(data: dict, path: Path = STATE_PATH) -> None:
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


def adult_domains(path: Path = ADULT_DOMAINS_PATH) -> list[str]:
    if not path.exists():
        return []
    domains: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            normalized, kind = normalize_target(candidate)
            if kind == "domain":
                domains.append(normalized)
        except ValidationError:
            continue
    return domains


def render_hosts(
    state: dict,
    hosts_path: Path = HOSTS_PATH,
    adult_path: Path = ADULT_DOMAINS_PATH,
    backup_path: Path = HOSTS_BACKUP_PATH,
) -> None:
    try:
        current = hosts_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise HelperError("err_hosts_read") from exc
    if not backup_path.exists():
        atomic_write(backup_path, current, 0o600)

    clean = remove_managed_section(current)
    domains: set[str] = set()
    for entry in state["entries"]:
        if entry.get("kind") == "domain":
            domains.update(aliases_for_domain(entry["value"]))
    if state["adult_protection"].get("enabled"):
        domains.update(adult_domains(adult_path))

    if domains:
        managed = ["", BEGIN_MARKER, "# Generated by Eduka-Block. Use the app to edit."]
        for domain in sorted(domains):
            managed.append(f"0.0.0.0 {domain}")
            managed.append(f":: {domain}")
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


def manual_domains(state: dict) -> list[str]:
    return sorted({e["value"] for e in state["entries"] if e.get("kind") == "domain"})


def render_dnsmasq(state: dict, path: Path = DNSMASQ_RULES_PATH) -> None:
    domains = manual_domains(state)
    if not domains:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    lines = [
        f"# Eduka-Block {APP_VERSION} - generated file",
        "# Blocks each selected domain and every subdomain.",
    ]
    for domain in domains:
        lines.append(f"local=/{domain}/")
        lines.append(f"address=/{domain}/0.0.0.0")
        lines.append(f"address=/{domain}/::")
    atomic_write(path, "\n".join(lines) + "\n", 0o644)


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


def apply_firewall(state: dict) -> None:
    ipv4, ipv6 = firewall_elements(state)
    binary = nft_binary()
    exists = subprocess.run(
        [binary, "list", "table", "inet", "eduka_block"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0
    lines: list[str] = []
    if exists:
        lines.append("delete table inet eduka_block")
    if ipv4 or ipv6:
        lines.append("table inet eduka_block {")
    if ipv4:
        lines.extend(
            [
                "  set blocked_ipv4 {",
                "    type ipv4_addr",
                "    flags interval",
                f"    elements = {{ {', '.join(ipv4)} }}",
                "  }",
            ]
        )
    if ipv6:
        lines.extend(
            [
                "  set blocked_ipv6 {",
                "    type ipv6_addr",
                "    flags interval",
                f"    elements = {{ {', '.join(ipv6)} }}",
                "  }",
            ]
        )
    if ipv4 or ipv6:
        lines.extend(["  chain output {", "    type filter hook output priority 0; policy accept;"])
        if ipv4:
            lines.append("    ip daddr @blocked_ipv4 drop")
        if ipv6:
            lines.append("    ip6 daddr @blocked_ipv6 drop")
        lines.extend(["  }", "}"])
    if not lines:
        return
    ruleset = "\n".join(lines) + "\n"
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


def apply_system(state: dict) -> None:
    render_hosts(state)
    render_dnsmasq(state)
    apply_firewall(state)
    reload_dns_plugin(full=True)


def apply_transaction(old_state: dict, new_state: dict) -> None:
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


def sync_smart_ips(resolved: dict[str, list[str]] | None = None) -> None:
    require_root()
    if resolved is None:
        resolved = resolve_smart_domains(load_state())
    # Re-read under the lock: rules may have changed while DNS was queried.
    state = load_state()
    changed = False
    for entry in state["entries"]:
        if entry.get("kind") != "domain" or not entry.get("smart"):
            continue
        addresses = resolved.get(entry["value"])
        if addresses:
            if addresses != entry.get("resolved_ips", []):
                entry["resolved_ips"] = addresses
                changed = True
            entry["last_resolved_at"] = now_iso()
    state["smart_sync"] = {"last_run": now_iso(), "processed": len(resolved)}
    save_state(state)
    if changed:
        apply_firewall(state)


def parse_hosts_download(content: str) -> list[str]:
    domains: set[str] = set()
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
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
    if not 1_000 <= len(domains) <= 250_000:
        raise HelperError("err_adult_integrity")
    return sorted(domains)


def download_adult_domains() -> list[str]:
    request = urllib.request.Request(
        ADULT_SOURCE_URL,
        headers={"User-Agent": f"Eduka-Block/{APP_VERSION} (+https://edukasaunos.tl)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "raw.githubusercontent.com":
                raise HelperError("err_adult_redirect")
            data = response.read(MAX_DOWNLOAD_BYTES + 1)
    except HelperError:
        raise
    except (OSError, urllib.error.URLError) as exc:
        raise HelperError("err_adult_download") from exc
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise HelperError("err_adult_large")
    try:
        return parse_hosts_download(data.decode("utf-8"))
    except UnicodeError as exc:
        raise HelperError("err_adult_encoding") from exc


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
    return {
        "version": APP_VERSION,
        "configured": credentials_configured(),
        "entries": state["entries"],
        "adult_protection": state["adult_protection"],
        "squid_proxy": squid,
        "smart_sync": state.get("smart_sync", {}),
        "manual_count": len(state["entries"]),
        "tracked_ip_count": len(tracked),
        "total_count": len(state["entries"])
        + int(state["adult_protection"].get("domain_count", 0))
        + len(tracked),
        "dns_engine": bool(
            NETWORKMANAGER_CONFIG.exists()
            and shutil.which("nmcli")
            and (shutil.which("dnsmasq") or Path("/usr/sbin/dnsmasq").exists())
        ),
    }


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
    value, kind = normalize_target(str(payload.get("target", "")))
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
            value, kind = normalize_target(str(item.get("target", "")))
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


def enable_adult_protection(domains: list[str] | None = None) -> None:
    require_root()
    if domains is None:
        domains = download_adult_domains()
    previous_content = ADULT_DOMAINS_PATH.read_text(encoding="utf-8") if ADULT_DOMAINS_PATH.exists() else None
    atomic_write(ADULT_DOMAINS_PATH, "\n".join(domains) + "\n", 0o644)
    old = load_state()
    new = json.loads(json.dumps(old))
    new["adult_protection"] = {
        "enabled": True,
        "domain_count": len(domains),
        "source": ADULT_SOURCE_URL,
        "updated_at": now_iso(),
    }
    try:
        apply_transaction(old, new)
    except Exception:
        if previous_content is None:
            try:
                ADULT_DOMAINS_PATH.unlink()
            except FileNotFoundError:
                pass
        else:
            atomic_write(ADULT_DOMAINS_PATH, previous_content, 0o644)
        try:
            apply_system(old)
        except Exception:
            pass
        raise


def disable_adult_protection() -> None:
    require_root()
    old = load_state()
    new = json.loads(json.dumps(old))
    new["adult_protection"]["enabled"] = False
    apply_transaction(old, new)


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
    try:
        DNSMASQ_RULES_PATH.unlink()
    except FileNotFoundError:
        pass
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


def prepare(action: str) -> object:
    """Slow network work that must not hold the system lock."""
    if action == "sync-smart-ips":
        require_root()
        return resolve_smart_domains(load_state())
    if action in {"adult-enable", "adult-update"}:
        require_root()
        return download_adult_domains()
    return None


def dispatch(action: str, payload: dict, prepared: object = None) -> dict:
    extra: dict = {}
    if action == "status":
        return public_status()
    if action == "setup":
        setup_credentials(payload, replace=False)
    elif action == "change-credentials":
        setup_credentials(payload, replace=True)
    elif action == "add":
        add_entry(payload)
    elif action == "import":
        extra["import_result"] = import_entries(payload)
    elif action == "remove":
        remove_entry(payload)
    elif action in {"adult-enable", "adult-update"}:
        enable_adult_protection(prepared)
    elif action == "adult-disable":
        disable_adult_protection()
    elif action == "squid-configure":
        configure_squid_proxy(payload)
    elif action == "sync-smart-ips":
        sync_smart_ips(prepared)
    elif action == "apply-firewall":
        require_root()
        apply_firewall(load_state())
    elif action == "apply-system":
        require_root()
        state = load_state()
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
            prepared = prepare(action)
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
