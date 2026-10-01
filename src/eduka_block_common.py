#!/usr/bin/python3
"""Shared validation and credential helpers for Eduka-Block."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlsplit


APP_VERSION = "0.5.0"
APP_SHARE_DIR = Path("/usr/share/Eduka-Block")
CREDENTIALS_PATH = APP_SHARE_DIR / "credentials.txt"
PBKDF2_ITERATIONS = 600_000
CATEGORIES = ("Manual", "Adult", "Harmful", "Malware", "Gambling", "Social", "Other")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


class ValidationError(ValueError):
    """Raised when user supplied data is not safe or valid."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def normalize_target(raw: str) -> tuple[str, str]:
    """Return (normalized value, 'domain'|'ipv4'|'ipv6')."""
    value = (raw or "").strip()
    if not value or len(value) > 2048:
        raise ValidationError("err_target_required")

    # CIDR ranges are accepted as an explicit advanced rule. They are never
    # inferred from a website because shared hosting/CDN ranges contain many
    # unrelated sites.
    if "://" not in value and "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            network = None
        if network is not None:
            if (network.version == 4 and network.prefixlen < 8) or (
                network.version == 6 and network.prefixlen < 32
            ):
                raise ValidationError("err_network_broad")
            address = network.network_address
            if (
                address.is_unspecified
                or address.is_loopback
                or address.is_multicast
                or address.is_link_local
            ):
                raise ValidationError("err_local_address")
            kind = "ipv4_network" if network.version == 4 else "ipv6_network"
            return network.with_prefixlen, kind

    candidate = value
    if "://" in candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValidationError("err_http_only")
        candidate = parsed.hostname
    else:
        candidate = candidate.split("/", 1)[0].strip()
        if candidate.startswith("[") and "]" in candidate:
            candidate = candidate[1 : candidate.index("]")]
        elif candidate.count(":") == 1:
            host, possible_port = candidate.rsplit(":", 1)
            if possible_port.isdigit():
                candidate = host

    candidate = candidate.strip().rstrip(".")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None
    if address is not None:
        kind = "ipv4" if address.version == 4 else "ipv6"
        if address.is_unspecified or address.is_loopback or address.is_multicast:
            raise ValidationError("err_local_address")
        return address.compressed, kind

    if "*" in candidate:
        raise ValidationError("err_wildcard")
    try:
        domain = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValidationError("err_domain_invalid") from exc
    if not DOMAIN_RE.fullmatch(domain):
        raise ValidationError("err_domain_invalid")
    return domain, "domain"


def rule_target(raw: str) -> tuple[str, str]:
    """Normalise a parent/teacher rule. "www.example.org" becomes "example.org"
    so the wildcard DNS rule covers every subdomain of the site, not only
    "*.www.example.org"."""
    value, kind = normalize_target(raw)
    if kind == "domain" and value.startswith("www.") and value.count(".") >= 2:
        value = value[4:]
    return value, kind


def validate_account(username: str, password: str) -> None:
    username = username.strip()
    if not 3 <= len(username) <= 64 or any(char in username for char in "\r\n="):
        raise ValidationError("err_username")
    if not 5 <= len(password) <= 256:
        raise ValidationError("err_password_length")


def create_credentials_text(username: str, password: str) -> str:
    validate_account(username, password)
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32
    )
    return (
        f"# Eduka-Block {APP_VERSION} - Parent/Teacher credentials\n"
        "# This is a readable text file, but the original password is never stored.\n"
        "# Edit only through Eduka-Block to avoid corrupting authentication.\n"
        f"username={username.strip()}\n"
        "algorithm=pbkdf2_sha256\n"
        f"iterations={PBKDF2_ITERATIONS}\n"
        f"salt={base64.b64encode(salt).decode('ascii')}\n"
        f"password_hash={base64.b64encode(digest).decode('ascii')}\n"
    )


def read_credentials(path: Path = CREDENTIALS_PATH) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValidationError("err_credentials_read") from exc
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    required = {"username", "algorithm", "iterations", "salt", "password_hash"}
    if not required.issubset(values) or values["algorithm"] != "pbkdf2_sha256":
        raise ValidationError("err_credentials_format")
    return values


def verify_credentials(username: str, password: str, path: Path = CREDENTIALS_PATH) -> bool:
    try:
        values = read_credentials(path)
        iterations = int(values["iterations"])
        if not 100_000 <= iterations <= 2_000_000:
            return False
        salt = base64.b64decode(values["salt"], validate=True)
        expected = base64.b64decode(values["password_hash"], validate=True)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected)
        )
        supplied_username = username.strip().encode("utf-8")
        stored_username = values["username"].encode("utf-8")
        return hmac.compare_digest(supplied_username, stored_username) and hmac.compare_digest(
            candidate, expected
        )
    except (ValidationError, ValueError, TypeError):
        return False


def aliases_for_domain(domain: str) -> list[str]:
    """Cover the common bare/www pair while keeping subdomains explicit."""
    aliases = {domain}
    labels = domain.split(".")
    if domain.startswith("www.") and len(labels) > 2:
        aliases.add(domain[4:])
    elif len(labels) == 2:
        aliases.add(f"www.{domain}")
    return sorted(aliases)


EXPORT_HEADER = "# Eduka-Block rule export. One website, domain, IP or CIDR per line."
HOSTS_SINK_ADDRESSES = {"0.0.0.0", "127.0.0.1", "::", "::1"}


def export_rules_text(entries: list[dict]) -> str:
    """Serialise rules as plain text: ``target  # Category`` per line."""
    lines = [EXPORT_HEADER, f"# Version {APP_VERSION}"]
    for entry in sorted(entries, key=lambda item: str(item.get("value", ""))):
        value = str(entry.get("value", "")).strip()
        if value:
            lines.append(f"{value}  # {entry.get('category', 'Manual')}")
    return "\n".join(lines) + "\n"


def parse_rules_text(text: str, default_category: str = "Manual") -> list[dict]:
    """Read an exported list, a plain list or a hosts-style blocklist.

    Validation happens again in the privileged helper; this only extracts
    candidate targets and an optional ``# Category`` suffix.
    """
    items: list[dict] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line, _, comment = raw_line.partition("#")
        tokens = line.split()
        if not tokens:
            continue
        if len(tokens) >= 2 and tokens[0] in HOSTS_SINK_ADDRESSES:
            tokens = tokens[1:]
        category = comment.strip()
        if category not in CATEGORIES:
            category = default_category
        for token in tokens:
            if token not in seen:
                seen.add(token)
                items.append({"target": token, "category": category})
    return items
