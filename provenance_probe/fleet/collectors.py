"""Collectors: discover where local agent CLIs are pointed (their base_url).

Two collectors behind a thin seam (plan-eng-review Step 0 — no formal interface
until a 3rd collector type lands): config files and process env. Both produce
CONFIGURED-tier evidence — the weakest tier, because a config value may be stale
and is not proof of effective traffic (Codex #4).

Config parsing is a dependency-free, format-agnostic regex over base-url-ish keys,
so it works on TOML (`base = "..."`), JSON (`"base_url": "..."`), and YAML
(`base_url: ...`) alike without pulling in per-format parsers. Filesystem access
is injected so the collectors are pure and unit-testable.

Env caveat (Codex #3): a scheduled scanner sees its OWN environment, not every
developer shell / IDE / direnv / npm session. Env findings carry that caveat.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

from .evidence import CONFIGURED, Finding
from ..presets import _hostname


def strip_userinfo(url: str) -> str:
    """Remove any user:password@ credentials from a URL, keeping host[:port]/path.

    A base_url like `https://user:sk-token@host/v1` must never enter a Finding —
    the report rolls up to a SIEM and the token would leak (provenance-reviewer
    HIGH). Classification only needs the hostname, so dropping userinfo is lossless
    for detection. Best-effort: an unparseable value is returned unchanged (it will
    still be classified by its parsed host, which is "" → unattributed)."""
    s = (url or "").strip()
    if "@" not in s:
        return s
    try:
        parts = urlsplit(s if "://" in s else "http://" + s)
    except ValueError:
        return s
    host = parts.hostname or ""
    if not host:
        return s
    hostpart = f"[{host}]" if ":" in host else host   # re-bracket IPv6 literals
    netloc = f"{hostpart}:{parts.port}" if parts.port else hostpart
    rebuilt = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    # If we synthesized the scheme, drop it back to how it came in (schemeless rare).
    return rebuilt if "://" in s else rebuilt.split("://", 1)[-1]


_HEADER_FLAGS = {"-h", "--header", "--headers"}
_SECRET_ARG = re.compile(
    r"(?i)(?:^|[\s=])(?:authorization|bearer|api[_-]?key|token|sk-|x-api-key)\b"
)


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _safe_endpoint(value: str, *, require_scheme: bool = False) -> str:
    """Hostname URL with userinfo and query stripped. Empty when it is not a host.

    `require_scheme` refuses a dotted token that is not a URL (a package name
    or a filename). Loopback listeners are quiet: this scanner does not treat
    them as a remote MCP server.
    """
    raw = (value or "").strip().strip("'\"")
    if not raw or (_SECRET_ARG.search(raw) and "://" not in raw):
        return ""
    if require_scheme and "://" not in raw:
        return ""
    safe = strip_userinfo(raw)
    try:
        parts = urlsplit(safe if "://" in safe else "http://" + safe)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if not host or "." not in host or host in _LOOPBACK_HOSTS:
        return ""
    hostpart = f"[{host}]" if ":" in host else host
    netloc = f"{hostpart}:{parts.port}" if parts.port else hostpart
    scheme = parts.scheme if "://" in safe else "https"
    return urlunsplit((scheme, netloc, parts.path, "", "")).rstrip("/")


def _endpoints_from_argv(parts: list[str]) -> list[str]:
    """Hosts named in an MCP command line. Header values are skipped, not stored."""
    out: list[str] = []
    skip = False
    for part in parts:
        token = str(part).strip()
        if skip:
            skip = False
            continue
        low = token.lower()
        if low in _HEADER_FLAGS:
            skip = True
            continue
        if low.startswith("--header=") or low.startswith("-h="):
            continue
        ep = _safe_endpoint(token, require_scheme=True)
        if ep:
            out.append(ep)
    return out


def extract_mcp_server_urls(text: str) -> list[str]:
    """Remote MCP server URLs and command-line hosts.

    `url` is the usual remote field and is not a base_url key, so the generic
    regex misses it. Header maps and `-H` / `--header` arguments are dropped.
    A local `command` with no host contributes nothing. De-duplicated.
    """
    try:
        doc = json.loads(text or "")
    except (ValueError, TypeError):
        return []
    if not isinstance(doc, dict):
        return []
    servers = doc.get("mcpServers")
    if not isinstance(servers, dict):
        return []
    out: list[str] = []
    seen: set[str] = set()

    def add(ep: str) -> None:
        if ep and ep not in seen:
            seen.add(ep)
            out.append(ep)

    for spec in servers.values():
        if not isinstance(spec, dict):
            continue
        url = spec.get("url")
        if isinstance(url, str):
            add(_safe_endpoint(url))
        argv: list[str] = []
        command = spec.get("command")
        if isinstance(command, str):
            argv.append(command)
        args = spec.get("args")
        if isinstance(args, list):
            argv.extend(str(a) for a in args)
        elif isinstance(args, str):
            argv.append(args)
        for ep in _endpoints_from_argv(argv):
            add(ep)
    return out

# Per-tool config files to scan (path is relative to home; "~" expanded by caller).
# These are home-relative dotfile paths, so they resolve on macOS, Linux AND Windows
# (`expanduser("~")` → the user profile; open() accepts the forward slashes).
DEFAULT_CONFIG_TARGETS: list[str] = [
    ".codex/config.toml",
    ".continue/config.json",
    ".aider.conf.yml",
    ".claude/settings.json",
    ".cursor/mcp.json",
]

# Env vars that redirect an agent CLI's base URL.
DEFAULT_ENV_VARS: list[str] = [
    "ANTHROPIC_BASE_URL",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
]

# Match a base-url-ish key followed by an http(s) URL, across TOML/JSON/YAML/env.
_BASE_URL_RE = re.compile(
    r"(?i)(?:api_base|base_url|openai_api_base|anthropic_base_url|openai_base_url"
    r"|api_url|base|endpoint)"
    r"""["']?\s*[:=]\s*["']?(https?://[^\s"',]+)""",
)


def extract_base_urls_from_text(text: str) -> list[str]:
    """Return base_url values found in a config file body (format-agnostic).
    De-duplicated, order-preserving."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _BASE_URL_RE.finditer(text or ""):
        url = m.group(1).rstrip("/")
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def collect_config_files(
    read_text: Callable[[str], str | None],
    home: str = "~",
    targets: list[str] | None = None,
) -> list[Finding]:
    """Scan per-tool config files for base_url redirects.

    `read_text(path)` returns the file body or None if absent/unreadable — the
    injection point that keeps this pure. A permission error surfaces as None
    (the collector degrades, never raises)."""
    findings: list[Finding] = []
    base = home.rstrip("/")
    for rel in (targets or DEFAULT_CONFIG_TARGETS):
        path = f"{base}/{rel}"
        try:
            text = read_text(path)
        except Exception:
            text = None
        if not text:
            continue
        urls = list(extract_base_urls_from_text(text))
        if rel.endswith("mcp.json") or path.endswith("mcp.json"):
            urls.extend(extract_mcp_server_urls(text))
        seen_hosts: set[str] = set()
        for url in urls:
            safe = strip_userinfo(url)
            host = _hostname(safe)
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            findings.append(Finding(
                source=path, base_url=safe, host=host,
                evidence_tier=CONFIGURED, classification="",
            ))
    return findings


def collect_env(
    environ: dict[str, str],
    var_names: list[str] | None = None,
) -> list[Finding]:
    """Scan the process environment for base_url redirects. Findings note the
    scanner-env coverage limit (Codex #3)."""
    findings: list[Finding] = []
    for name in (var_names or DEFAULT_ENV_VARS):
        val = (environ or {}).get(name)
        if not val:
            continue
        url = strip_userinfo(val.strip().rstrip("/"))
        findings.append(Finding(
            source=f"env:{name}", base_url=url, host=_hostname(url),
            evidence_tier=CONFIGURED, classification="",
            notes=["scanner-process env only; not every developer shell/IDE session"],
        ))
    return findings
