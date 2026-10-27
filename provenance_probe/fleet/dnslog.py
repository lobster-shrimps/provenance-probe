"""Offline DNS, SNI, and proxy-log join.

A SOC already has the destination name in a Zeek log or a gateway CSV. This
module classifies those names with the same corpus match and allowlist as a
config finding. It does not open a socket, it does not scan the operator's
home, and it does not read a gateway config: a row whose only name is in a
gateway, proxy, or via column stays unresolved.

Corpus-attributed hosts are findings. Names the corpus does not know, and
IP-only rows, are a count. A DNS label such as `ai-gateway` is not special.

An empty log is not a clean bill. Callers turn `LogUnavailable` into a
non-zero exit instead of a zero-finding report. A log of only unknown names
is a report: the count is on the headline, and the exit is success.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field

from ..presets import _hostname
from .allowlist import is_sanctioned, load_allowlist
from .attribute import attribute, is_aggregator
from .collectors import strip_userinfo
from .evidence import (
    AGGREGATOR_UNRESOLVABLE,
    GATEWAY_UPSTREAM_UNRESOLVED,
    IMPORTED_LOG,
    OFF_ALLOWLIST_ATTRIBUTED,
    OFF_ALLOWLIST_UNATTRIBUTED,
    SANCTIONED,
    Finding,
    ScanResult,
)

# Destination columns that are unambiguous in Zeek and SNI exports. A bare
# `host` is often the workstation. `url` and `domain` need `--dns-columns`.
_DEFAULT_DEST = (
    "query", "server_name", "sni", "ssl.sni", "http.host", "http.hostname",
)
_DEFAULT_CLIENT = ("id.orig_h", "src_ip", "client_ip", "client")
_DEFAULT_TIME = ("ts", "timestamp", "time")
# The proxy the client connected to. Not an upstream. Never classified as the
# destination, and never resolved by reading a gateway config.
_GATEWAY_FIELDS = {"gateway", "proxy", "via", "proxy_host"}
_UNSET = {"", "-", "(empty)", "none", "null"}
_COLUMN_ROLES = {"dest", "client", "time"}


class LogUnavailable(Exception):
    """The log was empty or had no usable rows. Not a clean host."""


@dataclass(frozen=True)
class _Columns:
    dest: tuple[str, ...]
    client: tuple[str, ...]
    time: tuple[str, ...]


@dataclass
class LogJoin:
    """Findings plus the unique names that were not corpus hits."""
    findings: list[Finding] = field(default_factory=list)
    unattributed_names: int = 0


def _is_ip(host: str) -> bool:
    """An address, not a name the corpus can match. No RDAP on this path."""
    if ":" in host:
        return True
    labels = host.split(".")
    if len(labels) != 4:
        return False
    for part in labels:
        if not part.isdigit():
            return False
        if int(part) > 255:
            return False
    return True


def parse_column_map(spec: str | None) -> _Columns:
    """`dest=url,client=src_ip,time=ts`. A dest role replaces the defaults."""
    dest: list[str] = []
    client: list[str] = []
    time: list[str] = []
    named = {"dest": False, "client": False, "time": False}
    buckets = {"dest": dest, "client": client, "time": time}
    if spec and str(spec).strip():
        for part in str(spec).split(","):
            piece = part.strip()
            if not piece:
                continue
            if "=" not in piece:
                raise LogUnavailable(f"dns column map {piece!r} is not role=name")
            role, name = piece.split("=", 1)
            role, name = role.strip().lower(), name.strip().lower()
            if role not in _COLUMN_ROLES or not name:
                raise LogUnavailable(
                    f"dns column map role {role!r} is not dest, client, or time")
            named[role] = True
            if name not in buckets[role]:
                buckets[role].append(name)
    return _Columns(
        dest=tuple(dest) if named["dest"] else _DEFAULT_DEST,
        client=tuple(client) if named["client"] else _DEFAULT_CLIENT,
        time=tuple(time) if named["time"] else _DEFAULT_TIME,
    )


def _cell_host(value: str) -> str:
    raw = (value or "").strip()
    if raw.lower() in _UNSET:
        return ""
    safe = strip_userinfo(raw.split()[0])
    return _hostname(safe)


def _parse_zeek(text: str) -> list[dict[str, str]] | None:
    """Return rows when the file is a Zeek log (`#fields`), else None."""
    lines = text.splitlines()
    if not any(line.startswith("#fields") for line in lines):
        return None
    fields: list[str] | None = None
    rows: list[dict[str, str]] = []
    for line in lines:
        if line.startswith("#fields"):
            parts = line.split("\t") if "\t" in line else line.split()
            fields = [p.strip().lower() for p in parts[1:]]
            continue
        if not line or line.startswith("#") or fields is None:
            continue
        cells = line.split("\t") if "\t" in line else line.split()
        rows.append({
            fields[i]: (cells[i].strip() if i < len(cells) else "")
            for i in range(len(fields))
        })
    if not rows:
        raise LogUnavailable("dns log has no data rows")
    return rows


def _parse_csv(text: str) -> list[dict[str, str]]:
    try:
        reader = csv.DictReader(io.StringIO(text))
        fieldnames = reader.fieldnames
    except csv.Error as e:
        raise LogUnavailable(f"dns log could not be parsed: {e}") from e
    if not fieldnames:
        raise LogUnavailable("dns log has no header")
    rows: list[dict[str, str]] = []
    for rec in reader:
        if not rec:
            continue
        norm = {
            (k or "").strip().lower(): (v or "").strip()
            for k, v in rec.items()
            if k is not None
        }
        if any(norm.values()):
            rows.append(norm)
    if not rows:
        raise LogUnavailable("dns log has no data rows")
    return rows


def parse_log(text: str) -> list[dict[str, str]]:
    """Parse a Zeek `#fields` log or a CSV with a header row."""
    if text is None or not str(text).strip():
        raise LogUnavailable("dns log is empty")
    zeek = _parse_zeek(text)
    if zeek is not None:
        return zeek
    return _parse_csv(text)


def _classify(host: str, allowlist: list[str]) -> tuple[str, object, list[str]]:
    if is_sanctioned(host, allowlist):
        return SANCTIONED, None, []
    agg = is_aggregator(host)
    if agg:
        return (AGGREGATOR_UNRESOLVABLE, None,
                [f"{agg}: neutral aggregator — provenance requires an active probe"])
    attr = attribute(host)
    if attr:
        return OFF_ALLOWLIST_ATTRIBUTED, attr, []
    return OFF_ALLOWLIST_UNATTRIBUTED, None, []


def _uniq(hosts: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def _cell_text(row: dict[str, str], names: tuple[str, ...]) -> str:
    for key in names:
        value = (row.get(key) or "").strip()
        if value and value.lower() not in _UNSET:
            return value
    return ""


def _rank(finding: Finding) -> int:
    if finding.classification == OFF_ALLOWLIST_ATTRIBUTED:
        return 0
    if finding.classification == SANCTIONED:
        return 1
    return 2


def join_log(
    text: str,
    allowlist: list[str] | None = None,
    columns: str | None = None,
) -> LogJoin:
    """Classify destination hosts in an offline log.

    A row with only a gateway, proxy, or via column stays
    `gateway-upstream-unresolved`, even when that name is on the allowlist.
    The log never named an upstream, and this import does not read a gateway
    config. A destination whose DNS label happens to be `ai-gateway` is an
    ordinary name.
    """
    allow = list(allowlist or [])
    chosen = parse_column_map(columns)
    rows = parse_log(text)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    unattributed: list[str] = []
    seen_names: set[str] = set()
    usable = False

    def add(host: str, classification: str, attr, notes: list[str], field: str,
            client: str, seen_at: str) -> None:
        key = (host, classification)
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(
            source=f"dns-log:{field}",
            base_url=host,
            host=host,
            evidence_tier=IMPORTED_LOG,
            classification=classification,
            attribution=attr,
            notes=notes,
            client=client,
            seen_at=seen_at,
        ))

    def count_name(host: str) -> None:
        if host and host not in seen_names:
            seen_names.add(host)
            unattributed.append(host)

    for row in rows:
        client = _cell_text(row, chosen.client)
        seen_at = _cell_text(row, chosen.time)
        dests: list[tuple[str, str]] = []
        gateways: list[tuple[str, str]] = []
        for key, value in row.items():
            host = _cell_host(value)
            if not host:
                continue
            if key in _GATEWAY_FIELDS and key not in chosen.dest:
                gateways.append((host, key))
            elif key in chosen.dest:
                dests.append((host, key))
        if not dests and not gateways:
            continue
        usable = True
        if not dests:
            for host, field in gateways:
                note = (
                    "log names a gateway and no destination SNI or DNS name; "
                    "upstream was not resolved"
                )
                add(host, GATEWAY_UPSTREAM_UNRESOLVED, None, [note], field,
                    client, seen_at)
            continue
        via = _uniq([h for h, _ in gateways])
        via_note = ""
        if via:
            via_note = (
                "seen via " + ", ".join(via)
                + "; gateway config was not read"
            )
        for host, field in dests:
            if _is_ip(host):
                count_name(host)
                continue
            cls, attr, notes = _classify(host, allow)
            if cls == OFF_ALLOWLIST_UNATTRIBUTED:
                count_name(host)
                continue
            if via_note:
                notes = notes + [via_note]
            add(host, cls, attr, notes, field, client, seen_at)

    if not usable:
        raise LogUnavailable("dns log has no destination or gateway names")
    findings.sort(key=_rank)
    return LogJoin(findings=findings, unattributed_names=len(unattributed))


def scan_log(
    text: str,
    allowlist_text: str = "",
    columns: str | None = None,
) -> ScanResult:
    """Log-only report. Does not read config files or the process environment."""
    joined = join_log(text, load_allowlist(allowlist_text), columns=columns)
    out = joined.findings
    sanctioned = sum(1 for f in out if f.classification == SANCTIONED)
    unresolved = sum(1 for f in out if f.classification in
                     (GATEWAY_UPSTREAM_UNRESOLVED, AGGREGATOR_UNRESOLVABLE))
    drifted = len(out) - sanctioned
    return ScanResult(
        findings=out, sanctioned=sanctioned, drifted=drifted,
        unresolved=unresolved, unattributed_names=joined.unattributed_names,
    )
