"""Offline DNS, SNI, and proxy-log join.

A SOC already has the destination name in a Zeek log or a gateway CSV. This
module classifies those names with the same corpus match and allowlist as a
config finding. It does not open a socket, and it does not read a gateway
config: a row that only names a non-loopback gateway stays unresolved.

An empty log is not a clean bill. Callers turn `LogUnavailable` into a
non-zero exit instead of a zero-finding report.
"""
from __future__ import annotations

import csv
import io

from ..presets import _hostname
from .allowlist import is_sanctioned
from .attribute import attribute, is_aggregator
from .collectors import strip_userinfo
from .evidence import (
    AGGREGATOR_UNRESOLVABLE,
    GATEWAY_UPSTREAM_UNRESOLVED,
    OBSERVED,
    OFF_ALLOWLIST_ATTRIBUTED,
    OFF_ALLOWLIST_UNATTRIBUTED,
    SANCTIONED,
    Finding,
)

# Destination columns (Zeek ssl/dns, Suricata, and common gateway exports).
_DEST_FIELDS = {
    "query", "server_name", "sni", "hostname", "host", "dest", "destination",
    "ssl.sni", "http.host", "http.hostname",
}
# The proxy the client connected to. Not an upstream. Never classified as the
# destination, and never resolved by reading a gateway config.
_GATEWAY_FIELDS = {"gateway", "proxy", "via", "proxy_host"}
_LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_UNSET = {"", "-", "(empty)", "none", "null"}


class LogUnavailable(Exception):
    """The log was empty or had no usable rows. Not a clean host."""


def _is_nonloopback_gateway(host: str) -> bool:
    """A gateway name we must not treat as the upstream it hides.

    DNS labels `ai-gateway` and `llm-gateway` match the documented non-loopback
    example (`ai-gateway.internal.example.com`). Loopback is a different case:
    the config scan can still read a localhost gateway's file. This importer
    cannot, so a loopback name in a gateway column is unresolved too, but it is
    not this predicate.
    """
    labels = [part for part in (host or "").split(".") if part]
    return "ai-gateway" in labels or "llm-gateway" in labels


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


def join_log(text: str, allowlist: list[str] | None = None) -> list[Finding]:
    """Classify destination hosts in an offline log.

    A row with only a gateway/proxy/via name, or whose only destination is a
    non-loopback gateway label, is `gateway-upstream-unresolved`. The allowlist
    does not turn that row into a sanctioned upstream: the log never named one.
    """
    allow = list(allowlist or [])
    rows = parse_log(text)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    usable = False

    def add(host: str, classification: str, attr, notes: list[str], field: str) -> None:
        key = (host, classification)
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(
            source=f"dns-log:{field}",
            base_url=host,
            host=host,
            evidence_tier=OBSERVED,
            classification=classification,
            attribution=attr,
            notes=notes,
        ))

    for row in rows:
        dests: list[tuple[str, str]] = []
        gateways: list[tuple[str, str]] = []
        for key, value in row.items():
            host = _cell_host(value)
            if not host:
                continue
            if key in _GATEWAY_FIELDS:
                gateways.append((host, key))
            elif key in _DEST_FIELDS:
                dests.append((host, key))
        if not dests and not gateways:
            continue
        usable = True
        if dests:
            hosts = _uniq([h for h, _ in dests])
            gateway_only = all(
                _is_nonloopback_gateway(h) or h in _LOOPBACK for h in hosts
            )
            if gateway_only:
                field = dests[0][1]
                for host in hosts:
                    if host in _LOOPBACK:
                        note = (
                            "loopback name in the log; this import does not "
                            "read a gateway config"
                        )
                    else:
                        note = (
                            "non-loopback gateway name in the log; upstream was "
                            "not in the row and was not resolved from a gateway config"
                        )
                    add(host, GATEWAY_UPSTREAM_UNRESOLVED, None, [note], field)
                continue
            via = _uniq([h for h, _ in gateways])
            via_note = ""
            if via:
                via_note = (
                    "seen via " + ", ".join(via)
                    + "; gateway config was not read"
                )
            for host, field in dests:
                if _is_nonloopback_gateway(host) or host in _LOOPBACK:
                    continue
                cls, attr, notes = _classify(host, allow)
                if via_note:
                    notes = notes + [via_note]
                add(host, cls, attr, notes, field)
            continue
        for host, field in gateways:
            note = (
                "log names a gateway and no destination SNI or DNS name; "
                "upstream was not resolved"
            )
            if host not in _LOOPBACK:
                note = (
                    "non-loopback gateway with no destination name; "
                    "upstream was not resolved"
                )
            add(host, GATEWAY_UPSTREAM_UNRESOLVED, None, [note], field)

    if not usable:
        raise LogUnavailable("dns log has no destination or gateway names")
    return findings
