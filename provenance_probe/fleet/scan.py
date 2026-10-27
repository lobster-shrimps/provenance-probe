"""fleet-scan orchestrator: discover → resolve gateways → classify → report.

Pure core: `run_scan` takes injectable IO (a file reader and a gateway-config
loader) so the whole pipeline is unit-testable with no filesystem. Real defaults
read from disk (file IO only — NEVER a network call; that is the module invariant).

Pipeline per discovered base_url:

    base_url ──▶ local gateway? ──yes──▶ load gateway config ──▶ upstream hosts
        │                                     │                        │
        no                              none found                  classify each
        ▼                                     ▼                        ▼
     classify host              GATEWAY_UPSTREAM_UNRESOLVED        (sanctioned /
     (sanctioned / attributed /                                    attributed / ...)
      aggregator / unattributed)
"""
from __future__ import annotations

import json
from collections.abc import Callable

from .allowlist import is_sanctioned, load_allowlist
from .attribute import attribute, is_aggregator
from .collectors import collect_config_files, collect_env
from .evidence import (
    AGGREGATOR_UNRESOLVABLE,
    CONFIGURED,
    GATEWAY_UPSTREAM_UNRESOLVED,
    OFF_ALLOWLIST_ATTRIBUTED,
    OFF_ALLOWLIST_UNATTRIBUTED,
    SANCTIONED,
    Finding,
    ScanResult,
)
from .collectors import extract_base_urls_from_text
from .resolve import local_gateway_name, resolve_gateway

# Best-effort gateway config locations (relative to home). These are recognition
# heuristics to confirm against real installs, NOT verified schemas — if none is
# found the endpoint is honestly marked GATEWAY_UPSTREAM_UNRESOLVED.
_GATEWAY_CONFIG_CANDIDATES: dict[str, list[str]] = {
    "omniroute": [".omniroute/config.json", ".config/omniroute/config.toml",
                  ".omniroute/config.toml"],
    "litellm": [".litellm/config.yaml", "litellm.config.yaml", ".config/litellm/config.yaml"],
    "unknown-local-gateway": [],
}


def _classify_host(host: str, allowlist: list[str]) -> tuple[str, object, list[str]]:
    """Return (classification, attribution|None, notes) for a resolved host."""
    if not host:
        return OFF_ALLOWLIST_UNATTRIBUTED, None, ["no parseable host"]
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


def _default_read_text(path: str) -> str | None:
    import os
    try:
        with open(os.path.expanduser(path), encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _parse_config(text: str) -> object:
    """Parse config text into an object for upstream extraction. Tries JSON then
    TOML; falls back to regex-wrapping any URLs so YAML/unknown formats still
    resolve without a yaml dependency."""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    try:
        import tomllib
        return tomllib.loads(text)
    except Exception:
        pass
    return [{"url": u} for u in extract_base_urls_from_text(text)]


def _default_gateway_config(
    gateway: str, home: str, read_text: Callable[[str], str | None],
) -> object | None:
    base = home.rstrip("/")
    for rel in _GATEWAY_CONFIG_CANDIDATES.get(gateway, []):
        text = read_text(f"{base}/{rel}")
        if text:
            return _parse_config(text)
    return None


def run_scan(
    allowlist_text: str = "",
    *,
    home: str = "~",
    environ: dict[str, str] | None = None,
    read_text: Callable[[str], str | None] | None = None,
    gateway_config_loader: Callable[[str], object | None] | None = None,
) -> ScanResult:
    """Run a read-only, no-egress fleet scan and return a private ScanResult.

    Injectable IO: `read_text(path)->str|None` and `gateway_config_loader(name)->
    config|None`. Defaults read from disk (file IO only)."""
    import os

    reader = read_text or _default_read_text
    allowlist = load_allowlist(allowlist_text)
    env = os.environ if environ is None else environ

    def load_gw(name: str) -> object | None:
        if gateway_config_loader is not None:
            return gateway_config_loader(name)
        return _default_gateway_config(name, home, reader)

    discovered = collect_config_files(reader, home=home) + collect_env(env)

    out: list[Finding] = []
    for f in discovered:
        gw = local_gateway_name(f.base_url)
        if gw is None:
            cls, attr, notes = _classify_host(f.host, allowlist)
            out.append(Finding(source=f.source, base_url=f.base_url, host=f.host,
                               evidence_tier=f.evidence_tier, classification=cls,
                               attribution=attr, notes=f.notes + notes))
            continue

        res = resolve_gateway(f.base_url, load_gw(gw))
        if not res.resolved:
            out.append(Finding(
                source=f.source, base_url=f.base_url, host=f.host,
                evidence_tier=f.evidence_tier, classification=GATEWAY_UPSTREAM_UNRESOLVED,
                via_gateway=gw,
                notes=f.notes + [f"{gw} gateway: upstream not resolved from config "
                                 "(config not found or unparseable) — active probe needed"]))
            continue

        for up_host in res.upstream_hosts:
            cls, attr, notes = _classify_host(up_host, allowlist)
            out.append(Finding(
                source=f.source, base_url=f.base_url, host=up_host,
                evidence_tier=f.evidence_tier, classification=cls, via_gateway=gw,
                attribution=attr,
                notes=f.notes + [f"resolved through {gw} gateway at {f.base_url}"] + notes))

    sanctioned = sum(1 for f in out if f.classification == SANCTIONED)
    unresolved = sum(1 for f in out if f.classification in
                     (GATEWAY_UPSTREAM_UNRESOLVED, AGGREGATOR_UNRESOLVABLE))
    drifted = len(out) - sanctioned
    return ScanResult(findings=out, sanctioned=sanctioned, drifted=drifted,
                      unresolved=unresolved)


# CONFIGURED re-exported for callers building custom collectors.
__all__ = ["run_scan", "ScanResult", "Finding", "CONFIGURED"]
