"""Render a fleet ScanResult as a private report (console + JSON).

Redaction (guardrail 4): a fleet report is "private" only in that it is never
published to the public observatory. Once it rolls up via osquery/Tanium/Intune it
enters the org's SIEM, so by default we redact operator PII — absolute home paths
collapse to `~/…` so a username never leaks. The DRIFT host (e.g. api.deepseek.com)
is the finding and is kept. `--no-redact` keeps full local detail for on-box use.
"""
from __future__ import annotations

import re

from .evidence import (
    OFF_ALLOWLIST_ATTRIBUTED,
    SANCTIONED,
    Finding,
    ScanResult,
)

# Collapse a home-directory prefix to ~ so a username never leaks into a SIEM / the
# rollup CSV. Matches ANYWHERE in the string (not just column-start) and covers both
# POSIX and Windows forms, since a `source` can be a Windows path or embedded mid-line:
#   * POSIX:   /Users/<user>, /home/<user>, /root
#   * Windows: C:\Users\<user>, \\srv\Users\<user> (UNC), D:\home\<user>, \home\<user>
# Case-insensitive on the segment names + drive letter; the trailing relative path is
# kept so the finding stays useful. The leading separator is consumed by the match and
# replaced by "~", yielding e.g. "~/.codex/config.toml" / "~\.config\x.toml".
_HOME_PATH_RE = re.compile(
    r"(?:[A-Za-z]:)?[\\/](?:Users|home)[\\/][^\\/]+"   # (drive)\Users\<user> or /home/<user>
    r"|[\\/]root(?=[\\/]|$)",                          # POSIX /root home
    re.IGNORECASE,
)


def _redact_source(source: str) -> str:
    return _HOME_PATH_RE.sub("~", source or "")


def _finding_json(f: Finding, redact: bool) -> dict:
    d = {
        "source": _redact_source(f.source) if redact else f.source,
        "base_url": f.base_url,
        "host": f.host,
        "evidence_tier": f.evidence_tier,
        "classification": f.classification,
        "via_gateway": f.via_gateway,
        "notes": f.notes,
    }
    if f.client:
        d["client"] = f.client
    if f.seen_at:
        d["seen_at"] = f.seen_at
    if f.attribution is not None:
        d["attribution"] = {
            "operator": f.attribution.operator,
            "origin": f.attribution.origin,
            "confidence": f.attribution.confidence,
            "source": f.attribution.source,
            "measured": f.attribution.measured,   # always False — sub-CONFIRMED pointer
        }
    return d


def to_json(result: ScanResult, redact: bool = True, *,
            machine: str | None = None, scanned_at: str | None = None) -> dict:
    """Render a ScanResult as JSON.

    `machine` + `scanned_at` are optional passthroughs (WS3): when a per-host JSON
    report is written with them, a directory-of-JSON fleet rollup can carry each
    file's machine id + freshness. The per-host output is otherwise unchanged."""
    out = {
        "headline": result.headline,
        "sanctioned": result.sanctioned,
        "drifted": result.drifted,
        "unresolved": result.unresolved,
        "redacted": redact,
        "findings": [_finding_json(f, redact) for f in result.findings],
    }
    if result.unattributed_names:
        out["unattributed_names"] = result.unattributed_names
    if machine is not None:
        out["machine"] = machine
    if scanned_at is not None:
        out["scanned_at"] = scanned_at
    return out


def _attr_line(f: Finding) -> str:
    if f.attribution is None:
        return ""
    a = f.attribution
    return (f"      → {a.operator} ({a.origin}), confidence {a.confidence:.2f} "
            f"[static pointer, NOT a measured provenance verdict]")


def truststore_to_json(result) -> dict:
    from .truststore import BASELINE
    return {
        "headline": result.headline,
        "total": result.total,
        "baseline": result.baseline,
        "unbaselined": result.unbaselined,
        "interception": result.interception,
        "findings": [
            {"sha256": f.ca.sha256, "label": f.ca.label, "source": f.ca.source,
             "classification": f.classification, "notes": f.notes}
            for f in result.findings if f.classification != BASELINE
        ],
    }


def render_truststore_console(result) -> str:
    from .truststore import BASELINE, INTERCEPTION_TOOL
    lines = [result.headline, ""]
    drift = [f for f in result.findings if f.classification != BASELINE]
    if not drift:
        lines.append("  all trusted roots are in the baseline.")
        return "\n".join(lines)
    for f in drift:
        marker = "MITM" if f.classification == INTERCEPTION_TOOL else "FLAG"
        who = f.ca.label or f.ca.source or "(unlabelled)"
        lines.append(f"  [{marker}] {who}  ({f.classification})")
        lines.append(f"      sha256: {f.ca.sha256}")
        for n in f.notes:
            lines.append(f"      note: {n}")
    return "\n".join(lines)


_UNPRIV_NOTE = ("scan ran unprivileged — only the current user's sockets were "
                "visible; run as root for a host-wide view (a router running as "
                "root or another user is otherwise invisible)")


def egress_to_json(result) -> dict:
    return {
        "headline": result.headline,
        "connections": result.connections,
        "privileged": result.privileged,
        "caveat": None if result.privileged else _UNPRIV_NOTE,
        "findings": [
            {"classification": f.classification, "command": f.command, "pid": f.pid,
             "detail": f.detail, "upstreams": f.upstreams, "notes": f.notes}
            for f in result.findings
        ],
    }


def render_egress_console(result) -> str:
    lines = [result.headline, ""]
    if not result.privileged:
        lines += [f"  NOTE: {_UNPRIV_NOTE}.", ""]
    if not result.findings:
        tail = "" if result.privileged else " in the current user's sockets"
        lines.append(f"  no router fan-out or local-gateway routing observed{tail}.")
        return "\n".join(lines)
    for f in result.findings:
        lines.append(f"  [FLAG] {f.command} (pid {f.pid})  ({f.classification})")
        lines.append(f"      {f.detail}")
        for n in f.notes:
            lines.append(f"      note: {n}")
    return "\n".join(lines)


def egress_attr_to_json(result) -> dict:
    """Render an EgressAttrResult (the opt-in --rdap attribution)."""
    return {
        "headline": result.headline,
        "ips_total": result.ips_total,
        "ips_resolved": result.ips_resolved,
        "dropped": result.dropped,
        "flagged": result.flagged,
        "measured": False,  # invariant: a static pointer, never a verdict
        "attributions": [
            {"ip": a.ip, "ptr": a.ptr, "country": a.country, "asn_name": a.asn_name,
             "jurisdiction": a.jurisdiction, "operator": a.operator, "origin": a.origin,
             "confidence": a.confidence, "prc_hint": a.prc_hint,
             "corpus_source": a.corpus_source, "processes": a.processes,
             "flagged": a.flagged, "measured": a.measured}
            for a in result.attributions
        ],
    }


def render_egress_attr_console(result) -> str:
    lines = [result.headline,
             "  (RDAP/PTR pointer — who an IP is registered to, NOT a measured verdict)", ""]
    if not result.attributions:
        lines.append("  no external upstream IPs to attribute.")
        return "\n".join(lines)
    for a in sorted(result.attributions, key=lambda x: (not x.flagged, x.ip)):
        tag = "[FLAG]" if a.flagged else "[ ok ]"
        who = a.operator or a.asn_name or a.ptr or "unattributed"
        juris = a.origin or a.jurisdiction
        lines.append(f"  {tag} {a.ip}  {who}  ({juris})")
        sub = []
        if a.ptr:
            sub.append(f"ptr={a.ptr}")
        if a.country:
            sub.append(f"cc={a.country}")
        if a.prc_hint:
            sub.append("PRC ASN heuristic")
        if sub:
            lines.append(f"      {', '.join(sub)}")
        lines.append(f"      used by: {', '.join(a.processes)}")
    return "\n".join(lines)


def ja3_to_json(observations) -> dict:
    """Render captured JA3 ClientHello observations (the --ja3 mode)."""
    from .ja3 import classify_ja3
    distinct = sorted({o.ja3_hash for o in observations})
    return {
        "headline": (f"JA3 capture: {len(observations)} ClientHello(s), "
                     f"{len(distinct)} distinct fingerprint(s)"),
        "measured": False,  # a client-TLS fingerprint pointer, never a verdict
        "distinct_fingerprints": len(distinct),
        "observations": [
            {"src_ip": o.src_ip, "dst_ip": o.dst_ip, "dst_port": o.dst_port,
             "ja3": o.ja3, "ja3_hash": o.ja3_hash, "known": classify_ja3(o.ja3_hash)}
            for o in observations
        ],
    }


def render_ja3_console(observations) -> str:
    from .ja3 import classify_ja3
    lines = ["JA3 client-TLS capture (passive; a fingerprint pointer, NOT a verdict)", ""]
    if not observations:
        lines.append("  no TLS ClientHellos captured in the window.")
        return "\n".join(lines)
    by_dst: dict[str, list] = {}
    for o in observations:
        by_dst.setdefault(o.dst_ip, []).append(o)
    for dst in sorted(by_dst):
        obs = by_dst[dst]
        hashes = sorted({o.ja3_hash for o in obs})
        lines.append(f"  {dst}:{obs[0].dst_port}  ({len(hashes)} distinct JA3)")
        for h in hashes:
            label = classify_ja3(h)
            lines.append(f"      {h} — {label if label else 'unknown client'}")
    distinct = len({o.ja3_hash for o in observations})
    if distinct > 1:
        lines += ["", "  note: multiple distinct client fingerprints observed — an "
                      "unexpected second JA3 to a sanctioned upstream can indicate an "
                      "interception proxy (corroborate with --trust-store)."]
    return "\n".join(lines)


def render_console(result: ScanResult, redact: bool = True) -> str:
    lines: list[str] = [result.headline, ""]
    if not result.findings:
        if not result.unattributed_names:
            lines.append("  no agent-CLI base_url configuration found.")
        return "\n".join(lines)
    for f in result.findings:
        marker = "OK  " if f.classification == SANCTIONED else "FLAG"
        via = f" via {f.via_gateway}" if f.via_gateway else ""
        src = _redact_source(f.source) if redact else f.source
        lines.append(f"  [{marker}] {f.host or '(unparsed)'}{via}  "
                     f"({f.classification}, evidence: {f.evidence_tier})")
        lines.append(f"      source: {src}  base_url: {f.base_url}")
        who = []
        if f.client:
            who.append(f"client {f.client}")
        if f.seen_at:
            who.append(f"time {f.seen_at}")
        if who:
            lines.append("      " + "  ".join(who))
        if f.classification == OFF_ALLOWLIST_ATTRIBUTED:
            lines.append(_attr_line(f))
        for n in f.notes:
            lines.append(f"      note: {n}")
    return "\n".join(lines)
