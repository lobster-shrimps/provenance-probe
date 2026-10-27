"""Fleet rollup: ONE CISO posture report across many scanned machines.

The fleet stack scans and reports one machine at a time; a security team piloting
this needs one report across the whole fleet — "of my N machines, which are reaching
unsanctioned or PRC-origin AI endpoints, and which ones." This module is the pure,
NO-EGRESS aggregation over already-collected data. It never writes and never makes a
network call; it only reads local files (the module invariant, asserted in tests).

Terminology (locked):
  * machine      = a scanned fleet COMPUTER (what a CISO counts: "42 machines").
  * endpoint host = the upstream AI hostname a machine is configured to reach.
The rollup COUNTS machines and GROUPS exposure by endpoint host — different axes,
never conflated.

Input is EITHER a single SQLite DB (collector-merged, rows carry `machine`) OR a
directory of per-machine files (`*.db` single-machine stores and/or `*.json`
per-host reports; one file = one machine; non-recursive; malformed files are
skipped + counted, never crash).

The `fleet_scans` table is AUTHORITATIVE for the machine count + freshness; the
findings are authoritative for exposures. On disagreement, trust each for its own
axis (a clean machine with zero findings is still counted from `fleet_scans`).
"""
from __future__ import annotations

import csv
import datetime
import io
import json
import os
import sqlite3
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from .evidence import (
    AGGREGATOR_UNRESOLVABLE,
    GATEWAY_UPSTREAM_UNRESOLVED,
    OFF_ALLOWLIST_ATTRIBUTED,
    OFF_ALLOWLIST_UNATTRIBUTED,
    SANCTIONED,
)
from .render import _redact_source

DEFAULT_STALE_DAYS = 7
_FINDINGS_TABLE = "fleet_findings"
_SCANS_TABLE = "fleet_scans"
_OFF_ALLOWLIST = (OFF_ALLOWLIST_ATTRIBUTED, OFF_ALLOWLIST_UNATTRIBUTED)
_UNRESOLVED = (AGGREGATOR_UNRESOLVABLE, GATEWAY_UPSTREAM_UNRESOLVED)


class RollupError(Exception):
    """Unrecoverable rollup input error → CLI exit 2 (missing/unreadable path,
    corrupt SQLite, or a directory whose only candidate files are all unusable)."""


@dataclass(frozen=True)
class RFinding:
    """One flat finding row, normalised across DB rows and JSON reports."""
    host: str
    base_url: str
    classification: str
    evidence_tier: str
    via_gateway: str
    operator: str
    origin: str
    confidence: object  # float | None
    source: str


@dataclass(frozen=True)
class Machine:
    """One scanned computer and the endpoints it was configured to reach."""
    machine: str
    scanned_at: str | None
    findings: tuple[RFinding, ...] = ()

    @property
    def holding_state(self) -> str:
        """HOLDING (all sanctioned / zero findings), DRIFTED (>=1 off-allowlist), or
        UNRESOLVED (only aggregator/gateway-unresolved). Precedence: drift > unresolved
        > holding — an aggregator-only machine is UNRESOLVED, never clean, never drift."""
        classes = {f.classification for f in self.findings}
        if classes & set(_OFF_ALLOWLIST):
            return "drifted"
        if classes & set(_UNRESOLVED):
            return "unresolved"
        return "holding"


@dataclass
class Rollup:
    """The aggregated fleet view, before rendering."""
    machines: list[Machine]
    machines_scanned: int | None  # None = "unknown" (old DB lacking machine signal)
    files_skipped: int = 0
    stale_days: int = DEFAULT_STALE_DAYS
    now: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def load_rollup(path: str, *, stale_days: int = DEFAULT_STALE_DAYS) -> Rollup:
    """Load a Rollup from a single SQLite DB, a single JSON report, or a directory.

    Raises RollupError (→ exit 2) on a missing/unreadable path, a corrupt/unopenable
    SQLite DB (single-file input), or a directory whose candidate files are all
    unusable. An empty directory (no candidate files) and an empty-but-valid DB both
    yield an honest 0-machine Rollup (exit 0)."""
    full = os.path.expanduser(path)
    if not os.path.exists(full):
        raise RollupError(f"no such path: {path}")
    if os.path.isdir(full):
        return _load_dir(full, stale_days=stale_days)
    return _load_single_file(full, stale_days=stale_days)


def _load_single_file(full: str, *, stale_days: int) -> Rollup:
    if full.lower().endswith(".json"):
        try:
            with open(full, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as e:
            raise RollupError(f"could not read JSON report {full}: {e}") from e
        machine = _machine_from_json(data, full)
        if machine is None:
            raise RollupError(f"not a fleet JSON report: {full}")
        return Rollup(machines=[machine], machines_scanned=1, stale_days=stale_days)
    # Otherwise treat as a SQLite DB.
    try:
        machines, count = _read_db(full)
    except (OSError, sqlite3.Error) as e:
        raise RollupError(f"could not read SQLite DB {full}: {e}") from e
    return Rollup(machines=machines, machines_scanned=count, stale_days=stale_days)


def _load_dir(full: str, *, stale_days: int) -> Rollup:
    try:
        entries = sorted(os.listdir(full))
    except OSError as e:
        raise RollupError(f"could not read directory {full}: {e}") from e
    candidates = [e for e in entries
                  if e.lower().endswith((".db", ".json"))
                  and os.path.isfile(os.path.join(full, e))]
    if not candidates:
        # An empty dir (no per-machine files) is an honest 0-machine report, exit 0.
        return Rollup(machines=[], machines_scanned=0, stale_days=stale_days)

    collected: list[Machine] = []
    skipped = 0
    for name in candidates:
        fpath = os.path.join(full, name)
        try:
            if name.lower().endswith(".json"):
                with open(fpath, encoding="utf-8") as fh:
                    data = json.load(fh)
                m = _machine_from_json(data, fpath)
                if m is None:
                    skipped += 1
                    continue
                collected.append(m)
            else:  # *.db — one file = one machine, but a merged store may hold several
                machines, _ = _read_db(fpath)
                if not machines:
                    # A valid-but-empty DB in a dir still counts as one machine.
                    collected.append(Machine(machine=_stem(fpath), scanned_at=None))
                else:
                    collected.extend(machines)
        except (OSError, ValueError, sqlite3.Error):
            skipped += 1
            continue

    if not collected:
        # Candidate files existed but none were usable — likely a wrong path.
        raise RollupError(
            f"directory {full}: {skipped} candidate file(s), none usable")

    deduped = _dedupe(collected)
    return Rollup(machines=deduped, machines_scanned=len(deduped),
                  files_skipped=skipped, stale_days=stale_days)


def _stem(path: str) -> str:
    return os.path.splitext(os.path.basename(path))[0]


def _dedupe(machines: list[Machine]) -> list[Machine]:
    """Directory dedup by machine id: a duplicate id -> keep the one with the latest
    `scanned_at`; on a tie (or all-unknown) keep both under disambiguated ids."""
    by_id: dict[str, list[Machine]] = {}
    order: list[str] = []
    for m in machines:
        if m.machine not in by_id:
            by_id[m.machine] = []
            order.append(m.machine)
        by_id[m.machine].append(m)

    out: list[Machine] = []
    for mid in order:
        group = by_id[mid]
        if len(group) == 1:
            out.append(group[0])
            continue
        # Sort newest-first; None sorts last.
        ranked = sorted(group, key=lambda x: (x.scanned_at or ""), reverse=True)
        top = ranked[0]
        # A unique, non-empty latest timestamp wins outright.
        if top.scanned_at and (len(ranked) == 1 or ranked[1].scanned_at != top.scanned_at):
            out.append(top)
        else:
            # Tie / all-unknown: keep all, disambiguating the 2nd+ under id#N.
            for i, m in enumerate(ranked):
                out.append(m if i == 0 else _rename(m, f"{mid}#{i + 1}"))
    return out


def _rename(m: Machine, new_id: str) -> Machine:
    return Machine(machine=new_id, scanned_at=m.scanned_at, findings=m.findings)


# --------------------------------------------------------------------------- #
# SQLite reader (back-compat via PRAGMA table_info)
# --------------------------------------------------------------------------- #

def _read_db(path: str) -> tuple[list[Machine], int | None]:
    """Read machines from a SQLite DB. Returns (machines, machines_scanned).

    `machines_scanned` is None when the DB predates the `machine` column (old DB) —
    the caller reports "machine count unknown". `fleet_scans` is authoritative for
    the count + freshness; findings are authoritative for exposures. A clean machine
    (in `fleet_scans` with zero findings) is still returned."""
    con = sqlite3.connect(path)
    try:
        find_cols = _table_cols(con, _FINDINGS_TABLE)
        if not find_cols:
            # No findings table at all: an unrecognised / non-fleet DB.
            raise sqlite3.DatabaseError(f"no {_FINDINGS_TABLE} table")
        has_machine = "machine" in find_cols
        has_scanned = "scanned_at" in find_cols
        has_scans = bool(_table_cols(con, _SCANS_TABLE))

        # findings grouped by machine (or under a single anonymous bucket)
        findings_by_machine: dict[str | None, list[RFinding]] = {}
        latest_from_findings: dict[str | None, str | None] = {}
        rows = con.execute(f"SELECT * FROM {_FINDINGS_TABLE}").fetchall()
        col_index = {c: i for i, c in enumerate(find_cols)}
        for r in rows:
            mid = r[col_index["machine"]] if has_machine else None
            sat = r[col_index["scanned_at"]] if has_scanned else None
            findings_by_machine.setdefault(mid, []).append(_finding_from_row(r, col_index))
            if sat and sat > (latest_from_findings.get(mid) or ""):
                latest_from_findings[mid] = sat

        if has_scans:
            scan_rows = con.execute(
                f"SELECT machine, scanned_at FROM {_SCANS_TABLE}").fetchall()
            # Authoritative machine set. Keep latest scanned_at per machine.
            scan_at: dict[str, str | None] = {}
            for mid, sat in scan_rows:
                if mid not in scan_at or (sat or "") > (scan_at[mid] or ""):
                    scan_at[mid] = sat
            machines: list[Machine] = []
            seen: set[str] = set()
            for mid in scan_at:
                seen.add(mid)
                machines.append(Machine(
                    machine=mid, scanned_at=scan_at[mid],
                    findings=tuple(findings_by_machine.get(mid, []))))
            # A machine present in findings but not in scans still shows exposures.
            for mid in findings_by_machine:
                if mid is not None and mid not in seen:
                    machines.append(Machine(
                        machine=mid, scanned_at=latest_from_findings.get(mid),
                        findings=tuple(findings_by_machine[mid])))
            return machines, len(scan_at)

        if has_machine:
            machines = [
                Machine(machine=mid, scanned_at=latest_from_findings.get(mid),
                        findings=tuple(fs))
                for mid, fs in findings_by_machine.items() if mid is not None]
            # rows with a NULL machine (partial old data) fold into one bucket
            if None in findings_by_machine:
                machines.append(Machine(machine="(unknown)", scanned_at=None,
                                        findings=tuple(findings_by_machine[None])))
            return machines, len({m.machine for m in machines})

        # Old DB: no machine column at all. One anonymous bucket; count unknown.
        all_findings = [f for fs in findings_by_machine.values() for f in fs]
        return [Machine(machine="(unknown)", scanned_at=None,
                        findings=tuple(all_findings))], None
    finally:
        con.close()


def _table_cols(con: sqlite3.Connection, table: str) -> list[str]:
    """Column names for `table` via PRAGMA table_info, [] if the table is absent."""
    return [r[1] for r in con.execute(f"PRAGMA table_info({table})").fetchall()]


def _finding_from_row(r: tuple, col_index: dict[str, int]) -> RFinding:
    def col(name: str, default=""):
        i = col_index.get(name)
        return r[i] if i is not None and r[i] is not None else default
    return RFinding(
        host=col("host"), base_url=col("base_url"),
        classification=col("classification"), evidence_tier=col("evidence_tier"),
        via_gateway=col("via_gateway"), operator=col("operator"),
        origin=col("origin"), confidence=col("confidence", None),
        source=col("source"))


# --------------------------------------------------------------------------- #
# JSON report reader
# --------------------------------------------------------------------------- #

def _machine_from_json(data: object, path: str) -> Machine | None:
    """Build one Machine from a `render.to_json` per-host report, or None if the
    file is not a recognisable report (→ skipped/counted)."""
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        return None
    mid = data.get("machine") or _stem(path)
    scanned_at = data.get("scanned_at")
    findings = [_finding_from_json(f) for f in data["findings"] if isinstance(f, dict)]
    return Machine(machine=str(mid), scanned_at=scanned_at, findings=tuple(findings))


def _finding_from_json(f: dict) -> RFinding:
    attr = f.get("attribution") or {}
    return RFinding(
        host=f.get("host", "") or "", base_url=f.get("base_url", "") or "",
        classification=f.get("classification", "") or "",
        evidence_tier=f.get("evidence_tier", "") or "",
        via_gateway=f.get("via_gateway", "") or "",
        operator=attr.get("operator", "") or "",
        origin=attr.get("origin", "") or "",
        confidence=attr.get("confidence"),
        source=f.get("source", "") or "")


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #

def _sanitize_base_url(base_url: str) -> str:
    """Strip any userinfo/credentials and the query string; keep scheme+host+path.
    A best-effort no-op on an unparseable value (which is still credential-free)."""
    try:
        parts = urlsplit(base_url or "")
    except ValueError:
        return ""
    if not parts.scheme and not parts.netloc:
        return base_url or ""
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _all_findings(rollup: Rollup):
    for m in rollup.machines:
        for f in m.findings:
            yield m, f


def _is_prc(origin: str) -> bool:
    return (origin or "").startswith("PRC")


def _freshness(rollup: Rollup) -> dict:
    stale: list[str] = []
    unknown = 0
    have_any = False
    cutoff = rollup.now - datetime.timedelta(days=rollup.stale_days)
    for m in rollup.machines:
        if not m.scanned_at:
            unknown += 1
            continue
        dt = _parse_iso(m.scanned_at)
        if dt is None:
            unknown += 1
            continue
        have_any = True
        if dt < cutoff:
            stale.append(m.machine)
    return {"available": have_any, "stale_days": rollup.stale_days,
            "stale_machines": sorted(stale), "unknown_machines": unknown}


def _parse_iso(value: str) -> datetime.datetime | None:
    try:
        dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def build_report(rollup: Rollup) -> dict:
    """The aggregated report as a plain dict (the JSON schema; also drives console)."""
    # Classification totals (FINDINGS per classification).
    totals: dict[str, int] = {}
    for _m, f in _all_findings(rollup):
        totals[f.classification] = totals.get(f.classification, 0) + 1

    # Per-machine holding split.
    holding = drifted = unresolved = 0
    for m in rollup.machines:
        state = m.holding_state
        if state == "holding":
            holding += 1
        elif state == "drifted":
            drifted += 1
        else:
            unresolved += 1

    # PRC exposure: endpoint host -> machines reaching it.
    prc: dict[str, dict] = {}
    for m, f in _all_findings(rollup):
        if not _is_prc(f.origin):
            continue
        e = prc.setdefault(f.host, {"endpoint": f.host, "operator": f.operator,
                                    "origin": f.origin, "machines": set()})
        e["machines"].add(m.machine)
        if not e["operator"] and f.operator:
            e["operator"] = f.operator
    prc_exposure = [
        {"endpoint": e["endpoint"], "operator": e["operator"], "origin": e["origin"],
         "machines": sorted(e["machines"])}
        for e in sorted(prc.values(), key=lambda x: x["endpoint"])]

    # Rogue upstreams: endpoint host with >=1 off-allowlist finding.
    rogue: dict[str, dict] = {}
    for m, f in _all_findings(rollup):
        if f.classification not in _OFF_ALLOWLIST:
            continue
        e = rogue.setdefault(f.host, {"host": f.host, "operator": f.operator,
                                      "origin": f.origin, "machines": set()})
        e["machines"].add(m.machine)
        # Prefer an attributed operator/origin if one row carries it.
        if not e["operator"] and f.operator:
            e["operator"] = f.operator
        if not e["origin"] and f.origin:
            e["origin"] = f.origin
    rogue_upstreams = [
        {"host": e["host"], "operator": e["operator"], "origin": e["origin"],
         "is_prc": _is_prc(e["origin"]), "machine_count": len(e["machines"]),
         "machines": sorted(e["machines"])}
        for e in sorted(rogue.values(),
                        key=lambda x: (not _is_prc(x["origin"]), x["host"]))]

    # Unresolved endpoints (aggregator / gateway-unresolved) — a separate line.
    unresolved_hosts = sorted({
        f.host for _m, f in _all_findings(rollup)
        if f.classification in _UNRESOLVED and f.host})

    machines_scanned = rollup.machines_scanned
    # The holding split iterates ALL rollup.machines (holding+drifted+unresolved ==
    # len(machines)); on a partial merged DB a machine can have findings but no
    # fleet_scans row, so len(machines) > machines_scanned. Use the larger as the
    # denominator so the fraction never reads "3/2".
    total_for_holding = max(len(rollup.machines),
                            machines_scanned if machines_scanned is not None else 0)
    prc_machine_count = len({m.machine for m, f in _all_findings(rollup) if _is_prc(f.origin)})

    return {
        "headline": _headline(machines_scanned, total_for_holding, holding,
                              prc_machine_count, totals),
        "machines_scanned": machines_scanned,
        "freshness": _freshness(rollup),
        "classification_totals": totals,
        "allowlist_holding": {"holding": holding, "drifted": drifted,
                              "unresolved": unresolved},
        "prc_exposure": prc_exposure,
        "rogue_upstreams": rogue_upstreams,
        "unresolved_endpoints": unresolved_hosts,
        "files_skipped": rollup.files_skipped,
    }


FAIL_ON_MODES = ("none", "prc", "drift", "any")


def rollup_from_scan(result, *, machine: str = "imported-log") -> Rollup:
    """One-machine rollup over a log or host scan.

    Names that never became findings (the unattributed count) stay out of
    the tallies, so drift is the corpus hits the log already classified.
    ``exposure_summary`` on this object is the same gate ``--rollup`` uses.
    """
    rows = []
    for f in result.findings:
        attr = f.attribution
        rows.append(RFinding(
            host=f.host or "",
            base_url=f.base_url or "",
            classification=f.classification or "",
            evidence_tier=f.evidence_tier or "",
            via_gateway=f.via_gateway or "",
            operator=attr.operator if attr else "",
            origin=attr.origin if attr else "",
            confidence=attr.confidence if attr else None,
            source=f.source or "",
        ))
    return Rollup(
        machines=[Machine(machine=machine, scanned_at=None, findings=tuple(rows))],
        machines_scanned=1,
    )


def exposure_counts(rollup: Rollup) -> dict:
    """FINDING-level exposure tallies (NOT the endpoint-grouped rogue-upstream count).

    * ``prc``        = findings whose attribution ``origin`` starts "PRC".
    * ``drift``      = findings classified OFF_ALLOWLIST_ATTRIBUTED / _UNATTRIBUTED.
    * ``unresolved`` = findings classified AGGREGATOR_UNRESOLVABLE / GATEWAY_UPSTREAM_UNRESOLVED.

    A finding may count toward BOTH ``prc`` and ``drift`` (a PRC-origin off-allowlist
    endpoint); the three buckets are not mutually exclusive. ``drift`` equals the sum
    of the report's two off-allowlist classification totals by construction."""
    prc = drift = unresolved = 0
    for _m, f in _all_findings(rollup):
        if _is_prc(f.origin):
            prc += 1
        if f.classification in _OFF_ALLOWLIST:
            drift += 1
        if f.classification in _UNRESOLVED:
            unresolved += 1
    return {"prc": prc, "drift": drift, "unresolved": unresolved}


def exposure_summary(rollup: Rollup, fail_on: str = "none") -> dict:
    """The deterministic exposure object an alert rule consumes:
    ``{prc, drift, unresolved, fail_on, matched, exit_code}``.

    Gate: ``prc`` matches iff prc>0; ``drift`` iff drift>0; ``any`` iff prc>0 or
    drift>0; ``none`` never matches (makes no pass/fail judgment). A match maps to
    exit code 3; no match to 0. UNRESOLVED is never exposure. Error (exit 2) is a
    CLI-level concern that outranks this and is decided before this is computed."""
    counts = exposure_counts(rollup)
    prc, drift = counts["prc"], counts["drift"]
    if fail_on == "prc":
        matched = prc > 0
    elif fail_on == "drift":
        matched = drift > 0
    elif fail_on == "any":
        matched = prc > 0 or drift > 0
    else:  # none (or any unknown mode) never gates
        matched = False
    return {"prc": prc, "drift": drift, "unresolved": counts["unresolved"],
            "fail_on": fail_on, "matched": matched,
            "exit_code": 3 if matched else 0}


def _exposure_line(exp: dict) -> str:
    """The stable, greppable summary string (shared by console + csv comment)."""
    base = f"EXPOSURE: prc={exp['prc']} drift={exp['drift']}"
    if exp["fail_on"] == "none":
        return f"{base} (fail-on=none)"
    verdict = "FAIL" if exp["matched"] else "ok"
    return f"{base} (fail-on={exp['fail_on']} -> {verdict})"


def _headline(machines_scanned: int | None, total: int, holding: int,
              prc_machines: int, totals: dict[str, int]) -> str:
    off_unattr = totals.get(OFF_ALLOWLIST_UNATTRIBUTED, 0)
    if machines_scanned is None:
        n_findings = sum(totals.values())
        return (f"machine count unknown (old DB); {n_findings} findings across "
                f"? machines; {prc_machines} reaching PRC-origin endpoints; "
                f"{off_unattr} off-allowlist unattributed")
    return (f"{machines_scanned} machines scanned; "
            f"{prc_machines} reaching PRC-origin endpoints; "
            f"{off_unattr} off-allowlist unattributed; "
            f"allowlist holding on {holding}/{total}")


# --------------------------------------------------------------------------- #
# Renderers (console / json / csv all live here to avoid render.py duplication)
# --------------------------------------------------------------------------- #

def to_json(rollup: Rollup, fail_on: str = "none") -> dict:
    rep = build_report(rollup)
    rep["exposure"] = exposure_summary(rollup, fail_on)
    return rep


CSV_HEADER = [
    "machine", "scanned_at", "host", "base_url", "classification", "evidence_tier",
    "via_gateway", "operator", "origin", "confidence", "source",
]


def to_csv(rollup: Rollup, fail_on: str = "none") -> str:
    """One flat row per (machine, finding); a zero-finding machine emits one row with
    empty finding columns so a clean machine still appears in the export. `source` is
    redacted and `base_url` is sanitized (no creds/query) in every row. A trailing
    `# EXPOSURE: ...` comment line (leading `#` so comment-skipping parsers ignore it)
    always carries the gate summary; the exit code is the primary machine signal."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_HEADER)
    for m in rollup.machines:
        if not m.findings:
            w.writerow([m.machine, m.scanned_at or "", "", "", "", "", "", "", "", "", ""])
            continue
        for f in m.findings:
            w.writerow([
                m.machine, m.scanned_at or "", f.host, _sanitize_base_url(f.base_url),
                f.classification, f.evidence_tier, f.via_gateway, f.operator, f.origin,
                "" if f.confidence is None else f.confidence,
                _redact_source(f.source),
            ])
    return buf.getvalue() + "# " + _exposure_line(exposure_summary(rollup, fail_on)) + "\n"


def render_console(rollup: Rollup, fail_on: str = "none") -> str:
    r = build_report(rollup)
    lines: list[str] = [r["headline"], ""]

    if rollup.files_skipped:
        lines.append(f"  {rollup.files_skipped} file(s) skipped (unreadable / not a "
                     f"fleet report).")
        lines.append("")

    # Machine count + holding split (labeled).
    fresh = r["freshness"]
    ms = r["machines_scanned"]
    lines.append(f"MACHINES: {ms if ms is not None else 'unknown'} scanned")
    hold = r["allowlist_holding"]
    lines.append(f"  allowlist (per machine): {hold['holding']} holding, "
                 f"{hold['drifted']} drifted, {hold['unresolved']} unresolved "
                 f"(needs an active probe)")
    if fresh["available"]:
        stale = fresh["stale_machines"]
        stale_note = (f"{len(stale)} stale (> {fresh['stale_days']}d): "
                      + ", ".join(stale)) if stale else "all fresh"
        unk = f"; {fresh['unknown_machines']} freshness unknown" if fresh["unknown_machines"] else ""
        lines.append(f"  freshness (>{fresh['stale_days']}d stale): {stale_note}{unk}")
    else:
        lines.append("  freshness unavailable (no scan timestamps in this input)")
    lines.append("")

    # Classification totals (FINDINGS) — labeled distinctly from the machine split.
    lines.append("CLASSIFICATION TOTALS (findings):")
    if r["classification_totals"]:
        for cls in sorted(r["classification_totals"]):
            lines.append(f"  {cls}: {r['classification_totals'][cls]}")
    else:
        lines.append("  (no endpoint findings across the fleet)")
    lines.append("")

    # PRC exposure.
    lines.append("PRC-ORIGIN EXPOSURE (endpoint -> machines):")
    if r["prc_exposure"]:
        for e in r["prc_exposure"]:
            who = f"{e['operator']} ({e['origin']})" if e["operator"] else e["origin"]
            lines.append(f"  {e['endpoint']}  [{who}]  "
                         f"{len(e['machines'])} machine(s): {', '.join(e['machines'])}")
    else:
        lines.append("  none.")
    lines.append("")

    # Rogue upstream table.
    lines.append("ROGUE UPSTREAMS (off-allowlist, grouped by endpoint host):")
    if r["rogue_upstreams"]:
        for e in r["rogue_upstreams"]:
            flag = "PRC " if e["is_prc"] else ""
            who = e["operator"] or "unattributed"
            origin = f", {e['origin']}" if e["origin"] else ""
            lines.append(f"  [{flag}FLAG] {e['host']}  ({who}{origin})  "
                         f"{e['machine_count']} machine(s): {', '.join(e['machines'])}")
    else:
        lines.append("  none.")
    lines.append("")

    # Unresolved endpoints (never counted clean or drift).
    if r["unresolved_endpoints"]:
        lines.append("UNRESOLVED (needs an active probe — not counted clean or drift):")
        for host in r["unresolved_endpoints"]:
            lines.append(f"  {host}")
        lines.append("")

    # Deterministic, greppable gate summary as the trailing final line.
    lines.append("")
    lines.append(_exposure_line(exposure_summary(rollup, fail_on)))
    return "\n".join(lines).rstrip() + "\n"


def render(rollup: Rollup, fmt: str = "console", fail_on: str = "none") -> str:
    if fmt == "json":
        return json.dumps(to_json(rollup, fail_on), indent=2)
    if fmt == "csv":
        return to_csv(rollup, fail_on)
    return render_console(rollup, fail_on)
