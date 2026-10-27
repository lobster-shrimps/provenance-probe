"""Duration-bounded continuous model-switch soak test (#124).

A "soak test" for silent model swaps: poll each configured service for a set
window (say 30 minutes) and get a timeline of what it served back. It is the
duration-bounded counterpart to the always-on ``watch`` daemon and the nightly
observatory — you run it, it ends, it hands you a report.

    t0 ──poll──▶ t1 ──poll──▶ … ──poll──▶ deadline
        │            │             │
        ▼            ▼             ▼
    per target: model card (ADVISORY) + tokenizer fingerprint (CONFIRMED)

WS1 applied over time (the founding z.ai case). Two signals per poll:

  * the model card — the echoed ``model`` id + the ``/models`` list — is a cheap,
    frequent ADVISORY signal. z.ai kept a CONSTANT Gemini persona while swapping
    the backend to GLM, so the card alone would never see the change.
  * the tokenizer FINGERPRINT (``monitor.fingerprint`` via a light ``assess``) is
    the HARD switch authority. A ``monitor.diff`` *critical* change is a CONFIRMED
    switch even when the echoed model id is unchanged (the z.ai shape).

No new detection logic: the fingerprint, the diff and the per-target store are
all reused from ``monitor`` / ``assess`` / ``watch``. This module only adds the
duration-bounded scheduler, the two-signal poll, the timeline and the summary.

SECRET-SAFETY (extends ``watch``'s no-secret-in-any-sink invariant to the NEW
untrusted fields): the echoed model id and the ``/models`` response are UNTRUSTED
and may echo an API key. We store ONLY the secret-scrubbed model-id string and
the ``models_hash`` (a hash over the sorted unique id set) — NEVER the raw
``/models`` response. Every model-id string is routed through the target's
credential redactor before it enters any timeline / switch / report / log sink.
The full assess bundle is held in memory ONLY (to feed ``monitor.diff``) and is
never serialized to a sink.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .config import Target
from .client import Client
from . import assess, monitor, watch


# ------------------------------------------------------------------ parsing ---
def parse_duration(s: str) -> int:
    """Parse ``30m`` / ``2m`` / ``45s`` / ``1h`` (or a bare integer = seconds).

    Shares ``watch``'s grammar so ``--duration`` / ``--interval`` / ``--card-interval``
    all accept the same forms; rejects the empty string, non-positive and garbage.
    """
    return watch.parse_interval(s)


def light_opts() -> assess.AssessOpts:
    """The fast, cheap poll profile: tokenizer ON (the strongest signal),
    behavioral + deception OFF — same trade-off the ``watch`` daemon makes."""
    return assess.AssessOpts(no_behavioral=True, no_deception=True)


# ------------------------------------------------------------- secret hygiene ---
def _secret_values(target: Target) -> list[str]:
    """Every raw credential string that could be echoed back by an untrusted
    target: the composed auth/cookie/extra header values AND the BARE token /
    cookie material.

    ``client._safe_err`` only knows the COMPOSED header value (``Bearer <tok>``),
    but a hostile endpoint can echo the BARE ``<tok>`` inside a model id or a
    ``/models`` entry — without the ``Bearer `` prefix. So we redact the bare
    env token / cookie too. Longest-first so a superset is replaced before a
    substring of it.
    """
    vals: set[str] = set()
    try:
        for k, v in target.headers().items():
            if k in ("Content-Type", "Accept", "anthropic-version"):
                continue
            if isinstance(v, str):
                vals.add(v)
    except Exception:
        pass
    tok = os.environ.get(target.auth_value_env, "") if target.auth_value_env else ""
    if tok:
        vals.add(tok)
    cookie = target.cookie or (os.environ.get(target.cookie_env, "") if target.cookie_env else "")
    if cookie:
        vals.add(cookie)
    return sorted((v for v in vals if len(v) >= 4), key=len, reverse=True)


def _scrub(target: Target, s: Optional[str], *, client: Optional[Client] = None) -> Optional[str]:
    """Route an UNTRUSTED string (an echoed model id / a ``/models`` entry) through
    the target's credential redactor before it can enter any sink.

    Redacts BOTH the composed header values (via ``client._safe_err``) AND the bare
    token / cookie material an endpoint could echo without the ``Bearer `` prefix.
    Fails CLOSED: if redaction itself raises we return a fixed generic string
    rather than the raw (possibly secret-bearing) value.
    """
    if s is None:
        return None
    try:
        out = str(s)
        c = client or Client(target)
        out = c._safe_err(out)                                # composed header values
        for secret in _secret_values(target):                # bare token / cookie
            if secret in out:
                out = out.replace(secret, "[redacted]")
        return out
    except Exception:
        return "[redacted]"


def models_hash(ids, redact: Optional[Callable[[str], str]] = None) -> str:
    """``sha256`` over the SORTED UNIQUE set of model-id strings only.

    Order and volatile metadata (created timestamps, list reordering) are ignored,
    so an incidental response reshuffle never produces a spurious advisory. Each
    id is optionally scrubbed first so even the hash input carries no secret.
    """
    clean = []
    for i in ids or []:
        if not i:
            continue
        v = str(i)
        clean.append(redact(v) if redact else v)
    uniq = sorted(set(clean))
    return hashlib.sha256("\n".join(uniq).encode()).hexdigest()[:24]


# -------------------------------------------------------------------- polling ---
@dataclass
class Poll:
    """One poll result. ``bundle`` is the full assess bundle held IN MEMORY only
    (to feed ``monitor.diff``); it is NEVER serialized to a sink. Only ``model_id``
    (scrubbed) + ``models_hash`` + ``fingerprint_id`` ever reach the report."""
    ok: bool
    ts: str
    model_id: Optional[str] = None
    models_hash: Optional[str] = None
    fingerprint_id: Optional[str] = None
    bundle: Optional[dict] = None
    reason: str = ""


def _catalog_ids(client: Client) -> list:
    """Extract the model-id list from a ``/models`` response (mirrors
    ``wire.model_catalog`` parsing). Returns the RAW ids — the caller MUST hash /
    scrub them; they are never stored verbatim."""
    r = client.list_models()
    ids = []
    b = r.body
    if isinstance(b, dict):
        for m in b.get("data", b.get("models", [])) or []:
            if isinstance(m, dict):
                ids.append(m.get("id") or m.get("name") or "")
            elif isinstance(m, str):
                ids.append(m)
    return ids


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def poll_full(target: Target, opts: assess.AssessOpts, *,
              client: Optional[Client] = None) -> Poll:
    """The HARD poll: a light ``assess`` (tokenizer + wire; no behavioral/deception)
    -> ``fingerprint_id`` (the switch authority) PLUS the model-card fields the
    bundle already carries (echoed id + ``/models`` list). One network round.

    A failed/partial poll (unreachable, auth error, non-2xx primary probe) is a
    NO-DATA observation (``ok=False`` + a redacted reason); it never raises.
    """
    ts = _now_iso()
    c = client or Client(target)
    try:
        b = assess.assess_target(target, opts, client=c)
    except Exception as e:                                    # never crash the soak
        return Poll(ok=False, ts=ts, reason=_scrub(target, str(e), client=c) or "poll failed")
    status = (b.get("headers") or {}).get("status")
    if not (isinstance(status, int) and 200 <= status < 400):
        return Poll(ok=False, ts=ts, reason=f"primary probe status {status}")
    model_id = _scrub(target, (b.get("headers") or {}).get("echoed_model"), client=c)
    ids = (b.get("catalog") or {}).get("ids") or []
    mh = models_hash(ids, redact=lambda s: _scrub(target, s, client=c))
    return Poll(ok=True, ts=ts, model_id=model_id, models_hash=mh,
                fingerprint_id=b.get("fingerprint_id"), bundle=b)


def poll_card(target: Target, *, client: Optional[Client] = None) -> Poll:
    """The CHEAP poll: a minimal 1-token chat (echoed ``model`` id) + a ``/models``
    GET (hashed). ADVISORY only — no fingerprint. Runs at ``--card-interval``."""
    ts = _now_iso()
    c = client or Client(target)
    r = c.chat("ping", max_tokens=1)
    if not r.ok:
        return Poll(ok=False, ts=ts,
                    reason=_scrub(target, r.err or f"chat status {r.status}", client=c) or "card poll failed")
    model_id = _scrub(target, r.echoed_model(), client=c)
    ids = _catalog_ids(c)
    mh = models_hash(ids, redact=lambda s: _scrub(target, s, client=c))
    return Poll(ok=True, ts=ts, model_id=model_id, models_hash=mh)


# -------------------------------------------------------------- state machine ---
def _has_critical(diff_result: dict) -> bool:
    """The CONFIRMED authority: a ``monitor.diff`` change graded ``critical``
    (fingerprint_id / tokenizer shape). Non-critical diffs (header/error/greedy/
    streaming/latency wire noise) are NOT a CONFIRMED switch."""
    return any(c.get("severity") == "critical" for c in diff_result.get("changes", []))


class TargetSoak:
    """Per-target soak state: the ordered timeline, emitted switches and gaps.

    Each poll is compared to the IMMEDIATELY-PREVIOUS observed state (not only t0),
    so a switch is emitted ONLY on a state change and A->B->B->A yields exactly two
    transitions. The previous full bundle is held in memory to feed ``monitor.diff``.
    """

    def __init__(self, name: str):
        self.name = name
        self.cycles = 0
        self.observations = 0
        self.timeline: list[dict] = []
        self.switches: list[dict] = []
        self.gaps: list[dict] = []
        self._prev_card: Optional[tuple] = None      # (model_id, models_hash)
        self._prev_bundle: Optional[dict] = None     # in-memory only
        self._prev_fp: Optional[str] = None

    # --- timeline maintenance ---
    def _timeline_record(self, ts: str, model_id, models_hash, fingerprint_id) -> None:
        state = (model_id, models_hash, fingerprint_id)
        if self.timeline:
            last = self.timeline[-1]
            if (last["model_id"], last["models_hash"], last["fingerprint_id"]) == state:
                last["last_seen"] = ts
                last["observations"] += 1
                return
        self.timeline.append({
            "model_id": model_id, "models_hash": models_hash,
            "fingerprint_id": fingerprint_id,
            "first_seen": ts, "last_seen": ts, "observations": 1})

    def _bump_current_run(self, ts: str) -> None:
        if self.timeline:
            self.timeline[-1]["last_seen"] = ts
            self.timeline[-1]["observations"] += 1

    # --- switch records (secret-safe by construction) ---
    def _advisory(self, ts: str, frm: tuple, to: tuple) -> dict:
        return {"ts": ts, "target": self.name, "grade": "ADVISORY", "signal": "card",
                "from": {"model_id": frm[0], "models_hash": frm[1]},
                "to": {"model_id": to[0], "models_hash": to[1]},
                "note": "model-card change with a stable fingerprint — honest relabel "
                        "or deception, NOT a confirmed switch on its own (WS1)."}

    def _confirmed(self, ts: str, frm_fp, to_fp, diff_result: dict) -> dict:
        return {"ts": ts, "target": self.name, "grade": "CONFIRMED", "signal": "fingerprint",
                "from": frm_fp, "to": to_fp,
                "changes": [c for c in diff_result.get("changes", []) if c.get("severity") == "critical"],
                "confidence": diff_result.get("confidence")}

    def _jurisdiction_shift(self, ts: str, diff_result: dict) -> dict:
        """A jurisdiction flip TO PRC — its OWN category (#129), SEPARATE from a
        CONFIRMED model switch. Built from the diff's distinct jurisdiction-shift
        change (verdict transition) only; carries no secret material."""
        jur = [c for c in diff_result.get("changes", [])
               if c.get("field") == "prc_jurisdiction_shift"]
        return {"ts": ts, "target": self.name, "grade": "PRC-JURISDICTION-SHIFT",
                "signal": "jurisdiction", "changes": jur,
                "confidence": diff_result.get("confidence"),
                "note": "jurisdiction verdict crossed into PRC (LIKELY/CONFIRMED) — the "
                        "endpoint's inference is now under PRC jurisdiction; SEPARATE "
                        "from a model/stack switch (not a confirmed model switch)."}

    # --- apply a poll ---
    def apply_full(self, poll: Poll) -> list[dict]:
        """Apply a HARD poll. Emits an ADVISORY on a card change and a CONFIRMED on
        a ``monitor.diff`` critical, updates the timeline + previous state, and
        returns the newly emitted switch records (for persistence)."""
        self.observations += 1
        emitted: list[dict] = []
        card = (poll.model_id, poll.models_hash)
        if self._prev_card is not None and card != self._prev_card:
            emitted.append(self._advisory(poll.ts, self._prev_card, card))
        if self._prev_bundle is not None and poll.bundle is not None:
            result = monitor.diff(self._prev_bundle, poll.bundle)
            if _has_critical(result):
                emitted.append(self._confirmed(poll.ts, self._prev_fp, poll.fingerprint_id, result))
            if result.get("prc_jurisdiction_shift"):     # separate axis (#129)
                emitted.append(self._jurisdiction_shift(poll.ts, result))
        self._timeline_record(poll.ts, poll.model_id, poll.models_hash, poll.fingerprint_id)
        self._prev_card = card
        self._prev_bundle = poll.bundle
        self._prev_fp = poll.fingerprint_id
        self.switches.extend(emitted)
        return emitted

    def apply_card(self, poll: Poll) -> tuple[str, list[dict]]:
        """Apply a CHEAP card poll. Returns ``(status, records)`` where status is
        ``"seed"`` / ``"stable"`` / ``"changed"``. On ``"changed"`` the caller must
        trigger an out-of-schedule ``apply_full`` to (maybe) upgrade to CONFIRMED."""
        self.observations += 1
        card = (poll.model_id, poll.models_hash)
        if self._prev_card is None:                          # unusual: first obs is card-only
            self._timeline_record(poll.ts, poll.model_id, poll.models_hash, None)
            self._prev_card = card
            return "seed", []
        if card != self._prev_card:
            adv = self._advisory(poll.ts, self._prev_card, card)
            self._prev_card = card
            self.switches.append(adv)
            return "changed", [adv]
        self._bump_current_run(poll.ts)
        return "stable", []

    def record_gap(self, ts: str, reason: str) -> None:
        """A NO-DATA poll: recorded as a timeline gap; the previous state is left
        UNCHANGED and no switch is emitted (there is nothing to compare)."""
        self.gaps.append({"ts": ts, "reason": reason})

    def report(self) -> dict:
        return {
            "name": self.name,
            "cycles": self.cycles,
            "observations": self.observations,
            "confirmed_switches": sum(1 for s in self.switches if s["grade"] == "CONFIRMED"),
            "advisory_switches": sum(1 for s in self.switches if s["grade"] == "ADVISORY"),
            "prc_jurisdiction_shifts": sum(1 for s in self.switches
                                           if s["grade"] == "PRC-JURISDICTION-SHIFT"),
            "timeline": list(self.timeline),
            "transitions": list(self.switches),
            "gaps": list(self.gaps),
        }


# ----------------------------------------------------------------- scheduling ---
class _RealClock:
    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float, stop_event: threading.Event) -> None:
        stop_event.wait(seconds)                             # interruptible


def _persist(name: str, records: list[dict], out: Callable[[str], None]) -> None:
    """Append each (secret-free) switch record to ``watch``'s per-target
    ``switches.jsonl`` — best-effort, never fatal (mirrors the daemon)."""
    for rec in records:
        try:
            watch.append_switch(name, rec)
        except Exception:
            out(f"[soak] {name}: could not append switches.jsonl (non-fatal)")


def _handle_full(st: TargetSoak, target: Target, poll: Poll,
                 out: Callable[[str], None]) -> None:
    if not poll.ok:
        st.record_gap(poll.ts, poll.reason or "no data")
        return
    _persist(st.name, st.apply_full(poll), out)


def _handle_card(st: TargetSoak, target: Target, poll: Poll,
                 poll_full_fn: Callable[[Target], Poll], out: Callable[[str], None]) -> None:
    if not poll.ok:
        st.record_gap(poll.ts, poll.reason or "no data")
        return
    status, recs = st.apply_card(poll)
    _persist(st.name, recs, out)
    if status == "changed":                                  # out-of-schedule fingerprint poll
        _handle_full(st, target, poll_full_fn(target), out)


def _write_report(out_dir: str, report: dict) -> str:
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    path = os.path.join(out_dir, f"soak-{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return path


def run_soak(targets: list[Target], opts: assess.AssessOpts, *,
             duration: int, interval: int, card_interval: Optional[int] = None,
             out_dir: str = "soak-reports",
             clock=None, stop_event: Optional[threading.Event] = None,
             poll_full_fn: Optional[Callable[[Target], Poll]] = None,
             poll_card_fn: Optional[Callable[[Target], Poll]] = None,
             now_iso_fn: Optional[Callable[[], str]] = None,
             log: Optional[Callable[[str], None]] = None) -> dict:
    """Run a duration-bounded soak and ALWAYS write + return the report.

    Targets are polled SEQUENTIALLY per cycle. The first poll is at t0. The
    deadline is checked BEFORE each new cycle; an in-flight per-target poll is
    bounded by the target's request timeout, so max overrun <= one timeout. A set
    ``stop_event`` (SIGINT/SIGTERM) stops after the current in-flight poll and
    still writes the report. ``clock`` / ``now_iso_fn`` / ``poll_*_fn`` are
    injectable so tests drive it with a virtual clock and no real network.
    """
    out = (lambda m: None) if log is None else log
    watch.assert_unique_slugs(targets)
    card_interval = card_interval or interval
    clock = clock or _RealClock()
    stop = stop_event or threading.Event()
    poll_full_fn = poll_full_fn or (lambda t: poll_full(t, opts))
    poll_card_fn = poll_card_fn or (lambda t: poll_card(t))
    now_iso_fn = now_iso_fn or _now_iso

    states = {t.name: TargetSoak(t.name) for t in targets}
    started_iso = now_iso_fn()
    start = clock.now()
    deadline = start + duration
    next_fp = start
    next_card = start

    try:
        while not stop.is_set():
            now = clock.now()
            if now >= deadline:                              # deadline BEFORE a new cycle
                break
            do_fp = now >= next_fp
            do_card = now >= next_card
            for t in targets:
                if stop.is_set():                            # finish nothing new after a stop
                    break
                st = states[t.name]
                st.cycles += 1
                try:
                    if do_fp:                                # a full poll subsumes the card
                        _handle_full(st, t, poll_full_fn(t), out)
                    elif do_card:
                        _handle_card(st, t, poll_card_fn(t), poll_full_fn, out)
                except Exception as e:                       # belt-and-suspenders: never die
                    st.record_gap(now_iso_fn(), _scrub(t, str(e)) or "poll error")
                    out(f"[soak] {t.name}: unexpected error (soak continues)")
            if do_fp:                                        # advance + skip missed ticks
                while next_fp <= now:
                    next_fp += interval
                while next_card <= now:
                    next_card += card_interval
            elif do_card:
                while next_card <= now:
                    next_card += card_interval
            if stop.is_set():
                break
            nxt = min(next_fp, next_card, deadline)
            delay = nxt - clock.now()
            if delay > 0:
                clock.sleep(delay, stop)
    finally:
        report = {
            "soak_version": 1,
            "started": started_iso,
            "ended": now_iso_fn(),
            "duration_s": duration,
            "interval_s": interval,
            "card_interval_s": card_interval,
            "targets": [states[t.name].report() for t in targets],
        }
        report["report_path"] = _write_report(out_dir, report)
    return report


# -------------------------------------------------------------------- summary ---
def summarize(report: dict) -> str:
    """A human-readable console summary: per target, cycles + CONFIRMED/ADVISORY
    counts + the ordered transitions with timestamps and from->to."""
    lines = [
        f"soak summary  ({report.get('duration_s')}s window, "
        f"interval {report.get('interval_s')}s / card {report.get('card_interval_s')}s)"
    ]
    for tr in report.get("targets", []):
        gap = f", {len(tr['gaps'])} gap(s)" if tr.get("gaps") else ""
        prc = tr.get("prc_jurisdiction_shifts", 0)
        prc_txt = f" / {prc} PRC-JURISDICTION-SHIFT" if prc else ""
        lines.append(
            f"  {tr['name']}: {tr['cycles']} cycles, "
            f"{tr['confirmed_switches']} CONFIRMED / {tr['advisory_switches']} ADVISORY"
            f"{prc_txt} switch(es){gap}")
        for s in tr.get("transitions", []):
            if s["grade"] == "CONFIRMED":
                lines.append(f"    [{s['ts']}] CONFIRMED  fingerprint {s['from']} -> {s['to']}")
            elif s["grade"] == "PRC-JURISDICTION-SHIFT":
                det = (s.get("changes") or [{}])[0].get("detail", "jurisdiction crossed into PRC")
                lines.append(f"    [{s['ts']}] PRC-JURISDICTION-SHIFT  {det}")
            else:
                lines.append(
                    f"    [{s['ts']}] ADVISORY   model-card "
                    f"{(s['from'] or {}).get('model_id')} -> {(s['to'] or {}).get('model_id')}")
        for g in tr.get("gaps", []):
            lines.append(f"    [{g['ts']}] gap        {g['reason']}")
        if not tr.get("transitions"):
            lines.append("    no switch observed")
    return "\n".join(lines)


def switch_gate(report: dict, *, fail_on_switch: bool) -> tuple[int, str | None]:
    """Exit code for ``--fail-on-switch``, plus a one-line console summary.

    Off (the default) the soak exits 0 and this adds no line. On, a CONFIRMED
    fingerprint switch or an ADVISORY card switch exits 2 after the report has
    already been written and printed. A PRC-JURISDICTION-SHIFT is its own
    category, not a model switch, and a gap is a no-data poll: neither trips
    the gate.
    """
    if not fail_on_switch:
        return 0, None
    confirmed = advisory = 0
    for tr in report.get("targets") or []:
        confirmed += int(tr.get("confirmed_switches") or 0)
        advisory += int(tr.get("advisory_switches") or 0)
    verdict = "FAIL" if confirmed or advisory else "ok"
    line = (f"SWITCH: confirmed={confirmed} advisory={advisory} "
            f"(fail-on-switch -> {verdict})")
    return (2 if confirmed or advisory else 0), line


def print_example() -> str:
    """A copy-pasteable recipe framing the founding z.ai case as the seed."""
    return (
        "# provenance-probe soak — a duration-bounded model-switch soak test\n"
        "#\n"
        "# The founding case: z.ai presented a Google-Gemini persona while serving\n"
        "# GLM; the swap was only revealed by repeated probing OVER TIME. `soak`\n"
        "# generalizes that: it polls each service's model card (ADVISORY) AND its\n"
        "# tokenizer fingerprint (the CONFIRMED authority) for a set window and\n"
        "# reports a timeline. A fingerprint move is a CONFIRMED switch even when\n"
        "# the echoed model id never changes (the z.ai shape) — a card-only harness\n"
        "# would miss it. (Live z.ai is signed/unreachable; the shipped fixture is\n"
        "# synthetic — see docs/soak.md.)\n"
        "#\n"
        "# 1) targets.json (same schema as `assess` / `watch`):\n"
        "#   [{\"name\": \"vendor-under-test\",\n"
        "#     \"base_url\": \"https://api.vendor.example/v1\",\n"
        "#     \"model\": \"vendor-flagship-1\",\n"
        "#     \"auth_value_env\": \"VENDOR_API_KEY\",\n"
        "#     \"authorized\": true}]\n"
        "#\n"
        "# 2) run a 30-minute soak, fingerprint every 2 minutes, card every 30s:\n"
        "provenance-probe soak --config targets.json \\\n"
        "    --duration 30m --interval 2m --card-interval 30s \\\n"
        "    --out ./soak-reports --i-am-authorized\n"
        "#\n"
        "# CI gate: the same run exits 2 when a CONFIRMED or ADVISORY switch was\n"
        "# recorded. A gap, or a PRC jurisdiction shift alone, still exits 0.\n"
        "# provenance-probe soak ... --fail-on-switch\n"
        "#\n"
        "# A per-target timeline + a CONFIRMED/ADVISORY summary print at the end; a\n"
        "# stamped report lands in ./soak-reports/soak-<stamp>.json. Add --json to\n"
        "# also print the machine-readable report. Ctrl-C ends early and still\n"
        "# writes the report.\n"
    )
