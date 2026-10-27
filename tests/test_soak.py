# -*- coding: utf-8 -*-
"""#124: the duration-bounded continuous model-switch `soak` test.

Locks the contracts the issue's Testing Plan + "Locked semantics" call out:

  * duration / interval parsing (30m / 2m / 45s / 1h / plain seconds);
  * a bounded loop that stops at the deadline (injected clock, no real sleep);
  * a clean SIGINT/stop still writes the report;
  * the z.ai shape: a mid-soak tokenizer-fingerprint change with a CONSTANT
    echoed model id is a CONFIRMED switch (a card-only harness would miss it);
  * a model-id-only / /models-only change with a stable fingerprint is ADVISORY,
    never CONFIRMED (WS1 "don't trust the confession");
  * timeline aggregation (distinct contiguous runs, first/last seen, revisits =
    new entry) + the summary shape (console + json);
  * secret-safety: an API key echoed back inside the model id AND inside the
    /models payload never reaches ANY sink (timeline / switches / report / log).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading

import pytest

from provenance_probe import soak, watch
from provenance_probe.config import Target


# --------------------------------------------------------------------------- #
# helpers: build minimal assess-style bundles that monitor.diff understands.
# #127: the CONFIRMED (critical) grade is driven by a tokenizer-SHAPE move, not
# the composite fingerprint_id string — so derive a distinct tokenizer shape from
# `fp` (distinct fp => distinct shape => critical; same fp => identical shape).
# echoed_model + catalog drive the ADVISORY (card) grade.
# --------------------------------------------------------------------------- #
def _vec_for(fp: str) -> dict:
    h = hashlib.sha256(fp.encode()).digest()
    return {p: 10 + h[i] % 16 for i, p in enumerate("abcdefg")}


def _bundle(fp: str, *, model: str = "gemini-pro", ids=None, err_sig: str = "E"):
    return {
        "fingerprint_id": fp,
        "tokenizer": {"usable": True, "vector": _vec_for(fp)},
        "errors": {"error_signature": err_sig},
        "headers": {"status": 200, "echoed_model": model},
        "catalog": {"ids": ids if ids is not None else ["gemini-pro", "gemini-flash"]},
        "score": {"jurisdictional_risk": {"verdict": "clean"},
                  "provenance_risk": {"verdict": "clean"}},
    }


def _full_poll(fp: str, *, model: str = "gemini-pro", ids=None, ts: str = "2026-01-01T00:00:00+00:00"):
    b = _bundle(fp, model=model, ids=ids)
    return soak.Poll(
        ok=True, ts=ts, model_id=model,
        models_hash=soak.models_hash(b["catalog"]["ids"]),
        fingerprint_id=fp, bundle=b)


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Redirect the private store so switches.jsonl lands under tmp_path."""
    monkeypatch.setenv("PROVENANCE_PROBE_HOME", str(tmp_path / "pp"))
    return tmp_path


# --------------------------------------------------------------------------- #
# duration / interval parsing
# --------------------------------------------------------------------------- #
def test_parse_duration_forms():
    assert soak.parse_duration("30m") == 1800
    assert soak.parse_duration("2m") == 120
    assert soak.parse_duration("45s") == 45
    assert soak.parse_duration("1h") == 3600
    assert soak.parse_duration("90") == 90          # bare integer = seconds


def test_parse_duration_rejects_garbage():
    for bad in ("", "0", "-5", "abc", "10x"):
        with pytest.raises(ValueError):
            soak.parse_duration(bad)


# --------------------------------------------------------------------------- #
# bounded loop: stops at the deadline; injected clock so no real minutes elapse
# --------------------------------------------------------------------------- #
class _FakeClock:
    """Virtual monotonic clock: `sleep` only advances the virtual time."""
    def __init__(self):
        self.t = 0.0

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float, stop_event) -> None:
        self.t += max(0.0, seconds)


def test_bounded_loop_stops_at_deadline(home):
    t = Target(name="svc", base_url="https://x.example/v1", authorized=True)
    calls = {"n": 0}

    def poll_full_fn(target):
        calls["n"] += 1
        return _full_poll("FP0", ts=f"2026-01-01T00:00:{calls['n']:02d}+00:00")

    rep = soak.run_soak(
        [t], soak.light_opts(), duration=5, interval=2, card_interval=2,
        out_dir=str(home / "reports"), clock=_FakeClock(),
        poll_full_fn=poll_full_fn, poll_card_fn=poll_full_fn, log=lambda *_: None)

    # ticks at t=0,2,4 then t>=5 -> stop. Exactly three polls.
    assert calls["n"] == 3
    assert rep["targets"][0]["cycles"] == 3
    assert os.path.exists(rep["report_path"])


def test_clean_stop_writes_report(home):
    t = Target(name="svc", base_url="https://x.example/v1", authorized=True)
    stop = threading.Event()

    def poll_full_fn(target):
        stop.set()                                  # simulate a SIGINT during the poll
        return _full_poll("FP0")

    rep = soak.run_soak(
        [t], soak.light_opts(), duration=3600, interval=60, card_interval=60,
        out_dir=str(home / "reports"), clock=_FakeClock(), stop_event=stop,
        poll_full_fn=poll_full_fn, poll_card_fn=poll_full_fn, log=lambda *_: None)

    # Stopped after the first in-flight poll, but the report was still written.
    assert os.path.exists(rep["report_path"])
    assert rep["targets"][0]["cycles"] == 1
    on_disk = json.load(open(rep["report_path"], encoding="utf-8"))
    assert on_disk["targets"][0]["name"] == "svc"


# --------------------------------------------------------------------------- #
# the z.ai shape: fingerprint switches mid-soak, echoed model id STAYS CONSTANT
# --------------------------------------------------------------------------- #
def test_zai_fingerprint_switch_with_constant_model_id_is_confirmed(home):
    st = soak.TargetSoak("zai")
    # t0 baseline: Gemini persona, Gemini-shape fingerprint.
    st.apply_full(_full_poll("GEMINI", model="gemini-pro", ts="t0"))
    # stable poll: same everything -> no switch.
    assert st.apply_full(_full_poll("GEMINI", model="gemini-pro", ts="t1")) == []
    # mid-soak: fingerprint MOVES to GLM-shape while the model id stays "gemini-pro".
    emitted = st.apply_full(_full_poll("GLM", model="gemini-pro", ts="t2"))

    grades = [e["grade"] for e in emitted]
    assert "CONFIRMED" in grades
    conf = next(e for e in emitted if e["grade"] == "CONFIRMED")
    assert conf["from"] == "GEMINI" and conf["to"] == "GLM"
    assert conf["signal"] == "fingerprint"
    assert conf["ts"] == "t2"
    # the echoed model id never changed -> a card-only harness would see nothing.
    assert "ADVISORY" not in grades
    rep = st.report()
    assert rep["confirmed_switches"] == 1
    assert rep["advisory_switches"] == 0


def test_model_id_only_change_is_advisory_never_confirmed():
    st = soak.TargetSoak("svc")
    st.apply_full(_full_poll("FP", model="claude-3", ts="t0"))
    # model id relabels, fingerprint UNCHANGED -> ADVISORY only.
    emitted = st.apply_full(_full_poll("FP", model="claude-3.5", ts="t1"))

    grades = [e["grade"] for e in emitted]
    assert grades == ["ADVISORY"]
    adv = emitted[0]
    assert adv["signal"] == "card"
    assert adv["from"]["model_id"] == "claude-3"
    assert adv["to"]["model_id"] == "claude-3.5"
    assert adv["ts"] == "t1"
    rep = st.report()
    assert rep["confirmed_switches"] == 0
    assert rep["advisory_switches"] == 1


def test_card_change_triggers_out_of_schedule_fingerprint_upgrade(home):
    """A card-only poll that changed AND whose triggered fingerprint poll is a
    diff-critical must upgrade to CONFIRMED (locked-semantics card/fp timing)."""
    t = Target(name="svc", base_url="https://x.example/v1", authorized=True)

    # scripted: t0 full seed (subsumes the card), then a card-only tick where the
    # card changed, whose triggered out-of-schedule fingerprint poll is critical.
    fulls = iter([
        _full_poll("FP0", model="m", ts="t0"),      # seed (full tick @ t0)
        _full_poll("FP1", model="m2", ts="t1b"),    # out-of-schedule (triggered) poll
    ])
    cards = iter([
        soak.Poll(ok=True, ts="t1", model_id="m2", models_hash="h1"),  # card changed @ t1
    ])

    clock = _FakeClock()
    rep = soak.run_soak(
        [t], soak.light_opts(), duration=2, interval=2, card_interval=1,
        out_dir=str(home / "reports"), clock=clock,
        poll_full_fn=lambda _t: next(fulls),
        poll_card_fn=lambda _t: next(cards), log=lambda *_: None)

    grades = [s["grade"] for s in rep["targets"][0]["transitions"]]
    assert "ADVISORY" in grades and "CONFIRMED" in grades


# --------------------------------------------------------------------------- #
# timeline aggregation + transitions + summary shape
# --------------------------------------------------------------------------- #
def test_timeline_aggregates_distinct_runs_and_revisits():
    st = soak.TargetSoak("svc")
    # fingerprint A -> A -> B -> A (model id CONSTANT so only the fingerprint moves):
    # three ordered runs (revisit = new entry), two CONFIRMED transitions.
    st.apply_full(_full_poll("A", model="m", ts="t0"))
    st.apply_full(_full_poll("A", model="m", ts="t1"))
    st.apply_full(_full_poll("B", model="m", ts="t2"))
    st.apply_full(_full_poll("A", model="m", ts="t3"))

    rep = st.report()
    tl = rep["timeline"]
    assert [r["fingerprint_id"] for r in tl] == ["A", "B", "A"]
    assert tl[0]["first_seen"] == "t0" and tl[0]["last_seen"] == "t1"
    assert tl[0]["observations"] == 2
    assert tl[1]["observations"] == 1
    # every state change produced a CONFIRMED transition (fingerprint moved).
    assert len(rep["transitions"]) == 2
    assert rep["confirmed_switches"] == 2


def test_summary_shape_console_and_json():
    st = soak.TargetSoak("svc")
    st.apply_full(_full_poll("A", model="A", ts="t0"))
    st.apply_full(_full_poll("B", model="B", ts="t1"))
    rep = {"started": "t0", "ended": "t1", "duration_s": 60, "interval_s": 30,
           "card_interval_s": 30, "targets": [st.report()]}
    text = soak.summarize(rep)
    assert "svc" in text
    assert "CONFIRMED" in text
    # json is round-trippable
    assert json.loads(json.dumps(rep))["targets"][0]["name"] == "svc"


# --------------------------------------------------------------------------- #
# failure / no-data poll: no switch, no prev-state update, recorded as a gap
# --------------------------------------------------------------------------- #
def test_no_data_poll_records_gap_and_does_not_emit_or_shift_state():
    st = soak.TargetSoak("svc")
    st.apply_full(_full_poll("A", model="A", ts="t0"))
    st.record_gap("t1", "unreachable")
    # a subsequent same-state poll must still read as no-change (state was frozen).
    emitted = st.apply_full(_full_poll("A", model="A", ts="t2"))
    assert emitted == []
    rep = st.report()
    assert rep["gaps"] == [{"ts": "t1", "reason": "unreachable"}]
    assert rep["confirmed_switches"] == 0


# --------------------------------------------------------------------------- #
# SECRET-SAFETY (the review's #1 concern): an echoed API key inside the model id
# AND inside the /models payload must never reach ANY sink.
# --------------------------------------------------------------------------- #
SECRET = "sk-live-DEADBEEFcafef00d1234567890"


def _sink_text(rep: dict, home) -> str:
    """Every place a secret could leak: the report JSON + switches.jsonl on disk."""
    blob = json.dumps(rep)
    for tgt in rep.get("targets", []):
        p = os.path.join(watch.target_dir(tgt["name"]), "switches.jsonl")
        if os.path.exists(p):
            blob += open(p, encoding="utf-8").read()
    return blob


def test_secret_in_model_id_and_models_payload_never_reaches_a_sink(home, monkeypatch):
    monkeypatch.setenv("VENDOR_KEY", SECRET)
    t = Target(name="leaky", base_url="https://x.example/v1",
               auth_value_env="VENDOR_KEY", authorized=True)
    logs: list[str] = []

    # Two full polls: t0 seed, t1 the fingerprint moves (forces a CONFIRMED +
    # writes switches.jsonl). BOTH echo the secret back inside the model id and
    # inside the /models list — exactly the untrusted-field leak we must scrub.
    evil_model = f"gpt-{SECRET}"
    evil_ids = [f"gpt-{SECRET}", "list-model-b"]
    seq = iter([
        soak.Poll(ok=True, ts="t0", model_id=soak._scrub(t, evil_model),
                  models_hash=soak.models_hash(evil_ids, redact=lambda s: soak._scrub(t, s)),
                  fingerprint_id="FP0", bundle=_bundle("FP0", model=evil_model, ids=evil_ids)),
        soak.Poll(ok=True, ts="t1", model_id=soak._scrub(t, evil_model),
                  models_hash=soak.models_hash(evil_ids, redact=lambda s: soak._scrub(t, s)),
                  fingerprint_id="FP1", bundle=_bundle("FP1", model=evil_model, ids=evil_ids)),
    ])

    clock = _FakeClock()
    rep = soak.run_soak(
        [t], soak.light_opts(), duration=3, interval=2, card_interval=2,
        out_dir=str(home / "reports"), clock=clock,
        poll_full_fn=lambda _t: next(seq), poll_card_fn=lambda _t: next(seq),
        log=lambda m: logs.append(str(m)))

    assert rep["targets"][0]["confirmed_switches"] == 1
    blob = _sink_text(rep, home) + "\n".join(logs)
    assert SECRET not in blob
    assert "[redacted]" in json.dumps(rep)          # the scrub actually fired


def test_default_poll_full_scrubs_echoed_model_and_models(home, monkeypatch):
    """The DEFAULT (real) poll path must scrub the untrusted echoed id + /models,
    never store the raw /models response."""
    monkeypatch.setenv("VENDOR_KEY", SECRET)
    t = Target(name="leaky", base_url="https://x.example/v1",
               auth_value_env="VENDOR_KEY", authorized=True)
    evil_model = f"gpt-{SECRET}"
    evil_ids = [f"gpt-{SECRET}", "b"]

    def fake_assess(target, opts, *, client=None, **kw):
        return _bundle("FP0", model=evil_model, ids=evil_ids)

    monkeypatch.setattr("provenance_probe.assess.assess_target", fake_assess)
    poll = soak.poll_full(t, soak.light_opts())
    assert poll.ok
    assert SECRET not in (poll.model_id or "")
    assert SECRET not in (poll.models_hash or "")
    # the raw /models id list is NOT carried on the poll's report-facing fields
    assert not hasattr(poll, "models") or SECRET not in json.dumps(getattr(poll, "models", []))


def test_poll_exception_is_recorded_as_gap_and_never_crashes(home):
    t = Target(name="svc", base_url="https://x.example/v1", authorized=True)

    def boom(target):
        raise RuntimeError("kaboom")

    rep = soak.run_soak(
        [t], soak.light_opts(), duration=1, interval=1, card_interval=1,
        out_dir=str(home / "reports"), clock=_FakeClock(),
        poll_full_fn=boom, poll_card_fn=boom, log=lambda *_: None)

    assert rep["targets"][0]["gaps"], "an exploding poll must be recorded as a gap"
    assert rep["targets"][0]["confirmed_switches"] == 0
    assert os.path.exists(rep["report_path"])


def test_models_hash_is_order_and_dupe_invariant():
    a = soak.models_hash(["m-b", "m-a", "m-a"])
    b = soak.models_hash(["m-a", "m-b"])
    assert a == b


# --------------------------------------------------------------------------- #
# #129: a jurisdiction flip TO PRC is its OWN soak event category
# (PRC-JURISDICTION-SHIFT) — SEPARATE from a CONFIRMED model switch.
# --------------------------------------------------------------------------- #
def _jur_full_poll(fp: str, verdict: str, *, model: str = "m", ts: str = "t"):
    b = _bundle(fp, model=model)
    b["score"]["jurisdictional_risk"]["verdict"] = verdict
    return soak.Poll(ok=True, ts=ts, model_id=model,
                     models_hash=soak.models_hash(b["catalog"]["ids"]),
                     fingerprint_id=fp, bundle=b)


def test_soak_surfaces_prc_jurisdiction_shift_category(home):
    st = soak.TargetSoak("jur")
    # tokenizer/fingerprint CONSTANT ("FP"); only the jurisdiction verdict crosses
    # INTO PRC -> a PRC-JURISDICTION-SHIFT, NOT a CONFIRMED model switch.
    st.apply_full(_jur_full_poll("FP", "INDETERMINATE", ts="t0"))
    emitted = st.apply_full(_jur_full_poll("FP", "CONFIRMED", ts="t1"))

    grades = [e["grade"] for e in emitted]
    assert "PRC-JURISDICTION-SHIFT" in grades
    assert "CONFIRMED" not in grades              # tokenizer unchanged -> not a switch
    js = next(e for e in emitted if e["grade"] == "PRC-JURISDICTION-SHIFT")
    assert js["ts"] == "t1"
    assert js["signal"] == "jurisdiction"

    rep = st.report()
    assert rep["prc_jurisdiction_shifts"] == 1
    assert rep["confirmed_switches"] == 0
    text = soak.summarize({"duration_s": 60, "interval_s": 30,
                           "card_interval_s": 30, "targets": [rep]})
    assert "PRC-JURISDICTION-SHIFT" in text


# --------------------------------------------------------------------------- #
# --fail-on-switch: CI gate. Default stays exit 0. CONFIRMED and ADVISORY
# trip exit 2. A PRC jurisdiction shift and a gap do not.
# --------------------------------------------------------------------------- #
def _switch_report(*, confirmed=0, advisory=0, prc=0, gaps=None, name="zai"):
    return {
        "report_path": "/tmp/soak-stamp.json",
        "duration_s": 60,
        "interval_s": 30,
        "card_interval_s": 30,
        "targets": [{
            "name": name,
            "cycles": 2,
            "confirmed_switches": confirmed,
            "advisory_switches": advisory,
            "prc_jurisdiction_shifts": prc,
            "transitions": [],
            "gaps": list(gaps or []),
        }],
    }


@pytest.mark.unit
def test_switch_gate_is_off_by_default():
    code, line = soak.switch_gate(_switch_report(confirmed=1, advisory=1),
                                  fail_on_switch=False)
    assert code == 0 and line is None


@pytest.mark.unit
@pytest.mark.parametrize("confirmed,advisory,prc,expected,verdict", [
    (1, 0, 0, 2, "FAIL"),
    (0, 1, 0, 2, "FAIL"),
    (1, 2, 1, 2, "FAIL"),
    (0, 0, 1, 0, "ok"),
    (0, 0, 0, 0, "ok"),
])
def test_switch_gate_counts_model_switches_only(confirmed, advisory, prc, expected, verdict):
    report = _switch_report(confirmed=confirmed, advisory=advisory, prc=prc,
                            gaps=[{"ts": "t", "reason": "unreachable"}])
    # a second target with no switches must still be summed, not ignored
    report["targets"].append(_switch_report(name="other")["targets"][0])
    code, line = soak.switch_gate(report, fail_on_switch=True)
    assert code == expected
    assert line == (f"SWITCH: confirmed={confirmed} advisory={advisory} "
                    f"(fail-on-switch -> {verdict})")


def _write_target(tmp_path):
    cfg = tmp_path / "targets.json"
    cfg.write_text(json.dumps({
        "name": "zai",
        "base_url": "https://example.invalid/v1",
        "model": "gemini-pro",
        "authorized": True,
    }))
    return cfg


def _cli_report(tmp_path, **counts):
    rep = _switch_report(**counts)
    rep["report_path"] = str(tmp_path / "soak-stamp.json")
    if counts.get("confirmed"):
        rep["targets"][0]["transitions"] = [{
            "grade": "CONFIRMED", "ts": "t1", "signal": "fingerprint",
            "from": "gemini-shape", "to": "glm-shape",
        }]
    elif counts.get("advisory"):
        rep["targets"][0]["transitions"] = [{
            "grade": "ADVISORY", "ts": "t1", "signal": "model-card",
            "from": {"model_id": "gemini-pro"}, "to": {"model_id": "glm"},
        }]
    return rep


@pytest.mark.unit
def test_cli_fail_on_switch_exits_2_and_still_prints(tmp_path, monkeypatch, capsys):
    from provenance_probe.cli import main
    rep = _cli_report(tmp_path, confirmed=1)
    monkeypatch.setattr(soak, "run_soak", lambda *a, **k: rep)
    rc = main(["soak", "--config", str(_write_target(tmp_path)),
               "--duration", "1s", "--out", str(tmp_path),
               "--i-am-authorized", "--fail-on-switch"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "CONFIRMED  fingerprint gemini-shape -> glm-shape" in out
    assert rep["report_path"] in out
    assert "SWITCH: confirmed=1 advisory=0 (fail-on-switch -> FAIL)" in out


@pytest.mark.unit
def test_cli_without_the_gate_exits_0_on_a_switch(tmp_path, monkeypatch, capsys):
    from provenance_probe.cli import main
    monkeypatch.setattr(soak, "run_soak",
                        lambda *a, **k: _cli_report(tmp_path, confirmed=1))
    rc = main(["soak", "--config", str(_write_target(tmp_path)),
               "--duration", "1s", "--out", str(tmp_path), "--i-am-authorized"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "fail-on-switch" not in out
    assert "CONFIRMED" in out


@pytest.mark.unit
def test_cli_gate_ignores_a_jurisdiction_shift_and_a_gap(tmp_path, monkeypatch, capsys):
    from provenance_probe.cli import main
    rep = _cli_report(tmp_path, prc=1, gaps=[{"ts": "t0", "reason": "401"}])
    rep["targets"][0]["transitions"] = [{
        "grade": "PRC-JURISDICTION-SHIFT", "ts": "t1", "signal": "jurisdiction",
        "changes": [{"detail": "jurisdiction crossed into PRC"}],
    }]
    monkeypatch.setattr(soak, "run_soak", lambda *a, **k: rep)
    rc = main(["soak", "--config", str(_write_target(tmp_path)),
               "--duration", "1s", "--out", str(tmp_path),
               "--i-am-authorized", "--fail-on-switch"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "SWITCH: confirmed=0 advisory=0 (fail-on-switch -> ok)" in out
    assert "PRC-JURISDICTION-SHIFT" in out


@pytest.mark.unit
def test_print_example_does_not_probe(monkeypatch, capsys):
    from provenance_probe.cli import main

    def _boom(*_a, **_k):
        raise AssertionError("print-example must not run a soak")

    monkeypatch.setattr(soak, "run_soak", _boom)
    rc = main(["soak", "--print-example", "--fail-on-switch"])
    assert rc == 0
    assert "--fail-on-switch" in capsys.readouterr().out
