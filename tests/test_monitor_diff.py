"""Tests for the shared monitor module (fingerprint + diff).

These lock the drift-detection contract the CLI, the web UI Monitor tab, and
the observatory runner all depend on.
"""
import pytest

from provenance_probe import monitor


def _bundle(vec, *, fp="fp-a", err="sig-1", jur="UNLIKELY", prov="NO EVIDENCE",
            header="h1", greedy="g1", streaming=("choices", "delta")):
    return {
        "fingerprint_id": fp,
        "tokenizer": {"vector": vec, "usable": True},
        "errors": {"error_signature": err},
        "headers": {"header_shape_hash": header},
        "greedy": {"signature": greedy},
        "streaming": {"chunk_fields": list(streaming)},
        "score": {"jurisdictional_risk": {"verdict": jur},
                  "provenance_risk": {"verdict": prov}},
    }


VEC = {"a": 10, "b": 12, "c": 15, "d": 11, "e": 13, "f": 14}


def _has_critical(out):
    return any(c["severity"] == "critical" for c in out["changes"])


def test_identical_runs_no_drift():
    b = _bundle(VEC)
    out = monitor.diff(b, dict(b))
    assert out["drift_detected"] is False
    assert out["changes"] == []


def test_composite_fingerprint_change_alone_is_not_critical():
    # #127: the composite fingerprint_id string moved but every real component
    # (tokenizer shape, error, header, greedy, streaming) is identical. This must
    # NOT be graded critical and must NOT set drift — the composite is only a pin.
    out = monitor.diff(_bundle(VEC, fp="fp-a"), _bundle(VEC, fp="fp-b"))
    assert _has_critical(out) is False
    assert out["drift_detected"] is False
    assert out["changes"] == []


# --- #127 grading matrix: only a tokenizer-shape move is a CONFIRMED switch ----

def test_ollama_error_signature_only_is_not_confirmed():
    # THE LIVE OLLAMA CASE: two probes of the same stable gemma4 — IDENTICAL
    # tokenizer shape, DIFFERING error_signature (wire noise). Must NOT be a
    # confirmed switch (was a false CONFIRMED before #127).
    out = monitor.diff(_bundle(VEC, err="sig-1"), _bundle(VEC, err="sig-2", fp="fp-b"))
    assert _has_critical(out) is False
    assert out["drift_detected"] is False
    err = [c for c in out["changes"] if c["field"] == "error_signature"]
    assert err and err[0]["severity"] != "critical"
    assert "not a confirmed model switch" in err[0]["detail"].lower()


def test_header_shape_only_is_advisory_no_drift():
    out = monitor.diff(_bundle(VEC, header="h1"), _bundle(VEC, header="h2", fp="fp-b"))
    assert _has_critical(out) is False
    assert out["drift_detected"] is False
    assert any(c["field"] == "header_shape" and c["severity"] != "critical"
               for c in out["changes"])


def test_streaming_only_is_advisory_no_drift():
    out = monitor.diff(_bundle(VEC, streaming=("choices", "delta")),
                       _bundle(VEC, streaming=("choices",), fp="fp-b"))
    assert _has_critical(out) is False
    assert out["drift_detected"] is False
    assert any(c["field"] == "streaming" and c["severity"] != "critical"
               for c in out["changes"])


def test_greedy_only_is_advisory_no_drift():
    out = monitor.diff(_bundle(VEC, greedy="g1"), _bundle(VEC, greedy="g2", fp="fp-b"))
    assert _has_critical(out) is False
    assert out["drift_detected"] is False
    gr = [c for c in out["changes"] if c["field"] == "greedy"]
    assert gr and gr[0]["severity"] != "critical"
    assert "same-tokenizer" in gr[0]["detail"].lower()


def test_real_tokenizer_move_is_confirmed_even_when_error_also_moves():
    # A genuine tokenizer-shape change -> critical + drift. Non-tokenizer
    # advisories are STILL listed alongside (combined case).
    shifted = dict(VEC); shifted["c"] = 99
    out = monitor.diff(_bundle(VEC, err="sig-1"), _bundle(shifted, err="sig-2", fp="fp-b"))
    assert out["drift_detected"] is True
    tok = [c for c in out["changes"] if c["field"] == "tokenizer_vector"]
    assert tok and tok[0]["severity"] == "critical"
    assert any(c["field"] == "error_signature" for c in out["changes"])  # listed too


def test_degraded_tokenizer_never_yields_critical():
    # tokenizer unusable in one run + a wire change -> advisory, degraded, NO drift.
    out = monitor.diff(_no_tok(err="s1"), _no_tok(err="s2", fp="fp-b"))
    assert _has_critical(out) is False
    assert out["drift_detected"] is False
    assert out["confidence"] == "degraded"


def test_tokenizer_shape_change_is_critical():
    shifted = dict(VEC); shifted["c"] = 99      # relative structure changed
    out = monitor.diff(_bundle(VEC), _bundle(shifted, fp="fp-a"))
    tok = [c for c in out["changes"] if c["field"] == "tokenizer_vector"]
    assert tok and tok[0]["severity"] == "critical"
    assert "different model family" in tok[0]["implication"].lower()


def test_constant_overhead_shift_is_not_drift():
    # every probe +7 (a chat-template/accounting change) must NOT read as a swap
    shifted = {k: v + 7 for k, v in VEC.items()}
    out = monitor.diff(_bundle(VEC), _bundle(shifted))   # same fp, err, verdicts
    assert out["drift_detected"] is False


def test_verdict_change_is_high():
    out = monitor.diff(_bundle(VEC, prov="NO EVIDENCE"),
                       _bundle(VEC, prov="CONFIRMED"))
    hi = [c for c in out["changes"] if c["field"] == "provenance_risk"]
    assert hi and hi[0]["severity"] == "high"
    assert "NO EVIDENCE -> CONFIRMED" in hi[0]["detail"]


def test_error_schema_change_is_high():
    out = monitor.diff(_bundle(VEC, err="sig-1"), _bundle(VEC, err="sig-2"))
    assert any(c["field"] == "error_signature" and c["severity"] == "high"
               for c in out["changes"])
    # #127: an error-schema move alone is a provider/wire change, not a switch.
    assert out["drift_detected"] is False


def test_fingerprint_stable_and_overhead_invariant():
    b1 = {"tokenizer": {"vector": VEC}, "errors": {"error_signature": "s"}}
    b2 = {"tokenizer": {"vector": {k: v + 100 for k, v in VEC.items()}},
          "errors": {"error_signature": "s"}}
    # deterministic, and a constant shift does not move the fingerprint
    assert monitor.fingerprint(b1) == monitor.fingerprint(b1)
    assert monitor.fingerprint(b1) == monitor.fingerprint(b2)
    # a real structural change does move it
    b3 = {"tokenizer": {"vector": {**VEC, "c": 99}}, "errors": {"error_signature": "s"}}
    assert monitor.fingerprint(b1) != monitor.fingerprint(b3)


# --- degraded confidence when usage/tokenizer is suppressed -----------------

def _no_tok(*, fp="fp-a", err="sig-1"):
    return {"fingerprint_id": fp, "tokenizer": {"usable": False},
            "errors": {"error_signature": err}, "score": {}}


def test_confidence_full_when_both_tokenizers_usable():
    out = monitor.diff(_bundle(VEC), _bundle(VEC))
    assert out["confidence"] == "full"
    assert "confidence_note" not in out


def test_confidence_degraded_when_usage_suppressed():
    out = monitor.diff(_no_tok(), _no_tok())
    assert out["confidence"] == "degraded"
    assert "usage suppressed" in out["confidence_note"]
    assert "not a clean bill" in out["confidence_note"]


def test_degraded_reports_wire_change_but_does_not_confirm_drift():
    # #127: tokenizer gone (not comparable) + error schema changed -> the change is
    # REPORTED as an advisory and confidence is degraded, but a switch cannot be
    # CONFIRMED from wire noise alone, so drift_detected stays False.
    out = monitor.diff(_no_tok(err="s1"), _no_tok(err="s2", fp="fp-b"))
    assert out["drift_detected"] is False
    assert out["confidence"] == "degraded"
    assert any(c["field"] == "error_signature" for c in out["changes"])


def test_degraded_if_only_one_side_suppressed():
    out = monitor.diff(_bundle(VEC), _no_tok(fp="fp-a"))
    assert out["confidence"] == "degraded"


# --- #129 jurisdiction-shift axis: a flip TO PRC — SEPARATE from the -----------
#     tokenizer/model-switch axis (do NOT reconflate; that was the #128 bug). ----

def _jur(out):
    return [c for c in out["changes"] if c["field"] == "prc_jurisdiction_shift"]


@pytest.mark.parametrize("base_v,cur_v", [
    ("INDETERMINATE", "CONFIRMED"),   # the edge the issue flags: SHOULD alert
    ("INDETERMINATE", "LIKELY"),
    ("UNLIKELY", "LIKELY"),
    ("NO EVIDENCE", "CONFIRMED"),
])
def test_crossing_into_prc_sets_shift(base_v, cur_v):
    # base NOT in {LIKELY, CONFIRMED} and cur IN {LIKELY, CONFIRMED} -> True, and a
    # DISTINCT labeled change; the tokenizer/model-switch grade is UNTOUCHED.
    out = monitor.diff(_bundle(VEC, jur=base_v), _bundle(VEC, jur=cur_v))
    assert out["prc_jurisdiction_shift"] is True
    j = _jur(out)
    assert j, "a distinct prc_jurisdiction_shift change entry must be present"
    assert "PRC" in j[0]["detail"].upper()
    assert "not a model-weights switch" in j[0]["detail"].lower()
    assert out["drift_detected"] is False          # jurisdiction axis != model-switch


@pytest.mark.parametrize("base_v,cur_v", [
    ("CONFIRMED", "CONFIRMED"),     # stable PRC
    ("LIKELY", "LIKELY"),           # stable PRC
    ("CONFIRMED", "UNLIKELY"),      # PRC -> non-PRC (cleared): NOT this alert
    ("LIKELY", "NO EVIDENCE"),      # PRC -> non-PRC
    ("UNLIKELY", "INDETERMINATE"),  # non-PRC -> non-PRC
    ("NO EVIDENCE", "UNLIKELY"),    # non-PRC -> non-PRC
])
def test_non_crossing_does_not_set_shift(base_v, cur_v):
    out = monitor.diff(_bundle(VEC, jur=base_v), _bundle(VEC, jur=cur_v))
    assert out["prc_jurisdiction_shift"] is False
    assert _jur(out) == []


def test_degraded_or_missing_verdict_never_sets_shift():
    # cur has no score -> can't assert a crossing.
    base = _bundle(VEC, jur="UNLIKELY")
    cur = _bundle(VEC, jur="CONFIRMED"); cur["score"] = {}
    assert monitor.diff(base, cur)["prc_jurisdiction_shift"] is False
    # base has no score -> can't assert a crossing.
    base2 = _bundle(VEC); base2["score"] = {}
    cur2 = _bundle(VEC, jur="CONFIRMED")
    assert monitor.diff(base2, cur2)["prc_jurisdiction_shift"] is False


def test_pure_model_switch_does_not_set_jurisdiction_shift():
    # tokenizer moves, jurisdiction UNCHANGED -> drift True, shift False (axes stay
    # separate; no #128-style reconflation).
    shifted = dict(VEC); shifted["c"] = 99
    out = monitor.diff(_bundle(VEC, jur="UNLIKELY"),
                       _bundle(shifted, jur="UNLIKELY", fp="fp-b"))
    assert out["drift_detected"] is True
    assert out["prc_jurisdiction_shift"] is False


def test_pure_jurisdiction_shift_does_not_set_drift():
    # jurisdiction crosses into PRC, tokenizer UNCHANGED -> shift True, drift False.
    out = monitor.diff(_bundle(VEC, jur="INDETERMINATE"), _bundle(VEC, jur="CONFIRMED"))
    assert out["prc_jurisdiction_shift"] is True
    assert out["drift_detected"] is False


def test_both_axes_at_once_are_set_independently():
    shifted = dict(VEC); shifted["c"] = 99
    out = monitor.diff(_bundle(VEC, jur="UNLIKELY"),
                       _bundle(shifted, jur="CONFIRMED", fp="fp-b"))
    assert out["drift_detected"] is True
    assert out["prc_jurisdiction_shift"] is True


def test_identical_runs_have_shift_false():
    out = monitor.diff(_bundle(VEC), dict(_bundle(VEC)))
    assert out["prc_jurisdiction_shift"] is False


# Signed/stateful replay cannot be pretended. A fresh tokenizer battery or wire
# fingerprint can still carry the verdict. Self-ID never confirms a switch.
_GLM = {"a": 10, "b": 40, "c": 15, "d": 70, "e": 13, "f": 3}


def test_unreplayable_tokenizer_confirms_and_names_the_signal():
    out = monitor.grade_unreplayable(
        _bundle(VEC), _bundle(_GLM), reason="signed", self_id_changed=True)
    assert out["replay"] == "impossible" and out["replay_carried"] is False
    assert out["signal"] == "tokenizer"
    assert out["confirmed_switch"] is True and out["switch_detected"] is True
    assert out["self_id_confirmed"] is False
    assert "Replay was impossible" in out["note"]
    assert "tokenizer battery carried this verdict" in out["note"]
    assert "did not confirm it" in out["note"]


def test_unreplayable_wire_flags_without_confirming():
    out = monitor.grade_unreplayable(
        _bundle(VEC, err="sig-1"), _bundle(VEC, err="sig-2"), reason="stateful")
    assert out["signal"] == "wire"
    assert out["switch_detected"] is True and out["confirmed_switch"] is False
    assert out["self_id_confirmed"] is False
    assert "wire fingerprint carried this verdict" in out["note"]
    assert "does not confirm" in out["note"]


def test_unreplayable_self_id_alone_does_not_confirm():
    out = monitor.grade_unreplayable(
        _bundle(VEC), _bundle(VEC), reason="signed", self_id_changed=True)
    assert out["signal"] == "none"
    assert out["switch_detected"] is False and out["confirmed_switch"] is False
    assert out["self_id_confirmed"] is False
    assert "does not confirm a switch" in out["note"]


def test_unreplayable_without_a_live_signal_is_not_a_clean_bill():
    out = monitor.grade_unreplayable(None, None, reason="signed-or-stateful")
    assert out["signal"] == "none" and out["switch_detected"] is False
    assert "not a clean bill" in out["note"]
    assert "Replay was impossible" in out["note"]


def test_unreplayable_one_sided_tokenizer_does_not_become_a_wire_switch():
    bare = _bundle(VEC)
    bare["tokenizer"] = {"usable": False, "vector": {}}
    out = monitor.grade_unreplayable(_bundle(VEC), bare, reason="signed")
    assert out["signal"] == "none"
    assert out["confirmed_switch"] is False and out["switch_detected"] is False
