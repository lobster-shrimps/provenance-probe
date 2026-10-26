"""Tests for the eval harness itself (not the corpus accuracy run).

The corpus run (eval/run_eval.py) is the accuracy/consistency gate and runs as
its own CI job. These tests prove the HARNESS is trustworthy: the matrix math,
the gate's fail conditions, the flagged-CN definition, and that the mock is
deterministic. Critically, a deliberately mislabeled case MUST make the gate
go red — a gate that can't fail is not a gate.
"""
import json
import os

import pytest

from eval import corpus, run_eval
from eval.run_eval import Result, confusion, gate


# --- flagged-CN definition --------------------------------------------------

def test_flagged_requires_adverse_verdict_and_cn_origin():
    cn = {"origin": "CN"}
    us = {"origin": "US"}
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "CONFIRMED"}}, cn) is True
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "LIKELY"}}, cn) is True
    # adverse tier but the driving match is NOT CN -> not a Chinese-origin flag
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "CONFIRMED"}}, us) is False
    # clean tiers are never flagged
    for v in ("INDETERMINATE", "UNLIKELY", "NO EVIDENCE"):
        assert corpus.is_flagged_cn({"provenance_risk": {"verdict": v}}, cn) is False


def test_flagged_behavioral_only_trusts_adverse_tier():
    # no tokenizer match (behavioral-only) + adverse tier -> flagged
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "CONFIRMED"}}, None) is True
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "UNLIKELY"}}, None) is False


# --- confusion matrix cell assignment ---------------------------------------

@pytest.mark.parametrize("expect,got,cell", [
    (True, True, "TP"),
    (True, False, "FN"),
    (False, True, "FP"),
    (False, False, "TN"),
])
def test_cell_assignment(expect, got, cell):
    r = Result("x", "bundle", expect, got, "CONFIRMED")
    assert r.cell == cell


def test_error_case_is_err_cell():
    r = Result("x", "vocab", True, False, None, False, error="boom")
    assert r.cell == "ERR"


def test_confusion_counts():
    rs = [Result("a", "b", True, True, "CONFIRMED"),
          Result("b", "b", False, False, "NO EVIDENCE"),
          Result("c", "b", False, True, "LIKELY")]      # a false positive
    assert confusion(rs) == {"TP": 1, "FP": 1, "TN": 1, "FN": 0, "ERR": 0}


# --- the gate can, and does, go red -----------------------------------------

def test_gate_passes_when_clean():
    rs = [Result("a", "b", True, True, "CONFIRMED"),
          Result("b", "b", False, False, "NO EVIDENCE")]
    assert gate(rs, confusion(rs), max_fn=0) == []


def test_gate_fails_on_false_positive():
    # a US model flagged CN — the exact regression the gate exists to catch
    rs = [Result("us-flagged", "b", False, True, "CONFIRMED")]
    reasons = gate(rs, confusion(rs), max_fn=0)
    assert reasons and any("FALSE POSITIVE" in r for r in reasons)


def test_gate_fails_on_false_negative_over_budget():
    rs = [Result("cn-missed", "b", True, False, "NO EVIDENCE")]
    assert gate(rs, confusion(rs), max_fn=0)          # 1 FN > budget 0
    assert gate(rs, confusion(rs), max_fn=1) == []    # within a ratcheted budget


def test_gate_fails_on_verdict_regression():
    rs = [Result("wrong-tier", "b", True, True, "LIKELY", verdict_ok=False)]
    reasons = gate(rs, confusion(rs), max_fn=0)
    assert any("verdict-tier regression" in r for r in reasons)


def test_gate_fails_on_harness_error():
    rs = [Result("broken", "vocab", True, False, None, False, error="missing vocab")]
    reasons = gate(rs, confusion(rs), max_fn=0)
    assert any("harness error" in r for r in reasons)


# --- bundle tier end-to-end (no heavy deps) ---------------------------------

def test_bundle_cases_all_pass_and_match_labels():
    results = run_eval.run_bundle_cases()
    assert len(results) == len(corpus.BUNDLE_CASES)
    for r in results:
        assert r.error is None, f"{r.name}: {r.error}"
        assert r.verdict_ok, f"{r.name} verdict {r.verdict} not in expected set"
        assert r.cell in ("TP", "TN")


def test_suppressed_usage_floors_to_indeterminate():
    # regression guard for the provenance floor (never a false clean bill)
    results = {r.name: r for r in run_eval.run_bundle_cases()}
    r = results["suppressed_usage_indeterminate.json"]
    assert r.verdict == "INDETERMINATE"
    assert r.got_flagged is False


def test_switch_tier_matches_hermetic_labels():
    from provenance_probe import redteam
    rows = run_eval.run_switch_cases()
    assert {r["id"] for r in rows} == {c["id"] for c in redteam.HERMETIC_SWITCH_CASES}
    for row in rows:
        assert row["ok"], f"{row['id']}: {row['detail']}"


# --- mock determinism + per-family regex ------------------------------------

@pytest.mark.skipif(
    not os.path.exists(os.path.join(run_eval.VOCAB_DIR, "qwen2.gguf")),
    reason="vendored vocabs not present")
def test_mock_is_deterministic():
    pytest.importorskip("gguf")
    pytest.importorskip("tokenizers")
    from eval import mock
    gguf = os.path.join(run_eval.VOCAB_DIR, "qwen2.gguf")
    app = mock.make_app(gguf, "blind-x", "qwen2")
    client = app.test_client()
    body = {"messages": [{"role": "user", "content": "The quick brown fox 你好世界"}],
            "max_tokens": 1}
    a = client.post("/v1/chat/completions", json=body).get_json()
    b = client.post("/v1/chat/completions", json=body).get_json()
    assert a["usage"]["prompt_tokens"] == b["usage"]["prompt_tokens"]
    assert a["model"] == "blind-x"          # brand is blind, not the family


def test_mock_rejects_unknown_regex_key():
    pytest.importorskip("gguf")
    from eval import mock
    with pytest.raises(ValueError):
        mock.load_tokenizer("/nonexistent.gguf", "no-such-family")


def test_mock_regexes_match_reference_builder():
    # the mock's per-family regexes MUST stay byte-identical to the reference
    # builder, or served counts drift from the vectors they are matched against
    pytest.importorskip("gguf")        # reference builder imports these at module load
    pytest.importorskip("tokenizers")
    from eval import mock
    from provenance_probe.tools import build_reference_from_gguf as b
    assert mock.RE_LLAMA3 == b.RE_LLAMA3
    assert mock.RE_GPT2 == b.RE_GPT2
    assert mock.RE_DEEPSEEK_LLM == b.RE_DEEPSEEK_LLM
    assert mock.RE_DEEPSEEK_CODER == b.RE_DEEPSEEK_CODER
    assert mock.RE_FALCON == b.RE_FALCON
    assert mock.RE_GLM4 == b.RE_GLM4
    assert mock.RE_MOONSHOT == b.RE_MOONSHOT
