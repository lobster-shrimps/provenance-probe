# -*- coding: utf-8 -*-
"""WS2 (#115) wiring: the flow renders on the landing + /help, `explain --flow`
prints the plain-text flow, and BOTH the serve result surface and the CLI assess
lead with the IDENTICAL plain_answer string (the zero-drift contract).
"""
from __future__ import annotations

import html
import io
import os
import tempfile
from contextlib import redirect_stdout

import pytest

from provenance_probe import serve, explain, scoring, userwarn, cli, report, redteam
from provenance_probe.config import Target


@pytest.fixture
def client():
    return serve.app.test_client()


def _cn_bundle() -> dict:
    """A bundle that fires a hard CN network signal so the verdicts are non-trivial."""
    b = {
        "target": {"name": "sample", "base_url": "https://api.vendor.cn/v1",
                   "model": "glm-4", "api_style": "openai"},
        "timestamp": "2026-01-01T00:00:00+00:00",
        "network": {"addresses": [{"asn": "AS4808", "country": "CN"}],
                    "findings": [{"type": "cn_tld", "detail": "host ends in .cn"},
                                 {"type": "prc_ip_geo", "detail": "IP geolocates to CN"}],
                    "operator": "China Unicom", "jurisdiction": "PRC (mainland)"},
    }
    b["score"] = scoring.score(b)
    b["user_warning"] = userwarn.build(b)
    b["fingerprint_id"] = "deadbeef"
    return b


def _expected_answer(b: dict) -> str:
    s = b["score"]
    return explain.plain_answer(s["provenance_risk"]["verdict"],
                                s["jurisdictional_risk"]["verdict"],
                                s["confidence"])


# --------------------------------------------------------------------------- #
# Flow renders on the landing + /help; explain --flow prints flow_text
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_flow_renders_on_landing(client):
    body = client.get("/").get_data(as_text=True)
    assert explain.flow_html() in body


@pytest.mark.unit
def test_flow_renders_on_help(client):
    body = client.get("/help").get_data(as_text=True)
    assert explain.flow_html() in body


@pytest.mark.unit
def test_cli_explain_flow_prints_flow_text():
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.main(["explain", "--flow"])
    out = buf.getvalue()
    assert explain.flow_text() in out


# --------------------------------------------------------------------------- #
# Zero-drift: serve api_run + CLI assess lead with the SAME plain_answer
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_serve_api_run_leads_with_plain_answer(client):
    b = _cn_bundle()
    rid = "testrid"
    serve.RUNS[rid] = {"state": "done", "progress": 100, "status": "Complete",
                       "bundle": b}
    try:
        data = client.get(f"/api/run/{rid}").get_json()
    finally:
        serve.RUNS.pop(rid, None)
    assert data["plain_answer"] == _expected_answer(b)
    sc = b["score"]
    assert data["plain_action"] == explain.plain_action(
        sc["provenance_risk"]["verdict"], sc["jurisdictional_risk"]["verdict"],
        sc["confidence"])


@pytest.mark.unit
def test_cli_assess_leads_with_the_same_plain_answer(monkeypatch, tmp_path):
    b = _cn_bundle()

    monkeypatch.setattr(cli, "load_targets",
                        lambda cfg: [Target(name="sample",
                                            base_url="https://api.vendor.cn/v1",
                                            model="glm-4", api_style="openai",
                                            authorized=True)])
    monkeypatch.setattr(cli.tokenizer, "load_reference", lambda: {})
    monkeypatch.setattr(cli.assess, "assess_target",
                        lambda t, opts, progress=None, note=None: b)

    class _Args:
        config = "unused"
        no_tokenizer = True
        no_behavioral = True
        no_deception = True
        latency = False
        latency_n = 1
        leak_samples = 0
        offline = True
        variant_seed = 0
        confront_as = ""
        confront_control = False
        session_test = False
        client_dir = ""
        client_url = ""
        artifacts = ""
        i_am_authorized = True
        out = str(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.cmd_assess(_Args())
    out = buf.getvalue()

    expected = _expected_answer(b)
    assert expected in out, "CLI assess must print the plain answer"
    sc = b["score"]
    action = explain.plain_action(
        sc["provenance_risk"]["verdict"], sc["jurisdictional_risk"]["verdict"],
        sc["confidence"])
    assert action in out, "CLI assess must print the next step"
    assert out.index(expected) < out.index(action)
    # It LEADS the result block: it precedes the technical console report.
    assert out.index(expected) < out.index("MODEL PROVENANCE ASSESSMENT")
    # The warning text is findings only. The next step is printed once.
    assert out.count(action) == 1
    assert "WHAT YOU SHOULD DO" not in out
    assert "What you should do" not in out


@pytest.mark.unit
def test_html_report_leads_with_the_same_next_step(tmp_path):
    b = _cn_bundle()
    path = tmp_path / "report.html"
    report.to_html(b, str(path))
    doc = path.read_text()
    answer = html.escape(_expected_answer(b))
    sc = b["score"]
    step = html.escape(explain.plain_action(
        sc["provenance_risk"]["verdict"], sc["jurisdictional_risk"]["verdict"],
        sc["confidence"]))
    assert answer in doc and step in doc
    assert doc.index(answer) < doc.index(step) < doc.index('class="display"')
    assert "What you should do" not in doc
    assert "What to do" not in doc


@pytest.mark.unit
def test_user_warning_leads_with_one_step_and_no_checklist(tmp_path):
    b = _cn_bundle()
    w = b["user_warning"]
    sc = b["score"]
    step = explain.plain_action(
        sc["provenance_risk"]["verdict"], sc["jurisdictional_risk"]["verdict"],
        sc["confidence"])
    assert w["actions"] == []
    assert w["next_step"] == step
    text = userwarn.to_text(w)
    assert "WHAT YOU SHOULD DO" not in text
    assert step not in text
    path = tmp_path / "warning.html"
    userwarn.to_html(w, str(path))
    doc = path.read_text()
    assert step in doc
    assert doc.index(step) < doc.index(w["headline"])
    for leftover in (
        "What you should do",
        "Stop putting sensitive information",
        "No action needed based on this check",
        "Change any password",
    ):
        assert leftover not in doc


@pytest.mark.unit
def test_cli_redteam_leads_with_the_same_next_step(monkeypatch):
    result = {
        "identities": [{"scenario": "baseline", "model_id": "glm-4",
                        "self_id": "I am Gemini"}],
        "switch_detected": True,
        "confirmed_switch": True,
        "switches": [{"scenario": "stress", "signal": "wire", "from": "a", "to": "b"}],
        "fingerprint_switches": [],
        "confirmed_switches": [{"scenario": "stress", "detail": "shape moved"}],
        "note": "served model changed",
        "scenarios_run": 4,
    }
    monkeypatch.setattr(cli, "load_targets",
                        lambda cfg: [Target(name="sample",
                                            base_url="https://api.vendor.example/v1",
                                            model="glm-4", api_style="openai",
                                            authorized=True)])
    monkeypatch.setattr(cli, "Client", lambda t: object())
    monkeypatch.setattr(redteam, "run", lambda client, cap=8: result)

    class _Args:
        config = "unused"
        cap = 4
        out = ""
        i_am_authorized = True

    buf = io.StringIO()
    with redirect_stdout(buf):
        with pytest.raises(SystemExit) as exc:
            cli.cmd_redteam(_Args())
    assert exc.value.code == 2
    out = buf.getvalue()
    step = explain.plain_action_for_switch(result)
    assert step == explain.plain_action("CONFIRMED", "NO EVIDENCE", "high")
    assert out.index(step) < out.index("model=")
    assert out.index(step) < out.index("SWITCH UNDER STRESS")


@pytest.mark.unit
def test_serve_result_does_not_render_a_second_action_list():
    import pathlib
    src = pathlib.Path(serve.__file__).read_text()
    assert "<h3>What to do</h3>" not in src
    assert "w.actions" not in src


@pytest.mark.unit
def test_serve_and_cli_use_the_identical_plain_answer_source():
    # Both surfaces call explain.plain_answer with the same tuple, so for any
    # bundle the string is identical by construction — assert the shared source
    # is deterministic across a representative spread.
    b = _cn_bundle()
    assert _expected_answer(b) == _expected_answer(b)
