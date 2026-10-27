"""The partner command and the serve page that shows the same log.

``fleet-scan --allowlist allow.txt --dns-log ssl.log --fail-on prc`` is
log-only. Corpus hits lead. Unattributed names are a count. A PRC-origin
hit exits 3. The live probe page reads the same log.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from provenance_probe.cli import main
from provenance_probe import serve

PARTNER = (
    "provenance-probe fleet-scan --allowlist allow.txt "
    "--dns-log ssl.log --fail-on prc"
)
DOCS = ("README.md", "docs/pilot/QUICKSTART.md", "docs/fleet-posture.md")


def _no_home_scan(*_a, **_k):
    raise AssertionError("log-only mode must not scan the operator home")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr("provenance_probe.fleet.run_scan", _no_home_scan)
    return serve.app.test_client()


@pytest.mark.unit
def test_partner_command_prints_corpus_hit_count_and_prc_fail(
        tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("provenance_probe.fleet.run_scan", _no_home_scan)
    log = tmp_path / "ssl.log"
    log.write_text(
        "server_name\napi.openai.com\napi.deepseek.com\n"
        "unknown-0.example\nunknown-1.example\n"
    )
    allow = tmp_path / "allow.txt"
    allow.write_text("api.openai.com\n")
    rc = main([
        "fleet-scan", "--allowlist", str(allow), "--dns-log", str(log),
        "--fail-on", "prc",
    ])
    out = capsys.readouterr().out
    assert rc == 3
    assert out.index("api.deepseek.com") < out.index("api.openai.com")
    assert "unknown-0.example" not in out
    assert "2 unattributed names" in out
    assert "imported-log" in out
    assert "EXPOSURE: prc=1 drift=1 (fail-on=prc -> FAIL)" in out


@pytest.mark.unit
def test_partner_json_is_one_document_and_prc_exits_3(
        tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("provenance_probe.fleet.run_scan", _no_home_scan)
    log = tmp_path / "ssl.log"
    log.write_text("server_name\napi.deepseek.com\nunknown.example\n")
    allow = tmp_path / "allow.txt"
    allow.write_text("api.openai.com\n")
    out_path = tmp_path / "report.json"
    rc = main([
        "fleet-scan", "--allowlist", str(allow), "--dns-log", str(log),
        "--fail-on", "prc", "--json", "--out", str(out_path),
    ])
    assert rc == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["host"] == "api.deepseek.com"
    assert payload["findings"][0]["evidence_tier"] == "imported-log"
    assert payload["unattributed_names"] == 1
    assert payload["exposure"]["prc"] == 1
    assert payload["exposure"]["drift"] == 1
    assert payload["exposure"]["exit_code"] == 3
    written = json.loads(out_path.read_text())
    assert written["exposure"]["matched"] is True


@pytest.mark.unit
def test_prc_exit_outranks_drift_exit_code(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("provenance_probe.fleet.run_scan", _no_home_scan)
    log = tmp_path / "ssl.log"
    log.write_text("server_name\napi.deepseek.com\n")
    allow = tmp_path / "allow.txt"
    allow.write_text("api.openai.com\n")
    rc = main([
        "fleet-scan", "--allowlist", str(allow), "--dns-log", str(log),
        "--fail-on", "prc", "--exit-code",
    ])
    assert rc == 3
    assert "fail-on=prc -> FAIL" in capsys.readouterr().out


@pytest.mark.unit
def test_gateway_column_does_not_fail_prc(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("provenance_probe.fleet.run_scan", _no_home_scan)
    log = tmp_path / "gw.log"
    log.write_text("gateway\nai-gateway.internal.example.com\n")
    allow = tmp_path / "allow.txt"
    allow.write_text("ai-gateway.internal.example.com\n")
    rc = main([
        "fleet-scan", "--allowlist", str(allow), "--dns-log", str(log),
        "--fail-on", "prc",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "gateway-upstream-unresolved" in out
    assert "EXPOSURE: prc=0 drift=0 (fail-on=prc -> ok)" in out


@pytest.mark.unit
def test_help_shows_the_partner_command(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["fleet-scan", "--help"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    assert PARTNER in out
    assert "imported-log" in out
    assert "Log only" in out
    assert "a count" in out
    assert "--dns-log" in out


@pytest.mark.unit
def test_end_user_docs_name_the_partner_command():
    root = Path(__file__).resolve().parents[1]
    for rel in DOCS:
        text = (root / rel).read_text(encoding="utf-8")
        assert PARTNER in text, rel
        assert "imported-log" in text, rel
        assert "Log-only" in text, rel
        assert "count" in text, rel
        assert "does not run in the same command" not in text, rel


@pytest.mark.unit
def test_serve_page_shows_the_imported_log_card(client):
    body = client.get("/").get_data(as_text=True)
    assert 'id=imported-log' in body
    assert PARTNER in body
    assert "imported-log" in body
    assert "Log-only mode" in body
    assert "Unattributed names" in body
    assert "/api/imported-log" in body
    assert "d.findings" in body


@pytest.mark.unit
def test_serve_log_is_corpus_first_with_prc_fail(client):
    res = client.post("/api/imported-log", json={
        "log": (
            "server_name\napi.openai.com\napi.deepseek.com\n"
            "unknown.example\nnot-a-model.example\n"
        ),
        "allowlist": "api.openai.com\n",
    })
    assert res.status_code == 200
    data = res.get_json()
    assert [f["host"] for f in data["findings"]] == [
        "api.deepseek.com", "api.openai.com",
    ]
    assert data["findings"][0]["evidence_tier"] == "imported-log"
    assert data["findings"][0]["origin"] == "PRC"
    assert "unknown.example" not in json.dumps(data["findings"])
    assert data["unattributed_names"] == 2
    assert "2 unattributed names" in data["headline"]
    assert data["exposure"]["prc"] == 1
    assert data["exposure"]["drift"] == 1
    assert data["exposure"]["matched"] is True
    assert data["exposure"]["exit_code"] == 3
    assert data["exposure_line"] == "EXPOSURE: prc=1 drift=1 (fail-on=prc -> FAIL)"


@pytest.mark.unit
def test_serve_empty_log_is_not_a_clean_bill(client):
    res = client.post("/api/imported-log", json={"log": "\n"})
    assert res.status_code == 400
    body = res.get_json()
    assert "not a clean bill" in body["error"]
    assert body["exit_code"] == 3


@pytest.mark.unit
def test_serve_gateway_column_does_not_fail_prc(client):
    res = client.post("/api/imported-log", json={
        "log": "gateway\nai-gateway.internal.example.com\n",
        "allowlist": "ai-gateway.internal.example.com\n",
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["findings"][0]["classification"] == "gateway-upstream-unresolved"
    assert data["unattributed_names"] == 0
    assert data["exposure"]["prc"] == 0
    assert data["exposure"]["drift"] == 0
    assert data["exposure"]["matched"] is False
    assert data["exposure_line"] == "EXPOSURE: prc=0 drift=0 (fail-on=prc -> ok)"


@pytest.mark.unit
def test_module_process_exits_3_on_prc(tmp_path):
    log = tmp_path / "ssl.log"
    log.write_text("server_name\napi.deepseek.com\nunknown.example\n")
    allow = tmp_path / "allow.txt"
    allow.write_text("api.openai.com\n")
    proc = subprocess.run(
        [sys.executable, "-m", "provenance_probe", "fleet-scan",
         "--allowlist", str(allow), "--dns-log", str(log), "--fail-on", "prc"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 3
    assert proc.stdout.index("api.deepseek.com") < proc.stdout.index("EXPOSURE:")
    assert "unknown.example" not in proc.stdout
    assert "1 unattributed names" in proc.stdout
    assert "imported-log" in proc.stdout
    assert "EXPOSURE: prc=1 drift=1 (fail-on=prc -> FAIL)" in proc.stdout
