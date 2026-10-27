"""MCP server url and command hosts. No network."""
import json

import pytest

from provenance_probe.fleet import run_scan
from provenance_probe.fleet import evidence as E
from provenance_probe.fleet.render import render_console, to_json
from provenance_probe.fleet.rollup import load_rollup, render_console as render_rollup
from provenance_probe.fleet.rollup import to_csv


SECRET = "sk-header-secret"
ARG_SECRET = "sk-arg-secret"


def _reader(mapping):
    return lambda path: mapping.get(path)


def _blobs(result):
    payload = to_json(result, machine="lap", scanned_at="2026-10-27T00:00:00Z")
    return json.dumps(payload), render_console(result), payload


@pytest.mark.unit
def test_mcp_url_is_attributed_and_secrets_stay_out_of_reports(tmp_path):
    body = json.dumps({"mcpServers": {"remote": {
        "url": "https://user:sk-userinfo@api.deepseek.com/mcp?token=sk-query",
        "headers": {"Authorization": f"Bearer {SECRET}"},
    }}})
    result = run_scan("", environ={}, read_text=_reader({"~/.cursor/mcp.json": body}))
    assert [f.host for f in result.findings] == ["api.deepseek.com"]
    hit = result.findings[0]
    assert hit.classification == E.OFF_ALLOWLIST_ATTRIBUTED
    assert hit.attribution.origin == "PRC"
    assert hit.evidence_tier == E.CONFIGURED
    js, console, payload = _blobs(result)
    report = tmp_path / "lap.json"
    report.write_text(js)
    roll = load_rollup(str(tmp_path))
    csv_text = to_csv(roll)
    rollup_console = render_rollup(roll)
    for leak in (SECRET, "sk-userinfo", "sk-query", "Bearer"):
        assert leak not in js
        assert leak not in console
        assert leak not in csv_text
        assert leak not in rollup_console
    assert payload["findings"][0]["base_url"] == "https://api.deepseek.com/mcp"


@pytest.mark.unit
def test_local_npx_server_is_quiet():
    body = json.dumps({"mcpServers": {"local": {
        "command": "npx",
        "args": ["-y", "some-mcp-server"],
    }}})
    result = run_scan("", environ={}, read_text=_reader({"~/.cursor/mcp.json": body}))
    assert result.findings == []


@pytest.mark.unit
def test_command_host_is_kept_and_header_arg_is_not():
    body = json.dumps({"mcpServers": {"cmd": {
        "command": "npx",
        "args": ["-y", "mcp-remote", "https://api.deepseek.com/mcp",
                 "--header", f"Authorization: Bearer {ARG_SECRET}"],
    }}})
    result = run_scan("", environ={}, read_text=_reader({"~/.cursor/mcp.json": body}))
    assert [f.host for f in result.findings] == ["api.deepseek.com"]
    blob = json.dumps(to_json(result)) + render_console(result)
    assert ARG_SECRET not in blob
    assert "Bearer" not in blob


@pytest.mark.unit
def test_base_url_and_url_for_the_same_host_count_once():
    body = json.dumps({"mcpServers": {"both": {
        "base_url": "https://api.deepseek.com/v1",
        "url": "https://api.deepseek.com/mcp",
        "headers": {"Authorization": f"Bearer {SECRET}"},
    }}})
    result = run_scan("", environ={}, read_text=_reader({"~/.cursor/mcp.json": body}))
    assert [f.host for f in result.findings] == ["api.deepseek.com"]
    assert SECRET not in json.dumps(to_json(result))


@pytest.mark.unit
def test_dotted_argv_token_is_not_a_host():
    body = json.dumps({"mcpServers": {"pkg": {
        "command": "npx",
        "args": ["-y", "some.package"],
    }}})
    result = run_scan("", environ={}, read_text=_reader({"~/.cursor/mcp.json": body}))
    assert result.findings == []


@pytest.mark.unit
def test_loopback_mcp_url_is_quiet():
    for url in ("http://127.0.0.1:8765/mcp", "127.0.0.1", "http://localhost:8765/mcp"):
        body = json.dumps({"mcpServers": {"local": {"url": url}}})
        result = run_scan("", environ={}, read_text=_reader({"~/.cursor/mcp.json": body}))
        assert result.findings == []
