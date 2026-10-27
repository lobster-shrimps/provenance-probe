"""Offline DNS / SNI / proxy-log join. No network."""
import json

import pytest

from provenance_probe.cli import main
from provenance_probe.fleet import evidence as E
from provenance_probe.fleet.dnslog import LogUnavailable, scan_log
from provenance_probe.fleet.render import render_console, to_json
from provenance_probe.fleet.rollup import exposure_summary, load_rollup


ZEEK = """\
#separator \\x09
#fields\tserver_name
api.deepseek.com
not-a-model.example
ai-gateway.internal.example.com
"""

CSV = """\
sni,gateway,note
api.deepseek.com,ai-gateway.internal.example.com,Bearer sk-should-not-leak
openrouter.ai,,
"""

GATEWAY_ONLY = """\
gateway
ai-gateway.internal.example.com
"""


@pytest.mark.unit
def test_zeek_prc_host_is_attributed_and_unknowns_are_a_count():
    result = scan_log(ZEEK, "api.openai.com\n")
    assert [f.host for f in result.findings] == ["api.deepseek.com"]
    prc = result.findings[0]
    assert prc.classification == E.OFF_ALLOWLIST_ATTRIBUTED
    assert prc.attribution.origin == "PRC"
    assert prc.attribution.measured is False
    assert prc.evidence_tier == E.IMPORTED_LOG
    assert prc.evidence_tier != E.OBSERVED
    assert result.unattributed_names == 2
    assert "2 unattributed names" in result.headline
    assert result.drifted == 1


@pytest.mark.unit
def test_gateway_column_stays_unresolved_even_on_the_allowlist():
    result = scan_log(GATEWAY_ONLY, "ai-gateway.internal.example.com\n")
    assert len(result.findings) == 1
    assert result.findings[0].classification == E.GATEWAY_UPSTREAM_UNRESOLVED
    assert result.findings[0].host == "ai-gateway.internal.example.com"
    assert result.findings[0].evidence_tier == E.IMPORTED_LOG
    assert result.unattributed_names == 0


@pytest.mark.unit
def test_csv_attributes_prc_and_leaves_aggregator_unresolved():
    result = scan_log(CSV, "")
    by_host = {f.host: f for f in result.findings}
    assert by_host["api.deepseek.com"].classification == E.OFF_ALLOWLIST_ATTRIBUTED
    assert "sk-should-not-leak" not in json.dumps(
        [(f.base_url, f.notes, f.source) for f in result.findings])
    assert by_host["openrouter.ai"].classification == E.AGGREGATOR_UNRESOLVABLE
    assert "ai-gateway.internal.example.com" not in by_host
    assert result.findings[0].host == "api.deepseek.com"


@pytest.mark.unit
def test_empty_and_header_only_logs_are_not_a_clean_bill():
    with pytest.raises(LogUnavailable):
        scan_log("")
    with pytest.raises(LogUnavailable):
        scan_log("sni,gateway\n")
    with pytest.raises(LogUnavailable):
        scan_log("# just a comment\n")


@pytest.mark.unit
def test_bare_host_column_is_not_a_destination_until_mapped():
    with pytest.raises(LogUnavailable):
        scan_log("host\napi.deepseek.com\n")
    result = scan_log("host\napi.deepseek.com\n", columns="dest=host")
    assert result.findings[0].host == "api.deepseek.com"
    assert result.findings[0].classification == E.OFF_ALLOWLIST_ATTRIBUTED


@pytest.mark.unit
def test_url_column_requires_the_map_and_keeps_client_and_time():
    body = "url,src_ip,when\nhttps://api.deepseek.com/v1,10.9.9.9,2026-10-27T01:00:00Z\n"
    with pytest.raises(LogUnavailable):
        scan_log(body)
    result = scan_log(body, columns="dest=url,client=src_ip,time=when")
    hit = result.findings[0]
    assert hit.host == "api.deepseek.com"
    assert hit.client == "10.9.9.9"
    assert hit.seen_at == "2026-10-27T01:00:00Z"
    rendered = to_json(result)
    assert rendered["findings"][0]["client"] == "10.9.9.9"
    assert rendered["findings"][0]["seen_at"] == "2026-10-27T01:00:00Z"
    assert "client 10.9.9.9" in render_console(result)
    assert "time 2026-10-27T01:00:00Z" in render_console(result)


@pytest.mark.unit
def test_default_client_and_time_and_ip_rows_are_a_count():
    body = "server_name,id.orig_h,ts\n8.8.8.8,10.1.2.3,1.0\napi.deepseek.com,10.1.2.4,2.0\n"
    result = scan_log(body)
    assert [f.host for f in result.findings] == ["api.deepseek.com"]
    assert result.findings[0].client == "10.1.2.4"
    assert result.findings[0].seen_at == "2.0"
    assert result.unattributed_names == 1


@pytest.mark.unit
def test_corpus_hits_lead_and_only_unknowns_are_a_report():
    mixed = "server_name\napi.openai.com\napi.deepseek.com\n"
    result = scan_log(mixed, "api.openai.com\n")
    assert [f.host for f in result.findings] == ["api.deepseek.com", "api.openai.com"]
    quiet = scan_log("server_name\nnot-a-model.example\nnot-a-model.example\n")
    assert quiet.findings == []
    assert quiet.unattributed_names == 1
    assert "1 unattributed names" in quiet.headline


@pytest.mark.unit
def test_rollup_fail_on_prc_sees_the_log_json(tmp_path):
    lines = ["server_name", "api.deepseek.com"]
    lines.extend(f"unknown-{i}.example" for i in range(20))
    result = scan_log("\n".join(lines) + "\n", "api.openai.com\n")
    assert result.unattributed_names == 20
    assert result.drifted == 1
    payload = to_json(result, machine="soc", scanned_at="2026-10-27T00:00:00Z")
    (tmp_path / "soc.json").write_text(json.dumps(payload))
    exp = exposure_summary(load_rollup(str(tmp_path)), "prc")
    assert exp["matched"] is True
    assert exp["exit_code"] == 3
    assert exp["prc"] == 1
    assert exp["drift"] == 1


@pytest.mark.unit
def test_cli_empty_log_exits_3(tmp_path, capsys):
    path = tmp_path / "empty.log"
    path.write_text("\n")
    rc = main(["fleet-scan", "--dns-log", str(path), "--allowlist", str(path)])
    err = capsys.readouterr().err
    assert rc == 3
    assert "not a clean bill" in err
    assert "allowlist holding" not in err


@pytest.mark.unit
def test_cli_missing_log_exits_3(tmp_path, capsys):
    rc = main(["fleet-scan", "--dns-log", str(tmp_path / "missing.log")])
    assert rc == 3
    assert "not a clean bill" in capsys.readouterr().err


@pytest.mark.unit
def test_cli_unrecognized_columns_exit_3(tmp_path, capsys):
    path = tmp_path / "hosts.csv"
    path.write_text("host\nworkstation.corp\n")
    rc = main(["fleet-scan", "--dns-log", str(path), "--allowlist", str(path)])
    assert rc == 3
    assert "not a clean bill" in capsys.readouterr().err


@pytest.mark.unit
def test_cli_zeek_log_json_has_no_network(tmp_path, capsys, monkeypatch):
    import socket
    log = tmp_path / "ssl.log"
    log.write_text(ZEEK)
    allow = tmp_path / "allow.txt"
    allow.write_text("api.openai.com\n")

    def boom(*_a, **_k):
        raise AssertionError("dns-log join must not open a socket")

    monkeypatch.setattr(socket, "socket", boom)
    rc = main(["fleet-scan", "--dns-log", str(log), "--allowlist", str(allow), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    hosts = {f["host"]: f["classification"] for f in payload["findings"]}
    assert hosts == {"api.deepseek.com": "off-allowlist-attributed"}
    assert payload["findings"][0]["evidence_tier"] == "imported-log"
    assert payload["unattributed_names"] == 2


@pytest.mark.unit
def test_cli_dns_log_does_not_scan_home(tmp_path, capsys, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("log-only mode must not scan the operator home")

    monkeypatch.setattr("provenance_probe.fleet.run_scan", boom)
    log = tmp_path / "ssl.log"
    log.write_text("server_name\napi.deepseek.com\n")
    allow = tmp_path / "allow.txt"
    allow.write_text("api.openai.com\n")
    rc = main(["fleet-scan", "--dns-log", str(log), "--allowlist", str(allow), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["host"] == "api.deepseek.com"
