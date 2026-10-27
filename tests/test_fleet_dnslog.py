"""Offline DNS / SNI / proxy-log join. No network."""
import json

import pytest

from provenance_probe.cli import main
from provenance_probe.fleet import evidence as E
from provenance_probe.fleet.dnslog import LogUnavailable, join_log


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
def test_zeek_prc_host_is_attributed_and_unknown_is_not():
    findings = join_log(ZEEK, allowlist=["api.openai.com"])
    by_host = {f.host: f for f in findings}
    prc = by_host["api.deepseek.com"]
    assert prc.classification == E.OFF_ALLOWLIST_ATTRIBUTED
    assert prc.attribution.origin == "PRC"
    assert prc.attribution.measured is False
    assert prc.evidence_tier == E.OBSERVED
    unknown = by_host["not-a-model.example"]
    assert unknown.classification == E.OFF_ALLOWLIST_UNATTRIBUTED
    assert unknown.attribution is None
    gw = by_host["ai-gateway.internal.example.com"]
    assert gw.classification == E.GATEWAY_UPSTREAM_UNRESOLVED


@pytest.mark.unit
def test_gateway_column_stays_unresolved_even_on_the_allowlist():
    findings = join_log(GATEWAY_ONLY, allowlist=["ai-gateway.internal.example.com"])
    assert len(findings) == 1
    assert findings[0].classification == E.GATEWAY_UPSTREAM_UNRESOLVED
    assert findings[0].host == "ai-gateway.internal.example.com"


@pytest.mark.unit
def test_csv_attributes_prc_and_leaves_aggregator_unresolved():
    findings = join_log(CSV, allowlist=[])
    by_host = {f.host: f for f in findings}
    assert by_host["api.deepseek.com"].classification == E.OFF_ALLOWLIST_ATTRIBUTED
    assert "sk-should-not-leak" not in json.dumps(
        [(f.base_url, f.notes, f.source) for f in findings])
    assert by_host["openrouter.ai"].classification == E.AGGREGATOR_UNRESOLVABLE
    assert "ai-gateway.internal.example.com" not in by_host


@pytest.mark.unit
def test_empty_and_header_only_logs_are_not_a_clean_bill():
    with pytest.raises(LogUnavailable):
        join_log("")
    with pytest.raises(LogUnavailable):
        join_log("sni,gateway\n")
    with pytest.raises(LogUnavailable):
        join_log("# just a comment\n")


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
    assert hosts["api.deepseek.com"] == "off-allowlist-attributed"
    assert hosts["not-a-model.example"] == "off-allowlist-unattributed"
    assert hosts["ai-gateway.internal.example.com"] == "gateway-upstream-unresolved"
