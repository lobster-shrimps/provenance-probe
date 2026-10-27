"""Tier-2 observed-egress: lsof parse, loopback fan-out + routed-via-gateway,
platform refusal, and the authorization gate."""
import json

import pytest

from provenance_probe.cli import main
from provenance_probe.fleet import connections as C

_HEADER = "COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"


def _lsof(*rows: str) -> str:
    return _HEADER + "".join(r + "\n" for r in rows)


def _fanout_lsof(n_upstreams: int) -> str:
    rows = ["omniroute  4242 rob    5u  IPv4 0x1  0t0  TCP 127.0.0.1:20128 (LISTEN)"]
    for i in range(n_upstreams):
        rows.append(f"omniroute  4242 rob   {6+i}u  IPv4 0x1  0t0  "
                    f"TCP 10.0.0.5:{5001+i}->140.82.{i}.{i}:443 (ESTABLISHED)")
    # a client routing through the gateway
    rows.append("node       9999 rob    3u  IPv4 0x1  0t0  TCP 127.0.0.1:5555->127.0.0.1:20128 (ESTABLISHED)")
    return _lsof(*rows)


# --- parsing ----------------------------------------------------------------- #

@pytest.mark.unit
def test_parse_lsof_established_and_listen_and_ipv6():
    text = _lsof(
        "omniroute 4242 rob 5u IPv4 0x1 0t0 TCP 127.0.0.1:20128 (LISTEN)",
        "node 99 rob 3u IPv4 0x1 0t0 TCP 10.0.0.5:5555->140.82.1.2:443 (ESTABLISHED)",
        "svc 77 rob 8u IPv6 0x1 0t0 TCP [fe80::1]:1024->[fe80::2]:1025 (ESTABLISHED)",
    )
    conns = C.parse_lsof(text)
    assert len(conns) == 3
    listen = next(c for c in conns if c.state == "LISTEN")
    assert listen.laddr_host == "127.0.0.1" and listen.laddr_port == 20128
    assert listen.ppid == ""
    est = next(c for c in conns if c.command == "node")
    assert est.raddr_host == "140.82.1.2" and est.raddr_port == 443
    v6 = next(c for c in conns if c.command == "svc")
    assert v6.raddr_host == "fe80::2" and v6.raddr_port == 1025

@pytest.mark.unit
def test_parse_lsof_reads_ppid_when_the_next_token_is_digits():
    text = _lsof(
        "gunicorn 100 1 rob 5u IPv4 0x1 0t0 TCP *:4000 (LISTEN)",
        "omniroute 4242 rob 5u IPv4 0x1 0t0 TCP 127.0.0.1:20128 (LISTEN)",
    )
    by_pid = {c.pid: c for c in C.parse_lsof(text)}
    assert by_pid["100"].ppid == "1"
    assert by_pid["4242"].ppid == ""


# --- fan-out + routed-via-gateway -------------------------------------------- #

@pytest.mark.unit
def test_router_fanout_and_routed_via_gateway():
    res = C.analyze(C.parse_lsof(_fanout_lsof(8)), min_upstreams=8)
    fan = [f for f in res.findings if f.classification == C.ROUTER_FANOUT]
    via = [f for f in res.findings if f.classification == C.ROUTED_VIA_GATEWAY]
    assert len(fan) == 1 and fan[0].command == "omniroute" and fan[0].upstreams == 8
    assert fan[0].pid == "4242"
    assert fan[0].detail == "listener on [20128] fans out to 8 distinct upstream hosts"
    assert len(via) == 1 and via[0].command == "node"
    assert "8 router fan-out" not in res.headline  # sanity: headline counts findings
    assert "1 router fan-out" in res.headline and "1 routed-via-gateway" in res.headline

@pytest.mark.unit
def test_below_threshold_is_not_a_fanout():
    res = C.analyze(C.parse_lsof(_fanout_lsof(3)), min_upstreams=8)
    assert not [f for f in res.findings if f.classification == C.ROUTER_FANOUT]
    # the client routing through the gateway is still flagged
    assert [f for f in res.findings if f.classification == C.ROUTED_VIA_GATEWAY]

@pytest.mark.unit
def test_wildcard_bound_router_is_detected():
    # HIGH-1: lsof renders an all-interfaces bind as `*`, not 0.0.0.0. A LiteLLM
    # `--host 0.0.0.0` router must still be caught.
    rows = ["litellm 555 rob 5u IPv4 0x1 0t0 TCP *:4000 (LISTEN)"]
    for i in range(9):
        rows.append(f"litellm 555 rob {6+i}u IPv4 0x1 0t0 TCP 10.0.0.9:{7000+i}->203.0.{i}.{i}:443 (ESTABLISHED)")
    res = C.analyze(C.parse_lsof(_lsof(*rows)), min_upstreams=8)
    fan = [f for f in res.findings if f.classification == C.ROUTER_FANOUT]
    assert len(fan) == 1 and fan[0].command == "litellm" and fan[0].upstreams == 9

def _prefork_rows(per_worker: int) -> list[str]:
    """A listening master plus two workers that hold the upstream sockets."""
    rows = ["gunicorn 100 1 rob 5u IPv4 0x1 0t0 TCP *:4000 (LISTEN)"]
    for worker, base in ((201, 1), (202, 50)):
        for i in range(per_worker):
            rows.append(
                f"gunicorn {worker} 100 rob {6 + i}u IPv4 0x1 0t0 "
                f"TCP 10.0.0.5:{5000 + i}->140.82.{base + i}.{i}:443 (ESTABLISHED)")
    return rows

@pytest.mark.unit
def test_prefork_workers_count_toward_the_listener():
    res = C.analyze(C.parse_lsof(_lsof(*_prefork_rows(4))), min_upstreams=8)
    fan = [f for f in res.findings if f.classification == C.ROUTER_FANOUT]
    assert len(fan) == 1
    assert fan[0].command == "gunicorn" and fan[0].pid == "100" and fan[0].upstreams == 8
    assert fan[0].detail == (
        "listener on [4000] fans out to 8 distinct upstream hosts across 3 processes")
    assert fan[0].notes == [
        "router shape regardless of name; upstream IPs need an active "
        "probe to attribute (no-egress collector)"]
    assert "1 router fan-out" in res.headline
    assert not [f for f in res.findings if f.classification == C.ROUTED_VIA_GATEWAY]

@pytest.mark.unit
def test_prefork_below_threshold_is_not_a_fanout():
    res = C.analyze(C.parse_lsof(_lsof(*_prefork_rows(2))), min_upstreams=8)
    assert not [f for f in res.findings if f.classification == C.ROUTER_FANOUT]

@pytest.mark.unit
def test_same_command_different_parent_and_port_is_not_merged():
    rows = ["python 10 1 rob 5u IPv4 0x1 0t0 TCP 127.0.0.1:9000 (LISTEN)"]
    for i in range(8):
        rows.append(
            f"python 20 1 rob {6 + i}u IPv4 0x1 0t0 "
            f"TCP 10.0.0.8:{6000 + i}->1.2.3.{i}:443 (ESTABLISHED)")
    res = C.analyze(C.parse_lsof(_lsof(*rows)), min_upstreams=8)
    assert not [f for f in res.findings if f.classification == C.ROUTER_FANOUT]

@pytest.mark.unit
def test_same_command_on_another_port_stays_its_own_fanout():
    rows = [
        "python 10 1 rob 5u IPv4 0x1 0t0 TCP 127.0.0.1:9000 (LISTEN)",
        "python 20 1 rob 4u IPv4 0x1 0t0 TCP 127.0.0.1:9001 (LISTEN)",
    ]
    for i in range(8):
        rows.append(
            f"python 20 1 rob {6 + i}u IPv4 0x1 0t0 "
            f"TCP 10.0.0.8:{6000 + i}->1.2.3.{i}:443 (ESTABLISHED)")
    res = C.analyze(C.parse_lsof(_lsof(*rows)), min_upstreams=8)
    fan = [f for f in res.findings if f.classification == C.ROUTER_FANOUT]
    assert len(fan) == 1 and fan[0].pid == "20" and fan[0].upstreams == 8
    assert "across" not in fan[0].detail

@pytest.mark.unit
def test_shared_listen_port_aggregates_without_ppid():
    # Windows netstat has no parent pid; workers that also LISTEN on the port
    # still belong to the same fan-out. The named pid is the numeric minimum.
    rows = [
        "gunicorn 100 rob 5u IPv4 0x1 0t0 TCP *:4000 (LISTEN)",
        "gunicorn 99 rob 5u IPv4 0x1 0t0 TCP *:4000 (LISTEN)",
        "gunicorn 202 rob 5u IPv4 0x1 0t0 TCP *:4000 (LISTEN)",
    ]
    for pid, base in ((99, 1), (202, 50)):
        for i in range(4):
            rows.append(
                f"gunicorn {pid} rob {6 + i}u IPv4 0x1 0t0 "
                f"TCP 10.0.0.5:{7000 + i}->9.9.{base + i}.{i}:443 (ESTABLISHED)")
    res = C.analyze(C.parse_lsof(_lsof(*rows)), min_upstreams=8)
    fan = [f for f in res.findings if f.classification == C.ROUTER_FANOUT]
    assert len(fan) == 1
    assert fan[0].pid == "99" and fan[0].upstreams == 8
    assert "across 3 processes" in fan[0].detail

@pytest.mark.unit
def test_port_4000_finding_is_hedged():
    text = _lsof("app 12 rob 3u IPv4 0x1 0t0 TCP 127.0.0.1:5555->127.0.0.1:4000 (ESTABLISHED)")
    f = C.analyze(C.parse_lsof(text)).findings[0]
    assert f.classification == C.ROUTED_VIA_GATEWAY
    assert "commonly uses" in f.detail and "corroborate" in f.detail   # not an auto-accuse

@pytest.mark.unit
def test_unprivileged_result_is_qualified_not_unconditional_clean():
    from provenance_probe.fleet.render import egress_to_json, render_egress_console
    res = C.analyze([], privileged=False)          # 0 findings, but unprivileged
    assert "current user's sockets only" in res.headline
    assert egress_to_json(res)["caveat"] is not None
    assert "unprivileged" in render_egress_console(res)

@pytest.mark.unit
def test_default_connections_refuses_on_exit1_empty(monkeypatch):
    import platform
    import subprocess

    class _R:
        returncode = 1
        stdout = ""

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _R())
    with pytest.raises(C.EgressUnavailable):
        C.default_connections()

@pytest.mark.unit
def test_default_connections_asks_lsof_for_ppid(monkeypatch):
    import platform
    import subprocess

    class _R:
        returncode = 0
        stdout = "gunicorn 100 1 rob 5u IPv4 0x1 0t0 TCP *:4000 (LISTEN)\n"

    seen = {}

    def _run(argv, **_k):
        seen["argv"] = argv
        return _R()

    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(subprocess, "run", _run)
    conns = C.default_connections()
    assert seen["argv"][:3] == ["lsof", "-nP", "-R"]
    assert conns[0].ppid == "1" and conns[0].pid == "100"


# --- refuse, never false-clean ----------------------------------------------- #

@pytest.mark.unit
def test_default_connections_refuses_unsupported_platform(monkeypatch):
    import platform
    # Windows is supported now — use a genuinely-unsupported OS so this exercises the
    # real unsupported-OS refuse branch (not a Windows netstat shell-out).
    monkeypatch.setattr(platform, "system", lambda: "SunOS")
    with pytest.raises(C.EgressUnavailable):
        C.default_connections()

@pytest.mark.unit
def test_default_connections_refuses_on_lsof_error(monkeypatch):
    import platform
    import subprocess

    class _R:
        returncode = 2
        stdout = ""

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _R())
    with pytest.raises(C.EgressUnavailable):
        C.default_connections()


# --- no egress --------------------------------------------------------------- #

@pytest.mark.unit
def test_connections_module_makes_no_network_import():
    assert not hasattr(C, "requests")


# --- CLI --------------------------------------------------------------------- #

@pytest.mark.unit
def test_cli_egress_requires_authorization(capsys):
    assert main(["fleet-scan", "--egress"]) == 1
    assert "i-am-authorized" in capsys.readouterr().err

@pytest.mark.integration
def test_cli_egress_flags_fanout(monkeypatch, capsys):
    monkeypatch.setattr(C, "default_connections",
                        lambda: C.parse_lsof(_fanout_lsof(10)))
    rc = main(["fleet-scan", "--egress", "--i-am-authorized", "--json", "--exit-code"])
    assert rc == 2                                    # findings present -> exit 2
    out = json.loads(capsys.readouterr().out)
    classes = {f["classification"] for f in out["findings"]}
    assert C.ROUTER_FANOUT in classes and C.ROUTED_VIA_GATEWAY in classes

@pytest.mark.integration
def test_cli_egress_unavailable_returns_3_not_clean(monkeypatch, capsys):
    def _raise():
        raise C.EgressUnavailable("not implemented on Windows")
    monkeypatch.setattr(C, "default_connections", _raise)
    rc = main(["fleet-scan", "--egress", "--i-am-authorized", "--exit-code"])
    assert rc == 3
    assert "not certified clean" in capsys.readouterr().err
