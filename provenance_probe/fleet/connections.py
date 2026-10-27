"""Tier-2 observed-egress signal (B-phase): the loopback fan-out shape.

The config scan sees a `base_url=localhost:20128`; this sees the matching NETWORK
shape from the OS connection table: a local process that fans out from a loopback
port to many distinct upstreams is a router regardless of what it's named, and a
process connected to a known local-gateway port (OmniRoute/LiteLLM) is a client
using one. That is the `observed` evidence tier — stronger than `configured`.

Deliberate no-egress scope (see docs/fleet-posture.md): this reads the connection
table (`lsof -nP -R`, no DNS) and never makes a network call. Two Tier-2 signals are
therefore OUT of scope here and stay deferred:
  * IP→operator attribution — a snapshot yields upstream IPs, and resolving an IP
    to a PRC operator needs reverse-DNS/RDAP (egress) — that is the prober's
    authorized `assess`/`network` path, not this no-egress collector.
  * JA3/TLS ClientHello fingerprint — needs raw packet capture (pcap/root).

Like the trust-store watch, this reads a privacy surface (per-process connections),
so it is inert until `--i-am-authorized`, and it REFUSES (never reports clean) when
the connection table cannot be read.
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field

from ..gateways import KNOWN_LOCAL_GATEWAYS

# Loopback remote addresses (lsof -n emits IPs, not "localhost").
_LOOPBACK = {"127.0.0.1", "::1"}
# A router's LISTEN side may be loopback OR a wildcard bind; lsof -nP renders an
# all-interfaces bind as `*` (or `::`), NOT `0.0.0.0` — the standard LiteLLM
# `--host 0.0.0.0` deployment shows as `*:4000`. Missing this hid the router shape.
_LISTEN_ROUTER_HOSTS = _LOOPBACK | {"*", "0.0.0.0", "::"}  # noqa: S104 (recognition, not a bind)
# Loopback ports of known local gateways (a connection whose remote is one of
# these is a client routing through that gateway).
_GATEWAY_PORTS = {port for _h, port in KNOWN_LOCAL_GATEWAYS.values()}

# Default: how many distinct non-loopback upstreams from one loopback listener
# reads as a router fan-out rather than incidental.
DEFAULT_MIN_UPSTREAMS = 8

# cmd + pid at the start; an optional PPID (`lsof -R`) when the next token is
# digits; the `addr-pair (STATE)` at the end of an lsof -nP line.
_CONN = re.compile(
    r"^(?P<cmd>\S+)\s+(?P<pid>\d+)(?:\s+(?P<ppid>\d+))?"
    r"\b.*\s(?P<name>\S+->\S+|\S+)\s+\((?P<state>[A-Z]+)\)\s*$")

# Classifications
ROUTER_FANOUT = "router-fanout"          # a loopback listener fanning out to many upstreams
ROUTED_VIA_GATEWAY = "routed-via-gateway"  # a client connected to a known local-gateway port


class EgressUnavailable(Exception):
    """The connection table could not be read (unsupported OS / reader failed).
    Raised instead of returning [] so an unreadable host is never reported clean."""


@dataclass(frozen=True)
class Conn:
    command: str
    pid: str
    laddr_host: str
    laddr_port: int | None
    raddr_host: str          # "" for a LISTEN line
    raddr_port: int | None
    state: str
    ppid: str = ""


@dataclass(frozen=True)
class EgressFinding:
    classification: str
    command: str
    pid: str
    detail: str
    upstreams: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EgressResult:
    findings: list[EgressFinding]
    connections: int
    privileged: bool = True   # False = only the current user's sockets were visible

    @property
    def headline(self) -> str:
        fan = sum(1 for f in self.findings if f.classification == ROUTER_FANOUT)
        via = sum(1 for f in self.findings if f.classification == ROUTED_VIA_GATEWAY)
        scope = "" if self.privileged else " (current user's sockets only)"
        return (f"observed egress: {self.connections} connections{scope}, "
                f"{fan} router fan-out, {via} routed-via-gateway")


def is_privileged() -> bool:
    """True if the process can see all sockets. On POSIX that means root (an
    unprivileged `lsof` sees only the current user's connections, so a zero-finding
    result must be qualified). On Windows, `netstat -ano` returns the whole-system
    TCP table regardless of elevation, so visibility is full."""
    import os
    import platform
    if platform.system() == "Windows":
        return True
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _split_addr(a: str) -> tuple[str, int | None]:
    """`host:port` / `[v6]:port` / `*:port` -> (host, port|None)."""
    a = a.strip()
    if "]" in a:                                   # [v6]:port
        host, _, port = a.rpartition("]:")
        host = host.lstrip("[")
    else:
        host, _, port = a.rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        return (host or a), None


def parse_lsof(text: str) -> list[Conn]:
    """Parse `lsof -nP -iTCP` output into Conn records (ESTABLISHED + LISTEN)."""
    conns: list[Conn] = []
    for line in (text or "").splitlines():
        m = _CONN.match(line)
        if not m:
            continue
        name, state = m.group("name"), m.group("state")
        if "->" in name:
            local, remote = name.split("->", 1)
            lh, lp = _split_addr(local)
            rh, rp = _split_addr(remote)
        else:
            lh, lp = _split_addr(name)
            rh, rp = "", None
        conns.append(Conn(m.group("cmd"), m.group("pid"), lh, lp, rh, rp, state,
                          m.group("ppid") or ""))
    return conns


def parse_tasklist(text: str) -> dict[str, str]:
    """Parse `tasklist /fo csv /nh` (`"image","pid","session","#","mem"`) into a
    pid->image map, so a netstat PID can be named. Robust to CSV quoting/commas;
    malformed rows are skipped, never raised."""
    names: dict[str, str] = {}
    for row in csv.reader((text or "").splitlines()):
        if len(row) < 2:
            continue
        image, pid = row[0].strip(), row[1].strip()
        if image and pid.isdigit():
            names[pid] = image
    return names


def parse_netstat(text: str, names: dict[str, str] | None = None) -> list[Conn]:
    """Parse Windows `netstat -ano` output into Conn records (TCP rows only, both
    IPv4 and IPv6; UDP rows are filtered out by the `TCP`-proto check).

    Columns: `Proto  Local Address  Foreign Address  State  PID`. Windows renders
    `LISTENING` (mapped -> "LISTEN" for `analyze`) and keeps `ESTABLISHED`; a
    LISTENING row's foreign address is a placeholder (`0.0.0.0:0` / `[::]:0`) so its
    remote is emptied, mirroring how `parse_lsof` treats a LISTEN line. `command`
    comes from the injected pid->name map, falling back to the PID itself so a
    finding still identifies the process. No DNS — the input is already numeric."""
    conns: list[Conn] = []
    for line in (text or "").splitlines():
        parts = line.split()
        # Proto Local Foreign State PID — anything else (headers, banner, UDP) skips.
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        _proto, local, foreign, raw_state, pid = parts[0], parts[1], parts[2], parts[3], parts[4]
        if not pid.isdigit():
            continue
        state = "LISTEN" if raw_state.upper() == "LISTENING" else raw_state.upper()
        lh, lp = _split_addr(local)
        if state == "LISTEN":
            rh, rp = "", None
        else:
            rh, rp = _split_addr(foreign)
        command = (names or {}).get(pid, pid)
        conns.append(Conn(command, pid, lh, lp, rh, rp, state))
    return conns


def _find(parent: dict, key: tuple[str, str]) -> tuple[str, str]:
    parent.setdefault(key, key)
    while parent[key] != key:
        parent[key] = parent[parent[key]]
        key = parent[key]
    return key


def _union(parent: dict, a: tuple[str, str], b: tuple[str, str]) -> None:
    ra, rb = _find(parent, a), _find(parent, b)
    if ra != rb:
        parent[rb] = ra


def _router_groups(conns: list[Conn]) -> list[dict]:
    """One group per pre-fork router.

    A listening master and its workers are the same fan-out. Workers join the
    listener when they share its listen port, or when `lsof -R` says their
    parent pid is that listener. A different program, or the same command with
    a different parent and a different port, stays separate.
    """
    listens: dict[tuple[str, str], set[int]] = {}
    upstreams: dict[tuple[str, str], set[str]] = {}
    ppid_of: dict[tuple[str, str], str] = {}
    for c in conns:
        key = (c.command, c.pid)
        if c.ppid:
            ppid_of[key] = c.ppid
        if c.state == "LISTEN" and c.laddr_host in _LISTEN_ROUTER_HOSTS and c.laddr_port:
            listens.setdefault(key, set()).add(c.laddr_port)
        if c.state == "ESTABLISHED" and c.raddr_host and c.raddr_host not in _LOOPBACK:
            upstreams.setdefault(key, set()).add(c.raddr_host)

    parent: dict[tuple[str, str], tuple[str, str]] = {}
    by_port: dict[tuple[str, int], list[tuple[str, str]]] = {}
    for key, ports in listens.items():
        cmd, _pid = key
        for port in ports:
            by_port.setdefault((cmd, port), []).append(key)
    for keys in by_port.values():
        for other in keys[1:]:
            _union(parent, keys[0], other)
    for key, ppid in ppid_of.items():
        cmd, _pid = key
        parent_key = (cmd, ppid)
        if parent_key in listens:
            _union(parent, key, parent_key)

    groups: dict[tuple[str, str], dict] = {}
    for key, ports in listens.items():
        root = _find(parent, key)
        group = groups.setdefault(root, {
            "cmd": key[0], "ports": set(), "pids": set(), "hosts": set()})
        group["ports"] |= ports
        group["pids"].add(key[1])
        group["hosts"] |= upstreams.get(key, set())
    for key, hosts in upstreams.items():
        if key not in parent:
            continue
        root = _find(parent, key)
        group = groups.get(root)
        if group is None:
            continue
        group["pids"].add(key[1])
        group["hosts"] |= hosts
    return list(groups.values())


def _listener_pid(group: dict, ppid_of: dict[tuple[str, str], str]) -> str:
    """The pid to name on the finding: the listener that is not a child of the group."""
    cmd = group["cmd"]
    pids = group["pids"]
    roots = [pid for pid in pids if ppid_of.get((cmd, pid), "") not in pids]
    return min(roots or pids, key=int)


def analyze(conns: list[Conn], *, min_upstreams: int = DEFAULT_MIN_UPSTREAMS,
            privileged: bool = True) -> EgressResult:
    """Derive the loopback/wildcard fan-out + routed-via-gateway findings."""
    findings: list[EgressFinding] = []

    # 1. Router fan-out. Pre-fork workers count toward the listener.
    ppid_of = {(c.command, c.pid): c.ppid for c in conns if c.ppid}
    for group in _router_groups(conns):
        n = len(group["hosts"])
        if n < min_upstreams:
            continue
        pid = _listener_pid(group, ppid_of)
        ports = sorted(group["ports"])
        detail = f"listener on {ports} fans out to {n} distinct upstream hosts"
        if len(group["pids"]) > 1:
            detail += f" across {len(group['pids'])} processes"
        findings.append(EgressFinding(
            ROUTER_FANOUT, group["cmd"], pid, detail, upstreams=n,
            notes=["router shape regardless of name; upstream IPs need an active "
                   "probe to attribute (no-egress collector)"]))

    # 2. Routed-via-gateway: any process connected to a known local-gateway port.
    #    Port 20128 is safely-unusual (OmniRoute); 4000 is a common dev port, so
    #    hedge that call rather than auto-accuse (never over-claim).
    seen: set[tuple[str, str, int]] = set()
    for c in conns:
        if (c.state == "ESTABLISHED" and c.raddr_host in _LOOPBACK
                and c.raddr_port in _GATEWAY_PORTS):
            k = (c.command, c.pid, c.raddr_port)
            if k in seen:
                continue
            seen.add(k)
            if c.raddr_port == 4000:
                detail = ("connected to local port 4000 — a port LiteLLM commonly uses, "
                          "but also a generic dev port; corroborate with the config scan "
                          "before treating as a gateway")
            else:
                detail = (f"connected to local gateway port {c.raddr_port} "
                          f"({c.raddr_host}) — routing AI traffic through a local gateway")
            findings.append(EgressFinding(ROUTED_VIA_GATEWAY, c.command, c.pid, detail))

    return EgressResult(findings=findings, connections=len(conns), privileged=privileged)


def default_connections() -> list[Conn]:
    """Read the host's TCP connection table (local-only, no DNS → no egress).
    Raises EgressUnavailable on an unsupported OS or a reader failure."""
    import platform
    import subprocess

    system = platform.system()
    if system == "Windows":
        return _windows_connections(subprocess)
    if system not in ("Darwin", "Linux"):
        raise EgressUnavailable(
            f"observed-egress scan is not implemented on {system}")
    try:
        out = subprocess.run(
            ["lsof", "-nP", "-R", "-iTCP", "-sTCP:ESTABLISHED,LISTEN"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        raise EgressUnavailable(f"could not run `lsof` to read the connection table: {e}")
    if out.returncode not in (0, 1):
        raise EgressUnavailable(f"`lsof` returned an error (exit {out.returncode})")
    # lsof exits 1 both for "found nothing" AND on errors. A real host always has
    # listeners, so exit 1 with EMPTY output is far more likely a blocked/errored
    # read than a genuinely empty table — refuse rather than report clean.
    if out.returncode == 1 and not out.stdout.strip():
        raise EgressUnavailable("`lsof` exited 1 with no output — likely a read error, "
                                "not an empty connection table")
    return parse_lsof(out.stdout)


def _windows_connections(subprocess) -> list[Conn]:  # noqa: ANN001 (module handle)
    """Read the Windows TCP table via `netstat -ano` (already numeric → no DNS).
    `tasklist` names the PIDs and is best-effort; a netstat failure REFUSES
    (EgressUnavailable) rather than reporting a false-clean empty table."""
    try:
        # NB: no `-p TCP` — on Windows that filters to IPv4 TCP only, hiding IPv6 TCP
        # (a false-clean vs the lsof path). Bare `-ano` lists both families as "TCP"
        # (IPv6 rows carry `[..]` addresses); UDP rows are dropped by parse_netstat's
        # `TCP`-proto filter.
        net = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        raise EgressUnavailable(f"could not run `netstat` to read the connection table: {e}")
    if net.returncode != 0:
        raise EgressUnavailable(f"`netstat` returned an error (exit {net.returncode})")
    # tasklist enriches PIDs with process names; if it fails we still report by PID.
    names: dict[str, str] | None = None
    try:
        tl = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=30)
        if tl.returncode == 0:
            names = parse_tasklist(tl.stdout)
    except (OSError, subprocess.SubprocessError):
        names = None
    return parse_netstat(net.stdout, names)
