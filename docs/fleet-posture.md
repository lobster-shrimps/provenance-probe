# Fleet posture: prevention first, `fleet-scan` as the proof

`fleet-scan` detects where local agent CLIs are pointed and flags anything off
your sanctioned list. But **detection is the failure-mode measure, not the
control.** The control is a posture you set; the scan proves the posture is
holding and shows, in one number, where it isn't yet.

Framed that way, this is not "we surveilled your developers and found rogue
tools." It is "here is the sanctioned AI posture; the scan reports
`allowlist holding: N sanctioned, M drifted`, and M is the work left." That is a
much easier thing for a security team to adopt, because it makes them the owner
of a posture, not the subject of a dragnet.

## The posture (two pieces)

1. **An egress allowlist.** The AI inference hosts your org sanctions. Everything
   else is drift by definition. Start from the shipped template and fork it:

   ```sh
   provenance-probe fleet-scan --print allowlist-template > allow.txt
   # edit allow.txt to match your policy, then:
   provenance-probe fleet-scan --allowlist allow.txt
   ```

   Matching is exact-or-subdomain on the hostname — a subdomain of a listed host
   is allowed; a suffix attack (`api.openai.com.evil.test`) is not.

2. **One sanctioned gateway (optional but ideal).** If you route AI traffic
   through a single approved gateway, add just that gateway's host to the
   allowlist. Now the allowlist is tiny and every other endpoint is drift you can
   see.

   **Know the gateway blind spot, though.** `fleet-scan` resolves a gateway to its
   real upstream only when the gateway is on **loopback** (`localhost`/`127.0.0.1`/`::1`)
   AND its config file is on disk at a known path and parseable (OmniRoute,
   LiteLLM). In that case a sanctioned localhost gateway pointed at a PRC backend is
   still caught. But:
   - A **non-loopback** gateway (e.g. `ai-gateway.internal.example.com`) is matched
     against the allowlist directly and its upstream is **not** resolved — if you
     sanction it, a PRC backend behind it is invisible to fleet-scan. Prefer a
     localhost gateway, or actively probe the gateway endpoint itself (the remote
     `assess` path), or don't sanction the gateway host wholesale.
   - A localhost gateway whose config can't be read is surfaced honestly as
     `gateway-upstream-unresolved` (needs an active probe), never as clean.

## Offline DNS / SNI / proxy log

Config files and a one-moment socket table miss traffic the network already
logged. Log-only mode: `fleet-scan --dns-log` reads a Zeek `#fields` log or
a CSV and classifies destinations with the corpus and the allowlist. It does
not scan the machine it runs on, and it does not open a socket.

Default destination columns are `query`, `server_name`, `sni`, `ssl.sni`,
`http.host`, and `http.hostname`. A bare `host` column is not a destination
(it is often the workstation). `url` and `domain` need an explicit map:

```sh
provenance-probe fleet-scan --allowlist allow.txt --dns-log ssl.log
provenance-probe fleet-scan --allowlist allow.txt --dns-log proxy.csv \
  --dns-columns dest=url,client=src_ip,time=ts
```

Corpus-attributed hosts come first, on the `imported-log` tier. Names the
corpus does not know, including a destination whose label is `ai-gateway`,
are a count on the headline, not one drifted finding each. IP-only rows are
part of that count. `id.orig_h` / `src_ip` / `client` and `ts` / `timestamp` /
`time` are kept when the export has them.

A `gateway`, `proxy`, or `via` column with no destination stays
`gateway-upstream-unresolved`. Putting that name on the allowlist does not
turn the row into a sanctioned upstream: the log never named one. An empty
or unreadable file, or a file with no recognized destination column, exits 3.

One command prints that report and gates it. Corpus hits come first, the
headline carries the unattributed count, and the last line is the exposure
gate. Exit 3 when a PRC-origin host is present:

```sh
provenance-probe fleet-scan --allowlist allow.txt --dns-log ssl.log --fail-on prc
```

`provenance-probe serve` shows the same result on the live probe page
(corpus hits first, the unattributed count, and `fail-on=prc -> FAIL`).
`--json --out report.json` is still a rollup input if you want the
multi-machine report: `fleet-scan --rollup report.json --fail-on prc`.

`.cursor/mcp.json` is one of the config files the home scan already opens. A
remote MCP server is often a `url`, or an `https://` host in `command` /
`args`, rather than a `base_url` key. Those hosts are recorded too. Header
values are not. The same host is not counted twice when both fields name it.
A dotted package argument is not a host. A loopback URL (`127.0.0.1`,
`localhost`) is quiet, the same way a local `npx` server is.

## The KPI: allowlist-holding, not a rogue list

The report headline is the posture's health, not an accusation:

```
allowlist holding: 38/40 sanctioned, 2 drifted (1 unresolved)
```

- **sanctioned** — on your allowlist. The posture is holding here.
- **drifted** — off the allowlist. Each drift is attributed where the bundled
  corpus can (`off-allowlist-attributed`, e.g. a PRC operator, as a SUB-CONFIRMED
  pointer), left honest where it can't (`off-allowlist-unattributed`), bucketed as
  `aggregator-unresolvable` for neutral aggregators, or
  `gateway-upstream-unresolved` when a local gateway's upstream needs an active
  probe.

Drive M → 0 by either sanctioning an endpoint (add it to the allowlist) or
removing it (fix the config). The number, not the developer, is the target.

## Rollout

- **One host, now:** `fleet-scan --allowlist allow.txt` (add `--json` / `--out` for
  a machine-readable report; `--exit-code` to fail a CI/scheduled run on any drift).
- **Fleet-wide:** schedule the scan and collect the SQLite table through osquery —
  see [fleet-osquery.md](fleet-osquery.md).

## Trust-store watch (the transparent-MITM case)

The base_url scan catches a gateway you *intentionally* point an agent CLI at. It
does not catch a **transparent** interceptor — a proxy that installs a root CA and
terminates TLS without any base_url change. That case has one unavoidable tell: a
MITM-capable proxy **must install a root CA**, and no fork removes that requirement.

`fleet-scan --trust-store` enumerates the host's admin/user-added trusted roots,
fingerprints each (SHA-256 of the DER), and flags any not in your baseline —
escalating CAs whose label matches a known interception tool (mitmproxy, Charles,
Burp, …).

```sh
# 1. On a GOLDEN (known-clean) machine, capture the trusted-root baseline:
provenance-probe fleet-scan --print ca-baseline --i-am-authorized > ca-baseline.txt

# 2. On fleet hosts, diff against it:
provenance-probe fleet-scan --trust-store --ca-baseline ca-baseline.txt --i-am-authorized
```

Two things to understand before you enable it:

- **"Non-enterprise root" is not machine-computable.** Zscaler, Netskope, corp-MDM
  and developer roots are legitimate and vary per org, so there is no built-in
  "bad root" list — you supply the baseline. Without `--ca-baseline`, every root
  reads as `unbaselined` (the report says so).
- **It reads the system trust store — a privacy/labor-review surface**, so it is
  inert until you pass `--i-am-authorized` (attesting documented policy). And the
  **installing process** of a rogue CA is not captured here (the macOS keychain
  records no PID); attributing *who* installed it needs an EDR/osquery event hook.

macOS, Linux, and Windows. On Windows the reader uses PowerShell to list the
LocalMachine and CurrentUser root stores. On an unsupported OS (or if the reader
can't run),
`fleet-scan --trust-store` **refuses with a non-zero exit (3, "host not certified
clean")** rather than reporting a green result — a host whose store was never read
is never counted as clean.

## Observed egress: the loopback fan-out shape (Tier-2)

The base_url scan reads *configured* intent; `fleet-scan --egress` reads the
*observed* network shape from the connection table. It flags two structural signals
that hold regardless of what a router is named:

- **Router fan-out** — a process listening on a loopback port that fans out to many
  distinct upstream hosts is a router (OmniRoute-class), even if renamed.
- **Routed-via-gateway** — a process connected to a known local-gateway port
  (`localhost:20128`, LiteLLM `:4000`) is a client using one.

```sh
provenance-probe fleet-scan --egress --i-am-authorized   # --min-upstreams N to tune
```

Bare `--egress` is deliberately narrow, for the no-egress invariant:

- It reads the connection table with `lsof -nP -R` (no DNS) and **makes no network
  call**. A snapshot yields upstream **IPs**, not entities — turning an IP into an
  operator needs reverse-DNS/RDAP, which is a network call and therefore an *opt-in*
  step (see below), never something the bare collector does.
- It reads per-process connections (a privacy surface), so it is **inert without
  `--i-am-authorized`**, and it **refuses (exit 3), never reports clean**, when the
  connection table can't be read (unsupported OS / `lsof` unavailable).
- Point-in-time: a short-lived agent call may not be in-flight during the snapshot;
  schedule it, or pair it with the config scan (which sees the persistent `base_url`).
- **Privilege matters.** Unprivileged, `lsof` sees only the current user's sockets —
  a router running as root or another user is invisible. A zero-finding result is
  **qualified as "current user's sockets only"** (in the headline, report, and JSON)
  when the scan isn't root, so it never reads as an unqualified clean. Run it as root
  (or via the scheduled-scan unit) for a host-wide view.
- Pre-fork routers count as one fan-out. A listening master and the workers that
  share its listen port, or whose parent pid is that listener, contribute one
  combined upstream count. The finding names the listener. A different program, or
  the same command with a different parent and a different port, stays separate.

### Tier-2 attribution (opt-in, EGRESS/capture — separate from the no-egress collector)

Two attribution signals go one step past "a connection exists". Each is a **separate
opt-in flag** so the bare `--egress` keeps its structural no-egress guarantee — the
same boundary as `catalog` (offline) vs `build-catalog` (explicit egress):

```sh
# IP → operator/jurisdiction pointer: RDAP + reverse-DNS the observed upstream IPs.
# MAKES network calls (unlike bare --egress); reuses the hardened assess/network
# RDAP path (SSRF denylist, PRC-ASN heuristic) and joins the PTR to corpus.py.
provenance-probe fleet-scan --egress --rdap --i-am-authorized

# JA3 client-TLS fingerprint: passively capture ClientHellos (tcpdump) and compute
# JA3 — spot a known interception proxy, or an unexpected second client fingerprint
# to a sanctioned upstream (corroborates the trust-store watch).
provenance-probe fleet-scan --ja3 --i-am-authorized      # --ja3-seconds N to tune
```

Both stay honest and safe:

- **Still a pointer, never a verdict.** RDAP tells you who an IP is *registered* to;
  JA3 tells you what a TLS stack *looks* like. Neither is a measured provenance
  verdict (`measured:false`) — treat a flag as a lead to probe.
- **Bounded + transparent.** `--rdap` caps how many distinct IPs it will look up and
  reports any it dropped (no silent truncation); an unknown JA3 is **not**
  auto-suspicious — `KNOWN_JA3` is operator-populated from golden captures (like the
  CA baseline), so it ships empty rather than shipping guessed fingerprints.
- **Refuse, never false-clean.** `--ja3` needs root + `tcpdump`; if it can't capture
  (unsupported OS / no `tcpdump` / not root) it **refuses (exit 3)**, exactly like the
  connection-table and trust-store collectors — an unrunnable check never reads clean.

## What this is not

- Not a package/registry — the allowlist is your policy, forked from a starter.
- Not surveillance of people — findings are host/config facts, redacted for SIEM
  rollup (home paths collapse to `~/`, `base_url` credentials stripped).
- Not a provenance verdict — attribution is a static corpus pointer, never a
  measured tokenizer-fingerprint verdict. Treat an attributed drift as a lead to
  probe, not a conviction.
