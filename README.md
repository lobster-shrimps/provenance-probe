<div align="center">

# 🕵️ provenance-probe

### A lie detector for AI APIs — find out *which model is actually serving you*, and whether it's **Chinese-origin** or running under **PRC jurisdiction**.

Vendors can silently swap models, reroute your requests, or resell a Chinese model under a Western name. `provenance-probe` catches it with black-box measurements — **no vendor cooperation, no API key for the demo, runs 100% on your machine.**

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![version](https://img.shields.io/badge/version-0.33.0-informational)
![tests](https://img.shields.io/badge/tests-729%20passing-brightgreen)
![tokenizer families](https://img.shields.io/badge/reference%20families-27-blueviolet)
![local](https://img.shields.io/badge/runs-100%25%20local-success)

![provenance-probe unmasking a Chinese model hiding behind a US name](docs/media/unmask-cn-model.gif)

*Above: a vendor's `northstar-secure-1` is fingerprinted as **Qwen2 (Chinese-origin), 20/20 exact match** — with no API key.*

</div>

---

## 🤔 The problem

When you pay for an AI model through an API, you're trusting the vendor to actually run what they advertise. They might quietly swap in a cheaper model, route your requests to someone else's servers, or resell a Chinese-made model under a Western-sounding name — and normally **you have no way to tell.**

That matters for two very different reasons, and this tool keeps them apart on purpose:

| Risk | The question | Why it bites |
|---|---|---|
| 🌏 **Jurisdiction** | Is inference executed by a PRC-domiciled operator or on PRC soil? | PIPL / DSL / CSL / National Intelligence Law Art. 7 — your data can be compelled |
| 🧬 **Provenance** | Are the model *weights* Chinese-origin, wherever they run? | Embedded alignment/censorship, poisoning, procurement policy |

A vendor can be clean on one and dirty on the other. Chinese open weights running **inside your own boundary** carry zero data-jurisdiction exposure — treating that as an egress problem misdirects your controls. So we never collapse the two into one verdict.

## 💡 How it works

The tool sends an endpoint a set of carefully chosen text snippets and watches **how the model chops text into tokens** — its tokenizer. Every model family does this slightly differently, like a fingerprint, and it's very hard to fake without breaking the service. That fingerprint (plus wire-headers, latency, behavioral and network signals) is matched against **27 real tokenizer families** to estimate provenance and jurisdiction — with an honest confidence label, never false certainty.

It reports in plain language first ("**this app uses an AI model built in China**"), technical evidence below, and can re-check an endpoint over time to catch a **silent swap months after you signed the contract.**

## ⚡ Quick start (60 seconds, no API key)

> **On Windows, or want the full stack (engine + observatory)?** See
> **[RUNNING-LOCALLY.md](RUNNING-LOCALLY.md)** — a from-scratch, cross-platform
> guide (Windows PowerShell / macOS / Linux / WSL) covering the probe UI, the
> observatory API, and the static site. The quick path below is macOS/Linux.

```bash
git clone https://github.com/lobster-shrimp/provenance-probe && cd provenance-probe
./install.sh                       # venv + install + pre-built reference vectors
source .venv/bin/activate
provenance-probe serve             # open http://127.0.0.1:8770
```

`install.sh` degrades gracefully — if HuggingFace is unreachable the install still succeeds (11 real tokenizer families ship pre-built). Try the exact demo from the GIF:

```bash
python mock_real_qwen.py &         # a fake "safe US model" that's really Qwen2
provenance-probe assess --config docs/media/demo-target.json --i-am-authorized --no-behavioral
```

## 📦 Install — Mac · Linux · Windows

**From PyPI** (fastest — the CLI + engine, with the tokenizer reference vectors and the
LLM-API catalog snapshot bundled):

```bash
pip install llm-provenance-probe      # PyPI name; the command is `provenance-probe`
provenance-probe --help
```

Add extras as needed: `llm-provenance-probe[reference]` (build tokenizer refs from Hugging
Face), `[capture]` (Playwright/mitmproxy web-app capture), `[eval]`. (Why the install name
differs from the command, and why it's on PyPI at all — see
[docs/PACKAGING.md](docs/PACKAGING.md).) For the one-command setup, the demo, and the
reference builder, clone the repo instead:

<details open>
<summary><b>🍎 macOS / 🐧 Linux</b></summary>

```bash
git clone https://github.com/lobster-shrimp/provenance-probe && cd provenance-probe
./install.sh                       # one command: venv, package, reference vectors
source .venv/bin/activate
provenance-probe --help
```

Manual (if you want control):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[reference]'      # '.[reference]' adds the tokenizer extras
provenance-probe build-reference   # optional: extend the reference corpus (needs HF access)
```
</details>

<details>
<summary><b>🪟 Windows (PowerShell)</b></summary>

**📖 Full walkthrough with prerequisites, WSL2 & Docker options, and troubleshooting: [docs/INSTALL-WINDOWS.md](docs/INSTALL-WINDOWS.md).**

**Prerequisites** (once): install **Python 3.12** (not the newest — best wheel coverage) and **Git**:

```powershell
winget install Python.Python.3.12
winget install Git.Git
```

Then, in a fresh PowerShell (`install.sh` is bash-only, so install manually — no C++ compiler needed, everything ships as wheels):

```powershell
git clone https://github.com/lobster-shrimp/provenance-probe; cd provenance-probe
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1        # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install --upgrade pip
pip install -e ".[reference]"
provenance-probe serve              # http://127.0.0.1:8770
```

The 11 GGUF-derived reference families ship pre-built, so you can probe immediately. Prefer a Linux-parity experience (one-command `./install.sh` + the full demo)? Use **WSL2** — see the guide.
</details>

<details>
<summary><b>🐳 Docker (any OS)</b></summary>

```bash
docker compose up --build                                   # binds 127.0.0.1:8770 only
docker compose exec provenance-probe provenance-probe build-reference
```

Reports persist to `/data` in the container (`~/.provenance-probe/reports` locally); override with `PROVENANCE_PROBE_HOME`.
</details>

## 🖥️ The local web UI

`provenance-probe serve` (binds to loopback, no auth — keep it local) gives you the whole harness in a browser:

- **Live probe tool** — endpoint + model → streamed multi-layer assessment → plain-language warning + technical report.
- **🧙 Add target** (`/wizard`) — **one box, no "which API style?"**. Paste a plain API address, a Copy-as-cURL, or a HAR: a URL is identified by *probing* it (OpenAI vs Anthropic auto-detected, behind an explicit consent gate); a capture auto-builds a web-app target. It dry-runs, offers a known-vendor key from your environment (the value never enters the config), and hands off to the probe tool prefilled.
- **🤖 Agent board** (`/agent`) — paste an agent trace (OpenTelemetry GenAI or minimal JSON) for a per-step provenance + model-switch + tool-egress board. The same paste runs the hermetic concerning-behavior checks below (no model call, no API key).

![the add-target wizard: paste a captured request, get a synthesized probe target](docs/media/wizard-demo.gif)

*The wizard synthesizes a `template` target from a pasted request — note it blanks the stateful `conversation_id` for replay-safety, flags the rotating CSRF header, and keeps the session cookie out of the config entirely.*

## 🧰 Commands

| Command | Purpose |
|---|---|
| `serve` | Local web UI (probe tool + `/catalog` LLM-API table + add-target wizard + agent board) |
| `assess` | Full multi-layer assessment of a configured target |
| `catalog` / `build-catalog` | Searchable running table of LLM APIs × their models × model-card facts (context, price, modalities, open-weights), **joined with a provenance/jurisdiction pointer** — built from [models.dev](https://models.dev) (MIT). Also the `/catalog` page in `serve`. |
| `agent-trace` / `agent` | Assess an **agent** (trace ingest, or active backend probe), including hermetic concerning-behavior checks on a captured trace |
| `watch` | **Unattended always-on daemon** — assess targets on a schedule, diff vs a pinned baseline, alert loudly on a silent swap (`--loop`/`--once`; launchd/systemd generators) |
| `sentinel` | Live reverse-proxy flight recorder — tees an agent's model calls, live board |
| `omniroute` | Fingerprint + cross-check a route through a local OmniRoute router (calibration-gated; confidence-capped until calibrated) |
| `capture` | Guided web-app request capture (annotated DevTools steps; `--auto` uses optional Playwright, login never recorded) |
| `redteam` | Drive an authorized endpoint through an adversarial corpus; detect a model switch |
| `monitor` | Diff two runs; **exit 2 on drift** — wire into CI to catch silent swaps |
| `build-reference` / `build-reference-endpoint` / `verify-reference` | Manage the tokenizer reference corpus |
| `init` | Write an example `targets.json` |
| `fleet-scan` | Allowlist drift on this machine, or a log-only DNS/SNI read (`--dns-log`) |

### Fleet log (one command)

Log-only mode. `fleet-scan --dns-log` does not scan the machine it runs on.
Hosts the corpus recognizes are findings on the `imported-log` tier and print
first. Other names are a count. Exit 3 when a PRC-origin host is in the log:

```bash
provenance-probe fleet-scan --allowlist allow.txt --dns-log ssl.log --fail-on prc
```

`provenance-probe serve` shows that same result on the live probe page.

### 🕰️ Always-on watch daemon (`watch`)

`watch` is the unattended, **local** counterpart to the tab-bound hosted watch: it re-probes your own targets on a schedule and raises a loud local alert the instant a served model silently changes — no browser, no open terminal, survives logout. It reuses the exact assess path + fingerprint + `monitor.diff` (no new detection logic), so its baselines are byte-identical to `serve` / the Observatory.

```bash
provenance-probe watch --once  --config targets.json    # one pass; exit 2 on ANY drift (cron/CI primitive)
provenance-probe watch --loop  --config targets.json --interval 30m   # run forever; Ctrl-C to stop cleanly
provenance-probe watch --pin   --config targets.json    # accept the current backend as the new baseline
```

First run **seeds** a per-target baseline under `~/.provenance-probe/watch/<target>/` (no drift). On drift you get a stderr **MODEL SWITCH DETECTED** banner, a machine-readable record appended to `switches.jsonl`, a best-effort desktop notification, and — with `--webhook <url>` — a POST of the (secret-free) switch record. Keys/cookies read from your config **never** appear in any alert sink.

**Make it always-on:**

```bash
# macOS (launchd)
provenance-probe watch --print-launchd --config "$PWD/targets.json" > ~/Library/LaunchAgents/com.provenance-probe.watch.plist
launchctl load ~/Library/LaunchAgents/com.provenance-probe.watch.plist

# Linux (systemd --user): the generator prints a .service + .timer with install steps
provenance-probe watch --print-systemd --config "$PWD/targets.json"

# Windows: register a Task Scheduler task running `provenance-probe watch --once --config <path>`
#   schtasks /Create /SC HOURLY /TN provenance-probe-watch /TR "provenance-probe watch --once --config C:\path\targets.json"
```

The daemon runs behavioral/deception probes **off** by default for a fast, cheap re-check (tokenizer, wire and determinism stay on — the strongest swap signals); opt back in with `--behavioral` / `--deception`.

### 🛰️ Live agent flight recorder (`sentinel`)

Point an agent's `base_url` at the sentinel; it tees every model call, fingerprints in parallel, and serves a live board (`/agent/live`) that updates as calls arrive:

![the sentinel live board updating as an agent makes calls through the proxy](docs/media/sentinel-board.gif)

*The board ticks up live (3 → 4 steps here) with a plain-language "what happened / what the tool did" summary. A passive proxy can't run the tokenizer probe, so trace-only provenance honestly floors at INDETERMINATE — only the active backend probe reaches CONFIRMED.*

### 🔍 Concerning agent behavior (`agent-trace`)

`agent-trace` and `agent.analyze` also match a captured trace against the tool artifacts in [Cohere's 26 October 2026 post](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model) on Qwen3.8-Flash-Next. The check reads the file you already have. No model call. No API key.

A hit is one of these, and only these:

- Reasoning says no tools will be called, then a shell command runs in the same trace.
- Reasoning invents a prior turn whose acknowledgment was "Understood. I will follow these instructions."
- One script lists `/tmp`, runs `which` for both curl and wget, and reads `/etc/resolv.conf`.
- An upload (`-X PUT`, `--request PUT`, `--data-binary`, or the word PUT) to `*.oss-cn-beijing.aliyuncs.com`. The caught bucket was `sanmaohe.oss-cn-beijing.aliyuncs.com`.
- The cloud metadata address `169.254.169.254`.
- A `routify-file-proxy*` host.
- A signed `aliyuncs.com` URL (`OSSAccessKeyId`, `x-oss-signature`, or `Signature=`) when the user and system text did not ask for one.
- `unshare` into a user namespace (`-U` or `--user`) that mounts a `tmpfs`.

User and system text are context only, so the detection-rule prompt itself stays quiet. A written detection rule with no tool call stays quiet too. A behavior hit prints `CONCERNING AGENT BEHAVIOR` on the board, names the same ids in the HTML report, and exits 2. It is an alert beside the provenance score.

```bash
provenance-probe agent-trace run.json                 # stdout board; exit 2 on a hit
provenance-probe agent-trace run.json --html board.html
```

## 🔒 Scope & authorization

Only run against systems you are **authorized in writing** to test. Targets carry an `authorized` flag and active probing aborts without it. The behavioral probes send politically sensitive prompts — put that in your test authorization explicitly. API keys you enter are held in memory for the run and never written to report files; nothing is sent anywhere except the endpoint you name.

## 📚 Documentation

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — technical reference: signal layers, the **tokenizer fingerprint math** (overhead correction, match score, Han compression), the OmniRoute **calibration gate** and three-state cross-check, the wizard state machine, guided capture, and the security invariants.
- **[docs/WIZARD.md](docs/WIZARD.md)** — no-jargon guide to **adding a target** (URL / cURL / HAR / OmniRoute / automated capture) and what happens on save.
- **[WHITEPAPER.md](WHITEPAPER.md)** — the problem, the method, and why it's open (for consumers, security, legal/compliance, policy).
- **[QUICKSTART.md](QUICKSTART.md)** — project layout and first run.
- **[RUNNING-LOCALLY.md](RUNNING-LOCALLY.md)** — from-scratch cross-platform local run (Windows/macOS/Linux).
- **[docs/PACKAGING.md](docs/PACKAGING.md)** — why the engine ships on PyPI (reproducible pinning for the Observatory + distribution), the dist-name-vs-command split, the trusted-publishing release flow, and why PyPI does *not* automate captures.
- **[docs/adding-sources.md](docs/adding-sources.md)** — point the probe at a new API or web app.
- **[docs/EXTENDING.md](docs/EXTENDING.md)** — grow coverage: endpoints, web apps, agents, reference families.
- **[docs/CONOPS.md](docs/CONOPS.md)** — executive / federal concept of operations.
- **[DISCLOSURE.md](DISCLOSURE.md)** — the full-transparency publication policy.

## 🛰️ Companion — the Observatory

This repo is the **engine + CLI + local UI** (point-in-time, run it yourself). **[provenance-observatory](https://github.com/lobster-shrimp/provenance-observatory)** is the **continuous, public monitoring layer** built on the same core: nightly probes, a cosign/Rekor-signed append-only evidence log, numbered advisories, and a published site. Same fingerprinting engine, two use cases.
