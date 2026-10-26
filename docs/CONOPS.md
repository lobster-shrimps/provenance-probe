# Agent Provenance Flight Recorder — Concept of Operations

For executives, federal / DoW leadership, and accreditation officials. Plain
language first, evidence second.

## The problem, in one sentence

When your organization fields an AI **agent** — a system that calls models in
steps and uses tools — a vendor can quietly route one of those steps to a
foreign-origin model, swap the model after you authorized it, or let a tool call
ship your data to foreign infrastructure, and you would have no way to see it.

## What this does

Point the harness at an agent you are authorized to test. It produces a
**per-step board**: for every step, which model actually answered, whether the
model changed across the run, and where each tool call sent data. The output is
signed evidence, not a hunch.

```
        AGENT PROVENANCE FLIGHT RECORDER — Concept of Operations
        ========================================================

  WHO IS REALLY RUNNING YOUR AI AGENTS?

  ┌─ AN AGENT YOU ARE AUTHORIZED TO TEST ───────────────────────────────┐
  │  call#1 planner → call#2 retriever → tool: web → call#3 writer       │
  └───────────────┬──────────────────────────────────────────────────────┘
                  │
      ┌───────────┴──────────────┬───────────────────────────┐
      ▼                          ▼                            ▼
 TRACE INGEST (general)   ACTIVE BACKEND PROBE        PROXY OBSERVE (Phase 2;
 OTel GenAI spans or      (only when a backend          only if you control the
 minimal JSON. Echoed     endpoint is reachable):       agent's config/network)
 model, self-ID, tool     the ONLY route to
 hosts, model switch.     CONFIRMED provenance.
                  │             │                            │
                  └─────────────┴────────────────────────────┘
                                ▼
   ┌───── PER-STEP VERDICT BOARD ─────────────────────────────────────────────┐
   │ call#1 planner   echoed gpt-4o   prov INDETERMINATE  juris non-PRC     ok │
   │ call#2 retriever echoed glm-4.6  prov LIKELY*        juris PRC         !! │
   │ tool   web       —               —                  egress PRC        !! │
   │ call#3 writer    echoed gpt-4o   prov INDETERMINATE  juris non-PRC     ok │
   │ AGENT VERDICT: MIXED  (worst step = call#2)                               │
   │ * CONFIRMED requires the active backend probe; trace alone = echoed/LIKELY │
   └───────────────────────────────────┬────────────────────────────────────────┘
                                        ▼
   ┌── SIGNED ASSURANCE ─────────────────────────────────────────────────────┐
   │  cosign + Rekor signed report → evidence pack (Phase 2/3)                │
   │  re-probe over time → silent swap fires ALERT → numbered advisory        │
   └──────────────────────────────────────────────────────────────────────────┘
```

## What is reliable vs best-effort (read this before you cite a verdict)

Being honest about the measurement is the whole point of the tool.

- **Reliable — data egress jurisdiction.** Where a tool call physically sends
  data is observable and hard to fake. If an agent ships data to PRC-jurisdiction
  infrastructure, this catches it.
- **Reliable — model switch / drift.** A model changing across steps, or between
  runs over time, is detectable.
- **Best-effort — per-step provenance (which model family).** A CONFIRMED
  foreign-origin verdict is reachable **only** through an active probe of a
  reachable backend endpoint. From a trace alone, provenance floors at
  **INDETERMINATE** — a post-hoc trace carries no tokenizer signal, and a
  well-built agent can rewrite intermediate model output before it reaches the
  trace. The board says INDETERMINATE honestly rather than guessing.

## Threat cards

| Threat | What the adversary does | Feature that catches it | Reliability |
|---|---|---|---|
| **Data egress** | Agent tool call ships data to PRC-jurisdiction infra | Egress host → jurisdiction (`network` layer) | Strong |
| **Silent model swap** | Backend changes model after you authorized it | Re-probe + switch/drift detection | Strong (when re-probable) |
| **PRC jurisdiction** | Inference runs on a PRC operator / PRC soil | Network + registry analysis of the backend host | Medium (CDN-fronting can mask) |
| **Foreign-origin weights** | Vendor routes a step to a Chinese-origin model | Active backend tokenizer probe | Best-effort (CONFIRMED only with the active probe; else INDETERMINATE) |
| **Concerning tool behavior** | A captured trace matches the 26 October 2026 Cohere Qwen artifacts: reasoning denies tools while a shell command runs; a fabricated prior-turn acknowledgment; `ls /tmp` plus `which curl`/`wget` plus `cat /etc/resolv.conf`; a PUT to `*.oss-cn-beijing.aliyuncs.com`; `169.254.169.254`; a `routify-file-proxy*` host; an unsolicited signed OSS URL; `unshare` into a user namespace with a `tmpfs` | Hermetic scan of the trace (`agent.analyze` / `agent-trace`) | Exact artifact match on the captured trace (no model call, no API key) |

## How to run it (Phase 1)

```bash
# Ingest a captured agent run (OpenTelemetry GenAI spans, or minimal JSON)
provenance-probe agent-trace run.json

# Config-driven, with an active backend probe (needs written authorization per backend)
provenance-probe agent --config agent.json --i-am-authorized
```

Exit code 2 signals a model switch or a concerning-behavior hit — wire it into CI or a monitor. The behavior check reads the captured trace only (no model call, no API key). A hit prints `CONCERNING AGENT BEHAVIOR` and is named in the HTML report (`--html`). It is an alert beside the provenance score. A written detection rule with no tool call stays quiet.

## Authorization

Assessing an agent widens the consent surface: you need written authorization for
the **agent operator AND every model backend** you actively probe. The tool
enforces this — each backend carries its own `authorized` flag, and active
probing aborts on the first unauthorized backend. Trace ingest of an
already-captured run needs only the authorization under which the run was
captured.

## Roadmap — all phases SHIPPED (2026-07-25)

- **Phase 1 ✓** — trace ingest, per-step board, egress mapping, active backend
  probe, per-backend authorization, this ConOps.
- **Phase 2 ✓** — live proxy interposition (`sentinel` tees SSE, fail-open), the
  `--export` signed-ready evidence pack (observatory signs it), sub-agent call
  graph (OTel `parentSpanId` / `X-Provenance-Parent` + `GET /agent/graph`), and
  the live board (`GET /agent/live`).
- **Phase 3 ✓** — continuous nightly agent monitoring (observatory `agent_monitor`
  drifts the agent fingerprint), agent-level numbered advisories (MPA, reusing the
  disclosure pipeline), and the adversarial red-team corpus (`redteam` command).
