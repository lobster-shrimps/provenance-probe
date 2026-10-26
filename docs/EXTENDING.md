# Extending coverage — the knowledge corpus

How to grow what the system can assess. There are **three axes**, and they are
independent — you can add any one without touching the others:

1. **Sources** — what you point the engine at: an API endpoint, a web app, or an
   **agent**. (§1–§3)
2. **The reference corpus** — what "Chinese-origin" is actually *measured against*:
   the tokenizer reference vectors, one per model family. Adding a family here is
   what lets a new model be matched (or cleared) with confidence. (§4)
3. **The watch list** — what the observatory monitors *continuously* and can raise
   a numbered advisory about. (§5)

Throughout: **only assess what you are authorized in writing to test.** Targets
carry an `authorized` flag and active probing aborts without it; agent backends
carry a *per-backend* flag (the consent surface is the operator AND each backend).
Findings are published in full — measurements and the interpreted verdict
together — as collected; see the full-transparency [DISCLOSURE.md](../DISCLOSURE.md).

---

## §1. Add an API endpoint

Full field reference and worked OpenAI/Anthropic examples:
[`adding-sources.md`](adding-sources.md). Short version:

```json
{ "name": "vendor-x", "base_url": "https://api.vendor.com/v1",
  "model": "vendor-flagship", "auth_value_env": "VENDOR_KEY", "authorized": true }
```

- **OpenAI-shaped** endpoints need only `base_url` + `model` + `auth_value_env`.
- **Anthropic-shaped** endpoints need only `"api_style": "anthropic"` — the adapter
  now auto-configures the `/v1/messages` path and the `x-api-key` header. (Set
  `chat_path`/`auth_header` explicitly only to override.)
- **Gemini** works through its OpenAI-compatible endpoint
  (`https://generativelanguage.googleapis.com/v1beta/openai`, `api_style: openai`).
  Use a *callable* model id for the account (e.g. `gemini-flash-latest`); the
  versioned ids in `/models` are not always callable by new accounts.

Run: `provenance-probe assess --config t.json --i-am-authorized`.

## §2. Add a web app (`api_style: "template"`)

For browser chat apps (custom request shapes, cookie sessions, SSE), capture one
real request from DevTools and describe it as a template with `__PROMPT__` /
`__MAX_TOKENS__` placeholders + dotted response paths. Full recipe:
[`adding-sources.md` → "Adding a web-app source"](adding-sources.md).

## §3. Add an agent

The unit is the agent (multi-step, multi-model). Three observation modes, pick by
how much access you have (see [`CONOPS.md`](CONOPS.md)):

**a) Trace ingest (general — no live access needed).** Feed a captured run:
OpenTelemetry GenAI spans (what LangChain / LlamaIndex / OpenAI Agents SDK emit)
or the minimal JSON form. Provenance floors at INDETERMINATE (a trace carries no
tokenizer signal); egress jurisdiction and model switch are the reliable signals.
```bash
provenance-probe agent-trace run.json --html board.html
```
The same ingest runs a hermetic scan (no model call, no API key) for the tool
artifacts in [Cohere's 26 October 2026 post](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model).
`agent.analyze` and `agent-trace` attach `concerning_behaviors` and exit 2 when
one matches: reasoning that says no tools will be called while a shell command
still runs; a fabricated prior-turn acknowledgment ("Understood. I will follow
these instructions."); a host inventory of `ls /tmp`, `which curl` and `wget`,
and `cat /etc/resolv.conf`; a PUT to `*.oss-cn-beijing.aliyuncs.com`;
`169.254.169.254`; a `routify-file-proxy*` host; a signed `aliyuncs.com` URL the
user did not ask for; and `unshare` into a user namespace that mounts a `tmpfs`.
A written detection rule for that task, with no tool call, stays quiet. The hit
is an alert on the board and in `board.html`. It sits beside the provenance score.

Minimal JSON: `{"steps": [{"model": "gpt-4o", "text": "...", "backend_url": "https://api.openai.com/v1"},
{"kind": "tool", "tool_host": "data.example.cn"}]}`. Sub-agent nesting comes free
from OTel `parentSpanId` (or `parent_id`/`span_id` in JSON).

**b) Active backend probe (the only route to CONFIRMED provenance).** When you can
reach a backend directly, add it to an `AgentTarget` with per-backend authorization:
```json
{ "name": "acme-copilot", "observation": ["trace", "active-probe"],
  "trace_path": "run.json",
  "backends": [ { "base_url": "https://api.vendor.com/v1", "model": "m",
                  "auth_value_env": "VENDOR_KEY", "authorized": true } ] }
```
```bash
provenance-probe agent --config acme.json --i-am-authorized --export evidence.json
```

**c) Live proxy interposition (privileged — you control the agent's `base_url`).**
Point the agent at the sentinel; it tees every model call, fingerprints in
parallel, and serves a live board:
```bash
provenance-probe sentinel --upstream https://api.vendor.com   # :8900
# agent sends header  X-Provenance-Session: <run-id>  (and X-Provenance-Parent for sub-agents)
# watch http://127.0.0.1:8900/agent/live?session=<run-id>
```

The `--export` bundle (§3b) is a signed-ready record — drop it under the
observatory `data/agents/<name>/<date>/verdict.json` to have the daily manifest
sign it (§5).

## §4. Add a model family to the reference corpus

This is how a *new* model becomes matchable. The reference is a set of
overhead-invariant tokenizer shape vectors, one per family, each tagged with an
`origin` (CN / US / …). A new endpoint's measured vector is compared against these;
a match ≥ 0.75 to a CN-origin family drives provenance, a match to a non-CN family
clears it. Without a family in the reference, a novel tokenizer just won't match
strongly (it floors at UNLIKELY/INDETERMINATE — measured, but inconclusive).

Build or extend the reference (merges, does not overwrite):
```bash
# from llama.cpp's bundled GGUF vocabs (no HF account):
bash provenance_probe/tools/fetch_gguf_vocabs.sh
python -m provenance_probe.tools.build_reference_from_gguf
# families GGUF doesn't cover (GLM, Yi, InternLM, Gemma, Mistral, Claude, Gemini):
provenance-probe build-reference           # needs HF access for the tokenizer
provenance-probe verify-reference          # self-check the merged file
```
A good reference addition: the real tokenizer (HF repo or GGUF vocab), the correct
`origin`, and — if you rotate the probe corpus for evasion-hardening
(`--variant-seed N`) — a reference built for the **same seed** (a comparison only
trusts a matching seed).

### Families with no published tokenizer (Claude, Gemini)

Some providers don't publish their tokenizer, so the HF/GGUF path above can't reach
them. But the reference is just an overhead-invariant *shape* vector, and the
definitional ground truth for "what does the Claude tokenizer do" is the genuine
first-party Anthropic API itself. Measure it through the same battery used against
targets — both paths go through `prompt_tokens` + overhead correction, so they are
maximally comparable:
```bash
provenance-probe build-reference-endpoint --config claude.json \
  --label Claude --family "Claude/Anthropic" --origin US --i-am-authorized
```
The entry is tagged `source: "live-first-party-api"` so its distinct provenance is
auditable next to the GGUF/tiktoken entries. **Only run this against an endpoint you
are authorized to probe AND that you know first-hand is the genuine first party** —
otherwise you would enshrine a spoofed vector as ground truth. This is how the
shipped reference now clears **Claude** and **Gemini** to a firm non-CN NO EVIDENCE
(a genuine endpoint matches its own family ≈1.0, with CN families near zero) instead
of flooring at UNLIKELY/INDETERMINATE.

## §5. Put it under continuous monitoring (observatory)

To watch a source nightly and get numbered advisories on change, add it to the
observatory watch list. Endpoint/web-app targets:
[`provenance-observatory/docs/adding-targets.md`](https://github.com/lobster-shrimp/provenance-observatory/blob/main/docs/adding-targets.md).
Agent targets (E2/E3): add a target with an `agent_trace` to `targets.yaml`; the
nightly runner assesses it, fingerprints its model composition, and opens an
MPA advisory when the composition drifts. Records land under `data/agents/` and
are covered by the daily cosign+Rekor manifest, and render in full on the
observatory page's **Agent & platform assessments** panel.

---

## Checklist for any new source

- [ ] Written authorization on file (per backend, for agents).
- [ ] `authorized: true` (source) / `authorized: true` per backend (agent).
- [ ] If it's a *new model family*, added to the reference corpus (§4) and
      `verify-reference` passes — otherwise the verdict floors at "measured but
      inconclusive," not a firm match.
- [ ] Ran once locally and eyeballed the board / report before trusting it.
- [ ] For continuous monitoring: added to the observatory watch list (findings
      publish in full once the target is probed).
