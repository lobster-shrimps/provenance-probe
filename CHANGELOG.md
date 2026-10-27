# Changelog

> This file tracks the Python package (`llm-provenance-probe`). The MV3 browser extension
> versions **independently** (released via `ext-v*` tags) — its history lives in
> [`extension/CHANGELOG.md`](extension/CHANGELOG.md).

## [Unreleased]

- **Offline DNS / SNI / proxy-log join.** `fleet-scan --dns-log` classifies
  destination hosts in a Zeek `#fields` log or a CSV against the corpus and the
  allowlist. No socket and no DNS lookup. A row that only names a non-loopback
  gateway stays `gateway-upstream-unresolved`. An empty or unreadable file
  exits 3 (not a clean bill).

- **Concerning agent behavior (Cohere, 2026-10-26).** `agent.analyze` and
  `agent-trace` scan a captured trace for the Qwen tool artifacts in
  [Cohere's post](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model):
  reasoning that denies tools while a shell command runs, a fabricated prior-turn
  acknowledgment, a `/tmp` + curl/wget + `/etc/resolv.conf` inventory, a PUT to
  `*.oss-cn-beijing.aliyuncs.com`, `169.254.169.254`, a `routify-file-proxy*` host,
  an unsolicited signed OSS URL, and `unshare` into a user namespace with a
  tmpfs. The scan is hermetic (no model call, no API key). A hit prints
  `CONCERNING AGENT BEHAVIOR`, is named in the HTML report, and exits 2. It is
  an alert beside the provenance score. A written detection rule with no tool
  call stays quiet.

## [0.41.0] — z.ai request-signing adapter: reactivate the founding case (2026-09-30)

**Reactivates active fingerprinting of z.ai (the founding case, advisory MPA-2026-001).**
z.ai went dark when it moved chat to a **signed, per-request API** —
`POST /api/v2/chat/completions` gated by an `X-Signature` header + a time-bound
query string; the gateway 404s any request without a fresh, valid signature, so a
captured URL can't be replayed and a static template can't precompute it. This
release recovers the signing scheme from the **public client JS** (read-only) and
ships a signer so the probe can sign requests itself.

- **New `provenance_probe/signers/` package** — a per-request signer framework for
  web apps that gate on a signed, time-bound query string / header. `get_signer(name)`
  resolves a signer; unknown names fail the request cleanly (never sent unsigned).
- **New `provenance_probe/signers/zai.py`** — pure, deterministic z.ai signer.
  Recovered algorithm (from the minified `ane`+`sne` client helpers):
  `canonical = "requestId,<id>,timestamp,<ts>,user_id,<uid>" + "|" + base64(utf8(message)) + "|" + ts`;
  `derived = HMAC_SHA256(signing_key, floor(ts/300000))`;
  `signature = HMAC_SHA256(derived, canonical)` (both hex, `js-sha256` semantics).
  The `signing_key` is a **constant embedded in the client JS** (no server-issued
  secret) — but this repo does **NOT** vendor the literal value: the operator recovers
  it from the current bundle and supplies it via `signer_config.secret_key`. The signer
  has **no embedded default** and raises a clear error if the key is unset.
  Python's stdlib HMAC-SHA256 reproduces `js-sha256` **byte-for-byte**, cross-verified
  against the real library incl. a multibyte-UTF-8 message.
- **Transport wiring (`config.py` / `client.py`):** `Target` gains optional
  `signer` + `signer_config`. When set (with `api_style="template"`), `Client.chat`
  runs the signer per request — appending its query params (`timestamp`, `requestId`,
  `user_id`, `signature_timestamp`, optional telemetry) to the URL and merging its
  headers (`X-Signature`, `X-FE-Version`). Empty `signer` → verbatim replay, unchanged.
- **Tests (`tests/test_zai_signer.py`, 15 cases):** deterministic golden vectors
  computed with a clearly-**FAKE** key (not z.ai's real one), UTF-8 parity, window
  sensitivity, key sensitivity, **missing-key-raises**, message extraction, and
  transport integration (monkeypatched session, no egress) asserting the signed URL
  + `X-Signature` header.
- **Docs (`docs/zai-reactivation.md`):** the recovered algorithm writeup + operator
  runbook to re-enable the observatory target (fresh `ZAI_COOKIE`, `authorized:true`,
  the `signer`/`signer_config`), with the honest caveat that it is a **fragile per-app
  adapter** that breaks if z.ai changes its signing.
- **No secret shipped; no live probing performed.** Reverse-engineering was read-only
  (public JS only). The literal signing key is **not** in the repo; the operator
  recovers it and supplies a fresh session credential to go live.

## [0.40.1] — assess: distinguish a config/endpoint HTTP error from a usage-suppression finding (2026-09-23)

- **Fix (`assess.py`):** when the tokenizer layer is unusable, a non-2xx primary-probe
  status (e.g. a **404** for a renamed model id or a wrong `base_url`/path) is now
  reported as an actionable **configuration issue** ("model 'X' not found … fix the
  model/base_url"), not mislabeled as the vendor **suppressing usage** ("transparency
  finding"). Only a 200-with-no-`usage.prompt_tokens` remains the transparency finding.
  Surfaced by the live soak run (a stale `gemini-2.0-flash` id → 404). New pure helper
  `assess.tokenizer_unusable_note()` + regression tests. No detection/scoring change.

## [0.40.0] — `build-service-catalog`: a signed-ready map of AI apps/websites/services (#131) (2026-09-22)

**A SERVICE/provider catalog, sibling to the model catalog (`build-catalog`).** The
probe already ships `build-catalog` -> a signed `catalog.json` mapping inference *APIs*
to model cards. There was no equivalent *service* map: the consumer-facing AI apps and
websites (ChatGPT, z.ai, DeepSeek chat, Perplexity, replit, …) classified by WHO operates
them, WHOSE jurisdiction, and WHICH backend model(s) they front. This release adds that
DATA GENERATOR. The observatory service-catalog page + `catalog.html` cross-link are a
separate follow-up that consumes this JSON.

- **New `provenance_probe/servicecatalog.py`** — pure, deterministic, **NO egress** (it
  composes LOCAL data only and NEVER contacts a service; there is deliberately no fetch
  entry point, unlike `catalog.py`). It merges three local sources into the locked
  `service-catalog.json` schema, de-duplicated by host (highest-confidence / most-specific
  row wins; `fronts` unioned; corpus is the tie-break authority for jurisdiction):
  1. **corpus** — every `PRC_ENDPOINTS` host -> a service row (operator/jurisdiction/
     confidence from the corpus value; `kind` by a host-shape heuristic); every
     `AGGREGATOR_ENDPOINTS` host -> an aggregator row (jurisdiction=`aggregator`).
  2. **clientsrc** — KNOWN prior live-scan findings shipped as curated `fronts` data with
     `source:"clientsrc"` + a scan-date evidence note (z.ai->GLM; replit->deepseek/moonshot/
     glm; hix->qwen/qvq/minimax; kimi.com->Moonshot; lindy->a PRC-origin model id). **Not
     re-scanned** by the generator.
  3. **curated** — a maintained, clearly-sourced list of MAJOR consumer AI apps (ChatGPT,
     Gemini, Claude.ai, Copilot, character.ai [US first-party]; Perplexity, Poe [US
     aggregators]; DeepSeek chat, Doubao, Tongyi/Qwen, Ernie, Tencent Yuanbao [PRC]).
- **INVARIANT: `measured:false` on EVERY row** — each row is a static attribution POINTER,
  never a measured runtime verdict (mirrors `catalog.py`). Run `assess`/`soak` for a
  measured verdict. No unverified accusation; a neutral aggregator whose backend varies
  gets `fronts=[]` + a "varies" note rather than a guess.
- **New `build-service-catalog` CLI** — `--out service-catalog.json` (+ stdout by default
  / `--json`), plus `--print service-catalog-sample` (emits the full deterministic catalog
  as a ready-to-render seed for the observatory follow-up). Services are sorted by
  jurisdiction, then name, then host, so the artifact is byte-identical across runs and
  signable — the same signing-ready shape as `build-catalog` (the observatory signs it
  nightly; this generator just emits JSON).
- **No detection / corpus / scoring change.** Additive new module + command only.
  Rollback = revert the PR.

## [0.39.0] — hard `watch` alert on a jurisdiction flip TO PRC (a SEPARATE axis) (2026-09-22)

**Alert when a vendor's endpoint starts running under PRC jurisdiction (#129).** After
#128 correctly scoped a CONFIRMED **model switch** to a tokenizer-shape change (and
`drift_detected` fires only on that), a real gap remained: the SAME endpoint's inference
moving under a PRC operator / PRC soil — its `jurisdictional_risk` verdict crossing into
LIKELY/CONFIRMED with the tokenizer unchanged — was only a silent advisory in `watch`.
That is an alert-worthy event. This release adds a hard alert for it as a **SEPARATE axis**
from the model-switch axis (the two are never reconflated — that reconflation was the #128
bug).

- **`monitor.diff` emits a new additive `prc_jurisdiction_shift: bool`.** True iff the
  jurisdiction verdict CROSSED INTO positive-PRC: base verdict **not** in {LIKELY,
  CONFIRMED} **and** cur verdict in {LIKELY, CONFIRMED}. A stable PRC verdict, a
  PRC→non-PRC change, and a non-PRC→non-PRC change all stay `False`; a missing/degraded
  verdict on either side stays `False` (a crossing cannot be asserted — no spurious alert).
  The INDETERMINATE→CONFIRMED case **does** alert. Verdicts are read from
  `score.jurisdictional_risk.verdict`; per WS1 (#114) a LIKELY/CONFIRMED-PRC verdict
  requires a HARD network/wire/client signal, so the crossing is measurement-anchored.
- **A DISTINCT labeled `changes[]` entry** ("Jurisdiction shifted to PRC operator/soil …
  not a model-weights switch") is added, graded `high` — **never** `critical` — so it can
  never be mistaken for a tokenizer/model switch by any consumer. **`drift_detected` and
  the tokenizer/model-switch grade are untouched** (still tokenizer-only).
- **`watch` fires a HARD alert on `prc_jurisdiction_shift`** in addition to
  `drift_detected`: exit-2 in `--once`, banner + `switches.jsonl` record + desktop notify +
  webhook, **labeled distinctly** ("PRC JURISDICTION SHIFT" vs "MODEL SWITCH"). Both axes
  at once → alert on both, labeled separately. The record carries `drift_detected`,
  `prc_jurisdiction_shift`, and `alert_kinds`, built from the diff + verdicts ONLY — it
  **carries `watch`'s no-secret-in-any-sink invariant** (no auth/cookie in any sink).
- **`soak` surfaces a jurisdiction shift as its own timeline/summary category**
  (`PRC-JURISDICTION-SHIFT`, alongside CONFIRMED/ADVISORY), reusing `prc_jurisdiction_shift`.
- **Observatory: no change.** It consumes the unchanged `monitor.diff` output shape plus
  the additive field; promoting a jurisdiction-shift advisory is a future follow-up.
- **Additive & reversible.** `prc_jurisdiction_shift` is additive to `monitor.diff`'s
  output (callers ignoring it are unaffected); no change to `drift_detected` /
  model-switch behavior or the scoring/verdict path (WS1 untouched).

## [0.38.0] — grade a switch by the tokenizer shape, not the composite fingerprint (2026-09-22)

**Stop false CONFIRMED switches on wire/error noise (#127).** The `soak` harness, the
`watch` daemon, the CLI `monitor` command, `serve`'s Monitor tab, and the observatory all
decide "did the model switch?" through `monitor.diff`. `diff` used to grade a `critical`
(CONFIRMED) switch on any change to the **composite** `fingerprint_id` — which folds
`error_signature`, `header_shape_hash`, streaming `chunk_fields`, and the greedy signature
in *alongside* the real model signal (the tokenizer shape). A stable local model (Ollama
`gemma4`, which cannot have switched) tripped a **false CONFIRMED** in a live soak because
its `error_signature` moved between two probes while the tokenizer shape was **identical**.

- **The tokenizer shape is now the sole switch authority (WS1).** `monitor.diff` grades
  `critical` **only** on a tokenizer-**shape** change (the overhead-invariant shape vector),
  never merely because the composite `fingerprint_id` string moved. `fingerprint_id` stays
  a fine identity pin/label; it is just no longer graded.
- **`drift_detected` == (a critical tokenizer-shape change exists) — nothing else.** A
  wire/error/greedy-only change is still **reported** in `changes[]` with its existing
  non-critical severity (`error_signature` `high`; header / streaming / greedy `medium`),
  each tagged "provider/wire change — NOT a confirmed model switch", but does **not** set
  drift. So `watch` no longer exits 2, `soak` no longer records a CONFIRMED, the CLI
  `monitor` no longer exits 2, and the observatory no longer promotes on CDN/error noise.
- **Degraded tokenizer path.** The tokenizer shapes are comparable only when **both** runs
  have a usable tokenizer (`usable` flag true **and** a non-empty shape vector). Otherwise a
  switch cannot be confirmed: any change is graded advisory, `confidence="degraded"`, and no
  false `critical` is emitted from wire noise. Both-unusable + nothing else = `changes=[]`,
  `drift_detected=False`, `confidence="degraded"`.
- **Real switches still fire.** A genuine tokenizer-shape move (DeepSeek/GLM/z.ai swaps,
  the mid-session boundary check) is still `critical` + `drift_detected=True`; when a
  critical tokenizer change is present, non-tokenizer advisories are listed alongside it.
- **Accepted limitation (WS1-honest).** Identical tokenizer shapes do **not** prove the
  model is unchanged — two models sharing a tokenizer (e.g. a finetune) look identical, so a
  same-tokenizer swap yields at most an ADVISORY, never a CONFIRMED switch. This is correct
  and intended: you can only CONFIRM a switch you can measure.
- **Output shape unchanged** (`changes[]` / `drift_detected` / `confidence` /
  `confidence_note`), so every caller and the observatory are compatible either way — only
  the switch-grading accuracy changes. Live corroboration: an Ollama `gemma4` soak now
  reports **0 CONFIRMED** switches (was 1); a synthetic tokenizer-shape move still CONFIRMED.

## [0.37.0] — `soak`: duration-bounded continuous model-switch soak test (2026-09-22)

**A "soak test" for silent model swaps (#124).** The always-on `watch` daemon and the
nightly observatory both detect model switches, but there was no *duration-bounded*
harness you run for, say, 30 minutes across a set of services to get a switch **timeline**
back. `soak` is that harness — the WS1 "don't trust the confession" idea applied
continuously, seeded by the founding z.ai case (a Gemini persona over GLM, revealed only
by repeated probing over time).

- **New `provenance-probe soak`** (`provenance_probe/soak.py`). `soak --config targets.json
  --duration 30m --interval 2m [--card-interval 30s] --out ./soak-reports [--json]
  --i-am-authorized`. Reuses `assess` → `monitor.fingerprint` → `monitor.diff` + the
  `watch` per-target store — **no new detection logic**.
- **Two signals per poll (WS1 over time).** The model **card** (echoed `model` id +
  `/models` list) is a cheap, frequent **ADVISORY** signal; the tokenizer **fingerprint**
  is the **CONFIRMED** authority. A CONFIRMED switch is exactly a `monitor.diff` *critical*
  change — so a fingerprint move is CONFIRMED **even when the echoed model id never
  changes** (the z.ai shape a card-only harness would miss). A card change alone is
  ADVISORY and also triggers an out-of-schedule fingerprint poll that can **upgrade** to
  CONFIRMED. Non-critical wire noise is recorded, never alerted.
- **Timeline + summary.** Ordered contiguous runs `{model_id, models_hash, fingerprint_id,
  first_seen, last_seen, observations}` (a revisit = a new entry); each poll compares to the
  *immediately-previous* state so `A→B→B→A` yields exactly two transitions. Per-target
  summary (console + `--json`) + a stamped `soak-<stamp>.json`; switches also append to
  `watch`'s `switches.jsonl`. `--print-example` prints a copy-pasteable recipe.
- **Bounded + clean.** First poll at t0; targets polled sequentially; deadline checked
  *before* each cycle; `SIGINT`/`SIGTERM` finishes the in-flight poll and still writes the
  report. A failed/partial poll is a no-data **gap** (no switch, previous state frozen) —
  the soak never crashes and exits `0`.
- **Secret-safety** carried to every new sink: only the **scrubbed** model-id + the
  `models_hash` (sha256 over the sorted unique id set) are stored — never the raw `/models`
  response; the redactor scrubs both the composed header value and the **bare** token/cookie
  an endpoint could echo back inside a model id or `/models` entry. The full assess bundle
  is held in memory only. New `docs/soak.md` runbook frames the (synthetic, hermetic) z.ai
  seed. **Eval-gated (GATE PASS, FP=0).**

## [0.36.1] — clientsrc: tighten over-broad `step-`/`seed-` CN model tokens (2026-09-22)

**Accuracy fix for the client-source scan (#123).** `PRC_MODEL_TOKENS` mapped the
bare prefixes `step-` -> StepFun and `seed-` -> ByteDance Seed. The `clientsrc`
grep (`["'/\s:=-]<tok>[a-z0-9._-]*`) then fired `client_prc_model_id` HIGH findings
on ubiquitous Western web/JS: `step-1`/`step-2` (UI wizards, steppers, CSS classes)
and `seed-123`/`seed=42`/`seed-value` (random seeds). Proven live on
`gemini.google.com` and `base44.com`, which were falsely read as "uses a StepFun /
ByteDance-Seed (CN) model."

- **Enumerated the real StepFun families** in place of bare `step-`: `step-1v`,
  `step-1x`, `step-1o`, `step-1-{8k,32k,128k,256k}`, `step-2-16k`, `step-2-mini`,
  `step-2x`, `step-3.` (matches `step-3.5-flash`/`step-3.7-flash`; not `step-3-of-5`),
  `step-r1`. Real ids (`step-1v-8k`, `step-2-16k`, `step-1x-medium`, `step-r1-v-mini`)
  still flag; `step-1`, `step-2`, `step-3-of-5`, `step-by-step`, `stepper` do not.
- **Enumerated the real ByteDance-Seed families** in place of bare `seed-`:
  `seed-oss`, `seed-coder`, `seed-thinking`, `seed-1.` (matches `seed-1.5`/`seed-1.6`;
  not `seed-123`). `seed-42`, `seed-value`, `seed-data`, `seed-42-abc` no longer flag.
  Bare `seed-x` intentionally omitted (collides with `seed-xml`/`seed-example`).
- **`SOURCE_GREP_PATTERNS`:** the info-severity `client_string` grep now keys on the
  distinctive vendor name `stepfun` instead of `step-1` (no misleading `step-1` echo).
- **Audit note:** `PRC_MODEL_TOKENS` is shared with the transcript / behavioral / wire
  self-id probes, where a *bare* brand word (`glm`, `minimax`, `kimi`, ...) is the wanted
  self-identification signal. Those are deliberately kept bare (narrowing them would be a
  new false negative); each carries a one-line rationale. Only `step-`/`seed-` — which no
  model self-ids as — were enumerated. No scoring or detection-surface change otherwise.
- **Tests:** +5 (`tests/test_clientsrc_prc_tokens.py`) covering the FP strings, real ids,
  every pre-existing CN token, a stepper-heavy HTML blob, and the live gemini `step-1`
  case. `pytest` green; hermetic eval GATE PASS (FP=0, FN=0).

## [0.36.0] — Fleet rollup exit gate: `--fail-on` / `--fail-on-exposure` (2026-09-22)

**Pilot hardening for WS3 (#120).** The `fleet-scan --rollup` report (WS3, #119) only
printed a posture a human had to read. A security team piloting it asked for the
actionable version: wire the rollup into cron / a CI gate / a SIEM rule so it **exits
non-zero** when the fleet has shadow-AI exposure.

- **`--fail-on {prc|drift|any|none}`** (default `none`, fully backward-compatible). `prc`
  gates on any PRC-origin finding; `drift` on any off-allowlist finding; `any` on either;
  `none` never gates. `--fail-on-exposure` is a convenience alias for `--fail-on any` (an
  explicit `--fail-on` wins if both are given). Both apply only with `--rollup` (an
  argparse error otherwise).
- **Exit `3` = exposure matched** (new). `0` = clean / no-match and `2` = error are
  unchanged; **error outranks exposure** (a corrupt DB with `--fail-on any` still exits
  `2`), so cron/SIEM can tell "found shadow AI" from "the scan broke". The full report
  still prints on exit `3`.
- **Deterministic `EXPOSURE:` summary line**, always emitted (additive, even at `none`):
  a trailing console line `EXPOSURE: prc=<n> drift=<n> (fail-on=<mode> -> FAIL|ok)`, a
  JSON `exposure` object `{prc, drift, unresolved, fail_on, matched, exit_code}`, and a
  trailing `# EXPOSURE: ...` CSV comment.
- Counts are FINDING-level (a PRC-origin off-allowlist finding counts toward both `prc`
  and `drift`); UNRESOLVED is never exposure. `docs/fleet-rollup.md` gains an
  "Alerting / CI gate" section with the exit-code table, a cron example, and a CI-gate
  example. **No scoring/detection change; eval-gated (GATE PASS, FP=0).**

## [0.35.0] — Fleet rollup: one CISO shadow-AI / PRC-exposure posture report (2026-09-21)

**WS3, the enterprise pilot deliverable.** The fleet stack scanned and reported ONE
machine at a time; a security team piloting this needs ONE report across the whole
fleet — "of my N machines, which are reaching unsanctioned or PRC-origin AI
endpoints, and which ones." `fleet-scan --rollup <path>` produces that report from
already-collected data. It is **pure and no-egress**: it only reads local files
(a SQLite DB, a JSON report, or a directory of per-machine `*.db`/`*.json` files),
never scans, never writes, never touches the network. **No scoring/detection change;
eval-gated (GATE PASS, FP=0).**

Terminology is locked to resolve the endpoint-vs-machine ambiguity: **machine** = a
scanned COMPUTER (what a CISO counts); **endpoint host** = the upstream AI hostname a
machine reaches. The rollup COUNTS machines and GROUPS exposure by endpoint host —
two axes, always labeled distinctly.

### Added
- **`provenance_probe/fleet/rollup.py` (NEW)** — pure aggregation + all three
  renderers (console/json/csv). Produces the CISO headline; machine count; finding
  classification totals AND the per-machine holding split (both labeled); PRC-origin
  exposure (endpoint → named machines); a rogue-upstream table grouped by endpoint
  host (rogue = ≥1 off-allowlist finding; aggregator/gateway-unresolved endpoints are
  a separate UNRESOLVED line, never counted clean or drift); and freshness via
  `scanned_at` (default stale threshold 7d, `--stale-days`). The `fleet_scans` table
  is authoritative for the machine count + freshness; findings for exposures.
- **`fleet-scan --rollup <path>`** with `--format console|json|csv` (default console;
  `--json` is an alias for `--format json` on the rollup path), `--machine-id`, and
  `--stale-days`. Exit 0 on any successful report (incl. empty); exit 2 on a
  missing/unreadable path, a corrupt SQLite DB, or a directory with zero usable files.
- **`fleet-scan --print rollup-quickstart`** — the one-command runbook; full docs in
  **`docs/fleet-rollup.md` (NEW)**.

### Changed (store, additive + back-compat)
- **`fleet/store.py`** — `write_sqlite` now writes a `machine` + `scanned_at` (UTC
  ISO) column per finding and a `fleet_scans(machine, scanned_at)` metadata table on
  EVERY scan, **including a zero-finding scan**, so a clean machine is still counted.
  `machine` defaults to `socket.gethostname()` (overridable via `--machine-id`). The
  rollup reader introspects old DBs with `PRAGMA table_info` and degrades (machine
  count "unknown", "freshness unavailable") rather than crashing. `write_sqlite` stays
  per-machine-local; two machines never write the same DB.
- **`fleet/render.py`** — `to_json()` gains optional `machine` + `scanned_at`
  passthroughs so a directory-of-JSON rollup carries each file's machine id +
  freshness; the per-host output is otherwise unchanged.

### Privacy
- Redaction holds in **every** rollup format (asserted): `source` home paths collapse
  to `~/…` (no `/Users/`, `/home/`, `\\Users\\` substring), and `base_url` is
  sanitized (userinfo/credentials + query stripped, scheme+host+path kept), since the
  report leaves the security team's control.
- **`_redact_source` broadened (privacy-review MEDIUM)** — it was start-anchored and
  POSIX-only, so a Windows source (`C:\\Users\\carol\\…`), a UNC/backslash home path,
  or a home path embedded mid-string (`loaded from /Users/bob/…`) passed through
  verbatim into the CSV `source` column. It now redacts a home-directory prefix
  ANYWHERE in the string, covering POSIX (`/Users/<u>`, `/home/<u>`, `/root`) and
  Windows (`<drive>:\\Users\\<u>`, `\\Users\\<u>`, `\\home\\<u>`, case-insensitive)
  forms. The redaction test no longer passes vacuously (adds Windows + mid-string +
  `/root` cases across CSV/JSON/console).
- **Holding-fraction denominator (privacy-review LOW)** — on a partial merged DB where
  a machine has findings but no `fleet_scans` row, the headline could read
  "holding on N/M" with M < the machines actually classified; the denominator is now
  `max(len(machines), machines_scanned)` so the fraction never exceeds 1.

## [0.34.1] — Plain-language layer labels in the how-it-works flow (2026-09-21)

**WS2 follow-up (legibility LOW finding).** The how-it-works flow's step 2 listed
the probe's evidence layers by their TECHNICAL names — a newcomer on the landing
page and in `provenance-probe explain --flow` saw bold headings like "Tokenizer
fingerprint" and "Wire fingerprint". WS2's whole point is non-technical legibility,
so the flow now shows plain, jargon-free layer labels instead. `/help` is a
technical reference page and is UNCHANGED — it still shows the technical `LAYERS`
titles + tooltips. **No scoring/detection change; `plain_answer` and the verdict
logic are untouched; eval-gated.**

### Changed (content / rendering only)
- **`explain.Layer` gains `flow_label` (+ optional `flow_blurb`)** — a plain,
  jargon-free heading (and optional blurb) per layer, kept in `explain.py` so the
  flow stays single-source. `flow_html()` / `flow_text()` step 2 now render
  `flow_label`/`flow_blurb`; `_layers_table()` (/help) still renders the technical
  `title`/`measures`. Plain labels chosen: network → "Where the servers really are
  (and who runs them)"; wire → "The delivery envelope around each reply (like a
  letterhead)"; tokenizer → "How it breaks text into pieces (like handwriting)";
  logprob → "Whether it answers the same way twice"; behavioral → "How it answers
  telltale questions"; deception → "Whether its own story matches the evidence";
  latency → "How fast and steady the replies come back"; artifacts → "Clues left
  in its files and app code".

### Tests
- The flow asserts the plain labels appear and that banned technical jargon
  (`tokenizer`, `fingerprint`, `wire`, …) never appears in `flow_text()` /
  `flow_html()`; `/help`'s `_layers_table()` still asserts the technical titles;
  the single-source guard now also forbids the plain flow labels in serve/cli.

## [0.34.0] — Plain-English result + a visual how-it-works flow (2026-09-21)

**WS2 of `docs/next-iteration-plan.md` — the shared-core legibility item.** The
text explainers were thorough but assumed a technical reader: a result led with
verdict *words* ("provenance: INDETERMINATE") and a wall of layer prose. Post-WS1,
INDETERMINATE is common (self-report caps there), so a plain-English "what this
means" matters more than ever. This adds a single plain-English lead sentence and
a visual pipeline — both sourced ONLY from `explain.py` so the serve UI and the
CLI cannot drift. **No scoring/detection change (WS1 untouched); eval-gated.**

### Added (content / rendering only)
- **`explain.plain_answer(provenance, jurisdiction, confidence)`** — one
  deterministic, single-sentence, plain-English answer, a PURE function of the
  verdict tuple (mirrors the serve monitor no-drift invariant). Leads with the
  more-severe axis (severity = `_TIER_ORDER` reversed; tie-break provenance-first);
  confidence adverb per bucket (high→"clearly", moderate→"likely",
  low→"a preliminary read suggests"); both-clean collapses to one reassuring
  sentence; an INDETERMINATE axis always says it is "not a clean bill" and "not an
  accusation" (teaches the WS1 nuance). Honest by construction — asserts origin /
  jurisdiction only, never misrepresentation. Every output ≤200 chars, no engine
  jargon.
- **`explain.FLOW_STAGES` + `explain.flow_html()` / `explain.flow_text()`** — the
  four-step "how it works" flow, both rendered from `FLOW_STAGES` + `LAYERS` /
  `VERDICTS` (single source, no duplicated copy). `flow_html()` is accessible
  static markup: no `<script>` (works with JS disabled), a semantic `<ol>`/`<li>`
  never color/icon-only (every stage has a visible text label), aria-labels on the
  container and each stage, all content escaped.
- **`provenance-probe explain --flow`** — prints `flow_text()` (no network).

### Changed
- The **serve** result surface (`/api/run`, `/api/monitor`) and the **CLI** `assess`
  result block now **lead with the identical `plain_answer` string**; the flow
  renders on the landing page and `/help`.

## [0.33.0] — Hard-evidence ceiling: a model's self-report can't confirm its weights (2026-09-21)

**WS1 of `docs/next-iteration-plan.md` — the z.ai "don't trust the confession"
fix.** A model's self-report is not evidence of what its weights are: it can be
instructed to claim any identity, in either direction. Before this change,
model-self-report signals alone could reach a positive verdict with **zero
measurement** (`informative_concession` + `selfid_cn` cleared CONFIRMED;
`false_jurisdiction_assurance` alone cleared jurisdiction LIKELY). This closes
that soft-signal false-positive path.

### Security / accuracy (behavior change)
- **Hard-evidence ceiling in `scoring.py`.** New `HARD_PROVENANCE` /
  `HARD_JURISDICTION` signal sets partition *measured / artifact* signals (tokenizer
  fingerprint, config/cache/gguf artifacts, client-source endpoints; wire/network
  jurisdiction signals) from *soft / self-report* signals (behavioral self-ID,
  informative concession, held persona, persona-management-in-trace, false
  compliance assurance, and lower-durability **claims** — the echoed model-id
  `model_name_cn`, `catalog_cn`, `cjk_compression`, and behavioral
  `alignment_asymmetry` / `cjk_leakage`). `score()` now caps an axis at
  **INDETERMINATE** unless ≥1 hard signal fired for that axis. CONFIRMED / LIKELY
  require measurement. The cap sets a deterministic `note` naming the soft signals
  present. This complements the existing clean-verdict **floor** (floor raises a
  clean verdict up to INDETERMINATE; ceiling lowers a soft-inflated one down to it;
  applied floor-then-ceiling, both converge on INDETERMINATE).
- **Deception is inculpatory, never exculpatory.** Soft signals only ever ADD
  log-odds; a false persona can never downgrade a hard-signal-driven verdict.
  `persona_mismatch` stays a corroborator, **not** a CN-provenance anchor.
- **Consequence (behavior change):** provenance/jurisdiction driven ONLY by a claim
  (a chat self-ID, an echoed CN model id, an advertised CN catalog) or by behavioral
  signals now reads **INDETERMINATE**, not LIKELY/CONFIRMED — matching the
  documented design that **trace-only provenance floors at INDETERMINATE** and
  CONFIRMED is reachable only through an active tokenizer probe. Passive-trace
  analysis (`agent.py` / `sentinel.py`) no longer alerts on an echoed CN model id
  alone; it alerts on a hard signal (active probe) or a model-identity/fingerprint
  switch.

### Added
- **Fingerprint-based HARD switch in `redteam.run()`** — `fingerprint_switch` bool
  + `fingerprint_switches` list, computed via `monitor.fingerprint` over each
  scenario's response envelope vs a backfilled baseline (first usable scenario;
  scenarios with a suppressed usage/tokenizer are skipped as advisory). Folded into
  `switch_detected`, so a router that swaps the backend while echoing a **constant**
  `model_id` (the z.ai shape) still trips. Existing `model_id` / `self_id` handling
  is unchanged; `monitor.diff` / `monitor.fingerprint` switch logic is untouched.
- **Eval cases (synthetic, per public-repo policy):** a POSITIVE z.ai case
  (`synth_zai_denies_switch.json` — GLM tokenizer match + `cn_architecture` +
  `cn_vocab_size` → CONFIRMED-CN while the model denies it; denial is context, not a
  downgrade) and a NEGATIVE case (`synth_false_cn_selfid.json` — a non-CN model that
  falsely self-IDs as CN, soft only → capped INDETERMINATE, zero-FP protection). The
  behavioral-only case is retuned to INDETERMINATE (soft-only under the ceiling).
- **Docs:** `docs/ARCHITECTURE.md` §4.1 (floor + ceiling) and §4.2 (honest
  capture-robustness note — signed/stateful apps defeat static replay; robustness is
  *detection given a capture*, with known limits).

### Tests
- `tests/test_scoring_provenance.py`: +6 ceiling / inculpatory-only cases.
- `tests/test_redteam.py`: +3 fingerprint-switch cases (fires on constant
  `model_id`; stable backend no-switch; skips unusable tokenizer).
- `tests/test_agent.py`, `tests/test_transcript.py`: updated to the hard-evidence
  policy (a hard signal now required to reach a positive tier).

## [0.32.0] — SentencePiece enabler: validate the last CN families (2026-09-16)

Closes the CN portion of Goal 3 (reference coverage). Adds a **SentencePiece
enabler** to the eval's GGUF-vocab path, then validates the four last-gap CN
families the byte-level-BPE mock could not serve: **Yi-1.5, InternLM2.5, MiniCPM3,
Baichuan2**. CN consistency-tier coverage goes 5 → **9**; the eval now exercises
17 of 25 families (TP=16 FP=0 TN=24 FN=0).

**Finding (surfaced, not tuned away):** all four are SentencePiece **BPE**
(proto `model_type=2`) with `byte_fallback`, **not** unigram — they carry piece
scores AND a merge table, and their front-end is Metaspace (`▁`) + ByteFallback,
not GPT-2 ByteLevel. `tokenizers.models.Unigram` is the wrong algorithm and does
not reproduce them; the faithful reconstruction is `models.BPE(..., byte_fallback=
True)` + a per-family SP front-end (`SP_CONFIG`), which reproduces the genuine HF
`AutoTokenizer` counts exactly.

### Added
- **SentencePiece enabler** in `provenance_probe/tools/build_reference_from_gguf.py`:
  `read_gguf_vocab` now also reads `tokenizer.ggml.scores`; `classify_vocab`
  distinguishes byte-level BPE (no scores) from SentencePiece (has scores). The
  ONE shared `build_sp_tokenizer` + `SP_CONFIG` (the SP analogue of the
  byte-identical `REGEX`) reconstructs the SP tokenizer; `eval/mock.py`
  `load_tokenizer` serves each SP vocab through that same builder, so mock and
  reference cannot drift (test-asserted).
- **Approach A** — `eval/vocabs/yi.gguf` (3.0 MB), `internlm.gguf` (4.9 MB),
  `minicpm.gguf` (3.1 MB): vocab-only SentencePiece GGUFs carrying id-ordered
  tokens + piece scores + merges (`tokenizer.ggml.model="llama"`), built from the
  HF fast tokenizers of `01-ai/Yi-1.5-9B-Chat` (rev `1a0fc698`, Apache-2.0),
  `internlm/internlm2_5-7b-chat` (rev `eb72b541`, Apache-2.0) and
  `openbmb/MiniCPM3-4B` (rev `d6b14dda`, Apache-2.0) via the new
  `scripts/build_spm_vocab_gguf.py`.
- **Approach B** — `eval/vocabs/baichuan.model` (2.0 MB): the raw SentencePiece
  `tokenizer.model` of `baichuan-inc/Baichuan2-7B-Chat` (rev `ea66ced1`, license:
  Baichuan-2 community license), served via `sentencepiece`. Baichuan2 is a slow
  custom tokenizer with no fast backend whose `_tokenize` is `sp_model.encode`, so
  raw SentencePiece reproduces its HF `AutoTokenizer` counts exactly. `sentencepiece`
  added to the `[eval]` extra for this path only.
- **Four `VOCAB_CASE`s** in `eval/corpus.py` (Yi/01.AI, InternLM, MiniCPM,
  Baichuan — all CN).
- **`tests/test_eval_sentencepiece.py`** — the enabler tests (classify bpe vs
  spm; shared-builder parity mock==reference; BPE path unchanged regression) plus
  four tests per family (faithful reproduction of the genuine HF `AutoTokenizer`
  counts; corpus wiring + `is_flagged_cn`; served blind → family match + flagged
  CN; rebuild is vocab-derived + siblings intact).

### Changed
- Rebuilt the four families' `tokenizer_ref.json` vectors from their committed
  vocab. Yi-1.5, InternLM2.5, MiniCPM3 are **byte-identical** to the prior
  HF-derived vectors (zero detection delta; only GGUF metadata added). **Baichuan2
  drifts on 4 probes** (`diacritics` 148→150, `cyrillic` 59→60, `base64ish`
  256→192, `newline_storm` 122→121): a surfaced vector-drift finding — the prior
  shipped Baichuan vector was slightly off; the genuine SentencePiece counts are
  the ground truth. The other 23 entries are byte-unchanged.

### Notes
- **InternLM2.5 byte_fallback finding.** InternLM2.5's *current* HF fast/slow
  tokenizers regressed `byte_fallback` to `False` (emoji/rare-unicode collapse to
  `<unk>`). The genuine model and the pre-existing shipped reference use
  `byte_fallback=True` with `add_dummy_prefix=False`; the served reconstruction
  reproduces that byte-fallback-correct behaviour (which a real endpoint reports),
  byte-for-byte with the shipped vector.
- Verdict tiers: Yi/InternLM/MiniCPM land at **LIKELY** (the same tier as the
  shipped Qwen/DeepSeek CN cases), Baichuan at **CONFIRMED**; all four match their
  own family at score 1.0 and are flagged Chinese-origin. Zero false positives.
- No change to `monitor.py`, `scoring.py`, matcher thresholds, or the
  `reference.py` HF path. The detection engine is untouched.

## [0.31.2] — validate Moonshot in the hermetic consistency tier (2026-09-16)

Continues the CN reference-coverage push (issue #107): a best-effort batch to
validate the four remaining CN families that ship a reference vector but no blind
GGUF test — Moonshot, Yi, InternLM2.5, MiniCPM3 — following the #106 GLM
template. Only **Moonshot** is byte-level-BPE-representable and lands; the other
three are SentencePiece-derived and are deferred (see below). Issue #107 stays
open for the SentencePiece enabler follow-up.

### Added
- **`RE_MOONSHOT`** — Moonshot (Moonlight/Kimi) pre-tokenizer regex. This family
  ships a *tiktoken* tokenizer, not an HF `tokenizer.json`; llama.cpp's matching
  pre-type `LLAMA_VOCAB_PRE_TYPE_KIMI_K2` (commit `7ceed87`) triggers on
  `\p{Han}+` and delegates the split to a custom `unicode.cpp` handler, so it
  carries no single-regex transcription. The faithful source is the model's own
  `pat_str` (`moonshotai/Moonlight-16B-A3B` `tokenization_moonshot.py`, revision
  `476b36a4`). Added byte-identically to both
  `provenance_probe/tools/build_reference_from_gguf.py` (new `"moonshot"` SPEC
  entry) and `eval/mock.py` (`REGEX["moonshot"]`); a test pins the two copies
  identical and equal to the source pat_str.
- **`eval/vocabs/moonshot.gguf`** (6.24 MB) — a vocab-only byte-level-BPE GGUF
  (163584 tokens, 163328 merges) reconstructed from the tiktoken vocabulary of
  `moonshotai/Moonlight-16B-A3B` (revision
  `476b36a473d4467f94469414bef6cee75c9c8172`, license: MIT). Built with the new
  `scripts/build_tiktoken_vocab_gguf.py` (standard OpenAI/llama.cpp merge
  reconstruction; GPT-2 byte-level encoding).
- **`scripts/build_tiktoken_vocab_gguf.py`** — reproducible tiktoken → byte-level
  BPE GGUF builder for tiktoken-vocab families.
- **`moonshot` `VOCAB_CASE`** in `eval/corpus.py` (family Moonshot, origin CN).
- Five tests (`tests/test_eval_moonshot.py`): regex byte-identical + equal to the
  Moonlight `pat_str`; GGUF loads as BPE and reproduces the genuine Moonlight
  tokenizer's counts (tiktoken, an independent oracle); `is_flagged_cn` CN;
  integration (Moonshot served blind → CONFIRMED CN); rebuild is GGUF-derived and
  siblings intact.

### Changed
- Rebuilt the `Moonshot` `tokenizer_ref.json` vector **from the GGUF**
  (rebuild-from-GGUF, so reference and blind mock agree by construction). The
  vector is **byte-identical** to the prior HF-derived one (zero detection
  delta); only metadata changed (`source` → the GGUF, added
  `merges`/`gguf_model`/`gguf_pre`/`note`). All other 26 reference entries are
  unchanged. Eval: TP=12 FP=0 TN=24 FN=0 (moonshot → CONFIRMED CN).

### Deferred (SentencePiece-derived — out of scope for the BPE mock)
- **Yi-1.5** (`01-ai/Yi-1.5-9B-Chat`), **MiniCPM3** (`openbmb/MiniCPM3-4B`),
  **InternLM2.5** (`internlm/internlm2_5-7b-chat`) are SentencePiece-derived:
  their vocabularies are `▁`-based (SentencePiece metaspace), not byte-level BPE,
  and expose no byte-level merges the mock's `load_tokenizer` can read (InternLM
  ships only a SentencePiece `tokenizer.model`; Yi/MiniCPM ship a `tokenizer.json`
  but with `▁` tokens + a ByteFallback decoder). They hit the same wall as
  Baichuan2 and are deferred to the SentencePiece mock enabler.

## [0.31.1] — validate GLM (Zhipu) in the hermetic consistency tier (2026-09-16)

Brings the founding z.ai/GLM field case into the eval's consistency tier, so the
tokenizer matcher is PROVEN — blind — to identify GLM as Chinese-origin. GLM was
the one CN family with a shipped reference vector but no blind GGUF test; this
closes the GLM portion of the reference-coverage goal (CN gap).

### Added
- **`RE_GLM4`** — GLM-4 pre-tokenizer regex, transcribed byte-for-byte from
  llama.cpp `src/llama-vocab.cpp` `LLAMA_VOCAB_PRE_TYPE_CHATGLM4`
  (commit `7ceed87`). Added byte-identically to both
  `provenance_probe/tools/build_reference_from_gguf.py` (new `"glm-4"` SPEC entry)
  and `eval/mock.py` (`REGEX["glm-4"]`); a test pins the two copies identical.
- **`eval/vocabs/glm-4.gguf`** (8.7 MB) — a vocab-only BPE GGUF (151329 base +
  14 special tokens, 318088 merges) built from `THUDM/glm-4-9b-chat-hf`
  (revision `8599336f`, license: GLM-4 / "other"). llama.cpp ships no bundled GLM
  vocab, so it is derived from that repo's `tokenizer.json`.
- **`glm-4` `VOCAB_CASE`** in `eval/corpus.py` (family GLM/Zhipu, origin CN).
- Five tests (`tests/test_eval_glm.py`): regex byte-identical + equal to the
  llama.cpp source value; GGUF loads as BPE and reproduces the genuine GLM-4
  tokenizer's counts (HF `AutoTokenizer`, an independent oracle); `is_flagged_cn`
  CN; integration (GLM served blind → CONFIRMED CN); other-26-entries-unchanged.

### Changed
- Rebuilt the `GLM-4-9B` `tokenizer_ref.json` vector **from the GGUF** (decision:
  rebuild-from-GGUF, so reference and blind mock agree by construction). The
  vector is **byte-identical** to the prior HF-derived one (zero detection
  delta); only metadata changed (`source` → the GGUF, added
  `gguf_model`/`gguf_pre`/`merges`, `vocab_size` 151329 → 151343). The other 26
  reference entries are unchanged. GLM-4.5 stays HF-derived (a follow-up).

## [0.31.0] — finish fleet: Windows collector + Intune/Tanium delivery (2026-08-18)

Closes the fleet B-phase: the scanner now runs on Windows and delivers through the
enterprise MDMs, so `fleet-scan` covers the three major desktop OSes and the common
management planes.

### Added
- **Windows collector.**
  - **Connection table** (`--egress`): `netstat -ano` + `tasklist` readers
    (`connections.parse_netstat` / `parse_tasklist`) feed the SAME analyzer as the
    macOS/Linux `lsof` path (`LISTENING`→`LISTEN`, wildcard-bind + gateway-port
    recognition unchanged). Refuses (never `[]`) on a netstat read failure.
  - **Trust-store watch** (`--trust-store`): roots read via PowerShell
    (`Get-ChildItem Cert:\LocalMachine\Root|CurrentUser\Root` → base64 DER) and run
    through the existing tested PEM path, so a Windows root's SHA-256 is byte-identical
    to a macOS/Linux baseline (cross-platform baselines). Refuses on a read failure.
  - **Config discovery** already resolves on Windows (home-relative dotfile paths).
  - `--ja3` stays honestly refused on Windows (raw capture needs npcap/pktmon) rather
    than false-clean.
- **Enterprise delivery.** `fleet-scan --print`:
  - `schtasks` — Windows Task Scheduler XML (parity with launchd/systemd/cron).
  - `intune` — a Microsoft Intune PowerShell deploy script (installs the probe +
    registers the scheduled task; idempotent, SYSTEM context).
  - `tanium` — a Tanium recipe (Package to schedule + osquery-ATC / Sensor to read).
  - The osquery ATC `platform` now includes `windows`.
- Delivery docs: `docs/fleet-osquery.md` gains the Windows + Intune + Tanium sections.

## [0.30.0] — fleet Tier-2 attribution: egress RDAP + JA3 (2026-08-18)

Extends `fleet-scan`'s observed-egress surface from "a connection exists" toward
"who it talks to" and "what client is talking" — both as **opt-in** flags so the
bare `fleet-scan --egress` keeps its structural no-egress guarantee.

### Added
- **`fleet-scan --egress --rdap` — IP → operator/jurisdiction attribution.** Resolves
  the observed upstream IPs (reverse-DNS + RDAP) to a jurisdiction/operator pointer,
  reusing the hardened `probes.network` RDAP path (SSRF denylist, PRC-ASN heuristic,
  vCard fallback) and joining the PTR to `corpus.py`. New `probes.network.attribute_ip`
  (single-IP, SSRF-guarded, never raises) + `fleet/egress_attr.py` (orchestration,
  bounded IP cap with dropped-count surfaced, deterministic). Bare `--egress` stays
  no-egress; `--rdap` is the explicit-egress opt-in (mirrors `catalog` vs
  `build-catalog`). A PRC-pointing upstream trips `--exit-code`.
- **`fleet-scan --ja3` — JA3 client-TLS fingerprint.** Passively captures TLS
  ClientHellos (`tcpdump`) and computes JA3 (Salesforce spec: field order, GREASE
  strip, MD5) to spot a known interception proxy or an unexpected second client
  fingerprint to a sanctioned upstream (corroborates `--trust-store`). New pure
  `fleet/ja3.py` (bounds-checked ClientHello parser, minimal pcap reader for
  Ethernet/loopback/raw link types, JA3 compute). `KNOWN_JA3` ships **empty** and is
  operator-populated from golden captures — an unknown JA3 is never auto-suspicious,
  and a wrong "this is curl" is worse than "unknown".

### Invariants held
- Both signals are **SUB-CONFIRMED pointers (`measured:false`)**, never measured
  verdicts. Both are **gated on `--i-am-authorized`**. `--ja3` needs root + `tcpdump`
  and **refuses (exit 3), never false-cleans**, when it can't capture — same contract
  as the connection-table and trust-store collectors.

## [0.29.0] — first-party provenance join in the catalog (2026-08-18)

### Fixed
- **Catalog first-party attribution.** models.dev omits the `api` base URL for ~26
  providers (openai, anthropic, google, mistral, cohere, xai, and several
  aggregators), so their catalog rows carried a blank provenance/jurisdiction
  column. `catalog.py` now falls back to a canonical host per known provider id
  (`_PROVIDER_ID_HOST`), keyed only to hosts that already exist in `corpus.py`, so
  first-party vendors resolve their origin (Anthropic/OpenAI/Google → US,
  Mistral → EU) and known aggregators resolve `jurisdiction:unresolved`. Still a
  SUB-CONFIRMED pointer (`measured:false`), never a measured verdict — the join
  only says who a host is registered to, not which model actually served.
- Regenerated the bundled `data/catalog.json` snapshot with the fallback applied.

## [0.28.0] — LLM-API catalog + guided assessment + friendlier UI (2026-08-14)

First PyPI release. Assigns the accumulated unreleased work a version.

**PyPI distribution name: `llm-provenance-probe`** (`pip install llm-provenance-probe`).
`provenance-probe` itself is too similar to the pre-existing PyPI project `provenance`
for PyPI to allow, so the distribution is namespaced. The **CLI command stays
`provenance-probe`**, the import package stays `provenance_probe`, and the GitHub repo
stays `provenance-probe` — only the `pip install` name differs.

### Added
- **LLM-API catalog — a searchable running table of inference APIs, their models,
  and model-card facts, joined with this project's provenance/jurisdiction.**
  - `provenance-probe catalog [query] [--cn/--jurisdiction/--kind/--open-weights/
    --modality/--json]` — search offline: API URL, model, context window, price,
    modalities, open-weights, **plus a provenance/jurisdiction column** (from the
    `corpus.py` join) that no generic model catalog has.
  - `provenance-probe build-catalog [--out/--input]` — generates the catalog from
    `models.dev` (MIT, `github.com/sst/models.dev`) by joining each provider's `api`
    host to `corpus.py` via the same exact-or-subdomain matcher the registry/fleet
    scanner use. The one explicit egress (like `build-reference`); search stays local.
  - `serve` **`/catalog`** page — a searchable table (external field values all
    `html.escape`d); linked from the nav. Parsed once and cached; never shipped to
    the browser.
  - New pure `provenance_probe/catalog.py` (build/join/flatten/search) + a bundled
    `data/catalog.json` snapshot (184 providers / 6,293 models at first build).
  - **Honesty:** every row's provenance is a **SUB-CONFIRMED pointer** (who a host is
    registered to), never a measured verdict — `assess` is for that; aggregators
    resolve jurisdiction but not provenance; unknown-open-weights is tri-state (a
    `--closed-weights` filter never lumps in "unknown"). The observatory will own the
    nightly refresh + signing (next increment).

### Changed
- **Friendlier local web UI (`serve`).** The home page gains a plain-language
  "Start here — three steps" strip (Quick check → Deep scan → Watch for swaps),
  each linking to where it happens. The probe form now validates inline and shows
  plain, actionable messages instead of `alert()`s and raw stack traces: a blank
  endpoint no longer fires a request; a failed run renders a friendly "that check
  couldn't finish" card with a **try again** button; and dropped-connection cases
  say the *local* probe is unreachable (accurate — those calls hit 127.0.0.1, not
  the target). Server-side, a new `_friendly_error()` maps common assessment
  failures (missing endpoint address, invalid request-template JSON) to plain
  sentences — presentation only; the full `traceback` is preserved and no error is
  swallowed. Wizard cross-origin/invalid-JSON refusals reworded to plain, actionable
  copy. No change to the auth gate, same-origin gate, consent tokens, cookie/secret
  handling, or egress logic; all user text stays `html.escape`d / `textContent`.

### Security
- **Hardening (incidental):** the reworded run-error branch now escapes the server-sent
  `status` through the page's `esc()` before writing it to the DOM, closing a latent
  unescaped-`innerHTML` write that previously rendered the status raw inside a `<pre>`.

### Added
- **`.claude/agents/provenance-guide.md`** — a repo-tuned interactive guide agent that
  walks a user through a full assessment end-to-end and does the non-interactive work
  itself. Phase 1: a no-auth passive scan (`clientsrc`, catalog read, `network`/RDAP) →
  an honest Face/Brain-hints/Pipeline summary → an observatory **watch-list entry**
  (`authorized: false`, NO VERDICT). Phase 2 (authorization-gated): a two-phase login
  capture (login handed off to the human — no password handling), a tokenizer-only
  `assess`, and set-up of continuous model-switch detection (`watch --pin/--once`,
  launchd/systemd, `session`, `sentinel`). Bakes in the invariants: authorization gates
  all active probing, passive yields pointers not verdicts, degraded coverage is never
  upgraded, and named-vendor adverse verdicts are handed to a human (Gate 1), never
  auto-published. Includes a plain-language **"When something goes wrong"** recovery
  table so the guide turns each real failure (missing venv, replay-unsafe capture,
  login walls, INDETERMINATE/degraded coverage, missing authorization, git push
  conflicts, YAML slips, RDAP hangs) into a clear next step instead of a traceback.

## [0.27.0] — Provider-attribution registry generator (from corpus.py)

### Added
- **`provenance-probe build-registry`** — generates the public provider-attribution
  registry (`domain → operating_entity → jurisdiction → kind → confidence`)
  deterministically FROM `corpus.py`, which stays the single source of truth. The
  registry is exact-or-subdomain, most-specific-wins; substring-only corpus keys
  (`openai-proxy`, `bedrock-runtime`) are excluded and counted. Entries are
  sub-CONFIRMED static pointers, never a measured verdict; aggregators carry
  `jurisdiction: unresolved`.
- **`provenance-probe verify-registry <file>`** — a drift gate that fails if a
  checked-in/published registry no longer matches a fresh generation. Compares the
  WHOLE document (not just entries), so a tampered honesty `note` or a `match` field
  flipped to `substring` is caught — the integrity gate until the observatory signs it.

Increment 1 of the signed public registry: signing (cosign/Rekor) and publication
are a follow-on in provenance-observatory, which owns the signing machinery.

## [0.26.0] — Fleet Tier-2: observed egress / loopback fan-out shape

### Added
- **`provenance-probe fleet-scan --egress`** — reads the OS connection table
  (`lsof -n`, no DNS) for the structural router shape, complementing the config
  scan's `configured` tier with an `observed` one. Two signals, both name-independent:
  **router fan-out** (a loopback/wildcard listener fanning out to ≥N distinct
  upstream hosts — `--min-upstreams`, default 8) and **routed-via-gateway** (a
  process connected to a known local-gateway port, `:20128`/`:4000`). macOS + Linux.

### Security
- **No egress** — reads the connection table only; upstream IPs are reported, never
  resolved (IP→operator attribution needs RDAP = the prober's authorized path; JA3
  needs pcap — both deferred and documented).
- **Inert without `--i-am-authorized`** (per-process connections are a privacy surface).
- **Never a silent false-clean** — refuses (exit 3) on an unsupported OS or an `lsof`
  read error (including exit-1-with-no-output); a zero-finding **unprivileged** scan
  is qualified "current user's sockets only" in the headline/report/JSON, since a
  router running as root or another user is invisible to a non-root `lsof`.
- Port 4000 (a common dev port) is hedged, not auto-accused; `--out` is 0600 / `O_NOFOLLOW`.

## [0.25.0] — Fleet trust-store watch: transparent-MITM root-CA detection

### Added
- **`provenance-probe fleet-scan --trust-store`** — watches the host's trusted root
  CAs for transparent interception. A MITM-capable proxy must install a root CA;
  this enumerates admin/user-added roots, fingerprints each (SHA-256 of the DER,
  stdlib — no `cryptography` dep), and flags any not in an operator-supplied
  baseline, escalating known interception tools (mitmproxy/Charles/Burp, matched on
  the DER commonName). Capture a golden baseline with `--print ca-baseline`.
- macOS + Linux; no-egress (reads local trust stores via the `security` CLI / cert
  dirs, no network). Report + `--json` + `--out` (0600 / `O_NOFOLLOW`).

### Security
- **Inert without `--i-am-authorized`** — reading the system trust store is a
  privacy/labor-review surface, so both `--trust-store` and `--print ca-baseline`
  refuse until documented policy is attested.
- **Never a silent false-clean** — an unsupported OS (Windows) or an unreadable
  store (`security` errored) refuses with exit 3 ("host not certified clean")
  rather than reporting a green result; a genuinely empty admin-CA dir is clean.
- **Honest limits** — attribution of the *installing process* is out of scope (the
  macOS keychain records no PID); that needs an EDR/osquery event hook.

## [0.24.1] — Fleet posture: prevention-first framing + starter allowlist (T7)

### Added
- **`provenance-probe fleet-scan --print allowlist-template`** emits a starter
  egress allowlist (sanctioned first-party hosts + commented placeholders for cloud
  tenants and one sanctioned gateway) for an operator to fork into their own policy.
- **`docs/fleet-posture.md`** — the prevention-first posture: the control is an
  egress allowlist + one sanctioned gateway, and `fleet-scan`'s
  `allowlist holding: N sanctioned, M drifted` headline is the posture's health,
  not a rogue-developer list. Documents the gateway blind spot honestly (upstream
  resolution is loopback-only + config-dependent; a non-loopback sanctioned gateway
  hides its backend — probe it directly).

## [0.24.0] — Fleet detection: find AI router/gateway tools on a host

### Added
- **`provenance-probe fleet-scan` — no-egress, read-only host forensics.** Discovers
  where local agent CLIs (Claude Code, Codex, Continue, aider, Cursor) are pointed by
  scanning config files + env for a redirected `base_url`, and classifies each endpoint
  against an operator allowlist plus bundled `corpus.py` attribution into honest buckets
  (`sanctioned` / `off-allowlist-attributed` / `off-allowlist-unattributed` /
  `aggregator-unresolvable` / `gateway-upstream-unresolved`). Report headline is
  allowlist-drift. Flags: `--allowlist`, `--json`, `--out`, `--no-redact`, `--exit-code`.
- **Gateway-config resolution (the localhost blind-spot fix).** When a `base_url` points at
  a local gateway (OmniRoute `localhost:20128`, LiteLLM), fleet-scan parses the gateway's
  own config to resolve the real upstream and attributes THAT — so the founding OmniRoute
  case is caught instead of shrugged off as "localhost".
- **osquery delivery (T6).** `fleet-scan --sqlite <db>` writes a `fleet_findings` SQLite
  table that osquery reads via ATC; `--print {launchd,systemd,cron,osquery-atc}` emits the
  scheduled-scan unit or the ATC config. Recipe in `docs/fleet-osquery.md`.

### Security
- The fleet package makes **no network calls** — a structural boundary: pure gateway
  knowledge lives in `provenance_probe/gateways.py`, which both `fleet/` and the
  network-bearing `omniroute.py` import, so `fleet/` never imports the egress path.
- Attribution is a **sub-CONFIRMED static pointer** (`measured=False`), never collapsed into
  a measured provenance verdict. Exact-or-subdomain host matching rejects suffix attacks
  (`api.deepseek.com.evil.test`).
- Credentials in a `base_url` (`user:pass@`) are stripped at collection; reports and the
  SQLite DB are written `0600` with home paths redacted, and the DB write refuses to follow
  a symlink (`O_NOFOLLOW`).

## [0.23.1] — Copy fixes: extension install honesty + always-on now shipped

### Changed
- **Capture-extension copy no longer oversells "one-click."** The landing card and
  the import page now describe the extension as a load-unpacked developer-mode install
  (a one-time ~2-minute setup, steps in the README) instead of a store one-click, and
  the link reads "Get the extension & install steps." The link target is unchanged.
- **"Always-on watching is coming" copy updated — it shipped (P3).** The landing watch
  card, the `/watch` "keep this tab open" banner, and the shared `explain.py`
  watching primer now point to the real local `watch` daemon (runs on a timer, installs
  under launchd/systemd) instead of promising a future "background watcher."

## [0.23.0] — Local always-on `watch` daemon (P3 / #66)

### Added
- **`provenance-probe watch` — an unattended, always-on model-swap daemon.** The
  local counterpart to the tab-bound hosted watch (P2 #64) and the real-time
  `sentinel` proxy: it re-probes your OWN configured targets on a schedule and
  raises a loud LOCAL alert the moment a served model silently changes — no
  browser, no open terminal, survives logout.
  - **Modes (mutually exclusive):** `--once` (single pass; **exit 2 on ANY
    drift**, 1 on operational error, 0 clean/seeded — the cron/launchd
    primitive), `--loop` (run forever on a timer with jitter; clean
    SIGINT/SIGTERM shutdown that finishes the in-flight target and exits 0;
    one target's exception never kills the loop), `--pin` / `--reset-baseline`
    (re-baseline to the current fingerprint), and `--print-launchd` /
    `--print-systemd` unit-file generators (Windows documented via Task
    Scheduler).
  - **Per-target baseline store** at `~/.provenance-probe/watch/<slug>/`
    (`baseline.json` = the FULL bundle, `state.json`, `switches.jsonl`). First
    run seeds the baseline (no drift), like the observatory's first-run seed;
    later runs `monitor.diff(baseline, current)`.
  - **Loud, secret-free alerts on drift:** a stderr **MODEL SWITCH DETECTED**
    banner with the changes table, an appended `switches.jsonl` record, a
    best-effort desktop notification (`osascript` / `notify-send`,
    feature-detected, never fatal), and an optional `--webhook <url>` POST
    (10 s timeout, failure logged not fatal). Keys/cookies read from local
    config **never** appear in any sink — payloads are built from the diff +
    fingerprints only, and every transport error is routed through
    `client._safe_err`.
  - **Path-traversal defense:** the per-target directory name is slugified to
    `[A-Za-z0-9._-]`, rejects `.`/`..`/empty, and is `realpath`-contained inside
    the watch root (same discipline as the `/media` route).
  - Pure-stdlib scheduling (no APScheduler / heavy deps). `--behavioral` /
    `--deception` are off by default for a fast, cheap re-check (tokenizer, wire
    and determinism — the strongest swap signals — stay on).

### Changed
- **New `provenance_probe/assess.py` — one source of truth for a "bundle".**
  Extracted `assess_target(target, opts) -> bundle` (full multi-layer bundle
  **incl. `score`, `user_warning` AND `fingerprint_id`**) and refactored BOTH
  `cli.cmd_assess` and the `serve.py` assess worker to call it. Previously
  `cmd_assess` omitted `fingerprint_id` and `serve` computed it inline; now the
  CLI, the web service and the daemon are byte-identical, so a `watch` baseline
  is directly comparable to `serve` / the Observatory. Behavior-preserving
  (full existing suite stays green; a fingerprint-parity test pins it).

## [Unreleased] — MV3 browser extension for one-click hosted capture (P2 / #54)

### Changed
- Added a **`/favicon.ico` + `/favicon.svg` route** serving the lie-detector
  SVG, so pages not rendered through `ui.doc()` (the agent flight-recorder
  report) and direct browser favicon requests resolve it instead of 404-ing.
- The web UI's **Observatory** nav link now defaults to the live public
  observatory (`https://lobster-shrimp.github.io/provenance-observatory/`) and
  opens in a new tab; override with `PROVENANCE_OBSERVATORY_URL` to point at a
  local observatory instead.
- Added a **lie-detector favicon** (a coral polygraph waveform on the deep-green
  brand square) inlined as an SVG data-URI in the shared page shell, so it needs
  no route and does not hit the hosted auth gate.

### Added
- **`extension/` — a Manifest V3 Chrome extension**, a one-click alternative to
  the HAR-upload path (#53). It captures the target app's chat request in the
  **user's own browser/session** (via the DevTools network API, scoped to the
  single inspected tab and only while explicitly armed), sanitizes it with the
  **same** header allow-list / registrable-domain binding / chat scorer / cookie
  consent as the built-in uploader, and POSTs the **same** normalized
  `{name, prompt_hint, cookie_consent, request, response}` payload to a
  user-configured instance's `POST /wizard/capture-import`. Purely a **second
  front-end** onto the existing #53 ingest — **no server-side browser** (no SSRF)
  and **no server contract change** (`serve.py` untouched).
  - Minimal MV3 permissions — `storage` + `declarativeNetRequestWithHostAccess`
    only; **no** `<all_urls>`, `webRequest`, `cookies`, `tabs`, `activeTab`,
    `scripting`, or static `host_permissions`. Host access to the single
    configured instance origin is requested at runtime. Every permission is
    documented in `extension/README.md`.
  - Credentials (instance URL + Basic auth) live only in `chrome.storage.local`,
    are read only by the background worker, attached only to the configured
    instance over HTTPS (`credentials: "omit"`), and never logged. No vendor keys.
  - Shared pure logic in `extension/lib/sanitize.js` with standalone
    `node --test` unit tests (payload assembly, header/cookie sanitization, XSS
    escaping); packaged into a Chrome Web Store zip by
    `.github/workflows/extension.yml` (**build only — not published**).
- **The extension versions independently** (`extension/manifest.json` /
  `extension/package.json` at `0.1.0`); this change ships **no Python code
  changes**, so the `provenance_probe` package version is intentionally unchanged.

## [0.22.0] - 2026-08-06 — Client-side "watch a service for a silent swap" (P2 / #64)

The mission's second half — **watching** a service over time — made real and
**self-service on BOTH hosted and local**. A server-side daemon can't run on the
scale-to-zero, single-credential, no-stored-keys hosted demo, so the watch loop
lives in the **user's own browser tab**: the API key never leaves the browser and
there is no server persistence.

### Added
- **A `/watch` page** (rendered via `ui.doc()`): configure a target, pin a baseline
  fingerprint, and re-check it on a timer (5 / 15 / 60 min, with a 5-min floor and a
  little jitter). Each tick reuses the **existing** endpoints with **no new detection
  logic** — `POST /api/assess` → poll `GET /api/run/<rid>` → `POST /api/monitor`
  (the same `monitor.diff` the CLI and observatory use). On drift it raises a **loud,
  unmissable alert**: a red banner, a browser-tab **title** change
  (`⚠ MODEL SWITCH — provenance-probe`), an optional permission-gated desktop
  **Notification**, and a timestamped entry in a live **Switches** log.
  **"Accept new baseline"** re-pins to the current fingerprint and stops re-alerting.
- **Entry points**: the landing "Watch a service for a silent swap" CTA now opens
  `/watch`; a **"Watch this"** button appears on a finished probe result; and each
  **Local-run-history** row gets a **watch** link. Each pre-fills the target
  (`base_url`/`model`/paths) — **never** the API key or session cookie (those would
  leak into browser history / server logs from a URL).
- **`/api/run` now also returns `fingerprint_id`** (the same value `/api/history`
  already exposes) so the client can display the pinned baseline id without a second
  round-trip. Purely additive; no secret is added to the response.

### Security properties (verified by tests + review)
- **The API key is held in the browser only** — in memory for the life of the tab,
  posted **solely** to `/api/assess` for each probe, and **never** written to server
  storage or to `localStorage`/`sessionStorage`, and never placed in a URL. The
  server continues to store only `base_url` in its run record and never echoes the
  key.
- **No DOM-XSS**: every probe-derived value (`monitor.diff` change severity/field/
  detail/implication, fingerprint ids, timestamps) and user string is HTML-escaped
  before it touches `innerHTML`; the Switches log uses `textContent`. (Does not
  reintroduce the #53 echoed-value DOM-XSS.)
- **Fast, cheap re-checks**: the watch spec defaults **behavioral + deception OFF**
  (fingerprint drift is a tokenizer+wire signal), so a re-check is quick and low-cost.
- **Egress guard intact**: each re-probe goes through `/api/assess`, so in
  public-hosting mode (`PROVENANCE_PROBE_BLOCK_PRIVATE`) a private target is still
  refused. **No new server endpoint, no new outbound request path** — nothing depends
  on a server daemon or stored keys, which is exactly why it works on the hosted demo.
- **The async poll can't wedge**: per-probe polling is bounded (attempt ceiling,
  always clears its interval) and a `busy` guard prevents overlapping probes.

### Security
- **Closed a credential-leak path** surfaced while hardening this feature (which
  runs unattended for hours, re-sending the key every tick): a pasted API key or
  session cookie carrying a stray newline / leading-trailing whitespace (a common
  clipboard/`.env` artifact) made `requests` raise `InvalidHeader` with the **raw
  secret in the exception message**, which the client swallowed into `Response.err`
  and then **persisted verbatim** into the on-disk report (served by
  `GET /report/<name>`). Fixed at the root in `Target.headers()` by sanitizing every
  caller-supplied header value (strip surrounding whitespace, drop control
  characters) so the secret can never reach header validation; added defense-in-depth
  redaction of any credential value from `Response.err` in `client.py`; and the watch
  form trims the key client-side. Protects the pre-existing `/api/assess` and CLI
  paths too — not just the new watch loop.

### Changed
- `explain.py` "Watching for model swaps" primer rewritten for the client-side watch
  (key stays in your browser, keep the tab open, always-on options: run locally — a
  background watcher is coming — or use the Observatory). Rendered on `/help`.

### Out of scope (P3)
- The **local always-on background watcher** + registry + webhook. P2 is browser-only.

## [0.21.0] - 2026-08-06 — Make the mission clear + automated capture discoverable (P1 / #62)

Content/UX only — **no engine, scoring, egress, auth, or route behaviour changed.**
The goal: a first-time, non-technical visitor should grasp within seconds that the
tool catches AI services that silently swap the model behind an API, see the two
things they can do, and know real services are being watched live.

### Added
- **Plain-English mission hero on the landing (`/`)** — headline *"Is the AI you're
  paying for still the AI you're getting?"* plus a jargon-free explanation of the
  silent-swap threat. The hero copy is the SINGLE source in `explain.py`
  (`MISSION_HEADLINE` / `MISSION_BODY`), shared with `/help` so the two never drift,
  and injected into the page escaped.
- **The two jobs named as the primary choices** — *"See what's answering right now"*
  (anchors to the existing probe form) and *"Watch a service for a silent swap"* (a
  prominent CTA to the capture/watch path). The watch card is honest that unattended,
  always-on watching is a later phase; for now it routes to capture + the Monitor
  compare panel.
- **Observatory "see it live" card** — a prominent LINKED card (not a heavy iframe)
  to the public observatory
  (`https://lobster-shrimp.github.io/provenance-observatory/`, override with
  `PROVENANCE_OBSERVATORY_URL`), opened in a new tab with `rel="noopener noreferrer"`.
- **Two new `/help` sections sourced from `explain.py`** — *"Why this matters"* (the
  silent-swap threat in non-technical terms, `WHY_THIS_MATTERS`) and *"Watching for
  model swaps"* (`WATCHING_PRIMER`), rendered through the escaping `_prose_section`
  helper.

### Changed
- **Capture-page UX pass** — the `/wizard` chooser and `/wizard/import` page now lead
  with the **one-click browser extension** (`extension/`, #54) as the recommended
  path, with the manual HAR recording kept as the no-install fallback. **Every route,
  form field id, JS behaviour, and the #53 `/wizard/capture-import` contract are
  preserved** (the extension link is a trusted internal literal, injected escaped).
- Landing hero styling: added `.jobs` / `.job` two-choice cards and the `.obs`
  Observatory linked-card styles to the shared design system (`ui.py`).

## [0.20.0] - 2026-08-05 — In-product documentation: plain-language `/help`, layer tooltips, verdict explainers

### Added
- **`provenance_probe/explain.py` — a single source of truth for all explainer
  copy.** `LAYERS` maps each evidence layer (network, wire, tokenizer, logprob,
  behavioral, deception, latency, artifacts) to a plain-language
  `{title, what it measures, what a "hit" means}`; `VERDICTS` explains the two
  independent axes (provenance = whose weights; jurisdiction = who runs it and
  where), each enumerating the **same five tiers** the scorer emits
  (`CONFIRMED / LIKELY / INDETERMINATE / UNLIKELY / NO EVIDENCE`) so a reader
  never meets an undocumented verdict word. `FLOWS`, `FAQ` and a worked
  `EXAMPLE` (a Chinese model on US servers = CONFIRMED provenance + UNLIKELY
  jurisdiction) live here too. Every downstream surface reads from this module —
  no copy is duplicated.
- **A `/help` page (`GET /help`)** rendered via `ui.doc()` from the module above:
  a plain-language tour of each flow (Live probe, Add a target / capture, Agent
  board, Monitor, Observatory), a "What each check does" table from `LAYERS`, a
  "What the verdict means" section from `VERDICTS` with the two-axis example, and
  a short privacy FAQ ("Do you store my key?", "Is my data sent anywhere?",
  "What if it says INDETERMINATE?"). Behind the global auth gate like every route.
- **A shared `ui.nav()` helper** carrying the standard poster nav incl. a **Help**
  link; `ui.header()` falls back to it when a page passes no custom nav, so Help
  is reachable from **every** page. The home nav gains the Help link alongside
  Observatory.
- **In-context explainers on the technical report** (`report.py`): each Signals
  "Layer" cell is now an `<abbr title=…>` sourced from `LAYERS` (hover for a
  one-line description; escaped for the attribute context), plus a "New here? see
  the help page" pointer. The probe form's Advanced options gains a short
  "these are optional — every check is explained on the help page" note.
- **Two demo-GIF slots** reusing the existing `<figure class="demo">` +
  `/media/` + caption-fallback pattern: `/media/probe-demo.gif` on the live
  probe page ("watch a probe run") and `/media/agent-demo.gif` on the agent
  board. The GIF files are dropped in by the maintainer later; until then the
  `<img>` 404s and its `onerror` hides it, leaving the caption.

### Notes
- **Additive/clarifying only.** No route, form field id, JS behavior, scoring or
  verdict path changed; the auth gate, egress guard, `/media` hardening and
  same-origin CSRF checks are untouched. Verified by `provenance-reviewer`
  (APPROVE) and `security-reviewer` (APPROVE — no findings).

## [0.19.0] - 2026-08-04 — Non-technical capture wizard: method chooser, plain-language guides, `/media` demo route

Restyle-and-clarify pass making the "add a target / capture" flow usable by a
**non-technical visitor**. No route, form field id, JS behavior, egress guard,
auth gate, same-origin gate, or the #53 `/wizard/capture-import` contract
changed — this is presentation only, built entirely on the shared `ui.doc()`
design system (no new dependencies, no framework).

### Added
- **A "which method is right for you?" chooser** at the top of `/wizard`: three
  plain-language cards — (A) "I have a plain API address" → the paste/identify
  path, (B) "It's a website I log into" (the **recommended, visually-emphasized**
  path) → the no-install browser capture / HAR import, and (C) "I already have a
  cURL or HAR" → the paste box. Each card says in one sentence when to use it and
  what it needs, and carries its primary action.
- **A read-only `GET /media/<path:name>` route** serving static demo media (GIF/
  PNG) from a new `provenance_probe/media/` package, so the capture guides can
  embed short walkthrough clips. Hardened against path traversal / LFI: it
  rejects any `..`/absolute/drive-letter/NUL path segment up front, resolves
  symlinks with `realpath()` and requires the result stay **inside** the media
  dir, allowlists a small set of media extensions/mimes, opens the final file
  with `O_NOFOLLOW` and requires a regular file (closing the realpath→open TOCTOU
  window), and sends `X-Content-Type-Options: nosniff`. It serves the bytes
  itself (no `send_file`, no directory listing) and stays **behind the global
  Basic-auth gate** like every route. `provenance_probe/media/*` is registered as
  package-data; a 1×1 `placeholder.gif` is committed so the route/tests work, and
  the real demo GIFs are dropped in later by the maintainer.
- **Embeddable demo-GIF slots** on `/wizard/capture` and `/wizard/import`: a
  `<figure>` whose `<img>` points at `/media/capture-guide.gif` /
  `/media/capture-import.gif` and, if the file is absent, hides itself via
  `onerror` and leaves a graceful caption fallback.
- `tests/test_capture_ux.py` — the `/media` route (serves an existing file, 404s
  a missing one, refuses percent-encoded/absolute traversal and non-allowlisted
  types, stays behind the auth gate), the chooser + capture/import step content
  rendering, and that `capture_guide.guide()` still returns coherent numbered
  steps.

### Changed
- **Every capture surface rewritten with big numbered visual steps and
  plain-language explainers.** `/wizard/capture` and `/wizard/import` now each
  open with a "What this does" line, an **"Is my login safe?"** reassurance
  (login never recorded / session cookie only sent to its own host / nothing
  leaves until you approve), a "What happens next" section, and 3–6 numbered
  steps with the exact click path. Jargon reduced (e.g. "the developer Network
  panel" instead of "DevTools → Network").
- Added `.chooser`, `ol.steps` (numbered step chips), and `figure.demo` classes
  to the shared `ui.py` stylesheet so the new surfaces stay on-system.
- Aligned the package version (`provenance_probe.__version__` and the
  `pyproject.toml` version were `0.18.0`/`0.18.2`) to **`0.19.0`**.

## [0.18.0] - 2026-08-04 — "Provenance" design system for the serve web UI

### Added
- **`provenance_probe/ui.py` — one shared "Provenance" stylesheet + page shell.**
  The DESIGN.md tokens (warm cream `--paper`, near-black `--ink`, deep-forest
  `--green` poster band, terminal-green `--green-ink` on the dark `--green-2`
  evidence card, and the verdict accents `--coral`/`--amber`/`--green`) as CSS
  custom properties, plus a Google Fonts `<link>` for **Fraunces** (display),
  **Geist** (UI), and **Geist Mono** (evidence/vectors). Exposes `header()`,
  `doc()`, and `verdict_color()` so both the live service and the standalone HTML
  report render from ONE source and never drift.

### Changed
- **`serve.py` — every server-rendered page now uses the shared shell.** The main
  probe/landing page, the agent board (`_AGENT_FORM`), the add-target wizard
  (`_WIZARD_FORM`), the consent (`_WIZARD_CONSENT`), preview (`_WIZARD_PREVIEW`),
  the `_wiz_page` helper, and the HAR-import page (`/wizard/import`) dropped their
  ad-hoc inline CSS in favour of a green poster header + cream body + one hot
  accent. The landing page leads with a Fraunces hero ("A lie detector for AI
  APIs") over a single clean form card.
- **`report.py` — the results HTML is now a verdict-first lab report.** A large
  Fraunces verdict headline in the verdict colour + a plain-English fact, a
  `VERDICT` stamp, then evidence as an editorial two-column layout: the
  tokenizer-match table as terminal-green mono on the dark card, big serif stat
  numbers, a signals table, a network & jurisdiction row, and a footer strip with
  artifact id, timestamp, engine version, target model, and a report hash.
- **The verdict → accent colour is driven by the real result** (`ui.verdict_color`
  / `report._lead_verdict`): `NO EVIDENCE`/US → green, `LIKELY` → amber,
  `CONFIRMED`/CN → coral. Never hardcoded per page.
- Corrected the stale `provenance_probe.__version__` (`0.3.0` → `0.18.0`) so the
  report's "analysis engine" footer reports the true version.

### Unchanged (restyle only — verified)
- Every route, form-field `name`/`id`, and client-side JS behaviour is preserved
  byte-for-byte: the `authorized` checkbox, the `/api/assess → run_id →
  /api/run/<rid>` polling, the wizard/import HAR JS (including its `esc()`
  DOM-XSS guard), and the `_same_origin_ok` / basic-auth / egress / cookie-origin
  gating. All user/measurement-derived strings remain HTML-escaped.

## [0.17.0] - 2026-08-04 — Hosted no-install capture: client-side HAR import (#53)

### Added
- **`provenance_probe/capture_import.py` — client-side capture normalizer.** Turns
  a client-supplied payload `{request:{method,url,headers,body},
  response:{status,headers,body}, prompt_hint}` (or a `{flows:[…]}` candidate
  list) into the internal `capture_proxy.Flow` / `wizard.Captured`. It REUSES the
  existing capture primitives — `capture_proxy.select_chat_flow` and
  `flow_to_captured` (which themselves use `detect_response_mode` /
  `sse_reassemble`) — so there is exactly ONE definition of "which request is the
  chat call" and how a response is fingerprinted; no new synthesis logic. Pure /
  no-I/O: it only reshapes an already-captured exchange.
- **`GET /wizard/import` page + `POST /wizard/capture-import` endpoint in
  `serve.py` — no-install, hosted-safe capture.** The user's OWN browser records
  the request (already logged into the target app), the HAR is parsed
  **client-side**, filtered to candidate JSON POSTs on the app's own registrable
  domain, auto-picked via `prompt_hint` (or chosen), sanitized (essential headers
  only; Cookie included only on explicit consent), and **only the single chosen
  flow is uploaded** — the full HAR with all its cookies never leaves the machine.
  The endpoint feeds the existing `flow_to_captured → synthesize → dry-run`
  pipeline and returns the synthesized target for review. A guided DevTools →
  Export HAR walkthrough is included; the wizard advertises this path in
  public-hosting mode (where server-side browser capture is refused).

### Security (load-bearing)
- **`/wizard/capture-import` is ALLOWED under the egress guard**
  (`PROVENANCE_PROBE_BLOCK_PRIVATE`), unlike `/wizard/capture-run` which stays
  refused. It is SSRF-safe by construction: it drives **no** browser and makes
  **no** arbitrary fetch at import time. The only outbound request is the optional
  dry-run replay, which goes through the ONE egress-guarded `Client` session — a
  target resolving to a private/metadata IP is refused before a socket opens.
- **Cookie handling:** a captured session cookie is used for an **ephemeral single
  dry-run and is NEVER persisted** on a guarded/public instance (no authed
  web-app target is saved there). Explicit consent must **name the destination
  host**; a cookie can only ever be replayed to the host it was captured from
  (`_cookie_origin_ok`, plus a captured-host cross-check before the cookie-bearing
  egress). The cookie value is never reflected into any response body.
- **CSRF / auth:** the endpoint requires `Content-Type: application/json` (415
  otherwise) and a localhost same-origin (`_same_origin_ok`, 403 otherwise),
  matching the other mutating wizard POSTs, and is covered by the global
  `before_request` basic-auth gate.
- The `/wizard/import` result page **HTML-escapes** every server/derived string
  (note / warnings / error / target JSON) before `innerHTML`, and renders
  HAR-derived values via `textContent`, so a malicious HAR cannot inject script
  (DOM-XSS closed in review).
- **OFF-path unchanged:** with the env flag unset, behavior is byte-identical; the
  only pre-existing-path change is `_capture_ui()` offering the import link
  instead of nothing when the guard is enabled.

### Tests
- **`tests/test_capture_import.py` (+14).** Normalizer (valid→Flow; missing
  request/response→clear error; non-JSON body→template adapter; SSE→reassembled;
  picks chat flow via `prompt_hint`), endpoint guards (auth-gated; JSON required;
  refuses without cookie-consent; cookie origin-bound; egress guard blocks a
  private dry-run host with no socket opened; ALLOWED while `/wizard/capture-run`
  is REFUSED under the same guard; page renders + escapes under the guard), and
  integration (a z.ai-shaped capture → import → synthesize → dry-run yields a
  usable target; a stateful/HTTP-400 capture → the existing "stale, re-capture"
  message with no false save).

## [0.16.0] - 2026-08-04 — Gated public-hosting mode: SSRF egress guard + basic auth (#51)

### Added
- **`provenance_probe/egress.py` — SSRF egress guard (`GuardedAdapter`).** A
  `requests` `HTTPAdapter` mounted on the shared probe session ONLY when
  `PROVENANCE_PROBE_BLOCK_PRIVATE` is truthy. It resolves the host the socket will
  actually connect to and **fails closed** if any answer is
  loopback / private (RFC1918 + ULA `fc00::/7`) / link-local / reserved /
  multicast / unspecified or the cloud-metadata IP `169.254.169.254`, and also on
  zero answers or a DNS failure. Literal-IP targets are validated directly.
  **DNS-rebinding defense:** the connection is *pinned* to the validated IP while
  the original `Host` header and TLS SNI + certificate hostname are preserved
  (`server_hostname`/`assert_hostname` stay the real name) — TLS verification is
  never weakened. Covers `chat` + its temperature retry + `raw_post` +
  `list_models` + redirects (all reuse the one guarded session, so a 3xx to an
  internal host is re-validated). When a proxy is configured the **proxy** host is
  validated (a private proxy is refused); `trust_env` is disabled so an ambient
  `HTTP(S)_PROXY` can't reroute the probe session.
- **Basic-auth gate in `serve.py`.** When `PROVENANCE_PROBE_BASIC_AUTH="user:pass"`
  is set, a `before_request` hook requires HTTP Basic auth on **all** routes
  (constant-time compare via `hmac.compare_digest`,
  `WWW-Authenticate: Basic realm="provenance-probe"` on 401). Parsed once at
  startup; a malformed value (no colon) fails loudly rather than silently
  disabling the gate.
- **`deploy/hf-space/README.md`** — Hugging Face Space file (YAML frontmatter
  `sdk: docker`, `app_port: 8770`) plus a PRIVATE→verify→PUBLIC deploy runbook:
  set both gates as Space secrets, hold ZERO vendor API keys (bring-your-own),
  and the "401 still reads as Running on HF" liveness note.
- Tests: `tests/test_egress.py` (classification incl. CGNAT/non-global,
  fail-closed, guard mount/unmount, the load-bearing rebinding/split-horizon pin
  for both the target and proxy legs, private-proxy refusal, and cross-surface +
  redirect + client-source + wizard-detect re-validation integration) and
  `tests/test_auth_gate.py`.

### Security (security-reviewer pass — all HIGH/CRITICAL driven to zero)
- **Every user-URL fetch on the public surface now routes through the guard, not
  just the probe `Client`.** The client-source scan (`clientsrc.scan_url`, reached
  via `/api/assess` `client_url`) and the wizard endpoint-detection probe
  (`detect._default_probe`, reached via `/wizard/detect`) previously used bare
  `requests` sessions — an unguarded SSRF hole in public-hosting mode. Both now
  mount the egress guard when the flag is set.
- **Proxy leg is pinned, not just validated once.** The proxy connection is now
  pinned to its validated IP (rewriting the proxy URL host), closing the
  DNS-rebinding window on the proxy socket.
- **RFC 6598 CGNAT (`100.64.0.0/10`) and all non-globally-routable addresses are
  blocked** (`is_private` misses CGNAT in CPython); added an explicit check plus an
  `is_global` catch-all.
- **`/api/assess` requires `Content-Type: application/json`** (415 otherwise),
  killing cross-origin form-based JSON-CSRF while the same-origin `fetch()` UI is
  unaffected.
- **Browser "Capture for me" flow refused in public-hosting mode.**
  `/wizard/capture-run` (+ `capture-advance`) navigate a real browser to a
  user-named URL and cannot be IP-pinned like the `requests` transport, so they are
  refused outright when `PROVENANCE_PROBE_BLOCK_PRIVATE` is set (capture is out of
  scope for the public instance); the button is hidden too. `_same_origin_ok` is
  not relied on here (a non-browser client sends no Origin/Referer).
- Fail-closed on all DNS resolution errors (`gaierror`/`OSError`/`UnicodeError`).

### Notes on proxy support
- Under `PROVENANCE_PROBE_BLOCK_PRIVATE=1`, `https://`-scheme proxies are
  unsupported: the proxy leg is pinned to the proxy's raw IP with no SNI override,
  so an `https://` proxy fails closed on a cert-hostname mismatch. Hosted mode
  should run without a proxy.

### Changed
- **`Dockerfile` `CMD` honors `$PORT`** (shell form,
  `--port ${PORT:-8770}`) for Render/HF/Cloud-Run portability.

### Notes
- All three pieces are **env-gated and OFF by default** — with the flags unset the
  transport is byte-identical to before (no adapter mounted, `trust_env`
  unchanged) and local single-user behavior is untouched. The HF Space deploy
  itself is the repo owner's step (needs their HF token) and is **not** performed
  by this change.

## [0.15.3] - 2026-07-30 — Security sign-off hardening for proxy capture (#44)

### Security (final security-reviewer pass)
- **CWE-59 symlink/TOCTOU on the credential write boundary.** `write_target` (and
  `ensure_gitignored`) now open `.env.capture` / `targets.json` / `.gitignore` with
  `O_NOFOLLOW` and fail loudly, so a pre-planted symlink can't redirect a captured
  session cookie to an attacker-chosen file on a shared/predictable directory.
- **`serve` capture leaked the ephemeral CA on process signal/exit.** The
  "Capture for me" flow runs in a daemon thread whose `finally` blocks don't run
  when the process is killed. `capture_proxy.install_process_cleanup()` (called by
  `serve`) now tears down every in-flight capture's browser + proxy + ephemeral-CA
  dir via `atexit` + a main-thread `SIGTERM` handler. Verified live: `SIGTERM` to
  `serve` mid-capture removes the CA dir and leaves no orphaned browser.
- **Domain binding for local/IP endpoints.** `_reg_domain` now exact-matches IP
  literals (previously `192.168.1.5` and `10.0.1.5` both collapsed to `1.5`) and
  uses the public-suffix list for multi-part TLDs — so a background request to an
  unrelated local endpoint can't be selected as the target and have its cookie saved.
- Defense-in-depth: Origin check added to `/wizard/save` + `/wizard/probe-response`;
  capture-worker error strings are redacted; recorded request/response bodies are
  size-capped (symmetry with the client's stream cap).

## [0.15.2] - 2026-07-30 — Clean teardown when a capture is aborted with SIGTERM (#44)

### Fixed
- **Aborting a proxy capture with `SIGTERM` (`kill <pid>`) leaked the ephemeral
  CA directory.** Python's default `SIGTERM` terminates the process without
  running the `finally` blocks that close the browser, stop the proxy, and remove
  the per-session CA dir — so the CA private-key files were left on disk. `capture()`
  now installs a `SIGTERM` handler (main thread only) that unwinds through those
  same teardown blocks, matching the existing clean `SIGINT` (Ctrl-C) behavior.
  Found by real-environment §4 abort testing. The proxy listener and browser
  already died with the process; this closes the on-disk CA leak.

## [0.15.1] - 2026-07-30 — Fix proxy capture on mitmproxy 12 (#44)

### Fixed
- **Proxy capture (`capture_proxy._MitmRecorder`) was broken on mitmproxy ≥12.**
  `DumpMaster.__init__` resolves the event loop via `asyncio.get_running_loop()`,
  so constructing it before the loop ran raised `RuntimeError: no running event
  loop` — i.e. `provenance-probe capture <url>` and the `/wizard` "Capture for
  me" button crashed on the version `mitmproxy>=11` resolves to today. The master
  is now built inside the running loop. Found by real-environment validation
  (the adapter was `# pragma: no cover` and had never run live).
- **Lingering proxy listener after teardown.** mitmproxy's Rust-backed listener
  isn't closed when `master.run()` returns, so the 127.0.0.1 proxy port survived
  `stop()` — a leaked listener per capture on the long-lived `serve` process. The
  servers are now torn down (`setup_servers()` with an empty mode) and the loop
  closed before the thread exits.

### Tests
- Added a `[capture]`-gated integration test that binds and cleanly tears down a
  real embedded proxy (skipped in CI; runs where the `[capture]` extra is
  installed). Registered the `integration` pytest marker.

## [0.15.0] - 2026-07-30 — Wizard "Capture for me" button (#44 child B)

### Added
- **"Capture for me" in the `/wizard` web UI.** The recording-proxy capture
  shipped in 0.14.0 (CLI) is now available from the browser: enter a URL, name,
  and the message you'll send, and the wizard runs the proxy capture and lands
  you on the editable preview → save. New endpoints: `POST /wizard/capture-run`
  (starts the capture in a background thread), `POST /wizard/capture-advance`
  (the two-phase "Continue" button — log in, then send one message),
  `GET /wizard/capture-run/<id>` (status poll), `GET /wizard/capture-preview/<id>`.
  The session cookie is held server-side only and never reflected to the browser;
  runs are one-shot. Shown only when the `[capture]` extra is installed.

### Security (adversarial review — Codex + Claude)
- **CSRF guard** on the capture endpoints: a cross-site POST can't start a
  browser-driving capture (Origin/Referer must be the local origin). URL scheme
  restricted to http(s).
- **No resource leak on abandon:** the worker's wait for each "Continue" is
  bounded (times out to an error) so a closed tab can't strand a thread/browser.
- **Safe eviction:** the run map drops only finished runs, never an in-flight one
  (which would strand its worker and lose its cookie).

## [0.14.0] - 2026-07-29 — Local recording-proxy web-app capture (#44)

### Added
- **Local recording-proxy capture (`provenance_probe/capture_proxy.py`).**
  `provenance-probe capture <url>` now captures the real chat request **and**
  response end-to-end and saves a probeable `template` target — no manual HAR
  paste. It drives an isolated throwaway browser through a localhost
  TLS-intercepting proxy (mitmproxy), two-phase so the login is never recorded,
  and feeds the existing `wizard.synthesize → dry_run → write_target` pipeline.
  The interception CA is ephemeral (per-session 0600 temp dir, removed on exit)
  and trusted by nothing in any OS/browser store — the throwaway context uses
  `ignore_https_errors` so no CA install is needed.
- **Three explicit capture modes:** `capture <url>` (proxy, default),
  `--paste` (manual copy-as-cURL / save-HAR steps), `--auto` (legacy HAR record).
- **Streamed-response support (SSE + JSON-lines), end-to-end.** Response mode is
  detected by sniffing the body, not the `content-type` header, so a stream
  mislabeled `text/plain` (e.g. v0.app) is handled. JSON-lines streams replay
  through the runtime client. `[capture]` extra now also installs `mitmproxy`.

### Changed
- **`wizard.synthesize` locates the reply path with the echo-safe detector**
  (`find_reply_path`) so an app that echoes the user's turn no longer mis-selects
  the prompt as the reply. Shared chat-request scorer (`score_chat_request`)
  lifted out of `parse_har` so HAR and proxy capture pick "the chat call" the
  same way. `Captured` gained `stream_delta_path`.
- Stateful request fields are blanked more precisely for replay-safety
  (`chatId`/`messageId` blanked; a `*model*` selector field is never blanked).

### Security (pre-landing review — Codex + security/python specialists + Claude)
- Flow selection is bound to the target's registrable domain, so a third-party
  background POST can't be saved with the wrong site's session cookie.
- Browser/contexts are torn down on the error/abort path (an abort no longer
  leaves a headed Chromium profile holding the live session cookie).
- A stream with no matching delta path fails the dry-run instead of saving a
  broken target that returns raw protocol text as the "reply."
- The recording proxy binds `127.0.0.1` only; the proxy thread is joined before
  the ephemeral-CA dir is removed; streamed bodies are byte-capped; capture error
  output redacts URL query strings.
- **Note:** the mitmproxy/Playwright adapter (`_MitmRecorder`, `_default_driver`)
  is exercised only with the `[capture]` extra installed and a real browser; it
  still needs a real-environment validation pass (TLS interception, keychain
  absence, abort cleanup) before it should be relied on in production.

## [0.13.0] - 2026-07-28 — Guided web-app capture (P3 / E8)

### Added
- **Guided capture (`provenance_probe/capture_guide.py` + `/wizard/capture` +
  `provenance-probe capture`).** Annotated, browser-specific (Chrome/Firefox/
  Safari) step-by-step instructions for capturing the one chat request the
  `template` adapter needs — for operators who have never opened DevTools.
  Names known apps (ChatGPT/Claude/Gemini/Lindy/Z.ai/…), tailors the "Copy as
  cURL" label per browser, offers the HAR alternative, and always carries the
  credential-safety note. No new dependency.
- **Optional Playwright capture assist (`capture --auto`, `[capture]` extra).**
  Drives a headed browser to your target and records the chat request to a HAR
  the wizard ingests. **Two-phase so your login is never recorded:** you log in
  in an *unrecorded* context; only the authenticated session's chat traffic is
  captured. The tool never types or sees a password. The HAR is written 0600 to
  a private `~/.provenance-probe/captures/` dir (gitignored if it lands in a
  repo) and clearly flagged as credential-bearing. Absent Playwright, `--auto`
  degrades to the manual guided steps.

### Security (adversarial review — Codex + Claude)
- Two-phase capture keeps the login POST / OAuth / password out of every HAR
  (was: recording started before login). Credential-bearing HAR defaults to a
  private 0600 path, never cwd, and is gitignored inside a repo.

## [0.12.0] - 2026-07-28 — OmniRoute cross-check + calibration gate (P2a)

### Added
- **`provenance_probe/omniroute.py` + `provenance-probe omniroute` CLI.** Uses a
  local OmniRoute router (localhost:20128) as an OPTIONAL accelerator and a second
  evidence source: fingerprint a model *through* OmniRoute and cross-check the
  router's claimed model against the tokenizer fingerprint.
- **Calibration gate (the honest core).** Measuring through OmniRoute only works
  if its injected ~2000-token system prompt is a *constant* offset that cancels.
  We test exactly that: subtract the modal overhead, then require ≥90% of probes
  to match a known family's first-party reference **exactly**. Until a given
  OmniRoute version calibrates, a via-OmniRoute verdict is **confidence-capped
  (never CONFIRMED, max SUGGESTIVE)**.
- **Three-state cross-check.** Router claim → family (maintained label→family map)
  vs fingerprint → `CORROBORATED` / `INCONCLUSIVE` / `CONTRADICTED`. INCONCLUSIVE
  is the default for any uncertainty (unknown label, uncalibrated, unclear family
  relation); version drift (V4 reuses V3's tokenizer) is CORROBORATED. **A
  CONTRADICTED result is an analyst-review signal, never an auto-published
  verdict** (quarantined).
- Captures `x-omniroute-*` router metadata as evidence; records a first-class
  `measurement_path: via_omniroute`.

### Finding
- **OmniRoute v3.8.48 does NOT calibrate.** Empirically it injects ~2004 tokens
  and lands 15/20 probes exact after offset (0.75, below the 0.90 bar); the 5
  misses are CJK/whitespace probes — the ones that matter most for CN origin.
  So measuring DeepSeek through this OmniRoute is reported as **SUGGESTIVE, not
  CONFIRMED** — the calibration gate correctly refuses to over-claim what an
  earlier n=1 observation had read as a clean match.

### Hardening (adversarial review — Codex + Claude)
- Calibration metric changed from Pearson correlation (scale-blind; false-passed
  156 cross-family pairs, e.g. OpenAI-o200k vs DeepSeek at r≈0.99) to
  exact-fraction-after-offset (cross-family false-passes → 4, all genuine
  tokenizer-twins). CONFIRMED now also requires the cross-check not be
  CONTRADICTED and a decisive fingerprint score. Router claim reads the
  `x-omniroute-model` header, never the user's typed route. Family rooting
  handles vendor-suffixed reference names (`GLM/Zhipu`); related roots
  (`gpt` ⊂ `gptneox`) never produce a false CONTRADICTED.

## [0.11.0] - 2026-07-28 — One-door add-target: auto-detect API style

### Added
- **One-door "Add a target" wizard (`/wizard`).** A single box takes whatever you
  have — a plain API address, a `curl` command, or a saved HAR — and figures out
  the rest. The operator never picks an "API style" (CEO plan E1/E2). A pasted
  URL is identified by *observing* the endpoint, not guessing from the name.
- **`provenance_probe/detect.py` — endpoint auto-detection.** A local input
  classifier (`classify_input`) plus an API-probe state machine (`detect`) that
  infers `api_style` (openai | anthropic) from responses. LLM-POSITIVE requires
  the full combination — assistant content **and** integer usage **and** a model
  id — else INDETERMINATE (no false-positive JSON detection). Ambiguous or
  partial matches ALWAYS ask for confirmation (E6); errors are plain sentences,
  never stack traces.
- **Consent gate before any network egress.** A pasted endpoint runs no probe
  until the operator approves, enforced by a one-shot **server-side consent
  token** (a direct/CSRF POST to `/wizard/detect` sends nothing). The consent
  copy states the real request volume (~28 for a full check), not "one test".
- **`provenance_probe/presets.py` — known-vendor presets (E4) + env-key lookup
  (E3).** Recognizes OpenAI/Anthropic/DeepSeek/Moonshot/OpenRouter/Gemini by
  **hostname** (exact-or-subdomain, not substring — a look-alike host like
  `api.openai.com.evil.test` is rejected) and offers a `{VENDOR}_API_KEY` already
  in your environment. The key **value never touches the committed config**; only
  the env-var NAME rides `auth_value_env`.
- **`EgressBudget`** caps the identify phase so it can't runaway.
- Plain-English detection card + one-click **"Probe it now"** hand-off to the
  probe tool with the target prefilled (E5). +48 tests.

### Security (hardening from adversarial review — Codex + Claude)
- Vendor matching is hostname-aware (was substring) — closes a credential-exfil
  path to look-alike hosts. The write-boundary secret-header filter now strips
  smuggled key headers (`X-Api-Key-Alt`, `x-session-token`) while keeping CSRF
  headers needed for replay. Every detection carries a self-reported-usage caveat.

## [0.10.0] - 2026-07-26 — Add-target wizard (paste-first)

### Added
- **Add-a-target wizard in the local `serve` UI (`/wizard`, 127.0.0.1 only).**
  Paste a captured web-app chat request (DevTools → Copy-as-cURL, or a saved HAR)
  and it synthesizes a `template` target: `base_url`/`chat_path`, a
  `request_template` (your prompt → `__PROMPT__`; stateful conversation/message
  ids blanked for replay-safety), response dotted-paths (text/usage/model, from a
  HAR response), SSE detection, and CSRF/origin headers (dynamic ones flagged).
  A 2-probe **dry-run** checks HTTP health, usage exposure, and replay-safety
  before saving. **Security:** the session cookie is written only to a gitignored
  `.env.capture` (auto-added to `.gitignore`) and referenced by `cookie_env` — it
  never enters the committed config; saved targets default `authorized: false`.
  Paste-first v1 (no browser dependency); `provenance_probe/wizard.py` +28 tests.
  Playwright auto-capture is a planned optional `[capture]` extra.

### Changed
- **Publication policy is now full transparency.** The observatory publishes the
  complete work behind every finding — measurements **and** the interpreted
  provenance/jurisdiction verdict — as collected, in an append-only signed log,
  so consumers can see exactly how each verdict was reached. The prior two-tier
  withholding + 30-day disclosure-window gate is removed. Accuracy safeguards are
  retained and emphasized: known-answer + negative controls, a published
  false-positive rate, per-verdict confidence labels, and prominent
  corrections/retractions. `DISCLOSURE.md` rewritten as the operative policy;
  `docs/tos-notes.md` / `counsel-brief.md` / `openrouter-approval-request.md`
  retained as risk context (no longer gates); README/WHITEPAPER/EXTENDING updated.

## [0.9.1] - 2026-07-26

### Fixed
- **Anthropic endpoints now measure provenance instead of flooring at
  INDETERMINATE.** `api_style: "anthropic"` auto-configures the `/v1/messages`
  path and `x-api-key` auth (they were defaulting to the OpenAI
  `/chat/completions` + `Authorization: Bearer`, so probes 404'd and no usage came
  back). Anthropic returns `usage.input_tokens`, which the tokenizer battery reads.
- **`serve` web UI now honours the target's auth scheme.** It injected the entered
  key as a hardcoded `Authorization: Bearer`, bypassing the anthropic `x-api-key`;
  it now uses the target's configured `auth_header`/`auth_prefix`.

### Added
- **Claude and Gemini reference vectors.** Both families now clear to a firm non-CN
  **NO EVIDENCE** (were UNLIKELY / INDETERMINATE). Their tokenizers aren't published,
  so the vectors are measured from the genuine first-party API — a genuine endpoint
  matches its own family ≈1.0 with CN families near zero.
- **`build-reference-endpoint`** — measure a reference vector from a live authorized
  first-party endpoint (requires `--i-am-authorized`; entries tagged
  `source: "live-first-party-api"`). This is the supported path for families with no
  published tokenizer.
- **[`docs/EXTENDING.md`](docs/EXTENDING.md)** — the coverage playbook: adding API
  / web-app / **agent** sources, adding a **model family to the reference corpus**
  (including the live-endpoint path for Claude/Gemini), and continuous monitoring.

## [0.9.0] - 2026-07-25 — Adversarial red-team corpus (E8)

### Fixed (pre-merge adversarial review — Codex)
- **`redteam` requires `--i-am-authorized`** (an explicit per-run attestation, not
  just config) — the prompts are deliberately adversarial.
- **Adapter-aware identity:** reads `Response.echoed_model()` / `.text()`, so
  template / Anthropic / raw endpoints are covered, not just OpenAI-shaped JSON.
- **`model_id` is the hard switch signal** (drives exit 2); a changing `self_id`
  is an advisory `self_id_flags` entry — the corpus asks about "underlying"
  identity, so a refusal/negation can trip the self-ID regex and must not fire a
  false alert. Baseline signals backfill (a never-seen signal is seeded, not a
  switch). A non-2xx transport response is recorded as an error, not a clean
  no-identity scenario.

### Added
- **`redteam` command.** Drives an authorized endpoint through a corpus of
  stress / adversarial prompts (`provenance_probe/redteam.py`) and detects whether
  the served model's identity **changes under pressure** — a router that swaps to a
  cheaper or fallback model when pushed, or reveals a different origin. Reuses the
  same passive identity (echoed model id + self-ID) as the sentinel, so a
  switch-under-stress is reported like a mid-session switch. `--cap N` bounds the
  quota/abuse budget; one scenario erroring never aborts the run; **exit 2** on a
  switch. Authorized-use only (the prompts are deliberately provocative).

## [0.8.0] - 2026-07-25 — Live agent board (E4)

### Fixed (pre-merge adversarial review — Codex)
- **Reflected XSS on `/agent/live` closed.** An attacker-controlled `?session=`
  went into an inline `<script>`; `json.dumps` escaped JS quotes but not
  `</script>`, so `?session=</script><img src=x onerror=…>` broke out. Now `<`/`>`
  are escaped to `<`/`>` too (regression test added). The rendered report
  fragment was already fully `html.escape`d.
- **Read-side DoS bounded:** `/agent/report.html` caches the rendered fragment per
  `(session, step-count)`, so a 2s poll with no new calls is O(1) (no re-render).
- Live/read endpoints are a local surface (like `/sentinel/events`) — serve
  loopback-only; front with auth if you change `--host`.

### Added
- **Live streaming board in the `sentinel` proxy.** `GET /agent/live?session=<id>`
  serves a self-contained page that shows the per-step board **updating in real
  time** as the agent makes calls through the proxy — session picker, animated
  live indicator, pause/resume. It polls a server-rendered report fragment
  (`GET /agent/report.html`), so it reuses the same tooltip-rich `agent_report`
  render (DRY) — hover any term for what it means. `GET /sentinel/sessions` lists
  active sessions. Browser-verified live against a real endpoint (board went
  2 → 3 steps as calls arrived, no reload).

## [0.7.0] - 2026-07-25 — Sub-agent call graph (E6)

### Fixed (pre-merge adversarial review — Codex)
- **No recursion on deep graphs.** `agent_graph.flatten` and the sentinel
  `/agent/graph` builder are now iterative (a 1500-deep acyclic chain — reachable
  under `MAX_STEPS=5000` — no longer `RecursionError`s the report/endpoint);
  `/agent/graph` caps nested-JSON depth.
- **Parent reachable even with no own call:** a child declaring `X-Provenance-Parent`
  creates a placeholder parent session, so `/agent/graph?session=<parent>` works
  even when the parent made no proxied call itself.
- **No silent reparenting** (first-writer wins) and **first-span-wins** on duplicate
  span ids (adversarial traces can't misattach nodes).

### Added
- **Sub-agent call graph.** When a trace carries span parentage (OpenTelemetry
  `spanId`/`parentSpanId`) or the proxy carries `X-Provenance-Parent`, the flat
  per-step board nests into the tree that actually ran — you see *which* step
  spawned the sub-call that switched models or leaked data. `AgentStep` gains
  `span_id`/`parent_id`; `agent_graph.build_tree` is cycle-safe (ancestor-walk
  guard) and drops nothing (a missing/cyclic parent attaches at the root).
- The HTML report renders a **"Sub-agent call graph"** section (indented tree)
  when parentage exists, and documents the blind spot: a sub-agent calling an
  un-proxied backend, or whose spans aren't exported, can't appear.
- **`sentinel` `GET /agent/graph?session=<root>`** returns the tree of sessions
  linked by `X-Provenance-Parent`, each node carrying that agent's verdict.

## [0.6.0] - 2026-07-25 — Agent Flight Recorder Phase 2 (A + E5)

### Fixed (pre-merge adversarial review — Codex)
- **Baseline no longer poisoned by a model-less first response.** A first response
  with no `model_id` (e.g. a 400) set the session baseline to `None` and silently
  swallowed all later switches; the baseline now backfills a never-seen signal
  without alerting, so a real later switch is still caught (regression test added).
- **SSE memory limits are now reliable under concurrency:** the runaway-line guard
  caps `buf` at `MAX_LINE`, and the per-call + global accumulation ceiling is
  checked-and-reserved atomically under one lock (was a TOCTOU race that let
  concurrent streams blow past `MAX_GLOBAL_ACCUM`).
- **Upstream sockets are closed** (`r.close()`) in the tee, JSON, and passthrough
  paths — no socket leak on client disconnect.
- **TTL eviction skips in-flight sessions** (`last` refreshed on entry) so a long
  stream isn't evicted mid-call; distinct sessions capped (evict oldest idle) and
  the event log bounded.
- **Passthrough is fully transparent:** adds `HEAD`/`OPTIONS`, forwards raw bytes,
  and preserves `content-encoding`.

### Added — live proxy interposition (A)
- **`sentinel` is now a live agent flight recorder.** The proxy **tees SSE**
  streams — forwards each chunk to the agent unchanged as it arrives (preserves
  token-streaming), accumulates the delta in parallel (capped per-call + a global
  in-flight ceiling), fingerprints on completion. **Fail-open:** a fingerprinting
  error can never alter or truncate the proxied bytes (tested: raise at mid-stream,
  all chunks still arrive).
- **Generic passthrough** — every path/method reaches upstream unchanged (not just
  `/v1/chat/completions`), so the proxy is a real `base_url` interposition point;
  provenance is collected only on chat completions.
- **Response headers preserved** end-to-end (hop-by-hop denylist) — vendor/rate-limit
  headers are both agent-visible behavior and wire evidence.
- Per-session `AgentStep` accumulation + `GET /agent/report?session=…` runs
  `agent.analyze` over the collected steps. Session key = `X-Provenance-Session`;
  concurrent calls without it are flagged `unordered`, which **withholds** the
  switch verdict. Per-session step cap + byte accounting + TTL eviction.
- Passive by design: the proxy emits a response-IDENTITY (model id / self-ID /
  header shape) for switch detection — NOT a tokenizer fingerprint (that needs the
  active probe). Shared `client.parse_sse_delta` (one SSE parser for client + proxy).

### Added — export pack (E5)
- **`--export` on `agent`/`agent-trace`** writes a deterministic, signed-ready
  evidence record (`agent_export.py`): verdict + per-step board + engine version +
  SHA256 of the input, canonical JSON (`captured_at` isolated so the core is
  reproducible). The record drops under the observatory `data/agents/<target>/<date>/`
  tree and is signed by the existing daily cosign+Rekor manifest — the observatory's
  `build_manifest` now includes agent records. No signing in the engine, no
  duplicated crypto.

### Added — `AgentStep` quality fields
- `degraded` / `unordered` / `truncated` / `session_id`, carried through `analyze`,
  the report (badges + tooltips), and the export. An `unordered` step withholds
  order-dependent switch claims instead of asserting a meaningless one.

## [0.5.2] - 2026-07-25

### Added — the agent report illustrates what happened, and it's in the local UI
- **Bolstered HTML report.** Beyond the per-step board, it now leads with a
  plain-language **"What happened"** narrative (steps, distinct models, each model
  switch, which steps flagged and why, overall verdict), a **"What this tool did"**
  panel naming the observation surfaces that ran (trace ingest / egress mapping /
  active probe — or why the probe didn't run), and an **"Evidence — why each verdict
  fired"** table listing the actual signals per step. So a non-technical reviewer
  sees the reasoning, not just a tier.
- **Agent board in the local `serve` UI.** New `/agent` route + an "Agent board →"
  nav link: paste an agent trace (OTel spans or minimal JSON), get the full
  tooltip-rich report in the browser. Reuses `agent_report.render_html` (DRY);
  untrusted-trace hosts are not DNS-resolved unless you tick the box.
- `render_html(..., fragment=True)` for embedding; +4 tests (112 total).

## [0.5.1] - 2026-07-25

### Added — agent board: operator/soil basis + educational HTML report
- **Jurisdiction basis on the board.** Each step now carries `jurisdiction_basis`
  (the network layer's operator-vs-soil distinction), so the board shows *why* a
  step is flagged: `CONFIRMED (PRC-soil)` vs `CONFIRMED (PRC-operator)` vs
  `UNLIKELY (non-PRC-1p)`. Surfaces that a CDN-fronted PRC vendor (e.g.
  `api.moonshot.ai` → Cloudflare) is caught on operator grounds even when geo-IP
  reads "US".
- **`--html` report** (`provenance_probe/agent_report.py`) — a self-contained HTML
  page for `agent-trace` / `agent` with **hover tooltips on every column, verdict
  tier, and concept** (provenance vs jurisdiction, each tier's meaning, model
  switch, egress, active probe, operator vs soil, …) plus a full glossary. Teaches
  a non-technical reviewer what the tool measured and what each verdict means.
- +3 tests (108 total).

## [0.5.0] - 2026-07-25

### Added — Agent Provenance Flight Recorder (Phase 1)
- The unit of assessment can now be an **agent** (a multi-step, multi-model
  workflow), not just one endpoint. `provenance_probe/agent.py` ingests a captured
  agent run and reports a per-step board: which model each step ran on, model
  switches across steps, and tool-call egress jurisdiction.
- `agent-trace <file>` CLI — ingest **OpenTelemetry GenAI spans** (primary) or a
  minimal JSON fallback; prints the board; **exit 2** on a model switch.
- `agent --config a.json` CLI — config-driven assessment: trace ingest + optional
  **active backend probe** (the only route to a CONFIRMED provenance verdict).
- `AgentTarget` / `AgentBackend` config types with **per-backend authorization** —
  active probing aborts on the first unauthorized backend (the consent surface
  widens to the agent operator AND each backend).
- `scoring.combine_agent()` — agent verdict = the worst step, labelled MIXED when
  steps differ; the full per-step board is always shown.
- Honest by design: trace-only provenance floors at INDETERMINATE (no tokenizer
  signal in a post-hoc trace). Egress jurisdiction and model switch are the
  reliable trace signals. `docs/CONOPS.md` = executive/federal concept of ops.
- 26 tests (`tests/test_agent.py`), fixtures for OTel + JSON traces.

### Security / hardening (agent trace ingest)
- **SSRF guard:** an ingested agent trace is untrusted, so `agent-trace` does NOT
  DNS-resolve trace-supplied hosts by default — static hostname jurisdiction
  signals (`.cn`, known PRC endpoints) still fire with zero network I/O. Pass
  `--resolve-hosts` to opt into DNS + RDAP. `network.analyze_host` gained a
  `resolve` flag and a private/reserved/loopback/link-local/metadata IP denylist
  (`_blocked_ip`) applied to both IP-literal hosts and resolved addresses
  (DNS-rebinding defense), plus a distinct-host cap.
- **Self-ID now scores:** a step whose text concedes a CN family feeds `selfid_cn`
  into scoring (previously written to a dead `_self_id` key scoring never read).
- **Switch detection namespaced:** echoed-model-id changes and self-ID brand flips
  are tracked separately (no more spurious `gpt-4o -> OpenAI` cross-namespace hits).
- **Exit-on-worst-verdict:** `agent`/`agent-trace` exit 2 on a LIKELY/CONFIRMED
  worst step even without a switch (CI no longer reads a PRC finding as clean).
- **Malformed-trace hardening:** non-object rows/spans, non-list containers, and
  over-size/over-step traces raise `TraceError`; unknown config keys raise a clear
  `ValueError` instead of a raw `TypeError`.

## [0.4.1] - 2026-07-20

### Fixed
- **`fingerprint_id` no longer flips on a benign chat-template / token-accounting
  change.** `_fp()` hashed the raw tokenizer vector (raw `prompt_tokens`), so a
  constant per-probe overhead shift from an endpoint changing its chat template
  or token accounting produced a new fingerprint — a false "backend changed"
  drift. The fingerprint now hashes the overhead-invariant *shape* of the vector
  (each probe minus the vector's own minimum), which cancels a constant offset
  while preserving the relative structure that distinguishes tokenizer families.
- **`monitor` no longer reports a critical `tokenizer_vector` drift on the same
  benign overhead shift.** Its direct probe-count diff now compares the
  overhead-corrected shape instead of raw counts, matching the fingerprint fix.
  A genuine change in relative token structure still drifts.

### Added
- `tokenizer.shape_vector()` — reference-free overhead-invariant form of a probe
  vector, used by both `_fp()` and `monitor`.
- First automated test suite (`tests/`, `pip install -e '.[test]'`): 12
  characterization tests pinning the three contracts downstream tooling depends
  on — fingerprint overhead-invariance, `monitor` exit-2 drift semantics
  (including no-false-drift on benign overhead), and tokenizer family match
  against the shipped Qwen2 reference.
