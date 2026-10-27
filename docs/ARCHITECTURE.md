# provenance-probe — Architecture & Algorithms

This is the technical reference: what the system measures, the math behind each
signal, the end-to-end workflows (assess / wizard / OmniRoute / capture), and the
security invariants that adversarial review hardened. For the *why* and the
policy framing, see [WHITEPAPER.md](../WHITEPAPER.md) and
[DISCLOSURE.md](../DISCLOSURE.md); for a first run, [QUICKSTART.md](../QUICKSTART.md).

---

## 1. What it determines

Two **separate** verdicts, kept apart on purpose because a vendor can be clean on
one and dirty on the other:

| Verdict | Question | Evidence that is hard to fake |
|---|---|---|
| **Provenance** | Are the model *weights* Chinese-origin, wherever they run? | Tokenizer fingerprint, embedded persona, catalog |
| **Jurisdiction** | Is inference executed by a PRC-domiciled operator / on PRC soil? | Network/RDAP, TLS/wire, client-source operators |

Every verdict carries an honest **confidence label** (never "proof") and a
measured false-positive rate. Chinese *open weights* running inside your own
boundary carry zero data-jurisdiction exposure — collapsing the two verdicts
would misdirect controls, so we never do.

---

## 2. Signal layers

`assess` runs up to eight layers; each contributes evidence to the scorer. Layers
degrade independently — a missing layer lowers confidence, it does not crash the
run.

| Layer | Module | Signal |
|---|---|---|
| Network / jurisdiction | `probes/network.py` | RDAP → operator + jurisdiction of the resolved host |
| Wire fingerprint | `probes/wire.py` | Header shape, error schema, streaming style, model catalog |
| **Tokenizer** | `probes/tokenizer.py` | Reported `prompt_tokens` shape vs 27 reference families (§3) |
| Logprob / determinism | `probes/logprob.py` | Logprob signature, greedy determinism |
| Behavioral | `probes/behavioral.py` | Self-identification, alignment asymmetry, CJK leakage |
| Latency | `probes/latency.py` | Timing profile |
| Deception | `probes/deception.py` | Persona vs jurisdiction claims, confrontation w/ false control |
| Client source / artifacts | `probes/clientsrc.py`, `artifact.py` | PRC operators in shipped source; on-disk model files |

The tokenizer layer is the load-bearing provenance signal and the one with real
math, so it gets its own section.

---

## 3. Tokenizer fingerprinting (the core algorithm)

### 3.1 Why it works

Every model family chops text into tokens with its own learned vocabulary (BPE /
unigram). The **number** of tokens a fixed string produces is a stable, per-family
signature that a served endpoint leaks for free in `usage.prompt_tokens` — and
that is very hard to fake without breaking billing/accounting. We never need the
model's weights or cooperation; we only need it to report prompt-token counts.

### 3.2 Measurement

`measure(client)` sends each probe in a fixed corpus (~20 probes:
`provenance_probe/data/corpus.py`, `CORPUS_VERSION`) with `max_tokens=1,
temperature=0` and records the reported prompt-token count:

```
vector[probe_id] = response.usage.prompt_tokens
```

The corpus mixes ASCII, whitespace runs, code, and CJK-dense strings so families
separate. A rotated variant set (`probe_variants.py`, `--variant-seed`) defeats
exact-string special-casing; a match is only trusted against a reference built
with the same seed.

**LLM-POSITIVE requirement.** A vector is only usable if the endpoint actually
behaves like a chat model — `usable = len(vector) >= 6`. (The wizard/detect path
applies a stricter test: assistant-content **and** integer usage **and** a model
id, else INDETERMINATE — §5.)

### 3.3 Chat-template overhead correction

A chat template wraps every probe in a roughly **constant** token overhead (system
scaffold, role markers). Comparing a raw observed vector to a reference would be
dominated by that offset, so we cancel it. The offset is estimated as the **modal
(median) delta** between observed and reference over shared probes:

```
off = median_k ( obs[k] - ref[k] )          # _overhead_correct()
```

For fingerprinting with **no reference at hand** (e.g. computing a stable
`fingerprint_id`), we instead subtract the vector's own minimum — a reference-free
way to cancel a constant offset while preserving inter-probe structure:

```
shape[k] = obs[k] - min(obs)                 # shape_vector()
```

This keeps the fingerprint stable when an aggregator tweaks its template (a benign
change that would otherwise read as a model swap).

### 3.4 Family match score

`compare(observed, reference)` scores the overhead-corrected observed vector
against each reference family over the shared probes:

```
diffs   = |(obs[k] - off) - ref[k]|   for k in shared
exact   = count(diffs == 0)
l1      = sum(diffs)
norm_l1 = l1 / sum(ref[k])                    # scale-normalized error
score   = max(0, 1 - norm_l1 * 6.0) * 0.5  +  (exact / n_shared) * 0.5
```

Two equally-weighted halves: a **continuous** closeness term (how far off the
counts are, normalized and clipped) and a **discrete** term (fraction of probes
that match *exactly* after offset). A family is called when the top
`score ≥ 0.75`; the `origin` field on that reference entry (`CN` / `US` / `EU` /
…) drives the provenance verdict. 27 reference vectors span 22 families
(`data/tokenizer_ref.json`); build/extend with `build-reference` /
`build-reference-endpoint`.

### 3.5 Han compression (supporting signal)

```
han_tok_per_char = vector["cjk_dense"] / CJK_DENSE_HAN_CHARS
```

Tokens-per-Han-character: lower = a more CJK-optimized vocabulary (Qwen2 ≈ 0.53,
DeepSeek ≈ 0.55 … GPT-2 ≈ 2.32). **Supporting only** — Cohere's Command-R overlaps
the Chinese families, so low Han cost alone never establishes origin. Use the full
20-probe match to call a family; use this to corroborate or triage.

### 3.6 Threat model — self-reported usage

`usage.prompt_tokens` is *self-reported* by the endpoint and could be forged to
spoof a tokenizer shape. Every verdict carries this caveat, and the detect path
adds a **linear-ramp consistency check** posture (does the reported count track a
controlled length ramp?). Treat the fingerprint as a strong signal, not a proof —
which is exactly why the confidence label exists.

---

## 4. Scoring & drift

`scoring.py` fuses the layers into the two verdicts with confidence. `monitor.py`
computes a `fingerprint_id` (a hash over the overhead-invariant shape + wire
signature) and `diff()`s two runs; **`monitor` exits 2 on drift** so CI can catch
a silent model swap months after signing a contract. `sentinel.py` is a passive
reverse-proxy flight recorder that tees an agent's calls and fingerprints them
live (trace-only provenance honestly floors at INDETERMINATE — only an active
backend probe reaches CONFIRMED).

### 4.1 Hard-evidence floor + ceiling (why a confession can't confirm)

The z.ai field case is the design requirement: an app served a Google-Gemini
persona over a GLM (Zhipu) backend and only admitted the switch after repeated
confrontation. **A model's self-report is not evidence of what its weights are —
it can be instructed to claim any identity, in either direction.** So `score()`
partitions provenance/jurisdiction signals into *hard* (measured / artifact —
tokenizer fingerprint, config/cache/gguf artifacts, client-source endpoints) and
*soft* (the model's own words: behavioral self-ID, informative concession, held
persona, persona-management in the trace, false compliance assurance; plus
lower-durability claims). Two guards then bound each axis and both converge on
INDETERMINATE:

- **Floor (raises):** a *clean* verdict (UNLIKELY / NO EVIDENCE) is only earned if
  a provenance-detecting layer actually returned data. If the tokenizer fingerprint,
  artifacts, and client-source all produced nothing, the verdict floors *up* to
  INDETERMINATE — "we did not look", not "probably not Chinese".
- **Ceiling (lowers):** CONFIRMED / LIKELY on an axis require ≥1 hard signal. If
  only soft/self-report signals fired, the verdict is capped *down* to INDETERMINATE
  with a deterministic note naming the soft signals. Deception is therefore
  **inculpatory, never exculpatory**: a soft signal only ever ADDS log-odds and a
  false persona can never downgrade a hard-signal-driven verdict.

`persona_mismatch` is artifact-derived (the app misrepresents its model) but is a
deception *corroborator*, not a CN-provenance anchor — a Western persona can sit
over a US model too — so it is deliberately excluded from the hard provenance set.

### 4.2 Capture robustness — what static replay catches, and what it can't

The automated capture + monitor path fingerprints a **recorded** request/response
and re-scores it. Be honest about the boundary: **signed or stateful apps defeat
static replay.** A per-request-signed API (an HMAC/nonce/timestamp over the body,
a rotating CSRF or anti-replay token, a bound session — the z.ai shape) will reject
a replayed capture, so the capture path cannot re-drive it. Robustness here means
**detection quality *given* a capture**, plus an honest grade from a fresh
tokenizer battery and wire fingerprint when that replay cannot run:

- **Caught given a capture:** a tokenizer-family change (overhead-invariant shape),
  a wire/error-schema change, a header/vendor change, and any hard artifact present
  in the captured client source. The redteam driver adds a fingerprint-based HARD
  switch (`fingerprint_switch`) so a router that swaps the backend while echoing a
  **constant** `model_id` still trips on the backend-envelope change.
- **When replay is impossible:** a signed or stateful app rejects the captured
  request, and the capture is not re-scored as if that replay worked.
  `monitor.grade_unreplayable` still flags a switch from a **fresh** live tokenizer
  battery and the wire fingerprint — the same WS1 signals, which do not replay the
  captured body. The verdict says replay was impossible and names the signal that
  carried it: `tokenizer` confirms a shape change; `wire` flags an envelope change
  and does not confirm it. What the model calls itself never confirms a switch.
  The wizard and `capture` surface that verdict when the dry-run cannot replay.
- **Still missed:** a swap hidden entirely behind an identical response envelope
  with no tokenizer signal (usage suppressed) — the degraded path, which
  `monitor.diff` already reports as *not a clean bill*; and provenance from a chat
  claim alone, which the §4.1 ceiling caps at INDETERMINATE by design. No
  over-claim: a green capture is evidence about the captured exchange, not a
  guarantee about every future live request.

---

## 5. The add-a-target wizard (one door)

**Goal (CEO plan E1/E2):** a non-technical user adds any target — API or web app —
without knowing "which API style". One box, no `api_style` question.

```
/wizard  — "Add a target"
   │ paste anything: a URL, a curl command, or a HAR
   ▼ classify_input()  (detect.py — LOCAL, no network)
   ├─ curl / HAR  → wizard.parse_curl / parse_har → synthesize() → template target
   └─ URL / host  → CONSENT GATE → detect() API-probe state machine
```

### 5.1 Input classification (local, no egress)

`detect.classify_input(text) -> empty | curl | har | endpoint | unknown`. cURL is
recognized by a leading `curl`, HAR by a leading `{`/`[`, an endpoint by a lone
URL/bare-host with no spaces. Everything else gets a friendly "I couldn't tell
what this is".

### 5.2 Consent gate (hard precondition of any egress)

For an endpoint, **nothing is sent** until the operator approves. The gate is
enforced server-side by a **one-shot consent token** (`_CONSENT_PENDING`): a
direct/CSRF POST to `/wizard/detect` with no valid token sends zero traffic, and
the endpoint under test is read from the server stash, not a tamperable form
field. The consent copy states the real request volume (~28 for a full check),
not "one test".

### 5.3 API-probe state machine

`detect(text, key, *, consented, passive_only, budget) -> Detection`:

1. **Passive** — `GET {base}/models` (Bearer, then `x-api-key` on 401; `/v1/models`
   fallback only when the base doesn't already end in `/v1`, so paths never
   double). Yields reachability + a model id to probe with, and detects an
   HTML/login wall → routes to guided capture (§7).
2. **Active** (post-consent, `max_tokens=1, temp=0`) — `POST …/chat/completions`
   (Bearer) → OpenAI shape? and `POST …/v1/messages`
   (`x-api-key` + `anthropic-version`) → Anthropic shape?
3. **LLM-POSITIVE** = assistant-content **string** AND usage **int** AND a model
   **id**. Both shapes positive → ambiguous → **always confirm** (never silently
   pick). One positive → that `api_style`, high confidence. Partial (≥2 of 3
   fields) → low confidence, confirm. Nothing → friendly INDETERMINATE.

**Bounds & safety.** A session-wide `EgressBudget` (default 40) plus a per-detect
cap (≤6 probes) bound the fan-out; 429 is surfaced explicitly; every transport
error maps to a plain sentence (no stack traces). Vendor **presets** (E4) match on
**hostname** (exact-or-subdomain, never substring — a look-alike host like
`api.openai.com.evil.test` is rejected) and offer a `{VENDOR}_API_KEY` from the
environment **by name only** — the key value never enters the committed config.

### 5.4 Save & dry-run

The synthesized target is previewed as editable JSON (credentials held
server-side, never reflected). Save runs a 2-probe **dry-run**: both probes must
reply, and reported prompt-token counts must be stable (a stateful/append backend
drifts or errors) → refuses to save an unsafe target. The session **cookie** is
written to a gitignored `.env.capture` created **0600** (owner-only) and
referenced by `cookie_env`; a write-boundary **sanitize** strips any
credential-bearing header (`cookie`, `authorization`, `x-*-key`, `*-token`,
`vault`, …) so a hand-edited target can't smuggle a secret into git.

---

## 6. OmniRoute integration (optional accelerator + second evidence source)

[OmniRoute](https://github.com/diegosouzapw/OmniRoute) is a local OpenAI-compatible
router (`localhost:20128`) that normalizes ~290 providers behind one wire shape and
returns `x-omniroute-*` metadata. `provenance_probe/omniroute.py` uses it two ways
— always **optional**; absent OmniRoute, everything falls back to direct probing.

### 6.1 The calibration gate (why measuring *through* a router is gated)

OmniRoute injects a hidden **~2000-token system prompt** into every request. The
"measure through it" mechanism assumes that injection is a **constant additive
offset** that cancels in overhead-correction (§3.3). That was observed once (n=1),
not proven — BPE **seam effects** (the injected prompt's tail merging with each
probe's head) can distort the per-probe *shape*, not just add a constant.

`calibrate(observed, reference)` tests the assumption directly: subtract the modal
offset, then require a high **fraction of probes to match the reference EXACTLY**:

```
residual[k] = (obs[k] - off) - ref[k]
exact_frac  = count(residual == 0) / n_shared
calibrated  = exact_frac ≥ 0.90        # CALIBRATION_TOLERANCE, n_shared ≥ 6
```

We deliberately do **not** use a correlation coefficient: Pearson ignores scale
and stays high for any two vectors that both track prompt length, so it
false-passes cross-family (OpenAI-o200k "matches" DeepSeek at r≈0.99 — 156 false
pairs). Exact-fraction-after-offset is scale-sensitive and family-specific: a
wrong family cannot match after any single offset.

**Until a given OmniRoute version calibrates, a via-OmniRoute verdict is
confidence-capped — never CONFIRMED, max SUGGESTIVE.**

> **Measured:** OmniRoute **v3.8.48** injects ~2004 tokens and lands **15/20**
> probes exact after offset (0.75, below the 0.90 bar). The 5 misses are
> CJK/whitespace probes — the ones that matter most for CN origin. So measuring
> DeepSeek through it is reported **SUGGESTIVE, not CONFIRMED**. The gate refuses
> to over-claim what an earlier n=1 read as a clean 1.0 match.

### 6.2 Three-state cross-check

The router's claimed model (`x-omniroute-model`, **never** the user's typed route)
is mapped to a tokenizer family via a maintained `LABEL → FAMILY` table (matched at
**letter boundaries**, so `o1` doesn't match inside `proto1`) and compared to the
fingerprint:

| State | Condition |
|---|---|
| **CORROBORATED** | mapped family == fingerprint family (version drift, e.g. V4↔V3, counts as same) |
| **CONTRADICTED** | two **distinct KNOWN** families (roots derived from families that actually have reference vectors — a label with no reference stays INCONCLUSIVE, never a false accusation) |
| **INCONCLUSIVE** | the default for any uncertainty: unknown label, uncalibrated, no fingerprint, or unclear relation |

**CONTRADICTED is an analyst-review signal, NEVER an auto-published verdict** — it
is a public accusation about a named third party, so it is quarantined
(enforced end-to-end by the observatory signer; see the observatory's
`lib/publish_policy.py`).

### 6.3 measurement_path

Every record is tagged `measurement_path: direct | via_omniroute`. `CONFIRMED`
through a proxy requires all of: calibration passed **and** the cross-check
CORROBORATED **and** a decisive fingerprint score; otherwise it caps at
SUGGESTIVE. The observatory refuses to sign a `via_omniroute` record lacking a
passing calibration + routing disclosure — a proxy measurement can never be
laundered as first-party.

CLI: `provenance-probe omniroute --route <id> --expect-ref <REFKEY> --i-am-authorized`.

---

## 7. Guided web-app capture (E8)

Authenticated web apps need a captured request. `capture_guide.py` produces
annotated, **browser-specific** (Chrome/Firefox/Safari) DevTools steps — the
no-dependency core. The optional Playwright assist (`capture --auto`, `[capture]`
extra) automates it and is **two-phase so the login is never recorded**:

```
Phase 1 (UNRECORDED context): navigate, operator logs in, snapshot storage_state
Phase 2 (recorded context):   reuse storage_state, operator sends one message,
                               record ONLY the authenticated chat traffic → HAR
```

The password / OAuth exchange never lands in any file. The credential-bearing HAR
is written **0600** to a private `~/.provenance-probe/captures/` dir (gitignored if
it lands in a repo), under a restrictive umask so there is no world-readable
window. The tool never types or sees a password.

---

## 8. Security invariants (hardened by adversarial review)

Every PR was reviewed by two independent models (Codex + a Claude subagent);
~20 real issues were fixed before merge. The standing invariants:

- **No egress before consent** — the wizard's endpoint path sends nothing without
  a valid one-shot consent token.
- **Credential values never reach git** — keys ride `auth_value_env` (name only);
  cookies ride a gitignored **0600** `.env.capture`; a write-boundary sanitize
  strips credential headers even from a hand-edited target.
- **No password handling, ever** — capture logs in via a browser the operator
  drives; login is never recorded.
- **Hostname-aware vendor matching** — never substring (closes credential-exfil to
  look-alike hosts).
- **Never over-claim through a proxy** — the calibration gate caps via-OmniRoute
  confidence; CONFIRMED needs calibration + corroboration + a decisive score.
- **Never auto-accuse** — a CONTRADICTED cross-check is quarantined for human
  review, never auto-published, on both the probe and observatory sides.
- **Authorization gates active probing** — targets carry `authorized`; active
  probes and browser-driving abort without it.

---

## 9. Module map

| Module | Role |
|---|---|
| `probes/*.py` | The eight signal layers (§2) |
| `scoring.py` · `report.py` · `userwarn.py` | Fuse layers → verdicts, render console/HTML/plain-language |
| `monitor.py` · `sentinel.py` | Drift diff (exit-2) · live proxy flight recorder |
| `detect.py` | Input classifier + API-probe state machine + consent + egress budget (§5) |
| `presets.py` | Known-vendor presets + env-key lookup (hostname-safe) |
| `omniroute.py` | OmniRoute detect / calibration gate / three-state cross-check (§6) |
| `wizard.py` | Paste → synthesize template target, dry-run, secure save (§5) |
| `capture_guide.py` · `capture_playwright.py` | Guided + optional two-phase capture (§7) |
| `client.py` · `config.py` | Transport (openai/anthropic/raw/template) · `Target` |
| `serve.py` | Local 127.0.0.1 web UI: probe tool + wizard + agent board |
| `reference.py` · `data/` | Reference corpus build/verify + committed vectors |
