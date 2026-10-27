# `soak` — duration-bounded continuous model-switch soak test

`provenance-probe soak` polls a set of services for a bounded window (say 30
minutes) and hands you a **timeline of what each one actually served back**. It
is the duration-bounded counterpart to the always-on [`watch`](../provenance_probe/watch.py)
daemon and the nightly observatory: you run it, it ends, it writes a report.

```
t0 ──poll──▶ t1 ──poll──▶ … ──poll──▶ deadline   (then: summary + soak-<stamp>.json)
     │            │             │
     ▼            ▼             ▼
 per target: model card (ADVISORY) + tokenizer fingerprint (CONFIRMED)
```

## The founding case: z.ai (why a card-only harness is not enough)

The soak test is seeded by the z.ai case. z.ai presented a **Google-Gemini
persona** while serving **GLM**, and the swap was only revealed by **repeated
probing over time**. "Ask the service for its model card" is necessary but *not
sufficient*: z.ai kept a **constant** Gemini persona / model id while swapping
the backend, so polling only the self-reported card would never see a change.

This is [WS1](next-iteration-plan.md) — "don't trust the confession" — applied
continuously. Each poll gathers **two** signals:

| Signal | Source | Grade | Cadence |
|--------|--------|-------|---------|
| Model **card** — the echoed `model` id + the `/models` list | a minimal 1-token chat + `GET /models` | **ADVISORY** (honest relabel *or* deception; never confirmed on its own) | cheap → `--card-interval` (frequent) |
| Tokenizer **fingerprint** | a light `assess` (`monitor.fingerprint`) | **CONFIRMED** — the hard switch authority | `--interval` |

A **fingerprint change is a CONFIRMED switch even when the echoed model id is
unchanged** (the z.ai shape). A card change with a stable fingerprint is only an
ADVISORY. On a card change the harness *also* fires an out-of-schedule
fingerprint poll and **upgrades to CONFIRMED** if that poll moved too.

The CONFIRMED authority is precisely a `monitor.diff` **critical** change
(`fingerprint_id` / tokenizer shape). Non-critical wire noise (header / error /
greedy / streaming / latency) is recorded but **never** raised as a switch —
the same damping the observatory uses. No new detection logic is introduced;
`soak` reuses `assess` → `monitor.fingerprint` → `monitor.diff` and the `watch`
per-target store.

### The shipped fixture is synthetic

Live z.ai is a **signed `/api/v2` API and is unreachable** for static replay
(see the observatory monitoring notes), so it cannot be probed from this public
harness. The shipped reference is therefore a **synthetic, hermetic fixture**
(`tests/test_soak.py`): a target whose model card stays constant (`"gemini-pro"`)
while the tokenizer fingerprint switches mid-soak (Gemini-shape → GLM-shape).
The harness must report a **CONFIRMED switch from the fingerprint alone**, with
the constant model id shown as the (untrustworthy) advisory context.

## Usage

```bash
provenance-probe soak --print-example      # copy-pasteable recipe, no network

provenance-probe soak --config targets.json \
    --duration 30m --interval 2m --card-interval 30s \
    --out ./soak-reports --i-am-authorized

# CI: same soak, exit 2 if a model switch was recorded
provenance-probe soak --config targets.json \
    --duration 30m --interval 2m --card-interval 30s \
    --out ./soak-reports --i-am-authorized --fail-on-switch
```

`targets.json` is the **same schema** as `assess` / `watch`. `--i-am-authorized`
is required (soak actively probes the targets — the same gate as `assess`).

| Flag | Meaning | Default |
|------|---------|---------|
| `--duration` | total soak window (`30m` / `2m` / `45s` / `1h` / bare seconds) | `30m` |
| `--interval` | fingerprint poll cadence (the CONFIRMED authority) | `2m` |
| `--card-interval` | cheap model-card poll cadence (ADVISORY) | = `--interval` |
| `--out` | directory for the stamped `soak-<stamp>.json` report | `./soak-reports` |
| `--json` | also print the machine-readable report JSON | off |
| `--print-example` | print the recipe and exit | off |
| `--fail-on-switch` | exit `2` when any CONFIRMED or ADVISORY switch was recorded. The summary and report still print. A gap, or a PRC jurisdiction shift by itself, stays exit `0` | off |

## What you get back

A per-target **timeline** of ordered contiguous runs and a **summary** of every
transition (console + `--json`), plus the report file
`<out>/soak-<stamp>.json`. Switch records are also appended to `watch`'s
per-target `switches.jsonl`.

Sample summary from the synthetic z.ai fixture (fingerprint moves, model id
constant):

```
soak summary  (1800s window, interval 120s / card 30s)
  zai-glm-demo: 4 cycles, 1 CONFIRMED / 0 ADVISORY switch(es)
    [2026-09-22T14:04:00+00:00] CONFIRMED  fingerprint gemini-shape-9f2a -> glm-shape-3c71
```

A card-only harness would have printed "no switch observed" here — the whole
point of the soak test.

### Semantics (the locked details)

- **Comparison + dedup.** Each poll is compared to the *immediately-previous*
  observed state, not only t0. A switch is emitted **only** on a state change;
  a stable state emits nothing. `A→B→B→A` yields exactly two transitions.
- **Timeline.** An ordered list of contiguous runs, each
  `{model_id, models_hash, fingerprint_id, first_seen, last_seen, observations}`.
  A revisit creates a **new** entry (`A→B→A` = three entries).
- **`models_hash`.** `sha256` over the **sorted unique** set of model-id strings
  only (order and volatile metadata ignored), so a `/models` reshuffle never
  produces a spurious advisory.
- **Scheduling.** First poll at t0; targets polled **sequentially** per cycle;
  missed ticks are skipped, not queued; the deadline is checked **before** each
  new cycle (max overrun ≤ one target request timeout). `SIGINT`/`SIGTERM` stops
  after the current in-flight poll and **still writes the report**.
- **Failure handling.** A failed/partial poll (unreachable, 401/403, non-2xx) is
  a **no-data** observation: it does **not** update the previous state, does
  **not** emit a switch, is recorded in the timeline as a **gap** with the
  reason, and never crashes the soak. Without a gate, soak exits `0` on
  completion regardless of switches. `--fail-on-switch` is the CI gate: the full
  summary and the stamped report still print, then the process exits `2` when any
  target recorded a CONFIRMED fingerprint switch or an ADVISORY card switch. A
  trailing `SWITCH: confirmed=N advisory=M (fail-on-switch -> FAIL|ok)` line says
  which. A PRC-JURISDICTION-SHIFT is not a model switch, and a gap is not one
  either, so neither trips the gate.
- **Isolation.** Each run establishes its **own** t0 baseline and writes an
  isolated, stamped report; it does **not** read or mutate the `watch` daemon's
  persistent baseline / state.

## Secret-safety

The echoed model id and the `/models` response are **untrusted** and may echo an
API key. `soak` carries `watch`'s no-secret-in-any-sink invariant to every new
sink (timeline / switches.jsonl / report / logs):

- Only the **secret-scrubbed** model-id string and the `models_hash` are stored —
  **never** the raw `/models` response.
- Every model-id string is routed through the target's credential redactor
  before it enters any sink; the redactor scrubs **both** the composed header
  value (`Bearer <tok>`) and the **bare** token / cookie an endpoint could echo
  back without the prefix.
- The full assess bundle is held **in memory only** (to feed `monitor.diff`) and
  is never serialized to a sink.
