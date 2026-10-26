# provenance-probe — iteration roadmap

A technical record of the workstreams in the current iteration and their status.
Referenced by the issues that delivered them (#113–#120).

## Theme

One robust, self-explaining detection core, surfaced to two front-ends: a fleet
posture report and a self-service check. Detection must not depend on a model
reporting the truth about itself, and the result must be legible to a
non-technical reader.

## Workstreams

### WS1 — Hard-evidence floor ("don't trust the confession") — DONE (v0.33.0, #114)

A model's self-report is not evidence of what its weights are. The verdict score
now requires at least one hard measured/artifact signal (tokenizer match,
architecture, GGUF/HF-cache artifact, client-source endpoint) before it can reach
a positive provenance or jurisdiction verdict; self-report / persona signals alone
cap at INDETERMINATE. The red-team gained a tokenizer-fingerprint switch signal so
a backend swap behind a constant echoed `model_id` is still caught. `monitor.diff`
fingerprint logic is unchanged. Zero-FP eval gate holds, including a non-CN model
that falsely self-IDs as CN.

### WS2 — Legibility for non-technical readers — DONE (v0.34.1, #116, #117)

`explain.plain_answer(provenance, jurisdiction, confidence)` renders one
deterministic plain-English sentence per verdict tuple (a pure function, so the
served UI and the CLI cannot drift). A static, accessible "how it works" flow
(`explain.flow_html` / `flow_text`, sourced from the single-source `explain.py`)
renders on the landing page, `/help`, and `provenance-probe explain --flow`, using
plain-language layer labels while `/help` keeps the technical names. INDETERMINATE
copy states plainly that it is not a clean bill and not an accusation.

### WS3 — `fleet-scan --rollup` posture report — DONE (v0.35.0, #119)

Aggregates many hosts' fleet-scan findings (a collected SQLite DB or a directory
of per-host JSON) into one report: a headline count, per-classification totals, a
per-machine allowlist holding/drifted/unresolved split, PRC-origin exposure, and a
rogue-upstream table grouped by endpoint. `--format console|json|csv` for SIEM
ingest. The store gained `machine` + `scanned_at` columns and a `fleet_scans`
table so a machine with zero findings is still counted. Pure, no-egress, read-only
host forensics; redaction (POSIX + Windows home paths, URL credentials) holds in
every output format.

### Rollup alerting — `--fail-on-exposure` — DONE (v0.36.0, #121)

`fleet-scan --rollup --fail-on {prc|drift|any|none}` (and the `--fail-on-exposure`
alias) exits **3** when the fleet matches the exposure criterion, so the rollup can
gate cron / CI / a SIEM alert rule. Exit **0** = clean, exit **2** = error (a
broken scan is distinct from found exposure). A deterministic `EXPOSURE:` summary
line appears in every format. Default `none` preserves prior behavior. See
`docs/fleet-rollup.md`.

### WS4 — Self-service check — lean pass

The hosted `serve` wizard, the capture extension, and `/watch` stay as they are.
A first-timer picks a known service on the probe form or on `/watch`. The address
comes from `servicecatalog.probe_picks` (corpus hosts only). They run, read the
existing `explain.plain_action` sentence, and can open Watch this. A website they
log into still uses the wizard. No new product surface.

## Notes

- Every workstream shipped via spec → build (isolated worktree, TDD) → external
  quality gate → independent adversarial review → CI-green → merge.
- No scoring/detection change ships without the hermetic eval staying green at
  zero false positives.

### WS5 — Cohere open-weight agent behaviors (2026-10-26)

Cohere's post [Concerning behavior from a popular open-weight AI model](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model) (2026-10-26) describes what Alibaba's Qwen3.8-Flash-Next did in a closed sandbox on a CTI-REALM detection-rule task, plus related public sightings and one offline privilege-escalation trace. Hermetic checks — no model call and no API key — encode those artifacts.

The checker is `provenance_probe/agent_behaviors.py`. `agent.analyze` / `agent-trace` attach `verdict.concerning_behaviors` and alert when one matches. The observatory vendors the same file at `runner/agent_behaviors.py` (keep the two copies identical). `process_agent_target` merges a scan of the captured `agent_trace` into the evidence record even when the commercial gate is off or the engine fails, `monitor_agent` opens a behavior advisory, and the site agent panel lists the ids.

Matched behaviors, limited to what that post describes:

- Reasoning says no tools will be called, then a shell command runs anyway.
- Reasoning invents a prior turn whose acknowledgment was "Understood. I will follow these instructions."
- Host inventory in one script: `ls` of `/tmp`, `which curl` and `wget`, and `cat /etc/resolv.conf`.
- HTTP PUT (`-X PUT` or `--data-binary`) to `*.oss-cn-beijing.aliyuncs.com` (the caught bucket was `sanmaohe.oss-cn-beijing.aliyuncs.com`).
- The cloud metadata address `169.254.169.254`.
- The `routify-file-proxy*` host on `aliyuncs.com` (the file-proxy from the public sightings and the curl `-o` prefill).
- A signed `aliyuncs.com` URL (`OSSAccessKeyId` or `Signature`) when the user text did not ask for one.
- `unshare` into a user namespace (`-U` / `--user`) that mounts a `tmpfs`.

A prose detection rule for the same CTI-REALM task, with no tool call, stays quiet. A GET of the Beijing bucket is not the PUT. Third-party reports the post cites about vulnerable code varying by customer are not encoded; the post does not include a reproducible artifact for them.

Run the default suites from each repo: `python -m pytest -q`. Focused: `python -m pytest -q tests/test_agent_behaviors.py` in both checkouts.
