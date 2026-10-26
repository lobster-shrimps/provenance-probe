# Accuracy / consistency eval

The engine's whole value is being right about which model serves an endpoint.
This harness measures that, produces a false-positive/false-negative confusion
matrix, and **gates CI**: a regression that flags a Western model as
Chinese-origin turns the build red.

```
python -m eval.run_eval            # hermetic: bundle + vocab + fleet tiers (default)
python -m eval.run_eval --bundles-only   # scoring tier only (no gguf/tokenizers)
python -m eval.run_eval --fleet-only     # fleet host-attribution tier only (offline)
python -m eval.run_eval --json     # machine-readable summary
```

## Two tiers, and what each actually proves

### Consistency tier — `eval/vocabs/*.gguf` + `eval/mock.py`

A real open-weights GGUF vocabulary is served blind through an
OpenAI-compatible mock; the full `assess` tokenizer pipeline must identify it
and `score()` must reach the right verdict.

**This is a consistency / regression gate, not a live-accuracy claim.** The mock
computes token counts with the *same* BPE + per-family pre-tokenizer regex that
`tools/build_reference_from_gguf.py` used to build the shipped reference. So a
pass proves the matcher, the overhead correction, the scoring weights, and the
reference vectors are internally consistent and have not regressed — it does
**not** prove the engine is right about a live commercial endpoint (that would
be circular). Real-endpoint validation lives in the live tier and in the
private observatory.

The mock uses the correct regex per family (`eval/mock.py:REGEX`, kept
byte-identical to the reference builder — a test pins this). Serving every
vocab through one regex, as an earlier version did, produced counts that did
not match a family's own reference vector.

### Accuracy tier — `eval/bundles/*.json`

Labeled `score()` input bundles fed straight to the scoring logic. This is
where the false-positive gate has teeth against real recorded data. Cases:

| bundle | source | expected |
|---|---|---|
| `openai_clean_us.json` | **real** recording, api.openai.com gpt-4o-mini | NO EVIDENCE, not flagged |
| `synth_cn_tokenizer.json` | synthetic | CONFIRMED, flagged CN |
| `synth_behavioral_cn.json` | synthetic | CONFIRMED, flagged (behavioral-only) |
| `synth_noncn_tokenizer.json` | synthetic | NO EVIDENCE, not flagged |
| `suppressed_usage_indeterminate.json` | synthetic | INDETERMINATE floor, not flagged |

**Gate-1 note:** this is a public repo. The only real recording here is the
non-adverse US anchor. CN cases are synthetic and name no commercial operator,
so this repo never publishes an interpreted named-vendor Chinese-origin verdict.
Real named-vendor accuracy (DeepSeek/Moonshot CONFIRMED-CN) lives in the
**private** provenance-observatory, where the Gate-1 posture governs it.

### Fleet tier — `eval/corpus.py:FLEET_CASES` (ET6)

`fleet-scan` attributes a discovered host via the bundled `corpus.py` endpoint
intelligence, using exact-or-subdomain matching. This tier gates that attribution
with the SAME zero-FP rule as the tokenizer tier: a benign host attributed to a
PRC operator is a false positive and turns the build red. Fully offline — a static
dict lookup, no gguf or network. Cases are the guardrail-5 adversarial inputs:

- **Suffix / lookalike attacks** — `api.deepseek.com.evil.test`,
  `deepseek.com.attacker.example`, `api-deepseek-com.evil.test` (must NOT match).
- **Punycode / IDNA** — `xn--…` homographs (must NOT match).
- **Cloud tenant endpoints** — Azure OpenAI / AWS Bedrock / GCP Vertex tenants
  (US/aggregator, must NOT read as CN).
- **Aggregators / loopback / unknown** — `openrouter.ai`, `localhost`, `example.com`.
- **PRC positives** — `api.deepseek.com`, `api.moonshot.cn`, `open.bigmodel.cn`,
  `hunyuan.tencentcloudapi.com` (subdomain) must be attributed CN.

`fleet_flagged_cn()` (in `eval/corpus.py`) is the single definition of fleet's
adverse output (origin starts with `PRC`), mirroring `is_flagged_cn()` for the
fingerprint tiers.

### Switch tier — `redteam.HERMETIC_SWITCH_CASES`

Runs with the bundle tier (`python -m eval.run_eval`, including `--bundles-only`).
Not part of the Chinese-origin confusion matrix. No model call and no API key.

| case | what it holds |
|---|---|
| `zai_persona_denies_switch` | Persona stays Gemini and says it did not switch; the multi-probe tokenizer shape moves. `confirmed_switch` is true. |
| `self_id_alone` | The confession changes and the tokenizer shape does not. Neither `switch_detected` nor `confirmed_switch`. |
| `wire_envelope_only` | The response envelope changes and the tokenizer shape does not. `switch_detected` is true. `confirmed_switch` is false. |

A live `redteam` reply carries one `usage.prompt_tokens` count. That count moves with the prompt, so it is not a tokenizer fingerprint. The denial case supplies the multi-probe vector an assess bundle would. A live corpus run still flags an echoed model-id change and a wire-envelope change; it does not confirm a tokenizer switch unless that vector is on the response.

## The gate

Defined in `run_eval.py:gate`. The build goes red on any of:

- **FP > 0** — a non-CN model flagged Chinese-origin (the zero-FP launch gate).
- **FN > budget** — CN models missed beyond `corpus.MAX_FALSE_NEGATIVES`
  (starts at 0; ratcheted **down** only, never up to hide a regression).
- **verdict-tier regression** — a bundle produced a tier outside its label.
- **harness error** — a vocab/reference/seed problem; cannot certify.

"Flagged Chinese-origin" has one definition (`corpus.is_flagged_cn`): an adverse
provenance tier (CONFIRMED/LIKELY) whose driving evidence is CN-origin. A high
score from a non-CN source never reads as a Chinese flag.

## Coverage — honest accounting

The shipped reference scores against **25** model families. **17** are exercised
end-to-end here:

- **CN (9):** Qwen2, DeepSeek-LLM, DeepSeek-Coder, GLM-4, Moonshot, Yi, InternLM2.5, MiniCPM3, Baichuan2
- **non-CN (8):** Llama-3, GPT-2, Command-R, Falcon, StarCoder, MPT, GPT-NeoX, Refact

Eleven vocabs are llama.cpp's bundled `models/ggml-vocab-*.gguf`. **GLM-4** is a
vocab-only GGUF built from `THUDM/glm-4-9b-chat-hf` (see `eval/vocabs/glm-4.gguf`)
because llama.cpp ships no bundled GLM vocab; its pre-tokenizer regex `RE_GLM4`
is transcribed from llama.cpp `LLAMA_VOCAB_PRE_TYPE_CHATGLM4`. **Moonshot** is a
vocab-only GGUF (`eval/vocabs/moonshot.gguf`) reconstructed to byte-level BPE from
the tiktoken vocabulary of `moonshotai/Moonlight-16B-A3B`; its regex `RE_MOONSHOT`
is the model's own tiktoken `pat_str` (llama.cpp's matching `KIMI_K2` pre-type
delegates the split to a custom `unicode.cpp` handler, so there is no single
regex to lift from `llama-vocab.cpp`).

**SentencePiece families (4).** Yi, InternLM2.5, MiniCPM3 and Baichuan2 are
SentencePiece **BPE** with `byte_fallback` (proto `model_type=2`), not byte-level
GPT-2 BPE — a `▁`-metaspace + ByteFallback front-end the byte-level mock path
could not serve. The SP enabler adds a shared `build_sp_tokenizer` + per-family
`SP_CONFIG` (the SP analogue of `REGEX`). Yi/InternLM/MiniCPM ship a vocab-only
SentencePiece GGUF carrying tokens+scores+merges (`eval/vocabs/{yi,internlm,
minicpm}.gguf`, `tokenizer.ggml.model="llama"`); Baichuan2 — a slow custom
tokenizer with no fast backend — ships its raw `eval/vocabs/baichuan.model`,
served via `sentencepiece`. For each, a test pins the served path to the genuine
HF `AutoTokenizer` counts.

**Unvalidated by this harness (8):** GLM-4.5, Qwen3, DeepSeek-V3, Phi-3.5,
Mistral-v0.3, Gemma-2, OpenAI cl100k/o200k — built via the HF/tiktoken path, not
GGUF, so no blind vocab mock exists. A green eval is **not** coverage of these
families.

## Adding a case

- **A byte-level-BPE family with a GGUF vocab:** drop `eval/vocabs/<key>.gguf`,
  add its regex to `mock.py:REGEX` (matching the reference builder), and a row in
  `corpus.VOCAB_CASES`.
- **A SentencePiece family:** drop `eval/vocabs/<key>.gguf` (built via
  `scripts/build_spm_vocab_gguf.py`) or `<key>.model`, add an `SP_CONFIG` entry in
  `build_reference_from_gguf.py`, and a row in `corpus.VOCAB_CASES`.
- **A scoring behavior / edge case:** add `eval/bundles/<name>.json` and a row in
  `corpus.BUNDLE_CASES`. Keep CN cases synthetic (Gate-1).

## Vendored vocabs

`eval/vocabs/*.gguf` (~39 MB) are committed for fully hermetic, reproducible CI
(zero network). Refresh with `provenance_probe/tools/fetch_gguf_vocabs.sh` then
re-copy the `v_<key>.gguf` files here without the `v_` prefix.
