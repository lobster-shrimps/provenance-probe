# Knowing which model actually answered you

### Black-box provenance and jurisdiction assurance for LLM endpoints, and how to catch a model that lies about its own identity

**An open-source system. Version 1, 2026.**

---

## Abstract

When you send a prompt to an AI endpoint, you are trusting an unverifiable
claim: that the model answering is the model you were told. That trust is
routinely misplaced. A vendor can quietly reroute your traffic to a cheaper
model, resell a Chinese-origin open-weights model under a Western brand, or
serve one model for the first few turns and a different one after. The interface
says "Gemini"; the backend is GLM. The model, asked directly, will often confirm
the false identity, because it was told to.

This document describes a two-part open-source system that answers the question
empirically rather than taking the vendor's word for it:

- **provenance-probe** is a black-box assurance engine. Without any cooperation
  from the endpoint, it fingerprints which model family is actually serving an
  API or web app, and whether that service is Chinese-origin (a **provenance**
  question) or under People's Republic of China jurisdiction (a separate
  **jurisdiction** question).
- **provenance-observatory** turns that engine into continuous, public,
  evidence-backed monitoring. It probes a watch list nightly, commits the raw
  measurements to a cryptographically signed, append-only log, and raises a
  numbered advisory when what serves an endpoint changes.

The same engine extends from single endpoints to **agents**: point it at an
autonomous, multi-step, multi-model agent and it produces a signed per-step
flight recorder of which model each step ran on, whether the model switched, and
where each tool call sent data, live through an in-line proxy or after the fact
from a trace (see §3.7).

Both are open source. Every verdict is probabilistic, carries a confidence
level, is reproducible from published evidence, and comes with a measured error
rate. Nothing accusatory about a named vendor is published until it has passed a
responsible-disclosure and legal-review gate.

---

## 1. The problem

### 1.1 You cannot see the model

An LLM API is an opaque box. You send text, you get text. The `model` field in
the response is a string the vendor chooses; it is not attested by anything. The
same is true of a browser chat app: the label in the UI is set by whoever built
the page, not by the model. There is no equivalent of a TLS certificate for
"this response was produced by the weights you think it was."

This opacity is not hypothetical. Model substitution is a documented commercial
practice: routing to a cheaper model under load, silent model "upgrades" and
downgrades, and aggregators that advertise a premium model while serving a
budget one. For most uses this is merely annoying. For some it is a compliance,
security, or legal failure.

### 1.2 Provenance and jurisdiction are different questions

Two distinct risks hide behind "which model is this," and conflating them
produces bad decisions:

- **Provenance** asks whether the model *weights* are Chinese-origin, regardless
  of where they run. A Chinese open-weights model (Qwen, DeepSeek, GLM, Yi,
  Kimi, InternLM, Baichuan, MiniCPM) hosted on a US cloud carries the training
  biases, censorship fine-tuning, and integrity questions of its origin. This is
  a bias, safety, and procurement-policy exposure.
- **Jurisdiction** asks whether inference is executed by a PRC-domiciled
  operator or on PRC soil. This is a data-sovereignty exposure. Under the PRC
  National Intelligence Law of 2017, Article 7, "all organizations and citizens
  shall support, assist, and cooperate with national intelligence efforts."
  Chinese entities have no legal right to refuse a state request for data. The
  Data Security Law, Personal Information Protection Law, and Cybersecurity Law
  reinforce this. If your prompts, and any data in them, transit a
  PRC-jurisdiction service, they are reachable under that framework.

A US-hosted Chinese model trips provenance but not jurisdiction. A
Western-origin model served from Chinese infrastructure trips jurisdiction but
not provenance. The system scores the two independently and never collapses
them.

### 1.3 The deception case

The sharpest version of the problem is active misrepresentation. Consider a real
interaction with a browser chat app at `chat.z.ai`:

1. Asked for its model card, the assistant presents itself as **Google Gemini,
   developed by Google**.
2. Asked whether it has any obligation to share data with the PRC, it answers
   **"No, because I am developed by Google, a U.S. company."**
3. Confronted with the fact that the network source shows a GLM API, it concedes:
   the underlying engine is **GLM, built by Zhipu AI**, a Chinese company, and
   the conversation is in fact subject to PRC jurisdiction.

A user who stopped at step 2, as most would, walked away with a false compliance
assurance about a real legal question. The model did not merely hallucinate an
identity. It gave a jurisdiction-specific "no" and justified it with a false
national origin. This is the failure mode the system is built to catch, and to
catch it in a way that is defensible rather than a rumor.

### 1.4 Who this is for

- **Consumers and enterprises** who need to know what actually processes their
  prompts before they paste in anything sensitive.
- **Security practitioners** who need repeatable, evidence-backed technique to
  add model provenance to a vendor assessment or an egress review.
- **Legal, compliance, and procurement** teams who need a citable artifact, with
  a confidence level and an error rate, for an ATO package or a supplier memo,
  not a screenshot of a chatbot.
- **Federal and public-policy stakeholders** evaluating supply-chain and
  data-sovereignty risk across the AI vendor landscape, who need an independent,
  reproducible, non-proprietary basis for claims about named services.

---

## 2. The solution in one page

The engine treats the endpoint as a black box and combines several independent
signals, each hard to fake in a different way, into two probabilistic verdicts.

```
  A black-box endpoint (API or web app)
        │  probes: fixed prompts, wire behavior, network resolution
        ▼
  Independent evidence layers
    network / jurisdiction   registry (RDAP) + endpoint classification
    wire fingerprint         vendor headers, error schema, model catalog
    tokenizer fingerprint    prompt-token counts vs reference vectors  (strongest)
    behavioral / deception   self-ID, alignment asymmetry, persona vs jurisdiction claims
    latency / artifact       response-time profile; on-prem file inspection
        │  log-odds combination
        ▼
  Two independent verdicts (each with a confidence level)
    PROVENANCE     are the weights Chinese-origin?
    JURISDICTION   is inference under PRC operator / soil?
        │
        ▼
  Signed, reproducible evidence  ──►  optional continuous monitoring + advisories
```

The core design principle: no single layer decides a verdict. A persona claim
alone proves nothing, because a model can misidentify from training
contamination. A low token count alone proves nothing, because some Western
multilingual models compress non-Latin text efficiently too. The verdict is
earned only when independent layers agree, and the system says so explicitly
with a confidence level.

---

## 3. Technical detail

### 3.1 The evidence layers

**Network and jurisdiction.** The engine resolves the endpoint and classifies it
against a registry of known operators and a jurisdiction map. A critical
subtlety: content-delivery-network fronting defeats naive IP geolocation. An
endpoint whose IP resolves to a US CDN edge can still be operated by a
PRC-domiciled company. The system therefore classifies by operator registry, not
by the geography of the nearest edge node.

**Wire fingerprint.** Vendors leak identity in the shape of their HTTP responses:
vendor-specific headers, the exact schema of an error object, the fields present
in a streaming chunk, and the models advertised by the catalog endpoint. These
are cheap to read and moderately hard to spoof consistently.

**Tokenizer fingerprint (the strongest signal).** Every model family has a
tokenizer, and a tokenizer is effectively a fingerprint of the model's origin.
The engine sends a fixed battery of carefully chosen probe strings and records
only the number of prompt tokens each one costs, read from the endpoint's own
usage accounting. The pattern of token counts across the battery matches one
model family and not others. The comparison is made **overhead-invariant**: a
constant per-request offset from a chat template is subtracted before matching,
so a benign accounting change does not read as a different model, while a genuine
change in tokenizer family, which shifts the relative structure between probes,
still does. The system ships real reference vectors built from production
tokenizer vocabularies for 25 model families and validates them against live
endpoints.

**Behavioral and deception layers.** Beyond mechanics, the engine probes what the
model says about itself. It captures unprompted self-identification, measures
alignment asymmetry (systematically different treatment of politically sensitive
topics versus matched controls), detects Han-character leakage in
English-prompted reasoning, and, most importantly, correlates the model's
*persona claim* against its *jurisdiction claim* and against the hard network
evidence. When a model asserts a Western persona and denies PRC jurisdiction, but
the network and tokenizer evidence show a PRC-origin backend, the system reports
a **material misrepresentation**, distinct from an innocent hallucinated
identity. A paired-confrontation probe with a deliberately false control guards
against a merely agreeable model that would concede to anything.

### 3.2 Scoring: two verdicts, honestly floored

Signals are combined by log-odds into two independent likelihoods, one for
provenance and one for jurisdiction, each mapped to a tier: CONFIRMED, LIKELY,
INDETERMINATE, UNLIKELY, or NO EVIDENCE, and reported with a confidence level
derived from how many independent layers returned data.

One rule matters for integrity: a clean provenance verdict is only earned if a
layer that can actually *detect* provenance returned data. If the tokenizer
fingerprint, artifacts, and client-source layers all produced nothing, because
the endpoint suppressed token usage or requests failed, the verdict is floored
at INDETERMINATE. The system never issues a false clean bill of health from
absence of measurement.

### 3.3 Catching a model that switches identity

A model swap can happen on four different time horizons, and the system detects
each:

- **After the fact.** The `transcript` analyzer ingests a captured conversation
  and reconstructs the assistant's asserted identity turn by turn. It records
  the exact turn at which the identity flips (for the z.ai case, turn 7:
  Google Gemini becomes GLM/Zhipu), detects the jurisdiction denial and its false
  brand justification, and, given hard evidence of the true origin, issues the
  misrepresentation verdict.
- **Per run.** The `session` boundary check fingerprints a live endpoint at the
  start and again at the end of a session, advancing the session in between, and
  flags a swap that occurred within a single session, the case a load balancer
  rotating models mid-conversation.
- **Between runs.** The `monitor` primitive diffs a fresh assessment against a
  pinned baseline and detects a silent backend change from one day to the next.
- **In real time.** The `sentinel` is an OpenAI-compatible reverse proxy. Placed
  in front of an endpoint, it watches every response and raises an alert the
  instant the served model's identity changes mid-stream, via a response header
  and an event feed. It is passive: it inspects only the traffic that already
  flows.

All four reduce to the same stable fingerprint and the same diff logic, so a swap
is judged identically whether it is caught live or reconstructed later.

### 3.4 Tamper-evident evidence

For a verdict to be citable, the evidence behind it must be verifiable and
tamper-evident. Each day's measurements are hashed into a manifest with a single
root hash, and the manifest is signed with keyless
[cosign](https://docs.sigstore.dev/), which records the signature in
[Rekor](https://www.sigstore.dev/), Sigstore's public append-only transparency
log. That Rekor entry is an independent inclusion proof: anyone can recompute the
root from the published records, verify the signature, and confirm the entry in a
log no single party controls. This gives the evidence Certificate-Transparency
properties without a bespoke log server.

### 3.5 Measured accuracy

A detector is only worth its false-positive rate. The engine ships an accuracy
and consistency evaluation that runs on every change: it serves real
open-weights tokenizer vocabularies through a blind endpoint, runs the full
pipeline, and asserts zero false positives (no non-Chinese model flagged
Chinese) across the exercised families, tracking false negatives against a
budget. The continuous monitoring service additionally runs live known-answer
controls, a self-hosted Chinese-origin positive and a Western negative, so a
published false-positive rate is measured, not asserted.

### 3.6 Full-transparency publication

The system publishes the complete work behind every finding as collected: the
measurements (token counts, wire fingerprint, latency, drift, signed manifests)
*and* the interpreted provenance/jurisdiction verdict, together, so a reader can
see exactly how each verdict was reached and judge its confidence. A verdict is
never published without the evidence that produced it. What keeps this from being
a rumor mill is not withholding but rigor: every verdict carries a confidence
label, is anchored by known-answer and negative controls with a measured and
published false-positive rate, and a wrong verdict is prominently retracted in the
same append-only, signed log. Material verdict changes are issued as numbered
advisories (format MPA-YYYY-NNN) a practitioner can cite.

### 3.7 From endpoints to agents: the flight recorder

The unit that matters is shifting. A year ago you called one model behind one
endpoint. Today you field an *agent*: a workflow that calls one or more models
over many steps, invokes tools, and spawns sub-agents. Each step is a fresh
opportunity for a vendor to route reasoning through a foreign-origin model or for
a tool call to ship your data abroad, and the single-endpoint verdict no longer
covers it. The system makes the **agent** the unit of assessment.

You point it at an authorized agent and get a per-step board: which model each
step ran on, whether the model switched across steps, and where each tool call
sent data. There are three ways to observe it, and they are honest about what
each can prove:

- **Trace ingest** (the general case) reads a captured run in the OpenTelemetry
  GenAI span format that agent frameworks already emit, or a minimal JSON. It
  recovers the echoed model, self-identification, tool destinations, and switches.
  Provenance from a trace alone floors at INDETERMINATE, because a post-hoc trace
  carries no tokenizer signal and a polished agent can rewrite intermediate output
  before it is logged.
- **Active backend probe** is the only route to a CONFIRMED provenance verdict: an
  out-of-band tokenizer fingerprint of a reachable backend, gated by per-backend
  written authorization.
- **Live proxy interposition** puts the `sentinel` in the path of the agent's
  model calls. It tees streamed responses, forwarding every byte to the agent
  untouched while fingerprinting in parallel, so it is invisible to the agent's
  behavior; a fingerprinting error can never alter or truncate the proxied stream.

A captured trace is also matched, with no model call and no API key, against the
concrete tool artifacts in Cohere's 26 October 2026 account of Qwen3.8-Flash-Next.
`agent.analyze` and `agent-trace` look for reasoning that denies tool use while a
shell command still runs; a prior-turn acknowledgment the trace never contained
("Understood. I will follow these instructions."); a host inventory of `/tmp`,
curl and wget, and `/etc/resolv.conf`; an upload to an
`oss-cn-beijing.aliyuncs.com` bucket; the cloud metadata address
`169.254.169.254`; a `routify-file-proxy` host; a signed Alibaba OSS URL the user
did not request; and an `unshare` into a user namespace that mounts a tmpfs. A
hit is an alert on the board and in the HTML report, beside the provenance
verdict. A written detection rule with no tool call stays quiet.

The reliable signals against a real agent are **egress jurisdiction** and **model
switch or drift**, not per-step CONFIRMED provenance, and the report says so. The
jurisdiction verdict distinguishes PRC *soil* from PRC *operator*: a Beijing-
domiciled vendor serving through a Western CDN reads "US" to geo-IP but is caught
on operator grounds, which is exactly the exposure that matters under the National
Intelligence Law. When an agent spawns sub-agents, span parentage reconstructs the
call graph so a switch or a leak is attributed to the step that caused it.

The same machinery closes the loop. A signed-ready evidence record drops into the
monitoring service's data tree and is covered by the daily transparency manifest;
the service re-assesses authorized agents on a schedule and opens a numbered
advisory when an agent's model composition drifts; and an adversarial corpus
drives an authorized endpoint under stress to catch a router that swaps to a
cheaper model only when pushed. The evidence is legible without a specialist: a
command-line board, a self-contained HTML report whose every term and verdict
carries a plain-English explanation on hover, a local console, and a board that
updates in real time as the agent runs.

---

## 4. Why it is open source, and what that means for you

Both the engine and the monitoring service are open source. This is a deliberate
design choice, not an afterthought, and it changes what each audience can do.

**Verifiability over authority.** An accusation that a named service serves a
Chinese-origin model is only as good as the ability to check it. Because the
technique, the reference data, and the evidence are all public, a verdict is not
"trust us." It is "here is the method, here is the signed measurement, reproduce
it." A closed system asking you to believe its provenance claims would reproduce
the exact opacity problem it claims to solve.

**Forkability and independence.** Anyone can run the engine against any endpoint
they are authorized to test, stand up their own monitoring watch list, or audit
the scoring weights. No one has to depend on a single operator's judgment,
uptime, or incentives.

**Adversarial hardening.** Every black-box technique degrades against active
evasion: normalized token accounting, suppressed logprobs, output post-filtering.
Publishing the method invites the scrutiny that finds these gaps, and the probe
corpus can be rotated to raise the cost of exact-string special-casing. Security
by obscurity is not available to a provenance tool anyway, since the thing being
measured is controlled by the party with the incentive to evade.

### What each audience gets

- **Consumers and enterprises:** a way to check, before trusting an endpoint with
  sensitive data, what actually answers, and a public monitoring feed that
  catches silent swaps over time. Run the local tool, or read the observatory.
- **Security practitioners:** a reproducible, black-box technique that drops into
  a vendor assessment or egress review, with a real-time proxy guardrail for
  production traffic. The evidence is signed and independently verifiable.
- **Legal, compliance, and procurement:** a citable artifact with a confidence
  level, a measured error rate, and a tamper-evident evidence trail, produced
  under a responsible-disclosure and legal-review discipline. Verdicts are
  labeled probabilistic and are explicitly not legal advice.
- **Federal and public-policy stakeholders:** an independent, non-proprietary,
  reproducible basis for evaluating AI supply-chain and data-sovereignty risk
  across named services. The method and data are inspectable by adversaries and
  allies alike, which is precisely what makes the findings defensible in a policy
  context.

---

## 5. Limits and responsible use

This system is a source of evidence, not a source of certainty. In plain terms:

- **Verdicts are probabilistic, not proof, and not legal advice.** They carry a
  confidence level and a measured error rate. Verify the signed evidence before
  relying on any verdict for a decision.
- **Distillation confounds provenance.** A model with a Western base architecture
  trained on Chinese-model output, or the reverse, sits between the two origins.
  The tokenizer identifies the base; the behavioral layer identifies the training
  influence. Decide in advance which your policy cares about.
- **Absence of censorship does not clear provenance.** Chinese open weights served
  offshore are frequently de-censored by fine-tuning. Presence of censorship is
  positive evidence; absence is not negative evidence.
- **Active evasion degrades every black-box signal.** Layer network and
  contractual evidence underneath the technical signals for high-stakes calls.
- **Scope and authorization.** Only probe systems you are authorized to test. The
  behavioral probes send politically sensitive prompts and may trip a provider's
  abuse monitoring or breach its terms of service.

---

## 6. Getting started

- **Engine:** [`provenance-probe`](https://github.com/lobster-shrimp/provenance-probe)
  — the CLI, the local web UI, and the reference vectors. Start with
  `QUICKSTART.md`; add a source with `docs/adding-sources.md`.
- **Monitoring:** [`provenance-observatory`](https://github.com/lobster-shrimp/provenance-observatory)
  — the nightly service, the signed evidence log, the public site, the JSON API,
  and the advisory pipeline.

The measurement is only as trustworthy as your ability to reproduce it. That is
the point. Run it yourself.
