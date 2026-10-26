"""Agent provenance flight recorder (Phase 1).

The unit of assessment is an AGENT: a workflow that calls 1..N models over M
steps and invokes tools. This module ingests an agent run and reports, per step,
which model it ran on, whether the model switched, and where its tool calls sent
data.

    trace file ─▶ parse_trace ─▶ AgentStep[] ─┬─▶ transcript._turn_identity(step.text) → self-ID / flip
      (OTel|JSON)  (one normalizer)            ├─▶ network.analyze_host(host)           → egress jurisdiction
                                               ├─▶ (active_probe, if authorized+reachable)
                                               │      tokenizer probe                    → CONFIRMED provenance
                                               └─▶ scoring.combine_agent(steps)          → agent verdict (worst)

Honesty rule: a post-hoc trace carries NO tokenizer signal (that needs active
max_tokens=1 probes), so trace-only provenance floors at INDETERMINATE in
scoring.py. CONFIRMED provenance is reachable ONLY through active_probe against a
reachable, authorized backend. Egress jurisdiction and model-switch detection are
the reliable trace-only signals.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import agent_behaviors, scoring
from .probes import network
from .probes import transcript as _tx


@dataclass
class AgentStep:
    """One normalized step of an agent run (a model call or a tool call).

    Both the OpenTelemetry-GenAI parser and the minimal-JSON parser produce this
    single shape, so everything downstream sees one type (DRY).
    """
    index: int
    kind: str                       # "model" | "tool"
    name: str                       # span/role name if present, else "call#N"
    echoed_model: str | None = None  # the model id the trace reports for this call
    text: str = ""                  # assistant text (for self-ID regex)
    tool_host: str | None = None    # destination host for a tool call (egress)
    backend_url: str | None = None  # the model endpoint this call hit, if known
    prompt_tokens: int | None = None
    # --- evidence-quality flags (live proxy mode) ----------------------------
    session_id: str | None = None   # the session this step belongs to (proxy mode)
    degraded: bool = False          # signal partially lost (e.g. fingerprint failed)
    unordered: bool = False         # arrival order unreliable -> withholds switch claims
    truncated: bool = False         # response body was capped before fingerprinting
    # --- sub-agent call graph (E6) -------------------------------------------
    span_id: str | None = None      # this step's id (OTel spanId)
    parent_id: str | None = None    # the id of the step/agent that spawned it
    command: str = ""               # tool command / arguments (behavior scan)
    reasoning: str = ""             # chain-of-thought, when the trace kept it separate


class TraceError(ValueError):
    """Raised when a trace cannot be parsed into steps."""


MAX_TRACE_BYTES = 32 * 1024 * 1024   # 32 MiB — a trace is a log, not a dataset
MAX_STEPS = 5000                     # bound the per-run step count
MAX_HOSTS = 256                      # cap distinct hosts resolved from one trace


# --- parsing -----------------------------------------------------------------

def _host_of(url: str | None) -> str | None:
    if not url:
        return None
    return urlparse(url).hostname or url or None


def _parse_otel(obj: dict) -> list[AgentStep]:
    """OpenTelemetry GenAI spans.

    Accepts either the OTLP shape ({"resourceSpans":[{"scopeSpans":[{"spans":[…]}]}]})
    or a flattened {"spans":[{"name":…, "attributes":{gen_ai.*}}]}. Attributes may
    be a flat dict or the OTLP key/value list form.
    """
    spans = _collect_spans(obj)
    steps: list[AgentStep] = []
    for i, sp in enumerate(spans):
        if not isinstance(sp, dict):
            raise TraceError(f"span {i} is not an object")
        attrs = _flatten_attrs(sp.get("attributes", {}))
        op = attrs.get("gen_ai.operation.name") or ""
        tool_name = attrs.get("gen_ai.tool.name")
        is_tool = bool(tool_name) or op in ("execute_tool", "tool")
        span_id = sp.get("spanId") or attrs.get("span.id")
        parent_id = sp.get("parentSpanId") or attrs.get("span.parent_id")
        command = _as_text(attrs.get("gen_ai.tool.call.arguments")
                           or attrs.get("gen_ai.tool.arguments"))
        reasoning = _as_text(attrs.get("gen_ai.reasoning") or attrs.get("gen_ai.reasoning.text"))
        if is_tool:
            host = _host_of(attrs.get("server.address") or attrs.get("url.full")
                            or attrs.get("http.url"))
            steps.append(AgentStep(index=i, kind="tool",
                                   name=str(tool_name or sp.get("name") or f"call#{i}"),
                                   tool_host=host, span_id=span_id, parent_id=parent_id,
                                   command=command, reasoning=reasoning,
                                   text=_as_text(attrs.get("gen_ai.completion")
                                                 or attrs.get("gen_ai.response.text"))))
        else:
            model = (attrs.get("gen_ai.response.model")
                     or attrs.get("gen_ai.request.model"))
            steps.append(AgentStep(
                index=i, kind="model",
                name=str(sp.get("name") or attrs.get("gen_ai.operation.name") or f"call#{i}"),
                echoed_model=model,
                text=str(attrs.get("gen_ai.completion") or attrs.get("gen_ai.response.text") or ""),
                backend_url=attrs.get("server.address") or attrs.get("gen_ai.system.endpoint"),
                prompt_tokens=_as_int(attrs.get("gen_ai.usage.input_tokens")),
                span_id=span_id, parent_id=parent_id,
                command=command, reasoning=reasoning))
    return steps


def _as_list(x, what: str) -> list:
    if not isinstance(x, list):
        raise TraceError(f"expected a list for {what}, got {type(x).__name__}")
    return x


def _collect_spans(obj: dict) -> list[dict]:
    if "spans" in obj:
        return _as_list(obj["spans"], "spans")
    out = []
    for rs in _as_list(obj.get("resourceSpans", []), "resourceSpans"):
        for ss in _as_list((rs or {}).get("scopeSpans", []), "scopeSpans"):
            out.extend(_as_list((ss or {}).get("spans", []), "spans"))
    return out


def _flatten_attrs(attrs) -> dict:
    """OTLP attributes come as [{"key":k,"value":{"stringValue":v}}] or a flat dict."""
    if isinstance(attrs, dict):
        return attrs
    flat = {}
    for kv in attrs or []:
        k = kv.get("key")
        v = kv.get("value", {})
        if k is None:
            continue
        flat[k] = (v.get("stringValue") if "stringValue" in v
                   else v.get("intValue") if "intValue" in v
                   else next(iter(v.values()), None) if isinstance(v, dict) else v)
    return flat


def _as_int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value)


def _parse_json(obj) -> list[AgentStep]:
    """Minimal hand-rolled fallback: {"steps":[{model,text,tool_host,backend_url,prompt_tokens}]}
    or a bare list of such step dicts."""
    rows = obj["steps"] if isinstance(obj, dict) else obj
    if not isinstance(rows, list):
        raise TraceError("JSON trace must be a list of steps or {'steps': [...]}")
    steps = []
    for i, r in enumerate(rows):
        if not isinstance(r, dict):
            raise TraceError(f"step {i} is not an object")
        host = r.get("tool_host") or _host_of(r.get("tool_url"))
        kind = r.get("kind") or ("tool" if host and not r.get("model") else "model")
        steps.append(AgentStep(
            index=i, kind=kind, name=str(r.get("name") or f"call#{i}"),
            echoed_model=r.get("model"), text=str(r.get("text") or ""),
            tool_host=host, backend_url=r.get("backend_url"),
            prompt_tokens=_as_int(r.get("prompt_tokens")),
            span_id=r.get("span_id"), parent_id=r.get("parent_id"),
            command=_as_text(r.get("command") or r.get("tool_input") or r.get("arguments")),
            reasoning=_as_text(r.get("reasoning") or r.get("thinking"))))
    return steps


def parse_trace(raw) -> list[AgentStep]:
    """Parse a trace (str/bytes JSON or an already-loaded object) into steps.

    OTel GenAI spans are primary; the minimal JSON schema is the documented
    fallback. Detection is by structure, not a flag.
    """
    if isinstance(raw, (str, bytes)):
        try:
            raw = json.loads(raw)
        except (ValueError, json.JSONDecodeError) as e:
            raise TraceError(f"trace is not valid JSON: {e}") from e
    if isinstance(raw, dict) and ("resourceSpans" in raw or "spans" in raw):
        steps = _parse_otel(raw)
    else:
        steps = _parse_json(raw)
    if not steps:
        raise TraceError("trace contained no steps")
    if len(steps) > MAX_STEPS:
        raise TraceError(f"trace has {len(steps)} steps; cap is {MAX_STEPS}")
    return steps


def load(path: str) -> list[AgentStep]:
    if os.path.getsize(path) > MAX_TRACE_BYTES:
        raise TraceError(f"trace file exceeds {MAX_TRACE_BYTES} bytes")
    with open(path, encoding="utf-8") as f:
        return parse_trace(f.read())


# --- per-step scoring --------------------------------------------------------

def _step_bundle(step: AgentStep, *, do_rdap: bool, resolve: bool) -> dict:
    """Build the smallest scoring bundle a single step supports (trace-only).

    No tokenizer_match here — trace mode cannot produce it, so scoring floors
    provenance at INDETERMINATE. That is the honest result. A text concession to a
    CN family is mapped into `selfid` so it actually scores (selfid_cn), not just
    into switch detection.
    """
    b: dict = {}
    host_url = step.tool_host or step.backend_url
    if host_url:
        b["network"] = network.analyze_host(host_url, do_rdap=do_rdap, resolve=resolve)
    if step.echoed_model:
        b.setdefault("headers", {})["echoed_model"] = step.echoed_model
    if step.kind == "model" and step.text:
        idy = _tx._turn_identity(step.text)
        conceded = idy.get("conceded")
        # A conceded CN family is a real provenance signal — feed it to scoring the
        # same way behavioral self-identification does (fires selfid_cn).
        if conceded and not _tx._western(conceded):
            b["selfid"] = {"claimed_families": [{"family": conceded, "token": conceded}]}
    return b


def _step_identity(step: AgentStep) -> tuple[str | None, str | None]:
    """(echoed_model_id, asserted_or_conceded_brand) for a model step — kept in
    separate namespaces so a raw model id is never compared against a brand."""
    if step.kind != "model":
        return None, None
    brand = None
    if step.text:
        idy = _tx._turn_identity(step.text)
        brand = idy.get("conceded") or idy.get("asserted")
    return step.echoed_model, brand


def analyze(steps: list[AgentStep], *, offline: bool = False, resolve_hosts: bool = False,
            step_overrides: dict[int, dict] | None = None) -> dict:
    """Score each step, detect model switches, and combine into an agent verdict.

    resolve_hosts: whether to DNS-resolve trace-supplied hosts (default False —
    an ingested trace is untrusted; static hostname signals still fire). offline
    additionally disables RDAP when resolving.
    step_overrides: {step_index: bundle_fragment} — grafts an active-probe result
    (e.g. tokenizer_match) onto a step before scoring.
    """
    step_overrides = step_overrides or {}
    rows, switches = [], []
    prev_echoed, prev_brand = None, None
    hosts_seen: set[str] = set()
    for st in steps:
        # host-count cap: once we've resolved MAX_HOSTS distinct hosts, stop resolving
        host = st.tool_host or st.backend_url
        do_resolve = resolve_hosts
        if resolve_hosts and host:
            if host not in hosts_seen and len(hosts_seen) >= MAX_HOSTS:
                do_resolve = False
            hosts_seen.add(host)
        bundle = _step_bundle(st, do_rdap=not offline, resolve=do_resolve)
        if st.index in step_overrides:
            bundle.update(step_overrides[st.index])
        sc = scoring.score(bundle)

        echoed, brand = _step_identity(st)
        # An unordered step's arrival position is unreliable, so it can't anchor an
        # order-dependent switch claim — skip it for switch detection (Codex C4).
        if st.kind == "model" and not st.unordered:
            if echoed and prev_echoed and echoed != prev_echoed:
                switches.append({"at_step": st.index, "reason": "echoed_model",
                                 "from": prev_echoed, "to": echoed})
            if brand and prev_brand and brand != prev_brand:
                switches.append({"at_step": st.index, "reason": "self_id",
                                 "from": prev_brand, "to": brand})
            if echoed:
                prev_echoed = echoed
            if brand:
                prev_brand = brand

        # operator-vs-soil basis for the jurisdiction verdict (network layer keeps
        # "PRC" = on-soil, "PRC-operator" = PRC-domiciled operator, CDN-fronted etc.)
        basis = (bundle.get("network") or {}).get("jurisdiction")
        rows.append({
            "index": st.index, "kind": st.kind, "name": st.name,
            "echoed_model": st.echoed_model, "host": host,
            "provenance": sc["provenance_risk"]["verdict"],
            "jurisdiction": sc["jurisdictional_risk"]["verdict"],
            "jurisdiction_basis": basis,
            "degraded": st.degraded, "unordered": st.unordered, "truncated": st.truncated,
            "span_id": st.span_id, "parent_id": st.parent_id,
            "score": sc,
        })
    combined = scoring.combine_agent([r["score"] for r in rows])
    combined["model_switches"] = switches
    combined["switch_detected"] = bool(switches)
    # If any step arrived unordered, order-dependent switch claims were withheld
    # for it — surface that the switch verdict is incomplete, don't hide it.
    ordering_incomplete = any(s.unordered for s in steps)
    combined["ordering_incomplete"] = ordering_incomplete
    if ordering_incomplete:
        combined["switch_note"] = ("some steps arrived unordered (concurrent calls "
                                   "without reliable ordering); switch claims withheld for them")
    # a worst-step LIKELY/CONFIRMED is alertable even without a switch
    findings = agent_behaviors.scan_steps(steps)
    combined["concerning_behaviors"] = findings
    combined["alert"] = (bool(switches)
                         or combined["worst_step_verdict"] in ("LIKELY", "CONFIRMED")
                         or bool(findings))
    return {"steps": rows, "verdict": combined}


def assert_backends_authorized(backends, i_am_authorized: bool) -> None:
    """Widened consent surface: every backend that will be actively probed must be
    authorized. Raises PermissionError on the first unauthorized backend."""
    for b in backends:
        if not (getattr(b, "authorized", False) and i_am_authorized):
            raise PermissionError(
                f"backend '{getattr(b, 'base_url', b)}' is not authorized for active "
                f"probing. Set authorized=true on the backend AND pass --i-am-authorized. "
                f"Active probing of an agent's model backend needs written authorization "
                f"for that backend, not just the agent.")
