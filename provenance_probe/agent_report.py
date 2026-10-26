"""Standalone HTML report for an agent assessment.

Renders the per-step board as a self-contained page where every column, verdict
tier, and concept has a hover tooltip that teaches what the tool measured and what
the verdict means. No external assets — one file you can open or hand to a
non-technical reviewer.
"""
from __future__ import annotations

import html


# --- the teaching glossary: term -> plain-English explanation (shown on hover) --
GLOSSARY: dict[str, str] = {
    # the two axes
    "provenance": "PROVENANCE — where the model's WEIGHTS came from. Are they "
                  "Chinese-origin, no matter who runs the server? Exposure: embedded "
                  "alignment/censorship, data poisoning, procurement policy.",
    "jurisdiction": "JURISDICTION — WHO runs the inference and WHERE. A PRC-domiciled "
                    "operator, or PRC soil? Exposure: PIPL / DSL / CSL / National "
                    "Intelligence Law Art.7 — your data can be compelled.",
    # verdict tiers
    "CONFIRMED": "CONFIRMED — strong, measured evidence. Act on it.",
    "LIKELY": "LIKELY — evidence points this way but isn't conclusive.",
    "INDETERMINATE": "INDETERMINATE — not measured or inconclusive. NOT a clean bill; "
                     "it means we could not tell (e.g. a trace carries no tokenizer signal).",
    "UNLIKELY": "UNLIKELY — measured, and the evidence points away from this risk.",
    "NO EVIDENCE": "NO EVIDENCE — actively measured and found clean (distinct from "
                   "INDETERMINATE, which means we never got to measure).",
    # jurisdiction basis (operator vs soil)
    "PRC-soil": "PRC-SOIL — inference runs on servers physically in China "
                "(strongest jurisdiction exposure).",
    "PRC-operator": "PRC-OPERATOR — run by a PRC-domiciled company, even if the "
                    "endpoint is CDN-fronted abroad. Geo-IP alone would miss this; "
                    "operator attribution catches it. NIL Art.7 still applies.",
    "non-PRC-operator": "NON-PRC-OPERATOR — a multi-model aggregator or non-PRC "
                        "operator. Jurisdiction likely clean, but PRC-origin WEIGHTS "
                        "may still be served (check provenance separately).",
    "non-PRC-firstparty": "NON-PRC-FIRSTPARTY — a non-PRC developer serving its own "
                          "weights (e.g. OpenAI, Anthropic). Verify the served model "
                          "still matches, though — a first party can reroute.",
    "unknown": "UNKNOWN — jurisdiction could not be determined from the evidence.",
    # concepts
    "agent": "AGENT — a workflow that calls one or more models over multiple steps "
             "and uses tools. This tool assesses the AGENT, not just one endpoint.",
    "model switch": "MODEL SWITCH — the served model changed identity across the "
                    "agent's steps (a silent swap). Detected from the echoed model id "
                    "or a self-identification flip in the reply text.",
    "egress": "EGRESS — where a tool call sent your data. The destination host's "
              "jurisdiction is scored: an agent on a US model that ships data to PRC "
              "infrastructure is still a jurisdiction breach.",
    "active probe": "ACTIVE BACKEND PROBE — an out-of-band tokenizer fingerprint sent "
                    "to a reachable backend. The ONLY route to a CONFIRMED provenance "
                    "verdict; a post-hoc trace alone can't reach it.",
    "echoed model": "ECHOED MODEL — the model id the trace / vendor REPORTS for this "
                    "step. Useful, but it is exactly the field a deceptive vendor "
                    "controls, so it never alone yields CONFIRMED provenance.",
    "agent verdict": "AGENT VERDICT — the worst single step wins; labelled MIXED when "
                     "steps disagree, so a MIXED board never hides its worst step.",
    "trace": "TRACE — a captured record of the agent run (OpenTelemetry GenAI spans, "
             "or a minimal JSON). Trace-only provenance floors at INDETERMINATE.",
    # columns
    "step": "The step's position in the agent run. A step = one model call or tool call.",
    "kind": "MODEL (a model call) or TOOL (a tool/function call the agent made).",
    "name": "The step's role/span name if the trace provides one; else call#N.",
    "host": "The endpoint the model call hit, or the destination host of a tool call.",
    "alert": "ALERT / exit code 2 — fires on a model switch OR a LIKELY/CONFIRMED "
             "worst step, so CI never reads a PRC finding as clean.",
    "degraded": "DEGRADED — a signal was partially lost for this step (e.g. the live "
                "response couldn't be fully fingerprinted); read its verdict with caution.",
    "unordered": "UNORDERED — this step arrived concurrently with others and its "
                 "position is unreliable, so order-dependent switch claims are WITHHELD "
                 "for it (they'd be meaningless without a reliable order).",
    "truncated": "TRUNCATED — the response body hit the size cap before fingerprinting; "
                 "the verdict is based on the head of the response.",
}

# how the network layer's jurisdiction string maps to a display label
_BASIS_LABEL = {"PRC": "PRC-soil", "PRC-operator": "PRC-operator",
                "non-PRC-operator": "non-PRC-operator",
                "non-PRC-firstparty": "non-PRC-firstparty", "unknown": "unknown"}

_TIER_CLASS = {"CONFIRMED": "t-bad", "LIKELY": "t-warn", "INDETERMINATE": "t-unk",
               "UNLIKELY": "t-ok", "NO EVIDENCE": "t-ok"}


def _tip(text: str, term: str) -> str:
    """A span that shows GLOSSARY[term] on hover (CSS tooltip + native title)."""
    g = GLOSSARY.get(term, "")
    return (f'<span class="tip" data-tip="{html.escape(g)}" '
            f'title="{html.escape(g)}">{html.escape(text)}</span>')


def _tier(verdict: str) -> str:
    cls = _TIER_CLASS.get(verdict, "t-unk")
    return f'<span class="tier {cls}">{_tip(verdict, verdict)}</span>'


def _narrative(result: dict) -> list[str]:
    """Plain-language sentences describing what happened — the 'so what'."""
    steps = result["steps"]
    v = result["verdict"]
    model_steps = [s for s in steps if s["kind"] == "model"]
    tool_steps = [s for s in steps if s["kind"] == "tool"]
    models = [m for m in {s.get("echoed_model") for s in model_steps} if m]
    out = [f"This agent ran <b>{len(steps)} step(s)</b> "
           f"({len(model_steps)} model call(s), {len(tool_steps)} tool call(s))"
           + (f" across <b>{len(models)} distinct model(s)</b>: "
              f"{html.escape(', '.join(sorted(models)))}." if models else ".")]
    if v["model_switches"]:
        for sw in v["model_switches"]:
            out.append(f"The served model <b>switched</b> at step {sw['at_step']}: "
                       f"{html.escape(str(sw['from']))} &rarr; {html.escape(str(sw['to']))} "
                       f"(detected from the {sw['reason'].replace('_', ' ')}).")
    else:
        out.append("No model switch across the steps.")
    # worst / flagged steps
    flagged = [s for s in steps if s["provenance"] in ("LIKELY", "CONFIRMED")
               or s["jurisdiction"] in ("LIKELY", "CONFIRMED")]
    for s in flagged:
        basis = _BASIS_LABEL.get(s.get("jurisdiction_basis") or "", "")
        bits = []
        if s["provenance"] in ("LIKELY", "CONFIRMED"):
            bits.append(f"provenance {s['provenance']}")
        if s["jurisdiction"] in ("LIKELY", "CONFIRMED"):
            bits.append(f"jurisdiction {s['jurisdiction']}" + (f" ({basis})" if basis else ""))
        kind = "tool call egress to" if s["kind"] == "tool" else "model on"
        out.append(f"Step {s['index']} flagged: {', '.join(bits)} — {kind} "
                   f"<span class='mono'>{html.escape(s.get('host') or '?')}</span>.")
    if not flagged:
        out.append("No PRC provenance or jurisdiction signal on any step — clean on the "
                   "evidence captured.")
    for beh in v.get("concerning_behaviors") or []:
        ind = f" ({html.escape(str(beh['indicator']))})" if beh.get("indicator") else ""
        out.append(f"Concerning agent behavior <b>{html.escape(str(beh.get('id') or ''))}</b>"
                   f"{ind}: {html.escape(str(beh.get('summary') or ''))}")
    if v.get("ordering_incomplete"):
        out.append("<b>Note:</b> some steps arrived unordered (concurrent calls); "
                   "switch claims were withheld for them, so the switch view is incomplete.")
    out.append(f"<b>Overall verdict: {html.escape(v['label'])}</b> "
               f"(worst step wins; provenance {v['provenance_verdict']} / "
               f"jurisdiction {v['jurisdiction_verdict']}).")
    return out


def _what_we_did(result: dict) -> list[tuple[str, str]]:
    """(mode, what it found) — the observation surfaces that actually ran."""
    steps = result["steps"]
    did = [("trace", "Ingested the agent run and reconstructed each step's model, "
                      "tool calls, and self-identification text.")]
    if any((s.get("host") and s.get("jurisdiction_basis")) for s in steps):
        did.append(("egress", "Mapped each host to its jurisdiction (operator vs soil)."))
    probed = any(sig["layer"] == "tokenizer"
                 for s in steps for sig in s["score"].get("signals", []))
    if probed:
        did.append(("active probe", "Actively fingerprinted a reachable backend's "
                                    "tokenizer — the only route to CONFIRMED provenance."))
    else:
        did.append(("active probe", "Not run (no reachable authorized backend), so "
                                    "provenance is trace-only and floors at INDETERMINATE."))
    if result["verdict"].get("concerning_behaviors"):
        did.append(("behavior", "Matched captured reasoning and tool commands against the "
                                "2026-10-26 Cohere open-weight agent behaviors."))
    return did


def _graph_section(result: dict) -> str:
    """Nested sub-agent call graph, when the trace/proxy carried parentage (E6)."""
    from . import agent_graph
    rows = result["steps"]
    if not agent_graph.has_structure(rows):
        return ""
    tree = agent_graph.build_tree(rows)
    out = ['<h2>Sub-agent call graph</h2>',
           '<p class="fine">Who spawned whom — the tree that actually ran. A step '
           'nested under another was spawned by it. (Blind spot: a sub-agent calling '
           'an un-proxied backend, or whose spans aren\'t exported, can\'t appear.)</p>',
           '<table><tbody>']
    for n in agent_graph.flatten(tree):
        indent = "&nbsp;" * (4 * n["depth"]) + ("&#8627; " if n["depth"] else "")
        out.append(
            f'<tr><td>{indent}<span class="mono">{html.escape(n["name"])}</span> '
            f'<span class="small">({html.escape(n["kind"])})</span></td>'
            f'<td class="mono">{html.escape(n.get("echoed_model") or "&mdash;")}</td>'
            f'<td>{_tier(n["provenance"])}</td>'
            f'<td>{_tier(n["jurisdiction"])}</td></tr>')
    out.append("</tbody></table>")
    return "".join(out)


def _evidence_rows(result: dict) -> str:
    rows = []
    for s in result["steps"]:
        for sig in s["score"].get("signals", []):
            rows.append(
                f'<tr><td class="num">{s["index"]}</td>'
                f'<td>{html.escape(sig["layer"])}</td>'
                f'<td class="mono">{html.escape(sig["signal"])}</td>'
                f'<td>{html.escape(sig["evidence"])}</td></tr>')
    if not rows:
        return '<p class="ok">No risk signals fired on any step.</p>'
    return ('<table><thead><tr><th>step</th><th>layer</th><th>signal</th>'
            '<th>evidence (why it fired)</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table>")


def render_html(result: dict, title: str, *, fragment: bool = False) -> str:
    v = result["verdict"]
    rows = []
    for s in result["steps"]:
        basis = _BASIS_LABEL.get(s.get("jurisdiction_basis") or "", "")
        basis_html = f' <span class="basis">{_tip(basis, basis)}</span>' if basis else ""
        flags = "".join(f' <span class="flag">{_tip(f, f)}</span>'
                        for f in ("degraded", "unordered", "truncated") if s.get(f))
        rows.append(
            "<tr>"
            f'<td class="num">{s["index"]}</td>'
            f'<td>{_tip(s["kind"], "kind")}</td>'
            f'<td>{html.escape(s["name"])}{flags}</td>'
            f'<td class="mono">{html.escape(s.get("echoed_model") or "—")}</td>'
            f'<td>{_tier(s["provenance"])}</td>'
            f'<td>{_tier(s["jurisdiction"])}{basis_html}</td>'
            f'<td class="mono host">{html.escape(s.get("host") or "—")}</td>'
            "</tr>")

    switches = ""
    if v["model_switches"]:
        items = "".join(
            f'<li>step {sw["at_step"]} <span class="mono">[{sw["reason"]}]</span>: '
            f'{html.escape(str(sw["from"]))} &rarr; {html.escape(str(sw["to"]))}</li>'
            for sw in v["model_switches"])
        switches = f'<h2>{_tip("Model switches", "model switch")}</h2><ul>{items}</ul>'
    else:
        switches = f'<p class="ok">No {_tip("model switch", "model switch")} detected across steps.</p>'

    alert = ""
    if v.get("alert"):
        behs = v.get("concerning_behaviors") or []
        extra = ""
        if behs:
            extra = " Concerning agent behavior: " + ", ".join(
                str(b.get("id") or "") for b in behs) + "."
        alert = (f'<p class="alertline">{_tip("ALERT", "alert")}: worst step is '
                 f'{_tier(v["worst_step_verdict"])} — exit code 2.{html.escape(extra)}</p>')

    glossary_rows = "".join(
        f'<tr><td class="mono">{html.escape(k)}</td><td>{html.escape(val)}</td></tr>'
        for k, val in GLOSSARY.items())

    narrative = "".join(f"<li>{s}</li>" for s in _narrative(result))
    whatwedid = "".join(
        f'<li><b>{_tip(mode, mode if mode in GLOSSARY else "trace")}</b> — {html.escape(desc)}</li>'
        for mode, desc in _what_we_did(result))
    evidence = _evidence_rows(result)
    graph = _graph_section(result)

    body = f"""
<h1>Agent provenance flight recorder</h1>
<p class="sub">{html.escape(title)} — hover any underlined term for what it means.</p>

<div class="panel"><h2>What happened</h2><ul class="narr">{narrative}</ul></div>

<div class="panel"><h2>What this tool did</h2><ul class="narr">{whatwedid}</ul>
<p class="fine">It keeps two verdicts separate on purpose: {_tip("provenance", "provenance")}
(whose weights) and {_tip("jurisdiction", "jurisdiction")} (who runs it, where) —
a model can be one without the other. {_tip("Trace", "trace")}-only provenance floors at
{_tip("INDETERMINATE", "INDETERMINATE")}; only the {_tip("active backend probe", "active probe")}
reaches {_tip("CONFIRMED", "CONFIRMED")}.</p></div>

<h2>Per-step board</h2>
<table>
 <thead><tr>
  <th>{_tip("#", "step")}</th><th>{_tip("kind", "kind")}</th><th>{_tip("name", "name")}</th>
  <th>{_tip("echoed model", "echoed model")}</th><th>{_tip("provenance", "provenance")}</th>
  <th>{_tip("jurisdiction", "jurisdiction")}</th><th>{_tip("host", "host")}</th>
 </tr></thead>
 <tbody>{''.join(rows)}</tbody>
</table>
{switches}
<div class="verdict">{_tip("Agent verdict", "agent verdict")}: <b>{html.escape(v["label"])}</b>
 &nbsp; (provenance {_tier(v["provenance_verdict"])} / jurisdiction {_tier(v["jurisdiction_verdict"])},
 worst of {v["steps"]} steps){alert}</div>

{graph}

<h2>Evidence — why each verdict fired</h2>
{evidence}

<details><summary>Glossary — every term this report uses</summary>
<table class="gloss"><tbody>{glossary_rows}</tbody></table></details>
<footer>Generated by provenance-probe. Verdicts carry confidence, not certainty; read the tier definitions before citing.</footer>"""

    if fragment:
        return f'<div class="agent-report">{_STYLE}{body}</div>'
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>Agent provenance — {html.escape(title)}</title>{_STYLE}'
            f'</head><body>{body}</body></html>')


_STYLE = """<style>
 .agent-report, body { --bad:#b00020; --warn:#b26a00; --ok:#1b7f4d; --unk:#555; --line:#e3e3e3; }
 body { font: 15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; margin: 2rem auto; max-width: 940px; color:#1a1a1a; padding:0 1rem; }
 .agent-report h1 { font-size: 1.35rem; margin-bottom:.2rem; } h1 { font-size: 1.35rem; margin-bottom:.2rem; }
 h2 { font-size: 1.05rem; margin-top: 1.6rem; }
 .sub { color:#555; margin-top:0; }
 .panel { border:1px solid var(--line); border-radius:8px; padding:.4rem .9rem 0.9rem; margin:1rem 0; background:#fafafa; }
 .panel h2 { margin-top:.6rem; }
 ul.narr { margin:.4rem 0 .2rem; padding-left:1.1rem; } ul.narr li { margin:.25rem 0; }
 .fine { color:#555; font-size:.86rem; margin:.5rem 0 0; }
 .small { font-size:.8rem; color:#666; }
 table { border-collapse: collapse; width:100%; margin:.7rem 0; }
 th,td { text-align:left; padding:.45rem .6rem; border-bottom:1px solid var(--line); vertical-align:top; }
 th { font-size:.8rem; text-transform:uppercase; letter-spacing:.03em; color:#333; }
 .num { color:#888; } .mono { font-family: ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.86rem; }
 .host { color:#444; } .basis { font-size:.8rem; color:#666; }
 .flag { font-size:.72rem; text-transform:uppercase; letter-spacing:.04em; color:var(--warn);
   border:1px solid var(--warn); border-radius:4px; padding:0 .3rem; margin-left:.25rem; }
 .tier { font-weight:600; } .t-bad{color:var(--bad);} .t-warn{color:var(--warn);} .t-ok{color:var(--ok);} .t-unk{color:var(--unk);}
 .verdict { font-size:1.05rem; padding:.7rem .9rem; border:1px solid var(--line); border-radius:8px; background:#fafafa; }
 .alertline { color:var(--bad); font-weight:600; } .ok { color:var(--ok); }
 .tip { border-bottom:1px dotted #999; cursor:help; position:relative; }
 .tip:hover::after { content: attr(data-tip); position:absolute; left:0; top:1.4em; z-index:20;
   width:320px; max-width:78vw; background:#1a1a1a; color:#fff; padding:.55rem .7rem; border-radius:6px;
   font-size:.82rem; font-weight:400; line-height:1.45; box-shadow:0 4px 14px rgba(0,0,0,.25); white-space:normal; }
 details { margin-top:1.5rem; } summary { cursor:pointer; font-weight:600; }
 .gloss td { font-size:.85rem; } footer { color:#888; font-size:.8rem; margin-top:2rem; }
</style>"""
