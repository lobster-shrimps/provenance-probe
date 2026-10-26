"""Reporting: console, JSON, standalone HTML."""
from __future__ import annotations
import json, html, hashlib

from . import ui, explain

# Retained for any external importers; the HTML report now derives its ONE hot
# accent from the verdict via ui.verdict_color / ui.LEVEL_COLOR.
SEV_COLOR = {"CONFIRMED": "#8b1a1a", "LIKELY": "#b4531a", "INDETERMINATE": "#8a7413",
             "UNLIKELY": "#2f6b3a", "NO EVIDENCE": "#3a5570"}


def console(bundle: dict) -> str:
    s = bundle["score"]
    L = []
    L.append("=" * 72)
    L.append(f"  MODEL PROVENANCE ASSESSMENT — {bundle['target']['name']}")
    L.append(f"  {bundle['target']['base_url']}   model='{bundle['target']['model']}'")
    L.append(f"  {bundle['timestamp']}")
    L.append("=" * 72)
    for k, label in (("jurisdictional_risk", "JURISDICTIONAL (PRC operator/soil)"),
                     ("provenance_risk", "PROVENANCE (Chinese-origin weights)")):
        r = s[k]
        L.append(f"\n  {label}")
        L.append(f"    verdict    : {r['verdict']}  (p={r['likelihood']})")
        L.append(f"    meaning    : {r['meaning']}")
    L.append(f"\n  Evidence confidence: {s['confidence']}")
    cov = ", ".join(k for k, v in s["evidence_coverage"].items() if v) or "none"
    L.append(f"  Layers with data   : {cov}")
    L.append("\n  SIGNALS")
    if not s["signals"]:
        L.append("    (none fired)")
    for sig in s["signals"]:
        L.append(f"    [{sig['layer']:<11}] {sig['signal']:<22} {sig['evidence'][:120]}")
    tm = bundle.get("tokenizer_match") or []
    if tm:
        L.append("\n  TOKENIZER FINGERPRINT (top 5)")
        L.append(f"    {'model':<48}{'origin':<10}{'score':<8}{'exact'}")
        for r in tm[:5]:
            L.append(f"    {r['model'][:47]:<48}{str(r['origin']):<10}"
                     f"{r['score']:<8}{r['exact_matches']}/{r['shared_probes']}")
    al = bundle.get("alignment") or {}
    if al:
        L.append(f"\n  ALIGNMENT ASYMMETRY: mean={al.get('mean_asymmetry')}")
        for p in al.get("pairs", []):
            L.append(f"    {p['pair']:<20} delta={p['asymmetry']:<6} "
                     f"treat_refusal={p['treatment']['refusal']} ctrl_refusal={p['control']['refusal']}")
    L.append("\n" + "=" * 72)
    return "\n".join(L)


def to_json(bundle: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(bundle, f, indent=2, default=str)


def _lead_verdict(s: dict) -> tuple[dict, str]:
    """Pick the verdict that leads the report: the higher-likelihood of the two
    risks, with a short human tag for the display headline."""
    jr, pr = s["jurisdictional_risk"], s["provenance_risk"]
    if pr.get("likelihood", 0) >= jr.get("likelihood", 0):
        return pr, "Chinese-origin model"
    return jr, "PRC jurisdiction"


def _pct(x) -> str:
    try:
        return f"{float(x) * 100:.1f}%"
    except (TypeError, ValueError):
        return "—"


def to_html(bundle: dict, path: str) -> None:
    e = html.escape
    s = bundle["score"]
    tgt = bundle.get("target", {})
    uw = bundle.get("user_warning") or {}
    lead, tag = _lead_verdict(s)
    verdict_word = lead.get("verdict", "INDETERMINATE")
    accent = ui.verdict_color(verdict_word)
    # A clean verdict names no origin tag ("NO EVIDENCE — Chinese-origin model"
    # would read as a false positive); only flagged/likely verdicts carry the tag.
    head_html = html.escape(verdict_word) + (
        "" if verdict_word in ("NO EVIDENCE", "UNLIKELY")
        else f" &mdash; {html.escape(tag)}")
    # Plain-English fact first (verdict-first voice); fall back to the technical
    # meaning if no user warning was attached to this bundle.
    fact = uw.get("headline") or lead.get("meaning", "")
    stamp_label = e(uw.get("level_label") or "Assessment complete")
    pv = s["provenance_risk"].get("verdict")
    jv = s["jurisdictional_risk"].get("verdict")
    conf_raw = s.get("confidence") or ""
    plain = explain.plain_answer(pv, jv, conf_raw)
    step = explain.plain_action(pv, jv, conf_raw)
    lead_copy = (
        f'<p class="lead" aria-label="Plain-English answer" style="max-width:52ch;margin:0 0 10px">{e(plain)}</p>'
        f'<p aria-label="Next step" style="max-width:52ch;margin:0 0 16px">{e(step)}</p>')

    # 1. Tokenizer match — terminal-green mono table on the dark evidence card.
    tm = bundle.get("tokenizer_match") or []
    if tm:
        trows = "".join(
            f'<tr{" class=hi" if i == 0 else ""}><td>{i + 1}</td>'
            f'<td>{e(str(r.get("model", "")))}</td>'
            f'<td>{_pct(r.get("score"))}</td>'
            f'<td>{e(str(r.get("origin")))}</td>'
            f'<td>{r.get("exact_matches", 0)}/{r.get("shared_probes", 0)}</td></tr>'
            for i, r in enumerate(tm[:8]))
        tok_card = (
            '<div class="evidence"><table>'
            "<tr><th>Rank</th><th>Tokenizer</th><th>Match</th><th>Origin</th><th>Exact</th></tr>"
            f"{trows}</table>"
            '<p style="margin:14px 0 0;color:#5fae86">Higher match &rarr; the served model '
            "shares this reference tokenizer. Top match significantly above the rest "
            "is a strong fingerprint.</p></div>")
    else:
        tok_card = ('<div class="evidence">Tokenizer fingerprint unavailable — the endpoint '
                    "did not expose prompt-token usage, so no vocabulary probe could run.</div>")

    # 2. High-level stats — big serif numbers.
    def _num(x) -> str:
        if isinstance(x, (int, float)):
            return f"{x:.3f}".rstrip("0").rstrip(".") or "0"
        return "—"
    stats = []
    if tm:
        stats.append((_pct(tm[0].get("score")), "Top tokenizer match"))
    stats.append((_num(s["provenance_risk"].get("likelihood")), "Provenance likelihood"))
    stats.append((_num(s["jurisdictional_risk"].get("likelihood")), "Jurisdiction likelihood"))
    statcells = "".join(
        f'<div><div class="statnum">{e(str(v))}</div>'
        f'<div class="statlbl">{e(lbl)}</div></div>' for v, lbl in stats)
    conf = e(str(s.get("confidence", "—")))

    # 3. Signals. Each layer cell carries a plain-language tooltip sourced from
    # explain.LAYERS (single source of truth), so a non-technical reader can hover
    # to learn what that check does. Falls back to the bare layer name if unknown.
    def _layer_cell(layer: str) -> str:
        tip = explain.tooltip_for(layer)
        inner = (f'<abbr title="{e(tip)}" style="text-decoration:underline dotted;'
                 f'cursor:help">{e(layer)}</abbr>') if tip else e(layer)
        return f'<td class="mono">{inner}</td>'
    sigrows = "".join(
        f'<tr>{_layer_cell(x["layer"])}'
        f'<td class="mono" style="font-weight:600">{e(x["signal"])}</td>'
        f'<td>{e(x["evidence"])}</td></tr>' for x in s["signals"]) or \
        '<tr><td colspan=3 class="sub" style="text-align:center;padding:18px">No signals fired.</td></tr>'

    # 4. Network & jurisdiction.
    net = bundle.get("network") or {}
    addr = (net.get("addresses") or [{}])[0]
    juris = net.get("jurisdiction") or "unknown"
    juris_accent = ui.verdict_color("CN") if str(juris).startswith("PRC") else "var(--muted)"
    netrow = (
        '<div class="grid3" style="gap:0;margin-top:6px">'
        f'<div><div class="statlbl" style="margin:0 0 3px">Operator</div>'
        f'<div class="mono">{e(str(net.get("operator") or "unknown"))}</div></div>'
        f'<div><div class="statlbl" style="margin:0 0 3px">Egress ASN / geo</div>'
        f'<div class="mono">{e(str(addr.get("asn") or "—"))} '
        f'{e(str(addr.get("country") or ""))}</div></div>'
        f'<div><div class="statlbl" style="margin:0 0 3px">Legal jurisdiction</div>'
        f'<div class="mono" style="color:{juris_accent}">{e(str(juris))}</div></div></div>')

    # Optional: alignment asymmetry (matched pairs).
    al = bundle.get("alignment") or {}
    alr = "".join(
        f'<tr><td class="mono">{e(p["pair"])}</td><td class="mono">{e(str(p["asymmetry"]))}</td>'
        f'<td class="mono">{p["treatment"]["refusal"]}/{p["treatment"]["state_framing"]}</td>'
        f'<td class="mono">{p["control"]["refusal"]}/{p["control"]["state_framing"]}</td>'
        f'<td class="sub">{e(p["treatment_excerpt"][:200])}</td></tr>'
        for p in al.get("pairs", []))
    align_block = (
        '<h3>Alignment asymmetry (matched pairs)</h3><div class="card"><table>'
        "<tr><th>Pair</th><th>&Delta;</th><th>Treat refuse/frame</th>"
        "<th>Ctrl refuse/frame</th><th>Treatment excerpt</th></tr>"
        f"{alr}</table></div>") if alr else ""

    # Footer strip: artifact id, timestamp, engine version, signed report hash.
    from . import __version__
    rhash = hashlib.sha256(
        json.dumps(bundle, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:24]
    footer = (
        '<div class="footer">'
        f'<div><div class="k">Artifact ID</div><div class="v">{e(str(bundle.get("fingerprint_id") or "—"))}</div></div>'
        f'<div><div class="k">Date (UTC)</div><div class="v">{e(str(bundle.get("timestamp") or "—"))}</div></div>'
        f'<div><div class="k">Analysis engine</div><div class="v">provenance-probe v{e(__version__)}</div></div>'
        f'<div><div class="k">Target model</div><div class="v">{e(str(tgt.get("model") or "—"))}</div></div>'
        f'<div><div class="k">Report hash</div><div class="v">{rhash}</div></div></div>')

    inner = f"""<div class="hero-row">
<div style="flex:1;min-width:260px">
<div class="seclabel" style="margin-top:0">Result</div>
{lead_copy}
<h1 class="display" style="font-size:clamp(38px,6vw,64px);color:{accent};margin:6px 0 14px">{head_html}</h1>
<p class="lead" style="max-width:52ch;margin:0">{e(fact)}</p>
</div>
<div class="stamp" style="color:{accent};border-color:{accent}">
<span class="lvl">Verdict</span>
<span class="stampverdict">{stamp_label}</span></div>
</div>

<div class="lab">
<div>
<h3>1. Tokenizer match (LLM fingerprint)</h3>
{tok_card}
</div>
<div>
<h3>2. High-level stats</h3>
<div class="card"><div class="statgrid">{statcells}</div>
<p class="stat" style="margin:16px 0 0">Evidence confidence: <b style="color:var(--ink)">{conf}</b></p></div>
<h3>4. Network &amp; jurisdiction</h3>
<div class="card">{netrow}</div>
</div>
</div>

<h3>3. Signals</h3>
<p class="stat" style="margin:0 0 10px">New here? Each check is explained in plain language on the <a href="/help">help page</a>. Hover a layer name for a one-line description.</p>
<div class="card"><table><tr><th>Layer</th><th>Signal</th><th>Evidence</th></tr>{sigrows}</table></div>
{align_block}

<div class="warn" style="margin-top:26px"><b>Interpretation limits.</b> Black-box probes degrade against a vendor actively
defeating them (normalized usage counts, suppressed logprobs, output post-filtering). Absence of
alignment asymmetry does not clear provenance &mdash; offshore-served Chinese open weights are frequently
de-censored by fine-tuning. Chinese weights served entirely inside your accreditation boundary carry
bias/integrity/policy risk but <i>no</i> PRC data-jurisdiction exposure; do not conflate the two.
Re-run continuously: silent backend swaps after contract award are the real threat model.</div>
{footer}"""

    endpoint = f'<div class="poster-right">{e(str(tgt.get("base_url") or ""))}</div>'
    doc = ui.doc(f"Provenance Assessment — {e(str(tgt.get('name', '')))}", inner, right=endpoint)
    with open(path, "w") as f:
        f.write(doc)
