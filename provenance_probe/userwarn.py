# -*- coding: utf-8 -*-
"""Plain-language user warning. No jargon, no probabilities, no acronyms.

The technical report is for the assessor. This is for the person who just
opened a free chat app and has no idea their prompts are leaving the country.
"""
from __future__ import annotations
import html, json

LEVELS = {
    "red":    ("Do not use this tool for anything sensitive",   "#8b1a1a", "#fdf2f2", "#e8c4c4"),
    "orange": ("Use with caution — verify before trusting it",  "#a8500f", "#fff8f0", "#f0d9bd"),
    "yellow": ("Some questions remain — worth checking",        "#7a6a12", "#fffdf0", "#ece0b0"),
    "green":  ("No problems found in this check",               "#2f6b3a", "#f3faf4", "#c6e0cc"),
}


def build(bundle: dict) -> dict:
    s = bundle.get("score", {})
    dec = bundle.get("deception") or {}
    corr = dec.get("correlation") or {}
    src = bundle.get("client_source") or {}
    jur = s.get("jurisdictional_risk", {}).get("likelihood", 0)
    prov = s.get("provenance_risk", {}).get("likelihood", 0)

    facts = []
    level = "green"

    # --- the headline: was the user actively misled? -------------------------
    if corr.get("severity") == "critical":
        level = "red"
        headline = (f"This app told you it was {corr.get('claimed')} — it is not.")
        facts.append(f"The app presents itself as {corr.get('claimed')}, a US-built AI service.")
        facts.append("It is actually powered by an AI model built and operated by a company in China.")
        facts.append("When asked directly whether your data falls under Chinese law, "
                     "the app said no. That answer was wrong.")
    elif corr.get("misrepresentation"):
        level = "red"
        headline = f"This app is not what it says it is."
        facts.append(f"It presents itself as {corr.get('claimed')}, but is powered by a "
                     f"Chinese-built AI model.")
    elif jur >= 0.6:
        level = "orange"
        headline = "Your messages are being sent to servers operated from China."
        facts.append("The company running this service is based in China.")
    elif prov >= 0.6:
        level = "orange"
        headline = "This app uses an AI model built in China."
        facts.append("The model itself was built in China. Depending on how it is hosted, "
                     "your messages may or may not leave your country — but the model's "
                     "answers may be shaped by rules set in China.")
    elif jur >= 0.35 or prov >= 0.35:
        level = "yellow"
        headline = "We could not confirm who is really running this app."
        facts.append("The check found some signals worth following up, but nothing conclusive.")
    else:
        headline = "No signs of a hidden or misrepresented AI model."
        facts.append("The checks did not find evidence that this app is disguising which AI "
                     "model it uses or where your data goes.")

    # --- what it means, in consequences the user cares about -----------------
    if level in ("red", "orange") and (jur >= 0.6 or corr.get("severity") == "critical"):
        facts.append("Under Chinese law, companies based there can be required to hand over "
                     "data to the government, and are not allowed to tell you when they do.")
        facts.append("Anything you typed here should be treated as no longer private: "
                     "work documents, personal details, passwords, client information, code.")

    if src.get("prc_operators_in_source"):
        ops = ", ".join(src["prc_operators_in_source"])
        facts.append(f"Evidence found directly in the app's own code: {ops}.")

    if (dec.get("jurisdiction") or {}).get("denies_prc_jurisdiction"):
        facts.append("We asked the app five times, in different ways, whether your data is "
                     "covered by Chinese law. It denied it. That denial was false.")

    conf = dec.get("confrontation") or {}
    if conf.get("sycophantic"):
        facts.append("Note: this app agrees with whatever you tell it. Asking it to confirm "
                     "which AI it uses will not give you a reliable answer.")

    # The next step is one sentence from explain.plain_action. This warning
    # does not keep a second checklist.
    from . import explain
    sc = s or {}
    next_step = explain.plain_action(
        (sc.get("provenance_risk") or {}).get("verdict") or "INDETERMINATE",
        (sc.get("jurisdictional_risk") or {}).get("verdict") or "INDETERMINATE",
        sc.get("confidence") or "low")

    return {"level": level, "level_label": LEVELS[level][0], "headline": headline,
            "facts": facts, "actions": [], "next_step": next_step,
            "app": bundle.get("target", {}).get("name", "this app"),
            "url": bundle.get("target", {}).get("base_url", "")}


def to_text(w: dict) -> str:
    L = [f"\n{'='*66}", f"  {w['headline'].upper()}", f"  {w['level_label']}", "="*66,
         "\n  WHAT WE FOUND"]
    L += [f"    - {f}" for f in w["facts"]]
    L.append("="*66)
    return "\n".join(L)


def to_html(w: dict, path: str) -> None:
    label, ink, bg, border = LEVELS[w["level"]]
    facts = "".join(f"<li>{html.escape(f)}</li>" for f in w["facts"])
    step = html.escape(w.get("next_step") or "")
    step_block = (f'<p style="font-size:18px;margin:0 0 18px">{step}</p>'
                  if step else "")
    doc = f"""<!doctype html><meta charset=utf-8><title>AI app safety check</title>
<style>
body{{font:17px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;
color:#1b1d21;background:#f6f7f8;margin:0;padding:28px}}
.w{{max-width:640px;margin:0 auto}}
.banner{{background:{bg};border:1px solid {border};border-left:6px solid {ink};
border-radius:10px;padding:22px 24px;margin-bottom:22px}}
.lvl{{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:{ink};font-weight:700}}
h1{{font-size:24px;line-height:1.3;margin:8px 0 6px;color:{ink};letter-spacing:-.01em}}
.sub{{font-size:14px;color:#5b6069}}
.card{{background:#fff;border:1px solid #e4e6ea;border-radius:10px;padding:20px 24px;
margin-bottom:16px}}
h2{{font-size:12px;letter-spacing:.09em;text-transform:uppercase;color:#6b7280;
margin:0 0 12px;font-weight:700}}
ul{{margin:0;padding-left:22px}} li{{margin-bottom:9px}}
ol{{margin:0;padding-left:22px}}
.foot{{font-size:13px;color:#6b7280;margin-top:20px;line-height:1.5}}
</style><div class=w>
<div class=banner><div class=lvl>{html.escape(label)}</div>
{step_block}
<h1>{html.escape(w['headline'])}</h1>
<div class=sub>Checked: {html.escape(w['app'])} &nbsp;·&nbsp; {html.escape(w['url'])}</div></div>
<div class=card><h2>What we found</h2><ul>{facts}</ul></div>
<div class=foot>This check looks at where your messages are actually sent and which AI model
answers them — not at what the app says about itself. Apps can change their AI provider at any
time without telling you, so a clean result today is not a permanent guarantee.</div>
</div>"""
    with open(path, "w") as f:
        f.write(doc)
