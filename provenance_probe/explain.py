# -*- coding: utf-8 -*-
"""Plain-language, non-technical-first explainers — the SINGLE source of truth.

Every in-product surface that describes what a probe does or what a verdict means
reads from the data here (never a copy-paste):

  * the ``/help`` page (rendered by :func:`help_html`),
  * the report's Signals-table layer tooltips (via :func:`tooltip_for`),
  * the probe form's "what these checks do" note.

Content is deliberately jargon-light: written for a visitor who has never heard of
a tokenizer. Structural HTML in :func:`help_html` is authored here; every *content*
string is passed through ``html.escape`` when rendered, so no field can inject
markup even though all of it is author-controlled (defense-in-depth).
"""
from __future__ import annotations

import html
from typing import NamedTuple


class Layer(NamedTuple):
    """One evidence layer, in plain language.

    ``title`` is the short, TECHNICAL name shown on ``/help`` (a technical
    reference page). ``flow_label`` is the friendly, jargon-free heading the
    "how it works" FLOW shows instead — WS2's whole point is non-technical
    legibility, so the flow never surfaces words like "tokenizer" or "wire".
    ``flow_blurb`` optionally overrides ``measures`` in the flow when the /help
    wording carries jargon (it defaults to ``measures``). Both flow fields live
    HERE so the flow keeps a single source and never hardcodes copy elsewhere.
    """
    title: str            # short, TECHNICAL name — shown on /help
    measures: str         # 1-2 plain sentences: what it looks at (/help + tooltips)
    hit_means: str        # what it means when this check "fires"
    flow_label: str = ""  # plain, jargon-free heading for the how-it-works flow
    flow_blurb: str = ""  # optional jargon-free flow blurb (falls back to measures)


# The engine's evidence layers, in the order `assess` runs them. This mapping is
# the ONE place layer copy lives; /help, the report tooltips AND the how-it-works
# flow all read it. /help shows `title`/`measures` (technical); the flow shows the
# plain `flow_label` (+ `flow_blurb` where the /help wording carries jargon).
LAYERS: "dict[str, Layer]" = {
    "network": Layer(
        "Network & location",
        "Looks up where the endpoint's address actually lives on the internet, "
        "and which company runs that server.",
        "The service is hosted by a Chinese company or on servers inside China.",
        flow_label="Where the servers really are (and who runs them)"),
    "wire": Layer(
        "Wire fingerprint",
        "Reads the technical 'envelope' around each reply — the response headers, "
        "error messages and streaming style — the way you'd recognise a company "
        "by its letterhead.",
        "The envelope matches a known Chinese provider, or the service names a "
        "Chinese model.",
        flow_label="The delivery envelope around each reply (like a letterhead)"),
    "tokenizer": Layer(
        "Tokenizer fingerprint",
        "Watches how the model chops text into pieces before it reads it. Every "
        "model family does this in a slightly different, hard-to-fake way — like "
        "handwriting.",
        "The 'handwriting' matches a Chinese-origin model family.",
        flow_label="How it breaks text into pieces (like handwriting)"),
    "logprob": Layer(
        "Determinism check",
        "Sends the same prompt more than once and measures how repeatable and "
        "confident the answers are — a fingerprint of the engine doing the work.",
        "Adds supporting detail about which kind of engine is answering; on its "
        "own it doesn't decide the model's origin.",
        flow_label="Whether it answers the same way twice",
        flow_blurb="Sends the same prompt more than once and measures how "
                   "repeatable and confident the answers are — a tell-tale "
                   "signature of the engine doing the work."),
    "behavioral": Layer(
        "Behaviour tests",
        "Asks the model who it is, compares how it answers matched pairs of "
        "sensitive questions, and watches for Chinese characters slipping into "
        "English answers.",
        "The model identifies as — or behaves like — a Chinese-trained model.",
        flow_label="How it answers telltale questions"),
    "deception": Layer(
        "Honesty check",
        "Asks the model directly about who made it and where it runs, then checks "
        "those claims against the hard evidence — including a deliberately false "
        "control question to catch a model that just agrees with anything.",
        "The model's own claims contradict the evidence — it is misrepresenting "
        "its origin or who runs it.",
        flow_label="Whether its own story matches the evidence"),
    "latency": Layer(
        "Timing profile",
        "Times how quickly replies come back and the rhythm of the stream, which "
        "can hint at where the servers are and what is running.",
        "The timing fits the suspected backend or region — a supporting clue, "
        "not proof on its own.",
        flow_label="How fast and steady the replies come back"),
    "artifacts": Layer(
        "Files & app source",
        "When you point it at model files on disk, or at the app's own shipped "
        "code, it reads them for names, file paths and settings that reveal the "
        "model's family or the company operating it.",
        "The files name a Chinese model family, or a Chinese operator baked into "
        "the app.",
        flow_label="Clues left in its files and app code"),
}

# Layer names as they appear on real signals (report + scoring) can differ from
# the canonical keys above; normalise so every tooltip resolves.
_LAYER_ALIASES = {
    "artifact": "artifacts",
    "client-source": "artifacts",
    "client source": "artifacts",
    "logprobs": "logprob",
}


def layer_info(name: str) -> "Layer | None":
    """Resolve a layer name (canonical or an on-signal alias) to its explainer."""
    key = (name or "").strip().lower()
    key = _LAYER_ALIASES.get(key, key)
    return LAYERS.get(key)


def tooltip_for(name: str) -> str:
    """Plain-text tooltip ('Title — what it measures') for a signal's layer cell,
    or "" when the layer is unknown. The caller escapes it for its context."""
    info = layer_info(name)
    return f"{info.title} — {info.measures}" if info else ""


class Tier(NamedTuple):
    name: str        # the verdict word the engine emits
    meaning: str     # plain-language meaning


class Axis(NamedTuple):
    title: str
    question: str
    tiers: "tuple[Tier, ...]"


# The two INDEPENDENT verdict axes. Provenance = whose model it is; jurisdiction =
# who runs it and where. A model can score high on one and low on the other. Both
# axes run through the SAME five-tier scale (scoring._verdict), so both tables list
# all five — a reader never meets a verdict word that isn't explained here.
VERDICTS: "dict[str, Axis]" = {
    "provenance": Axis(
        "Provenance — whose model is it?",
        "Whose model weights are actually answering, no matter where the servers are?",
        (
            Tier("CONFIRMED",
                 "Strong, direct evidence the weights are Chinese-origin — for "
                 "example a matching tokenizer fingerprint."),
            Tier("LIKELY",
                 "Several clues point to Chinese-origin weights, but no single "
                 "piece is decisive on its own."),
            Tier("INDETERMINATE",
                 "Not enough could be measured to say either way. Treat this as "
                 "'unknown', not as a clean bill of health."),
            Tier("UNLIKELY",
                 "The checks that ran point away from Chinese-origin weights, "
                 "though nothing is ever ruled out with total certainty."),
            Tier("NO EVIDENCE",
                 "A provenance check actually ran and found nothing at all "
                 "suggesting Chinese-origin weights."),
        )),
    "jurisdiction": Axis(
        "Jurisdiction — who runs it, and where?",
        "Is the service operated by a Chinese company, or running on servers inside China?",
        (
            Tier("CONFIRMED",
                 "Direct evidence the operator is Chinese, or the servers sit on "
                 "Chinese soil."),
            Tier("LIKELY",
                 "Signals point to a Chinese operator or location, short of proof."),
            Tier("INDETERMINATE",
                 "Not enough could be measured to place who runs it or where. "
                 "Treat this as 'unknown', not as safe."),
            Tier("UNLIKELY",
                 "The operator and the server location both look non-Chinese."),
            Tier("NO EVIDENCE",
                 "Nothing found points to a Chinese operator or a China-based "
                 "server."),
        )),
}

# The worked example that makes the two axes click for a newcomer.
EXAMPLE = (
    "The two answers are independent. A Chinese-origin model running on US servers "
    "reads as CONFIRMED provenance (the weights are Chinese) but UNLIKELY "
    "jurisdiction (a US operator on US soil). Neither answer overrides the other — "
    "read them together.")

# The mission, in plain language — the SINGLE source for the landing hero AND the
# /help "Why this matters" section, so the two never drift. Honest by design: the
# tool reports with *confidence*, not certainty — the copy says "catch a silent
# switch", never "guarantee".
MISSION_HEADLINE = "Is the AI you're paying for still the AI you're getting?"
MISSION_BODY = (
    "Services can quietly swap the model behind an API — for a cheaper, weaker, "
    "or foreign-built one — without telling you. provenance-probe fingerprints "
    "the model that's actually answering, then re-checks over time so you catch "
    "a silent switch.")

# "Why this matters" — the silent-swap threat spelled out for a non-technical
# reader. Rendered on /help; the landing hero shows the short MISSION_BODY above.
WHY_THIS_MATTERS: "tuple[str, ...]" = (
    "When you pay for an AI API, you are trusting that one particular model is on "
    "the other end. But nothing stops the service from changing the model behind "
    "that same address — swapping in one that is cheaper to run, less capable, or "
    "built in another country — while your app keeps calling the very same URL, "
    "none the wiser. That is a silent model swap.",
    "It matters because the swap is invisible from the outside. A weaker model can "
    "quietly degrade the answers you depend on. A model run by a different operator, "
    "or built in another country, can change who is able to see your prompts and "
    "which country's laws apply to them. You approved one thing and are being served "
    "another, without ever being told.",
    "provenance-probe fingerprints the model that is actually answering — from the "
    "way it chops up text, the shape of its replies, where its servers sit, and how "
    "it answers a fixed set of questions. Re-run that fingerprint over time and a "
    "swap can no longer hide: if the fingerprint moves, the model behind the API "
    "moved with it.")

# "Watching for model swaps" — a short primer on catching a swap over time. Honest
# about the two ways to watch that ship today: a browser-tab watch you keep open, and
# the local always-on `watch` daemon (P3) for unattended monitoring.
WATCHING_PRIMER: "tuple[str, ...]" = (
    "Catching a swap is a matter of comparison. Fingerprint the service once to set "
    "a baseline, then fingerprint it again later. If the two fingerprints disagree, "
    "the model behind the API changed between the runs.",
    "The Watch page does that comparison for you on a timer. You pin a baseline, "
    "pick how often to re-check (every 5, 15 or 60 minutes), and the page re-probes "
    "the same target and diffs each result against the baseline. The moment the "
    "fingerprint moves it raises a loud alert — a red banner, a change to the browser "
    "tab title, and an optional desktop notification — and lists exactly what shifted. "
    "'Accept new baseline' re-pins to the current fingerprint and stops re-alerting.",
    "Your API key never leaves your browser. It is held in this tab only (in memory), "
    "sent solely to the probe for each re-check, and is never written to server "
    "storage or to your browser's saved data — which is what lets the watch run the "
    "same way on the hosted demo as it does locally.",
    "One honest limit: a browser-tab watch only runs while the tab stays open. For "
    "always-on, unattended monitoring, install the watch timer locally at 12 hours. "
    "It runs watch --once and then exits. Behavioral checks stay off. Do not also "
    "start watch --loop. The public Observatory still runs once a night at 03:17 UTC. "
    "A new API or web target is an entry in the Observatory targets.yaml; that cron "
    "does not change.")

# Plain-language tour of each flow in the web UI, in nav order.
FLOWS: "tuple[tuple[str, str], ...]" = (
    ("Live probe",
     "The home page. Paste an AI endpoint's address (and a model or key if it "
     "needs one), confirm you're allowed to test it, and press Run. The probe "
     "runs its checks and shows a plain-language verdict plus a detailed report."),
    ("Add a target / capture",
     "Not sure how to point the probe at your service? The 'Add target' wizard "
     "walks you through it. If your service is a website you log into, it can "
     "read the one message you send — your password and login are never recorded, "
     "and nothing is saved until you review it."),
    ("Agent board",
     "Paste a recording of an AI agent's steps and see, step by step, which model "
     "answered, whether the model changed mid-run, and whether any step sent data "
     "to a Chinese host."),
    ("Monitor (compare runs)",
     "Run the probe twice — for example before and after a contract — and compare "
     "the two runs. If the backend model was quietly swapped, the comparison "
     "flags exactly what changed."),
    ("Observatory",
     "A public gallery of provenance findings for well-known services, so you can "
     "see how the checks read on endpoints you already recognise."),
)

# Short FAQ. Answers reflect the tool's real privacy posture (loopback-bound,
# keys held in memory, nothing sent except to the endpoint you name).
FAQ: "tuple[tuple[str, str], ...]" = (
    ("Do you store my key?",
     "No. Any API key or session cookie you enter is held in memory for that one "
     "run and is never written into the saved report files."),
    ("Is my data sent anywhere?",
     "The tool runs on your own machine and only ever contacts the one endpoint "
     "you ask it to test. Results are stored on your local disk — nothing is "
     "uploaded to us."),
    ("What if it says INDETERMINATE?",
     "It means there wasn't enough evidence to decide — treat it as 'unknown', "
     "not 'safe'. Often the endpoint hid the information a check needs. Try again "
     "with more of the optional fields filled in, or re-run later."),
)


class Stage(NamedTuple):
    """One step of the 'how it works' flow, in plain language.

    ``detail`` is a pointer, never a copy: "layers" enumerates :data:`LAYERS` and
    "axes" enumerates :data:`VERDICTS` — so :func:`flow_html` and :func:`flow_text`
    both read the per-check / per-question wording from the SAME single source.
    """
    title: str
    body: str
    detail: str = ""          # "" | "layers" | "axes"


# The pipeline as plain-English steps — the SINGLE source for both the visual
# :func:`flow_html` (landing + /help) and the plain-text :func:`flow_text`
# (``explain --flow``). Step 2 enumerates the LAYERS; step 3 the two VERDICT axes;
# neither copies their wording (it is pulled from LAYERS / VERDICTS at render time).
FLOW_STAGES: "tuple[Stage, ...]" = (
    Stage("You point it at an AI app",
          "Give it an AI endpoint's address — plus a model id, key or login if the "
          "app needs one — and confirm you're authorized to test it."),
    Stage("It measures hard-to-fake signals",
          "A full run tries up to eight independent checks. Each reads something "
          "the operator can't easily rewrite:", "layers"),
    Stage("It answers two independent questions",
          "The evidence rolls up into two separate reads — a model can score high "
          "on one and low on the other:", "axes"),
    Stage("You get a verdict, a confidence, and what it means",
          "Each question gets one of five plain verdicts and a confidence level, "
          "led by a single plain-English sentence telling you what it means for you."),
    Stage("You get one next step",
          "The same result ends with one plain instruction: leave it, check again, "
          "or stop sending sensitive data until a person who owns the risk reviews it."),
)


# ------------------------------------------------------- plain-English answer ---
# Confidence buckets -> one adverb each (the string _conf() returns; we take the
# first token, so the long low-bucket note normalises to "low"). The low phrasing
# is a sentence-leading qualifier, applied inline per positive clause.
_CONF_ADVERB = {"high": "clearly", "moderate": "likely",
                "low": "a preliminary read suggests"}

_CLEAN_TIERS = frozenset({"UNLIKELY", "NO EVIDENCE"})

# Both-clean collapses to one reassuring sentence (no per-axis clauses).
_BOTH_CLEAN = ("This app looks like it's serving the kind of model it claims, "
               "run where it claims.")


def _conf_bucket(confidence: str) -> str:
    """Normalise whatever ``_conf()`` returned to one of high/moderate/low."""
    tok = (confidence or "").strip().split()
    head = tok[0].lower() if tok else "low"
    return head if head in _CONF_ADVERB else "low"


def _severity_rank(verdict: str) -> int:
    """0 = most severe. Severity order is _TIER_ORDER reversed (single source)."""
    from .scoring import _TIER_ORDER
    order = list(reversed(_TIER_ORDER))       # CONFIRMED > … > NO EVIDENCE
    try:
        return order.index(verdict)
    except ValueError:
        return len(order)                      # unknown -> least severe


def _indeterminate_clause(noun: str) -> str:
    return (f"not enough hard evidence yet to call {noun} — "
            "not a clean bill, not an accusation")


def _provenance_clause(verdict: str, bucket: str) -> str:
    if verdict in ("CONFIRMED", "LIKELY"):
        if bucket == "low":
            return "a preliminary read suggests this app is serving a Chinese-origin model"
        return f"this app is {_CONF_ADVERB[bucket]} serving a Chinese-origin model"
    if verdict == "INDETERMINATE":
        return _indeterminate_clause("its model")
    return "no sign of a Chinese-origin model"


def _jurisdiction_clause(verdict: str, bucket: str) -> str:
    tail = "produced under PRC jurisdiction (Chinese data law can apply)"
    if verdict in ("CONFIRMED", "LIKELY"):
        if bucket == "low":
            return f"a preliminary read suggests this app's answers are {tail}"
        return f"this app's answers are {_CONF_ADVERB[bucket]} {tail}"
    if verdict == "INDETERMINATE":
        return _indeterminate_clause("where it runs")
    return "no sign of PRC-jurisdiction operation"


def plain_answer(provenance_verdict: str, jurisdiction_verdict: str,
                 confidence: str) -> str:
    """One deterministic, plain-English sentence for a (provenance, jurisdiction,
    confidence) tuple — the lead line on every assess result surface.

    A PURE function of its inputs so the serve UI and the CLI cannot drift (mirrors
    the serve.py monitor invariant). ``confidence`` is whatever ``scoring._conf()``
    returned ("high"/"moderate"/"low…"); it is normalised to one adverb bucket.

    Honest by construction: the tuple supports only origin + jurisdiction claims,
    never misrepresentation — so positive provenance reads "serving a Chinese-origin
    model", never "not what it claims" (that needs a persona-mismatch signal the
    tuple doesn't carry). An INDETERMINATE axis always says it is neither a clean
    bill nor an accusation.
    """
    bucket = _conf_bucket(confidence)

    # Both axes clean -> a single reassuring sentence.
    if provenance_verdict in _CLEAN_TIERS and jurisdiction_verdict in _CLEAN_TIERS:
        return _BOTH_CLEAN

    prov = ("provenance", _provenance_clause(provenance_verdict, bucket),
            _severity_rank(provenance_verdict))
    jur = ("jurisdiction", _jurisdiction_clause(jurisdiction_verdict, bucket),
           _severity_rank(jurisdiction_verdict))

    # Lead with the more-severe axis; tie-break = provenance first (its rank is
    # listed first, and Python's sort is stable, so an equal rank keeps prov ahead).
    ordered = sorted((prov, jur), key=lambda c: c[2])
    sentence = "; ".join(clause for _, clause, _ in ordered)
    return sentence[:1].upper() + sentence[1:] + "."


def plain_action(provenance_verdict: str, jurisdiction_verdict: str,
                 confidence: str) -> str:
    """One plain next step for the same tuple ``plain_answer`` reads.

    A pure function, so the CLI and the local UI cannot drift. It does not
    repeat the two verdicts. Confidence decides whether a serious read is
    strong enough to act on.
    """
    bucket = _conf_bucket(confidence)
    positive = provenance_verdict in ("CONFIRMED", "LIKELY") or jurisdiction_verdict in ("CONFIRMED", "LIKELY")
    unknown = provenance_verdict == "INDETERMINATE" or jurisdiction_verdict == "INDETERMINATE"
    if positive and bucket == "low":
        return ("Do not act on this alone; run the check again or ask the person "
                "who owns the risk to review the detail.")
    if positive:
        return ("Stop sending sensitive data through this app until the person "
                "who owns the risk reviews it.")
    if unknown:
        return ("Do not treat this as safe; run the check again once more of the "
                "optional fields are filled in.")
    return ("No change is needed; keep this result and run the check again if "
            "the app is updated.")


def plain_action_for_switch(result: dict) -> str:
    """The one next-step sentence for a red-team result.

    A confirmed tokenizer-shape move uses the serious step. A wire or echoed-id
    flag is not strong enough to act on alone. A self-ID change is not a switch,
    so it gets the quiet step. Every sentence is ``plain_action``.
    """
    if result.get("confirmed_switch"):
        return plain_action("CONFIRMED", "NO EVIDENCE", "high")
    if result.get("switch_detected"):
        return plain_action("LIKELY", "NO EVIDENCE", "low")
    return plain_action("UNLIKELY", "NO EVIDENCE", "high")


# --------------------------------------------------------------- /help render ---
def _layers_table() -> str:
    e = html.escape
    rows = "".join(
        f'<tr><td><b>{e(info.title)}</b></td><td>{e(info.measures)}</td>'
        f'<td>{e(info.hit_means)}</td></tr>'
        for info in LAYERS.values())
    return ('<div class="card"><table>'
            '<tr><th>Check</th><th>What it measures</th>'
            '<th>What a "hit" means</th></tr>'
            f'{rows}</table></div>')


def _prose_section(heading: str, paras: "tuple[str, ...]", *, top: int = 30) -> str:
    """A plain-prose /help section (heading + escaped paragraphs), used for the
    non-technical 'Why this matters' and 'Watching for model swaps' copy. Every
    paragraph is passed through html.escape — the copy is author-controlled, but
    escaping keeps it inert (defense-in-depth, like the rest of this module)."""
    e = html.escape
    body = "".join(
        f'<p style="max-width:64ch;margin:0 0 12px;font-size:15px">{e(p)}</p>'
        for p in paras)
    return f'<h2 style="margin-top:{top}px">{e(heading)}</h2>{body}'


def _verdict_block(axis: Axis) -> str:
    e = html.escape
    rows = "".join(
        f'<tr><td class="mono">{e(t.name)}</td><td>{e(t.meaning)}</td></tr>'
        for t in axis.tiers)
    return (f'<h3>{e(axis.title)}</h3>'
            f'<p class="sub">{e(axis.question)}</p>'
            '<div class="card"><table><tr><th>Verdict</th><th>What it means</th></tr>'
            f'{rows}</table></div>')


def _flow_detail_pairs(detail: str) -> "tuple[tuple[str, str], ...]":
    """Resolve a stage's ``detail`` pointer to (label, blurb) pairs — pulled LIVE
    from LAYERS / VERDICTS so the flow never carries its own copy of that wording.

    For "layers" the flow shows each layer's PLAIN ``flow_label`` (not the technical
    ``title`` /help uses) and its ``flow_blurb`` (falling back to ``measures``), so a
    non-technical reader never meets jargon like "tokenizer" or "wire fingerprint".
    """
    if detail == "layers":
        return tuple((info.flow_label or info.title,
                      info.flow_blurb or info.measures)
                     for info in LAYERS.values())
    if detail == "axes":
        return tuple((axis.title, axis.question) for axis in VERDICTS.values())
    return ()


def flow_html() -> str:
    """The 'how it works' flow as accessible static HTML — no ``<script>`` (works
    with JS disabled), never color/icon-only (every stage carries a visible text
    label), a semantic ordered list with an aria-label on the container and on each
    stage. Rendered from FLOW_STAGES + LAYERS / VERDICTS (the single source).
    """
    e = html.escape
    items = []
    for i, stage in enumerate(FLOW_STAGES, start=1):
        # The step NUMBER is drawn by the shared ol.steps CSS counter (a visible,
        # non-color label); the aria-label restates it for assistive tech.
        label = f"Step {i}: {stage.title}"
        detail = ""
        pairs = _flow_detail_pairs(stage.detail)
        if pairs:
            detail = ('<ul class="flow-detail">' + "".join(
                f'<li><b>{e(lbl)}</b> — {e(blurb)}</li>' for lbl, blurb in pairs)
                + "</ul>")
        items.append(
            f'<li class="flow-step" aria-label="{e(label)}">'
            f'<b class="flow-title">{e(stage.title)}</b>'
            f'<p class="sub">{e(stage.body)}</p>{detail}</li>')
    return ('<ol class="flow steps" aria-label="How provenance-probe works, step by step">'
            + "".join(items) + "</ol>")


def flow_text() -> str:
    """Plain-text twin of :func:`flow_html`, from the SAME FLOW_STAGES + LAYERS /
    VERDICTS source — printed by ``provenance-probe explain --flow``."""
    lines = ["How provenance-probe works", "=" * 26, ""]
    for i, stage in enumerate(FLOW_STAGES, start=1):
        lines.append(f"{i}. {stage.title}")
        lines.append(f"   {stage.body}")
        for lbl, blurb in _flow_detail_pairs(stage.detail):
            lines.append(f"     - {lbl}: {blurb}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def help_html() -> str:
    """The full ``/help`` page body, rendered from LAYERS / VERDICTS / FLOWS / FAQ.

    Returns only the inner body; the caller wraps it with :func:`ui.doc` so it
    gets the shared poster header and design-system stylesheet.
    """
    e = html.escape
    flows = "".join(
        f'<h3>{e(title)}</h3><p class="sub">{e(body)}</p>'
        for title, body in FLOWS)
    faq = "".join(
        f'<div class="box" style="margin-bottom:12px"><b>{e(q)}</b>'
        f'<p class="sub" style="margin:.4rem 0 0">{e(a)}</p></div>'
        for q, a in FAQ)
    return (
        '<h1 class="display" style="font-size:clamp(30px,5vw,46px);margin:2px 0 14px">'
        'How provenance-probe works</h1>'
        '<p class="lead">This tool points a battery of controlled checks at an AI '
        'endpoint and tells you two things in plain language: whose model is really '
        'answering, and who is running it. Here is what every part does — no jargon.</p>'

        # The visual pipeline first: the plain-English steps (single source:
        # FLOW_STAGES + LAYERS / VERDICTS), so a newcomer sees the shape before the prose.
        '<h2 style="margin-top:26px">How it works, step by step</h2>'
        + flow_html()

        # The plain-language mission next: the silent-swap threat and how to watch
        # for it. Both sections are sourced from the single-source constants above.
        + _prose_section("Why this matters", WHY_THIS_MATTERS, top=26)
        + _prose_section("Watching for model swaps", WATCHING_PRIMER) +

        '<h2 style="margin-top:30px">The tools, one by one</h2>'
        + flows +

        '<h2 style="margin-top:30px">What each check does</h2>'
        '<p class="sub">A full run tries up to eight checks. Each one adds evidence; '
        'a check that can\'t run just lowers confidence — it never invents a result.</p>'
        + _layers_table() +

        '<h2 style="margin-top:30px">What the verdict means</h2>'
        '<p class="sub">You get two <b>independent</b> answers. Read them together.</p>'
        + _verdict_block(VERDICTS["provenance"])
        + _verdict_block(VERDICTS["jurisdiction"])
        + f'<div class="ok"><b>Worked example.</b> {e(EXAMPLE)}</div>'

        '<h2 style="margin-top:30px">Questions</h2>'
        + faq +

        '<p class="sub" style="margin-top:24px">'
        '<a href="/">&larr; back to the live probe</a></p>')
