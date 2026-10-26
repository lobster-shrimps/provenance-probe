# -*- coding: utf-8 -*-
"""WS2 (#115): non-technical legibility.

Two new surfaces, both sourced ONLY from ``explain.py`` (single source of truth):

  * :func:`explain.plain_answer` — one deterministic, plain-English sentence that
    LEADS the assess result (serve UI + CLI), a PURE function of the
    (provenance, jurisdiction, confidence) tuple so the two surfaces cannot drift.
  * :func:`explain.flow_html` / :func:`explain.flow_text` — the visual/plain-text
    "how it works" flow, both rendered from ``FLOW_STAGES`` + ``LAYERS``/``VERDICTS``.

These tests are the acceptance criteria: the full 25 x 3 grid (quality proxies +
the INDETERMINATE disclaimer), the flow structure/accessibility assertions, the
single-source guard, and the serve-vs-CLI drift test.
"""
from __future__ import annotations

import re

import pytest

from provenance_probe import explain
from provenance_probe.scoring import _TIER_ORDER


VERDICT_WORDS = tuple(_TIER_ORDER)  # NO EVIDENCE, UNLIKELY, INDETERMINATE, LIKELY, CONFIRMED
CONFIDENCES = ("high", "moderate", "low")
CLEAN = {"UNLIKELY", "NO EVIDENCE"}
# The full string _conf() actually returns for the low bucket — plain_answer must
# normalise it to the "low" adverb (it takes the first token).
LOW_RAW = "low - insufficient evidence layers; do not report a verdict on this alone"

# Jargon a non-technical reader should never meet in the plain answer (AC1).
BANNED_JARGON = ("tokenizer", "fingerprint", "log-odds", "logprob",
                 "sigmoid", "vector", "entropy")


def _grid():
    for p in VERDICT_WORDS:
        for j in VERDICT_WORDS:
            for c in CONFIDENCES:
                yield p, j, c


# --------------------------------------------------------------------------- #
# plain_answer — the full 25 x 3 grid
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_plain_answer_covers_the_full_grid_deterministically():
    for p, j, c in _grid():
        s1 = explain.plain_answer(p, j, c)
        s2 = explain.plain_answer(p, j, c)
        assert isinstance(s1, str) and s1, (p, j, c)
        assert s1 == s2, "plain_answer must be a pure, deterministic function"


@pytest.mark.unit
def test_plain_answer_is_a_single_sentence_under_200_chars():
    for p, j, c in _grid():
        s = explain.plain_answer(p, j, c)
        assert len(s) <= 200, f"{len(s)} chars for {(p, j, c)}: {s}"
        assert s.endswith("."), (p, j, c, s)
        # One sentence: no interior sentence break (". " mid-string). Clauses are
        # joined with "; ", never a full stop.
        assert ". " not in s, f"multiple sentences for {(p, j, c)}: {s}"


@pytest.mark.unit
def test_plain_answer_has_no_banned_jargon():
    for p, j, c in _grid():
        s = explain.plain_answer(p, j, c).lower()
        for term in BANNED_JARGON:
            assert term not in s, f"jargon '{term}' in {(p, j, c)}: {s}"


@pytest.mark.unit
def test_plain_answer_indeterminate_axis_carries_the_disclaimer():
    # AC2: whenever an axis is INDETERMINATE, the sentence teaches the WS1 nuance —
    # it is neither a clean bill nor an accusation.
    for p, j, c in _grid():
        s = explain.plain_answer(p, j, c)
        if "INDETERMINATE" in (p, j):
            assert "not a clean bill" in s, (p, j, c, s)
            assert "not an accusation" in s, (p, j, c, s)


@pytest.mark.unit
def test_plain_answer_both_clean_collapses_to_one_reassuring_sentence():
    for c in CONFIDENCES:
        for p in CLEAN:
            for j in CLEAN:
                s = explain.plain_answer(p, j, c)
                assert "the kind of model it claims" in s
                assert "run where it claims" in s
                assert ";" not in s, f"both-clean must be one clause: {s}"


@pytest.mark.unit
def test_plain_answer_leads_with_the_more_severe_axis():
    # CONFIRMED provenance + UNLIKELY jurisdiction -> the provenance (positive) clause
    # comes first; the reassuring jurisdiction clause second.
    s = explain.plain_answer("CONFIRMED", "UNLIKELY", "high")
    assert s.index("Chinese-origin model") < s.index("no sign of PRC")
    # UNLIKELY provenance + CONFIRMED jurisdiction -> jurisdiction clause first.
    s2 = explain.plain_answer("UNLIKELY", "CONFIRMED", "high")
    assert s2.index("PRC jurisdiction") < s2.index("no sign of a Chinese-origin")


@pytest.mark.unit
def test_plain_answer_tie_break_is_provenance_first():
    # Equal severity on both axes -> provenance (the founding concern) leads.
    s = explain.plain_answer("CONFIRMED", "CONFIRMED", "high")
    assert s.index("Chinese-origin model") < s.index("PRC jurisdiction")


@pytest.mark.unit
def test_plain_answer_confidence_adverbs_are_distinct_per_bucket():
    hi = explain.plain_answer("CONFIRMED", "NO EVIDENCE", "high")
    mod = explain.plain_answer("CONFIRMED", "NO EVIDENCE", "moderate")
    lo = explain.plain_answer("CONFIRMED", "NO EVIDENCE", "low")
    assert "clearly" in hi
    assert "likely" in mod
    assert "preliminary" in lo
    assert hi != mod != lo


@pytest.mark.unit
def test_plain_answer_accepts_the_raw_conf_string():
    # _conf() returns a long string for the low bucket; plain_answer normalises it.
    assert explain.plain_answer("CONFIRMED", "NO EVIDENCE", LOW_RAW) == \
        explain.plain_answer("CONFIRMED", "NO EVIDENCE", "low")


@pytest.mark.unit
def test_plain_action_is_one_plain_next_step():
    for p, j, c in _grid():
        s1 = explain.plain_action(p, j, c)
        s2 = explain.plain_action(p, j, c)
        assert s1 == s2 and s1.endswith(".")
        assert len(s1) <= 200
        assert ". " not in s1
        low = s1.lower()
        for term in BANNED_JARGON:
            assert term not in low


def test_plain_action_follows_severity_and_confidence():
    assert explain.plain_action("CONFIRMED", "NO EVIDENCE", "high").startswith("Stop sending")
    assert explain.plain_action("NO EVIDENCE", "LIKELY", "moderate").startswith("Stop sending")
    assert explain.plain_action("CONFIRMED", "UNLIKELY", "low").startswith("Do not act on this alone")
    assert explain.plain_action("INDETERMINATE", "UNLIKELY", "high").startswith("Do not treat this as safe")
    assert explain.plain_action("UNLIKELY", "NO EVIDENCE", "high").startswith("No change is needed")


def test_plain_action_for_switch_reuses_the_same_sentence():
    # Red-team has no second copy. Confirmed, wire-only, and quiet map onto
    # the three plain_action sentences.
    confirmed = explain.plain_action_for_switch(
        {"confirmed_switch": True, "switch_detected": True})
    flagged = explain.plain_action_for_switch({"switch_detected": True})
    quiet = explain.plain_action_for_switch(
        {"switch_detected": False, "self_id_changed": True})
    assert confirmed == explain.plain_action("CONFIRMED", "NO EVIDENCE", "high")
    assert flagged == explain.plain_action("LIKELY", "NO EVIDENCE", "low")
    assert quiet == explain.plain_action("UNLIKELY", "NO EVIDENCE", "high")
    assert len({confirmed, flagged, quiet}) == 3


def test_plain_answer_positive_provenance_is_honest_not_deceptive():
    # Pure-tuple honesty: it asserts origin, NOT misrepresentation. No "not what it
    # claims" framing (that needs a persona-mismatch signal not in the tuple).
    for c in CONFIDENCES:
        s = explain.plain_answer("CONFIRMED", "NO EVIDENCE", c)
        assert "serving a Chinese-origin model" in s
        assert "not what it claims" not in s


# --------------------------------------------------------------------------- #
# flow_text / flow_html — sourced from FLOW_STAGES + LAYERS/VERDICTS
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_flow_text_renders_every_stage_and_is_sourced_from_layers_and_axes():
    txt = explain.flow_text()
    assert txt.strip()
    # Every stage title from the single source appears.
    for stage in explain.FLOW_STAGES:
        assert stage.title in txt, stage.title
    # Stage that enumerates the layers pulls every LAYER's PLAIN flow label from
    # the source (the flow is non-technical; the technical title stays on /help).
    for info in explain.LAYERS.values():
        assert info.flow_label in txt, info.flow_label
    # Stage that enumerates the axes pulls both axis questions from VERDICTS.
    for axis in explain.VERDICTS.values():
        assert axis.question in txt, axis.question


# The flow is the non-technical surface: step 2 must never show a layer's TECHNICAL
# name or the engineering jargon a newcomer wouldn't know (mirrors BANNED_JARGON,
# plus the layer-name jargon the reviewer flagged).
FLOW_BANNED_JARGON = ("tokenizer", "fingerprint", "wire", "log-odds", "logprob",
                      "sigmoid", "vector", "entropy")


@pytest.mark.unit
def test_flow_uses_plain_layer_labels_not_technical_titles():
    import html as _html
    txt = explain.flow_text()
    h = explain.flow_html()
    for info in explain.LAYERS.values():
        # A non-empty plain label distinct from the technical /help title.
        assert info.flow_label, info.title
        assert info.flow_label != info.title, info.title
        assert info.flow_label in txt, info.flow_label
        assert _html.escape(info.flow_label) in h, info.flow_label
    # The two technical layer titles the reviewer flagged must NOT leak into the flow.
    for technical in ("Tokenizer fingerprint", "Wire fingerprint"):
        assert technical not in txt, technical
        assert technical not in h, technical


@pytest.mark.unit
def test_flow_has_no_banned_technical_jargon():
    txt = explain.flow_text().lower()
    h = explain.flow_html().lower()
    for term in FLOW_BANNED_JARGON:
        assert term not in txt, f"jargon '{term}' leaked into flow_text(): {txt}"
        assert term not in h, f"jargon '{term}' leaked into flow_html()"


@pytest.mark.unit
def test_flow_html_is_accessible_static_markup():
    h = explain.flow_html()
    # No script — works with JS disabled (AC5).
    assert "<script" not in h.lower()
    # Semantic list/figure structure.
    assert "<ol" in h and "<li" in h
    # aria-label on the container AND on every stage (count stages).
    assert h.count("aria-label=") >= len(explain.FLOW_STAGES) + 1
    # Every stage exposes a VISIBLE text label (not color/icon alone): the stage
    # title appears as escaped text in the markup.
    import html as _html
    for stage in explain.FLOW_STAGES:
        assert _html.escape(stage.title) in h, stage.title


@pytest.mark.unit
def test_flow_html_enumerates_layers_and_axes_from_the_single_source():
    import html as _html
    h = explain.flow_html()
    # Step 2 shows each layer's PLAIN flow label (the technical title stays on /help).
    for info in explain.LAYERS.values():
        assert _html.escape(info.flow_label) in h, info.flow_label
    for axis in explain.VERDICTS.values():
        assert _html.escape(axis.question) in h, axis.question


@pytest.mark.unit
def test_help_layers_table_keeps_the_technical_titles():
    # The plain flow labels must NOT bleed into /help: _layers_table (the technical
    # reference) still renders the technical LAYERS titles verbatim, unchanged.
    import html as _html
    table = explain._layers_table()
    for info in explain.LAYERS.values():
        assert _html.escape(info.title) in table, info.title
    # And the two flagged technical names are present on the /help table specifically.
    for technical in ("Tokenizer fingerprint", "Wire fingerprint"):
        assert technical in table, technical


@pytest.mark.unit
def test_flow_html_escapes_stage_copy(monkeypatch):
    # Defense-in-depth: author-controlled copy still lands escaped.
    boom = explain.FLOW_STAGES[0]._replace(title="<script>x</script>")
    monkeypatch.setattr(explain, "FLOW_STAGES",
                        (boom,) + tuple(explain.FLOW_STAGES[1:]))
    h = explain.flow_html()
    assert "<script>x</script>" not in h
    assert "&lt;script&gt;x&lt;/script&gt;" in h


# --------------------------------------------------------------------------- #
# Single-source guard: no verdict-word sentences or stage labels in serve/cli
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_no_plain_answer_or_flow_copy_is_hardcoded_in_serve_or_cli():
    import pathlib
    root = pathlib.Path(explain.__file__).parent
    serve_src = (root / "serve.py").read_text()
    cli_src = (root / "cli.py").read_text()

    # Distinctive plain_answer fragments — these must live ONLY in explain.py.
    forbidden = [
        "serving a Chinese-origin model",
        "no sign of PRC-jurisdiction operation",
        "no sign of a Chinese-origin model",
        "not a clean bill",
        "not an accusation",
        "the kind of model it claims",
        "under PRC jurisdiction (Chinese data law can apply)",
        "Stop sending sensitive data through this app",
        "Do not act on this alone",
        "Do not treat this as safe",
        "No change is needed",
    ]
    # ...plus every FLOW_STAGES stage title and every plain layer flow label.
    forbidden += [stage.title for stage in explain.FLOW_STAGES]
    forbidden += [info.flow_label for info in explain.LAYERS.values()]

    for src, name in ((serve_src, "serve.py"), (cli_src, "cli.py")):
        for frag in forbidden:
            assert frag not in src, f"{name} hardcodes explain copy: {frag!r}"
