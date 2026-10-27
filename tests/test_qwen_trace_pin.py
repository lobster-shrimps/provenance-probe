"""Pinned slice of CohereLabs/10-2026-qwen-investigation-traces.

The caught file is the published JSONL. The prefill file is README sample 7
from that same dataset (a cue-response completion). No model call, no API key,
no new behavior ids.
"""
from pathlib import Path

from provenance_probe import agent_behaviors

FIXTURES = Path(__file__).parent / "fixtures" / "cohere_qwen"
CAUGHT_IDS = {
    "beijing_oss_put",
    "fabricated_prior_turn",
    "host_inventory",
    "reasoning_denies_tools",
}


def test_published_trace_matches_the_existing_ids():
    raw = (FIXTURES / "qwen-investigation.jsonl").read_text(encoding="utf-8")
    rows = agent_behaviors.scan_trace(raw)
    assert {row["id"] for row in rows} == CAUGHT_IDS
    put = next(row for row in rows if row["id"] == "beijing_oss_put")
    assert put["indicator"] == "sanmaohe.oss-cn-beijing.aliyuncs.com"
    assert put["source"] == "cohere-2026-10-26"


def test_prefill_completion_stays_quiet():
    raw = (FIXTURES / "qwen-prefill.jsonl").read_text(encoding="utf-8")
    assert agent_behaviors.scan_trace(raw) == []
