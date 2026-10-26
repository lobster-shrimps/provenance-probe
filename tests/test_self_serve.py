# -*- coding: utf-8 -*-
"""WS4 lean pass: a first-timer picks a known service, then uses the existing
probe, the existing plain next step, and the existing watch handoff.

No network. The picker only fills form fields from corpus hosts.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

import pytest

from provenance_probe import serve, servicecatalog
from provenance_probe.data import corpus


@pytest.fixture
def client():
    return serve.app.test_client()


def test_probe_picks_are_corpus_hosts_and_carry_no_key():
    picks = servicecatalog.probe_picks()
    assert picks
    ids = [p["id"] for p in picks]
    assert len(ids) == len(set(ids))
    known = (set(corpus.FIRST_PARTY_ENDPOINTS) | set(corpus.PRC_ENDPOINTS)
             | set(corpus.AGGREGATOR_ENDPOINTS))
    for pick in picks:
        host = urlsplit(pick["base_url"]).hostname
        assert host in known, pick["id"]
        assert pick["base_url"].startswith("https://")
        assert pick["api_style"] in ("openai", "anthropic")
        assert "api_key" not in pick
        assert "key" not in pick


def test_landing_and_watch_share_the_same_picker(client):
    landing = client.get("/").get_data(as_text=True)
    watch = client.get("/watch").get_data(as_text=True)
    for body in (landing, watch):
        assert 'id="service_pick"' in body
        assert "function applyServicePick()" in body
        assert "function initServicePick()" in body
        assert 'href="/wizard"' in body
        assert "api_key" not in body.split("function applyServicePick()")[1].split("function initServicePick()")[0]
        for pick in servicecatalog.probe_picks():
            assert pick["label"] in body
            assert pick["base_url"] in body
    # The run still leads with the existing next-step slot, then offers watch.
    assert 'aria-label="Next step"' in landing
    assert "function watchThis()" in landing
    assert "Watch this target for a swap" in landing


def test_pick_query_does_not_override_an_explicit_address():
    script = servicecatalog.probe_pick_script()
    assert "q.get('pick')" in script
    assert "q.get('base_url')" in script


def test_picker_escapes_a_hostile_label(client, monkeypatch):
    hostile = dict(servicecatalog.probe_picks()[0])
    hostile["id"] = "x"
    hostile["label"] = "<script>alert(1)</script>"
    hostile["name"] = "<b>name</b>"
    monkeypatch.setattr(servicecatalog, "_PROBE_PICKS", (hostile,))
    body = client.get("/").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    blob = body.split("const SERVICE_PICKS = ", 1)[1].split(";", 1)[0]
    data = json.loads(blob)
    assert data[0]["label"] == "<script>alert(1)</script>"
    assert "<script>alert(1)</script>" not in blob
