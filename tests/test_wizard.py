"""Add-a-target wizard: cURL/HAR parse + template synthesis (paste-first v1)."""
import json
import os

import pytest

from provenance_probe import wizard


# --- cURL parsing ------------------------------------------------------------

def test_parse_curl_basic():
    cur = (
        "curl 'https://chat.example.com/api/chat' "
        "-X POST "
        "-H 'content-type: application/json' "
        "-H 'x-csrf-token: abc123' "
        "-H 'cookie: session=secret; other=1' "
        "--data-raw '{\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}'"
    )
    c = wizard.parse_curl(cur)
    assert c.url == "https://chat.example.com/api/chat"
    assert c.method == "POST"
    assert c.headers["content-type"] == "application/json"
    assert c.headers["x-csrf-token"] == "abc123"
    assert c.cookie == "session=secret; other=1"      # cookie split out of headers
    assert "cookie" not in {k.lower() for k in c.headers}
    assert json.loads(c.body)["messages"][0]["content"] == "hello"


def test_parse_curl_line_continuations_and_b_flag():
    c = wizard.parse_curl("curl 'https://x.ai/c' \\\n  -b 'sid=9' \\\n  --data '{\"q\":\"hi\"}'")
    assert c.cookie == "sid=9" and c.method == "POST"


def test_parse_curl_empty_raises():
    with pytest.raises(ValueError):
        wizard.parse_curl("   ")


def test_parse_curl_no_url_raises():
    with pytest.raises(ValueError):
        wizard.parse_curl("curl -X POST -H 'a: b'")


# --- HAR parsing -------------------------------------------------------------

def _har(entries):
    return json.dumps({"log": {"entries": entries}})


def test_parse_har_picks_prompt_bearing_post():
    har = _har([
        {"request": {"method": "GET", "url": "https://x.ai/ping", "headers": []}},
        {"request": {"method": "POST", "url": "https://x.ai/api/chat",
                     "headers": [{"name": "cookie", "value": "s=1"},
                                 {"name": "content-type", "value": "application/json"}],
                     "postData": {"text": '{"content":"fingerprint me"}'}},
         "response": {"headers": [{"name": "content-type", "value": "application/json"}],
                      "content": {"text": '{"reply":"ok","usage":{"prompt_tokens":7},"model":"glm-4.6"}'}}},
    ])
    c = wizard.parse_har(har, prompt_hint="fingerprint me")
    assert c.url == "https://x.ai/api/chat" and c.cookie == "s=1"
    assert c.response["usage"]["prompt_tokens"] == 7


def test_parse_har_no_post_raises():
    with pytest.raises(ValueError):
        wizard.parse_har(_har([{"request": {"method": "GET", "url": "https://x.ai/", "headers": []}}]))


# --- dotted-path search ------------------------------------------------------

def test_find_paths_in_nested_response():
    resp = {"choices": [{"message": {"content": "the answer"}}],
            "usage": {"prompt_tokens": 12}, "model": "glm-4.6"}
    assert wizard.find_text_path(resp, "the answer") == "choices.0.message.content"
    assert wizard.find_usage_path(resp) == "usage.prompt_tokens"
    assert wizard.find_model_path(resp) == "model"


def test_find_usage_path_absent_returns_none():
    assert wizard.find_usage_path({"choices": [{"text": "hi"}]}) is None


# --- synthesis ---------------------------------------------------------------

def _cap(body, cookie="sess=abc", response=None, ct=""):
    return wizard.Captured(url="https://chat.example.com/api/v1/chat",
                           method="POST", headers={"x-csrf-token": "t1", "host": "drop"},
                           body=json.dumps(body), cookie=cookie, response=response, content_type=ct)


def test_synthesize_prompt_becomes_placeholder():
    s = wizard.synthesize(_cap({"messages": [{"role": "user", "content": "PROBE"}]}), "PROBE", "lindy")
    assert s.target["request_template"]["messages"][0]["content"] == "__PROMPT__"
    assert s.target["base_url"] == "https://chat.example.com"
    assert s.target["chat_path"] == "/api/v1/chat"
    assert s.target["api_style"] == "template"


def test_synthesize_cookie_never_in_committable_config():
    s = wizard.synthesize(_cap({"content": "PROBE"}), "PROBE", "lindy")
    blob = json.dumps(s.target)
    assert "sess=abc" not in blob                  # the credential is NOT in the config
    assert s.target["cookie_env"] == "LINDY_COOKIE"
    assert s.cookie_value == "sess=abc"            # it is returned separately for env storage


def test_synthesize_strips_stateful_ids_with_warning():
    s = wizard.synthesize(_cap({"conversation_id": "c-99", "content": "PROBE"}), "PROBE", "t")
    assert s.target["request_template"]["conversation_id"] == ""
    assert any("stateful" in w for w in s.warnings)


def test_synthesize_authorized_defaults_false():
    s = wizard.synthesize(_cap({"content": "PROBE"}), "PROBE", "t")
    assert s.target["authorized"] is False          # never auto-authorize probing


def test_synthesize_keeps_csrf_drops_host_header():
    s = wizard.synthesize(_cap({"content": "PROBE"}), "PROBE", "t")
    assert s.target["extra_headers"].get("x-csrf-token") == "t1"
    assert "host" not in s.target["extra_headers"]
    assert any("dynamic" in w for w in s.warnings)  # csrf flagged as dynamic


def test_synthesize_warns_when_usage_absent():
    resp = {"choices": [{"message": {"content": "hi"}}], "model": "m"}  # no usage
    s = wizard.synthesize(_cap({"content": "PROBE"}, response=resp), "PROBE", "t")
    assert any("tokenizer fingerprint will be UNAVAILABLE" in w for w in s.warnings)


def test_synthesize_finds_response_paths_from_har_response():
    resp = {"choices": [{"message": {"content": "PROBE reply"}}],
            "usage": {"prompt_tokens": 5}, "model": "glm-4.6"}
    s = wizard.synthesize(_cap({"content": "PROBE"}, response=resp), "PROBE reply", "t")
    assert s.target["response_prompt_tokens_path"] == "usage.prompt_tokens"
    assert s.target["response_model_path"] == "model"
    assert s.target["response_text_path"] == "choices.0.message.content"


def test_synthesize_detects_sse():
    s = wizard.synthesize(_cap({"content": "PROBE"}, ct="text/event-stream; charset=utf-8"), "PROBE", "t")
    assert s.target["stream_mode"] == "sse"
    assert any("SSE" in w for w in s.warnings)


def test_synthesize_non_json_body_warns():
    cap = wizard.Captured(url="https://x.ai/c", method="POST", headers={},
                          body="q=hi&n=1", cookie="s=1")
    s = wizard.synthesize(cap, "hi", "t")
    assert any("not JSON" in w for w in s.warnings)


# --- dry-run -----------------------------------------------------------------

class _Resp:
    def __init__(self, status, n, text="reply"):
        self.status, self._n, self._t = status, n, text
    @property
    def ok(self):                      # mirror client.Response.ok (a property, not a method)
        return 200 <= self.status < 300
    def usage_prompt_tokens(self):
        return self._n
    def text(self):
        return self._t


class _Client:
    def __init__(self, script):
        self.script, self.i = list(script), -1
    def chat(self, prompt, **kw):
        self.i += 1
        return _Resp(*self.script[min(self.i, len(self.script) - 1)])


def test_dry_run_usable_and_replay_safe():
    out = wizard.dry_run(_Client([(200, 7, "hi"), (200, 8, "ok")]))
    assert out["ok"] and out["usage_exposed"] and out["replay_safe"]


def test_dry_run_http_error_is_not_ok():
    out = wizard.dry_run(_Client([(401, None, "")]))
    assert not out["ok"] and "HTTP 401" in out["error"]


def test_dry_run_usage_suppressed_is_degraded_but_replay_safe():
    out = wizard.dry_run(_Client([(200, None, "hi"), (200, None, "ok")]))
    assert out["ok"] and not out["usage_exposed"] and out["replay_safe"]  # stateless, degraded


def test_dry_run_unstable_counts_flag_replay_unsafe():
    out = wizard.dry_run(_Client([(200, 7, "hi"), (200, 900, "ok")]))   # wild drift = stateful
    assert out["usage_exposed"] and not out["replay_safe"]
    assert out["verdict"]["replay"] == "impossible"
    assert out["verdict"]["replay_reason"] == "stateful"
    assert out["verdict"]["signal"] == "none"
    assert out["verdict"]["confirmed_switch"] is False


def test_dry_run_rejected_replay_can_still_flag_a_live_tokenizer_switch():
    from provenance_probe import monitor
    base = {"tokenizer": {"usable": True, "vector": {"a": 10, "b": 12, "c": 15, "d": 11, "e": 13, "f": 14}},
            "errors": {"error_signature": "sig"}, "headers": {"header_shape_hash": "h"},
            "greedy": {"signature": "g"}, "streaming": {"chunk_fields": ["choices"]}}
    cur = dict(base)
    cur["tokenizer"] = {"usable": True, "vector": {"a": 10, "b": 40, "c": 15, "d": 70, "e": 13, "f": 3}}
    out = wizard.dry_run(
        _Client([(401, None, "")]),
        live={"baseline": base, "current": cur, "self_id_changed": True})
    v = out["verdict"]
    assert not out["ok"] and "HTTP 401" in out["error"]
    assert v["replay"] == "impossible" and v["replay_carried"] is False
    assert v["signal"] == "tokenizer" and v["confirmed_switch"] is True
    assert v["self_id_confirmed"] is False
    assert monitor.grade_unreplayable(base, cur, reason="signed-or-stateful",
                                      self_id_changed=True)["note"] == v["note"]


def test_dry_run_that_replays_does_not_claim_replay_was_impossible():
    out = wizard.dry_run(_Client([(200, 7, "hi"), (200, 8, "ok")]))
    assert "verdict" not in out


def test_dry_run_no_reply_is_not_ok():
    out = wizard.dry_run(_Client([(200, 7, ""), (200, 7, "")]))   # HTTP ok but empty replies
    assert not out["ok"] and "no reply" in out["error"]


# --- auto-detect response paths (replay + introspect) ------------------------

class _RichResp:
    def __init__(self, status=200, body=None, headers=None, stream_text=None, raw=""):
        self.status, self.body, self.err = status, body, None
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.stream_text = stream_text
        self.raw = raw
    @property
    def ok(self):
        return 200 <= self.status < 300
    def text(self):
        if self.stream_text is not None:
            return self.stream_text
        try:
            return self.body["choices"][0]["message"]["content"]
        except Exception:
            return self.raw


class _RichClient:
    def __init__(self, resp): self.resp = resp
    def chat(self, prompt, **kw): return self.resp


def test_find_reply_path_prefers_standard_shape():
    body = {"choices": [{"message": {"content": "the assistant reply here"}}],
            "usage": {"prompt_tokens": 12}, "model": "glm-4.6"}
    assert wizard.find_reply_path(body) == "choices.0.message.content"


def test_find_reply_path_falls_back_to_longest_string():
    body = {"id": "abc", "data": {"answer_blob": "a much longer assistant response string"}}
    assert wizard.find_reply_path(body) == "data.answer_blob"


def test_find_reply_path_skips_credential_and_echo_fields():
    # MEDIUM (Codex): the fallback must not point at a reflected cookie/prompt.
    body = {"echoed_cookie": "sid=" + "X" * 200,                 # credential-ish leaf → skipped
            "prompt": "fingerprint me now please and thanks",    # echo leaf → skipped
            "out": {"reply": "the genuine model reply text here"}}
    p = wizard.find_reply_path(body, skip_values=("fingerprint me now please and thanks",))
    assert p == "out.reply"          # 'reply' is a standard path, and echoes are excluded


def test_discover_response_paths_openai_shape():
    body = {"choices": [{"message": {"content": "hi there friend"}}],
            "usage": {"prompt_tokens": 9}, "model": "glm-4.6"}
    out = wizard.discover_response_paths(_RichClient(_RichResp(200, body,
                                        {"content-type": "application/json"})), "fingerprint me")
    assert out["ok"]
    assert out["paths"]["response_text_path"] == "choices.0.message.content"
    assert out["paths"]["response_prompt_tokens_path"] == "usage.prompt_tokens"
    assert out["paths"]["response_model_path"] == "model"


def test_discover_response_paths_detects_sse():
    r = _RichResp(200, body="data: {...}", headers={"content-type": "text/event-stream"},
                  stream_text="streamed reply")
    out = wizard.discover_response_paths(_RichClient(r), "hi")
    assert out["ok"] and out["stream_mode"] == "sse"
    assert out["paths"]["stream_delta_path"]


def test_discover_response_paths_http_error_is_friendly():
    out = wizard.discover_response_paths(_RichClient(_RichResp(401, None)), "hi")
    assert not out["ok"] and "401" in out["error"] and "re-capture" in out["error"]


def test_discover_response_paths_non_json():
    r = _RichResp(200, body="<html>not json</html>", headers={"content-type": "text/html"})
    out = wizard.discover_response_paths(_RichClient(r), "hi")
    assert not out["ok"] and "not JSON" in out["error"]


# --- sanitize (defense-in-depth at the write boundary) -----------------------

def test_sanitize_strips_cookie_and_auth_headers():
    dirty = {"name": "x", "cookie": "sess=SECRET",
             "extra_headers": {"x-csrf-token": "ok", "Cookie": "c=SECRET", "Authorization": "Bearer S"}}
    clean, removed = wizard.sanitize_target(dirty)
    assert "cookie" not in clean
    assert clean["extra_headers"] == {"x-csrf-token": "ok"}
    assert "cookie" in removed and any("Cookie" in r for r in removed) and any("Authorization" in r for r in removed)


def test_sanitize_strips_smuggled_key_headers_keeps_csrf():
    # HIGH (Codex): a key smuggled under a non-exact header name must be stripped;
    # but a CSRF token (needed for replay) must be KEPT.
    dirty = {"name": "x", "extra_headers": {
        "X-Api-Key-Alt": "sk-SMUGGLED", "x-session-token": "SESS", "authorization": "Bearer S",
        "x-csrf-token": "keep-me", "origin": "https://app.example"}}
    clean, removed = wizard.sanitize_target(dirty)
    assert clean["extra_headers"] == {"x-csrf-token": "keep-me", "origin": "https://app.example"}
    assert any("X-Api-Key-Alt" in r for r in removed)
    assert any("x-session-token" in r for r in removed)


def test_sanitize_strips_vendor_key_and_vault_headers_keeps_idempotency():
    # MEDIUM (Claude): vendor key + vault/security-token headers must be stripped;
    # a non-secret idempotency-key (Stripe-style, no x- prefix) must be KEPT.
    dirty = {"name": "x", "extra_headers": {
        "x-anthropic-key": "sk-A", "x-openai-key": "sk-O", "x-vault-token": "V",
        "x-amz-security-token": "T", "idempotency-key": "keep-123", "origin": "https://a.b"}}
    clean, removed = wizard.sanitize_target(dirty)
    assert clean["extra_headers"] == {"idempotency-key": "keep-123", "origin": "https://a.b"}
    for smuggled in ("x-anthropic-key", "x-openai-key", "x-vault-token", "x-amz-security-token"):
        assert any(smuggled in r for r in removed)


def test_is_git_tracked_detects_tracked_file():
    # HIGH (Claude): _is_git_tracked raised a swallowed NameError (os not in scope)
    # and always returned False, silently disabling the git-tracked-cookie warning.
    from provenance_probe import wizard as _wz
    import subprocess
    repo = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True).stdout.strip()
    tracked = os.path.join(repo, "pyproject.toml")     # git confirms this is tracked
    assert _wz._is_git_tracked(tracked) is True
    assert _wz._is_git_tracked(os.path.join(repo, "does-not-exist-xyz.tmp")) is False


# --- save --------------------------------------------------------------------

def test_write_target_appends_list_and_keeps_cookie_out_of_config(tmp_path):
    cfg = tmp_path / "targets.json"
    env = tmp_path / ".env.capture"
    target = {"name": "lindy", "base_url": "https://chat.lindy.ai", "api_style": "template",
              "cookie_env": "LINDY_COOKIE", "authorized": False}
    res = wizard.write_target(target, "sess=SECRET", config_path=str(cfg),
                              env_path=str(env), repo_root=str(tmp_path))
    written = json.loads(cfg.read_text())
    assert isinstance(written, list) and written[0]["name"] == "lindy"   # loader-consumable shape
    assert "SECRET" not in cfg.read_text()               # cookie never in committed config
    assert "LINDY_COOKIE=sess=SECRET" in env.read_text()  # cookie in the env file only
    assert ".env.capture" in (tmp_path / ".gitignore").read_text()   # env file gitignored
    assert res["added"] == "lindy"
    # HIGH (Claude): the cookie file must be owner-only (0600), never world-readable.
    assert (os.stat(env).st_mode & 0o777) == 0o600


def test_write_target_sanitizes_smuggled_cookie_in_edited_target(tmp_path):
    cfg = tmp_path / "targets.json"
    # a hand-edited target that tries to smuggle a cookie into the committed config
    target = {"name": "x", "api_style": "template", "cookie": "sess=SMUGGLED",
              "extra_headers": {"Cookie": "c=SMUGGLED", "x-csrf-token": "keep"}}
    res = wizard.write_target(target, "", config_path=str(cfg),
                              env_path=str(tmp_path / ".env"), repo_root=str(tmp_path))
    text = cfg.read_text()
    assert "SMUGGLED" not in text                        # sanitized at the write boundary
    assert "keep" in text                                # non-secret header preserved
    assert any("stripped credential" in w for w in res["warnings"])


def test_write_target_refuses_name_clobber(tmp_path):
    cfg = tmp_path / "targets.json"
    cfg.write_text(json.dumps([{"name": "lindy"}]))      # loader shape = list
    with pytest.raises(ValueError):
        wizard.write_target({"name": "lindy"}, "", config_path=str(cfg),
                            env_path=str(tmp_path / ".env"), repo_root=str(tmp_path))


def test_ensure_gitignored_idempotent(tmp_path):
    wizard.ensure_gitignored(str(tmp_path), ".env.capture")
    wizard.ensure_gitignored(str(tmp_path), ".env.capture")   # second call no dupe
    assert (tmp_path / ".gitignore").read_text().count(".env.capture") == 1


# --- serve UI routes ---------------------------------------------------------

_CURL = ("curl 'https://chat.example.com/api/chat' -X POST "
         "-H 'content-type: application/json' -H 'cookie: sid=LEAKME' "
         "--data-raw '{\"messages\":[{\"role\":\"user\",\"content\":\"fingerprint me\"}]}'")


def _client():
    from provenance_probe import serve
    return serve.app.test_client()


def test_wizard_get_renders_form():
    r = _client().get("/wizard")
    assert r.status_code == 200 and b"Add a target" in r.data
    # One door (E2): the default view never asks the operator to pick an api_style.
    assert b"API style" not in r.data and b"api_style" not in r.data


def test_wizard_post_previews_and_never_reflects_cookie():
    r = _client().post("/wizard", data={"name": "demo", "prompt": "fingerprint me",
                                         "fmt": "curl", "capture": _CURL})
    assert r.status_code == 200 and b"Confirm" in r.data and b"__PROMPT__" in r.data
    assert b"LEAKME" not in r.data          # cookie NOWHERE in the response (no hidden round-trip)
    assert b"name=token" in r.data          # server-side stash token instead


def test_wizard_post_bad_capture_shows_error():
    # One-door: an unclassifiable paste gets the friendly "couldn't tell" message.
    r = _client().post("/wizard", data={"name": "x", "prompt": "hi",
                                        "capture": "not a url with spaces"})
    assert r.status_code == 200 and b"tell what that is" in r.data


# --------------------------------------------------------------------------- #
# One-door endpoint path: classify -> consent gate -> detect -> preview
# --------------------------------------------------------------------------- #

import re as _re


def _consent_token(client, name, capture):
    """Drive the /wizard endpoint branch and return the issued consent token."""
    r = client.post("/wizard", data={"name": name, "capture": capture})
    assert r.status_code == 200 and b"/wizard/detect" in r.data
    m = _re.search(rb'name=token value="([0-9a-f]+)"', r.data)
    assert m, "consent page did not issue a token"
    return r, m.group(1).decode()


def test_wizard_endpoint_shows_consent_gate_no_egress():
    # A plain URL must land on the consent gate, NOT probe anything yet.
    r, token = _consent_token(_client(), "oai", "https://api.openai.com/v1")
    assert b"identify test" in r.data or b"Send a short identify test" in r.data
    assert b"api.openai.com" in r.data
    assert token                                 # a one-shot token was issued


def test_wizard_detect_requires_consent_token():
    # CRITICAL (Codex): a direct POST without a valid token must send NOTHING.
    r = _client().post("/wizard/detect", data={"passive_only": "0"})
    assert r.status_code == 200 and b"Consent expired" in r.data


def test_wizard_detect_token_is_one_shot():
    c = _client()
    _r, token = _consent_token(c, "oai", "https://api.openai.com/v1")
    from provenance_probe import detect
    # First use consumes the token; stub detect so no network is hit.
    import pytest as _pt
    _mp = _pt.MonkeyPatch()
    _mp.setattr(detect, "detect", lambda *a, **k: detect.Detection(
        base_url="https://api.openai.com/v1", api_style="openai", ok=True,
        chat_path="/chat/completions", model="gpt-4o-mini", confidence="high",
        caveat="usage is self-reported"))
    try:
        first = c.post("/wizard/detect", data={"token": token})
        assert first.status_code == 200 and b"Consent expired" not in first.data
        second = c.post("/wizard/detect", data={"token": token})   # reused
        assert b"Consent expired" in second.data
    finally:
        _mp.undo()


def test_wizard_detect_builds_openai_target(monkeypatch):
    # Assert the preview carries the detected api_style and NO api-key value.
    from provenance_probe import detect
    fake = detect.Detection(ok=True, api_style="openai", base_url="https://api.deepseek.com",
                            chat_path="/chat/completions", model="deepseek-chat",
                            confidence="high", llm_positive=True, probes_used=3,
                            caveat="usage is self-reported")
    monkeypatch.setattr(detect, "detect", lambda *a, **k: fake)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-secret-should-not-leak")
    c = _client()
    _r, token = _consent_token(c, "ds", "https://api.deepseek.com")
    r = c.post("/wizard/detect", data={"token": token})
    assert r.status_code == 200
    # JSON is html-escaped inside the editable textarea, so match the fields loosely.
    assert b"api_style" in r.data and b"openai" in r.data
    assert b"DEEPSEEK_API_KEY" in r.data            # the NAME is shown
    assert b"sk-secret-should-not-leak" not in r.data   # the VALUE never is
    assert b"self-reported" in r.data                   # forged-usage caveat surfaced


def test_wizard_detect_html_routes_to_capture(monkeypatch):
    from provenance_probe import detect
    fake = detect.Detection(base_url="https://chat.app.com", route_hint="capture",
                            error="this looks like a web app (HTML), not an API")
    monkeypatch.setattr(detect, "detect", lambda *a, **k: fake)
    c = _client()
    _r, token = _consent_token(c, "wa", "https://chat.app.com")
    r = c.post("/wizard/detect", data={"token": token})
    assert r.status_code == 200 and b"web app" in r.data


def test_wizard_parse_error_does_not_leak_cookie():
    # a malformed cURL (no URL) that still carries a cookie must not be echoed back
    bad = "curl -X POST -H 'cookie: sid=LEAKME2' -H 'accept: */*'"
    r = _client().post("/wizard", data={"name": "x", "prompt": "hi", "fmt": "curl", "capture": bad})
    assert r.status_code == 200 and b"Could not parse capture" in r.data
    assert b"LEAKME2" not in r.data          # capture (with cookie) not reflected into error HTML


def test_write_target_output_is_loadable_after_unknown_keys_stripped(tmp_path):
    from provenance_probe import config
    cfg = tmp_path / "targets.json"
    target = {"name": "wz", "base_url": "https://x.ai", "api_style": "template",
              "chat_path": "/c", "bogus_field": 1, "another_typo": "z"}   # unknown keys
    wizard.write_target(target, "", config_path=str(cfg),
                        env_path=str(tmp_path / ".env"), repo_root=str(tmp_path))
    loaded = config.load_targets(str(cfg))          # must NOT raise on unknown kwargs
    assert loaded[0].name == "wz" and loaded[0].api_style == "template"


def test_wizard_curl_preview_offers_autodetect_button():
    # A cURL paste (no response) should surface the one-request auto-detect.
    r = _client().post("/wizard", data={"name": "demo", "prompt": "fingerprint me",
                                        "capture": _CURL})
    assert r.status_code == 200
    assert b"/wizard/probe-response" in r.data and b"Auto-detect response fields" in r.data


def test_wizard_probe_response_fills_paths(monkeypatch):
    import re as _re
    from provenance_probe import wizard as _wz
    c = _client()
    prev = c.post("/wizard", data={"name": "demo", "prompt": "fingerprint me", "capture": _CURL})
    token = _re.search(rb'name=token value="([0-9a-f]+)"', prev.data).group(1).decode()
    # Stub the live replay so no network is touched; return discovered paths.
    monkeypatch.setattr(_wz, "discover_response_paths", lambda *a, **k: {
        "ok": True, "stream_mode": "none", "sample": "hello from the model",
        "paths": {"response_text_path": "choices.0.message.content",
                  "response_prompt_tokens_path": "usage.prompt_tokens",
                  "response_model_path": "model"}, "error": None})
    # base_url must match the captured origin (chat.example.com) or the cookie
    # replay is refused by origin-binding.
    target = json.dumps({"name": "demo", "base_url": "https://chat.example.com", "api_style": "template",
                         "chat_path": "/api/chat", "request_template": {"m": "__PROMPT__"},
                         "response_text_path": ""})
    r = c.post("/wizard/probe-response", data={"token": token, "target": target})
    assert r.status_code == 200
    assert b"Auto-detected from a live response" in r.data
    assert b"choices.0.message.content" in r.data      # path now filled in the preview
    assert b"usage.prompt_tokens" in r.data


def test_wizard_probe_response_refuses_cross_origin(monkeypatch):
    # HIGH (Codex): the captured cookie must NOT be replayed to an edited host.
    from provenance_probe import wizard as _wz
    import re as _re
    c = _client()
    prev = c.post("/wizard", data={"name": "demo", "prompt": "hi", "capture": _CURL})
    token = _re.search(rb'name=token value="([0-9a-f]+)"', prev.data).group(1).decode()
    sent = {"called": False}
    monkeypatch.setattr(_wz, "discover_response_paths",
                        lambda *a, **k: sent.update(called=True) or {"ok": True, "paths": {},
                        "stream_mode": "none", "error": None})
    # _CURL captures chat.example.com; point base_url at an attacker host.
    target = json.dumps({"name": "demo", "base_url": "https://evil.example", "api_style": "template",
                         "request_template": {"m": "__PROMPT__"}, "response_text_path": ""})
    r = c.post("/wizard/probe-response", data={"token": token, "target": target})
    assert r.status_code == 200 and b"Refusing to auto-detect" in r.data
    assert sent["called"] is False          # NO request was sent to the edited host


def test_wizard_probe_response_refuses_chat_path_host_smuggle(monkeypatch):
    # CRITICAL (Claude): base_url passes the origin check but chat_path smuggles a
    # host (base_url@evil.com). The effective-host check must catch it.
    from provenance_probe import wizard as _wz
    import re as _re
    c = _client()
    prev = c.post("/wizard", data={"name": "demo", "prompt": "hi", "capture": _CURL})
    token = _re.search(rb'name=token value="([0-9a-f]+)"', prev.data).group(1).decode()
    sent = {"called": False}
    monkeypatch.setattr(_wz, "discover_response_paths",
                        lambda *a, **k: sent.update(called=True) or {"ok": True, "paths": {},
                        "stream_mode": "none", "error": None})
    target = json.dumps({"name": "demo", "base_url": "https://chat.example.com",
                         "chat_path": "@evil.com/v1/chat", "api_style": "template",
                         "request_template": {"m": "__PROMPT__"}, "response_text_path": ""})
    r = c.post("/wizard/probe-response", data={"token": token, "target": target})
    assert b"Refusing to auto-detect" in r.data and sent["called"] is False


def test_wizard_save_refuses_cross_origin_cookie(monkeypatch):
    # CRITICAL (Claude): save runs a dry-run with the cookie — it must apply the
    # same origin binding, or an edited host exfiltrates the cookie.
    from provenance_probe import wizard as _wz
    import re as _re
    c = _client()
    prev = c.post("/wizard", data={"name": "demo", "prompt": "hi", "capture": _CURL})
    token = _re.search(rb'name=token value="([0-9a-f]+)"', prev.data).group(1).decode()
    ran = {"dry": False}
    monkeypatch.setattr(_wz, "dry_run", lambda *a, **k: ran.update(dry=True) or {"ok": True})
    target = json.dumps({"name": "demo", "base_url": "https://evil.example", "api_style": "template",
                         "request_template": {"m": "__PROMPT__"}, "response_text_path": "x"})
    r = c.post("/wizard/save", data={"token": token, "target": target})
    assert b"Refusing to save" in r.data and ran["dry"] is False


def test_wizard_probe_response_failure_falls_back(monkeypatch):
    import re as _re
    from provenance_probe import wizard as _wz
    c = _client()
    prev = c.post("/wizard", data={"name": "demo", "prompt": "hi", "capture": _CURL})
    token = _re.search(rb'name=token value="([0-9a-f]+)"', prev.data).group(1).decode()
    monkeypatch.setattr(_wz, "discover_response_paths", lambda *a, **k: {
        "ok": False, "paths": {}, "stream_mode": "none",
        "error": "the request returned HTTP 403 — the capture may be stale"})
    r = c.post("/wizard/probe-response",
               data={"token": token, "target": json.dumps(
                   {"api_style": "template", "base_url": "https://chat.example.com"})})
    assert r.status_code == 200 and b"Auto-detect failed" in r.data and b"403" in r.data


def test_wizard_save_expired_token():
    r = _client().post("/wizard/save", data={"token": "nope", "target": "{}"})
    assert r.status_code == 200 and b"expired" in r.data


def test_wizard_save_rejects_bad_json_with_valid_token():
    import re as _re
    c = _client()
    prev = c.post("/wizard", data={"name": "demo", "prompt": "fingerprint me",
                                   "fmt": "curl", "capture": _CURL})
    token = _re.search(rb'name=token value="([0-9a-f]+)"', prev.data).group(1).decode()
    r = c.post("/wizard/save", data={"token": token, "target": "{not json"})
    # invalid-JSON message reworded in the UX pass (#79): "…isn't valid JSON — check
    # for a missing quote, comma, or brace." Assert the stable, distinctive phrase.
    assert r.status_code == 200 and b"check for a missing quote" in r.data
