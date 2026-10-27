"""Add-a-target wizard: parse a captured web-app request and synthesize a
`template` Target config for probing.

Paste-first v1 (design 2026-07-26): the operator captures ONE real chat request
in their own browser (DevTools -> Copy-as-cURL, or Save HAR) and pastes it; this
module parses it and synthesizes a `template`-adapter target + a dry-run-ready
spec. No browser automation, no network. Playwright auto-capture is a P2 add-on
that would feed the same `synthesize()`.

SECURITY (design D3): the session cookie is a credential. `synthesize()` returns
the committable config and the cookie VALUE as SEPARATE fields. The cookie value
is NEVER placed in the returned `target` dict — the config carries only
`cookie_env` (a name). The caller writes the value to a gitignored env file.

Synthesis is best-effort and every guessed field is returned for the operator to
confirm/edit — never trusted silently (design: response-path synthesis is
inherently brittle).
"""
from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import monitor

# Body keys that carry per-conversation state. Replaying a captured request 20x
# (the tokenizer battery) with a frozen conversation/message id can fail or
# append to the operator's real chat, so we blank them and warn (design: replay
# safety is P1). Matched case-insensitively as whole-ish tokens.
_STATEFUL_KEY_RE = re.compile(
    r"(conversation|thread|message|parent|session|request|idempotenc|nonce|trace|chat)"
    r".*(id|key|token)$|^(id|nonce|timestamp|ts)$",
    re.IGNORECASE,
)

# Request headers worth carrying to make replay work (CSRF / origin / tenant).
# Cookie is handled separately (-> cookie_env); hop-by-hop / volatile are dropped.
_KEEP_HEADER_RE = re.compile(
    r"^(x-csrf|x-xsrf|csrf|origin|referer|x-request|x-tenant|x-org|"
    r"x-client|anthropic-version|openai-|x-api|x-requested-with)",
    re.IGNORECASE,
)
_DROP_HEADERS = {
    "host", "content-length", "connection", "accept-encoding", "cookie",
    "authorization",  # captured separately if present; never auto-committed
}
# Header values that look dynamic/rotating -> replay may break; flag them.
_DYNAMIC_HEADER_RE = re.compile(r"^(x-csrf|x-xsrf|csrf|x-request|nonce)", re.IGNORECASE)

_USAGE_KEY_RE = re.compile(r"(prompt_tokens|input_tokens|prompt_token_count)$", re.IGNORECASE)
_MODEL_VALUE_RE = re.compile(r"^[\w.:-]+$")  # a model-id-looking scalar


@dataclass
class Captured:
    """One captured chat request (+ its response, if a HAR provided it)."""
    url: str
    method: str = "POST"
    headers: dict = field(default_factory=dict)
    body: str = ""                      # raw request body text
    cookie: str = ""                    # raw Cookie header value (credential)
    response: object = None             # parsed response JSON, if available
    content_type: str = ""              # response content-type (for SSE detect)
    stream_delta_path: str = ""         # per-chunk SSE delta path, if pre-detected
                                        # (proxy capture fills this; HAR/cURL leave "")


@dataclass
class Synthesis:
    """Result of synthesize(): a committable target + the cookie held apart."""
    target: dict                        # committable config (NO cookie value)
    cookie_value: str                   # the credential — caller stores in env, never commits
    cookie_env: str                     # env var name the config references
    warnings: list                      # operator-facing caveats (each a string)
    fields_to_confirm: list             # synthesized fields the operator should verify


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #

def parse_curl(text: str) -> Captured:
    """Parse a `curl '...'` command (DevTools 'Copy as cURL').

    Handles -X/--request, -H/--header, --data/--data-raw/--data-binary/-d,
    -b/--cookie, and the URL as the lone bare argument.
    """
    text = text.strip()
    if not text:
        raise ValueError("empty cURL input")
    # Normalize line-continuations, then shell-tokenize so quotes are honored.
    text = re.sub(r"\\\r?\n", " ", text)
    try:
        toks = shlex.split(text)
    except ValueError as e:
        raise ValueError(f"could not parse cURL (unbalanced quotes?): {e}") from e
    if toks and toks[0] == "curl":
        toks = toks[1:]

    url, method, body, cookie = "", "", "", ""
    headers: dict = {}
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in ("-X", "--request") and i + 1 < len(toks):
            method = toks[i + 1]; i += 2; continue
        if t in ("-H", "--header") and i + 1 < len(toks):
            k, _, v = toks[i + 1].partition(":")
            k, v = k.strip(), v.strip()
            if k.lower() == "cookie":
                cookie = v
            elif k:
                headers[k] = v
            i += 2; continue
        if t in ("-b", "--cookie") and i + 1 < len(toks):
            cookie = toks[i + 1]; i += 2; continue
        if t in ("--data", "--data-raw", "--data-binary", "--data-ascii", "-d") and i + 1 < len(toks):
            body = toks[i + 1]; i += 2; continue
        if t.startswith("http://") or t.startswith("https://"):
            url = t; i += 1; continue
        i += 1

    if not url:
        raise ValueError("no URL found in cURL input")
    if not method:
        method = "POST" if body else "GET"
    return Captured(url=url, method=method, headers=headers, body=body, cookie=cookie)


_CHATISH_URL_RE = re.compile(r"chat|complet|message|conversation|generate|ask", re.IGNORECASE)


def score_chat_request(method: str, body: str, url: str, prompt_hint: str = "") -> tuple:
    """Rank an HTTP request as a likely chat/completion call; higher tuple sorts
    first. Shared by parse_har (HAR entries) and capture_proxy (proxy flows) so
    there is ONE definition of "which request is the model call" (design #44)."""
    body = body or ""
    has_prompt = bool(prompt_hint) and prompt_hint in body
    is_post_with_body = (method or "").upper() == "POST" and bool(body)
    looks_chat = bool(_CHATISH_URL_RE.search(url or ""))
    return (has_prompt, is_post_with_body, looks_chat, len(body))


def parse_har(text: str, prompt_hint: str = "") -> Captured:
    """Parse a HAR export and pick the best chat-request entry.

    Preference: a POST whose request body contains `prompt_hint` (the message
    the operator sent); else a POST with a JSON body to a chat-ish path; else
    the first POST with a body. HAR uniquely also carries the RESPONSE body,
    which lets synthesize() locate the reply/usage/model paths.
    """
    try:
        har = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"not valid HAR JSON: {e}") from e
    if not isinstance(har, dict):
        raise ValueError("HAR root is not an object")
    entries = (((har.get("log") or {}) if isinstance(har.get("log"), dict) else {}).get("entries")) or []
    entries = [e for e in entries if isinstance(e, dict)]
    if not entries:
        raise ValueError("HAR has no usable entries")

    def _score(entry) -> tuple:
        req = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        return score_chat_request(req.get("method") or "",
                                  ((req.get("postData") or {}).get("text")) or "",
                                  req.get("url") or "", prompt_hint)

    entry = max(entries, key=_score)
    req = entry.get("request") or {}
    if (req.get("method") or "").upper() != "POST":
        raise ValueError("no POST chat request found in HAR (websocket/GET app?)")
    headers, cookie = {}, ""
    for h in req.get("headers") or []:
        if not isinstance(h, dict):
            continue
        name, val = h.get("name", ""), h.get("value", "")
        if name.lower() == "cookie":
            cookie = val
        elif name and not name.startswith(":"):   # skip HTTP/2 pseudo-headers
            headers[name] = val
    resp = entry.get("response") or {}
    resp_text = ((resp.get("content") or {}).get("text")) or ""
    resp_ct = ""
    for h in resp.get("headers") or []:
        if isinstance(h, dict) and h.get("name", "").lower() == "content-type":
            resp_ct = h.get("value", "")
    resp_json = None
    try:
        resp_json = json.loads(resp_text) if resp_text else None
    except json.JSONDecodeError:
        resp_json = None   # streamed/SSE or non-JSON; handled downstream
    return Captured(
        url=req.get("url", ""), method="POST", headers=headers,
        body=((req.get("postData") or {}).get("text")) or "",
        cookie=cookie, response=resp_json, content_type=resp_ct,
    )


# --------------------------------------------------------------------------- #
# Dotted-path search (for response field synthesis)
# --------------------------------------------------------------------------- #

def _walk(obj, prefix=""):
    """Yield (dotted_path, value) for every scalar-bearing node."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for idx, v in enumerate(obj):
            yield from _walk(v, f"{prefix}.{idx}" if prefix else str(idx))
    else:
        yield prefix, obj


def find_text_path(resp, reply_text: str) -> str | None:
    """Path whose string value equals (or contains) the assistant reply."""
    if resp is None or not reply_text:
        return None
    norm = " ".join(reply_text.split())
    best = None
    for path, val in _walk(resp):
        if isinstance(val, str) and val.strip():
            v = " ".join(val.split())
            if v == norm:
                return path
            if norm and (norm in v or v in norm) and len(v) >= 8:
                best = best or path
    return best


def find_usage_path(resp) -> str | None:
    for path, val in _walk(resp or {}):
        leaf = path.rsplit(".", 1)[-1]
        if isinstance(val, int) and _USAGE_KEY_RE.search(leaf):
            return path
    return None


def find_model_path(resp) -> str | None:
    for path, val in _walk(resp or {}):
        leaf = path.rsplit(".", 1)[-1]
        if leaf.lower() == "model" and isinstance(val, str) and _MODEL_VALUE_RE.match(val):
            return path
    return None


# Well-known reply locations, tried before the longest-string heuristic so a
# standard openai/anthropic shape is nailed exactly (not guessed).
_STD_TEXT_PATHS = ("choices.0.message.content", "choices.0.text", "content.0.text",
                   "message.content", "delta.content", "response", "reply", "answer",
                   "output_text", "text")


# Leaf names the longest-string fallback must NOT point at: credential-ish or
# request-echo fields. Prevents auto-selecting a reflected cookie/key or the
# echoed prompt as the "reply" path (Codex adversarial).
_REPLY_SKIP_LEAF = re.compile(
    r"(cookie|authorization|token|api[-_]?key|secret|password|prompt|input|"
    r"system|request|messages?|session|sid|csrf|xsrf|jwt|bearer|cred)", re.IGNORECASE)


def find_reply_path(resp, *, skip_values=()) -> str | None:
    """Path to the assistant's reply in a REAL response. Tries known shapes, then
    falls back to the longest non-trivial string value (the reply is almost always
    the longest string), EXCLUDING credential/echo fields and any request echo.
    Used to auto-detect response paths from a live replay so the operator never
    hand-types them."""
    from .client import dig
    for p in _STD_TEXT_PATHS:
        v = dig(resp, p)
        if isinstance(v, str) and v.strip():
            return p
    skip = {s.strip() for s in skip_values if s}
    best, best_len = None, 7          # require >= 8 chars to skip ids/short flags
    for path, val in _walk(resp or {}):
        if not isinstance(val, str):
            continue
        v = val.strip()
        if _REPLY_SKIP_LEAF.search(path.rsplit(".", 1)[-1]):   # not a credential/echo field
            continue
        if v in skip:                                          # not the echoed prompt
            continue
        if len(v) > best_len:
            best, best_len = path, len(v)
    return best


def discover_response_paths(client, prompt_text: str, *, max_tokens: int = 24) -> dict:
    """Replay the captured request ONCE and read the response paths off the real
    reply — the automation that removes hand-typed `response_*_path` guesswork on
    the cURL-paste flow (a HAR gets these for free; this gets them from one live
    call). Returns {ok, paths, stream_mode, sample, error}.

    `client` is a Client for the synthesized target. This performs ONE network
    request, so the caller must have the operator's consent (it names the host).
    """
    r = client.chat(prompt_text or "fingerprint me", max_tokens=max_tokens, temperature=0.0)
    if not r.ok:
        return {"ok": False, "paths": {}, "stream_mode": "none",
                "error": f"the request returned HTTP {r.status or '—'}"
                         f"{' ('+r.err+')' if r.err else ''} — the capture may be stale "
                         f"(cookie expired) or need another header; re-capture and retry."}
    # SSE? The client accumulates stream deltas into stream_text; the body is raw.
    ctype = (r.headers.get("content-type") or "").lower()
    if "text/event-stream" in ctype or (r.stream_text is not None and not isinstance(r.body, (dict, list))):
        return {"ok": True, "stream_mode": "sse",
                "paths": {"response_text_path": "", "response_prompt_tokens_path": "",
                          "response_model_path": "",
                          "stream_delta_path": "choices.0.delta.content"},
                "sample": (r.text() or "")[:160],
                "error": None}
    body = r.body
    if not isinstance(body, (dict, list)):
        return {"ok": False, "paths": {}, "stream_mode": "none",
                "error": "the response was not JSON — this app may stream or use a "
                         "non-JSON protocol; paste a HAR or set the paths by hand."}
    paths = {
        "response_text_path": find_reply_path(body, skip_values=(prompt_text,)) or "",
        "response_prompt_tokens_path": find_usage_path(body) or "",
        "response_model_path": find_model_path(body) or "",
    }
    return {"ok": True, "paths": paths, "stream_mode": "none",
            "sample": (r.text() or "")[:160], "error": None}


# --------------------------------------------------------------------------- #
# Synthesis
# --------------------------------------------------------------------------- #

def _templatize(node, prompt_text, warnings):
    """Deep-copy the request body, swapping the prompt + stripping stateful ids."""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            # A key like `chatModelId` matches the stateful pattern but selects
            # WHICH model the backend calls — blanking it would probe the wrong
            # model, corrupting the exact signal we measure (review #44). Never
            # blank a model-selector field.
            if _STATEFUL_KEY_RE.search(k) and "model" not in k.lower():
                warnings.append(f"blanked stateful field '{k}' (replay-safety); "
                                f"confirm the app accepts a fresh/empty value")
                out[k] = ""
            else:
                out[k] = _templatize(v, prompt_text, warnings)
        return out
    if isinstance(node, list):
        return [_templatize(v, prompt_text, warnings) for v in node]
    if isinstance(node, str) and prompt_text and node == prompt_text:
        return "__PROMPT__"
    if isinstance(node, str) and prompt_text and prompt_text in node:
        return node.replace(prompt_text, "__PROMPT__")
    return node


def synthesize(cap: Captured, prompt_text: str, name: str) -> Synthesis:
    """Turn a Captured request into a committable `template` target + held cookie."""
    warnings: list = []
    confirm: list = []
    parts = urlsplit(cap.url)
    base_url = f"{parts.scheme}://{parts.netloc}"
    chat_path = parts.path or "/"

    body_json = None
    if cap.body:
        try:
            body_json = json.loads(cap.body)
        except json.JSONDecodeError:
            warnings.append("request body is not JSON — the template adapter needs "
                            "a JSON body; this app may be unsupported (form/multipart/ws).")
    request_template = _templatize(body_json, prompt_text, warnings) if body_json is not None else {}
    if body_json is not None and json.dumps(request_template) == json.dumps(body_json):
        warnings.append("could not locate the prompt text in the request body — "
                        "set the __PROMPT__ placeholder by hand.")
    confirm.append("request_template")

    # Response field paths (only when a HAR gave us the response body).
    # Locate the reply path with the echo-safe detector. In the proxy/live flow
    # `prompt_text` is the message the OPERATOR sent, and many chat apps echo the
    # user's turn back in the response — matching on it would pick the echoed
    # prompt as the "reply" (review #44). find_reply_path tries the standard
    # shapes, then the longest non-echo string, excluding the sent prompt.
    resp_text_path = ""
    if cap.response is not None:
        resp_text_path = find_reply_path(cap.response, skip_values=(prompt_text,)) or ""
    usage_path = find_usage_path(cap.response) if cap.response else ""
    model_path = find_model_path(cap.response) if cap.response else ""
    _ctl = (cap.content_type or "").lower()
    _is_stream = "event-stream" in _ctl or "ndjson" in _ctl
    if cap.response is None and not _is_stream:
        warnings.append("no JSON response body captured — set response_text_path / "
                        "response_prompt_tokens_path by hand, or paste a HAR so they "
                        "can be synthesized.")
    if cap.response is not None and not usage_path:
        warnings.append("no prompt-token usage found in the response — the tokenizer "
                        "fingerprint will be UNAVAILABLE; provenance floors at "
                        "INDETERMINATE (wire/behavioral only).")
    for f in ("response_text_path", "response_prompt_tokens_path", "response_model_path"):
        confirm.append(f)

    ctl = (cap.content_type or "").lower()
    if "text/event-stream" in ctl:
        stream_mode = "sse"
    elif "ndjson" in ctl:                     # newline-delimited JSON stream (e.g. v0.app)
        stream_mode = "jsonlines"
    else:
        stream_mode = "none"
    stream_delta_path = cap.stream_delta_path if stream_mode in ("sse", "jsonlines") else ""
    if stream_mode == "sse" and not stream_delta_path:
        warnings.append("response is SSE — set stream_delta_path to the per-chunk "
                        "delta; the shipped parser handles `data:` JSON chunks only.")
    elif stream_mode == "jsonlines" and not stream_delta_path:
        warnings.append("response is a streamed JSON-lines / custom format — the per-chunk "
                        "delta path could not be auto-located; set stream_delta_path by hand "
                        "(or use --paste).")

    extra_headers = {}
    for k, v in (cap.headers or {}).items():
        if k.lower() in _DROP_HEADERS:
            continue
        if _KEEP_HEADER_RE.match(k):
            extra_headers[k] = v
            if _DYNAMIC_HEADER_RE.match(k):
                warnings.append(f"header '{k}' looks dynamic/rotating — replay may "
                                f"fail when it expires; re-capture if probes 401.")

    cookie_env = re.sub(r"[^A-Z0-9]", "_", (name or "target").upper()) + "_COOKIE"
    if not cap.cookie:
        warnings.append("no Cookie captured — if the app is authenticated the probe "
                        "will fail; re-capture a logged-in request.")

    target = {
        "name": name,
        "base_url": base_url,
        "chat_path": chat_path,
        "api_style": "template",
        "request_template": request_template,
        "response_text_path": resp_text_path or "",
        "response_prompt_tokens_path": usage_path or "",
        "response_model_path": model_path or "",
        "stream_mode": stream_mode,
        "stream_delta_path": stream_delta_path,
        "cookie_env": cookie_env,          # NAME only — never the value
        "extra_headers": extra_headers,
        "authorized": False,               # design: never auto-authorize probing
    }
    return Synthesis(target=target, cookie_value=cap.cookie, cookie_env=cookie_env,
                     warnings=warnings, fields_to_confirm=confirm)


# --------------------------------------------------------------------------- #
# Dry-run (replay safety) — validate before saving
# --------------------------------------------------------------------------- #

def _live_grade(reason: str, live) -> dict:
    """Verdict for a replay that did not work. ``live`` may carry fresh
    tokenizer/wire bundles; it is never the captured request."""
    base = cur = None
    self_id = False
    if isinstance(live, dict):
        base, cur = live.get("baseline"), live.get("current")
        self_id = bool(live.get("self_id_changed"))
    return monitor.grade_unreplayable(base, cur, reason=reason, self_id_changed=self_id)


def dry_run(client, probes=None, *, live=None) -> dict:
    """Send >=2 probes through the synthesized target and check replay safety.

    Design (P1): the tokenizer battery replays ~20 messages; if the captured
    request carried conversation state we blanked, replay may still 401 or
    append to the operator's real chat. Two independent probes surface that
    BEFORE save: both must return a reply and reported prompt-token usage that
    is stable (a stateful backend typically errors or drifts the count wildly).

    When the replay is rejected or unstable, the result includes ``verdict``
    from ``monitor.grade_unreplayable``. That verdict does not pretend the
    captured request was re-driven. Optional ``live`` bundles are a fresh
    tokenizer battery and wire fingerprint, not another replay.

    `client` is a provenance_probe.client.Client for the synthesized Target.
    Returns {ok, usage_exposed, replay_safe, prompt_tokens, error} and, when
    replay was impossible, ``verdict``.
    """
    probes = probes or ["Say hi.", "Reply with the word ok."]
    seen, got_reply = [], 0
    for text in probes[:2]:
        r = client.chat(text, max_tokens=1, temperature=0.0)
        if not r.ok:                       # Response.ok is a property, not a method
            return {"ok": False, "usage_exposed": False, "replay_safe": False,
                    "prompt_tokens": None,
                    "error": f"probe returned HTTP {r.status} — capture may be stale "
                             f"(cookie expired / stateful request); re-capture.",
                    "verdict": _live_grade("signed-or-stateful", live)}
        if (r.text() or "").strip():
            got_reply += 1
        seen.append(r.usage_prompt_tokens())
    if got_reply == 0:
        return {"ok": False, "usage_exposed": False, "replay_safe": False,
                "prompt_tokens": None,
                "error": "endpoint returned no reply text on either probe — the "
                         "response paths are likely wrong, or the app didn't answer; "
                         "re-check response_text_path / re-capture."}
    usable = [n for n in seen if n is not None]
    usage_exposed = len(usable) == len(seen) and bool(usable)
    # Replay-safety: both probes must have replied independently. If usage is
    # exposed, the two one-token prompts should give close counts (a wild swing =
    # stateful/append). Usage-suppressed-but-both-replied is DEGRADED yet stateless
    # -> still safe to save. Inconsistent exposure (one count, one not) = unsafe.
    if got_reply < 2:
        replay_safe = False
    elif len(usable) == 2:
        replay_safe = max(usable) - min(usable) <= 3
    elif len(usable) == 0:
        replay_safe = True
    else:
        replay_safe = False
    out = {"ok": True, "usage_exposed": usage_exposed, "replay_safe": replay_safe,
           "prompt_tokens": usable, "error": None}
    if not replay_safe:
        out["verdict"] = _live_grade("stateful", live)
    return out


# --------------------------------------------------------------------------- #
# Save — committable config + gitignored cookie (never committed)
# --------------------------------------------------------------------------- #

def _open_nofollow(path: str, flags: int, mode: int = 0o600):
    """os.open with O_NOFOLLOW so a pre-planted symlink at `path` can't redirect a
    write (a captured session cookie, most importantly) to an attacker-chosen file
    on a shared/predictable dir (CWE-59, security sign-off #44). Fails loudly."""
    import os
    import errno
    try:
        return os.open(path, flags | os.O_NOFOLLOW, mode)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK):
            raise ValueError(f"refusing to open '{path}' — it is a symlink (possible "
                             f"credential-redirect attack); remove it and retry.") from e
        raise


def ensure_gitignored(repo_root: str, rel_path: str) -> None:
    """Guarantee `rel_path` is in the repo's .gitignore (design: no-footgun)."""
    import os
    gi = os.path.join(repo_root, ".gitignore")
    lines = []
    if os.path.exists(gi):
        with os.fdopen(_open_nofollow(gi, os.O_RDONLY), "r") as f:
            lines = f.read().splitlines()
    if rel_path not in lines:
        with os.fdopen(_open_nofollow(gi, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644), "a") as f:
            if lines and lines[-1].strip():
                f.write("\n")
            f.write(f"# add-target wizard: captured session credentials — never commit\n{rel_path}\n")


# Header names that carry credentials and must NEVER be written to the committed
# config, no matter what the (possibly hand-edited/injected) target says. Matched
# by SUBSTRING on the name so a smuggled variant like `X-Api-Key-Alt` or
# `X-Session-Token` is caught too, not only exact names (Codex adversarial, HIGH).
# The token/value itself rides an env var (auth_value_env / cookie_env), never a
# committed header, so aggressive stripping here has no legitimate false-positive.
# NB: match credential TOKENs (auth/access/session/api/refresh/bearer token) but
# NOT `x-csrf-token` — the wizard intentionally KEEPS CSRF headers for replay, and
# a CSRF token is not a long-lived credential. So `token` is only matched with a
# credential-ish prefix, never bare.
_SECRET_HEADER_RE = re.compile(
    r"(cookie|authorization|api[-_]?key|access[-_]?key|secret|bearer|"
    r"(auth|access|session|api|refresh|bearer)[-_]?token|"
    r"x-[a-z0-9]+[-_]key|"                       # vendor key headers: x-anthropic-key, x-openai-key
    r"vault|security[-_]?token|"                 # x-vault-token, x-amz-security-token
    r"x-auth|x-goog-api-key|password|passwd|credential)",
    re.IGNORECASE,
)


def sanitize_target(target: dict) -> tuple[dict, list]:
    """Strip credential-bearing fields from a target before it is committed.

    Runs at the write boundary so a hand-edited or injected target dict can't
    smuggle a `cookie` value or a Cookie/Authorization header into the config
    (design D3 + Codex). Returns (clean_copy, removed_field_names).
    """
    from dataclasses import fields
    from .config import Target
    clean = dict(target)
    removed = []
    if clean.pop("cookie", None):
        removed.append("cookie")
    eh = clean.get("extra_headers")
    if isinstance(eh, dict):
        kept = {}
        for k, v in eh.items():
            if _SECRET_HEADER_RE.search(str(k).strip()):   # substring, not anchored
                removed.append(f"extra_headers.{k}")
            else:
                kept[k] = v
        clean["extra_headers"] = kept
    # Drop any key that isn't a real Target field, so a hand-edited target can't
    # produce a config that config.load_targets (Target(**t)) chokes on (Codex).
    allowed = {f.name for f in fields(Target)}
    for k in [k for k in clean if k not in allowed]:
        clean.pop(k)
        removed.append(f"unknown:{k}")
    return clean, removed


def _is_git_tracked(path: str) -> bool:
    import subprocess
    try:
        r = subprocess.run(["git", "ls-files", "--error-unmatch", path],
                           capture_output=True, cwd=os.path.dirname(path) or ".", timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def write_target(target: dict, cookie_value: str, *, config_path: str,
                 env_path: str, repo_root: str) -> dict:
    """Append the target to a JSON config (no-clobber on name) and write the
    cookie to a gitignored env file. The cookie NEVER enters `config_path`.

    The config is written as a JSON LIST (the shape `config.load_targets`
    consumes). The target is sanitized first so no credential can reach the
    committed file even if the caller edited it. Returns a summary dict.
    """
    import os
    clean, removed = sanitize_target(target)
    name = clean.get("name") or "target"
    # config.load_targets accepts a JSON list (or a lone dict = one target).
    existing = []
    if os.path.exists(config_path):
        with os.fdopen(_open_nofollow(config_path, os.O_RDONLY), "r") as f:
            loaded = json.load(f)
        existing = loaded if isinstance(loaded, list) else [loaded]
    if any(isinstance(t, dict) and t.get("name") == name for t in existing):
        raise ValueError(f"a target named '{name}' already exists in {config_path}; "
                         f"choose a distinct name (no clobber).")
    existing.append(clean)
    os.makedirs(os.path.dirname(config_path) or ".", exist_ok=True)
    with os.fdopen(_open_nofollow(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644), "w") as f:
        json.dump(existing, f, indent=2)

    warnings = []
    if removed:
        warnings.append(f"stripped credential field(s) from the saved config: "
                        f"{', '.join(removed)} (kept out of git).")
    # cookie -> gitignored env file (KEY=VALUE), and make sure it's ignored.
    cookie_env = clean.get("cookie_env") or "TARGET_COOKIE"
    if cookie_value:
        env_rel = os.path.relpath(env_path, repo_root) if repo_root else os.path.basename(env_path)
        ensure_gitignored(repo_root or os.path.dirname(env_path), env_rel)
        if _is_git_tracked(env_path):
            warnings.append(f"WARNING: {env_rel} is already git-tracked — the .gitignore "
                            f"line won't help; run `git rm --cached {env_rel}` or the cookie "
                            f"WILL be committed.")
        prior = ""
        if os.path.exists(env_path):
            with os.fdopen(_open_nofollow(env_path, os.O_RDONLY), "r") as f:
                prior = "".join(l for l in f if not l.startswith(f"{cookie_env}="))
        # The env file holds the raw session cookie — create it OWNER-ONLY (0600)
        # from the start (no world-readable window), AND O_NOFOLLOW so a pre-planted
        # symlink can't redirect the cookie to an attacker's file (CWE-59, #44).
        fd = _open_nofollow(env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), 0o600)         # on the OPEN fd (no path re-follow, tightens a pre-existing file)
            f.write(prior)
            if prior and not prior.endswith("\n"):
                f.write("\n")
            f.write(f"{cookie_env}={cookie_value}\n")
    return {"config_path": config_path, "env_path": env_path if cookie_value else None,
            "cookie_env": cookie_env, "added": name, "warnings": warnings}
