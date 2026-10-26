"""E8: adversarial red-team corpus — detect a model-identity switch under stress."""
from provenance_probe import redteam


class _Resp:
    def __init__(self, model, content, status=200):
        self._model, self._content, self.status = model, content, status
    def echoed_model(self):
        return self._model
    def text(self):
        return self._content
    def ok(self):
        return 200 <= self.status < 300


class _Client:
    """Returns a scripted (model, content) per call; can swap identity after N."""
    def __init__(self, script):
        self.script = list(script)
        self.i = -1

    def chat(self, prompt, **kw):
        self.i += 1
        return _Resp(*self.script[min(self.i, len(self.script) - 1)])


def test_stable_identity_no_switch():
    c = _Client([("gpt-4o", "I am ChatGPT by OpenAI.")] * 8)
    out = redteam.run(c, cap=8)
    assert out["switch_detected"] is False
    assert out["scenarios_run"] == 8
    assert "stable" in out["note"]


def test_switch_under_stress_detected():
    # stable for 2, then the backend swaps to glm-4 (a cheaper fallback under load)
    script = [("gpt-4o", "I am ChatGPT.")] * 2 + [("glm-4", "Actually I'm GLM.")] * 6
    out = redteam.run(_Client(script), cap=8)
    assert out["switch_detected"] is True
    hops = {(s["signal"], s["from"], s["to"]) for s in out["switches"]}
    assert ("model_id", "gpt-4o", "glm-4") in hops
    # echoed id is not a tokenizer fingerprint, so it does not confirm
    assert out["confirmed_switch"] is False


def test_cap_bounds_volume():
    c = _Client([("m", "x")] * 20)
    out = redteam.run(c, cap=3)                       # quota guard
    assert out["scenarios_run"] == 3


def test_transport_error_is_not_a_clean_scenario():
    # a non-2xx Response must NOT count as a successful no-identity scenario
    c = _Client([("gpt-4o", "hi", 200), ("", "", 500), ("gpt-4o", "hi", 200)])
    out = redteam.run(c, cap=3)
    assert out["scenarios_run"] == 2                       # the 500 didn't count
    assert any("transport" in r.get("error", "") for r in out["identities"])


def test_self_id_change_is_advisory_not_hard_switch():
    # echoed model stable, only the self-ID text changes (e.g. a refusal/negation)
    c = _Client([("gpt-4o", "I am ChatGPT."), ("gpt-4o", "Actually I'm GLM.")] + [("gpt-4o", "x")] * 6)
    out = redteam.run(c, cap=8)
    assert out["switch_detected"] is False                 # NOT a hard switch (exit 0)
    assert out["confirmed_switch"] is False                # a confession cannot upgrade
    assert out["self_id_flags"]                            # but flagged for review


def test_self_id_backfills_when_first_response_has_no_selfid():
    # first response: model id only; later a self-ID appears then changes -> flagged
    c = _Client([("router", "ok."), ("router", "I am ChatGPT."), ("router", "Actually GLM.")]
                + [("router", "x")] * 5)
    out = redteam.run(c, cap=8)
    # the self-ID went ChatGPT(OpenAI) -> GLM; backfill means the change is seen
    assert any(f["signal"] == "self_id" for f in out["self_id_flags"])


# --- WS1 (#113): fingerprint-based HARD switch. A router can hold a CONSTANT fake
# model_id while swapping the backend (the z.ai shape); the backend fingerprint
# (monitor.fingerprint over the response envelope) still moves.

class _FpResp(_Resp):
    """Response that also carries the fields monitor.fingerprint consumes: a
    usable usage.prompt_tokens count (the tokenizer-usability gate) plus header
    keys + body schema (the prompt-invariant envelope shape)."""
    def __init__(self, model, content, status=200, ptoks=11, headers=None, body=None):
        super().__init__(model, content, status)
        self._ptoks = ptoks
        self.headers = headers if headers is not None else {"content-type": "application/json"}
        self.body = body if body is not None else {"choices": [{"message": {}}], "usage": {}}
    def usage_prompt_tokens(self):
        return self._ptoks


class _FpClient:
    def __init__(self, script):
        self.script = list(script); self.i = -1
    def chat(self, prompt, **kw):
        self.i += 1
        return self.script[min(self.i, len(self.script) - 1)]


def test_fingerprint_switch_fires_on_constant_model_id():
    # model_id is the CONSTANT fake "gemini" throughout; the backend envelope
    # changes on scenario 3 (different provider response shape) -> switch flag.
    # No tokenizer vector, so this is a wire flag, not a CONFIRMED switch.
    stable = _FpResp("gemini", "I am Gemini.", headers={"content-type": "application/json"},
                     body={"choices": [{"message": {}}], "usage": {}})
    swapped = _FpResp("gemini", "I am Gemini.",
                      headers={"content-type": "application/json", "x-glm-backend": "1"},
                      body={"choices": [{"message": {}}], "usage": {}, "system_fingerprint": "glm"})
    script = [stable, stable, swapped, swapped] + [swapped] * 4
    out = redteam.run(_FpClient(script), cap=8)
    assert out["fingerprint_switch"] is True
    assert out["fingerprint_switches"]                       # scenario id(s) listed
    assert out["switch_detected"] is True                    # folded into the hard signal
    assert out["confirmed_switch"] is False                  # wire does not confirm
    # the echoed model id never changed -> model_id switches empty
    assert out["switches"] == []


def test_fingerprint_stable_backend_no_switch():
    stable = _FpResp("gemini", "I am Gemini.")
    out = redteam.run(_FpClient([stable] * 8), cap=8)
    assert out["fingerprint_switch"] is False
    assert out["switch_detected"] is False


def test_fingerprint_skips_unusable_tokenizer():
    # usage suppressed (ptoks None) -> tokenizer unusable -> scenario skipped for
    # fingerprint comparison (advisory, never a switch).
    a = _FpResp("m", "x", ptoks=None)
    b = _FpResp("m", "x", ptoks=None, headers={"content-type": "text/plain"})
    out = redteam.run(_FpClient([a, b] * 4), cap=8)
    assert out["fingerprint_switch"] is False


def test_one_scenario_error_does_not_abort():
    class _Boom(_Client):
        def chat(self, prompt, **kw):
            self.i += 1
            if self.i == 1:
                raise RuntimeError("rate limited")
            return _Resp("gpt-4o", "I am ChatGPT.")
    out = redteam.run(_Boom([]), cap=4)
    assert any("error" in r for r in out["identities"])   # the failure is recorded
    assert out["switch_detected"] is False                # and the run continued


def _hermetic(case_id):
    case = next(c for c in redteam.HERMETIC_SWITCH_CASES if c["id"] == case_id)
    if case.get("client_factory"):
        client = case["client_factory"]()
        out = redteam.run(client, cap=case["cap"])
        out["_client"] = client
        return out
    return redteam.run(redteam.ScriptedClient(case["turns"]), cap=len(case["turns"]))


def test_zai_denial_tokenizer_drift_is_confirmed_switch():
    # Persona and echoed id stay Gemini and the text denies a switch. The
    # multi-probe tokenizer shape still moves, so the grade is CONFIRMED.
    out = _hermetic("zai_persona_denies_switch")
    assert out["confirmed_switch"] is True
    assert out["switch_detected"] is True
    assert out["fingerprint_switch"] is True
    assert out["switches"] == []                  # echoed model id never moved
    assert out["self_id_flags"] == []             # the denial is not a new confession
    assert out["confirmed_switches"]
    assert "CONFIRMED" in out["note"]


def test_self_id_alone_does_not_upgrade_with_stable_tokenizer():
    out = _hermetic("self_id_alone")
    assert out["confirmed_switch"] is False
    assert out["switch_detected"] is False
    assert out["fingerprint_switch"] is False
    assert out["self_id_flags"]                  # supporting only


def test_wire_envelope_flags_without_confirming():
    out = _hermetic("wire_envelope_only")
    assert out["fingerprint_switch"] is True
    assert out["switch_detected"] is True
    assert out["confirmed_switch"] is False
    assert out["self_id_flags"] == []


def test_live_measure_confirms_tokenizer_switch_without_attached_bundle():
    # The scenario count moves with the prompt. The battery supplies the shape.
    out = _hermetic("live_measure_tokenizer_switch")
    client = out.pop("_client")
    assert client.probe_calls >= 6
    assert len(set(client.scenario_ptoks)) > 1       # one count is not the fingerprint
    assert out["confirmed_switch"] is True
    assert out["switches"] == []
    assert out["self_id_flags"] == []
    assert "probes" in out["confirmed_switches"][0]["detail"]


def test_live_measure_same_tokenizer_is_wire_flag_not_confirmed():
    out = _hermetic("live_measure_same_tokenizer")
    out.pop("_client")
    assert out["fingerprint_switch"] is True
    assert out["switch_detected"] is True
    assert out["confirmed_switch"] is False
    assert "CONFIRMED" not in out["note"]


def test_live_measure_self_id_does_not_upgrade():
    out = _hermetic("live_measure_self_id")
    client = out.pop("_client")
    assert client.probe_calls >= 6
    assert out["confirmed_switch"] is False
    assert out["switch_detected"] is False
    assert out["fingerprint_switch"] is False
    assert out["self_id_flags"]


def test_response_ok_property_is_not_a_transport_error():
    # client.Response.ok is a property. A live reply must still be scored.
    class _Prop:
        ok = True
        body = {"choices": [{"message": {}}], "usage": {"prompt_tokens": 4}}
        status = 200
        def echoed_model(self):
            return "gemini"
        def text(self):
            return "I am Gemini."
        def usage_prompt_tokens(self):
            return 4

    class _C:
        def chat(self, prompt, **kw):
            return _Prop()

    out = redteam.run(_C(), cap=2)
    assert out["scenarios_run"] == 2
    assert out["confirmed_switch"] is False
