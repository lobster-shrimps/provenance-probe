"""Eval driver: run labeled cases, build a confusion matrix, gate the build.

    ┌───────────── cases ─────────────┐
    │ BUNDLE_CASES → score(bundle)     │   accuracy tier (scoring logic)
    │ VOCAB_CASES  → mock → assess     │   consistency tier (matcher+ref)
    └──────────────┬───────────────────┘
                   ▼   is_flagged_cn(verdict, top_match)
        classify vs label:  TP  FP
                            FN  TN
                   ▼
        GATE:  FP > 0            → FAIL (a non-CN model read as Chinese)
               FN > budget       → FAIL (missed CN models beyond ratchet)
               verdict mismatch  → FAIL (scoring tier regressed)
               else              → PASS

Exit code 0 = pass, 1 = gate failure, 2 = harness error (deps/seed/vocab).

Tiers:
  --hermetic (default)  bundle + vocab cases, fully offline, vendored vocabs.
  --bundles-only        scoring tier only (no gguf/tokenizers deps needed).
  --vocab-only          consistency tier only.

Live named-vendor accuracy is deliberately NOT run here: probing a named
commercial vendor and publishing an interpreted verdict from this PUBLIC repo
is a Gate-1 legal exposure. That validation runs on a schedule in the PRIVATE
provenance-observatory.
"""
from __future__ import annotations

import argparse
import json
import os
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
VOCAB_DIR = os.path.join(HERE, "vocabs")
BUNDLE_DIR = os.path.join(HERE, "bundles")


class Result:
    __slots__ = ("name", "kind", "expect_flagged", "got_flagged",
                 "verdict", "verdict_ok", "error")

    def __init__(self, name, kind, expect_flagged, got_flagged,
                 verdict, verdict_ok=True, error=None):
        self.name = name
        self.kind = kind
        self.expect_flagged = expect_flagged
        self.got_flagged = got_flagged
        self.verdict = verdict
        self.verdict_ok = verdict_ok
        self.error = error

    @property
    def cell(self) -> str:
        if self.error:
            return "ERR"
        if self.expect_flagged and self.got_flagged:
            return "TP"
        if self.expect_flagged and not self.got_flagged:
            return "FN"
        if not self.expect_flagged and self.got_flagged:
            return "FP"
        return "TN"


# --- accuracy tier: labeled score() bundles ---------------------------------

def run_bundle_cases():
    from provenance_probe import scoring
    from eval.corpus import BUNDLE_CASES, is_flagged_cn
    results = []
    for case in BUNDLE_CASES:
        path = os.path.join(BUNDLE_DIR, case["file"])
        try:
            bundle = json.load(open(path))
            out = scoring.score(bundle)
            tm = bundle.get("tokenizer_match") or []
            top = tm[0] if tm else None
            verdict = (out.get("provenance_risk") or {}).get("verdict")
            flagged = is_flagged_cn(out, top)
            verdict_ok = verdict in case["expect_provenance"]
            results.append(Result(case["file"], "bundle", case["expect_flagged"],
                                  flagged, verdict, verdict_ok))
        except Exception as e:  # noqa: BLE001 — a broken fixture is a harness error
            results.append(Result(case["file"], "bundle", case["expect_flagged"],
                                  False, None, False, str(e)))
    return results


# --- consistency tier: real GGUF vocab served blind through assess ----------

def _serve(app):
    """Start a Flask app on an ephemeral port in a background thread."""
    import logging
    from werkzeug.serving import make_server
    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # quiet per-request logs
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_port


def run_vocab_cases():
    from provenance_probe.config import Target
    from provenance_probe.client import Client
    from provenance_probe.probes import tokenizer
    from eval import mock
    from eval.corpus import VOCAB_CASES, EXPECTED_VARIANT_SEED, is_flagged_cn
    from provenance_probe import scoring

    ref = tokenizer.load_reference()
    if not ref:
        return [Result("<reference>", "vocab", True, False, None, False,
                       "no tokenizer reference vectors shipped")]
    results = []
    for i, case in enumerate(VOCAB_CASES):
        gguf = mock.vocab_path(VOCAB_DIR, case["key"])
        if not os.path.exists(gguf):
            results.append(Result(case["key"], "vocab", case["expect_flagged"],
                                  False, None, False, f"missing vocab {gguf}"))
            continue
        srv = None
        try:
            app = mock.make_app(gguf, f"blind-{i}", case["key"])
            srv, port = _serve(app)
            t = Target(name=case["key"], base_url=f"http://127.0.0.1:{port}/v1",
                       model=f"blind-{i}", authorized=True)
            obs = tokenizer.measure(Client(t), variant_seed=EXPECTED_VARIANT_SEED)
            if obs.get("variant_seed") != EXPECTED_VARIANT_SEED:
                raise RuntimeError(f"probe seed {obs.get('variant_seed')} != "
                                   f"{EXPECTED_VARIANT_SEED}")
            if not obs.get("usable"):
                raise RuntimeError("mock returned no usable token counts")
            matches = tokenizer.compare(obs, ref)
            bundle = {"tokenizer": obs, "tokenizer_match": matches,
                      "headers": {"status": 200, "vendor_headers": []},
                      "network": {"addresses": [], "findings": []},
                      "catalog": {"prc_origin_models": []}}
            out = scoring.score(bundle)
            top = matches[0] if matches else None
            verdict = (out.get("provenance_risk") or {}).get("verdict")
            flagged = is_flagged_cn(out, top)
            results.append(Result(
                f"{case['key']} ({case['origin']}"
                + (f"->{top['model']} {top['score']}" if top else "")
                + ")", "vocab", case["expect_flagged"], flagged, verdict))
        except Exception as e:  # noqa: BLE001
            results.append(Result(case["key"], "vocab", case["expect_flagged"],
                                  False, None, False, str(e)))
        finally:
            if srv is not None:
                srv.shutdown()
    return results


def run_switch_cases():
    """Hermetic red-team switch grade. Not part of the CN confusion matrix.

    A CONFIRMED switch is tokenizer-shape drift. The z.ai denial case keeps the
    persona and echoed model id on Gemini while the shape moves. A self-ID change
    with a stable shape must not confirm. A wire-envelope change flags and does
    not confirm. No model call.
    """
    from provenance_probe import redteam
    rows = []
    for case in redteam.HERMETIC_SWITCH_CASES:
        try:
            out = redteam.run(redteam.ScriptedClient(case["turns"]),
                              cap=len(case["turns"]))
            problems = []
            for key, field in (
                ("expect_confirmed", "confirmed_switch"),
                ("expect_fingerprint_switch", "fingerprint_switch"),
                ("expect_switch_detected", "switch_detected"),
            ):
                if out[field] is not case[key]:
                    problems.append(f"{field}={out[field]!r} expected {case[key]!r}")
            rows.append({"id": case["id"], "ok": not problems,
                         "detail": "; ".join(problems), "note": case.get("note", "")})
        except Exception as e:  # noqa: BLE001 — a broken fixture is a harness error
            rows.append({"id": case["id"], "ok": False, "detail": str(e), "note": ""})
    return rows


# --- fleet control tier: host attribution zero-FP gate ----------------------

def run_fleet_cases():
    """Attribute each labeled host via fleet's corpus lookup and gate FPs. Fully
    offline (no network, no gguf) — attribution is a static dict lookup."""
    from provenance_probe.fleet.attribute import attribute
    from eval.corpus import FLEET_CASES, fleet_flagged_cn
    results = []
    for case in FLEET_CASES:
        try:
            attr = attribute(case["host"])
            flagged = fleet_flagged_cn(attr)
            verdict = attr.origin if attr else "none"
            results.append(Result(f"{case['host']} ({case['note']})", "fleet",
                                  case["expect_flagged"], flagged, verdict))
        except Exception as e:  # noqa: BLE001
            results.append(Result(case["host"], "fleet", case["expect_flagged"],
                                  False, None, False, str(e)))
    return results


# --- matrix + gate ----------------------------------------------------------

def confusion(results):
    m = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERR": 0}
    for r in results:
        m[r.cell] += 1
    return m


def report(results, matrix):
    lines = ["", "EVAL RESULTS", "=" * 68]
    for r in results:
        mark = "ok " if (r.cell in ("TP", "TN") and r.verdict_ok) else "!! "
        tail = f"  [{r.error}]" if r.error else (
            "" if r.verdict_ok else f"  verdict={r.verdict} UNEXPECTED")
        lines.append(f"  {mark}{r.cell:<3} {r.kind:<7} {r.name} "
                     f"-> {r.verdict}{tail}")
    tp, fp, tn, fn = matrix["TP"], matrix["FP"], matrix["TN"], matrix["FN"]
    denom_p = tp + fn or 1
    denom_n = tn + fp or 1
    lines += [
        "-" * 68,
        f"  confusion:  TP={tp}  FP={fp}  TN={tn}  FN={fn}  ERR={matrix['ERR']}",
        f"  recall (CN caught):      {tp}/{tp + fn} = {tp / denom_p:.0%}",
        f"  specificity (US clean):  {tn}/{tn + fp} = {tn / denom_n:.0%}",
        f"  false-positive rate:     {fp}/{tn + fp} = {fp / denom_n:.0%}",
    ]
    return "\n".join(lines)


def gate(results, matrix, max_fn):
    reasons = []
    if matrix["ERR"]:
        reasons.append(f"{matrix['ERR']} harness error(s) — cannot certify")
    if matrix["FP"]:
        reasons.append(f"{matrix['FP']} FALSE POSITIVE(s): a non-CN model was "
                       f"flagged Chinese-origin (zero-FP gate)")
    if matrix["FN"] > max_fn:
        reasons.append(f"{matrix['FN']} false negative(s) > budget {max_fn}")
    bad_verdicts = [r.name for r in results if not r.verdict_ok and not r.error]
    if bad_verdicts:
        reasons.append("verdict-tier regression: " + ", ".join(bad_verdicts))
    return reasons


def main(argv=None):
    ap = argparse.ArgumentParser(description="provenance engine accuracy/consistency eval")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--hermetic", action="store_true", help="bundle + vocab + fleet tiers (default)")
    g.add_argument("--bundles-only", action="store_true", help="scoring tier only (no gguf deps)")
    g.add_argument("--vocab-only", action="store_true", help="consistency tier only")
    g.add_argument("--fleet-only", action="store_true", help="fleet host-attribution tier only (offline)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable summary")
    a = ap.parse_args(argv)

    from eval.corpus import MAX_FALSE_NEGATIVES
    # Pick tiers: an --X-only flag restricts to that tier; otherwise run all three.
    # The switch tier is offline (no vocab) and rides with the bundle tier.
    only = a.bundles_only or a.vocab_only or a.fleet_only
    results = []
    switch_rows = []
    if a.bundles_only or not only:
        results += run_bundle_cases()
        switch_rows = run_switch_cases()
    if a.vocab_only or not only:
        results += run_vocab_cases()
    if a.fleet_only or not only:
        results += run_fleet_cases()

    matrix = confusion(results)
    reasons = gate(results, matrix, MAX_FALSE_NEGATIVES)
    for row in switch_rows:
        if not row["ok"]:
            reasons.append(f"switch-case {row['id']}: {row['detail'] or 'failed'}")
    passed = not reasons

    if a.json:
        print(json.dumps({"matrix": matrix, "passed": passed, "reasons": reasons,
                          "switch_cases": switch_rows,
                          "cases": [{"name": r.name, "cell": r.cell,
                                     "verdict": r.verdict, "verdict_ok": r.verdict_ok,
                                     "error": r.error} for r in results]}, indent=2))
    else:
        print(report(results, matrix))
        if switch_rows:
            print("-" * 68)
            print("  SWITCH TIER (tokenizer fingerprint; not in the CN matrix)")
            for row in switch_rows:
                mark = "ok " if row["ok"] else "!! "
                print(f"  {mark}{row['id']}: {row['note']}"
                      + (f"  [{row['detail']}]" if row["detail"] else ""))
        print("-" * 68)
        if passed:
            print("  GATE: PASS — 0 false positives, all verdicts as labeled")
        else:
            print("  GATE: FAIL")
            for r in reasons:
                print(f"    - {r}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
