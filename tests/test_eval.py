"""Measure the offline detector against a labeled set. `python tests/test_eval.py`

This exists because "does it catch the demo message" is not a measurement. The gates
below are set slightly above the current measured rates, so a change that makes
detection worse fails CI, and a change that makes it better is visible as headroom.

Measured two ways, because they answer different questions:

**warm** — the sender has spoken in this channel before. Isolates the content detectors.
**cold** — nobody has, so every message also carries the +2 new-sender term. This is a
brand-new Connect channel on day one, and it is the configuration where false positives
actually bite: the first week is when people decide whether to trust the tool.

Flagged == the risk level Aegis actually posts on (`high` or `critical`).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from aegis import orchestrator                                           # noqa: E402
from mcp_server import tools                                             # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures", "messages.jsonl")
VENDOR_KEY = "acme_supplies"
POST_LEVELS = {"high", "critical"}

# Gates. Currently measured: 0% false positives and 0% false negatives in both warm and
# cold modes, across 30 benign and 14 malicious cases. The budgets sit above that so
# growing the corpus doesn't immediately break the build. Tighten as detection improves;
# never loosen without saying why in the PR.
MAX_FALSE_POSITIVE_RATE = 0.10
MAX_FALSE_NEGATIVE_RATE = 0.15


def load_cases():
    with open(FIXTURES, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def evaluate(case, warm=True):
    """Score one case through the real pipeline.

    Goes through `orchestrator.evaluate` rather than reimplementing the scoring, so the
    baseline and risk modules are actually covered — an eval that rebuilds the pipeline
    inline measures a copy of the system, not the system.
    """
    message = {"user": case["user"], "text": case["text"], "ts": "2026-06-08T09:00:00"}
    history = ([{"user": case["user"], "text": "earlier chat", "ts": "1.0", "team": "T_V"}]
               if warm else [])
    vendor = tools.get_vendor(VENDOR_KEY)
    return orchestrator.evaluate(message, history, vendor, VENDOR_KEY,
                                 dry_run=True)["risk"]


def measure(warm=True):
    fp = fn = 0
    benign = malicious = 0
    misses, false_alarms = [], []

    for case in load_cases():
        flagged = evaluate(case, warm=warm)["level"] in POST_LEVELS
        if case["label"] == "benign":
            benign += 1
            if flagged:
                fp += 1
                false_alarms.append(case["id"])
        else:
            malicious += 1
            if not flagged:
                fn += 1
                misses.append(case["id"])

    return {
        "warm": warm, "benign": benign, "malicious": malicious,
        "false_positives": fp, "false_negatives": fn,
        "fp_rate": fp / benign if benign else 0.0,
        "fn_rate": fn / malicious if malicious else 0.0,
        "false_alarms": false_alarms, "misses": misses,
    }


def test_fixture_set_is_balanced_enough_to_mean_something():
    r = measure()
    assert r["benign"] >= 20, f"only {r['benign']} benign cases"
    assert r["malicious"] >= 10, f"only {r['malicious']} malicious cases"


def test_false_positive_rate_within_budget():
    for warm in (True, False):
        r = measure(warm=warm)
        assert r["fp_rate"] <= MAX_FALSE_POSITIVE_RATE, (
            f"[{'warm' if warm else 'cold'}] false-positive rate {r['fp_rate']:.0%} "
            f"exceeds {MAX_FALSE_POSITIVE_RATE:.0%}; flagged: {r['false_alarms']}"
        )


def test_false_negative_rate_within_budget():
    for warm in (True, False):
        r = measure(warm=warm)
        assert r["fn_rate"] <= MAX_FALSE_NEGATIVE_RATE, (
            f"[{'warm' if warm else 'cold'}] false-negative rate {r['fn_rate']:.0%} "
            f"exceeds {MAX_FALSE_NEGATIVE_RATE:.0%}; missed: {r['misses']}"
        )


def test_the_headline_attack_is_critical():
    case = next(c for c in load_cases() if c["id"] == "m01")
    assert evaluate(case)["level"] == "critical"


def test_a_new_sender_alone_never_raises_an_alert():
    """+2 for an unknown sender must not, on its own, put anything over the bar.
    Everyone is a new sender on day one of a channel."""
    r = measure(warm=False)
    assert r["fp_rate"] <= MAX_FALSE_POSITIVE_RATE, r["false_alarms"]


def report():
    for warm in (True, False):
        r = measure(warm=warm)
        label = "warm (sender known)" if warm else "cold (new channel)"
        if warm:
            print(f"\n  corpus: {r['benign']} benign, {r['malicious']} malicious")
        print(f"  {label}: "
              f"FP {r['false_positives']}/{r['benign']} ({r['fp_rate']:.0%})"
              + (f" {r['false_alarms']}" if r["false_alarms"] else "")
              + f" · FN {r['false_negatives']}/{r['malicious']} ({r['fn_rate']:.0%})"
              + (f" {r['misses']}" if r["misses"] else ""))


if __name__ == "__main__":
    failed = 0
    for name, fn_ in sorted(globals().items()):
        if name.startswith("test_") and callable(fn_):
            try:
                fn_()
                print(f"PASS {name}")
            except AssertionError as e:
                failed += 1
                print(f"FAIL {name}: {e}")
    report()
    sys.exit(1 if failed else 0)
