"""Aegis detection tests (stdlib).  python tests/test_detection.py"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from aegis import signals, orchestrator
from mcp_server import tools

THREAD = json.load(open(os.path.join(ROOT, "scripts", "sample_thread.json"), encoding="utf-8"))
ATTACK = THREAD["messages"][-1]["text"]
BENIGN = THREAD["messages"][0]["text"]


def test_attack_signals():
    types = {s["type"] for s in signals.detect(ATTACK)}
    assert {"payment_change", "urgency", "secrecy", "iban_present"} <= types, types


def test_benign_has_no_payment_change():
    types = {s["type"] for s in signals.detect(BENIGN)}
    assert "payment_change" not in types


def test_bank_mismatch_via_mcp():
    chk = tools.verify_vendor_bank("acme_supplies", "GB29NWBK60161331926819")
    assert chk["match"] is False and chk["on_file_iban"].startswith("DE89")


def test_scan_flags_exactly_the_attack_as_critical():
    res = orchestrator.scan(THREAD, dry_run=True)
    assert len(res["events"]) == 1
    ev = res["events"][0]
    assert ev["risk"]["level"] == "critical"
    joined = " ".join(ev["risk"]["reasons"]).lower()
    assert "iban" in joined and "not seen before" in joined


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"PASS {name}")
            except AssertionError as e:
                failed += 1; print(f"FAIL {name}: {e}")
    sys.exit(1 if failed else 0)
