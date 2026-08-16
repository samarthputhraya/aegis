"""Aegis orchestration — scan a Connect channel, flag social-engineering attempts.

scan() (dry_run) uses the offline detector + MCP bank check + builders, so it runs
with no creds. Production swaps signals.detect -> reasoner.classify and pulls
history via RTS.
"""
from __future__ import annotations
from aegis import signals, baseline, risk, reasoner, surfaces as ui
from mcp_server import tools as mcp_tools


def evaluate(message: dict, history: list, vendor: dict, vendor_key: str,
             dry_run: bool = True, baseline_available: bool = True) -> dict:
    sigs = signals.detect(message["text"]) if dry_run else reasoner.classify(message)
    base = baseline.build(history, vendor, available=baseline_available)
    r = risk.assess(message, sigs, base, vendor_key)
    return {"message": message, "signals": sigs, "risk": r}


def scan(thread: dict, dry_run: bool = True) -> dict:
    msgs = sorted(thread["messages"], key=lambda m: m["ts"])
    our = thread["our_team"]
    vkey = thread["vendor_key"]
    vendor = mcp_tools.get_vendor(vkey)

    events, history = [], []
    for m in msgs:
        if m["team"] != our:  # only external messages are threats
            ev = evaluate(m, history, vendor, vkey, dry_run=dry_run)
            if ev["risk"]["level"] in ("medium", "high", "critical"):
                events.append(ev)
        history.append(m)

    return {"vendor": vendor, "events": events,
            "trust_log_md": ui.trust_log_md(vendor, events)}
