"""Replay a Slack Connect thread containing a bank-change fraud attempt (no creds).

    python scripts/simulate_attack.py
"""
from __future__ import annotations
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.dirname(HERE))


def main():
    from aegis import orchestrator
    from mcp_server import tools
    thread = json.load(open(os.path.join(HERE, "sample_thread.json"), encoding="utf-8"))
    res = orchestrator.scan(thread, dry_run=True)
    print(f"\n=== Aegis scan · {res['vendor'].get('vendor')} "
          f"(bank on file {res['vendor'].get('bank_on_file',{}).get('iban')}) ===\n")
    if not res["events"]:
        print("No risks detected."); return
    for e in res["events"]:
        m, r = e["message"], e["risk"]
        print(f"[{r['level'].upper()}  score={r['score']}]  {m['user']}  {m['ts'][:10]}")
        print(f"  msg: {m['text']}")
        for reason in r["reasons"]:
            print(f"   - {reason}")
        iban = next((s["evidence"] for s in e["signals"] if s["type"] == "iban_present"), None)
        if iban:
            chk = tools.verify_vendor_bank(thread["vendor_key"], iban)
            print(f"   MCP verify_vendor_bank -> match={chk['match']} "
                  f"(on file {chk['on_file_iban']})")
        print()
    print("--- Canvas trust log (markdown) ---")
    print(res["trust_log_md"])


if __name__ == "__main__":
    main()
