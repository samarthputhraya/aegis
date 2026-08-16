"""Aegis verification actions (mostly mock; one real GitHub option).

verify_vendor_bank is the high-value action: compare a requested IBAN against the
bank details ON FILE, which is what turns a suspicious message into a provable
fraud flag. Pure/stdlib so it's testable offline.
"""
from __future__ import annotations
import json
import os
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


def _norm(iban: str) -> str:
    return "".join(iban.split()).upper()


def get_vendor(key: str) -> dict:
    with open(DATA_DIR / "vendors.json", encoding="utf-8") as f:
        return json.load(f).get(key, {})


def verify_vendor_bank(vendor_key: str, requested_iban: str) -> dict:
    """Compare a requested IBAN to the one on file. The crux check for BEC.

    `match` is tri-state and callers must treat the three cases differently:

    ``True``   the requested account is the one on record
    ``False``  it is not — this is the finding that turns suspicion into evidence
    ``None``   there is no record for this vendor, so nothing was compared

    Collapsing ``None`` into ``False`` would make a typo in VENDOR_KEY look like a
    confirmed fraud against an empty account number, so it stays distinct. `known`
    is the same information as a plain boolean, for callers that want it.
    """
    v = get_vendor(vendor_key)
    on_file = v.get("bank_on_file", {}).get("iban", "")
    known = bool(on_file)
    match = (_norm(on_file) == _norm(requested_iban)) if known else None
    return {"match": match, "known": known, "on_file_iban": on_file,
            "requested_iban": _norm(requested_iban),
            "on_file_since": v.get("bank_on_file", {}).get("updated"),
            "vendor_key": vendor_key}


def open_verification_task(title: str, body: str = "") -> dict:
    """Open a verification/escalation task (real GitHub issue if configured)."""
    if os.getenv("GITHUB_TOKEN") and os.getenv("GITHUB_REPO"):
        import httpx
        r = httpx.post(f"https://api.github.com/repos/{os.environ['GITHUB_REPO']}/issues",
                       headers={"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
                                "Accept": "application/vnd.github+json"},
                       json={"title": title, "body": body}, timeout=20)
        r.raise_for_status(); d = r.json()
        return {"id": f"#{d['number']}", "url": d["html_url"], "mock": False}
    return {"id": "VERIFY-1042", "title": title, "mock": True}
