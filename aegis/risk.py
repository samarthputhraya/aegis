"""Risk scoring — combine signals + baseline + the on-file bank check (MCP).

Each signal contributes a fixed weight, scaled by the classifier's `confidence` for
that signal (absent confidence is treated as 1.0, so the offline detector scores
exactly as it always has). The IBAN-mismatch check is never scaled: it is a factual
comparison against a record, not a judgement call.
"""
from __future__ import annotations

from aegis import baseline as bl
from mcp_server import tools as mcp_tools

WEIGHTS = {
    "payment_change": 3,
    "iban_mismatch": 4,
    "credential_request": 4,
    "urgency": 2,
    "secrecy": 2,
    "out_of_band_redirect": 2,
    "new_sender": 2,
}

THRESHOLDS = [("critical", 7), ("high", 5), ("medium", 3)]


def _mask(iban: str) -> str:
    return f"{iban[:4]}…{iban[-4:]}" if iban and len(iban) > 8 else (iban or "?")


def _ev(signals, t):
    return next((s["evidence"] for s in signals if s["type"] == t), "")


def _evs(signals, t):
    """Every evidence value for a signal type, in order, de-duplicated."""
    out = []
    for s in signals:
        if s["type"] == t and s["evidence"] not in out:
            out.append(s["evidence"])
    return out


def _conf(signals, t) -> float:
    """Classifier confidence for a signal type, defaulting to 1.0."""
    for s in signals:
        if s["type"] == t:
            try:
                return min(1.0, max(0.0, float(s.get("confidence", 1.0))))
            except (TypeError, ValueError):
                return 1.0
    return 1.0


def level_for(score: float) -> str:
    for name, floor in THRESHOLDS:
        if score >= floor:
            return name
    return "low"


def assess(message: dict, signals: list, base: dict, vendor_key: str) -> dict:
    types = {s["type"] for s in signals}
    ibans = _evs(signals, "iban_present")
    who = message.get("display") or message.get("user", "")
    score, reasons = 0.0, []

    if "payment_change" in types:
        score += WEIGHTS["payment_change"] * _conf(signals, "payment_change")
        reasons.append("Payment/bank-detail change requested")

    # The bank check runs whenever an IBAN is present, not only when a "change" word
    # appeared. An account number in the channel that doesn't match the record is a
    # fact worth scoring regardless of how it was phrased. On its own it scores 4,
    # which is "medium" — it needs corroboration before Aegis raises an alert.
    #
    # Every IBAN in the message is checked, not just the first. "Do not use DE89…,
    # remit to GB29…" names the legitimate account first; checking only that one lets
    # the fraudulent account through.
    mismatched, unknown_vendor = [], False
    for iban in ibans:
        chk = mcp_tools.verify_vendor_bank(vendor_key, iban)       # MCP check vs on-file
        if chk["match"] is False:
            mismatched.append((iban, chk["on_file_iban"]))
        elif chk["match"] is None:
            unknown_vendor = True

    if mismatched:
        score += WEIGHTS["iban_mismatch"]                          # factual, never scaled
        shown = ", ".join(_mask(i) for i, _ in mismatched)
        reasons.append(
            f"Requested IBAN {shown} ≠ IBAN on file {_mask(mismatched[0][1])}"
        )
    elif unknown_vendor:
        # No record to compare against. Scored at zero on purpose — an unverifiable
        # account is not evidence of fraud — but said out loud, because a card that
        # stays silent about it implies a check that never happened.
        reasons.append(
            f"No bank record on file for '{vendor_key}', so the account number in this "
            "message could not be verified"
        )

    if "credential_request" in types:
        score += WEIGHTS["credential_request"] * _conf(signals, "credential_request")
        reasons.append(f"Credentials/secret requested ('{_ev(signals, 'credential_request')}')")
    if "urgency" in types:
        score += WEIGHTS["urgency"] * _conf(signals, "urgency")
        reasons.append(f"Urgency pressure ('{_ev(signals, 'urgency')}')")
    if "secrecy" in types:
        score += WEIGHTS["secrecy"] * _conf(signals, "secrecy")
        reasons.append(f"Secrecy cue ('{_ev(signals, 'secrecy')}')")
    if "out_of_band_redirect" in types:
        score += WEIGHTS["out_of_band_redirect"] * _conf(signals, "out_of_band_redirect")
        reasons.append(
            f"Pushes the conversation off-channel ('{_ev(signals, 'out_of_band_redirect')}')")
    if base and base.get("available", True) and bl.is_new_sender(message.get("user", ""), base):
        score += WEIGHTS["new_sender"]
        reasons.append(f"Sender '{who}' not seen before in this channel")

    rounded = int(score) if float(score).is_integer() else round(score, 1)
    return {"level": level_for(score), "score": rounded, "reasons": reasons,
            "requested_iban": (mismatched[0][0] if mismatched
                               else (ibans[0] if ibans else None)),
            "all_ibans": ibans, "vendor_key": vendor_key}
