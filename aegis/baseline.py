"""Relationship baseline from channel history (pulled via RTS in production).

The baseline is what makes detection possible: who normally talks here and the
bank details on file. RTS scoped to the Connect channel supplies the history
without exposing either org's internal Slack.
"""
from __future__ import annotations


def build(history: list, vendor: dict, available: bool = True) -> dict:
    """Build the baseline. `available=False` means history could not be read.

    That distinction matters: an empty history and an *unreadable* history look
    identical downstream, and treating an outage as "nobody has ever spoken here"
    tags every message with "sender not seen before" — noise that trains people to
    dismiss the card.
    """
    return {
        "known_users": {m["user"] for m in history},
        "known_contacts": set(vendor.get("known_contacts", [])),
        "on_file_iban": vendor.get("bank_on_file", {}).get("iban", ""),
        "available": available,
    }


def is_new_sender(user: str, baseline: dict) -> bool:
    return user not in baseline["known_users"] and user not in baseline["known_contacts"]
