"""The live logic behind the Slack app, kept free of Bolt so it can be tested.

`app.py` is a thin wrapper that hands Bolt events to these functions with a real
`WebClient`. Everything here takes the client as an argument, so the tests drive it with
a fake one — no tokens, no network.

State note: `_TRUST_LOG` and `_TRUSTED` are in-memory, so the trust log and any
"mark safe" decisions reset when the process restarts. That is fine for a demo and
explicitly not fine for production; see docs/ROADMAP.md.
"""
from __future__ import annotations

import json
import logging
import os

from aegis import orchestrator, slack_io, surfaces
from aegis.risk import _mask          # one source of truth for account masking
from mcp_server import tools as mcp_tools

log = logging.getLogger(__name__)

POST_LEVELS = {"high", "critical"}

_TRUST_LOG: dict = {}      # channel_id -> [event, ...]
_TRUSTED: dict = {}        # channel_id -> {user_id, ...}


def reset_state() -> None:
    """Clear in-memory state. Used by tests."""
    _TRUST_LOG.clear()
    _TRUSTED.clear()
    slack_io.clear_name_cache()


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


# ------------------------------------------------------------------- inbound messages


def should_scan(event: dict, our_team_id: str) -> bool:
    """Only external, human, first-class messages are candidates.

    Every rejection is logged. A tripwire that silently declines to look at things is
    indistinguishable from one that is working, and the most likely misconfiguration —
    OUR_TEAM_ID pointing at the vendor's workspace instead of yours — turns every
    external message into a skip.
    """
    inner = slack_io.unwrap(event)

    if not slack_io.is_conversational(event):
        log.debug("skip: not conversational (subtype=%s)", inner.get("subtype"))
        return False
    if inner.get("bot_id"):
        log.debug("skip: bot message")
        return False
    team = slack_io.sender_team(inner)
    if our_team_id and team == our_team_id:
        log.debug("skip: internal message from our own team %s", team)
        return False
    if not (inner.get("channel") or event.get("channel")):
        log.debug("skip: no channel on the event")
        return False
    return True


def handle_external_message(client, event: dict, our_team_id: str = "",
                            vendor_key: str = "", history_limit: int = 200,
                            dry_run: bool = False):
    """Scan one inbound Slack message. Returns the evaluation, or None if skipped."""
    our_team_id = our_team_id or _env("OUR_TEAM_ID")
    vendor_key = vendor_key or _env("VENDOR_KEY", "acme_supplies")

    if not should_scan(event, our_team_id):
        return None

    inner = slack_io.unwrap(event)
    channel = inner.get("channel") or event["channel"]
    message = slack_io.normalize(event)
    message["display"] = slack_io.display_name(client, message["user"])

    baseline_available = True
    try:
        history = slack_io.fetch_history(client, channel, limit=history_limit,
                                         query=message["text"][:200])
    except Exception as exc:                                  # noqa: BLE001
        # Scan anyway, but mark the baseline unavailable so the new-sender signal is
        # dropped rather than fired at everyone. Content signals are unaffected.
        log.warning("history fetch failed for %s: %s", channel, exc)
        history, baseline_available = [], False

    history = [m for m in history if m.get("ts") != message["ts"]]
    for uid in _TRUSTED.get(channel, ()):                     # honour earlier "mark safe"
        history.append({"user": uid, "text": "", "ts": "0", "team": ""})

    vendor = mcp_tools.get_vendor(vendor_key)
    ev = orchestrator.evaluate(message, history, vendor, vendor_key, dry_run=dry_run,
                               baseline_available=baseline_available)
    ev["channel"] = channel
    ev["baseline_available"] = baseline_available

    log.info("scanned %s in %s -> %s (score %s)",
             message["user"], channel, ev["risk"]["level"], ev["risk"]["score"])

    if ev["risk"]["level"] in POST_LEVELS:
        _record(channel, ev)
        try:
            surfaces.post_warning(channel, ev, thread_ts=message["ts"], client=client)
        except Exception as exc:                              # noqa: BLE001
            log.error("failed to post warning in %s: %s", channel, exc)
        try:
            surfaces.upsert_trust_log(
                client, channel, surfaces.trust_log_md(vendor, _TRUST_LOG.get(channel, [])))
        except Exception as exc:                              # noqa: BLE001
            log.warning("failed to update trust log in %s: %s", channel, exc)

    return ev


def _record(channel: str, ev: dict) -> None:
    _TRUST_LOG.setdefault(channel, []).append(ev)


def trust_log_events(channel: str) -> list:
    return list(_TRUST_LOG.get(channel, []))


# --------------------------------------------------------------------- button actions


def parse_action_value(raw: str) -> dict:
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def actor_is_external(actor_team: str, our_team_id: str) -> bool:
    """Is the person who clicked demonstrably on the other side of the Connect channel?

    The warning card is posted into the shared channel, so the vendor — including a
    sender Aegis has just flagged — can see it and press its buttons. Neither button
    should obey them: `mark_safe` would let a fraudster clear themselves, and `verify`
    replies with the account on file.

    Only a *positive* mismatch refuses. If Slack sends no team on the payload we allow
    it and log, because silently disabling both buttons on an unexpected payload shape
    would be its own failure — the operator would think they had a control they didn't.
    """
    return bool(our_team_id and actor_team and actor_team != our_team_id)


def _refuse(client, channel: str, thread_ts: str, what: str) -> dict:
    text = (f":no_entry: That button can only be used by someone from this workspace. "
            f"The {what} request was ignored and nothing was changed.")
    try:
        client.chat_postMessage(channel=channel, thread_ts=thread_ts or None, text=text)
    except Exception as exc:                                  # noqa: BLE001
        log.error("failed to post refusal in %s: %s", channel, exc)
    return {"refused": True, "text": text}


def handle_verify(client, action_value: str, channel: str, thread_ts: str = "",
                  actor: str = "", actor_team: str = "", our_team_id: str = "") -> dict:
    """Run the out-of-band check: bank verification + a verification task."""
    our_team_id = our_team_id or _env("OUR_TEAM_ID")
    if actor_is_external(actor_team, our_team_id):
        log.warning("verify pressed by external actor %s (team %s); refusing",
                    actor or "?", actor_team)
        return _refuse(client, channel, thread_ts, "verification")

    payload = parse_action_value(action_value)
    vendor_key = payload.get("vendor_key") or _env("VENDOR_KEY", "acme_supplies")
    vendor_key = vendor_key if isinstance(vendor_key, str) else _env("VENDOR_KEY", "acme_supplies")
    iban = payload.get("iban") or ""

    iban = iban if isinstance(iban, str) else ""
    check = mcp_tools.verify_vendor_bank(vendor_key, iban) if iban else {
        "match": None, "known": True, "on_file_iban": mcp_tools.get_vendor(vendor_key)
                       .get("bank_on_file", {}).get("iban", ""),
        "requested_iban": "", "on_file_since": None,
    }

    vendor = mcp_tools.get_vendor(vendor_key)
    vendor_name = vendor.get("vendor", vendor_key)

    if check["match"] is True:
        headline = (f":white_check_mark: The requested IBAN *matches* the account on file "
                    f"for {vendor_name}.")
        detail = ("That removes the mismatch, but it does not clear the message on its own — "
                  "urgency and secrecy cues are still worth a phone call.")
        task = None
    elif check["match"] is False:
        headline = (f":rotating_light: The requested IBAN does *not* match the account on "
                    f"file for {vendor_name}.")
        # Masked, for the same reason the card masks it: this thread is in a Connect
        # channel that the counterparty reads. Posting the real account number here
        # would hand it to whoever sent the message we just flagged. The unmasked
        # value goes to the verification task, which is internal.
        detail = (f"On file: `{_mask(check['on_file_iban'])}` "
                  f"(since {check.get('on_file_since') or 'unknown'})\n"
                  f"Requested: `{_mask(check['requested_iban'])}`\n"
                  "Do not pay. Confirm by calling a number you already had for this vendor — "
                  "not one from this thread.")
        task = mcp_tools.open_verification_task(
            f"Verify bank-detail change from {vendor_name}",
            body=(f"Requested IBAN: {check['requested_iban']}\n"
                  f"IBAN on file: {check['on_file_iban']}\n"
                  f"Slack channel: {channel}\nMessage ts: {payload.get('ts','')}\n"
                  f"Reported by: {actor or 'unknown'}\n\n"
                  "Raised automatically by Aegis. Confirm out-of-band before any payment."),
        )
    elif not check.get("known", True):
        headline = (f":warning: There is no bank record on file for "
                    f"`{vendor_key}`, so nothing could be compared.")
        detail = ("This is a configuration problem, not a verdict — check `VENDOR_KEY` "
                  "and `mcp_server/data/vendors.json`. Treat the request as unverified.")
        task = None
    else:
        headline = ":mag: No IBAN was present in that message, so there was nothing to compare."
        detail = (f"The account on file for {vendor_name} ends `{_mask(check['on_file_iban'])}`. "
                  "Check the full number in your own finance system, not from this thread.")
        task = None

    if task:
        where = task.get("url") or task.get("id", "")
        detail += f"\n\nVerification task opened: {where}" + (" _(mock)_" if task.get("mock") else "")

    try:
        client.chat_postMessage(channel=channel, thread_ts=thread_ts or None,
                                text=f"{headline}\n{detail}")
    except Exception as exc:                                  # noqa: BLE001
        log.error("failed to post verification result in %s: %s", channel, exc)

    return {"check": check, "task": task, "text": f"{headline}\n{detail}"}


def handle_mark_safe(client, action_value: str, channel: str, thread_ts: str = "",
                     actor: str = "", actor_team: str = "", our_team_id: str = "") -> dict:
    """Record a human decision that this sender is legitimate in this channel."""
    our_team_id = our_team_id or _env("OUR_TEAM_ID")
    if actor_is_external(actor_team, our_team_id):
        log.warning("mark_safe pressed by external actor %s (team %s); refusing",
                    actor or "?", actor_team)
        return _refuse(client, channel, thread_ts, "mark-safe")

    payload = parse_action_value(action_value)
    # Validate BEFORE mutating: button values are attacker-echoable, and a list or dict
    # here used to reach `set.add` and raise, or store a non-string in _TRUSTED.
    user = payload.get("user", "")
    user = user if isinstance(user, str) else ""
    if user:
        _TRUSTED.setdefault(channel, set()).add(user)

    who = f"<@{user}>" if user.startswith(("U", "W")) else (user or "that sender")
    text = (f":white_check_mark: {who} marked as trusted in this channel"
            + (f" by <@{actor}>" if actor else "") + ".\n"
            "Aegis will stop treating them as a new sender here. Payment-change and "
            "IBAN-mismatch checks still apply — trusting a person is not trusting an "
            "account number.")
    try:
        client.chat_postMessage(channel=channel, thread_ts=thread_ts or None, text=text)
    except Exception as exc:                                  # noqa: BLE001
        log.error("failed to post mark-safe confirmation in %s: %s", channel, exc)

    return {"trusted": sorted(_TRUSTED.get(channel, set())), "text": text}
