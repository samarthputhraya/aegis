"""Regressions. `python tests/test_regressions.py`

Every test here corresponds to a bug that was actually in this repo and got shipped past
its own test suite. They're kept together, and each names the failure it prevents, so
nobody removes one thinking it's redundant.

The theme is fail-open: a fraud tripwire that misses is far worse than one that raises,
and almost every bug below made Aegis quietly score a real attack as safe.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import app                                                              # noqa: E402
from fake_slack import FakeSlackClient, FakeSlackResponse, msg          # noqa: E402
from aegis import handlers, risk, signals, slack_io                     # noqa: E402
from mcp_server import tools                                            # noqa: E402

CHANNEL = "C_CONNECT"
OUR_TEAM = "T_BUYER"
ON_FILE = "DE89370400440532013000"
FRAUD = "GB29NWBK60161331926819"


def _client(history=None, **kw):
    return FakeSlackClient(
        history=history if history is not None else [
            msg("U_RAVI", "Invoice 2211 attached, net 30 as usual.", "1717000001.0")],
        users={"U_RAVI": "Ravi Kumar", "U_MALLORY": "Ravi K."},
        **kw,
    )


def _event(text, user="U_MALLORY", ts="1717000099.0", **extra):
    return {"user": user, "text": text, "ts": ts, "team": "T_VENDOR",
            "channel": CHANNEL, "type": "message", **extra}


def _assess(text, user="U_RAVI"):
    """Score a message with the sender already known, so only content is measured."""
    vendor = tools.get_vendor("acme_supplies")
    base = {"known_users": {user}, "known_contacts": set(),
            "on_file_iban": ON_FILE, "available": True}
    return risk.assess({"user": user, "text": text, "ts": "1.0"},
                       signals.detect(text), base, "acme_supplies")


# ------------------------------------------------------- IBAN extraction fail-opens


def test_the_old_account_named_first_does_not_shield_the_new_one():
    """Was: extract_iban returned only the first IBAN. Naming the legitimate account
    before the fraudulent one meant the bank check compared against the account the
    attacker was trying to replace, and passed."""
    text = (f"Our bank account has changed - do not use {ON_FILE} any more, "
            f"please remit invoice 2211 to GB29 NWBK 60161331926819.")
    assert signals.extract_ibans(text) == [ON_FILE, FRAUD]
    result = _assess(text)
    assert result["level"] == "critical", result
    assert result["requested_iban"] == FRAUD, "the mismatching account must be the one carried forward"


def test_a_lowercase_iban_is_still_an_iban():
    """Was: the IBAN regex had no re.I, so a lowercased account number produced no
    signal at all and the MCP check never ran."""
    assert signals.extract_ibans("remit to gb29 nwbk 60161331926819 today") == [FRAUD]


def test_a_following_word_is_not_absorbed_into_the_account_number():
    """Was: greedy matching swallowed the next word ('…926819 THANKS'), producing a
    corrupted IBAN — which then read as a mismatch against a benign confirmation, and
    was written into the verification task."""
    for text in (f"Payment sent to {ON_FILE} THANKS",
                 f"remit to {FRAUD} urgently and keep it confidential",
                 f"Ref {ON_FILE} attached for your records"):
        for iban in signals.extract_ibans(text):
            assert iban in (ON_FILE, FRAUD), f"{iban!r} extracted from {text!r}"


def test_grouped_and_hyphenated_ibans_still_parse():
    assert signals.extract_ibans("IBAN GB29 NWBK 6016 1331 9268 19 please") == [FRAUD]
    assert signals.extract_ibans("Ref DE89-3704-0044-0532-0130-00") == [ON_FILE]


def test_a_short_alphanumeric_token_is_not_mistaken_for_an_account():
    assert signals.extract_ibans("Order DE12 and PO GB44 attached") == []


# --------------------------------------------------------- keyword false positives


def test_ordinary_business_words_do_not_raise_a_fraud_card():
    """Was: substring matching. 'wire' fired on 'wireless', 'ach' on 'attached' and
    'approach'. Posting a red fraud card at a vendor over a shipping note is how a
    tripwire gets muted."""
    for text in ("The wireless units ship today, tracking to follow.",
                 "Invoice 2211 attached, revised copy is now in the drive.",
                 "Our approach has changed slightly on the packaging.",
                 "Please remit invoice 2211 by Friday.",
                 "We reached agreement on the machinery order."):
        assert _assess(text)["level"] not in handlers.POST_LEVELS, text


# ------------------------------------------------------------- evasion / bypasses


def test_an_edited_message_is_scanned():
    """Was: `message_changed` was skipped wholesale. Post something bland, edit it into
    the payment request, and nothing ever looked at it."""
    handlers.reset_state()
    c = _client()
    edit = {
        "type": "message", "subtype": "message_changed", "channel": CHANNEL,
        "ts": "1717000100.0",
        "previous_message": {"text": "hi", "user": "U_MALLORY", "ts": "1717000099.0"},
        "message": {"user": "U_MALLORY", "ts": "1717000099.0", "team": "T_VENDOR",
                    "text": f"Our bank account has changed, remit to IBAN {FRAUD} "
                            "urgently. Keep this confidential."},
    }
    ev = handlers.handle_external_message(c, edit, our_team_id=OUR_TEAM, dry_run=True)
    assert ev is not None, "an edit must be scanned, not skipped"
    assert ev["risk"]["level"] == "critical"
    assert c.called("chat.postMessage")


def test_text_carried_only_in_blocks_is_scanned():
    """Was: is_conversational required a non-empty top-level `text`, so a Block Kit
    message with everything in blocks was skipped."""
    handlers.reset_state()
    event = _event("", blocks=[{"type": "section", "text": {
        "type": "mrkdwn",
        "text": f"Our bank details have changed - remit to {FRAUD} urgently, confidential."}}])
    ev = handlers.handle_external_message(_client(), event, our_team_id=OUR_TEAM, dry_run=True)
    assert ev is not None and ev["risk"]["level"] == "critical"


def test_the_senders_team_decides_internal_versus_external():
    """Was: `team` was preferred over `user_team`. On a Connect message `team` can name
    the host workspace, which would make every external message look internal and be
    skipped — a total, silent fail-open."""
    external = {"user": "U_MALLORY", "text": "hello", "ts": "1.0", "channel": CHANNEL,
                "team": OUR_TEAM, "user_team": "T_VENDOR"}
    assert handlers.should_scan(external, OUR_TEAM) is True

    internal = {"user": "U_US", "text": "hello", "ts": "1.0", "channel": CHANNEL,
                "team": "T_VENDOR", "user_team": OUR_TEAM}
    assert handlers.should_scan(internal, OUR_TEAM) is False


# -------------------------------------------------------------- API contract traps


def test_rts_reads_a_slackresponse_not_just_a_dict():
    """Was: `dict(resp)` on a real SlackResponse raises, because its __iter__ is cursor
    pagination. Every RTS fetch would have failed, been caught upstream, and produced an
    empty baseline — the exact fail-open the module claims to refuse."""
    resp = FakeSlackResponse({"ok": True, "results": {"messages": [
        {"user": "U_RAVI", "text": "hello", "ts": "1.0"}]}})
    assert slack_io._messages_from_rts_response(resp) == [
        {"user": "U_RAVI", "text": "hello", "ts": "1.0"}]

    out = slack_io.fetch_history(_client(), CHANNEL, source="rts")
    assert len(out) == 1, "the RTS path must survive a SlackResponse-shaped reply"


def test_an_unknown_vendor_is_not_reported_as_a_confirmed_mismatch():
    """Was: verify_vendor_bank collapsed 'no record' into match=False. A typo in
    VENDOR_KEY made every IBAN look like confirmed fraud against an empty account, and
    the Verify button filed a GitHub issue asserting it."""
    check = tools.verify_vendor_bank("typo_vendor", FRAUD)
    assert check["match"] is None and check["known"] is False

    vendor_base = {"known_users": {"U_RAVI"}, "known_contacts": set(),
                   "on_file_iban": "", "available": True}
    text = f"Please remit to {FRAUD}."
    scored = risk.assess({"user": "U_RAVI", "text": text, "ts": "1.0"},
                         signals.detect(text), vendor_base, "typo_vendor")
    assert scored["level"] == "low", "an unverifiable account is not evidence of fraud"
    assert any("No bank record on file" in r for r in scored["reasons"]), (
        "but it must be said out loud, not silently skipped")

    verdict = handlers.handle_verify(
        _client(), f'{{"vendor_key":"typo_vendor","iban":"{FRAUD}"}}', CHANNEL)
    assert verdict["task"] is None
    assert "no bank record on file" in verdict["text"].lower()


def test_a_history_outage_does_not_tag_everyone_as_a_new_sender():
    """Was: a failed history fetch left an empty baseline, so every message gained
    'sender not seen before'. The old test asserted only the risk level and could
    never have caught it."""
    handlers.reset_state()
    c = _client(fail={"conversations.history"})
    ev = handlers.handle_external_message(c, _event("Order shipped Friday.", user="U_RAVI"),
                                          our_team_id=OUR_TEAM, dry_run=True)
    assert ev is not None, "an outage must not stop the scan"
    assert ev["baseline_available"] is False
    assert not any("not seen before" in r for r in ev["risk"]["reasons"]), ev["risk"]["reasons"]


def test_a_failed_name_lookup_is_not_cached_forever():
    """Was: display_name cached the fallback, so one transient users.info error pinned
    that person to a raw ID for the life of the process."""
    slack_io.clear_name_cache()
    c = _client()
    assert slack_io.display_name(c, "U_GHOST") == "U_GHOST"
    c.users["U_GHOST"] = "Later Known"
    assert slack_io.display_name(c, "U_GHOST") == "Later Known"


def test_a_button_payload_without_a_channel_is_ignored_not_crashed():
    """Was: body["channel"]["id"] raised KeyError after ack() had already fired, so the
    person who clicked got silence and the app logged a 500."""
    app._dispatch(handlers.handle_verify, _client(), {"actions": [{"value": "{}"}]})
    app._dispatch(handlers.handle_verify, _client(), {})


def test_a_tampered_button_value_does_not_raise():
    """Slack echoes button values back verbatim, so treat them as untrusted input."""
    handlers.handle_mark_safe(_client(), '{"user": 12345}', CHANNEL)
    handlers.handle_verify(_client(), '{"iban": ["not", "a", "string"]}', CHANNEL)
    handlers.handle_verify(_client(), "not json at all", CHANNEL)


# ------------------------------------------------------- the production code path


def test_the_production_path_flags_the_attack():
    """Was: every live-path test passed dry_run=True, exercising signals.detect. app.py
    uses the default dry_run=False, which goes through reasoner.classify — so the path
    that actually runs in production had no end-to-end coverage at all."""
    handlers.reset_state()
    saved = os.environ.pop("ANTHROPIC_API_KEY", None), os.environ.pop("LLM_API_KEY", None)
    try:
        c = _client()
        ev = handlers.handle_external_message(
            c, _event(f"Our bank account has changed, remit to IBAN {FRAUD} urgently. "
                      "Keep this confidential."),
            our_team_id=OUR_TEAM)                    # dry_run defaults to False
        assert ev["risk"]["level"] == "critical", ev["risk"]
        assert c.called("chat.postMessage")
        assert all("confidence" in s for s in ev["signals"])
    finally:
        for name, value in zip(("ANTHROPIC_API_KEY", "LLM_API_KEY"), saved):
            if value is not None:
                os.environ[name] = value


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failed += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:                             # noqa: BLE001
                failed += 1
                print(f"ERROR {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
