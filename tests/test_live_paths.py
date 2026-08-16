"""The live Slack paths, driven with a fake client. `python tests/test_live_paths.py`

Covers history retrieval (both sources), the message handler's decisions, the button
handlers, and the Canvas trust log — none of which need credentials or a network.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from fake_slack import FakeSlackClient, msg                              # noqa: E402
from aegis import handlers, slack_io, surfaces                           # noqa: E402
from mcp_server import tools                                             # noqa: E402

ATTACK = ("Hi, please note our bank account has changed. Kindly remit this month's "
          "invoice to IBAN GB29 NWBK 60161331926819. It's urgent - send today before "
          "5pm. Keep this confidential between us.")
BENIGN = "Order #4471 shipped this morning, tracking should hit your inbox shortly."

CHANNEL = "C_CONNECT"
OUR_TEAM = "T_BUYER"


def _client(history=None, **kw):
    return FakeSlackClient(
        history=history if history is not None else [
            msg("U_RAVI", "Invoice 2211 attached, net 30 as usual.", "1717000001.0"),
            msg("U_PRIYA", BENIGN, "1717000002.0"),
        ],
        users={"U_RAVI": "Ravi Kumar", "U_PRIYA": "Priya S", "U_MALLORY": "Ravi K."},
        **kw,
    )


def _event(user, text, ts="1717000099.0", team="T_VENDOR"):
    return {"user": user, "text": text, "ts": ts, "team": team, "channel": CHANNEL,
            "type": "message"}


# --------------------------------------------------------------------- history


def test_history_uses_conversations_history_by_default():
    slack_io.clear_name_cache()
    c = _client()
    out = slack_io.fetch_history(c, CHANNEL, limit=50)
    assert c.called("conversations.history")
    assert [m["user"] for m in out] == ["U_RAVI", "U_PRIYA"]
    assert out[0]["ts"] < out[1]["ts"], "history must come back oldest-first"


def test_history_can_use_rts():
    c = _client()
    out = slack_io.fetch_history(c, CHANNEL, limit=50, source="rts")
    assert c.called("assistant.search.context")
    params = c.calls_to("assistant.search.context")[-1]
    assert params["context_channel_id"] == CHANNEL
    assert int(params["limit"]) <= 20, "RTS caps limit at 20"
    assert len(out) == 2


def test_history_skips_joins_and_bot_noise():
    c = _client(history=[
        msg("U_RAVI", "hello", "1.0"),
        {"user": "U_X", "text": "has joined the channel", "ts": "2.0", "subtype": "channel_join"},
        {"bot_id": "B1", "text": "automated digest", "ts": "3.0"},
        {"user": "U_Y", "text": "", "ts": "4.0"},
    ])
    out = slack_io.fetch_history(c, CHANNEL)
    assert [m["user"] for m in out] == ["U_RAVI"]


def test_unknown_rts_envelope_raises_rather_than_failing_open():
    c = _client()
    c.api_call = lambda method, params=None: {"ok": True, "surprise": {}}
    try:
        slack_io.fetch_history(c, CHANNEL, source="rts")
    except RuntimeError as e:
        assert "will not guess" in str(e)
    else:
        raise AssertionError("expected a RuntimeError instead of an empty baseline")


# ------------------------------------------------------------- message handling


def test_internal_and_bot_messages_are_skipped():
    handlers.reset_state()
    c = _client()
    assert handlers.handle_external_message(
        c, _event("U_US", ATTACK, team=OUR_TEAM), our_team_id=OUR_TEAM) is None
    assert handlers.handle_external_message(
        c, {"bot_id": "B1", "text": ATTACK, "ts": "1.0", "channel": CHANNEL},
        our_team_id=OUR_TEAM) is None
    assert not c.called("chat.postMessage")


def test_benign_external_message_posts_nothing():
    handlers.reset_state()
    c = _client()
    ev = handlers.handle_external_message(c, _event("U_RAVI", BENIGN), our_team_id=OUR_TEAM,
                                          dry_run=True)
    assert ev["risk"]["level"] == "low"
    assert not c.called("chat.postMessage")


def test_attack_posts_a_threaded_warning_and_writes_the_canvas():
    handlers.reset_state()
    c = _client()
    ev = handlers.handle_external_message(c, _event("U_MALLORY", ATTACK),
                                          our_team_id=OUR_TEAM, dry_run=True)
    assert ev["risk"]["level"] == "critical"

    posts = c.calls_to("chat.postMessage")
    assert len(posts) == 1
    assert posts[0]["thread_ts"] == "1717000099.0", "warning should thread under the message"
    blocks = posts[0]["attachments"][0]["blocks"]
    rendered = str(blocks)
    assert "CRITICAL" in rendered
    assert "IBAN" in rendered and "not seen before" in rendered
    assert "Ravi K." in rendered, "the resolved display name should appear"

    md = c.last_canvas_markdown()
    assert "Aegis trust log" in md and "CRITICAL" in md


def test_the_message_being_judged_is_excluded_from_its_own_baseline():
    handlers.reset_state()
    # The sender's only prior appearance is the message under evaluation.
    c = _client(history=[msg("U_MALLORY", ATTACK, "1717000099.0")])
    ev = handlers.handle_external_message(c, _event("U_MALLORY", ATTACK),
                                          our_team_id=OUR_TEAM, dry_run=True)
    joined = " ".join(ev["risk"]["reasons"])
    assert "not seen before" in joined, "a message must not vouch for its own sender"


def test_history_failure_does_not_invent_a_new_sender_alert():
    handlers.reset_state()
    c = _client(fail={"conversations.history"})
    ev = handlers.handle_external_message(c, _event("U_RAVI", BENIGN),
                                          our_team_id=OUR_TEAM, dry_run=True)
    assert ev is not None, "a history outage must not stop the scan"
    assert ev["baseline_available"] is False
    assert not any("not seen before" in r for r in ev["risk"]["reasons"]), (
        "an unreadable history is not evidence that nobody has spoken here")
    assert ev["risk"]["level"] == "low"


def test_a_canvas_failure_does_not_suppress_the_warning():
    handlers.reset_state()
    c = _client(fail={"conversations.canvases.create", "canvases.edit"})
    handlers.handle_external_message(c, _event("U_MALLORY", ATTACK),
                                     our_team_id=OUR_TEAM, dry_run=True)
    assert c.called("chat.postMessage"), "the alert matters more than the audit log"


# ---------------------------------------------------------------------- buttons


def test_verify_button_runs_the_mcp_check_and_opens_a_task():
    handlers.reset_state()
    c = _client()
    ev = handlers.handle_external_message(c, _event("U_MALLORY", ATTACK),
                                          our_team_id=OUR_TEAM, dry_run=True)
    value = surfaces.action_value(ev)

    result = handlers.handle_verify(c, value, CHANNEL, thread_ts="1717000099.0",
                                    actor="U_FINANCE")
    assert result["check"]["match"] is False
    assert result["check"]["on_file_iban"].startswith("DE89")
    assert result["task"] is not None
    assert "does *not* match" in result["text"]
    assert "Do not pay" in result["text"]


def test_verify_button_on_a_matching_iban_does_not_open_a_task():
    handlers.reset_state()
    on_file = tools.get_vendor("acme_supplies")["bank_on_file"]["iban"]
    value = f'{{"vendor_key":"acme_supplies","iban":"{on_file}","ts":"1.0","user":"U_RAVI"}}'
    result = handlers.handle_verify(_client(), value, CHANNEL)
    assert result["check"]["match"] is True
    assert result["task"] is None


def test_mark_safe_trusts_the_sender_for_later_messages():
    handlers.reset_state()
    c = _client(history=[])
    first = handlers.handle_external_message(c, _event("U_MALLORY", ATTACK),
                                             our_team_id=OUR_TEAM, dry_run=True)
    assert "not seen before" in " ".join(first["risk"]["reasons"])

    handlers.handle_mark_safe(c, surfaces.action_value(first), CHANNEL, actor="U_FINANCE")

    second = handlers.handle_external_message(
        c, _event("U_MALLORY", ATTACK, ts="1717000100.0"), our_team_id=OUR_TEAM, dry_run=True)
    assert "not seen before" not in " ".join(second["risk"]["reasons"])
    assert second["risk"]["level"] == "critical", (
        "trusting a person must not clear an IBAN mismatch")


# ----------------------------------------------------------------------- canvas


def test_canvas_is_created_when_absent_and_edited_when_present():
    c = _client(canvas_id="")
    assert surfaces.upsert_trust_log(c, CHANNEL, "# hello") == "F_NEWCANVAS"
    assert c.called("conversations.canvases.create")

    c2 = _client(canvas_id="F_EXISTING")
    assert surfaces.upsert_trust_log(c2, CHANNEL, "# hello") == "F_EXISTING"
    assert c2.called("canvases.edit")
    assert not c2.called("conversations.canvases.create")


def test_canvas_upsert_returns_empty_instead_of_raising():
    c = _client(canvas_id="F_EXISTING", fail={"canvases.edit"})
    assert surfaces.upsert_trust_log(c, CHANNEL, "# hello") == ""


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
