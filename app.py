"""Aegis Slack app — a tripwire inside a Slack Connect channel.

On each external message it scores social-engineering risk (signals, a relationship
baseline from channel history, and an on-file bank check via MCP), posts a warning card
with the reasons, and appends the event to a Canvas trust log.

Two entrypoints:

    SLACK_MODE=socket python app.py    # Socket Mode — no public URL needed
    python app.py                      # Flask/HTTP on $PORT, needs a public URL

All the decision logic lives in `aegis/handlers.py` so it can be tested without Slack;
this file is only wiring.
"""
from __future__ import annotations

import logging
import os
import sys

from aegis import handlers

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("aegis.app")


def create_bolt_app():
    """Build the Bolt app. Kept lazy so importing this module needs no credentials."""
    from slack_bolt import App

    token = os.environ.get("SLACK_BOT_TOKEN")
    if not token:
        raise SystemExit(
            "SLACK_BOT_TOKEN is not set. Copy .env.example to .env and fill it in, or "
            "run `python scripts/simulate_attack.py` for the credential-free demo."
        )

    bolt = App(token=token, signing_secret=os.environ.get("SLACK_SIGNING_SECRET"))

    @bolt.event("message")
    def on_message(event, client):
        handlers.handle_external_message(
            client, event,
            our_team_id=os.getenv("OUR_TEAM_ID", ""),
            vendor_key=os.getenv("VENDOR_KEY", "acme_supplies"),
            history_limit=int(os.getenv("HISTORY_LIMIT", "200")),
        )

    @bolt.action("verify_oob")
    def on_verify(ack, body, client):
        ack()
        _dispatch(handlers.handle_verify, client, body)

    @bolt.action("mark_safe")
    def on_mark_safe(ack, body, client):
        ack()
        _dispatch(handlers.handle_mark_safe, client, body)

    return bolt


def _dispatch(fn, client, body: dict) -> None:
    """Pull the bits a button handler needs, tolerating payloads that lack them.

    `ack()` has already fired by the time this runs, so an exception here is invisible
    to the person who clicked — they get silence. Anything optional is read defensively
    and a missing channel is logged rather than raised.
    """
    channel = (body.get("channel") or {}).get("id", "")
    if not channel:
        log.warning("%s: block_actions payload had no channel; ignoring", fn.__name__)
        return
    actions = body.get("actions") or [{}]
    try:
        fn(client,
           action_value=actions[0].get("value", ""),
           channel=channel,
           thread_ts=_thread_ts(body),
           actor=(body.get("user") or {}).get("id", ""))
    except Exception:                                          # noqa: BLE001
        log.exception("%s failed", fn.__name__)


def _thread_ts(body: dict) -> str:
    message = body.get("message") or {}
    return message.get("thread_ts") or message.get("ts") or ""


def create_flask_app(bolt=None):
    """WSGI app for HTTP mode. Exposed for gunicorn: `gunicorn 'app:create_flask_app()'`."""
    from flask import Flask, request
    from slack_bolt.adapter.flask import SlackRequestHandler

    bolt = bolt or create_bolt_app()
    handler = SlackRequestHandler(bolt)
    flask_app = Flask(__name__)

    @flask_app.post("/slack/events")
    def slack_events():
        return handler.handle(request)

    @flask_app.get("/healthz")
    def healthz():
        return {"ok": True}

    return flask_app


def run_socket_mode() -> None:
    from slack_bolt.adapter.socket_mode import SocketModeHandler

    app_token = os.environ.get("SLACK_APP_TOKEN")
    if not app_token:
        raise SystemExit(
            "Socket Mode needs SLACK_APP_TOKEN (an app-level token starting with 'xapp-'). "
            "Generate one under Basic Information -> App-Level Tokens with the "
            "connections:write scope."
        )
    log.info("Starting Aegis in Socket Mode …")
    SocketModeHandler(create_bolt_app(), app_token).start()


def main(argv=None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    socket = "--socket" in argv or os.getenv("SLACK_MODE", "").lower() == "socket"
    if socket:
        run_socket_mode()
    else:
        port = int(os.getenv("PORT", "3000"))
        log.info("Starting Aegis on http://0.0.0.0:%s/slack/events …", port)
        create_flask_app().run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
