"""Slack surfaces: the Block Kit warning card, the Canvas trust log, and their senders.

The builders (`warning_blocks`, `trust_log_md`) are pure — they take data and return
Slack payloads, so they can be tested without a client. The senders (`post_warning`,
`upsert_trust_log`) are the only things here that touch the network.

Canvas method names and behaviour are per the Slack docs:

* https://docs.slack.dev/reference/methods/conversations.canvases.create/
* https://docs.slack.dev/reference/methods/canvases.edit/
* `conversations.canvases.create` returns `channel_canvas_already_exists` when the
  channel already has one; the existing id lives at `channel.properties.canvas` in a
  `conversations.info` response.
"""
from __future__ import annotations

import json
import logging
import os

log = logging.getLogger(__name__)

_ICON = {"critical": ":red_circle:", "high": ":red_circle:",
         "medium": ":large_yellow_circle:", "low": ":white_circle:"}

_ACCENT = {"critical": "#B00020", "high": "#D93025",
           "medium": "#F2A93B", "low": "#5B7083"}

TRUST_LOG_TITLE = "Aegis trust log"


def _when(ts: str) -> str:
    """Render a timestamp as a date. Slack sends epoch seconds ("1717000099.000100");
    the offline fixtures use ISO strings. Show something readable either way."""
    ts = str(ts or "")
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return ts[:16] or "unknown time"


def _who(message: dict) -> str:
    """Render the sender as a Slack mention when we have an ID, else a plain name."""
    display = message.get("display")
    user = message.get("user", "")
    if user.startswith(("U", "W")) and len(user) >= 9:
        return f"<@{user}>" + (f" ({display})" if display and display != user else "")
    return display or user or "unknown"


# --------------------------------------------------------------------------- builders


def action_value(event: dict) -> str:
    """Compact JSON payload carried on the buttons, so handlers need no side channel."""
    m, r = event["message"], event["risk"]
    return json.dumps({
        "vendor_key": r.get("vendor_key", ""),
        "iban": r.get("requested_iban") or "",
        "ts": m.get("ts", ""),
        "user": m.get("user", ""),
        "level": r.get("level", ""),
    }, separators=(",", ":"))[:2000]     # Slack caps button values at 2000 chars


def warning_blocks(event: dict) -> list:
    m, r = event["message"], event["risk"]
    reasons = "\n".join(f"• {x}" for x in r["reasons"])
    value = action_value(event)
    text = m.get("text", "")
    quoted = "\n".join(f">{line}" for line in (text.splitlines() or [""]))

    return [
        {"type": "header", "text": {"type": "plain_text",
            "text": f"{_ICON[r['level']]} {r['level'].upper()}: possible vendor-payment fraud"}},
        {"type": "context", "elements": [{"type": "mrkdwn",
            "text": f"Aegis scored this *{r['score']}*. Do not action any payment change "
                    "until it is verified on a channel other than Slack."}]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*From* {_who(m)}\n{quoted}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Why Aegis flagged this*\n{reasons}"}},
        {"type": "actions", "elements": [
            {"type": "button", "style": "primary", "action_id": "verify_oob",
             "text": {"type": "plain_text", "text": "Verify out-of-band"}, "value": value},
            {"type": "button", "action_id": "mark_safe",
             "text": {"type": "plain_text", "text": "Mark safe"}, "value": value},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn",
            "text": f"Logged to the *{TRUST_LOG_TITLE}* canvas on this channel."}]},
    ]


def warning_attachments(event: dict) -> list:
    """Severity-coloured wrapper. Slack only renders a colour bar via attachments."""
    level = event["risk"]["level"]
    return [{"color": _ACCENT.get(level, _ACCENT["low"]), "blocks": warning_blocks(event)}]


def trust_log_md(vendor: dict, events: list) -> str:
    L = [f"# {TRUST_LOG_TITLE} — {vendor.get('vendor','Vendor')}", "",
         f"**Bank on file:** {vendor.get('bank_on_file',{}).get('iban','-')} "
         f"(since {vendor.get('bank_on_file',{}).get('updated','-')})", ""]
    if not events:
        L.append("_No risks detected._")
        return "\n".join(L) + "\n"
    L.append("## Flagged events")
    for e in events:
        m, r = e["message"], e["risk"]
        display = m.get("display") or m.get("user", "")
        L.append(f"### {_ICON[r['level']]} {r['level'].upper()} — {_when(m.get('ts'))} · {display}")
        L.append(f"> {m['text']}")
        for x in r["reasons"]:
            L.append(f"- {x}")
        L.append("")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------- senders


def _client():
    from slack_sdk import WebClient
    return WebClient(token=os.environ["SLACK_BOT_TOKEN"])


def post_warning(channel: str, event: dict, thread_ts: str = "", client=None):
    """Post the warning card. Threads under the offending message when `thread_ts` is set."""
    client = client or _client()
    kwargs = {"channel": channel,
              "attachments": warning_attachments(event),
              "text": f"Aegis: {event['risk']['level'].upper()} vendor-payment fraud warning"}
    if thread_ts:
        kwargs["thread_ts"] = thread_ts
    return client.chat_postMessage(**kwargs)


def find_channel_canvas(client, channel_id: str) -> str:
    """Existing channel-canvas id via conversations.info, or "" if there isn't one."""
    try:
        channel = client.conversations_info(channel=channel_id).get("channel", {})
    except Exception as exc:                                  # noqa: BLE001
        log.warning("conversations.info failed for %s: %s", channel_id, exc)
        return ""
    canvas = (channel.get("properties") or {}).get("canvas") or {}
    return canvas.get("document_id") or canvas.get("file_id") or ""


def upsert_trust_log(client, channel_id: str, markdown: str, title: str = TRUST_LOG_TITLE) -> str:
    """Create the channel canvas if absent, otherwise replace its contents.

    Returns the canvas id, or "" if the workspace/app can't do canvases (missing
    `canvases:write`, a plan without canvases, and so on). Never raises: failing to
    write an audit log must not stop the warning from being posted.
    """
    content = {"type": "markdown", "markdown": markdown}

    canvas_id = find_channel_canvas(client, channel_id)
    if not canvas_id:
        try:
            resp = client.api_call("conversations.canvases.create", params={
                "channel_id": channel_id,
                "title": title,
                "document_content": json.dumps(content),
            })
            canvas_id = (resp or {}).get("canvas_id", "")
            if canvas_id:
                return canvas_id
        except Exception as exc:                              # noqa: BLE001
            if "channel_canvas_already_exists" not in str(exc):
                log.warning("conversations.canvases.create failed for %s: %s", channel_id, exc)
                return ""
            canvas_id = find_channel_canvas(client, channel_id)

    if not canvas_id:
        log.warning("no canvas id available for channel %s; trust log not written", channel_id)
        return ""

    try:
        client.api_call("canvases.edit", params={
            "canvas_id": canvas_id,
            "changes": json.dumps([{"operation": "replace", "document_content": content}]),
        })
    except Exception as exc:                                  # noqa: BLE001
        log.warning("canvases.edit failed for %s: %s", canvas_id, exc)
        return ""
    return canvas_id
