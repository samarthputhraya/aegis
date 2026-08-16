"""Reading from Slack: channel history for the relationship baseline, plus name lookups.

Two history sources, selected by ``HISTORY_SOURCE``:

``conversations.history`` (default)
    Enumerates the channel. This is the right tool for a *relationship baseline*, which
    needs every participant who has ever spoken here, not the most relevant ones.

``assistant.search.context`` (``HISTORY_SOURCE=rts``)
    Slack's Real-Time Search API — a permission-aware semantic search interface. Useful
    on a long-running channel where you want the slice of history relevant to the message
    being judged rather than the last N messages.

Method names and arguments below are taken from the Slack docs:

* https://docs.slack.dev/reference/methods/conversations.history/
* https://docs.slack.dev/reference/methods/assistant.search.context/

The RTS *response envelope* is not published in the public reference at the time of
writing, so ``_messages_from_rts_response`` accepts the plausible shapes and raises a
clear error if it sees none of them. That is deliberate: guessing a shape and silently
returning an empty baseline would make Aegis fail open, which for a security tripwire is
the worst possible failure mode.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

DEFAULT_HISTORY_LIMIT = 200

# Message subtypes that are channel noise rather than someone talking.
# `message_changed` is deliberately NOT here — see unwrap().
_SKIP_SUBTYPES = {
    "channel_join", "channel_leave", "channel_topic", "channel_purpose",
    "channel_name", "channel_archive", "channel_unarchive", "bot_message",
    "message_deleted", "channel_convert_to_private", "channel_convert_to_public",
}


def unwrap(raw: dict) -> dict:
    """Return the message that actually needs judging.

    Slack delivers an edit as `{"subtype": "message_changed", "message": {...}}`. Judging
    the envelope means judging empty text, so "post something bland, then edit it into
    the payment request" walks straight past the tripwire. The edited body is what gets
    scanned, carrying the channel and the original timestamp forward.
    """
    if raw.get("subtype") == "message_changed" and isinstance(raw.get("message"), dict):
        inner = dict(raw["message"])
        inner.setdefault("channel", raw.get("channel", ""))
        inner.setdefault("team", raw.get("team", ""))
        inner["ts"] = inner.get("ts") or raw.get("ts", "")
        inner["edited_from"] = (raw.get("previous_message") or {}).get("text", "")
        inner.pop("subtype", None)
        return inner
    return raw


def message_text(raw: dict) -> str:
    """Message text, including text carried only in blocks or attachments.

    A message can have an empty top-level `text` and still say something — Block Kit
    payloads routinely do. Reading only `text` there is another silent bypass.
    """
    parts = [raw.get("text") or ""]

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") in ("mrkdwn", "plain_text") and isinstance(node.get("text"), str):
                parts.append(node["text"])
            elif node.get("type") == "text" and isinstance(node.get("text"), str):
                parts.append(node["text"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(raw.get("blocks"))
    for attachment in raw.get("attachments") or []:
        if isinstance(attachment, dict):
            for key in ("text", "fallback", "pretext", "title"):
                if isinstance(attachment.get(key), str):
                    parts.append(attachment[key])
            walk(attachment.get("blocks"))

    seen, out = set(), []
    for part in parts:
        cleaned = part.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)
    return "\n".join(out)


def sender_team(raw: dict) -> str:
    """The team the *sender* belongs to.

    `user_team` and `source_team` name the author's workspace; on a Slack Connect
    message the top-level `team` can be the host workspace instead. Preferring `team`
    would make every external message look internal and be skipped — a total, silent
    fail-open — so it is consulted last.
    """
    return raw.get("user_team") or raw.get("source_team") or raw.get("team") or ""


def normalize(raw: dict, default_team: str = "") -> dict:
    """Reduce a Slack message payload to the shape the rest of Aegis expects."""
    raw = unwrap(raw)
    return {
        "user": raw.get("user") or raw.get("bot_id") or raw.get("author_user_id") or "",
        "text": message_text(raw),
        "ts": raw.get("ts") or "",
        "team": sender_team(raw) or default_team,
    }


def is_conversational(raw: dict) -> bool:
    """True if this message represents a person saying something."""
    raw = unwrap(raw)
    if raw.get("subtype") in _SKIP_SUBTYPES:
        return False
    if raw.get("bot_id") and not raw.get("user"):
        return False
    return bool(message_text(raw))


# --------------------------------------------------------------------------- history


def fetch_history(client, channel_id: str, limit: int = DEFAULT_HISTORY_LIMIT,
                  source: str = "", query: str = "") -> list:
    """Return normalized prior messages for `channel_id`, oldest first.

    `client` is a slack_sdk WebClient (or anything exposing the same call surface).
    """
    source = (source or os.getenv("HISTORY_SOURCE", "conversations")).lower()
    if source in ("rts", "search", "assistant.search.context"):
        msgs = _history_via_rts(client, channel_id, limit, query)
    else:
        msgs = _history_via_conversations(client, channel_id, limit)
    return sorted(msgs, key=lambda m: m["ts"])


def _history_via_conversations(client, channel_id: str, limit: int) -> list:
    """conversations.history — requires channels:history (or groups:history)."""
    out, cursor = [], None
    while len(out) < limit:
        resp = client.conversations_history(
            channel=channel_id,
            limit=min(200, limit - len(out)),
            **({"cursor": cursor} if cursor else {}),
        )
        for raw in resp.get("messages", []):
            if is_conversational(raw):
                out.append(normalize(raw))
        cursor = (resp.get("response_metadata") or {}).get("next_cursor")
        if not cursor:
            break
    return out


def _history_via_rts(client, channel_id: str, limit: int, query: str) -> list:
    """assistant.search.context — Slack Real-Time Search.

    Requires `search:read.public` (plus `search:read.private` for private channels).
    `limit` is capped at 20 per the API reference.
    """
    resp = client.api_call(
        "assistant.search.context",
        params={
            "query": query or "payment invoice bank account remittance",
            "context_channel_id": channel_id,
            "channel_types": "public_channel,private_channel",
            "content_types": "messages",
            "include_context_messages": "true",
            "limit": str(min(20, limit)),      # the API reference caps this at 20
        },
    )
    return [normalize(m) for m in _messages_from_rts_response(resp) if is_conversational(m)]


def _messages_from_rts_response(resp) -> list:
    """Pull the message list out of an assistant.search.context response.

    The public reference documents the request arguments but not the response envelope,
    so accept the shapes Slack search responses have historically used and fail loudly
    rather than returning an empty list.
    """
    # slack_sdk returns a SlackResponse, whose __iter__ implements cursor pagination —
    # dict(resp) raises rather than giving you the body. The payload is on .data.
    data = resp if isinstance(resp, dict) else getattr(resp, "data", None)
    if not isinstance(data, dict):
        raise RuntimeError(
            f"assistant.search.context returned {type(resp).__name__}, which Aegis "
            "could not read as a response body."
        )

    results = data.get("results")
    if isinstance(results, dict) and isinstance(results.get("messages"), list):
        return results["messages"]
    if isinstance(results, list):
        return results
    for key in ("messages", "context_messages", "items"):
        value = data.get(key)
        if isinstance(value, dict) and isinstance(value.get("matches"), list):
            return value["matches"]
        if isinstance(value, list):
            return value

    raise RuntimeError(
        "Unrecognised assistant.search.context response shape "
        f"(top-level keys: {sorted(data.keys())}). Aegis will not guess at a search "
        "envelope, because an empty baseline would make it fail open. Inspect the live "
        "response and extend aegis/slack_io._messages_from_rts_response, or set "
        "HISTORY_SOURCE=conversations."
    )


# ----------------------------------------------------------------------- name lookups

_NAME_CACHE: dict = {}


def display_name(client, user_id: str) -> str:
    """Human-readable name for a user ID, cached. Falls back to the raw ID."""
    if not user_id:
        return "unknown"
    if user_id in _NAME_CACHE:
        return _NAME_CACHE[user_id]
    try:
        profile = client.users_info(user=user_id).get("user", {})
        name = (profile.get("profile", {}).get("real_name")
                or profile.get("real_name") or profile.get("name") or user_id)
    except Exception as exc:                                  # noqa: BLE001
        # Not cached: a transient users.info error would otherwise pin this person to a
        # raw ID on every warning card and canvas entry for the life of the process.
        log.warning("users.info failed for %s: %s", user_id, exc)
        return user_id
    _NAME_CACHE[user_id] = name
    return name


def clear_name_cache() -> None:
    _NAME_CACHE.clear()
