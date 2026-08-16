"""A minimal fake Slack WebClient, so the live paths are testable with no credentials.

Records every call it receives and replays canned responses. Only the methods Aegis
actually uses are implemented; anything else raises, which is the point — an unexpected
API call should fail a test rather than pass silently.
"""
from __future__ import annotations

import json


class SlackError(Exception):
    """Stands in for slack_sdk.errors.SlackApiError, which formats its message similarly."""


class FakeSlackResponse:
    """Mimics slack_sdk's SlackResponse closely enough to catch the real trap.

    The real class puts the body on `.data` and uses `__iter__`/`__next__` for cursor
    pagination, so `dict(response)` raises instead of giving you the payload. Returning
    plain dicts from a fake is exactly how that bug reaches production untested.
    """

    def __init__(self, data):
        self.data = data

    def __getitem__(self, key):
        return self.data[key]

    def get(self, key, default=None):
        return self.data.get(key, default)

    def __iter__(self):
        return self

    def __next__(self):
        raise StopIteration


class FakeSlackClient:
    def __init__(self, history=None, users=None, canvas_id="", channel_props=None,
                 fail=None):
        self.history = list(history or [])
        self.users = dict(users or {})
        self.canvas_id = canvas_id
        self.channel_props = dict(channel_props or {})
        self.fail = set(fail or ())
        self.calls = []          # [(method, kwargs), ...]

    # -- helpers -----------------------------------------------------------------

    def _record(self, method, **kwargs):
        self.calls.append((method, kwargs))
        if method in self.fail:
            raise SlackError(f"{method} failed: {self.fail}")

    def calls_to(self, method):
        return [kw for name, kw in self.calls if name == method]

    def called(self, method):
        return any(name == method for name, _ in self.calls)

    # -- the Slack surface Aegis uses --------------------------------------------

    def conversations_history(self, channel, limit=200, cursor=None):
        self._record("conversations.history", channel=channel, limit=limit, cursor=cursor)
        return {"ok": True, "messages": self.history, "response_metadata": {}}

    def conversations_info(self, channel):
        self._record("conversations.info", channel=channel)
        props = dict(self.channel_props)
        if self.canvas_id:
            props["canvas"] = {"document_id": self.canvas_id, "is_empty": False}
        return {"ok": True, "channel": {"id": channel, "properties": props}}

    def users_info(self, user):
        self._record("users.info", user=user)
        if user not in self.users:
            raise SlackError("user_not_found")
        return {"ok": True, "user": {"profile": {"real_name": self.users[user]}}}

    def chat_postMessage(self, **kwargs):
        self._record("chat.postMessage", **kwargs)
        return {"ok": True, "ts": "9999.0001"}

    def api_call(self, method, params=None):
        params = params or {}
        self._record(method, **params)
        if method == "conversations.canvases.create":
            if self.canvas_id:
                raise SlackError("channel_canvas_already_exists")
            self.canvas_id = "F_NEWCANVAS"
            return {"ok": True, "canvas_id": self.canvas_id}
        if method == "canvases.edit":
            return {"ok": True}
        if method == "assistant.search.context":
            return FakeSlackResponse({"ok": True, "results": {"messages": self.history}})
        raise SlackError(f"unexpected method {method}")

    # -- assertions used by tests -------------------------------------------------

    def last_canvas_markdown(self):
        edits = self.calls_to("canvases.edit")
        creates = self.calls_to("conversations.canvases.create")
        if edits:
            return json.loads(edits[-1]["changes"])[0]["document_content"]["markdown"]
        if creates:
            return json.loads(creates[-1]["document_content"])["markdown"]
        return ""


def msg(user, text, ts, team="T_VENDOR", **extra):
    return {"user": user, "text": text, "ts": ts, "team": team, **extra}
