"""Signal classification via an LLM, with the offline detector as the floor.

`classify(message)` returns the same signal-list shape as `signals.detect`, with an
added `confidence` (0–1) per signal. Two providers:

* **Anthropic** (default when `ANTHROPIC_API_KEY` is set) — the Messages API.
* **Generic** — any endpoint accepting `{model, prompt, response_format}` and returning
  `{"output": "<json string>"}`, configured by `LLM_URL` + `LLM_API_KEY`.

Design notes, both deliberate:

1. **The offline detector is a floor, not an alternative.** `signals.detect` runs on
   every message regardless of provider, and the model's output is unioned on top. The
   model can add signals or raise confidence; it can never remove one or talk a score
   down. Otherwise a model that returns `[]` — because it was truncated, refused, or
   because the message contained instructions aimed at it — would silently disarm the
   tripwire. A prompt injection in a vendor message is a realistic attack here, and the
   floor is what makes it survivable.
2. **IBANs are extracted by regex and checksum, never reported by the model**, which is
   why the prompt tells it not to. Transcribing a 22-character account number is a task
   models fail at occasionally and silently.
3. **Any provider failure falls back to the offline detector** and logs a warning. A
   fraud tripwire that goes blind because an API returned 503 is worse than one running
   on keywords.
"""
from __future__ import annotations

import json
import logging
import os
import re

from aegis import signals

log = logging.getLogger(__name__)

VALID_TYPES = {"payment_change", "credential_request", "urgency", "secrecy",
               "out_of_band_redirect", "iban_present"}

SYSTEM = (
    "You are Aegis, a security tripwire in a Slack Connect channel between two "
    "companies. Classify the message for social-engineering signals.\n\n"
    "Return STRICT JSON: a list of objects {\"type\", \"evidence\", \"confidence\"} where "
    "type is one of [payment_change, credential_request, urgency, secrecy, "
    "out_of_band_redirect], evidence is the shortest verbatim span from the message that "
    "justifies the signal, and confidence is a number from 0 to 1.\n\n"
    "out_of_band_redirect means pushing the conversation somewhere this channel cannot "
    "see it — 'email me directly instead', 'text me', 'let's take this offline'.\n\n"
    "Include a signal only if it is actually present. Paraphrases count: 'send the "
    "remittance to our updated account' is a payment_change even with no keyword match. "
    "Routine business talk about invoices, deliveries or schedules is NOT a signal. "
    "Do not report IBANs; those are extracted separately. Return [] if nothing applies."
)


def _provider() -> str:
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.getenv("LLM_API_KEY"):
        return "generic"
    return "offline"


def classify(message: dict) -> list:
    """Classify one message. Never raises on provider failure."""
    text = message.get("text", "")
    provider = _provider()

    if provider == "offline":
        return _with_default_confidence(signals.detect(text))

    try:
        model_signals = _call_anthropic(text) if provider == "anthropic" else _call_generic(text)
    except Exception as exc:                                  # noqa: BLE001
        log.warning("LLM classification failed (%s); falling back to the offline "
                    "detector: %s", provider, exc)
        model_signals = []

    return merge(model_signals, text)


# ------------------------------------------------------------------------- providers


def _call_anthropic(text: str) -> list:
    import httpx

    resp = httpx.post(
        os.getenv("LLM_URL") or "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": os.getenv("LLM_MODEL", "claude-sonnet-4-5"),
            "max_tokens": 1024,
            "system": SYSTEM,
            "messages": [{"role": "user", "content": f"MESSAGE:\n{text}"}],
        },
        timeout=30,
    )
    resp.raise_for_status()
    parts = resp.json().get("content", [])
    raw = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
    return _coerce(raw)


def _call_generic(text: str) -> list:
    import httpx

    url = os.getenv("LLM_URL")
    if not url:
        raise RuntimeError(
            "LLM_API_KEY is set but LLM_URL is not. Point LLM_URL at an endpoint that "
            'accepts {model, prompt, response_format} and returns {"output": "<json>"}, '
            "or set ANTHROPIC_API_KEY to use the Anthropic Messages API instead."
        )
    resp = httpx.post(
        url,
        headers={"Authorization": f"Bearer {os.environ['LLM_API_KEY']}"},
        json={
            "model": os.getenv("LLM_MODEL", "default"),
            "prompt": SYSTEM + "\n\nMESSAGE:\n" + text,
            "response_format": "json",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return _coerce(resp.json().get("output", "[]"))


# --------------------------------------------------------------------------- parsing


def _coerce(raw) -> list:
    """Parse and validate a model response into a clean signal list."""
    if isinstance(raw, str):
        raw = raw.strip()
        # Models like wrapping JSON in fences even when told not to.
        fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", raw, re.S)
        if fence:
            raw = fence.group(1)
        raw = json.loads(raw or "[]")

    if isinstance(raw, dict):
        raw = raw.get("signals", [])
    if not isinstance(raw, list):
        raise ValueError(f"expected a JSON list of signals, got {type(raw).__name__}")

    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        stype = item.get("type")
        if stype not in VALID_TYPES or stype == "iban_present":
            continue                       # unknown types dropped; IBANs handled by regex
        try:
            conf = float(item.get("confidence", 1.0))
        except (TypeError, ValueError):
            conf = 1.0
        out.append({
            "type": stype,
            "evidence": str(item.get("evidence", ""))[:200],
            "confidence": min(1.0, max(0.0, conf)),
        })
    return out


def merge(model_signals: list, text: str) -> list:
    """Union the model's signals over the deterministic ones. Never subtracts.

    For a type both found, the higher confidence wins and the model's evidence is
    preferred (it quotes the message rather than naming a keyword). Every IBAN comes
    from `signals.extract_ibans`, checksum-validated; model-reported IBANs were already
    dropped in `_coerce`.
    """
    merged: dict = {}

    for s in _with_default_confidence(signals.detect(text)):
        if s["type"] == "iban_present":
            continue                                   # handled below, may be several
        merged[s["type"]] = s

    for s in model_signals:
        if s["type"] == "iban_present":
            continue
        existing = merged.get(s["type"])
        if existing is None:
            merged[s["type"]] = s
        else:
            merged[s["type"]] = {
                "type": s["type"],
                "evidence": s["evidence"] or existing["evidence"],
                "confidence": max(existing["confidence"], s["confidence"]),
            }

    out = list(merged.values())
    out.extend({"type": "iban_present", "evidence": iban, "confidence": 1.0}
               for iban in signals.extract_ibans(text))
    return out


def _with_default_confidence(sigs: list) -> list:
    return [{**s, "confidence": s.get("confidence", 1.0)} for s in sigs]
