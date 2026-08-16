"""Detect social-engineering signals in a message (offline detector).

The deterministic floor under the system: `reasoner.classify()` uses a model to catch
paraphrases this misses, but this always runs, needs no credentials, and produces the
same signal shape. Pure stdlib.

Signals produced:

``payment_change``          a request to change where money goes
``credential_request``      a request for a password, OTP, token or similar
``urgency``                 time pressure
``secrecy``                 a request to keep the exchange quiet
``out_of_band_redirect``    a push to continue somewhere Slack can't see
``iban_present``            one or more IBANs, extracted exactly and checksum-validated

Two things worth knowing about the matching:

* Keywords match on **word boundaries**, not substrings. "wire" must not fire on
  "wireless units", and "ach" must not fire on "attached" — a fraud card posted at a
  vendor over a shipping note is how a tripwire gets switched off.
* "Change" indicators are matched as **stems** (`chang` → changed/changing/change), so
  they carry a leading boundary only.
"""
from __future__ import annotations

import re

# Terms that put the message in the domain of money movement.
_PAY = ["bank account", "bank details", "banking details", "account number", "iban",
        "routing", "routing number", "swift", "bic", "sort code", "remit", "remittance",
        "wire", "wire transfer", "ach", "payment details", "payment information",
        "beneficiary", "payee"]

# Stems indicating something is being changed. Prefix-matched.
#
# A bare "new" is deliberately NOT in this list. It is prefix-matched, so it fires on
# "news", "newsletter", "newly" and "Newcastle"; and because a change stem only has to
# appear somewhere in the same message as a payment term — there is no proximity
# requirement — "New invoice attached, please remit by end of day" scored `high` and
# posted a fraud card. That is one of the most ordinary sentences in vendor
# correspondence. The eval corpus missed it because no benign row happened to pair
# "new" with a payment term, which is exactly the blind spot a same-author corpus has.
# Pinned by test_a_new_invoice_is_not_a_payment_change.
_CHG = ["chang", "updat", "different", "switch", "moved", "note our",
        "are now", "is now", "revised", "amend", "no longer use", "instead of our",
        # "new" only where it is already bound to something money-moving
        "new bank", "new account", "new iban", "new beneficiary", "new payee",
        "new remittance", "new payment", "new routing", "new sort code", "new swift"]

_CRED = ["password", "mfa", "2fa", "otp", "one-time", "one time password", "credential",
         "credentials", "login", "log-in", "access token", "api key", "ssn",
         "share your", "passcode", "verification code", "security code"]

_URG = ["urgent", "urgently", "asap", "today", "before 5", "before eod", "by eod",
        "by end of day", "end of day", "immediately", "right now", "time-sensitive",
        "time sensitive", "cannot wait", "can't wait", "overdue", "before close of business"]

_SEC = ["confidential", "confidentially", "between us", "keep this quiet",
        "keep it quiet", "don't tell", "do not tell", "discreet", "discreetly",
        "not to mention", "without involving", "before the announcement",
        "until the announcement", "off the record"]

# Pushing the conversation somewhere the channel — and therefore Aegis — can't see.
# Deliberately narrow: "send me an email" in isolation is ordinary business.
_OOB = ["email me directly", "email me instead", "email me rather", "rather than the channel",
        "outside of slack", "outside slack", "off slack", "text me on", "whatsapp me",
        "message me on whatsapp", "call me on my", "my personal email", "my private email",
        "reply to my personal", "let's take this offline", "lets take this offline",
        "continue this over email", "contact me directly at"]


def _compile_words(keywords):
    """Whole-word alternation, longest first so 'wire transfer' wins over 'wire'."""
    parts = sorted((re.escape(k) for k in keywords), key=len, reverse=True)
    return re.compile(r"(?<![\w-])(?:" + "|".join(parts) + r")(?![\w-])", re.I)


def _compile_stems(keywords):
    """Prefix alternation: 'chang' matches changed/changing, but not 'exchange'."""
    parts = sorted((re.escape(k) for k in keywords), key=len, reverse=True)
    return re.compile(r"(?<![\w-])(?:" + "|".join(parts) + r")", re.I)


_RE_PAY = _compile_words(_PAY)
_RE_CHG = _compile_stems(_CHG)
_RE_CRED = _compile_words(_CRED)
_RE_URG = _compile_words(_URG)
_RE_SEC = _compile_words(_SEC)
_RE_OOB = _compile_words(_OOB)


def _hit(pattern, text):
    m = pattern.search(text)
    return m.group(0).lower() if m else None


# ------------------------------------------------------------------------------ IBANs

_TOKEN = re.compile(r"[A-Za-z0-9]+")
_IBAN_START = re.compile(r"^[A-Za-z]{2}\d{2}")


def _mod97_ok(iban: str) -> bool:
    """ISO 13616 / ISO 7064 MOD-97-10 check."""
    if not 15 <= len(iban) <= 34:
        return False
    rotated = iban[4:] + iban[:4]
    digits = []
    for ch in rotated:
        if ch.isdigit():
            digits.append(ch)
        elif ch.isalpha():
            digits.append(str(ord(ch.upper()) - 55))     # A=10 … Z=35
        else:
            return False
    return int("".join(digits)) % 97 == 1


def _absorbable(token: str) -> bool:
    """Can this token be part of an IBAN written in groups?

    IBAN groups are conventionally four characters ("GB29 NWBK 6016 …"), and the
    account portion is digit-bearing. An ordinary English word is neither, which is
    what stops "…926819 urgently and keep this confidential" from being read as one
    31-character account number. The checksum alone is not enough to prevent that:
    mod-97 passes by chance roughly one time in ninety-seven, so the more candidate
    strings we test, the more likely a nonsense match becomes. Testing fewer, better
    candidates is the actual defence.
    """
    return len(token) <= 4 or any(c.isdigit() for c in token)


def extract_ibans(text: str) -> list:
    """Every checksum-valid IBAN in the message, uppercased and de-spaced, in order.

    Returns *all* of them, not the first. A BEC message that names the legitimate
    account before the fraudulent one ("do not use DE89…, remit to GB29…") would
    otherwise be checked against the account it was trying to replace, and pass.
    """
    tokens = list(_TOKEN.finditer(text))
    found, seen = [], set()

    for i, token in enumerate(tokens):
        if not _IBAN_START.match(token.group(0)):
            continue

        # Grow the candidate one token at a time, but only across a single space or
        # hyphen, and only over tokens that could plausibly be IBAN groups.
        pieces = [token.group(0)]
        end = token.end()
        for nxt in tokens[i + 1:]:
            gap = text[end:nxt.start()]
            if gap not in (" ", "-", ""):
                break
            if not _absorbable(nxt.group(0)):
                break
            if sum(len(p) for p in pieces) + len(nxt.group(0)) > 34:
                break
            pieces.append(nxt.group(0))
            end = nxt.end()

        # Longest first, evaluated only at group boundaries.
        for cut in range(len(pieces), 0, -1):
            candidate = "".join(pieces[:cut]).upper()
            if _mod97_ok(candidate):
                if candidate not in seen:
                    seen.add(candidate)
                    found.append(candidate)
                break
    return found


def extract_iban(text: str):
    """First valid IBAN, or None. Kept for callers that only want one."""
    ibans = extract_ibans(text)
    return ibans[0] if ibans else None


# ---------------------------------------------------------------------------- detector


def detect(text: str) -> list:
    sigs = []

    pay = _hit(_RE_PAY, text)
    chg = _hit(_RE_CHG, text)
    if pay and chg:
        sigs.append({"type": "payment_change", "evidence": f"{pay} / {chg}"})

    for pattern, stype in ((_RE_CRED, "credential_request"), (_RE_URG, "urgency"),
                           (_RE_SEC, "secrecy"), (_RE_OOB, "out_of_band_redirect")):
        hit = _hit(pattern, text)
        if hit:
            sigs.append({"type": stype, "evidence": hit})

    for iban in extract_ibans(text):
        sigs.append({"type": "iban_present", "evidence": iban})
    return sigs
