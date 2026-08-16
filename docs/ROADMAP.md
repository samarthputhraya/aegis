# Aegis roadmap

Ordered by value. `CLAUDE.md` holds the architectural context; each item below is written
to be self-contained enough to drop into a GitHub issue.

The items that used to head this list — the live message handler, RTS history, the LLM
path, the buttons, the Canvas trust log, Socket Mode — are now implemented. See the
README's [Implementation status](../README.md#implementation-status).

---

## 1. Grow the eval corpus, and make it adversarial

`tests/fixtures/messages.jsonl` currently holds 30 benign and 14 malicious messages,
written by the same person who wrote the detectors. It measures 0% false positives and
0% false negatives, which mostly proves the detectors match their own author's intuitions.

What's needed:

- Real vendor-channel traffic, redacted, as benign cases. Ordinary business messages about
  invoices, remittances and account details are exactly where false positives will come
  from, and none of the current benign cases were written to be hard.
- Attacks that deliberately avoid the vocabulary in `aegis/signals.py`: no "change",
  no "urgent", no IBAN in the same message as the request.
- Multilingual cases, or an explicit decision that Aegis is English-only.
- A held-out split, so tuning against the corpus stops being self-confirming.

Then tighten the gates in `tests/test_eval.py`.

## 2. Close out live verification

The demo path is confirmed working against a real Connect channel (August 2026): warning
card, Verify button, canvas, and no card on ordinary traffic. What that run left open:

- **The `assistant.search.context` response envelope.** Still the one genuinely unverified
  shape in the repo — the live run used the default `conversations.history` source. The
  request arguments are documented; the response is not.
  `slack_io._messages_from_rts_response` accepts the plausible shapes and raises on
  anything else, so the first person to set `HISTORY_SOURCE=rts` will find out
  immediately. Replace the guesswork with the observed shape.
- **Rate limiting.** `fetch_history` paginates with no handling for HTTP 429. A channel
  busier than a demo will hit Slack's limits — see item 7.
- **The `Mark safe` button and HTTP mode**, neither of which the live run touched.
- **A second vendor.** Everything so far has run against the single mock record in
  `mcp_server/data/vendors.json`.

## 3. Persist state

`aegis/handlers.py` keeps the trust log and "mark safe" decisions in module-level dicts,
so both reset on restart. Move them behind a small storage interface with a SQLite
implementation. The trust log in particular is meant to be an audit trail, and an audit
trail that evaporates on deploy isn't one.

## 4. Cross-message reasoning

Every judgement today is made on a single message. A patient attacker introduces
themselves in one message, builds rapport over several, and only then asks for the payment
change — and each message on its own looks fine.

Score the *conversation*: a new sender who becomes payment-relevant within a few messages,
a tone or cadence shift against the baseline, a first-ever mention of banking details from
someone who has only discussed logistics.

## 5. Point `verify_vendor_bank` at a system of record

Right now it reads `mcp_server/data/vendors.json`. Make the source pluggable behind an env
flag — an ERP, a CRM, a finance API — keeping the mock as the default so the demo and
tests still run offline. This is what turns a demo into something deployable.

## 6. Lookalike detection

Detectors for lookalike sender names against known contacts (`Ravi K.` versus `Ravi
Kumar`), lookalike domains in links, and homoglyphs. The current new-sender check is
binary; a name one character away from a trusted contact is a stronger signal than a
genuinely unknown one.

## 7. Rate limiting and backoff

`slack_io.fetch_history` paginates without handling HTTP 429. A busy channel will hit
Slack's rate limits. Respect `Retry-After`, and cache the baseline per channel with a
short TTL rather than re-fetching on every message.

## 8. Packaging and tooling

Add `pyproject.toml`, pin dependencies, split dev requirements, and add a linter and
formatter to CI.
