# Contributing to Aegis

Thanks for looking. Aegis is a working prototype, not a finished product — the
[Implementation status](README.md#implementation-status) section is honest about what is
and isn't wired up, and `docs/ROADMAP.md` lists the open work in priority order.

## Getting set up

```bash
git clone https://github.com/samarthputhraya/aegis.git
cd aegis
python -m venv .venv
source .venv/bin/activate          # Windows (Git Bash): source .venv/Scripts/activate
pip install -r requirements.txt
python tests/run_all.py            # should print 32 PASS lines
```

No credentials are needed for the tests or the offline demo.

## Ground rules

- **Keep the offline path working.** `signals.detect()`, the risk scorer, and the pure
  Block Kit / Canvas builders must stay dependency-light and runnable with no API keys, so
  the test suite and demo never need credentials.
- **Every new signal or scoring rule needs a test**, plus a case in
  `tests/fixtures/messages.jsonl`. CI runs the full suite on Python 3.10–3.12 and gates
  on the measured false-positive and false-negative rates; both have to stay green.
- **Slack interactions are tested with `tests/fake_slack.py`**, not mocks scattered
  through the tests. If you touch a new Slack method, add it there — an unexpected API
  call should fail a test rather than pass silently.
- **Don't invent Slack API method names.** Check them against the Slack docs and verify at
  runtime. Several parts of this repo are unfinished precisely because the API shape wasn't
  confirmed, and a plausible-looking wrong method name is worse than a TODO.
- **False positives are the priority.** This is a security tool; crying wolf makes it
  useless. If a change widens detection, it should come with evidence about what it does to
  the false-positive rate.
- **Never log message contents** in any production path, and never commit secrets — `.env`
  is gitignored, and `.env.example` should only ever contain placeholders.

## Where help is most useful

1. **Adversarial eval cases.** `tests/fixtures/messages.jsonl` measures 0% false positives
   and 0% false negatives — which mostly proves the detectors match their own author's
   intuitions. Benign messages that trip it, or attacks that slip past, are the single
   most valuable contribution. Redacted real vendor-channel traffic especially.
2. **Running it against a live workspace** and reporting what breaks. Every Slack call is
   tested against a fake client; none has touched a real workspace. `docs/E2E.md` is the
   walkthrough.
3. **The RTS response envelope.** `assistant.search.context`'s response shape isn't in the
   public docs, so `aegis/slack_io._messages_from_rts_response` accepts plausible shapes
   and raises otherwise. If you've seen a real one, replace the guesswork.

See `docs/ROADMAP.md` for the full list.

## Pull requests

Small and focused beats large and sweeping. Describe what you changed, why, and how you
tested it. If the change touches detection behaviour, say what it does to the sample thread
in `scripts/sample_thread.json`.
