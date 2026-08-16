# CLAUDE.md — Aegis (build context for Claude Code)

> Read this first. It's the full context for continuing Aegis in Claude Code:
> what it is, what's real vs stubbed, the #1 priority, how to run it, and the
> ordered punch list.
>
> The README's [Implementation status](README.md#implementation-status) section is the
> canonical statement of what works; `docs/ROADMAP.md` is the current ordered backlog.
> This file is the architectural context behind both.

## What we're building
**Aegis** — a social-engineering / vendor-fraud **tripwire for Slack Connect**.
It sits in the shared channel between our org and an external party, builds a
relationship **baseline** from the channel (Slack **Real-Time Search**), reads each
external message for social-engineering signals (**Slack AI**), checks any requested
bank details against what's **on file** (**MCP**), and posts a real-time **warning**
with reasons + a one-tap out-of-band verification.

- **Origin:** built for the Slack Agent Builder Challenge (Devpost), New Slack Agent
  track. That submission window closed on 2026-07-13; the rubric notes below are kept as
  design rationale, not as a live deadline.
- **Must use ≥1 of:** Slack AI, MCP, Real-Time Search. We use **all three**.
- **Positioning:** trust & safety lane (uncrowded at hackathons). Honest prior art:
  Abnormal AI / DoControl do *platform-level* Slack security; our edge is the
  *focused, in-channel, RTS-baseline agent*. Don't claim we invented Slack security.

## Architecture / module map
```
aegis/signals.py       Deterministic detector (payment_change, credential_request, urgency,
                       secrecy, out_of_band_redirect, iban_present). The floor — always runs.
aegis/reasoner.py      LLM classification (Anthropic Messages API, or a generic endpoint).
                       Validates untrusted model output; falls back to signals.detect on
                       any provider failure. Regex IBAN is merged in, never model-reported.
aegis/slack_io.py      Channel history via conversations.history (default) or
                       assistant.search.context / RTS (HISTORY_SOURCE=rts); name lookups.
aegis/baseline.py      Relationship baseline (known users/contacts, IBAN on file).
aegis/risk.py          Confidence-weighted scoring + MCP bank check -> level + reasons.
aegis/surfaces.py      Block Kit card + Canvas trust log builders, and their senders.
aegis/orchestrator.py  scan(thread) / evaluate(message,...) — the main loop.
aegis/handlers.py      Live decision logic, Bolt-free so it is testable with a fake client.
app.py                 Bolt wiring only: Socket Mode + Flask/HTTP entrypoints.
mcp_server/server.py   FastMCP: get_vendor, verify_vendor_bank, open_verification_task.
mcp_server/tools.py    Tool bodies over mock data (verify_vendor_bank is the crux check).
scripts/               simulate_attack.py (creds-free demo), start_socket_mode.sh
tests/                 run_all.py + test_detection / test_reasoner / test_live_paths /
                       test_regressions / test_eval. fake_slack.py drives the live paths
                       and mimics SlackResponse, not a plain dict. 51 tests.
```

## What's REAL vs TODO
- ✅ Signal detection, LLM classification with fallback, history retrieval (both sources),
  confidence-weighted risk scoring, MCP bank check, live message handling, both buttons,
  Canvas trust log, Socket Mode + HTTP entrypoints, 51 offline tests, a labeled eval set.
- ✅ **Demo path verified live** (Aug 2026, two workspaces, Socket Mode): warning card,
  Verify button + MCP check, canvas trust log, and silence on ordinary traffic.
- 🔧 Not covered by that run: the RTS history source, HTTP mode, the Mark safe button,
  a second vendor, sustained operation, or rate limiting. See docs/E2E.md.
- 🔧 The `assistant.search.context` **response envelope** is not published. `slack_io`
  accepts plausible shapes and RAISES on anything else — deliberately, because an empty
  baseline would make Aegis fail open. Replace with the real shape once observed.
- 🔧 State (trust log, mark-safe decisions) is in-memory and resets on restart.
- 🔧 `verify_vendor_bank` reads mock JSON; point it at a system of record for real use.

## #1 PRIORITY — false positives
This is a security agent; **crying wolf kills it**. `tests/test_eval.py` measures the
rate against `tests/fixtures/messages.jsonl` and fails CI on regression. Currently 0% FP
and 0% FN across 30 benign and 14 malicious cases, measured both warm (sender known) and
cold (new channel) — but that corpus was written by the same person as the detectors, so
treat it as a regression guard, not evidence. Growing it with real redacted traffic is
roadmap item 1. Add a test for every new signal, and ALWAYS show
the reasons on the card.

## Run it
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/simulate_attack.py     # replays the BEC attempt, shows the flag
python tests/run_all.py               # 51 tests — must stay green
python -m mcp_server.server           # MCP server
bash scripts/start_socket_mode.sh     # live, Socket Mode (needs .env)
```

## Slack setup
Full walkthrough in **docs/E2E.md**. In short: two sandbox workspaces with a Slack
Connect channel between them, one app installed to both, Socket Mode, and bot scopes
`chat:write`, `channels:read`, `channels:history`, `users:read`, `canvases:write`
(plus `search:read.public` only if `HISTORY_SOURCE=rts`). Drive via events and buttons —
slash commands don't cross the org boundary.

## Judging rubric (optimize for this; tie-break order matters)
1. **Technological Implementation** (also the tie-breaker + a bonus prize) — real RTS
   baseline + Slack AI + MCP; clean code; tests.
2. **Design** — clear warning UX + Canvas trust log.
3. **Potential Impact** — BEC ≈ $4.67M/incident; every org with vendors in Slack.
4. **Quality of Idea** — trust & safety agent; not another productivity bot.

## Conventions / guardrails
- Keep pure builders + deterministic offline stand-ins so tests run without creds.
- Never fabricate Slack API method names/signatures — check the docs and verify at runtime.
  Where a shape genuinely isn't documented (the RTS response envelope), raise loudly
  rather than guessing: a tripwire that fails open is worse than one that crashes.
- Add/keep tests green; add a test with each new signal or risk rule.
- Secrets only in `.env`. Don't log message contents in production.

## Punch list
Lives in **docs/ROADMAP.md** now. Top of the list: grow the eval corpus with real redacted
traffic so the 0%/0% numbers mean something, then close out the parts of live verification
the first run didn't touch — chiefly the RTS response envelope and rate limiting.
