# Security policy

## Status of this project

Aegis is a **prototype**, not production security software. The
[Implementation status](README.md#implementation-status) section of the README lists
exactly what is and isn't wired up. The load-bearing caveats:

- **The demo path has been run live once** (August 2026, two workspaces, Socket Mode):
  the warning card, the MCP bank check behind the Verify button, the canvas trust log, and
  silence on ordinary traffic. That is one run on one small channel — not a soak test, not
  a multi-vendor deployment, and not evidence about your traffic. CI cannot reach Slack, so
  the automated suite says nothing about live behaviour either way.
- Vendor and bank-on-file data is mock data in `mcp_server/data/vendors.json`. There is no
  integration with any real system of record.
- The false-positive rate is measured (0% across 35 benign messages in
  `tests/fixtures/messages.jsonl`) but that corpus is small and was written by the same
  person as the detectors. It is a regression guard, not evidence about your traffic.
- The trust log and "mark safe" decisions are held in memory and reset on restart.

Do not deploy this as a control you rely on.

## Reporting a vulnerability

If you find a security issue in this repository, please report it privately through
[GitHub's private vulnerability reporting](https://github.com/samarthputhraya/aegis/security/advisories/new)
rather than opening a public issue.

Please include reproduction steps and, if relevant, the message text that triggers the
behaviour. Note that reports of the detector *missing* an attack or *over-flagging* a
benign message are welcome as ordinary issues — see `docs/ROADMAP.md` item 1 — and don't
need to go through the private channel.

## Handling secrets

`.env` is gitignored and `.env.example` contains placeholders only. If you ever commit a
real Slack token, GitHub token, or API key, rotate it immediately — rewriting git history
is not sufficient, because the value may already have been fetched.
