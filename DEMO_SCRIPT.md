# Aegis — 3-minute demo script (the "caught the fraud live" beat)

Two sandbox workspaces with a Slack Connect channel ("Us ⇄ Acme Supplies").
Sample thread pre-loaded. Judges may stop at 3:00 — the flag fires by 1:30.

| Time | On screen | Say |
|---|---|---|
| 0:00–0:18 | Title: "Aegis — the fraud tripwire for Slack Connect" | "Companies now run vendor relationships in Slack Connect. Attackers know it — they slip into a real thread and ask finance to 'update our bank account, urgently.' Business email compromise costs ~$4.67M an incident. Email tools don't watch Slack. Aegis does." |
| 0:18–0:45 | The normal thread (order updates from Ravi at Acme Supplies) | "Here's a healthy vendor channel — order updates, delivery questions. Aegis quietly learns the baseline: who normally talks here, and the bank details on file." |
| 0:45–1:30 | A new message: "note our bank account has changed… remit to IBAN GB29…, urgent, today, keep confidential" → 🔴 warning card appears | "Now the attack. Looks plausible. Aegis flags it **critical**, in real time, with the reasons: payment-detail change, **requested IBAN ≠ the one on file**, urgency pressure, a secrecy cue — and the sender is **'Ravi K.', not the Ravi we've talked to for months.**" |
| 1:30–2:10 | Click "Verify out-of-band" → MCP check shows mismatch; verification task opened | "One tap. Aegis calls our finance system over MCP, confirms the IBAN doesn't match, and opens an out-of-band verification before a cent moves." |
| 2:10–2:40 | Canvas trust log | "Every flag lands in a shared trust log — an audit trail both sides can see." |
| 2:40–3:00 | Recap slide | "A behavioral baseline from Slack's own data via Real-Time Search, reasoning with Slack AI, action over MCP — catching the most expensive attack on Slack Connect, live. That's Aegis." |

**Pre-empt the judge question** ("doesn't Abnormal do Slack security?") on a slide:
*"Security platforms scan from outside; Aegis is the in-channel agent with the
relationship baseline — and it's the RTS use the platform is built to showcase."*
**Recording:** 1080p, big font; pre-stage the thread so the flag is instant.
