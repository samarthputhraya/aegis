# End-to-end setup: two workspaces, one Slack Connect channel

Aegis is a cross-org agent, so a real test needs **two** workspaces with a Slack Connect
channel between them. This walks through it start to finish. Budget about 45 minutes the
first time.

Nothing here is needed to run the offline demo or the tests — see the README Quickstart
for that.

---

## 1. Two sandbox workspaces

Join the [Slack Developer Program](https://api.slack.com/developer-program) (free), then
create two workspaces:

| Workspace | Plays the part of |
|---|---|
| **Aegis-Buyer** | You. Aegis runs here and this is where finance would sit. |
| **Aegis-Vendor** | The external company. The attack comes from here. |

Use a normal browser window for one and a private window for the other, so you can stay
signed into both at once.

Note each workspace's **team ID** — you can read it from the URL of the admin pages, or
from `auth.test`. You need the *Buyer* one for `OUR_TEAM_ID`.

## 2. Create the app

At <https://api.slack.com/apps> → **Create New App** → **From scratch**, installed into
**Aegis-Buyer**.

### Socket Mode

**Settings → Socket Mode → Enable**. Generate an **app-level token** with the
`connections:write` scope. It starts `xapp-`. Save it — this is `SLACK_APP_TOKEN`.

Socket Mode is much easier than HTTP here: no tunnel, no public URL, and it survives
your laptop changing networks.

### Bot token scopes

**OAuth & Permissions → Scopes → Bot Token Scopes**:

| Scope | Why |
|---|---|
| `chat:write` | post the warning card |
| `channels:read` | resolve channel metadata, and find an existing canvas |
| `channels:history` | read channel history for the relationship baseline |
| `users:read` | turn user IDs into names in the warning |
| `canvases:write` | create and update the trust-log canvas |
| `search:read.public` | only if you set `HISTORY_SOURCE=rts` |

If your Connect channel is private, add `groups:read` and `groups:history` as well, and
`search:read.private` for the RTS path.

### Events

**Event Subscriptions → Enable**, then under **Subscribe to bot events** add
`message.channels` (and `message.groups` for a private channel).

### Install

Install to **Aegis-Buyer** and copy the **Bot User OAuth Token** (`xoxb-`) — that's
`SLACK_BOT_TOKEN`. From **Basic Information**, copy the **Signing Secret**; you only need
it for HTTP mode, but `.env.example` has a slot for it.

## 3. Install to the vendor workspace too

**Settings → Manage Distribution → Activate Public Distribution**, then open the sharable
install link in your Vendor window and approve it there.

## 4. Create the Slack Connect channel

In **Aegis-Buyer**, create a channel — say `#connect-acme-supplies` — then
**Channel settings → Integrations → Connect to another workspace** and send the
invitation to your Vendor workspace. Accept it on the Vendor side.

Invite the Aegis bot into the channel from the Buyer side: `/invite @Aegis`.

## 5. Configure Aegis

```bash
cp .env.example .env
```

Fill in:

```bash
SLACK_BOT_TOKEN=xoxb-…          # from step 2
SLACK_APP_TOKEN=xapp-…          # from step 2
OUR_TEAM_ID=T0123BUYER          # the BUYER workspace's team ID
VENDOR_KEY=acme_supplies        # key into mcp_server/data/vendors.json
```

`OUR_TEAM_ID` is what makes Aegis a *cross-org* tripwire rather than a surveillance bot:
messages from your own team are skipped entirely.

Optionally add `ANTHROPIC_API_KEY` to switch on model-based classification. Without it,
Aegis uses the offline detector — everything below still works.

## 6. Run it

```bash
bash scripts/start_socket_mode.sh
```

You should see `Starting Aegis in Socket Mode …`.

## 7. The demo

In the **Vendor** workspace, in the shared channel:

**First, something normal.**

> Order #4471 ships Friday, tracking to follow.

Aegis stays quiet. Your logs show `scanned … -> low`. This matters: the interesting claim
isn't that it fires, it's that it doesn't fire on ordinary traffic.

**Then the attack.**

> Hi, please note our bank account has changed. Kindly remit this month's invoice to IBAN
> GB29 NWBK 60161331926819. It's urgent — send today before 5pm. Keep this confidential
> between us.

Aegis posts a red **CRITICAL** card in thread, listing why:

- payment/bank-detail change requested
- requested IBAN ≠ the IBAN on file (checked over MCP)
- urgency pressure
- secrecy cue
- sender not seen before in this channel

**Then press *Verify out-of-band*.** Aegis re-runs the MCP bank check, replies in thread
with both account numbers, and opens a verification task — a real GitHub issue if you set
`GITHUB_TOKEN` and `GITHUB_REPO`, otherwise a mock.

**Check the canvas.** The channel now has an *Aegis trust log* canvas with the flagged
event and its reasons.

## 8. Troubleshooting

**Nothing happens at all.** Is the bot in the channel? Did you subscribe to
`message.channels`? Is `OUR_TEAM_ID` accidentally set to the *vendor* team, so real
external messages are being skipped as internal?

**Everything gets flagged as a new sender.** The baseline is empty — usually a missing
`channels:history` scope. Aegis logs `history fetch failed` when this happens.

**`missing_scope` in the logs.** Slack names the scope it wanted. Add it under OAuth &
Permissions and **reinstall the app** — scope changes need a reinstall.

**No canvas appears.** `canvases:write` missing, or the workspace plan doesn't include
canvases. Aegis logs a warning and carries on; the warning card is unaffected.

**RTS returns an unrecognised shape.** `assistant.search.context`'s response envelope
isn't in the public reference. Aegis raises rather than silently returning an empty
baseline — paste the real response into
`aegis/slack_io._messages_from_rts_response`, or set `HISTORY_SOURCE=conversations`.

## 9. HTTP mode instead

If you'd rather not use Socket Mode:

```bash
python app.py                 # listens on $PORT, default 3000
ngrok http 3000               # in another terminal
```

Set the Request URL under **Event Subscriptions** to
`https://<your-ngrok-host>/slack/events`. `SLACK_SIGNING_SECRET` is required in this mode.
