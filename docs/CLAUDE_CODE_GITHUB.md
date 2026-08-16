# Using Claude Code with this repo on GitHub

Optional setup: describe a task in a GitHub Issue, tag **@claude**, and Claude Code
implements it in a pull request that you review and merge.

> These are account-level actions — installing a GitHub App and adding repository
> secrets — so they have to be done by hand in the GitHub UI.

## Prerequisites

- Authentication for the action, one of:
  - a **Claude Pro/Max subscription** → use a `CLAUDE_CODE_OAUTH_TOKEN` (no per-use cost), or
  - an **Anthropic API key** → use `ANTHROPIC_API_KEY` (pay per token).

> **Note on public repos:** this repository is public, so anyone can open an issue.
> If the workflow triggers on any `@claude` mention, an outside contributor can spend
> your tokens. Restrict the workflow to trusted authors — gate on
> `github.event.issue.author_association` being `OWNER`, `MEMBER`, or `COLLABORATOR` —
> before enabling it.

## Option A — let Claude Code set it up

1. Install Claude Code: `npm install -g @anthropic-ai/claude-code` (or use the installer).
2. From the repo folder run `claude`, then type `/install-github-app`.

It walks you through installing the GitHub App on the repo and adding the required secret
and workflow file. This always writes the current correct config, so prefer it over
hand-copying.

## Option B — manual

1. **Install the app:** <https://github.com/apps/claude> → Install → select the `aegis` repo.
2. **Add the secret:** repo **Settings → Secrets and variables → Actions → New repository
   secret**.
   - Pro/Max: name it `CLAUDE_CODE_OAUTH_TOKEN` (generate locally with `claude setup-token`).
   - API key: name it `ANTHROPIC_API_KEY`.
3. **Add the workflow:** copy `examples/claude.yml` from
   [anthropics/claude-code-action](https://github.com/anthropics/claude-code-action) into
   `.github/workflows/claude.yml`, then commit and push. The shape is roughly:

```yaml
name: Claude
on:
  issues: { types: [opened, assigned] }
  issue_comment: { types: [created] }
  pull_request_review_comment: { types: [created] }
jobs:
  claude:
    # Public repo: also gate on author_association so outside contributors
    # can't trigger runs against your token.
    if: |
      (contains(github.event.issue.body, '@claude') || contains(github.event.comment.body, '@claude'))
      && contains(fromJSON('["OWNER", "MEMBER", "COLLABORATOR"]'), github.event.issue.author_association)
    runs-on: ubuntu-latest
    permissions: { contents: write, pull-requests: write, issues: write, id-token: write }
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          # or: anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Use the action repo's current example as the source of truth — the snippet above is
illustrative.

## Using it

Open an issue, describe the task, include **@claude** in the body. Claude reads the repo
(including `CLAUDE.md`), implements the change, and opens a PR. Review the diff, comment
**@claude** again to request changes, then merge.

`docs/ROADMAP.md` items are written to be pasted directly into issues.

## Sources

- Claude Code GitHub Actions docs: <https://code.claude.com/docs/en/github-actions>
- Action repo: <https://github.com/anthropics/claude-code-action>
