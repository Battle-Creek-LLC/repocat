# repobot

> The GitHub **App / bot identity** for repocat projects. `repobot` does the one
> thing `gh` can't — act as a GitHub App (e.g. `battle-bot[bot]`) — and gives a bot
> the complete surface it needs to **review a pull request** end to end: mint an
> identity token, read PR context, post a review **with inline comments**, and
> signal a check. GitHub only.

## Why repobot (and not gh, and not repocat)

- **`gh` can't be a bot.** `gh` authenticates as *you* (a user PAT/OAuth). It has
  no way to mint a GitHub App **installation token** and act as `app[bot]`. That
  minting is repobot's core job.
- **Not a repocat verb.** repocat is **control-plane** (declarative config
  reconciliation, user auth). Reviewing a PR is **execution-plane** (imperative,
  App auth). They don't even share an auth path. Separate tool — repocat stays
  clean.
- **Self-sufficient for the review loop.** repobot reads *and* writes with the
  App token, so an event-driven runner needs only `repobot` — no `gh` in the
  loop. For one-off needs outside this surface, `repobot token` still composes
  with `gh` by injecting the minted token into the environment.

## Command surface

```
AUTH
  repobot token [<org/repo>]                 Mint a short-lived (~1h) App installation token.

READ  (gather context, as the bot)
  repobot pr show     <pr> [<org/repo>]      PR metadata: title, body, author,
                                             state, base/head SHA, labels, mergeable.
  repobot pr diff     <pr>                    Unified diff (the patch).
  repobot pr files    <pr>                    Changed files: path, status,
                                             additions/deletions, per-file patch.
  repobot pr comments <pr>                    Existing review comments/threads
                                             (dedupe findings, find reply targets).

REVIEW / WRITE  (as the bot)
  repobot pr review   <pr> -f <review.json>   Submit a full review: summary body +
        [--disposition comment|full]          INLINE comments + event.
        [--dry-run]
  repobot pr comment  <pr> --body <md>        Single note: top-level, or INLINE
        [--path <file> --line <n>             when --path/--line are given
         --side LEFT|RIGHT                     (optionally a multi-line range).
         --start-line <n>]
  repobot pr reply    <pr> --in-reply-to <comment-id> --body <md>
                                             Reply within an existing inline thread.

SIGNAL  (optional; the compounding verbs)
  repobot pr check    <pr> --name <ctx>       Post a check-run / commit status on
        --conclusion success|failure|neutral  the PR head SHA.
        [--summary <md>]

GLOBAL FLAGS
  --json               machine-readable output (for read verbs)
  --dry-run            resolve + print the action, post nothing
```

`<org/repo>` defaults to the cwd git remote, so inside a checkout a bare `<pr>`
is enough; pass `<org/repo>` explicitly to act on another repo.

## Inline comments (first-class)

Inline, line-anchored comments are the point of a code review, so they are
supported two ways:

**1. As part of a full review** — the `comments[]` array in `review.json`. Each
entry anchors a comment to a line in the diff:

```json
{
  "event": "REQUEST_CHANGES",
  "body": "Overall solid; a couple of blocking issues inline.",
  "comments": [
    { "path": "src/app.rs", "line": 42, "body": "This unwrap panics on a 404 — handle the None." },
    {
      "path": "src/review.rs",
      "start_line": 10,
      "line": 18,
      "side": "RIGHT",
      "body": "This whole block duplicates `gh-core::client`; extract it."
    }
  ]
}
```

- `path` — file path in the PR.
- `line` — line number in the file's **new** version (RIGHT side of the diff).
- `start_line` (+ `line`) — a **multi-line** comment spanning `start_line..line`.
- `side` / `start_side` — `RIGHT` (added/context, default) or `LEFT` (deleted).
- A comment must anchor to a line in the diff; if it doesn't, repobot errors and
  posts nothing. Use `repobot pr files` to see which lines accept inline comments.

**2. As a standalone inline comment** — `repobot pr comment <pr> --path <f>
--line <n> [--side RIGHT|LEFT] [--start-line <n>] --body <md>`, for a single
note without opening a formal review.

**3. Replies** — `repobot pr reply <pr> --in-reply-to <comment-id> --body <md>`
continues an existing inline thread (e.g. responding to a maintainer).

## End-to-end: how a bot reviews a PR

```
# 1. Gather context — every call is the bot's own App identity.
repobot pr show     123 --json > pr.json
repobot pr diff     123        > pr.diff
repobot pr files    123 --json > files.json     # path + line ranges that accept inline comments
repobot pr comments 123 --json > existing.json  # so we don't repeat past findings

# 2. The reviewer (an LLM, a ruleset, /code-review, whatever) consumes that
#    context and emits review.json — a summary body plus inline comments.

# 3. Post the review AS the bot. The token is minted and used in-process, so it
#    never appears on a command line (ward-safe). Disposition is capped here.
repobot pr review 123 -f review.json --disposition full

# 4. (optional) Signal a check so the PR can gate on the bot's verdict.
repobot pr check 123 --name "repobot/review" --conclusion success
```

## Disposition (configurable, safe by default)

- `--disposition comment` (**default**) → any `APPROVE`/`REQUEST_CHANGES` in the
  payload is downgraded to `COMMENT` before posting. Advisory only; inline
  comments are still posted.
- `--disposition full` → honor the payload's `event` (allow approve/block).

This lets the same bot stay advisory on most repos and act as a real gate on the
few where `required_reviews > 0`.

## Credentials

One config file: `~/.config/repobot/config.yml`. Nothing else — no env vars, no
flags, no fallbacks.

```yaml
app_id: 3858237
private_key: ~/.config/repobot/key.pem
```

If the file or a field is missing, repobot errors and says which. The app is
whatever this file points at.

## How it maps to GitHub APIs (implementation notes)

| Verb | GitHub call |
|---|---|
| `token` | JWT(RS256) → `GET /repos/{o}/{r}/installation` → `POST /app/installations/{id}/access_tokens` |
| `pr show` | `GET /repos/{o}/{r}/pulls/{n}` |
| `pr diff` | `GET /repos/{o}/{r}/pulls/{n}` (Accept: `application/vnd.github.v3.diff`) |
| `pr files` | `GET /repos/{o}/{r}/pulls/{n}/files` |
| `pr comments` | `GET /repos/{o}/{r}/pulls/{n}/comments` |
| `pr review` | `POST /repos/{o}/{r}/pulls/{n}/reviews` (with `comments[]` for inline) |
| `pr comment` | `POST …/pulls/{n}/comments` (inline) or `…/issues/{n}/comments` (top-level) |
| `pr reply` | `POST …/pulls/{n}/comments` with `in_reply_to` |
| `pr check` | `POST /repos/{o}/{r}/check-runs` (or `…/statuses/{sha}`) |

Inline anchoring uses the review-comment fields `path`, `line`, `side`,
`start_line`, `start_side` exactly as the GitHub "create review" /
"create review comment" APIs define them.

Stack: Rust, `ureq` + `serde_json`, `jsonwebtoken` (RS256), `base64`, `anyhow` —
the same dependencies repocat already uses, so the binary stays small and
self-contained (no openssl/python/bash, cross-platform).

## Build scope

- **v1 (build now):** `token`, `pr show`, `pr diff`, `pr files`, `pr comments`,
  `pr review` (with inline `comments[]`) — the full read→review loop, everything
  needed to review a PR as the bot.
- **Fast-follow:** `pr comment`, `pr reply`, `pr check`.
- **Out of scope:** the external trigger (CI/webhook), review *generation* (the
  LLM), GitLab.

## Relationship to `/battle-review`

`repobot` is the self-contained successor to the skill's `mint-token.sh`
(→ `repobot token`) and `post-review.sh` (→ `repobot pr review`). The skill can
later shell out to `repobot` instead of carrying bash; not required now.
