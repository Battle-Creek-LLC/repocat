# Spec 0001 — GitLab support

Status: **Implemented** (Phases 1–3 shipped in 0.5.0; `init --provider gitlab` added)
Author: repocat maintainers
Created: 2026-05-26
Tracking: adds GitLab as a second, co-equal repository host alongside GitHub.

## 1. Summary

`repocat` today audits and reconciles **GitHub** repositories against a
declarative `.repo.yml` baseline. This spec adds **GitLab** (gitlab.com and
self-managed instances) as a **co-equal** host, reusing the credentials already
provisioned by the [`glab`](https://gitlab.com/gitlab-org/cli) CLI the way we
reuse `gh`'s credentials today.

The design is **completely separate per host, top to bottom.** GitHub and GitLab
are equals — neither is the default. Each has:

- its **own config file** — `.repo.github.yml` / `.repo.gitlab.yml` — with its
  **own schema in that host's native vocabulary** (no shared/portable schema
  reinterpreted per host);
- its own config + resolve, HTTP client, auth, git-remote parsing, rule set, and
  action execution, in its own module;

and the providers share **only** the `Finding` reporting type and `output.rs`.
There is no `RepositoryHost` trait, no `Box<dyn …>`, no generic orchestration,
and no lowest-common-denominator config. `main` discovers which config files are
present and hands each to its provider module.

## 2. Goals / Non-goals

### Goals

- Run `audit` / `diff` / `apply` against a GitLab project (and group, for the
  group-scoped check) using the same command surface.
- Reuse `glab`'s stored token with zero extra configuration, mirroring the
  existing `gh` reuse in `src/auth.rs`.
- Express GitLab policy in **GitLab's own terms** — protected branches, approval
  rules, push rules, project settings, CI security templates — not GitHub
  concepts in disguise.
- Keep the GitHub rule *logic* unchanged. (Its config file is renamed to
  `.repo.github.yml`; see §12.)
- Treat the two hosts as equals: no default provider, symmetric file names,
  symmetric module layout.

### Non-goals

- A unified provider abstraction / plugin system, or any shared config schema.
  Explicitly rejected — see §4 and §8.
- Bitbucket, Gitea, or other hosts (the layout makes them cheap to add later,
  but they are out of scope here).
- Auto-translating a `.repo.github.yml` into a `.repo.gitlab.yml`. They are
  authored independently.

## 3. Current architecture (baseline)

For reference, the GitHub-only structure as of v0.4.0:

| File | Role |
|------|------|
| `src/main.rs` | CLI dispatch + the `audit`/`diff`/`apply` pipeline, including `execute_actions` |
| `src/auth.rs` | Loads a `gh` token (env → keyring → `hosts.yml`) |
| `src/api.rs` | `Client` — all GitHub HTTP via `ureq`, base `https://api.github.com` |
| `src/git.rs` | Parses `github.com` remotes → org |
| `src/config.rs` | `.repo.yml` deserialization (`Config`, `RepoConfig`, …) |
| `src/resolve.rs` | Merges `defaults:` with per-repo overlays |
| `src/rules.rs` | `run_all` + 11 rule fns; owns `Finding`, `Severity`, `Status`, `Action` |
| `src/output.rs` | Renders findings as text / JSON / SARIF |
| `src/presets.rs` + `src/templates/` | `init` scaffolding |

The pipeline (`main.rs:135`) is: load config → `auth::load_credentials()` →
`api::Client::new(token)` → per repo `rules::run_all(client, org, name, cfg)` →
render → in `apply`, `execute_actions(client, org, name, findings)`.

Two facts drive the design:

1. **`Action` is a GitHub payload.** Variants like
   `PatchRepo { body: Value }` / `PutBranchProtection { branch, body }`
   (`rules.rs`) are literal GitHub request bodies executed by
   `main::execute_actions`. Not reusable for GitLab.
2. **`Finding` is host-agnostic.** `rule`, `severity`, `nist`, `status`,
   `messages` are pure reporting data that `output.rs` reads. Only the
   executable `actions` payload is host-specific.

Reporting is shared; everything else is not. That is the only seam.

## 4. Design decision: separate modules, not a trait

A trait (`trait RepositoryHost { fn put_branch_protection(...); … }`) is the
"obvious" OO move and is explicitly **not** wanted:

- **The hosts don't share a model, only a goal.** GitHub has org→repo, branch
  protection objects, and "code security configurations." GitLab has
  group→project, with branch protection *spread across protected branches,
  approval rules, push rules, and project settings*, and no
  security-configuration object at all. A common trait would either be raw HTTP
  verbs (no value) or coarse methods whose impls share nothing.
- **A trait leaks.** The first host-only parameter (URL-encoded project path,
  approval-rule IDs, pagination cursors) forces `Option`s and "ignored on the
  other host" doc-comments — negative value.
- **Duplication here is cheap and honest** and keeps each host independently
  changeable; a GitLab change can never regress GitHub.
- **It matches the codebase**, which already prefers flat concrete functions
  over indirection (`run_all` is a static list of calls).

Shared things are shared as **plain data + rendering**, which needs no trait:
`Finding` and `output.rs`. That is not "orchestration" — no central controller
reaches into provider internals.

### The one refactor this requires

Move `Finding` / `Severity` / `Status` out of `rules.rs` into `src/finding.rs`,
and **drop the executable `Action` from the shared type:**

```rust
// src/finding.rs
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub nist: &'static str,
    pub status: Status,           // Pass | Fail | Skip
    pub messages: Vec<String>,
    pub planned: Vec<String>,     // human-readable "what apply would do",
                                  // for `diff` and JSON output — NOT executable
}
```

Execution moves *into* each provider module: a rule decides the change, appends
a one-line summary to `planned`, and — in `Apply` — performs its own HTTP call
internally. `main` no longer owns `execute_actions`.

## 5. Target module layout

Symmetric. Neither tree is privileged.

```
src/
  main.rs            # discover present config files → for each, match provider → provider::run
  provider.rs        # enum Provider { GitHub, GitLab }; filename → Provider; expected file names
  finding.rs         # SHARED: Finding, Severity, Status (reporting contract)
  output.rs          # SHARED, unchanged: renders Findings (text/json/sarif)
  presets.rs
  templates/

  github/
    mod.rs           # pub fn run(mode, path, &Args) -> Result<Outcome>
    config.rs        # `.repo.github.yml` schema + load  (moved from src/config.rs)
    resolve.rs       # defaults⊕overlay merge for the GitHub schema (moved from src/resolve.rs)
    auth.rs          # gh creds            (moved from src/auth.rs)
    api.rs           # GitHub Client       (moved from src/api.rs)
    git.rs           # github.com remotes  (moved from src/git.rs)
    rules.rs         # GitHub rules + GitHub action execution (moved from src/rules.rs)

  gitlab/
    mod.rs           # pub fn run(mode, path, &Args) -> Result<Outcome>
    config.rs        # `.repo.gitlab.yml` schema + load (GitLab-native, §8)
    resolve.rs       # defaults⊕overlay merge for the GitLab schema
    auth.rs          # glab creds (§6)
    api.rs           # GitLab Client: /api/v4, PRIVATE-TOKEN, URL-encoded project path, pagination
    git.rs           # gitlab.com + self-managed remotes (honors ssh_host)
    rules.rs         # GitLab rules + GitLab action execution
```

There is no top-level `config.rs` or `resolve.rs` — each provider parses and
merges its **own** schema. The only cross-provider code is `provider.rs` (a tiny
filename↔enum map), `finding.rs`, and `output.rs`.

Each `mod.rs` exposes one entry point — same signature by convention, **not** a
trait:

```rust
pub fn run(mode: Mode, config_path: &Path, args: &Args) -> Result<Outcome>;

pub struct Outcome {
    pub findings: Vec<(String, Vec<Finding>)>, // (project/group label, findings)
    pub any_error: bool,        // a Fail at Error severity (audit/diff exit 1)
    pub any_apply_error: bool,  // an action failed (apply exit 3)
}
```

`main::run`:

```rust
fn run(mode: Mode, raw: &[String]) -> Result<ExitCode> {
    let args = parse_args(raw)?;
    // explicit -f, else every .repo.{github,gitlab}.yml present in the dir
    let configs = provider::discover(&args)?;   // Vec<(Provider, PathBuf)>
    if configs.is_empty() {
        return Err(anyhow!(
            "no config found — expected .repo.github.yml or .repo.gitlab.yml \
             (create one with `repocat init --provider <github|gitlab>`)"
        ));
    }
    let mut outcomes = Vec::new();
    for (provider, path) in configs {
        outcomes.push(match provider {
            Provider::GitHub => github::run(mode, &path, &args)?,
            Provider::GitLab => gitlab::run(mode, &path, &args)?,
        });
    }
    output::render_all(&outcomes, args.format)?;
    Ok(exit_code(mode, &outcomes))
}
```

If both files are present, both run (they are equals). `-f <path>` targets one;
its provider is inferred from the filename (§9).

## 6. Credential reuse from `glab`

Mirror `src/auth.rs`, but `glab` is **simpler than `gh`** in two ways verified
against a live install:

- `glab` stores the token in **plaintext** in its config file and does **not**
  use the OS keyring. The keyring + Go-base64 decode dance in `auth.rs:40-55` is
  unnecessary here.
- `glab` keeps everything in a **single** `config.yml`. There is no separate
  `hosts.yml` like `gh` has.

### `glab` `config.yml` shape (verified)

```yaml
# ~/.config/glab-cli/config.yml
git_protocol: ssh
host: gitlab.com                  # glab's DEFAULT host (top level)
hosts:                            # map keyed by hostname; 4-space indent
    gitlab.com:
        api_protocol: https
        api_host: gitlab.com
        token:                    # NOTE: can be empty if not authed to this host
    git.example.com:              # a self-managed instance
        token: <plaintext-PAT>    # the credential we read, verbatim
        api_host: git.example.com
        api_protocol: https
        git_protocol: ssh
        user: someuser
        ssh_host:                 # alternate SSH host, when set (affects remotes)
        subfolder:                # set when GitLab is served under a path prefix
        skip_tls_verify: "true"   # present on self-signed-cert instances
skip_ssl_verify: "true"           # top-level TLS-skip (read only to warn — §15)
```

Facts that drive the parser:

- The credential key is **`token`** (not `oauth_token`).
- Host blocks nest under a top-level `hosts:` map keyed by hostname. With
  `glab`'s 4-space indent and the existing `auth.rs:117` `line_indent`
  (spaces÷4): `hosts:` at depth 0 → `<host>:` at depth 1 → `token` / `user` /
  `api_host` / … at depth 2. This is the **same nested walk** as `auth.rs:139`
  `nested_user_token` (`users:` → `<user>:` → `oauth_token`); reuse that pattern
  rather than adding a full YAML parse, keeping behavior and dependencies
  identical to the `gh` path.
- A host block's `token` may be **empty** (e.g. the default `gitlab.com` block
  is tokenless while a self-managed host carries the real PAT). So credential
  loading selects a host *first*, then reads that host's token, and errors if it
  is empty — it does not assume the default host is the authed one.

### Resolution order (`gitlab::auth::load_credentials`)

Returns `(token, base_url, user)`.

1. **Env var.** `GITLAB_TOKEN` (the variable `glab` itself honors). If set and
   non-empty, use it. Host for the base URL comes from `GITLAB_HOST` / `GL_HOST`
   if set, else the host chosen in step 2's selection, else `gitlab.com`.
2. **`glab` config file.** Locate the config dir in `glab`'s own precedence:
   `GLAB_CONFIG_DIR` → `XDG_CONFIG_HOME/glab-cli` → `~/.config/glab-cli`. Read
   `config.yml`. Select the host by:
   1. explicit `host:` in `.repo.gitlab.yml`,
   2. else the git remote host,
   3. else `glab`'s top-level `host:` value,
   4. else `gitlab.com`.
   Then read `hosts.<host>.token`. If that token is empty, error rather than
   silently falling through to a different host.
3. **Error** naming exactly what was checked, matching `auth.rs:35`:
   `no glab credentials found for <host> (checked GITLAB_TOKEN, ~/.config/glab-cli/config.yml)`.

### Base URL

`{api_protocol}://{api_host}[/{subfolder}]/api/v4` from the selected host's
block; `api_protocol` defaults to `https`, `api_host` defaults to the host key,
`subfolder` (when non-empty) becomes a path prefix. gitlab.com → `https://gitlab.com/api/v4`.

### TLS verification

Read `skip_tls_verify` (and the top-level `skip_ssl_verify`) from the **same**
glab host block and **honor it, scoped to that host.** The token already comes
from this block, so this is the user's own per-host decision, already made for
glab — not a new trust choice. Refusing to honor it would make repocat fail the
TLS handshake on exactly the self-managed instances glab connects to fine.

When the flag is set, `gitlab/api.rs` builds its `ureq::Agent` with certificate
verification disabled for that host (ureq + a rustls "dangerous"/accept-invalid
config, or native-tls `danger_accept_invalid_certs`), and emits a single stderr
line for transparency:
`warning: TLS verification disabled for <host> (per glab config skip_tls_verify)`.
This is a notice, not a prompt or a separate opt-in.

### Token validation / whoami

Validate by `GET /api/v4/user`; the response `username` is printed as
`authenticated as <user>` (parallel to `auth.rs:172`).

### Auth header

- `PRIVATE-TOKEN: <token>` for personal/project/group access tokens (the common
  `glab` case).
- `Authorization: Bearer <token>` only if the token is an OAuth token (no PAT
  prefix). Default to `PRIVATE-TOKEN`.

## 7. GitLab API client (`gitlab/api.rs`)

A sibling of `github::api::Client`: a `token` + `base_url`, the same `ureq`
usage, the same error-mapping shape (`"{method} {url} → {code}: {body}"`).
Host-specific internals:

- **Base URL** is the value resolved in §6 (not hardcoded like `api.rs:30`).
- **Project addressing.** Projects use the URL-encoded full path:
  `group/subgroup/project` → `group%2Fsubgroup%2Fproject`. Reuse `urlencode`
  (`api.rs:7`).
- **Pagination.** GitLab list endpoints page with `?per_page=100&page=N` and an
  `X-Next-Page` header; a small `get_all_pages` loop lives only here.
- **404 handling.** Same `get_optional` pattern (`api.rs:47`).

## 8. GitLab config: `.repo.gitlab.yml` (its own native schema)

GitLab's config shares **nothing** with GitHub's. It is authored in GitLab's
vocabulary, parsed by `gitlab/config.rs` into GitLab-only structs, and merged by
`gitlab/resolve.rs`. The filename is the discriminator — there is no `provider:`
key inside.

```yaml
# .repo.gitlab.yml
group: my-group/platform          # namespace path (top-level or nested)
# host: git.example.com           # self-managed only; defaults to gitlab.com,
                                   # and selects the glab hosts.<host> block (§6)

defaults:
  protected_branches:
    - name: main
      allow_force_push: false
      push_access_level: maintainer     # no_one | developer | maintainer
      merge_access_level: developer
      code_owner_approval_required: true   # Premium
  approval_rules:
    - name: default
      approvals_required: 1
  merge_request_approvals:
    reset_approvals_on_push: true
  project_settings:
    merge_method: ff                      # merge | rebase_merge | ff
    squash_option: default_on             # never | always | default_on | default_off
    remove_source_branch_after_merge: true
    only_allow_merge_if_pipeline_succeeds: true
    only_allow_merge_if_all_discussions_are_resolved: true
  push_rules:
    reject_unsigned_commits: false        # Premium
  required_files:
    - README.md
    - LICENSE
  codeowners: true                        # .gitlab/CODEOWNERS present + non-empty
  ci_security:                            # presence in .gitlab-ci.yml
    require_sast: true                    # GitLab SAST (semgrep-based analyzers)
    require_secret_detection: true
    require_dependency_scanning: true
    pin_includes: true                    # pin `include:` refs
  members:
    direct_members_allowed: false         # flag direct project members
    shares:                               # group shares with max access level
      - group: my-group/security
        access_level: maintainer

projects:                                 # GitLab "projects" (not "repos")
  my-project: {}
  special-service:
    approval_rules:
      - name: default
        approvals_required: 2

# group_security:                         # group-scoped, Phase 2 (§10)
```

Decisions:

- **Top-level key is `group`** (the namespace path), not `org`. Projects live
  under `projects:`, not `repos:`. The vocabulary is GitLab's throughout.
- **Blocks model GitLab APIs directly** — `protected_branches`,
  `approval_rules`, `push_rules`, `project_settings` are separate because GitLab
  *implements* them separately. We do not fold them into a single
  `branch_protection` block the way GitHub does.
- **`gitlab/config.rs` owns parsing**, with `#[serde(deny_unknown_fields)]`, its
  own `GitlabConfig` / `GitlabProjectConfig` structs, and validation (e.g.
  `group:` required). It does not import anything from `github/`.
- **`init` requires a provider** — `repocat init --provider gitlab` writes
  `.repo.gitlab.yml`; `--provider github` writes `.repo.github.yml`. There is no
  default, so `--provider` is mandatory.

## 9. Config discovery & provider selection (`provider.rs`)

The **filename** selects the provider; no network I/O, no in-file `provider:`
key.

```rust
pub enum Provider { GitHub, GitLab }

pub fn provider_for(path: &Path) -> Option<Provider> {
    match path.file_name()?.to_str()? {
        n if n.ends_with(".repo.github.yml") || n == ".repo.github.yml" => Some(Provider::GitHub),
        n if n.ends_with(".repo.gitlab.yml") || n == ".repo.gitlab.yml" => Some(Provider::GitLab),
        _ => None,
    }
}

/// -f <path> if given (provider inferred from its name), else every recognized
/// config file present in the working directory.
pub fn discover(args: &Args) -> Result<Vec<(Provider, PathBuf)>>;
```

`-f` pointed at a file whose name matches neither pattern is an error that asks
for a `.repo.github.yml` / `.repo.gitlab.yml` name (or a future explicit
`--provider` override). Self-managed git remotes may use `ssh_host` while
`host`/`api_host` differ — `gitlab/git.rs` matches both the configured `host:`
and a known `ssh_host`.

## 10. GitLab rule set (native)

GitLab gets its **own** rules, written against the `.repo.gitlab.yml` schema and
GitLab endpoints — not GitHub rules reinterpreted. Each keeps a NIST tag so
`output.rs`, JSON, and SARIF stay uniform across hosts. Support levels:

- ✅ **Full** — clean GitLab endpoint.
- ⚠️ **Partial** — near-equivalent with a caveat; may require a GitLab tier
  (Premium/Ultimate).
- ⏭️ **Skip** — not expressible / tier-gated; emits `Status::Skip` with a
  reason, never an error.

| GitLab rule (id) | `.repo.gitlab.yml` fields | Endpoint(s) | NIST | Level |
|------------------|---------------------------|-------------|------|-------|
| `protected_branches` | `protected_branches[]` (`allow_force_push`, `*_access_level`, `code_owner_approval_required`) | `…/protected_branches` (DELETE+POST; PATCH on 15.x+) | AC-3, CM-3 | ✅ / ⚠️ (code-owner = Premium) |
| `approval_rules` | `approval_rules[]` (`approvals_required`) | `GET/POST/PUT …/approval_rules` | AC-3, CM-3 | ✅ |
| `merge_request_approvals` | `merge_request_approvals.reset_approvals_on_push` | `POST …/approvals` | CM-3 | ✅ |
| `project_settings` | `project_settings.*` (`merge_method`, `squash_option`, `remove_source_branch_after_merge`, `only_allow_merge_if_pipeline_succeeds`, `only_allow_merge_if_all_discussions_are_resolved`) | `PUT /projects/:id` | CM-3 | ✅ |
| `push_rules` | `push_rules.reject_unsigned_commits` | `GET/POST/PUT …/push_rule` | SI-7 | ⚠️ (Premium) |
| `required_files` | `required_files[]` | `GET …/repository/files/:path?ref=` (404 = missing) | CM-2 | ✅ |
| `codeowners` | `codeowners` | files API (`.gitlab/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS`) | CM-3, AC-5 | ✅ |
| `ci_security` | `ci_security.require_{sast,secret_detection,dependency_scanning}` | scan `.gitlab-ci.yml`; scaffold `include:` of the GitLab template | SA-11, RA-5, SI-2 | ✅ (SAST is semgrep-based) |
| `ci_yaml` | `ci_security.pin_includes` | scan `.gitlab-ci.yml` `include:` refs | AC-6, SR-3 | ⚠️ (no per-job `permissions:` concept) |
| `members` | `members.direct_members_allowed`, `members.shares[]` | `…/members`, `…/members/all`, `…/share` | AC-2, AC-6 | ⚠️ |
| `secret_push_protection` | (in `ci_security` or its own block) | `secret_push_protection_enabled` via `PUT /projects/:id` | SI-2, SI-4 | ⚠️ (Ultimate 16.7+) |
| `group_security` (group-scoped) | `group_security` block | group security policies / `secret_push_protection` group default | CM-6, SI-2, SI-4 | ⏭️ Phase 2 |

GitLab access levels for `members` / `protected_branches`: No access `0`,
Minimal `5`, Guest `10`, Reporter `20`, Developer `30`, Maintainer `40`,
Owner `50`.

> **Migration aid only** (not a config mapping): for someone porting a
> `.repo.github.yml`, the rough correspondence is `branch_protection` → split
> across `protected_branches` + `approval_rules` + `project_settings`;
> `merge` → `project_settings`; `signed_commits` → `push_rules`;
> `secret_scanning` → `ci_security` + `secret_push_protection`;
> `semgrep_workflow` → `ci_security.require_sast`; `teams_only_access` →
> `members`; `org_security` → `group_security`. The two configs are still
> authored independently.

### Reconcile caveats GitLab forces on us

- **Protected branches often need DELETE + re-create.** Older GitLab has no
  PATCH for a protected branch; updating access levels means
  `DELETE …/protected_branches/:name` then `POST`. 15.x+ adds
  `PATCH …/protected_branches/:name` for `allow_force_push` /
  `code_owner_approval_required` only. `gitlab/rules.rs` encapsulates this.
- **`merge_method` is one field**, so `require_linear_history`-style intent is
  expressed directly as `project_settings.merge_method: ff`. There is no need to
  reconcile three independent booleans (that was a GitHub-schema artifact).

## 11. Apply-mode preflight (token scopes)

`main` runs no preflight; each provider module owns its own. GitLab PATs carry
scopes (`api`, `read_api`, …) readable from `GET /personal_access_tokens/self`.
`apply` requires `api`; `audit`/`diff` work with `read_api`. (GitHub keeps its
existing `preflight_scopes` inside `github/`.)

## 12. Migration (GitHub config rename)

Because there is **no default provider**, the bare `.repo.yml` goes away — GitHub
config moves to `.repo.github.yml`.

- **Behavior change:** `repocat` no longer reads `.repo.yml`. If it finds one and
  no `.repo.github.yml`, it errors with a one-line migration hint:
  `found legacy .repo.yml — rename it to .repo.github.yml (repocat no longer has a default provider)`.
- The GitHub schema itself is **unchanged**; only the file name moves. A user
  migrates with `git mv .repo.yml .repo.github.yml`.
- `Action` is removed from the public `Finding`, but `Finding` is internal — no
  serialized format depends on it. JSON/SARIF are built from `messages` +
  `planned`, carrying the same human-readable content `Action.summary` did.
- The `src/{auth,api,git,config,resolve,rules}.rs` files move under
  `src/github/` unchanged (pure move + re-namespace). Worth a standalone commit
  before any GitLab code lands.
- **Hard cut — no deprecation shim.** `repocat` does not read `.repo.yml` for a
  transitional release; the migration error above is the entire behavior.

## 13. Phasing

1. **Refactor (no logic change).** Extract `finding.rs`; move GitHub files under
   `src/github/`; add `provider.rs`; rename `.repo.yml` → `.repo.github.yml` +
   migration error; move `execute_actions` into `github::rules`. Ship.
2. **GitLab read path.** `gitlab/{auth,api,git,config,resolve}.rs` and the
   ✅/⚠️ rules in **audit-only** form; `apply` returns "not yet supported" per
   unmapped action.
3. **GitLab apply path.** Action execution in `gitlab/rules.rs` for ✅ and safe
   ⚠️ rules; preflight scopes; protected-branch DELETE+recreate.
4. **Phase 2.** `group_security`; external status checks; richer dependency /
   secret-protection coverage.

## 14. Testing

- **Auth parsing** — unit tests over sample `glab` `config.yml` blocks
  (gitlab.com only; self-managed; multiple hosts; **tokenless default host with
  a token on a self-managed host**; missing token), mirroring the `hosts.yml`
  tests in `auth.rs`. Redacted placeholder tokens only.
- **Config parsing** — `gitlab/config.rs` tests over `.repo.gitlab.yml` samples
  (defaults-only; per-project overlay; unknown-field rejection; missing
  `group:`), and a `provider::provider_for` test over both file names + an
  unrecognized name.
- **Remote parsing** — `gitlab/git.rs` tests: SSH/HTTPS, gitlab.com +
  self-managed, nested groups, `ssh_host` aliases; a "rejects github.com remote"
  case (mirror `git.rs:41`).
- **URL encoding** of nested project paths (`a/b/c` → `a%2Fb%2Fc`).
- **Rule mapping** — table-driven: GitLab API response fixture + `GitlabConfig`
  → expected `Finding`. No live network.
- **Live smoke** (opt-in, gated on `GITLAB_TOKEN`) — audit a throwaway
  gitlab.com project end to end.

## 15. Open questions

1. **Subfolder installs.** `subfolder` is read into the base URL (§6); needs a
   live self-managed-with-subfolder instance to validate path construction.
2. **Approval rules vs project-level approvals** — `approvals_required` maps to
   a named approval rule (the non-deprecated path) rather than the deprecated
   `approvals_before_merge`. Confirm against target GitLab versions.
3. **Tier detection** — pre-probe instance tier to pre-emptively `Skip` ⚠️
   (Premium/Ultimate) rules, or attempt and downgrade a 403 to `Skip`? Spec
   leans attempt-then-downgrade.

(Resolved during review: legacy `.repo.yml` is a hard cut, §12; `skip_tls_verify`
is honored per-host from the glab config, §6.)
