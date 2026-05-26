# repocat

GitHub **and** GitLab repository hardening CLI. Reads a declarative baseline and
either reports drift (`audit`) or reconciles it (`apply`).

GitHub and GitLab are co-equal: each has its own native config file —
`.repo.github.yml` and `.repo.gitlab.yml` — with no shared schema and no default
provider. The filename selects the host; `repocat` runs whichever file(s) are
present in the current directory.

## Install

### crates.io (recommended)

```sh
cargo install bcl-repocat
```

Installs the `repocat` binary. The crate is published as **`bcl-repocat`**
(`repocat` was already taken on crates.io by an unrelated project) — the command
is still `repocat`.

On Linux the `keyring` crate (used by the GitHub credential path) needs
`libdbus-1-dev` and `pkg-config` to build (`sudo apt-get install libdbus-1-dev
pkg-config` on Debian/Ubuntu), and `libdbus-1-3` at runtime.

### Prebuilt binary (no compile)

With [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall):

```sh
cargo binstall bcl-repocat
```

Or download an archive directly from a
[release](https://github.com/Battle-Creek-LLC/repocat/releases) — each ships a
single `repocat` (or `repocat.exe`) binary plus a `.sha256` checksum:

```sh
gh release download --pattern 'repocat-aarch64-apple-darwin.tar.gz' -R Battle-Creek-LLC/repocat
tar -xzf repocat-aarch64-apple-darwin.tar.gz && sudo mv repocat /usr/local/bin/
```

Targets: `aarch64-apple-darwin`, `x86_64-apple-darwin`,
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-pc-windows-msvc` (`.zip`). macOS binaries aren't notarized — clear the
quarantine attribute with `xattr -d com.apple.quarantine /usr/local/bin/repocat`.

### From source

```sh
cargo install --git https://github.com/Battle-Creek-LLC/repocat
```

## Getting started

`repocat` is driven by a baseline file that names your org/group, the
repos/projects to harden, and the rules to enforce.

### GitHub

```sh
gh auth login                                          # if you haven't already
repocat init --preset standard --org my-org            # writes .repo.github.yml
repocat repo add my-repo                               # add each repo to harden
repocat audit                                          # report drift
repocat diff                                           # preview what apply would change
repocat apply                                          # reconcile to the baseline
```

### GitLab

```sh
glab auth login                                        # if you haven't already
repocat init --provider gitlab                         # writes .repo.gitlab.yml from the git remote
repocat audit                                          # reuses glab's stored token
repocat diff
repocat apply
```

The baseline is created and read from the current working directory — `cd` to
wherever it lives, or pass `-f <path>` to point elsewhere. `repocat` no longer
has a default provider, so a leftover `.repo.yml` prints a migration hint
(rename it to `.repo.github.yml`).

> **Stuck on an error or finding?** Paste the command, the output, and your
> config into Claude Code, Cursor, or ChatGPT and ask what to do. `repocat`'s
> output is designed to be agent-friendly — an LLM will usually translate a
> finding into a concrete fix faster than scanning the rule reference below.

## Credentials

- **GitHub** — resolved from `GH_TOKEN`/`GITHUB_TOKEN`, then the macOS keychain
  (matching the `gh` CLI), then `~/.config/gh/hosts.yml`.
- **GitLab** — resolved from `GITLAB_TOKEN`, then `glab`'s config
  (`~/.config/glab-cli/config.yml`, plaintext `hosts.<host>.token`). Works for
  gitlab.com and self-managed instances; honors the host's `api_host`,
  `api_protocol`, `subfolder`, and `skip_tls_verify`. `apply` needs the `api`
  scope; `audit`/`diff` need `read_api`.

## Rules

### GitHub (`.repo.github.yml`)

`audit`, `diff`, and `apply` work for:

- `branch_protection` (AC-3, CM-3)
- `merge_settings` (CM-3)
- `secret_scanning` (SI-2, SI-4)
- `required_files` (CM-2) — audit-only; surfaces missing paths but cannot create them
- `codeowners` (CM-3, AC-5) — audit-only; verifies `.github/CODEOWNERS` exists and has at least one ownership rule
- `dependabot_security` (SI-2, SR-3) — vulnerability alerts, Dependabot security updates, optional `.github/dependabot.yml` presence
- `workflow_permissions` (AC-6, SR-3) — repo-level default `GITHUB_TOKEN` scope and PR-approval permission
- `workflow_yaml` (AC-6, SR-3) — audit-only; scans `.github/workflows/*.yml` for unpinned action refs and missing `permissions:` blocks
- `semgrep_workflow` (SA-11, RA-5) — audits for `.github/workflows/semgrep.yml` and scaffolds one (Semgrep OSS rulesets → SARIF → code scanning); skips on private repos (SARIF upload needs GitHub Advanced Security)
- `signed_commits` (SI-7) — required-signatures enforcement on the protected branch
- `teams_only_access` (AC-2, AC-6) — audit-only; flags direct collaborators and team-permission drift
- `org_code_security` (CM-6, SI-2, SI-4) — **org-scoped** (runs once per invocation); manages a GitHub code security configuration and sets it as the org default for new repos

### GitLab (`.repo.gitlab.yml`)

Authored in GitLab's native vocabulary. `audit` + `apply`:

- `protected_branches` (AC-3, CM-3) — force-push, push/merge access levels, code-owner approval
- `approval_rules` (AC-3, CM-3) — merge-request approval rules *(Premium/Ultimate)*
- `merge_request_approvals` (CM-3) — `reset_approvals_on_push` *(Premium/Ultimate)*
- `project_settings` (CM-3) — merge method, squash, pipeline-must-succeed, discussions-resolved
- `push_rules` (SI-7) — `reject_unsigned_commits` *(Premium/Ultimate)*

Audit-only:

- `required_files` (CM-2), `codeowners` (CM-3, AC-5) — checks `.gitlab/CODEOWNERS`, `CODEOWNERS`, or `docs/CODEOWNERS`
- `ci_security` (SA-11, RA-5, SI-2) — SAST / Secret Detection / Dependency Scanning templates in `.gitlab-ci.yml`
- `members` (AC-2, AC-6) — direct project members vs group shares

On GitLab Free/CE, Premium/Ultimate rules degrade cleanly: `approval_rules` and
`push_rules` `skip` on a 403, and `reset_approvals_on_push` reports an honest
failure instead of a false pass. The generated config marks these lines
`## PREMIUM/ULTIMATE`. See [docs/gitlab.md](docs/gitlab.md) for details and the
[design spec](docs/specs/0001-gitlab-support.md).

## Usage

```sh
repocat audit                       # report drift, exit 1 on error-severity failures
repocat audit --format json         # structured findings for downstream tooling
repocat audit --format sarif        # SARIF 2.1.0 for GitHub Code Scanning upload
repocat diff                        # preview changes apply would make
repocat apply                       # reconcile to the baseline
repocat apply --dry-run             # same as diff
repocat init --provider gitlab      # scaffold a GitLab config (default provider is github)
repocat changelog                   # release notes for the installed version
repocat changelog --since 0.4.0     # only what changed since a version
repocat changelog --upgrade         # how to upgrade + adopt new config fields
```

## Upgrading

Upgrade the tool with `cargo install bcl-repocat` (add `--force` to replace an
older build). The changelog and the migration notes are baked into the binary,
so they always match the version you have installed:

```sh
repocat changelog            # full release notes
repocat changelog --upgrade  # how to upgrade and adopt new config fields
```

The upgrade notes live in [`CHANGELOG.md`](CHANGELOG.md) under each release's
`### Upgrading` heading (that's exactly what `changelog --upgrade` prints).

> **0.5.0 is a breaking change:** the GitHub config moves from `.repo.yml` to
> `.repo.github.yml`. Rename it with `git mv .repo.yml .repo.github.yml`. The
> schema is unchanged.
