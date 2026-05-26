# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] — 2026-05-26

### Added

- **GitLab support.** repocat now hardens GitLab projects alongside GitHub. It
  reuses the token the [`glab`](https://gitlab.com/gitlab-org/cli) CLI stores
  (`GITLAB_TOKEN`, then `~/.config/glab-cli/config.yml`), works against
  gitlab.com and self-managed instances, and honors a host's `skip_tls_verify`
  for self-signed instances. Rules: `protected_branches`, `approval_rules`,
  `merge_request_approvals`, `project_settings`, `push_rules` (audit + apply);
  `required_files`, `codeowners`, `ci_security`, `members` (audit-only). Premium/
  Ultimate-gated rules degrade cleanly — `approval_rules`/`push_rules` `skip` on
  403, and `reset_approvals_on_push` reports an honest failure rather than a
  false success when GitLab silently ignores it.
- `repocat init --provider <github|gitlab>` — scaffolds the provider's native
  config. `--provider gitlab` detects the namespace from the git remote and
  writes a secure-by-default `.repo.gitlab.yml` (every hardening rule enabled,
  paid-tier lines marked `## PREMIUM/ULTIMATE`).

### Changed

- **Two co-equal providers, two config files.** GitHub and GitLab each have
  their own native config — `.repo.github.yml` and `.repo.gitlab.yml` — with no
  shared schema and no default provider. The filename selects the provider;
  repocat runs whichever file(s) are present (`-f <path>` targets one).
- Internals refactored into self-contained `github/` and `gitlab/` provider
  modules (no shared host trait); only the `Finding` reporting type and output
  rendering are shared.

### Upgrading

**Breaking: the config file is renamed.** `repocat` no longer reads `.repo.yml`.
Rename your GitHub config:

```sh
git mv .repo.yml .repo.github.yml
```

The GitHub schema is unchanged — only the filename moves. If you run a command
with a `.repo.yml` still present, repocat prints a migration hint and exits.

To start hardening a GitLab project, scaffold its config (reusing your `glab`
login) and audit:

```sh
glab auth login                      # if you haven't already
repocat init --provider gitlab       # writes .repo.gitlab.yml from the git remote
repocat audit                        # reuses glab's token
```

On GitLab Free/CE, Premium/Ultimate rules in the generated config are marked
`## PREMIUM/ULTIMATE`; comment them out for a quieter audit, or leave them —
they `skip` (403) or report an honest failure rather than a false pass.

## [0.4.0] — 2026-05-25

### Added

- `changelog` command — prints the release notes baked into the binary, so the
  output always matches the installed version. `--since <version>` filters to
  entries newer than a version; `--upgrade` extracts just the per-version
  `### Upgrading` notes (how to adopt new `.repo.yml` fields) and combines with
  `--since` to show only upgrades newer than the version you're on.
- Per-version `### Upgrading` sections in this changelog, giving an agent (or a
  human) the concrete steps — exact YAML, field names, required token scopes — to
  adopt each release's `.repo.yml` changes.

### Changed

- Release workflow now publishes to crates.io on tag push (new `publish-crate`
  job), matching the other Battle-Creek-LLC crates — tagged releases are now
  fully automated end to end.

## [0.3.0] — 2026-05-25

### Added

- `org_security` — repocat's first organization-scoped block. Manages a GitHub
  code security configuration (`/orgs/{org}/code-security/configurations`) and
  sets it as the org default for new repositories. `audit`/`diff` report whether
  a named configuration exists with the wanted features (dependency graph,
  Dependabot alerts and security updates, secret scanning and push protection)
  and is the default for the configured visibility scope; `apply` creates or
  updates it and sets the default (idempotent). Acts as the org-level backstop
  for the per-repo `security:` block — keeping Dependency Graph enabled even when
  it is disabled org-wide, a state the per-repo check cannot detect on public
  repos (CM-6, SI-2, SI-4).
- Strict preset ships an `org_security` block defaulting to all repositories.

### Changed

- `apply` preflight now also requires the `admin:org` scope when an
  `org_security` block is present, failing fast with a `gh auth refresh` hint.

### Upgrading

Add a top-level `org_security:` block (a sibling of `defaults:` and `repos:` —
it is org-scoped, not per-repo), then run `repocat apply` with a token that has
the `admin:org` scope (`gh auth refresh -s admin:org`):

```yaml
org_security:
  configuration_name: "repocat baseline"   # stable name repocat reconciles by
  default_for_new_repos: all                # all | public | private_and_internal | none
  dependency_graph: true
  dependabot_alerts: true
  dependabot_security_updates: true
  # secret_scanning / secret_scanning_push_protection are GitHub Advanced
  # Security-gated on private repos — set them only where repos are eligible.
```

Requires repocat 0.3.0+ (older versions reject the unknown `org_security` field).

## [0.2.0] — 2026-05-23

### Changed

- Release workflow now self-creates the GitHub release on tag push via an
  explicit `contents: write` `create-release` job, then attaches binaries to it.
  Fixes tag-push releases failing to create the release under the read-only
  default workflow token enforced by the repocat baseline.

## [0.1.3] — 2026-05-23

### Added

- `actions.require_semgrep_workflow` — when set, repocat audits for a
  `.github/workflows/semgrep.yml` and scaffolds one (Semgrep OSS rulesets via
  pipx, SARIF uploaded to GitHub code scanning, actions SHA-pinned). Skips on
  private repos, where SARIF→code-scanning needs GitHub Advanced Security.
  Surfaces SAST findings in the same place CodeQL would (SA-11, RA-5).

### Packaging

- Published to crates.io as **`bcl-repocat`** (the `repocat` name is taken by an
  unrelated crate). `cargo install bcl-repocat` installs the `repocat` binary.

### Upgrading

Set `require_semgrep_workflow: true` under a repo's `actions:` block; `apply`
scaffolds `.github/workflows/semgrep.yml` if missing (needs the `workflow`
scope). Skipped on private repos, where SARIF upload to code scanning needs
GitHub Advanced Security.

## [0.1.2] — 2026-04-29

### Fixed

- `init --preset strict` no longer ships a `required_files` list that
  contradicts the `codeowners` rule. The strict template previously listed
  bare `CODEOWNERS` under `required_files` (a literal repo-root path check)
  while also enabling the `codeowners` rule (which reads `.github/CODEOWNERS`).
  Repos following GitHub's recommended `.github/CODEOWNERS` convention would
  permanently fail `required_files` while passing `codeowners`. Corrected
  the entry to `.github/CODEOWNERS` so both rules check the same path.
  ([#27](https://github.com/Battle-Creek-LLC/repocat/issues/27))

## [0.1.1] — 2026-04-29

### Security

- Replace the unmaintained `serde_yml` crate (and its `libyml` dependency)
  with the community-maintained [`serde_yaml_ng`](https://crates.io/crates/serde_yaml_ng)
  fork. Closes two open Dependabot advisories: [GHSA-gfxp-f68g-8x78][]
  (high — `libyml::string::yaml_string_extend` is unsound) and
  [GHSA-hhw4-xg65-fp2x][] (medium — `serde_yml` crate is unmaintained).
  YAML parsing behavior is unchanged; this is a drop-in API swap.

[GHSA-gfxp-f68g-8x78]: https://github.com/advisories/GHSA-gfxp-f68g-8x78
[GHSA-hhw4-xg65-fp2x]: https://github.com/advisories/GHSA-hhw4-xg65-fp2x

## [0.1.0] — 2026-04-29

First tagged release. The CLI is functional end-to-end against GitHub.com,
covering ten built-in rules with NIST 800-53 control mappings.

### Added

- `audit`, `diff`, and `apply` commands covering ten rules: `branch_protection`,
  `merge_settings`, `secret_scanning`, `required_files`, `codeowners`,
  `dependabot_security`, `workflow_permissions`, `workflow_yaml`,
  `signed_commits`, and `teams_only_access`.
- `init` command with three opinionated presets (`minimal`, `standard`,
  `strict`). Templates are heavily commented and double as the live schema
  reference via `repocat init --preset strict --stdout`.
- `repo add <name>` for appending a repo entry to an existing baseline while
  preserving comments.
- Top-level `defaults:` block. Per-repo entries overlay defaults: scalars
  override, vec fields extend and dedupe, nested struct fields recurse with the
  same rules.
- `--format json` and `--format sarif` output for `audit`, suitable for
  downstream tooling and GitHub Code Scanning upload.
- Preflight OAuth scope check on `apply` so runs that need the `workflow` scope
  fail fast with an explicit `gh auth refresh` hint.
- Prebuilt binaries on each tagged release for Linux (x86_64, aarch64), macOS
  (x86_64, aarch64), and Windows (x86_64).

[0.4.0]: https://github.com/Battle-Creek-LLC/repocat/releases/tag/v0.4.0
[0.3.0]: https://github.com/Battle-Creek-LLC/repocat/releases/tag/v0.3.0
[0.2.0]: https://github.com/Battle-Creek-LLC/repocat/releases/tag/v0.2.0
[0.1.2]: https://github.com/Battle-Creek-LLC/repocat/releases/tag/v0.1.2
[0.1.1]: https://github.com/Battle-Creek-LLC/repocat/releases/tag/v0.1.1
[0.1.0]: https://github.com/Battle-Creek-LLC/repocat/releases/tag/v0.1.0
