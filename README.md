# repocat

GitHub repository hardening CLI. Reads a declarative `.repo.yml` baseline and
either reports drift (`audit`) or reconciles it (`apply`).

## Install

### crates.io (recommended)

```sh
cargo install bcl-repocat
```

Installs the `repocat` binary. The crate is published as **`bcl-repocat`**
(`repocat` was already taken on crates.io by an unrelated project) — the command
is still `repocat`.

On Linux the `keyring` crate needs `libdbus-1-dev` and `pkg-config`
(`sudo apt-get install libdbus-1-dev pkg-config` on Debian/Ubuntu).

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

`repocat` is driven by a `.repo.yml` baseline that lists your GitHub org, the
repos to harden, and the rules to enforce. A typical first run:

```sh
gh auth login                                # if you haven't already
repocat init --preset standard --org my-org  # writes .repo.yml in the current dir
repocat repo add my-repo                     # add each repo you want to harden
repocat audit                                # report drift
repocat diff                                 # preview what `apply` would change
repocat apply                                # reconcile the repo to .repo.yml
```

`.repo.yml` is created and read from the current working directory — `cd` to
wherever you want it to live, or pass `-f <path>` to point elsewhere. The
`error: reading .repo.yml: No such file or directory` message just means you
haven't run `init` in that directory yet.

> **Stuck on an error or finding?** Paste the command, the output, and your
> `.repo.yml` into Claude Code, Cursor, or ChatGPT and ask what to do.
> `repocat`'s output is designed to be agent-friendly — an LLM will usually
> translate a finding into a concrete fix faster than scanning the rule
> reference below.

## Status

Early development. `audit`, `diff`, and `apply` work for these rules:

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
- `org_code_security` (CM-6, SI-2, SI-4) — **org-scoped** (runs once per invocation, not per repo); manages a GitHub code security configuration and sets it as the org default for new repos. See [Upgrading](#upgrading)

## Usage

```sh
repocat audit                       # report drift, exit 1 on error-severity failures
repocat audit --format json         # structured findings for downstream tooling
repocat audit --format sarif        # SARIF 2.1.0 for GitHub Code Scanning upload
repocat diff                        # preview changes apply would make
repocat apply                       # reconcile to .repo.yml
repocat apply --dry-run             # same as `diff`
repocat changelog                   # release notes for the installed version
repocat changelog --since 0.2.0     # only what changed since a version
repocat changelog --upgrade         # how to upgrade + adopt new .repo.yml fields
```

Credentials are resolved from `GH_TOKEN`/`GITHUB_TOKEN`, then the macOS
keychain (matching the `gh` CLI), then `~/.config/gh/hosts.yml`.

## Upgrading

Upgrade the tool with `cargo install bcl-repocat` (add `--force` to replace an
older build). The changelog and the `.repo.yml` migration notes are baked into
the binary, so they always match the version you have installed:

```sh
repocat changelog            # full release notes
repocat changelog --upgrade  # how to upgrade and adopt new .repo.yml fields
```

The upgrade notes live in [`CHANGELOG.md`](CHANGELOG.md) under each release's
`### Upgrading` heading (that's exactly what `changelog --upgrade` prints). Older
versions reject `.repo.yml` files that use newer fields with an `unknown field`
error — upgrade before adopting a new block (e.g. `org_security`, added in 0.3.0).
