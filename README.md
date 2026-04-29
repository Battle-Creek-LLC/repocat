# repocat

GitHub repository hardening CLI. Reads a declarative `.repo.yml` baseline and
either reports drift (`audit`) or reconciles it (`apply`).

## Install

Prebuilt binaries for Linux, macOS, and Windows are attached to each release.
Pick the archive matching your platform (`x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, or
`x86_64-pc-windows-msvc`):

```sh
gh release download --pattern '*<your-platform>*' -R Battle-Creek-LLC/repocat
tar -xzf repocat-*.tar.gz
mv repocat /usr/local/bin/
```

Or build from source:

```sh
cargo install --git https://github.com/Battle-Creek-LLC/repocat
```

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
- `signed_commits` (SI-7) — required-signatures enforcement on the protected branch
- `teams_only_access` (AC-2, AC-6) — audit-only; flags direct collaborators and team-permission drift

## Usage

```sh
repocat audit                       # report drift, exit 1 on error-severity failures
repocat audit --format json         # structured findings for downstream tooling
repocat audit --format sarif        # SARIF 2.1.0 for GitHub Code Scanning upload
repocat diff                        # preview changes apply would make
repocat apply                       # reconcile to .repo.yml
repocat apply --dry-run             # same as `diff`
```

Credentials are resolved from `GH_TOKEN`/`GITHUB_TOKEN`, then the macOS
keychain (matching the `gh` CLI), then `~/.config/gh/hosts.yml`.
