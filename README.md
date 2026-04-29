# repocat

GitHub repository hardening CLI. Reads a declarative `.repo.yml` baseline and
either reports drift (`audit`) or reconciles it (`apply`).

## Install

Prebuilt binaries are attached to each [release](https://github.com/Battle-Creek-LLC/repocat/releases).
Each archive ships a single `repocat` (or `repocat.exe`) binary plus a
matching `.sha256` checksum.

### macOS (Apple Silicon)

```sh
gh release download --pattern 'repocat-aarch64-apple-darwin.tar.gz' -R Battle-Creek-LLC/repocat
tar -xzf repocat-aarch64-apple-darwin.tar.gz
sudo mv repocat /usr/local/bin/
```

### macOS (Intel)

```sh
gh release download --pattern 'repocat-x86_64-apple-darwin.tar.gz' -R Battle-Creek-LLC/repocat
tar -xzf repocat-x86_64-apple-darwin.tar.gz
sudo mv repocat /usr/local/bin/
```

> Binaries aren't notarized. On first run macOS may block them — clear the
> quarantine attribute with `xattr -d com.apple.quarantine /usr/local/bin/repocat`.

### Linux (x86_64)

```sh
gh release download --pattern 'repocat-x86_64-unknown-linux-gnu.tar.gz' -R Battle-Creek-LLC/repocat
tar -xzf repocat-x86_64-unknown-linux-gnu.tar.gz
sudo mv repocat /usr/local/bin/
```

### Linux (ARM64)

```sh
gh release download --pattern 'repocat-aarch64-unknown-linux-gnu.tar.gz' -R Battle-Creek-LLC/repocat
tar -xzf repocat-aarch64-unknown-linux-gnu.tar.gz
sudo mv repocat /usr/local/bin/
```

### Windows (PowerShell)

```powershell
gh release download --pattern 'repocat-x86_64-pc-windows-msvc.zip' -R Battle-Creek-LLC/repocat
Expand-Archive repocat-x86_64-pc-windows-msvc.zip -DestinationPath .
# Move repocat.exe into a directory on your PATH, e.g.:
Move-Item repocat.exe "$env:USERPROFILE\bin\"
```

### From source

```sh
cargo install --git https://github.com/Battle-Creek-LLC/repocat
```

On Linux the `keyring` crate needs `libdbus-1-dev` and `pkg-config` installed
(`sudo apt-get install libdbus-1-dev pkg-config` on Debian/Ubuntu).

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
