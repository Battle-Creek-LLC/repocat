# repocat

GitHub repository hardening CLI. Reads a declarative `.repo.yml` baseline and
either reports drift (`audit`) or reconciles it (`apply`).

## Status

Early development. `audit`, `diff`, and `apply` work for these rules:

- `branch_protection` (AC-3, CM-3)
- `merge_settings` (CM-3)
- `secret_scanning` (SI-2, SI-4)

## Usage

```sh
repocat audit             # report drift, exit 1 on error-severity failures
repocat diff              # preview changes apply would make
repocat apply             # reconcile to .repo.yml
repocat apply --dry-run   # same as `diff`
```

Credentials are resolved from `GH_TOKEN`/`GITHUB_TOKEN`, then the macOS
keychain (matching the `gh` CLI), then `~/.config/gh/hosts.yml`.
