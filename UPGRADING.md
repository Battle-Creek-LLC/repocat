# Upgrading

How to upgrade repocat and adopt new `.repo.yml` features. Run
`repocat changelog` for the full release notes, or `repocat changelog --upgrade`
to print this guide.

## Upgrade the tool

```sh
cargo install bcl-repocat        # crates.io (add --force to replace an older build)
# or: cargo binstall bcl-repocat # prebuilt binary, no compile
```

`repocat version` prints the installed version. Older versions reject `.repo.yml`
files that use newer fields with an `unknown field` error — upgrade the tool
before adopting the schema changes below.

## `.repo.yml` schema changes

### 0.3.0 — org-wide code security (`org_security`)

repocat's first org-scoped block. It manages a GitHub *code security
configuration* and sets it as the org default for new repositories — the
org-level backstop for the per-repo `security:` block. Notably it re-enables
Dependency Graph if it has been disabled org-wide, a state the per-repo
`dependabot_security` check can't detect on public repos (GitHub omits the field
and absence reads as enabled).

Add a top-level `org_security:` block (a sibling of `defaults:` and `repos:`):

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

Requirements:

- repocat **0.3.0+**.
- `apply` needs a token with the **`admin:org`** scope (reading the config during
  `audit` only needs `read:org`): `gh auth refresh -s admin:org`.

`audit`/`diff` report whether the configuration exists with the wanted features
and is the default for the chosen scope; `apply` creates or updates it and sets
the default. `default_for_new_repos` governs repos created *after* it is set —
consult GitHub's code security configuration docs to also attach it to existing
repos.

### 0.1.3 — Semgrep workflow (`actions.require_semgrep_workflow`)

Set `require_semgrep_workflow: true` under a repo's `actions:` block and repocat
audits for `.github/workflows/semgrep.yml`, scaffolding one if missing (Semgrep
OSS rulesets → SARIF → GitHub code scanning). Skipped on private repos, where
SARIF upload needs GitHub Advanced Security.
