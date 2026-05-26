# Using repocat with GitLab

> **Status: available (since 0.5.0).** `audit`, `diff`, and `apply` work for
> GitLab projects. See [`docs/specs/0001-gitlab-support.md`](specs/0001-gitlab-support.md)
> for the design.

`repocat` hardens GitLab **projects** the same way it hardens GitHub repos:
`audit` / `diff` / `apply` against a declarative baseline. GitLab and GitHub are
**co-equal** — each has its own config file and its own schema in that host's
native vocabulary. There is no default provider and no shared config.

- GitHub config lives in **`.repo.github.yml`**.
- GitLab config lives in **`.repo.gitlab.yml`**.

The filename tells `repocat` which host it's for. With no arguments, `repocat`
runs whichever of the two files are present (both, if both exist); `-f <path>`
targets one.

## Authentication — reuses your `glab` login

If you've authenticated the [`glab`](https://gitlab.com/gitlab-org/cli) CLI,
`repocat` reuses that token automatically. No separate login.

```sh
glab auth login            # if you haven't already
repocat audit              # reads .repo.gitlab.yml, uses the token glab stored
```

Resolution order (first match wins):

1. **`GITLAB_TOKEN`** environment variable.
2. **`glab`'s config** at `~/.config/glab-cli/config.yml` (or `$GLAB_CONFIG_DIR`
   / `$XDG_CONFIG_HOME/glab-cli`). repocat reads the `token` for the relevant
   host from the `hosts:` block — the same plaintext token `glab` itself uses.
   (`glab` does not use the OS keyring, so there's nothing to unlock.)

The host is chosen from `host:` in `.repo.gitlab.yml`, else the git remote, else
`glab`'s default `host:`, else `gitlab.com`.

A personal access token with the **`api`** scope is required for `apply`;
**`read_api`** is enough for `audit` and `diff`.

> **Self-managed instances:** repocat respects the `api_host`, `api_protocol`,
> `subfolder`, and `skip_tls_verify` from your `glab` host block, so a
> self-managed GitLab works with no extra flags. If glab is set to skip TLS
> verification for that host, repocat honors it for that host too (it prints a
> one-line notice) — matching glab rather than failing the handshake where glab
> succeeds.

## Writing `.repo.gitlab.yml`

The GitLab config is authored in **GitLab's own terms** — protected branches,
approval rules, push rules, project settings, CI security templates. It does not
mirror the GitHub config; the two are written independently.

```yaml
# .repo.gitlab.yml
group: my-group/platform          # namespace path (nested groups allowed)
# host: git.example.com           # self-managed only; defaults to gitlab.com

defaults:
  protected_branches:
    - name: main
      allow_force_push: false
      push_access_level: maintainer       # no_one | developer | maintainer
      merge_access_level: developer
      code_owner_approval_required: true  # Premium
  approval_rules:
    - name: default
      approvals_required: 1
  merge_request_approvals:
    reset_approvals_on_push: true
  project_settings:
    merge_method: ff                       # merge | rebase_merge | ff
    squash_option: default_on              # never | always | default_on | default_off
    remove_source_branch_after_merge: true
    only_allow_merge_if_pipeline_succeeds: true
    only_allow_merge_if_all_discussions_are_resolved: true
  push_rules:
    reject_unsigned_commits: false         # Premium
  required_files:
    - README.md
    - LICENSE
  ci_security:
    require_sast: true                     # GitLab SAST (semgrep-based)
    require_secret_detection: true
    require_dependency_scanning: true
    pin_includes: true                     # pin `include:` refs

projects:                                  # GitLab "projects" within `group`
  my-project: {}
  special-service:
    approval_rules:
      - name: default
        approvals_required: 2
```

Scaffold one with:

```sh
repocat init --provider gitlab     # writes .repo.gitlab.yml
```

(There is no default provider, so `--provider` is required.)

## GitLab rules

GitLab has its own rule set, expressed against the fields above. Highlights:

| Rule | What it checks | Notes |
|------|----------------|-------|
| `protected_branches` | force-push / access levels / code-owner approval | code-owner approval is Premium |
| `approval_rules` | required MR approvals | — |
| `merge_request_approvals` | reset approvals on push | — |
| `project_settings` | merge method, squash, pipeline-must-pass, discussions resolved | — |
| `push_rules` | reject unsigned commits | Premium |
| `required_files` / `codeowners` | files present (`.gitlab/CODEOWNERS`) | fully portable |
| `ci_security` | SAST / secret detection / dependency scanning in `.gitlab-ci.yml` | SAST is semgrep-based |
| `members` | direct members vs group shares + access levels | — |
| `group_security` | group-level security policies | planned later (Phase 2) |

Anything that needs a GitLab tier you don't have (Premium/Ultimate) reports
`Skip` with a reason, not an error — so an audit stays green for what your tier
can enforce.

For the complete rule set, endpoints, access levels, and reconcile caveats, see
the [spec](specs/0001-gitlab-support.md#10-gitlab-rule-set-native).

## Porting an existing GitHub baseline

The two configs are authored independently, but for orientation: a
`.repo.github.yml` `branch_protection` block splits into `protected_branches`
+ `approval_rules` + `project_settings`; `merge` → `project_settings`;
`signed_commits` → `push_rules`; `secret_scanning`/`semgrep_workflow` →
`ci_security`; `teams_only_access` → `members`. You write the GitLab file in
GitLab's terms rather than translating field-by-field.
