# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.2]: https://github.com/Battle-Creek-LLC/repocat/releases/tag/v0.1.2
[0.1.1]: https://github.com/Battle-Creek-LLC/repocat/releases/tag/v0.1.1
[0.1.0]: https://github.com/Battle-Creek-LLC/repocat/releases/tag/v0.1.0
