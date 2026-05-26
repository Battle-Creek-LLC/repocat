# Releasing repocat

`repocat` is published to crates.io as **`bcl-repocat`**. A release is cut by
pushing a `vX.Y.Z` tag, which fires
[`.github/workflows/release.yml`](../.github/workflows/release.yml). That
workflow:

1. **create-release** — creates the GitHub release for the tag.
2. **upload-assets** — builds the per-target binaries and attaches an archive
   plus a `.sha256` checksum for each of the 5 targets:
   - `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`
   - `x86_64-apple-darwin`, `aarch64-apple-darwin`
   - `x86_64-pc-windows-msvc`
3. **publish-crate** — `cargo publish` using the org-level `CRATES_IO_TOKEN`
   secret.

The tag push is the trigger and is effectively irreversible (a published
crates.io version cannot be unpublished, only yanked). **Confirm the version is
correct before tagging.**

## 1. Sync and sanity-check `main`

```sh
git checkout main && git pull --ff-only
```

Then confirm, replacing `X.Y.Z` with the release version. **Stop and
investigate if any of these disagree** — they are the guard against tagging the
wrong code:

- `version = "X.Y.Z"` in `Cargo.toml`.
- `Cargo.lock` agrees: `cargo build --locked` succeeds and reports
  `bcl-repocat vX.Y.Z`.
- `CHANGELOG.md` has a `## [X.Y.Z]` section.
- The release PR for this version is **merged** to `main` (not just open).

```sh
cargo test   # all green before tagging
```

## 2. Tag and push (the release trigger)

```sh
git tag -a vX.Y.Z -m "repocat X.Y.Z — <summary>"
git push origin vX.Y.Z
```

If `git push` is rejected because the tag already exists, the release was
already cut — skip to step 4 and verify rather than re-tagging.

## 3. Watch the release workflow

```sh
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')" --exit-status
```

If it fails: read the failed job log, fix forward on `main`, and re-run via
`workflow_dispatch` with input `tag: vX.Y.Z` — **do not re-tag**:

```sh
gh workflow run release.yml -f tag=vX.Y.Z
```

## 4. Verify the release landed

```sh
gh release view vX.Y.Z          # confirm 5 archives + 5 .sha256 attached
curl -s https://crates.io/api/v1/crates/bcl-repocat | jq -r .crate.max_version   # == X.Y.Z
cargo install bcl-repocat --force && repocat version                              # repocat X.Y.Z
```

## Notes

- Only **squash-merge** is enabled on this repo, so the release PR squashes to a
  single commit on `main`.
- `main` is branch-protected; the release PR must clear its required review
  before it can be merged. The release cannot proceed until then.
