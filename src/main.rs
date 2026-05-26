mod finding;
mod github;
mod gitlab;
mod output;
mod provider;

use anyhow::{anyhow, Context, Result};
use std::{fs, path::PathBuf, process::ExitCode};

use crate::github::presets::Preset;
use crate::output::Format;
use crate::provider::Provider;

const DEFAULT_CONFIG: &str = provider::GITHUB_CONFIG;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Audit,
    Diff,
    Apply,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return ExitCode::from(2);
    }
    let cmd = args[1].as_str();
    let rest = &args[2..];

    let result: Result<ExitCode> = match cmd {
        "audit" => run(Mode::Audit, rest),
        "diff" => run(Mode::Diff, rest),
        "apply" => run(Mode::Apply, rest),
        "init" => run_init(rest),
        "repo" => run_repo(rest),
        "changelog" => run_changelog(rest),
        "version" => {
            println!("repocat {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(ExitCode::SUCCESS)
        }
        other => Err(anyhow!("unknown command: {other}")),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage:\n  \
         repocat audit [<repo>...] [-f <path>] [--all] [--format text|json|sarif]\n  \
         repocat diff  [<repo>...] [-f <path>] [--all]\n  \
         repocat apply [<repo>...] [-f <path>] [--all] [--dry-run]\n  \
         repocat init  [--preset minimal|standard|strict] [-f <path>] [--stdout] [--force] [--org <name>]\n  \
         repocat repo add <name> [-f <path>]\n  \
         repocat changelog [--since <version>] [--upgrade]\n  \
         repocat version\n\
         \n\
         Tip: to see every available setting with comments, run:\n  \
         repocat init --preset strict --stdout"
    );
}

pub struct Args {
    pub config_path: Option<PathBuf>,
    pub filter_repos: Vec<String>,
    pub all: bool,
    pub dry_run: bool,
    pub format: Format,
}

fn parse_args(args: &[String]) -> Result<Args> {
    let mut out = Args {
        config_path: None,
        filter_repos: Vec::new(),
        all: false,
        dry_run: false,
        format: Format::Text,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--file" => {
                i += 1;
                out.config_path = Some(PathBuf::from(
                    args.get(i).ok_or_else(|| anyhow!("--file needs a value"))?,
                ));
            }
            "--all" => out.all = true,
            "--dry-run" => out.dry_run = true,
            "--format" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| anyhow!("--format needs a value"))?;
                out.format = output::parse_format(v)?;
            }
            other if !other.starts_with('-') => out.filter_repos.push(other.to_string()),
            other => return Err(anyhow!("unknown flag: {other}")),
        }
        i += 1;
    }
    Ok(out)
}

// Dispatch: discover which config files are present (or the explicit -f), then
// hand each to its provider module. The providers are equals — neither is the
// default — so `main` only routes and aggregates; the per-host pipeline,
// rendering, and execution live inside the module.
fn run(mode: Mode, raw_args: &[String]) -> Result<ExitCode> {
    let args = parse_args(raw_args)?;
    let effective_mode = if mode == Mode::Apply && args.dry_run { Mode::Diff } else { mode };
    if args.format != Format::Text && effective_mode != Mode::Audit {
        return Err(anyhow!("--format is only supported with `audit`"));
    }

    let configs = provider::discover(args.config_path.as_deref())?;

    let mut any_error = false;
    let mut any_apply_error = false;
    // `--format` implies `audit`, and in practice at most one config of each
    // kind is present, so holding the last outcome covers JSON/SARIF rendering.
    let mut deferred: Option<finding::Outcome> = None;

    for (prov, path) in configs {
        let outcome = match prov {
            Provider::GitHub => github::run(mode, &path, &args)?,
            Provider::GitLab => gitlab::run(mode, &path, &args)?,
        };
        any_error |= outcome.any_error;
        any_apply_error |= outcome.any_apply_error;
        if args.format != Format::Text {
            deferred = Some(outcome);
        }
    }

    if let Some(o) = deferred {
        let rendered = match args.format {
            Format::Json => output::render_json(&o.namespace, &o.findings)?,
            Format::Sarif => output::render_sarif(&o.namespace, &o.findings)?,
            Format::Text => unreachable!("text doesn't defer"),
        };
        println!("{rendered}");
    }

    let code = match effective_mode {
        Mode::Audit | Mode::Diff => if any_error { 1 } else { 0 },
        Mode::Apply => if any_apply_error { 3 } else { 0 },
    };
    Ok(ExitCode::from(code))
}

fn run_init(raw_args: &[String]) -> Result<ExitCode> {
    let mut preset = Preset::Standard;
    let mut path = PathBuf::from(DEFAULT_CONFIG);
    let mut force = false;
    let mut to_stdout = false;
    let mut org_override: Option<String> = None;

    let mut i = 0;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "--preset" => {
                i += 1;
                let v = raw_args.get(i).ok_or_else(|| anyhow!("--preset needs a value"))?;
                preset = Preset::parse(v)?;
            }
            "-f" | "--file" => {
                i += 1;
                path = PathBuf::from(
                    raw_args.get(i).ok_or_else(|| anyhow!("--file needs a value"))?,
                );
            }
            "--stdout" => to_stdout = true,
            "--force" => force = true,
            "--org" => {
                i += 1;
                org_override = Some(
                    raw_args.get(i).ok_or_else(|| anyhow!("--org needs a value"))?.clone(),
                );
            }
            other => return Err(anyhow!("unknown flag for init: {other}")),
        }
        i += 1;
    }

    let org = match org_override {
        Some(o) => o,
        None => github::git::detect_org().map_err(|e| {
            anyhow!("could not detect org from git remote ({e}); pass --org <name>")
        })?,
    };

    let rendered = github::init_template(preset, &org);

    if to_stdout {
        print!("{rendered}");
        return Ok(ExitCode::SUCCESS);
    }

    if path.exists() && !force {
        return Err(anyhow!(
            "{} already exists; pass --force to overwrite or --stdout to print",
            path.display()
        ));
    }
    fs::write(&path, &rendered)
        .with_context(|| format!("writing {}", path.display()))?;
    eprintln!("wrote {}", path.display());

    // Validate by running the same loader the other commands use.
    github::config::load(&path).with_context(|| {
        format!("template wrote but failed to re-parse from {}", path.display())
    })?;
    Ok(ExitCode::SUCCESS)
}

// `changelog` prints the release notes baked into the binary at build time, so
// the output always matches the installed version. `--since` filters to newer
// entries; `--upgrade` prints the consumer upgrade guide (how to update the tool
// and adopt new `.repo.yml` fields) instead.
const CHANGELOG: &str = include_str!("../CHANGELOG.md");

const UPGRADE_HEADER: &str = "\
# Upgrading repocat

Update the tool with `cargo install bcl-repocat` (add `--force` to replace an
older build), then adopt any new `.repo.yml` fields below. Older versions reject
files that use newer fields with an `unknown field` error.

";

fn run_changelog(raw_args: &[String]) -> Result<ExitCode> {
    let mut since: Option<String> = None;
    let mut upgrade = false;
    let mut i = 0;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "--upgrade" => upgrade = true,
            "--since" => {
                i += 1;
                since = Some(raw_args.get(i).ok_or_else(|| anyhow!("--since needs a value"))?.clone());
            }
            other => return Err(anyhow!("unknown flag for changelog: {other}")),
        }
        i += 1;
    }
    if upgrade {
        // The upgrade guide is derived from the `### Upgrading` sections in
        // CHANGELOG.md — one source of truth, so it can't drift from the notes.
        print!("{UPGRADE_HEADER}");
        let notes = extract_upgrade_notes(CHANGELOG, since.as_deref())?;
        if notes.trim().is_empty() {
            println!("No `.repo.yml` schema changes to adopt in this range.");
        } else {
            print!("{notes}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    match since {
        None => print!("{CHANGELOG}"),
        Some(v) => print!("{}", filter_changelog_since(CHANGELOG, &v)?),
    }
    Ok(ExitCode::SUCCESS)
}

// Collects the `### Upgrading` subsection from each version section, prefixed by
// that version's heading for context. With `since`, only versions newer than it
// are included — the set of steps an agent needs to go from `since` to current.
fn extract_upgrade_notes(full: &str, since: Option<&str>) -> Result<String> {
    let target = match since {
        Some(s) => Some(
            parse_version(s).ok_or_else(|| anyhow!("invalid --since version `{s}` (want X.Y.Z)"))?,
        ),
        None => None,
    };
    let mut out = String::new();
    let mut current_header: Option<&str> = None;
    let mut version_included = false;
    let mut header_emitted = false;
    let mut in_upgrade = false;
    for line in full.lines() {
        if line.starts_with("## [") {
            current_header = Some(line);
            version_included = heading_version(line).is_none_or(|v| target.is_none_or(|t| v > t));
            header_emitted = false;
            in_upgrade = false;
        } else if line.starts_with("### ") {
            in_upgrade = version_included && line.starts_with("### Upgrading");
        } else if in_upgrade {
            if !header_emitted {
                if !out.is_empty() {
                    out.push('\n');
                }
                if let Some(h) = current_header {
                    out.push_str(h);
                    out.push('\n');
                }
                header_emitted = true;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    Ok(out)
}

// Parses a dotted "X.Y.Z" (an optional leading `v` is tolerated) into a tuple
// for ordering. Returns None for anything that isn't three numeric components.
fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.trim().trim_start_matches('v').split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

// Extracts the version from a Keep-a-Changelog heading like `## [0.3.0] — ...`.
fn heading_version(line: &str) -> Option<(u32, u32, u32)> {
    let start = line.find('[')? + 1;
    let end = line[start..].find(']')? + start;
    parse_version(&line[start..end])
}

// Keeps the preamble (everything before the first version heading) plus every
// section newer than `since`. The trailing link-reference block follows the
// oldest section's keep state, which is the desired behaviour: drop it when the
// oldest section is filtered out.
fn filter_changelog_since(full: &str, since: &str) -> Result<String> {
    let target = parse_version(since)
        .ok_or_else(|| anyhow!("invalid --since version `{since}` (want X.Y.Z)"))?;
    let mut out = String::new();
    let mut keep = true;
    for line in full.lines() {
        if line.starts_with("## [") {
            // An unparseable heading is kept rather than silently dropped.
            keep = heading_version(line).is_none_or(|v| v > target);
        }
        if keep {
            out.push_str(line);
            out.push('\n');
        }
    }
    Ok(out)
}

fn run_repo(raw_args: &[String]) -> Result<ExitCode> {
    let sub = raw_args.first().map(String::as_str).ok_or_else(|| {
        anyhow!("repo: missing subcommand (try `repocat repo add <name>`)")
    })?;
    match sub {
        "add" => run_repo_add(&raw_args[1..]),
        other => Err(anyhow!("unknown repo subcommand: {other}")),
    }
}

fn run_repo_add(raw_args: &[String]) -> Result<ExitCode> {
    let mut name: Option<String> = None;
    let mut path = PathBuf::from(DEFAULT_CONFIG);

    let mut i = 0;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "-f" | "--file" => {
                i += 1;
                path = PathBuf::from(
                    raw_args.get(i).ok_or_else(|| anyhow!("--file needs a value"))?,
                );
            }
            other if !other.starts_with("--") => {
                if name.is_some() {
                    return Err(anyhow!("repo add takes a single <name> argument"));
                }
                name = Some(other.to_string());
            }
            other => return Err(anyhow!("unknown flag for repo add: {other}")),
        }
        i += 1;
    }
    let name = name.ok_or_else(|| anyhow!("repo add: missing <name>"))?;

    let text = fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    if !has_top_level_key(&text, "defaults") {
        return Err(anyhow!(
            "{} has no top-level `defaults:` block; run `repocat init` first",
            path.display()
        ));
    }
    if has_repo_entry(&text, &name) {
        return Err(anyhow!(
            "repo `{name}` already present in {}",
            path.display()
        ));
    }

    let new_text = append_repo_entry(&text, &name)?;
    fs::write(&path, &new_text)
        .with_context(|| format!("writing {}", path.display()))?;
    eprintln!("added repo `{name}` to {}", path.display());

    github::config::load(&path).with_context(|| {
        format!("file wrote but failed to re-parse from {}", path.display())
    })?;
    Ok(ExitCode::SUCCESS)
}

// True if a non-indented line of the form `key:` (or `key: ...`) appears.
// This is a text-level scan rather than a YAML reparse so we can keep
// existing comments and formatting intact when editing the file.
fn has_top_level_key(text: &str, key: &str) -> bool {
    text.lines().any(|line| {
        let trimmed_end = line.trim_end();
        if trimmed_end.starts_with(' ') || trimmed_end.starts_with('\t') {
            return false;
        }
        let stripped = match trimmed_end.strip_prefix(key) {
            Some(s) => s,
            None => return false,
        };
        stripped.starts_with(':')
    })
}

fn has_repo_entry(text: &str, name: &str) -> bool {
    let mut in_repos = false;
    for line in text.lines() {
        if line.starts_with("repos:") {
            in_repos = true;
            continue;
        }
        if !in_repos {
            continue;
        }
        // Leaving the repos block: any non-indented, non-blank, non-comment line
        // (other than the `repos:` line itself) marks the end.
        let trimmed = line.trim_start();
        if !line.starts_with(' ') && !line.starts_with('\t') && !trimmed.is_empty()
            && !trimmed.starts_with('#')
        {
            in_repos = false;
            continue;
        }
        // A repo entry is `  <name>:` (any depth of indent, then `name:`).
        if let Some(rest) = trimmed.strip_prefix(name) {
            if rest.starts_with(':') {
                return true;
            }
        }
    }
    false
}

// Append `<name>: {}` under the existing `repos:` block. If the block is
// `repos: {}` (the empty-flow-mapping form preset templates ship with),
// rewrite it to a block-style mapping with the new entry. Otherwise append a
// new line to the end of the block.
fn append_repo_entry(text: &str, name: &str) -> Result<String> {
    let lines: Vec<&str> = text.lines().collect();
    let repos_idx = lines
        .iter()
        .position(|l| l.starts_with("repos:"))
        .ok_or_else(|| anyhow!("no top-level `repos:` block found"))?;
    let trailing_newline = text.ends_with('\n');

    // Case 1: `repos: {}` — convert to block form with the new entry.
    if lines[repos_idx].trim_end() == "repos: {}" {
        let mut out: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
        out[repos_idx] = "repos:".to_string();
        out.insert(repos_idx + 1, format!("  {name}: {{}}"));
        return Ok(join_lines(&out, trailing_newline));
    }

    // Case 2: block-style `repos:` — append after the last line that belongs
    // to the block (last indented or comment line following `repos:`).
    let mut last_in_block = repos_idx;
    for (i, line) in lines.iter().enumerate().skip(repos_idx + 1) {
        let trimmed = line.trim_start();
        let is_blank = trimmed.is_empty();
        let is_comment = trimmed.starts_with('#');
        let is_indented = line.starts_with(' ') || line.starts_with('\t');
        if is_indented || is_blank || is_comment {
            if is_indented || is_comment {
                last_in_block = i;
            }
            continue;
        }
        break;
    }
    let mut out: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    out.insert(last_in_block + 1, format!("  {name}: {{}}"));
    Ok(join_lines(&out, trailing_newline))
}

fn join_lines(lines: &[String], trailing_newline: bool) -> String {
    let mut s = lines.join("\n");
    if trailing_newline {
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod text_edit_tests {
    use super::*;

    #[test]
    fn detects_top_level_key_only() {
        let yml = "org: acme\ndefaults:\n  branch_protection:\n    branch: main\nrepos: {}\n";
        assert!(has_top_level_key(yml, "defaults"));
        assert!(has_top_level_key(yml, "org"));
        assert!(has_top_level_key(yml, "repos"));
        // nested keys must not match
        assert!(!has_top_level_key(yml, "branch_protection"));
        assert!(!has_top_level_key(yml, "branch"));
    }

    #[test]
    fn detects_existing_repo_entry() {
        let yml = "org: acme\ndefaults:\n  merge:\n    allow_squash: true\nrepos:\n  alpha: {}\n  beta: {}\n";
        assert!(has_repo_entry(yml, "alpha"));
        assert!(has_repo_entry(yml, "beta"));
        assert!(!has_repo_entry(yml, "gamma"));
        // do not mistake a defaults nested key for a repo entry
        assert!(!has_repo_entry(yml, "merge"));
    }

    #[test]
    fn append_into_empty_flow_mapping_repos() {
        let yml = "org: acme\ndefaults:\n  merge:\n    allow_squash: true\nrepos: {}\n";
        let out = append_repo_entry(yml, "alpha").unwrap();
        assert!(out.contains("\nrepos:\n  alpha: {}\n"), "got:\n{out}");
        assert!(!out.contains("repos: {}"));
    }

    #[test]
    fn append_into_block_mapping_repos_preserves_existing() {
        let yml = "org: acme\ndefaults:\n  merge:\n    allow_squash: true\nrepos:\n  alpha: {}\n";
        let out = append_repo_entry(yml, "beta").unwrap();
        assert!(out.contains("  alpha: {}"));
        assert!(out.contains("  beta: {}"));
        // alpha must come before beta
        let a = out.find("alpha").unwrap();
        let b = out.find("beta").unwrap();
        assert!(a < b);
    }

    #[test]
    fn append_preserves_trailing_newline() {
        let yml = "org: acme\ndefaults:\n  merge:\n    allow_squash: true\nrepos: {}\n";
        let out = append_repo_entry(yml, "alpha").unwrap();
        assert!(out.ends_with('\n'));
    }

    const SAMPLE_CHANGELOG: &str = "\
# Changelog

intro paragraph

## [0.3.0] — 2026-05-25

org_security added

## [0.2.0] — 2026-05-23

release workflow

## [0.1.0] — 2026-04-29

first release

[0.3.0]: https://example/v0.3.0
[0.2.0]: https://example/v0.2.0
";

    #[test]
    fn parse_version_handles_v_prefix_and_rejects_non_triples() {
        assert_eq!(parse_version("0.3.0"), Some((0, 3, 0)));
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.3"), None);
        assert_eq!(parse_version("0.3.0.1"), None);
        assert_eq!(parse_version("x.y.z"), None);
    }

    #[test]
    fn heading_version_extracts_bracketed_version() {
        assert_eq!(heading_version("## [0.3.0] — 2026-05-25"), Some((0, 3, 0)));
        assert_eq!(heading_version("## not a version"), None);
    }

    #[test]
    fn changelog_since_keeps_newer_sections_and_preamble() {
        let out = filter_changelog_since(SAMPLE_CHANGELOG, "0.2.0").unwrap();
        assert!(out.contains("# Changelog"), "preamble kept");
        assert!(out.contains("## [0.3.0]"), "newer section kept");
        assert!(!out.contains("## [0.2.0]"), "equal version excluded");
        assert!(!out.contains("## [0.1.0]"), "older section excluded");
        // footer link refs trail the oldest (excluded) section, so they drop too
        assert!(!out.contains("[0.2.0]: https"));
    }

    #[test]
    fn changelog_since_rejects_invalid_version() {
        assert!(filter_changelog_since(SAMPLE_CHANGELOG, "garbage").is_err());
    }

    #[test]
    fn changelog_since_newer_than_all_keeps_only_preamble() {
        let out = filter_changelog_since(SAMPLE_CHANGELOG, "9.9.9").unwrap();
        assert!(out.contains("# Changelog"));
        assert!(!out.contains("## ["));
    }

    const SAMPLE_WITH_UPGRADE: &str = "\
# Changelog

intro

## [0.3.0] — 2026-05-25

### Added

- a feature

### Upgrading

add the org_security block.

## [0.2.0] — 2026-05-23

### Changed

- ci-only change, no schema impact

## [0.1.3] — 2026-05-23

### Upgrading

set require_semgrep_workflow.
";

    #[test]
    fn upgrade_notes_collect_upgrading_sections_with_headers() {
        let out = extract_upgrade_notes(SAMPLE_WITH_UPGRADE, None).unwrap();
        assert!(out.contains("## [0.3.0]"), "version header for an upgrade section");
        assert!(out.contains("add the org_security block."));
        assert!(out.contains("## [0.1.3]"));
        assert!(out.contains("set require_semgrep_workflow."));
        // a version with no `### Upgrading` contributes nothing
        assert!(!out.contains("## [0.2.0]"));
        assert!(!out.contains("ci-only change"));
        // non-Upgrading content from an included version is excluded
        assert!(!out.contains("- a feature"));
    }

    #[test]
    fn upgrade_notes_since_excludes_older_versions() {
        let out = extract_upgrade_notes(SAMPLE_WITH_UPGRADE, Some("0.2.0")).unwrap();
        assert!(out.contains("## [0.3.0]"));
        assert!(out.contains("add the org_security block."));
        // 0.1.3 is older than 0.2.0 -> dropped
        assert!(!out.contains("## [0.1.3]"));
        assert!(!out.contains("require_semgrep_workflow"));
    }

    #[test]
    fn upgrade_notes_reject_invalid_since() {
        assert!(extract_upgrade_notes(SAMPLE_WITH_UPGRADE, Some("nope")).is_err());
    }
}
