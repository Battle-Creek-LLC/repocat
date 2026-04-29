mod api;
mod auth;
mod config;
mod git;
mod output;
mod presets;
mod resolve;
mod rules;

use anyhow::{anyhow, Context, Result};
use std::{fs, path::PathBuf, process::ExitCode};

use crate::config::Config;
use crate::output::Format;
use crate::presets::Preset;
use crate::rules::{Finding, Severity, Status};

const DEFAULT_CONFIG: &str = ".repo.yml";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
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
         repocat version\n\
         \n\
         Tip: to see every available setting with comments, run:\n  \
         repocat init --preset strict --stdout"
    );
}

struct Args {
    config_path: PathBuf,
    filter_repos: Vec<String>,
    all: bool,
    dry_run: bool,
    format: Format,
}

fn parse_args(args: &[String]) -> Result<Args> {
    let mut out = Args {
        config_path: PathBuf::from(DEFAULT_CONFIG),
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
                out.config_path = PathBuf::from(
                    args.get(i).ok_or_else(|| anyhow!("--file needs a value"))?,
                );
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

fn target_repos<'a>(cfg: &'a Config, args: &Args) -> Result<Vec<&'a String>> {
    if args.all || args.filter_repos.is_empty() {
        return Ok(cfg.repos.keys().collect());
    }
    let mut out = Vec::new();
    for name in &args.filter_repos {
        let key = cfg
            .repos
            .keys()
            .find(|k| *k == name)
            .ok_or_else(|| anyhow!("repo `{name}` not found in {}", args.config_path.display()))?;
        out.push(key);
    }
    Ok(out)
}

fn run(mode: Mode, raw_args: &[String]) -> Result<ExitCode> {
    let args = parse_args(raw_args)?;
    let effective_mode = if mode == Mode::Apply && args.dry_run { Mode::Diff } else { mode };

    if args.format != Format::Text && effective_mode != Mode::Audit {
        return Err(anyhow!("--format is only supported with `audit`"));
    }
    let defer_rendering = args.format != Format::Text;

    let cfg = config::load(&args.config_path)?;
    if cfg.repos.is_empty() {
        return Err(anyhow!(
            "no repos in {} — add one with `repocat repo add <name>`",
            args.config_path.display()
        ));
    }
    let (token, login) = auth::load_credentials()?;
    eprintln!("authenticated as {login}");
    let client = api::Client::new(token);

    if effective_mode == Mode::Apply {
        preflight_scopes(&client, &cfg, &args)?;
    }

    let mut any_error = false;
    let mut any_apply_error = false;
    let mut all_findings: Vec<(String, Vec<Finding>)> = Vec::new();

    for name in target_repos(&cfg, &args)? {
        let repo_cfg = resolve::effective(&cfg.defaults, &cfg.repos[name]);
        eprintln!("\n=== {}/{name} ===", cfg.org);
        let findings = rules::run_all(&client, &cfg.org, name, &repo_cfg)?;

        if findings.iter().any(|f| f.status == Status::Fail && f.severity == Severity::Error) {
            any_error = true;
        }

        if !defer_rendering {
            render_table(&findings);
            match effective_mode {
                Mode::Audit => {}
                Mode::Diff => render_actions(&findings),
                Mode::Apply => {
                    if !execute_actions(&client, &cfg.org, name, &findings) {
                        any_apply_error = true;
                    }
                }
            }
        }

        all_findings.push((name.clone(), findings));
    }

    if defer_rendering {
        let rendered = match args.format {
            Format::Json => output::render_json(&cfg.org, &all_findings)?,
            Format::Sarif => output::render_sarif(&cfg.org, &all_findings)?,
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

fn preflight_scopes(client: &api::Client, cfg: &Config, args: &Args) -> Result<()> {
    let needs_workflow = target_repos(cfg, args)?
        .iter()
        .any(|name| {
            resolve::effective(&cfg.defaults, &cfg.repos[*name])
                .actions
                .as_ref()
                .and_then(|a| a.require_dependency_review_action)
                .unwrap_or(false)
        });
    if !needs_workflow {
        return Ok(());
    }
    let scopes = client.oauth_scopes()?;
    if scopes.is_empty() {
        // Fine-grained PAT — scopes don't appear in this header. Trust and proceed;
        // the API will return a clear error if permissions are insufficient.
        return Ok(());
    }
    if !scopes.iter().any(|s| s == "workflow") {
        return Err(anyhow!(
            "apply needs the `workflow` OAuth scope to scaffold dependency-review \
             workflows, but the current token has only [{}]. Run \
             `gh auth refresh --hostname github.com -s workflow` and retry.",
            scopes.join(", ")
        ));
    }
    Ok(())
}

fn render_table(findings: &[Finding]) {
    let rule_w = findings.iter().map(|f| f.rule.len()).max().unwrap_or(4).max(4);
    let sev_w = 7;
    let status_w = 6;

    println!(
        "{:rule_w$}  {:sev_w$}  {:status_w$}  {}",
        "rule", "sev", "status", "details",
        rule_w = rule_w, sev_w = sev_w, status_w = status_w
    );
    println!("{}", "-".repeat(rule_w + sev_w + status_w + 20));

    for f in findings {
        let detail = if f.messages.is_empty() {
            format!("[{}]", f.nist)
        } else {
            format!("{} [{}]", f.messages.join("; "), f.nist)
        };
        println!(
            "{:rule_w$}  {:sev_w$}  {:status_w$}  {}",
            f.rule, f.severity.to_string(), f.status.to_string(), detail,
            rule_w = rule_w, sev_w = sev_w, status_w = status_w
        );
    }
}

fn render_actions(findings: &[Finding]) {
    let actions: Vec<_> = findings.iter().flat_map(|f| f.actions.iter().map(move |a| (f.rule, a))).collect();
    if actions.is_empty() {
        println!("\n(no changes)");
        return;
    }
    println!("\nplanned changes:");
    for (rule, action) in actions {
        println!("  [{rule}] {}", action.summary());
    }
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
        None => git::detect_org().map_err(|e| {
            anyhow!("could not detect org from git remote ({e}); pass --org <name>")
        })?,
    };

    let rendered = preset.template().replace("{{ORG}}", &org);

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
    config::load(&path).with_context(|| {
        format!("template wrote but failed to re-parse from {}", path.display())
    })?;
    Ok(ExitCode::SUCCESS)
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

    config::load(&path).with_context(|| {
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
}

fn execute_actions(
    client: &api::Client,
    org: &str,
    repo: &str,
    findings: &[Finding],
) -> bool {
    let actions: Vec<_> = findings.iter().flat_map(|f| f.actions.iter().map(move |a| (f.rule, a))).collect();
    if actions.is_empty() {
        println!("\n(nothing to apply)");
        return true;
    }
    println!("\napplying:");
    let mut all_ok = true;
    for (rule, action) in actions {
        match action.execute(client, org, repo) {
            Ok(()) => println!("  ✓ [{rule}] {}", action.summary()),
            Err(e) => {
                println!("  ✗ [{rule}] {}: {e}", action.summary());
                all_ok = false;
            }
        }
    }
    all_ok
}
