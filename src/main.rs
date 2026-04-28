mod api;
mod auth;
mod config;
mod rules;

use anyhow::{anyhow, Result};
use std::{path::PathBuf, process::ExitCode};

use crate::config::Config;
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
         repocat audit [<repo>...] [--config <path>] [--all]\n  \
         repocat diff  [<repo>...] [--config <path>] [--all]\n  \
         repocat apply [<repo>...] [--config <path>] [--all] [--dry-run]\n  \
         repocat version"
    );
}

struct Args {
    config_path: PathBuf,
    filter_repos: Vec<String>,
    all: bool,
    dry_run: bool,
}

fn parse_args(args: &[String]) -> Result<Args> {
    let mut out = Args {
        config_path: PathBuf::from(DEFAULT_CONFIG),
        filter_repos: Vec::new(),
        all: false,
        dry_run: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                out.config_path = PathBuf::from(
                    args.get(i).ok_or_else(|| anyhow!("--config needs a value"))?,
                );
            }
            "--all" => out.all = true,
            "--dry-run" => out.dry_run = true,
            other if !other.starts_with("--") => out.filter_repos.push(other.to_string()),
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

    let cfg = config::load(&args.config_path)?;
    let (token, login) = auth::load_credentials()?;
    eprintln!("authenticated as {login}");
    let client = api::Client::new(token);

    let mut any_error = false;
    let mut any_apply_error = false;

    for name in target_repos(&cfg, &args)? {
        let repo_cfg = &cfg.repos[name];
        eprintln!("\n=== {}/{name} ===", cfg.org);
        let findings = rules::run_all(&client, &cfg.org, name, repo_cfg)?;
        render_table(&findings);

        if findings.iter().any(|f| f.status == Status::Fail && f.severity == Severity::Error) {
            any_error = true;
        }

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

    let code = match effective_mode {
        Mode::Audit | Mode::Diff => if any_error { 1 } else { 0 },
        Mode::Apply => if any_apply_error { 3 } else { 0 },
    };
    Ok(ExitCode::from(code))
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
