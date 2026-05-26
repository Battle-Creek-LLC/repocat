//! GitLab provider: a self-contained vertical mirroring `github/`, reading
//! `.repo.gitlab.yml` and reusing `glab`'s credentials. It runs the
//! audit/diff/apply pipeline, executing its own changes via the rule actions.

mod api;
mod auth;
mod config;
pub mod init;
mod resolve;
mod rules;

use anyhow::{anyhow, Result};
use std::path::Path;

use crate::finding::{Finding, Outcome, Severity, Status};
use crate::output::Format;
use crate::{Args, Mode};

use self::config::Config;
use self::rules::RuleResult;

fn to_shared(r: &RuleResult) -> Finding {
    Finding {
        rule: r.rule,
        severity: r.severity,
        nist: r.nist,
        status: r.status,
        messages: r.messages.clone(),
    }
}

pub fn run(mode: Mode, config_path: &Path, args: &Args) -> Result<Outcome> {
    let effective_mode = if mode == Mode::Apply && args.dry_run { Mode::Diff } else { mode };
    let defer_rendering = args.format != Format::Text;

    let cfg = config::load(config_path)?;
    if cfg.projects.is_empty() {
        return Err(anyhow!(
            "no projects in {} — add one under `projects:`",
            config_path.display()
        ));
    }

    let creds = auth::load_credentials(cfg.host.as_deref())?;
    let host = creds.host.clone();
    let client = api::Client::new(&creds);
    let user = client.whoami().unwrap_or_else(|_| "<token>".to_string());
    eprintln!("authenticated as {user} on {host}");

    let mut any_error = false;
    let mut any_apply_error = false;
    let mut all_findings: Vec<(String, Vec<Finding>)> = Vec::new();

    for name in target_projects(&cfg, args)? {
        let eff = resolve::effective(&cfg.defaults, &cfg.projects[name]);
        let project_path = format!("{}/{name}", cfg.group);
        eprintln!("\n=== {project_path} ===");
        let results = rules::run_all(&client, &project_path, &eff)?;

        if results.iter().any(|r| r.status == Status::Fail && r.severity == Severity::Error) {
            any_error = true;
        }

        if !defer_rendering {
            render_table(&results);
            match effective_mode {
                Mode::Audit => {}
                Mode::Diff => render_actions(&results),
                Mode::Apply => {
                    if !execute_actions(&client, &project_path, &results) {
                        any_apply_error = true;
                    }
                }
            }
        }

        all_findings.push((name.clone(), results.iter().map(to_shared).collect()));
    }

    Ok(Outcome {
        namespace: cfg.group,
        findings: all_findings,
        any_error,
        any_apply_error,
    })
}

fn target_projects<'a>(cfg: &'a Config, args: &Args) -> Result<Vec<&'a String>> {
    if args.all || args.filter_repos.is_empty() {
        return Ok(cfg.projects.keys().collect());
    }
    let mut out = Vec::new();
    for name in &args.filter_repos {
        let key = cfg
            .projects
            .keys()
            .find(|k| *k == name)
            .ok_or_else(|| anyhow!("project `{name}` not found in config"))?;
        out.push(key);
    }
    Ok(out)
}

fn render_table(results: &[RuleResult]) {
    let rule_w = results.iter().map(|r| r.rule.len()).max().unwrap_or(4).max(4);
    let sev_w = 7;
    let status_w = 6;

    println!(
        "{:rule_w$}  {:sev_w$}  {:status_w$}  {}",
        "rule", "sev", "status", "details",
        rule_w = rule_w, sev_w = sev_w, status_w = status_w
    );
    println!("{}", "-".repeat(rule_w + sev_w + status_w + 20));

    for r in results {
        let detail = if r.messages.is_empty() {
            format!("[{}]", r.nist)
        } else {
            format!("{} [{}]", r.messages.join("; "), r.nist)
        };
        println!(
            "{:rule_w$}  {:sev_w$}  {:status_w$}  {}",
            r.rule, r.severity.to_string(), r.status.to_string(), detail,
            rule_w = rule_w, sev_w = sev_w, status_w = status_w
        );
    }
}

fn render_actions(results: &[RuleResult]) {
    let actions: Vec<_> = results.iter().flat_map(|r| r.actions.iter().map(move |a| (r.rule, a))).collect();
    if actions.is_empty() {
        println!("\n(no changes)");
        return;
    }
    println!("\nplanned changes:");
    for (rule, action) in actions {
        println!("  [{rule}] {}", action.summary());
    }
}

fn execute_actions(client: &api::Client, project: &str, results: &[RuleResult]) -> bool {
    let actions: Vec<_> = results.iter().flat_map(|r| r.actions.iter().map(move |a| (r.rule, a))).collect();
    if actions.is_empty() {
        println!("\n(nothing to apply)");
        return true;
    }
    println!("\napplying:");
    let mut all_ok = true;
    for (rule, action) in actions {
        match action.execute(client, project) {
            Ok(()) => println!("  ✓ [{rule}] {}", action.summary()),
            Err(e) => {
                println!("  ✗ [{rule}] {}: {e}", action.summary());
                all_ok = false;
            }
        }
    }
    all_ok
}
