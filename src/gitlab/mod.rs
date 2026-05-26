//! GitLab provider: a self-contained vertical mirroring `github/`, reading
//! `.repo.gitlab.yml` and reusing `glab`'s credentials. Phase 2 implements the
//! read (audit/diff) path; `apply` is not yet wired (Phase 3).

mod api;
mod auth;
mod config;
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
    if effective_mode == Mode::Apply {
        return Err(anyhow!(
            "GitLab apply is not yet implemented (Phase 3); use `audit` or `diff`"
        ));
    }
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
            if effective_mode == Mode::Diff {
                render_planned(&results);
            }
        }

        all_findings.push((name.clone(), results.iter().map(to_shared).collect()));
    }

    Ok(Outcome {
        namespace: cfg.group,
        findings: all_findings,
        any_error,
        any_apply_error: false,
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

fn render_planned(results: &[RuleResult]) {
    let planned: Vec<_> = results.iter().flat_map(|r| r.planned.iter().map(move |p| (r.rule, p))).collect();
    if planned.is_empty() {
        println!("\n(no changes)");
        return;
    }
    println!("\nplanned changes (apply not yet implemented for GitLab):");
    for (rule, p) in planned {
        println!("  [{rule}] {p}");
    }
}
