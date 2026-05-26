//! GitHub provider: a self-contained vertical (auth, API client, config,
//! resolve, rules, action execution). It reads `.repo.github.yml`, runs the
//! audit/diff/apply pipeline, executes its own changes, and reports via the
//! shared [`crate::finding::Finding`].

mod api;
mod auth;
pub mod config;
pub mod git;
pub mod presets;
mod resolve;
mod rules;

use anyhow::{anyhow, Result};
use std::path::Path;

use crate::finding::{Finding, Outcome, Severity, Status};
use crate::output::Format;
use crate::{Args, Mode};

use self::config::Config;
use self::rules::Finding as RuleResult;

/// Map a GitHub rule result down to the shared, action-free reporting type.
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
    if cfg.repos.is_empty() {
        return Err(anyhow!(
            "no repos in {} — add one with `repocat repo add <name>`",
            config_path.display()
        ));
    }
    let (token, login) = auth::load_credentials()?;
    eprintln!("authenticated as {login}");
    let client = api::Client::new(token);

    if effective_mode == Mode::Apply {
        preflight_scopes(&client, &cfg, args)?;
    }

    let mut any_error = false;
    let mut any_apply_error = false;
    let mut all_findings: Vec<(String, Vec<Finding>)> = Vec::new();

    // Org-wide checks run once per invocation, independent of which repos are
    // targeted — they describe the org, not any single repo.
    if let Some(org_sec) = cfg.org_security.as_ref() {
        eprintln!("\n=== {} :: org security ===", cfg.org);
        let finding = rules::org_security(&client, &cfg.org, org_sec);
        if finding.status == Status::Fail && finding.severity == Severity::Error {
            any_error = true;
        }
        if defer_rendering {
            all_findings.push(("(org)".to_string(), vec![to_shared(&finding)]));
        } else {
            let one = std::slice::from_ref(&finding);
            render_table(one);
            match effective_mode {
                Mode::Audit => {}
                Mode::Diff => render_actions(one),
                Mode::Apply => {
                    // Org actions ignore the repo argument.
                    if !execute_actions(&client, &cfg.org, "", one) {
                        any_apply_error = true;
                    }
                }
            }
        }
    }

    for name in target_repos(&cfg, args)? {
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

        all_findings.push((name.clone(), findings.iter().map(to_shared).collect()));
    }

    Ok(Outcome {
        namespace: cfg.org,
        findings: all_findings,
        any_error,
        any_apply_error,
    })
}

/// Scaffold a `.repo.github.yml` from a preset. Provider-specific because the
/// schema and org detection are GitHub's.
pub fn init_template(preset: presets::Preset, org: &str) -> String {
    preset.template().replace("{{ORG}}", org)
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
            .ok_or_else(|| anyhow!("repo `{name}` not found in config"))?;
        out.push(key);
    }
    Ok(out)
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
    let needs_org = cfg.org_security.is_some();
    if !needs_workflow && !needs_org {
        return Ok(());
    }
    let scopes = client.oauth_scopes()?;
    if scopes.is_empty() {
        // Fine-grained PAT — scopes don't appear in this header. Trust and proceed;
        // the API will return a clear error if permissions are insufficient.
        return Ok(());
    }
    if needs_workflow && !scopes.iter().any(|s| s == "workflow") {
        return Err(anyhow!(
            "apply needs the `workflow` OAuth scope to scaffold dependency-review \
             workflows, but the current token has only [{}]. Run \
             `gh auth refresh --hostname github.com -s workflow` and retry.",
            scopes.join(", ")
        ));
    }
    if needs_org && !scopes.iter().any(|s| s == "admin:org" || s == "write:org") {
        return Err(anyhow!(
            "apply needs the `admin:org` scope to manage org code security \
             configurations (org_security block), but the current token has only \
             [{}]. Run `gh auth refresh --hostname github.com -s admin:org` and retry.",
            scopes.join(", ")
        ));
    }
    Ok(())
}

fn render_table(findings: &[RuleResult]) {
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

fn render_actions(findings: &[RuleResult]) {
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

fn execute_actions(client: &api::Client, org: &str, repo: &str, findings: &[RuleResult]) -> bool {
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
