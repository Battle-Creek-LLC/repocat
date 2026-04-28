use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;

use crate::rules::{Finding, Severity, Status};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Sarif,
}

pub fn parse_format(s: &str) -> Result<Format> {
    match s {
        "text" => Ok(Format::Text),
        "json" => Ok(Format::Json),
        "sarif" => Ok(Format::Sarif),
        other => Err(anyhow!("unknown --format: {other} (want text, json, or sarif)")),
    }
}

pub fn render_json(org: &str, repo_findings: &[(String, Vec<Finding>)]) -> Result<String> {
    let mut out = Vec::new();
    for (repo, findings) in repo_findings {
        for f in findings {
            out.push(json!({
                "repo": format!("{org}/{repo}"),
                "rule": f.rule,
                "severity": f.severity.to_string(),
                "status": f.status.to_string(),
                "nist": f.nist,
                "messages": f.messages,
            }));
        }
    }
    Ok(serde_json::to_string_pretty(&Value::Array(out))?)
}

// SARIF v2.1.0 — emits one run, with each Status::Fail finding as a result.
// Pass and Skip findings are not emitted: SARIF results represent problems, and
// downstream consumers (notably GitHub Code Scanning) expect that semantics.
//
// Each result's physicalLocation points at .repo.yml — the declarative baseline
// is the source of truth for what's expected, and lives in the repo where the
// scanner workflow runs. The audited repo (which may be a different repo from
// the scanner) is carried in logicalLocations and properties.
pub fn render_sarif(org: &str, repo_findings: &[(String, Vec<Finding>)]) -> Result<String> {
    let mut rule_ids: BTreeSet<&'static str> = BTreeSet::new();
    for (_, findings) in repo_findings {
        for f in findings {
            rule_ids.insert(f.rule);
        }
    }
    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            // Derive rule metadata from the first finding we see for this id —
            // every Finding for a given rule shares severity and nist controls.
            let any = repo_findings
                .iter()
                .flat_map(|(_, fs)| fs.iter())
                .find(|f| f.rule == *id)
                .expect("rule id came from findings");
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": format!("{id} ({})", any.nist) },
                "defaultConfiguration": { "level": sarif_level(any.severity) },
                "properties": { "nist": any.nist },
            })
        })
        .collect();

    let mut results = Vec::new();
    for (repo, findings) in repo_findings {
        let qualified = format!("{org}/{repo}");
        for f in findings {
            if f.status != Status::Fail {
                continue;
            }
            let message = if f.messages.is_empty() {
                format!("{} failed", f.rule)
            } else {
                f.messages.join("; ")
            };
            results.push(json!({
                "ruleId": f.rule,
                "level": sarif_level(f.severity),
                "message": { "text": format!("[{qualified}] {message}") },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": ".repo.yml" },
                        "region": { "startLine": 1 }
                    },
                    "logicalLocations": [{
                        "fullyQualifiedName": qualified,
                        "kind": "resource"
                    }]
                }],
                "properties": {
                    "repo": qualified,
                    "nist": f.nist,
                },
            }));
        }
    }

    let doc = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "repocat",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/Battle-Creek-LLC/repocat",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    });
    Ok(serde_json::to_string_pretty(&doc)?)
}

fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Error => "error",
        Severity::Warning => "warning",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Finding;

    fn fail_finding(rule: &'static str, sev: Severity, msg: &str) -> Finding {
        Finding {
            rule,
            severity: sev,
            nist: "AC-3, CM-3",
            status: Status::Fail,
            messages: vec![msg.into()],
            actions: vec![],
        }
    }

    fn pass_finding(rule: &'static str) -> Finding {
        Finding {
            rule,
            severity: Severity::Error,
            nist: "CM-3",
            status: Status::Pass,
            messages: vec![],
            actions: vec![],
        }
    }

    #[test]
    fn json_includes_all_findings_with_repo_qualifier() {
        let f = vec![("repo-a".to_string(), vec![
            fail_finding("branch_protection", Severity::Error, "drift"),
            pass_finding("merge_settings"),
        ])];
        let out = render_json("acme", &f).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 2, "json emits all findings, not just failures");
        assert_eq!(arr[0]["repo"], "acme/repo-a");
        assert_eq!(arr[0]["status"], "fail");
        assert_eq!(arr[1]["status"], "pass");
    }

    #[test]
    fn sarif_omits_pass_and_skip_results() {
        let f = vec![("repo-a".to_string(), vec![
            fail_finding("branch_protection", Severity::Error, "drift"),
            pass_finding("merge_settings"),
        ])];
        let out = render_sarif("acme", &f).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1, "only failures emitted as SARIF results");
        assert_eq!(results[0]["ruleId"], "branch_protection");
    }

    #[test]
    fn sarif_has_required_top_level_shape() {
        let out = render_sarif("acme", &[]).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["$schema"].is_string());
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "repocat");
        assert!(parsed["runs"][0]["results"].is_array());
    }

    #[test]
    fn sarif_result_has_location_and_repo_property() {
        let f = vec![("repo-a".to_string(), vec![
            fail_finding("branch_protection", Severity::Error, "drift"),
        ])];
        let out = render_sarif("acme", &f).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let r = &parsed["runs"][0]["results"][0];
        assert_eq!(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], ".repo.yml");
        assert_eq!(r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"], "acme/repo-a");
        assert_eq!(r["properties"]["repo"], "acme/repo-a");
        assert_eq!(r["level"], "error");
        assert!(r["message"]["text"].as_str().unwrap().contains("acme/repo-a"));
    }

    #[test]
    fn sarif_rules_are_deduplicated_across_repos() {
        let f = vec![
            ("a".to_string(), vec![fail_finding("branch_protection", Severity::Error, "x")]),
            ("b".to_string(), vec![fail_finding("branch_protection", Severity::Error, "y")]),
        ];
        let out = render_sarif("acme", &f).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "duplicate rule ids collapsed");
        assert_eq!(rules[0]["id"], "branch_protection");
    }
}
