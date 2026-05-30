//! repobot — the GitHub App / bot identity CLI. Mints a short-lived installation
//! token and reviews PRs as the bot. Hand-rolled arg dispatch (repocat style).

mod app;
mod client;
mod config;
mod git;
mod pr;
mod review;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Result, anyhow};

use client::Client;
use review::Disposition;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return ExitCode::from(2);
    }

    let result = match args[1].as_str() {
        "token" => run_token(&args[2..]),
        "pr" => run_pr(&args[2..]),
        "version" | "--version" | "-V" => {
            println!("repobot {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => Err(anyhow!("unknown command: {other}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage:\n  \
         repobot token [<org/repo>]                         mint a ~9-min App installation token\n  \
         repobot pr show     <pr> [<org/repo>] [--json]     PR metadata\n  \
         repobot pr diff     <pr> [<org/repo>]              unified diff\n  \
         repobot pr files    <pr> [<org/repo>] [--json]     changed files (path/status/+/-/patch)\n  \
         repobot pr comments <pr> [<org/repo>] [--json]     existing review comments\n  \
         repobot pr review   <pr> [<org/repo>] -f <review.json>\n                      \
         [--disposition comment|full] [--dry-run]\n  \
         repobot version\n\
         \n\
         <org/repo> defaults to the cwd git remote.\n\
         Credentials come only from ~/.config/repobot/config.yml."
    );
}

/// Resolve `<org/repo>`: explicit positional, else the cwd git remote.
fn resolve_repo(arg: Option<&str>) -> Result<(String, String)> {
    match arg {
        Some(s) => {
            let (o, r) = s
                .split_once('/')
                .ok_or_else(|| anyhow!("expected <org/repo>, got `{s}`"))?;
            if o.is_empty() || r.is_empty() {
                return Err(anyhow!("expected <org/repo>, got `{s}`"));
            }
            Ok((o.to_string(), r.to_string()))
        }
        None => git::detect_repo(),
    }
}

fn run_token(args: &[String]) -> Result<()> {
    let mut repo_arg = None;
    for a in args {
        if a.starts_with('-') {
            return Err(anyhow!("unknown flag: {a}"));
        }
        if repo_arg.is_some() {
            return Err(anyhow!("unexpected argument: {a}"));
        }
        repo_arg = Some(a.clone());
    }
    let (org, repo) = resolve_repo(repo_arg.as_deref())?;
    let cfg = config::load()?;
    let token = app::mint_installation_token(&cfg, &org, &repo)?;
    println!("{token}");
    Ok(())
}

fn run_pr(args: &[String]) -> Result<()> {
    let sub = args
        .first()
        .ok_or_else(|| anyhow!("usage: repobot pr <show|diff|files|comments|review> <pr> ..."))?
        .clone();
    let rest = &args[1..];

    let mut pr: Option<u64> = None;
    let mut repo_arg: Option<String> = None;
    let mut json = false;
    let mut dry_run = false;
    let mut file: Option<PathBuf> = None;
    let mut disposition = Disposition::Comment;

    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        match a {
            "--json" => json = true,
            "--dry-run" => dry_run = true,
            "-f" | "--file" => {
                i += 1;
                file = Some(PathBuf::from(
                    rest.get(i).ok_or_else(|| anyhow!("-f needs a value"))?,
                ));
            }
            "--disposition" => {
                i += 1;
                let v = rest
                    .get(i)
                    .ok_or_else(|| anyhow!("--disposition needs a value"))?;
                disposition = match v.as_str() {
                    "comment" => Disposition::Comment,
                    "full" => Disposition::Full,
                    other => {
                        return Err(anyhow!(
                            "--disposition must be `comment` or `full`, got `{other}`"
                        ));
                    }
                };
            }
            other if other.starts_with('-') => return Err(anyhow!("unknown flag: {other}")),
            other if pr.is_none() => {
                pr = Some(
                    other
                        .parse()
                        .map_err(|_| anyhow!("<pr> must be a number, got `{other}`"))?,
                );
            }
            other if repo_arg.is_none() => repo_arg = Some(other.to_string()),
            other => return Err(anyhow!("unexpected argument: {other}")),
        }
        i += 1;
    }

    let pr = pr.ok_or_else(|| anyhow!("missing <pr> number"))?;
    let (org, repo) = resolve_repo(repo_arg.as_deref())?;
    let cfg = config::load()?;
    let token = app::mint_installation_token(&cfg, &org, &repo)?;
    let client = Client::new(token);

    match sub.as_str() {
        "show" => pr::show(&client, &org, &repo, pr, json),
        "diff" => pr::diff(&client, &org, &repo, pr),
        "files" => pr::files(&client, &org, &repo, pr, json),
        "comments" => pr::comments(&client, &org, &repo, pr, json),
        "review" => {
            let file = file.ok_or_else(|| anyhow!("`pr review` requires -f <review.json>"))?;
            review::run(&client, &org, &repo, pr, &file, disposition, dry_run)
        }
        other => Err(anyhow!("unknown pr subcommand: {other}")),
    }
}
