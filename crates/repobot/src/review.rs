//! Post a review as the bot, with inline comments. Correctness guarantees,
//! all checked locally BEFORE any write so a bad review never half-posts:
//!   1. Every inline comment must anchor to a line that is actually in the PR
//!      diff, on a single side. If any does not, we error and post NOTHING.
//!   2. The outgoing review must be one GitHub will accept — a COMMENT or
//!      REQUEST_CHANGES review needs a body or at least one inline comment.
//!   3. Disposition caps the outgoing event: `comment` (default) downgrades
//!      APPROVE/REQUEST_CHANGES to COMMENT; `full` honors the payload.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::client::Client;
use crate::pr::{self, ChangedFile};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Side {
    Left,
    Right,
}

fn side_str(s: Side) -> &'static str {
    match s {
        Side::Left => "LEFT",
        Side::Right => "RIGHT",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Comment,
    Full,
}

/// The GitHub "create review" payload as authored by the reviewer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewFile {
    pub event: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub comments: Vec<ReviewComment>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewComment {
    pub path: String,
    pub line: u64,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub side: Option<Side>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_side: Option<Side>,
}

pub fn run(
    client: &Client,
    org: &str,
    repo: &str,
    pr: u64,
    file: &Path,
    disposition: Disposition,
    dry_run: bool,
) -> Result<()> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("reading review file {}", file.display()))?;
    let review: ReviewFile = serde_json::from_str(&text)
        .with_context(|| format!("parsing review JSON {}", file.display()))?;

    // Fetch the diff and validate every inline anchor BEFORE any write.
    let files = pr::fetch_files(client, org, repo, pr)?;
    validate_anchors(&review, &files)?;

    let event = effective_event(&review.event, disposition);

    // GitHub rejects an empty COMMENT/REQUEST_CHANGES review (only APPROVE may be
    // bodiless). Catch it here with a clear message instead of a 422 at POST.
    if empty_review_disallowed(event, review.body.as_deref(), review.comments.len()) {
        let hint = if event == "COMMENT" && !review.event.trim().eq_ignore_ascii_case("comment") {
            format!(
                " (the requested `{}` was downgraded to COMMENT by `--disposition comment`; \
                 use `--disposition full` to keep it)",
                review.event.trim()
            )
        } else {
            String::new()
        };
        return Err(anyhow!(
            "refusing to post an empty {event} review: it has no body and no inline \
             comments, which GitHub rejects{hint}"
        ));
    }

    let payload = build_payload(&review, event);
    let path = format!("/repos/{org}/{repo}/pulls/{pr}/reviews");

    if dry_run {
        println!("[dry-run] would POST {path}");
        println!(
            "[dry-run] event: {event} (requested {})",
            review.event.trim()
        );
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let _: serde_json::Value = client.post_json(&path, &payload)?;
    println!("posted review on {org}/{repo}#{pr} as {event}");
    Ok(())
}

/// Map a requested event to the one actually sent, honoring the disposition cap.
/// Unknown events normalize to COMMENT (defensive; review.json is bot-authored).
pub fn effective_event(requested: &str, disposition: Disposition) -> &'static str {
    let r = requested.trim();
    let canon = if r.eq_ignore_ascii_case("APPROVE") {
        "APPROVE"
    } else if r.eq_ignore_ascii_case("REQUEST_CHANGES") {
        "REQUEST_CHANGES"
    } else {
        "COMMENT"
    };
    match disposition {
        Disposition::Full => canon,
        Disposition::Comment => "COMMENT",
    }
}

/// GitHub accepts a bodiless review only for APPROVE; a COMMENT or
/// REQUEST_CHANGES review with no body and no inline comments is a 422.
fn empty_review_disallowed(event: &str, body: Option<&str>, comment_count: usize) -> bool {
    let has_body = body.map(|b| !b.trim().is_empty()).unwrap_or(false);
    event != "APPROVE" && !has_body && comment_count == 0
}

fn build_payload(review: &ReviewFile, event: &str) -> serde_json::Value {
    let mut o = serde_json::Map::new();
    o.insert("event".into(), json!(event));
    if let Some(b) = &review.body {
        o.insert("body".into(), json!(b));
    }
    if !review.comments.is_empty() {
        // ReviewComment derives Serialize with the exact GitHub field names and
        // skips absent options, so this reproduces the create-review shape.
        o.insert(
            "comments".into(),
            serde_json::to_value(&review.comments).expect("serializing review comments"),
        );
    }
    serde_json::Value::Object(o)
}

/// Lines that accept an inline comment, per side, for one file.
/// RIGHT = added/context lines numbered in the NEW file; LEFT = deleted/context
/// numbered in the OLD file.
#[derive(Debug, Default)]
struct FileAnchors {
    right: HashSet<u64>,
    left: HashSet<u64>,
}

impl FileAnchors {
    fn contains(&self, side: Side, line: u64) -> bool {
        match side {
            Side::Right => self.right.contains(&line),
            Side::Left => self.left.contains(&line),
        }
    }
}

/// Parse a unified-diff `patch` into the anchorable line numbers per side.
fn parse_patch(patch: &str) -> Result<FileAnchors> {
    let mut a = FileAnchors::default();
    let mut old_ln = 0u64;
    let mut new_ln = 0u64;
    let mut in_hunk = false;

    for line in patch.lines() {
        if line.starts_with("@@") {
            let (old_start, new_start) =
                parse_hunk_header(line).ok_or_else(|| anyhow!("malformed hunk header: {line}"))?;
            old_ln = old_start;
            new_ln = new_start;
            in_hunk = true;
            continue;
        }
        if !in_hunk {
            continue; // file-header noise before the first @@
        }
        match line.as_bytes().first() {
            Some(b'+') => {
                a.right.insert(new_ln);
                new_ln += 1;
            }
            Some(b'-') => {
                a.left.insert(old_ln);
                old_ln += 1;
            }
            Some(b'\\') => {} // "\ No newline at end of file"
            // context line (leading space) or a blank context line
            _ => {
                a.right.insert(new_ln);
                a.left.insert(old_ln);
                new_ln += 1;
                old_ln += 1;
            }
        }
    }
    Ok(a)
}

/// `@@ -old_start[,len] +new_start[,len] @@ ...` → (old_start, new_start).
fn parse_hunk_header(line: &str) -> Option<(u64, u64)> {
    let body = line.trim_start_matches('@').trim();
    let body = body.split("@@").next()?.trim();
    let mut parts = body.split_whitespace();
    let old = parts.next()?.strip_prefix('-')?;
    let new = parts.next()?.strip_prefix('+')?;
    let old_start = old.split(',').next()?.parse().ok()?;
    let new_start = new.split(',').next()?.parse().ok()?;
    Some((old_start, new_start))
}

/// Per-file anchor sets. `None` means the file IS in the PR but GitHub returned
/// no `patch` for it (binary, or a diff too large to render) — distinct from a
/// file that isn't in the PR at all, so we can give an accurate error.
fn anchor_index(files: &[ChangedFile]) -> Result<HashMap<&str, Option<FileAnchors>>> {
    let mut idx = HashMap::new();
    for f in files {
        let anchors = match &f.patch {
            Some(p) => {
                Some(parse_patch(p).map_err(|e| anyhow!("parsing diff for {}: {e}", f.filename))?)
            }
            None => None,
        };
        idx.insert(f.filename.as_str(), anchors);
    }
    Ok(idx)
}

/// The gate. Validate every inline comment against the diff; on the first
/// offender return Err naming path+side+line so the caller posts nothing.
pub fn validate_anchors(review: &ReviewFile, files: &[ChangedFile]) -> Result<()> {
    let idx = anchor_index(files)?;
    for (i, c) in review.comments.iter().enumerate() {
        let n = i + 1;
        let anchors = match idx.get(c.path.as_str()) {
            None => {
                return Err(anyhow!(
                    "comment #{n}: path `{}` is not among the PR's changed files",
                    c.path
                ));
            }
            Some(None) => {
                return Err(anyhow!(
                    "comment #{n} on `{}`: GitHub returned no diff for this file \
                     (binary, or too large to render), so an inline comment can't be \
                     anchored to it",
                    c.path
                ));
            }
            Some(Some(a)) => a,
        };
        let side = c.side.unwrap_or(Side::Right);
        if !anchors.contains(side, c.line) {
            return Err(anyhow!(
                "comment #{n} on `{}`: line {} ({}) is not part of the PR diff",
                c.path,
                c.line,
                side_str(side)
            ));
        }
        if let Some(start) = c.start_line {
            if start >= c.line {
                return Err(anyhow!(
                    "comment #{n} on `{}`: start_line ({start}) must be < line ({})",
                    c.path,
                    c.line
                ));
            }
            // GitHub requires a multi-line range to lie on a single side.
            let start_side = c.start_side.unwrap_or(side);
            if start_side != side {
                return Err(anyhow!(
                    "comment #{n} on `{}`: start_side ({}) and side ({}) must match — \
                     a multi-line comment can't span both sides of the diff",
                    c.path,
                    side_str(start_side),
                    side_str(side)
                ));
            }
            if !anchors.contains(start_side, start) {
                return Err(anyhow!(
                    "comment #{n} on `{}`: start_line {start} ({}) is not part of the PR diff",
                    c.path,
                    side_str(start_side)
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATCH: &str = "@@ -1,3 +1,4 @@\n ctx line 1\n-removed old 2\n+added new 2\n+added new 3\n ctx line 4";

    fn file_with_patch() -> Vec<ChangedFile> {
        vec![ChangedFile {
            filename: "a.rs".into(),
            status: "modified".into(),
            additions: 2,
            deletions: 1,
            patch: Some(PATCH.into()),
            extra: Default::default(),
        }]
    }

    fn file_without_patch() -> Vec<ChangedFile> {
        vec![ChangedFile {
            filename: "big.bin".into(),
            status: "modified".into(),
            additions: 0,
            deletions: 0,
            patch: None,
            extra: Default::default(),
        }]
    }

    fn single(path: &str, line: u64) -> ReviewFile {
        ReviewFile {
            event: "COMMENT".into(),
            body: None,
            comments: vec![ReviewComment {
                path: path.into(),
                line,
                body: "x".into(),
                start_line: None,
                side: None,
                start_side: None,
            }],
        }
    }

    #[test]
    fn parser_numbers_right_side() {
        let a = parse_patch(PATCH).unwrap();
        // new file: 1 ctx, 2 added, 3 added, 4 ctx
        assert!(a.right.contains(&1) && a.right.contains(&2));
        assert!(a.right.contains(&3) && a.right.contains(&4));
        assert!(!a.right.contains(&5));
    }

    #[test]
    fn parser_numbers_left_side() {
        let a = parse_patch(PATCH).unwrap();
        // old file: 1 ctx, 2 removed, 3 ctx (trailing context)
        assert!(a.left.contains(&1) && a.left.contains(&2) && a.left.contains(&3));
        assert!(!a.left.contains(&4));
    }

    #[test]
    fn header_without_length_defaults_to_one() {
        let a = parse_patch("@@ -5 +7 @@\n+only added").unwrap();
        assert!(a.right.contains(&7));
    }

    #[test]
    fn accepts_on_diff_line() {
        assert!(validate_anchors(&single("a.rs", 3), &file_with_patch()).is_ok());
    }

    #[test]
    fn rejects_off_diff_line_and_posts_nothing() {
        let e = validate_anchors(&single("a.rs", 99), &file_with_patch()).unwrap_err();
        assert!(e.to_string().contains("line 99"), "got: {e}");
        assert!(e.to_string().contains("not part of the PR diff"), "got: {e}");
    }

    #[test]
    fn rejects_unknown_path() {
        let e = validate_anchors(&single("missing.rs", 3), &file_with_patch()).unwrap_err();
        assert!(
            e.to_string().contains("not among the PR's changed files"),
            "got: {e}"
        );
    }

    #[test]
    fn rejects_inverted_multiline_range() {
        let mut r = single("a.rs", 2);
        r.comments[0].start_line = Some(4); // start > line
        let e = validate_anchors(&r, &file_with_patch()).unwrap_err();
        assert!(e.to_string().contains("must be < line"), "got: {e}");
    }

    #[test]
    fn rejects_mismatched_sides_on_multiline() {
        // line 3 is a valid RIGHT anchor; start on the LEFT side must be refused.
        let mut r = single("a.rs", 3);
        r.comments[0].start_line = Some(1);
        r.comments[0].side = Some(Side::Right);
        r.comments[0].start_side = Some(Side::Left);
        let e = validate_anchors(&r, &file_with_patch()).unwrap_err();
        assert!(e.to_string().contains("must match"), "got: {e}");
    }

    #[test]
    fn patchless_file_gives_distinct_error() {
        let e = validate_anchors(&single("big.bin", 1), &file_without_patch()).unwrap_err();
        assert!(e.to_string().contains("no diff for this file"), "got: {e}");
        // and is NOT misreported as "not among the changed files"
        assert!(!e.to_string().contains("not among"), "got: {e}");
    }

    #[test]
    fn empty_comment_review_is_disallowed() {
        // COMMENT/REQUEST_CHANGES with no body and no comments → would 422.
        assert!(empty_review_disallowed("COMMENT", None, 0));
        assert!(empty_review_disallowed("REQUEST_CHANGES", Some("   "), 0));
        // APPROVE may be bodiless; a body or a comment makes any event fine.
        assert!(!empty_review_disallowed("APPROVE", None, 0));
        assert!(!empty_review_disallowed("COMMENT", Some("summary"), 0));
        assert!(!empty_review_disallowed("COMMENT", None, 1));
    }

    #[test]
    fn build_payload_emits_github_comment_shape() {
        let r = ReviewFile {
            event: "COMMENT".into(),
            body: Some("summary".into()),
            comments: vec![ReviewComment {
                path: "a.rs".into(),
                line: 18,
                body: "note".into(),
                start_line: Some(10),
                side: Some(Side::Right),
                start_side: Some(Side::Right),
            }],
        };
        let p = build_payload(&r, "COMMENT");
        let c = &p["comments"][0];
        assert_eq!(c["path"], "a.rs");
        assert_eq!(c["line"], 18);
        assert_eq!(c["start_line"], 10);
        assert_eq!(c["side"], "RIGHT");
        assert_eq!(c["start_side"], "RIGHT");
        assert_eq!(p["event"], "COMMENT");
        assert_eq!(p["body"], "summary");
    }

    #[test]
    fn disposition_comment_caps_everything() {
        assert_eq!(effective_event("APPROVE", Disposition::Comment), "COMMENT");
        assert_eq!(
            effective_event("REQUEST_CHANGES", Disposition::Comment),
            "COMMENT"
        );
        assert_eq!(effective_event("COMMENT", Disposition::Comment), "COMMENT");
    }

    #[test]
    fn disposition_full_passes_through() {
        assert_eq!(effective_event("APPROVE", Disposition::Full), "APPROVE");
        assert_eq!(
            effective_event("request_changes", Disposition::Full),
            "REQUEST_CHANGES"
        );
        assert_eq!(effective_event("LGTM", Disposition::Full), "COMMENT");
    }
}
