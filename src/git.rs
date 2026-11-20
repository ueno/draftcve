//! Git operations, done by shelling out to the `git` binary.
//!
//! Through goose's [`git_command`], since the repository is the user's to
//! choose and may not be trusted: it cannot run an fsmonitor hook from its
//! own configuration, and a bare repository must be named explicitly.

use anyhow::{Context, Result, bail};
use oi_kit_agent::subprocess::git_command;
use std::path::Path;

pub fn capture(home: &Path, args: &[&str]) -> Result<String> {
    let output = git_command()
        .args(args)
        .current_dir(home)
        .output()
        .context("failed to run git")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Resolve a revision to a full commit hash.
///
/// Revisions from the model go through here before reaching any other git
/// command, so that an argument like `--output=<file>` is never taken as an
/// option.
pub fn resolve(home: &Path, revision: &str) -> Result<String> {
    if revision.starts_with('-') {
        bail!("{revision} is not a commit in this repository");
    }
    let hash = capture(
        home,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &format!("{revision}^{{commit}}"),
        ],
    )
    .with_context(|| format!("{revision} is not a commit in this repository"))?;
    Ok(hash.trim().to_string())
}

/// Whether `ancestor` is reachable from `descendant`.
pub fn is_ancestor(home: &Path, ancestor: &str, descendant: &str) -> Result<bool> {
    let status = git_command()
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .current_dir(home)
        .status()
        .context("failed to run git")?;
    Ok(status.success())
}

/// Metadata of a single commit.
pub struct CommitInfo {
    pub id: String,
    pub author: String,
    pub date: String,
    pub subject: String,
    pub body: String,
    pub trailers: Vec<(String, String)>,
}

pub fn commit_info(home: &Path, commit: &str) -> Result<CommitInfo> {
    // NUL-separated so that no message content can confuse the split.
    let raw = capture(
        home,
        &[
            "show",
            "--no-patch",
            "--format=format:%H%x00%an <%ae>%x00%aI%x00%s%x00%b%x00%(trailers:only,unfold)",
            "--end-of-options",
            commit,
        ],
    )?;
    let fields: Vec<_> = raw.splitn(6, '\0').collect();
    if fields.len() != 6 {
        bail!("failed to parse git output for {commit}");
    }
    let trailers = fields[5]
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect();
    Ok(CommitInfo {
        id: fields[0].to_string(),
        author: fields[1].to_string(),
        date: fields[2].to_string(),
        subject: fields[3].to_string(),
        body: fields[4].trim().to_string(),
        trailers,
    })
}

pub fn read_commit(home: &Path, commit: &str) -> Result<String> {
    let commits = capture(
        home,
        &[
            "show",
            "--no-ext-diff",
            "--no-textconv",
            "--end-of-options",
            commit,
        ],
    )?;
    Ok(commits.trim().to_string())
}

/// The blob at `path`, or the listing if it is a directory.
pub fn read_file(home: &Path, commit: &str, path: &Path) -> Result<String> {
    // `cat-file` only prints the object: unlike `show`, it has no diff options
    // to misuse, and runs no textconv filter.
    let object = format!("{}:{}", commit, path.display());
    let commits = capture(home, &["cat-file", "-p", "--end-of-options", &object])?;
    Ok(commits.trim().to_string())
}

/// Lines `start..=end` of `path` at `commit`, each prefixed with the commit
/// that last touched it.
pub fn blame(home: &Path, commit: &str, path: &Path, start: usize, end: usize) -> Result<String> {
    let path = path.display().to_string();
    let text = capture(
        home,
        &[
            "blame",
            "-s",
            "--abbrev=11",
            "-L",
            &format!("{start},{end}"),
            "--end-of-options",
            commit,
            "--",
            &path,
        ],
    )?;
    Ok(text.trim_end().to_string())
}

/// Commits that added or removed `text`, newest first.
pub fn search_history(
    home: &Path,
    commit: &str,
    text: &str,
    path: Option<&Path>,
    count: usize,
) -> Result<Vec<(String, String)>> {
    let pickaxe = format!("-S{text}");
    let max_count = format!("--max-count={count}");
    let mut args = vec![
        "log",
        "--format=format:%H %as %s",
        "--no-merges",
        &max_count,
        &pickaxe,
    ];
    let path = path.map(|path| path.display().to_string());
    if path.is_some() {
        // Keep searching past a rename, under the file's earlier names.
        args.push("--follow");
    }
    args.extend(["--end-of-options", commit]);
    if let Some(path) = path.as_deref() {
        args.extend(["--", path]);
    }
    let output = capture(home, &args)?;
    Ok(output
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(hash, rest)| (hash.to_string(), rest.to_string()))
        .collect())
}

/// The line ranges each fixing commit removed or modified, as
/// `(path, start, count)` in the parent's coordinates.
pub fn changed_ranges(home: &Path, commit: &str) -> Result<Vec<(String, usize, usize)>> {
    let diff = capture(
        home,
        &[
            "diff",
            "--unified=0",
            "--no-color",
            &format!("{commit}^"),
            commit,
        ],
    )?;
    let mut ranges = vec![];
    let mut path = None;
    for line in diff.lines() {
        if let Some(name) = line.strip_prefix("--- a/") {
            path = Some(name.to_string());
        } else if line.starts_with("--- ") {
            // A new file: nothing to blame.
            path = None;
        } else if let Some(hunk) = line.strip_prefix("@@ -")
            && let Some(path) = &path
        {
            let old = hunk.split(' ').next().unwrap_or_default();
            let (start, count) = match old.split_once(',') {
                Some((start, count)) => (start.parse()?, count.parse()?),
                None => (old.parse()?, 1),
            };
            ranges.push((path.clone(), start, count));
        }
    }
    Ok(ranges)
}

pub fn tags_containing(home: &Path, commit: &str) -> Result<Vec<String>> {
    let output = capture(home, &["tag", "--contains", commit])?;
    Ok(output.lines().map(str::to_string).collect())
}

pub fn tags_merged(home: &Path, commit: &str) -> Result<Vec<String>> {
    let output = capture(home, &["tag", "--merged", commit])?;
    Ok(output.lines().map(str::to_string).collect())
}

/// The creation date of a tag, in RFC 3339.
pub fn tag_date(home: &Path, tag: &str) -> Result<String> {
    let output = capture(
        home,
        &[
            "for-each-ref",
            "--format=%(creatordate:iso-strict)",
            &format!("refs/tags/{tag}"),
        ],
    )?;
    Ok(output.trim().to_string())
}

/// The URL of a remote, if configured.
pub fn remote_url(home: &Path, remote: &str) -> Option<String> {
    capture(home, &["remote", "get-url", remote])
        .ok()
        .map(|url| url.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repository's own configuration must not run code of its choosing.
    #[test]
    fn an_fsmonitor_hook_is_not_run() {
        let dir = tempdir::TempDir::new("cve-report-fsmonitor").unwrap();
        let (repo, marker) = (dir.path().join("repo"), dir.path().join("ran"));
        crate::fixtures::import(crate::fixtures::SIMPLE, &repo);
        let hook = format!("touch {}", marker.display());
        std::process::Command::new("git")
            .args(["config", "core.fsmonitor", &hook])
            .current_dir(&repo)
            .status()
            .unwrap();

        capture(&repo, &["status", "--porcelain"]).unwrap();
        assert!(!marker.exists(), "the fsmonitor hook ran");

        // Without the guard, git does run it.
        std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(marker.exists(), "the test's hook never runs");
    }
}
