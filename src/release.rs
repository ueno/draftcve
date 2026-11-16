//! Mapping between commits and released versions, through git tags.
//!
//! A release is a tag matching one of the user's `--tag-format` regular
//! expressions, tried in order; projects change tagging style over time.
//! Capture groups are joined with `.` to form the version, so both `v1.2.3`
//! (`^v(\d+\.\d+\.\d+)$`) and `foo_1_2_3` (`^foo_(\d+)_(\d+)_(\d+)$`) work.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::cmp::Ordering;
use std::path::{Path, PathBuf};

pub const DEFAULT_TAG_FORMAT: &str = r"^v?(\d+(?:\.\d+)+)$";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    pub version: String,
}

pub struct Releases {
    root: PathBuf,
    formats: Vec<Regex>,
}

/// Compare dotted versions numerically, component by component.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let parse = |v: &str| -> Vec<u64> {
        v.split(['.', '-', '_'])
            .map(|part| part.parse().unwrap_or(0))
            .collect()
    };
    parse(a).cmp(&parse(b))
}

impl Releases {
    pub fn new(root: &Path, formats: &[impl AsRef<str>]) -> Result<Self> {
        if formats.is_empty() {
            bail!("at least one tag format is needed");
        }
        let formats = formats
            .iter()
            .map(|format| {
                let format = format.as_ref();
                let regex = Regex::new(format)
                    .with_context(|| format!("invalid tag format `{format}`"))?;
                if regex.captures_len() < 2 {
                    bail!("tag format `{format}` needs at least one capture group for the version");
                }
                Ok(regex)
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            root: root.to_path_buf(),
            formats,
        })
    }

    /// The version of `tag`, from the first format that matches it.
    pub fn version_of(&self, tag: &str) -> Option<String> {
        let captures = self
            .formats
            .iter()
            .find_map(|format| format.captures(tag))?;
        let parts: Vec<_> = captures
            .iter()
            .skip(1)
            .flatten()
            .map(|part| part.as_str())
            .collect();
        Some(parts.join("."))
    }

    fn releases(&self, tags: Vec<String>) -> Vec<Release> {
        let mut releases: Vec<_> = tags
            .into_iter()
            .filter_map(|tag| {
                self.version_of(&tag)
                    .map(|version| Release { tag, version })
            })
            .collect();
        releases.sort_by(|a, b| compare_versions(&a.version, &b.version));
        releases
    }

    /// The earliest release that contains `commit`, if it has been released.
    pub fn first_containing(&self, commit: &str) -> Result<Option<Release>> {
        let tags = crate::git::tags_containing(&self.root, commit)?;
        Ok(self.releases(tags).into_iter().next())
    }

    /// The latest release reachable from `commit`.
    pub fn last_before(&self, commit: &str) -> Result<Option<Release>> {
        let tags = crate::git::tags_merged(&self.root, commit)?;
        Ok(self.releases(tags).into_iter().last())
    }

    /// The release whose version is exactly `version`.
    pub fn by_version(&self, version: &str) -> Result<Option<Release>> {
        let tags = crate::git::capture(&self.root, &["tag"])?;
        Ok(self
            .releases(tags.lines().map(str::to_string).collect())
            .into_iter()
            .find(|release| release.version == version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_groups_are_joined() {
        let releases = Releases::new(Path::new("."), &[r"^gnutls_(\d+)_(\d+)_(\d+)$"]).unwrap();
        assert_eq!(
            releases.version_of("gnutls_3_6_12").as_deref(),
            Some("3.6.12")
        );
        assert_eq!(releases.version_of("3.6.12"), None);
    }

    #[test]
    fn alternatives_leave_unmatched_groups_out() {
        let releases = Releases::new(
            Path::new("."),
            &[r"^(?:(\d+\.\d+\.\d+)|gnutls_(\d+)_(\d+)_(\d+))$"],
        )
        .unwrap();
        assert_eq!(releases.version_of("3.8.13").as_deref(), Some("3.8.13"));
        assert_eq!(
            releases.version_of("gnutls_3_5_9").as_deref(),
            Some("3.5.9")
        );
    }

    #[test]
    fn default_format_skips_suffixed_tags() {
        let releases = Releases::new(Path::new("."), &[DEFAULT_TAG_FORMAT]).unwrap();
        assert_eq!(releases.version_of("v1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(releases.version_of("3.6.14-windows"), None);
    }

    #[test]
    fn the_first_matching_format_wins() {
        let releases = Releases::new(
            Path::new("."),
            &[r"^(\d+\.\d+\.\d+)$", r"^gnutls_(\d+)_(\d+)_(\d+)$", r"^(\d+)\..*$"],
        )
        .unwrap();
        assert_eq!(releases.version_of("3.8.13").as_deref(), Some("3.8.13"));
        assert_eq!(
            releases.version_of("gnutls_3_5_9").as_deref(),
            Some("3.5.9")
        );
        assert_eq!(releases.version_of("3.8").as_deref(), Some("3"));
        assert_eq!(releases.version_of("v3.8.13"), None);
    }

    #[test]
    fn versions_compare_numerically() {
        assert_eq!(compare_versions("3.8.9", "3.8.13"), Ordering::Less);
        assert_eq!(compare_versions("3.6.0.1", "3.6.0"), Ordering::Greater);
    }

    #[test]
    fn a_format_without_a_group_is_rejected() {
        assert!(Releases::new(Path::new("."), &[r"^v\d+$"]).is_err());
        assert!(Releases::new(Path::new("."), &[DEFAULT_TAG_FORMAT, r"^v\d+$"]).is_err());
        assert!(Releases::new(Path::new("."), &[] as &[&str]).is_err());
    }
}
