//! Project-wide configuration, from `.cve-report.toml` or `--config`.
//!
//! Each key is named after the `generate` option it stands for. Options on
//! the command line take precedence; `app::apply_config` does the merging.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

/// The file looked up at the top of the repository.
pub const FILE_NAME: &str = ".cve-report.toml";

/// Options that stay the same for every CVE of a project.
///
/// Options about a single vulnerability, such as `--introduced`, are left
/// out on purpose: a value kept in a file would leak into the next record.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub project: Option<String>,
    pub repo_url: Option<String>,
    pub policy: Option<PathBuf>,
    pub hints: Option<PathBuf>,
    pub template: Option<PathBuf>,
    pub schema: Option<PathBuf>,
    pub cwe_catalog: Option<PathBuf>,
    #[serde(default)]
    pub tag_formats: Vec<String>,
    pub version_type: Option<String>,
    pub issue_url: Option<String>,
    #[serde(default)]
    pub issue_formats: Vec<String>,
    #[serde(default)]
    pub severity_levels: Vec<String>,
    pub parallel: Option<NonZeroUsize>,
    /// Template variables, as with `--var`.
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
}

impl ProjectConfig {
    /// Load `explicit`, or else `<root>/.cve-report.toml` if there is one.
    ///
    /// Returns the file used along with its contents, with relative paths
    /// resolved against the file's directory.
    pub fn load(explicit: Option<&Path>, root: &Path) -> Result<Option<(PathBuf, Self)>> {
        let path = match explicit {
            Some(path) => {
                if !path.is_file() {
                    bail!("configuration file {} does not exist", path.display());
                }
                path.to_path_buf()
            }
            None => {
                let path = root.join(FILE_NAME);
                if !path.is_file() {
                    return Ok(None);
                }
                path
            }
        };
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("could not read {}", path.display()))?;
        let mut config: Self = toml::from_str(&raw)
            .with_context(|| format!("could not parse {}", path.display()))?;
        config.resolve_paths(path.parent().unwrap_or(Path::new("")));
        Ok(Some((path, config)))
    }

    /// Make relative paths relative to `base` rather than to the current
    /// directory, so that the file works wherever cve-report is run from.
    fn resolve_paths(&mut self, base: &Path) {
        for path in [
            &mut self.policy,
            &mut self.hints,
            &mut self.template,
            &mut self.schema,
            &mut self.cwe_catalog,
        ]
        .into_iter()
        .flatten()
        {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_relative_to_the_file() {
        let dir = tempdir::TempDir::new("cve-report").unwrap();
        std::fs::write(
            dir.path().join(FILE_NAME),
            "policy = \"SECURITY.md\"\nschema = \"/abs/schema.json\"\n",
        )
        .unwrap();
        let (path, config) = ProjectConfig::load(None, dir.path()).unwrap().unwrap();
        assert_eq!(path, dir.path().join(FILE_NAME));
        assert_eq!(config.policy, Some(dir.path().join("SECURITY.md")));
        assert_eq!(config.schema, Some(PathBuf::from("/abs/schema.json")));
    }

    #[test]
    fn an_explicit_file_is_used_instead_of_the_repository_one() {
        let dir = tempdir::TempDir::new("cve-report").unwrap();
        std::fs::write(dir.path().join(FILE_NAME), "project = \"repo\"\n").unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let explicit = elsewhere.join("gnutls.toml");
        std::fs::write(&explicit, "project = \"GnuTLS\"\nhints = \"hints.md\"\n").unwrap();
        let (_, config) = ProjectConfig::load(Some(&explicit), dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(config.project.as_deref(), Some("GnuTLS"));
        assert_eq!(config.hints, Some(elsewhere.join("hints.md")));
    }

    #[test]
    fn a_missing_file_is_an_error_only_when_given() {
        let dir = tempdir::TempDir::new("cve-report").unwrap();
        assert!(ProjectConfig::load(None, dir.path()).unwrap().is_none());
        assert!(ProjectConfig::load(Some(&dir.path().join("nope.toml")), dir.path()).is_err());
    }

    #[test]
    fn the_readme_example_parses() {
        let config: ProjectConfig = toml::from_str(
            r#"
project = "GnuTLS"
repo_url = "https://gitlab.com/gnutls/gnutls"
policy = "SECURITY.md"
tag_formats = ['^(\d+)\.(\d+)\.(\d+)$', '^gnutls_(\d+)_(\d+)_(\d+)$']
version_type = "semver"
issue_url = "https://gitlab.com/gnutls/gnutls/-/work_items/"
issue_formats = ['^#(\d+)$']
severity_levels = ["Critical", "High", "Medium", "Low"]
parallel = 1

[vars]
assigner_org_id = "..."
"#,
        )
        .unwrap();
        assert_eq!(config.tag_formats.len(), 2);
        assert_eq!(config.vars["assigner_org_id"], "...");
    }

    #[test]
    fn single_vulnerability_options_are_rejected() {
        assert!(toml::from_str::<ProjectConfig>("introduced = \"abc123\"\n").is_err());
    }
}
