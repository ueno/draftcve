//! Tools exposed to the agent, and the findings they record.
//!
//! The model never writes the report. Each `write_*` tool takes a few
//! constrained values, validates them against the repository, and records them
//! here; the app renders the report from these findings afterwards.

use crate::agent::Session;
use crate::cvss::Cvss;
use crate::cwe::{Catalog, Verdict};
use crate::release::{Release, Releases};
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use oi_kit_agent::{
    operation::{Emitter, messages_since_kickoff},
    tool::ToolProvider,
};
use oi_kit_providers::conversation::message::MessageContent;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ErrorData, JsonObject, Tool,
};
use schemars::{JsonSchema, Schema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Lines returned by a read when the model does not ask for a limit.
const DEFAULT_LIMIT: usize = 300;

/// The vulnerable version range.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Affected {
    /// The commit that introduced the flaw.
    pub introduced_commit: Option<String>,
    /// The first release containing it.
    pub introduced: Option<String>,
    pub introduced_tag: Option<String>,
    /// The first release containing every fix.
    pub fixed: Option<String>,
    pub fixed_tag: Option<String>,
    /// The latest affected release, when the fix is not released yet.
    pub last_affected: Option<String>,
    pub last_affected_tag: Option<String>,
    pub rationale: Option<String>,
    /// `affected[].versions` as the CVE schema defines it.
    pub versions: Vec<Value>,
}

impl Affected {
    pub fn new(
        introduced_commit: Option<String>,
        introduced: Option<Release>,
        fixed: &FixedIn,
        version_type: &str,
    ) -> Self {
        let mut affected = Self {
            introduced_commit,
            introduced: introduced.as_ref().map(|r| r.version.clone()),
            introduced_tag: introduced.map(|r| r.tag),
            fixed: fixed.fixed.as_ref().map(|r| r.version.clone()),
            fixed_tag: fixed.fixed.as_ref().map(|r| r.tag.clone()),
            last_affected: fixed.last_affected.as_ref().map(|r| r.version.clone()),
            last_affected_tag: fixed.last_affected.as_ref().map(|r| r.tag.clone()),
            ..Default::default()
        };
        if let Some(introduced) = &affected.introduced {
            let mut range = serde_json::Map::new();
            range.insert("version".into(), json!(introduced));
            range.insert("status".into(), json!("affected"));
            if let Some(fixed) = &affected.fixed {
                range.insert("lessThan".into(), json!(fixed));
            } else if let Some(last) = &affected.last_affected {
                range.insert("lessThanOrEqual".into(), json!(last));
            } else {
                range.insert("lessThan".into(), json!("*"));
            }
            range.insert("versionType".into(), json!(version_type));
            affected.versions.push(Value::Object(range));
        }
        affected
    }
}

/// Where the fix landed, computed before the model is involved.
#[derive(Debug, Clone, Default)]
pub struct FixedIn {
    pub fixed: Option<Release>,
    pub last_affected: Option<Release>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Severity {
    pub rating: String,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cwe {
    /// `CWE-<number>`.
    pub id: String,
    pub name: String,
    /// MITRE's mapping guidance, when checked against the catalog.
    pub usage: Option<String>,
}

pub struct Workspace {
    pub root: PathBuf,
    pub releases: Releases,
    /// Full hashes of the fixing commits.
    pub fixes: Vec<String>,
    pub fixed_in: FixedIn,
    pub version_type: String,
    /// Allowed severity ratings, as spelled in the policy.
    pub severity_levels: Vec<String>,
    pub affected: Option<Affected>,
    pub cvss: Option<Cvss>,
    pub severity: Option<Severity>,
    pub cwe: Option<Cwe>,

    /// The CWE catalog to check `write_cwe` against, if available.
    pub cwe_catalog: Option<Arc<Catalog>>,
    /// Discouraged CWEs the model was already warned about once.
    pub discouraged: BTreeSet<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ReadFileParams {
    /// Git commit hash.
    pub commit: String,
    /// Relative path to the file.
    pub path: PathBuf,
    /// Line number to start reading from (1-based).
    #[schemars(range(min = 1))]
    pub line: Option<usize>,
    /// Maximum number of lines to read.
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ReadCommitParams {
    /// Git commit hash.
    pub commit: String,
    /// Line number to start reading from (1-based).
    #[schemars(range(min = 1))]
    pub line: Option<usize>,
    /// Maximum number of lines to read.
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct BlameParams {
    /// Relative path to the file.
    pub path: PathBuf,
    /// First line to blame (1-based).
    #[schemars(range(min = 1))]
    pub start_line: usize,
    /// Last line to blame (inclusive).
    #[schemars(range(min = 1))]
    pub end_line: usize,
    /// Git commit hash to blame at (default: the parent of the fix).
    pub commit: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SearchHistoryParams {
    /// Exact code snippet to search for, e.g. `strlen(info->username)`.
    pub text: String,
    /// Restrict the search to this file.
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct FindReleaseParams {
    /// Git commit hash.
    pub commit: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct WriteAffectedVersionsParams {
    /// Hash of the commit that introduced the vulnerability.
    pub introduced_by: String,
    /// Why this commit introduced it, in one sentence.
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct WriteCvssScoreParams {
    #[schemars(extend("enum" = ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]))]
    pub attack_vector: String,
    #[schemars(extend("enum" = ["LOW", "HIGH"]))]
    pub attack_complexity: String,
    #[schemars(extend("enum" = ["NONE", "LOW", "HIGH"]))]
    pub privileges_required: String,
    #[schemars(extend("enum" = ["NONE", "REQUIRED"]))]
    pub user_interaction: String,
    #[schemars(extend("enum" = ["UNCHANGED", "CHANGED"]))]
    pub scope: String,
    #[schemars(extend("enum" = ["NONE", "LOW", "HIGH"]))]
    pub confidentiality_impact: String,
    #[schemars(extend("enum" = ["NONE", "LOW", "HIGH"]))]
    pub integrity_impact: String,
    #[schemars(extend("enum" = ["NONE", "LOW", "HIGH"]))]
    pub availability_impact: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct WriteSeverityParams {
    /// Severity rating, one of the levels defined in the security policy.
    pub rating: String,
    /// Why this rating applies under the policy, in one or two sentences.
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct WriteCweParams {
    /// CWE identifier, e.g. `CWE-170`.
    pub cwe_id: String,
    /// CWE name, e.g. `Improper Null Termination`.
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SearchCweParams {
    /// Words describing the weakness, e.g. `null terminated string length`.
    pub query: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ReadCweParams {
    /// CWE identifier, e.g. `CWE-170`.
    pub cwe_id: String,
}

fn parse_args<T: serde::de::DeserializeOwned>(arguments: &Option<JsonObject>) -> Result<T> {
    let value = arguments
        .clone()
        .map(Value::Object)
        .ok_or_else(|| anyhow!("Missing arguments"))?;
    Ok(serde_json::from_value(value)?)
}

fn apply_line_limit(content: &str, line: Option<usize>, limit: Option<usize>) -> String {
    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    let start = line.unwrap_or(1).saturating_sub(1);
    if start >= lines.len() {
        return String::new();
    }
    let end = start
        .saturating_add(limit.unwrap_or(DEFAULT_LIMIT))
        .min(lines.len());
    let mut text = lines[start..end].concat();
    // Say so when truncating: a small model otherwise assumes it saw it all.
    if end < lines.len() {
        text.push_str(&format!(
            "\n[{} more lines; call again with line={} to continue]",
            lines.len() - end,
            end + 1
        ));
    }
    text
}

/// Parse `170`, `cwe-170` or `CWE 170` as 170.
pub fn parse_cwe(id: &str) -> Result<u32> {
    let digits = id
        .trim()
        .trim_start_matches(|c: char| c.is_ascii_alphabetic() || c == '-' || c == ' ' || c == ':');
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        bail!("invalid CWE identifier `{id}`; expected the form `CWE-<number>`");
    }
    Ok(digits.parse()?)
}

impl Workspace {
    pub fn new(root: impl Into<PathBuf>, releases: Releases, fixes: Vec<String>) -> Result<Self> {
        let root = root.into();
        if !root.is_dir() {
            bail!("directory {} does not exist", root.display());
        }
        let root = root
            .canonicalize()
            .with_context(|| format!("could not resolve {}", root.display()))?;
        Ok(Self {
            root,
            releases,
            fixes,
            fixed_in: FixedIn::default(),
            version_type: "semver".into(),
            severity_levels: vec![],
            affected: None,
            cvss: None,
            severity: None,
            cwe: None,
            cwe_catalog: None,
            discouraged: BTreeSet::new(),
        })
    }

    /// The first fixing commit, used as the default revision for searches.
    fn fix(&self) -> &str {
        &self.fixes[0]
    }

    pub fn describe_release(&self, commit: &str) -> Result<String> {
        Ok(match self.releases.first_containing(commit)? {
            Some(release) => format!("first released in {}", release.version),
            None => "not released".to_string(),
        })
    }

    pub fn read_file(
        &self,
        revision: &str,
        path: &Path,
        line: Option<usize>,
        limit: Option<usize>,
    ) -> Result<String> {
        let revision = crate::git::resolve(&self.root, revision)?;
        let content = crate::git::read_file(&self.root, &revision, path)?;
        Ok(apply_line_limit(&content, line, limit))
    }

    pub fn read_commit(
        &self,
        revision: &str,
        line: Option<usize>,
        limit: Option<usize>,
    ) -> Result<String> {
        let revision = crate::git::resolve(&self.root, revision)?;
        let content = crate::git::read_commit(&self.root, &revision)?;
        Ok(apply_line_limit(&content, line, limit))
    }

    pub fn blame(
        &self,
        revision: Option<&str>,
        path: &Path,
        start: usize,
        end: usize,
    ) -> Result<String> {
        if end < start {
            bail!("end_line {end} is before start_line {start}");
        }
        let end = end.min(start.saturating_add(200));
        let revision = match revision {
            Some(revision) => crate::git::resolve(&self.root, revision)?,
            None => format!("{}^", self.fix()),
        };
        let lines = crate::git::blame(&self.root, &revision, path, start, end)?;
        let mut commits = BTreeSet::new();
        for line in lines.lines() {
            if let Some(hash) = line.split_whitespace().next() {
                commits.insert(hash.trim_start_matches('^').to_string());
            }
        }
        let mut text = format!("{lines}\n\nCommits:\n");
        for commit in commits {
            let info = crate::git::commit_info(&self.root, &commit)?;
            text.push_str(&format!(
                "- {} {} {} ({})\n",
                &info.id[..11],
                &info.date[..10],
                info.subject,
                self.describe_release(&info.id)?
            ));
        }
        Ok(text)
    }

    pub fn search_history(&self, text: &str, path: Option<&Path>) -> Result<String> {
        let found = crate::git::search_history(&self.root, self.fix(), text, path, 10)?;
        if found.is_empty() {
            return Ok(format!("No commit added or removed `{text}`."));
        }
        let mut lines = vec![];
        for (hash, rest) in found {
            lines.push(format!(
                "- {hash} {rest} ({})",
                self.describe_release(&hash)?
            ));
        }
        Ok(lines.join("\n"))
    }

    pub fn find_release(&self, commit: &str) -> Result<String> {
        let commit = crate::git::resolve(&self.root, commit)?;
        Ok(match self.releases.first_containing(&commit)? {
            Some(release) => {
                let date = crate::git::tag_date(&self.root, &release.tag)?;
                format!(
                    "{commit} was first released in {} (tag {}, {date}).",
                    release.version, release.tag
                )
            }
            None => format!("{commit} has not been released yet."),
        })
    }

    /// Record the vulnerable range starting at `commit`.
    pub fn write_affected(&mut self, commit: &str, rationale: Option<String>) -> Result<String> {
        let commit = crate::git::resolve(&self.root, commit)?;
        if self.fixes.contains(&commit) {
            bail!("{commit} is the fix itself; give the commit that introduced the flaw");
        }
        if !self
            .fixes
            .iter()
            .try_fold(false, |any, fix| -> Result<bool> {
                Ok(any || crate::git::is_ancestor(&self.root, &commit, fix)?)
            })?
        {
            bail!("{commit} is not an ancestor of the fix, so it cannot have introduced the flaw");
        }
        let introduced = self.releases.first_containing(&commit)?;
        let note = match &introduced {
            Some(release) => format!("first released in {}", release.version),
            None => "never released, so no released version is affected".to_string(),
        };
        let mut affected = Affected::new(
            Some(commit.clone()),
            introduced,
            &self.fixed_in,
            &self.version_type,
        );
        affected.rationale = rationale;
        let range = serde_json::to_string(&affected.versions)?;
        self.affected = Some(affected);
        Ok(format!(
            "Recorded {commit} ({note}). Affected versions: {range}"
        ))
    }

    pub fn write_severity(&mut self, rating: &str, rationale: Option<String>) -> Result<String> {
        let Some(level) = self
            .severity_levels
            .iter()
            .find(|level| level.eq_ignore_ascii_case(rating.trim()))
        else {
            bail!(
                "invalid rating `{rating}`; expected one of {}",
                self.severity_levels.join(", ")
            );
        };
        let text = format!("Recorded severity {level}.");
        self.severity = Some(Severity {
            rating: level.clone(),
            rationale,
        });
        Ok(text)
    }

    pub fn search_cwe(&self, query: &str) -> Result<String> {
        let catalog = self.catalog()?;
        let found = catalog.search(query, 10);
        if found.is_empty() {
            return Ok(format!("No CWE matches `{query}`. Try other words."));
        }
        let lines: Vec<_> = found
            .iter()
            .map(|entry| format!("- {}", catalog.summary(entry)))
            .collect();
        Ok(format!(
            "{}\n\nUse `read_cwe` to read an entry before choosing it.",
            lines.join("\n")
        ))
    }

    pub fn read_cwe(&self, id: &str) -> Result<String> {
        let catalog = self.catalog()?;
        let id = parse_cwe(id)?;
        match catalog.get(id) {
            Some(entry) => Ok(catalog.describe(entry)),
            None => bail!("CWE-{id} does not exist in CWE {}", catalog.version),
        }
    }

    fn catalog(&self) -> Result<&Catalog> {
        self.cwe_catalog
            .as_deref()
            .ok_or_else(|| anyhow!("no CWE catalog is available"))
    }

    /// Record the CWE the model chose, checked against the catalog if any.
    pub fn write_cwe(&mut self, id: &str, name: &str) -> Result<String> {
        let number = parse_cwe(id)?;
        let Some(catalog) = self.cwe_catalog.clone() else {
            // Without a catalog, trust the model; the user was warned.
            let id = format!("CWE-{number}");
            let name = name
                .trim()
                .trim_start_matches(&id)
                .trim_start_matches([':', ' ', '-'])
                .to_string();
            if name.is_empty() {
                bail!("the CWE name is empty");
            }
            let text = format!("Recorded {id}: {name}.");
            self.cwe = Some(Cwe {
                id,
                name,
                usage: None,
            });
            return Ok(text);
        };
        let name = Some(name.trim()).filter(|name| !name.is_empty());
        let (entry, note) = match catalog.check(number, name)? {
            Verdict::Accepted(entry) => (entry, String::new()),
            Verdict::Review(entry) => {
                let children: Vec<_> = catalog
                    .mappable_children(entry.id)
                    .into_iter()
                    .take(10)
                    .map(|child| format!("- {}", catalog.summary(child)))
                    .collect();
                let note = if children.is_empty() {
                    String::new()
                } else {
                    format!(
                        "\nMITRE asks to review this mapping: {}\n\
                         If one of these more specific entries fits better, \
                         call `write_cwe` again with it:\n{}",
                        entry.rationale,
                        children.join("\n")
                    )
                };
                (entry, note)
            }
            // Rejected once, so the model considers the alternatives; then
            // accepted, since sometimes nothing more specific fits.
            Verdict::Discouraged(entry) if self.discouraged.insert(entry.id) => {
                bail!(catalog.discouraged_message(entry));
            }
            Verdict::Discouraged(entry) => (entry, String::new()),
        };
        let text = format!("Recorded CWE-{}: {}.{note}", entry.id, entry.name);
        self.cwe = Some(Cwe {
            id: format!("CWE-{}", entry.id),
            name: entry.name.clone(),
            usage: Some(entry.usage.name().to_string()),
        });
        Ok(text)
    }
}

struct Tools {
    tools: Vec<Tool>,
}

#[async_trait]
impl ToolProvider<Session> for Tools {
    async fn tools(&self, session: &Session) -> Result<Vec<Tool>> {
        // Hide write tools for findings the user supplied: a model offered a
        // tool will call it, and overwrite the user's answer.
        // Lookups are offered only along with the tool they serve.
        let workspace = session.workspace.lock().unwrap();
        Ok(self
            .tools
            .iter()
            .filter(|tool| match tool.name.as_ref() {
                "search_cwe" | "read_cwe" => {
                    workspace.cwe_catalog.is_some() && session.writes.contains("write_cwe")
                }
                name if name.starts_with("write_") => session.writes.contains(name),
                _ => true,
            })
            .cloned()
            .collect())
    }

    async fn call(
        &self,
        session: &Session,
        _request_id: &str,
        call: CallToolRequestParams,
        _emit: &Emitter,
    ) -> Result<CallToolResult, ErrorData> {
        let offered = self.tools(session).await.map_err(|error| {
            ErrorData::internal_error(format!("unable to list tools: {error}"), None)
        })?;
        if !offered.iter().any(|tool| tool.name == call.name) {
            return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Error: unsupported tool call: {}",
                call.name,
            ))]));
        }

        let messages = messages_since_kickoff(&session.conversation).map_err(|error| {
            ErrorData::internal_error(
                format!("unable to retrieve messages from conversation: {error}"),
                None,
            )
        })?;
        let count = messages
            .iter()
            .flat_map(|message| message.content.iter())
            .filter_map(MessageContent::as_tool_request)
            .filter_map(|request| request.tool_call.as_ref().ok())
            .filter(|other| call.name == other.name && call.arguments == other.arguments)
            .count();
        if count >= 3 {
            return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Error: {} called {count} times with the same arguments; \
                 use the result you already have",
                call.name,
            ))]));
        }

        session.reporter.tool_call(&call);

        let result = dispatch(session, &call).unwrap_or_else(|error| {
            let text = format!("Error: {error:#}");
            CallToolResult::error(vec![ContentBlock::text(text)])
        });

        session.reporter.tool_result(&result);

        Ok(result)
    }
}

fn tool(name: &'static str, description: &'static str, input_schema: Schema) -> Tool {
    let input_schema = serde_json::to_value(input_schema)
        .expect("schema serialization should succeed")
        .as_object()
        .expect("schema should serialize to an object")
        .clone();
    Tool::new(name, description, input_schema)
}

fn read_commit_tool() -> Tool {
    tool(
        "read_commit",
        "Read a commit's full contents, including its message and diff.",
        schema_for!(ReadCommitParams),
    )
}

fn read_file_tool() -> Tool {
    tool(
        "read_file",
        "Read a file at a given commit.",
        schema_for!(ReadFileParams),
    )
}

/// Tools for finding the commit that introduced the flaw.
pub fn affected_tool_provider() -> Arc<dyn ToolProvider<Session>> {
    Arc::new(Tools {
        tools: vec![
            read_commit_tool(),
            read_file_tool(),
            tool(
                "blame",
                "Show which commit last changed each line of a file. \
                 Defaults to the state just before the fix.",
                schema_for!(BlameParams),
            ),
            tool(
                "search_history",
                "List commits that added or removed an exact code snippet, newest first.",
                schema_for!(SearchHistoryParams),
            ),
            tool(
                "find_release",
                "Find the first release that contains a commit.",
                schema_for!(FindReleaseParams),
            ),
            tool(
                "write_affected_versions",
                "Record the commit that introduced the vulnerability. \
                 The affected version range is computed from it.",
                schema_for!(WriteAffectedVersionsParams),
            ),
        ],
    })
}

fn write_cvss_score_tool() -> Tool {
    let mut tool = tool(
        "write_cvss_score",
        "Record the CVSS v3.1 base metrics, as the CVSS v3.1 specification \
         defines them. The score is computed from them.",
        schema_for!(WriteCvssScoreParams),
    );
    if let Some(properties) = Arc::make_mut(&mut tool.input_schema)
        .get_mut("properties")
        .and_then(Value::as_object_mut)
    {
        crate::cvss::describe_params(properties);
    }
    tool
}

/// Tools for scoring the flaw under CVSS and classifying it under CWE.
pub fn score_tool_provider() -> Arc<dyn ToolProvider<Session>> {
    Arc::new(Tools {
        tools: vec![
            read_commit_tool(),
            read_file_tool(),
            write_cvss_score_tool(),
            tool(
                "search_cwe",
                "Search the CWE catalog for weaknesses matching some words.",
                schema_for!(SearchCweParams),
            ),
            tool(
                "read_cwe",
                "Read a CWE entry: its description, mapping guidance, and \
                 more specific entries.",
                schema_for!(ReadCweParams),
            ),
            tool(
                "write_cwe",
                "Record the CWE that best describes the root cause.",
                schema_for!(WriteCweParams),
            ),
        ],
    })
}

/// Tools for rating the flaw under the project's policy.
pub fn rate_tool_provider() -> Arc<dyn ToolProvider<Session>> {
    Arc::new(Tools {
        tools: vec![
            read_commit_tool(),
            read_file_tool(),
            tool(
                "write_severity",
                "Record the severity rating according to the security policy.",
                schema_for!(WriteSeverityParams),
            ),
        ],
    })
}

/// Tools for writing prose.
pub fn describe_tool_provider() -> Arc<dyn ToolProvider<Session>> {
    Arc::new(Tools {
        tools: vec![read_commit_tool(), read_file_tool()],
    })
}

/// No tools; the reply itself is the answer.
pub fn no_tool_provider() -> Arc<dyn ToolProvider<Session>> {
    Arc::new(Tools { tools: vec![] })
}

/// Mark a write tool as answered for this run.
fn satisfied(session: &Session, name: &str) {
    session.record.lock().unwrap().pending.remove(name);
}

fn text_result(text: String) -> Result<CallToolResult> {
    let text = if text.is_empty() {
        "No more lines".to_string()
    } else {
        text
    };
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

fn dispatch(session: &Session, call: &CallToolRequestParams) -> Result<CallToolResult> {
    let name = call.name.to_string();
    let result = match name.as_str() {
        "read_file" => {
            let params = parse_args::<ReadFileParams>(&call.arguments)?;
            let workspace = session.workspace.lock().unwrap();
            text_result(workspace.read_file(
                &params.commit,
                &params.path,
                params.line,
                params.limit,
            )?)
        }
        "read_commit" => {
            let params = parse_args::<ReadCommitParams>(&call.arguments)?;
            let workspace = session.workspace.lock().unwrap();
            text_result(workspace.read_commit(&params.commit, params.line, params.limit)?)
        }
        "blame" => {
            let params = parse_args::<BlameParams>(&call.arguments)?;
            let workspace = session.workspace.lock().unwrap();
            text_result(workspace.blame(
                params.commit.as_deref(),
                &params.path,
                params.start_line,
                params.end_line,
            )?)
        }
        "search_history" => {
            let params = parse_args::<SearchHistoryParams>(&call.arguments)?;
            let workspace = session.workspace.lock().unwrap();
            text_result(workspace.search_history(&params.text, params.path.as_deref())?)
        }
        "find_release" => {
            let params = parse_args::<FindReleaseParams>(&call.arguments)?;
            let workspace = session.workspace.lock().unwrap();
            text_result(workspace.find_release(&params.commit)?)
        }
        "write_affected_versions" => {
            let params = parse_args::<WriteAffectedVersionsParams>(&call.arguments)?;
            let mut workspace = session.workspace.lock().unwrap();
            text_result(workspace.write_affected(&params.introduced_by, params.rationale)?)
        }
        "write_cvss_score" => {
            let arguments = call.arguments.clone().unwrap_or_default();
            let cvss = Cvss::from_named(&arguments)?;
            let text = format!(
                "Recorded {} (base score {} {}).",
                cvss.vector(),
                cvss.base_score(),
                cvss.base_severity()
            );
            session.workspace.lock().unwrap().cvss = Some(cvss);
            text_result(text)
        }
        "write_severity" => {
            let params = parse_args::<WriteSeverityParams>(&call.arguments)?;
            let mut workspace = session.workspace.lock().unwrap();
            text_result(workspace.write_severity(&params.rating, params.rationale)?)
        }
        "search_cwe" => {
            let params = parse_args::<SearchCweParams>(&call.arguments)?;
            let workspace = session.workspace.lock().unwrap();
            text_result(workspace.search_cwe(&params.query)?)
        }
        "read_cwe" => {
            let params = parse_args::<ReadCweParams>(&call.arguments)?;
            let workspace = session.workspace.lock().unwrap();
            text_result(workspace.read_cwe(&params.cwe_id)?)
        }
        "write_cwe" => {
            let params = parse_args::<WriteCweParams>(&call.arguments)?;
            let mut workspace = session.workspace.lock().unwrap();
            text_result(workspace.write_cwe(&params.cwe_id, &params.name)?)
        }
        other => bail!("unknown tool `{other}`"),
    };
    if result.is_ok() && name.starts_with("write_") {
        satisfied(session, &name);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_metrics_carry_the_specification() {
        let tool = write_cvss_score_tool();
        let properties = tool.input_schema["properties"].as_object().unwrap();
        assert_eq!(properties.len(), 8);
        for (name, property) in properties {
            let description = property["description"].as_str().unwrap_or_default();
            for value in property["enum"].as_array().unwrap() {
                let value = value.as_str().unwrap();
                assert!(
                    description.contains(&format!("\n{value}: ")),
                    "{name} does not describe {value}"
                );
            }
        }
        let complexity = properties["attack_complexity"]["description"]
            .as_str()
            .unwrap();
        assert!(
            complexity
                .contains("scored assuming the vulnerable component is in that configuration")
        );
    }

    #[test]
    fn cwe_ids_are_parsed() {
        assert_eq!(parse_cwe("170").unwrap(), 170);
        assert_eq!(parse_cwe("cwe-170").unwrap(), 170);
        assert_eq!(parse_cwe("CWE 170").unwrap(), 170);
        assert!(parse_cwe("CWE-17a").is_err());
        assert!(parse_cwe("CWE-").is_err());
    }

    fn workspace_with_catalog() -> (tempdir::TempDir, Workspace) {
        let dir = tempdir::TempDir::new("cve-report-cwe").unwrap();
        let releases = Releases::new(dir.path(), &[crate::release::DEFAULT_TAG_FORMAT]).unwrap();
        let mut workspace = Workspace::new(dir.path(), releases, vec!["0".into()]).unwrap();
        workspace.cwe_catalog = Some(Arc::new(crate::cwe::tests::catalog()));
        (dir, workspace)
    }

    #[test]
    fn the_catalog_name_is_recorded() {
        let (_dir, mut workspace) = workspace_with_catalog();
        workspace.write_cwe("cwe 170", "NUL termination").unwrap();
        let cwe = workspace.cwe.unwrap();
        assert_eq!(cwe.id, "CWE-170");
        assert_eq!(cwe.name, "Improper Null Termination");
        assert_eq!(cwe.usage.as_deref(), Some("Allowed"));
    }

    #[test]
    fn a_mismatched_name_is_not_recorded() {
        let (_dir, mut workspace) = workspace_with_catalog();
        let error = workspace
            .write_cwe("CWE-20", "Improper Null Termination")
            .unwrap_err()
            .to_string();
        assert!(error.contains("Did you mean CWE-170"), "{error}");
        assert!(workspace.cwe.is_none());
    }

    #[test]
    fn a_discouraged_cwe_needs_insisting() {
        let (_dir, mut workspace) = workspace_with_catalog();
        let error = workspace
            .write_cwe("CWE-20", "Improper Input Validation")
            .unwrap_err()
            .to_string();
        assert!(error.contains("discouraged"), "{error}");
        assert!(error.contains("CWE-1284"), "{error}");
        assert!(workspace.cwe.is_none());
        workspace
            .write_cwe("CWE-20", "Improper Input Validation")
            .unwrap();
        assert_eq!(workspace.cwe.unwrap().usage.as_deref(), Some("Discouraged"));
    }

    #[test]
    fn a_prohibited_cwe_is_never_recorded() {
        let (_dir, mut workspace) = workspace_with_catalog();
        for _ in 0..2 {
            assert!(workspace.write_cwe("CWE-1035", "OWASP").is_err());
        }
        assert!(workspace.cwe.is_none());
    }

    #[test]
    fn truncation_is_announced() {
        let text = "a\nb\nc\n";
        assert_eq!(apply_line_limit(text, None, None), text);
        let truncated = apply_line_limit(text, Some(1), Some(2));
        assert!(truncated.starts_with("a\nb\n"), "{truncated}");
        assert!(truncated.contains("line=3"), "{truncated}");
        assert_eq!(apply_line_limit(text, Some(4), None), "");
    }

    #[test]
    fn a_huge_limit_does_not_overflow() {
        let text = "a\nb\nc\n";
        assert_eq!(apply_line_limit(text, Some(2), Some(usize::MAX)), "b\nc\n");
        assert_eq!(
            apply_line_limit(text, Some(usize::MAX), Some(usize::MAX)),
            ""
        );
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?} failed");
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    /// A repository with two commits, and a secret file outside it.
    fn workspace_with_repository() -> (tempdir::TempDir, Workspace) {
        let dir = tempdir::TempDir::new("cve-report-tools").unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(dir.path().join("secret"), "SECRET-CONTENTS\n").unwrap();
        git(&repo, &["init", "-q"]);
        std::fs::write(repo.join("src/lib.c"), "int f(void) {\n  return 0;\n}\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "initial"]);
        std::fs::write(repo.join("src/lib.c"), "int f(void) {\n  return 1;\n}\n").unwrap();
        git(&repo, &["commit", "-q", "-a", "-m", "fix"]);
        let fix = git(&repo, &["rev-parse", "HEAD"]);
        let releases = Releases::new(&repo, &[crate::release::DEFAULT_TAG_FORMAT]).unwrap();
        let workspace = Workspace::new(&repo, releases, vec![fix]).unwrap();
        (dir, workspace)
    }

    #[test]
    fn files_and_directories_are_read() {
        let (_dir, workspace) = workspace_with_repository();
        let file = workspace
            .read_file("HEAD~1", Path::new("src/lib.c"), None, None)
            .unwrap();
        assert!(file.contains("return 0;"), "{file}");
        let listing = workspace
            .read_file("HEAD", Path::new("src"), None, None)
            .unwrap();
        assert!(listing.contains("lib.c"), "{listing}");
    }

    #[test]
    fn options_are_not_taken_as_revisions() {
        let (dir, mut workspace) = workspace_with_repository();
        let written = dir.path().join("written");
        let output = format!("--output={}", written.display());
        let contents = format!("--contents={}", dir.path().join("secret").display());
        let path = Path::new("src/lib.c");
        for revision in [output.as_str(), contents.as_str(), "--all", "-h"] {
            let results = [
                workspace.read_commit(revision, None, None),
                workspace.read_file(revision, path, None, None),
                workspace.blame(Some(revision), path, 1, 3),
                workspace.find_release(revision),
                workspace.write_affected(revision, None),
            ];
            for result in results {
                let error = format!("{:#}", result.unwrap_err());
                assert!(!error.contains("SECRET"), "{error}");
            }
        }
        assert!(!written.exists(), "{} was written", written.display());
        assert!(workspace.affected.is_none());
    }

    #[test]
    fn an_unreleased_fix_closes_the_range_at_the_last_release() {
        let fixed = FixedIn {
            fixed: None,
            last_affected: Some(Release {
                tag: "v1.4.0".into(),
                version: "1.4.0".into(),
            }),
        };
        let introduced = Release {
            tag: "v1.2.0".into(),
            version: "1.2.0".into(),
        };
        let affected = Affected::new(None, Some(introduced), &fixed, "semver");
        assert_eq!(
            affected.versions,
            vec![json!({
                "version": "1.2.0",
                "status": "affected",
                "lessThanOrEqual": "1.4.0",
                "versionType": "semver",
            })]
        );
    }
}
