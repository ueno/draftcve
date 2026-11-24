use crate::agent::{Agent, Outcome, Role};
use crate::cvss::Cvss;
use crate::model::Task;
use crate::release::{Release, Releases};
use crate::tools::{Affected, Cwe, FixedIn, Severity, Workspace};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::{env, fs};
use tokio_util::sync::CancellationToken;

/// Lines of each fixing commit included in an opening message.
const FIX_LINES: usize = 300;

/// Blamed lines included in the opening message, across all hunks.
const BLAME_LINES: usize = 80;

#[derive(Parser)]
#[command(
    name = "draftcve",
    about = "A helper program for writing CVE records",
    after_help = "Run `draftcve <command> --help` for details on any command.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: CommandName,

    /// Hints file, appended to every opening message (default: `hints` in the project configuration)
    #[arg(long, global = true)]
    hints: Option<PathBuf>,

    /// Print verbose output.
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum CommandName {
    /// Create a new draftcve configuration.
    ///
    /// Creates configuration files under `~/.config/draftcve/`. Safe to
    /// re-run: existing files are left alone.
    #[command(visible_alias = "i")]
    Init,

    /// Generate a CVE record from the commits fixing a vulnerability.
    ///
    /// The model is asked only for prose and for tool calls; the record is
    /// assembled by rendering a template with the findings.
    ///
    /// Project-wide options can be kept in `.draftcve.toml` at the top of
    /// the repository, or in the file given with `--config`; options on the
    /// command line take precedence.
    ///
    ///   draftcve generate CVE-2026-42010 cb1833afd9 --policy SECURITY.md
    #[command(visible_alias = "g")]
    Generate(Box<GenerateArgs>),
}

#[derive(clap::Args)]
struct GenerateArgs {
    /// CVE identifier, e.g. CVE-2026-42010
    cve: String,
    /// Commits fixing the vulnerability
    #[arg(required = true)]
    commits: Vec<String>,
    /// Git repository
    #[arg(short = 'C', long, default_value = ".")]
    repo: PathBuf,
    /// Project configuration file (default: <repo>/.draftcve.toml, if any)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Security issue handling policy, e.g. SECURITY.md
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Record template in Jinja format (default: built-in)
    #[arg(short, long)]
    template: Option<PathBuf>,
    /// Regex matching release tags; capture groups are joined with `.` to form the version; may be repeated, the first match wins (default: `^v?(\d+(?:\.\d+)+)$`)
    #[arg(long = "tag-format", value_name = "REGEX")]
    tag_formats: Vec<String>,
    /// Version type of affected ranges, e.g. semver, git, custom (default: semver)
    #[arg(long)]
    version_type: Option<String>,
    /// Project name (default: the repository directory name)
    #[arg(long)]
    project: Option<String>,
    /// Public URL of the repository (default: derived from the `origin` remote)
    #[arg(long)]
    repo_url: Option<String>,
    /// URL prefix of issues, to which the issue number is appended (default: <repo-url>/issues/)
    #[arg(long, value_name = "URL")]
    issue_url: Option<String>,
    /// Regex matching issue references in `Fixes:`, `Closes:` and `Resolves:` trailers; the first capture group is the issue number; may be repeated, the first match wins (default: `#123` and GitHub or GitLab issue URLs)
    #[arg(long = "issue-format", value_name = "REGEX")]
    issue_formats: Vec<String>,
    /// Comma-separated severity ratings defined by the policy (default: Critical,High,Medium,Low)
    #[arg(long, value_delimiter = ',')]
    severity_levels: Vec<String>,
    /// Commit or version that introduced the vulnerability (skips the model)
    #[arg(long)]
    introduced: Option<String>,
    /// Version that fixes the vulnerability, when not yet tagged
    #[arg(long)]
    fixed_version: Option<String>,
    /// CVSS v3.1 vector (skips the model; default: from commit messages, if any)
    #[arg(long)]
    cvss: Option<String>,
    /// Severity rating under the policy (skips the model)
    #[arg(long)]
    severity: Option<String>,
    /// CWE as `CWE-<n>` or `CWE-<n>:<name>` (skips the model)
    #[arg(long)]
    cwe: Option<String>,
    /// MITRE CWE catalog (cwec_v*.xml), or a directory holding one (default: ~/.config/draftcve/cwe)
    #[arg(long)]
    cwe_catalog: Option<PathBuf>,
    /// Title (skips the model)
    #[arg(long)]
    title: Option<String>,
    /// Description (skips the model)
    #[arg(long)]
    description: Option<String>,
    /// The finder's original report, e.g. an email or issue text, given to the model as context
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,
    /// Name to credit, e.g. `finder=NAME`, in addition to those in `Reported-by:`, `Signed-off-by:`, `Reviewed-by:` and `Tested-by:` trailers; TYPE is a CVE credit type, with `-` for spaces; may be repeated
    #[arg(long = "credit", value_name = "TYPE=NAME")]
    credits: Vec<String>,
    /// Public disclosure date as YYYY-MM-DD (default: the fixed release's date)
    #[arg(long)]
    date_public: Option<String>,
    /// Template variable as KEY=VALUE, available as `vars.KEY`; may be repeated
    #[arg(long = "var", value_name = "KEY=VALUE")]
    vars: Vec<String>,
    /// JSON schema to validate the record against, e.g. CVE_Record_Format_bundled.json
    #[arg(long)]
    schema: Option<PathBuf>,
    /// Agent runs in flight at once; runs started together do not see each other's findings (default: 1)
    #[arg(long, value_name = "N")]
    parallel: Option<NonZeroUsize>,
    /// Print the template context as JSON instead of rendering
    #[arg(long)]
    dump_context: bool,
    /// Output file name (default: <CVE>.json)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let home = env::home_dir()
        .ok_or_else(|| anyhow!("unable to determine home directory"))
        .map(|home| home.join(".config").join("draftcve"))?;
    match cli.command {
        CommandName::Init => init(&home),
        CommandName::Generate(args) => generate(&home, cli.hints, cli.verbose, *args),
    }
}

fn init(home: &Path) -> Result<()> {
    fs::create_dir_all(home.join("providers"))?;
    if !home.join("config.toml").exists() {
        fs::write(
            home.join("config.toml"),
            concat!(
                "# draftcve configuration\n",
                "#\n",
                "# Reports are often about vulnerabilities still under embargo, so\n",
                "# the model should run locally. Each task may use its own model;\n",
                "# tasks without a table use [default].\n",
                "#\n",
                "# Tasks: affected (finding the introducing commit),\n",
                "#        assess (CVSS, severity, CWE), describe (title, description)\n",
                "#\n",
                "# provider: provider name | none\n",
                "# name: model name; omit for the provider's own default.\n",
                "\n",
                "[default]\n",
                "provider = \"ramalama\"\n",
                "name = \"qwen3.8-27b\"\n",
            ),
        )?;
    }
    let provider = home.join("providers").join("ramalama.json");
    if !provider.exists() {
        fs::write(
            provider,
            include_str!("../config/draftcve/providers/ramalama.json"),
        )?;
    }
    fs::create_dir_all(home.join("cwe"))?;
    println!("Initialized draftcve configuration at {}", home.display());
    if crate::cwe::locate(&home.join("cwe")).is_err() {
        println!(
            "\nTo check CWEs against the official catalog, download it:\n\n  \
             curl -LO https://cwe.mitre.org/data/xml/cwec_latest.xml.zip\n  \
             unzip -d {} cwec_latest.xml.zip",
            home.join("cwe").display()
        );
    }
    Ok(())
}

/// One fixing commit, as templates see it.
#[derive(Serialize)]
struct CommitContext {
    id: String,
    short_id: String,
    author: String,
    date: String,
    subject: String,
    body: String,
    trailers: BTreeMap<String, Vec<String>>,
}

/// Everything a template can use. See `--dump-context`.
#[derive(Serialize)]
struct TemplateContext<'a> {
    cve_id: &'a str,
    project: &'a str,
    repo_url: Option<&'a str>,
    /// URL prefix of issues; `issue_url ~ issues[i]` is the issue's URL.
    issue_url: Option<String>,
    title: Option<String>,
    description: Option<String>,
    affected: Option<Affected>,
    /// The `cvssV3_1` object.
    cvss: Option<Value>,
    severity: Option<Severity>,
    cwe: Option<Cwe>,
    commits: Vec<CommitContext>,
    /// Trailers of all fixing commits, merged.
    trailers: BTreeMap<String, Vec<String>>,
    /// Names from `Reported-by:` trailers and `--credit finder=NAME`.
    reporters: Vec<String>,
    /// Names from `CREDIT_TRAILERS`, followed by `--credit` names.
    credits: Vec<Credit>,
    /// Issue numbers from `Fixes:`, `Closes:` and `Resolves:` trailers.
    issues: Vec<String>,
    /// Other `Fixes:` values, such as project advisory identifiers.
    advisories: Vec<String>,
    date_public: Option<String>,
    now: String,
    generator: String,
    vars: BTreeMap<String, String>,
}

/// Turn a remote URL into a browsable one, or `None` for local paths.
fn public_url(remote: &str) -> Option<String> {
    let url = remote.trim().trim_end_matches('/').trim_end_matches(".git");
    if let Some(rest) = url.strip_prefix("git@")
        && let Some((host, path)) = rest.split_once(':')
    {
        return Some(format!("https://{host}/{path}"));
    }
    if let Some(rest) = url.strip_prefix("ssh://") {
        let rest = rest.split_once('@').map_or(rest, |(_, rest)| rest);
        let (host, path) = rest.split_once('/')?;
        let host = host.split(':').next()?;
        return Some(format!("https://{host}/{path}"));
    }
    if url.starts_with("https://") || url.starts_with("http://") {
        return Some(url.to_string());
    }
    None
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Credit {
    #[serde(rename = "type")]
    kind: &'static str,
    value: String,
}

/// The credit types of the CVE record format.
const CREDIT_TYPES: [&str; 10] = [
    "finder",
    "reporter",
    "analyst",
    "coordinator",
    "remediation developer",
    "remediation reviewer",
    "remediation verifier",
    "tool",
    "sponsor",
    "other",
];

/// Trailers of fixing commits that credit a name, and the credit type.
const CREDIT_TRAILERS: [(&str, &str); 4] = [
    ("Reported-by", "finder"),
    ("Signed-off-by", "remediation developer"),
    ("Reviewed-by", "remediation reviewer"),
    ("Tested-by", "remediation verifier"),
];

/// Parse `--credit TYPE=NAME`, where TYPE may use `-` or `_` for spaces.
fn parse_credit(credit: &str) -> Result<Credit> {
    let (kind, name) = credit
        .split_once('=')
        .ok_or_else(|| anyhow!("--credit `{credit}` is not of the form TYPE=NAME"))?;
    let normalized = kind.trim().to_ascii_lowercase().replace(['-', '_'], " ");
    let kind = CREDIT_TYPES
        .into_iter()
        .find(|known| *known == normalized)
        .ok_or_else(|| {
            anyhow!(
                "--credit type `{}` is not one of {}",
                kind.trim(),
                CREDIT_TYPES.map(|known| known.replace(' ', "-")).join(", ")
            )
        })?;
    Ok(Credit {
        kind,
        value: name.trim().to_string(),
    })
}

/// Strip the address from `Name <name@example.com>`.
fn person(value: &str) -> String {
    match value.find('<') {
        Some(index) => value[..index].trim().to_string(),
        None => value.trim().to_string(),
    }
}

/// Issue references as `#123`, or as GitHub or GitLab issue URLs.
const DEFAULT_ISSUE_FORMATS: [&str; 2] = [r"^#(\d+)$", r"/(?:issues|work_items)/(\d+)$"];

const DEFAULT_SEVERITY_LEVELS: [&str; 4] = ["Critical", "High", "Medium", "Low"];

/// Fill in options not given on the command line from the project
/// configuration, then from the built-in defaults.
fn apply_config(
    args: &mut GenerateArgs,
    hints: &mut Option<PathBuf>,
    config: crate::project::ProjectConfig,
) {
    fn fill<T>(option: &mut Option<T>, value: Option<T>) {
        if option.is_none() {
            *option = value;
        }
    }
    fn fill_all<T>(values: &mut Vec<T>, config: Vec<T>) {
        if values.is_empty() {
            *values = config;
        }
    }
    fill(&mut args.project, config.project);
    fill(&mut args.repo_url, config.repo_url);
    fill(&mut args.policy, config.policy);
    fill(hints, config.hints);
    fill(&mut args.template, config.template);
    fill(&mut args.schema, config.schema);
    fill(&mut args.cwe_catalog, config.cwe_catalog);
    fill_all(&mut args.tag_formats, config.tag_formats);
    fill(&mut args.version_type, config.version_type);
    fill(&mut args.issue_url, config.issue_url);
    fill_all(&mut args.issue_formats, config.issue_formats);
    fill_all(&mut args.severity_levels, config.severity_levels);
    fill(&mut args.parallel, config.parallel);
    // `--var` overrides a variable of the same name; the rest are kept.
    let given: BTreeSet<_> = args
        .vars
        .iter()
        .filter_map(|var| var.split_once('=').map(|(key, _)| key.trim().to_string()))
        .collect();
    for (key, value) in config.vars {
        if !given.contains(&key) {
            args.vars.push(format!("{key}={value}"));
        }
    }
}

/// Built-in defaults for options neither given nor configured.
fn apply_defaults(args: &mut GenerateArgs) {
    let strings = |values: &[&str]| values.iter().map(|value| value.to_string()).collect();
    if args.tag_formats.is_empty() {
        args.tag_formats = strings(&[crate::release::DEFAULT_TAG_FORMAT]);
    }
    if args.issue_formats.is_empty() {
        args.issue_formats = strings(&DEFAULT_ISSUE_FORMATS);
    }
    if args.severity_levels.is_empty() {
        args.severity_levels = strings(&DEFAULT_SEVERITY_LEVELS);
    }
    args.version_type
        .get_or_insert_with(|| "semver".to_string());
    args.parallel.get_or_insert(NonZeroUsize::MIN);
}

fn issue_formats(formats: &[impl AsRef<str>]) -> Result<Vec<Regex>> {
    formats
        .iter()
        .map(|format| {
            let format = format.as_ref();
            let regex =
                Regex::new(format).with_context(|| format!("invalid issue format `{format}`"))?;
            if regex.captures_len() < 2 {
                bail!("issue format `{format}` needs a capture group for the issue number");
            }
            Ok(regex)
        })
        .collect()
}

/// The issue number in `value`, from the first format that matches.
fn issue_number(value: &str, formats: &[Regex]) -> Option<String> {
    let value = value.trim();
    formats.iter().find_map(|regex| {
        let captures = regex.captures(value)?;
        let number = captures.iter().skip(1).flatten().next()?.as_str();
        Some(number.to_string()).filter(|number| !number.is_empty())
    })
}

fn cvss_in(text: &str) -> Option<Cvss> {
    let re = Regex::new(r"CVSS:3\.1(?:/[A-Z]{1,2}:[A-Z])+").unwrap();
    re.find_iter(text)
        .find_map(|found| Cvss::parse_vector(found.as_str()).ok())
}

fn truncate_lines(text: &str, limit: usize) -> String {
    let lines: Vec<_> = text.lines().collect();
    if lines.len() <= limit {
        return text.to_string();
    }
    format!(
        "{}\n[{} more lines; use `read_commit` to read them]",
        lines[..limit].join("\n"),
        lines.len() - limit
    )
}

fn fixes_text(root: &Path, fixes: &[String]) -> Result<String> {
    let mut parts = vec![];
    for fix in fixes {
        let text = crate::git::read_commit(root, fix)?;
        parts.push(truncate_lines(&text, FIX_LINES));
    }
    Ok(parts.join("\n\n"))
}

/// Blame the lines each fix touched, so the model starts from candidates
/// instead of having to discover `blame` on its own.
fn blame_hints(workspace: &Workspace) -> Result<String> {
    let mut lines = vec![];
    let mut commits = BTreeSet::new();
    for fix in &workspace.fixes {
        for (path, start, count) in crate::git::changed_ranges(&workspace.root, fix)? {
            // An insertion has no old lines; blame its surroundings instead.
            let (start, end) = if count == 0 {
                (start.saturating_sub(2).max(1), start + 2)
            } else {
                (start, start + count - 1)
            };
            let Ok(blame) = crate::git::blame(
                &workspace.root,
                &format!("{fix}^"),
                Path::new(&path),
                start,
                end,
            ) else {
                continue;
            };
            lines.push(format!("{path}:"));
            for line in blame.lines() {
                if let Some(hash) = line.split_whitespace().next() {
                    commits.insert(hash.trim_start_matches('^').to_string());
                }
                lines.push(line.to_string());
            }
        }
    }
    let mut text = truncate_lines(&lines.join("\n"), BLAME_LINES);
    text.push_str("\n\nBlamed commits:\n");
    for commit in commits {
        let info = crate::git::commit_info(&workspace.root, &commit)?;
        text.push_str(&format!(
            "- {} {} {} ({})\n",
            info.id,
            &info.date[..10],
            info.subject,
            workspace.describe_release(&info.id)?
        ));
    }
    Ok(text)
}

/// A one-line-per-finding summary, for later stages to build on. The CVSS
/// score is left out with `cvss` false, so that it does not sway a rating
/// meant to follow the project's policy alone.
fn facts(workspace: &Workspace, reporters: &[String], cvss: bool) -> String {
    let mut lines = vec![];
    if let Some(affected) = &workspace.affected {
        let mut range = match &affected.introduced {
            Some(introduced) => format!("from {introduced}"),
            None => "all versions".to_string(),
        };
        if let Some(fixed) = &affected.fixed {
            range.push_str(&format!(" before {fixed}"));
        } else if let Some(last) = &affected.last_affected {
            range.push_str(&format!(" up to {last}"));
        }
        lines.push(format!("- Affected versions: {range}"));
        if let Some(rationale) = &affected.rationale {
            lines.push(format!("- How it was introduced: {rationale}"));
        }
    }
    if let Some(cvss) = workspace.cvss.as_ref().filter(|_| cvss) {
        lines.push(format!(
            "- CVSS: {} ({} {})",
            cvss.vector(),
            cvss.base_score(),
            cvss.base_severity()
        ));
    }
    if let Some(severity) = &workspace.severity {
        lines.push(format!("- Severity: {}", severity.rating));
    }
    if let Some(cwe) = &workspace.cwe {
        lines.push(format!("- Weakness: {} {}", cwe.id, cwe.name));
    }
    if !reporters.is_empty() {
        lines.push(format!("- Reported by: {}", reporters.join(", ")));
    }
    lines.join("\n")
}

struct Runner {
    home: PathBuf,
    verbose: bool,
    cve: String,
    workspace: Arc<Mutex<Workspace>>,
    /// Label each line with the role, since runs may print at once.
    labelled: bool,
    step: AtomicUsize,
    steps: usize,
}

impl Runner {
    /// Run one role. `writes` lists the write tools the model must call.
    async fn run(
        &self,
        task: Task,
        role: Role,
        what: &str,
        writes: &[&'static str],
        opening: &str,
        cancel: CancellationToken,
    ) -> Result<Outcome> {
        let step = self.step.fetch_add(1, Ordering::Relaxed) + 1;
        let settings = crate::model::ModelSettings::load(&self.home, task)?;
        let backend = crate::model::build(&settings, &self.home)?;
        let mut agent = Agent::new(backend, role);
        agent.writes = writes.iter().copied().collect();
        agent.cancel = cancel;
        agent.reporter = Arc::new(if self.labelled {
            crate::progress::Reporter::labelled(role.name)
        } else {
            crate::progress::Reporter::new()
        });
        agent
            .reporter
            .started(task.name(), step, self.steps, &self.cve, what);
        if self.verbose {
            eprintln!("{opening}");
        }
        let outcome = agent
            .run(
                &format!("draftcve-{}-{}", task.name(), self.cve),
                self.workspace.clone(),
                opening,
            )
            .await?;
        if self.verbose {
            eprintln!(
                "{} turn{}, {} in / {} out tokens",
                outcome.turns,
                if outcome.turns == 1 { "" } else { "s" },
                outcome.usage.input_tokens.unwrap_or(0),
                outcome.usage.output_tokens.unwrap_or(0)
            );
        }
        Ok(outcome)
    }
}

/// Stop the runs on the first Ctrl-C, and quit on the second, in case a run
/// is stuck in git where cancellation cannot reach it.
async fn interrupt(cancel: CancellationToken, reporter: Arc<crate::progress::Reporter>) {
    if tokio::signal::ctrl_c().await.is_err() {
        return;
    }
    reporter.warn("interrupted; stopping (press Ctrl-C again to quit now)");
    cancel.cancel();
    if tokio::signal::ctrl_c().await.is_ok() {
        std::process::exit(130);
    }
}

fn parse_vars(vars: &[String]) -> Result<BTreeMap<String, String>> {
    vars.iter()
        .map(|var| {
            var.split_once('=')
                .map(|(key, value)| (key.trim().to_string(), value.to_string()))
                .ok_or_else(|| anyhow!("--var `{var}` is not of the form KEY=VALUE"))
        })
        .collect()
}

fn generate(
    home: &Path,
    mut hints: Option<PathBuf>,
    verbose: bool,
    mut args: GenerateArgs,
) -> Result<()> {
    let cve = args.cve.trim().to_ascii_uppercase();
    if !Regex::new(r"^CVE-\d{4}-\d{4,}$").unwrap().is_match(&cve) {
        bail!("`{}` is not a CVE identifier like CVE-2026-12345", args.cve);
    }
    let root = args
        .repo
        .canonicalize()
        .with_context(|| format!("could not resolve {}", args.repo.display()))?;
    let config = crate::project::ProjectConfig::load(args.config.as_deref(), &root)?;
    if let Some((path, config)) = config {
        if verbose {
            crate::progress::Reporter::new().warn(&format!("using {}", path.display()));
        }
        apply_config(&mut args, &mut hints, config);
    }
    apply_defaults(&mut args);
    let parallel = args.parallel.unwrap_or(NonZeroUsize::MIN);
    let vars = parse_vars(&args.vars)?;
    // Read every input up front: a typo should not cost a model run.
    let template = match &args.template {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?,
        None => crate::render::DEFAULT_TEMPLATE.to_string(),
    };
    let hints = match &hints {
        Some(path) => Some(
            fs::read_to_string(path)
                .with_context(|| format!("could not read {}", path.display()))?,
        ),
        None => None,
    };
    let hints = hints.as_deref();
    let template_name = args
        .template
        .as_ref()
        .map_or("default.json.j2".to_string(), |path| {
            path.display().to_string()
        });
    let policy = match &args.policy {
        Some(path) => Some(
            fs::read_to_string(path)
                .with_context(|| format!("could not read {}", path.display()))?,
        ),
        None => None,
    };
    let report = match &args.report {
        Some(path) => Some(
            fs::read_to_string(path)
                .with_context(|| format!("could not read {}", path.display()))?,
        ),
        None => None,
    };

    let project = match &args.project {
        Some(project) => project.clone(),
        None => root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| anyhow!("cannot derive a project name; pass --project"))?,
    };
    let repo_url = args
        .repo_url
        .clone()
        .or_else(|| crate::git::remote_url(&root, "origin").and_then(|remote| public_url(&remote)));
    if repo_url.is_none() {
        crate::progress::Reporter::new()
            .warn("no public repository URL; pass --repo-url to add references");
    }
    let issue_url = args.issue_url.clone().or_else(|| {
        repo_url
            .as_ref()
            .map(|url| format!("{}/issues/", url.trim_end_matches('/')))
    });
    let issue_formats = issue_formats(&args.issue_formats)?;

    let fixes = args
        .commits
        .iter()
        .map(|commit| crate::git::resolve(&root, commit))
        .collect::<Result<Vec<_>>>()?;
    let releases = Releases::new(&root, &args.tag_formats)?;
    let mut workspace = Workspace::new(&root, releases, fixes.clone())?;
    workspace.version_type = args.version_type.clone().unwrap_or_default();
    workspace.severity_levels = args
        .severity_levels
        .iter()
        .map(|level| level.trim().to_string())
        .filter(|level| !level.is_empty())
        .collect();
    workspace.fixed_in = fixed_in(&workspace, args.fixed_version.as_deref())?;
    let reporter = Arc::new(crate::progress::Reporter::new());
    match (&workspace.fixed_in.fixed, &workspace.fixed_in.last_affected) {
        (Some(fixed), _) => reporter.warn(&format!("fixed in {}", fixed.version)),
        (None, Some(last)) => reporter.warn(&format!(
            "fix not released; last affected release is {}",
            last.version
        )),
        (None, None) => reporter.warn("no release matches the tag format"),
    }

    // Facts git already knows.
    let mut commits = vec![];
    let mut trailers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut messages = String::new();
    for fix in &fixes {
        let info = crate::git::commit_info(&root, fix)?;
        let mut own: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, value) in &info.trailers {
            own.entry(key.clone()).or_default().push(value.clone());
            let merged = trailers.entry(key.clone()).or_default();
            if !merged.contains(value) {
                merged.push(value.clone());
            }
        }
        messages.push_str(&info.body);
        messages.push('\n');
        commits.push(CommitContext {
            short_id: info.id[..12].to_string(),
            id: info.id,
            author: info.author,
            date: info.date,
            subject: info.subject,
            body: info.body,
            trailers: own,
        });
    }
    let values = |keys: &[&str]| -> Vec<String> {
        keys.iter()
            .flat_map(|key| trailers.get(*key).cloned().unwrap_or_default())
            .collect()
    };
    let mut credits: Vec<Credit> = vec![];
    let trailed = CREDIT_TRAILERS.into_iter().flat_map(|(key, kind)| {
        values(&[key]).into_iter().map(move |value| Credit {
            kind,
            value: person(&value),
        })
    });
    let given = args
        .credits
        .iter()
        .map(|credit| parse_credit(credit))
        .collect::<Result<Vec<_>>>()?;
    for credit in trailed.chain(given) {
        if !credit.value.is_empty() && !credits.contains(&credit) {
            credits.push(credit);
        }
    }
    let reporters: Vec<String> = credits
        .iter()
        .filter(|credit| credit.kind == "finder")
        .map(|credit| credit.value.clone())
        .collect();
    let mut issues = vec![];
    let mut advisories = vec![];
    for value in values(&["Fixes", "Closes", "Resolves"]) {
        if let Some(number) = issue_number(&value, &issue_formats) {
            if !issues.contains(&number) {
                issues.push(number);
            }
        } else if !value.to_ascii_uppercase().starts_with("CVE-")
            && !value.contains("://")
            && !advisories.contains(&value)
        {
            advisories.push(value);
        }
    }

    // Answers the user already gave, which the model must not second-guess.
    if let Some(introduced) = &args.introduced {
        workspace.affected = Some(introduced_from(&workspace, introduced)?);
    }
    if let Some(vector) = &args.cvss {
        workspace.cvss = Some(Cvss::parse_vector(vector)?);
    } else if let Some(cvss) = cvss_in(&messages) {
        reporter.warn(&format!("using {} from the commit message", cvss.vector()));
        workspace.cvss = Some(cvss);
    }
    if let Some(severity) = &args.severity {
        workspace.write_severity(severity, None)?;
    }
    if args.cwe.is_some() || workspace.cwe.is_none() {
        workspace.cwe_catalog = load_cwe_catalog(home, args.cwe_catalog.as_deref(), &reporter)?;
    }
    if let Some(cwe) = &args.cwe {
        workspace.cwe = Some(cwe_override(&workspace, cwe, &reporter)?);
    }
    let mut title = args.title.clone();
    let mut description = args.description.clone();

    let fixes_text = fixes_text(&root, &fixes)?;
    let needs_affected = workspace.affected.is_none();
    let mut score_tools = vec![];
    if workspace.cvss.is_none() {
        score_tools.push("write_cvss_score");
    }
    if workspace.cwe.is_none() {
        score_tools.push("write_cwe");
    }
    let needs_severity = workspace.severity.is_none();
    let steps = [
        needs_affected,
        !score_tools.is_empty(),
        needs_severity,
        description.is_none(),
        title.is_none(),
    ]
    .iter()
    .filter(|&&step| step)
    .count();

    let blame = if needs_affected {
        Some(blame_hints(&workspace)?)
    } else {
        None
    };
    let workspace = Arc::new(Mutex::new(workspace));
    let runner = Arc::new(Runner {
        home: home.to_path_buf(),
        verbose,
        cve: cve.clone(),
        workspace: workspace.clone(),
        labelled: parallel.get() > 1,
        step: AtomicUsize::new(0),
        steps,
    });
    // A worker per run, since runs block on git, and one for Ctrl-C.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(parallel.get() + 1)
        .enable_all()
        .build()?;
    let cancel = CancellationToken::new();
    runtime.spawn(interrupt(cancel.clone(), reporter.clone()));

    // Each later run builds on the findings recorded when it starts, and
    // nothing else. Run one at a time, every run sees everything before it;
    // run in parallel, a run sees only what had finished by then.
    // The description waits for all of them, as it is where the facts matter.
    let hints_owned = hints.map(str::to_string);
    let mut subtasks: Vec<(String, crate::subtasks::Start)> = vec![];
    if let Some(blame) = blame {
        let (runner, workspace, reporter) = (runner.clone(), workspace.clone(), reporter.clone());
        let (project, fixes_text) = (project.clone(), fixes_text.clone());
        let (report, hints) = (report.clone(), hints_owned.clone());
        subtasks.push((
            "affected".to_string(),
            Box::new(move |cancel| {
                Box::pin(async move {
                    let opening = crate::prompts::affected_opening(
                        &project,
                        &fixes_text,
                        &blame,
                        report.as_deref(),
                        hints.as_deref(),
                    );
                    runner
                        .run(
                            Task::Affected,
                            crate::agent::AFFECTED,
                            "finding the introducing commit",
                            &["write_affected_versions"],
                            &opening,
                            cancel,
                        )
                        .await?;
                    let mut workspace = workspace.lock().unwrap();
                    if workspace.affected.is_none() {
                        reporter.warn(
                            "the model did not identify the introducing commit; \
                             assuming every version before the fix is affected (pass --introduced to fix)",
                        );
                        let all = Release {
                            tag: String::new(),
                            version: "0".to_string(),
                        };
                        workspace.affected = Some(Affected::new(
                            None,
                            Some(all),
                            &workspace.fixed_in,
                            &workspace.version_type,
                        ));
                    }
                    Ok(())
                })
            }),
        ));
    }

    if !score_tools.is_empty() {
        let (runner, workspace, reporter) = (runner.clone(), workspace.clone(), reporter.clone());
        let (project, fixes_text, reporters) =
            (project.clone(), fixes_text.clone(), reporters.clone());
        let (report, hints) = (report.clone(), hints_owned.clone());
        subtasks.push((
            "score".to_string(),
            Box::new(move |cancel| {
                Box::pin(async move {
                    let opening = {
                        let workspace = workspace.lock().unwrap();
                        crate::prompts::score_opening(
                            &project,
                            &fixes_text,
                            &facts(&workspace, &reporters, true),
                            &score_tools,
                            report.as_deref(),
                            hints.as_deref(),
                        )
                    };
                    runner
                        .run(
                            Task::Assess,
                            crate::agent::SCORE,
                            "scoring the impact",
                            &score_tools,
                            &opening,
                            cancel,
                        )
                        .await?;
                    let workspace = workspace.lock().unwrap();
                    for (tool, missing) in [
                        ("CVSS score", workspace.cvss.is_none()),
                        ("CWE", workspace.cwe.is_none()),
                    ] {
                        if missing {
                            reporter.warn(&format!("the model did not record the {tool}"));
                        }
                    }
                    Ok(())
                })
            }),
        ));
    }

    if needs_severity {
        let (runner, workspace, reporter) = (runner.clone(), workspace.clone(), reporter.clone());
        let (project, fixes_text, reporters) =
            (project.clone(), fixes_text.clone(), reporters.clone());
        let (policy, report, hints) = (policy.clone(), report.clone(), hints_owned.clone());
        subtasks.push((
            "rate".to_string(),
            Box::new(move |cancel| {
                Box::pin(async move {
                    let opening = {
                        let workspace = workspace.lock().unwrap();
                        crate::prompts::rate_opening(
                            &project,
                            &fixes_text,
                            &facts(&workspace, &reporters, false),
                            policy.as_deref(),
                            &workspace.severity_levels,
                            report.as_deref(),
                            hints.as_deref(),
                        )
                    };
                    runner
                        .run(
                            Task::Assess,
                            crate::agent::RATE,
                            "rating the severity under the policy",
                            &["write_severity"],
                            &opening,
                            cancel,
                        )
                        .await?;
                    if workspace.lock().unwrap().severity.is_none() {
                        reporter.warn("the model did not record the severity");
                    }
                    Ok(())
                })
            }),
        ));
    }
    runtime.block_on(crate::subtasks::run(parallel, cancel.clone(), subtasks))?;

    let known = facts(&workspace.lock().unwrap(), &reporters, true);
    if description.is_none() {
        let opening = crate::prompts::describe_opening(
            &project,
            &fixes_text,
            &known,
            report.as_deref(),
            hints,
        );
        let outcome = runtime.block_on(runner.run(
            Task::Describe,
            crate::agent::DESCRIBE,
            "writing the description",
            &[],
            &opening,
            cancel.clone(),
        ))?;
        description = outcome
            .result
            .map(|text| crate::prompts::clean_prose(&text))
            .filter(|text| !text.is_empty());
        if description.is_none() {
            reporter.warn("the model did not write a description");
        }
    }

    if title.is_none()
        && let Some(description) = &description
    {
        let opening = crate::prompts::title_opening(description, &known);
        let outcome = runtime.block_on(runner.run(
            Task::Describe,
            crate::agent::TITLE,
            "writing the title",
            &[],
            &opening,
            cancel.clone(),
        ))?;
        title = outcome
            .result
            .map(|text| crate::prompts::clean_title(&text, &project))
            .filter(|text| !text.is_empty());
    }

    let workspace = workspace.lock().unwrap();
    let date_public = match &args.date_public {
        Some(date) => Some(midnight(date)?),
        None => match &workspace.fixed_in.fixed {
            Some(fixed) if !fixed.tag.is_empty() => {
                let date = crate::git::tag_date(&root, &fixed.tag)?;
                date.get(..10).map(midnight).transpose()?
            }
            _ => None,
        },
    };
    let context = TemplateContext {
        cve_id: &cve,
        project: &project,
        repo_url: repo_url.as_deref(),
        issue_url,
        title,
        description,
        affected: workspace.affected.clone(),
        cvss: workspace.cvss.as_ref().map(Cvss::to_json),
        severity: workspace.severity.clone(),
        cwe: workspace.cwe.clone(),
        commits,
        trailers: trailers.clone(),
        reporters,
        credits,
        issues,
        advisories,
        date_public,
        now: jiff::Timestamp::now()
            .strftime("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string(),
        generator: format!("draftcve {}", env!("CARGO_PKG_VERSION")),
        vars,
    };

    let output = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{cve}.json")));
    if args.dump_context {
        println!("{}", serde_json::to_string_pretty(&context)?);
        return Ok(());
    }
    let record = crate::render::render(&template, &template_name, &context)?;
    fs::write(&output, crate::render::to_pretty(&record)?)
        .with_context(|| format!("could not write {}", output.display()))?;
    println!("Wrote {}", output.display());

    if let Some(schema) = &args.schema {
        let errors = crate::render::validate(schema, &record)?;
        if !errors.is_empty() {
            for error in &errors {
                reporter.warn(error);
            }
            bail!(
                "{} does not conform to {} ({} error{})",
                output.display(),
                schema.display(),
                errors.len(),
                if errors.len() == 1 { "" } else { "s" }
            );
        }
    }
    Ok(())
}

/// The CWE catalog given, or the one under the configuration directory.
/// Missing is not an error, as long as the user hears about it.
fn load_cwe_catalog(
    home: &Path,
    path: Option<&Path>,
    reporter: &crate::progress::Reporter,
) -> Result<Option<Arc<crate::cwe::Catalog>>> {
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => {
            let default = home.join("cwe");
            if crate::cwe::locate(&default).is_err() {
                reporter.warn(&format!(
                    "no CWE catalog in {}; CWEs will not be verified (see `draftcve init`)",
                    default.display()
                ));
                return Ok(None);
            }
            default
        }
    };
    let catalog = crate::cwe::Catalog::load(&path)?;
    reporter.warn(&format!("checking CWEs against CWE {}", catalog.version));
    Ok(Some(Arc::new(catalog)))
}

/// `--cwe` is the user's call, but a typo in the number is still caught.
fn cwe_override(
    workspace: &Workspace,
    cwe: &str,
    reporter: &crate::progress::Reporter,
) -> Result<Cwe> {
    let (id, name) = match cwe.split_once(':') {
        Some((id, name)) => (id, Some(name.trim()).filter(|name| !name.is_empty())),
        None => (cwe, None),
    };
    let number = crate::tools::parse_cwe(id)?;
    let Some(catalog) = &workspace.cwe_catalog else {
        let name = name.ok_or_else(|| {
            anyhow!("--cwe needs a name, as in CWE-<n>:<name>, without a CWE catalog")
        })?;
        return Ok(Cwe {
            id: format!("CWE-{number}"),
            name: name.to_string(),
            usage: None,
        });
    };
    let Some(entry) = catalog.get(number) else {
        bail!(
            "--cwe: CWE-{number} does not exist in CWE {}",
            catalog.version
        );
    };
    if let Some(name) = name
        && !crate::cwe::names_match(name, &entry.name)
    {
        bail!("--cwe: CWE-{number} is \"{}\", not \"{name}\"", entry.name);
    }
    if !entry.usage.mappable() {
        reporter.warn(&format!(
            "{} is {} for mapping: {}",
            catalog.summary(entry),
            entry.usage.name(),
            entry.rationale
        ));
    }
    Ok(Cwe {
        id: format!("CWE-{number}"),
        name: entry.name.clone(),
        usage: Some(entry.usage.name().to_string()),
    })
}

/// Where the fix landed: the first release containing every fix, or, when
/// some fix is unreleased, the last release before it.
fn fixed_in(workspace: &Workspace, fixed_version: Option<&str>) -> Result<FixedIn> {
    if let Some(version) = fixed_version {
        let release = workspace
            .releases
            .by_version(version)?
            .unwrap_or_else(|| Release {
                tag: String::new(),
                version: version.to_string(),
            });
        return Ok(FixedIn {
            fixed: Some(release),
            last_affected: None,
        });
    }
    let mut fixed: Option<Release> = None;
    for fix in &workspace.fixes {
        match workspace.releases.first_containing(fix)? {
            Some(release) => {
                if fixed.as_ref().is_none_or(|current| {
                    crate::release::compare_versions(&release.version, &current.version).is_gt()
                }) {
                    fixed = Some(release);
                }
            }
            None => {
                return Ok(FixedIn {
                    fixed: None,
                    last_affected: workspace.releases.last_before(fix)?,
                });
            }
        }
    }
    Ok(FixedIn {
        fixed,
        last_affected: None,
    })
}

/// `--introduced` takes a commit, or a version when the commit is unknown.
fn introduced_from(workspace: &Workspace, introduced: &str) -> Result<Affected> {
    // A release version first: its tag also resolves as a commit, but the
    // release commit did not introduce anything.
    let (commit, release) = if let Some(release) = workspace.releases.by_version(introduced)? {
        (None, Some(release))
    } else if let Ok(commit) = crate::git::resolve(&workspace.root, introduced) {
        let release = workspace.releases.first_containing(&commit)?;
        (Some(commit), release)
    } else {
        let release = Release {
            tag: String::new(),
            version: introduced.to_string(),
        };
        (None, Some(release))
    };
    Ok(Affected::new(
        commit,
        release,
        &workspace.fixed_in,
        &workspace.version_type,
    ))
}

/// `2026-04-29` to `2026-04-29T00:00:00.000Z`.
fn midnight(date: &str) -> Result<String> {
    let date: jiff::civil::Date = date
        .parse()
        .with_context(|| format!("`{date}` is not a date like 2026-04-29"))?;
    Ok(format!("{date}T00:00:00.000Z"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn credit_types_accept_dashes_for_spaces() {
        let credit = parse_credit("Remediation-Developer = Jane Doe").unwrap();
        assert_eq!(credit.kind, "remediation developer");
        assert_eq!(credit.value, "Jane Doe");
        assert_eq!(parse_credit("tool=fuzzer").unwrap().kind, "tool");
        assert!(parse_credit("hacker=Jane Doe").is_err());
        assert!(parse_credit("Jane Doe").is_err());
    }

    /// Help text is documentation, and documentation that only exists in one
    /// place goes stale silently. This at least enforces that it exists.
    #[test]
    fn every_command_and_argument_is_documented() {
        let command = Cli::command();
        for subcommand in command.get_subcommands() {
            let name = subcommand.get_name();
            if name == "help" {
                continue;
            }
            assert!(
                subcommand.get_about().is_some(),
                "`draftcve {name}` has no help text"
            );
            for argument in subcommand.get_arguments() {
                let id = argument.get_id();
                if id == "help" {
                    continue;
                }
                assert!(
                    argument.get_help().is_some(),
                    "`draftcve {name} --{id}` has no help text"
                );
            }
        }
    }

    #[test]
    fn the_command_line_overrides_the_project_configuration() {
        let cli = Cli::parse_from([
            "draftcve",
            "generate",
            "CVE-2026-1",
            "HEAD",
            "--version-type",
            "git",
            "--var",
            "a=cli",
        ]);
        let CommandName::Generate(mut args) = cli.command else {
            unreachable!()
        };
        let config: crate::project::ProjectConfig = toml::from_str(
            "version_type = \"custom\"\n\
             severity_levels = [\"Important\", \"Moderate\"]\n\
             [vars]\n\
             a = \"config\"\n\
             b = \"config\"\n",
        )
        .unwrap();
        let mut hints = None;
        apply_config(&mut args, &mut hints, config);
        apply_defaults(&mut args);
        assert_eq!(args.version_type.as_deref(), Some("git"));
        assert_eq!(args.severity_levels, ["Important", "Moderate"]);
        assert_eq!(args.tag_formats, [crate::release::DEFAULT_TAG_FORMAT]);
        assert_eq!(args.parallel, NonZeroUsize::new(1));
        let vars = parse_vars(&args.vars).unwrap();
        assert_eq!(vars["a"], "cli");
        assert_eq!(vars["b"], "config");
    }

    #[test]
    fn remotes_become_browsable_urls() {
        assert_eq!(
            public_url("git@gitlab.com:gnutls/gnutls.git").as_deref(),
            Some("https://gitlab.com/gnutls/gnutls")
        );
        assert_eq!(
            public_url("ssh://git@github.com:22/foo/bar.git").as_deref(),
            Some("https://github.com/foo/bar")
        );
        assert_eq!(
            public_url("https://gitlab.com/gnutls/gnutls.git/").as_deref(),
            Some("https://gitlab.com/gnutls/gnutls")
        );
        assert_eq!(public_url("/home/user/gnutls"), None);
    }

    #[test]
    fn trailers_yield_people_and_issues() {
        assert_eq!(
            person("Joshua Rogers of AISLE Research Team <joshua@joshua.hu>"),
            "Joshua Rogers of AISLE Research Team"
        );
        let formats = issue_formats(&DEFAULT_ISSUE_FORMATS).unwrap();
        assert_eq!(issue_number("#1850", &formats).as_deref(), Some("1850"));
        assert_eq!(
            issue_number("https://gitlab.com/gnutls/gnutls/-/issues/1850", &formats).as_deref(),
            Some("1850")
        );
        assert_eq!(issue_number("GNUTLS-SA-2026-04-29-4", &formats), None);

        let bugzilla = r"^(?:rhbz#|https://bugzilla\.redhat\.com/show_bug\.cgi\?id=)(\d+)$";
        let formats = issue_formats(&[bugzilla]).unwrap();
        assert_eq!(
            issue_number("rhbz#2345678", &formats).as_deref(),
            Some("2345678")
        );
        let url = "https://bugzilla.redhat.com/show_bug.cgi?id=2345678";
        assert_eq!(issue_number(url, &formats).as_deref(), Some("2345678"));
        assert_eq!(issue_number("#1850", &formats), None);
        assert!(issue_formats(&[r"^#\d+$"]).is_err());
    }

    #[test]
    fn cvss_is_found_in_messages() {
        let message =
            "CVSS: 7.1 High CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N\nSigned-off-by: x";
        assert_eq!(
            cvss_in(message).unwrap().vector(),
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
        );
        assert!(cvss_in("no score here").is_none());
    }

    #[test]
    fn dates_become_timestamps() {
        assert_eq!(midnight("2026-04-29").unwrap(), "2026-04-29T00:00:00.000Z");
        assert!(midnight("29/04/2026").is_err());
    }
}
