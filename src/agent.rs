//! The agent loop, driven by `oi_kit_agent`'s `StateMachine`.
//!
//! The turn limit is goose's stock [`MaxTurnsOperation`] and the closing summary
//! its [`FinalOutputOperation`]; the rest are ours. The machine tries each step
//! in order per iteration; the first that applies produces effects and the loop
//! repeats. A reply with no tool calls ends the run, as inference no longer
//! applies.

use crate::model::{Backend, Usage};
use crate::progress::Reporter;
use crate::tools::{self, Workspace};
use anyhow::Result;
use async_trait::async_trait;
use oi_kit_agent::final_output::{
    FINAL_OUTPUT_TOOL_NAME, FinalOutputOperation, FinalOutputSchemaSource, FinalOutputTool,
};
use oi_kit_agent::machine::{EffectHandler, MachineSession, SessionLoader, StateMachine, Step};
use oi_kit_agent::max_turns::MaxTurnsOperation;
use oi_kit_agent::operation::{
    ConversationEffect, Emitter, Inference, InferenceInput, Operation, OperationResult, applied,
    ends_turn, messages_since_kickoff, not_applicable, trailing_error, yielded,
};
use oi_kit_agent::tool::{ToolOperation, ToolProvider};
use oi_kit_agent::tool_call_state::{EXECUTABLE_KEY, pending_tool_requests};
use oi_kit_agent::unhandled_tool_calls::UnhandledToolCallsOperation;
use oi_kit_providers::conversation::Conversation;
use oi_kit_providers::conversation::message::{Message, MessageContent, MessageErrorKind};
use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// What the agent is for: one focused task per run, since a small model loses
/// track of a long checklist.
#[derive(Clone, Copy)]
pub struct Role {
    /// Short name, for progress output.
    pub name: &'static str,
    /// Tools offered to the model.
    pub tools: fn() -> Arc<dyn ToolProvider<Session>>,
    /// Instructions.
    pub system: &'static str,
    /// Give up after this many turns.
    pub max_turns: u32,
    /// Start advising the model when this many turns remain.
    pub warn_at: u32,
    /// Role-specific advice sent alongside goose's turn budget near the end.
    pub warning: &'static str,
    /// What running out means for this role.
    pub exhausted: &'static str,
    /// Whether the model closes with a summary through `final_output`. If
    /// not, its closing prose is the result.
    pub summarizes: bool,
}

pub const AFFECTED: Role = Role {
    name: "affected",
    tools: tools::affected_tool_provider,
    system: crate::prompts::AFFECTED,
    max_turns: 32,
    warn_at: 4,
    exhausted: "could not determine the affected versions",
    warning: "You are about to run out of turns. \
              Call `write_affected_versions` with your best candidate commit now, \
              even if you are not completely sure. Then call `final_output`.",
    summarizes: true,
};

pub const SCORE: Role = Role {
    name: "score",
    tools: tools::score_tool_provider,
    system: crate::prompts::SCORE,
    max_turns: 16,
    warn_at: 4,
    exhausted: "could not score the vulnerability",
    warning: "You are about to run out of turns. \
              Record your assessment now, even if you are not completely sure. \
              Then call `final_output`.",
    summarizes: true,
};

pub const RATE: Role = Role {
    name: "rate",
    tools: tools::rate_tool_provider,
    system: crate::prompts::RATE,
    max_turns: 8,
    warn_at: 3,
    exhausted: "could not rate the vulnerability",
    warning: "You are about to run out of turns. \
              Call `write_severity` with your best rating now. Then call `final_output`.",
    summarizes: true,
};

pub const DESCRIBE: Role = Role {
    name: "describe",
    tools: tools::describe_tool_provider,
    system: crate::prompts::DESCRIBE,
    max_turns: 8,
    warn_at: 3,
    exhausted: "could not write the description",
    warning: "You are about to run out of turns. \
              Write the description now, as plain prose.",
    summarizes: false,
};

pub const TITLE: Role = Role {
    name: "title",
    tools: tools::no_tool_provider,
    system: crate::prompts::TITLE,
    max_turns: 2,
    warn_at: 1,
    exhausted: "could not write the title",
    warning: "Reply with the title only.",
    summarizes: false,
};

/// How often to remind a model that ended its turn with work outstanding.
const MAX_NUDGES: usize = 2;

#[derive(Debug)]
pub struct Outcome {
    /// The `final_output` summary, or the closing prose. `None` when the
    /// model ran out of turns: the caller must not mistake an apology for
    /// an answer.
    pub result: Option<String>,
    pub usage: Usage,
    pub turns: usize,
}

#[derive(Default)]
pub struct Record {
    usage: Usage,
    turns: usize,
    /// Reminders sent about outstanding `write_*` calls.
    nudges: usize,
    /// `write_*` tools the model has yet to call.
    pub pending: BTreeSet<&'static str>,
}

/// Everything a step may touch. `StateMachine` hands `&Session` to each
/// operation, so shared mutable state lives behind mutexes.
pub struct Session {
    id: String,
    pub conversation: Conversation,
    pub workspace: Arc<Mutex<Workspace>>,
    pub record: Arc<Mutex<Record>>,
    pub reporter: Arc<Reporter>,
    /// `write_*` tools offered in this run.
    pub writes: Arc<BTreeSet<&'static str>>,
    role: Role,
}

impl MachineSession for Session {
    fn id(&self) -> &str {
        &self.id
    }
    fn conversation(&self) -> Option<&Conversation> {
        Some(&self.conversation)
    }
}

/// Owns the conversation between machine iterations: `load` is called at the top
/// of each pass and `apply_effects` at the end, so the transcript lives here
/// rather than being threaded through the loop.
struct Runtime {
    conversation: Mutex<Conversation>,
    workspace: Arc<Mutex<Workspace>>,
    record: Arc<Mutex<Record>>,
    reporter: Arc<Reporter>,
    writes: Arc<BTreeSet<&'static str>>,
    role: Role,
}

#[async_trait]
impl SessionLoader<Session> for Runtime {
    async fn load(&self, session_id: &str) -> Result<Session> {
        Ok(Session {
            id: session_id.to_string(),
            conversation: self.conversation.lock().unwrap().clone(),
            workspace: self.workspace.clone(),
            record: self.record.clone(),
            reporter: self.reporter.clone(),
            writes: self.writes.clone(),
            role: self.role,
        })
    }
}

#[async_trait]
impl EffectHandler<Session, ConversationEffect> for Runtime {
    async fn apply_effects(
        &self,
        _session: &Session,
        effects: &mut [ConversationEffect],
        _emit: &Emitter,
    ) -> Result<()> {
        let mut conversation = self.conversation.lock().unwrap();
        for effect in effects {
            match effect {
                ConversationEffect::AppendMessage(message) => conversation.push(message.clone()),
                ConversationEffect::ReplaceConversation(replacement) => {
                    *conversation = replacement.clone()
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// The closing summary, collected by [`FinalOutputOperation`].
#[derive(Deserialize, JsonSchema)]
struct Summary {
    /// The summary of the task, in prose.
    summary: String,
}

/// Offer `final_output` to roles that record findings through tools.
struct SummarySchema;

impl FinalOutputSchemaSource<Session> for SummarySchema {
    fn json_schema(&self, session: &Session) -> Option<serde_json::Value> {
        session
            .role
            .summarizes
            .then(|| serde_json::to_value(schemars::schema_for!(Summary)).unwrap())
    }
}

/// Holds the model to its `write_*` calls, which [`FinalOutputOperation`]
/// knows nothing of.
struct PendingWritesOperation;

#[async_trait]
impl Operation<Session, ConversationEffect> for PendingWritesOperation {
    fn name(&self) -> &'static str {
        "pending_writes"
    }

    async fn run(
        &self,
        session: &Session,
        conversation: &Conversation,
        _emit: &Emitter,
    ) -> Result<OperationResult<ConversationEffect>> {
        let mut record = session.record.lock().unwrap();
        if record.pending.is_empty() {
            return not_applicable();
        }
        let pending: Vec<_> = record.pending.iter().copied().collect();
        let pending = pending.join(", ");

        // Refuse to close while findings are outstanding. This runs after
        // the other tools, so a write called alongside has been counted.
        let messages = messages_since_kickoff(conversation)?;
        let summaries: Vec<_> = pending_tool_requests(messages)
            .filter(|request| {
                request
                    .tool_call
                    .as_ref()
                    .is_ok_and(|call| call.name == FINAL_OUTPUT_TOOL_NAME)
            })
            .collect();
        if !summaries.is_empty() {
            let text =
                format!("Error: you have not called {pending} yet. Call it before `final_output`.");
            let mut response = Message::user();
            for request in summaries {
                response.add_tool_response_with_metadata(
                    request.id.clone(),
                    Ok(CallToolResult::error(vec![ContentBlock::text(&text)])),
                    request.metadata.as_ref(),
                );
            }
            return applied([ConversationEffect::AppendMessage(response)]);
        }

        if !ends_turn(messages) {
            return not_applicable();
        }

        // The model stopped with findings outstanding. Small models often
        // describe the call they meant to make instead of making it.
        if record.nudges < MAX_NUDGES {
            record.nudges += 1;
            drop(record);
            let text = format!(
                "You have not called {pending} yet. Call the tool now; \
                 describing the call in prose does not record anything."
            );
            session.reporter.warn(&text);
            return applied([ConversationEffect::AppendMessage(
                Message::user().agent_visible_content().with_text(text),
            )]);
        }

        // Reminders did not help; asking for a summary will not either.
        yielded()
    }
}

/// Ask the model what to do next.
struct InferenceRunner {
    backend: Arc<dyn Backend>,
}

#[async_trait]
impl Operation<Session, ConversationEffect> for InferenceRunner {
    fn name(&self) -> &'static str {
        "inference"
    }
}

#[async_trait]
impl Inference<Session, ConversationEffect> for InferenceRunner {
    fn applies(&self, conversation: &Conversation) -> bool {
        !ends_turn(conversation.messages())
    }

    async fn infer(
        &self,
        session: &Session,
        conversation: &Conversation,
        input: InferenceInput,
        _emit: &Emitter,
    ) -> Result<OperationResult<ConversationEffect>> {
        let next_turn = session.record.lock().unwrap().turns + 1;
        session.reporter.thinking(next_turn);

        let mut messages = conversation.messages().to_vec();
        if let Some(context) = turn_context(session.role, next_turn, input.moim_parts) {
            session.reporter.warn(&context);
            messages.push(Message::user().agent_visible_content().with_text(context));
        }
        // Operations' contributions, chiefly `final_output`'s instructions.
        let system = std::iter::once(session.role.system)
            .chain(input.prompt_parts.iter().map(|(_, part)| part.as_str()))
            .collect::<Vec<_>>()
            .join("\n\n");
        let (mut reply, usage) = self
            .backend
            .complete(&system, &messages, &input.tools)
            .await?;
        session.reporter.model_text(&reply.as_concat_text());
        approve_tool_calls(&mut reply);

        let mut record = session.record.lock().unwrap();
        record.turns += 1;
        if let Some(input_tokens) = usage.input_tokens {
            *record.usage.input_tokens.get_or_insert(0) += input_tokens;
        }
        if let Some(output_tokens) = usage.output_tokens {
            *record.usage.output_tokens.get_or_insert(0) += output_tokens;
        }
        drop(record);

        applied([ConversationEffect::AppendMessage(reply)])
    }
}

/// Context for the coming turn: what operations contributed, chiefly
/// [`MaxTurnsOperation`]'s turn budget, plus the role's advice once few turns
/// remain.
///
/// Sent with the request rather than kept in the conversation, since it is
/// stale by the next turn.
///
/// Hitting the limit is a failure: the run is discarded and the user waited for
/// nothing. Telling the model how many turns remain lets it land somewhere
/// useful instead.
fn turn_context(role: Role, next_turn: usize, mut parts: Vec<String>) -> Option<String> {
    let remaining = (role.max_turns as usize + 1).saturating_sub(next_turn);
    if remaining <= role.warn_at as usize {
        parts.push(role.warning.to_string());
    }
    (!parts.is_empty()).then(|| parts.join("\n"))
}

/// `ToolOperation` runs only calls marked executable, a mark goose leaves to
/// a `ToolApprovalOperation`. Our tools are read-only or write to the
/// workspace, so nothing needs a user's confirmation: mark every call up front
/// rather than run an approval step that allows everything.
fn approve_tool_calls(message: &mut Message) {
    for content in &mut message.content {
        let MessageContent::ToolRequest(request) = content else {
            continue;
        };
        let meta = request
            .tool_meta
            .get_or_insert_with(|| serde_json::json!({}));
        if let Some(meta) = meta.as_object_mut() {
            meta.insert(EXECUTABLE_KEY.to_string(), true.into());
        }
    }
}

pub struct Agent {
    backend: Arc<dyn Backend>,
    role: Role,
    pub reporter: Arc<Reporter>,
    /// `write_*` tools to offer; each must be called before `final_output`.
    pub writes: BTreeSet<&'static str>,
    /// Stops the run between steps.
    pub cancel: CancellationToken,
}

impl Agent {
    pub fn new(backend: Arc<dyn Backend>, role: Role) -> Self {
        Self {
            backend,
            role,
            reporter: Arc::new(Reporter::silent()),
            writes: BTreeSet::new(),
            cancel: CancellationToken::new(),
        }
    }

    /// Run until the model finishes, gives up, or exceeds its turn limit.
    ///
    /// Takes the workspace by value and hands it back, so a caller can inspect
    /// what happened without sharing mutable state with the loop.
    pub async fn run(
        &self,
        session_id: &str,
        workspace: Arc<Mutex<Workspace>>,
        opening: &str,
    ) -> Result<Outcome> {
        let record = Arc::new(Mutex::new(Record {
            pending: self.writes.clone(),
            ..Default::default()
        }));

        let runtime = Runtime {
            conversation: Mutex::new(Conversation::new_unvalidated([
                Message::user().with_text(opening)
            ])),
            workspace: workspace.clone(),
            record: record.clone(),
            reporter: self.reporter.clone(),
            writes: Arc::new(self.writes.clone()),
            role: self.role,
        };

        let steps: Vec<Step<'_, Session, ConversationEffect>> = vec![
            Step::Operation(Arc::new(MaxTurnsOperation::new(self.role.max_turns))),
            Step::Operation(Arc::new(
                ToolOperation::new().with_provider((self.role.tools)()),
            )),
            Step::Operation(Arc::new(PendingWritesOperation)),
            Step::Operation(Arc::new(FinalOutputOperation::new(
                Arc::new(SummarySchema),
                true,
            ))),
            // Answer calls to tools the role lacks, so each turn is counted.
            Step::Operation(Arc::new(UnhandledToolCallsOperation::new())),
            Step::Inference(Arc::new(InferenceRunner {
                backend: self.backend.clone(),
            })),
        ];

        let machine = StateMachine::new(steps, self.cancel.clone());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let emitter = Emitter::new(tx, self.cancel.clone());
        let result = machine.run(&runtime, session_id, &emitter).await;
        rx.close();
        while rx.recv().await.is_some() {}
        result?;

        let conversation = runtime.conversation.into_inner().unwrap();
        if trailing_error(&conversation) == Some(MessageErrorKind::ResourceExhausted) {
            self.reporter
                .warn(&format!("gave up: {}", self.role.exhausted));
        }

        let result = if self.role.summarizes {
            FinalOutputTool::latest_turn_output(&conversation)
                .and_then(|output| serde_json::from_str::<Summary>(&output).ok())
                .map(|output| output.summary)
        } else {
            // A reply with no tool calls is the last word; anything else
            // means the run was cut short.
            ends_turn(conversation.messages())
                .then(|| conversation.messages().last())
                .flatten()
                .map(|message| message.as_concat_text())
        };
        let result = result.map(|text| text.trim().to_string());
        if let Some(summary) = result.as_deref().filter(|_| self.role.summarizes) {
            self.reporter.finished(summary);
        }

        // `record` holds clones of these, so copy the data out.
        let (usage, turns) = {
            let record = record.lock().unwrap();
            (record.usage, record.turns)
        };

        Ok(Outcome {
            result,
            usage,
            turns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::Releases;
    use async_trait::async_trait;
    use rmcp::model::{CallToolRequestParams, Tool};
    use std::collections::VecDeque;
    use std::path::Path;
    use std::process::Command;

    /// Replays canned replies, the way a small model might misbehave, and
    /// keeps what it was shown.
    struct ScriptedBackend {
        replies: Mutex<VecDeque<Message>>,
        seen: Mutex<String>,
    }

    #[async_trait]
    impl Backend for ScriptedBackend {
        async fn complete(
            &self,
            _system: &str,
            messages: &[Message],
            _tools: &[Tool],
        ) -> Result<(Message, Usage)> {
            *self.seen.lock().unwrap() = serde_json::to_string(messages)?;
            let reply = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("the script ran out of replies");
            Ok((reply, Usage::default()))
        }
    }

    fn call(name: &'static str, arguments: serde_json::Value) -> Message {
        // Request ids must be unique: goose skips a request it has answered.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let params =
            CallToolRequestParams::new(name).with_arguments(arguments.as_object().unwrap().clone());
        Message::assistant().with_tool_request(format!("call-{id}"), Ok(params))
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?} failed");
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    /// v1.0 is clean, v1.1 introduces the flaw, v1.2 refactors it, v1.3 fixes it.
    fn repository(dir: &Path) -> (String, String) {
        git(dir, &["init", "-q"]);
        let commit = |text: &str, message: &str, tag: &str| {
            std::fs::write(dir.join("lib.c"), text).unwrap();
            git(dir, &["add", "lib.c"]);
            git(dir, &["commit", "-q", "-m", message]);
            git(dir, &["tag", tag]);
            git(dir, &["rev-parse", "HEAD"])
        };
        commit("int f(char *s) {\n  return 0;\n}\n", "initial", "v1.0");
        let introduced = commit(
            "int f(char *s) {\n  return strlen(s);\n}\n",
            "allow binary names",
            "v1.1",
        );
        commit(
            "int f(char *name) {\n  return strlen(name);\n}\n",
            "rename argument",
            "v1.2",
        );
        let fix = commit(
            "int f(char *name, size_t len) {\n  return len;\n}\n",
            "fix length of binary names",
            "v1.3",
        );
        (introduced, fix)
    }

    #[tokio::test]
    async fn a_misbehaving_model_is_steered_to_an_answer() {
        let dir = tempdir::TempDir::new("cve-report-agent").unwrap();
        let (introduced, fix) = repository(dir.path());
        let releases = Releases::new(dir.path(), &[crate::release::DEFAULT_TAG_FORMAT]).unwrap();
        let mut workspace = Workspace::new(dir.path(), releases, vec![fix.clone()]).unwrap();
        workspace.fixed_in.fixed = workspace.releases.first_containing(&fix).unwrap();
        let workspace = Arc::new(Mutex::new(workspace));

        let backend = Arc::new(ScriptedBackend {
            replies: Mutex::new(VecDeque::from([
                // Describes the call instead of making it.
                Message::assistant().with_text("The flaw was introduced by the rename."),
                // Blames the fix itself.
                call(
                    "write_affected_versions",
                    serde_json::json!({"introduced_by": fix}),
                ),
                // Tries to stop early.
                call(
                    FINAL_OUTPUT_TOOL_NAME,
                    serde_json::json!({"summary": "done"}),
                ),
                call(
                    "write_affected_versions",
                    serde_json::json!({"introduced_by": introduced, "rationale": "added strlen"}),
                ),
                call(
                    FINAL_OUTPUT_TOOL_NAME,
                    serde_json::json!({"summary": "introduced in v1.1"}),
                ),
            ])),
            seen: Mutex::new(String::new()),
        });
        let mut agent = Agent::new(backend.clone(), AFFECTED);
        agent.writes = ["write_affected_versions"].into();
        let outcome = agent
            .run("test", workspace.clone(), "find it")
            .await
            .unwrap();

        assert_eq!(outcome.result.as_deref(), Some("introduced in v1.1"));
        assert_eq!(outcome.turns, 5);
        let seen = backend.seen.lock().unwrap().clone();
        assert!(
            seen.contains("You have not called write_affected_versions yet"),
            "{seen}"
        );
        assert!(seen.contains("is the fix itself"), "{seen}");
        assert!(seen.contains("before `final_output`"), "{seen}");

        let workspace = workspace.lock().unwrap();
        let affected = workspace.affected.as_ref().unwrap();
        assert_eq!(affected.introduced.as_deref(), Some("1.1"));
        assert_eq!(affected.fixed.as_deref(), Some("1.3"));
    }

    #[tokio::test]
    async fn prose_is_the_result_of_a_prose_role() {
        let dir = tempdir::TempDir::new("cve-report-prose").unwrap();
        let (_, fix) = repository(dir.path());
        let releases = Releases::new(dir.path(), &[crate::release::DEFAULT_TAG_FORMAT]).unwrap();
        let workspace = Workspace::new(dir.path(), releases, vec![fix]).unwrap();
        let backend = Arc::new(ScriptedBackend {
            replies: Mutex::new(VecDeque::from([
                Message::assistant().with_text("A flaw was found in lib.")
            ])),
            seen: Mutex::new(String::new()),
        });
        let agent = Agent::new(backend, DESCRIBE);
        let outcome = agent
            .run("test", Arc::new(Mutex::new(workspace)), "describe it")
            .await
            .unwrap();
        assert_eq!(outcome.result.as_deref(), Some("A flaw was found in lib."));
    }

    #[tokio::test]
    async fn running_out_of_turns_yields_no_result() {
        let dir = tempdir::TempDir::new("cve-report-exhausted").unwrap();
        let (_, fix) = repository(dir.path());
        let releases = Releases::new(dir.path(), &[crate::release::DEFAULT_TAG_FORMAT]).unwrap();
        let workspace = Workspace::new(dir.path(), releases, vec![fix.clone()]).unwrap();
        let replies: VecDeque<_> = (0..TITLE.max_turns)
            .map(|_| call("read_commit", serde_json::json!({"commit": fix})))
            .collect();
        let backend = Arc::new(ScriptedBackend {
            replies: Mutex::new(replies),
            seen: Mutex::new(String::new()),
        });
        let agent = Agent::new(backend, TITLE);
        let outcome = agent
            .run("test", Arc::new(Mutex::new(workspace)), "title")
            .await
            .unwrap();
        assert_eq!(outcome.result, None);
    }
}
