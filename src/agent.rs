//! The agent loop, driven by `goose_agent`'s `StateMachine`.
//!
//! Operations are ours because goose's are not public API yet. The machine tries
//! each step in order per iteration; the first that applies produces effects and
//! the loop repeats.
//!
//! One sharp edge: `StateMachine::step` always reaches the inference step and
//! does not consult `Inference::applies`, so a prose reply with no tool calls
//! would loop forever without [`EndTurnOperation`] ahead of it.

use crate::model::{Backend, Usage};
use crate::progress::Reporter;
use crate::tools::{self, Workspace};
use anyhow::Result;
use async_trait::async_trait;
use goose_agent::machine::{EffectHandler, MachineSession, SessionLoader, StateMachine, Step};
use goose_agent::operation::{
    ConversationEffect, Emitter, Inference, InferenceInput, Operation, OperationResult, applied,
    ends_turn, not_applicable, yielded,
};
use goose_agent::tool::{ToolOperation, ToolProvider};
use goose_agent::tool_call_state::EXECUTABLE_KEY;
use goose_providers::conversation::Conversation;
use goose_providers::conversation::message::{Message, MessageContent};
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
    pub max_turns: usize,
    /// Start warning the model when this many turns remain.
    pub warn_at: usize,
    /// How to phrase the warning. `{remaining}` is substituted.
    pub warning: &'static str,
    /// What running out means for this role.
    pub exhausted: &'static str,
}

pub const AFFECTED: Role = Role {
    name: "affected",
    tools: tools::affected_tool_provider,
    system: crate::prompts::AFFECTED,
    max_turns: 32,
    warn_at: 4,
    exhausted: "could not determine the affected versions",
    warning: "You have {remaining} retries left before this run is stopped. \
              Call `write_affected_versions` with your best candidate commit now, \
              even if you are not completely sure. Then call `finish`.",
};

pub const SCORE: Role = Role {
    name: "score",
    tools: tools::score_tool_provider,
    system: crate::prompts::SCORE,
    max_turns: 16,
    warn_at: 4,
    exhausted: "could not score the vulnerability",
    warning: "You have {remaining} retries left before this run is stopped. \
              Record your assessment now, even if you are not completely sure. \
              Then call `finish`.",
};

pub const RATE: Role = Role {
    name: "rate",
    tools: tools::rate_tool_provider,
    system: crate::prompts::RATE,
    max_turns: 8,
    warn_at: 3,
    exhausted: "could not rate the vulnerability",
    warning: "You have {remaining} retries left before this run is stopped. \
              Call `write_severity` with your best rating now. Then call `finish`.",
};

pub const DESCRIBE: Role = Role {
    name: "describe",
    tools: tools::describe_tool_provider,
    system: crate::prompts::DESCRIBE,
    max_turns: 8,
    warn_at: 3,
    exhausted: "could not write the description",
    warning: "You have {remaining} retries left before this run is stopped. \
              Write the description now, as plain prose.",
};

pub const TITLE: Role = Role {
    name: "title",
    tools: tools::no_tool_provider,
    system: crate::prompts::TITLE,
    max_turns: 2,
    warn_at: 1,
    exhausted: "could not write the title",
    warning: "Reply with the title only.",
};

/// How often to remind a model that ended its turn with work outstanding.
const MAX_NUDGES: usize = 2;

#[derive(Debug)]
pub struct Outcome {
    /// The terminal tool's result, or the closing prose. `None` when the
    /// model ran out of turns: the caller must not mistake an apology for
    /// an answer.
    pub result: Option<String>,
    pub usage: Usage,
    pub turns: usize,
}

#[derive(Default)]
pub struct Record {
    pub result: Option<String>,
    usage: Usage,
    turns: usize,
    /// Remaining-turn count at the last warning, so each is issued once.
    warned_at: Option<usize>,
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

/// Stop before an agent runs away, and warn it as the limit approaches.
///
/// Hitting the limit is a failure: the run is discarded and the user waited for
/// nothing. Telling the model how many turns remain lets it land somewhere
/// useful instead.
/// Without this a small model will happily search until it exhausts its context.
struct MaxTurnsOperation;

#[async_trait]
impl Operation<Session, ConversationEffect> for MaxTurnsOperation {
    fn name(&self) -> &'static str {
        "max_turns"
    }

    async fn run(
        &self,
        session: &Session,
        conversation: &Conversation,
        _emit: &Emitter,
    ) -> Result<OperationResult<ConversationEffect>> {
        let role = session.role;
        let record = session.record.lock().unwrap();
        if record.turns >= role.max_turns {
            drop(record);
            session
                .reporter
                .warn(&format!("gave up: {}", role.exhausted));
            return yielded();
        }

        let remaining = role.max_turns - record.turns;
        if remaining > role.warn_at || record.warned_at == Some(remaining) {
            return not_applicable();
        }
        drop(record);

        // Never nag a model that has stopped asking for tools. Warning after a
        // prose reply restarts a finished conversation, and the model — having
        // already answered — spends the rest of its budget saying so.
        if ends_turn(conversation.messages()) {
            return not_applicable();
        }
        let mut record = session.record.lock().unwrap();
        // Once per turn, not once per run: a model that ignores the first
        // warning should see the number fall.
        record.warned_at = Some(remaining);
        drop(record);

        let text = role.warning.replace("{remaining}", &remaining.to_string());
        session.reporter.warn(&text);
        applied([ConversationEffect::AppendMessage(
            Message::user().agent_visible_content().with_text(text),
        )])
    }
}

/// The model replied with prose and no tool calls, so it has nothing further to
/// do. Take its words as the result rather than discarding them.
struct EndTurnOperation;

#[async_trait]
impl Operation<Session, ConversationEffect> for EndTurnOperation {
    fn name(&self) -> &'static str {
        "end_turn"
    }

    async fn run(
        &self,
        session: &Session,
        conversation: &Conversation,
        _emit: &Emitter,
    ) -> Result<OperationResult<ConversationEffect>> {
        // The agent has called `finish` in the previous iteration.
        let mut record = session.record.lock().unwrap();
        if record.result.is_some() {
            return yielded();
        }

        if !ends_turn(conversation.messages()) {
            return not_applicable();
        }

        // The model stopped with findings outstanding. Small models often
        // describe the call they meant to make instead of making it.
        let pending: Vec<_> = record.pending.iter().copied().collect();
        if !pending.is_empty() && record.nudges < MAX_NUDGES {
            record.nudges += 1;
            drop(record);
            let text = format!(
                "You have not called {} yet. Call the tool now; \
                 describing the call in prose does not record anything.",
                pending.join(", ")
            );
            session.reporter.warn(&text);
            return applied([ConversationEffect::AppendMessage(
                Message::user().agent_visible_content().with_text(text),
            )]);
        }

        // The agent hasn't called `finish`, but ended the
        // conversation with a prose. Use it as a result.
        let text = conversation
            .messages()
            .last()
            .map(|message| message.as_concat_text())
            .unwrap_or_default();
        record.result = Some(text.trim().to_string());
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

        let (mut reply, usage) = self
            .backend
            .complete(session.role.system, conversation.messages(), &input.tools)
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

/// `ToolOperation` runs only calls marked executable, a mark goose leaves to
/// a `ToolApprovalOperation`. Our tools are read-only or write to the
/// workspace, so nothing needs a user's confirmation: mark every call up front
/// rather than run an approval step that allows everything.
fn approve_tool_calls(message: &mut Message) {
    for content in &mut message.content {
        let MessageContent::ToolRequest(request) = content else {
            continue;
        };
        let meta = request.tool_meta.get_or_insert_with(|| serde_json::json!({}));
        if let Some(meta) = meta.as_object_mut() {
            meta.insert(EXECUTABLE_KEY.to_string(), true.into());
        }
    }
}

pub struct Agent {
    backend: Arc<dyn Backend>,
    role: Role,
    pub reporter: Arc<Reporter>,
    /// `write_*` tools to offer; each must be called before `finish`.
    pub writes: BTreeSet<&'static str>,
}

impl Agent {
    pub fn new(backend: Arc<dyn Backend>, role: Role) -> Self {
        Self {
            backend,
            role,
            reporter: Arc::new(Reporter::silent()),
            writes: BTreeSet::new(),
        }
    }

    /// Run until the model finishes, gives up, or exceeds its turn limit.
    ///
    /// Takes the workspace by value and hands it back, so a caller can inspect
    /// what happened without sharing mutable state with the loop.
    pub fn run(
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
            Step::Operation(Arc::new(EndTurnOperation)),
            Step::Operation(Arc::new(MaxTurnsOperation)),
            Step::Operation(Arc::new(
                ToolOperation::new().with_provider((self.role.tools)()),
            )),
            Step::Inference(Arc::new(InferenceRunner {
                backend: self.backend.clone(),
            })),
        ];

        let cancel = CancellationToken::new();
        let machine = StateMachine::new(steps, cancel.clone());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let emitter = Emitter::new(tx, cancel);

        // The machine is async; the CLI is not.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let result = machine.run(&runtime, session_id, &emitter).await;
                rx.close();
                while rx.recv().await.is_some() {}
                result
            })?;

        // `record` holds clones of these, so copy the data out.
        let (result, usage, turns) = {
            let record = record.lock().unwrap();
            (record.result.clone(), record.usage, record.turns)
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

    #[test]
    fn a_misbehaving_model_is_steered_to_an_answer() {
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
                call("finish", serde_json::json!({"summary": "done"})),
                call(
                    "write_affected_versions",
                    serde_json::json!({"introduced_by": introduced, "rationale": "added strlen"}),
                ),
                call(
                    "finish",
                    serde_json::json!({"summary": "introduced in v1.1"}),
                ),
            ])),
            seen: Mutex::new(String::new()),
        });
        let mut agent = Agent::new(backend.clone(), AFFECTED);
        agent.writes = ["write_affected_versions"].into();
        let outcome = agent.run("test", workspace.clone(), "find it").unwrap();

        assert_eq!(outcome.result.as_deref(), Some("introduced in v1.1"));
        assert_eq!(outcome.turns, 5);
        let seen = backend.seen.lock().unwrap().clone();
        assert!(
            seen.contains("You have not called write_affected_versions yet"),
            "{seen}"
        );
        assert!(seen.contains("is the fix itself"), "{seen}");
        assert!(seen.contains("before `finish`"), "{seen}");

        let workspace = workspace.lock().unwrap();
        let affected = workspace.affected.as_ref().unwrap();
        assert_eq!(affected.introduced.as_deref(), Some("1.1"));
        assert_eq!(affected.fixed.as_deref(), Some("1.3"));
    }

    #[test]
    fn prose_is_the_result_of_a_prose_role() {
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
            .unwrap();
        assert_eq!(outcome.result.as_deref(), Some("A flaw was found in lib."));
    }

    #[test]
    fn running_out_of_turns_yields_no_result() {
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
            .unwrap();
        assert_eq!(outcome.result, None);
    }
}
