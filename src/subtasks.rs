//! Runs independent agent runs side by side, through `oi_kit_agent`'s
//! [`SubagentOperation`].
//!
//! A parent `StateMachine` has that operation as its only step. Its opening
//! message names the subtasks; the operation starts them in order, at most
//! `parallel` at a time, and appends each one's outcome to the parent
//! conversation as it finishes. Once every outcome is in, nothing applies and
//! the parent yields.

use crate::agent::Interrupted;
use anyhow::Result;
use async_trait::async_trait;
use futures::{FutureExt, stream};
use oi_kit_agent::machine::{EffectHandler, MachineSession, SessionLoader, StateMachine, Step};
use oi_kit_agent::operation::{ConversationEffect, Emitter, OperationStream};
use oi_kit_agent::subagent::{SubagentOperation, SubagentOutcome, SubagentRunner, SubagentUpdate};
use oi_kit_providers::conversation::Conversation;
use oi_kit_providers::conversation::message::Message;
use std::collections::HashMap;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Where the opening message lists the subtasks.
const NOTE: (&str, &str) = ("cve_report", "subtasks");

/// Starts one subtask. Called only when its turn comes, so that it sees the
/// findings of the subtasks that finished before it.
pub type Start = Box<dyn FnOnce(CancellationToken) -> Subtask + Send>;
pub type Subtask = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

struct Parent {
    conversation: Conversation,
}

impl MachineSession for Parent {
    fn id(&self) -> &str {
        "cve-report"
    }
    fn conversation(&self) -> Option<&Conversation> {
        Some(&self.conversation)
    }
}

struct Runtime {
    conversation: Mutex<Conversation>,
}

#[async_trait]
impl SessionLoader<Parent> for Runtime {
    async fn load(&self, _session_id: &str) -> Result<Parent> {
        Ok(Parent {
            conversation: self.conversation.lock().unwrap().clone(),
        })
    }
}

#[async_trait]
impl EffectHandler<Parent, ConversationEffect> for Runtime {
    async fn apply_effects(
        &self,
        _session: &Parent,
        effects: &mut [ConversationEffect],
        _emit: &Emitter,
    ) -> Result<()> {
        let mut conversation = self.conversation.lock().unwrap();
        for effect in effects {
            if let ConversationEffect::AppendMessage(message) = effect {
                conversation.push(message.clone());
            }
        }
        Ok(())
    }
}

struct Runner {
    starts: Mutex<HashMap<String, Start>>,
    /// The first failure. Once set, no further subtask starts.
    error: Arc<Mutex<Option<anyhow::Error>>>,
}

#[async_trait]
impl SubagentRunner<Parent> for Runner {
    fn requested_subagent_session_ids(&self, _parent: &Parent, message: &Message) -> Vec<String> {
        message
            .metadata
            .operation_note(NOTE.0, NOTE.1)
            .and_then(|names| serde_json::from_value(names.clone()).ok())
            .unwrap_or_default()
    }

    async fn start(
        &self,
        _parent: &Parent,
        name: &str,
        cancel: CancellationToken,
    ) -> OperationStream<'static, SubagentUpdate> {
        let start = self.starts.lock().unwrap().remove(name);
        let (Some(start), None) = (start, self.error.lock().unwrap().as_ref()) else {
            return Box::pin(stream::once(async {
                SubagentUpdate::Finished(SubagentOutcome::Cancelled)
            }));
        };
        // A task of its own, so that a run blocked on git does not hold up
        // the others.
        let task = tokio::spawn(start(cancel));
        let error = self.error.clone();
        Box::pin(
            async move {
                let outcome = match task.await {
                    Ok(Ok(())) => SubagentOutcome::Completed(String::new()),
                    Ok(Err(failure)) => {
                        let reason = format!("{failure:#}");
                        error.lock().unwrap().get_or_insert(failure);
                        SubagentOutcome::Failed(reason)
                    }
                    Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
                    Err(_) => SubagentOutcome::Cancelled,
                };
                SubagentUpdate::Finished(outcome)
            }
            .into_stream(),
        )
    }
}

/// Run subtasks in order, up to `parallel` at a time. After a failure no new
/// subtask starts, and the first error is returned once the running ones
/// finish.
///
/// Cancelling `cancel` stops at once: each running subtask is handed the same
/// token, and is left to wind down on its own. The result is then
/// [`Interrupted`].
///
/// Must be called within a multi-threaded runtime with at least `parallel`
/// workers, since the subtasks block on git.
pub async fn run(
    parallel: NonZeroUsize,
    cancel: CancellationToken,
    subtasks: Vec<(String, Start)>,
) -> Result<()> {
    let names: Vec<_> = subtasks.iter().map(|(name, _)| name.clone()).collect();
    let mut opening = Message::user().with_text("Run the subtasks.");
    opening
        .metadata
        .set_operation_note(NOTE.0, NOTE.1, serde_json::json!(names));

    let error = Arc::new(Mutex::new(None));
    let runner = Runner {
        starts: Mutex::new(subtasks.into_iter().collect()),
        error: error.clone(),
    };
    let runtime = Runtime {
        conversation: Mutex::new(Conversation::new_unvalidated([opening])),
    };
    let steps: Vec<Step<'_, Parent, ConversationEffect>> = vec![Step::Operation(Arc::new(
        SubagentOperation::new(Arc::new(runner)).with_max_concurrency(parallel),
    ))];

    let machine = StateMachine::new(steps, cancel.clone());
    let (tx, mut rx) = mpsc::unbounded_channel();
    let emitter = Emitter::new(tx, cancel.clone());
    let result = machine.run(&runtime, "cve-report", &emitter).await;
    rx.close();
    while rx.recv().await.is_some() {}
    result?;

    match error.lock().unwrap().take() {
        Some(error) => Err(error),
        None if cancel.is_cancelled() => Err(Interrupted.into()),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn parallel(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    fn subtask<F>(name: impl ToString, run: F) -> (String, Start)
    where
        F: Future<Output = Result<()>> + Send + 'static,
    {
        (name.to_string(), Box::new(move |_| Box::pin(run)))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn one_subtask_at_a_time_runs_in_order() {
        let order = Arc::new(Mutex::new(vec![]));
        let subtasks = (0..4)
            .map(|i| {
                let order = order.clone();
                subtask(i, async move {
                    order.lock().unwrap().push(i);
                    Ok(())
                })
            })
            .collect();
        run(parallel(1), CancellationToken::new(), subtasks)
            .await
            .unwrap();
        assert_eq!(*order.lock().unwrap(), [0, 1, 2, 3]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn subtasks_overlap_up_to_the_limit() {
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let subtasks = (0..6)
            .map(|i| {
                let (running, peak) = (running.clone(), peak.clone());
                subtask(i, async move {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    // Blocking, as a run does on git.
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    running.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
            })
            .collect();
        run(parallel(3), CancellationToken::new(), subtasks)
            .await
            .unwrap();
        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn a_failure_starts_no_more_subtasks() {
        let ran = Arc::new(AtomicUsize::new(0));
        let counted = ran.clone();
        let subtasks = vec![
            subtask("fails", async { bail!("model request failed") }),
            subtask("skipped", async move {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        ];
        let error = run(parallel(1), CancellationToken::new(), subtasks)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "model request failed");
        assert_eq!(ran.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn cancelling_interrupts_and_starts_no_more_subtasks() {
        let cancel = CancellationToken::new();
        let ran = Arc::new(AtomicUsize::new(0));
        let counted = ran.clone();
        let stop = cancel.clone();
        let subtasks: Vec<(String, Start)> = vec![
            (
                "waits".to_string(),
                Box::new(move |cancel: CancellationToken| {
                    Box::pin(async move {
                        stop.cancel();
                        cancel.cancelled().await;
                        Err(Interrupted.into())
                    })
                }),
            ),
            subtask("skipped", async move {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        ];
        let error = run(parallel(1), cancel, subtasks).await.unwrap_err();
        assert!(error.is::<Interrupted>(), "{error:#}");
        assert_eq!(ran.load(Ordering::SeqCst), 0);
    }
}
