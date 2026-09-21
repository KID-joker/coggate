use std::sync::Arc;

use coggate_core::{
    ChallengeService, IssueRequest, LifecycleRejection, ServiceError, Submission,
    VerificationOutcome, VerifyRequest,
};
use tokio::sync::broadcast;

use crate::{
    db::Database,
    error::{ArenaError, ArenaResult},
    lifecycle::{SqliteLifecycle, StaticKeyring},
    runner::{RunStatus, RunnerClient},
    util::{ascii_trim, now_unix},
};

#[derive(Clone, Debug)]
pub struct WorkerEvent {
    pub submission_id: String,
    pub kind: &'static str,
}

#[derive(Clone)]
pub struct SubmissionWorker {
    database: Database,
    runner: RunnerClient,
    keys: StaticKeyring,
    events: broadcast::Sender<WorkerEvent>,
    arena_events: broadcast::Sender<String>,
    worker_id: String,
}

pub fn issue_body(work: &crate::model::IssueWork) -> String {
    let marker = format!(
        "<!-- coggate-playground:{}:{} -->",
        work.round_id, work.submission_id
    );
    let mut fence = "```".to_owned();
    while work.source.contains(&fence) {
        fence.push('`');
    }
    format!(
        "# CogGate Playground cleared\n\nSolver: [@{login}](https://github.com/{login})\n\n\
- Round: `{round}` (epoch {epoch})\n\
- SDK: `{sdk}` (`{commit}`)\n\
- Generator: `{generator}`\n\
- Solution language: `{language}`\n\
- Runner image: `{image}`\n\
- Source SHA-256: `{sha}`\n\
- Compile time: {compile} ms\n\
- Run time: {run} ms\n\n\
{fence}{language}\n{source}\n{fence}\n\n{marker}\n",
        login = work.github_login,
        round = work.round_id,
        epoch = work.epoch,
        sdk = work.sdk_version,
        commit = work.sdk_commit,
        generator = work.generator_version,
        language = work.language,
        image = work.runner_image_digest,
        sha = work.source_sha256,
        compile = work.compile_ms.unwrap_or_default(),
        run = work.run_ms.unwrap_or_default(),
        source = work.source,
    )
}

pub async fn run_issue_worker(database: Database, github: crate::github::GitHubClient) {
    loop {
        match database.claim_issue_work() {
            Ok(Some(work)) => {
                let marker = format!(
                    "coggate-playground:{}:{}",
                    work.round_id, work.submission_id
                );
                let title = format!(
                    "CogGate Playground epoch {} solved by @{}",
                    work.epoch, work.github_login
                );
                let body = issue_body(&work);
                match github.find_or_create_issue(&marker, &title, &body).await {
                    Ok(issue) => {
                        if let Err(error) =
                            database.complete_issue(&work.event_id, issue.number, &issue.html_url)
                        {
                            tracing::error!(event_id=%work.event_id, error=%error, "issue completion commit failed");
                        }
                    }
                    Err(_) => {
                        let _ = database.fail_issue(
                            &work.event_id,
                            work.attempt_count,
                            "github_unavailable",
                        );
                    }
                }
            }
            Ok(None) => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
            Err(error) => {
                tracing::error!(error=%error, "issue worker failed");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

impl SubmissionWorker {
    pub fn new(
        database: Database,
        runner: RunnerClient,
        keys: StaticKeyring,
        events: broadcast::Sender<WorkerEvent>,
        arena_events: broadcast::Sender<String>,
    ) -> ArenaResult<Self> {
        Ok(Self {
            database,
            runner,
            keys,
            events,
            arena_events,
            worker_id: crate::util::random_id("worker")?,
        })
    }

    pub async fn run(self: Arc<Self>) {
        match self.database.recover_stale_work() {
            Ok(pending_finalizers) => {
                for (submission_id, lease_id) in pending_finalizers {
                    if let Ok(true) = self.database.finalize_verified(&submission_id, &lease_id) {
                        let _ = self.arena_events.send("arena_solved".into());
                    }
                }
            }
            Err(error) => tracing::error!(error=%error, "startup recovery failed"),
        }
        loop {
            match self.database.claim_next(&self.worker_id, 30) {
                Ok(Some(submission)) => {
                    if let Err(error) = self.process(submission.clone()).await {
                        tracing::error!(submission_id=%submission.id, error=%error, "submission failed internally");
                        let _ = self.database.terminal_failure(
                            &submission.id,
                            &submission.lease_id,
                            "INTERNAL_ERROR",
                            "internal_error",
                        );
                    }
                }
                Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
                Err(error) => {
                    tracing::error!(error=%error, "worker claim failed");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn notify(&self, submission_id: &str, kind: &'static str) {
        let _ = self.events.send(WorkerEvent {
            submission_id: submission_id.into(),
            kind,
        });
    }

    async fn process(&self, submission: crate::model::ClaimedSubmission) -> ArenaResult<()> {
        self.notify(&submission.id, "compiling");
        let compiled = self
            .runner
            .prepare(
                &submission.id,
                &submission.lease_id,
                submission.language,
                &submission.source,
            )
            .await?;
        if !self
            .database
            .record_compile(&submission.id, &submission.lease_id, &compiled)?
        {
            if let Some(artifact) = compiled.artifact_id.as_deref() {
                self.runner.destroy(artifact).await;
            }
            return Err(ArenaError::Conflict);
        }
        if !compiled.success {
            self.notify(&submission.id, "compile_error");
            return Ok(());
        }
        let artifact_id = compiled
            .artifact_id
            .as_deref()
            .ok_or(ArenaError::Upstream)?;
        if !self
            .database
            .round_is_open(&submission.round_id, submission.epoch)?
        {
            self.runner.destroy(artifact_id).await;
            self.database.terminal_failure(
                &submission.id,
                &submission.lease_id,
                "ARENA_CLOSED",
                "arena_closed",
            )?;
            self.notify(&submission.id, "arena_closed");
            return Ok(());
        }

        let binding = format!(
            "arena-v1|{}|{}|{}|{}",
            submission.round_id, submission.epoch, submission.id, submission.github_id
        );
        let mut service = ChallengeService::new(
            SqliteLifecycle::new(self.database.clone()),
            self.keys.clone(),
        );
        let challenge = service
            .issue_challenge(
                IssueRequest::v1(binding.as_bytes()).map_err(|_| ArenaError::Internal)?,
            )
            .map_err(|_| ArenaError::Internal)?;
        let deadline = challenge.expires_at - 2;
        if !self.database.record_challenge(
            &submission.id,
            &submission.lease_id,
            &challenge,
            deadline,
        )? || !self
            .database
            .mark_running(&submission.id, &submission.lease_id)?
        {
            self.runner.destroy(artifact_id).await;
            return Err(ArenaError::Conflict);
        }
        self.notify(&submission.id, "running");
        let available_ms = (deadline - now_unix()).saturating_mul(1000);
        if available_ms <= 0 {
            self.runner.destroy(artifact_id).await;
            self.database.terminal_failure(
                &submission.id,
                &submission.lease_id,
                "CHALLENGE_EXPIRED",
                "challenge_expired",
            )?;
            return Ok(());
        }
        let run = self
            .runner
            .execute(
                artifact_id,
                &challenge.question,
                available_ms.min(5_000) as u64,
            )
            .await;
        self.runner.destroy(artifact_id).await;
        let run = run?;
        self.database
            .record_run(&submission.id, &submission.lease_id, &run)?;
        match run.status {
            RunStatus::TimedOut => {
                return self.finish_failure(&submission, "TIMED_OUT", "timed_out");
            }
            RunStatus::OutputLimitExceeded => {
                return self.finish_failure(
                    &submission,
                    "OUTPUT_LIMIT_EXCEEDED",
                    "output_limit_exceeded",
                );
            }
            RunStatus::SandboxError => {
                return self.finish_failure(&submission, "INTERNAL_ERROR", "sandbox_error");
            }
            RunStatus::Exited if run.exit_code != Some(0) => {
                return self.finish_failure(&submission, "RUNTIME_ERROR", "nonzero_exit");
            }
            RunStatus::Exited => {}
        }
        if now_unix() > deadline {
            return self.finish_failure(&submission, "CHALLENGE_EXPIRED", "challenge_expired");
        }
        if run.output_encoding != "utf8" {
            return self.finish_failure(&submission, "INVALID_OUTPUT", "stdout_not_utf8");
        }
        let answer_bytes = ascii_trim(run.stdout.as_bytes());
        if answer_bytes.is_empty() || answer_bytes.len() > 256 {
            return self.finish_failure(&submission, "INVALID_OUTPUT", "invalid_answer_length");
        }
        let answer = std::str::from_utf8(answer_bytes).map_err(|_| ArenaError::Internal)?;
        if !self
            .database
            .mark_verifying(&submission.id, &submission.lease_id)?
        {
            return Err(ArenaError::Conflict);
        }
        let request = Submission {
            challenge_id: challenge.challenge_id,
            nonce: challenge.nonce,
            answer: answer.into(),
        };
        match service.verify_submission(
            VerifyRequest::new(&request, binding.as_bytes()).map_err(|_| ArenaError::Internal)?,
        ) {
            Ok(VerificationOutcome::Accepted) => {
                let won = self
                    .database
                    .finalize_verified(&submission.id, &submission.lease_id)?;
                self.notify(&submission.id, if won { "passed" } else { "lost_race" });
                if won {
                    let _ = self.arena_events.send("arena_solved".into());
                }
            }
            Ok(VerificationOutcome::Rejected(LifecycleRejection::Expired)) => {
                self.finish_failure(&submission, "CHALLENGE_EXPIRED", "challenge_expired")?;
            }
            Ok(VerificationOutcome::Rejected(_)) => {
                self.finish_failure(&submission, "INTERNAL_ERROR", "lifecycle_rejected")?;
            }
            Err(ServiceError::AnswerMismatch) => {
                self.finish_failure(&submission, "WRONG_ANSWER", "answer_mismatch")?;
            }
            Err(ServiceError::InvalidAnswerEncoding) => {
                self.finish_failure(&submission, "INVALID_OUTPUT", "invalid_answer_encoding")?;
            }
            Err(_) => self.finish_failure(&submission, "INTERNAL_ERROR", "verification_error")?,
        }
        Ok(())
    }

    fn finish_failure(
        &self,
        submission: &crate::model::ClaimedSubmission,
        status: &str,
        disposition: &str,
    ) -> ArenaResult<()> {
        self.database.terminal_failure(
            &submission.id,
            &submission.lease_id,
            status,
            disposition,
        )?;
        self.notify(&submission.id, "finished");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::model::IssueWork;

    #[test]
    fn issue_fence_cannot_be_closed_by_source() {
        let work = IssueWork {
            event_id: "event".into(),
            attempt_count: 1,
            round_id: "round".into(),
            epoch: 1,
            sdk_version: "0.1".into(),
            sdk_commit: "abc".into(),
            generator_version: "1.0".into(),
            submission_id: "submission".into(),
            github_login: "octocat".into(),
            language: "python".into(),
            source: "print('```')".into(),
            source_sha256: "sha".into(),
            compile_ms: Some(1),
            run_ms: Some(2),
            runner_image_digest: "image@sha256:abc".into(),
        };
        let body = super::issue_body(&work);
        assert!(body.contains("````python"));
        assert!(body.contains("<!-- coggate-playground:round:submission -->"));
    }
}
