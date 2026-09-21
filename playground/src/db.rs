use std::{
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
};

use coggate_contracts::PublicChallenge;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{
    error::{ArenaError, ArenaResult},
    model::{
        AcceptedSubmission, ArenaView, ClaimedSubmission, DAILY_LIMIT, ExecutionView, IssueWork,
        Language, QuotaView, Round, SubmissionView, User, Winner,
    },
    runner::{CompileResult, RunResult},
    util::{now_unix, random_id, sha256_hex, token_hash},
};

const SCHEMA: &str = include_str!("db/schema.sql");
const INFLIGHT_SQL: &str = "'ACCEPTED','COMPILING','READY','CHALLENGE_ISSUED','RUNNING','VERIFYING','VERIFIED_ACCEPTED_PENDING_FINALIZE'";

#[derive(Clone)]
pub struct Database {
    connection: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Database").finish_non_exhaustive()
    }
}

impl Database {
    pub fn open(path: &Path) -> ArenaResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| {
                ArenaError::Configuration("cannot create database directory".into())
            })?;
        }
        let connection = Connection::open(path)?;
        Self::configure(&connection)?;
        connection.execute_batch(SCHEMA)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn open_in_memory() -> ArenaResult<Self> {
        let connection = Connection::open_in_memory()?;
        Self::configure(&connection)?;
        connection.execute_batch(SCHEMA)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    fn configure(connection: &Connection) -> ArenaResult<()> {
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        Ok(())
    }

    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Connection>, ArenaError> {
        self.connection.lock().map_err(|_| ArenaError::Internal)
    }

    pub fn create_round(
        &self,
        sdk_version: &str,
        sdk_commit: &str,
        generator_version: &str,
        runner_manifest_digest: &str,
    ) -> ArenaResult<Round> {
        let id = random_id("round")?;
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let epoch: i64 = tx.query_row(
            "SELECT COALESCE(MAX(epoch), 0) + 1 FROM arena_rounds",
            [],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO arena_rounds
             (id, epoch, status, sdk_version, sdk_commit, generator_version, runner_manifest_digest)
             VALUES (?1, ?2, 'PREPARING', ?3, ?4, ?5, ?6)",
            params![
                id,
                epoch,
                sdk_version,
                sdk_commit,
                generator_version,
                runner_manifest_digest
            ],
        )?;
        tx.commit()?;
        Ok(Round {
            id,
            epoch,
            status: "PREPARING".into(),
            sdk_version: sdk_version.into(),
            sdk_commit: sdk_commit.into(),
            generator_version: generator_version.into(),
            runner_manifest_digest: runner_manifest_digest.into(),
        })
    }

    pub fn open_round(&self, round_id: &str, actor: &str) -> ArenaResult<()> {
        let now = now_unix();
        let audit_id = random_id("audit")?;
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM arena_rounds WHERE id=?1",
                [round_id],
                |row| row.get(0),
            )
            .optional()?;
        if status.as_deref() != Some("PREPARING") {
            return Err(ArenaError::Conflict);
        }
        tx.execute(
            "UPDATE submissions SET status='ARENA_CLOSED',source=NULL,finished_at=?1,result_expires_at=?2,
             verification_disposition='round_archived' WHERE status='ACCEPTED'
             AND round_id IN (SELECT id FROM arena_rounds WHERE status='OPEN')",
            params![now, now + 86400],
        )?;
        tx.execute(
            "UPDATE arena_rounds SET status='ARCHIVED' WHERE status='OPEN'",
            [],
        )?;
        tx.execute(
            "UPDATE arena_rounds SET status='OPEN', opened_at=?2 WHERE id=?1 AND status='PREPARING'",
            params![round_id, now],
        )?;
        tx.execute(
            "INSERT INTO admin_audit(id,actor,action,target_id,created_at,reason_code)
             VALUES (?1,?2,'OPEN_ROUND',?3,?4,'self_checks_passed')",
            params![audit_id, actor, round_id, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn enter_maintenance(&self, actor: &str, reason_code: &str) -> ArenaResult<String> {
        let now = now_unix();
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let round_id: String = tx
            .query_row(
                "SELECT id FROM arena_rounds WHERE status='OPEN'",
                [],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(ArenaError::ArenaClosed)?;
        tx.execute(
            "UPDATE submissions SET status='ARENA_CLOSED',source=NULL,finished_at=?2,result_expires_at=?3,
             verification_disposition='maintenance' WHERE round_id=?1 AND status='ACCEPTED'",
            params![round_id, now, now + 86400],
        )?;
        tx.execute(
            "UPDATE arena_rounds SET status='MAINTENANCE' WHERE id=?1 AND status='OPEN'",
            [&round_id],
        )?;
        tx.execute(
            "INSERT INTO admin_audit(id,actor,action,target_id,created_at,reason_code)
             VALUES (?1,?2,'ENTER_MAINTENANCE',?3,?4,?5)",
            params![random_id("audit")?, actor, round_id, now, reason_code],
        )?;
        tx.commit()?;
        Ok(round_id)
    }

    pub fn archive_round(&self, round_id: &str, actor: &str, reason_code: &str) -> ArenaResult<()> {
        let now = now_unix();
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE arena_rounds SET status='ARCHIVED' WHERE id=?1 AND status IN ('PREPARING','SOLVED','MAINTENANCE')",
            [round_id],
        )?;
        if changed != 1 {
            return Err(ArenaError::Conflict);
        }
        tx.execute(
            "INSERT INTO admin_audit(id,actor,action,target_id,created_at,reason_code)
             VALUES (?1,?2,'ARCHIVE_ROUND',?3,?4,?5)",
            params![random_id("audit")?, actor, round_id, now, reason_code],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_user_disabled(
        &self,
        github_id: i64,
        disabled: bool,
        actor: &str,
        reason_code: &str,
    ) -> ArenaResult<()> {
        let now = now_unix();
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE users SET disabled_at=?2 WHERE github_id=?1",
            params![github_id, disabled.then_some(now)],
        )?;
        if changed != 1 {
            return Err(ArenaError::NotFound);
        }
        if disabled {
            tx.execute("DELETE FROM auth_sessions WHERE github_id=?1", [github_id])?;
        }
        tx.execute(
            "INSERT INTO admin_audit(id,actor,action,target_id,created_at,reason_code)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                random_id("audit")?,
                actor,
                if disabled {
                    "DISABLE_USER"
                } else {
                    "ENABLE_USER"
                },
                github_id.to_string(),
                now,
                reason_code
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn add_manual_credit(
        &self,
        github_id: i64,
        amount: i64,
        actor: &str,
        reason_code: &str,
    ) -> ArenaResult<()> {
        if !(1..=100).contains(&amount) {
            return Err(ArenaError::InvalidRequest("invalid_credit"));
        }
        let now = now_unix();
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let date = Self::quota_date(&tx, now)?;
        tx.execute(
            "INSERT INTO daily_quotas(github_id,quota_date,used,manual_credit) VALUES (?1,?2,0,?3)
             ON CONFLICT(github_id,quota_date) DO UPDATE SET manual_credit=manual_credit+excluded.manual_credit",
            params![github_id, date, amount],
        )?;
        tx.execute(
            "INSERT INTO admin_audit(id,actor,action,target_id,created_at,reason_code)
             VALUES (?1,?2,'ADD_CREDIT',?3,?4,?5)",
            params![
                random_id("audit")?,
                actor,
                github_id.to_string(),
                now,
                reason_code
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn retry_issue(&self, event_id: &str) -> ArenaResult<()> {
        let changed = self.lock()?.execute(
            "UPDATE outbox SET status='RETRYABLE_ERROR',next_attempt_at=?2,last_error_code=NULL
             WHERE id=?1 AND status IN ('TERMINAL_ERROR','RETRYABLE_ERROR')",
            params![event_id, now_unix()],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ArenaError::Conflict)
        }
    }

    pub fn integrity_check(&self) -> ArenaResult<bool> {
        let result: String = self
            .lock()?
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(result == "ok")
    }

    pub fn current_round(&self) -> ArenaResult<Round> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT id,epoch,status,sdk_version,sdk_commit,generator_version,runner_manifest_digest
                 FROM arena_rounds WHERE status <> 'ARCHIVED'
                 ORDER BY CASE WHEN status='PREPARING' THEN 1 ELSE 0 END, epoch DESC LIMIT 1",
                [],
                |row| {
                    Ok(Round {
                        id: row.get(0)?,
                        epoch: row.get(1)?,
                        status: row.get(2)?,
                        sdk_version: row.get(3)?,
                        sdk_commit: row.get(4)?,
                        generator_version: row.get(5)?,
                        runner_manifest_digest: row.get(6)?,
                    })
                },
            )
            .optional()?
            .ok_or(ArenaError::NotFound)
    }

    pub fn arena_view(&self, source_limit_bytes: usize) -> ArenaResult<ArenaView> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT r.id,r.epoch,r.status,r.sdk_version,r.sdk_commit,r.generator_version,
                        r.winner_github_login,r.winner_submission_id,o.issue_url
                 FROM arena_rounds r
                 LEFT JOIN outbox o ON o.round_id=r.id AND o.event_type='CREATE_WINNER_ISSUE'
                 WHERE r.status <> 'ARCHIVED'
                 ORDER BY CASE WHEN r.status='PREPARING' THEN 1 ELSE 0 END, r.epoch DESC LIMIT 1",
                [],
                |row| {
                    let login: Option<String> = row.get(6)?;
                    let submission_id: Option<String> = row.get(7)?;
                    let winner = login
                        .zip(submission_id)
                        .map(|(github_login, submission_id)| Winner {
                            profile_url: format!("https://github.com/{github_login}"),
                            github_login,
                            submission_id,
                        });
                    Ok(ArenaView {
                        round_id: row.get(0)?,
                        epoch: row.get(1)?,
                        status: row.get(2)?,
                        sdk_version: row.get(3)?,
                        sdk_commit: row.get(4)?,
                        generator_version: row.get(5)?,
                        supported_languages: Language::ALL.iter().map(|v| v.as_str()).collect(),
                        daily_limit: DAILY_LIMIT,
                        source_limit_bytes,
                        winner,
                        issue_url: row.get(8)?,
                    })
                },
            )
            .optional()?
            .ok_or(ArenaError::NotFound)
    }

    pub fn store_oauth_state(&self, state: &str, expires_at: i64) -> ArenaResult<()> {
        self.lock()?.execute(
            "INSERT INTO oauth_states(state_hash,created_at,expires_at) VALUES (?1,?2,?3)",
            params![token_hash(state), now_unix(), expires_at],
        )?;
        Ok(())
    }

    pub fn consume_oauth_state(&self, state: &str) -> ArenaResult<()> {
        let now = now_unix();
        let changed = self.lock()?.execute(
            "UPDATE oauth_states SET consumed_at=?2
             WHERE state_hash=?1 AND consumed_at IS NULL AND expires_at>=?2",
            params![token_hash(state), now],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ArenaError::Unauthorized)
        }
    }

    pub fn create_login_session(
        &self,
        github_id: i64,
        login: &str,
        ttl_seconds: i64,
    ) -> ArenaResult<String> {
        let now = now_unix();
        let token = crate::util::random_token(32)?;
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO users(github_id,github_login,last_login_at) VALUES (?1,?2,?3)
             ON CONFLICT(github_id) DO UPDATE SET github_login=excluded.github_login,last_login_at=excluded.last_login_at",
            params![github_id, login, now],
        )?;
        tx.execute(
            "INSERT INTO auth_sessions(token_hash,github_id,created_at,expires_at) VALUES (?1,?2,?3,?4)",
            params![token_hash(&token), github_id, now, now + ttl_seconds],
        )?;
        tx.commit()?;
        Ok(token)
    }

    pub fn authenticate(&self, token: &str) -> ArenaResult<User> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT u.github_id,u.github_login FROM auth_sessions s
                 JOIN users u ON u.github_id=s.github_id
                 WHERE s.token_hash=?1 AND s.expires_at>?2 AND u.disabled_at IS NULL",
                params![token_hash(token), now_unix()],
                |row| {
                    Ok(User {
                        github_id: row.get(0)?,
                        github_login: row.get(1)?,
                    })
                },
            )
            .optional()?
            .ok_or(ArenaError::Unauthorized)
    }

    pub fn logout(&self, token: &str) -> ArenaResult<()> {
        self.lock()?.execute(
            "DELETE FROM auth_sessions WHERE token_hash=?1",
            [token_hash(token)],
        )?;
        Ok(())
    }

    fn quota_date(tx: &rusqlite::Transaction<'_>, now: i64) -> rusqlite::Result<String> {
        tx.query_row(
            "SELECT strftime('%Y-%m-%d', ?1, 'unixepoch', '+8 hours')",
            [now],
            |row| row.get(0),
        )
    }

    pub fn quota_for(&self, github_id: i64) -> ArenaResult<QuotaView> {
        let mut connection = self.lock()?;
        let tx = connection.transaction()?;
        let date = Self::quota_date(&tx, now_unix())?;
        let (used, credit): (i64, i64) = tx
            .query_row(
                "SELECT used,manual_credit FROM daily_quotas WHERE github_id=?1 AND quota_date=?2",
                params![github_id, date],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .unwrap_or((0, 0));
        Ok(QuotaView {
            used_today: used,
            remaining_today: (DAILY_LIMIT + credit - used).max(0),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept_submission(
        &self,
        user: &User,
        epoch: i64,
        language: Language,
        source: &str,
        idempotency_key: &str,
        queue_limit: i64,
        runner_image_digest: &str,
        policy_digest: &str,
    ) -> ArenaResult<AcceptedSubmission> {
        let now = now_unix();
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(id) = tx
            .query_row(
                "SELECT id FROM submissions WHERE github_id=?1 AND idempotency_key=?2",
                params![user.github_id, idempotency_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let date = Self::quota_date(&tx, now)?;
            let (used, credit): (i64, i64) = tx
                .query_row(
                    "SELECT used,manual_credit FROM daily_quotas WHERE github_id=?1 AND quota_date=?2",
                    params![user.github_id, date],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .unwrap_or((0, 0));
            return Ok(AcceptedSubmission {
                id,
                created: false,
                quota: QuotaView {
                    used_today: used,
                    remaining_today: (DAILY_LIMIT + credit - used).max(0),
                },
            });
        }

        let round: Option<(String, i64)> = tx
            .query_row(
                "SELECT id,epoch FROM arena_rounds WHERE status='OPEN'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (round_id, active_epoch) = round.ok_or(ArenaError::ArenaClosed)?;
        if active_epoch != epoch {
            return Err(ArenaError::EpochChanged);
        }
        let inflight_query = format!(
            "SELECT id FROM submissions WHERE github_id=?1 AND status IN ({INFLIGHT_SQL}) LIMIT 1"
        );
        if let Some(id) = tx
            .query_row(&inflight_query, [user.github_id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
        {
            return Err(ArenaError::SubmissionInFlight(Some(id)));
        }
        let queued: i64 = tx.query_row(
            "SELECT COUNT(*) FROM submissions WHERE status='ACCEPTED'",
            [],
            |row| row.get(0),
        )?;
        if queued >= queue_limit {
            return Err(ArenaError::QueueFull);
        }

        let date = Self::quota_date(&tx, now)?;
        tx.execute(
            "INSERT INTO daily_quotas(github_id,quota_date,used,manual_credit)
             VALUES (?1,?2,0,0) ON CONFLICT(github_id,quota_date) DO NOTHING",
            params![user.github_id, date],
        )?;
        let changed = tx.execute(
            "UPDATE daily_quotas SET used=used+1
             WHERE github_id=?1 AND quota_date=?2 AND used < ?3 + manual_credit",
            params![user.github_id, date, DAILY_LIMIT],
        )?;
        if changed != 1 {
            return Err(ArenaError::QuotaExhausted);
        }
        let (used, credit): (i64, i64) = tx.query_row(
            "SELECT used,manual_credit FROM daily_quotas WHERE github_id=?1 AND quota_date=?2",
            params![user.github_id, date],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let id = random_id("sub")?;
        tx.execute(
            "INSERT INTO submissions
             (id,round_id,epoch,github_id,idempotency_key,language,source,source_sha256,status,
              created_at,runner_image_digest,policy_digest)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'ACCEPTED',?9,?10,?11)",
            params![
                id,
                round_id,
                epoch,
                user.github_id,
                idempotency_key,
                language.as_str(),
                source,
                sha256_hex(source.as_bytes()),
                now,
                runner_image_digest,
                policy_digest
            ],
        )?;
        tx.commit()?;
        Ok(AcceptedSubmission {
            id,
            created: true,
            quota: QuotaView {
                used_today: used,
                remaining_today: (DAILY_LIMIT + credit - used).max(0),
            },
        })
    }

    pub fn claim_next(
        &self,
        worker_id: &str,
        lease_seconds: i64,
    ) -> ArenaResult<Option<ClaimedSubmission>> {
        let now = now_unix();
        let lease_id = random_id("lease")?;
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate: Option<(String, String, i64, i64, String, String, String)> = tx
            .query_row(
                "SELECT s.id,s.round_id,s.epoch,s.github_id,u.github_login,s.language,s.source
                 FROM submissions s JOIN users u ON u.github_id=s.github_id
                 JOIN arena_rounds r ON r.id=s.round_id
                 WHERE s.status='ACCEPTED' AND r.status='OPEN'
                 ORDER BY s.created_at LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, round_id, epoch, github_id, github_login, language, source)) = candidate
        else {
            return Ok(None);
        };
        let changed = tx.execute(
            "UPDATE submissions SET status='COMPILING',worker_id=?2,lease_id=?3,lease_expires_at=?4,
             heartbeat_at=?5,started_at=COALESCE(started_at,?5),execution_attempt=execution_attempt+1
             WHERE id=?1 AND status='ACCEPTED'",
            params![id, worker_id, lease_id, now + lease_seconds, now],
        )?;
        if changed != 1 {
            return Ok(None);
        }
        tx.commit()?;
        Ok(Some(ClaimedSubmission {
            id,
            round_id,
            epoch,
            github_id,
            github_login,
            language: Language::from_str(&language).map_err(|_| ArenaError::Internal)?,
            source,
            lease_id,
        }))
    }

    pub fn record_compile(
        &self,
        submission_id: &str,
        lease_id: &str,
        result: &CompileResult,
    ) -> ArenaResult<bool> {
        let connection = self.lock()?;
        if result.success {
            let changed = connection.execute(
                "UPDATE submissions SET status='READY',compile_ms=?3,compile_output=?4,
                 runner_image_digest=?5,heartbeat_at=?6 WHERE id=?1 AND lease_id=?2 AND status='COMPILING'",
                params![submission_id, lease_id, result.duration_ms, result.output, result.image_digest, now_unix()],
            )?;
            Ok(changed == 1)
        } else {
            let now = now_unix();
            let changed = connection.execute(
                "UPDATE submissions SET status='COMPILE_ERROR',compile_ms=?3,compile_output=?4,
                 runner_image_digest=?5,source=NULL,finished_at=?6,result_expires_at=?7
                 WHERE id=?1 AND lease_id=?2 AND status='COMPILING'",
                params![
                    submission_id,
                    lease_id,
                    result.duration_ms,
                    result.output,
                    result.image_digest,
                    now,
                    now + 86400
                ],
            )?;
            Ok(changed == 1)
        }
    }

    pub fn round_is_open(&self, round_id: &str, epoch: i64) -> ArenaResult<bool> {
        let exists: i64 = self.lock()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM arena_rounds WHERE id=?1 AND epoch=?2 AND status='OPEN')",
            params![round_id, epoch],
            |row| row.get(0),
        )?;
        Ok(exists == 1)
    }

    pub fn record_challenge(
        &self,
        submission_id: &str,
        lease_id: &str,
        challenge: &PublicChallenge,
        verification_deadline: i64,
    ) -> ArenaResult<bool> {
        let changed = self.lock()?.execute(
            "UPDATE submissions SET status='CHALLENGE_ISSUED',challenge_id=?3,public_challenge_json=?4,
             verification_deadline=?5,heartbeat_at=?6
             WHERE id=?1 AND lease_id=?2 AND status='READY'",
            params![submission_id, lease_id, challenge.challenge_id, serde_json::to_string(challenge).map_err(|_| ArenaError::Internal)?, verification_deadline, now_unix()],
        )?;
        Ok(changed == 1)
    }

    pub fn mark_running(&self, submission_id: &str, lease_id: &str) -> ArenaResult<bool> {
        Ok(self.lock()?.execute(
            "UPDATE submissions SET status='RUNNING',heartbeat_at=?3 WHERE id=?1 AND lease_id=?2 AND status='CHALLENGE_ISSUED'",
            params![submission_id, lease_id, now_unix()],
        )? == 1)
    }

    pub fn record_run(
        &self,
        submission_id: &str,
        lease_id: &str,
        result: &RunResult,
    ) -> ArenaResult<bool> {
        let changed = self.lock()?.execute(
            "UPDATE submissions SET run_ms=?3,exit_code=?4,stdout=?5,stderr=?6,output_encoding=?7,
             stdout_truncated=?8,stderr_truncated=?9,heartbeat_at=?10
             WHERE id=?1 AND lease_id=?2 AND status='RUNNING'",
            params![
                submission_id,
                lease_id,
                result.duration_ms,
                result.exit_code,
                result.stdout,
                result.stderr,
                result.output_encoding,
                result.stdout_truncated,
                result.stderr_truncated,
                now_unix()
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn mark_verifying(&self, submission_id: &str, lease_id: &str) -> ArenaResult<bool> {
        Ok(self.lock()?.execute(
            "UPDATE submissions SET status='VERIFYING',heartbeat_at=?3 WHERE id=?1 AND lease_id=?2 AND status='RUNNING'",
            params![submission_id, lease_id, now_unix()],
        )? == 1)
    }

    pub fn terminal_failure(
        &self,
        submission_id: &str,
        lease_id: &str,
        status: &str,
        disposition: &str,
    ) -> ArenaResult<()> {
        if !crate::model::is_terminal(status) || status == "PASSED" {
            return Err(ArenaError::Internal);
        }
        let now = now_unix();
        let changed = self.lock()?.execute(
            "UPDATE submissions SET status=?3,verification_disposition=?4,source=NULL,finished_at=?5,
             result_expires_at=?6 WHERE id=?1 AND lease_id=?2 AND status NOT IN
             ('PASSED','CORRECT_BUT_LOST_RACE','COMPILE_ERROR','RUNTIME_ERROR','TIMED_OUT','OUTPUT_LIMIT_EXCEEDED','INVALID_OUTPUT','CHALLENGE_EXPIRED','WRONG_ANSWER','ARENA_CLOSED','INTERNAL_ERROR')",
            params![submission_id, lease_id, status, disposition, now, now + 86400],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ArenaError::Conflict)
        }
    }

    pub fn finalize_verified(&self, submission_id: &str, lease_id: &str) -> ArenaResult<bool> {
        let now = now_unix();
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(String, i64, i64, String)> = tx
            .query_row(
                "SELECT s.round_id,s.epoch,s.github_id,u.github_login FROM submissions s
                 JOIN users u ON u.github_id=s.github_id
                 WHERE s.id=?1 AND s.lease_id=?2 AND s.status='VERIFIED_ACCEPTED_PENDING_FINALIZE'",
                params![submission_id, lease_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((round_id, epoch, github_id, github_login)) = row else {
            return Err(ArenaError::Conflict);
        };
        let won = tx.execute(
            "UPDATE arena_rounds SET status='SOLVED',winner_github_id=?3,winner_github_login=?4,
             winner_submission_id=?5,solved_at=?6 WHERE id=?1 AND epoch=?2 AND status='OPEN'",
            params![round_id, epoch, github_id, github_login, submission_id, now],
        )? == 1;
        if won {
            tx.execute(
                "UPDATE submissions SET status='PASSED',verification_disposition='accepted',finished_at=?2,
                 result_expires_at=?3 WHERE id=?1",
                params![submission_id, now, now + 86400],
            )?;
            tx.execute(
                "INSERT INTO outbox(id,round_id,submission_id,event_type,status,next_attempt_at)
                 VALUES (?1,?2,?3,'CREATE_WINNER_ISSUE','PENDING',?4)
                 ON CONFLICT(round_id,event_type) DO NOTHING",
                params![random_id("event")?, round_id, submission_id, now],
            )?;
            tx.execute(
                "UPDATE submissions SET status='ARENA_CLOSED',source=NULL,finished_at=?2,result_expires_at=?3,
                 verification_disposition='arena_closed' WHERE round_id=?1 AND id<>?4 AND status='ACCEPTED'",
                params![round_id, now, now + 86400, submission_id],
            )?;
        } else {
            tx.execute(
                "UPDATE submissions SET status='CORRECT_BUT_LOST_RACE',source=NULL,
                 verification_disposition='correct_but_lost_race',finished_at=?2,result_expires_at=?3 WHERE id=?1",
                params![submission_id, now, now + 86400],
            )?;
        }
        tx.commit()?;
        Ok(won)
    }

    pub fn submission_view(&self, id: &str, github_id: i64) -> ArenaResult<SubmissionView> {
        let connection = self.lock()?;
        let mut view = connection
            .query_row(
                "SELECT s.status,s.language,s.source_sha256,s.public_challenge_json,s.compile_ms,s.run_ms,
                        s.exit_code,s.compile_output,s.stdout,s.stderr,s.output_encoding,s.stdout_truncated,
                        s.stderr_truncated,s.verification_disposition,r.status,r.winner_github_login,
                        r.winner_submission_id
                 FROM submissions s JOIN arena_rounds r ON r.id=s.round_id
                 WHERE s.id=?1 AND s.github_id=?2",
                params![id, github_id],
                |row| {
                    let status: String = row.get(0)?;
                    let terminal = crate::model::is_terminal(&status);
                    let challenge_json: Option<String> = row.get(3)?;
                    let winner_login: Option<String> = row.get(15)?;
                    let winner_submission: Option<String> = row.get(16)?;
                    Ok(SubmissionView {
                        submission_id: id.into(),
                        status,
                        language: row.get(1)?,
                        source_sha256: row.get(2)?,
                        challenge: if terminal {
                            challenge_json.and_then(|value| serde_json::from_str(&value).ok())
                        } else {
                            None
                        },
                        execution: ExecutionView {
                            compile_ms: row.get(4)?, run_ms: row.get(5)?, exit_code: row.get(6)?,
                            compile_output: if terminal { row.get(7)? } else { None },
                            stdout: if terminal { row.get(8)? } else { None },
                            stderr: if terminal { row.get(9)? } else { None },
                            output_encoding: if terminal { row.get(10)? } else { None },
                            stdout_truncated: row.get::<_, i64>(11)? != 0,
                            stderr_truncated: row.get::<_, i64>(12)? != 0,
                        },
                        verification_disposition: row.get(13)?,
                        quota: QuotaView { used_today: 0, remaining_today: 0 },
                        arena_status: row.get(14)?,
                        winner: winner_login.zip(winner_submission).map(|(github_login, submission_id)| Winner {
                            profile_url: format!("https://github.com/{github_login}"), github_login, submission_id,
                        }),
                    })
                },
            )
            .optional()?
            .ok_or(ArenaError::NotFound)?;
        drop(connection);
        view.quota = self.quota_for(github_id)?;
        Ok(view)
    }

    pub fn recent_submission_ids(&self, github_id: i64) -> ArenaResult<Vec<String>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id FROM submissions WHERE github_id=?1 ORDER BY created_at DESC LIMIT 20",
        )?;
        Ok(statement
            .query_map([github_id], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?)
    }

    pub fn cleanup_expired_payloads(&self) -> ArenaResult<usize> {
        let now = now_unix();
        let connection = self.lock()?;
        let mut changed = connection.execute(
            "UPDATE submissions SET public_challenge_json=NULL,compile_output=NULL,stdout=NULL,stderr=NULL
             WHERE result_expires_at IS NOT NULL AND result_expires_at<?1",
            [now],
        )?;
        changed += connection.execute(
            "DELETE FROM challenge_lifecycle WHERE expires_at<?1 AND
             (submission_id IS NULL OR submission_id IN (
                SELECT id FROM submissions WHERE status IN
                ('COMPILE_ERROR','RUNTIME_ERROR','TIMED_OUT','OUTPUT_LIMIT_EXCEEDED','INVALID_OUTPUT',
                 'CHALLENGE_EXPIRED','WRONG_ANSWER','PASSED','CORRECT_BUT_LOST_RACE','ARENA_CLOSED','INTERNAL_ERROR')
             ))",
            [now - 3600],
        )?;
        changed += connection.execute(
            "UPDATE submissions SET source=NULL WHERE status='PASSED' AND finished_at<?1
             AND EXISTS(SELECT 1 FROM outbox WHERE outbox.submission_id=submissions.id AND status='TERMINAL_ERROR')",
            [now - 30 * 86400],
        )?;
        changed += connection.execute("DELETE FROM auth_sessions WHERE expires_at<?1", [now])?;
        changed += connection.execute("DELETE FROM oauth_states WHERE expires_at<?1", [now])?;
        Ok(changed)
    }

    pub fn claim_issue_work(&self) -> ArenaResult<Option<IssueWork>> {
        let now = now_unix();
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate: Option<String> = tx
            .query_row(
                "SELECT id FROM outbox WHERE
             (status IN ('PENDING','RETRYABLE_ERROR') AND next_attempt_at<=?1)
             OR (status='CREATING' AND next_attempt_at<=?1)
             ORDER BY next_attempt_at LIMIT 1",
                [now],
                |row| row.get(0),
            )
            .optional()?;
        let Some(event_id) = candidate else {
            return Ok(None);
        };
        let changed = tx.execute(
            "UPDATE outbox SET status='CREATING',attempt_count=attempt_count+1,next_attempt_at=?2
             WHERE id=?1 AND status IN ('PENDING','RETRYABLE_ERROR','CREATING')",
            params![event_id, now + 300],
        )?;
        if changed != 1 {
            return Ok(None);
        }
        let work = tx.query_row(
            "SELECT o.id,o.attempt_count,r.id,r.epoch,r.sdk_version,r.sdk_commit,r.generator_version,
                    s.id,u.github_login,s.language,s.source,s.source_sha256,s.compile_ms,s.run_ms,s.runner_image_digest
             FROM outbox o JOIN arena_rounds r ON r.id=o.round_id
             JOIN submissions s ON s.id=o.submission_id JOIN users u ON u.github_id=s.github_id
             WHERE o.id=?1 AND o.event_type='CREATE_WINNER_ISSUE'",
            [&event_id],
            |row| Ok(IssueWork {
                event_id: row.get(0)?, attempt_count: row.get(1)?, round_id: row.get(2)?, epoch: row.get(3)?,
                sdk_version: row.get(4)?, sdk_commit: row.get(5)?, generator_version: row.get(6)?,
                submission_id: row.get(7)?, github_login: row.get(8)?, language: row.get(9)?,
                source: row.get(10)?, source_sha256: row.get(11)?, compile_ms: row.get(12)?,
                run_ms: row.get(13)?, runner_image_digest: row.get(14)?,
            }),
        )?;
        tx.commit()?;
        Ok(Some(work))
    }

    pub fn recover_stale_work(&self) -> ArenaResult<Vec<(String, String)>> {
        let now = now_unix();
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE submissions SET status='ACCEPTED',worker_id=NULL,lease_id=NULL,lease_expires_at=NULL,
             heartbeat_at=NULL WHERE status IN ('COMPILING','READY') AND lease_expires_at<?1 AND source IS NOT NULL",
            [now],
        )?;
        tx.execute(
            "UPDATE submissions SET status='INTERNAL_ERROR',source=NULL,finished_at=?1,result_expires_at=?2,
             verification_disposition='worker_lease_expired' WHERE status IN ('CHALLENGE_ISSUED','RUNNING','VERIFYING')
             AND lease_expires_at<?1",
            params![now, now + 86400],
        )?;
        let mut statement = tx.prepare(
            "SELECT id,lease_id FROM submissions
             WHERE status='VERIFIED_ACCEPTED_PENDING_FINALIZE' AND lease_id IS NOT NULL",
        )?;
        let pending = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<(String, String)>, _>>()?;
        drop(statement);
        tx.commit()?;
        Ok(pending)
    }

    pub fn complete_issue(
        &self,
        event_id: &str,
        issue_number: i64,
        issue_url: &str,
    ) -> ArenaResult<()> {
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let submission_id: String = tx.query_row(
            "SELECT submission_id FROM outbox WHERE id=?1 AND status='CREATING'",
            [event_id],
            |row| row.get(0),
        )?;
        tx.execute(
            "UPDATE outbox SET status='CREATED',issue_number=?2,issue_url=?3,last_error_code=NULL
             WHERE id=?1 AND status='CREATING'",
            params![event_id, issue_number, issue_url],
        )?;
        tx.execute(
            "UPDATE submissions SET source=NULL WHERE id=?1 AND status='PASSED'",
            [submission_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn fail_issue(
        &self,
        event_id: &str,
        attempt_count: i64,
        error_code: &str,
    ) -> ArenaResult<()> {
        let now = now_unix();
        let (status, next) = if attempt_count >= 10 {
            ("TERMINAL_ERROR", now)
        } else {
            let delay = (30_i64 * (1_i64 << attempt_count.min(8))).min(3600);
            ("RETRYABLE_ERROR", now + delay)
        };
        self.lock()?.execute(
            "UPDATE outbox SET status=?2,next_attempt_at=?3,last_error_code=?4 WHERE id=?1 AND status='CREATING'",
            params![event_id, status, next, error_code],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_arena() -> (Database, User, Round) {
        let database = Database::open_in_memory().unwrap();
        let token = database.create_login_session(42, "octocat", 3600).unwrap();
        let user = database.authenticate(&token).unwrap();
        let round = database
            .create_round("0.1.0", "abc123", "1.0", "manifest-sha")
            .unwrap();
        database.open_round(&round.id, "test").unwrap();
        (database, user, round)
    }

    #[test]
    fn idempotency_does_not_charge_twice() {
        let (database, user, round) = open_arena();
        let first = database
            .accept_submission(
                &user,
                round.epoch,
                Language::Python,
                "print('x')",
                "request-key-1",
                20,
                "image",
                "policy",
            )
            .unwrap();
        let second = database
            .accept_submission(
                &user,
                round.epoch,
                Language::Python,
                "different",
                "request-key-1",
                20,
                "image",
                "policy",
            )
            .unwrap();
        assert!(first.created);
        assert!(!second.created);
        assert_eq!(first.id, second.id);
        assert_eq!(second.quota.used_today, 1);
    }

    #[test]
    fn compile_failure_removes_source_but_keeps_hash() {
        let (database, user, round) = open_arena();
        let accepted = database
            .accept_submission(
                &user,
                round.epoch,
                Language::Rust,
                "not rust",
                "request-key-2",
                20,
                "image",
                "policy",
            )
            .unwrap();
        let claimed = database.claim_next("worker", 30).unwrap().unwrap();
        database
            .record_compile(
                &claimed.id,
                &claimed.lease_id,
                &CompileResult {
                    success: false,
                    artifact_id: None,
                    duration_ms: 4,
                    output: "syntax error".into(),
                    output_truncated: false,
                    image_digest: "image@sha256:abc".into(),
                },
            )
            .unwrap();
        let connection = database.lock().unwrap();
        let (source, hash, status): (Option<String>, String, String) = connection
            .query_row(
                "SELECT source,source_sha256,status FROM submissions WHERE id=?1",
                [&accepted.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(source.is_none());
        assert_eq!(hash, sha256_hex(b"not rust"));
        assert_eq!(status, "COMPILE_ERROR");
    }

    #[test]
    fn quota_rejects_eleventh_accepted_run() {
        let (database, user, round) = open_arena();
        for index in 0..DAILY_LIMIT {
            let accepted = database
                .accept_submission(
                    &user,
                    round.epoch,
                    Language::Go,
                    "package main",
                    &format!("request-key-{index:02}"),
                    20,
                    "image",
                    "policy",
                )
                .unwrap();
            let connection = database.lock().unwrap();
            connection
                .execute(
                    "UPDATE submissions SET status='COMPILE_ERROR',source=NULL WHERE id=?1",
                    [&accepted.id],
                )
                .unwrap();
        }
        assert!(matches!(
            database.accept_submission(
                &user,
                round.epoch,
                Language::Go,
                "package main",
                "request-key-11",
                20,
                "image",
                "policy",
            ),
            Err(ArenaError::QuotaExhausted)
        ));
    }

    #[test]
    fn oauth_state_can_only_be_consumed_once() {
        let database = Database::open_in_memory().unwrap();
        database
            .store_oauth_state("state", now_unix() + 10)
            .unwrap();
        database.consume_oauth_state("state").unwrap();
        assert!(matches!(
            database.consume_oauth_state("state"),
            Err(ArenaError::Unauthorized)
        ));
    }

    #[test]
    fn concurrent_acceptance_allows_only_one_inflight_submission() {
        let (database, user, round) = open_arena();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for index in 0..2 {
            let database = database.clone();
            let user = user.clone();
            let round = round.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                database.accept_submission(
                    &user,
                    round.epoch,
                    Language::Python,
                    "pass",
                    &format!("parallel-key-{index}"),
                    20,
                    "image",
                    "policy",
                )
            }));
        }
        barrier.wait();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ArenaError::SubmissionInFlight(_))))
                .count(),
            1
        );
        assert_eq!(database.quota_for(user.github_id).unwrap().used_today, 1);
    }

    #[test]
    fn winner_finalization_closes_round_and_writes_one_outbox_event() {
        let (database, first_user, round) = open_arena();
        let second_token = database.create_login_session(43, "hubot", 3600).unwrap();
        let second_user = database.authenticate(&second_token).unwrap();
        let first = database
            .accept_submission(
                &first_user,
                round.epoch,
                Language::Python,
                "first",
                "winner-key-1",
                20,
                "image",
                "policy",
            )
            .unwrap();
        let second = database
            .accept_submission(
                &second_user,
                round.epoch,
                Language::Python,
                "second",
                "winner-key-2",
                20,
                "image",
                "policy",
            )
            .unwrap();
        {
            let connection = database.lock().unwrap();
            for (challenge_id, submission_id) in
                [("challenge-1", &first.id), ("challenge-2", &second.id)]
            {
                connection.execute(
                    "INSERT INTO challenge_lifecycle
                     (challenge_id,submission_id,private_material_json,binding,nonce,state,attempts_remaining,
                      outcome,issued_at,expires_at,updated_at)
                     VALUES (?1,?2,'{}',X'01','nonce','ACCEPTED',0,'accepted',1,2,2)",
                    params![challenge_id, submission_id],
                ).unwrap();
            }
            connection.execute(
                "UPDATE submissions SET status='VERIFIED_ACCEPTED_PENDING_FINALIZE',lease_id='lease-1' WHERE id=?1",
                [&first.id],
            ).unwrap();
            connection.execute(
                "UPDATE submissions SET status='VERIFIED_ACCEPTED_PENDING_FINALIZE',lease_id='lease-2' WHERE id=?1",
                [&second.id],
            ).unwrap();
        }
        assert!(database.finalize_verified(&first.id, "lease-1").unwrap());
        assert!(!database.finalize_verified(&second.id, "lease-2").unwrap());
        let connection = database.lock().unwrap();
        let outbox_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))
            .unwrap();
        assert_eq!(outbox_count, 1);
        drop(connection);
        assert_eq!(
            database
                .arena_view(32 * 1024)
                .unwrap()
                .winner
                .unwrap()
                .github_login,
            "octocat"
        );
    }
}
