use coggate_core::{
    ActiveMacKey, AttemptLimit, AttemptOutcome, BeginAttemptError, KeyProviderError,
    LifecycleAdapter, LifecycleAdapterError, LifecycleRejection, MacKey, MacKeyProvider,
    PendingAttempt, PrivateChallengeMaterial, SubmissionIdentity,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

use crate::{
    db::Database,
    util::{now_unix, random_token},
};

#[derive(Clone)]
pub struct StaticKeyring {
    active_id: String,
    keys: HashMap<String, Vec<u8>>,
}

impl StaticKeyring {
    pub fn new(active_id: String, key: Vec<u8>) -> Result<Self, KeyProviderError> {
        Self::from_keys(active_id.clone(), HashMap::from([(active_id, key)]))
    }

    pub fn from_keys(
        active_id: String,
        keys: HashMap<String, Vec<u8>>,
    ) -> Result<Self, KeyProviderError> {
        if active_id.is_empty() || !keys.contains_key(&active_id) || keys.is_empty() {
            return Err(KeyProviderError::InvalidMaterial);
        }
        for key in keys.values() {
            MacKey::new(key.clone())?;
        }
        Ok(Self { active_id, keys })
    }
}

impl MacKeyProvider for StaticKeyring {
    fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
        let key = self
            .keys
            .get(&self.active_id)
            .ok_or(KeyProviderError::NotFound)?
            .clone();
        ActiveMacKey::new(self.active_id.clone(), MacKey::new(key)?)
    }

    fn key_by_id(&mut self, key_id: &str) -> Result<MacKey, KeyProviderError> {
        let key = self
            .keys
            .get(key_id)
            .ok_or(KeyProviderError::NotFound)?
            .clone();
        MacKey::new(key)
    }
}

#[derive(Clone)]
pub struct SqliteLifecycle {
    database: Database,
}

impl SqliteLifecycle {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    fn submission_from_binding(binding: &[u8]) -> Option<String> {
        let value = std::str::from_utf8(binding).ok()?;
        let mut parts = value.split('|');
        if parts.next()? != "arena-v1" {
            return None;
        }
        parts.next()?;
        parts.next()?;
        let submission = parts.next()?;
        parts.next()?;
        if parts.next().is_some() || submission.is_empty() {
            return None;
        }
        Some(submission.to_owned())
    }
}

#[derive(Debug)]
pub struct SqliteAttemptToken {
    challenge_id: String,
    reservation_token: String,
}

impl LifecycleAdapter for SqliteLifecycle {
    type AttemptToken = SqliteAttemptToken;

    fn store_issued(
        &mut self,
        material: PrivateChallengeMaterial,
        binding: &[u8],
        attempt_limit: AttemptLimit,
    ) -> Result<(), LifecycleAdapterError> {
        let material_json =
            serde_json::to_string(&material).map_err(|_| LifecycleAdapterError::Internal)?;
        let attempts = match attempt_limit {
            AttemptLimit::One => 1,
            AttemptLimit::Two => 2,
        };
        let submission_id = Self::submission_from_binding(binding);
        let connection = self
            .database
            .lock()
            .map_err(|_| LifecycleAdapterError::Unavailable)?;
        connection.execute(
            "INSERT INTO challenge_lifecycle
             (challenge_id,submission_id,private_material_json,binding,nonce,state,attempts_remaining,
              issued_at,expires_at,updated_at)
             VALUES (?1,?2,?3,?4,?5,'ISSUED',?6,?7,?8,?9)",
            params![material.challenge_id, submission_id, material_json, binding, material.nonce,
                attempts, material.issued_at, material.expires_at, now_unix()],
        ).map_err(|error| if error.to_string().contains("UNIQUE") {
            LifecycleAdapterError::Conflict
        } else {
            LifecycleAdapterError::Unavailable
        })?;
        Ok(())
    }

    fn begin_attempt(
        &mut self,
        identity: SubmissionIdentity<'_>,
        binding: &[u8],
        server_time: i64,
    ) -> Result<PendingAttempt<Self::AttemptToken>, BeginAttemptError> {
        let mut connection = self
            .database
            .lock()
            .map_err(|_| BeginAttemptError::Adapter(LifecycleAdapterError::Unavailable))?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BeginAttemptError::Adapter(LifecycleAdapterError::Unavailable))?;
        let row: Option<(String, Vec<u8>, String, String, i64, i64)> = tx
            .query_row(
                "SELECT private_material_json,binding,nonce,state,attempts_remaining,expires_at
             FROM challenge_lifecycle WHERE challenge_id=?1",
                [identity.challenge_id()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| BeginAttemptError::Adapter(LifecycleAdapterError::Unavailable))?;
        let Some((material_json, stored_binding, nonce, state, attempts, expires_at)) = row else {
            return Err(LifecycleRejection::NotFound.into());
        };
        if server_time > expires_at {
            tx.execute(
                "UPDATE challenge_lifecycle SET state='EXPIRED',outcome='expired',updated_at=?2
                 WHERE challenge_id=?1 AND state='ISSUED'",
                params![identity.challenge_id(), server_time],
            )
            .map_err(|_| BeginAttemptError::Adapter(LifecycleAdapterError::Unavailable))?;
            tx.commit()
                .map_err(|_| BeginAttemptError::Adapter(LifecycleAdapterError::Unavailable))?;
            return Err(LifecycleRejection::Expired.into());
        }
        if state != "ISSUED" {
            return Err(LifecycleRejection::AlreadyConsumed.into());
        }
        if attempts <= 0 {
            return Err(LifecycleRejection::AttemptsExhausted.into());
        }
        if stored_binding.len() != binding.len() || stored_binding.ct_eq(binding).unwrap_u8() != 1 {
            return Err(LifecycleRejection::BindingMismatch.into());
        }
        if nonce.len() != identity.nonce().len()
            || nonce
                .as_bytes()
                .ct_eq(identity.nonce().as_bytes())
                .unwrap_u8()
                != 1
        {
            return Err(LifecycleRejection::NonceMismatch.into());
        }
        let reservation_token = random_token(24)
            .map_err(|_| BeginAttemptError::Adapter(LifecycleAdapterError::Internal))?;
        let changed = tx.execute(
            "UPDATE challenge_lifecycle SET state='RESERVED',attempts_remaining=attempts_remaining-1,
             reservation_token=?2,updated_at=?3 WHERE challenge_id=?1 AND state='ISSUED'",
            params![identity.challenge_id(), reservation_token, server_time],
        ).map_err(|_| BeginAttemptError::Adapter(LifecycleAdapterError::Unavailable))?;
        if changed != 1 {
            return Err(LifecycleRejection::AlreadyConsumed.into());
        }
        let material = serde_json::from_str(&material_json)
            .map_err(|_| BeginAttemptError::Adapter(LifecycleAdapterError::Internal))?;
        tx.commit()
            .map_err(|_| BeginAttemptError::Adapter(LifecycleAdapterError::Unavailable))?;
        Ok(PendingAttempt::new(
            SqliteAttemptToken {
                challenge_id: identity.challenge_id().to_owned(),
                reservation_token,
            },
            material,
        ))
    }

    fn finish_attempt(
        &mut self,
        token: Self::AttemptToken,
        outcome: AttemptOutcome,
    ) -> Result<(), LifecycleAdapterError> {
        let now = now_unix();
        let (state, disposition) = match outcome {
            AttemptOutcome::Accepted => ("ACCEPTED", "accepted"),
            AttemptOutcome::Rejected => ("REJECTED", "rejected"),
            AttemptOutcome::SystemFailure => ("SYSTEM_FAILURE", "system_failure"),
        };
        let mut connection = self
            .database
            .lock()
            .map_err(|_| LifecycleAdapterError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LifecycleAdapterError::Unavailable)?;
        let submission_id: Option<Option<String>> = tx
            .query_row(
                "SELECT submission_id FROM challenge_lifecycle
             WHERE challenge_id=?1 AND state='RESERVED' AND reservation_token=?2",
                params![token.challenge_id, token.reservation_token],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| LifecycleAdapterError::Unavailable)?;
        let Some(submission_id) = submission_id else {
            return Err(LifecycleAdapterError::Conflict);
        };
        let changed = tx.execute(
            "UPDATE challenge_lifecycle SET state=?3,outcome=?4,reservation_token=NULL,updated_at=?5
             WHERE challenge_id=?1 AND state='RESERVED' AND reservation_token=?2",
            params![token.challenge_id, token.reservation_token, state, disposition, now],
        ).map_err(|_| LifecycleAdapterError::Unavailable)?;
        if changed != 1 {
            return Err(LifecycleAdapterError::Conflict);
        }
        if outcome == AttemptOutcome::Accepted {
            let Some(submission_id) = submission_id else {
                return Err(LifecycleAdapterError::Internal);
            };
            let changed = tx
                .execute(
                    "UPDATE submissions SET status='VERIFIED_ACCEPTED_PENDING_FINALIZE',
                 verification_disposition='accepted',heartbeat_at=?2
                 WHERE id=?1 AND status='VERIFYING'",
                    params![submission_id, now],
                )
                .map_err(|_| LifecycleAdapterError::Unavailable)?;
            if changed != 1 {
                return Err(LifecycleAdapterError::Conflict);
            }
        }
        tx.commit()
            .map_err(|_| LifecycleAdapterError::Unavailable)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use coggate_core::{
        ChallengeService, IssueRequest, Submission, VerificationOutcome, VerifyRequest,
    };

    use super::*;

    #[test]
    fn sqlite_lifecycle_is_one_shot() {
        let database = Database::open_in_memory().unwrap();
        let mut service = ChallengeService::new(
            SqliteLifecycle::new(database),
            StaticKeyring::new("key-v1".into(), vec![7; 32]).unwrap(),
        );
        let binding = b"preview:round:1";
        let challenge = service
            .issue_challenge(IssueRequest::v1(binding).unwrap())
            .unwrap();
        let wrong = Submission {
            challenge_id: challenge.challenge_id,
            nonce: challenge.nonce,
            answer: "AA".into(),
        };
        let first = service.verify_submission(VerifyRequest::new(&wrong, binding).unwrap());
        assert!(first.is_err());
        let second = service
            .verify_submission(VerifyRequest::new(&wrong, binding).unwrap())
            .unwrap();
        assert!(matches!(
            second,
            VerificationOutcome::Rejected(LifecycleRejection::AlreadyConsumed)
        ));
    }

    #[test]
    fn keyring_reads_an_exact_retiring_key_without_fallback() {
        let mut keyring = StaticKeyring::from_keys(
            "new".into(),
            HashMap::from([("old".into(), vec![1; 32]), ("new".into(), vec![2; 32])]),
        )
        .unwrap();
        assert!(keyring.key_by_id("old").is_ok());
        assert_eq!(
            keyring.key_by_id("missing").unwrap_err(),
            KeyProviderError::NotFound
        );
    }
}
