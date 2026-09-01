use agentgate_contracts::PrivateChallengeMaterial;

use super::{
    AttemptLimit, AttemptOutcome, BeginAttemptError, LifecycleAdapterError, PendingAttempt,
    SubmissionIdentity,
};

pub trait LifecycleAdapter {
    type AttemptToken;

    fn store_issued(
        &mut self,
        material: PrivateChallengeMaterial,
        binding: &[u8],
        attempt_limit: AttemptLimit,
    ) -> Result<(), LifecycleAdapterError>;

    fn begin_attempt(
        &mut self,
        identity: SubmissionIdentity<'_>,
        binding: &[u8],
        server_time: i64,
    ) -> Result<PendingAttempt<Self::AttemptToken>, BeginAttemptError>;

    fn finish_attempt(
        &mut self,
        token: Self::AttemptToken,
        outcome: AttemptOutcome,
    ) -> Result<(), LifecycleAdapterError>;
}
