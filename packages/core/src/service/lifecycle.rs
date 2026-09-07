use agentgate_contracts::PrivateChallengeMaterial;

use super::{
    AttemptLimit, AttemptOutcome, BeginAttemptError, LifecycleAdapterError, PendingAttempt,
    SubmissionIdentity,
};

/// Durable, synchronous storage boundary for the one-shot challenge lifecycle.
///
/// Implementations provide the security properties that the SDK cannot infer
/// from an answer MAC alone:
///
/// - [`LifecycleAdapter::store_issued`] must durably create the private record,
///   binding, attempt budget, and initial `ISSUED` state before returning. It
///   must reject duplicate challenge IDs. A failure can be ambiguous, so the
///   service never retries the call automatically.
/// - [`LifecycleAdapter::begin_attempt`] must atomically locate the exact
///   challenge ID; require `ISSUED`; enforce expiry using `server_time`; compare
///   the binding and nonce exactly; require a remaining attempt; reserve that
///   attempt by transitioning it from `ISSUED` to `RESERVED`; and
///   return its private material and an opaque token. Concurrent and replayed
///   attempts must be rejected. Expiry must be persisted as terminal before
///   returning [`crate::LifecycleRejection::Expired`].
/// - A token dropped without [`LifecycleAdapter::finish_attempt`] is
///   fail-closed: its reserved attempt stays used and cannot be reopened.
///   `finish_attempt` must durably commit the terminal or remaining-attempt
///   transition before returning. The service returns an accepted outcome only
///   after an accepted transition commits successfully.
///
/// Implementations also own recovery, persistence, concurrency, rate limiting,
/// and any session policy. The associated token should not expose secrets in
/// its debug or error representations.
pub trait LifecycleAdapter {
    /// Opaque capability identifying one atomically reserved attempt.
    type AttemptToken;

    /// Durably stores a newly issued challenge and its exact binding.
    fn store_issued(
        &mut self,
        material: PrivateChallengeMaterial,
        binding: &[u8],
        attempt_limit: AttemptLimit,
    ) -> Result<(), LifecycleAdapterError>;

    /// Atomically validates lifecycle state and reserves one attempt.
    fn begin_attempt(
        &mut self,
        identity: SubmissionIdentity<'_>,
        binding: &[u8],
        server_time: i64,
    ) -> Result<PendingAttempt<Self::AttemptToken>, BeginAttemptError>;

    /// Durably records the result of a previously reserved attempt.
    fn finish_attempt(
        &mut self,
        token: Self::AttemptToken,
        outcome: AttemptOutcome,
    ) -> Result<(), LifecycleAdapterError>;
}
