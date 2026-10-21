//! Experimental server-side programming challenges.
//!
//! A successful result demonstrates that submitted code passed finite tests. It
//! is not evidence that a model was called. Access tokens remain the host's job.
pub mod runtime;
pub mod store;

pub use coggate_core::{Engine, PublicChallenge};
pub use runtime::{Runtime, Verdict};
pub use store::{InMemoryStore, StateStore, StoreError};

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum Error {
    Core(coggate_core::Error),
    Store(StoreError),
    Clock,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// The store must be shared by all gateways that accept a given challenge.
/// The worker path is trusted deployment configuration, never request input.
pub struct Gate<S: StateStore> {
    engine: Engine,
    store: S,
    runtime: Runtime,
}

impl<S: StateStore> Gate<S> {
    pub fn new(engine: Engine, store: S, runtime: Runtime) -> Self {
        Self {
            engine,
            store,
            runtime,
        }
    }

    /// `scope` must come from trusted host routing/authentication.
    pub fn issue(&self, scope: &str, factor: &[u8]) -> Result<PublicChallenge, Error> {
        let now = unix_now()?;
        let (public, private) = self.engine.issue(scope, factor, now).map_err(Error::Core)?;
        self.store
            .insert(Arc::new(private), now)
            .map_err(Error::Store)?;
        Ok(public)
    }

    pub fn verify(&self, scope: &str, id: &str, source: &str) -> Result<Verdict, Error> {
        store::validate_lookup(scope, id).map_err(Error::Store)?;
        // Reject oversized input before consuming challenge state or spawning.
        if source.len() > runtime::MAX_SOURCE {
            return Ok(Verdict::InvalidSubmission);
        }
        // Capacity is reserved before claiming; busy requests do not spend tries.
        let Some(permit) = self.runtime.reserve() else {
            return Ok(Verdict::Busy);
        };
        let claim = self
            .store
            .claim(scope, id, unix_now()?)
            .map_err(Error::Store)?;
        let verdict = self
            .runtime
            .execute_reserved(&claim.challenge, source, permit);
        let outcome = match verdict {
            Verdict::Passed => store::Completion::Passed,
            Verdict::InternalError | Verdict::Unsupported | Verdict::Busy => {
                store::Completion::InternalError
            }
            _ => store::Completion::Rejected,
        };
        // Completing an expired challenge must never produce an accepted result.
        self.store
            .complete(&claim, outcome, unix_now()?)
            .map_err(Error::Store)?;
        Ok(verdict)
    }
}

fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Clock)
}
