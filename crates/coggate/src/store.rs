//! Atomic challenge lifecycle. Production adapters must preserve these semantics.
use coggate_core::PrivateChallenge;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    InvalidId,
    InvalidScope,
    NotFound,
    WrongScope,
    Expired,
    InFlight,
    Exhausted,
    StaleClaim,
    Capacity,
    Internal,
}

pub(crate) fn validate_lookup(scope: &str, id: &str) -> Result<(), StoreError> {
    if scope.is_empty() || scope.len() > coggate_core::MAX_SCOPE_BYTES {
        return Err(StoreError::InvalidScope);
    }
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(StoreError::InvalidId);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    Passed,
    Rejected,
    InternalError,
}

/// A lease token is internal server state; never return it to the client.
pub struct Claim {
    pub challenge: Arc<PrivateChallenge>,
    pub token: [u8; 16],
}

/// Implementations must atomically serialize claim/complete across all instances.
///
/// Claim consumes one attempt; InternalError refunds it, Rejected spends it, and
/// Passed permanently consumes the challenge. Every completion checks both lease
/// and expiration. There is no automatic lease stealing: crash recovery must
/// first guarantee the previous worker can no longer complete, or await expiry.
pub trait StateStore: Send + Sync {
    fn insert(&self, challenge: Arc<PrivateChallenge>, now: u64) -> Result<(), StoreError>;
    fn claim(&self, scope: &str, id: &str, now: u64) -> Result<Claim, StoreError>;
    fn complete(&self, claim: &Claim, outcome: Completion, now: u64) -> Result<(), StoreError>;
}

struct Entry {
    challenge: Arc<PrivateChallenge>,
    attempts: u8,
    lease: Option<[u8; 16]>,
    consumed: bool,
}

/// Single-process bounded storage; no external database required.
/// An application with multiple processes must supply a shared atomic adapter.
pub struct InMemoryStore {
    entries: Mutex<HashMap<String, Entry>>,
    capacity: usize,
}

impl InMemoryStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }
}

impl StateStore for InMemoryStore {
    fn insert(&self, challenge: Arc<PrivateChallenge>, now: u64) -> Result<(), StoreError> {
        if challenge.expires_at() <= now {
            return Err(StoreError::Expired);
        }
        let mut entries = self.entries.lock().map_err(|_| StoreError::Internal)?;
        entries.retain(|_, e| e.challenge.expires_at() > now);
        // Never overwrite a live challenge, including a consumed tombstone.
        if entries.contains_key(challenge.id()) {
            return Err(StoreError::Internal);
        }
        if entries.len() >= self.capacity {
            return Err(StoreError::Capacity);
        }
        entries.insert(
            challenge.id().to_owned(),
            Entry {
                challenge,
                attempts: 0,
                lease: None,
                consumed: false,
            },
        );
        Ok(())
    }

    fn claim(&self, scope: &str, id: &str, now: u64) -> Result<Claim, StoreError> {
        validate_lookup(scope, id)?;
        let mut token = [0; 16];
        getrandom::fill(&mut token).map_err(|_| StoreError::Internal)?;
        let mut entries = self.entries.lock().map_err(|_| StoreError::Internal)?;
        let entry = entries.get_mut(id).ok_or(StoreError::NotFound)?;
        if entry.challenge.scope() != scope {
            return Err(StoreError::WrongScope);
        }
        if entry.challenge.expires_at() <= now {
            return Err(StoreError::Expired);
        }
        if entry.consumed || entry.attempts >= entry.challenge.max_attempts() {
            return Err(StoreError::Exhausted);
        }
        if entry.lease.is_some() {
            return Err(StoreError::InFlight);
        }
        entry.attempts += 1;
        entry.lease = Some(token);
        Ok(Claim {
            challenge: Arc::clone(&entry.challenge),
            token,
        })
    }

    fn complete(&self, claim: &Claim, outcome: Completion, now: u64) -> Result<(), StoreError> {
        let mut entries = self.entries.lock().map_err(|_| StoreError::Internal)?;
        let entry = entries
            .get_mut(claim.challenge.id())
            .ok_or(StoreError::NotFound)?;
        if entry.lease != Some(claim.token) {
            return Err(StoreError::StaleClaim);
        }
        entry.lease = None;
        if entry.challenge.expires_at() <= now {
            entry.consumed = true;
            return Err(StoreError::Expired);
        }
        match outcome {
            Completion::Passed => entry.consumed = true,
            Completion::Rejected => {}
            Completion::InternalError => entry.attempts -= 1,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coggate_core::Engine;

    fn challenge() -> Arc<PrivateChallenge> {
        Arc::new(
            Engine::new([41; 32])
                .issue("tenant", b"factor", 1000)
                .unwrap()
                .1,
        )
    }

    #[test]
    fn concurrent_claims_have_exactly_one_winner() {
        let store = Arc::new(InMemoryStore::new(8));
        let challenge = challenge();
        let id = challenge.id().to_owned();
        store.insert(challenge, 1000).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let joins: Vec<_> = (0..8)
            .map(|_| {
                let (store, barrier, id) = (store.clone(), barrier.clone(), id.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    store.claim("tenant", &id, 1001).is_ok()
                })
            })
            .collect();
        assert_eq!(
            joins
                .into_iter()
                .filter_map(|j| j.join().ok())
                .filter(|won| *won)
                .count(),
            1
        );
    }

    #[test]
    fn two_rejections_exhaust_challenge_and_success_cannot_replay() {
        let store = InMemoryStore::new(8);
        let c = challenge();
        let id = c.id().to_owned();
        store.insert(c, 1000).unwrap();
        for _ in 0..2 {
            let claim = store.claim("tenant", &id, 1001).unwrap();
            store.complete(&claim, Completion::Rejected, 1002).unwrap();
            assert!(matches!(
                store.complete(&claim, Completion::Passed, 1002),
                Err(StoreError::StaleClaim)
            ));
        }
        assert!(matches!(
            store.claim("tenant", &id, 1003),
            Err(StoreError::Exhausted)
        ));

        let c = challenge();
        let id = c.id().to_owned();
        store.insert(c, 1000).unwrap();
        let claim = store.claim("tenant", &id, 1001).unwrap();
        store.complete(&claim, Completion::Passed, 1002).unwrap();
        assert!(matches!(
            store.claim("tenant", &id, 1003),
            Err(StoreError::Exhausted)
        ));
    }

    #[test]
    fn internal_failure_refunds_and_expiration_blocks_late_success() {
        let store = InMemoryStore::new(8);
        let c = challenge();
        let (id, expires) = (c.id().to_owned(), c.expires_at());
        store.insert(c, 1000).unwrap();
        assert!(matches!(
            store.claim("other", &id, 1001),
            Err(StoreError::WrongScope)
        ));
        for _ in 0..3 {
            let claim = store.claim("tenant", &id, 1001).unwrap();
            store
                .complete(&claim, Completion::InternalError, 1002)
                .unwrap();
        }
        let claim = store.claim("tenant", &id, expires - 1).unwrap();
        assert!(matches!(
            store.complete(&claim, Completion::Passed, expires),
            Err(StoreError::Expired)
        ));
    }

    #[test]
    fn capacity_is_bounded_and_expired_entries_are_reclaimed() {
        let store = InMemoryStore::new(1);
        store.insert(challenge(), 1000).unwrap();
        assert_eq!(store.insert(challenge(), 1000), Err(StoreError::Capacity));
        let later = Engine::new([7; 32]).issue("tenant", b"", 2000).unwrap().1;
        store.insert(Arc::new(later), 2000).unwrap();
    }

    #[test]
    fn invalid_lookup_is_rejected_before_lock_or_rng_work() {
        let store = InMemoryStore::new(1);
        assert!(matches!(
            store.claim("tenant", &"a".repeat(100_000), 0),
            Err(StoreError::InvalidId)
        ));
        assert!(matches!(
            store.claim("", &"a".repeat(64), 0),
            Err(StoreError::InvalidScope)
        ));
        assert!(matches!(
            store.claim("tenant", &"G".repeat(64), 0),
            Err(StoreError::InvalidId)
        ));
    }
}
