//! Experimental server-side programming challenges.
//!
//! Passing a challenge demonstrates a correct program, not the use of a model.
//! The ten task families are deliberately a measurable baseline. A specialized
//! solver can parse their public descriptions; secret derivation prevents advance
//! prediction but does not hide the rules required to solve a public challenge.
//!
//! Keep [`Engine`], [`PrivateChallenge`], and expected results in the trusted host.
//! Pass only source and test inputs to an isolated execution worker. The core
//! does not implement a sandbox, persistent state, attempt accounting, or tokens.

/// Experimental composition generator; excluded from default production builds.
#[cfg(feature = "dev-tools")]
pub mod composition;
#[cfg(feature = "dev-tools")]
pub use composition::screening::ScreeningStats;
mod task;

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::fmt;
use task::{RandomStream, Task};

pub const MAX_SCOPE_BYTES: usize = 128;
pub const MAX_CONTEXT_FACTOR_BYTES: usize = 1_024;
pub const MAX_INPUT_LEN: usize = 64;
pub const MAX_INPUT_ABS: i64 = 10_000;
pub const HIDDEN_TEST_COUNT: usize = 32;
pub const CHALLENGE_TTL_SECS: u64 = 180;
pub const MAX_ATTEMPTS: u8 = 2;

type HmacSha256 = Hmac<Sha256>;

/// Safe to transmit to the solver. Contains no private test or generation seed.
#[derive(Clone, Debug, Serialize)]
pub struct PublicChallenge {
    pub id: String,
    pub scope: String,
    pub expires_at: u64,
    pub max_attempts: u8,
    pub prompt: String,
}

/// Private judging state, deliberately neither serializable nor `Debug`.
///
/// Store the resolved state at issuance time. Do not regenerate from a mutable
/// business factor at verification time. An external store must enforce scope,
/// expiry, atomic attempt claims, and one-time success consumption.
pub struct PrivateChallenge {
    id: String,
    scope: String,
    expires_at: u64,
    cases: Vec<TestCase>,
    #[cfg(any(test, feature = "dev-tools"))]
    reference: Reference,
}

#[cfg(any(test, feature = "dev-tools"))]
enum Reference {
    Baseline(Task),
    #[cfg(feature = "dev-tools")]
    Composition(String),
}

impl PrivateChallenge {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn max_attempts(&self) -> u8 {
        MAX_ATTEMPTS
    }

    /// Trusted-host API: expected values must never enter untrusted workers.
    pub fn cases(&self) -> &[TestCase] {
        &self.cases
    }

    /// Development only: a reference implementation for measuring the runner.
    ///
    /// Never enable this feature or return this source in a production endpoint.
    #[cfg(any(test, feature = "dev-tools"))]
    pub fn reference_solution(&self) -> String {
        match &self.reference {
            Reference::Baseline(task) => task.reference_solution(),
            #[cfg(feature = "dev-tools")]
            Reference::Composition(source) => source.clone(),
        }
    }
}

/// A private test case. Only `input()` may be sent to an execution worker.
pub struct TestCase {
    input: Vec<i64>,
    expected: serde_json::Value,
}

impl TestCase {
    pub fn input(&self) -> &[i64] {
        &self.input
    }

    /// Read or compare this value in the trusted host, outside the worker.
    pub fn expected(&self) -> &serde_json::Value {
        &self.expected
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidScope,
    ContextFactorTooLarge,
    TimeOverflow,
    RandomnessUnavailable,
    #[cfg(feature = "dev-tools")]
    GenerationExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidScope => "scope must contain 1 to 128 UTF-8 bytes",
            Self::ContextFactorTooLarge => "context factor exceeds 1024 bytes",
            Self::TimeOverflow => "challenge expiry overflows the clock range",
            Self::RandomnessUnavailable => "operating-system randomness unavailable",
            #[cfg(feature = "dev-tools")]
            Self::GenerationExhausted => "screened generation exhausted its candidate budget",
        };
        f.write_str(message)
    }
}

impl std::error::Error for Error {}

/// A server-only keyed challenge generator. Intentionally does not implement
/// `Debug`, `Clone`, or serialization.
pub struct Engine {
    key: [u8; 32],
}

impl Engine {
    /// `key` must be independently generated with a cryptographically secure
    /// random source and retained only by the server. The API cannot determine
    /// whether caller-supplied bytes have sufficient entropy. A user ID, password,
    /// timestamp, or public factor is not a suitable key.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Issue a fresh challenge using OS randomness and the supplied server clock.
    ///
    /// `context_factor` is optional (`&[]`) and may be public. It changes the
    /// resolved task without replacing the secret key or the fresh nonce. Raw
    /// factor bytes are never included in the public challenge or private tests.
    pub fn issue(
        &self,
        scope: &str,
        context_factor: &[u8],
        now_secs: u64,
    ) -> Result<(PublicChallenge, PrivateChallenge), Error> {
        validate_request(scope, context_factor, now_secs)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;
        self.issue_with_nonce(scope, context_factor, now_secs, nonce)
    }

    fn issue_with_nonce(
        &self,
        scope: &str,
        context_factor: &[u8],
        now_secs: u64,
        nonce: [u8; 32],
    ) -> Result<(PublicChallenge, PrivateChallenge), Error> {
        let expires_at = validate_request(scope, context_factor, now_secs)?;
        let derive =
            |label: &[u8]| derive_seed(&self.key, label, scope.as_bytes(), context_factor, &nonce);
        let mut problem_random = RandomStream::new(derive(b"problem"));
        let mut wording_random = RandomStream::new(derive(b"wording"));
        let mut test_random = RandomStream::new(derive(b"tests"));
        let task = Task::generate(&mut problem_random);
        let id = hex(&derive(b"id"));
        let prompt = task.prompt(wording_random.below(4) as usize);
        let cases = task
            .test_inputs(&mut test_random)
            .into_iter()
            .map(|input| {
                let expected = task.evaluate(&input);
                TestCase { input, expected }
            })
            .collect();
        let public = PublicChallenge {
            id: id.clone(),
            scope: scope.to_owned(),
            expires_at,
            max_attempts: MAX_ATTEMPTS,
            prompt,
        };
        let private = PrivateChallenge {
            id,
            scope: scope.to_owned(),
            expires_at,
            cases,
            #[cfg(any(test, feature = "dev-tools"))]
            reference: Reference::Baseline(task),
        };
        Ok((public, private))
    }
}

fn validate_request(scope: &str, factor: &[u8], now_secs: u64) -> Result<u64, Error> {
    if scope.is_empty() || scope.len() > MAX_SCOPE_BYTES {
        return Err(Error::InvalidScope);
    }
    if factor.len() > MAX_CONTEXT_FACTOR_BYTES {
        return Err(Error::ContextFactorTooLarge);
    }
    now_secs
        .checked_add(CHALLENGE_TTL_SECS)
        .ok_or(Error::TimeOverflow)
}

/// A versioned HMAC input with explicit lengths on every variable field. This
/// avoids concatenation ambiguity and domain-separates problem, wording, tests,
/// and public challenge ID. The nonce is a fixed-width final field.
fn derive_seed(
    key: &[u8; 32],
    label: &[u8],
    scope: &[u8],
    factor: &[u8],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(b"coggate/challenge/v1\0");
    for field in [label, scope, factor] {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field);
    }
    mac.update(nonce);
    mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        Engine::new([73; 32])
    }

    #[test]
    fn seed_domains_and_length_encoding_are_distinct() {
        let key = [73; 32];
        let nonce = [19; 32];
        let seeds: Vec<_> = [b"problem".as_slice(), b"wording", b"tests", b"id"]
            .map(|label| derive_seed(&key, label, b"scope", b"factor", &nonce))
            .into_iter()
            .collect();
        for (index, seed) in seeds.iter().enumerate() {
            assert!(seeds[index + 1..].iter().all(|other| seed != other));
        }
        assert_ne!(
            derive_seed(&key, b"problem", b"a", b"bc", &nonce),
            derive_seed(&key, b"problem", b"ab", b"c", &nonce),
        );
        assert_ne!(
            derive_seed(&key, b"a", b"bc", b"d", &nonce),
            derive_seed(&key, b"ab", b"c", b"d", &nonce),
        );
    }

    #[test]
    fn factor_scope_key_and_nonce_influence_generation() {
        let baseline = derive_seed(&[73; 32], b"problem", b"s", b"f", &[19; 32]);
        for changed in [
            derive_seed(&[74; 32], b"problem", b"s", b"f", &[19; 32]),
            derive_seed(&[73; 32], b"problem", b"t", b"f", &[19; 32]),
            derive_seed(&[73; 32], b"problem", b"s", b"g", &[19; 32]),
            derive_seed(&[73; 32], b"problem", b"s", b"f", &[20; 32]),
        ] {
            assert_ne!(baseline, changed);
        }
        let (a, private_a) = engine().issue_with_nonce("s", b"f", 100, [19; 32]).unwrap();
        let (b, private_b) = engine().issue_with_nonce("s", b"f", 100, [19; 32]).unwrap();
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.id, b.id);
        assert_eq!(
            private_a.reference_solution(),
            private_b.reference_solution()
        );
        for (left, right) in private_a.cases().iter().zip(private_b.cases()) {
            assert_eq!(left.input(), right.input());
            assert_eq!(left.expected(), right.expected());
        }
        let (changed, _) = engine().issue_with_nonce("s", b"g", 100, [19; 32]).unwrap();
        assert_ne!(a.id, changed.id);
        assert_ne!(a.prompt, changed.prompt);
        let (changed_nonce, _) = engine().issue_with_nonce("s", b"f", 100, [20; 32]).unwrap();
        assert_ne!(a.id, changed_nonce.id);
    }

    #[test]
    fn fresh_challenges_do_not_reuse_ids_or_test_suites() {
        let (_, a) = engine().issue("gateway", b"same context", 100).unwrap();
        let (_, b) = engine().issue("gateway", b"same context", 100).unwrap();
        assert_ne!(a.id(), b.id());
        assert!(a
            .cases()
            .iter()
            .zip(b.cases())
            .any(|(left, right)| left.input() != right.input()));
    }

    #[test]
    fn public_boundary_exposes_only_intended_fields() {
        let factor = b"private-business-context-do-not-publish";
        let (public, private) = engine().issue("gateway", factor, 100).unwrap();
        let value = serde_json::to_value(&public).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert_eq!(value["expires_at"], 280);
        assert_eq!(value["max_attempts"], 2);
        assert_eq!(public.id, private.id());
        assert_eq!(public.scope, private.scope());
        let encoded = value.to_string();
        assert!(!encoded.contains(std::str::from_utf8(factor).unwrap()));
        assert!(!encoded.contains("expected"));
        assert!(!encoded.contains("seed"));
        assert!(public.prompt.contains("function solve(input)"));
        assert!(public.prompt.contains("10000"));
    }

    #[test]
    fn request_limits_fail_before_randomness_or_generation() {
        let generate = |scope: &str, factor: &[u8], time| {
            engine()
                .issue_with_nonce(scope, factor, time, [0; 32])
                .err()
        };
        assert_eq!(generate("", &[], 0), Some(Error::InvalidScope));
        assert_eq!(
            generate(&"a".repeat(MAX_SCOPE_BYTES + 1), &[], 0),
            Some(Error::InvalidScope)
        );
        assert_eq!(
            generate("ok", &[0; MAX_CONTEXT_FACTOR_BYTES + 1], 0),
            Some(Error::ContextFactorTooLarge)
        );
        assert_eq!(generate("ok", &[], u64::MAX), Some(Error::TimeOverflow));
        assert!(engine()
            .issue_with_nonce(
                &"a".repeat(MAX_SCOPE_BYTES),
                &[0; MAX_CONTEXT_FACTOR_BYTES],
                u64::MAX - CHALLENGE_TTL_SECS,
                [0; 32]
            )
            .is_ok());
    }
}
