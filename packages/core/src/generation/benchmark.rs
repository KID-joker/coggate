use std::fmt;

use coggate_contracts::{AnswerEncoding, GENERATOR_VERSION_V1};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    DeterministicRandom, RenderMetadata, generate_candidate_with, retry_candidates_with_attempts,
};
use crate::canonicalize_answer;

const SEED_DOMAIN: &[u8] = b"coggate:benchmark-seed:v1";
const MAX_SEED_NAMESPACE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BenchmarkError {
    #[error("unsupported generator version")]
    UnsupportedGeneratorVersion,
    #[error("invalid benchmark seed namespace")]
    InvalidSeedNamespace,
    #[error("benchmark case generation failed")]
    GenerationFailed,
}

pub struct BenchmarkCase {
    question: String,
    metadata: RenderMetadata,
    oracle: BenchmarkOracle,
}

impl BenchmarkCase {
    pub fn question(&self) -> &str {
        &self.question
    }

    pub const fn metadata(&self) -> &RenderMetadata {
        &self.metadata
    }

    pub const fn oracle(&self) -> &BenchmarkOracle {
        &self.oracle
    }

    /// Exposes a zeroizing copy only for training a benchmark calibration set.
    /// This API is available only through the explicitly insecure benchmark feature.
    pub fn calibration_answer(&self) -> Zeroizing<String> {
        Zeroizing::new(self.oracle.answer.to_string())
    }
}

impl fmt::Debug for BenchmarkCase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BenchmarkCase")
            .field("question", &"[REDACTED]")
            .field("metadata", &self.metadata)
            .field("oracle", &self.oracle)
            .finish()
    }
}

pub struct BenchmarkOracle {
    answer: Zeroizing<String>,
}

impl BenchmarkOracle {
    pub fn matches(&self, candidate: &str) -> bool {
        let Ok(candidate) = canonicalize_answer(AnswerEncoding::Base64Url, candidate) else {
            return false;
        };
        let candidate = Zeroizing::new(candidate);
        bool::from(self.answer.as_bytes().ct_eq(candidate.as_bytes()))
    }
}

impl fmt::Debug for BenchmarkOracle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BenchmarkOracle")
            .field("answer", &"[REDACTED]")
            .finish()
    }
}

pub fn generate_benchmark_case(
    generator_version: &str,
    seed_namespace: &[u8],
    sample_index: u64,
) -> Result<BenchmarkCase, BenchmarkError> {
    if generator_version != GENERATOR_VERSION_V1 {
        return Err(BenchmarkError::UnsupportedGeneratorVersion);
    }

    let seed = derive_seed(seed_namespace, sample_index)?;
    let mut random = DeterministicRandom::new(seed);
    let (candidate, _) = retry_candidates_with_attempts(|| generate_candidate_with(&mut random))
        .map_err(|_| BenchmarkError::GenerationFailed)?;

    Ok(BenchmarkCase {
        question: candidate.question().to_owned(),
        metadata: candidate.render_metadata().clone(),
        oracle: BenchmarkOracle {
            answer: Zeroizing::new(candidate.answer().to_owned()),
        },
    })
}

fn derive_seed(namespace: &[u8], index: u64) -> Result<[u8; 32], BenchmarkError> {
    if namespace.is_empty() || namespace.len() > MAX_SEED_NAMESPACE_BYTES {
        return Err(BenchmarkError::InvalidSeedNamespace);
    }

    let mut hash = Sha256::new();
    hash.update(SEED_DOMAIN);
    hash.update(
        u64::try_from(namespace.len())
            .map_err(|_| BenchmarkError::InvalidSeedNamespace)?
            .to_be_bytes(),
    );
    hash.update(namespace);
    hash.update(index.to_be_bytes());
    Ok(hash.finalize().into())
}
