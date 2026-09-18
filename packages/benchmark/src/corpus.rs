use std::{collections::BTreeSet, fmt};

use coggate_core::generation::{
    BenchmarkCase, BenchmarkError, RenderMetadata, generate_benchmark_case,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::manifest::{ProfileName, SuiteManifest};

const CASE_DOMAIN: &[u8] = b"coggate:benchmark-case:v1";
const QUESTION_DOMAIN: &[u8] = b"coggate:question:v1";

pub struct CorpusCase {
    id: String,
    question_digest: String,
    benchmark: BenchmarkCase,
}

impl CorpusCase {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn question(&self) -> &str {
        self.benchmark.question()
    }

    pub fn question_digest(&self) -> &str {
        &self.question_digest
    }

    pub const fn metadata(&self) -> &RenderMetadata {
        self.benchmark.metadata()
    }

    pub fn oracle_matches(&self, candidate: &str) -> bool {
        self.benchmark.oracle().matches(candidate)
    }

    pub(crate) fn calibration_answer(&self) -> Zeroizing<String> {
        self.benchmark.calibration_answer()
    }
}

impl fmt::Debug for CorpusCase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CorpusCase")
            .field("id", &self.id)
            .field("question_digest", &self.question_digest)
            .field("question", &"[REDACTED]")
            .field("metadata", self.metadata())
            .finish()
    }
}

pub struct Corpus {
    calibration: Vec<CorpusCase>,
    scored: Vec<CorpusCase>,
}

impl Corpus {
    pub fn generate(suite: &SuiteManifest, profile_name: ProfileName) -> Result<Self, CorpusError> {
        let profile = suite
            .profile(profile_name)
            .ok_or(CorpusError::MissingProfile)?;
        let calibration = generate_role(
            suite,
            b"calibration",
            profile.calibration_namespace(),
            profile.calibration_cases(),
        )?;
        let scored = generate_role(
            suite,
            b"scored",
            profile.scored_namespace(),
            profile.scored_cases(),
        )?;

        let mut ids = BTreeSet::new();
        for case in calibration.iter().chain(&scored) {
            if !ids.insert(case.id.clone()) {
                return Err(CorpusError::DuplicateCaseId);
            }
        }

        Ok(Self {
            calibration,
            scored,
        })
    }

    pub fn calibration(&self) -> &[CorpusCase] {
        &self.calibration
    }

    pub fn scored(&self) -> &[CorpusCase] {
        &self.scored
    }

    pub fn public_fingerprints(&self) -> CorpusFingerprint {
        CorpusFingerprint {
            calibration: fingerprints(&self.calibration),
            scored: fingerprints(&self.scored),
        }
    }
}

impl fmt::Debug for Corpus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Corpus")
            .field("calibration_cases", &self.calibration.len())
            .field("scored_cases", &self.scored.len())
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CorpusFingerprint {
    calibration: Vec<CaseFingerprint>,
    scored: Vec<CaseFingerprint>,
}

#[derive(Debug, Eq, PartialEq)]
struct CaseFingerprint {
    id: String,
    question_digest: String,
}

fn fingerprints(cases: &[CorpusCase]) -> Vec<CaseFingerprint> {
    cases
        .iter()
        .map(|case| CaseFingerprint {
            id: case.id.clone(),
            question_digest: case.question_digest.clone(),
        })
        .collect()
}

fn generate_role(
    suite: &SuiteManifest,
    role: &[u8],
    namespace: &str,
    count: usize,
) -> Result<Vec<CorpusCase>, CorpusError> {
    (0..count)
        .map(|index| {
            let index = u64::try_from(index).map_err(|_| CorpusError::InvalidIndex)?;
            let benchmark =
                generate_benchmark_case(suite.generator_version(), namespace.as_bytes(), index)?;
            let id = case_id(suite.digest(), role, namespace, index)?;
            let question_digest = question_digest(benchmark.question())?;
            Ok(CorpusCase {
                id,
                question_digest,
                benchmark,
            })
        })
        .collect()
}

fn case_id(
    manifest_digest: &str,
    role: &[u8],
    namespace: &str,
    index: u64,
) -> Result<String, CorpusError> {
    let mut hash = Sha256::new();
    hash.update(CASE_DOMAIN);
    push_field(&mut hash, manifest_digest.as_bytes())?;
    push_field(&mut hash, role)?;
    push_field(&mut hash, namespace.as_bytes())?;
    hash.update(index.to_be_bytes());
    Ok(hex::encode(hash.finalize()))
}

pub(crate) fn scored_case_id(
    suite: &SuiteManifest,
    profile_name: ProfileName,
    index: usize,
) -> Result<String, CorpusError> {
    let profile = suite
        .profile(profile_name)
        .ok_or(CorpusError::MissingProfile)?;
    let index = u64::try_from(index).map_err(|_| CorpusError::InvalidIndex)?;
    case_id(suite.digest(), b"scored", profile.scored_namespace(), index)
}

fn question_digest(question: &str) -> Result<String, CorpusError> {
    let mut hash = Sha256::new();
    hash.update(QUESTION_DOMAIN);
    push_field(&mut hash, question.as_bytes())?;
    Ok(hex::encode(hash.finalize()))
}

fn push_field(hash: &mut Sha256, value: &[u8]) -> Result<(), CorpusError> {
    hash.update(
        u64::try_from(value.len())
            .map_err(|_| CorpusError::LengthOverflow)?
            .to_be_bytes(),
    );
    hash.update(value);
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    #[error("benchmark profile is missing")]
    MissingProfile,
    #[error("benchmark sample index is invalid")]
    InvalidIndex,
    #[error("benchmark field length overflow")]
    LengthOverflow,
    #[error("duplicate benchmark case ID")]
    DuplicateCaseId,
    #[error("benchmark case generation failed")]
    Benchmark(#[from] BenchmarkError),
}
