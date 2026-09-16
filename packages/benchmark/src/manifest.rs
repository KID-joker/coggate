use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const TRACKED_V1: &str = include_str!("../../../benchmarks/suites/v1.json");
const MANIFEST_DOMAIN: &[u8] = b"agentgate-suite-manifest-v1";
const REQUIRED_PROFILES: [&str; 2] = ["quick", "release"];
const REQUIRED_THRESHOLDS: [&str; 5] = ["direct", "fingerprint", "llm", "regex", "simple_parser"];
const REQUIRED_BASELINES: [&str; 4] = ["direct", "fingerprint", "regex", "simple_parser"];
const REQUIRED_TOOLS: [&str; 5] = ["c", "cpp", "go", "java", "rust"];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProfileName {
    Quick,
    Release,
}

impl ProfileName {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Release => "release",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    AtMost,
    AtLeast,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Threshold {
    comparison: Comparison,
    percent: u8,
}

impl Threshold {
    pub const fn comparison(self) -> Comparison {
        self.comparison
    }

    pub const fn percent(self) -> u8 {
        self.percent
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    scored_cases: usize,
    calibration_cases: usize,
    scored_namespace: String,
    calibration_namespace: String,
}

impl Profile {
    pub const fn scored_cases(&self) -> usize {
        self.scored_cases
    }

    pub const fn calibration_cases(&self) -> usize {
        self.calibration_cases
    }

    pub fn scored_namespace(&self) -> &str {
        &self.scored_namespace
    }

    pub fn calibration_namespace(&self) -> &str {
        &self.calibration_namespace
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    max_question_bytes: usize,
    max_result_line_bytes: usize,
    process_timeout_ms: u64,
    max_process_output_bytes: usize,
}

impl Limits {
    pub const fn max_question_bytes(&self) -> usize {
        self.max_question_bytes
    }

    pub const fn max_result_line_bytes(&self) -> usize {
        self.max_result_line_bytes
    }

    pub const fn process_timeout_ms(&self) -> u64 {
        self.process_timeout_ms
    }

    pub const fn max_process_output_bytes(&self) -> usize {
        self.max_process_output_bytes
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteManifest {
    schema_version: u8,
    suite_version: String,
    generator_version: String,
    profiles: BTreeMap<String, Profile>,
    thresholds: BTreeMap<String, Threshold>,
    baseline_versions: BTreeMap<String, String>,
    limits: Limits,
    tools: BTreeMap<String, String>,
    #[serde(skip)]
    digest: String,
}

impl SuiteManifest {
    pub fn tracked_v1() -> Result<Self, ManifestError> {
        Self::parse(TRACKED_V1)
    }

    pub fn parse(source: &str) -> Result<Self, ManifestError> {
        let mut manifest: Self = serde_json::from_str(source).map_err(ManifestError::Json)?;
        manifest.validate()?;
        let canonical = serde_json::to_vec(&manifest).map_err(ManifestError::Json)?;
        let mut hash = Sha256::new();
        hash.update(MANIFEST_DOMAIN);
        hash.update(canonical);
        manifest.digest = hex::encode(hash.finalize());
        Ok(manifest)
    }

    pub const fn schema_version(&self) -> u8 {
        self.schema_version
    }

    pub fn suite_version(&self) -> &str {
        &self.suite_version
    }

    pub fn generator_version(&self) -> &str {
        &self.generator_version
    }

    pub fn profile(&self, name: ProfileName) -> Option<&Profile> {
        self.profiles.get(name.as_str())
    }

    pub fn threshold(&self, name: &str) -> Option<Threshold> {
        self.thresholds.get(name).copied()
    }

    pub fn baseline_version(&self, name: &str) -> Option<&str> {
        self.baseline_versions.get(name).map(String::as_str)
    }

    pub const fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn tools(&self) -> &BTreeMap<String, String> {
        &self.tools
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != 1
            || self.suite_version != "1.0"
            || self.generator_version != agentgate_core::contracts::GENERATOR_VERSION_V1
        {
            return Err(ManifestError::Invalid("unsupported suite identity"));
        }

        require_exact_keys(&self.profiles, &REQUIRED_PROFILES)?;
        require_exact_keys(&self.thresholds, &REQUIRED_THRESHOLDS)?;
        require_exact_keys(&self.baseline_versions, &REQUIRED_BASELINES)?;
        require_exact_keys(&self.tools, &REQUIRED_TOOLS)?;

        let quick = self
            .profile(ProfileName::Quick)
            .ok_or(ManifestError::Invalid("missing quick profile"))?;
        let release = self
            .profile(ProfileName::Release)
            .ok_or(ManifestError::Invalid("missing release profile"))?;
        if (quick.scored_cases, quick.calibration_cases) != (100, 100)
            || (release.scored_cases, release.calibration_cases) != (1_000, 1_000)
        {
            return Err(ManifestError::Invalid("invalid profile case counts"));
        }

        let namespaces = [
            quick.scored_namespace(),
            quick.calibration_namespace(),
            release.scored_namespace(),
            release.calibration_namespace(),
        ];
        if namespaces
            .iter()
            .any(|value| value.is_empty() || value.len() > 64)
            || namespaces.iter().copied().collect::<BTreeSet<_>>().len() != namespaces.len()
        {
            return Err(ManifestError::Invalid("invalid profile namespaces"));
        }

        let expected_thresholds = [
            ("llm", Comparison::AtLeast, 80),
            ("direct", Comparison::AtMost, 5),
            ("fingerprint", Comparison::AtMost, 1),
            ("regex", Comparison::AtMost, 1),
            ("simple_parser", Comparison::AtMost, 1),
        ];
        for (name, comparison, percent) in expected_thresholds {
            let actual = self
                .threshold(name)
                .ok_or(ManifestError::Invalid("missing threshold"))?;
            if actual.comparison != comparison || actual.percent != percent {
                return Err(ManifestError::Invalid("invalid threshold"));
            }
        }

        if self
            .baseline_versions
            .values()
            .any(|value| value.is_empty() || value.len() > 32)
            || self
                .tools
                .values()
                .any(|value| value.is_empty() || value.len() > 32)
        {
            return Err(ManifestError::Invalid("invalid version or tool value"));
        }
        if self.limits.max_question_bytes != agentgate_core::generation::MAX_QUESTION_BYTES
            || self.limits.max_result_line_bytes != 16_384
            || self.limits.process_timeout_ms != 5_000
            || self.limits.max_process_output_bytes != 65_536
        {
            return Err(ManifestError::Invalid("invalid benchmark limits"));
        }
        Ok(())
    }
}

fn require_exact_keys<T>(
    map: &BTreeMap<String, T>,
    expected: &[&str],
) -> Result<(), ManifestError> {
    let actual = map.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(ManifestError::Invalid(
            "manifest keys do not match contract",
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("invalid benchmark manifest JSON")]
    Json(#[source] serde_json::Error),
    #[error("invalid benchmark manifest: {0}")]
    Invalid(&'static str),
}
