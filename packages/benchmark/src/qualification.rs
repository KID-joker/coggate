use std::collections::BTreeMap;

use crate::{
    baseline::{
        Baseline, fingerprint::FingerprintBaseline, regex_extract::RegexBaseline, score_baseline,
        simple_parser::SimpleParserBaseline,
    },
    corpus::{Corpus, CorpusCase},
    manifest::{ProfileName, SuiteManifest},
    report::{QualificationReport, ReportBinding, ReportCase},
};

pub fn qualify_baselines(
    suite: &SuiteManifest,
    profile: ProfileName,
    corpus: &Corpus,
    direct: &impl Baseline,
    direct_tool_versions: BTreeMap<String, String>,
) -> Result<Vec<QualificationReport>, QualificationError> {
    let expected = suite
        .profile(profile)
        .ok_or(QualificationError::InvalidCorpus)?
        .scored_cases();
    if corpus.scored().len() != expected || direct.id() != "direct" {
        return Err(QualificationError::InvalidCorpus);
    }

    let fingerprint = FingerprintBaseline::train(corpus.calibration());
    let regex = RegexBaseline::new().map_err(|_| QualificationError::Composition)?;
    let parser = SimpleParserBaseline;
    Ok(vec![
        score_report(
            suite,
            profile,
            direct,
            corpus.scored(),
            direct_tool_versions,
        )?,
        score_report(
            suite,
            profile,
            &fingerprint,
            corpus.scored(),
            BTreeMap::new(),
        )?,
        score_report(suite, profile, &regex, corpus.scored(), BTreeMap::new())?,
        score_report(suite, profile, &parser, corpus.scored(), BTreeMap::new())?,
    ])
}

fn score_report(
    suite: &SuiteManifest,
    profile: ProfileName,
    baseline: &impl Baseline,
    cases: &[CorpusCase],
    tool_versions: BTreeMap<String, String>,
) -> Result<QualificationReport, QualificationError> {
    let binding = ReportBinding::baseline(suite, profile, baseline.id(), tool_versions)
        .map_err(|_| QualificationError::Composition)?;
    let cases = score_baseline(baseline, cases)
        .map_err(QualificationError::Baseline)?
        .into_iter()
        .map(|result| {
            ReportCase::new(
                result.case_id().to_owned(),
                result.outcome(),
                result.reason(),
                result.duration_ms(),
            )
            .map_err(|_| QualificationError::Composition)
        })
        .collect::<Result<Vec<_>, _>>()?;
    QualificationReport::from_cases(binding, cases).map_err(|_| QualificationError::Composition)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum QualificationError {
    #[error("invalid benchmark corpus or direct baseline")]
    InvalidCorpus,
    #[error("baseline infrastructure failed")]
    Baseline(#[from] crate::baseline::BaselineError),
    #[error("benchmark qualification composition failed")]
    Composition,
}
