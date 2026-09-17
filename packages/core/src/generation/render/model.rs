use std::{collections::BTreeMap, fmt, ops::Range};

use crate::generation::{NodeId, Operation, OperationKind};

/// Maximum conservative pre-emission budget for one effective display fragment.
pub(super) const MAX_FRAGMENT_BYTES: usize = 2_048;

/// Maximum UTF-8 byte length of a complete rendered question.
pub const MAX_QUESTION_BYTES: usize = 12_288;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RenderLanguage {
    C,
    Cpp,
    Rust,
    Go,
    Java,
    Pseudocode,
}

impl RenderLanguage {
    pub const ALL: [Self; 6] = [
        Self::C,
        Self::Cpp,
        Self::Rust,
        Self::Go,
        Self::Java,
        Self::Pseudocode,
    ];
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(super) enum TemplateFamily {
    Direct,
    Helper,
    AliasChain,
    Guarded,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum HelperSemantic {
    BytesAscii,
    Operation(OperationKind),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum NumericStyle {
    Decimal,
    LowerHex,
    IdentityOffset { delta: u8 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum FragmentLiteralPlan {
    Whole,
    OrderedChunks(Vec<Range<usize>>),
    ShuffledChunks {
        chunks: Vec<Range<usize>>,
        restore_order: Vec<usize>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ObfuscationProfile {
    aliases: BTreeMap<HelperSemantic, String>,
}

impl ObfuscationProfile {
    pub(super) fn new(aliases: BTreeMap<HelperSemantic, String>) -> Self {
        Self { aliases }
    }

    pub(super) fn aliases(&self) -> &BTreeMap<HelperSemantic, String> {
        &self.aliases
    }

    #[allow(
        dead_code,
        reason = "Task 6 consumes aliases during expression emission"
    )]
    pub(super) fn alias(&self, semantic: HelperSemantic) -> Option<&str> {
        self.aliases.get(&semantic).map(String::as_str)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(super) enum DisplayStepKind {
    Fragment {
        index: usize,
    },
    Operation {
        operation: Operation,
        inputs: Vec<NodeId>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(super) struct DisplayStep {
    pub(super) node: NodeId,
    pub(super) output_label: String,
    pub(super) local_name: String,
    pub(super) template: TemplateFamily,
    pub(super) numeric_style: NumericStyle,
    pub(super) literal_plan: Option<FragmentLiteralPlan>,
    pub(super) guard_value: Option<u8>,
    pub(super) kind: DisplayStepKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(super) struct DisplayFragment {
    pub(super) heading: String,
    pub(super) language: RenderLanguage,
    pub(super) steps: Vec<DisplayStep>,
    pub(super) distractor: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(super) struct RenderPlan {
    pub(super) fragments: Vec<DisplayFragment>,
    pub(super) output: NodeId,
    pub(super) profile: ObfuscationProfile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderMetadata {
    languages: Vec<RenderLanguage>,
    effective_fragment_count: usize,
    has_distractor: bool,
    byte_length: usize,
}

impl RenderMetadata {
    pub(super) fn from_validated_plan(plan: &RenderPlan, byte_length: usize) -> Self {
        let languages = plan
            .fragments
            .iter()
            .filter(|fragment| !fragment.distractor)
            .map(|fragment| fragment.language)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let effective_fragment_count = plan
            .fragments
            .iter()
            .filter(|fragment| !fragment.distractor)
            .count();
        let has_distractor = plan.fragments.iter().any(|fragment| fragment.distractor);

        Self {
            languages,
            effective_fragment_count,
            has_distractor,
            byte_length,
        }
    }

    pub fn languages(&self) -> &[RenderLanguage] {
        &self.languages
    }

    pub fn effective_fragment_count(&self) -> usize {
        self.effective_fragment_count
    }

    pub fn has_distractor(&self) -> bool {
        self.has_distractor
    }

    pub fn byte_length(&self) -> usize {
        self.byte_length
    }
}

pub struct RenderedQuestion {
    question: String,
    metadata: RenderMetadata,
}

impl RenderedQuestion {
    pub(super) fn new(question: String, metadata: RenderMetadata) -> Self {
        Self { question, metadata }
    }

    pub fn question(&self) -> &str {
        &self.question
    }

    pub fn metadata(&self) -> &RenderMetadata {
        &self.metadata
    }
}

impl fmt::Debug for RenderedQuestion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedQuestion")
            .field("question", &"[REDACTED]")
            .field("metadata", &self.metadata)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        DisplayFragment, DisplayStep, DisplayStepKind, FragmentLiteralPlan, HelperSemantic,
        NumericStyle, ObfuscationProfile, RenderLanguage, RenderMetadata, RenderPlan,
        RenderedQuestion, TemplateFamily,
    };
    use crate::generation::{NodeId, Operation};

    const SECRET_MARKER: &str = "SECRET_MARKER";

    #[test]
    fn rendered_question_exposes_only_read_only_result_data() {
        let metadata = RenderMetadata {
            languages: vec![RenderLanguage::Rust, RenderLanguage::Pseudocode],
            effective_fragment_count: 3,
            has_distractor: true,
            byte_length: 144,
        };
        let rendered = RenderedQuestion {
            question: SECRET_MARKER.to_owned(),
            metadata,
        };

        assert_eq!(rendered.question(), SECRET_MARKER);
        assert_eq!(
            rendered.metadata().languages(),
            &[RenderLanguage::Rust, RenderLanguage::Pseudocode,]
        );
        assert_eq!(rendered.metadata().effective_fragment_count(), 3);
        assert!(rendered.metadata().has_distractor());
        assert_eq!(rendered.metadata().byte_length(), 144);
    }

    #[test]
    fn rendered_question_debug_redacts_question_text() {
        let rendered = RenderedQuestion {
            question: SECRET_MARKER.to_owned(),
            metadata: RenderMetadata {
                languages: vec![RenderLanguage::Go],
                effective_fragment_count: 2,
                has_distractor: false,
                byte_length: 88,
            },
        };

        let debug = format!("{rendered:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("RenderMetadata"));
        assert!(!debug.contains(SECRET_MARKER));
    }

    #[test]
    fn internal_plan_model_carries_fragment_and_operation_steps() {
        let fragment_step = DisplayStep {
            node: NodeId(0),
            output_label: "fragment output".to_owned(),
            local_name: "part_0".to_owned(),
            template: TemplateFamily::Direct,
            numeric_style: NumericStyle::Decimal,
            literal_plan: Some(FragmentLiteralPlan::Whole),
            guard_value: None,
            kind: DisplayStepKind::Fragment { index: 0 },
        };
        let operation_step = DisplayStep {
            node: NodeId(1),
            output_label: "operation output".to_owned(),
            local_name: "value_0".to_owned(),
            template: TemplateFamily::Helper,
            numeric_style: NumericStyle::LowerHex,
            literal_plan: None,
            guard_value: None,
            kind: DisplayStepKind::Operation {
                operation: Operation::Reverse,
                inputs: vec![NodeId(0)],
            },
        };
        let profile = ObfuscationProfile::new(BTreeMap::from([(
            HelperSemantic::BytesAscii,
            "decode_bytes".to_owned(),
        )]));
        let plan = RenderPlan {
            fragments: vec![DisplayFragment {
                heading: "Step one".to_owned(),
                language: RenderLanguage::C,
                steps: vec![fragment_step, operation_step],
                distractor: false,
            }],
            output: NodeId(1),
            profile,
        };

        assert_eq!(plan.fragments.len(), 1);
        assert_eq!(plan.fragments[0].steps.len(), 2);
        assert_eq!(plan.output, NodeId(1));
        assert_eq!(
            plan.profile.alias(HelperSemantic::BytesAscii),
            Some("decode_bytes")
        );
    }
}
