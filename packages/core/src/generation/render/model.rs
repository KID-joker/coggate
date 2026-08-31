use std::fmt;

use crate::generation::{NodeId, Operation};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RenderLanguage {
    C,
    Cpp,
    Rust,
    Go,
    Java,
    Pseudocode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(super) enum TemplateFamily {
    Direct,
    Helper,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderMetadata {
    languages: Vec<RenderLanguage>,
    effective_fragment_count: usize,
    has_distractor: bool,
    byte_length: usize,
}

impl RenderMetadata {
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
    use super::{
        DisplayFragment, DisplayStep, DisplayStepKind, RenderLanguage, RenderMetadata, RenderPlan,
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
            kind: DisplayStepKind::Fragment { index: 0 },
        };
        let operation_step = DisplayStep {
            node: NodeId(1),
            output_label: "operation output".to_owned(),
            local_name: "value_0".to_owned(),
            template: TemplateFamily::Helper,
            kind: DisplayStepKind::Operation {
                operation: Operation::Reverse,
                inputs: vec![NodeId(0)],
            },
        };
        let plan = RenderPlan {
            fragments: vec![DisplayFragment {
                heading: "Step one".to_owned(),
                language: RenderLanguage::C,
                steps: vec![fragment_step, operation_step],
                distractor: false,
            }],
            output: NodeId(1),
        };

        assert_eq!(plan.fragments.len(), 1);
        assert_eq!(plan.fragments[0].steps.len(), 2);
        assert_eq!(plan.output, NodeId(1));
    }
}
