mod c;
mod cpp;
mod go;
mod java;
mod pseudocode;
mod rust;

use super::error::RenderError;
use super::model::{RenderLanguage, TemplateFamily};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BaseTemplateFamily {
    Direct,
    Helper,
}

pub(super) fn emit_assignment(
    language: RenderLanguage,
    family: TemplateFamily,
    output_label: &str,
    local_name: &str,
    expression: &str,
) -> Result<String, RenderError> {
    emit_base_assignment(
        language,
        base_template_family(family),
        output_label,
        local_name,
        expression,
    )
}

fn emit_base_assignment(
    language: RenderLanguage,
    family: BaseTemplateFamily,
    output_label: &str,
    local_name: &str,
    expression: &str,
) -> Result<String, RenderError> {
    match language {
        RenderLanguage::C => c::emit_assignment(family, output_label, local_name, expression),
        RenderLanguage::Cpp => cpp::emit_assignment(family, output_label, local_name, expression),
        RenderLanguage::Rust => rust::emit_assignment(family, output_label, local_name, expression),
        RenderLanguage::Go => go::emit_assignment(family, output_label, local_name, expression),
        RenderLanguage::Java => java::emit_assignment(family, output_label, local_name, expression),
        RenderLanguage::Pseudocode => {
            pseudocode::emit_assignment(family, output_label, local_name, expression)
        }
    }
}

pub(super) fn base_template_family(family: TemplateFamily) -> BaseTemplateFamily {
    // Task 7 replaces this scaffold mapping with real AliasChain and Guarded syntax.
    match family {
        TemplateFamily::Direct => BaseTemplateFamily::Direct,
        TemplateFamily::Helper => BaseTemplateFamily::Helper,
        TemplateFamily::AliasChain | TemplateFamily::Guarded => BaseTemplateFamily::Direct,
    }
}

#[cfg(test)]
mod tests {
    use super::{BaseTemplateFamily, base_template_family, emit_base_assignment};
    use crate::generation::render::model::{RenderLanguage, TemplateFamily};

    #[test]
    fn one_boundary_maps_every_planned_template_to_its_current_base() {
        assert_eq!(
            base_template_family(TemplateFamily::Direct),
            BaseTemplateFamily::Direct
        );
        assert_eq!(
            base_template_family(TemplateFamily::Helper),
            BaseTemplateFamily::Helper
        );
        assert_eq!(
            base_template_family(TemplateFamily::AliasChain),
            BaseTemplateFamily::Direct
        );
        assert_eq!(
            base_template_family(TemplateFamily::Guarded),
            BaseTemplateFamily::Direct
        );
    }

    #[test]
    fn every_backend_accepts_only_both_base_template_families() {
        for language in RenderLanguage::ALL {
            let direct = emit_base_assignment(
                language,
                BaseTemplateFamily::Direct,
                "result_0",
                "local_0",
                "reverse(source_0)",
            )
            .unwrap();
            let helper = emit_base_assignment(
                language,
                BaseTemplateFamily::Helper,
                "result_0",
                "local_0",
                "reverse(source_0)",
            )
            .unwrap();

            assert!(direct.contains("result_0"));
            assert!(!direct.contains("local_0"));
            assert!(helper.contains("result_0"));
            assert!(helper.contains("local_0"));
        }
    }
}
