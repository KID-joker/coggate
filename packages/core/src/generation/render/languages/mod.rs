mod c;
mod cpp;
mod go;
mod java;
mod pseudocode;
mod rust;

use super::error::RenderError;
use super::model::{RenderLanguage, TemplateFamily};

pub(super) fn emit_assignment(
    language: RenderLanguage,
    family: TemplateFamily,
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
