mod c;
mod cpp;
mod go;
mod java;
mod pseudocode;
mod rust;

use super::model::{RenderLanguage, TemplateFamily};
use super::{emitter::bounded_parts, error::RenderError};

pub(super) fn emit_assignment(
    language: RenderLanguage,
    family: TemplateFamily,
    output_label: &str,
    local_name: &str,
    expression: &str,
    guard_value: Option<u8>,
    decoy_expression: Option<&str>,
) -> Result<String, RenderError> {
    match family {
        TemplateFamily::Guarded if guard_value.is_some() && decoy_expression.is_some() => {}
        TemplateFamily::Direct | TemplateFamily::Helper | TemplateFamily::AliasChain
            if guard_value.is_none() && decoy_expression.is_none() => {}
        TemplateFamily::Direct
        | TemplateFamily::Helper
        | TemplateFamily::AliasChain
        | TemplateFamily::Guarded => return Err(RenderError::InvalidPlan),
    }
    let guard_value = guard_value.unwrap_or_default();
    let decoy_expression = decoy_expression.unwrap_or_default();
    match language {
        RenderLanguage::C => c::emit_assignment(
            family,
            output_label,
            local_name,
            expression,
            guard_value,
            decoy_expression,
        ),
        RenderLanguage::Cpp => cpp::emit_assignment(
            family,
            output_label,
            local_name,
            expression,
            guard_value,
            decoy_expression,
        ),
        RenderLanguage::Rust => rust::emit_assignment(
            family,
            output_label,
            local_name,
            expression,
            guard_value,
            decoy_expression,
        ),
        RenderLanguage::Go => go::emit_assignment(
            family,
            output_label,
            local_name,
            expression,
            guard_value,
            decoy_expression,
        ),
        RenderLanguage::Java => java::emit_assignment(
            family,
            output_label,
            local_name,
            expression,
            guard_value,
            decoy_expression,
        ),
        RenderLanguage::Pseudocode => pseudocode::emit_assignment(
            family,
            output_label,
            local_name,
            expression,
            guard_value,
            decoy_expression,
        ),
    }
}

pub(super) fn emit_inline_chunk_lookup(
    language: RenderLanguage,
    displayed_chunks: &[String],
    index: &str,
) -> Result<String, RenderError> {
    let (open, separator, close) = match language {
        RenderLanguage::C => ("((bytes[]){", ", ", "})["),
        RenderLanguage::Cpp => ("(std::array{", ", ", "})["),
        RenderLanguage::Rust => ("([", ", ", "])["),
        RenderLanguage::Go => ("([]bytes{", ", ", "})["),
        RenderLanguage::Java => ("(new byte[][]{", ", ", "})["),
        RenderLanguage::Pseudocode => ("[", ", ", "]["),
    };
    let mut parts = Vec::with_capacity(displayed_chunks.len() * 2 + 3);
    parts.push(open);
    for (position, chunk) in displayed_chunks.iter().enumerate() {
        if position != 0 {
            parts.push(separator);
        }
        parts.push(chunk);
    }
    parts.extend([close, index, "]"]);
    bounded_parts(&parts)
}

#[cfg(test)]
mod tests {
    use super::emit_assignment;
    use crate::generation::render::model::{RenderLanguage, TemplateFamily};

    #[test]
    fn every_backend_accepts_all_planned_template_families_directly() {
        for language in RenderLanguage::ALL {
            for family in [
                TemplateFamily::Direct,
                TemplateFamily::Helper,
                TemplateFamily::AliasChain,
                TemplateFamily::Guarded,
            ] {
                let guarded = family == TemplateFamily::Guarded;
                let emitted = emit_assignment(
                    language,
                    family,
                    "result_0",
                    "local_0",
                    "reverse(source_0)",
                    guarded.then_some(7),
                    guarded.then_some("bytes_ascii(\"A\")"),
                )
                .unwrap();
                assert!(emitted.contains("result_0"));
                assert_eq!(
                    emitted.contains("local_0"),
                    family != TemplateFamily::Direct
                );
            }
        }
    }
}
