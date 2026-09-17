use super::super::emitter::bounded_parts;
use super::super::error::RenderError;
use super::super::model::TemplateFamily;

pub(super) fn emit_assignment(
    family: TemplateFamily,
    output: &str,
    local: &str,
    expression: &str,
) -> Result<String, RenderError> {
    match family {
        TemplateFamily::Direct | TemplateFamily::AliasChain | TemplateFamily::Guarded => {
            bounded_parts(&[
                "bytes ",
                output,
                " = ",
                expression,
                ";  // exports ",
                output,
            ])
        }
        TemplateFamily::Helper => bounded_parts(&[
            "bytes ",
            local,
            "() { return ",
            expression,
            "; }\nbytes ",
            output,
            " = ",
            local,
            "();  // exports ",
            output,
        ]),
    }
}
