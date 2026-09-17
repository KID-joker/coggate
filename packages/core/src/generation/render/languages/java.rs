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
                "byte[] ",
                output,
                " = ",
                expression,
                "; // exports ",
                output,
            ])
        }
        TemplateFamily::Helper => bounded_parts(&[
            "byte[] ",
            local,
            "() { return ",
            expression,
            "; }\nbyte[] ",
            output,
            " = ",
            local,
            "(); // exports ",
            output,
        ]),
    }
}
