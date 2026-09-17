use super::super::emitter::bounded_parts;
use super::super::error::RenderError;
use super::BaseTemplateFamily;

pub(super) fn emit_assignment(
    family: BaseTemplateFamily,
    output: &str,
    local: &str,
    expression: &str,
) -> Result<String, RenderError> {
    match family {
        BaseTemplateFamily::Direct => bounded_parts(&[
            "byte[] ",
            output,
            " = ",
            expression,
            "; // exports ",
            output,
        ]),
        BaseTemplateFamily::Helper => bounded_parts(&[
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
