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
        BaseTemplateFamily::Direct => {
            bounded_parts(&["auto ", output, " = ", expression, ";  // exports ", output])
        }
        BaseTemplateFamily::Helper => bounded_parts(&[
            "auto ",
            local,
            "() { return ",
            expression,
            "; }\nauto ",
            output,
            " = ",
            local,
            "();  // exports ",
            output,
        ]),
    }
}
