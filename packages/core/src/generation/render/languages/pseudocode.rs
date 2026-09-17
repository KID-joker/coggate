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
            bounded_parts(&[output, " <- ", expression, "  # exports ", output])
        }
        BaseTemplateFamily::Helper => bounded_parts(&[
            "function ",
            local,
            ": return ",
            expression,
            "\n",
            output,
            " <- ",
            local,
            "()  # exports ",
            output,
        ]),
    }
}
