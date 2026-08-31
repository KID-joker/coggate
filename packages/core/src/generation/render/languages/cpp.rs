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
        TemplateFamily::Direct => {
            bounded_parts(&["auto ", output, " = ", expression, ";  // exports ", output])
        }
        TemplateFamily::Helper => bounded_parts(&[
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
