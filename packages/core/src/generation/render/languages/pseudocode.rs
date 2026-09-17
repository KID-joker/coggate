use super::super::emitter::bounded_parts;
use super::super::error::RenderError;
use super::super::model::TemplateFamily;

pub(super) fn emit_assignment(
    family: TemplateFamily,
    output: &str,
    local: &str,
    expression: &str,
    guard_value: u8,
    decoy_expression: &str,
) -> Result<String, RenderError> {
    match family {
        TemplateFamily::Direct => {
            bounded_parts(&[output, " <- ", expression, "  # exports ", output])
        }
        TemplateFamily::Helper => bounded_parts(&[
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
        TemplateFamily::AliasChain => bounded_parts(&[
            local,
            " <- ",
            expression,
            "\n",
            output,
            " <- ",
            local,
            "  # exports ",
            output,
        ]),
        TemplateFamily::Guarded => {
            let guard = guard_value.to_string();
            bounded_parts(&[
                "bytes ",
                output,
                "\nif ((((u32(",
                &guard,
                ")*u32(",
                &guard,
                "))+u32(",
                &guard,
                "))&1)==0) then\n",
                output,
                " <- ",
                expression,
                "\nelse\n",
                local,
                " <- ",
                decoy_expression,
                "\nend if",
            ])
        }
    }
}
