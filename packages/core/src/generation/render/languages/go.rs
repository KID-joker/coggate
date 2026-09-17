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
            bounded_parts(&[output, " := ", expression, " // exports ", output])
        }
        TemplateFamily::Helper => bounded_parts(&[
            local,
            " := func() bytes { return ",
            expression,
            " }\n",
            output,
            " := ",
            local,
            "() // exports ",
            output,
        ]),
        TemplateFamily::AliasChain => bounded_parts(&[
            local,
            " := ",
            expression,
            "\n",
            output,
            " := ",
            local,
            " // exports ",
            output,
        ]),
        TemplateFamily::Guarded => {
            let guard = guard_value.to_string();
            bounded_parts(&[
                "var ",
                output,
                " bytes\nif (((uint32(",
                &guard,
                ")*uint32(",
                &guard,
                "))+uint32(",
                &guard,
                "))&1)==0 {\n",
                output,
                " = ",
                expression,
                "\n} else {\n",
                local,
                " := ",
                decoy_expression,
                "\n}",
            ])
        }
    }
}
