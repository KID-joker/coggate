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
        TemplateFamily::Direct => bounded_parts(&[
            "byte[] ",
            output,
            " = ",
            expression,
            "; // exports ",
            output,
        ]),
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
        TemplateFamily::AliasChain => bounded_parts(&[
            "byte[] ",
            local,
            " = ",
            expression,
            ";\nbyte[] ",
            output,
            " = ",
            local,
            "; // exports ",
            output,
        ]),
        TemplateFamily::Guarded => {
            let guard = guard_value.to_string();
            bounded_parts(&[
                "byte[] ",
                output,
                ";\nif ((((",
                &guard,
                "L*",
                &guard,
                "L)+",
                &guard,
                "L)&1L)==0L) {\n",
                output,
                " = ",
                expression,
                ";\n} else {\nbyte[] ",
                local,
                " = ",
                decoy_expression,
                ";\n}",
            ])
        }
    }
}
