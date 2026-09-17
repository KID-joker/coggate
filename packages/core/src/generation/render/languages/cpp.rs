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
        TemplateFamily::AliasChain => bounded_parts(&[
            "auto ",
            local,
            " = ",
            expression,
            ";\nauto ",
            output,
            " = ",
            local,
            ";  // exports ",
            output,
        ]),
        TemplateFamily::Guarded => {
            let guard = guard_value.to_string();
            bounded_parts(&[
                "bytes ",
                output,
                ";\nif ((((",
                &guard,
                "UL*",
                &guard,
                "UL)+",
                &guard,
                "UL)&1UL)==0UL) {\n",
                output,
                " = ",
                expression,
                ";\n} else {\nauto ",
                local,
                " = ",
                decoy_expression,
                ";\n}",
            ])
        }
    }
}
