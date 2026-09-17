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
            bounded_parts(&["let ", output, " = ", expression, "; // exports ", output])
        }
        TemplateFamily::Helper => bounded_parts(&[
            "fn ",
            local,
            "() -> Bytes { ",
            expression,
            " }\nlet ",
            output,
            " = ",
            local,
            "(); // exports ",
            output,
        ]),
        TemplateFamily::AliasChain => bounded_parts(&[
            "let ",
            local,
            " = ",
            expression,
            ";\nlet ",
            output,
            " = ",
            local,
            "; // exports ",
            output,
        ]),
        TemplateFamily::Guarded => {
            let guard = guard_value.to_string();
            bounded_parts(&[
                "let ",
                output,
                ": Bytes;\nif ((((",
                &guard,
                "_u32*",
                &guard,
                "_u32)+",
                &guard,
                "_u32)&1_u32)==0_u32) {\n",
                output,
                " = ",
                expression,
                ";\n} else {\nlet ",
                local,
                " = ",
                decoy_expression,
                ";\n}",
            ])
        }
    }
}
