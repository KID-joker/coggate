use crate::generation::Operation;

use super::error::RenderError;
use super::languages;
use super::model::{RenderLanguage, TemplateFamily};

pub(super) const MAX_STEP_BYTES: usize = 512;

pub(super) fn emit_operation(
    language: RenderLanguage,
    family: TemplateFamily,
    output_label: &str,
    local_name: &str,
    operation: &Operation,
    inputs: &[String],
) -> Result<String, RenderError> {
    operation
        .validate_arity(inputs.len())
        .map_err(|_| RenderError::InvalidPlan)?;
    let expression = operation_expression(operation, inputs)?;
    languages::emit_assignment(language, family, output_label, local_name, &expression)
}

pub(super) fn emit_fragment(
    language: RenderLanguage,
    family: TemplateFamily,
    output_label: &str,
    local_name: &str,
    value: &[u8],
) -> Result<String, RenderError> {
    if value.is_empty() || value.len() > 16 || !value.iter().all(u8::is_ascii_alphanumeric) {
        return Err(RenderError::InvalidPlan);
    }

    let value = std::str::from_utf8(value).map_err(|_| RenderError::InvalidPlan)?;
    let mut expression = String::new();
    push_bounded(&mut expression, "bytes_ascii(\"")?;
    push_bounded(&mut expression, value)?;
    push_bounded(&mut expression, "\")")?;
    languages::emit_assignment(language, family, output_label, local_name, &expression)
}

pub(super) fn declared_template_max_bytes(
    language: RenderLanguage,
    family: TemplateFamily,
) -> usize {
    match (language, family) {
        (RenderLanguage::C, TemplateFamily::Direct) => 512,
        (RenderLanguage::C, TemplateFamily::Helper) => 512,
        (RenderLanguage::Cpp, TemplateFamily::Direct) => 512,
        (RenderLanguage::Cpp, TemplateFamily::Helper) => 512,
        (RenderLanguage::Rust, TemplateFamily::Direct) => 512,
        (RenderLanguage::Rust, TemplateFamily::Helper) => 512,
        (RenderLanguage::Go, TemplateFamily::Direct) => 512,
        (RenderLanguage::Go, TemplateFamily::Helper) => 512,
        (RenderLanguage::Java, TemplateFamily::Direct) => 512,
        (RenderLanguage::Java, TemplateFamily::Helper) => 512,
        (RenderLanguage::Pseudocode, TemplateFamily::Direct) => 512,
        (RenderLanguage::Pseudocode, TemplateFamily::Helper) => 512,
    }
}

pub(super) fn bounded_parts(parts: &[&str]) -> Result<String, RenderError> {
    let mut output = String::new();
    for part in parts {
        push_bounded(&mut output, part)?;
    }
    Ok(output)
}

fn push_bounded(output: &mut String, value: &str) -> Result<(), RenderError> {
    let length = output
        .len()
        .checked_add(value.len())
        .ok_or(RenderError::LengthLimit)?;
    if length > MAX_STEP_BYTES {
        return Err(RenderError::LengthLimit);
    }
    output.push_str(value);
    Ok(())
}

fn push_number(output: &mut String, value: usize) -> Result<(), RenderError> {
    push_bounded(output, &value.to_string())
}

fn push_call(output: &mut String, helper: &str, inputs: &[String]) -> Result<(), RenderError> {
    push_bounded(output, helper)?;
    push_bounded(output, "(")?;
    for (index, input) in inputs.iter().enumerate() {
        if index != 0 {
            push_bounded(output, ", ")?;
        }
        push_bounded(output, input)?;
    }
    Ok(())
}

fn push_list<T>(
    output: &mut String,
    values: &[T],
    mut append: impl FnMut(&mut String, &T) -> Result<(), RenderError>,
) -> Result<(), RenderError> {
    push_bounded(output, "[")?;
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            push_bounded(output, ", ")?;
        }
        append(output, value)?;
    }
    push_bounded(output, "]")
}

fn operation_expression(operation: &Operation, inputs: &[String]) -> Result<String, RenderError> {
    let mut output = String::new();
    match operation {
        Operation::Reverse => push_call(&mut output, "reverse", inputs)?,
        Operation::RotateLeft(amount) => {
            push_call(&mut output, "rotate_left", inputs)?;
            push_bounded(&mut output, ", ")?;
            push_number(&mut output, *amount)?;
        }
        Operation::RotateRight(amount) => {
            push_call(&mut output, "rotate_right", inputs)?;
            push_bounded(&mut output, ", ")?;
            push_number(&mut output, *amount)?;
        }
        Operation::Xor(key) => {
            push_call(&mut output, "xor_repeat", inputs)?;
            push_bounded(&mut output, ", ")?;
            push_list(&mut output, key, |target, value| {
                push_number(target, usize::from(*value))
            })?;
        }
        Operation::EvenBytes => push_call(&mut output, "even_bytes", inputs)?,
        Operation::OddBytes => push_call(&mut output, "odd_bytes", inputs)?,
        Operation::Permute(permutation) => {
            push_call(&mut output, "permute", inputs)?;
            push_bounded(&mut output, ", ")?;
            push_list(&mut output, permutation, |target, value| {
                push_number(target, *value)
            })?;
        }
        Operation::Slice { start, end } => {
            push_call(&mut output, "slice", inputs)?;
            push_bounded(&mut output, ", ")?;
            push_number(&mut output, *start)?;
            push_bounded(&mut output, ", ")?;
            push_number(&mut output, *end)?;
        }
        Operation::Concat => push_call(&mut output, "concat", inputs)?,
        Operation::AddModulo => push_call(&mut output, "add_u8", inputs)?,
        Operation::SubModulo => push_call(&mut output, "sub_u8", inputs)?,
        Operation::HexEncode => push_call(&mut output, "hex_lower", inputs)?,
        Operation::HexDecode => push_call(&mut output, "hex_decode_lower", inputs)?,
        Operation::Base64UrlEncode => push_call(&mut output, "base64url_no_pad", inputs)?,
        Operation::Base64UrlDecode => push_call(&mut output, "base64url_decode_no_pad", inputs)?,
        Operation::Sha256Prefix(prefix_length) => {
            push_call(&mut output, "sha256_prefix", inputs)?;
            push_bounded(&mut output, ", ")?;
            push_number(&mut output, *prefix_length)?;
        }
        Operation::RotateLeftDerived => push_call(&mut output, "rotate_left_derived", inputs)?,
        Operation::ConditionalOrder => push_call(&mut output, "conditional_order", inputs)?,
    }
    push_bounded(&mut output, ")")?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{MAX_STEP_BYTES, declared_template_max_bytes, emit_fragment, emit_operation};
    use crate::generation::Operation;
    use crate::generation::render::error::RenderError;
    use crate::generation::render::model::{RenderLanguage, TemplateFamily};

    fn operations() -> Vec<Operation> {
        vec![
            Operation::Reverse,
            Operation::RotateLeft(3),
            Operation::RotateRight(2),
            Operation::Xor(vec![1, 2]),
            Operation::EvenBytes,
            Operation::OddBytes,
            Operation::Permute(vec![2, 0, 1]),
            Operation::Slice { start: 1, end: 3 },
            Operation::Concat,
            Operation::AddModulo,
            Operation::SubModulo,
            Operation::HexEncode,
            Operation::HexDecode,
            Operation::Base64UrlEncode,
            Operation::Base64UrlDecode,
            Operation::Sha256Prefix(8),
            Operation::RotateLeftDerived,
            Operation::ConditionalOrder,
        ]
    }

    fn emit(language: RenderLanguage, operation: &Operation) -> String {
        let input_count = operation.arity().unwrap_or(3);
        let inputs = (0..input_count)
            .map(|index| format!("source_{index}"))
            .collect::<Vec<_>>();
        emit_operation(
            language,
            TemplateFamily::Direct,
            "result_0",
            "local_0",
            operation,
            &inputs,
        )
        .unwrap()
    }

    #[test]
    fn every_language_emits_every_v1_operation() {
        assert_eq!(operations().len(), 18);

        for language in RenderLanguage::ALL {
            for operation in operations() {
                let input_count = operation.arity().unwrap_or(3);
                let inputs = (0..input_count)
                    .map(|index| format!("source_{index}"))
                    .collect::<Vec<_>>();
                let rendered = emit_operation(
                    language,
                    TemplateFamily::Direct,
                    "result_0",
                    "local_0",
                    &operation,
                    &inputs,
                )
                .unwrap();

                assert!(rendered.contains("result_0"), "{language:?} {operation:?}");
                for input in &inputs {
                    assert!(rendered.contains(input), "{language:?} {operation:?}");
                }
                assert!(rendered.len() <= MAX_STEP_BYTES);
            }
        }
    }

    #[test]
    fn direct_templates_have_stable_language_specific_syntax() {
        assert_eq!(
            emit(RenderLanguage::C, &Operation::Reverse),
            "bytes result_0 = reverse(source_0);  // exports result_0"
        );
        assert_eq!(
            emit(RenderLanguage::Cpp, &Operation::RotateLeft(3)),
            "auto result_0 = rotate_left(source_0, 3);  // exports result_0"
        );
        assert_eq!(
            emit(RenderLanguage::Rust, &Operation::Xor(vec![1, 2])),
            "let result_0 = xor_repeat(source_0, [1, 2]); // exports result_0"
        );
        assert_eq!(
            emit(RenderLanguage::Go, &Operation::Concat),
            "result_0 := concat(source_0, source_1, source_2) // exports result_0"
        );
        assert_eq!(
            emit(RenderLanguage::Java, &Operation::Sha256Prefix(8)),
            "byte[] result_0 = sha256_prefix(source_0, 8); // exports result_0"
        );
        assert_eq!(
            emit(RenderLanguage::Pseudocode, &Operation::ConditionalOrder),
            "result_0 <- conditional_order(source_0, source_1, source_2)  # exports result_0"
        );
    }

    #[test]
    fn operation_parameters_and_ordered_inputs_are_explicit() {
        let cases = [
            (Operation::RotateLeft(3), "rotate_left(source_0, 3)"),
            (Operation::RotateRight(2), "rotate_right(source_0, 2)"),
            (Operation::Xor(vec![1, 2]), "xor_repeat(source_0, [1, 2])"),
            (
                Operation::Permute(vec![2, 0, 1]),
                "permute(source_0, [2, 0, 1])",
            ),
            (
                Operation::Slice { start: 1, end: 3 },
                "slice(source_0, 1, 3)",
            ),
            (Operation::Sha256Prefix(8), "sha256_prefix(source_0, 8)"),
            (
                Operation::RotateLeftDerived,
                "rotate_left_derived(source_0, source_1)",
            ),
            (
                Operation::ConditionalOrder,
                "conditional_order(source_0, source_1, source_2)",
            ),
        ];

        for (operation, expected) in cases {
            assert!(emit(RenderLanguage::Rust, &operation).contains(expected));
        }
    }

    #[test]
    fn helper_templates_export_the_requested_output_within_declared_bounds() {
        for language in RenderLanguage::ALL {
            for family in [TemplateFamily::Direct, TemplateFamily::Helper] {
                let rendered = emit_operation(
                    language,
                    family,
                    "result_0",
                    "local_0",
                    &Operation::ConditionalOrder,
                    &["source_0".into(), "source_1".into(), "source_2".into()],
                )
                .unwrap();

                assert!(rendered.contains("result_0"));
                assert!(rendered.len() <= declared_template_max_bytes(language, family));
                assert!(declared_template_max_bytes(language, family) <= MAX_STEP_BYTES);
                if family == TemplateFamily::Helper {
                    assert!(rendered.contains("local_0"));
                }
            }
        }
    }

    #[test]
    fn fragments_accept_only_bounded_ascii_alphanumeric_bytes() {
        for value in [
            b"A".as_slice(),
            b"aB09".as_slice(),
            b"0123456789ABCDEF".as_slice(),
        ] {
            let rendered = emit_fragment(
                RenderLanguage::Rust,
                TemplateFamily::Direct,
                "result_0",
                "local_0",
                value,
            )
            .unwrap();
            assert!(rendered.contains("bytes_ascii(\""));
            assert!(rendered.contains(std::str::from_utf8(value).unwrap()));
            assert!(rendered.len() <= MAX_STEP_BYTES);
        }

        for value in [
            b"".as_slice(),
            b"not-valid".as_slice(),
            b"has space".as_slice(),
            "café".as_bytes(),
            b"0123456789ABCDEFG".as_slice(),
        ] {
            assert_eq!(
                emit_fragment(
                    RenderLanguage::Rust,
                    TemplateFamily::Direct,
                    "result_0",
                    "local_0",
                    value,
                ),
                Err(RenderError::InvalidPlan)
            );
        }
    }
}
