use std::collections::{BTreeMap, BTreeSet};

use crate::generation::{NodeId, Operation};

use super::error::RenderError;
use super::languages;
use super::model::{
    DisplayStepKind, MAX_FRAGMENT_BYTES, MAX_QUESTION_BYTES, RenderLanguage, RenderPlan,
    TemplateFamily,
};

pub(super) const MAX_STEP_BYTES: usize = 512;

const BYTE_SEMANTICS_PREAMBLE: &str = "Treat every value as a byte array. Indices are zero-based and slices use half-open [start,end) ranges. Addition and subtraction use wrapping u8 arithmetic modulo 256. Rotate amounts are reduced modulo the nonempty current array length. Hex is lowercase. Base64url is unpadded base64url.\n\n";
const HELPER_SEMANTICS_GLOSSARY: &str = concat!(
    "Helper semantics:\n",
    "bytes_ascii(\"...\"): the listed ASCII bytes.\n",
    "reverse(x): the bytes of x in reverse order.\n",
    "rotate_left(x, n): cyclically rotate x left by n modulo len(x); x must be nonempty.\n",
    "rotate_right(x, n): cyclically rotate x right by n modulo len(x); x must be nonempty.\n",
    "xor_repeat(x, key): out[i] = x[i] XOR key[i modulo len(key)].\n",
    "even_bytes(x): bytes of x at zero-based indices 0, 2, ...\n",
    "odd_bytes(x): bytes of x at zero-based indices 1, 3, ...\n",
    "permute(x, p): out[j] = x[p[j]].\n",
    "slice(x, start, end): bytes x[start..end] using a half-open range.\n",
    "concat(x1, x2, ...): concatenate inputs in the listed order.\n",
    "add_u8(x, y): elementwise x[i] + y[i] modulo 256.\n",
    "sub_u8(x, y): elementwise x[i] - y[i] modulo 256.\n",
    "hex_lower(x): encode bytes as canonical lowercase hexadecimal.\n",
    "hex_decode_lower(x): inverse of hex_lower for canonical lowercase hexadecimal only.\n",
    "base64url_no_pad(x): encode bytes as canonical unpadded base64url.\n",
    "base64url_decode_no_pad(x): inverse of base64url_no_pad for canonical unpadded base64url only.\n",
    "sha256_prefix(x, n): the first n raw bytes of the SHA-256 digest of x.\n",
    "rotate_left_derived(x, key): rotate_left(x, unsigned key[0]).\n",
    "conditional_order(control, a, b): concat(a, b) if unsigned control[0] is even; otherwise concat(b, a).\n\n",
);
const DEPENDENCY_CLUES_HEADER: &str = "Dependency clues:\n";
const DISPLAY_ORDER_WARNING: &str = "Display order is not evaluation order.\n";
const OUTPUT_REQUEST_PREFIX: &str = "The requested result is output label ";
const OUTPUT_REQUEST_SUFFIX: &str = ". Submit its byte array as unpadded base64url.\n";

#[cfg(test)]
pub(super) fn common_question_bytes() -> usize {
    let mut emitted = String::new();
    push_question_preamble(&mut emitted).unwrap();
    push_dependency_clues(&mut emitted, &[String::new()]).unwrap();
    push_final_request(&mut emitted, "").unwrap();
    emitted.len()
}

pub(super) fn emit_question(
    plan: &RenderPlan,
    fragments: &[Vec<u8>],
) -> Result<String, RenderError> {
    let locations = index_output_locations(plan)?;
    let mut question = String::new();
    push_question_preamble(&mut question)?;

    let mut dependency_clues = Vec::new();
    let mut dependency_bytes_by_fragment = vec![0_usize; plan.fragments.len()];

    for (display_index, display_fragment) in plan.fragments.iter().enumerate() {
        let mut rendered_fragment = String::new();
        push_with_limit(
            &mut rendered_fragment,
            &format!(
                "[Fragment {} — {}]\n",
                display_index + 1,
                language_name(display_fragment.language)
            ),
            MAX_FRAGMENT_BYTES,
        )?;

        if display_fragment.distractor {
            push_with_limit(
                &mut rendered_fragment,
                "This audit/example branch does not contribute to the requested result.\n\n",
                MAX_FRAGMENT_BYTES,
            )?;
        } else {
            push_with_limit(
                &mut rendered_fragment,
                &format!("Section identifier: {}\n", display_fragment.heading),
                MAX_FRAGMENT_BYTES,
            )?;

            for step in &display_fragment.steps {
                let emitted = match &step.kind {
                    DisplayStepKind::Fragment { index } => emit_fragment(
                        display_fragment.language,
                        step.template,
                        &step.output_label,
                        &step.local_name,
                        fragments.get(*index).ok_or(RenderError::InvalidPlan)?,
                    )?,
                    DisplayStepKind::Operation { operation, inputs } => {
                        let input_labels = inputs
                            .iter()
                            .map(|input| {
                                locations
                                    .get(input)
                                    .map(|location| location.output_label.clone())
                                    .ok_or(RenderError::MissingReference(*input))
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        emit_operation(
                            display_fragment.language,
                            step.template,
                            &step.output_label,
                            &step.local_name,
                            operation,
                            &input_labels,
                        )?
                    }
                };
                if emitted.len() > MAX_STEP_BYTES {
                    return Err(RenderError::LengthLimit);
                }
                push_with_limit(&mut rendered_fragment, &emitted, MAX_FRAGMENT_BYTES)?;
                push_with_limit(&mut rendered_fragment, "\n", MAX_FRAGMENT_BYTES)?;

                if let DisplayStepKind::Operation { inputs, .. } = &step.kind {
                    let mut seen_producers = BTreeSet::new();
                    let mut producers = Vec::new();
                    for input in inputs {
                        let producer = locations
                            .get(input)
                            .ok_or(RenderError::MissingReference(*input))?;
                        if producer.display_index != display_index && seen_producers.insert(*input)
                        {
                            producers
                                .push((producer.output_label.as_str(), producer.display_index));
                        }
                    }
                    if !producers.is_empty() {
                        let clue =
                            format_dependency_clue(&producers, &step.output_label, display_index)?;
                        let clue_bytes = dependency_bytes_by_fragment[display_index]
                            .checked_add(clue.len())
                            .ok_or(RenderError::LengthLimit)?;
                        let accounted_fragment_bytes = rendered_fragment
                            .len()
                            .checked_add(clue_bytes)
                            .ok_or(RenderError::LengthLimit)?;
                        if accounted_fragment_bytes > MAX_FRAGMENT_BYTES {
                            return Err(RenderError::LengthLimit);
                        }
                        dependency_bytes_by_fragment[display_index] = clue_bytes;
                        dependency_clues.push(clue);
                    }
                }
            }
            push_with_limit(&mut rendered_fragment, "\n", MAX_FRAGMENT_BYTES)?;
        }

        let accounted_fragment_bytes = rendered_fragment
            .len()
            .checked_add(dependency_bytes_by_fragment[display_index])
            .ok_or(RenderError::LengthLimit)?;
        if accounted_fragment_bytes > MAX_FRAGMENT_BYTES {
            return Err(RenderError::LengthLimit);
        }

        push_with_limit(&mut question, &rendered_fragment, MAX_QUESTION_BYTES)?;
    }

    push_dependency_clues(&mut question, &dependency_clues)?;

    let output_label = locations
        .get(&plan.output)
        .map(|location| location.output_label.as_str())
        .ok_or(RenderError::MissingReference(plan.output))?;
    push_final_request(&mut question, output_label)?;

    Ok(question)
}

pub(super) fn format_dependency_clue(
    producers: &[(&str, usize)],
    output_label: &str,
    output_display_index: usize,
) -> Result<String, RenderError> {
    if producers.is_empty() {
        return Err(RenderError::InvalidPlan);
    }

    let mut clue = String::new();
    push_with_limit(&mut clue, "Dependency: output labels ", MAX_FRAGMENT_BYTES)?;
    for (index, (label, display_index)) in producers.iter().enumerate() {
        if index > 0 {
            push_with_limit(&mut clue, ", ", MAX_FRAGMENT_BYTES)?;
        }
        push_with_limit(
            &mut clue,
            &format!("{label} (Fragment {})", display_index + 1),
            MAX_FRAGMENT_BYTES,
        )?;
    }
    push_with_limit(
        &mut clue,
        &format!(
            " are inputs to output label {output_label} in Fragment {}.\n",
            output_display_index + 1
        ),
        MAX_FRAGMENT_BYTES,
    )?;
    Ok(clue)
}

fn push_question_preamble(question: &mut String) -> Result<(), RenderError> {
    push_with_limit(question, BYTE_SEMANTICS_PREAMBLE, MAX_QUESTION_BYTES)?;
    push_with_limit(question, HELPER_SEMANTICS_GLOSSARY, MAX_QUESTION_BYTES)
}

fn push_dependency_clues(question: &mut String, clues: &[String]) -> Result<(), RenderError> {
    if clues.is_empty() {
        return Ok(());
    }
    push_with_limit(question, DEPENDENCY_CLUES_HEADER, MAX_QUESTION_BYTES)?;
    for clue in clues {
        push_with_limit(question, clue, MAX_QUESTION_BYTES)?;
    }
    push_with_limit(question, "\n", MAX_QUESTION_BYTES)
}

fn push_final_request(question: &mut String, output_label: &str) -> Result<(), RenderError> {
    push_with_limit(question, DISPLAY_ORDER_WARNING, MAX_QUESTION_BYTES)?;
    push_with_limit(
        question,
        &format!("{OUTPUT_REQUEST_PREFIX}{output_label}{OUTPUT_REQUEST_SUFFIX}"),
        MAX_QUESTION_BYTES,
    )
}

struct OutputLocation {
    output_label: String,
    display_index: usize,
}

fn index_output_locations(
    plan: &RenderPlan,
) -> Result<BTreeMap<NodeId, OutputLocation>, RenderError> {
    let mut locations = BTreeMap::new();
    for (display_index, fragment) in plan.fragments.iter().enumerate() {
        if fragment.distractor {
            continue;
        }
        for step in &fragment.steps {
            if locations
                .insert(
                    step.node,
                    OutputLocation {
                        output_label: step.output_label.clone(),
                        display_index,
                    },
                )
                .is_some()
            {
                return Err(RenderError::DuplicateReference(step.node));
            }
        }
    }
    Ok(locations)
}

fn language_name(language: RenderLanguage) -> &'static str {
    match language {
        RenderLanguage::C => "C",
        RenderLanguage::Cpp => "C++",
        RenderLanguage::Rust => "Rust",
        RenderLanguage::Go => "Go",
        RenderLanguage::Java => "Java",
        RenderLanguage::Pseudocode => "Pseudocode",
    }
}

fn push_with_limit(output: &mut String, value: &str, limit: usize) -> Result<(), RenderError> {
    let length = output
        .len()
        .checked_add(value.len())
        .ok_or(RenderError::LengthLimit)?;
    if length > limit {
        return Err(RenderError::LengthLimit);
    }
    output.push_str(value);
    Ok(())
}

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
        (RenderLanguage::C, TemplateFamily::Direct) => 304,
        (RenderLanguage::C, TemplateFamily::Helper) => 352,
        (RenderLanguage::Cpp, TemplateFamily::Direct) => 304,
        (RenderLanguage::Cpp, TemplateFamily::Helper) => 352,
        (RenderLanguage::Rust, TemplateFamily::Direct) => 304,
        (RenderLanguage::Rust, TemplateFamily::Helper) => 352,
        (RenderLanguage::Go, TemplateFamily::Direct) => 288,
        (RenderLanguage::Go, TemplateFamily::Helper) => 352,
        (RenderLanguage::Java, TemplateFamily::Direct) => 304,
        (RenderLanguage::Java, TemplateFamily::Helper) => 352,
        (RenderLanguage::Pseudocode, TemplateFamily::Direct) => 288,
        (RenderLanguage::Pseudocode, TemplateFamily::Helper) => 352,
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
    use super::{
        MAX_STEP_BYTES, bounded_parts, declared_template_max_bytes, emit_fragment, emit_operation,
        operation_expression,
    };
    use crate::generation::render::error::RenderError;
    use crate::generation::render::model::{RenderLanguage, TemplateFamily};
    use crate::generation::{MAX_CONCAT_INPUTS, MAX_PERMUTATION_LENGTH, Operation};

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

    fn worst_case_operations() -> Vec<(&'static str, Operation, Vec<String>)> {
        let unary = || vec!["source_000000000".to_owned()];
        let binary = || vec!["source_000000000".to_owned(), "source_000000001".to_owned()];
        let ternary = || {
            vec![
                "source_000000000".to_owned(),
                "source_000000001".to_owned(),
                "source_000000002".to_owned(),
            ]
        };

        vec![
            ("reverse", Operation::Reverse, unary()),
            (
                "rotate_left",
                Operation::RotateLeft(u32::MAX as usize),
                unary(),
            ),
            (
                "rotate_right",
                Operation::RotateRight(u32::MAX as usize),
                unary(),
            ),
            ("xor_16", Operation::Xor(vec![u8::MAX; 16]), unary()),
            ("even", Operation::EvenBytes, unary()),
            ("odd", Operation::OddBytes, unary()),
            (
                "permute_16",
                Operation::Permute((0..MAX_PERMUTATION_LENGTH).rev().collect()),
                unary(),
            ),
            (
                "slice",
                Operation::Slice {
                    start: u32::MAX as usize,
                    end: u32::MAX as usize,
                },
                unary(),
            ),
            (
                "concat_13",
                Operation::Concat,
                (0..MAX_CONCAT_INPUTS)
                    .map(|index| format!("source_{index:09}"))
                    .collect(),
            ),
            ("add", Operation::AddModulo, binary()),
            ("sub", Operation::SubModulo, binary()),
            ("hex_encode", Operation::HexEncode, unary()),
            ("hex_decode", Operation::HexDecode, unary()),
            ("base64_encode", Operation::Base64UrlEncode, unary()),
            ("base64_decode", Operation::Base64UrlDecode, unary()),
            ("sha_32", Operation::Sha256Prefix(32), unary()),
            ("rotate_derived", Operation::RotateLeftDerived, binary()),
            ("conditional", Operation::ConditionalOrder, ternary()),
        ]
    }

    fn expected_stable_longest(language: RenderLanguage, family: TemplateFamily) -> usize {
        match (language, family) {
            (RenderLanguage::C, TemplateFamily::Direct) => 295,
            (RenderLanguage::C, TemplateFamily::Helper) => 351,
            (RenderLanguage::Cpp, TemplateFamily::Direct) => 294,
            (RenderLanguage::Cpp, TemplateFamily::Helper) => 349,
            (RenderLanguage::Rust, TemplateFamily::Direct) => 292,
            (RenderLanguage::Rust, TemplateFamily::Helper) => 346,
            (RenderLanguage::Go, TemplateFamily::Direct) => 288,
            (RenderLanguage::Go, TemplateFamily::Helper) => 351,
            (RenderLanguage::Java, TemplateFamily::Direct) => 295,
            (RenderLanguage::Java, TemplateFamily::Helper) => 352,
            (RenderLanguage::Pseudocode, TemplateFamily::Direct) => 288,
            (RenderLanguage::Pseudocode, TemplateFamily::Helper) => 341,
        }
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
    fn every_operation_expression_has_exact_helper_parameters_and_input_order() {
        let cases = [
            (Operation::Reverse, "reverse(source_0)"),
            (Operation::RotateLeft(3), "rotate_left(source_0, 3)"),
            (Operation::RotateRight(2), "rotate_right(source_0, 2)"),
            (Operation::Xor(vec![1, 2]), "xor_repeat(source_0, [1, 2])"),
            (Operation::EvenBytes, "even_bytes(source_0)"),
            (Operation::OddBytes, "odd_bytes(source_0)"),
            (
                Operation::Permute(vec![2, 0, 1]),
                "permute(source_0, [2, 0, 1])",
            ),
            (
                Operation::Slice { start: 1, end: 3 },
                "slice(source_0, 1, 3)",
            ),
            (Operation::Concat, "concat(source_0, source_1, source_2)"),
            (Operation::AddModulo, "add_u8(source_0, source_1)"),
            (Operation::SubModulo, "sub_u8(source_0, source_1)"),
            (Operation::HexEncode, "hex_lower(source_0)"),
            (Operation::HexDecode, "hex_decode_lower(source_0)"),
            (Operation::Base64UrlEncode, "base64url_no_pad(source_0)"),
            (
                Operation::Base64UrlDecode,
                "base64url_decode_no_pad(source_0)",
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
            let input_count = operation.arity().unwrap_or(3);
            let inputs = (0..input_count)
                .map(|index| format!("source_{index}"))
                .collect::<Vec<_>>();

            assert_eq!(operation_expression(&operation, &inputs).unwrap(), expected);
        }
    }

    #[test]
    fn helper_templates_have_stable_language_specific_syntax() {
        let inputs = ["source_0".to_owned()];
        let cases = [
            (
                RenderLanguage::C,
                "bytes local_0() { return reverse(source_0); }\nbytes result_0 = local_0();  // exports result_0",
            ),
            (
                RenderLanguage::Cpp,
                "auto local_0() { return reverse(source_0); }\nauto result_0 = local_0();  // exports result_0",
            ),
            (
                RenderLanguage::Rust,
                "fn local_0() -> Bytes { reverse(source_0) }\nlet result_0 = local_0(); // exports result_0",
            ),
            (
                RenderLanguage::Go,
                "local_0 := func() bytes { return reverse(source_0) }\nresult_0 := local_0() // exports result_0",
            ),
            (
                RenderLanguage::Java,
                "byte[] local_0() { return reverse(source_0); }\nbyte[] result_0 = local_0(); // exports result_0",
            ),
            (
                RenderLanguage::Pseudocode,
                "function local_0: return reverse(source_0)\nresult_0 <- local_0()  # exports result_0",
            ),
        ];

        for (language, expected) in cases {
            assert_eq!(
                emit_operation(
                    language,
                    TemplateFamily::Helper,
                    "result_0",
                    "local_0",
                    &Operation::Reverse,
                    &inputs,
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn bounded_parts_counts_utf8_bytes_and_redacts_rejected_content() {
        let ascii_limit = "A".repeat(MAX_STEP_BYTES);
        assert_eq!(bounded_parts(&[&ascii_limit]).unwrap(), ascii_limit);
        assert_eq!(
            bounded_parts(&[&"A".repeat(MAX_STEP_BYTES + 1)]),
            Err(RenderError::LengthLimit)
        );

        let ascii_over_limit = "SECRET_MARKER".repeat(40);
        assert!(ascii_over_limit.len() > MAX_STEP_BYTES);
        let error = bounded_parts(&[&ascii_over_limit]).unwrap_err();
        assert_eq!(error, RenderError::LengthLimit);
        assert!(!error.to_string().contains("SECRET_MARKER"));
        assert!(!format!("{error:?}").contains("SECRET_MARKER"));

        let utf8_limit = "é".repeat(MAX_STEP_BYTES / 2);
        assert_eq!(utf8_limit.len(), MAX_STEP_BYTES);
        assert_eq!(bounded_parts(&[&utf8_limit]).unwrap(), utf8_limit);
        assert_eq!(
            bounded_parts(&[&utf8_limit, "x"]),
            Err(RenderError::LengthLimit)
        );
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
    fn declarations_strictly_cover_every_worst_case_operation_template() {
        let operations = worst_case_operations();
        assert_eq!(operations.len(), 18);
        let mut measured = Vec::new();

        for language in RenderLanguage::ALL {
            for family in [TemplateFamily::Direct, TemplateFamily::Helper] {
                let declared = declared_template_max_bytes(language, family);
                let mut longest = 0;
                let mut winner = "";

                for (name, operation, inputs) in &operations {
                    let rendered = emit_operation(
                        language,
                        family,
                        "output_000000000",
                        "helper_000000000",
                        operation,
                        inputs,
                    )
                    .unwrap();
                    if rendered.len() > longest {
                        longest = rendered.len();
                        winner = name;
                    }
                    assert!(
                        rendered.len() <= declared,
                        "{language:?} {family:?} {operation:?}: {} > {declared}",
                        rendered.len()
                    );
                }
                assert_eq!(winner, "concat_13");
                assert_eq!(longest, expected_stable_longest(language, family));
                let rounded_longest = longest.div_ceil(16) * 16;
                assert_eq!(
                    declared, rounded_longest,
                    "{language:?} {family:?} declaration is not the smallest 16-byte-rounded bound"
                );
                measured.push((language, family, declared, longest));
            }
        }
        assert!(
            measured
                .iter()
                .all(|(_, _, declared, _)| *declared < MAX_STEP_BYTES),
            "declarations must be strict; measured {measured:?}"
        );
    }

    #[test]
    fn platform_maximum_numeric_parameters_fit_stable_declarations() {
        let inputs = ["source_000000000".to_owned()];
        let operations = [
            Operation::RotateLeft(usize::MAX),
            Operation::RotateRight(usize::MAX),
            Operation::Slice {
                start: usize::MAX,
                end: usize::MAX,
            },
        ];

        for language in RenderLanguage::ALL {
            for family in [TemplateFamily::Direct, TemplateFamily::Helper] {
                for operation in &operations {
                    let rendered = emit_operation(
                        language,
                        family,
                        "output_000000000",
                        "helper_000000000",
                        operation,
                        &inputs,
                    )
                    .unwrap();
                    assert!(rendered.len() <= declared_template_max_bytes(language, family));
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

    #[test]
    fn renderer_accepts_v1_collection_limits_and_rejects_the_next_item() {
        let mut labels = (0..=MAX_CONCAT_INPUTS)
            .map(|index| format!("source_{index:09}"))
            .collect::<Vec<_>>();
        assert!(
            emit_operation(
                RenderLanguage::Rust,
                TemplateFamily::Direct,
                "output_000000000",
                "helper_000000000",
                &Operation::Concat,
                &labels[..MAX_CONCAT_INPUTS],
            )
            .is_ok()
        );
        labels[MAX_CONCAT_INPUTS] = "SECRET_BOUNDARY_MARKER".to_owned();
        let error = emit_operation(
            RenderLanguage::Rust,
            TemplateFamily::Direct,
            "output_000000000",
            "helper_000000000",
            &Operation::Concat,
            &labels,
        )
        .unwrap_err();
        assert_eq!(error, RenderError::InvalidPlan);
        assert!(!error.to_string().contains("SECRET_BOUNDARY_MARKER"));
        assert!(!format!("{error:?}").contains("SECRET_BOUNDARY_MARKER"));

        let input = vec!["source_000000000".to_owned()];
        assert!(
            emit_operation(
                RenderLanguage::Rust,
                TemplateFamily::Direct,
                "output_000000000",
                "helper_000000000",
                &Operation::Permute((0..MAX_PERMUTATION_LENGTH).collect()),
                &input,
            )
            .is_ok()
        );
        assert_eq!(
            emit_operation(
                RenderLanguage::Rust,
                TemplateFamily::Direct,
                "output_000000000",
                "helper_000000000",
                &Operation::Permute((0..=MAX_PERMUTATION_LENGTH).collect()),
                &input,
            ),
            Err(RenderError::InvalidPlan)
        );
    }
}
