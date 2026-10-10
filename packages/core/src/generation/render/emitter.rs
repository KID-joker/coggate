use std::collections::{BTreeMap, BTreeSet};

use crate::generation::{NodeId, Operation, OperationKind};

use super::error::RenderError;
use super::languages;
use super::model::{
    DisplayDistractor, DisplayDistractorStep, DisplayStep, DisplayStepKind, FragmentLiteralPlan,
    HelperSemantic, MAX_FRAGMENT_BYTES, MAX_QUESTION_BYTES, NumericStyle, ObfuscationProfile,
    RenderLanguage, RenderPlan, TemplateFamily,
};

pub(super) const MAX_STEP_BYTES: usize = 512;

const BYTE_SEMANTICS_PREAMBLE: &str = "Treat every value as a byte array. Indices are zero-based and slices use half-open [start,end) ranges. Addition and subtraction use wrapping u8 arithmetic modulo 256. Rotate amounts are reduced modulo the nonempty current array length. Hex is lowercase. Base64url is unpadded base64url. The names below are per-question aliases with the stated mathematical semantics. Parenthesized additions and subtractions are nonnegative integer expressions evaluated mathematically before use. Guard predicates use mathematical arithmetic rendered in a widened integer type; the effective answer follows the true branch.\n\n";
const DEPENDENCY_CLUES_HEADER: &str = "Dependency clues:\n";
const DISPLAY_ORDER_WARNING: &str = "Display order is not evaluation order.\n";
const OUTPUT_REQUEST_PREFIX: &str = "The requested result is output label ";
const OUTPUT_REQUEST_SUFFIX: &str = ". Submit its byte array as unpadded base64url.\n";

#[cfg(test)]
pub(super) fn common_question_bytes(profile: &ObfuscationProfile) -> usize {
    let mut emitted = String::new();
    push_question_preamble(&mut emitted, profile).unwrap();
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
    push_question_preamble(&mut question, &plan.profile)?;

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

        push_with_limit(
            &mut rendered_fragment,
            &format!("Section identifier: {}\n", display_fragment.heading),
            MAX_FRAGMENT_BYTES,
        )?;

        for step in &display_fragment.steps {
            let emitted = match &step.kind {
                DisplayStepKind::Fragment { index } => emit_fragment(
                    display_fragment.language,
                    step,
                    &plan.profile,
                    fragments.get(*index).ok_or(RenderError::InvalidPlan)?,
                )?,
                DisplayStepKind::Operation {
                    operation: _,
                    inputs,
                } => {
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
                        step,
                        &plan.profile,
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
                    if producer.display_index != display_index && seen_producers.insert(*input) {
                        producers.push((producer.output_label.as_str(), producer.display_index));
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

        let accounted_fragment_bytes = rendered_fragment
            .len()
            .checked_add(dependency_bytes_by_fragment[display_index])
            .ok_or(RenderError::LengthLimit)?;
        if accounted_fragment_bytes > MAX_FRAGMENT_BYTES {
            return Err(RenderError::LengthLimit);
        }

        push_with_limit(&mut question, &rendered_fragment, MAX_QUESTION_BYTES)?;
    }

    if let Some(distractor) = &plan.distractor {
        let rendered = emit_distractor(distractor, &plan.profile)?;
        push_with_limit(&mut question, &rendered, MAX_QUESTION_BYTES)?;
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

fn push_question_preamble(
    question: &mut String,
    profile: &ObfuscationProfile,
) -> Result<(), RenderError> {
    push_with_limit(question, BYTE_SEMANTICS_PREAMBLE, MAX_QUESTION_BYTES)?;
    push_with_limit(question, "Alias semantics:\n", MAX_QUESTION_BYTES)?;
    for (semantic, alias) in profile.aliases() {
        push_with_limit(question, alias, MAX_QUESTION_BYTES)?;
        push_with_limit(
            question,
            helper_semantic_definition(*semantic),
            MAX_QUESTION_BYTES,
        )?;
        push_with_limit(question, "\n", MAX_QUESTION_BYTES)?;
    }
    push_with_limit(question, "\n", MAX_QUESTION_BYTES)
}

fn helper_semantic_definition(semantic: HelperSemantic) -> &'static str {
    match semantic {
        HelperSemantic::BytesAscii => {
            "(text): the bytes represented by the escaped ASCII literal text."
        }
        HelperSemantic::Operation(OperationKind::Reverse) => {
            "(x): returns the input bytes in opposite positional order."
        }
        HelperSemantic::Operation(OperationKind::RotateLeft) => {
            "(x, n): cyclically rotate x left by n modulo len(x); x must be nonempty."
        }
        HelperSemantic::Operation(OperationKind::RotateRight) => {
            "(x, n): cyclically rotate x right by n modulo len(x); x must be nonempty."
        }
        HelperSemantic::Operation(OperationKind::EvenBytes) => {
            "(x): the bytes of x at zero-based indices 0, 2, and so on."
        }
        HelperSemantic::Operation(OperationKind::OddBytes) => {
            "(x): the bytes of x at zero-based indices 1, 3, and so on."
        }
        HelperSemantic::Operation(OperationKind::Permute) => {
            "(x, p): output byte j is x at index p[j]."
        }
        HelperSemantic::Operation(OperationKind::Slice) => {
            "(x, start, end): returns x[i] in increasing index order for start <= i < end."
        }
        HelperSemantic::Operation(OperationKind::Xor) => {
            "(x, key): output byte i is x[i] XOR key[i modulo len(key)]."
        }
        HelperSemantic::Operation(OperationKind::AddModulo) => {
            "(x, y): output byte i is x[i] plus y[i] modulo 256."
        }
        HelperSemantic::Operation(OperationKind::SubModulo) => {
            "(x, y): output byte i is x[i] minus y[i] modulo 256."
        }
        HelperSemantic::Operation(OperationKind::HexEncode) => {
            "(x): encode x as canonical lowercase hexadecimal ASCII bytes."
        }
        HelperSemantic::Operation(OperationKind::HexDecode) => {
            "(x): decode canonical lowercase hexadecimal ASCII bytes x."
        }
        HelperSemantic::Operation(OperationKind::Base64UrlEncode) => {
            "(x): encode x as canonical unpadded base64url ASCII bytes."
        }
        HelperSemantic::Operation(OperationKind::Base64UrlDecode) => {
            "(x): decode canonical unpadded base64url ASCII bytes x."
        }
        HelperSemantic::Operation(OperationKind::Sha256Prefix) => {
            "(x, n): the first n raw bytes of the SHA-256 digest of x."
        }
        HelperSemantic::Operation(OperationKind::Concat) => {
            "(x1, x2, ...): concatenate all inputs in their listed order."
        }
        HelperSemantic::Operation(OperationKind::RotateLeftDerived) => {
            "(x, key): cyclically rotate x left by unsigned key[0] modulo len(x); both inputs must be nonempty."
        }
        HelperSemantic::Operation(OperationKind::ConditionalOrder) => {
            "(control, a, b): a followed by b when unsigned control[0] is even; otherwise b followed by a."
        }
    }
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
    step: &DisplayStep,
    profile: &ObfuscationProfile,
    inputs: &[String],
) -> Result<String, RenderError> {
    let DisplayStepKind::Operation { operation, .. } = &step.kind else {
        return Err(RenderError::InvalidPlan);
    };
    operation
        .validate_arity(inputs.len())
        .map_err(|_| RenderError::InvalidPlan)?;
    let expression = operation_expression(operation, inputs, step.numeric_style, profile)?;
    emit_step_assignment(language, step, profile, &expression)
}

pub(super) fn emit_fragment(
    language: RenderLanguage,
    step: &DisplayStep,
    profile: &ObfuscationProfile,
    value: &[u8],
) -> Result<String, RenderError> {
    if value.is_empty() || value.len() > 16 || !value.iter().all(u8::is_ascii_alphanumeric) {
        return Err(RenderError::InvalidPlan);
    }
    if !matches!(step.kind, DisplayStepKind::Fragment { .. }) {
        return Err(RenderError::InvalidPlan);
    }
    let literal_plan = step.literal_plan.as_ref().ok_or(RenderError::InvalidPlan)?;
    let expression =
        fragment_expression(language, value, literal_plan, step.numeric_style, profile)?;
    emit_step_assignment(language, step, profile, &expression)
}

fn emit_step_assignment(
    language: RenderLanguage,
    step: &DisplayStep,
    profile: &ObfuscationProfile,
    expression: &str,
) -> Result<String, RenderError> {
    emit_assignment(
        language,
        step.template,
        &step.output_label,
        &step.local_name,
        step.guard_value,
        profile,
        expression,
    )
}

fn emit_assignment(
    language: RenderLanguage,
    template: TemplateFamily,
    output_label: &str,
    local_name: &str,
    guard_value: Option<u8>,
    profile: &ObfuscationProfile,
    expression: &str,
) -> Result<String, RenderError> {
    let decoy_expression = match (template, guard_value) {
        (TemplateFamily::Guarded, Some(_)) => {
            let bytes_alias = profile
                .alias(HelperSemantic::BytesAscii)
                .ok_or(RenderError::InvalidPlan)?;
            Some(bytes_call(bytes_alias, b"A")?)
        }
        (TemplateFamily::Direct | TemplateFamily::Helper | TemplateFamily::AliasChain, None) => {
            None
        }
        _ => return Err(RenderError::InvalidPlan),
    };
    languages::emit_assignment(
        language,
        template,
        output_label,
        local_name,
        expression,
        guard_value,
        decoy_expression.as_deref(),
    )
}

pub(super) fn emit_distractor(
    distractor: &DisplayDistractor,
    profile: &ObfuscationProfile,
) -> Result<String, RenderError> {
    let mut rendered = String::new();
    push_with_limit(
        &mut rendered,
        &format!(
            "[Unrelated scratch calculation — {}]\nSection identifier: {}\nThis is an unrelated scratch calculation; ignore it. It is not part of the requested result.\n",
            language_name(distractor.language),
            distractor.heading
        ),
        MAX_FRAGMENT_BYTES,
    )?;
    let mut previous = fragment_expression(
        distractor.language,
        &distractor.seed_value,
        &distractor.literal_plan,
        NumericStyle::Decimal,
        profile,
    )?;
    for step in &distractor.steps {
        let operation = step.operation.operation();
        let expression = operation_expression(
            &operation,
            std::slice::from_ref(&previous),
            step.numeric_style,
            profile,
        )?;
        let emitted = emit_distractor_step(distractor.language, step, profile, &expression)?;
        push_with_limit(&mut rendered, &emitted, MAX_FRAGMENT_BYTES)?;
        push_with_limit(&mut rendered, "\n", MAX_FRAGMENT_BYTES)?;
        previous.clone_from(&step.output_label);
    }
    push_with_limit(&mut rendered, "\n", MAX_FRAGMENT_BYTES)?;
    Ok(rendered)
}

fn emit_distractor_step(
    language: RenderLanguage,
    step: &DisplayDistractorStep,
    profile: &ObfuscationProfile,
    expression: &str,
) -> Result<String, RenderError> {
    emit_assignment(
        language,
        step.template,
        &step.output_label,
        &step.local_name,
        step.guard_value,
        profile,
        expression,
    )
}

pub(super) fn declared_template_max_bytes(
    language: RenderLanguage,
    family: TemplateFamily,
) -> usize {
    match (language, family) {
        (RenderLanguage::C, TemplateFamily::Direct) => 416,
        (RenderLanguage::C, TemplateFamily::Helper) => 464,
        (RenderLanguage::C, TemplateFamily::AliasChain) => 464,
        (RenderLanguage::C, TemplateFamily::Guarded) => 496,
        (RenderLanguage::Cpp, TemplateFamily::Direct) => 416,
        (RenderLanguage::Cpp, TemplateFamily::Helper) => 464,
        (RenderLanguage::Cpp, TemplateFamily::AliasChain) => 464,
        (RenderLanguage::Cpp, TemplateFamily::Guarded) => 512,
        (RenderLanguage::Rust, TemplateFamily::Direct) => 400,
        (RenderLanguage::Rust, TemplateFamily::Helper) => 448,
        (RenderLanguage::Rust, TemplateFamily::AliasChain) => 448,
        (RenderLanguage::Rust, TemplateFamily::Guarded) => 496,
        (RenderLanguage::Go, TemplateFamily::Direct) => 400,
        (RenderLanguage::Go, TemplateFamily::Helper) => 464,
        (RenderLanguage::Go, TemplateFamily::AliasChain) => 432,
        (RenderLanguage::Go, TemplateFamily::Guarded) => 512,
        (RenderLanguage::Java, TemplateFamily::Direct) => 416,
        (RenderLanguage::Java, TemplateFamily::Helper) => 480,
        (RenderLanguage::Java, TemplateFamily::AliasChain) => 464,
        (RenderLanguage::Java, TemplateFamily::Guarded) => 512,
        (RenderLanguage::Pseudocode, TemplateFamily::Direct) => 400,
        (RenderLanguage::Pseudocode, TemplateFamily::Helper) => 448,
        (RenderLanguage::Pseudocode, TemplateFamily::AliasChain) => 432,
        (RenderLanguage::Pseudocode, TemplateFamily::Guarded) => 496,
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

pub(super) fn render_number(
    value: usize,
    numeric_style: NumericStyle,
) -> Result<String, RenderError> {
    match numeric_style {
        NumericStyle::Decimal => Ok(value.to_string()),
        NumericStyle::LowerHex => Ok(format!("0x{value:x}")),
        NumericStyle::IdentityOffset { delta } if (1..=15).contains(&delta) => {
            Ok(format!("(({value} + {delta}) - {delta})"))
        }
        NumericStyle::IdentityOffset { .. } => Err(RenderError::InvalidPlan),
    }
}

fn push_number(
    output: &mut String,
    value: usize,
    numeric_style: NumericStyle,
) -> Result<(), RenderError> {
    push_bounded(output, &render_number(value, numeric_style)?)
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

fn operation_expression(
    operation: &Operation,
    inputs: &[String],
    numeric_style: NumericStyle,
    profile: &ObfuscationProfile,
) -> Result<String, RenderError> {
    let helper = profile
        .alias(HelperSemantic::Operation(OperationKind::from(operation)))
        .ok_or(RenderError::InvalidPlan)?;
    let mut output = String::new();
    match operation {
        Operation::Reverse => push_call(&mut output, helper, inputs)?,
        Operation::RotateLeft(amount) => {
            push_call(&mut output, helper, inputs)?;
            push_bounded(&mut output, ", ")?;
            push_number(&mut output, *amount, numeric_style)?;
        }
        Operation::RotateRight(amount) => {
            push_call(&mut output, helper, inputs)?;
            push_bounded(&mut output, ", ")?;
            push_number(&mut output, *amount, numeric_style)?;
        }
        Operation::Xor(key) => {
            push_call(&mut output, helper, inputs)?;
            push_bounded(&mut output, ", ")?;
            push_list(&mut output, key, |target, value| {
                push_number(target, usize::from(*value), numeric_style)
            })?;
        }
        Operation::EvenBytes | Operation::OddBytes => push_call(&mut output, helper, inputs)?,
        Operation::Permute(permutation) => {
            push_call(&mut output, helper, inputs)?;
            push_bounded(&mut output, ", ")?;
            push_list(&mut output, permutation, |target, value| {
                push_number(target, *value, numeric_style)
            })?;
        }
        Operation::Slice { start, end } => {
            push_call(&mut output, helper, inputs)?;
            push_bounded(&mut output, ", ")?;
            push_number(&mut output, *start, numeric_style)?;
            push_bounded(&mut output, ", ")?;
            push_number(&mut output, *end, numeric_style)?;
        }
        Operation::Concat
        | Operation::AddModulo
        | Operation::SubModulo
        | Operation::HexEncode
        | Operation::HexDecode
        | Operation::Base64UrlEncode
        | Operation::Base64UrlDecode
        | Operation::RotateLeftDerived
        | Operation::ConditionalOrder => push_call(&mut output, helper, inputs)?,
        Operation::Sha256Prefix(prefix_length) => {
            push_call(&mut output, helper, inputs)?;
            push_bounded(&mut output, ", ")?;
            push_number(&mut output, *prefix_length, numeric_style)?;
        }
    }
    push_bounded(&mut output, ")")?;
    Ok(output)
}

fn fragment_expression(
    language: RenderLanguage,
    value: &[u8],
    literal_plan: &FragmentLiteralPlan,
    numeric_style: NumericStyle,
    profile: &ObfuscationProfile,
) -> Result<String, RenderError> {
    let bytes_alias = profile
        .alias(HelperSemantic::BytesAscii)
        .ok_or(RenderError::InvalidPlan)?;
    let mut reconstructed = Vec::with_capacity(value.len());
    let expression = match literal_plan {
        FragmentLiteralPlan::Whole => {
            reconstructed.extend_from_slice(value);
            bytes_call(bytes_alias, value)?
        }
        FragmentLiteralPlan::OrderedChunks(chunks) => {
            validate_emitted_chunks(chunks, value.len())?;
            if !chunks.windows(2).all(|pair| pair[0].end == pair[1].start)
                || chunks.first().is_none_or(|chunk| chunk.start != 0)
                || chunks.last().is_none_or(|chunk| chunk.end != value.len())
            {
                return Err(RenderError::InvalidPlan);
            }
            let concat_alias = concat_alias(profile)?;
            let mut calls = Vec::with_capacity(chunks.len());
            for chunk in chunks {
                let bytes = value.get(chunk.clone()).ok_or(RenderError::InvalidPlan)?;
                reconstructed.extend_from_slice(bytes);
                calls.push(bytes_call(bytes_alias, bytes)?);
            }
            complete_call(concat_alias, &calls)?
        }
        FragmentLiteralPlan::ShuffledChunks {
            chunks,
            restore_order,
        } => {
            validate_emitted_chunks(chunks, value.len())?;
            if restore_order.len() != chunks.len()
                || restore_order.iter().copied().collect::<BTreeSet<_>>()
                    != (0..chunks.len()).collect()
            {
                return Err(RenderError::InvalidPlan);
            }
            let restored_ranges = restore_order
                .iter()
                .map(|index| chunks[*index].clone())
                .collect::<Vec<_>>();
            if restored_ranges.first().is_none_or(|chunk| chunk.start != 0)
                || restored_ranges
                    .last()
                    .is_none_or(|chunk| chunk.end != value.len())
                || !restored_ranges
                    .windows(2)
                    .all(|pair| pair[0].end == pair[1].start)
                || chunks == &restored_ranges
            {
                return Err(RenderError::InvalidPlan);
            }
            let concat_alias = concat_alias(profile)?;
            let displayed = chunks
                .iter()
                .map(|chunk| {
                    value
                        .get(chunk.clone())
                        .ok_or(RenderError::InvalidPlan)
                        .and_then(|bytes| bytes_call(bytes_alias, bytes))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut restored_calls = Vec::with_capacity(restore_order.len());
            for display_index in restore_order {
                let chunk = chunks.get(*display_index).ok_or(RenderError::InvalidPlan)?;
                reconstructed
                    .extend_from_slice(value.get(chunk.clone()).ok_or(RenderError::InvalidPlan)?);
                restored_calls.push(languages::emit_inline_chunk_lookup(
                    language,
                    &displayed,
                    &render_number(*display_index, numeric_style)?,
                )?);
            }
            complete_call(concat_alias, &restored_calls)?
        }
    };
    if reconstructed != value {
        return Err(RenderError::InvalidPlan);
    }
    Ok(expression)
}

fn concat_alias(profile: &ObfuscationProfile) -> Result<&str, RenderError> {
    profile
        .alias(HelperSemantic::Operation(OperationKind::Concat))
        .ok_or(RenderError::InvalidPlan)
}

fn bytes_call(alias: &str, value: &[u8]) -> Result<String, RenderError> {
    let value = std::str::from_utf8(value).map_err(|_| RenderError::InvalidPlan)?;
    let mut escaped = String::new();
    for character in value.chars() {
        for escaped_character in character.escape_default() {
            push_bounded(&mut escaped, &escaped_character.to_string())?;
        }
    }
    bounded_parts(&[alias, "(\"", &escaped, "\")"])
}

fn complete_call(helper: &str, inputs: &[String]) -> Result<String, RenderError> {
    let mut output = String::new();
    push_call(&mut output, helper, inputs)?;
    push_bounded(&mut output, ")")?;
    Ok(output)
}

fn validate_emitted_chunks(
    chunks: &[std::ops::Range<usize>],
    source_length: usize,
) -> Result<(), RenderError> {
    if !(2..=3).contains(&chunks.len()) || (chunks.len() == 3 && source_length < 3) {
        return Err(RenderError::InvalidPlan);
    }
    if chunks
        .iter()
        .any(|chunk| chunk.start >= chunk.end || chunk.end > source_length)
    {
        return Err(RenderError::InvalidPlan);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        MAX_STEP_BYTES, bounded_parts, declared_template_max_bytes,
        emit_fragment as emit_fragment_step, emit_operation as emit_operation_step, emit_question,
        fragment_expression, helper_semantic_definition,
        operation_expression as operation_expression_step, render_number,
    };
    use crate::generation::render::error::RenderError;
    use crate::generation::render::model::{
        DisplayDistractor, DisplayDistractorStep, DisplayFragment, DisplayStep, DisplayStepKind,
        DistractorOperation, FragmentLiteralPlan, HelperSemantic, NumericStyle, ObfuscationProfile,
        RenderLanguage, RenderPlan, TemplateFamily,
    };
    use crate::generation::render::names::LEGACY_HELPER_IDENTIFIERS;
    use crate::generation::{
        MAX_CONCAT_INPUTS, MAX_PERMUTATION_LENGTH, NodeId, Operation, OperationKind,
    };

    fn operation_alias(operation: &Operation) -> &'static str {
        match operation {
            Operation::Reverse => "reverse",
            Operation::RotateLeft(_) => "rotate_left",
            Operation::RotateRight(_) => "rotate_right",
            Operation::Xor(_) => "xor_repeat",
            Operation::EvenBytes => "even_bytes",
            Operation::OddBytes => "odd_bytes",
            Operation::Permute(_) => "permute",
            Operation::Slice { .. } => "slice",
            Operation::Concat => "concat",
            Operation::AddModulo => "add_u8",
            Operation::SubModulo => "sub_u8",
            Operation::HexEncode => "hex_lower",
            Operation::HexDecode => "hex_decode_lower",
            Operation::Base64UrlEncode => "base64url_no_pad",
            Operation::Base64UrlDecode => "base64url_decode_no_pad",
            Operation::Sha256Prefix(_) => "sha256_prefix",
            Operation::RotateLeftDerived => "rotate_left_derived",
            Operation::ConditionalOrder => "conditional_order",
        }
    }

    fn operation_profile(operation: &Operation) -> ObfuscationProfile {
        ObfuscationProfile::new(BTreeMap::from([
            (HelperSemantic::BytesAscii, "bytes_ascii".to_owned()),
            (
                HelperSemantic::Operation(OperationKind::from(operation)),
                operation_alias(operation).to_owned(),
            ),
        ]))
    }

    fn operation_step(
        family: TemplateFamily,
        output_label: &str,
        local_name: &str,
        operation: &Operation,
    ) -> DisplayStep {
        DisplayStep {
            node: NodeId(0),
            output_label: output_label.to_owned(),
            local_name: local_name.to_owned(),
            template: family,
            numeric_style: NumericStyle::Decimal,
            literal_plan: None,
            guard_value: (family == TemplateFamily::Guarded).then_some(0),
            kind: DisplayStepKind::Operation {
                operation: operation.clone(),
                inputs: Vec::new(),
            },
        }
    }

    fn emit_operation(
        language: RenderLanguage,
        family: TemplateFamily,
        output_label: &str,
        local_name: &str,
        operation: &Operation,
        inputs: &[String],
    ) -> Result<String, RenderError> {
        emit_operation_step(
            language,
            &operation_step(family, output_label, local_name, operation),
            &operation_profile(operation),
            inputs,
        )
    }

    fn emit_fragment(
        language: RenderLanguage,
        family: TemplateFamily,
        output_label: &str,
        local_name: &str,
        value: &[u8],
    ) -> Result<String, RenderError> {
        let step = DisplayStep {
            node: NodeId(0),
            output_label: output_label.to_owned(),
            local_name: local_name.to_owned(),
            template: family,
            numeric_style: NumericStyle::Decimal,
            literal_plan: Some(FragmentLiteralPlan::Whole),
            guard_value: (family == TemplateFamily::Guarded).then_some(0),
            kind: DisplayStepKind::Fragment { index: 0 },
        };
        let profile = ObfuscationProfile::new(BTreeMap::from([(
            HelperSemantic::BytesAscii,
            "bytes_ascii".to_owned(),
        )]));
        emit_fragment_step(language, &step, &profile, value)
    }

    fn operation_expression(
        operation: &Operation,
        inputs: &[String],
    ) -> Result<String, RenderError> {
        operation_expression_step(
            operation,
            inputs,
            NumericStyle::Decimal,
            &operation_profile(operation),
        )
    }

    #[test]
    fn question_uses_only_profile_aliases_for_definitions_and_expressions() {
        let mut plan = RenderPlan {
            fragments: vec![DisplayFragment {
                heading: "section".to_owned(),
                language: RenderLanguage::Rust,
                steps: vec![
                    DisplayStep {
                        node: NodeId(0),
                        output_label: "source".to_owned(),
                        local_name: "load".to_owned(),
                        template: TemplateFamily::Direct,
                        numeric_style: NumericStyle::Decimal,
                        literal_plan: Some(FragmentLiteralPlan::Whole),
                        guard_value: None,
                        kind: DisplayStepKind::Fragment { index: 0 },
                    },
                    DisplayStep {
                        node: NodeId(1),
                        output_label: "result".to_owned(),
                        local_name: "turn_local".to_owned(),
                        template: TemplateFamily::Direct,
                        numeric_style: NumericStyle::Decimal,
                        literal_plan: None,
                        guard_value: None,
                        kind: DisplayStepKind::Operation {
                            operation: Operation::Reverse,
                            inputs: vec![NodeId(0)],
                        },
                    },
                ],
            }],
            output: NodeId(1),
            profile: ObfuscationProfile::new(BTreeMap::from([
                (HelperSemantic::BytesAscii, "mkbytes".to_owned()),
                (
                    HelperSemantic::Operation(OperationKind::Reverse),
                    "turn".to_owned(),
                ),
            ])),
            distractor: None,
        };

        for language in RenderLanguage::ALL {
            plan.fragments[0].language = language;
            let question = emit_question(&plan, &[b"Ab".to_vec()]).unwrap();

            assert!(question.contains("mkbytes(\"Ab\")"));
            assert!(question.contains("turn(source)"));
            assert!(question.contains("mkbytes(text):"));
            assert!(question.contains("turn(x):"));
            assert_eq!(question.matches("mkbytes(text):").count(), 1);
            assert_eq!(question.matches("turn(x):").count(), 1);
            assert!(question.find("mkbytes(text):") < question.find("turn(x):"));
            assert!(!question.contains("bytes_ascii"));
            assert!(!question.contains("reverse("));
            assert!(!question.contains("rotate_left"));
        }

        let first = emit_question(&plan, &[b"Ab".to_vec()]).unwrap();
        plan.profile = ObfuscationProfile::new(BTreeMap::from([
            (HelperSemantic::BytesAscii, "forge".to_owned()),
            (
                HelperSemantic::Operation(OperationKind::Reverse),
                "mirror".to_owned(),
            ),
        ]));
        let second = emit_question(&plan, &[b"Ab".to_vec()]).unwrap();
        assert_ne!(first, second);
        assert!(second.contains("forge(\"Ab\")"));
        assert!(second.contains("mirror(source)"));
    }

    #[test]
    fn distractor_is_explicitly_irrelevant_and_emits_only_its_seed_chain_names() {
        let plan = RenderPlan {
            fragments: vec![DisplayFragment {
                heading: "effective_heading".to_owned(),
                language: RenderLanguage::Go,
                steps: vec![DisplayStep {
                    node: NodeId(0),
                    output_label: "requested_output".to_owned(),
                    local_name: "effective_local".to_owned(),
                    template: TemplateFamily::Direct,
                    numeric_style: NumericStyle::Decimal,
                    literal_plan: Some(FragmentLiteralPlan::Whole),
                    guard_value: None,
                    kind: DisplayStepKind::Fragment { index: 0 },
                }],
            }],
            output: NodeId(0),
            profile: ObfuscationProfile::new(BTreeMap::from([
                (HelperSemantic::BytesAscii, "bytes_alias".to_owned()),
                (
                    HelperSemantic::Operation(OperationKind::Reverse),
                    "turn_alias".to_owned(),
                ),
                (
                    HelperSemantic::Operation(OperationKind::Xor),
                    "mask_alias".to_owned(),
                ),
            ])),
            distractor: Some(DisplayDistractor {
                heading: "scratch_heading".to_owned(),
                language: RenderLanguage::Rust,
                seed_value: b"Seed7".to_vec(),
                literal_plan: FragmentLiteralPlan::Whole,
                steps: vec![
                    DisplayDistractorStep {
                        output_label: "scratch_one".to_owned(),
                        local_name: "scratch_local_one".to_owned(),
                        template: TemplateFamily::Direct,
                        numeric_style: NumericStyle::Decimal,
                        guard_value: None,
                        operation: DistractorOperation::Reverse,
                    },
                    DisplayDistractorStep {
                        output_label: "scratch_two".to_owned(),
                        local_name: "scratch_local_two".to_owned(),
                        template: TemplateFamily::Direct,
                        numeric_style: NumericStyle::Decimal,
                        guard_value: None,
                        operation: DistractorOperation::Xor(vec![7]),
                    },
                ],
            }),
        };

        let question = emit_question(&plan, &[b"Ab".to_vec()]).unwrap();
        let scratch_start = question.find("[Unrelated scratch calculation").unwrap();
        let scratch_end = question[scratch_start..]
            .find("Display order is not evaluation order.")
            .map(|offset| scratch_start + offset)
            .unwrap();
        let scratch = &question[scratch_start..scratch_end];

        assert!(scratch.contains("ignore it"));
        assert!(scratch.contains("not part of the requested result"));
        assert!(scratch.contains("turn_alias(bytes_alias(\"Seed7\"))"));
        assert!(scratch.contains("mask_alias(scratch_one, [7])"));
        for effective_name in ["effective_heading", "requested_output", "effective_local"] {
            assert!(!scratch.contains(effective_name));
        }
        assert!(scratch.contains("scratch_one"));
        assert!(scratch.contains("scratch_two"));
        assert!(!scratch.contains("scratch_local_one"));
        assert!(!scratch.contains("scratch_local_two"));
    }

    #[test]
    fn every_helper_definition_declares_exact_ordered_parameters() {
        let cases = [
            (HelperSemantic::BytesAscii, "(text):"),
            (HelperSemantic::Operation(OperationKind::Reverse), "(x):"),
            (
                HelperSemantic::Operation(OperationKind::RotateLeft),
                "(x, n):",
            ),
            (
                HelperSemantic::Operation(OperationKind::RotateRight),
                "(x, n):",
            ),
            (HelperSemantic::Operation(OperationKind::EvenBytes), "(x):"),
            (HelperSemantic::Operation(OperationKind::OddBytes), "(x):"),
            (HelperSemantic::Operation(OperationKind::Permute), "(x, p):"),
            (
                HelperSemantic::Operation(OperationKind::Slice),
                "(x, start, end):",
            ),
            (HelperSemantic::Operation(OperationKind::Xor), "(x, key):"),
            (
                HelperSemantic::Operation(OperationKind::AddModulo),
                "(x, y):",
            ),
            (
                HelperSemantic::Operation(OperationKind::SubModulo),
                "(x, y):",
            ),
            (HelperSemantic::Operation(OperationKind::HexEncode), "(x):"),
            (HelperSemantic::Operation(OperationKind::HexDecode), "(x):"),
            (
                HelperSemantic::Operation(OperationKind::Base64UrlEncode),
                "(x):",
            ),
            (
                HelperSemantic::Operation(OperationKind::Base64UrlDecode),
                "(x):",
            ),
            (
                HelperSemantic::Operation(OperationKind::Sha256Prefix),
                "(x, n):",
            ),
            (
                HelperSemantic::Operation(OperationKind::Concat),
                "(x1, x2, ...):",
            ),
            (
                HelperSemantic::Operation(OperationKind::RotateLeftDerived),
                "(x, key):",
            ),
            (
                HelperSemantic::Operation(OperationKind::ConditionalOrder),
                "(control, a, b):",
            ),
        ];
        assert_eq!(cases.len(), OperationKind::ALL.len() + 1);
        for (semantic, parameters) in cases {
            let definition = helper_semantic_definition(semantic);
            assert!(definition.starts_with(parameters));
            let tokens = definition
                .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .collect::<BTreeSet<_>>();
            for legacy in LEGACY_HELPER_IDENTIFIERS {
                assert!(!tokens.contains(legacy), "{semantic:?} leaked {legacy}");
            }
        }

        let slice = helper_semantic_definition(HelperSemantic::Operation(OperationKind::Slice));
        assert!(slice.contains("start <= i < end"));
        assert!(!slice.contains("through end"));
    }

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
            ("rotate_left", Operation::RotateLeft(usize::MAX), unary()),
            ("rotate_right", Operation::RotateRight(usize::MAX), unary()),
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
                    start: usize::MAX,
                    end: usize::MAX,
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
            (_, TemplateFamily::AliasChain | TemplateFamily::Guarded) => 0,
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

    fn evaluate_rendered_number(rendered: &str) -> u128 {
        if let Some(hex) = rendered.strip_prefix("0x") {
            return u128::from_str_radix(hex, 16).unwrap();
        }
        if let Some(expression) = rendered
            .strip_prefix("((")
            .and_then(|value| value.strip_suffix(")"))
        {
            let (sum, delta) = expression.split_once(" - ").unwrap();
            let sum = sum.strip_suffix(')').unwrap();
            let (value, added) = sum.split_once(" + ").unwrap();
            return value.parse::<u128>().unwrap() + added.parse::<u128>().unwrap()
                - delta.parse::<u128>().unwrap();
        }
        rendered.parse().unwrap()
    }

    #[test]
    fn every_numeric_style_is_exact_and_evaluates_to_the_original_integer() {
        let styles = [
            NumericStyle::Decimal,
            NumericStyle::LowerHex,
            NumericStyle::IdentityOffset { delta: 7 },
        ];
        for value in [0, 1, 15, 255, usize::MAX] {
            for style in styles {
                let rendered = render_number(value, style).unwrap();
                assert_eq!(evaluate_rendered_number(&rendered), value as u128);
                match style {
                    NumericStyle::Decimal => assert_eq!(rendered, value.to_string()),
                    NumericStyle::LowerHex => assert_eq!(rendered, format!("0x{value:x}")),
                    NumericStyle::IdentityOffset { delta } => {
                        assert_eq!(rendered, format!("(({value} + {delta}) - {delta})"));
                    }
                }
            }
        }
        for delta in [0, 16, u8::MAX] {
            assert_eq!(
                render_number(7, NumericStyle::IdentityOffset { delta }),
                Err(RenderError::InvalidPlan)
            );
        }
    }

    #[test]
    fn dynamic_operation_alias_and_numeric_style_cover_every_parameter_position() {
        let cases = [
            Operation::RotateLeft(3),
            Operation::RotateRight(4),
            Operation::Xor(vec![1, 15, 255]),
            Operation::Permute(vec![2, 0, 1]),
            Operation::Slice { start: 1, end: 3 },
            Operation::Sha256Prefix(8),
        ];
        let styles = [
            NumericStyle::Decimal,
            NumericStyle::LowerHex,
            NumericStyle::IdentityOffset { delta: 7 },
        ];
        for operation in cases {
            let inputs = ["source".to_owned()];
            let profile = ObfuscationProfile::new(BTreeMap::from([(
                HelperSemantic::Operation(OperationKind::from(&operation)),
                "dynop".to_owned(),
            )]));
            for style in styles {
                let expression =
                    operation_expression_step(&operation, &inputs, style, &profile).unwrap();
                assert!(expression.starts_with("dynop(source"));
                let parameter_values = match &operation {
                    Operation::RotateLeft(value) | Operation::RotateRight(value) => vec![*value],
                    Operation::Xor(values) => values.iter().map(|value| *value as usize).collect(),
                    Operation::Permute(values) => values.clone(),
                    Operation::Slice { start, end } => vec![*start, *end],
                    Operation::Sha256Prefix(value) => vec![*value],
                    _ => unreachable!(),
                };
                for value in parameter_values {
                    assert!(expression.contains(&render_number(value, style).unwrap()));
                }
            }
        }

        for operation in operations() {
            let input_count = operation.arity().unwrap_or(3);
            let inputs = (0..input_count)
                .map(|index| format!("source_{index}"))
                .collect::<Vec<_>>();
            let profile = ObfuscationProfile::new(BTreeMap::from([(
                HelperSemantic::Operation(OperationKind::from(&operation)),
                "dynamic_alias".to_owned(),
            )]));
            let expression =
                operation_expression_step(&operation, &inputs, NumericStyle::LowerHex, &profile)
                    .unwrap();
            assert!(expression.starts_with("dynamic_alias("));
            for (position, input) in inputs.iter().enumerate() {
                let offset = expression.find(input).unwrap();
                if position > 0 {
                    assert!(offset > expression.find(&inputs[position - 1]).unwrap());
                }
            }
        }
    }

    #[test]
    fn all_literal_plans_reconstruct_exact_bytes_in_every_language() {
        let value = b"abcdef";
        let profile = ObfuscationProfile::new(BTreeMap::from([
            (HelperSemantic::BytesAscii, "mk".to_owned()),
            (
                HelperSemantic::Operation(OperationKind::Concat),
                "join".to_owned(),
            ),
        ]));
        let whole = FragmentLiteralPlan::Whole;
        let ordered = FragmentLiteralPlan::OrderedChunks(vec![0..2, 2..4, 4..6]);
        let shuffled = FragmentLiteralPlan::ShuffledChunks {
            chunks: vec![2..4, 0..2, 4..6],
            restore_order: vec![1, 0, 2],
        };

        for language in RenderLanguage::ALL {
            assert_eq!(
                fragment_expression(
                    language,
                    value,
                    &whole,
                    NumericStyle::IdentityOffset { delta: 7 },
                    &profile,
                )
                .unwrap(),
                "mk(\"abcdef\")"
            );
            assert_eq!(
                fragment_expression(
                    language,
                    value,
                    &ordered,
                    NumericStyle::IdentityOffset { delta: 7 },
                    &profile,
                )
                .unwrap(),
                "join(mk(\"ab\"), mk(\"cd\"), mk(\"ef\"))"
            );

            let table = match language {
                RenderLanguage::C => "((bytes[]){mk(\"cd\"), mk(\"ab\"), mk(\"ef\")})",
                RenderLanguage::Cpp => "(std::array{mk(\"cd\"), mk(\"ab\"), mk(\"ef\")})",
                RenderLanguage::Rust => "([mk(\"cd\"), mk(\"ab\"), mk(\"ef\")])",
                RenderLanguage::Go => "([]bytes{mk(\"cd\"), mk(\"ab\"), mk(\"ef\")})",
                RenderLanguage::Java => "(new byte[][]{mk(\"cd\"), mk(\"ab\"), mk(\"ef\")})",
                RenderLanguage::Pseudocode => "[mk(\"cd\"), mk(\"ab\"), mk(\"ef\")]",
            };
            let expected = format!(
                "join({table}[((1 + 7) - 7)], {table}[((0 + 7) - 7)], {table}[((2 + 7) - 7)])"
            );
            assert_eq!(
                fragment_expression(
                    language,
                    value,
                    &shuffled,
                    NumericStyle::IdentityOffset { delta: 7 },
                    &profile,
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn missing_fragment_operation_and_reconstruction_aliases_are_rejected_safely() {
        let fragment_step = DisplayStep {
            node: NodeId(0),
            output_label: "output".to_owned(),
            local_name: "local".to_owned(),
            template: TemplateFamily::Direct,
            numeric_style: NumericStyle::Decimal,
            literal_plan: Some(FragmentLiteralPlan::Whole),
            guard_value: None,
            kind: DisplayStepKind::Fragment { index: 0 },
        };
        assert_eq!(
            emit_fragment_step(
                RenderLanguage::Rust,
                &fragment_step,
                &ObfuscationProfile::new(BTreeMap::new()),
                b"Ab"
            ),
            Err(RenderError::InvalidPlan)
        );

        let operation = Operation::Reverse;
        assert_eq!(
            emit_operation_step(
                RenderLanguage::Rust,
                &operation_step(TemplateFamily::Direct, "output", "local", &operation),
                &ObfuscationProfile::new(BTreeMap::new()),
                &["source".to_owned()],
            ),
            Err(RenderError::InvalidPlan)
        );

        let mut chunked_step = fragment_step;
        chunked_step.literal_plan = Some(FragmentLiteralPlan::OrderedChunks(vec![0..1, 1..2]));
        assert_eq!(
            emit_fragment_step(
                RenderLanguage::Rust,
                &chunked_step,
                &ObfuscationProfile::new(BTreeMap::from([(
                    HelperSemantic::BytesAscii,
                    "mk".to_owned(),
                )])),
                b"Ab"
            ),
            Err(RenderError::InvalidPlan)
        );
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
    fn alias_chain_and_guarded_templates_have_real_distinct_syntax_in_every_language() {
        let inputs = ["source_0".to_owned()];
        for language in RenderLanguage::ALL {
            let direct = emit_operation(
                language,
                TemplateFamily::Direct,
                "result_0",
                "local_0",
                &Operation::Reverse,
                &inputs,
            )
            .unwrap();
            let alias_chain = emit_operation(
                language,
                TemplateFamily::AliasChain,
                "result_0",
                "local_0",
                &Operation::Reverse,
                &inputs,
            )
            .unwrap();
            let mut guarded_step = operation_step(
                TemplateFamily::Guarded,
                "result_0",
                "local_0",
                &Operation::Reverse,
            );
            guarded_step.guard_value = Some(255);
            let guarded = emit_operation_step(
                language,
                &guarded_step,
                &operation_profile(&Operation::Reverse),
                &inputs,
            )
            .unwrap();

            assert_ne!(alias_chain, direct, "{language:?}");
            assert_ne!(guarded, direct, "{language:?}");
            assert_ne!(guarded, alias_chain, "{language:?}");
            let expression = "reverse(source_0)";
            let local_assignment = alias_chain.find(expression).unwrap();
            let export = alias_chain.rfind("result_0").unwrap();
            assert!(
                alias_chain.contains("local_0"),
                "{language:?}: {alias_chain}"
            );
            assert!(local_assignment < export, "{language:?}: {alias_chain}");
            assert!(guarded.contains("if "), "{language:?}: {guarded}");
            assert!(guarded.contains("else"), "{language:?}: {guarded}");
            assert!(guarded.contains("255"), "{language:?}: {guarded}");
            assert!(guarded.contains(expression), "{language:?}: {guarded}");
            assert!(
                guarded.contains("bytes_ascii(\"A\")"),
                "{language:?}: {guarded}"
            );
        }
    }

    #[test]
    fn every_language_operation_and_template_preserves_the_effective_inputs_and_names() {
        let families = [
            TemplateFamily::Direct,
            TemplateFamily::Helper,
            TemplateFamily::AliasChain,
            TemplateFamily::Guarded,
        ];

        for language in RenderLanguage::ALL {
            for operation in operations() {
                let input_count = operation.arity().unwrap_or(3);
                let inputs = ["alpha_input", "bravo_input", "charlie_input"]
                    .into_iter()
                    .take(input_count)
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                for family in families {
                    let rendered = emit_operation(
                        language,
                        family,
                        "result_final",
                        "planned_local",
                        &operation,
                        &inputs,
                    )
                    .unwrap();

                    for input in &inputs {
                        assert_eq!(
                            rendered.matches(input).count(),
                            1,
                            "{language:?} {family:?} {operation:?}: {rendered}"
                        );
                    }
                    assert_eq!(
                        rendered.matches(operation_alias(&operation)).count(),
                        1,
                        "{language:?} {family:?} {operation:?}: {rendered}"
                    );
                    let expected_local_count = match family {
                        TemplateFamily::Direct => 0,
                        TemplateFamily::Helper | TemplateFamily::AliasChain => 2,
                        TemplateFamily::Guarded => 1,
                    };
                    assert_eq!(
                        rendered.matches("planned_local").count(),
                        expected_local_count,
                        "{language:?} {family:?} {operation:?}: {rendered}"
                    );
                    assert!(
                        rendered.contains("result_final"),
                        "{language:?} {family:?} {operation:?}: {rendered}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_language_fragment_and_template_uses_the_profile_bytes_alias() {
        for language in RenderLanguage::ALL {
            for family in [
                TemplateFamily::Direct,
                TemplateFamily::Helper,
                TemplateFamily::AliasChain,
                TemplateFamily::Guarded,
            ] {
                let rendered =
                    emit_fragment(language, family, "result_final", "planned_local", b"Ab1")
                        .unwrap();
                assert!(
                    rendered.contains("bytes_ascii(\"Ab1\")"),
                    "{language:?} {family:?}: {rendered}"
                );
                assert_eq!(
                    rendered.matches("planned_local").count(),
                    match family {
                        TemplateFamily::Direct => 0,
                        TemplateFamily::Helper | TemplateFamily::AliasChain => 2,
                        TemplateFamily::Guarded => 1,
                    },
                    "{language:?} {family:?}: {rendered}"
                );
            }
        }
    }

    #[test]
    fn every_guard_value_uses_a_language_specific_widened_constant_predicate() {
        for language in RenderLanguage::ALL {
            for guard in u8::MIN..=u8::MAX {
                let mut step = operation_step(
                    TemplateFamily::Guarded,
                    "result_final",
                    "decoy_local",
                    &Operation::Reverse,
                );
                step.guard_value = Some(guard);
                let rendered = emit_operation_step(
                    language,
                    &step,
                    &operation_profile(&Operation::Reverse),
                    &["source".to_owned()],
                )
                .unwrap();
                let widened = match language {
                    RenderLanguage::C | RenderLanguage::Cpp => format!("{guard}UL"),
                    RenderLanguage::Rust => format!("{guard}_u32"),
                    RenderLanguage::Go => format!("uint32({guard})"),
                    RenderLanguage::Java => format!("{guard}L"),
                    RenderLanguage::Pseudocode => format!("u32({guard})"),
                };
                assert!(
                    rendered.matches(&widened).count() >= 3,
                    "{language:?} guard {guard}: {rendered}"
                );
                assert!(rendered.contains("&") || rendered.contains("bitand"));
                assert!(rendered.contains("=="));
            }
        }
    }

    fn false_branch(language: RenderLanguage, emitted: &str) -> &str {
        let false_and_suffix = emitted.split_once("else").unwrap().1;
        match language {
            RenderLanguage::Pseudocode => false_and_suffix.split_once("end if").unwrap().0,
            RenderLanguage::C
            | RenderLanguage::Cpp
            | RenderLanguage::Rust
            | RenderLanguage::Go
            | RenderLanguage::Java => false_and_suffix.split_once('}').unwrap().0,
        }
    }

    #[test]
    fn guarded_false_branch_is_an_isolated_display_only_decoy() {
        let inputs = ["source_alpha".to_owned(), "source_beta".to_owned()];
        for language in RenderLanguage::ALL {
            let operation = Operation::AddModulo;
            let mut step = operation_step(
                TemplateFamily::Guarded,
                "result_final",
                "decoy_local",
                &operation,
            );
            step.guard_value = Some(173);
            let emitted =
                emit_operation_step(language, &step, &operation_profile(&operation), &inputs)
                    .unwrap();
            let false_branch = false_branch(language, &emitted);
            let tokens = false_branch
                .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .filter(|token| !token.is_empty())
                .collect::<BTreeSet<_>>();

            assert!(
                tokens.contains("decoy_local"),
                "{language:?}: {false_branch}"
            );
            assert!(
                tokens.contains("bytes_ascii"),
                "{language:?}: {false_branch}"
            );
            assert!(tokens.contains("A"), "{language:?}: {false_branch}");
            for forbidden in [
                "result_final",
                "source_alpha",
                "source_beta",
                "other_effective_local",
                "add_u8",
            ] {
                assert!(
                    !tokens.contains(forbidden),
                    "{language:?}: false branch leaked {forbidden}: {false_branch}"
                );
            }
        }
    }

    #[test]
    fn emitter_rejects_guard_fields_that_do_not_match_the_template_family() {
        for language in RenderLanguage::ALL {
            for family in [
                TemplateFamily::Direct,
                TemplateFamily::Helper,
                TemplateFamily::AliasChain,
            ] {
                let mut step = operation_step(family, "output", "local", &Operation::Reverse);
                step.guard_value = Some(7);
                assert_eq!(
                    emit_operation_step(
                        language,
                        &step,
                        &operation_profile(&Operation::Reverse),
                        &["source".to_owned()],
                    ),
                    Err(RenderError::InvalidPlan),
                    "{language:?} {family:?}"
                );
            }

            let mut step = operation_step(
                TemplateFamily::Guarded,
                "output",
                "local",
                &Operation::Reverse,
            );
            step.guard_value = None;
            assert_eq!(
                emit_operation_step(
                    language,
                    &step,
                    &operation_profile(&Operation::Reverse),
                    &["source".to_owned()],
                ),
                Err(RenderError::InvalidPlan),
                "{language:?} guarded without value"
            );
        }
    }

    #[test]
    fn question_preamble_explains_guarded_branch_semantics_without_runtime_ambiguity() {
        let mut plan = RenderPlan {
            fragments: vec![DisplayFragment {
                heading: "section".to_owned(),
                language: RenderLanguage::Rust,
                steps: vec![DisplayStep {
                    node: NodeId(0),
                    output_label: "result".to_owned(),
                    local_name: "decoy".to_owned(),
                    template: TemplateFamily::Guarded,
                    numeric_style: NumericStyle::Decimal,
                    literal_plan: Some(FragmentLiteralPlan::Whole),
                    guard_value: Some(255),
                    kind: DisplayStepKind::Fragment { index: 0 },
                }],
            }],
            output: NodeId(0),
            profile: ObfuscationProfile::new(BTreeMap::from([(
                HelperSemantic::BytesAscii,
                "mkbytes".to_owned(),
            )])),
            distractor: None,
        };

        for language in RenderLanguage::ALL {
            plan.fragments[0].language = language;
            let question = emit_question(&plan, &[b"Ab".to_vec()]).unwrap();
            assert!(question.contains("widened integer"));
            assert!(question.contains("effective answer follows the true branch"));
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
    fn declarations_are_tight_for_every_template_numeric_literal_and_language_combination() {
        let styles = [
            NumericStyle::Decimal,
            NumericStyle::LowerHex,
            NumericStyle::IdentityOffset { delta: 15 },
        ];
        let families = [
            TemplateFamily::Direct,
            TemplateFamily::Helper,
            TemplateFamily::AliasChain,
            TemplateFamily::Guarded,
        ];
        let literal_plans = [
            FragmentLiteralPlan::Whole,
            FragmentLiteralPlan::OrderedChunks(vec![0..5, 5..10, 10..16]),
            FragmentLiteralPlan::ShuffledChunks {
                chunks: vec![10..16, 0..5, 5..10],
                restore_order: vec![1, 2, 0],
            },
        ];
        let value = b"ABCDEFGHIJKLMNOP";
        let mut matrix = Vec::new();

        for language in RenderLanguage::ALL {
            for family in families {
                let mut longest = 0;
                for style in styles {
                    for (_, operation, inputs) in worst_case_operations() {
                        let mut step = operation_step(
                            family,
                            "output_000000000",
                            "helper_000000000",
                            &operation,
                        );
                        step.numeric_style = style;
                        step.guard_value = (family == TemplateFamily::Guarded).then_some(u8::MAX);
                        let profile = ObfuscationProfile::new(BTreeMap::from([
                            (HelperSemantic::BytesAscii, "bbbbbbbbbbbbbbbb".to_owned()),
                            (
                                HelperSemantic::Operation(OperationKind::from(&operation)),
                                "aaaaaaaaaaaaaaaa".to_owned(),
                            ),
                        ]));
                        let emitted = emit_operation_step(language, &step, &profile, &inputs)
                            .unwrap_or_else(|error| {
                                panic!("{language:?} {family:?} {style:?} {operation:?}: {error:?}")
                            });
                        longest = longest.max(emitted.len());
                    }

                    for literal_plan in &literal_plans {
                        let step = DisplayStep {
                            node: NodeId(0),
                            output_label: "output_000000000".to_owned(),
                            local_name: "helper_000000000".to_owned(),
                            template: family,
                            numeric_style: style,
                            literal_plan: Some(literal_plan.clone()),
                            guard_value: (family == TemplateFamily::Guarded).then_some(u8::MAX),
                            kind: DisplayStepKind::Fragment { index: 0 },
                        };
                        let profile = ObfuscationProfile::new(BTreeMap::from([
                            (HelperSemantic::BytesAscii, "bbbbbbbbbbbbbbbb".to_owned()),
                            (
                                HelperSemantic::Operation(OperationKind::Concat),
                                "cccccccccccccccc".to_owned(),
                            ),
                        ]));
                        let emitted = emit_fragment_step(language, &step, &profile, value)
                            .unwrap_or_else(|error| {
                                panic!(
                                    "{language:?} {family:?} {style:?} {literal_plan:?}: {error:?}"
                                )
                            });
                        longest = longest.max(emitted.len());
                    }
                }

                let expected = longest.div_ceil(16) * 16;
                matrix.push((language, family, expected, longest));
                assert!(expected <= MAX_STEP_BYTES);
            }
        }
        let mismatches = matrix
            .iter()
            .filter(|(language, family, expected, _)| {
                declared_template_max_bytes(*language, *family) != *expected
            })
            .collect::<Vec<_>>();
        assert!(
            mismatches.is_empty(),
            "tight bound mismatches: {mismatches:?}"
        );
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
