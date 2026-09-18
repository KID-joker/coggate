use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use coggate_core::generation::{MAX_CONCAT_INPUTS, MAX_QUESTION_BYTES, Operation};
use zeroize::Zeroizing;

use super::{Baseline, BaselineError, NoGuessReason, Prediction};
use crate::corpus::CorpusCase;

const MAX_TOKENS: usize = 256;
const MAX_DEPTH: usize = 16;
const MAX_VALUE_BYTES: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 32;
const REQUEST_PREFIX: &str = "The requested result is output label ";
const REQUEST_SUFFIX: &str = ". Submit its byte array as unpadded base64url.";

#[derive(Default)]
pub struct SimpleParserBaseline;

impl SimpleParserBaseline {
    pub fn predict_text(&self, question: &str) -> Prediction {
        if question.len() > MAX_QUESTION_BYTES {
            return Prediction::NoGuess(NoGuessReason::Unsupported);
        }
        let Some(label) = requested_label(question) else {
            return Prediction::NoGuess(NoGuessReason::ParseFailed);
        };

        let mut candidate: Option<Vec<u8>> = None;
        for section in question.split("[Fragment ").skip(1) {
            let Some((_, body)) = section.split_once('\n') else {
                continue;
            };
            let body = body
                .split("Dependency clues:")
                .next()
                .unwrap_or(body)
                .split("Display order is not evaluation order.")
                .next()
                .unwrap_or(body);
            if let Some(value) = parse_one_fragment(body, label) {
                if let Some(existing) = &candidate {
                    if existing != &value {
                        return Prediction::NoGuess(NoGuessReason::Ambiguous);
                    }
                } else {
                    candidate = Some(value);
                }
            }
        }

        candidate.map_or(Prediction::NoGuess(NoGuessReason::ParseFailed), |value| {
            Prediction::Guess(Zeroizing::new(URL_SAFE_NO_PAD.encode(value)))
        })
    }
}

impl Baseline for SimpleParserBaseline {
    fn id(&self) -> &'static str {
        "simple_parser"
    }

    fn predict(&self, case: &CorpusCase) -> Result<Prediction, BaselineError> {
        Ok(self.predict_text(case.question()))
    }
}

impl fmt::Debug for SimpleParserBaseline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SimpleParserBaseline")
    }
}

pub fn parse_one_fragment(source: &str, requested_label: &str) -> Option<Vec<u8>> {
    if source.len() > MAX_QUESTION_BYTES
        || requested_label.is_empty()
        || requested_label.len() > 16
        || !is_identifier(requested_label)
    {
        return None;
    }

    let mut environment = BTreeMap::<String, Vec<u8>>::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, expression)) = helper_definition(line) {
            if name.len() > 16 || !is_identifier(name) {
                return None;
            }
            let value = parse_expression(expression, &environment)?;
            environment.insert(name.to_owned(), value);
            continue;
        }

        let Some((code, exported)) = exported_assignment(line) else {
            continue;
        };
        if exported.len() > 16 || !is_identifier(exported) {
            return None;
        }
        let expression = assignment_expression(code, exported)?;
        let value = parse_expression(expression, &environment)?;
        environment.insert(exported.to_owned(), value);
    }
    environment.remove(requested_label)
}

fn requested_label(question: &str) -> Option<&str> {
    let start = question.rfind(REQUEST_PREFIX)? + REQUEST_PREFIX.len();
    let remainder = &question[start..];
    let end = remainder.find(REQUEST_SUFFIX)?;
    let label = &remainder[..end];
    (label.len() <= 16 && is_identifier(label)).then_some(label)
}

fn helper_definition(line: &str) -> Option<(&str, &str)> {
    if let Some(rest) = line.strip_prefix("function ") {
        let (name, expression) = rest.split_once(": return ")?;
        return Some((name.trim(), expression.trim()));
    }

    if let Some((left, expression)) = line.split_once(" := func() bytes { return ") {
        return Some((left.trim(), expression.strip_suffix(" }")?.trim()));
    }

    if let Some(rest) = line.strip_prefix("fn ") {
        let name_end = rest.find("()")?;
        let expression_start = rest.find('{')? + 1;
        let expression_end = rest.rfind('}')?;
        return Some((
            rest[..name_end].trim(),
            rest[expression_start..expression_end].trim(),
        ));
    }

    let marker = "() { return ";
    let (left, expression) = line.split_once(marker)?;
    let name = left.split_ascii_whitespace().last()?;
    Some((name, expression.strip_suffix("; }")?.trim()))
}

fn exported_assignment(line: &str) -> Option<(&str, &str)> {
    for marker in ["// exports ", "# exports "] {
        if let Some((code, label)) = line.split_once(marker) {
            return Some((code.trim(), label.trim()));
        }
    }
    None
}

fn assignment_expression<'a>(code: &'a str, exported: &str) -> Option<&'a str> {
    let (declaration, expression) = if let Some(parts) = code.split_once(" <- ") {
        parts
    } else if let Some(parts) = code.split_once(" := ") {
        parts
    } else {
        code.split_once(" = ")?
    };
    let declared = declaration.split_ascii_whitespace().last()?;
    if declared != exported || declared.len() > 16 || !is_identifier(declared) {
        return None;
    }
    Some(expression.trim().trim_end_matches(';').trim())
}

fn parse_expression(source: &str, environment: &BTreeMap<String, Vec<u8>>) -> Option<Vec<u8>> {
    let tokens = tokenize(source)?;
    let mut parser = Parser {
        tokens: &tokens,
        position: 0,
        environment,
    };
    let value = parser.parse_value(0)?;
    if parser.position != tokens.len() {
        return None;
    }
    let Value::Bytes(value) = value else {
        return None;
    };
    (value.len() <= MAX_VALUE_BYTES).then_some(value)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Ident(String),
    Text(Vec<u8>),
    Number(usize),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
}

fn tokenize(source: &str) -> Option<Vec<Token>> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if tokens.len() >= MAX_TOKENS {
            return None;
        }
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => index += 1,
            b'(' => {
                tokens.push(Token::LParen);
                index += 1;
            }
            b')' => {
                tokens.push(Token::RParen);
                index += 1;
            }
            b'[' => {
                tokens.push(Token::LBracket);
                index += 1;
            }
            b']' => {
                tokens.push(Token::RBracket);
                index += 1;
            }
            b',' => {
                tokens.push(Token::Comma);
                index += 1;
            }
            b'"' => {
                index += 1;
                let start = index;
                while index < bytes.len() && bytes[index] != b'"' {
                    if !bytes[index].is_ascii_alphanumeric() {
                        return None;
                    }
                    index += 1;
                }
                if index == bytes.len() || index - start > 16 {
                    return None;
                }
                tokens.push(Token::Text(bytes[start..index].to_vec()));
                index += 1;
            }
            byte if byte.is_ascii_digit() => {
                let start = index;
                while index < bytes.len() && bytes[index].is_ascii_digit() {
                    index += 1;
                }
                let number = std::str::from_utf8(&bytes[start..index])
                    .ok()?
                    .parse()
                    .ok()?;
                tokens.push(Token::Number(number));
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                if index - start > MAX_IDENTIFIER_BYTES {
                    return None;
                }
                tokens.push(Token::Ident(
                    std::str::from_utf8(&bytes[start..index]).ok()?.to_owned(),
                ));
            }
            _ => return None,
        }
    }
    Some(tokens)
}

enum Value {
    Bytes(Vec<u8>),
    Number(usize),
    Numbers(Vec<usize>),
}

struct Parser<'a> {
    tokens: &'a [Token],
    position: usize,
    environment: &'a BTreeMap<String, Vec<u8>>,
}

impl Parser<'_> {
    fn parse_value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        let token = self.tokens.get(self.position)?.clone();
        self.position += 1;
        match token {
            Token::Text(value) => Some(Value::Bytes(value)),
            Token::Number(value) => Some(Value::Number(value)),
            Token::LBracket => self.parse_number_list(),
            Token::Ident(name) if self.consume(&Token::LParen) => {
                let arguments = self.parse_arguments(depth + 1)?;
                evaluate_call(&name, arguments, self.environment)
            }
            Token::Ident(name) => self.environment.get(&name).cloned().map(Value::Bytes),
            _ => None,
        }
    }

    fn parse_arguments(&mut self, depth: usize) -> Option<Vec<Value>> {
        let mut arguments = Vec::new();
        if self.consume(&Token::RParen) {
            return Some(arguments);
        }
        loop {
            if arguments.len() >= MAX_CONCAT_INPUTS {
                return None;
            }
            arguments.push(self.parse_value(depth)?);
            if self.consume(&Token::RParen) {
                return Some(arguments);
            }
            if !self.consume(&Token::Comma) {
                return None;
            }
        }
    }

    fn parse_number_list(&mut self) -> Option<Value> {
        let mut numbers = Vec::new();
        if self.consume(&Token::RBracket) {
            return Some(Value::Numbers(numbers));
        }
        loop {
            let Token::Number(number) = self.tokens.get(self.position)?.clone() else {
                return None;
            };
            self.position += 1;
            numbers.push(number);
            if numbers.len() > 16 {
                return None;
            }
            if self.consume(&Token::RBracket) {
                return Some(Value::Numbers(numbers));
            }
            if !self.consume(&Token::Comma) {
                return None;
            }
        }
    }

    fn consume(&mut self, expected: &Token) -> bool {
        if self.tokens.get(self.position) == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

fn evaluate_call(
    name: &str,
    mut arguments: Vec<Value>,
    environment: &BTreeMap<String, Vec<u8>>,
) -> Option<Value> {
    if name == "bytes_ascii" {
        return match arguments.as_slice() {
            [Value::Bytes(value)]
                if !value.is_empty()
                    && value.len() <= 16
                    && value.iter().all(u8::is_ascii_alphanumeric) =>
            {
                Some(Value::Bytes(value.clone()))
            }
            _ => None,
        };
    }
    if arguments.is_empty() {
        return environment.get(name).cloned().map(Value::Bytes);
    }

    let operation = match name {
        "reverse" => Operation::Reverse,
        "rotate_left" => Operation::RotateLeft(pop_number(&mut arguments)?),
        "rotate_right" => Operation::RotateRight(pop_number(&mut arguments)?),
        "xor_repeat" => Operation::Xor(
            pop_numbers(&mut arguments)?
                .into_iter()
                .map(u8::try_from)
                .collect::<Result<Vec<_>, _>>()
                .ok()?,
        ),
        "even_bytes" => Operation::EvenBytes,
        "odd_bytes" => Operation::OddBytes,
        "permute" => Operation::Permute(pop_numbers(&mut arguments)?),
        "slice" => {
            let end = pop_number(&mut arguments)?;
            let start = pop_number(&mut arguments)?;
            Operation::Slice { start, end }
        }
        "concat" => Operation::Concat,
        "add_u8" => Operation::AddModulo,
        "sub_u8" => Operation::SubModulo,
        "hex_lower" => Operation::HexEncode,
        "hex_decode_lower" => Operation::HexDecode,
        "base64url_no_pad" => Operation::Base64UrlEncode,
        "base64url_decode_no_pad" => Operation::Base64UrlDecode,
        "sha256_prefix" => Operation::Sha256Prefix(pop_number(&mut arguments)?),
        "rotate_left_derived" => Operation::RotateLeftDerived,
        "conditional_order" => Operation::ConditionalOrder,
        _ => return None,
    };

    let inputs = arguments
        .iter()
        .map(|value| match value {
            Value::Bytes(bytes) => Some(bytes.as_slice()),
            Value::Number(_) | Value::Numbers(_) => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let result = operation.evaluate(&inputs).ok()?;
    (result.len() <= MAX_VALUE_BYTES).then_some(Value::Bytes(result))
}

fn pop_number(arguments: &mut Vec<Value>) -> Option<usize> {
    match arguments.pop()? {
        Value::Number(value) => Some(value),
        Value::Bytes(_) | Value::Numbers(_) => None,
    }
}

fn pop_numbers(arguments: &mut Vec<Value>) -> Option<Vec<usize>> {
    match arguments.pop()? {
        Value::Numbers(value) => Some(value),
        Value::Bytes(_) | Value::Number(_) => None,
    }
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}
