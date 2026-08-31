use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use super::GenerationError;

pub const MAX_XOR_KEY_LENGTH: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    Reverse,
    RotateLeft(usize),
    RotateRight(usize),
    Xor(Vec<u8>),
    EvenBytes,
    OddBytes,
    Permute(Vec<usize>),
    Slice { start: usize, end: usize },
    Concat,
    AddModulo,
    SubModulo,
    HexEncode,
    HexDecode,
    Base64UrlEncode,
    Base64UrlDecode,
    Sha256Prefix(usize),
    RotateLeftDerived,
    ConditionalOrder,
}

impl Operation {
    pub fn arity(&self) -> Option<usize> {
        match self {
            Self::Concat => None,
            Self::AddModulo | Self::SubModulo | Self::RotateLeftDerived => Some(2),
            Self::ConditionalOrder => Some(3),
            Self::Reverse
            | Self::RotateLeft(_)
            | Self::RotateRight(_)
            | Self::Xor(_)
            | Self::EvenBytes
            | Self::OddBytes
            | Self::Permute(_)
            | Self::Slice { .. }
            | Self::HexEncode
            | Self::HexDecode
            | Self::Base64UrlEncode
            | Self::Base64UrlDecode
            | Self::Sha256Prefix(_) => Some(1),
        }
    }

    pub fn validate_arity(&self, input_count: usize) -> Result<(), GenerationError> {
        match self.arity() {
            Some(expected) if input_count == expected => self.validate_static_parameters(),
            None if input_count >= 2 => self.validate_static_parameters(),
            _ => Err(GenerationError::InvalidOperation),
        }
    }

    fn validate_static_parameters(&self) -> Result<(), GenerationError> {
        match self {
            Self::Xor(key) if !(1..=MAX_XOR_KEY_LENGTH).contains(&key.len()) => {
                Err(GenerationError::InvalidOperation)
            }
            Self::Sha256Prefix(prefix_length) => valid_sha256_prefix(*prefix_length).map(|_| ()),
            Self::Slice { start, end } if start > end => Err(GenerationError::InvalidOperation),
            Self::Permute(permutation) => validate_permutation_parameters(permutation),
            _ => Ok(()),
        }
    }

    pub fn output_length(&self, input_lengths: &[usize]) -> Result<usize, GenerationError> {
        self.validate_arity(input_lengths.len())?;

        match self {
            Self::Reverse => Ok(input_lengths[0]),
            Self::Xor(key) => {
                if key.is_empty() {
                    Err(GenerationError::InvalidOperation)
                } else {
                    Ok(input_lengths[0])
                }
            }
            Self::Permute(permutation) => equal_length(permutation.len(), input_lengths[0]),
            Self::RotateLeft(_) | Self::RotateRight(_) => non_empty_length(input_lengths[0]),
            Self::EvenBytes => Ok(input_lengths[0] / 2 + input_lengths[0] % 2),
            Self::OddBytes => Ok(input_lengths[0] / 2),
            Self::Slice { start, end } => slice_length(*start, *end, input_lengths[0]),
            Self::Concat => checked_sum(input_lengths),
            Self::AddModulo | Self::SubModulo => equal_length(input_lengths[0], input_lengths[1]),
            Self::HexEncode => input_lengths[0]
                .checked_mul(2)
                .ok_or(GenerationError::InvalidLength),
            Self::HexDecode => hex_decoded_length(input_lengths[0]),
            Self::Base64UrlEncode => base64_encoded_length(input_lengths[0]),
            Self::Base64UrlDecode => base64_decoded_length(input_lengths[0]),
            Self::Sha256Prefix(prefix_length) => valid_sha256_prefix(*prefix_length),
            Self::RotateLeftDerived => {
                non_empty_length(input_lengths[0])?;
                non_empty_length(input_lengths[1])?;
                Ok(input_lengths[0])
            }
            Self::ConditionalOrder => {
                non_empty_length(input_lengths[0])?;
                input_lengths[1]
                    .checked_add(input_lengths[2])
                    .ok_or(GenerationError::InvalidLength)
            }
        }
    }

    pub fn evaluate(&self, inputs: &[&[u8]]) -> Result<Vec<u8>, GenerationError> {
        let input_lengths: Vec<usize> = inputs.iter().map(|input| input.len()).collect();
        let output_length = self.output_length(&input_lengths)?;

        match self {
            Self::Reverse => {
                let mut result = inputs[0].to_vec();
                result.reverse();
                Ok(result)
            }
            Self::RotateLeft(amount) => rotate_left(inputs[0], *amount),
            Self::RotateRight(amount) => rotate_right(inputs[0], *amount),
            Self::Xor(key) => xor(inputs[0], key),
            Self::EvenBytes => Ok(inputs[0].iter().step_by(2).copied().collect()),
            Self::OddBytes => Ok(inputs[0].iter().skip(1).step_by(2).copied().collect()),
            Self::Permute(permutation) => Ok(permute(inputs[0], permutation)),
            Self::Slice { start, end } => Ok(inputs[0][*start..*end].to_vec()),
            Self::Concat => concatenate(inputs, output_length),
            Self::AddModulo => modular_combine(inputs[0], inputs[1], u8::wrapping_add),
            Self::SubModulo => modular_combine(inputs[0], inputs[1], u8::wrapping_sub),
            Self::HexEncode => Ok(hex::encode(inputs[0]).into_bytes()),
            Self::HexDecode => decode_hex(inputs[0]),
            Self::Base64UrlEncode => Ok(URL_SAFE_NO_PAD.encode(inputs[0]).into_bytes()),
            Self::Base64UrlDecode => decode_base64_url(inputs[0]),
            Self::Sha256Prefix(prefix_length) => {
                Ok(Sha256::digest(inputs[0])[..*prefix_length].to_vec())
            }
            Self::RotateLeftDerived => rotate_left(inputs[0], usize::from(inputs[1][0])),
            Self::ConditionalOrder => {
                if inputs[0][0] % 2 == 0 {
                    concatenate(&[inputs[1], inputs[2]], output_length)
                } else {
                    concatenate(&[inputs[2], inputs[1]], output_length)
                }
            }
        }
    }
}

fn non_empty_length(length: usize) -> Result<usize, GenerationError> {
    if length == 0 {
        Err(GenerationError::InvalidLength)
    } else {
        Ok(length)
    }
}

fn equal_length(left: usize, right: usize) -> Result<usize, GenerationError> {
    if left == right {
        Ok(left)
    } else {
        Err(GenerationError::InvalidLength)
    }
}

fn checked_sum(lengths: &[usize]) -> Result<usize, GenerationError> {
    lengths.iter().try_fold(0_usize, |sum, length| {
        sum.checked_add(*length)
            .ok_or(GenerationError::InvalidLength)
    })
}

fn slice_length(start: usize, end: usize, input_length: usize) -> Result<usize, GenerationError> {
    if start > end {
        return Err(GenerationError::InvalidOperation);
    }
    if end > input_length {
        return Err(GenerationError::InvalidLength);
    }
    Ok(end - start)
}

fn hex_decoded_length(length: usize) -> Result<usize, GenerationError> {
    if length % 2 == 0 {
        Ok(length / 2)
    } else {
        Err(GenerationError::InvalidEncoding)
    }
}

fn base64_encoded_length(length: usize) -> Result<usize, GenerationError> {
    let complete_groups = length / 3;
    let remainder = length % 3;
    let encoded = complete_groups
        .checked_mul(4)
        .ok_or(GenerationError::InvalidLength)?;
    encoded
        .checked_add(match remainder {
            0 => 0,
            1 => 2,
            _ => 3,
        })
        .ok_or(GenerationError::InvalidLength)
}

fn base64_decoded_length(length: usize) -> Result<usize, GenerationError> {
    if length % 4 == 1 {
        return Err(GenerationError::InvalidEncoding);
    }
    let complete_groups = length / 4;
    let remainder = length % 4;
    let decoded = complete_groups
        .checked_mul(3)
        .ok_or(GenerationError::InvalidLength)?;
    decoded
        .checked_add(match remainder {
            0 => 0,
            2 => 1,
            _ => 2,
        })
        .ok_or(GenerationError::InvalidLength)
}

fn valid_sha256_prefix(prefix_length: usize) -> Result<usize, GenerationError> {
    if (1..=32).contains(&prefix_length) {
        Ok(prefix_length)
    } else {
        Err(GenerationError::InvalidOperation)
    }
}

fn rotate_left(input: &[u8], amount: usize) -> Result<Vec<u8>, GenerationError> {
    let length = non_empty_length(input.len())?;
    let mut result = input.to_vec();
    result.rotate_left(amount % length);
    Ok(result)
}

fn rotate_right(input: &[u8], amount: usize) -> Result<Vec<u8>, GenerationError> {
    let length = non_empty_length(input.len())?;
    let mut result = input.to_vec();
    result.rotate_right(amount % length);
    Ok(result)
}

fn xor(input: &[u8], key: &[u8]) -> Result<Vec<u8>, GenerationError> {
    if key.is_empty() {
        return Err(GenerationError::InvalidOperation);
    }
    Ok(input
        .iter()
        .zip(key.iter().cycle())
        .map(|(value, key_byte)| value ^ key_byte)
        .collect())
}

fn permute(input: &[u8], permutation: &[usize]) -> Vec<u8> {
    permutation.iter().map(|&index| input[index]).collect()
}

fn validate_permutation_parameters(permutation: &[usize]) -> Result<(), GenerationError> {
    let mut seen = Vec::new();
    seen.try_reserve_exact(permutation.len())
        .map_err(|_| GenerationError::InvalidLength)?;
    seen.resize(permutation.len(), false);
    for &index in permutation {
        let Some(slot) = seen.get_mut(index) else {
            return Err(GenerationError::InvalidOperation);
        };
        if *slot {
            return Err(GenerationError::InvalidOperation);
        }
        *slot = true;
    }
    Ok(())
}

fn concatenate(inputs: &[&[u8]], output_length: usize) -> Result<Vec<u8>, GenerationError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(output_length)
        .map_err(|_| GenerationError::InvalidLength)?;
    for input in inputs {
        result.extend_from_slice(input);
    }
    Ok(result)
}

fn modular_combine(
    left: &[u8],
    right: &[u8],
    combine: impl Fn(u8, u8) -> u8,
) -> Result<Vec<u8>, GenerationError> {
    equal_length(left.len(), right.len())?;
    Ok(left
        .iter()
        .zip(right)
        .map(|(left_byte, right_byte)| combine(*left_byte, *right_byte))
        .collect())
}

fn decode_hex(input: &[u8]) -> Result<Vec<u8>, GenerationError> {
    hex_decoded_length(input.len())?;
    let decoded = hex::decode(input).map_err(|_| GenerationError::InvalidEncoding)?;
    if hex::encode(&decoded).as_bytes() == input {
        Ok(decoded)
    } else {
        Err(GenerationError::InvalidEncoding)
    }
}

fn decode_base64_url(input: &[u8]) -> Result<Vec<u8>, GenerationError> {
    base64_decoded_length(input.len())?;
    let decoded = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| GenerationError::InvalidEncoding)?;
    if URL_SAFE_NO_PAD.encode(&decoded).as_bytes() == input {
        Ok(decoded)
    } else {
        Err(GenerationError::InvalidEncoding)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_XOR_KEY_LENGTH, Operation};
    use crate::generation::GenerationError;

    #[test]
    fn evaluates_v1_operation_vectors() {
        assert_eq!(
            Operation::Reverse.evaluate(&[b"abcd"]),
            Ok(b"dcba".to_vec())
        );
        assert_eq!(
            Operation::RotateLeft(1).evaluate(&[b"abcd"]),
            Ok(b"bcda".to_vec())
        );
        assert_eq!(
            Operation::RotateRight(1).evaluate(&[b"abcd"]),
            Ok(b"dabc".to_vec())
        );
        assert_eq!(
            Operation::Xor(vec![0x20]).evaluate(&[b"AZ"]),
            Ok(b"az".to_vec())
        );
        assert_eq!(
            Operation::EvenBytes.evaluate(&[b"abcdef"]),
            Ok(b"ace".to_vec())
        );
        assert_eq!(
            Operation::OddBytes.evaluate(&[b"abcdef"]),
            Ok(b"bdf".to_vec())
        );
        assert_eq!(
            Operation::Permute(vec![2, 0, 1]).evaluate(&[b"abc"]),
            Ok(b"cab".to_vec())
        );
        assert_eq!(
            Operation::Slice { start: 1, end: 3 }.evaluate(&[b"abcd"]),
            Ok(b"bc".to_vec())
        );
        assert_eq!(
            Operation::Concat.evaluate(&[b"ab", b"cd"]),
            Ok(b"abcd".to_vec())
        );
        assert_eq!(
            Operation::AddModulo.evaluate(&[&[250, 1], &[10, 2]]),
            Ok(vec![4, 3])
        );
        assert_eq!(
            Operation::SubModulo.evaluate(&[&[4, 1], &[10, 2]]),
            Ok(vec![250, 255])
        );
        assert_eq!(
            Operation::HexEncode.evaluate(&[&[0xab, 0x01]]),
            Ok(b"ab01".to_vec())
        );
        assert_eq!(
            Operation::HexDecode.evaluate(&[b"ab01"]),
            Ok(vec![0xab, 0x01])
        );
        assert_eq!(
            Operation::Base64UrlEncode.evaluate(&[b"a?"]),
            Ok(b"YT8".to_vec())
        );
        assert_eq!(
            Operation::Base64UrlDecode.evaluate(&[b"YT8"]),
            Ok(b"a?".to_vec())
        );
        assert_eq!(
            Operation::Sha256Prefix(4).evaluate(&[b"abc"]),
            Ok(vec![0xba, 0x78, 0x16, 0xbf])
        );
        assert_eq!(
            Operation::RotateLeftDerived.evaluate(&[&b"abcd"[..], &[5]]),
            Ok(b"bcda".to_vec())
        );
        assert_eq!(
            Operation::ConditionalOrder.evaluate(&[&[2], &b"ab"[..], &b"cd"[..]]),
            Ok(b"abcd".to_vec())
        );
        assert_eq!(
            Operation::ConditionalOrder.evaluate(&[&[3], &b"ab"[..], &b"cd"[..]]),
            Ok(b"cdab".to_vec())
        );
    }

    #[test]
    fn reduces_rotation_amounts_modulo_input_length() {
        assert_eq!(
            Operation::RotateLeft(5).evaluate(&[b"abcd"]),
            Ok(b"bcda".to_vec())
        );
        assert_eq!(
            Operation::RotateRight(5).evaluate(&[b"abcd"]),
            Ok(b"dabc".to_vec())
        );
    }

    #[test]
    fn repeats_multi_byte_xor_keys_and_concatenates_many_inputs_in_order() {
        assert_eq!(
            Operation::Xor(vec![1, 2]).evaluate(&[&[0, 0, 0]]),
            Ok(vec![1, 2, 1])
        );
        assert_eq!(
            Operation::Concat.evaluate(&[b"ab", b"cd", b"ef"]),
            Ok(b"abcdef".to_vec())
        );
    }

    #[test]
    fn defines_empty_input_behavior_for_length_safe_operations() {
        assert_eq!(Operation::EvenBytes.evaluate(&[b""]), Ok(Vec::new()));
        assert_eq!(Operation::OddBytes.evaluate(&[b""]), Ok(Vec::new()));
        assert_eq!(
            Operation::Permute(Vec::new()).evaluate(&[b""]),
            Ok(Vec::new())
        );
        assert_eq!(Operation::HexEncode.evaluate(&[b""]), Ok(Vec::new()));
        assert_eq!(Operation::HexDecode.evaluate(&[b""]), Ok(Vec::new()));
        assert_eq!(Operation::Base64UrlEncode.evaluate(&[b""]), Ok(Vec::new()));
        assert_eq!(Operation::Base64UrlDecode.evaluate(&[b""]), Ok(Vec::new()));
    }

    #[test]
    fn rejects_invalid_parameters_and_input_lengths() {
        assert_eq!(
            Operation::Xor(vec![]).evaluate(&[b"x"]),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::Permute(vec![0, 0]).evaluate(&[b"ab"]),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::Slice { start: 1, end: 3 }.evaluate(&[b"ab"]),
            Err(GenerationError::InvalidLength)
        );
        assert_eq!(
            Operation::Slice { start: 2, end: 1 }.evaluate(&[b"ab"]),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::AddModulo.evaluate(&[&b"a"[..], &b"bc"[..]]),
            Err(GenerationError::InvalidLength)
        );
        assert_eq!(
            Operation::HexDecode.evaluate(&[b"ABC"]),
            Err(GenerationError::InvalidEncoding)
        );
        assert_eq!(
            Operation::HexDecode.evaluate(&[b"AB"]),
            Err(GenerationError::InvalidEncoding)
        );
        assert_eq!(
            Operation::Base64UrlDecode.evaluate(&[b"YQ=="]),
            Err(GenerationError::InvalidEncoding)
        );
        assert_eq!(
            Operation::RotateLeft(1).evaluate(&[b""]),
            Err(GenerationError::InvalidLength)
        );
        assert_eq!(
            Operation::RotateLeftDerived.evaluate(&[b"ab", b""]),
            Err(GenerationError::InvalidLength)
        );
        assert_eq!(
            Operation::ConditionalOrder.evaluate(&[b"", b"ab", b"cd"]),
            Err(GenerationError::InvalidLength)
        );
        assert_eq!(
            Operation::Sha256Prefix(0).evaluate(&[b"abc"]),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::Sha256Prefix(33).evaluate(&[b"abc"]),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::Reverse.evaluate(&[]),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::Concat.evaluate(&[b"a"]),
            Err(GenerationError::InvalidOperation)
        );
    }

    #[test]
    fn rejects_xor_keys_longer_than_the_v1_limit() {
        let operation = Operation::Xor(vec![0x20; 17]);

        assert_eq!(
            operation.validate_arity(1),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            operation.output_length(&[2]),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            operation.evaluate(&[b"AZ"]),
            Err(GenerationError::InvalidOperation)
        );
    }

    #[test]
    fn accepts_an_xor_key_at_the_v1_limit() {
        let operation = Operation::Xor(vec![0x20; MAX_XOR_KEY_LENGTH]);

        assert_eq!(operation.validate_arity(1), Ok(()));
        assert_eq!(operation.output_length(&[2]), Ok(2));
        assert_eq!(operation.evaluate(&[b"AZ"]), Ok(b"az".to_vec()));
    }

    #[test]
    fn validates_arity_and_calculates_static_output_lengths() {
        assert_eq!(Operation::Reverse.arity(), Some(1));
        assert_eq!(Operation::Concat.arity(), None);
        assert_eq!(Operation::ConditionalOrder.arity(), Some(3));
        assert_eq!(Operation::Concat.validate_arity(2), Ok(()));
        assert_eq!(
            Operation::Xor(vec![]).validate_arity(1),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::Sha256Prefix(0).validate_arity(1),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::Sha256Prefix(33).validate_arity(1),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::Permute(vec![1]).validate_arity(1),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::Permute(vec![0, 2]).validate_arity(1),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::Concat.validate_arity(1),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::RotateLeftDerived.validate_arity(1),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(Operation::Concat.output_length(&[2, 3]), Ok(5));
        assert_eq!(Operation::AddModulo.output_length(&[4, 4]), Ok(4));
        assert_eq!(
            Operation::AddModulo.output_length(&[4, 3]),
            Err(GenerationError::InvalidLength)
        );
        assert_eq!(
            Operation::Xor(vec![]).output_length(&[4]),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::Permute(vec![0, 0]).output_length(&[2]),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            Operation::HexEncode.output_length(&[usize::MAX]),
            Err(GenerationError::InvalidLength)
        );
        assert_eq!(
            Operation::Concat.output_length(&[usize::MAX, 1]),
            Err(GenerationError::InvalidLength)
        );
    }

    #[test]
    fn static_output_lengths_match_all_positive_operation_evaluations() {
        assert_output_length_matches_evaluation(&Operation::Reverse, &[b"abcd"]);
        assert_output_length_matches_evaluation(&Operation::RotateLeft(1), &[b"abcd"]);
        assert_output_length_matches_evaluation(&Operation::RotateRight(1), &[b"abcd"]);
        assert_output_length_matches_evaluation(&Operation::Xor(vec![0x20]), &[b"AZ"]);
        assert_output_length_matches_evaluation(&Operation::EvenBytes, &[b"abcdef"]);
        assert_output_length_matches_evaluation(&Operation::OddBytes, &[b"abcdef"]);
        assert_output_length_matches_evaluation(&Operation::Permute(vec![2, 0, 1]), &[b"abc"]);
        assert_output_length_matches_evaluation(&Operation::Slice { start: 1, end: 3 }, &[b"abcd"]);
        assert_output_length_matches_evaluation(&Operation::Concat, &[b"ab", b"cd"]);
        assert_output_length_matches_evaluation(&Operation::AddModulo, &[&[250, 1], &[10, 2]]);
        assert_output_length_matches_evaluation(&Operation::SubModulo, &[&[4, 1], &[10, 2]]);
        assert_output_length_matches_evaluation(&Operation::HexEncode, &[&[0xab, 0x01]]);
        assert_output_length_matches_evaluation(&Operation::HexDecode, &[b"ab01"]);
        assert_output_length_matches_evaluation(&Operation::Base64UrlEncode, &[b"a?"]);
        assert_output_length_matches_evaluation(&Operation::Base64UrlDecode, &[b"YT8"]);
        assert_output_length_matches_evaluation(&Operation::Sha256Prefix(4), &[b"abc"]);
        assert_output_length_matches_evaluation(
            &Operation::RotateLeftDerived,
            &[&b"abcd"[..], &[5]],
        );
        assert_output_length_matches_evaluation(
            &Operation::ConditionalOrder,
            &[&[2], &b"ab"[..], &b"cd"[..]],
        );
    }

    fn assert_output_length_matches_evaluation(operation: &Operation, inputs: &[&[u8]]) {
        let input_lengths: Vec<usize> = inputs.iter().map(|input| input.len()).collect();
        assert_eq!(
            operation.output_length(&input_lengths),
            operation.evaluate(inputs).map(|output| output.len())
        );
    }
}
