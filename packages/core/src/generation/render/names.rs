use crate::generation::random::{RandomSource, sample_below, shuffle};

use super::error::RenderError;

#[allow(dead_code)]
pub(super) const MAX_IDENTIFIER_BYTES: usize = 16;
#[allow(dead_code)]
pub(super) const MAX_ALLOCATED_NAMES: usize = 48;

const FIRST_ALPHABET: [u8; 52] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const CONTINUATION_ALPHABET: [u8; 63] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";

pub(super) const LEGACY_HELPER_IDENTIFIERS: &[&str] = &[
    "bytes_ascii",
    "reverse",
    "rotate_left",
    "rotate_right",
    "xor_repeat",
    "even_bytes",
    "odd_bytes",
    "permute",
    "slice",
    "concat",
    "add_u8",
    "sub_u8",
    "hex_lower",
    "hex_decode_lower",
    "base64url_no_pad",
    "base64url_decode_no_pad",
    "sha256_prefix",
    "rotate_left_derived",
    "conditional_order",
];

// Union of reserved words and reserved identifiers in C, C++, Rust, Go, and Java.
const RESERVED_WORDS: &[&str] = &[
    "Self",
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_BitInt",
    "_Bool",
    "_Complex",
    "_Decimal128",
    "_Decimal32",
    "_Decimal64",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
    "abstract",
    "alignas",
    "alignof",
    "and",
    "and_eq",
    "as",
    "asm",
    "assert",
    "async",
    "atomic_cancel",
    "atomic_commit",
    "atomic_noexcept",
    "auto",
    "await",
    "become",
    "bitand",
    "bitor",
    "bool",
    "boolean",
    "box",
    "break",
    "byte",
    "case",
    "catch",
    "chan",
    "char",
    "char16_t",
    "char32_t",
    "char8_t",
    "class",
    "co_await",
    "co_return",
    "co_yield",
    "compl",
    "concept",
    "const",
    "const_cast",
    "consteval",
    "constexpr",
    "constinit",
    "continue",
    "contract_assert",
    "crate",
    "decltype",
    "default",
    "defer",
    "delete",
    "do",
    "double",
    "dyn",
    "dynamic_cast",
    "else",
    "enum",
    "explicit",
    "export",
    "exports",
    "extends",
    "extern",
    "fallthrough",
    "false",
    "final",
    "finally",
    "float",
    "fn",
    "for",
    "friend",
    "func",
    "gen",
    "go",
    "goto",
    "if",
    "impl",
    "implements",
    "import",
    "in",
    "inline",
    "instanceof",
    "int",
    "interface",
    "let",
    "long",
    "loop",
    "macro",
    "macro_rules",
    "map",
    "match",
    "mod",
    "module",
    "move",
    "mut",
    "mutable",
    "namespace",
    "native",
    "new",
    "noexcept",
    "not",
    "not_eq",
    "null",
    "nullptr",
    "open",
    "opens",
    "operator",
    "or",
    "or_eq",
    "override",
    "package",
    "permits",
    "private",
    "priv",
    "protected",
    "provides",
    "pub",
    "public",
    "range",
    "raw",
    "record",
    "ref",
    "reflexpr",
    "register",
    "reinterpret_cast",
    "requires",
    "restrict",
    "return",
    "safe",
    "sealed",
    "select",
    "self",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "static_cast",
    "strictfp",
    "struct",
    "super",
    "switch",
    "synchronized",
    "template",
    "this",
    "thread_local",
    "throw",
    "throws",
    "to",
    "trait",
    "transient",
    "transitive",
    "true",
    "try",
    "type",
    "typedef",
    "typeid",
    "typename",
    "typeof",
    "typeof_unqual",
    "union",
    "unsafe",
    "unsigned",
    "unsized",
    "use",
    "uses",
    "using",
    "var",
    "virtual",
    "void",
    "volatile",
    "wchar_t",
    "when",
    "where",
    "while",
    "with",
    "xor",
    "xor_eq",
    "yield",
];

#[derive(Clone)]
struct IdentifierProfile {
    first_alphabet: [u8; FIRST_ALPHABET.len()],
    continuation_alphabet: [u8; CONTINUATION_ALPHABET.len()],
    salt: Vec<u8>,
    start_offset: u8,
    minimum_body_width: usize,
}

#[allow(dead_code)]
pub(super) struct NameAllocator {
    profile: IdentifierProfile,
    allocated_count: usize,
    next_ordinal: usize,
}

#[allow(dead_code)]
impl NameAllocator {
    pub(super) fn new(random: &mut impl RandomSource) -> Result<Self, RenderError> {
        let mut first_alphabet = FIRST_ALPHABET;
        shuffle(random, &mut first_alphabet).map_err(RenderError::from_generation_error)?;

        let mut continuation_alphabet = CONTINUATION_ALPHABET;
        shuffle(random, &mut continuation_alphabet).map_err(RenderError::from_generation_error)?;

        let salt_length = sample_below(random, 3).map_err(RenderError::from_generation_error)?;
        let mut salt = Vec::with_capacity(salt_length);
        for _ in 0..salt_length {
            let index = sample_below(random, first_alphabet.len())
                .map_err(RenderError::from_generation_error)?;
            salt.push(first_alphabet[index]);
        }

        let start_offset = sample_below(random, 256)
            .map_err(RenderError::from_generation_error)?
            .try_into()
            .map_err(|_| RenderError::NameExhausted)?;
        let minimum_body_width =
            2 + sample_below(random, 3).map_err(RenderError::from_generation_error)?;

        Ok(Self::from_profile(IdentifierProfile {
            first_alphabet,
            continuation_alphabet,
            salt,
            start_offset,
            minimum_body_width,
        }))
    }

    fn from_profile(profile: IdentifierProfile) -> Self {
        Self {
            profile,
            allocated_count: 0,
            next_ordinal: 0,
        }
    }

    pub(super) fn allocate_identifier(&mut self) -> Result<String, RenderError> {
        self.allocate_identifier_avoiding(&std::collections::BTreeSet::new())
    }

    pub(super) fn allocate_identifier_avoiding(
        &mut self,
        forbidden: &std::collections::BTreeSet<String>,
    ) -> Result<String, RenderError> {
        if self.allocated_count >= MAX_ALLOCATED_NAMES {
            return Err(RenderError::NameExhausted);
        }

        let maximum_skips = RESERVED_WORDS
            .len()
            .checked_add(LEGACY_HELPER_IDENTIFIERS.len())
            .and_then(|count| count.checked_add(forbidden.len()))
            .ok_or(RenderError::NameExhausted)?;
        for _ in 0..=maximum_skips {
            let ordinal = self.next_ordinal;
            let next_ordinal = ordinal.checked_add(1).ok_or(RenderError::NameExhausted)?;
            let candidate = encode_candidate(&self.profile, ordinal)?;
            self.next_ordinal = next_ordinal;
            if is_valid_identifier(&candidate) && !forbidden.contains(&candidate) {
                self.allocated_count = self
                    .allocated_count
                    .checked_add(1)
                    .ok_or(RenderError::NameExhausted)?;
                return Ok(candidate);
            }
        }

        Err(RenderError::NameExhausted)
    }
}

fn encode_candidate(profile: &IdentifierProfile, ordinal: usize) -> Result<String, RenderError> {
    let position = usize::from(profile.start_offset)
        .checked_add(ordinal)
        .ok_or(RenderError::NameExhausted)?;
    let body = encode_body(profile, position)?;
    let name_length = profile
        .salt
        .len()
        .checked_add(body.len())
        .ok_or(RenderError::NameExhausted)?;
    if name_length > MAX_IDENTIFIER_BYTES {
        return Err(RenderError::NameExhausted);
    }

    let mut bytes = Vec::with_capacity(name_length);
    bytes.extend_from_slice(&profile.salt);
    bytes.extend_from_slice(&body);
    String::from_utf8(bytes).map_err(|_| RenderError::NameExhausted)
}

fn encode_body(profile: &IdentifierProfile, position: usize) -> Result<Vec<u8>, RenderError> {
    if profile.minimum_body_width == 0
        || profile
            .salt
            .len()
            .checked_add(profile.minimum_body_width)
            .is_none_or(|length| length > MAX_IDENTIFIER_BYTES)
    {
        return Err(RenderError::NameExhausted);
    }

    let mut width = profile.minimum_body_width;
    let mut within_width = position;
    loop {
        let capacity = body_capacity(width).ok_or(RenderError::NameExhausted)?;
        if within_width < capacity {
            break;
        }
        within_width = within_width
            .checked_sub(capacity)
            .ok_or(RenderError::NameExhausted)?;
        width = width.checked_add(1).ok_or(RenderError::NameExhausted)?;
        if profile
            .salt
            .len()
            .checked_add(width)
            .is_none_or(|length| length > MAX_IDENTIFIER_BYTES)
        {
            return Err(RenderError::NameExhausted);
        }
    }

    let continuation_places = width.checked_sub(1).ok_or(RenderError::NameExhausted)?;
    let first_divisor = checked_power(CONTINUATION_ALPHABET.len(), continuation_places)
        .ok_or(RenderError::NameExhausted)?;
    let first_index = within_width / first_divisor;
    let mut remainder = within_width % first_divisor;
    let first = *profile
        .first_alphabet
        .get(first_index)
        .ok_or(RenderError::NameExhausted)?;
    let mut body = Vec::with_capacity(width);
    body.push(first);

    for remaining_places in (0..continuation_places).rev() {
        let divisor = checked_power(CONTINUATION_ALPHABET.len(), remaining_places)
            .ok_or(RenderError::NameExhausted)?;
        let index = remainder / divisor;
        remainder %= divisor;
        body.push(
            *profile
                .continuation_alphabet
                .get(index)
                .ok_or(RenderError::NameExhausted)?,
        );
    }

    Ok(body)
}

fn body_capacity(width: usize) -> Option<usize> {
    let continuation_places = width.checked_sub(1)?;
    FIRST_ALPHABET.len().checked_mul(checked_power(
        CONTINUATION_ALPHABET.len(),
        continuation_places,
    )?)
}

fn checked_power(base: usize, exponent: usize) -> Option<usize> {
    (0..exponent).try_fold(1_usize, |value, _| value.checked_mul(base))
}

fn is_reserved_word(candidate: &str) -> bool {
    RESERVED_WORDS.contains(&candidate)
}

pub(super) fn is_valid_identifier(candidate: &str) -> bool {
    let Some((first, remaining)) = candidate.as_bytes().split_first() else {
        return false;
    };

    candidate.len() <= MAX_IDENTIFIER_BYTES
        && first.is_ascii_alphabetic()
        && remaining
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        && !candidate.as_bytes().windows(2).any(|pair| pair == b"__")
        && !is_reserved_word(candidate)
        && !LEGACY_HELPER_IDENTIFIERS.contains(&candidate)
}

pub(super) fn ascii_identifier_tokens(input: &str) -> impl Iterator<Item = &str> {
    let bytes = input.as_bytes();
    let mut index = 0;
    std::iter::from_fn(move || {
        while index < bytes.len() && !(bytes[index].is_ascii_alphabetic() || bytes[index] == b'_') {
            index += 1;
        }
        if index == bytes.len() {
            return None;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        Some(&input[start..index])
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        CONTINUATION_ALPHABET, FIRST_ALPHABET, IdentifierProfile, LEGACY_HELPER_IDENTIFIERS,
        MAX_ALLOCATED_NAMES, MAX_IDENTIFIER_BYTES, NameAllocator, RESERVED_WORDS, body_capacity,
        encode_candidate, is_reserved_word, is_valid_identifier,
    };
    use crate::generation::{
        GenerationError, random::RandomSource, render::error::RenderError,
        test_random::DeterministicRandom,
    };

    const C_RESERVED_WORDS: &[&str] = &[
        "_Alignas",
        "_Alignof",
        "_Atomic",
        "_BitInt",
        "_Bool",
        "_Complex",
        "_Decimal128",
        "_Decimal32",
        "_Decimal64",
        "_Generic",
        "_Imaginary",
        "_Noreturn",
        "_Static_assert",
        "_Thread_local",
        "alignas",
        "alignof",
        "auto",
        "bool",
        "break",
        "case",
        "char",
        "const",
        "constexpr",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "false",
        "float",
        "for",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "nullptr",
        "register",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "static_assert",
        "struct",
        "switch",
        "thread_local",
        "true",
        "typedef",
        "typeof",
        "typeof_unqual",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
    ];

    const CPP_RESERVED_ADDITIONS: &[&str] = &[
        "and",
        "and_eq",
        "asm",
        "atomic_cancel",
        "atomic_commit",
        "atomic_noexcept",
        "bitand",
        "bitor",
        "catch",
        "char16_t",
        "char32_t",
        "char8_t",
        "class",
        "co_await",
        "co_return",
        "co_yield",
        "compl",
        "concept",
        "const_cast",
        "consteval",
        "constinit",
        "contract_assert",
        "decltype",
        "delete",
        "dynamic_cast",
        "explicit",
        "export",
        "final",
        "friend",
        "import",
        "module",
        "mutable",
        "namespace",
        "new",
        "noexcept",
        "not",
        "not_eq",
        "operator",
        "or",
        "or_eq",
        "override",
        "private",
        "protected",
        "public",
        "reflexpr",
        "reinterpret_cast",
        "requires",
        "static_cast",
        "synchronized",
        "template",
        "this",
        "throw",
        "try",
        "typeid",
        "typename",
        "using",
        "virtual",
        "wchar_t",
        "xor",
        "xor_eq",
    ];

    const RUST_RESERVED_WORDS: &[&str] = &[
        "Self",
        "abstract",
        "as",
        "async",
        "await",
        "become",
        "box",
        "break",
        "const",
        "continue",
        "crate",
        "do",
        "dyn",
        "else",
        "enum",
        "extern",
        "false",
        "final",
        "fn",
        "for",
        "gen",
        "if",
        "impl",
        "in",
        "let",
        "loop",
        "macro",
        "macro_rules",
        "match",
        "mod",
        "move",
        "mut",
        "override",
        "priv",
        "pub",
        "raw",
        "ref",
        "return",
        "safe",
        "self",
        "static",
        "struct",
        "super",
        "trait",
        "true",
        "try",
        "type",
        "typeof",
        "union",
        "unsafe",
        "unsized",
        "use",
        "virtual",
        "where",
        "while",
        "yield",
    ];

    const GO_RESERVED_WORDS: &[&str] = &[
        "break",
        "case",
        "chan",
        "const",
        "continue",
        "default",
        "defer",
        "else",
        "fallthrough",
        "for",
        "func",
        "go",
        "goto",
        "if",
        "import",
        "interface",
        "map",
        "package",
        "range",
        "return",
        "select",
        "struct",
        "switch",
        "type",
        "var",
    ];

    const JAVA_RESERVED_WORDS: &[&str] = &[
        "abstract",
        "assert",
        "boolean",
        "break",
        "byte",
        "case",
        "catch",
        "char",
        "class",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "exports",
        "extends",
        "false",
        "final",
        "finally",
        "float",
        "for",
        "goto",
        "if",
        "implements",
        "import",
        "instanceof",
        "int",
        "interface",
        "long",
        "module",
        "native",
        "new",
        "null",
        "open",
        "opens",
        "package",
        "permits",
        "private",
        "protected",
        "provides",
        "public",
        "record",
        "requires",
        "return",
        "sealed",
        "short",
        "static",
        "strictfp",
        "super",
        "switch",
        "synchronized",
        "this",
        "throw",
        "throws",
        "to",
        "transient",
        "transitive",
        "true",
        "try",
        "uses",
        "var",
        "void",
        "volatile",
        "when",
        "while",
        "with",
        "yield",
    ];

    #[derive(Default)]
    struct CountingRandom {
        fills: usize,
    }

    impl RandomSource for CountingRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
            self.fills += 1;
            destination.fill(0);
            Ok(())
        }
    }

    struct ScriptedRandom {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl RandomSource for ScriptedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
            let end = self.offset + destination.len();
            let source = self
                .bytes
                .get(self.offset..end)
                .ok_or(GenerationError::RandomnessUnavailable)?;
            destination.copy_from_slice(source);
            self.offset = end;
            Ok(())
        }
    }

    fn sequence_for(seed: u8) -> Vec<String> {
        let mut random = DeterministicRandom::new([seed; 32]);
        let mut allocator = NameAllocator::new(&mut random).unwrap();
        (0..MAX_ALLOCATED_NAMES)
            .map(|_| allocator.allocate_identifier().unwrap())
            .collect()
    }

    #[test]
    fn equal_seeds_produce_the_same_forty_eight_name_sequence() {
        assert_eq!(MAX_ALLOCATED_NAMES, 48);
        assert_eq!(sequence_for(0xA5), sequence_for(0xA5));
    }

    #[test]
    fn checked_in_reserved_union_matches_authoritative_language_tables() {
        let authoritative = [
            C_RESERVED_WORDS,
            CPP_RESERVED_ADDITIONS,
            RUST_RESERVED_WORDS,
            GO_RESERVED_WORDS,
            JAVA_RESERVED_WORDS,
        ]
        .into_iter()
        .flatten()
        .copied()
        .collect::<BTreeSet<_>>();
        let production = RESERVED_WORDS.iter().copied().collect::<BTreeSet<_>>();

        assert!(CPP_RESERVED_ADDITIONS.contains(&"contract_assert"));
        assert_eq!(production.len(), RESERVED_WORDS.len());
        assert_eq!(production, authoritative);
    }

    #[test]
    fn current_cpp_contract_keyword_is_reserved_and_skipped() {
        assert!(is_reserved_word("contract_assert"));

        let mut profile = identity_profile();
        profile.salt = b"contract_as".to_vec();
        profile.start_offset = 65;
        profile.minimum_body_width = 4;
        move_to_front(&mut profile.first_alphabet, b's');
        move_to_index(&mut profile.continuation_alphabet, b'e', 0);
        move_to_index(&mut profile.continuation_alphabet, b'r', 1);
        move_to_index(&mut profile.continuation_alphabet, b't', 2);
        assert_eq!(encode_candidate(&profile, 0).unwrap(), "contract_assert");

        let expected = encode_candidate(&profile, 1).unwrap();
        let mut allocator = NameAllocator::from_profile(profile);

        assert_eq!(allocator.allocate_identifier().unwrap(), expected);
        assert_eq!(allocator.next_ordinal, 2);
    }

    #[test]
    fn shared_identifier_policy_covers_every_reserved_form() {
        assert!(is_valid_identifier("portable_name9"));
        for reserved in RESERVED_WORDS
            .iter()
            .chain(LEGACY_HELPER_IDENTIFIERS)
            .chain(["_implementation", "A__B"].iter())
        {
            assert!(!is_valid_identifier(reserved), "accepted {reserved:?}");
        }
        for malformed in ["", "9name", "not-portable", "abcdefghijklmnopq"] {
            assert!(!is_valid_identifier(malformed), "accepted {malformed:?}");
        }
    }

    #[test]
    fn seed_matrix_exercises_profile_variation() {
        let mut first_alphabets = BTreeSet::new();
        let mut continuation_alphabets = BTreeSet::new();
        let mut salt_lengths = BTreeSet::new();
        let mut offsets = BTreeSet::new();
        let mut widths = BTreeSet::new();

        for seed in 0_u8..=255 {
            let mut random = DeterministicRandom::new([seed; 32]);
            let allocator = NameAllocator::new(&mut random).unwrap();
            first_alphabets.insert(allocator.profile.first_alphabet.to_vec());
            continuation_alphabets.insert(allocator.profile.continuation_alphabet.to_vec());
            salt_lengths.insert(allocator.profile.salt.len());
            offsets.insert(allocator.profile.start_offset);
            widths.insert(allocator.profile.minimum_body_width);
            assert!(allocator.profile.salt.iter().all(|byte| {
                byte.is_ascii_alphabetic() && allocator.profile.first_alphabet.contains(byte)
            }));
        }

        assert!(first_alphabets.len() > 1);
        assert!(continuation_alphabets.len() > 1);
        assert_eq!(salt_lengths, BTreeSet::from([0, 1, 2]));
        assert!(offsets.len() > 1);
        assert_eq!(widths, BTreeSet::from([2, 3, 4]));
    }

    #[test]
    fn sampled_alphabets_are_exact_permutations() {
        let expected_first = FIRST_ALPHABET.into_iter().collect::<BTreeSet<_>>();
        let expected_continuation = CONTINUATION_ALPHABET.into_iter().collect::<BTreeSet<_>>();

        assert_eq!(expected_first.len(), FIRST_ALPHABET.len());
        assert_eq!(expected_continuation.len(), CONTINUATION_ALPHABET.len());

        for seed in [0, 1, 2, 31, 127, 255] {
            let mut random = DeterministicRandom::new([seed; 32]);
            let allocator = NameAllocator::new(&mut random).unwrap();
            assert_eq!(
                allocator
                    .profile
                    .first_alphabet
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                expected_first
            );
            assert_eq!(
                allocator
                    .profile
                    .continuation_alphabet
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                expected_continuation
            );
        }
    }

    #[test]
    fn representative_profiles_allocate_unique_portable_non_reserved_names() {
        for seed in [0, 1, 2, 7, 31, 63, 127, 255] {
            let names = sequence_for(seed);
            let unique = names.iter().collect::<BTreeSet<_>>();

            assert_eq!(names.len(), MAX_ALLOCATED_NAMES);
            assert_eq!(unique.len(), MAX_ALLOCATED_NAMES);
            for name in names {
                assert!(!name.is_empty());
                assert!(name.len() <= MAX_IDENTIFIER_BYTES);
                assert!(name.as_bytes()[0].is_ascii_alphabetic());
                assert!(
                    name.as_bytes()[1..]
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                );
                assert!(!name.contains("__"));
                assert!(!is_reserved_word(&name));
            }
        }
    }

    #[test]
    fn positional_encoding_crosses_width_capacity_without_repetition() {
        let profile = identity_profile();
        let last_width_two = body_capacity(2).unwrap() - 1;

        let before = encode_candidate(&profile, last_width_two).unwrap();
        let after = encode_candidate(&profile, last_width_two + 1).unwrap();
        let following = encode_candidate(&profile, last_width_two + 2).unwrap();

        assert_eq!(before, "z_");
        assert_eq!(after, "AAA");
        assert_eq!(following, "AAB");
        assert_eq!(BTreeSet::from([before, after, following]).len(), 3);
    }

    #[test]
    fn reserved_word_skip_is_deterministic_and_advances_once() {
        let mut profile = identity_profile();
        move_to_front(&mut profile.first_alphabet, b'i');
        move_to_front(&mut profile.continuation_alphabet, b'f');
        assert_eq!(encode_candidate(&profile, 0).unwrap(), "if");

        let mut first = NameAllocator::from_profile(profile.clone());
        let mut second = NameAllocator::from_profile(profile.clone());
        let expected = encode_candidate(&profile, 1).unwrap();

        assert_eq!(first.allocate_identifier().unwrap(), expected);
        assert_eq!(second.allocate_identifier().unwrap(), expected);
        assert_eq!(first.next_ordinal, 2);
        assert_eq!(first.allocated_count, 1);
    }

    #[test]
    fn legacy_helper_identifier_is_skipped_like_a_reserved_word() {
        let mut profile = identity_profile();
        profile.salt = b"sli".to_vec();
        profile.minimum_body_width = 2;
        move_to_front(&mut profile.first_alphabet, b'c');
        move_to_front(&mut profile.continuation_alphabet, b'e');
        assert_eq!(encode_candidate(&profile, 0).unwrap(), "slice");

        let mut allocator = NameAllocator::from_profile(profile);
        assert_ne!(allocator.allocate_identifier().unwrap(), "slice");
        assert_eq!(allocator.next_ordinal, 2);
        assert_eq!(allocator.allocated_count, 1);
    }

    #[test]
    fn structurally_reserved_double_underscore_run_is_skipped() {
        let mut profile = identity_profile();
        profile.minimum_body_width = 4;
        move_to_front(&mut profile.continuation_alphabet, b'_');
        assert_eq!(encode_candidate(&profile, 0).unwrap(), "A___");

        let mut allocator = NameAllocator::from_profile(profile);

        assert_eq!(allocator.allocate_identifier().unwrap(), "A_B_");
        assert_eq!(allocator.next_ordinal, 64);
    }

    #[test]
    fn forty_ninth_allocation_is_exact_exhaustion_without_more_randomness() {
        let mut random = CountingRandom::default();
        let mut allocator = NameAllocator::new(&mut random).unwrap();
        let construction_fills = random.fills;

        for _ in 0..MAX_ALLOCATED_NAMES {
            allocator.allocate_identifier().unwrap();
        }

        assert_eq!(
            allocator.allocate_identifier(),
            Err(RenderError::NameExhausted)
        );
        assert_eq!(random.fills, construction_fills);
    }

    #[test]
    fn randomness_failure_happens_at_construction_and_maps_safely() {
        let mut random = ScriptedRandom {
            bytes: vec![0; FIRST_ALPHABET.len() - 1],
            offset: 0,
        };
        let error = match NameAllocator::new(&mut random) {
            Ok(_) => panic!("allocator construction must fail"),
            Err(error) => error,
        };

        assert_eq!(error, RenderError::RandomnessUnavailable);
        assert_eq!(error.to_string(), "cryptographic randomness is unavailable");
    }

    fn identity_profile() -> IdentifierProfile {
        IdentifierProfile {
            first_alphabet: FIRST_ALPHABET,
            continuation_alphabet: CONTINUATION_ALPHABET,
            salt: Vec::new(),
            start_offset: 0,
            minimum_body_width: 2,
        }
    }

    fn move_to_front<const N: usize>(values: &mut [u8; N], target: u8) {
        let index = values.iter().position(|value| *value == target).unwrap();
        values.swap(0, index);
    }

    fn move_to_index<const N: usize>(values: &mut [u8; N], target: u8, target_index: usize) {
        let current_index = values.iter().position(|value| *value == target).unwrap();
        values.swap(target_index, current_index);
    }
}
