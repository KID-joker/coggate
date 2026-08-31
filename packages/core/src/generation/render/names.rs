use std::collections::BTreeSet;

use crate::generation::random::{RandomSource, sample_below};

use super::error::RenderError;

#[allow(dead_code)]
pub(super) const MAX_IDENTIFIER_BYTES: usize = 16;
#[allow(dead_code)]
pub(super) const MAX_ALLOCATED_NAMES: usize = 32;

#[allow(dead_code)]
const NAME_STEMS: [&str; 8] = [
    "buf", "chunk", "data", "part", "piece", "result", "step", "value",
];
#[allow(dead_code)]
const SUFFIX_COUNT: usize = MAX_ALLOCATED_NAMES / NAME_STEMS.len();

#[allow(dead_code)]
pub(super) struct NameAllocator<'a, R: RandomSource> {
    allocated: BTreeSet<String>,
    random: &'a mut R,
}

#[allow(dead_code)]
impl<'a, R: RandomSource> NameAllocator<'a, R> {
    pub(super) fn new(random: &'a mut R) -> Self {
        Self {
            allocated: BTreeSet::new(),
            random,
        }
    }

    pub(super) fn allocate_identifier(&mut self) -> Result<String, RenderError> {
        if self.allocated.len() >= MAX_ALLOCATED_NAMES {
            return Err(RenderError::NameExhausted);
        }

        let start =
            sample_below(self.random, MAX_ALLOCATED_NAMES).map_err(|_| RenderError::InvalidPlan)?;

        for offset in 0..MAX_ALLOCATED_NAMES {
            let index = (start + offset) % MAX_ALLOCATED_NAMES;
            let stem = NAME_STEMS[index / SUFFIX_COUNT];
            let suffix = index % SUFFIX_COUNT;
            let candidate = format!("{stem}_{suffix}");
            if self.allocated.insert(candidate.clone()) {
                return Ok(candidate);
            }
        }

        Err(RenderError::NameExhausted)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{MAX_ALLOCATED_NAMES, MAX_IDENTIFIER_BYTES, NameAllocator};
    use crate::generation::{
        GenerationError, random::RandomSource, render::error::RenderError,
        test_random::DeterministicRandom,
    };

    struct FiniteRandom {
        remaining: usize,
    }

    impl RandomSource for FiniteRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
            if destination.len() > self.remaining {
                return Err(GenerationError::RandomnessUnavailable);
            }
            destination.fill(0);
            self.remaining -= destination.len();
            Ok(())
        }
    }

    #[test]
    fn allocates_the_complete_namespace_without_duplicates() {
        let mut random = DeterministicRandom::new([0xA5; 32]);
        let mut allocator = NameAllocator::new(&mut random);
        let names = (0..MAX_ALLOCATED_NAMES)
            .map(|_| allocator.allocate_identifier().unwrap())
            .collect::<BTreeSet<_>>();

        assert_eq!(names.len(), MAX_ALLOCATED_NAMES);
    }

    #[test]
    fn allocated_identifiers_are_bounded_and_portable() {
        let mut random = DeterministicRandom::new([0x5A; 32]);
        let mut allocator = NameAllocator::new(&mut random);

        for _ in 0..MAX_ALLOCATED_NAMES {
            let name = allocator.allocate_identifier().unwrap();
            assert!(name.len() <= MAX_IDENTIFIER_BYTES);
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            );
        }
    }

    #[test]
    fn reports_exhaustion_after_the_complete_namespace_is_allocated() {
        let mut random = DeterministicRandom::new([0x3C; 32]);
        let mut allocator = NameAllocator::new(&mut random);
        for _ in 0..MAX_ALLOCATED_NAMES {
            allocator.allocate_identifier().unwrap();
        }

        assert_eq!(
            allocator.allocate_identifier(),
            Err(RenderError::NameExhausted)
        );
    }

    #[test]
    fn reports_name_exhaustion_without_requesting_more_randomness() {
        let mut random = FiniteRandom {
            remaining: MAX_ALLOCATED_NAMES,
        };
        let mut allocator = NameAllocator::new(&mut random);
        for _ in 0..MAX_ALLOCATED_NAMES {
            allocator.allocate_identifier().unwrap();
        }

        assert_eq!(
            allocator.allocate_identifier(),
            Err(RenderError::NameExhausted)
        );
    }
}
