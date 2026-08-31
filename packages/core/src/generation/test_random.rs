use sha2::{Digest, Sha256};

use super::{GenerationError, random::RandomSource};

pub(crate) struct DeterministicRandom {
    seed: [u8; 32],
    counter: u64,
}

impl DeterministicRandom {
    pub(crate) const fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }
}

impl RandomSource for DeterministicRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
        for chunk in destination.chunks_mut(32) {
            let mut hasher = Sha256::new();
            hasher.update(self.seed);
            hasher.update(self.counter.to_be_bytes());
            let block = hasher.finalize();
            chunk.copy_from_slice(&block[..chunk.len()]);
            self.counter = self.counter.wrapping_add(1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_repeatable_streams_for_equal_seeds() {
        let mut first = DeterministicRandom::new([42; 32]);
        let mut second = DeterministicRandom::new([42; 32]);
        let mut first_bytes = [0; 97];
        let mut second_bytes = [0; 97];

        first.fill(&mut first_bytes).unwrap();
        second.fill(&mut second_bytes).unwrap();

        assert_eq!(first_bytes, second_bytes);
    }

    #[test]
    fn produces_distinct_current_samples_for_different_seeds() {
        let mut first = DeterministicRandom::new([1; 32]);
        let mut second = DeterministicRandom::new([2; 32]);
        let mut first_bytes = [0; 97];
        let mut second_bytes = [0; 97];

        first.fill(&mut first_bytes).unwrap();
        second.fill(&mut second_bytes).unwrap();

        assert_ne!(first_bytes, second_bytes);
    }

    #[test]
    fn advances_the_counter_across_consecutive_fills() {
        let seed = [0xA5; 32];
        let mut expected = Vec::new();
        for counter in 0_u64..=2 {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(counter.to_be_bytes());
            expected.extend_from_slice(&hasher.finalize());
        }

        let mut random = DeterministicRandom::new(seed);
        let mut first_fill = [0; 64];
        let mut second_fill = [0; 32];
        random.fill(&mut first_fill).unwrap();
        random.fill(&mut second_fill).unwrap();

        assert_eq!(first_fill.as_slice(), &expected[..64]);
        assert_eq!(second_fill.as_slice(), &expected[64..]);
    }
}
