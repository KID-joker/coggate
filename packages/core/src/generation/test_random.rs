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
}
