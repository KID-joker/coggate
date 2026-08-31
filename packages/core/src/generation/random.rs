use super::GenerationError;

pub(crate) trait RandomSource {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError>;
}

pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
        getrandom::fill(destination).map_err(|_| GenerationError::RandomnessUnavailable)
    }
}

pub(crate) fn sample_below(
    random: &mut impl RandomSource,
    upper: usize,
) -> Result<usize, GenerationError> {
    if upper == 0 || upper > 256 {
        return Err(GenerationError::InvalidOperation);
    }

    let acceptance = 256 - (256 % upper);
    loop {
        let mut byte = [0_u8; 1];
        random.fill(&mut byte)?;
        let value = usize::from(byte[0]);
        if value < acceptance {
            return Ok(value % upper);
        }
    }
}

pub(crate) fn shuffle<T>(
    random: &mut impl RandomSource,
    values: &mut [T],
) -> Result<(), GenerationError> {
    for index in (1..values.len()).rev() {
        let other = sample_below(random, index + 1)?;
        values.swap(index, other);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ScriptedRandom(Vec<u8>);

    impl RandomSource for ScriptedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
            if self.0.len() < destination.len() {
                return Err(GenerationError::RandomnessUnavailable);
            }
            destination.copy_from_slice(&self.0[..destination.len()]);
            self.0.drain(..destination.len());
            Ok(())
        }
    }

    #[test]
    fn samples_only_inside_the_requested_bound() {
        let mut random = ScriptedRandom((0_u8..=255).cycle().take(4096).collect());
        for upper in 1..=62 {
            for _ in 0..32 {
                assert!(sample_below(&mut random, upper).unwrap() < upper);
            }
        }
    }

    #[test]
    fn rejects_out_of_range_bytes_before_sampling() {
        let mut random = ScriptedRandom(vec![255, 7]);

        assert_eq!(sample_below(&mut random, 10), Ok(7));
    }

    #[test]
    fn samples_the_full_byte_range() {
        let mut random = ScriptedRandom(vec![255]);

        assert_eq!(sample_below(&mut random, 256), Ok(255));
    }

    #[test]
    fn rejects_invalid_sampling_bounds() {
        let mut random = ScriptedRandom(vec![]);

        assert_eq!(
            sample_below(&mut random, 0),
            Err(GenerationError::InvalidOperation)
        );
        assert_eq!(
            sample_below(&mut random, 257),
            Err(GenerationError::InvalidOperation)
        );
    }

    #[test]
    fn propagates_random_source_exhaustion() {
        let mut random = ScriptedRandom(vec![]);

        assert_eq!(
            sample_below(&mut random, 10),
            Err(GenerationError::RandomnessUnavailable)
        );
    }

    #[test]
    fn shuffling_preserves_every_element_once() {
        let mut values = vec![1, 2, 3, 4, 5, 6];
        let mut random = ScriptedRandom((0_u8..=255).cycle().take(128).collect());
        shuffle(&mut random, &mut values).unwrap();
        values.sort_unstable();
        assert_eq!(values, vec![1, 2, 3, 4, 5, 6]);
    }
}
