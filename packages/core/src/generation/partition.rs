use agentgate_contracts::fragment_count_for_secret_length;

use super::GenerationError;
use super::random::{RandomSource, shuffle};

pub(crate) fn partition_with(
    secret: &[u8],
    random: &mut impl RandomSource,
) -> Result<Vec<Vec<u8>>, GenerationError> {
    let secret_length = u8::try_from(secret.len()).map_err(|_| GenerationError::InvalidLength)?;
    let fragment_count = usize::from(
        fragment_count_for_secret_length(secret_length).ok_or(GenerationError::InvalidLength)?,
    );

    let mut splits: Vec<usize> = (1..secret.len()).collect();
    shuffle(random, &mut splits)?;
    splits.truncate(fragment_count - 1);
    splits.sort_unstable();

    let mut fragments = Vec::with_capacity(fragment_count);
    let mut start = 0;
    for end in splits {
        fragments.push(secret[start..end].to_vec());
        start = end;
    }
    fragments.push(secret[start..].to_vec());

    Ok(fragments)
}

#[cfg(test)]
use super::test_random::DeterministicRandom;

#[test]
fn partitions_each_supported_length_into_the_policy_count_without_empty_fragments() {
    for length in 8_u8..=16 {
        let secret: Vec<u8> = (0..length)
            .map(|value| value.wrapping_add(length))
            .collect();

        for seed in 0_u8..=63 {
            let mut random = DeterministicRandom::new([seed; 32]);
            let fragments = partition_with(&secret, &mut random).unwrap();

            assert_eq!(
                fragments.len(),
                usize::from(fragment_count_for_secret_length(length).unwrap())
            );
            assert!(fragments.iter().all(|fragment| !fragment.is_empty()));
            assert_eq!(fragments.concat(), secret);
        }
    }
}

#[test]
fn rejects_unsupported_secret_lengths() {
    for length in [0, 7, 17] {
        let secret = vec![0; length];
        let mut random = DeterministicRandom::new([0; 32]);

        assert_eq!(
            partition_with(&secret, &mut random),
            Err(GenerationError::InvalidLength)
        );
    }
}
