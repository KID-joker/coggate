//! Bounded quality screening for the composition experiment.
//!
//! The gate removes observable shortcuts and ineffective stages from its finite
//! test suite. It does not stop a solver that correctly implements the prompt,
//! and finite witness search cannot prove equivalence on the complete domain.

use super::{Composition, Guard, RandomStream};
use crate::{
    derive_seed, hex, validate_request, Engine, Error, PrivateChallenge, PublicChallenge,
    Reference, TestCase, HIDDEN_TEST_COUNT, MAX_ATTEMPTS, MAX_INPUT_ABS, MAX_INPUT_LEN,
};
use serde::Serialize;
use serde_json::{json, Value};

const CANDIDATE_LIMIT: usize = 64;
const POOL_LIMIT: usize = 128;
const EXTRA_DRAW_LIMIT: usize = 192;
const HOLDOUT_CASE_COUNT: usize = 8;
const SEARCH_CASE_COUNT: usize = HIDDEN_TEST_COUNT - HOLDOUT_CASE_COUNT;

/// Aggregate development metrics. Contains no seeds, task parameters, input
/// values, expected outputs, or reference source. Keep separate from the public
/// challenge protocol; these counters are intended for the trusted evaluator.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ScreeningStats {
    pub candidate_limit: usize,
    pub input_pool_limit: usize,
    pub candidate_count: usize,
    pub rejected_count: usize,
    pub rejected_constant: usize,
    pub rejected_shortcut: usize,
    pub rejected_stage: usize,
    pub rejected_guard: usize,
    pub rejected_original_guard: usize,
    pub rejected_coverage: usize,
    pub total_pool_inputs: usize,
    pub peak_pool_inputs: usize,
    pub accepted_pool_inputs: usize,
    pub reference_evaluations: usize,
    pub shortcut_evaluations: usize,
    pub mutation_evaluations: usize,
    pub requirement_count: usize,
    /// Greedy witness selection size, including the four mandatory boundaries,
    /// before filling the search portion to 24 inputs.
    pub witness_case_count: usize,
    pub mandatory_case_count: usize,
    pub selected_search_case_count: usize,
    /// Independently drawn after a candidate is accepted. These inputs never
    /// participate in candidate screening or witness selection.
    pub holdout_case_count: usize,
    pub holdout_evaluations: usize,
    pub final_case_count: usize,
}

impl Engine {
    /// Development-only, bounded quality-screened composition experiment.
    ///
    /// A successful result kills the documented shortcuts and witnesses every
    /// stage deletion, conditional-to-always mutation, and original-input guard
    /// mutation on the returned suite.
    /// After 64 rejected candidates it fails explicitly; there is no fallback.
    pub fn issue_screened_composition(
        &self,
        scope: &str,
        factor: &[u8],
        now_secs: u64,
    ) -> Result<(PublicChallenge, PrivateChallenge, ScreeningStats), Error> {
        validate_request(scope, factor, now_secs)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;
        self.screened_with_nonce(scope, factor, now_secs, nonce)
    }

    fn screened_with_nonce(
        &self,
        scope: &str,
        factor: &[u8],
        now_secs: u64,
        nonce: [u8; 32],
    ) -> Result<(PublicChallenge, PrivateChallenge, ScreeningStats), Error> {
        let expires_at = validate_request(scope, factor, now_secs)?;
        let derive = |label: &[u8]| derive_seed(&self.key, label, scope.as_bytes(), factor, &nonce);
        let mut problem = RandomStream::new(derive(b"composition-screened/v3/problem"));
        let mut wording = RandomStream::new(derive(b"composition-screened/v3/wording"));
        let mut tests = RandomStream::new(derive(b"composition-screened/v3/tests"));
        let (task, mut cases, mut stats) = find_screened(
            &mut problem,
            &mut tests,
            CANDIDATE_LIMIT,
            Composition::generate,
        )
        .map_err(|_| Error::GenerationExhausted)?;
        // A separate stream is first used only after acceptance. Neither the
        // holdout values nor their outputs can influence candidate selection.
        let mut holdout = RandomStream::new(derive(b"composition-screened/v3/holdout"));
        append_holdout(&task, &mut cases, &mut stats, &mut holdout);
        let id = hex(&derive(b"composition-screened/v3/id"));
        let public = PublicChallenge {
            id: id.clone(),
            scope: scope.to_owned(),
            expires_at,
            max_attempts: MAX_ATTEMPTS,
            prompt: task.prompt(&mut wording),
        };
        let private = PrivateChallenge {
            id,
            scope: scope.to_owned(),
            expires_at,
            cases,
            reference: Reference::Composition(task.reference_solution()),
        };
        Ok((public, private, stats))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rejection {
    Constant,
    Shortcut,
    Stage,
    Guard,
    OriginalGuard,
    Coverage,
}

#[derive(Clone, Copy)]
enum Shortcut {
    Empty,
    Identity,
    Reverse,
    Sort(bool),
    Unique(bool),
    Take(usize),
}

const SHORTCUTS: [Shortcut; 15] = [
    Shortcut::Empty,
    Shortcut::Identity,
    Shortcut::Reverse,
    Shortcut::Sort(false),
    Shortcut::Sort(true),
    Shortcut::Unique(false),
    Shortcut::Unique(true),
    Shortcut::Take(1),
    Shortcut::Take(2),
    Shortcut::Take(3),
    Shortcut::Take(4),
    Shortcut::Take(5),
    Shortcut::Take(6),
    Shortcut::Take(7),
    Shortcut::Take(8),
];

impl Shortcut {
    fn evaluate(self, input: &[i64], sum: bool) -> Value {
        let mut values = input.to_vec();
        match self {
            Self::Empty => values.clear(),
            Self::Identity => {}
            Self::Reverse => values.reverse(),
            Self::Sort(descending) => {
                values.sort_unstable();
                if descending {
                    values.reverse();
                }
            }
            Self::Unique(last) => {
                values = input
                    .iter()
                    .enumerate()
                    .filter(|&(i, x)| {
                        if last {
                            !input[i + 1..].contains(x)
                        } else {
                            !input[..i].contains(x)
                        }
                    })
                    .map(|(_, &x)| x)
                    .collect();
            }
            Self::Take(count) => values.truncate(count),
        }
        // Use the task's public output shape: array tasks face array shortcuts,
        // sum tasks also face sum-of-dedup/take shortcuts, not only type errors.
        if sum {
            json!(values.iter().sum::<i64>())
        } else {
            json!(values)
        }
    }
}

fn find_screened(
    problem: &mut RandomStream,
    tests: &mut RandomStream,
    budget: usize,
    mut generate: impl FnMut(&mut RandomStream) -> Composition,
) -> Result<(Composition, Vec<TestCase>, ScreeningStats), Box<ScreeningStats>> {
    let budget = budget.min(CANDIDATE_LIMIT);
    let mut stats = ScreeningStats {
        candidate_limit: budget,
        input_pool_limit: POOL_LIMIT,
        ..ScreeningStats::default()
    };
    for _ in 0..budget {
        stats.candidate_count += 1;
        let task = generate(problem);
        let pool = input_pool(&task, tests);
        stats.total_pool_inputs += pool.len();
        stats.peak_pool_inputs = stats.peak_pool_inputs.max(pool.len());
        match screen_candidate(&task, &pool, SEARCH_CASE_COUNT, &mut stats) {
            Ok(cases) => {
                stats.accepted_pool_inputs = pool.len();
                stats.selected_search_case_count = cases.len();
                return Ok((task, cases, stats));
            }
            Err(reason) => {
                stats.rejected_count += 1;
                match reason {
                    Rejection::Constant => stats.rejected_constant += 1,
                    Rejection::Shortcut => stats.rejected_shortcut += 1,
                    Rejection::Stage => stats.rejected_stage += 1,
                    Rejection::Guard => stats.rejected_guard += 1,
                    Rejection::OriginalGuard => stats.rejected_original_guard += 1,
                    Rejection::Coverage => stats.rejected_coverage += 1,
                }
            }
        }
    }
    Err(Box::new(stats))
}

fn shuffle<T>(values: &mut [T], random: &mut RandomStream) {
    for index in (1..values.len()).rev() {
        values.swap(index, random.below((index + 1) as u64) as usize);
    }
}

/// Mix scales within each input rather than choosing one distribution for an
/// entire array. Long inputs contain every category, then draw additional
/// categories independently. Short inputs retain both a small and a large
/// value with opposite signs. The full-domain category gives every legal
/// integer positive probability; this does not promise to cover rare branches.
fn holdout_inputs(task: &Composition, random: &mut RandomStream) -> Vec<Vec<i64>> {
    const LENGTH_STRATA: [(usize, usize); HOLDOUT_CASE_COUNT] = [
        (2, 8),
        (9, 12),
        (13, 24),
        (25, 36),
        (37, 48),
        (49, 63),
        (64, 64),
        (64, 64),
    ];
    LENGTH_STRATA
        .into_iter()
        .enumerate()
        .map(|(case_index, (minimum, maximum))| {
            let length = minimum + random.below((maximum - minimum + 1) as u64) as usize;
            let sign = if random.below(2) == 0 { -1 } else { 1 };
            let mut categories = [1, 6, 0, 4, 5, 2, 3, 7];
            // Keep the first two categories for short inputs, while varying
            // which other scales are represented when fewer than eight fit.
            shuffle(&mut categories[2..], random);
            let mut input: Vec<_> = (0..length)
                .map(|index| {
                    let category = if index < categories.len() {
                        categories[index]
                    } else {
                        random.below(8)
                    };
                    let random_sign = if random.below(2) == 0 { -1 } else { 1 };
                    match category {
                        0 => 0,
                        1 => sign * super::between(random, 1, 8),
                        2 => task.predicates.threshold + super::between(random, -3, 3),
                        3 => {
                            super::between(random, -4, 4) * task.predicates.modulus
                                + task.predicates.residue
                        }
                        4 => random_sign * super::between(random, 16, 255),
                        5 => random_sign * super::between(random, 256, 4095),
                        6 => -sign * super::between(random, MAX_INPUT_ABS - 255, MAX_INPUT_ABS),
                        _ => super::between(random, -MAX_INPUT_ABS, MAX_INPUT_ABS),
                    }
                })
                .collect();
            // Permute the guaranteed category prefix without losing a scale.
            let prefix_len = length.min(categories.len());
            shuffle(&mut input[..prefix_len], random);
            if matches!(case_index, 1 | 4 | 7) {
                // These positions are beyond the category prefix. Keep that
                // coverage while adding a bounded number of duplicate values.
                for index in categories.len()..length {
                    if random.below(4) == 0 {
                        input[index] = input[random.below(categories.len() as u64) as usize];
                    }
                }
            }
            match case_index {
                2 => input.sort_unstable(),
                3 => input.sort_unstable_by(|left, right| right.cmp(left)),
                // Only some cases require a non-adjacent repeat. Forcing it
                // on every holdout would itself create a recognizable shape.
                4 | 7 => {
                    input[length - 1] = input[0];
                }
                _ => shuffle(&mut input, random),
            }
            input
        })
        .collect()
}

fn append_holdout(
    task: &Composition,
    cases: &mut Vec<TestCase>,
    stats: &mut ScreeningStats,
    random: &mut RandomStream,
) {
    let holdouts = holdout_inputs(task, random);
    stats.holdout_case_count = holdouts.len();
    stats.holdout_evaluations = holdouts.len();
    stats.reference_evaluations += holdouts.len();
    cases.extend(holdouts.into_iter().map(|input| TestCase {
        expected: task.evaluate(&input),
        input,
    }));
    shuffle(cases, random);
    stats.final_case_count = cases.len();
}

fn insert_unique(pool: &mut Vec<Vec<i64>>, input: Vec<i64>) {
    if pool.len() < POOL_LIMIT && !pool.contains(&input) {
        pool.push(input);
    }
}

fn input_pool(task: &Composition, random: &mut RandomStream) -> Vec<Vec<i64>> {
    let mut pool = Vec::with_capacity(POOL_LIMIT);
    for input in task.test_inputs(random) {
        insert_unique(&mut pool, input);
    }
    // Small exhaustive singleton probes give guards and affine/threshold
    // boundaries a chance to differ. The rest includes ordered, repeated,
    // mixed-sign and full-domain values. Every loop has a fixed upper bound.
    for value in -24..=24 {
        insert_unique(&mut pool, vec![value]);
    }
    for draw in 0..EXTRA_DRAW_LIMIT {
        if pool.len() == POOL_LIMIT {
            break;
        }
        let length = 2 + random.below(11) as usize;
        let mut input: Vec<_> = (0..length)
            .map(|_| match draw % 4 {
                0 => super::between(random, -12, 12),
                1 => task.predicates.threshold + super::between(random, -3, 3),
                2 => super::between(random, -MAX_INPUT_ABS, MAX_INPUT_ABS),
                _ => {
                    super::between(random, -4, 4) * task.predicates.modulus
                        + task.predicates.residue
                }
            })
            .collect();
        if draw % 5 == 0 {
            input.sort_unstable();
        } else if draw % 5 == 1 {
            input.sort_unstable_by(|a, b| b.cmp(a));
        } else if draw % 5 == 2 {
            input[length - 1] = input[0];
        }
        insert_unique(&mut pool, input);
    }
    pool
}

/// Record the inputs that distinguish one candidate shortcut/mutation. A
/// requirement receives a fresh bit only after a witness has been observed.
fn add_requirement(
    differences: impl Iterator<Item = bool>,
    masks: &mut [u64],
    requirement_count: &mut usize,
) -> bool {
    let bit = 1_u64 << *requirement_count;
    let mut witnessed = false;
    for (different, mask) in differences.zip(masks) {
        if different {
            *mask |= bit;
            witnessed = true;
        }
    }
    if witnessed {
        *requirement_count += 1;
    }
    witnessed
}

/// Independent semantic mutant: every guard observes the original input, while
/// its operation still transforms the current sequence. This intentionally
/// differs from the correct contract and is only used to seek counterexamples.
fn evaluate_with_original_guards(task: &Composition, input: &[i64]) -> Value {
    let mut current = input.to_vec();
    for stage in &task.stages {
        let enabled = match stage.guard {
            Guard::Always => true,
            Guard::Any(predicate) => input.iter().any(|&x| task.predicates.matches(predicate, x)),
            Guard::All(predicate) => input.iter().all(|&x| task.predicates.matches(predicate, x)),
        };
        if enabled {
            let mut operation = stage.clone();
            operation.guard = Guard::Always;
            operation.apply(&mut current, &task.predicates);
        }
    }
    if task.sum {
        json!(current.iter().sum::<i64>())
    } else {
        json!(current)
    }
}

fn screen_candidate(
    task: &Composition,
    pool: &[Vec<i64>],
    max_cases: usize,
    stats: &mut ScreeningStats,
) -> Result<Vec<TestCase>, Rejection> {
    if pool.is_empty() {
        return Err(Rejection::Coverage);
    }
    let outputs: Vec<_> = pool.iter().map(|input| task.evaluate(input)).collect();
    stats.reference_evaluations += pool.len();
    let mut masks = vec![0_u64; pool.len()];
    let mut requirements = 0;
    if !add_requirement(
        outputs.iter().map(|value| value != &outputs[0]),
        &mut masks,
        &mut requirements,
    ) {
        return Err(Rejection::Constant);
    }
    for shortcut in SHORTCUTS {
        stats.shortcut_evaluations += pool.len();
        if !add_requirement(
            pool.iter()
                .zip(&outputs)
                .map(|(input, expected)| shortcut.evaluate(input, task.sum) != *expected),
            &mut masks,
            &mut requirements,
        ) {
            return Err(Rejection::Shortcut);
        }
    }
    for index in 0..task.stages.len() {
        let mut deleted = task.clone();
        deleted.stages.remove(index);
        stats.mutation_evaluations += pool.len();
        if !add_requirement(
            pool.iter()
                .zip(&outputs)
                .map(|(input, expected)| deleted.evaluate(input) != *expected),
            &mut masks,
            &mut requirements,
        ) {
            return Err(Rejection::Stage);
        }
        if !matches!(task.stages[index].guard, Guard::Always) {
            let mut unconditional = task.clone();
            unconditional.stages[index].guard = Guard::Always;
            stats.mutation_evaluations += pool.len();
            if !add_requirement(
                pool.iter()
                    .zip(&outputs)
                    .map(|(input, expected)| unconditional.evaluate(input) != *expected),
                &mut masks,
                &mut requirements,
            ) {
                return Err(Rejection::Guard);
            }
        }
    }
    // Single-guard witnesses do not imply a witness against dropping every
    // guard together: distinct changes can cancel. Cover that attack explicitly.
    let mut no_guards = task.clone();
    for stage in &mut no_guards.stages {
        stage.guard = Guard::Always;
    }
    stats.mutation_evaluations += pool.len();
    if !add_requirement(
        pool.iter()
            .zip(&outputs)
            .map(|(input, expected)| no_guards.evaluate(input) != *expected),
        &mut masks,
        &mut requirements,
    ) {
        return Err(Rejection::Guard);
    }
    stats.mutation_evaluations += pool.len();
    if !add_requirement(
        pool.iter()
            .zip(&outputs)
            .map(|(input, expected)| evaluate_with_original_guards(task, input) != *expected),
        &mut masks,
        &mut requirements,
    ) {
        return Err(Rejection::OriginalGuard);
    }

    let alternating: Vec<_> = (0..MAX_INPUT_LEN)
        .map(|i| {
            if i % 2 == 0 {
                -MAX_INPUT_ABS
            } else {
                MAX_INPUT_ABS
            }
        })
        .collect();
    let boundaries = [
        vec![],
        vec![-MAX_INPUT_ABS],
        vec![MAX_INPUT_ABS],
        alternating,
    ];
    let mut selected = Vec::with_capacity(max_cases);
    let mut used = vec![false; pool.len()];
    let mut covered = 0_u64;
    for input in &boundaries {
        let Some(index) = pool.iter().position(|candidate| candidate == input) else {
            return Err(Rejection::Coverage);
        };
        if selected.len() == max_cases {
            return Err(Rejection::Coverage);
        }
        selected.push(index);
        used[index] = true;
        covered |= masks[index];
    }
    let required = (1_u64 << requirements) - 1;
    while covered != required {
        if selected.len() == max_cases {
            return Err(Rejection::Coverage);
        }
        let Some((index, gain)) = masks
            .iter()
            .enumerate()
            .filter(|(index, _)| !used[*index])
            .map(|(index, &mask)| (index, (mask & !covered).count_ones()))
            .max_by_key(|&(index, gain)| (gain, std::cmp::Reverse(index)))
        else {
            return Err(Rejection::Coverage);
        };
        if gain == 0 {
            return Err(Rejection::Coverage);
        }
        selected.push(index);
        used[index] = true;
        covered |= masks[index];
    }
    stats.requirement_count = requirements;
    stats.witness_case_count = selected.len();
    stats.mandatory_case_count = boundaries.len();
    for (index, already_used) in used.iter().enumerate() {
        if selected.len() == max_cases {
            break;
        }
        if !already_used {
            selected.push(index);
        }
    }
    if selected.len() != max_cases {
        return Err(Rejection::Coverage);
    }
    Ok(selected
        .into_iter()
        .map(|index| TestCase {
            input: pool[index].clone(),
            expected: outputs[index].clone(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composition::{Operation, Predicates, Stage};

    fn predicates() -> Predicates {
        Predicates {
            threshold: 0,
            greater: true,
            modulus: 3,
            residue: 1,
            both: true,
            negate_middle: true,
            negate_outer: false,
        }
    }

    fn stage(operation: Operation) -> Stage {
        Stage {
            operation,
            guard: Guard::Always,
        }
    }

    fn task(stages: Vec<Stage>) -> Composition {
        Composition {
            predicates: predicates(),
            stages,
            sum: false,
        }
    }

    fn reject(task: &Composition) -> Option<Rejection> {
        let pool = input_pool(task, &mut RandomStream::new([7; 32]));
        screen_candidate(task, &pool, 32, &mut ScreeningStats::default()).err()
    }

    fn constant_task() -> Composition {
        task(vec![
            stage(Operation::Filter(2)),
            stage(Operation::Filter(3)),
            stage(Operation::Affine(2, 1)),
        ])
    }

    #[test]
    fn known_empty_and_zero_collapses_are_rejected() {
        let mut task = constant_task();
        assert_eq!(reject(&task), Some(Rejection::Constant));
        task.sum = true;
        assert_eq!(reject(&task), Some(Rejection::Constant));
    }

    #[test]
    fn shortcuts_redundant_stages_and_guards_are_rejected_separately() {
        let identity = task(vec![stage(Operation::Reverse), stage(Operation::Reverse)]);
        assert_eq!(reject(&identity), Some(Rejection::Shortcut));
        let repeated_sort = task(vec![
            stage(Operation::Sort(false)),
            stage(Operation::Sort(false)),
            stage(Operation::Affine(2, 1)),
        ]);
        assert_eq!(reject(&repeated_sort), Some(Rejection::Stage));
        let always_true_after_filter = task(vec![
            stage(Operation::Filter(0)),
            Stage {
                operation: Operation::Affine(2, 1),
                guard: Guard::All(0),
            },
            stage(Operation::Reverse),
        ]);
        assert_eq!(reject(&always_true_after_filter), Some(Rejection::Guard));
    }

    #[test]
    fn original_input_guard_mutant_changes_a_noncommuting_example() {
        let mut task = task(vec![
            stage(Operation::Affine(-3, 2)),
            Stage {
                operation: Operation::Filter(1),
                guard: Guard::Any(0),
            },
        ]);
        task.predicates.greater = false;
        task.predicates.residue = 0;
        task.sum = true;
        // Original -31 qualifies for x <= 0, but the current value 95 does not.
        // The buggy guard therefore runs a residue filter that removes 95.
        assert_eq!(task.evaluate(&[-31]), json!(95));
        assert_eq!(evaluate_with_original_guards(&task, &[-31]), json!(0));
        // Operations themselves still use the current value, not the original.
        assert_eq!(task.evaluate(&[1]), json!(0));
        assert_eq!(evaluate_with_original_guards(&task, &[1]), json!(-1));
        assert_eq!(evaluate_with_original_guards(&task, &[]), json!(0));
    }

    #[test]
    fn selected_suite_preserves_every_shortcut_and_mutation_witness() {
        let task = task(vec![
            stage(Operation::Affine(2, 1)),
            stage(Operation::Filter(0)),
            Stage {
                operation: Operation::Reverse,
                guard: Guard::Any(1),
            },
        ]);
        let pool = input_pool(&task, &mut RandomStream::new([7; 32]));
        let mut stats = ScreeningStats::default();
        let mut cases = screen_candidate(&task, &pool, SEARCH_CASE_COUNT, &mut stats).unwrap();
        let search_inputs: Vec<_> = cases.iter().map(|case| case.input().to_vec()).collect();
        assert_eq!(cases.len(), 24);
        assert!(stats.witness_case_count <= 24);
        append_holdout(
            &task,
            &mut cases,
            &mut stats,
            &mut RandomStream::new([8; 32]),
        );
        assert_eq!(cases.len(), 32);
        assert_eq!(stats.holdout_case_count, 8);
        assert_eq!(stats.holdout_evaluations, 8);
        assert_eq!(stats.mandatory_case_count, 4);
        for input in search_inputs {
            assert!(cases.iter().any(|case| case.input() == input));
        }
        assert!(cases.iter().any(|case| case.input().is_empty()));
        assert!(cases.iter().any(|case| case.input().len() == 64));
        for shortcut in SHORTCUTS {
            assert!(cases
                .iter()
                .any(|case| shortcut.evaluate(case.input(), task.sum) != *case.expected()));
        }
        for index in 0..task.stages.len() {
            let mut mutant = task.clone();
            mutant.stages.remove(index);
            assert!(cases
                .iter()
                .any(|case| mutant.evaluate(case.input()) != *case.expected()));
            if !matches!(task.stages[index].guard, Guard::Always) {
                let mut mutant = task.clone();
                mutant.stages[index].guard = Guard::Always;
                assert!(cases
                    .iter()
                    .any(|case| mutant.evaluate(case.input()) != *case.expected()));
            }
        }
        let mut mutant = task.clone();
        for stage in &mut mutant.stages {
            stage.guard = Guard::Always;
        }
        assert!(cases
            .iter()
            .any(|case| mutant.evaluate(case.input()) != *case.expected()));
        assert!(cases.iter().any(|case| {
            evaluate_with_original_guards(&task, case.input()) != *case.expected()
        }));
        for case in cases {
            assert_eq!(case.expected(), &task.evaluate(case.input()));
        }
    }

    #[test]
    fn holdouts_cover_length_strata_scales_signs_and_nonadjacent_repeats() {
        let task = task(vec![stage(Operation::Affine(2, 1))]);
        for seed in 0..32 {
            let inputs = holdout_inputs(&task, &mut RandomStream::new([seed; 32]));
            assert_eq!(inputs.len(), HOLDOUT_CASE_COUNT);
            let strata = [
                (2, 8),
                (9, 12),
                (13, 24),
                (25, 36),
                (37, 48),
                (49, 63),
                (64, 64),
                (64, 64),
            ];
            for (case_index, (input, (minimum, maximum))) in inputs.iter().zip(strata).enumerate() {
                assert!((minimum..=maximum).contains(&input.len()));
                assert!(input.iter().all(|value| value.abs() <= MAX_INPUT_ABS));
                assert!(input.iter().any(|&value| value < 0));
                assert!(input.iter().any(|&value| value > 0));
                assert!(input.iter().any(|value| (1..=8).contains(&value.abs())));
                assert!(input
                    .iter()
                    .any(|value| (MAX_INPUT_ABS - 255..=MAX_INPUT_ABS).contains(&value.abs())));
                if input.len() >= 8 {
                    assert!(input.contains(&0));
                    assert!(input.iter().any(|value| (16..=255).contains(&value.abs())));
                    assert!(input
                        .iter()
                        .any(|value| (256..=4095).contains(&value.abs())));
                }
                if matches!(case_index, 4 | 7) {
                    assert_eq!(input.first(), input.last());
                }
            }
            assert!(inputs[2].windows(2).all(|pair| pair[0] <= pair[1]));
            assert!(inputs[3].windows(2).all(|pair| pair[0] >= pair[1]));
            assert_ne!(inputs[2].first(), inputs[2].last());
            assert_ne!(inputs[3].first(), inputs[3].last());
            // Both ordered shapes still mix scales and signs, so ordering
            // cannot be used to recognize an omitted distribution category.
            for ordered in &inputs[2..=3] {
                assert!(ordered.contains(&0));
                assert!(ordered
                    .iter()
                    .any(|value| (256..=4095).contains(&value.abs())));
                assert!(ordered.iter().any(|&value| value < 0));
                assert!(ordered.iter().any(|&value| value > 0));
            }
        }
    }

    #[test]
    fn holdout_seed_changes_final_cases_without_changing_acceptance_or_search_cases() {
        let accepted = || {
            find_screened(
                &mut RandomStream::new([11; 32]),
                &mut RandomStream::new([12; 32]),
                CANDIDATE_LIMIT,
                Composition::generate,
            )
            .unwrap()
        };
        let (left_task, mut left_cases, mut left_stats) = accepted();
        let (right_task, mut right_cases, mut right_stats) = accepted();
        assert_eq!(
            left_task.reference_solution(),
            right_task.reference_solution()
        );
        assert_eq!(
            serde_json::to_value(&left_stats).unwrap(),
            serde_json::to_value(&right_stats).unwrap()
        );
        assert_eq!(left_stats.final_case_count, 0);
        assert_eq!(left_stats.holdout_evaluations, 0);
        assert_eq!(left_stats.selected_search_case_count, SEARCH_CASE_COUNT);
        let search_inputs: Vec<_> = left_cases
            .iter()
            .map(|case| case.input().to_vec())
            .collect();
        let search_evaluations = left_stats.reference_evaluations;
        append_holdout(
            &left_task,
            &mut left_cases,
            &mut left_stats,
            &mut RandomStream::new([13; 32]),
        );
        append_holdout(
            &right_task,
            &mut right_cases,
            &mut right_stats,
            &mut RandomStream::new([14; 32]),
        );
        for input in search_inputs {
            assert!(left_cases.iter().any(|case| case.input() == input));
            assert!(right_cases.iter().any(|case| case.input() == input));
        }
        assert!(left_cases.iter().any(|left| {
            !right_cases
                .iter()
                .any(|right| left.input() == right.input())
        }));
        assert_eq!(left_stats.reference_evaluations, search_evaluations + 8);
        assert_eq!(
            serde_json::to_value(&left_stats).unwrap(),
            serde_json::to_value(&right_stats).unwrap()
        );
    }

    #[test]
    fn independent_holdout_stream_ignores_search_randomness_consumption() {
        let task = task(vec![stage(Operation::Affine(2, 1))]);
        let holdout_seed = derive_seed(
            &[37; 32],
            b"composition-screened/v3/holdout",
            b"s",
            b"f",
            &[9; 32],
        );
        let tests_seed = derive_seed(
            &[37; 32],
            b"composition-screened/v3/tests",
            b"s",
            b"f",
            &[9; 32],
        );
        assert_ne!(holdout_seed, tests_seed);
        let before = holdout_inputs(&task, &mut RandomStream::new(holdout_seed));
        let mut search_random = RandomStream::new(tests_seed);
        for _ in 0..17 {
            input_pool(&task, &mut search_random);
        }
        let after = holdout_inputs(&task, &mut RandomStream::new(holdout_seed));
        assert_eq!(before, after);
    }

    #[test]
    fn exhausted_budget_reports_failure_without_a_fallback() {
        let exhausted = find_screened(
            &mut RandomStream::new([8; 32]),
            &mut RandomStream::new([9; 32]),
            3,
            |_| constant_task(),
        )
        .err()
        .unwrap();
        assert_eq!(exhausted.candidate_count, 3);
        assert_eq!(exhausted.rejected_count, 3);
        assert_eq!(exhausted.rejected_constant, 3);
        assert_eq!(exhausted.final_case_count, 0);
        assert_eq!(exhausted.selected_search_case_count, 0);
        assert_eq!(exhausted.holdout_case_count, 0);
        assert_eq!(exhausted.holdout_evaluations, 0);
        assert!(exhausted.peak_pool_inputs <= POOL_LIMIT);
    }

    #[test]
    fn insufficient_witness_budget_is_not_silently_truncated() {
        let task = task(vec![
            stage(Operation::Affine(2, 1)),
            stage(Operation::Filter(0)),
            Stage {
                operation: Operation::Reverse,
                guard: Guard::Any(1),
            },
        ]);
        let pool = input_pool(&task, &mut RandomStream::new([7; 32]));
        assert_eq!(
            screen_candidate(&task, &pool, 2, &mut ScreeningStats::default()).err(),
            Some(Rejection::Coverage)
        );
    }

    #[test]
    fn screened_domains_are_distinct_and_generation_is_reproducible() {
        let engine = Engine::new([37; 32]);
        let (public, private, stats) = engine.screened_with_nonce("s", b"f", 100, [9; 32]).unwrap();
        let (same, same_private, same_stats) =
            engine.screened_with_nonce("s", b"f", 100, [9; 32]).unwrap();
        assert_eq!(public.id, same.id);
        assert_eq!(public.prompt, same.prompt);
        assert_eq!(
            private.reference_solution(),
            same_private.reference_solution()
        );
        assert_eq!(
            serde_json::to_value(&stats).unwrap(),
            serde_json::to_value(&same_stats).unwrap()
        );
        assert_ne!(
            public.id,
            engine
                .composition_with_nonce("s", b"f", 100, [9; 32])
                .unwrap()
                .0
                .id
        );
        assert_ne!(
            public.id,
            hex(&derive_seed(
                &[37; 32],
                b"composition-screened/v1/id",
                b"s",
                b"f",
                &[9; 32]
            ))
        );
        assert_ne!(
            public.id,
            hex(&derive_seed(
                &[37; 32],
                b"composition-screened/v2/id",
                b"s",
                b"f",
                &[9; 32]
            ))
        );
        assert_eq!(private.cases().len(), 32);
        assert_eq!(stats.selected_search_case_count, 24);
        assert_eq!(stats.holdout_case_count, 8);
        assert_eq!(stats.holdout_evaluations, 8);
        assert_eq!(stats.final_case_count, 32);
        assert!(stats.candidate_count <= CANDIDATE_LIMIT);
        assert!(stats.accepted_pool_inputs <= POOL_LIMIT);
        assert_eq!(stats.rejected_count + 1, stats.candidate_count);
        for (left, right) in private.cases().iter().zip(same_private.cases()) {
            assert_eq!(left.input(), right.input());
            assert_eq!(left.expected(), right.expected());
        }
    }
}
