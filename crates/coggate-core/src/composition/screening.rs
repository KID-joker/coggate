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
    pub rejected_coverage: usize,
    pub total_pool_inputs: usize,
    pub peak_pool_inputs: usize,
    pub accepted_pool_inputs: usize,
    pub reference_evaluations: usize,
    pub shortcut_evaluations: usize,
    pub mutation_evaluations: usize,
    pub requirement_count: usize,
    /// Greedy witness selection size, including the four mandatory boundaries,
    /// before filling the suite to 32 inputs.
    pub witness_case_count: usize,
    pub mandatory_case_count: usize,
    pub final_case_count: usize,
}

impl Engine {
    /// Development-only, bounded quality-screened composition experiment.
    ///
    /// A successful result kills the documented shortcuts and witnesses every
    /// stage deletion and conditional-to-always mutation on the returned suite.
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
        let mut problem = RandomStream::new(derive(b"composition-screened/v1/problem"));
        let mut wording = RandomStream::new(derive(b"composition-screened/v1/wording"));
        let mut tests = RandomStream::new(derive(b"composition-screened/v1/tests"));
        let (task, cases, stats) = find_screened(
            &mut problem,
            &mut tests,
            CANDIDATE_LIMIT,
            Composition::generate,
        )
        .map_err(|_| Error::GenerationExhausted)?;
        let id = hex(&derive(b"composition-screened/v1/id"));
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
        match screen_candidate(&task, &pool, HIDDEN_TEST_COUNT, &mut stats) {
            Ok(mut cases) => {
                for i in (1..cases.len()).rev() {
                    cases.swap(i, tests.below((i + 1) as u64) as usize);
                }
                stats.accepted_pool_inputs = pool.len();
                stats.final_case_count = cases.len();
                return Ok((task, cases, stats));
            }
            Err(reason) => {
                stats.rejected_count += 1;
                match reason {
                    Rejection::Constant => stats.rejected_constant += 1,
                    Rejection::Shortcut => stats.rejected_shortcut += 1,
                    Rejection::Stage => stats.rejected_stage += 1,
                    Rejection::Guard => stats.rejected_guard += 1,
                    Rejection::Coverage => stats.rejected_coverage += 1,
                }
            }
        }
    }
    Err(Box::new(stats))
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
        let cases = screen_candidate(&task, &pool, 32, &mut stats).unwrap();
        assert_eq!(cases.len(), 32);
        assert!(stats.witness_case_count <= 32);
        assert_eq!(stats.mandatory_case_count, 4);
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
        for case in cases {
            assert_eq!(case.expected(), &task.evaluate(case.input()));
        }
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
        assert_eq!(private.cases().len(), 32);
        assert!(stats.candidate_count <= CANDIDATE_LIMIT);
        assert!(stats.accepted_pool_inputs <= POOL_LIMIT);
        assert_eq!(stats.rejected_count + 1, stats.candidate_count);
        for (left, right) in private.cases().iter().zip(same_private.cases()) {
            assert_eq!(left.input(), right.input());
            assert_eq!(left.expected(), right.expected());
        }
    }
}
