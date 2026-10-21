//! Small, deliberately falsifiable order-synthesis experiment.
//!
//! Public examples uniquely identify one permutation of four operation cards.
//! This adds bounded search to prompt interpretation; it does not establish a
//! model advantage over a non-model solver enumerating the same 24 orders.

use super::{Composition, Guard, RandomStream, Stage};
use crate::{
    derive_seed, hex, validate_request, Engine, Error, PrivateChallenge, PublicChallenge,
    Reference, TestCase, HIDDEN_TEST_COUNT, MAX_ATTEMPTS, MAX_INPUT_ABS, MAX_INPUT_LEN,
};
use serde::Serialize;
use serde_json::Value;

const STAGE_COUNT: usize = 4;
const PERMUTATION_COUNT: usize = 24;
const CANDIDATE_LIMIT: usize = 64;
const PUBLIC_PROBE_LIMIT: usize = 32;
const PRIVATE_DRAW_LIMIT: usize = 128;

/// Trusted development counters, never part of the public challenge protocol.
#[derive(Clone, Debug, Default, Serialize)]
pub struct OrderSynthesisStats {
    pub candidate_limit: usize,
    pub stage_count: usize,
    pub output_shape: &'static str,
    pub permutation_limit: usize,
    pub public_probe_limit: usize,
    pub private_draw_limit: usize,
    pub candidate_count: usize,
    pub rejected_ambiguous: usize,
    pub rejected_constant: usize,
    pub public_probe_count: usize,
    pub permutation_evaluations: usize,
    pub public_example_count: usize,
    pub surviving_orders: usize,
    pub private_draw_count: usize,
    pub private_case_count: usize,
}

#[derive(Clone)]
struct Example {
    input: Vec<i64>,
    output: Value,
}

struct Accepted {
    reference: Composition,
    cards: Composition,
    examples: Vec<Example>,
    stats: OrderSynthesisStats,
}

impl Engine {
    /// Development-only four-card order inference, with complete public
    /// semantics and a unique order determined solely by public examples.
    pub fn issue_order_synthesis(
        &self,
        scope: &str,
        factor: &[u8],
        now_secs: u64,
    ) -> Result<(PublicChallenge, PrivateChallenge, OrderSynthesisStats), Error> {
        validate_request(scope, factor, now_secs)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;
        self.order_synthesis_with_nonce(scope, factor, now_secs, nonce)
    }

    fn order_synthesis_with_nonce(
        &self,
        scope: &str,
        factor: &[u8],
        now_secs: u64,
        nonce: [u8; 32],
    ) -> Result<(PublicChallenge, PrivateChallenge, OrderSynthesisStats), Error> {
        let expires_at = validate_request(scope, factor, now_secs)?;
        let derive = |label: &[u8]| derive_seed(&self.key, label, scope.as_bytes(), factor, &nonce);
        let mut problem = RandomStream::new(derive(b"order-synthesis/v1/problem"));
        let mut cards = RandomStream::new(derive(b"order-synthesis/v1/cards"));
        let mut probes = RandomStream::new(derive(b"order-synthesis/v1/public-probes"));
        let Accepted {
            reference,
            cards,
            examples,
            mut stats,
        } = find_candidate(
            &mut problem,
            &mut cards,
            &mut probes,
            CANDIDATE_LIMIT,
            generate_candidate,
        )
        .map_err(|_| Error::GenerationExhausted)?;
        // Private inputs are first sampled after public-only uniqueness has
        // accepted a candidate. They cannot choose between ambiguous orders.
        let mut private_random = RandomStream::new(derive(b"order-synthesis/v1/private-tests"));
        let cases = private_cases(&reference, &examples, &mut private_random, &mut stats)
            .ok_or(Error::GenerationExhausted)?;
        let mut wording = RandomStream::new(derive(b"order-synthesis/v1/wording"));
        let id = hex(&derive(b"order-synthesis/v1/id"));
        let public = PublicChallenge {
            id: id.clone(),
            scope: scope.to_owned(),
            expires_at,
            max_attempts: MAX_ATTEMPTS,
            prompt: prompt(&cards, &examples, &mut wording),
        };
        let private = PrivateChallenge {
            id,
            scope: scope.to_owned(),
            expires_at,
            cases,
            reference: Reference::Composition(reference.reference_solution()),
        };
        Ok((public, private, stats))
    }
}

fn shuffle<T>(items: &mut [T], random: &mut RandomStream) {
    for index in (1..items.len()).rev() {
        items.swap(index, random.below((index + 1) as u64) as usize);
    }
}

fn generate_candidate(random: &mut RandomStream) -> Composition {
    let mut task = Composition::generate(random);
    task.stages.truncate(STAGE_COUNT);
    while task.stages.len() < STAGE_COUNT {
        task.stages.push(Stage {
            operation: super::affine(random),
            guard: Guard::Always,
        });
    }
    // The first pilot keeps the complete final sequence. A sum can erase order
    // differences and would add avoidable rejection cost to this small test.
    task.sum = false;
    task
}

fn permutations() -> Vec<[usize; STAGE_COUNT]> {
    fn visit(
        position: usize,
        current: &mut [usize; STAGE_COUNT],
        result: &mut Vec<[usize; STAGE_COUNT]>,
    ) {
        if position == current.len() {
            result.push(*current);
        } else {
            for next in position..current.len() {
                current.swap(position, next);
                visit(position + 1, current, result);
                current.swap(position, next);
            }
        }
    }
    let mut result = Vec::with_capacity(PERMUTATION_COUNT);
    visit(0, &mut [0, 1, 2, 3], &mut result);
    result
}

fn reordered(cards: &Composition, permutation: &[usize; STAGE_COUNT]) -> Composition {
    Composition {
        predicates: cards.predicates,
        stages: permutation
            .iter()
            .map(|&i| cards.stages[i].clone())
            .collect(),
        sum: cards.sum,
    }
}

fn distinct_outputs(examples: &[Example]) -> bool {
    examples.first().is_some_and(|first| {
        examples
            .iter()
            .any(|example| example.output != first.output)
    })
}

fn find_candidate(
    problem: &mut RandomStream,
    card_random: &mut RandomStream,
    probe_random: &mut RandomStream,
    budget: usize,
    mut generate: impl FnMut(&mut RandomStream) -> Composition,
) -> Result<Accepted, Box<OrderSynthesisStats>> {
    let mut stats = OrderSynthesisStats {
        candidate_limit: budget.min(CANDIDATE_LIMIT),
        stage_count: STAGE_COUNT,
        output_shape: "array",
        permutation_limit: PERMUTATION_COUNT,
        public_probe_limit: PUBLIC_PROBE_LIMIT,
        private_draw_limit: PRIVATE_DRAW_LIMIT,
        ..OrderSynthesisStats::default()
    };
    let orders = permutations();
    for _ in 0..stats.candidate_limit {
        stats.candidate_count += 1;
        let reference = generate(problem);
        let mut cards = reference.clone();
        shuffle(&mut cards.stages, card_random);
        let mut survivors: Vec<_> = orders
            .iter()
            .map(|order| reordered(&cards, order))
            .collect();
        let mut examples = Vec::new();
        for input in reference
            .test_inputs(probe_random)
            .into_iter()
            .take(PUBLIC_PROBE_LIMIT)
        {
            stats.public_probe_count += 1;
            let output = reference.evaluate(&input);
            let before = survivors.len();
            stats.permutation_evaluations += before;
            survivors.retain(|candidate| candidate.evaluate(&input) == output);
            let new_output = !examples.is_empty()
                && examples
                    .iter()
                    .all(|example: &Example| example.output != output);
            if examples.is_empty()
                || survivors.len() < before
                || new_output && !distinct_outputs(&examples)
            {
                examples.push(Example { input, output });
            }
            if survivors.len() == 1 && distinct_outputs(&examples) {
                stats.public_example_count = examples.len();
                stats.surviving_orders = survivors.len();
                return Ok(Accepted {
                    reference,
                    cards,
                    examples,
                    stats,
                });
            }
        }
        if !distinct_outputs(&examples) {
            stats.rejected_constant += 1;
        } else {
            stats.rejected_ambiguous += 1;
        }
    }
    Err(Box::new(stats))
}

fn private_cases(
    task: &Composition,
    public: &[Example],
    random: &mut RandomStream,
    stats: &mut OrderSynthesisStats,
) -> Option<Vec<TestCase>> {
    let mut inputs = Vec::with_capacity(HIDDEN_TEST_COUNT);
    let mut add = |input: Vec<i64>| {
        if inputs.len() < HIDDEN_TEST_COUNT
            && !inputs.contains(&input)
            && !public.iter().any(|example| example.input == input)
        {
            inputs.push(input);
        }
    };
    for input in task.test_inputs(random) {
        add(input);
        stats.private_draw_count += 1;
    }
    for draw in 0..PRIVATE_DRAW_LIMIT - HIDDEN_TEST_COUNT {
        if inputs.len() == HIDDEN_TEST_COUNT {
            break;
        }
        let length = random.below((MAX_INPUT_LEN + 1) as u64) as usize;
        let mut input: Vec<_> = (0..length)
            .map(|index| match (draw + index) % 4 {
                0 => super::between(random, -MAX_INPUT_ABS, MAX_INPUT_ABS),
                1 => super::between(random, -8, 8),
                2 => task.predicates.threshold + super::between(random, -3, 3),
                _ => {
                    super::between(random, -4, 4) * task.predicates.modulus
                        + task.predicates.residue
                }
            })
            .collect();
        shuffle(&mut input, random);
        stats.private_draw_count += 1;
        if !inputs.contains(&input) && !public.iter().any(|example| example.input == input) {
            inputs.push(input);
        }
    }
    if inputs.len() != HIDDEN_TEST_COUNT {
        return None;
    }
    shuffle(&mut inputs, random);
    stats.private_case_count = inputs.len();
    Some(
        inputs
            .into_iter()
            .map(|input| TestCase {
                expected: task.evaluate(&input),
                input,
            })
            .collect(),
    )
}

fn prompt(cards: &Composition, examples: &[Example], wording: &mut RandomStream) -> String {
    let procedural = cards.prompt(wording);
    let mut lines = Vec::new();
    for line in procedural.lines() {
        if line.starts_with("Experimental composition challenge.") {
            lines.push("Experimental order-synthesis challenge. Infer a fixed card ordering from the public examples and implement it.".to_owned());
        } else if line.starts_with("Start with a copy of input.") {
            lines.push("Start with a copy of input. Infer one fixed ordering of the cards from all public examples. Apply each card exactly once in that ordering, using the same ordering for every input. Card identifiers and their display positions do not indicate execution order. Each condition inspects the entire sequence immediately before its card. Each filtering predicate and mapping uses the values at that card, not the original input. For an empty sequence, any is false and all is true. Cards not explicitly sorting or reversing preserve the order of surviving values.".to_owned());
        } else if let Some((index, description)) =
            line.split_once(". ").and_then(|(index, description)| {
                index
                    .parse::<usize>()
                    .ok()
                    .map(|index| (index, description))
            })
        {
            lines.push(format!(
                "Card {}: {description}",
                (b'A' + (index - 1) as u8) as char
            ));
        } else {
            lines.push(line.to_owned());
        }
    }
    lines.push("Exactly one permutation of the distinct card identifiers agrees with every public example.".to_owned());
    for (index, example) in examples.iter().enumerate() {
        lines.push(format!(
            "Example {}: input = {}; output = {}",
            index + 1,
            serde_json::to_string(&example.input).expect("integer arrays serialize"),
            example.output,
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composition::{Operation, Predicates};
    use std::collections::HashSet;

    fn accepted(card_seed: u8) -> Accepted {
        find_candidate(
            &mut RandomStream::new([19; 32]),
            &mut RandomStream::new([card_seed; 32]),
            &mut RandomStream::new([21; 32]),
            CANDIDATE_LIMIT,
            generate_candidate,
        )
        .unwrap()
    }

    #[test]
    fn all_twenty_four_card_orders_are_enumerated_once() {
        let orders = permutations();
        assert_eq!(orders.len(), 24);
        assert_eq!(orders.iter().collect::<HashSet<_>>().len(), 24);
        for mut order in orders {
            order.sort_unstable();
            assert_eq!(order, [0, 1, 2, 3]);
        }
    }

    #[test]
    fn public_examples_alone_identify_exactly_one_order() {
        let accepted = accepted(20);
        let mut matching = Vec::new();
        // Independently enumerate all index tuples, including the display
        // order. No expected private result participates in this proof.
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        let order = [a, b, c, d];
                        if order.into_iter().collect::<HashSet<_>>().len() != 4 {
                            continue;
                        }
                        let task = reordered(&accepted.cards, &order);
                        if accepted
                            .examples
                            .iter()
                            .all(|example| task.evaluate(&example.input) == example.output)
                        {
                            matching.push(task);
                        }
                    }
                }
            }
        }
        assert_eq!(matching.len(), 1);
        assert!(distinct_outputs(&accepted.examples));
        assert!(accepted.examples.len() <= PUBLIC_PROBE_LIMIT);
        for input in accepted
            .reference
            .test_inputs(&mut RandomStream::new([22; 32]))
        {
            assert_eq!(
                matching[0].evaluate(&input),
                accepted.reference.evaluate(&input)
            );
        }
    }

    #[test]
    fn exchangeable_cards_exhaust_the_budget_instead_of_using_private_tests() {
        let exhausted = find_candidate(
            &mut RandomStream::new([1; 32]),
            &mut RandomStream::new([2; 32]),
            &mut RandomStream::new([3; 32]),
            2,
            |_| Composition {
                predicates: Predicates {
                    threshold: 0,
                    greater: true,
                    modulus: 3,
                    residue: 0,
                    both: true,
                    negate_middle: false,
                    negate_outer: false,
                },
                stages: (0..4)
                    .map(|_| Stage {
                        operation: Operation::Reverse,
                        guard: Guard::Always,
                    })
                    .collect(),
                sum: false,
            },
        )
        .err()
        .unwrap();
        assert_eq!(exhausted.candidate_count, 2);
        assert_eq!(exhausted.rejected_ambiguous, 2);
        assert_eq!(exhausted.public_probe_count, 64);
        assert_eq!(exhausted.private_draw_count, 0);
        assert_eq!(exhausted.private_case_count, 0);
    }

    #[test]
    fn card_randomness_changes_presentation_without_changing_the_target() {
        let first = accepted(20);
        let second = accepted(22);
        assert_eq!(
            first.reference.reference_solution(),
            second.reference.reference_solution()
        );
        assert_ne!(
            first.cards.reference_solution(),
            second.cards.reference_solution()
        );
        assert_eq!(first.stats.candidate_count, second.stats.candidate_count);
        assert_eq!(first.examples.len(), second.examples.len());
        for (left, right) in first.examples.iter().zip(&second.examples) {
            assert_eq!(left.input, right.input);
            assert_eq!(left.output, right.output);
        }
    }

    #[test]
    fn private_inputs_are_independent_unique_and_disjoint_from_public_examples() {
        let mut accepted = accepted(20);
        let cases = private_cases(
            &accepted.reference,
            &accepted.examples,
            &mut RandomStream::new([30; 32]),
            &mut accepted.stats,
        )
        .unwrap();
        let other = private_cases(
            &accepted.reference,
            &accepted.examples,
            &mut RandomStream::new([31; 32]),
            &mut OrderSynthesisStats::default(),
        )
        .unwrap();
        assert_eq!(cases.len(), 32);
        assert_eq!(
            cases
                .iter()
                .map(|case| case.input().to_vec())
                .collect::<HashSet<_>>()
                .len(),
            32
        );
        assert!(cases
            .iter()
            .any(|case| !other.iter().any(|other| case.input() == other.input())));
        assert!(accepted.stats.private_draw_count <= PRIVATE_DRAW_LIMIT);
        for case in cases {
            assert!(case.input().len() <= MAX_INPUT_LEN);
            assert!(case
                .input()
                .iter()
                .all(|value| value.abs() <= MAX_INPUT_ABS));
            assert!(accepted
                .examples
                .iter()
                .all(|example| example.input != case.input()));
            assert_eq!(*case.expected(), accepted.reference.evaluate(case.input()));
        }
    }

    #[test]
    fn public_prompt_removes_procedural_order_and_keeps_complete_card_semantics() {
        let accepted = accepted(20);
        let public = prompt(
            &accepted.cards,
            &accepted.examples,
            &mut RandomStream::new([41; 32]),
        );
        assert!(!public.contains("Apply the numbered stages"));
        assert!(!public.contains("exact listed order"));
        assert!(public.contains("Apply each card exactly once"));
        assert!(public.contains("using the same ordering for every input"));
        assert!(public.contains("Exactly one permutation"));
        assert!(public.contains("For an empty sequence, any is false and all is true"));
        assert!(public.contains("Return the final sequence as an array."));
        assert_eq!(
            public
                .lines()
                .filter(|line| line.starts_with("Card "))
                .count(),
            4
        );
        assert_eq!(
            public
                .lines()
                .filter(|line| line.starts_with("Example "))
                .count(),
            accepted.examples.len()
        );
        for (index, example) in accepted.examples.iter().enumerate() {
            assert!(public.contains(&format!(
                "Example {}: input = {}; output = {}",
                index + 1,
                serde_json::to_string(&example.input).unwrap(),
                example.output,
            )));
        }
    }

    #[test]
    fn domain_separation_and_fixed_nonce_are_reproducible() {
        let engine = Engine::new([49; 32]);
        let (public, private, stats) = engine
            .order_synthesis_with_nonce("s", b"factor", 100, [50; 32])
            .unwrap();
        let (same, same_private, same_stats) = engine
            .order_synthesis_with_nonce("s", b"factor", 100, [50; 32])
            .unwrap();
        assert_eq!(public.prompt, same.prompt);
        assert_eq!(public.id, same.id);
        assert_eq!(
            private.reference_solution(),
            same_private.reference_solution()
        );
        assert_eq!(
            serde_json::to_value(stats).unwrap(),
            serde_json::to_value(same_stats).unwrap()
        );
        for (left, right) in private.cases().iter().zip(same_private.cases()) {
            assert_eq!(left.input(), right.input());
            assert_eq!(left.expected(), right.expected());
        }
        let public_seed = derive_seed(
            &[49; 32],
            b"order-synthesis/v1/public-probes",
            b"s",
            b"factor",
            &[50; 32],
        );
        let private_seed = derive_seed(
            &[49; 32],
            b"order-synthesis/v1/private-tests",
            b"s",
            b"factor",
            &[50; 32],
        );
        assert_ne!(public_seed, private_seed);
        assert_ne!(
            public.id,
            hex(&derive_seed(
                &[49; 32],
                b"composition/v1/id",
                b"s",
                b"factor",
                &[50; 32]
            ))
        );
    }
}
