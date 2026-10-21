//! Development-only experiment: three to six ordered array operations, scoped
//! predicate aliases, and conditional stages. This is another falsifiable public
//! grammar, not a claim of resistance to specialized non-model solvers.
//!
//! All task semantics are present in the public prompt. Hidden factors change
//! instances, but do not hide the language that an adaptive parser can learn.

pub mod screening;

use crate::{
    derive_seed, hex, task::RandomStream, validate_request, Engine, Error, PrivateChallenge,
    PublicChallenge, Reference, TestCase, HIDDEN_TEST_COUNT, MAX_ATTEMPTS, MAX_INPUT_ABS,
    MAX_INPUT_LEN,
};
use serde_json::{json, Value};

impl Engine {
    /// Generate a development-only composition challenge. The public and private
    /// boundaries are identical to `issue`, but this mechanism is not enabled by
    /// default and has not passed adversarial acceptance.
    pub fn issue_composition(
        &self,
        scope: &str,
        context_factor: &[u8],
        now_secs: u64,
    ) -> Result<(PublicChallenge, PrivateChallenge), Error> {
        validate_request(scope, context_factor, now_secs)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;
        self.composition_with_nonce(scope, context_factor, now_secs, nonce)
    }

    fn composition_with_nonce(
        &self,
        scope: &str,
        factor: &[u8],
        now_secs: u64,
        nonce: [u8; 32],
    ) -> Result<(PublicChallenge, PrivateChallenge), Error> {
        let expires_at = validate_request(scope, factor, now_secs)?;
        let derive = |label: &[u8]| derive_seed(&self.key, label, scope.as_bytes(), factor, &nonce);
        let mut problem = RandomStream::new(derive(b"composition/v1/problem"));
        let mut wording = RandomStream::new(derive(b"composition/v1/wording"));
        let mut tests = RandomStream::new(derive(b"composition/v1/tests"));
        let task = Composition::generate(&mut problem);
        let id = hex(&derive(b"composition/v1/id"));
        let public = PublicChallenge {
            id: id.clone(),
            scope: scope.to_owned(),
            expires_at,
            max_attempts: MAX_ATTEMPTS,
            prompt: task.prompt(&mut wording),
        };
        let cases = task
            .test_inputs(&mut tests)
            .into_iter()
            .map(|input| {
                let expected = task.evaluate(&input);
                TestCase { input, expected }
            })
            .collect();
        let private = PrivateChallenge {
            id,
            scope: scope.to_owned(),
            expires_at,
            cases,
            reference: Reference::Composition(task.reference_solution()),
        };
        Ok((public, private))
    }
}

#[derive(Clone, Copy)]
struct Predicates {
    threshold: i64,
    greater: bool,
    modulus: i64,
    residue: i64,
    both: bool,
    negate_middle: bool,
    negate_outer: bool,
}

impl Predicates {
    fn matches(&self, predicate: usize, x: i64) -> bool {
        match predicate {
            0 => {
                if self.greater {
                    x >= self.threshold
                } else {
                    x <= self.threshold
                }
            }
            1 => x.rem_euclid(self.modulus) == self.residue,
            2 if self.both => self.matches(0, x) && self.matches(1, x),
            2 => self.matches(0, x) || self.matches(1, x),
            3 => self.matches(2, x) != self.negate_middle,
            4 => self.matches(3, x) != self.negate_outer,
            _ => unreachable!("there are five local predicate definitions"),
        }
    }
}

#[derive(Clone)]
enum Operation {
    Filter(usize),
    Affine(i64, i64),
    Sort(bool),
    Reverse,
    Unique(bool),
    Take(usize),
}

#[derive(Clone, Copy)]
enum Guard {
    Always,
    Any(usize),
    All(usize),
}

#[derive(Clone)]
struct Stage {
    operation: Operation,
    guard: Guard,
}

impl Stage {
    fn apply(&self, values: &mut Vec<i64>, predicates: &Predicates) {
        let enabled = match self.guard {
            Guard::Always => true,
            Guard::Any(p) => values.iter().any(|&x| predicates.matches(p, x)),
            Guard::All(p) => values.iter().all(|&x| predicates.matches(p, x)),
        };
        if !enabled {
            return;
        }
        match self.operation {
            Operation::Filter(p) => values.retain(|&x| predicates.matches(p, x)),
            Operation::Affine(a, b) => values.iter_mut().for_each(|x| *x = a * *x + b),
            Operation::Sort(descending) => {
                values.sort_unstable();
                if descending {
                    values.reverse();
                }
            }
            Operation::Reverse => values.reverse(),
            Operation::Unique(last) => {
                let mut output = Vec::new();
                for (index, &value) in values.iter().enumerate() {
                    let duplicate = if last {
                        values[index + 1..].contains(&value)
                    } else {
                        values[..index].contains(&value)
                    };
                    if !duplicate {
                        output.push(value);
                    }
                }
                *values = output;
            }
            Operation::Take(count) => values.truncate(count),
        }
    }

    fn describe(&self, names: &[&str], variant: bool) -> String {
        let operation = match self.operation {
            Operation::Filter(p) if variant => format!(
                "keep elements for which `{}` is true, preserving their order",
                names[p]
            ),
            Operation::Filter(p) => format!(
                "retain only values satisfying `{}`, preserving their order",
                names[p]
            ),
            Operation::Affine(a, b) if variant => {
                format!("map each current value x to ({a} * x) + ({b})")
            }
            Operation::Affine(a, b) => format!("replace each x with ({a} * x) + ({b})"),
            Operation::Sort(descending) => format!(
                "sort values numerically in {} order",
                if descending { "descending" } else { "ascending" }
            ),
            Operation::Reverse => "reverse the current sequence".to_owned(),
            Operation::Unique(last) => format!(
                "keep only the {} occurrence of each distinct value, preserving the order of surviving occurrences",
                if last { "last" } else { "first" }
            ),
            Operation::Take(count) if variant => {
                format!("take the first {count} current values")
            }
            Operation::Take(count) => format!("keep at most the first {count} values"),
        };
        match self.guard {
            Guard::Always => format!("{operation}."),
            Guard::Any(p) => format!(
                "If any current value satisfies `{}`, {operation}; otherwise leave the sequence unchanged.",
                names[p]
            ),
            Guard::All(p) => format!(
                "If all current values satisfy `{}`, {operation}; otherwise leave the sequence unchanged.",
                names[p]
            ),
        }
    }
}

#[derive(Clone)]
struct Composition {
    predicates: Predicates,
    stages: Vec<Stage>,
    sum: bool,
}

fn between(random: &mut RandomStream, low: i64, high: i64) -> i64 {
    low + random.below((high - low + 1) as u64) as i64
}

fn affine(random: &mut RandomStream) -> Operation {
    Operation::Affine(
        [-3, -2, -1, 2, 3][random.below(5) as usize],
        [-9, -5, -2, -1, 1, 2, 5, 9][random.below(8) as usize],
    )
}

impl Composition {
    fn generate(random: &mut RandomStream) -> Self {
        let modulus = between(random, 2, 7);
        let predicates = Predicates {
            threshold: between(random, -20, 20),
            greater: random.below(2) != 0,
            modulus,
            residue: random.below(modulus as u64) as i64,
            both: random.below(2) != 0,
            negate_middle: random.below(2) != 0,
            negate_outer: random.below(2) != 0,
        };
        let length = 3 + random.below(4) as usize;
        // Affine and filtering are mandatory and shuffled with the other
        // operations: order can change meaning, not just the prose.
        let mut operations = vec![affine(random), Operation::Filter(4)];
        while operations.len() < length {
            operations.push(match random.below(6) {
                0 => affine(random),
                1 => Operation::Filter(random.below(5) as usize),
                2 => Operation::Sort(random.below(2) != 0),
                3 => Operation::Reverse,
                4 => Operation::Unique(random.below(2) != 0),
                _ => Operation::Take(1 + random.below(8) as usize),
            });
        }
        for index in (1..operations.len()).rev() {
            operations.swap(index, random.below((index + 1) as u64) as usize);
        }
        let mut stages: Vec<_> = operations
            .into_iter()
            .map(|operation| {
                let guard = match random.below(3) {
                    0 => Guard::Any(random.below(5) as usize),
                    1 => Guard::All(random.below(5) as usize),
                    _ => Guard::Always,
                };
                Stage { operation, guard }
            })
            .collect();
        // Guarantee that the local three-level predicate chain participates
        // in a conditional, even in a short sampled pipeline.
        stages[2].guard = if random.below(2) == 0 {
            Guard::Any(4)
        } else {
            Guard::All(4)
        };
        Self {
            predicates,
            stages,
            sum: random.below(2) != 0,
        }
    }

    fn prompt(&self, wording: &mut RandomStream) -> String {
        let mut names = [
            "amber", "birch", "cobalt", "delta", "ember", "fern", "grove", "hazel", "iris", "jade",
            "kelp", "lumen",
        ];
        for index in (1..names.len()).rev() {
            names.swap(index, wording.below((index + 1) as u64) as usize);
        }
        let p = self.predicates;
        let mut lines = vec![
            "Experimental composition challenge. Implement exactly the sequential rules below."
                .to_owned(),
            "Names below are local to this challenge. A predicate is true or false for the current integer x. Definitions never change during execution.".to_owned(),
            format!(
                "Predicate `{}` holds for x exactly when x {} {}.",
                names[0],
                if p.greater { ">=" } else { "<=" },
                p.threshold
            ),
            format!(
                "Predicate `{}` holds for x exactly when ((x % {m}) + {m}) % {m} equals {r}.",
                names[1],
                m = p.modulus,
                r = p.residue,
            ),
        ];
        let expressions = [
            if p.both {
                format!("both `{}` and `{}`", names[0], names[1])
            } else {
                format!("either `{}` or `{}`", names[0], names[1])
            },
            format!(
                "{}`{}`",
                if p.negate_middle { "not " } else { "" },
                names[2]
            ),
            format!("{}`{}`", if p.negate_outer { "not " } else { "" }, names[3]),
        ];
        for (index, expression) in expressions.iter().enumerate() {
            lines.push(format!(
                "Predicate `{}` {} {}.",
                names[index + 2],
                if wording.below(2) == 0 {
                    "means"
                } else {
                    "is another way to say"
                },
                expression
            ));
        }
        lines.push(
            "In these definitions, both/and is logical AND, either/or is inclusive OR, and not is logical negation. Remainders are normalized to be nonnegative.".to_owned(),
        );
        lines.push(
            "Start with a copy of input. Apply the numbered stages in their exact listed order. Each condition inspects the entire sequence immediately before its stage. Each filtering predicate and mapping uses the values at that stage, not the original input. For an empty sequence, any is false and all is true. Stages not explicitly sorting or reversing preserve the order of surviving values.".to_owned(),
        );
        for (index, stage) in self.stages.iter().enumerate() {
            lines.push(format!(
                "{}. {}",
                index + 1,
                stage.describe(&names, wording.below(2) != 0)
            ));
        }
        lines.push(if self.sum {
            "Return the sum of the final sequence as one integer; the empty sum is 0.".to_owned()
        } else {
            "Return the final sequence as an array.".to_owned()
        });
        lines.push(
            "Submission contract: define function solve(input) in JavaScript source. Input is an array of 0 to 64 integers in [-10000, 10000]. Return only the specified integer or integer array; all required arithmetic is exactly representable as a JavaScript Number. Use ES5-style function, var, loops, numeric arithmetic, comparisons, and arrays with indexing, length, and push. Avoid let/const, arrow functions, classes, modules, promises, eval, and host APIs. Do not print the answer. Each test starts a fresh context.".to_owned(),
        );
        lines.join("\n")
    }

    fn evaluate(&self, input: &[i64]) -> Value {
        let mut values = input.to_vec();
        for stage in &self.stages {
            stage.apply(&mut values, &self.predicates);
        }
        if self.sum {
            json!(values.iter().sum::<i64>())
        } else {
            json!(values)
        }
    }

    fn test_inputs(&self, random: &mut RandomStream) -> Vec<Vec<i64>> {
        let p = self.predicates;
        let mut cases = vec![
            vec![],
            vec![0],
            vec![-MAX_INPUT_ABS],
            vec![MAX_INPUT_ABS],
            vec![-MAX_INPUT_ABS, MAX_INPUT_ABS],
            vec![p.threshold - 1, p.threshold, p.threshold + 1],
            vec![p.residue - p.modulus, p.residue, p.residue + p.modulus],
            vec![2, 1, 2, -1, 1, 0, -1],
            vec![0; MAX_INPUT_LEN],
            vec![MAX_INPUT_ABS; MAX_INPUT_LEN],
            vec![-MAX_INPUT_ABS; MAX_INPUT_LEN],
            (0..MAX_INPUT_LEN)
                .map(|i| {
                    if i % 2 == 0 {
                        -MAX_INPUT_ABS
                    } else {
                        MAX_INPUT_ABS
                    }
                })
                .collect(),
            vec![p.threshold - 1; 7],
            vec![p.threshold; 7],
            vec![p.threshold + 1; 7],
            (-8..=8).collect(),
        ];
        while cases.len() < HIDDEN_TEST_COUNT {
            let length = random.below((MAX_INPUT_LEN + 1) as u64) as usize;
            let mode = cases.len() % 4;
            cases.push(
                (0..length)
                    .map(|_| match mode {
                        0 => between(random, -MAX_INPUT_ABS, MAX_INPUT_ABS),
                        1 => between(random, -8, 8),
                        2 => p.threshold + between(random, -2, 2),
                        _ => between(random, -8, 8) * p.modulus + p.residue,
                    })
                    .collect(),
            );
        }
        for index in (1..cases.len()).rev() {
            cases.swap(index, random.below((index + 1) as u64) as usize);
        }
        cases
    }

    fn reference_solution(&self) -> String {
        let p = self.predicates;
        let mut code = format!(
            "function solve(input){{\
             function p0(x){{return x{cmp}{t};}}\
             function p1(x){{return ((x%{m})+{m})%{m}==={r};}}\
             function p2(x){{return p0(x){join}p1(x);}}\
             function p3(x){{return {not_mid}p2(x);}}\
             function p4(x){{return {not_outer}p3(x);}}\
             var current=[],out,i,j,x,flag,keep,total;\
             for(i=0;i<input.length;i++){{current.push(input[i]);}}",
            cmp = if p.greater { ">=" } else { "<=" },
            t = p.threshold,
            m = p.modulus,
            r = p.residue,
            join = if p.both { "&&" } else { "||" },
            not_mid = if p.negate_middle { "!" } else { "" },
            not_outer = if p.negate_outer { "!" } else { "" },
        );
        for stage in &self.stages {
            match stage.guard {
                Guard::Always => code.push_str("flag=true;"),
                Guard::Any(predicate) => code.push_str(&format!(
                    "flag=false;for(i=0;i<current.length;i++){{if(p{predicate}(current[i])){{flag=true;break;}}}}"
                )),
                Guard::All(predicate) => code.push_str(&format!(
                    "flag=true;for(i=0;i<current.length;i++){{if(!p{predicate}(current[i])){{flag=false;break;}}}}"
                )),
            }
            code.push_str("if(flag){");
            match stage.operation {
                Operation::Filter(predicate) => code.push_str(&format!(
                    "out=[];for(i=0;i<current.length;i++){{if(p{predicate}(current[i])){{out.push(current[i]);}}}}current=out;"
                )),
                Operation::Affine(a, b) => code.push_str(&format!(
                    "for(i=0;i<current.length;i++){{current[i]=({a})*current[i]+({b});}}"
                )),
                Operation::Sort(descending) => code.push_str(&format!(
                    "for(i=1;i<current.length;i++){{x=current[i];j=i-1;while(j>=0&&current[j]{cmp}x){{current[j+1]=current[j];j--;}}current[j+1]=x;}}",
                    cmp = if descending { "<" } else { ">" }
                )),
                Operation::Reverse => code.push_str(
                    "out=[];for(i=current.length-1;i>=0;i--){out.push(current[i]);}current=out;"
                ),
                Operation::Unique(last) => code.push_str(&format!(
                    "out=[];for(i=0;i<current.length;i++){{keep=true;for(j={start};j<{end};j++){{if(current[j]===current[i]){{keep=false;}}}}if(keep){{out.push(current[i]);}}}}current=out;",
                    start = if last { "i+1" } else { "0" },
                    end = if last { "current.length" } else { "i" },
                )),
                Operation::Take(count) => code.push_str(&format!(
                    "out=[];for(i=0;i<current.length&&i<{count};i++){{out.push(current[i]);}}current=out;"
                )),
            }
            code.push('}');
        }
        code.push_str(if self.sum {
            "total=0;for(i=0;i<current.length;i++){total+=current[i];}return total;}"
        } else {
            "return current;}"
        });
        code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn predicates() -> Predicates {
        Predicates {
            threshold: 0,
            greater: true,
            modulus: 3,
            residue: 2,
            both: true,
            negate_middle: true,
            negate_outer: true,
        }
    }

    fn stage(operation: Operation) -> Stage {
        Stage {
            operation,
            guard: Guard::Always,
        }
    }

    #[test]
    fn three_alias_levels_and_normalized_remainders_match_hand_results() {
        let p = predicates();
        assert!(p.matches(1, -1));
        assert!(!p.matches(2, -1));
        assert!(p.matches(3, -1));
        assert!(!p.matches(4, -1));
        assert!(p.matches(2, 2));
        assert!(!p.matches(3, 2));
        assert!(p.matches(4, 2));
        let either = Predicates { both: false, ..p };
        assert!(either.matches(4, -1));
        assert!(either.matches(4, 0));
        assert!(!either.matches(4, -2));
    }

    #[test]
    fn operation_order_and_predicate_time_are_semantic() {
        let mut task = Composition {
            predicates: predicates(),
            stages: vec![stage(Operation::Affine(1, 2)), stage(Operation::Filter(0))],
            sum: false,
        };
        // A translation does not commute with a threshold filter.
        assert_eq!(task.evaluate(&[-1, 0]), json!([1, 2]));
        task.stages.reverse();
        assert_eq!(task.evaluate(&[-1, 0]), json!([2]));
    }

    #[test]
    fn conditions_inspect_current_values_and_empty_all_is_true() {
        let task = Composition {
            predicates: predicates(),
            stages: vec![
                stage(Operation::Affine(-1, -1)),
                Stage {
                    operation: Operation::Take(1),
                    guard: Guard::Any(0),
                },
            ],
            sum: false,
        };
        assert_eq!(task.evaluate(&[0, 1]), json!([-1, -2]));
        assert_eq!(task.evaluate(&[-2, 0]), json!([1]));
        let mut empty = Vec::new();
        let all = Guard::All(4);
        assert!(matches!(all, Guard::All(p) if empty.iter().all(|&x| predicates().matches(p, x))));
        Stage {
            operation: Operation::Affine(3, 7),
            guard: all,
        }
        .apply(&mut empty, &predicates());
        assert!(empty.is_empty());
    }

    #[test]
    fn sort_dedup_reverse_limit_and_sum_match_hand_results() {
        let input = [2, 1, 2, -1, 1, 0, -1];
        let mut task = Composition {
            predicates: predicates(),
            stages: vec![stage(Operation::Unique(false)), stage(Operation::Take(3))],
            sum: false,
        };
        assert_eq!(task.evaluate(&input), json!([2, 1, -1]));
        task.stages[0] = stage(Operation::Unique(true));
        assert_eq!(task.evaluate(&input), json!([2, 1, 0]));
        task.stages = vec![
            stage(Operation::Sort(false)),
            stage(Operation::Unique(false)),
            stage(Operation::Reverse),
            stage(Operation::Take(3)),
        ];
        assert_eq!(task.evaluate(&input), json!([2, 1, 0]));
        task.sum = true;
        assert_eq!(task.evaluate(&input), json!(3));
        assert_eq!(task.evaluate(&[]), json!(0));
    }

    #[test]
    fn experimental_derivation_is_separate_and_factors_are_private() {
        let engine = Engine::new([37; 32]);
        let nonce = [9; 32];
        let factor = b"private-composition-factor";
        let (a, private) = engine
            .composition_with_nonce("s", factor, 100, nonce)
            .unwrap();
        let (same, same_private) = engine
            .composition_with_nonce("s", factor, 100, nonce)
            .unwrap();
        assert_eq!(a.prompt, same.prompt);
        assert_eq!(a.id, same.id);
        assert_eq!(
            private.reference_solution(),
            same_private.reference_solution()
        );
        assert_ne!(
            a.id,
            engine
                .issue_with_nonce("s", factor, 100, nonce)
                .unwrap()
                .0
                .id
        );
        assert_ne!(
            a.id,
            engine
                .composition_with_nonce("s", b"other", 100, nonce)
                .unwrap()
                .0
                .id
        );
        assert_ne!(
            a.id,
            engine
                .composition_with_nonce("s", factor, 100, [10; 32])
                .unwrap()
                .0
                .id
        );
        assert!(!serde_json::to_string(&a)
            .unwrap()
            .contains(std::str::from_utf8(factor).unwrap()));
        assert_eq!(private.cases().len(), HIDDEN_TEST_COUNT);
    }

    #[test]
    fn generated_cases_bound_arithmetic_and_keep_all_required_structures() {
        let mut random = RandomStream::new([91; 32]);
        for _ in 0..500 {
            let task = Composition::generate(&mut random);
            assert!((3..=6).contains(&task.stages.len()));
            assert!(task
                .stages
                .iter()
                .any(|s| matches!(s.operation, Operation::Affine(_, _))));
            assert!(task
                .stages
                .iter()
                .any(|s| matches!(s.operation, Operation::Filter(4))));
            assert!(task
                .stages
                .iter()
                .any(|s| !matches!(s.guard, Guard::Always)));
            let prompt = task.prompt(&mut random);
            assert_eq!(
                prompt
                    .lines()
                    .filter(|line| line.starts_with("Predicate `"))
                    .count(),
                5
            );
            assert!(prompt.contains("any is false and all is true"));
            let inputs = task.test_inputs(&mut random);
            assert_eq!(inputs.len(), 32);
            assert!(inputs.iter().any(Vec::is_empty));
            assert!(inputs.iter().any(|x| x.len() == 64));
            for input in inputs {
                assert!(input.len() <= MAX_INPUT_LEN);
                assert!(input.iter().all(|x| x.abs() <= MAX_INPUT_ABS));
                let value = task.evaluate(&input);
                let values = match value {
                    Value::Number(number) => vec![number.as_i64().unwrap()],
                    Value::Array(values) => values.iter().map(|x| x.as_i64().unwrap()).collect(),
                    _ => panic!("unexpected output type"),
                };
                assert!(values.len() <= MAX_INPUT_LEN);
                assert!(values.iter().all(|x| x.abs() < 1_000_000_000));
            }
        }
    }
}
