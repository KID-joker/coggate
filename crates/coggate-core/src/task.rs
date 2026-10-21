use crate::{HmacSha256, HIDDEN_TEST_COUNT, MAX_INPUT_ABS, MAX_INPUT_LEN};
use hmac::Mac;
use serde_json::{json, Value};

/// Small deterministic stream; separate instances are keyed by distinct domains.
pub(crate) struct RandomStream {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    cursor: usize,
}

impl RandomStream {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0; 32],
            cursor: 32,
        }
    }

    fn next_u64(&mut self) -> u64 {
        if self.cursor == 32 {
            let mut mac =
                HmacSha256::new_from_slice(&self.seed).expect("HMAC accepts a 32-byte key");
            mac.update(b"coggate/random-stream/v1\0");
            mac.update(&self.counter.to_be_bytes());
            self.block = mac.finalize().into_bytes().into();
            self.counter += 1;
            self.cursor = 0;
        }
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.block[self.cursor..self.cursor + 8]);
        self.cursor += 8;
        u64::from_be_bytes(bytes)
    }

    pub(crate) fn below(&mut self, upper: u64) -> u64 {
        assert!(upper > 0);
        let threshold = upper.wrapping_neg() % upper;
        loop {
            let candidate = self.next_u64();
            if candidate >= threshold {
                return candidate % upper;
            }
        }
    }

    fn between(&mut self, lower: i64, upper: i64) -> i64 {
        lower + self.below((upper - lower + 1) as u64) as i64
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Task {
    kind: u8,
    modulus: i64,
    residue: i64,
    multiplier: i64,
    offset: i64,
    threshold: i64,
    width: usize,
    reverse: bool,
}

impl Task {
    pub(crate) fn generate(random: &mut RandomStream) -> Self {
        let kind = random.below(10) as u8;
        let modulus = random.between(2, 7);
        Self {
            kind,
            modulus,
            residue: random.below(modulus as u64) as i64,
            multiplier: [-3, -2, -1, 1, 2, 3][random.below(6) as usize],
            offset: random.between(-9, 9),
            threshold: random.between(-20, 20),
            width: random.between(1, 6) as usize,
            reverse: random.below(2) != 0,
        }
    }

    pub(crate) fn prompt(&self, wording: usize) -> String {
        let introduction = [
            "Implement the following array transformation.",
            "Write a program that obeys the rules below.",
            "Produce the specified result from an integer sequence.",
            "Solve this deterministic sequence-processing task.",
        ][wording % 4];
        let residue = format!(
            "The residue of x means ((x % {m}) + {m}) % {m}, so it is nonnegative even for negative x.",
            m = self.modulus,
        );
        let transform = format!("({} * x) + ({})", self.multiplier, self.offset);
        let rules = match self.kind {
            0 => format!(
                "{residue} Keep exactly the values with residue {r}. For each kept value x, compute {transform}. Return the sum of these transformed values as one integer. Return 0 if none are kept.",
                r = self.residue,
            ),
            1 => format!(
                "Keep every input value x with x >= {t}. Replace each kept value by {transform}. Sort the transformed values numerically in {order} order, preserving duplicates, and return at most the first {k} values as an array. Apply the limit after sorting. Return [] if none are kept.",
                t = self.threshold,
                order = if self.reverse { "descending" } else { "ascending" },
                k = self.width,
            ),
            2 => format!(
                "Keep only the {occurrence} occurrence of each distinct input value. Preserve the original left-to-right order of those kept occurrences. Then replace each kept value x by {transform}, and return the resulting array. Decide duplicates before transforming.",
                occurrence = if self.reverse { "last" } else { "first" },
            ),
            3 => format!(
                "{residue} Return an array of exactly {m} integers. Element j is the sum of the original input values whose residue equals j, for j from 0 through {last}. A bucket with no values has sum 0.",
                m = self.modulus,
                last = self.modulus - 1,
            ),
            4 => format!(
                "{residue} Start an integer total at 0. Visit every input value x from left to right. If its residue is {r}, add {transform} to the total; otherwise leave the total unchanged. After EACH input value, append the current total to the output array. Return that array, including entries for values that did not change the total.",
                r = self.residue,
            ),
            5 => format!(
                "Find the longest contiguous run of values x satisfying x >= {t}. Among runs of equal maximum length, choose the one with the {tie} starting index. Return [starting_index, length], with zero-based indices. If no value qualifies, return [-1, 0].",
                t = self.threshold,
                tie = if self.reverse { "largest" } else { "smallest" },
            ),
            6 => format!(
                "For each index i from 1 to input.length - 1 in ascending order, let x = input[i] - input[i - 1]. Keep this difference only if its absolute value is at most {limit}. Replace each kept difference x by {transform}. Return the transformed differences as an array in their original order. With fewer than two input values return [].",
                limit = self.width * 3,
            ),
            7 => format!(
                "For every contiguous window of exactly {width} input values, in ascending order of starting index, compute its sum. Keep only sums that are >= {t}. Return the kept sums as an array, preserving duplicate sums. Windows overlap. If the input is shorter than {width}, return [].",
                width = self.width,
                t = self.threshold,
            ),
            8 => format!(
                "{residue} Split the values into two groups: A contains values with residue {r}, and B contains all other values. Preserve the input order within each group. Concatenate {groups}, then replace each value x by {transform}. Return the resulting array.",
                r = self.residue,
                groups = if self.reverse { "B followed by A" } else { "A followed by B" },
            ),
            9 => format!(
                "Pair the first value with the last, the second with the second-last, and so on. For each pair of distinct positions compute x as their sum. If an odd-length input has a middle value, use x = {middle} for that final item. For each resulting x compute {transform}. Return these results as an array ordered from the outermost pair inward. The middle item, if present, is last. For an empty input return [].",
                middle = if self.reverse { "twice that middle value" } else { "that middle value itself" },
            ),
            _ => unreachable!("task family is in 0..10"),
        };
        format!(
            "{introduction}\n\n{rules}\n\n\
             Submission contract:\n\
             Define function solve(input) in JavaScript source. It receives an array of 0 to 64 integers, each between -10000 and 10000 inclusive, and must return the specified JSON-compatible integer or integer array. All arithmetic results fit exactly in a JavaScript Number. Never return undefined, NaN, Infinity, strings, or extra wrapper objects. Array order is significant.\n\
             Use the supported ES5-style subset: function, var, if/else, for/while, numeric arithmetic, comparisons, and arrays. Avoid let/const, arrow functions, classes, modules, promises, eval, and host APIs. Use array indexing, length, and push when needed. Do not print the answer; return it. The function must depend only on its input, with no persistent state between test cases."
        )
    }

    pub(crate) fn evaluate(&self, input: &[i64]) -> Value {
        let transform = |x| self.multiplier * x + self.offset;
        let matches = |x: i64| x.rem_euclid(self.modulus) == self.residue;
        match self.kind {
            0 => json!(input
                .iter()
                .copied()
                .filter(|&x| matches(x))
                .map(transform)
                .sum::<i64>()),
            1 => {
                let mut values: Vec<_> = input
                    .iter()
                    .copied()
                    .filter(|&x| x >= self.threshold)
                    .map(transform)
                    .collect();
                values.sort_unstable();
                if self.reverse {
                    values.reverse();
                }
                values.truncate(self.width);
                json!(values)
            }
            2 => json!(input
                .iter()
                .enumerate()
                .filter(|&(index, value)| {
                    if self.reverse {
                        !input[index + 1..].contains(value)
                    } else {
                        !input[..index].contains(value)
                    }
                })
                .map(|(_, &value)| transform(value))
                .collect::<Vec<_>>()),
            3 => {
                let mut buckets = vec![0_i64; self.modulus as usize];
                for &x in input {
                    buckets[x.rem_euclid(self.modulus) as usize] += x;
                }
                json!(buckets)
            }
            4 => {
                let mut total = 0;
                json!(input
                    .iter()
                    .map(|&x| {
                        if matches(x) {
                            total += transform(x);
                        }
                        total
                    })
                    .collect::<Vec<_>>())
            }
            5 => {
                let mut start = -1_i64;
                let mut best_length = 0;
                let mut current_length = 0;
                for (index, &x) in input.iter().enumerate() {
                    if x >= self.threshold {
                        current_length += 1;
                        if current_length > best_length
                            || (self.reverse && current_length == best_length)
                        {
                            best_length = current_length;
                            start = (index + 1 - current_length) as i64;
                        }
                    } else {
                        current_length = 0;
                    }
                }
                json!([start, best_length as i64])
            }
            6 => json!(input
                .windows(2)
                .map(|window| window[1] - window[0])
                .filter(|x| x.abs() <= self.width as i64 * 3)
                .map(transform)
                .collect::<Vec<_>>()),
            7 => json!(input
                .windows(self.width)
                .map(|window| window.iter().sum::<i64>())
                .filter(|&sum| sum >= self.threshold)
                .collect::<Vec<_>>()),
            8 => {
                let mut first = Vec::new();
                let mut second = Vec::new();
                for &x in input {
                    if matches(x) != self.reverse {
                        first.push(transform(x));
                    } else {
                        second.push(transform(x));
                    }
                }
                first.extend(second);
                json!(first)
            }
            9 => json!((0..input.len().div_ceil(2))
                .map(|index| {
                    let opposite = input.len() - index - 1;
                    let x = if index == opposite && !self.reverse {
                        input[index]
                    } else {
                        input[index] + input[opposite]
                    };
                    transform(x)
                })
                .collect::<Vec<_>>()),
            _ => unreachable!("task family is in 0..10"),
        }
    }

    pub(crate) fn test_inputs(&self, random: &mut RandomStream) -> Vec<Vec<i64>> {
        // These boundary cases complement hidden randomness. Every input is
        // generated independently of the public wording domain.
        let mut cases = vec![
            vec![],
            vec![0],
            vec![-MAX_INPUT_ABS],
            vec![MAX_INPUT_ABS],
            vec![-MAX_INPUT_ABS, MAX_INPUT_ABS],
            vec![self.threshold - 1, self.threshold, self.threshold + 1],
            vec![
                self.residue - self.modulus,
                self.residue,
                self.residue + self.modulus,
            ],
            vec![2, 1, 2, -1, 1, 0, -1],
            vec![0; MAX_INPUT_LEN],
            vec![MAX_INPUT_ABS; MAX_INPUT_LEN],
            vec![-MAX_INPUT_ABS; MAX_INPUT_LEN],
            (0..MAX_INPUT_LEN)
                .map(|index| {
                    if index % 2 == 0 {
                        -MAX_INPUT_ABS
                    } else {
                        MAX_INPUT_ABS
                    }
                })
                .collect(),
            vec![
                self.threshold,
                self.threshold,
                self.threshold - 1,
                self.threshold,
                self.threshold,
            ],
            vec![1; self.width.saturating_sub(1)],
            vec![self.threshold; self.width],
            vec![1; self.width + 1],
        ];
        while cases.len() < HIDDEN_TEST_COUNT {
            let length = random.below((MAX_INPUT_LEN + 1) as u64) as usize;
            let index = cases.len();
            let values = (0..length)
                .map(|_| match index % 4 {
                    0 => random.between(-MAX_INPUT_ABS, MAX_INPUT_ABS),
                    1 => random.between(-8, 8),
                    2 => self.threshold + random.between(-2, 2),
                    _ => {
                        random.between(-8, 8) * self.modulus
                            + random.below(self.modulus as u64) as i64
                    }
                })
                .collect();
            cases.push(values);
        }
        // Keep both the random inputs and their execution order private.
        for index in (1..cases.len()).rev() {
            cases.swap(index, random.below((index + 1) as u64) as usize);
        }
        cases
    }

    #[cfg(any(test, feature = "dev-tools"))]
    pub(crate) fn reference_solution(&self) -> String {
        let declarations = format!(
            "var a={}, b={}, m={}, r={}, t={}, k={}, rev={}, n=input.length;\n\
             var out=[], i, j, x, y, total=0;",
            self.multiplier,
            self.offset,
            self.modulus,
            self.residue,
            self.threshold,
            self.width,
            self.reverse
        );
        let body = match self.kind {
            0 => "for(i=0;i<n;i++){x=input[i];if(((x%m)+m)%m===r){total+=a*x+b;}}return total;",
            1 => "for(i=0;i<n;i++){x=input[i];if(x>=t){out.push(a*x+b);}}\
                  for(i=1;i<out.length;i++){x=out[i];j=i-1;while(j>=0&&((!rev&&out[j]>x)||(rev&&out[j]<x))){out[j+1]=out[j];j--;}out[j+1]=x;}\
                  var limited=[];for(i=0;i<out.length&&i<k;i++){limited.push(out[i]);}return limited;",
            2 => "for(i=0;i<n;i++){x=input[i];var keep=true;\
                  if(rev){for(j=i+1;j<n;j++){if(input[j]===x){keep=false;}}}\
                  else{for(j=0;j<i;j++){if(input[j]===x){keep=false;}}}\
                  if(keep){out.push(a*x+b);}}return out;",
            3 => "for(i=0;i<m;i++){out.push(0);}for(i=0;i<n;i++){x=input[i];j=((x%m)+m)%m;out[j]+=x;}return out;",
            4 => "for(i=0;i<n;i++){x=input[i];if(((x%m)+m)%m===r){total+=a*x+b;}out.push(total);}return out;",
            5 => "var start=-1,best=0,current=0;for(i=0;i<n;i++){if(input[i]>=t){current++;\
                  if(current>best||(rev&&current===best)){best=current;start=i-current+1;}}\
                  else{current=0;}}return [start,best];",
            6 => "for(i=1;i<n;i++){x=input[i]-input[i-1];if(x>=-k*3&&x<=k*3){out.push(a*x+b);}}return out;",
            7 => "for(i=0;i+k<=n;i++){total=0;for(j=0;j<k;j++){total+=input[i+j];}if(total>=t){out.push(total);}}return out;",
            8 => "var tail=[];for(i=0;i<n;i++){x=input[i];if(((((x%m)+m)%m)===r)!==rev){out.push(a*x+b);}\
                  else{tail.push(a*x+b);}}for(i=0;i<tail.length;i++){out.push(tail[i]);}return out;",
            9 => "for(i=0;i<n-i;i++){j=n-1-i;x=(i===j&&!rev)?input[i]:input[i]+input[j];out.push(a*x+b);}return out;",
            _ => unreachable!("task family is in 0..10"),
        };
        format!("function solve(input){{{declarations}\n{body}}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(kind: u8, reverse: bool) -> Task {
        Task {
            kind,
            modulus: 3,
            residue: 2,
            multiplier: -2,
            offset: 3,
            threshold: 1,
            width: 2,
            reverse,
        }
    }

    #[test]
    fn all_families_match_hand_computed_examples() {
        let input = [-1, 2, 2, 0, 5];
        let expected = [
            json!(-4),
            json!([-7, -1]),
            json!([5, -1, 3, -7]),
            json!([0, 0, 8]),
            json!([5, 4, 3, 3, -4]),
            json!([1, 2]),
            json!([-3, 3, 7, -7]),
            json!([1, 4, 2, 5]),
            json!([5, -1, -1, -7, 3]),
            json!([-5, -1, -1]),
        ];
        for (kind, value) in expected.iter().enumerate() {
            assert_eq!(
                task(kind as u8, false).evaluate(&input),
                *value,
                "family {kind}"
            );
        }
    }

    #[test]
    fn reverse_rules_change_order_ties_and_middle_semantics() {
        assert_eq!(task(1, true).evaluate(&[-1, 2, 2, 0, 5]), json!([-1, -1]));
        assert_eq!(
            task(2, true).evaluate(&[-1, 2, -1, 0, 2]),
            json!([5, 3, -1])
        );
        assert_eq!(task(5, false).evaluate(&[1, 1, 0, 1, 1]), json!([0, 2]));
        assert_eq!(task(5, true).evaluate(&[1, 1, 0, 1, 1]), json!([3, 2]));
        assert_eq!(
            task(8, true).evaluate(&[-1, 2, 2, 0, 5]),
            json!([3, 5, -1, -1, -7])
        );
        assert_eq!(
            task(9, true).evaluate(&[-1, 2, 2, 0, 5]),
            json!([-5, -1, -5])
        );
    }

    #[test]
    fn empty_inputs_and_strict_boundaries_are_defined() {
        for kind in 0..10 {
            let result = task(kind, false).evaluate(&[]);
            assert_eq!(
                result,
                match kind {
                    0 => json!(0),
                    3 => json!([0, 0, 0]),
                    5 => json!([-1, 0]),
                    _ => json!([]),
                }
            );
        }
        assert_eq!(task(5, false).evaluate(&[-1, 0]), json!([-1, 0]));
        assert_eq!(task(6, false).evaluate(&[0, 6, 13, 7]), json!([-9, 15]));
        assert_eq!(task(7, false).evaluate(&[4]), json!([]));
        assert_eq!(task(7, false).evaluate(&[-2, 3]), json!([1]));
        assert_eq!(task(0, false).evaluate(&[-4]), json!(11));
    }

    #[test]
    fn prompt_parameters_and_reference_are_bound_to_the_same_task() {
        let sample = task(0, false);
        let prompt = sample.prompt(0);
        assert!(prompt.contains("((x % 3) + 3) % 3"));
        assert!(prompt.contains("residue 2"));
        assert!(prompt.contains("(-2 * x) + (3)"));
        assert!(sample.reference_solution().contains("a=-2, b=3, m=3, r=2"));
        for kind in 0..10 {
            let current = task(kind, false);
            for wording in 0..4 {
                assert!(current.prompt(wording).contains("function solve(input)"));
            }
            assert!(current
                .reference_solution()
                .starts_with("function solve(input)"));
        }
    }

    fn assert_safe_json(value: &Value) {
        match value {
            Value::Number(number) => {
                let integer = number.as_i64().expect("integer result");
                assert!(integer.abs() <= 2_000_000);
            }
            Value::Array(values) => {
                assert!(values.len() <= MAX_INPUT_LEN);
                for value in values {
                    assert_safe_json(value);
                }
            }
            _ => panic!("results must be an integer or integer array"),
        }
    }

    #[test]
    fn all_hidden_suites_cover_bounds_and_remain_exact_in_js() {
        let mut random = RandomStream::new([83; 32]);
        for _ in 0..100 {
            let generated = Task::generate(&mut random);
            for kind in 0..10 {
                let current = Task { kind, ..generated };
                let inputs = current.test_inputs(&mut random);
                assert_eq!(inputs.len(), HIDDEN_TEST_COUNT);
                assert!(inputs.iter().any(Vec::is_empty));
                assert!(inputs.iter().any(|input| input.len() == MAX_INPUT_LEN));
                assert!(inputs.iter().flatten().any(|&x| x == -MAX_INPUT_ABS));
                assert!(inputs.iter().flatten().any(|&x| x == MAX_INPUT_ABS));
                for input in inputs {
                    assert!(input.len() <= MAX_INPUT_LEN);
                    assert!(input.iter().all(|x| x.abs() <= MAX_INPUT_ABS));
                    assert_safe_json(&current.evaluate(&input));
                }
            }
        }
    }
}
