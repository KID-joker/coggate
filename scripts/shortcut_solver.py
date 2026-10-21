#!/usr/bin/env python3
"""Public-only trivial attacks, independent of the composition grammar solver.

Default: inspect only the public output-type sentence and emit a constant []
or 0. Other strategies form a fixed, auditable baseline bank. No strategy
reads task rules, hidden tests, fixtures, reference programs, files, or models.
"""

import argparse
import json
import sys


ARRAY_BODIES = {
    "constant": "return [];",
    "identity": "return input;",
    "reverse": "var out=[],i;for(i=input.length-1;i>=0;i--){out.push(input[i]);}return out;",
    "sort-ascending": (
        "var out=[],i,j,x;for(i=0;i<input.length;i++){out.push(input[i]);}"
        "for(i=1;i<out.length;i++){x=out[i];j=i-1;"
        "while(j>=0&&out[j]>x){out[j+1]=out[j];j--;}out[j+1]=x;}return out;"
    ),
    "sort-descending": (
        "var out=[],i,j,x;for(i=0;i<input.length;i++){out.push(input[i]);}"
        "for(i=1;i<out.length;i++){x=out[i];j=i-1;"
        "while(j>=0&&out[j]<x){out[j+1]=out[j];j--;}out[j+1]=x;}return out;"
    ),
    "distinct-first": (
        "var out=[],i,j,keep;for(i=0;i<input.length;i++){keep=true;"
        "for(j=0;j<i;j++){if(input[j]===input[i]){keep=false;}}"
        "if(keep){out.push(input[i]);}}return out;"
    ),
    "distinct-last": (
        "var out=[],i,j,keep;for(i=0;i<input.length;i++){keep=true;"
        "for(j=i+1;j<input.length;j++){if(input[j]===input[i]){keep=false;}}"
        "if(keep){out.push(input[i]);}}return out;"
    ),
}
for count in (1, 2, 4, 8):
    ARRAY_BODIES["take-first-" + str(count)] = (
        "var out=[],i;for(i=0;i<input.length&&i<%d;i++){out.push(input[i]);}return out;"
        % count
    )

RAW_BODIES = {
    "empty": "return [];",
    "zero": "return 0;",
    "identity": "return input;",
    "sum": "var total=0,i;for(i=0;i<input.length;i++){total+=input[i];}return total;",
}
STRATEGIES = tuple(RAW_BODIES) + tuple("typed-" + name for name in ARRAY_BODIES)


def read_prompt(text):
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return text
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("prompt"), str):
        if any(key in value for key in ("cases", "reference_source", "private")):
            raise ValueError("only public challenge input is accepted")
        return value["prompt"]
    raise ValueError("expected a public challenge object or prompt")


def output_is_sum(prompt):
    array = "Return the final sequence as an array." in prompt
    scalar = "Return the sum of the final sequence as one integer; the empty sum is 0." in prompt
    if array == scalar:
        raise ValueError("missing or ambiguous public composition return type")
    return scalar


def solve(prompt, strategy):
    if strategy in RAW_BODIES:
        body = RAW_BODIES[strategy]
    else:
        body = ARRAY_BODIES[strategy[len("typed-"):]]
        if output_is_sum(prompt):
            body = (
                "function project(input){" + body + "}"
                "var values=project(input),total=0,i;"
                "for(i=0;i<values.length;i++){total+=values[i];}return total;"
            )
    return (
        "// public-grammar family: shortcut_" + strategy.replace("-", "_")
        + "\nfunction solve(input){" + body + "}\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strategy", choices=STRATEGIES, default="typed-constant")
    parser.add_argument("--list-strategies", action="store_true")
    arguments = parser.parse_args()
    if arguments.list_strategies:
        print(json.dumps(list(STRATEGIES)))
        return 0
    try:
        sys.stdout.write(solve(read_prompt(sys.stdin.read()), arguments.strategy))
    except ValueError as error:
        print("shortcut solver: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
