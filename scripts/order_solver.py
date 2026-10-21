#!/usr/bin/env python3
"""Standalone offline baseline for the unordered-operation cost experiment.

This standalone program reads only public challenge JSON or plain prompt text
from stdin. It does not import the generator, load fixtures, inspect secrets,
call a network service, or run a model. Random names are resolved within each
prompt; their spelling carries no assumed meaning.

Development reuse: public predicate/card parsing and the ES5 interpreter below
are copied and adapted from scripts/composition_solver.py. This is explicitly
reuse of a previously developed attack, not an independently handwritten
baseline or evidence of independent attacker development cost.

Pipeline: parse public declarations/cards/examples -> enumerate every ordering
of at most five cards -> simulate public examples in Python -> require exactly
one matching order -> emit ES5 code using that order. At most 120 permutations
is only a bounded cost experiment; this does not establish greater difficulty.

Successful stdout contains JavaScript only. Stderr contains one prefixed JSON
metrics object. No existing solver or generator is imported at runtime. An old
parser failing to recognize this format is not evidence of a successful defense.
"""

import itertools
import json
import re
import sys
import time


NAME = r"`([a-z]+)`"


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


def expression_tokens(text):
    """Lex names separately from grammar words, rejecting leftover characters."""
    tokens = []
    cursor = 0
    pattern = re.compile(r"\s*(`([a-z]+)`|both|either|not|and|or)\s*")
    while cursor < len(text):
        match = pattern.match(text, cursor)
        if match is None:
            raise ValueError("unrecognized predicate expression token")
        tokens.append(("name", match[2]) if match[2] else ("word", match[1]))
        cursor = match.end()
    return tokens


def alias_expression(text):
    tokens = expression_tokens(text)
    if len(tokens) == 1 and tokens[0][0] == "name":
        return ("ref", tokens[0][1])
    if len(tokens) == 2 and tokens[0] == ("word", "not") and tokens[1][0] == "name":
        return ("not", ("ref", tokens[1][1]))
    if len(tokens) == 4 and tokens[1][0] == tokens[3][0] == "name":
        if tokens[0] == ("word", "both") and tokens[2] == ("word", "and"):
            return ("and", ("ref", tokens[1][1]), ("ref", tokens[3][1]))
        if tokens[0] == ("word", "either") and tokens[2] == ("word", "or"):
            return ("or", ("ref", tokens[1][1]), ("ref", tokens[3][1]))
    raise ValueError("unrecognized predicate expression structure")


def predicate_declaration(line):
    atom = re.fullmatch(r"Predicate " + NAME + r" holds for x exactly when (.*)\.", line)
    if atom:
        name, expression = atom.groups()
        comparison = re.fullmatch(r"x (>=|<=) (-?\d+)", expression)
        if comparison:
            return name, ("compare", comparison[1], int(comparison[2]))
        residue = re.fullmatch(r"\(\(x % (\d+)\) \+ (\d+)\) % (\d+) equals (\d+)", expression)
        if residue:
            modulus, repeated, final, target = map(int, residue.groups())
            if modulus <= 0 or repeated != modulus or final != modulus:
                raise ValueError("inconsistent normalized-residue definition")
            return name, ("residue", modulus, target)
        raise ValueError("unrecognized atomic predicate")
    alias = re.fullmatch(
        r"Predicate " + NAME + r" (?:means|is another way to say) (.*)\.", line
    )
    if alias:
        return alias[1], alias_expression(alias[2])
    raise ValueError("unrecognized predicate declaration")


def resolve_expression(expression, symbols, active=()):
    """Resolve a fresh per-prompt symbol table, with cycle detection."""
    kind = expression[0]
    if kind == "ref":
        name = expression[1]
        if name not in symbols:
            raise ValueError("undefined local predicate: " + name)
        if name in active:
            raise ValueError("cyclic local predicate definition")
        return resolve_expression(symbols[name], symbols, active + (name,))
    if kind == "not":
        return (kind, resolve_expression(expression[1], symbols, active))
    if kind in ("and", "or"):
        return (
            kind,
            resolve_expression(expression[1], symbols, active),
            resolve_expression(expression[2], symbols, active),
        )
    return expression


def predicate_js(expression):
    kind = expression[0]
    if kind == "compare":
        return "(x%s%d)" % (expression[1], expression[2])
    if kind == "residue":
        modulus, target = expression[1:]
        return "(((x%%%d)+%d)%%%d===%d)" % (modulus, modulus, modulus, target)
    if kind == "not":
        return "(!%s)" % predicate_js(expression[1])
    if kind in ("and", "or"):
        return "(%s%s%s)" % (
            predicate_js(expression[1]), "&&" if kind == "and" else "||",
            predicate_js(expression[2]),
        )
    raise ValueError("unresolved predicate expression")


def predicate_number(name, indexes):
    if name not in indexes:
        raise ValueError("operation references undefined predicate: " + name)
    return indexes[name]


def operation_plan(text, indexes):
    # Encodings belong to this independent attack implementation, not to the
    # generator: filter=0, map=1, sort=2, reverse=3, unique=4, take=5.
    match = re.fullmatch(r"retain only values satisfying " + NAME + r", preserving their order", text)
    if not match:
        match = re.fullmatch(r"keep elements for which " + NAME + r" is true, preserving their order", text)
    if match:
        return [0, predicate_number(match[1], indexes), 0]
    match = re.fullmatch(
        r"(?:replace each x with|map each current value x to) \((-?\d+) \* x\) \+ \((-?\d+)\)",
        text,
    )
    if match:
        return [1, int(match[1]), int(match[2])]
    match = re.fullmatch(r"sort values numerically in (ascending|descending) order", text)
    if match:
        return [2, 1 if match[1] == "ascending" else -1, 0]
    if text == "reverse the current sequence":
        return [3, 0, 0]
    match = re.fullmatch(
        r"keep only the (first|last) occurrence of each distinct value, preserving the order of surviving occurrences",
        text,
    )
    if match:
        return [4, 0 if match[1] == "first" else 1, 0]
    match = re.fullmatch(r"keep at most the first (\d+) values", text)
    if not match:
        match = re.fullmatch(r"take the first (\d+) current values", text)
    if match:
        return [5, int(match[1]), 0]
    raise ValueError("unrecognized sequence operation")


def stage_plan(text, indexes):
    guarded = re.fullmatch(
        r"If (any current value satisfies|all current values satisfy) " + NAME +
        r", (.*); otherwise leave the sequence unchanged\.",
        text,
    )
    if guarded:
        mode, predicate, operation = guarded.groups()
        return [1 if mode.startswith("any ") else 2, predicate_number(predicate, indexes)] + operation_plan(operation, indexes)
    if not text.endswith("."):
        raise ValueError("operation sentence missing terminator")
    return [0, -1] + operation_plan(text[:-1], indexes)


def public_example(line):
    if not line.startswith("Example "):
        return None
    example = re.fullmatch(r"Example (\d+): input = (\[.*\]); output = (.+)", line)
    if example is None:
        raise ValueError("malformed public example")
    index = int(example[1])
    values = json.loads(example[2])
    expected = json.loads(example[3])
    if not isinstance(values, list) or len(values) > 64:
        raise ValueError("public example input must be an array of at most 64 integers")
    if any(type(x) is not int or not -10000 <= x <= 10000 for x in values):
        raise ValueError("public example input value outside the declared contract")
    if type(expected) is not int and (
        not isinstance(expected, list) or any(type(x) is not int for x in expected)
    ):
        raise ValueError("public output must be an integer or integer array")
    return index, (values, expected)


def ordered_examples(examples):
    if not examples or len(examples) > 32:
        raise ValueError("public example count must be between one and 32")
    if sorted(examples) != list(range(1, len(examples) + 1)):
        raise ValueError("non-contiguous example labels")
    return [examples[index] for index in sorted(examples)]


def parse_prompt(prompt):
    symbols, cards, examples = {}, {}, {}
    result_mode = None
    for raw_line in prompt.splitlines():
        line = raw_line.strip()
        if line.startswith("Predicate "):
            name, expression = predicate_declaration(line)
            if name in symbols:
                raise ValueError("duplicate predicate name in prompt scope")
            symbols[name] = expression
        card = re.fullmatch(r"Card ([A-E]): (.+)", line)
        if line.startswith("Card ") and card is None:
            raise ValueError("malformed public card")
        if card:
            index = card[1]
            if index in cards:
                raise ValueError("duplicate card label")
            cards[index] = card[2]
        example = public_example(line)
        if example:
            index, value = example
            if index in examples:
                raise ValueError("duplicate example label")
            examples[index] = value
        if line == "Return the final sequence as an array.":
            result_mode = "array"
        if line == "Return the sum of the final sequence as one integer; the empty sum is 0.":
            result_mode = "sum"
    if not symbols or not cards or not examples or result_mode is None:
        raise ValueError("incomplete public unordered-operation specification")
    if not 1 <= len(cards) <= 5:
        raise ValueError("unordered experiment supports one to five cards")
    if sorted(cards) != [chr(ord("A") + index) for index in range(len(cards))]:
        raise ValueError("non-contiguous card labels")
    examples = ordered_examples(examples)
    for _, expected in examples:
        if result_mode == "array":
            if not isinstance(expected, list) or any(type(x) is not int for x in expected):
                raise ValueError("public output must be an integer array")
        elif type(expected) is not int:
            raise ValueError("public output must be an integer")
    indexes = {name: index for index, name in enumerate(symbols)}
    predicates = [resolve_expression(("ref", name), symbols) for name in symbols]
    operations = [stage_plan(cards[index], indexes) for index in sorted(cards)]
    return predicates, operations, result_mode, examples


def predicate_matches(expression, x):
    """Independent Python evaluator for the public predicate expression tree."""
    kind = expression[0]
    if kind == "compare":
        return x >= expression[2] if expression[1] == ">=" else x <= expression[2]
    if kind == "residue":
        return x % expression[1] == expression[2]
    if kind == "not":
        return not predicate_matches(expression[1], x)
    if kind == "and":
        return predicate_matches(expression[1], x) and predicate_matches(expression[2], x)
    if kind == "or":
        return predicate_matches(expression[1], x) or predicate_matches(expression[2], x)
    raise ValueError("unresolved Python predicate expression")


def evaluate_plan(predicates, plan, result_mode, values):
    """Simulate a candidate using public values only; never invokes the worker."""
    current = list(values)
    for mode, guard, operation, first, second in plan:
        if mode == 1 and not any(predicate_matches(predicates[guard], x) for x in current):
            continue
        if mode == 2 and not all(predicate_matches(predicates[guard], x) for x in current):
            continue
        if operation == 0:
            current = [x for x in current if predicate_matches(predicates[first], x)]
        elif operation == 1:
            current = [first * x + second for x in current]
        elif operation == 2:
            current = sorted(current, reverse=first == -1)
        elif operation == 3:
            current = current[::-1]
        elif operation == 4:
            current = [
                x for i, x in enumerate(current)
                if x not in (current[:i] if first == 0 else current[i + 1:])
            ]
        elif operation == 5:
            current = current[:first]
        else:
            raise ValueError("unknown Python operation")
    return sum(current) if result_mode == "sum" else current


def infer_order(predicates, cards, result_mode, examples):
    matching = []
    enumerated = 0
    evaluations = 0
    for order in itertools.permutations(range(len(cards))):
        enumerated += 1
        plan = [cards[index] for index in order]
        for values, expected in examples:
            evaluations += 1
            if evaluate_plan(predicates, plan, result_mode, values) != expected:
                break
        else:
            matching.append(plan)
    if len(matching) != 1:
        raise ValueError(
            "expected one matching card order; found %d among %d permutations"
            % (len(matching), enumerated)
        )
    return matching[0], {
        "permutations_enumerated": enumerated,
        "example_evaluations": evaluations,
        "matching_orders": len(matching),
    }


INTERPRETER = r"""
function solve(input){
  var plan=PLAN_LITERAL,current=input,next,step,run,mode,operation;
  var s,i,j,x,n,duplicate,total=0,scanStart,scanEnd;
  for(s=0;s<plan.length;s++){
    step=plan[s];mode=step[0];operation=step[2];n=current.length;
    run=(mode===0 || mode===2);
    if(mode!==0){
      for(i=0;i<GUARD_LENGTH;i++){
        if(mode===1 && predicate(step[1],GUARD_VALUES[i])){run=true;}
        if(mode===2 && !predicate(step[1],GUARD_VALUES[i])){run=false;}
      }
    }
    if(run){
      next=[];
      if(operation===0){
        for(i=0;i<n;i++){
          if(predicate(step[3],current[i])){next.push(current[i]);}
        }
      }else if(operation===1){
        for(i=0;i<n;i++){next.push(step[3]*current[i]+step[4]);}
      }else if(operation===2){
        for(i=0;i<n;i++){next.push(current[i]);}
        for(i=1;i<n;i++){
          x=next[i];j=i-1;
          while(j>=0 && ((step[3]===1 && next[j]>x)||(step[3]===-1 && next[j]<x))){
            next[j+1]=next[j];j--;
          }
          next[j+1]=x;
        }
      }else if(operation===3){
        for(i=n-1;i>=0;i--){next.push(current[i]);}
      }else if(operation===4){
        for(i=0;i<n;i++){
          duplicate=false;
          if(step[3]===0){scanStart=0;scanEnd=i;}
          else{scanStart=i+1;scanEnd=n;}
          for(j=scanStart;j<scanEnd;j++){
            if(current[j]===current[i]){duplicate=true;}
          }
          if(!duplicate){next.push(current[i]);}
        }
      }else if(operation===5){
        for(i=0;i<n && i<step[3];i++){next.push(current[i]);}
      }
      current=next;
    }
  }
  RETURN_EXPRESSION
}
"""


def emit_source(predicates, plan, result_mode):
    dispatch = "function predicate(id,x){\n"
    for index, expression in enumerate(predicates):
        dispatch += "if(id===%d){return %s;}\n" % (index, predicate_js(expression))
    dispatch += "return false;\n}\n"
    body = INTERPRETER.replace("PLAN_LITERAL", json.dumps(plan, separators=(",", ":")))
    body = body.replace("GUARD_LENGTH", "n").replace("GUARD_VALUES", "current")
    body = body.replace(
        "RETURN_EXPRESSION",
        "for(i=0;i<current.length;i++){total=total+current[i];}return total;"
        if result_mode == "sum" else "return current;",
    )
    return "// public-grammar family: order_%d_cards\n%s%s" % (
        len(plan), dispatch, body,
    )


def solve(prompt):
    started = time.perf_counter()
    predicates, cards, result_mode, examples = parse_prompt(prompt)
    parsed = time.perf_counter()
    plan, metrics = infer_order(predicates, cards, result_mode, examples)
    searched = time.perf_counter()
    source = emit_source(predicates, plan, result_mode)
    emitted = time.perf_counter()
    metrics.update({
        "schema": "coggate-order-solver-v1",
        "mode": "order-search",
        "card_count": len(cards),
        "public_example_count": len(examples),
        "parse_ms": round((parsed - started) * 1000, 6),
        "search_ms": round((searched - parsed) * 1000, 6),
        "codegen_ms": round((emitted - searched) * 1000, 6),
        "source_bytes": len(source.encode("utf-8")),
        "model_calls": 0,
    })
    return source, metrics


def solve_examples_only(prompt):
    """Negative control: exact public-example lookup with null on every miss."""
    started = time.perf_counter()
    examples = {}
    for raw_line in prompt.splitlines():
        example = public_example(raw_line.strip())
        if example is not None:
            index, value = example
            if index in examples:
                raise ValueError("duplicate example label")
            examples[index] = value
    examples = ordered_examples(examples)
    parsed = time.perf_counter()
    lines = ["// public-grammar family: order_examples_only", "function solve(input){"]
    for values, expected in examples:
        checks = ["input.length===%d" % len(values)]
        checks.extend("input[%d]===%d" % (index, x) for index, x in enumerate(values))
        lines.append(
            "if(%s){return %s;}"
            % ("&&".join(checks), json.dumps(expected, separators=(",", ":")))
        )
    lines.append("return null;}")
    source = "\n".join(lines) + "\n"
    emitted = time.perf_counter()
    return source, {
        "schema": "coggate-order-solver-v1",
        "mode": "examples-only",
        "permutations_enumerated": 0,
        "example_evaluations": 0,
        "matching_orders": 0,
        "card_count": 0,
        "public_example_count": len(examples),
        "parse_ms": round((parsed - started) * 1000, 6),
        "search_ms": 0,
        "codegen_ms": round((emitted - parsed) * 1000, 6),
        "source_bytes": len(source.encode("utf-8")),
        "model_calls": 0,
    }


def self_test():
    """Small public-only regression cases; no fixtures, files, worker or model."""
    prompt = """Predicate `plain` holds for x exactly when x >= 0.
Card D: replace each x with (-3 * x) + (-2).
Card B: replace each x with (3 * x) + (5).
Card A: replace each x with (2 * x) + (1).
Card C: replace each x with (-2 * x) + (9).
Return the final sequence as an array.
Exactly one permutation of the distinct card identifiers agrees with every public example.
Example 1: input = [0]; output = [-172]
Example 2: input = [1,2]; output = [-136,-100]"""
    source, metrics = solve(prompt)
    assert metrics["permutations_enumerated"] == 24
    assert metrics["matching_orders"] == 1
    assert metrics["source_bytes"] == len(source.encode("utf-8"))
    predicates, cards, mode, examples = parse_prompt(prompt)
    plan, _ = infer_order(predicates, cards, mode, examples)
    assert plan == [cards[2], cards[0], cards[3], cards[1]]
    assert evaluate_plan(predicates, plan, mode, [-1, 0, 3]) == [-208, -172, -64]
    assert "let " not in source and "const " not in source and "=>" not in source
    source, metrics = solve_examples_only(prompt)
    assert metrics["mode"] == "examples-only"
    assert metrics["permutations_enumerated"] == metrics["example_evaluations"] == 0
    assert metrics["matching_orders"] == 0
    assert "return null;" in source
    # This control intentionally needs neither cards nor predicate declarations.
    assert solve_examples_only("Example 1: input = [1]; output = 2")[1]["public_example_count"] == 1

    def rejects(operation, contains):
        try:
            operation()
        except ValueError as error:
            assert contains in str(error), str(error)
        else:
            raise AssertionError("invalid public specification was accepted")

    ambiguous = prompt.replace(
        "Example 1: input = [0]; output = [-172]", "Example 1: input = []; output = []"
    ).replace(
        "Example 2: input = [1,2]; output = [-136,-100]", "Example 2: input = []; output = []"
    )
    rejects(lambda: solve(ambiguous), "found 24")
    rejects(lambda: solve(prompt.replace("[-172]", "[999]")), "found 0")
    rejects(lambda: solve(prompt.replace("input = [0]", "input = [true]")), "input value")
    rejects(lambda: solve(prompt.replace("output = [-172]", "output = [false]")), "integer array")
    rejects(lambda: solve(prompt.replace("Card D:", "Card A:")), "duplicate card")
    rejects(lambda: solve(prompt.replace("Card D:", "Card Z:")), "malformed public card")
    rejects(lambda: solve(prompt.replace("Example 2:", "Example 1:")), "duplicate example")
    rejects(lambda: solve(prompt.replace("Example 2:", "Example 3:")), "example labels")
    rejects(
        lambda: solve(prompt.replace(
            "Predicate `plain` holds for x exactly when x >= 0.", "Predicate `plain` means `plain`."
        )),
        "cyclic",
    )
    rejects(lambda: read_prompt(json.dumps({"prompt": prompt, "cases": []})), "only public")

    predicates = [("compare", ">=", 0), ("residue", 2, 1)]
    assert predicate_matches(predicates[1], -3)
    assert not predicate_matches(("not", predicates[1]), -3)
    assert predicate_matches(("and", predicates[0], predicates[1]), 3)
    assert predicate_matches(("or", predicates[0], predicates[1]), -3)
    checks = [
        ([0, -1, 0, 0, 0], [-2, 2], [2]),
        ([0, -1, 1, 2, 1], [-2, 2], [-3, 5]),
        ([0, -1, 2, 1, 0], [3, -1, 2], [-1, 2, 3]),
        ([0, -1, 2, -1, 0], [3, -1, 2], [3, 2, -1]),
        ([0, -1, 3, 0, 0], [3, -1, 2], [2, -1, 3]),
        ([0, -1, 4, 0, 0], [3, 1, 3, 2, 1], [3, 1, 2]),
        ([0, -1, 4, 1, 0], [3, 1, 3, 2, 1], [3, 2, 1]),
        ([0, -1, 5, 2, 0], [3, -1, 2], [3, -1]),
        ([1, 0, 1, 2, 1], [-2, 2], [-3, 5]),
        ([1, 0, 1, 2, 1], [-2, -1], [-2, -1]),
        ([2, 0, 1, 2, 1], [-2, 2], [-2, 2]),
        ([2, 0, 1, 2, 1], [1, 2], [3, 5]),
    ]
    for stage, values, expected in checks:
        assert evaluate_plan(predicates, [stage], "array", values) == expected
        assert evaluate_plan(predicates, [stage], "sum", values) == sum(expected)
        assert evaluate_plan(predicates, [stage], "array", []) == []
    print("order solver public-only self-test passed", file=sys.stderr)
    return 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if sys.argv[1:] not in ([], ["--examples-only"]):
        print("usage: order_solver.py [--self-test | --examples-only]", file=sys.stderr)
        return 2
    try:
        prompt = read_prompt(sys.stdin.read())
        source, metrics = solve_examples_only(prompt) if sys.argv[1:] else solve(prompt)
        sys.stdout.write(source)
        print("COGGATE_SOLVER_METRICS " + json.dumps(metrics, sort_keys=True), file=sys.stderr)
    except ValueError as error:
        print(json.dumps({"schema": "coggate-order-solver-v1", "error": str(error)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
