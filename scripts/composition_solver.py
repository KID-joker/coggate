#!/usr/bin/env python3
"""Adaptive white-box attack for the public composition experiment grammar.

This standalone program reads only public challenge JSON or plain prompt text
from stdin. It does not import the generator, load fixtures, inspect secrets,
call a network service, or run a model. Random names are resolved within each
prompt; their spelling carries no assumed meaning.

Pipeline: recognize declarations -> parse scoped predicate expressions ->
resolve references -> parse guarded sequence operations -> emit a small JS
interpreter plus the extracted operation plan.
"""

import argparse
import json
import re
import sys


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


def parse_prompt(prompt):
    symbols, stages = {}, {}
    result_mode = None
    for raw_line in prompt.splitlines():
        line = raw_line.strip()
        if line.startswith("Predicate "):
            name, expression = predicate_declaration(line)
            if name in symbols:
                raise ValueError("duplicate predicate name in prompt scope")
            symbols[name] = expression
        numbered = re.fullmatch(r"(\d+)\. (.+)", line)
        if numbered:
            index = int(numbered[1])
            if index in stages:
                raise ValueError("duplicate stage number")
            stages[index] = numbered[2]
        if line == "Return the final sequence as an array.":
            result_mode = "array"
        if line == "Return the sum of the final sequence as one integer; the empty sum is 0.":
            result_mode = "sum"
    if not symbols or not stages or result_mode is None:
        raise ValueError("incomplete public composition specification")
    if sorted(stages) != list(range(1, len(stages) + 1)):
        raise ValueError("non-contiguous stage numbering")
    indexes = {name: index for index, name in enumerate(symbols)}
    predicates = [resolve_expression(("ref", name), symbols) for name in symbols]
    operations = [stage_plan(stages[index], indexes) for index in sorted(stages)]
    return predicates, operations, result_mode


INTERPRETER = r"""
function solve(input){
  var plan=PLAN_LITERAL,current=input,next,step,run,mode,operation;
  var s,i,j,x,n,duplicate,total=0,scanStart,scanEnd;
  for(s=0;s<plan.length;s++){
    step=plan[s];mode=step[0];operation=step[2];n=current.length;
    run=(mode===0 || mode===2);
    if(mode!==0){
      for(i=0;i<n;i++){
        if(mode===1 && predicate(step[1],current[i])){run=true;}
        if(mode===2 && !predicate(step[1],current[i])){run=false;}
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


def solve(prompt, ignore_guards=False):
    predicates, plan, result_mode = parse_prompt(prompt)
    if ignore_guards:
        for stage in plan:
            stage[0], stage[1] = 0, -1
    dispatch = "function predicate(id,x){\n"
    for index, expression in enumerate(predicates):
        dispatch += "if(id===%d){return %s;}\n" % (index, predicate_js(expression))
    dispatch += "return false;\n}\n"
    body = INTERPRETER.replace("PLAN_LITERAL", json.dumps(plan, separators=(",", ":")))
    body = body.replace(
        "RETURN_EXPRESSION",
        "for(i=0;i<current.length;i++){total=total+current[i];}return total;"
        if result_mode == "sum" else "return current;",
    )
    suffix = "_ignore_guards" if ignore_guards else ""
    return "// public-grammar family: composition_%d_steps%s\n%s%s" % (
        len(plan), suffix, dispatch, body,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ignore-guards", action="store_true",
        help="ablation attack: execute every stage regardless of its public condition",
    )
    arguments = parser.parse_args()
    try:
        sys.stdout.write(solve(read_prompt(sys.stdin.read()), arguments.ignore_guards))
    except ValueError as error:
        print("composition solver: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
