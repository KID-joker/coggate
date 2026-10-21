#!/usr/bin/env python3
"""White-box baseline attack against the v0.1 challenge grammar.

Runtime input is ONLY a public challenge JSON object, a JSON prompt string, or
plain prompt text on stdin. Runtime does not load fixtures, reference code,
keys, project files, models, or network services. This is deliberately a
specialized solver, not evidence that arbitrary programming tasks are easy.
"""

import json
import re
import sys


FAMILIES = (
    ("filter_sum", "Return the sum of these transformed values"),
    ("sort_limit", "Apply the limit after sorting"),
    ("unique_occurrence", "Decide duplicates before transforming"),
    ("residue_buckets", "A bucket with no values has sum 0"),
    ("prefix_total", "After EACH input value"),
    ("longest_run", "Find the longest contiguous run"),
    ("adjacent_difference", "let x = input[i] - input[i - 1]"),
    ("window_sum", "Windows overlap"),
    ("stable_partition", "Split the values into two groups"),
    ("outside_in_pairs", "Pair the first value with the last"),
)


def identify_family(prompt):
    matches = [name for name, marker in FAMILIES if marker in prompt]
    if len(matches) != 1:
        raise ValueError("unrecognized or ambiguous public task grammar")
    return matches[0]


def capture(prompt, pattern):
    match = re.search(pattern, prompt)
    if match is None:
        raise ValueError("missing public parameter: " + pattern)
    return match.groups()


def integer(prompt, pattern):
    return int(capture(prompt, pattern)[0])


def solve(prompt):
    family = identify_family(prompt)
    declarations = ["var i, j, x, total=0, result=[], n=input.length;"]
    if family in {
        "filter_sum", "sort_limit", "unique_occurrence", "prefix_total",
        "adjacent_difference", "stable_partition", "outside_in_pairs",
    }:
        a, b = map(int, capture(prompt, r"\((-?\d+) \* x\) \+ \((-?\d+)\)"))
        declarations.append("var a=%d,b=%d;" % (a, b))
    if family in {"filter_sum", "residue_buckets", "prefix_total", "stable_partition"}:
        modulus = integer(prompt, r"The residue of x means \(\(x % (\d+)\)")
        declarations.append("var modulus=%d;" % modulus)
    if family in {"filter_sum", "prefix_total", "stable_partition"}:
        residue = integer(prompt, r"(?:with residue |residue is )(\d+)")
        declarations.append("var residue=%d;" % residue)
    if family in {"sort_limit", "longest_run"}:
        threshold = integer(prompt, r"x >= (-?\d+)")
        declarations.append("var threshold=%d;" % threshold)

    if family == "filter_sum":
        body = """
for(i=0;i<n;i++){
  x=input[i];
  if(((x%modulus)+modulus)%modulus===residue){total=total+a*x+b;}
}
return total;
"""
    elif family == "sort_limit":
        limit = integer(prompt, r"first (\d+) values")
        comparator = ">" if "descending order" in prompt else "<"
        body = """
var pool=[],best,picked=%d;
for(i=0;i<n;i++){if(input[i]>=threshold){pool.push(a*input[i]+b);}}
while(result.length<picked && pool.length>0){
  best=0;
  for(i=1;i<pool.length;i++){if(pool[i]%s pool[best]){best=i;}}
  result.push(pool[best]);
  for(i=best;i+1<pool.length;i++){pool[i]=pool[i+1];}
  pool.length=pool.length-1;
}
return result;
""" % (limit, comparator)
    elif family == "unique_occurrence":
        last = capture(prompt, r"Keep only the (first|last) occurrence")[0] == "last"
        scan = "j=i+1;j<n;j++" if last else "j=0;j<i;j++"
        body = """
var duplicate;
for(i=0;i<n;i++){
  duplicate=false;
  for(%s){if(input[j]===input[i]){duplicate=true;}}
  if(!duplicate){result.push(a*input[i]+b);}
}
return result;
""" % scan
    elif family == "residue_buckets":
        body = """
for(i=0;i<modulus;i++){
  total=0;
  for(j=0;j<n;j++){
    x=input[j];
    if(((x%modulus)+modulus)%modulus===i){total=total+x;}
  }
  result.push(total);
}
return result;
"""
    elif family == "prefix_total":
        body = """
for(i=0;i<n;i++){
  x=input[i];
  if(((x%modulus)+modulus)%modulus===residue){total=total+a*x+b;}
  result.push(total);
}
return result;
"""
    elif family == "longest_run":
        last = "largest starting index" in prompt
        comparator = ">=" if last else ">"
        body = """
var start=-1,best=0,current=0;
for(i=0;i<=n;i++){
  if(i<n && input[i]>=threshold){current=current+1;}
  else {
    if(current>0 && current%s best){start=i-current;best=current;}
    current=0;
  }
}
return [start,best];
""" % comparator
    elif family == "adjacent_difference":
        limit = integer(prompt, r"absolute value is at most (\d+)")
        body = """
for(i=1;i<n;i++){
  x=input[i]-input[i-1];
  if(x>=%d && x<=%d){result.push(a*x+b);}
}
return result;
""" % (-limit, limit)
    elif family == "window_sum":
        width = integer(prompt, r"window of exactly (\d+) input")
        threshold = integer(prompt, r"sums that are >= (-?\d+)")
        body = """
var width=%d,threshold=%d;
for(i=0;i+width<=n;i++){
  total=0;
  for(j=i;j<i+width;j++){total=total+input[j];}
  if(total>=threshold){result.push(total);}
}
return result;
""" % (width, threshold)
    elif family == "stable_partition":
        a_first = capture(prompt, r"Concatenate (A followed by B|B followed by A)")[0].startswith("A")
        first, second = ("===", "!==") if a_first else ("!==", "===")
        body = """
for(i=0;i<n;i++){
  x=input[i];
  if(((x%%modulus)+modulus)%%modulus%s residue){result.push(a*x+b);}
}
for(i=0;i<n;i++){
  x=input[i];
  if(((x%%modulus)+modulus)%%modulus%s residue){result.push(a*x+b);}
}
return result;
""" % (first, second)
    else:
        middle_multiplier = 2 if "x = twice that middle value" in prompt else 1
        body = """
i=0;j=n-1;
while(i<j){x=input[i]+input[j];result.push(a*x+b);i++;j--;}
if(i===j){x=%d*input[i];result.push(a*x+b);}
return result;
""" % middle_multiplier
    return "// public-grammar family: %s\nfunction solve(input){\n%s\n%s}\n" % (
        family, "\n".join(declarations), body,
    )


def read_prompt(text):
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return text
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("prompt"), str):
        if "cases" in value or "reference_source" in value or "private" in value:
            raise ValueError("only public challenge input is accepted")
        return value["prompt"]
    raise ValueError("expected a public challenge object or prompt")


def main():
    try:
        prompt = read_prompt(sys.stdin.read())
        sys.stdout.write(solve(prompt))
    except ValueError as error:
        print("offline solver: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
