# Binding contract fixtures

`v1.json` is the runtime-neutral contract shared by the C, C++, Python, and
future Phase 5C bindings. It freezes stable status values, reusable binary test
vectors, callback scripts, expected outcomes and traces, release counts, and
values that must never appear in diagnostics or observer events.

Binary values use lowercase hexadecimal unless the ABI field is JSON-facing,
in which case it uses canonical unpadded base64url. Cases and generated output
are sorted by case ID. Unknown fields are rejected so consumers cannot silently
diverge from the versioned schema.

Regenerate the checked-in C representation with:

```sh
python3 bindings/c/tools/generate_fixtures.py \
  --input fixtures/bindings/v1.json \
  --output bindings/c/tests/generated_fixtures.h
```

Use `--check` in tests and CI to detect drift without rewriting the file.
