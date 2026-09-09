#!/usr/bin/env python3
"""Validate the shared binding contract and render its C representation."""

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path


TOP_KEYS = {"fixture_version", "statuses", "vectors", "cases"}
CASE_KEYS = {
    "id",
    "operation",
    "submission",
    "binding_hex",
    "lifecycle",
    "keys",
    "expected_status",
    "expected_code",
    "expected_outcome",
    "expected_trace",
    "expected_release_count",
    "forbidden_sentinels",
}
STATUS_DEFINITIONS = {
    "ok": (0, "ok"),
    "invalid_configuration": (1, "invalid_configuration"),
    "generation_failed": (2, "generation_failed"),
    "invalid_challenge_material": (3, "invalid_challenge_material"),
    "invalid_answer_encoding": (4, "invalid_answer_encoding"),
    "answer_mismatch": (5, "answer_mismatch"),
    "unsupported_generator_version": (6, "unsupported_generator_version"),
    "internal_error": (7, "internal_error"),
    "invalid_argument": (100, "invalid_argument"),
    "callback_failed": (101, "callback_failed"),
    "panic_caught": (102, "panic_caught"),
}
VECTOR_KEYS = {
    "challenge_id",
    "nonce",
    "answer",
    "wrong_answer",
    "binding_hex",
    "token_hex",
    "active_key_id",
    "active_key_hex",
    "old_key_id",
    "old_key_hex",
    "private_material",
    "observer_allowlist",
}
MATERIAL_KEYS = {
    "challenge_id",
    "generator_version",
    "nonce",
    "issued_at",
    "expires_at",
    "mac_key_id",
    "answer_mac",
    "answer_encoding",
}
SUBMISSION_KEYS = {"challenge_id", "nonce", "answer"}
LIFECYCLE_KEYS = {
    "begin_status",
    "finish_status",
    "material",
    "token",
    "replay",
    "callback_exception",
}
KEYS_KEYS = {"status", "key_id", "callback_exception"}
REQUIRED_CASE_IDS = {
    "accepted",
    "answer_mismatch",
    "lifecycle_not_found",
    "lifecycle_expired",
    "lifecycle_already_consumed",
    "lifecycle_binding_mismatch",
    "lifecycle_nonce_mismatch",
    "lifecycle_attempts_exhausted",
    "replay_after_accept",
    "key_rotation_old_key",
    "finish_failure",
    "observer_allowlist",
    "exact_release",
    "close_after_use",
    "callback_exception",
}
REJECTION_REASONS = {
    "not_found",
    "expired",
    "already_consumed",
    "binding_mismatch",
    "nonce_mismatch",
    "attempts_exhausted",
}
BEGIN_STATUSES = {"ok", "internal", "exception", "unused"} | REJECTION_REASONS
FINISH_STATUSES = {"ok", "internal", "unused"}
KEY_STATUSES = {"ok", "unavailable", "not_found", "invalid_material", "unused"}
OPERATIONS = {"verify", "observe", "release", "close"}
TRACE_VALUES = {
    "begin_attempt",
    "begin_attempt:exception",
    "key_by_id:active",
    "key_by_id:old",
    "finish_attempt:accepted",
    "finish_attempt:rejected",
    "finish_attempt:system_failure",
    "observe:verification_completed",
    "observe:service_failed",
    "release:material",
    "release:token",
    "release:key",
    "service_destroy",
}
KNOWN_VECTOR = {
    "challenge_id": "Y2hhbGxlbmdlLTEyMzQ1Ng",
    "nonce": "bm9uY2UtMTIzNDU2Nzg5MA",
    "answer": "YQ",
    "old_key_id": "2026-08",
    "old_key_hex": "3031323334353637383961626364656630313233343536373839616263646566",
    "generator_version": "1.0",
    "issued_at": 1788062400,
    "expires_at": 1788062408,
    "answer_mac": "b9cb8fd013b40e31c7bc3a1c33b7e36143ef98d045a924ed09ebd38ff07cec2c",
}
OBSERVER_FIELDS = {
    "event",
    "challenge_id",
    "generator_version",
    "disposition",
    "elapsed_since_issue_us",
    "duration_us",
}


class FixtureError(Exception):
    pass


def _object_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError()
        result[key] = value
    return result


def _exact_object(value, keys):
    if not isinstance(value, dict) or set(value) != keys:
        raise FixtureError()


def _string(value, allow_empty=False):
    if not isinstance(value, str) or (not allow_empty and not value):
        raise FixtureError()


def _integer(value):
    if type(value) is not int:
        raise FixtureError()


def _hex(value, allow_empty=False):
    _string(value, allow_empty=allow_empty)
    if len(value) % 2 or re.fullmatch(r"[0-9a-f]*", value) is None:
        raise FixtureError()


def _base64url(value):
    _string(value)
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise FixtureError()
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise FixtureError()
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value:
        raise FixtureError()


def _random_token(value):
    _base64url(value)
    padding = "=" * ((4 - len(value) % 4) % 4)
    decoded = base64.urlsafe_b64decode(value + padding)
    if len(value) != 22 or len(decoded) != 16:
        raise FixtureError()


def _validate_statuses(statuses):
    if not isinstance(statuses, dict) or set(statuses) != set(STATUS_DEFINITIONS):
        raise FixtureError()
    for name, expected in STATUS_DEFINITIONS.items():
        definition = statuses[name]
        _exact_object(definition, {"value", "code"})
        _integer(definition["value"])
        _string(definition["code"])
        if (definition["value"], definition["code"]) != expected:
            raise FixtureError()


def _validate_vectors(vectors):
    _exact_object(vectors, VECTOR_KEYS)
    for field in ("challenge_id", "nonce"):
        _random_token(vectors[field])
    for field in ("answer", "wrong_answer"):
        _base64url(vectors[field])
    for field in ("binding_hex", "token_hex", "active_key_hex", "old_key_hex"):
        _hex(vectors[field])
    for field in ("active_key_id", "old_key_id"):
        _string(vectors[field])

    material = vectors["private_material"]
    _exact_object(material, MATERIAL_KEYS)
    _random_token(material["challenge_id"])
    _random_token(material["nonce"])
    for field in ("generator_version", "mac_key_id"):
        _string(material[field])
    for field in ("issued_at", "expires_at"):
        _integer(material[field])
    _hex(material["answer_mac"])
    if len(material["answer_mac"]) != 64 or material["answer_encoding"] != "base64url":
        raise FixtureError()
    if material["challenge_id"] != vectors["challenge_id"] or material["nonce"] != vectors["nonce"]:
        raise FixtureError()
    for field in ("challenge_id", "nonce", "answer", "old_key_id", "old_key_hex"):
        if vectors[field] != KNOWN_VECTOR[field]:
            raise FixtureError()
    for field in ("generator_version", "issued_at", "expires_at", "answer_mac"):
        if material[field] != KNOWN_VECTOR[field]:
            raise FixtureError()
    if material["mac_key_id"] != vectors["old_key_id"]:
        raise FixtureError()

    allowlist = vectors["observer_allowlist"]
    if not isinstance(allowlist, list) or any(not isinstance(field, str) for field in allowlist):
        raise FixtureError()
    if set(allowlist) != OBSERVER_FIELDS:
        raise FixtureError()


def _validate_submission(submission, operation):
    if operation == "close":
        if submission is not None:
            raise FixtureError()
        return
    _exact_object(submission, SUBMISSION_KEYS)
    _random_token(submission["challenge_id"])
    _random_token(submission["nonce"])
    _base64url(submission["answer"])


def _validate_lifecycle(lifecycle):
    _exact_object(lifecycle, LIFECYCLE_KEYS)
    if not isinstance(lifecycle["begin_status"], str) or not isinstance(lifecycle["finish_status"], str):
        raise FixtureError()
    if lifecycle["begin_status"] not in BEGIN_STATUSES:
        raise FixtureError()
    if lifecycle["finish_status"] not in FINISH_STATUSES:
        raise FixtureError()
    if lifecycle["material"] not in {"primary", "none"}:
        raise FixtureError()
    if lifecycle["token"] not in {"default", "empty", "none"}:
        raise FixtureError()
    if type(lifecycle["replay"]) is not bool or type(lifecycle["callback_exception"]) is not bool:
        raise FixtureError()


def _validate_keys(keys):
    _exact_object(keys, KEYS_KEYS)
    if not isinstance(keys["status"], str) or not isinstance(keys["key_id"], str):
        raise FixtureError()
    if keys["status"] not in KEY_STATUSES or keys["key_id"] not in {"active", "old", "none"}:
        raise FixtureError()
    if type(keys["callback_exception"]) is not bool:
        raise FixtureError()


def _validate_outcome(outcome):
    if outcome is None:
        return
    if not isinstance(outcome, dict) or not isinstance(outcome.get("status"), str):
        raise FixtureError()
    if outcome["status"] not in {"accepted", "rejected"}:
        raise FixtureError()
    if outcome["status"] == "accepted":
        _exact_object(outcome, {"status"})
    else:
        _exact_object(outcome, {"status", "reason"})
        if outcome["reason"] not in REJECTION_REASONS:
            raise FixtureError()


def _validate_case(case, status_by_value):
    _exact_object(case, CASE_KEYS)
    _string(case["id"])
    if re.fullmatch(r"[a-z][a-z0-9_]*", case["id"]) is None:
        raise FixtureError()
    if case["operation"] not in OPERATIONS:
        raise FixtureError()
    _validate_submission(case["submission"], case["operation"])
    _hex(case["binding_hex"], allow_empty=case["operation"] == "close")
    _validate_lifecycle(case["lifecycle"])
    _validate_keys(case["keys"])
    _integer(case["expected_status"])
    _string(case["expected_code"])
    if status_by_value.get(case["expected_status"]) != case["expected_code"]:
        raise FixtureError()
    _validate_outcome(case["expected_outcome"])
    trace = case["expected_trace"]
    if not isinstance(trace, list) or any(not isinstance(item, str) for item in trace):
        raise FixtureError()
    if any(item not in TRACE_VALUES for item in trace):
        raise FixtureError()
    _integer(case["expected_release_count"])
    if not 0 <= case["expected_release_count"] <= 0xFFFFFFFF:
        raise FixtureError()
    sentinels = case["forbidden_sentinels"]
    if not isinstance(sentinels, list) or not sentinels or any(not isinstance(item, str) or not item for item in sentinels):
        raise FixtureError()
    if case["expected_release_count"] != sum(
        item.startswith("release:") for item in trace
    ):
        raise FixtureError()

    if case["lifecycle"]["begin_status"] == "exception":
        if (case["expected_status"], case["expected_code"]) != (7, "internal_error"):
            raise FixtureError()
    if case["lifecycle"]["finish_status"] == "internal":
        if (case["expected_status"], case["expected_code"]) != (7, "internal_error"):
            raise FixtureError()
        if "observe:service_failed" not in trace:
            raise FixtureError()
    if case["lifecycle"]["begin_status"] == "ok" and case["lifecycle"]["material"] == "primary":
        release_prefix = ["release:token", "release:material"]
        try:
            token_index = trace.index(release_prefix[0])
            material_index = trace.index(release_prefix[1])
        except ValueError:
            raise FixtureError()
        if material_index != token_index + 1:
            raise FixtureError()
        later_callbacks = [
            index
            for index, item in enumerate(trace)
            if item.startswith("key_by_id:") or item.startswith("finish_attempt:")
        ]
        if later_callbacks and material_index >= min(later_callbacks):
            raise FixtureError()


def validate(manifest):
    _exact_object(manifest, TOP_KEYS)
    _integer(manifest["fixture_version"])
    if manifest["fixture_version"] != 1:
        raise FixtureError()
    _validate_statuses(manifest["statuses"])
    _validate_vectors(manifest["vectors"])
    cases = manifest["cases"]
    if not isinstance(cases, list):
        raise FixtureError()
    status_by_value = {value: code for value, code in STATUS_DEFINITIONS.values()}
    ids = []
    for case in cases:
        _validate_case(case, status_by_value)
        ids.append(case["id"])
    if len(ids) != len(set(ids)) or not REQUIRED_CASE_IDS.issubset(ids):
        raise FixtureError()


def _json(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _c_string(value):
    if value is None:
        return "NULL"
    encoded = _json(value if isinstance(value, str) else _json(value))
    return encoded


def _c_bytes(name, encoded):
    values = ", ".join("0x%02x" % byte for byte in bytes.fromhex(encoded))
    return "static const uint8_t %s[] = {%s};" % (name, values)


def render(manifest):
    vectors = manifest["vectors"]
    vector_storage = "\n".join(
        [
            _c_bytes("AG_BINDING_FIXTURE_BINDING", vectors["binding_hex"]),
            _c_bytes("AG_BINDING_FIXTURE_TOKEN", vectors["token_hex"]),
            _c_bytes("AG_BINDING_FIXTURE_ACTIVE_KEY", vectors["active_key_hex"]),
            _c_bytes("AG_BINDING_FIXTURE_OLD_KEY", vectors["old_key_hex"]),
        ]
    )
    rows = []
    for case in sorted(manifest["cases"], key=lambda item: item["id"]):
        fields = [
            _c_string(case["id"]),
            _c_string(case["operation"]),
            _c_string(case["submission"]),
            _c_string(case["binding_hex"]),
            _c_string(case["lifecycle"]),
            _c_string(case["keys"]),
            "INT32_C(%d)" % case["expected_status"],
            _c_string(case["expected_code"]),
            _c_string(case["expected_outcome"]),
            _c_string(case["expected_trace"]),
            "UINT32_C(%d)" % case["expected_release_count"],
            _c_string(case["forbidden_sentinels"]),
        ]
        rows.append("    {\n        %s\n    }," % ",\n        ".join(fields))
    return """/* Generated by bindings/c/tools/generate_fixtures.py. */
#ifndef AGENTGATE_GENERATED_FIXTURES_H
#define AGENTGATE_GENERATED_FIXTURES_H

#include <stddef.h>
#include <stdint.h>

typedef struct ag_binding_fixture_case {
    const char *id;
    const char *operation;
    const char *submission_json;
    const char *binding_hex;
    const char *lifecycle_json;
    const char *keys_json;
    int32_t expected_status;
    const char *expected_code;
    const char *expected_outcome_json;
    const char *expected_trace_json;
    uint32_t expected_release_count;
    const char *forbidden_sentinels_json;
} ag_binding_fixture_case;

typedef struct ag_binding_fixture_vectors {
    const char *challenge_id;
    const char *nonce;
    const char *answer;
    const char *wrong_answer;
    const uint8_t *binding;
    size_t binding_len;
    const uint8_t *token;
    size_t token_len;
    const char *active_key_id;
    const uint8_t *active_key;
    size_t active_key_len;
    const char *old_key_id;
    const uint8_t *old_key;
    size_t old_key_len;
    const char *private_material_json;
    const char *observer_allowlist_json;
} ag_binding_fixture_vectors;

%s

static const ag_binding_fixture_vectors AG_BINDING_FIXTURE_VECTORS = {
    %s,
    %s,
    %s,
    %s,
    AG_BINDING_FIXTURE_BINDING,
    sizeof(AG_BINDING_FIXTURE_BINDING),
    AG_BINDING_FIXTURE_TOKEN,
    sizeof(AG_BINDING_FIXTURE_TOKEN),
    %s,
    AG_BINDING_FIXTURE_ACTIVE_KEY,
    sizeof(AG_BINDING_FIXTURE_ACTIVE_KEY),
    %s,
    AG_BINDING_FIXTURE_OLD_KEY,
    sizeof(AG_BINDING_FIXTURE_OLD_KEY),
    %s,
    %s,
};

static const ag_binding_fixture_case AG_BINDING_FIXTURE_CASES[] = {
%s
};

#define AG_BINDING_FIXTURE_CASE_COUNT \\
    (sizeof(AG_BINDING_FIXTURE_CASES) / sizeof(AG_BINDING_FIXTURE_CASES[0]))

#endif /* AGENTGATE_GENERATED_FIXTURES_H */
""" % (
        vector_storage,
        _c_string(vectors["challenge_id"]),
        _c_string(vectors["nonce"]),
        _c_string(vectors["answer"]),
        _c_string(vectors["wrong_answer"]),
        _c_string(vectors["active_key_id"]),
        _c_string(vectors["old_key_id"]),
        _c_string(vectors["private_material"]),
        _c_string(vectors["observer_allowlist"]),
        "\n".join(rows),
    )


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        manifest = json.loads(
            args.input.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
        validate(manifest)
        generated = render(manifest)
    except (FixtureError, OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        sys.stderr.write("invalid binding fixture\n")
        return 2

    if args.check:
        try:
            current = args.output.read_bytes()
        except (OSError, UnicodeError):
            current = None
        if current != generated.encode("utf-8"):
            sys.stderr.write("generated binding fixtures are stale\n")
            return 1
        return 0

    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(generated.encode("utf-8"))
    except OSError:
        sys.stderr.write("unable to write generated binding fixtures\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
