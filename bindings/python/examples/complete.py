#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "bindings" / "python" / "src"))

from agentgate import (  # noqa: E402
    ActiveKeyResult,
    BeginAttemptResult,
    IssueRequest,
    KeyResult,
    Service,
    Submission,
)
from agentgate import _ffi  # noqa: E402


FIXTURE = json.loads(
    (ROOT / "fixtures" / "bindings" / "v1.json").read_text(encoding="utf-8")
)
VECTORS = FIXTURE["vectors"]
ACCEPTED = next(case for case in FIXTURE["cases"] if case["id"] == "accepted")


class Lifecycle:
    def __init__(self):
        self.finish_calls = 0

    def store_issued(self, private_json, binding, attempt_limit):
        del private_json, binding, attempt_limit
        return _ffi.AG_LIFECYCLE_STATUS_OK

    def begin_attempt(self, identity_json, binding, server_time):
        del identity_json, server_time
        if binding != bytes.fromhex(VECTORS["binding_hex"]):
            return BeginAttemptResult(_ffi.AG_BEGIN_STATUS_BINDING_MISMATCH)
        material = json.dumps(
            VECTORS["private_material"], separators=(",", ":")
        ).encode("utf-8")
        return BeginAttemptResult(
            _ffi.AG_BEGIN_STATUS_OK,
            material,
            bytes.fromhex(VECTORS["token_hex"]),
        )

    def finish_attempt(self, token, outcome):
        self.finish_calls += 1
        valid = (
            token == bytes.fromhex(VECTORS["token_hex"])
            and outcome == _ffi.AG_ATTEMPT_OUTCOME_ACCEPTED
        )
        return (
            _ffi.AG_LIFECYCLE_STATUS_OK
            if valid
            else _ffi.AG_LIFECYCLE_STATUS_INTERNAL
        )


class Keys:
    def __init__(self):
        self.lookup_calls = 0

    def active_key(self):
        return ActiveKeyResult(
            _ffi.AG_KEY_STATUS_OK,
            VECTORS["active_key_id"],
            bytes.fromhex(VECTORS["active_key_hex"]),
        )

    def key_by_id(self, key_id):
        self.lookup_calls += 1
        if key_id != VECTORS["old_key_id"]:
            return KeyResult(_ffi.AG_KEY_STATUS_NOT_FOUND)
        return KeyResult(_ffi.AG_KEY_STATUS_OK, bytes.fromhex(VECTORS["old_key_hex"]))


class Observer:
    def observe(self, event_json):
        json.loads(event_json)


def main():
    configured = os.environ.get("AGENTGATE_LIBRARY_PATH")
    library = Path(configured) if configured else ROOT / "target" / "release" / (
        "agentgate_ffi.dll" if sys.platform == "win32" else
        "libagentgate_ffi.dylib" if sys.platform == "darwin" else
        "libagentgate_ffi.so"
    )
    lifecycle = Lifecycle()
    keys = Keys()
    binding = bytes.fromhex(VECTORS["binding_hex"])
    with Service(lifecycle, keys, Observer(), library_path=library) as service:
        challenge = service.issue(IssueRequest.v1(binding))
        submission = Submission.from_json(
            json.dumps(ACCEPTED["submission"], separators=(",", ":"))
        )
        outcome = service.verify(submission, binding)
    expected = json.dumps(ACCEPTED["expected_outcome"], separators=(",", ":"))
    return 0 if challenge.challenge_id and outcome.to_json() == expected and lifecycle.finish_calls == 1 and keys.lookup_calls == 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
