import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "fixtures" / "bindings" / "v1.json"
HEADER = ROOT / "bindings" / "c" / "tests" / "generated_fixtures.h"
GENERATOR = ROOT / "bindings" / "c" / "tools" / "generate_fixtures.py"
TOP_LEVEL_KEYS = {"fixture_version", "statuses", "vectors", "cases"}
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
REQUIRED_CASES = {
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


class SharedBindingFixtureContractTests(unittest.TestCase):
    def run_generator(self, source, output, check=False):
        command = [
            sys.executable,
            str(GENERATOR),
            "--input",
            str(source),
            "--output",
            str(output),
        ]
        if check:
            command.append("--check")
        return subprocess.run(command, capture_output=True, text=True)

    def test_generator_validates_checked_in_contract(self):
        completed = self.run_generator(FIXTURE, HEADER, check=True)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        generated = HEADER.read_bytes()
        self.assertNotIn(b"\r\n", generated)
        self.assertIn(b"AG_BINDING_FIXTURE_VECTORS", generated)
        self.assertIn(b"AG_BINDING_FIXTURE_OLD_KEY", generated)
        self.assertIn(
            b"b9cb8fd013b40e31c7bc3a1c33b7e36143ef98d045a924ed09ebd38ff07cec2c",
            generated,
        )
        self.assertIn(
            b'{\\"status\\":\\"rejected\\",\\"reason\\":\\"already_consumed\\"}',
            generated,
        )
        self.assertNotIn(
            b'{\\"reason\\":\\"already_consumed\\",\\"status\\":\\"rejected\\"}',
            generated,
        )

    def test_manifest_has_exact_schema_and_required_scenarios(self):
        manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))

        self.assertEqual(set(manifest), TOP_LEVEL_KEYS)
        self.assertEqual(
            [case["id"] for case in manifest["cases"]],
            sorted(case["id"] for case in manifest["cases"]),
        )
        self.assertEqual(
            {case["id"] for case in manifest["cases"]}, REQUIRED_CASES
        )
        for case in manifest["cases"]:
            self.assertEqual(set(case), CASE_KEYS, case["id"])

    def test_generator_sorts_cases_deterministically(self):
        manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
        manifest["cases"].reverse()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "reversed.json"
            output = Path(directory) / "generated.h"
            source.write_text(json.dumps(manifest), encoding="utf-8")

            completed = self.run_generator(source, output)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(output.read_bytes(), HEADER.read_bytes())

    def test_validator_rejects_malformed_contracts_without_secret_diagnostics(self):
        manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
        mutations = {}

        unknown_top = copy.deepcopy(manifest)
        unknown_top["private_answer"] = "ANSWER_SENTINEL_private_answer"
        mutations["unknown top-level field"] = unknown_top

        unknown_case = copy.deepcopy(manifest)
        unknown_case["cases"][0]["private_answer"] = "ANSWER_SENTINEL_private_answer"
        mutations["unknown case field"] = unknown_case

        duplicate_id = copy.deepcopy(manifest)
        duplicate_id["cases"][1]["id"] = duplicate_id["cases"][0]["id"]
        mutations["duplicate case ID"] = duplicate_id

        invalid_operation = copy.deepcopy(manifest)
        invalid_operation["cases"][0]["operation"] = "execute_secret"
        mutations["invalid operation"] = invalid_operation

        invalid_status = copy.deepcopy(manifest)
        invalid_status["cases"][0]["expected_status"] = 999
        mutations["invalid status"] = invalid_status

        boolean_fixture_version = copy.deepcopy(manifest)
        boolean_fixture_version["fixture_version"] = True
        mutations["boolean fixture version"] = boolean_fixture_version

        oversized_release_count = copy.deepcopy(manifest)
        oversized_release_count["cases"][0]["expected_release_count"] = 2**32
        mutations["oversized release count"] = oversized_release_count

        missing_release_trace = copy.deepcopy(manifest)
        missing_release_trace["cases"][0]["expected_trace"].remove(
            "release:key"
        )
        mutations["release count and trace mismatch"] = missing_release_trace

        missing_observer_trace = copy.deepcopy(manifest)
        missing_observer_trace["cases"][0]["expected_trace"].remove(
            "observe:verification_completed"
        )
        mutations["missing observer expectation"] = missing_observer_trace

        invalid_code = copy.deepcopy(manifest)
        invalid_code["cases"][0]["expected_code"] = "secret_failure"
        mutations["invalid status code"] = invalid_code

        invalid_reason = copy.deepcopy(manifest)
        invalid_reason["cases"][0]["expected_outcome"] = {
            "status": "rejected",
            "reason": "secret_reason",
        }
        mutations["invalid rejection reason"] = invalid_reason

        invalid_hex = copy.deepcopy(manifest)
        invalid_hex["cases"][0]["binding_hex"] = "0g"
        mutations["invalid hex"] = invalid_hex

        invalid_base64url = copy.deepcopy(manifest)
        invalid_base64url["cases"][0]["submission"]["answer"] = "YQ=="
        mutations["invalid base64url"] = invalid_base64url

        invalid_token_alphabet = copy.deepcopy(manifest)
        invalid_token_alphabet["cases"][0]["submission"][
            "challenge_id"
        ] = "not+canonical-token-12"
        mutations["invalid random token alphabet"] = invalid_token_alphabet

        short_random_token = copy.deepcopy(manifest)
        short_random_token["cases"][0]["submission"]["nonce"] = "bm9uY2U"
        mutations["short random token"] = short_random_token

        noncanonical_random_token = copy.deepcopy(manifest)
        noncanonical_random_token["cases"][0]["submission"][
            "challenge_id"
        ] = "Y2hhbGxlbmdlLTEyMzQ1Nn"
        mutations["noncanonical random token"] = noncanonical_random_token

        non_string_begin = copy.deepcopy(manifest)
        non_string_begin["cases"][0]["lifecycle"]["begin_status"] = [
            "ANSWER_SENTINEL"
        ]
        mutations["non-string begin status"] = non_string_begin

        non_string_trace = copy.deepcopy(manifest)
        non_string_trace["cases"][0]["expected_trace"][0] = {
            "ANSWER_SENTINEL": True
        }
        mutations["non-string trace item"] = non_string_trace

        non_string_allowlist = copy.deepcopy(manifest)
        non_string_allowlist["vectors"]["observer_allowlist"][0] = {
            "ANSWER_SENTINEL": True
        }
        mutations["non-string observer field"] = non_string_allowlist

        unsupported_frozen_version = copy.deepcopy(manifest)
        unsupported_frozen_version["vectors"]["private_material"][
            "generator_version"
        ] = "v1"
        mutations["unsupported frozen generator version"] = (
            unsupported_frozen_version
        )

        forged_mac = copy.deepcopy(manifest)
        forged_mac["vectors"]["private_material"]["answer_mac"] = "0" * 64
        mutations["forged known-vector MAC"] = forged_mac

        wrong_exception_mapping = copy.deepcopy(manifest)
        exception_case = next(
            case
            for case in wrong_exception_mapping["cases"]
            if case["id"] == "callback_exception"
        )
        exception_case["expected_status"] = 101
        exception_case["expected_code"] = "callback_failed"
        mutations["wrong callback exception mapping"] = wrong_exception_mapping

        wrong_finish_mapping = copy.deepcopy(manifest)
        finish_failure = next(
            case
            for case in wrong_finish_mapping["cases"]
            if case["id"] == "finish_failure"
        )
        finish_failure["expected_status"] = 101
        finish_failure["expected_code"] = "callback_failed"
        mutations["wrong finish failure mapping"] = wrong_finish_mapping

        missing_service_failed = copy.deepcopy(manifest)
        finish_failure = next(
            case
            for case in missing_service_failed["cases"]
            if case["id"] == "finish_failure"
        )
        finish_failure["expected_trace"].remove("observe:service_failed")
        mutations["missing service failure observation"] = missing_service_failed

        reversed_release = copy.deepcopy(manifest)
        accepted = next(
            case
            for case in reversed_release["cases"]
            if case["id"] == "accepted"
        )
        token_index = accepted["expected_trace"].index("release:token")
        material_index = accepted["expected_trace"].index("release:material")
        accepted["expected_trace"][token_index], accepted["expected_trace"][
            material_index
        ] = (
            accepted["expected_trace"][material_index],
            accepted["expected_trace"][token_index],
        )
        mutations["reversed host buffer release order"] = reversed_release

        late_release = copy.deepcopy(manifest)
        accepted = next(
            case for case in late_release["cases"] if case["id"] == "accepted"
        )
        accepted["expected_trace"] = [
            "begin_attempt",
            "key_by_id:old",
            "finish_attempt:accepted",
            "release:token",
            "release:material",
            "release:key",
            "observe:verification_completed",
        ]
        mutations["release after core callbacks"] = late_release

        invalid_base64url_length = copy.deepcopy(manifest)
        invalid_base64url_length["cases"][0]["submission"]["answer"] = "A"
        mutations["invalid base64url length"] = invalid_base64url_length

        with tempfile.TemporaryDirectory() as directory:
            for index, (label, payload) in enumerate(mutations.items()):
                with self.subTest(label):
                    source = Path(directory) / ("invalid-%d.json" % index)
                    output = Path(directory) / ("invalid-%d.h" % index)
                    source.write_text(json.dumps(payload), encoding="utf-8")

                    completed = self.run_generator(source, output)

                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(completed.stderr, "invalid binding fixture\n")
                    self.assertNotIn("ANSWER_SENTINEL", completed.stderr)
                    self.assertNotIn("private_answer", completed.stderr)
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
