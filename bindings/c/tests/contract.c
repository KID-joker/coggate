#include "harness.h"
#include "generated_fixtures.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK_OR_CLEANUP(condition)                                            \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "contract check failed at line %d\n", __LINE__); \
            goto cleanup;                                                      \
        }                                                                      \
    } while (0)

static const ag_binding_fixture_case *accepted_case(void) {
    size_t index;
    for (index = 0; index < AG_BINDING_FIXTURE_CASE_COUNT; ++index) {
        if (strcmp(AG_BINDING_FIXTURE_CASES[index].id, "accepted") == 0) {
            return &AG_BINDING_FIXTURE_CASES[index];
        }
    }
    return NULL;
}

static int issue_contract(void) {
    ag_test_harness harness;
    ag_owned_buffer public_out = {0};
    char public_id[AG_TEST_TEXT_CAPACITY];
    char private_id[AG_TEST_TEXT_CAPACITY];
    char public_version[AG_TEST_TEXT_CAPACITY];
    char private_version[AG_TEST_TEXT_CAPACITY];
    char public_nonce[AG_TEST_TEXT_CAPACITY];
    char private_nonce[AG_TEST_TEXT_CAPACITY];
    ag_status status;
    int result = EXIT_FAILURE;

    ag_test_harness_init(&harness);
    CHECK_OR_CLEANUP(ag_test_harness_create(&harness) == AG_STATUS_OK);
    status = ag_service_issue(
        harness.service,
        ag_test_slice_string("1.0"),
        ag_test_slice(AG_BINDING_FIXTURE_VECTORS.binding,
                      AG_BINDING_FIXTURE_VECTORS.binding_len),
        AG_ATTEMPT_LIMIT_ONE,
        &public_out);
    CHECK_OR_CLEANUP(status == AG_STATUS_OK);
    CHECK_OR_CLEANUP(ag_test_trace_before(&harness, AG_TEST_ACTIVE_KEY,
                                          AG_TEST_STORE_ISSUED));
    CHECK_OR_CLEANUP(
        ag_test_trace_contains(&harness, AG_TEST_OBSERVE_CHALLENGE_ISSUED));
    CHECK_OR_CLEANUP(harness.active_key_id_output.release_calls == 1);
    CHECK_OR_CLEANUP(harness.active_key_output.release_calls == 1);
    CHECK_OR_CLEANUP(harness.release_mismatches == 0);
    CHECK_OR_CLEANUP(ag_test_json_string(
        public_out.data, public_out.len, "challenge_id", public_id,
        sizeof(public_id)));
    CHECK_OR_CLEANUP(ag_test_json_string(harness.stored_private,
                              harness.stored_private_len, "challenge_id",
                              private_id, sizeof(private_id)));
    CHECK_OR_CLEANUP(strcmp(public_id, private_id) == 0);
    CHECK_OR_CLEANUP(ag_test_json_string(public_out.data, public_out.len,
                              "generator_version", public_version,
                              sizeof(public_version)));
    CHECK_OR_CLEANUP(ag_test_json_string(harness.stored_private,
                              harness.stored_private_len,
                              "generator_version", private_version,
                              sizeof(private_version)));
    CHECK_OR_CLEANUP(strcmp(public_version, private_version) == 0);
    CHECK_OR_CLEANUP(ag_test_json_string(public_out.data, public_out.len, "nonce",
                              public_nonce, sizeof(public_nonce)));
    CHECK_OR_CLEANUP(ag_test_json_string(harness.stored_private,
                              harness.stored_private_len, "nonce",
                              private_nonce, sizeof(private_nonce)));
    CHECK_OR_CLEANUP(strcmp(public_nonce, private_nonce) == 0);
    CHECK_OR_CLEANUP(ag_test_json_i64_equal(public_out.data, public_out.len,
                                 harness.stored_private,
                                 harness.stored_private_len, "issued_at"));
    CHECK_OR_CLEANUP(ag_test_json_i64_equal(public_out.data, public_out.len,
                                 harness.stored_private,
                                 harness.stored_private_len, "expires_at"));
    CHECK_OR_CLEANUP(ag_test_json_string(public_out.data, public_out.len,
                              "answer_encoding", public_version,
                              sizeof(public_version)));
    CHECK_OR_CLEANUP(ag_test_json_string(harness.stored_private,
                              harness.stored_private_len, "answer_encoding",
                              private_version, sizeof(private_version)));
    CHECK_OR_CLEANUP(strcmp(public_version, private_version) == 0);
    CHECK_OR_CLEANUP(ag_buffer_free(&public_out) == AG_STATUS_OK);
    CHECK_OR_CLEANUP(public_out.data == NULL && public_out.len == 0 &&
          public_out.capacity == 0);
    CHECK_OR_CLEANUP(ag_test_harness_destroy(&harness) == AG_STATUS_OK);
    result = EXIT_SUCCESS;

cleanup:
    if (public_out.data != NULL) {
        (void)ag_buffer_free(&public_out);
    }
    if (harness.service != NULL) {
        (void)ag_test_harness_destroy(&harness);
    }
    return result;
}

static int accepted_verify_contract(void) {
    static const char expected_trace_json[] =
        "[\"begin_attempt\",\"release:token\",\"release:material\","
        "\"key_by_id:old\",\"release:key\",\"finish_attempt:accepted\","
        "\"observe:verification_completed\"]";
    static const ag_test_event expected[] = {
        AG_TEST_BEGIN_ATTEMPT,
        AG_TEST_RELEASE_TOKEN,
        AG_TEST_RELEASE_MATERIAL,
        AG_TEST_KEY_BY_ID,
        AG_TEST_RELEASE_KEY,
        AG_TEST_FINISH_ACCEPTED,
        AG_TEST_OBSERVE_VERIFICATION_COMPLETED,
    };
    const ag_binding_fixture_case *fixture = accepted_case();
    ag_test_harness harness;
    ag_owned_buffer outcome = {0};
    ag_status status;
    int result = EXIT_FAILURE;

    ag_test_harness_init(&harness);
    CHECK_OR_CLEANUP(fixture != NULL);
    ag_test_harness_prepare_verify(
        &harness, AG_BINDING_FIXTURE_VECTORS.private_material_json,
        AG_BINDING_FIXTURE_VECTORS.token,
        AG_BINDING_FIXTURE_VECTORS.token_len,
        AG_BINDING_FIXTURE_VECTORS.old_key_id,
        AG_BINDING_FIXTURE_VECTORS.old_key,
        AG_BINDING_FIXTURE_VECTORS.old_key_len);
    CHECK_OR_CLEANUP(ag_test_harness_create(&harness) == AG_STATUS_OK);

    status = ag_service_verify(
        harness.service, ag_test_slice_string(fixture->submission_json),
        ag_test_slice(AG_BINDING_FIXTURE_VECTORS.binding,
                      AG_BINDING_FIXTURE_VECTORS.binding_len),
        &outcome);
    CHECK_OR_CLEANUP(status == fixture->expected_status);
    CHECK_OR_CLEANUP(outcome.len == strlen(fixture->expected_outcome_json));
    CHECK_OR_CLEANUP(memcmp(outcome.data, fixture->expected_outcome_json, outcome.len) ==
          0);
    CHECK_OR_CLEANUP(ag_test_trace_equals(&harness, expected,
                               sizeof(expected) / sizeof(expected[0])));
    CHECK_OR_CLEANUP(strcmp(fixture->expected_trace_json, expected_trace_json) == 0);
    CHECK_OR_CLEANUP(harness.material_output.release_calls == 1);
    CHECK_OR_CLEANUP(harness.token_output.release_calls == 1);
    CHECK_OR_CLEANUP(harness.lookup_key_output.release_calls == 1);
    CHECK_OR_CLEANUP(harness.material_output.release_calls +
              harness.token_output.release_calls +
              harness.lookup_key_output.release_calls ==
          fixture->expected_release_count);
    CHECK_OR_CLEANUP(harness.release_mismatches == 0);
    CHECK_OR_CLEANUP(harness.finish_outcome == AG_ATTEMPT_OUTCOME_ACCEPTED);
    CHECK_OR_CLEANUP(harness.requested_key_id_len ==
          strlen(AG_BINDING_FIXTURE_VECTORS.old_key_id));
    CHECK_OR_CLEANUP(memcmp(harness.requested_key_id,
                 AG_BINDING_FIXTURE_VECTORS.old_key_id,
                 harness.requested_key_id_len) == 0);
    CHECK_OR_CLEANUP(ag_buffer_free(&outcome) == AG_STATUS_OK);
    CHECK_OR_CLEANUP(ag_test_harness_destroy(&harness) == AG_STATUS_OK);
    result = EXIT_SUCCESS;

cleanup:
    if (outcome.data != NULL) {
        (void)ag_buffer_free(&outcome);
    }
    if (harness.service != NULL) {
        (void)ag_test_harness_destroy(&harness);
    }
    return result;
}

int main(void) {
    if (issue_contract() != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    return accepted_verify_contract();
}
