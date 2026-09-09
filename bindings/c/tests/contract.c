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

#define CHECK_RETURN(condition)                                                \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "contract check failed at line %d\n", __LINE__); \
            return EXIT_FAILURE;                                               \
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

static const ag_binding_fixture_case *fixture_case(const char *id) {
    size_t index;
    for (index = 0; index < AG_BINDING_FIXTURE_CASE_COUNT; ++index) {
        if (strcmp(AG_BINDING_FIXTURE_CASES[index].id, id) == 0) {
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
    CHECK_OR_CLEANUP(ag_test_harness_prepare_verify(
        &harness, AG_BINDING_FIXTURE_VECTORS.private_material_json,
        AG_BINDING_FIXTURE_VECTORS.token,
        AG_BINDING_FIXTURE_VECTORS.token_len,
        AG_BINDING_FIXTURE_VECTORS.old_key_id,
        AG_BINDING_FIXTURE_VECTORS.old_key,
        AG_BINDING_FIXTURE_VECTORS.old_key_len));
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

static int generated_fixture_contract(
    const ag_binding_fixture_case *fixture) {
    ag_test_harness harness;
    ag_owned_buffer out = {0};
    ag_owned_buffer closed_out = {0};
    ag_status status;
    int result = EXIT_FAILURE;

    ag_test_harness_init(&harness);
    status = ag_test_harness_run_fixture(
        &harness, fixture, &AG_BINDING_FIXTURE_VECTORS, &out);
    CHECK_OR_CLEANUP(status == fixture->expected_status);
    if (fixture->expected_outcome_json == NULL) {
        CHECK_OR_CLEANUP(out.data == NULL && out.len == 0 && out.capacity == 0);
    } else {
        CHECK_OR_CLEANUP(out.data != NULL);
        CHECK_OR_CLEANUP(out.len == strlen(fixture->expected_outcome_json));
        CHECK_OR_CLEANUP(memcmp(out.data, fixture->expected_outcome_json,
                                out.len) == 0);
    }
    CHECK_OR_CLEANUP(ag_test_trace_matches_json(
        &harness, fixture->expected_trace_json));
    CHECK_OR_CLEANUP(ag_test_release_count(&harness) ==
                     fixture->expected_release_count);
    CHECK_OR_CLEANUP(harness.release_mismatches == 0);
    if (strstr(fixture->keys_json, "\"key_id\":\"old\"") != NULL) {
        CHECK_OR_CLEANUP(harness.active_key_calls == 0);
        CHECK_OR_CLEANUP(harness.key_by_id_calls == 1);
        CHECK_OR_CLEANUP(harness.requested_key_id_len ==
                         strlen(AG_BINDING_FIXTURE_VECTORS.old_key_id));
        CHECK_OR_CLEANUP(memcmp(harness.requested_key_id,
                                AG_BINDING_FIXTURE_VECTORS.old_key_id,
                                harness.requested_key_id_len) == 0);
    }
    CHECK_OR_CLEANUP(ag_test_observer_is_allowlisted(
        &harness, AG_BINDING_FIXTURE_VECTORS.observer_allowlist_json));
    CHECK_OR_CLEANUP(ag_test_forbidden_sentinels_absent(
        &harness, &out, fixture->forbidden_sentinels_json));
    if (out.data != NULL) {
        CHECK_OR_CLEANUP(ag_buffer_free(&out) == AG_STATUS_OK);
        CHECK_OR_CLEANUP(out.data == NULL && out.len == 0 &&
                         out.capacity == 0);
    }
    if (harness.service != NULL) {
        CHECK_OR_CLEANUP(ag_test_harness_destroy(&harness) == AG_STATUS_OK);
    } else if (strcmp(fixture->operation, "close") == 0) {
        CHECK_OR_CLEANUP(ag_service_verify(
                             harness.service, ag_test_slice_string("{}"),
                             ag_test_slice(
                                 AG_BINDING_FIXTURE_VECTORS.binding,
                                 AG_BINDING_FIXTURE_VECTORS.binding_len),
                             &closed_out) == AG_STATUS_INVALID_ARGUMENT);
        CHECK_OR_CLEANUP(closed_out.data == NULL && closed_out.len == 0 &&
                         closed_out.capacity == 0);
        CHECK_OR_CLEANUP(ag_test_harness_destroy(&harness) ==
                         AG_STATUS_INVALID_ARGUMENT);
    }
    result = EXIT_SUCCESS;

cleanup:
    if (out.data != NULL) (void)ag_buffer_free(&out);
    if (closed_out.data != NULL) (void)ag_buffer_free(&closed_out);
    if (harness.service != NULL) (void)ag_test_harness_destroy(&harness);
    return result;
}

static int every_generated_fixture_contract(void) {
    size_t index;
    for (index = 0; index < AG_BINDING_FIXTURE_CASE_COUNT; ++index) {
        if (generated_fixture_contract(&AG_BINDING_FIXTURE_CASES[index]) !=
            EXIT_SUCCESS) {
            fprintf(stderr, "fixture failed: %s\n",
                    AG_BINDING_FIXTURE_CASES[index].id);
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

static bool prepare_fault_harness(ag_test_harness *harness,
                                  const char *private_material) {
    ag_test_harness_init(harness);
    if (!ag_test_harness_prepare_verify(
        harness, private_material, AG_BINDING_FIXTURE_VECTORS.token,
        AG_BINDING_FIXTURE_VECTORS.token_len,
        AG_BINDING_FIXTURE_VECTORS.old_key_id,
        AG_BINDING_FIXTURE_VECTORS.old_key,
        AG_BINDING_FIXTURE_VECTORS.old_key_len)) {
        return false;
    }
    harness->observer_enabled = false;
    return true;
}

static ag_status verify_fixture_submission(
    ag_test_harness *harness, const ag_binding_fixture_case *fixture,
    ag_owned_buffer *out) {
    return ag_service_verify(
        harness->service, ag_test_slice_string(fixture->submission_json),
        ag_test_slice(AG_BINDING_FIXTURE_VECTORS.binding,
                      AG_BINDING_FIXTURE_VECTORS.binding_len),
        out);
}

static int callback_fault_scenario(
    size_t scenario, const ag_binding_fixture_case *accepted,
    const ag_binding_fixture_case *rejected) {
    ag_test_harness harness;
    ag_owned_buffer out = {0};
    ag_status status;
    int result = EXIT_FAILURE;

    CHECK_OR_CLEANUP(prepare_fault_harness(
        &harness, AG_BINDING_FIXTURE_VECTORS.private_material_json));
    if (scenario == 0) {
        harness.begin_status = INT32_C(77);
    } else if (scenario == 1) {
        harness.begin_status = AG_BEGIN_STATUS_EXPIRED;
        harness.begin_output_behavior = AG_TEST_BEGIN_OUTPUT_WRITE_ON_FAILURE;
    } else if (scenario == 2) {
        harness.begin_output_behavior = AG_TEST_BEGIN_OUTPUT_MALFORMED_TOKEN;
    } else if (scenario == 3) {
        harness.begin_output_behavior =
            AG_TEST_BEGIN_OUTPUT_NONCANONICAL_EMPTY_TOKEN;
    } else if (scenario <= 6) {
        const ag_binding_fixture_case *fixture =
            scenario == 5 ? rejected : accepted;
        ag_attempt_outcome expected =
            scenario == 4 ? AG_ATTEMPT_OUTCOME_ACCEPTED
                          : (scenario == 5 ? AG_ATTEMPT_OUTCOME_REJECTED
                                           : AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE);
        if (scenario == 6) {
            char *version = strstr((char *)harness.verify_material,
                                   "\"generator_version\":\"1.0\"");
            CHECK_OR_CLEANUP(version != NULL);
            version += strlen("\"generator_version\":\"");
            version[0] = '2';
        }
        harness.finish_status = AG_LIFECYCLE_STATUS_INTERNAL;
        CHECK_OR_CLEANUP(ag_test_harness_create(&harness) == AG_STATUS_OK);
        status = verify_fixture_submission(&harness, fixture, &out);
        CHECK_OR_CLEANUP(status == AG_STATUS_INTERNAL_ERROR);
        CHECK_OR_CLEANUP(out.data == NULL && out.len == 0 &&
                         out.capacity == 0);
        CHECK_OR_CLEANUP(harness.finish_calls == 1);
        CHECK_OR_CLEANUP(harness.finish_outcome == expected);
        CHECK_OR_CLEANUP(harness.release_mismatches == 0);
        CHECK_OR_CLEANUP(ag_test_harness_destroy(&harness) == AG_STATUS_OK);
        result = EXIT_SUCCESS;
        goto cleanup;
    } else {
        goto cleanup;
    }

    CHECK_OR_CLEANUP(ag_test_harness_create(&harness) == AG_STATUS_OK);
    status = verify_fixture_submission(&harness, accepted, &out);
    if (scenario == 0) {
        CHECK_OR_CLEANUP(status == AG_STATUS_CALLBACK_FAILED);
        CHECK_OR_CLEANUP(out.data == NULL && out.len == 0 && out.capacity == 0);
        CHECK_OR_CLEANUP(ag_test_release_count(&harness) == 0);
    } else if (scenario == 1) {
        CHECK_OR_CLEANUP(status == AG_STATUS_OK && out.data != NULL);
        CHECK_OR_CLEANUP(ag_test_release_count(&harness) == 0);
        CHECK_OR_CLEANUP(ag_buffer_free(&out) == AG_STATUS_OK);
        CHECK_OR_CLEANUP(out.data == NULL && out.len == 0 && out.capacity == 0);
    } else {
        CHECK_OR_CLEANUP(status == AG_STATUS_CALLBACK_FAILED);
        CHECK_OR_CLEANUP(out.data == NULL && out.len == 0 && out.capacity == 0);
        CHECK_OR_CLEANUP(ag_test_release_count(&harness) ==
                         (scenario == 2 ? 1u : 2u));
        CHECK_OR_CLEANUP(harness.key_by_id_calls == 0 &&
                         harness.finish_calls == 0);
        CHECK_OR_CLEANUP(harness.release_mismatches == 0);
    }
    CHECK_OR_CLEANUP(ag_test_harness_destroy(&harness) == AG_STATUS_OK);
    result = EXIT_SUCCESS;

cleanup:
    if (out.data != NULL) (void)ag_buffer_free(&out);
    if (harness.service != NULL) (void)ag_test_harness_destroy(&harness);
    return result;
}

static int oversized_sentinel_contract(void) {
    char oversized[AG_TEST_BYTES_CAPACITY + 2];
    ag_binding_fixture_case fixture;
    ag_test_harness harness;
    ag_owned_buffer out = {0};
    size_t index;

    CHECK_RETURN(accepted_case() != NULL);
    fixture = *accepted_case();
    for (index = 0; index < sizeof(oversized) - 1; ++index) {
        oversized[index] = 'S';
    }
    oversized[sizeof(oversized) - 1] = '\0';
    fixture.forbidden_sentinels_json = oversized;
    ag_test_harness_init(&harness);
    CHECK_RETURN(!ag_test_harness_prepare_verify(
        &harness, AG_BINDING_FIXTURE_VECTORS.private_material_json,
        (const uint8_t *)oversized, sizeof(oversized) - 1,
        AG_BINDING_FIXTURE_VECTORS.old_key_id,
        AG_BINDING_FIXTURE_VECTORS.old_key,
        AG_BINDING_FIXTURE_VECTORS.old_key_len));
    CHECK_RETURN(harness.verify_material_len == 0 &&
                 harness.verify_token_len == 0 &&
                 harness.verify_key_id[0] == '\0' &&
                 harness.verify_key_len == 0);
    CHECK_RETURN(ag_test_harness_run_fixture(
                     &harness, &fixture, &AG_BINDING_FIXTURE_VECTORS, &out) ==
                 AG_STATUS_INVALID_ARGUMENT);
    CHECK_RETURN(harness.service == NULL);
    CHECK_RETURN(harness.verify_material_len == 0 &&
                 harness.verify_token_len == 0 &&
                 harness.verify_key_id[0] == '\0' &&
                 harness.verify_key_len == 0);
    CHECK_RETURN(out.data == NULL && out.len == 0 && out.capacity == 0);
    return EXIT_SUCCESS;
}

static int callback_fault_contract(void) {
    const ag_binding_fixture_case *accepted = fixture_case("accepted");
    const ag_binding_fixture_case *rejected = fixture_case("answer_mismatch");
    size_t scenario;

    CHECK_RETURN(accepted != NULL && rejected != NULL);
    for (scenario = 0; scenario < 7; ++scenario) {
        if (callback_fault_scenario(scenario, accepted, rejected) !=
            EXIT_SUCCESS) {
            fprintf(stderr, "callback fault scenario failed: %u\n",
                    (unsigned)scenario);
            return EXIT_FAILURE;
        }
    }
    return oversized_sentinel_contract();
}

int main(void) {
    if (issue_contract() != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    if (accepted_verify_contract() != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    if (callback_fault_contract() != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    return every_generated_fixture_contract();
}
