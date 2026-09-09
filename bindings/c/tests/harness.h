#ifndef AGENTGATE_C_TEST_HARNESS_H
#define AGENTGATE_C_TEST_HARNESS_H

#include "agentgate.h"
#include "generated_fixtures.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AG_TEST_TEXT_CAPACITY 256
#define AG_TEST_BYTES_CAPACITY 512
#define AG_TEST_JSON_CAPACITY 8192
#define AG_TEST_TRACE_CAPACITY 64

typedef enum ag_test_event {
    AG_TEST_ACTIVE_KEY,
    AG_TEST_RELEASE_ACTIVE_KEY,
    AG_TEST_RELEASE_ACTIVE_KEY_ID,
    AG_TEST_STORE_ISSUED,
    AG_TEST_BEGIN_ATTEMPT,
    AG_TEST_BEGIN_EXCEPTION,
    AG_TEST_RELEASE_TOKEN,
    AG_TEST_RELEASE_MATERIAL,
    AG_TEST_KEY_BY_ID,
    AG_TEST_RELEASE_KEY,
    AG_TEST_FINISH_ACCEPTED,
    AG_TEST_FINISH_REJECTED,
    AG_TEST_FINISH_SYSTEM_FAILURE,
    AG_TEST_OBSERVE_CHALLENGE_ISSUED,
    AG_TEST_OBSERVE_VERIFICATION_COMPLETED,
    AG_TEST_OBSERVE_SERVICE_FAILED,
    AG_TEST_SERVICE_DESTROY
} ag_test_event;

typedef enum ag_test_begin_output_behavior {
    AG_TEST_BEGIN_OUTPUT_NORMAL,
    AG_TEST_BEGIN_OUTPUT_WRITE_ON_FAILURE,
    AG_TEST_BEGIN_OUTPUT_MALFORMED_TOKEN,
    AG_TEST_BEGIN_OUTPUT_NONCANONICAL_EMPTY_TOKEN
} ag_test_begin_output_behavior;

struct ag_test_harness;

typedef struct ag_test_host_output {
    struct ag_test_harness *owner;
    uint8_t bytes[AG_TEST_JSON_CAPACITY];
    size_t len;
    size_t release_calls;
    ag_test_event release_event;
} ag_test_host_output;

typedef struct ag_test_harness {
    ag_service *service;
    ag_lifecycle_callbacks lifecycle;
    ag_key_callbacks keys;
    ag_observer_callbacks observer;
    ag_test_event trace[AG_TEST_TRACE_CAPACITY];
    size_t trace_len;
    size_t release_mismatches;
    ag_begin_status begin_status;
    bool begin_exception;
    ag_lifecycle_status finish_status;
    ag_key_status key_status;
    bool key_callback_exception;
    ag_test_begin_output_behavior begin_output_behavior;
    bool observer_enabled;
    size_t active_key_calls;
    size_t key_by_id_calls;
    size_t finish_calls;

    uint8_t stored_private[AG_TEST_JSON_CAPACITY];
    size_t stored_private_len;
    uint8_t stored_binding[AG_TEST_BYTES_CAPACITY];
    size_t stored_binding_len;
    ag_attempt_limit stored_attempt_limit;

    uint8_t verify_material[AG_TEST_JSON_CAPACITY];
    size_t verify_material_len;
    uint8_t verify_token[AG_TEST_BYTES_CAPACITY];
    size_t verify_token_len;
    char verify_key_id[AG_TEST_TEXT_CAPACITY];
    uint8_t verify_key[AG_TEST_BYTES_CAPACITY];
    size_t verify_key_len;
    uint8_t requested_key_id[AG_TEST_TEXT_CAPACITY];
    size_t requested_key_id_len;
    ag_attempt_outcome finish_outcome;
    uint8_t observed_event[AG_TEST_JSON_CAPACITY];
    size_t observed_event_len;

    ag_test_host_output active_key_id_output;
    ag_test_host_output active_key_output;
    ag_test_host_output material_output;
    ag_test_host_output token_output;
    ag_test_host_output lookup_key_output;
} ag_test_harness;

void ag_test_harness_init(ag_test_harness *harness);
bool ag_test_harness_prepare_verify(ag_test_harness *harness,
                                    const char *private_material_json,
                                    const uint8_t *token, size_t token_len,
                                    const char *key_id, const uint8_t *key,
                                    size_t key_len);
ag_status ag_test_harness_create(ag_test_harness *harness);
ag_status ag_test_harness_destroy(ag_test_harness *harness);

ag_byte_slice ag_test_slice(const void *data, size_t len);
ag_byte_slice ag_test_slice_string(const char *text);
bool ag_test_trace_contains(const ag_test_harness *harness,
                            ag_test_event event);
bool ag_test_trace_before(const ag_test_harness *harness,
                          ag_test_event first, ag_test_event second);
bool ag_test_trace_equals(const ag_test_harness *harness,
                          const ag_test_event *expected, size_t expected_len);
bool ag_test_json_string(const uint8_t *json, size_t json_len,
                         const char *field, char *out, size_t out_capacity);
bool ag_test_json_i64_equal(const uint8_t *left, size_t left_len,
                            const uint8_t *right, size_t right_len,
                            const char *field);
ag_status ag_test_harness_run_fixture(
    ag_test_harness *harness, const ag_binding_fixture_case *fixture,
    const ag_binding_fixture_vectors *vectors, ag_owned_buffer *out);
bool ag_test_trace_matches_json(const ag_test_harness *harness,
                                const char *expected_json);
size_t ag_test_release_count(const ag_test_harness *harness);
bool ag_test_observer_is_allowlisted(const ag_test_harness *harness,
                                     const char *allowlist_json);
bool ag_test_forbidden_sentinels_absent(
    const ag_test_harness *harness, const ag_owned_buffer *out,
    const char *sentinels_json);

#endif /* AGENTGATE_C_TEST_HARNESS_H */
