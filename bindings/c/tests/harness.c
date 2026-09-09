#include "harness.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void trace(ag_test_harness *harness, ag_test_event event) {
    if (harness->trace_len < AG_TEST_TRACE_CAPACITY) {
        harness->trace[harness->trace_len++] = event;
    }
}

static bool copy_bytes(uint8_t *destination, size_t capacity,
                       size_t *destination_len, const void *source,
                       size_t source_len) {
    if (source_len > capacity || (source == NULL && source_len != 0)) {
        *destination_len = 0;
        return false;
    }
    if (source_len != 0) {
        memcpy(destination, source, source_len);
    }
    *destination_len = source_len;
    return true;
}

static void init_output(ag_test_host_output *output, ag_test_harness *owner,
                        ag_test_event release_event) {
    output->owner = owner;
    output->len = 0;
    output->release_calls = 0;
    output->release_event = release_event;
}

static bool write_output(ag_test_host_output *storage, const void *bytes,
                         size_t len, ag_host_buffer *out) {
    if (!copy_bytes(storage->bytes, sizeof(storage->bytes), &storage->len,
                    bytes, len)) {
        return false;
    }
    out->data = storage->bytes;
    out->len = storage->len;
    out->release_data = storage;
    out->release = NULL;
    return true;
}

static void AG_CALL release_output(void *release_data, uint8_t *data,
                                   size_t len) {
    ag_test_host_output *output = (ag_test_host_output *)release_data;
    if (output == NULL || output->owner == NULL) {
        return;
    }
    if (output->release_calls != 0 || data != output->bytes ||
        len != output->len) {
        output->owner->release_mismatches++;
    }
    output->release_calls++;
    trace(output->owner, output->release_event);
}

static bool finish_output(ag_test_host_output *storage, const void *bytes,
                          size_t len, ag_host_buffer *out) {
    if (!write_output(storage, bytes, len, out)) {
        return false;
    }
    out->release = release_output;
    return true;
}

static ag_lifecycle_status AG_CALL
store_issued(void *user_data, ag_byte_slice private_json, ag_byte_slice binding,
             ag_attempt_limit attempt_limit) {
    ag_test_harness *harness = (ag_test_harness *)user_data;
    trace(harness, AG_TEST_STORE_ISSUED);
    if (!copy_bytes(harness->stored_private, sizeof(harness->stored_private),
                    &harness->stored_private_len, private_json.data,
                    private_json.len) ||
        !copy_bytes(harness->stored_binding, sizeof(harness->stored_binding),
                    &harness->stored_binding_len, binding.data, binding.len)) {
        return AG_LIFECYCLE_STATUS_INTERNAL;
    }
    harness->stored_attempt_limit = attempt_limit;
    return AG_LIFECYCLE_STATUS_OK;
}

static ag_begin_status AG_CALL
begin_attempt(void *user_data, ag_byte_slice identity_json,
              ag_byte_slice binding, int64_t server_time,
              ag_host_buffer *material_out, ag_host_buffer *token_out) {
    ag_test_harness *harness = (ag_test_harness *)user_data;
    (void)server_time;
    trace(harness, AG_TEST_BEGIN_ATTEMPT);
    if ((identity_json.data == NULL && identity_json.len != 0) ||
        (binding.data == NULL && binding.len != 0) ||
        harness->verify_material_len == 0 || material_out == NULL ||
        token_out == NULL) {
        return AG_BEGIN_STATUS_INTERNAL;
    }
    if (!finish_output(&harness->material_output, harness->verify_material,
                       harness->verify_material_len, material_out) ||
        !finish_output(&harness->token_output, harness->verify_token,
                       harness->verify_token_len, token_out)) {
        return AG_BEGIN_STATUS_INTERNAL;
    }
    return AG_BEGIN_STATUS_OK;
}

static ag_lifecycle_status AG_CALL finish_attempt(void *user_data,
                                                   ag_byte_slice token,
                                                   ag_attempt_outcome outcome) {
    ag_test_harness *harness = (ag_test_harness *)user_data;
    if (token.len != harness->verify_token_len ||
        (token.len != 0 &&
         memcmp(token.data, harness->verify_token, token.len) != 0)) {
        return AG_LIFECYCLE_STATUS_INTERNAL;
    }
    harness->finish_outcome = outcome;
    if (outcome == AG_ATTEMPT_OUTCOME_ACCEPTED) {
        trace(harness, AG_TEST_FINISH_ACCEPTED);
    } else if (outcome == AG_ATTEMPT_OUTCOME_REJECTED) {
        trace(harness, AG_TEST_FINISH_REJECTED);
    } else if (outcome == AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE) {
        trace(harness, AG_TEST_FINISH_SYSTEM_FAILURE);
    } else {
        return AG_LIFECYCLE_STATUS_INTERNAL;
    }
    return AG_LIFECYCLE_STATUS_OK;
}

static ag_key_status AG_CALL active_key(void *user_data,
                                        ag_host_buffer *key_id_out,
                                        ag_host_buffer *key_out) {
    static const char key_id[] = "active-2026-09";
    static const uint8_t key[32] = {
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    };
    ag_test_harness *harness = (ag_test_harness *)user_data;
    trace(harness, AG_TEST_ACTIVE_KEY);
    if (key_id_out == NULL || key_out == NULL ||
        !finish_output(&harness->active_key_id_output, key_id,
                       sizeof(key_id) - 1, key_id_out) ||
        !finish_output(&harness->active_key_output, key, sizeof(key),
                       key_out)) {
        return AG_KEY_STATUS_INVALID_MATERIAL;
    }
    return AG_KEY_STATUS_OK;
}

static ag_key_status AG_CALL key_by_id(void *user_data, ag_byte_slice key_id,
                                       ag_host_buffer *key_out) {
    ag_test_harness *harness = (ag_test_harness *)user_data;
    trace(harness, AG_TEST_KEY_BY_ID);
    if (!copy_bytes(harness->requested_key_id,
                    sizeof(harness->requested_key_id),
                    &harness->requested_key_id_len, key_id.data, key_id.len)) {
        return AG_KEY_STATUS_INVALID_MATERIAL;
    }
    if (key_id.len != strlen(harness->verify_key_id) ||
        memcmp(key_id.data, harness->verify_key_id, key_id.len) != 0) {
        return AG_KEY_STATUS_NOT_FOUND;
    }
    if (key_out == NULL ||
        !finish_output(&harness->lookup_key_output, harness->verify_key,
                       harness->verify_key_len, key_out)) {
        return AG_KEY_STATUS_INVALID_MATERIAL;
    }
    return AG_KEY_STATUS_OK;
}

static void AG_CALL observe(void *user_data, ag_byte_slice event_json) {
    ag_test_harness *harness = (ag_test_harness *)user_data;
    char event[AG_TEST_TEXT_CAPACITY];
    if (!copy_bytes(harness->observed_event, sizeof(harness->observed_event),
                    &harness->observed_event_len, event_json.data,
                    event_json.len)) {
        return;
    }
    if (ag_test_json_string(event_json.data, event_json.len, "event", event,
                            sizeof(event))) {
        if (strcmp(event, "challenge_issued") == 0) {
            trace(harness, AG_TEST_OBSERVE_CHALLENGE_ISSUED);
        } else if (strcmp(event, "verification_completed") == 0) {
            trace(harness, AG_TEST_OBSERVE_VERIFICATION_COMPLETED);
        } else if (strcmp(event, "service_failed") == 0) {
            trace(harness, AG_TEST_OBSERVE_SERVICE_FAILED);
        }
    }
}

void ag_test_harness_init(ag_test_harness *harness) {
    memset(harness, 0, sizeof(*harness));
    init_output(&harness->active_key_id_output, harness,
                AG_TEST_RELEASE_ACTIVE_KEY_ID);
    init_output(&harness->active_key_output, harness,
                AG_TEST_RELEASE_ACTIVE_KEY);
    init_output(&harness->material_output, harness, AG_TEST_RELEASE_MATERIAL);
    init_output(&harness->token_output, harness, AG_TEST_RELEASE_TOKEN);
    init_output(&harness->lookup_key_output, harness, AG_TEST_RELEASE_KEY);
}

void ag_test_harness_prepare_verify(ag_test_harness *harness,
                                    const char *private_material_json,
                                    const uint8_t *token, size_t token_len,
                                    const char *key_id, const uint8_t *key,
                                    size_t key_len) {
    size_t material_len = strlen(private_material_json);
    size_t key_id_len = strlen(key_id);
    harness->trace_len = 0;
    (void)copy_bytes(harness->verify_material,
                     sizeof(harness->verify_material),
                     &harness->verify_material_len, private_material_json,
                     material_len);
    (void)copy_bytes(harness->verify_token, sizeof(harness->verify_token),
                     &harness->verify_token_len, token, token_len);
    if (key_id_len < sizeof(harness->verify_key_id)) {
        memcpy(harness->verify_key_id, key_id, key_id_len + 1);
    }
    (void)copy_bytes(harness->verify_key, sizeof(harness->verify_key),
                     &harness->verify_key_len, key, key_len);
}

ag_status ag_test_harness_create(ag_test_harness *harness) {
    ag_status status;
    harness->lifecycle.struct_size =
        (uint32_t)sizeof(ag_lifecycle_callbacks);
    harness->lifecycle.abi_version = AG_ABI_VERSION_1;
    harness->lifecycle.user_data = harness;
    harness->lifecycle.store_issued = store_issued;
    harness->lifecycle.begin_attempt = begin_attempt;
    harness->lifecycle.finish_attempt = finish_attempt;
    harness->keys.struct_size = (uint32_t)sizeof(ag_key_callbacks);
    harness->keys.abi_version = AG_ABI_VERSION_1;
    harness->keys.user_data = harness;
    harness->keys.active_key = active_key;
    harness->keys.key_by_id = key_by_id;
    harness->observer.struct_size = (uint32_t)sizeof(ag_observer_callbacks);
    harness->observer.abi_version = AG_ABI_VERSION_1;
    harness->observer.user_data = harness;
    harness->observer.observe = observe;
    status = ag_service_create(&harness->lifecycle, &harness->keys,
                               &harness->observer, &harness->service);
    if (status != AG_STATUS_OK) {
        harness->service = NULL;
    }
    return status;
}

ag_status ag_test_harness_destroy(ag_test_harness *harness) {
    ag_status status;
    if (harness->service == NULL) {
        return AG_STATUS_INVALID_ARGUMENT;
    }
    status = ag_service_destroy(harness->service);
    if (status == AG_STATUS_OK) {
        harness->service = NULL;
    }
    return status;
}

ag_byte_slice ag_test_slice(const void *data, size_t len) {
    ag_byte_slice result;
    result.data = (const uint8_t *)data;
    result.len = len;
    return result;
}

ag_byte_slice ag_test_slice_string(const char *text) {
    return ag_test_slice(text, strlen(text));
}

bool ag_test_trace_contains(const ag_test_harness *harness,
                            ag_test_event event) {
    size_t index;
    for (index = 0; index < harness->trace_len; ++index) {
        if (harness->trace[index] == event) {
            return true;
        }
    }
    return false;
}

bool ag_test_trace_before(const ag_test_harness *harness,
                          ag_test_event first, ag_test_event second) {
    size_t index;
    bool saw_first = false;
    for (index = 0; index < harness->trace_len; ++index) {
        if (harness->trace[index] == first) {
            saw_first = true;
        }
        if (harness->trace[index] == second) {
            return saw_first;
        }
    }
    return false;
}

bool ag_test_trace_equals(const ag_test_harness *harness,
                          const ag_test_event *expected,
                          size_t expected_len) {
    return harness->trace_len == expected_len &&
           memcmp(harness->trace, expected,
                  expected_len * sizeof(expected[0])) == 0;
}

bool ag_test_json_string(const uint8_t *json, size_t json_len,
                         const char *field, char *out, size_t out_capacity) {
    char text[AG_TEST_JSON_CAPACITY + 1];
    char pattern[AG_TEST_TEXT_CAPACITY];
    char *value;
    char *end;
    int written;
    size_t value_len;
    if (json_len > AG_TEST_JSON_CAPACITY || out_capacity == 0) {
        return false;
    }
    memcpy(text, json, json_len);
    text[json_len] = '\0';
    written = snprintf(pattern, sizeof(pattern), "\"%s\":\"", field);
    if (written < 0 || (size_t)written >= sizeof(pattern)) {
        return false;
    }
    value = strstr(text, pattern);
    if (value == NULL) {
        return false;
    }
    value += strlen(pattern);
    end = strchr(value, '"');
    if (end == NULL) {
        return false;
    }
    value_len = (size_t)(end - value);
    if (value_len >= out_capacity) {
        return false;
    }
    memcpy(out, value, value_len);
    out[value_len] = '\0';
    return true;
}

static bool json_i64(const uint8_t *json, size_t json_len, const char *field,
                     int64_t *out) {
    char text[AG_TEST_JSON_CAPACITY + 1];
    char pattern[AG_TEST_TEXT_CAPACITY];
    char *value;
    char *end;
    long long parsed;
    int written;
    if (json_len > AG_TEST_JSON_CAPACITY) {
        return false;
    }
    memcpy(text, json, json_len);
    text[json_len] = '\0';
    written = snprintf(pattern, sizeof(pattern), "\"%s\":", field);
    if (written < 0 || (size_t)written >= sizeof(pattern)) {
        return false;
    }
    value = strstr(text, pattern);
    if (value == NULL) {
        return false;
    }
    value += strlen(pattern);
    errno = 0;
    parsed = strtoll(value, &end, 10);
    if (errno != 0 || end == value) {
        return false;
    }
    *out = (int64_t)parsed;
    return true;
}

bool ag_test_json_i64_equal(const uint8_t *left, size_t left_len,
                            const uint8_t *right, size_t right_len,
                            const char *field) {
    int64_t left_value;
    int64_t right_value;
    return json_i64(left, left_len, field, &left_value) &&
           json_i64(right, right_len, field, &right_value) &&
           left_value == right_value;
}
