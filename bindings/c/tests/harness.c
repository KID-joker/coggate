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

static void COGGATE_CALL release_output(void *release_data, uint8_t *data,
                                   size_t len) {
    ag_test_host_output *output = (ag_test_host_output *)release_data;
    bool noncanonical_empty;
    if (output == NULL || output->owner == NULL) {
        return;
    }
    noncanonical_empty =
        output->release_event == AG_TEST_RELEASE_TOKEN &&
        output->owner->begin_output_behavior ==
            AG_TEST_BEGIN_OUTPUT_NONCANONICAL_EMPTY_TOKEN;
    if (output->release_calls != 0 ||
        data != (noncanonical_empty ? NULL : output->bytes) ||
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

static ag_lifecycle_status COGGATE_CALL
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

static ag_begin_status COGGATE_CALL
begin_attempt(void *user_data, ag_byte_slice identity_json,
              ag_byte_slice binding, int64_t server_time,
              ag_host_buffer *material_out, ag_host_buffer *token_out) {
    ag_test_harness *harness = (ag_test_harness *)user_data;
    (void)server_time;
    if (harness->begin_exception) {
        trace(harness, AG_TEST_BEGIN_EXCEPTION);
        return AG_BEGIN_STATUS_INTERNAL;
    }
    trace(harness, AG_TEST_BEGIN_ATTEMPT);
    if (harness->begin_status != AG_BEGIN_STATUS_OK) {
        if (harness->begin_output_behavior ==
            AG_TEST_BEGIN_OUTPUT_WRITE_ON_FAILURE) {
            (void)finish_output(&harness->material_output,
                                harness->verify_material,
                                harness->verify_material_len, material_out);
            (void)finish_output(&harness->token_output, harness->verify_token,
                                harness->verify_token_len, token_out);
        }
        return harness->begin_status;
    }
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
    if (harness->begin_output_behavior ==
        AG_TEST_BEGIN_OUTPUT_MALFORMED_TOKEN) {
        token_out->data = NULL;
        token_out->len = 1;
        token_out->release_data = NULL;
        token_out->release = NULL;
    } else if (harness->begin_output_behavior ==
               AG_TEST_BEGIN_OUTPUT_NONCANONICAL_EMPTY_TOKEN) {
        token_out->data = NULL;
        token_out->len = 0;
        harness->token_output.len = 0;
    }
    return AG_BEGIN_STATUS_OK;
}

static ag_lifecycle_status COGGATE_CALL finish_attempt(void *user_data,
                                                   ag_byte_slice token,
                                                   ag_attempt_outcome outcome) {
    ag_test_harness *harness = (ag_test_harness *)user_data;
    harness->finish_calls++;
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
    return harness->finish_status;
}

static ag_key_status COGGATE_CALL active_key(void *user_data,
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
    harness->active_key_calls++;
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

static ag_key_status COGGATE_CALL key_by_id(void *user_data, ag_byte_slice key_id,
                                       ag_host_buffer *key_out) {
    ag_test_harness *harness = (ag_test_harness *)user_data;
    harness->key_by_id_calls++;
    trace(harness, AG_TEST_KEY_BY_ID);
    if (!copy_bytes(harness->requested_key_id,
                    sizeof(harness->requested_key_id),
                    &harness->requested_key_id_len, key_id.data, key_id.len)) {
        return AG_KEY_STATUS_INVALID_MATERIAL;
    }
    if (harness->key_callback_exception) {
        return AG_KEY_STATUS_INVALID_MATERIAL;
    }
    if (harness->key_status != AG_KEY_STATUS_OK) {
        return harness->key_status;
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

static void COGGATE_CALL observe(void *user_data, ag_byte_slice event_json) {
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
    harness->begin_status = AG_BEGIN_STATUS_OK;
    harness->finish_status = AG_LIFECYCLE_STATUS_OK;
    harness->key_status = AG_KEY_STATUS_OK;
    harness->observer_enabled = true;
    init_output(&harness->active_key_id_output, harness,
                AG_TEST_RELEASE_ACTIVE_KEY_ID);
    init_output(&harness->active_key_output, harness,
                AG_TEST_RELEASE_ACTIVE_KEY);
    init_output(&harness->material_output, harness, AG_TEST_RELEASE_MATERIAL);
    init_output(&harness->token_output, harness, AG_TEST_RELEASE_TOKEN);
    init_output(&harness->lookup_key_output, harness, AG_TEST_RELEASE_KEY);
}

static bool bounded_text_length(const char *text, size_t capacity,
                                size_t *length_out) {
    size_t length;
    if (text == NULL || length_out == NULL) {
        return false;
    }
    for (length = 0; length < capacity; ++length) {
        if (text[length] == '\0') {
            *length_out = length;
            return true;
        }
    }
    return false;
}

bool ag_test_harness_prepare_verify(ag_test_harness *harness,
                                    const char *private_material_json,
                                    const uint8_t *token, size_t token_len,
                                    const char *key_id, const uint8_t *key,
                                    size_t key_len) {
    size_t material_len;
    size_t key_id_len;
    if (harness == NULL) {
        return false;
    }
    harness->trace_len = 0;
    harness->verify_material_len = 0;
    harness->verify_token_len = 0;
    harness->verify_key_id[0] = '\0';
    harness->verify_key_len = 0;
    if (!bounded_text_length(private_material_json,
                             sizeof(harness->verify_material),
                             &material_len) ||
        material_len == 0 ||
        !bounded_text_length(key_id, sizeof(harness->verify_key_id),
                             &key_id_len) ||
        key_id_len == 0 || token_len > sizeof(harness->verify_token) ||
        (token == NULL && token_len != 0) ||
        key_len > sizeof(harness->verify_key) ||
        (key == NULL && key_len != 0) || key_len == 0 ||
        !copy_bytes(harness->verify_material,
                    sizeof(harness->verify_material),
                    &harness->verify_material_len, private_material_json,
                    material_len) ||
        !copy_bytes(harness->verify_token, sizeof(harness->verify_token),
                    &harness->verify_token_len, token, token_len) ||
        !copy_bytes(harness->verify_key, sizeof(harness->verify_key),
                    &harness->verify_key_len, key, key_len)) {
        harness->verify_material_len = 0;
        harness->verify_token_len = 0;
        harness->verify_key_id[0] = '\0';
        harness->verify_key_len = 0;
        return false;
    }
    memcpy(harness->verify_key_id, key_id, key_id_len);
    harness->verify_key_id[key_id_len] = '\0';
    return true;
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
    status = ag_service_create(
        &harness->lifecycle, &harness->keys,
        harness->observer_enabled ? &harness->observer : NULL,
        &harness->service);
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
        trace(harness, AG_TEST_SERVICE_DESTROY);
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

static bool fixture_string(const char *json, const char *field, char *out,
                           size_t out_capacity) {
    size_t json_len;
    return bounded_text_length(json, AG_TEST_JSON_CAPACITY, &json_len) &&
           ag_test_json_string((const uint8_t *)json, json_len, field, out,
                               out_capacity);
}

static bool fixture_bool(const char *json, const char *field, bool *out) {
    char true_pattern[AG_TEST_TEXT_CAPACITY];
    char false_pattern[AG_TEST_TEXT_CAPACITY];
    int true_written;
    int false_written;
    bool has_true;
    bool has_false;
    if (json == NULL || field == NULL || out == NULL) {
        return false;
    }
    true_written = snprintf(true_pattern, sizeof(true_pattern),
                            "\"%s\":true", field);
    false_written = snprintf(false_pattern, sizeof(false_pattern),
                             "\"%s\":false", field);
    if (true_written < 0 || false_written < 0 ||
        (size_t)true_written >= sizeof(true_pattern) ||
        (size_t)false_written >= sizeof(false_pattern)) {
        return false;
    }
    has_true = strstr(json, true_pattern) != NULL;
    has_false = strstr(json, false_pattern) != NULL;
    if (has_true == has_false) {
        return false;
    }
    *out = has_true;
    return true;
}

static bool map_begin_status(const char *name, ag_begin_status *status,
                             bool *exception, bool *unused) {
    *exception = false;
    *unused = false;
    if (strcmp(name, "ok") == 0) *status = AG_BEGIN_STATUS_OK;
    else if (strcmp(name, "internal") == 0) *status = AG_BEGIN_STATUS_INTERNAL;
    else if (strcmp(name, "exception") == 0) {
        *status = AG_BEGIN_STATUS_INTERNAL;
        *exception = true;
    } else if (strcmp(name, "not_found") == 0) *status = AG_BEGIN_STATUS_NOT_FOUND;
    else if (strcmp(name, "expired") == 0) *status = AG_BEGIN_STATUS_EXPIRED;
    else if (strcmp(name, "already_consumed") == 0) *status = AG_BEGIN_STATUS_ALREADY_CONSUMED;
    else if (strcmp(name, "binding_mismatch") == 0) *status = AG_BEGIN_STATUS_BINDING_MISMATCH;
    else if (strcmp(name, "nonce_mismatch") == 0) *status = AG_BEGIN_STATUS_NONCE_MISMATCH;
    else if (strcmp(name, "attempts_exhausted") == 0) *status = AG_BEGIN_STATUS_ATTEMPTS_EXHAUSTED;
    else if (strcmp(name, "unused") == 0) {
        *status = AG_BEGIN_STATUS_OK;
        *unused = true;
    } else return false;
    return true;
}

static bool map_key_status(const char *name, ag_key_status *status,
                           bool *unused) {
    *unused = false;
    if (strcmp(name, "ok") == 0) *status = AG_KEY_STATUS_OK;
    else if (strcmp(name, "unavailable") == 0) *status = AG_KEY_STATUS_UNAVAILABLE;
    else if (strcmp(name, "not_found") == 0) *status = AG_KEY_STATUS_NOT_FOUND;
    else if (strcmp(name, "invalid_material") == 0) *status = AG_KEY_STATUS_INVALID_MATERIAL;
    else if (strcmp(name, "unused") == 0) {
        *status = AG_KEY_STATUS_OK;
        *unused = true;
    } else return false;
    return true;
}

static bool configure_fixture(ag_test_harness *harness,
                              const ag_binding_fixture_case *fixture,
                              const ag_binding_fixture_vectors *vectors,
                              const uint8_t **binding, size_t *binding_len,
                              bool *replay) {
    char begin[AG_TEST_TEXT_CAPACITY];
    char finish[AG_TEST_TEXT_CAPACITY];
    char material[AG_TEST_TEXT_CAPACITY];
    char token_name[AG_TEST_TEXT_CAPACITY];
    char key_status_name[AG_TEST_TEXT_CAPACITY];
    char key_id[AG_TEST_TEXT_CAPACITY];
    bool lifecycle_exception;
    bool key_exception;
    bool begin_unused;
    bool key_unused;
    bool close;
    const uint8_t *token;
    size_t token_len;
    const char *verify_key_id;
    const uint8_t *verify_key;
    size_t verify_key_len;
    size_t sentinel_len;

    if (!fixture_string(fixture->lifecycle_json, "begin_status", begin,
                        sizeof(begin)) ||
        !fixture_string(fixture->lifecycle_json, "finish_status", finish,
                        sizeof(finish)) ||
        !fixture_string(fixture->lifecycle_json, "material", material,
                        sizeof(material)) ||
        !fixture_string(fixture->lifecycle_json, "token", token_name,
                        sizeof(token_name)) ||
        !fixture_bool(fixture->lifecycle_json, "replay", replay) ||
        !fixture_bool(fixture->lifecycle_json, "callback_exception",
                      &lifecycle_exception) ||
        !fixture_string(fixture->keys_json, "status", key_status_name,
                        sizeof(key_status_name)) ||
        !fixture_string(fixture->keys_json, "key_id", key_id,
                        sizeof(key_id)) ||
        !fixture_bool(fixture->keys_json, "callback_exception",
                      &key_exception) ||
        !map_begin_status(begin, &harness->begin_status,
                          &harness->begin_exception, &begin_unused) ||
        !map_key_status(key_status_name, &harness->key_status, &key_unused) ||
        !bounded_text_length(fixture->forbidden_sentinels_json,
                             AG_TEST_JSON_CAPACITY, &sentinel_len) ||
        sentinel_len > AG_TEST_BYTES_CAPACITY) {
        return false;
    }
    close = strcmp(fixture->operation, "close") == 0;
    if (!close && strcmp(fixture->operation, "verify") != 0 &&
        strcmp(fixture->operation, "observe") != 0 &&
        strcmp(fixture->operation, "release") != 0) {
        return false;
    }
    if (begin_unused != close || harness->begin_exception != lifecycle_exception) {
        return false;
    }
    if (strcmp(finish, "ok") == 0) {
        harness->finish_status = AG_LIFECYCLE_STATUS_OK;
    } else if (strcmp(finish, "internal") == 0) {
        harness->finish_status = AG_LIFECYCLE_STATUS_INTERNAL;
    } else if (strcmp(finish, "unused") == 0) {
        if (!close && harness->begin_status == AG_BEGIN_STATUS_OK) return false;
        harness->finish_status = AG_LIFECYCLE_STATUS_OK;
    } else return false;

    if (close) {
        if (strcmp(material, "none") != 0 || strcmp(token_name, "none") != 0 ||
            *replay || !key_unused || strcmp(key_id, "none") != 0 ||
            lifecycle_exception || key_exception) return false;
    } else if (harness->begin_status == AG_BEGIN_STATUS_OK) {
        if (strcmp(material, "primary") != 0 ||
            (strcmp(token_name, "default") != 0 &&
             strcmp(token_name, "empty") != 0) || *replay ||
            (key_exception ? !key_unused : key_unused) ||
            strcmp(key_id, "none") == 0) return false;
    } else {
        if (strcmp(material, "none") != 0 || strcmp(token_name, "none") != 0 ||
            (!*replay && strcmp(begin, "already_consumed") == 0 &&
             strcmp(fixture->id, "lifecycle_already_consumed") != 0) ||
            (*replay && strcmp(begin, "already_consumed") != 0) ||
            !key_unused || strcmp(key_id, "none") != 0 || key_exception)
            return false;
    }

    harness->key_callback_exception = key_exception;
    if (key_exception) harness->key_status = AG_KEY_STATUS_INVALID_MATERIAL;
    if (close || strcmp(key_id, "old") == 0 || strcmp(key_id, "none") == 0) {
        verify_key_id = vectors->old_key_id;
        verify_key = vectors->old_key;
        verify_key_len = vectors->old_key_len;
    } else if (strcmp(key_id, "active") == 0) {
        verify_key_id = vectors->active_key_id;
        verify_key = vectors->active_key;
        verify_key_len = vectors->active_key_len;
    } else return false;

    token = vectors->token;
    token_len = vectors->token_len;
    if (!close && strcmp(token_name, "empty") == 0) {
        token = NULL;
        token_len = 0;
    } else if (harness->begin_status == AG_BEGIN_STATUS_OK) {
        token = (const uint8_t *)fixture->forbidden_sentinels_json;
        token_len = sentinel_len;
    }
    *binding = harness->begin_status == AG_BEGIN_STATUS_OK
                   ? vectors->binding
                   : (const uint8_t *)fixture->forbidden_sentinels_json;
    *binding_len = harness->begin_status == AG_BEGIN_STATUS_OK
                       ? vectors->binding_len
                       : sentinel_len;
    return ag_test_harness_prepare_verify(
        harness, vectors->private_material_json, token, token_len,
        verify_key_id, verify_key, verify_key_len);
}

ag_status ag_test_harness_run_fixture(
    ag_test_harness *harness, const ag_binding_fixture_case *fixture,
    const ag_binding_fixture_vectors *vectors, ag_owned_buffer *out) {
    ag_status status;
    const uint8_t *binding;
    size_t binding_len;
    bool replay;
    if (harness == NULL || fixture == NULL || vectors == NULL || out == NULL) {
        return AG_STATUS_INVALID_ARGUMENT;
    }
    if (!configure_fixture(harness, fixture, vectors, &binding, &binding_len,
                           &replay)) {
        return AG_STATUS_INVALID_ARGUMENT;
    }
    harness->observer_enabled = strcmp(fixture->operation, "verify") == 0 ||
                                strcmp(fixture->operation, "observe") == 0;
    status = ag_test_harness_create(harness);
    if (status != AG_STATUS_OK) {
        return status;
    }
    if (strcmp(fixture->operation, "close") == 0) {
        char submission[AG_TEST_JSON_CAPACITY];
        ag_owned_buffer used = {0};
        int written = snprintf(
            submission, sizeof(submission),
            "{\"answer\":\"%s\",\"challenge_id\":\"%s\",\"nonce\":\"%s\"}",
            vectors->answer, vectors->challenge_id, vectors->nonce);
        if (written < 0 || (size_t)written >= sizeof(submission)) {
            return AG_STATUS_INTERNAL_ERROR;
        }
        status = ag_service_verify(
            harness->service, ag_test_slice_string(submission),
            ag_test_slice(binding, binding_len), &used);
        if (status != AG_STATUS_OK || used.data == NULL ||
            ag_buffer_free(&used) != AG_STATUS_OK) {
            return status == AG_STATUS_OK ? AG_STATUS_INTERNAL_ERROR : status;
        }
        harness->trace_len = 0;
        harness->release_mismatches = 0;
        harness->material_output.release_calls = 0;
        harness->token_output.release_calls = 0;
        harness->lookup_key_output.release_calls = 0;
        harness->observed_event_len = 0;
        return ag_test_harness_destroy(harness);
    }
    if (replay) {
        ag_owned_buffer first = {0};
        harness->begin_status = AG_BEGIN_STATUS_OK;
        status = ag_service_verify(
            harness->service, ag_test_slice_string(fixture->submission_json),
            ag_test_slice(binding, binding_len), &first);
        if (status != AG_STATUS_OK || first.data == NULL ||
            ag_buffer_free(&first) != AG_STATUS_OK) {
            return status == AG_STATUS_OK ? AG_STATUS_INTERNAL_ERROR : status;
        }
        harness->trace_len = 0;
        harness->release_mismatches = 0;
        harness->material_output.release_calls = 0;
        harness->token_output.release_calls = 0;
        harness->lookup_key_output.release_calls = 0;
        harness->observed_event_len = 0;
        harness->begin_status = AG_BEGIN_STATUS_ALREADY_CONSUMED;
    }
    return ag_service_verify(
        harness->service, ag_test_slice_string(fixture->submission_json),
        ag_test_slice(binding, binding_len), out);
}

static const char *event_name(ag_test_event event) {
    switch (event) {
    case AG_TEST_ACTIVE_KEY: return "active_key";
    case AG_TEST_RELEASE_ACTIVE_KEY: return "release:active_key";
    case AG_TEST_RELEASE_ACTIVE_KEY_ID: return "release:active_key_id";
    case AG_TEST_STORE_ISSUED: return "store_issued";
    case AG_TEST_BEGIN_ATTEMPT: return "begin_attempt";
    case AG_TEST_BEGIN_EXCEPTION: return "begin_attempt:exception";
    case AG_TEST_RELEASE_TOKEN: return "release:token";
    case AG_TEST_RELEASE_MATERIAL: return "release:material";
    case AG_TEST_KEY_BY_ID: return "key_by_id:old";
    case AG_TEST_RELEASE_KEY: return "release:key";
    case AG_TEST_FINISH_ACCEPTED: return "finish_attempt:accepted";
    case AG_TEST_FINISH_REJECTED: return "finish_attempt:rejected";
    case AG_TEST_FINISH_SYSTEM_FAILURE: return "finish_attempt:system_failure";
    case AG_TEST_OBSERVE_CHALLENGE_ISSUED: return "observe:challenge_issued";
    case AG_TEST_OBSERVE_VERIFICATION_COMPLETED:
        return "observe:verification_completed";
    case AG_TEST_OBSERVE_SERVICE_FAILED: return "observe:service_failed";
    case AG_TEST_SERVICE_DESTROY: return "service_destroy";
    default: return NULL;
    }
}

bool ag_test_trace_matches_json(const ag_test_harness *harness,
                                const char *expected_json) {
    char actual[AG_TEST_JSON_CAPACITY];
    size_t used = 0;
    size_t index;
    int written;
    if (harness == NULL || expected_json == NULL) {
        return false;
    }
    actual[used++] = '[';
    for (index = 0; index < harness->trace_len; ++index) {
        const char *name = event_name(harness->trace[index]);
        if (name == NULL) {
            return false;
        }
        written = snprintf(actual + used, sizeof(actual) - used,
                           "%s\"%s\"", index == 0 ? "" : ",", name);
        if (written < 0 || (size_t)written >= sizeof(actual) - used) {
            return false;
        }
        used += (size_t)written;
    }
    if (used + 2 > sizeof(actual)) {
        return false;
    }
    actual[used++] = ']';
    actual[used] = '\0';
    return strcmp(actual, expected_json) == 0;
}

size_t ag_test_release_count(const ag_test_harness *harness) {
    return harness->material_output.release_calls +
           harness->token_output.release_calls +
           harness->lookup_key_output.release_calls;
}

static bool list_has_quoted(const char *list, const uint8_t *value,
                            size_t value_len) {
    const char *cursor = list;
    while ((cursor = strchr(cursor, '"')) != NULL) {
        const char *end = strchr(cursor + 1, '"');
        if (end == NULL) {
            return false;
        }
        if ((size_t)(end - cursor - 1) == value_len &&
            memcmp(cursor + 1, value, value_len) == 0) {
            return true;
        }
        cursor = end + 1;
    }
    return false;
}

bool ag_test_observer_is_allowlisted(const ag_test_harness *harness,
                                     const char *allowlist_json) {
    static const char service_failed_allowlist[] =
        "[\"event\",\"challenge_id\",\"generator_version\",\"stage\","
        "\"error\",\"attempts\",\"duration_us\"]";
    char event[AG_TEST_TEXT_CAPACITY];
    const uint8_t *cursor;
    const uint8_t *limit;
    if (harness == NULL || allowlist_json == NULL) {
        return false;
    }
    if (harness->observed_event_len == 0) {
        return true;
    }
    if (!ag_test_json_string(harness->observed_event,
                             harness->observed_event_len, "event", event,
                             sizeof(event))) {
        return false;
    }
    if (strcmp(event, "service_failed") == 0) {
        allowlist_json = service_failed_allowlist;
    }
    cursor = harness->observed_event;
    limit = cursor + harness->observed_event_len;
    while (cursor < limit) {
        const uint8_t *key;
        const uint8_t *end;
        while (cursor < limit && *cursor != '"') {
            cursor++;
        }
        if (cursor == limit) {
            break;
        }
        key = ++cursor;
        while (cursor < limit && *cursor != '"') {
            cursor++;
        }
        if (cursor == limit) {
            return false;
        }
        end = cursor++;
        while (cursor < limit && (*cursor == ' ' || *cursor == '\t' ||
                                  *cursor == '\r' || *cursor == '\n')) {
            cursor++;
        }
        if (cursor < limit && *cursor == ':' &&
            !list_has_quoted(allowlist_json, key, (size_t)(end - key))) {
            return false;
        }
    }
    return true;
}

static bool bytes_contain(const uint8_t *bytes, size_t bytes_len,
                          const uint8_t *needle, size_t needle_len) {
    size_t index;
    if (needle_len == 0 || needle_len > bytes_len || bytes == NULL) {
        return false;
    }
    for (index = 0; index <= bytes_len - needle_len; ++index) {
        if (memcmp(bytes + index, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

bool ag_test_forbidden_sentinels_absent(
    const ag_test_harness *harness, const ag_owned_buffer *out,
    const char *sentinels_json) {
    const char *cursor = sentinels_json;
    if (harness == NULL || out == NULL || sentinels_json == NULL) {
        return false;
    }
    while ((cursor = strchr(cursor, '"')) != NULL) {
        const char *end = strchr(cursor + 1, '"');
        size_t len;
        if (end == NULL) {
            return false;
        }
        len = (size_t)(end - cursor - 1);
        if (bytes_contain(out->data, out->len, (const uint8_t *)cursor + 1,
                          len) ||
            bytes_contain(harness->observed_event,
                          harness->observed_event_len,
                          (const uint8_t *)cursor + 1, len)) {
            return false;
        }
        cursor = end + 1;
    }
    return true;
}
