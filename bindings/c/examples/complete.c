#include "agentgate.h"
#include "../tests/generated_fixtures.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXAMPLE_CAPACITY 8192

typedef struct example_state example_state;

typedef struct example_output {
    example_state *owner;
    uint8_t bytes[EXAMPLE_CAPACITY];
    size_t len;
    size_t release_calls;
} example_output;

struct example_state {
    uint8_t private_json[EXAMPLE_CAPACITY];
    size_t private_json_len;
    uint8_t binding[EXAMPLE_CAPACITY];
    size_t binding_len;
    example_output active_id;
    example_output active_key;
    example_output material;
    example_output token;
    example_output lookup_key;
    size_t release_errors;
};

static ag_byte_slice bytes(const void *data, size_t len) {
    ag_byte_slice slice;
    slice.data = (const uint8_t *)data;
    slice.len = len;
    return slice;
}

static ag_byte_slice text(const char *value) {
    return bytes(value, strlen(value));
}

static int copy(uint8_t *out, size_t *out_len, const void *data, size_t len) {
    if (len > EXAMPLE_CAPACITY || (data == NULL && len != 0)) {
        *out_len = 0;
        return 0;
    }
    if (len != 0) {
        memcpy(out, data, len);
    }
    *out_len = len;
    return 1;
}

static void AG_CALL release_output(void *release_data, uint8_t *data,
                                   size_t len) {
    example_output *output = (example_output *)release_data;
    if (output == NULL || output->owner == NULL) {
        return;
    }
    if (output->release_calls != 0 || data != output->bytes ||
        len != output->len) {
        output->owner->release_errors++;
    }
    output->release_calls++;
}

static int write_output(example_output *storage, const void *data, size_t len,
                        ag_host_buffer *out) {
    if (out == NULL || !copy(storage->bytes, &storage->len, data, len)) {
        return 0;
    }
    out->data = storage->bytes;
    out->len = storage->len;
    out->release_data = storage;
    out->release = release_output;
    return 1;
}

static ag_lifecycle_status AG_CALL
store_issued(void *user_data, ag_byte_slice private_json, ag_byte_slice binding,
             ag_attempt_limit attempt_limit) {
    example_state *state = (example_state *)user_data;
    if (attempt_limit != AG_ATTEMPT_LIMIT_ONE ||
        !copy(state->private_json, &state->private_json_len,
              private_json.data, private_json.len) ||
        !copy(state->binding, &state->binding_len, binding.data,
              binding.len)) {
        return AG_LIFECYCLE_STATUS_INTERNAL;
    }
    return AG_LIFECYCLE_STATUS_OK;
}

static ag_begin_status AG_CALL
begin_attempt(void *user_data, ag_byte_slice identity_json,
              ag_byte_slice binding, int64_t server_time,
              ag_host_buffer *material_out, ag_host_buffer *token_out) {
    example_state *state = (example_state *)user_data;
    (void)identity_json;
    (void)server_time;
    /* This callback demonstrates verification of a previously issued,
       checked-in record. It intentionally does not return the random record
       captured by store_issued in the separate issue demonstration. */
    if (binding.len != AG_BINDING_FIXTURE_VECTORS.binding_len ||
        memcmp(binding.data, AG_BINDING_FIXTURE_VECTORS.binding,
               binding.len) != 0 ||
        !write_output(&state->material,
                      AG_BINDING_FIXTURE_VECTORS.private_material_json,
                      strlen(AG_BINDING_FIXTURE_VECTORS.private_material_json),
                      material_out) ||
        !write_output(&state->token, AG_BINDING_FIXTURE_VECTORS.token,
                      AG_BINDING_FIXTURE_VECTORS.token_len, token_out)) {
        return AG_BEGIN_STATUS_INTERNAL;
    }
    return AG_BEGIN_STATUS_OK;
}

static ag_lifecycle_status AG_CALL finish_attempt(void *user_data,
                                                   ag_byte_slice token,
                                                   ag_attempt_outcome outcome) {
    (void)user_data;
    if (outcome != AG_ATTEMPT_OUTCOME_ACCEPTED ||
        token.len != AG_BINDING_FIXTURE_VECTORS.token_len ||
        memcmp(token.data, AG_BINDING_FIXTURE_VECTORS.token, token.len) != 0) {
        return AG_LIFECYCLE_STATUS_INTERNAL;
    }
    return AG_LIFECYCLE_STATUS_OK;
}

static ag_key_status AG_CALL active_key(void *user_data,
                                        ag_host_buffer *key_id_out,
                                        ag_host_buffer *key_out) {
    example_state *state = (example_state *)user_data;
    if (!write_output(&state->active_id,
                      AG_BINDING_FIXTURE_VECTORS.active_key_id,
                      strlen(AG_BINDING_FIXTURE_VECTORS.active_key_id),
                      key_id_out) ||
        !write_output(&state->active_key,
                      AG_BINDING_FIXTURE_VECTORS.active_key,
                      AG_BINDING_FIXTURE_VECTORS.active_key_len, key_out)) {
        return AG_KEY_STATUS_INVALID_MATERIAL;
    }
    return AG_KEY_STATUS_OK;
}

static ag_key_status AG_CALL key_by_id(void *user_data, ag_byte_slice key_id,
                                       ag_host_buffer *key_out) {
    example_state *state = (example_state *)user_data;
    size_t expected_len = strlen(AG_BINDING_FIXTURE_VECTORS.old_key_id);
    if (key_id.len != expected_len ||
        memcmp(key_id.data, AG_BINDING_FIXTURE_VECTORS.old_key_id,
               expected_len) != 0) {
        return AG_KEY_STATUS_NOT_FOUND;
    }
    if (!write_output(&state->lookup_key, AG_BINDING_FIXTURE_VECTORS.old_key,
                      AG_BINDING_FIXTURE_VECTORS.old_key_len, key_out)) {
        return AG_KEY_STATUS_INVALID_MATERIAL;
    }
    return AG_KEY_STATUS_OK;
}

static void AG_CALL observe(void *user_data, ag_byte_slice event_json) {
    (void)user_data;
    (void)event_json;
}

static const ag_binding_fixture_case *accepted_case(void) {
    size_t index;
    for (index = 0; index < AG_BINDING_FIXTURE_CASE_COUNT; ++index) {
        if (strcmp(AG_BINDING_FIXTURE_CASES[index].id, "accepted") == 0) {
            return &AG_BINDING_FIXTURE_CASES[index];
        }
    }
    return NULL;
}

static int expect_ok(ag_status status, const char *operation) {
    if (status == AG_STATUS_OK) {
        return 1;
    }
    fprintf(stderr, "%s failed with AgentGate status %d\n", operation,
            (int)status);
    return 0;
}

static int print_buffer(const char *label, const ag_owned_buffer *buffer) {
    if (fputs(label, stdout) == EOF ||
        fwrite(buffer->data, 1, buffer->len, stdout) != buffer->len ||
        fputc('\n', stdout) == EOF) {
        fputs("unable to write example output\n", stderr);
        return 0;
    }
    return 1;
}

int main(void) {
    const ag_binding_fixture_case *fixture = accepted_case();
    example_state state;
    ag_lifecycle_callbacks lifecycle;
    ag_key_callbacks keys;
    ag_observer_callbacks observer;
    ag_service *service = NULL;
    ag_owned_buffer public_challenge = {0};
    ag_owned_buffer verification = {0};
    int result = EXIT_FAILURE;

    memset(&state, 0, sizeof(state));
    state.active_id.owner = &state;
    state.active_key.owner = &state;
    state.material.owner = &state;
    state.token.owner = &state;
    state.lookup_key.owner = &state;
    memset(&lifecycle, 0, sizeof(lifecycle));
    lifecycle.struct_size = (uint32_t)sizeof(lifecycle);
    lifecycle.abi_version = AG_ABI_VERSION_1;
    lifecycle.user_data = &state;
    lifecycle.store_issued = store_issued;
    lifecycle.begin_attempt = begin_attempt;
    lifecycle.finish_attempt = finish_attempt;
    memset(&keys, 0, sizeof(keys));
    keys.struct_size = (uint32_t)sizeof(keys);
    keys.abi_version = AG_ABI_VERSION_1;
    keys.user_data = &state;
    keys.active_key = active_key;
    keys.key_by_id = key_by_id;
    memset(&observer, 0, sizeof(observer));
    observer.struct_size = (uint32_t)sizeof(observer);
    observer.abi_version = AG_ABI_VERSION_1;
    observer.user_data = &state;
    observer.observe = observe;

    if (fixture == NULL ||
        !expect_ok(ag_service_create(&lifecycle, &keys, &observer, &service),
                   "create")) {
        return EXIT_FAILURE;
    }
    if (!expect_ok(
            ag_service_issue(service, text("1.0"),
                             bytes(AG_BINDING_FIXTURE_VECTORS.binding,
                                   AG_BINDING_FIXTURE_VECTORS.binding_len),
                             AG_ATTEMPT_LIMIT_ONE, &public_challenge),
            "issue")) {
        goto cleanup;
    }
    if (!print_buffer("random issue demonstration: ", &public_challenge)) {
        goto cleanup;
    }
    if (!expect_ok(ag_buffer_free(&public_challenge), "free issue output")) {
        goto cleanup;
    }

    /* Independent verification demonstration: the application supplies a
       submission for the checked-in, previously issued fixture record. */
    if (!expect_ok(
            ag_service_verify(
                service, text(fixture->submission_json),
                bytes(AG_BINDING_FIXTURE_VECTORS.binding,
                      AG_BINDING_FIXTURE_VECTORS.binding_len),
                &verification),
            "verify")) {
        goto cleanup;
    }
    if (!print_buffer("pre-issued fixture verification: ", &verification)) {
        goto cleanup;
    }
    if (verification.len != strlen(fixture->expected_outcome_json) ||
        memcmp(verification.data, fixture->expected_outcome_json,
               verification.len) != 0 ||
        !expect_ok(ag_buffer_free(&verification), "free verify output") ||
        state.release_errors != 0 || state.material.release_calls != 1 ||
        state.token.release_calls != 1 || state.lookup_key.release_calls != 1) {
        goto cleanup;
    }
    result = EXIT_SUCCESS;

cleanup:
    if (public_challenge.data != NULL) {
        (void)ag_buffer_free(&public_challenge);
    }
    if (verification.data != NULL) {
        (void)ag_buffer_free(&verification);
    }
    if (!expect_ok(ag_service_destroy(service), "destroy")) {
        result = EXIT_FAILURE;
    }
    return result;
}
