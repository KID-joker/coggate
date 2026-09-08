#include "agentgate.h"

#include <stddef.h>
#include <stdint.h>

_Static_assert(AG_ABI_VERSION_1 == UINT32_C(1), "ABI version changed");

_Static_assert(AG_STATUS_OK == INT32_C(0), "status changed");
_Static_assert(AG_STATUS_INVALID_CONFIGURATION == INT32_C(1), "status changed");
_Static_assert(AG_STATUS_GENERATION_FAILED == INT32_C(2), "status changed");
_Static_assert(AG_STATUS_INVALID_CHALLENGE_MATERIAL == INT32_C(3), "status changed");
_Static_assert(AG_STATUS_INVALID_ANSWER_ENCODING == INT32_C(4), "status changed");
_Static_assert(AG_STATUS_ANSWER_MISMATCH == INT32_C(5), "status changed");
_Static_assert(AG_STATUS_UNSUPPORTED_GENERATOR_VERSION == INT32_C(6), "status changed");
_Static_assert(AG_STATUS_INTERNAL_ERROR == INT32_C(7), "status changed");
_Static_assert(AG_STATUS_INVALID_ARGUMENT == INT32_C(100), "status changed");
_Static_assert(AG_STATUS_CALLBACK_FAILED == INT32_C(101), "status changed");
_Static_assert(AG_STATUS_PANIC_CAUGHT == INT32_C(102), "status changed");

_Static_assert(AG_LIFECYCLE_STATUS_OK == INT32_C(0), "lifecycle status changed");
_Static_assert(AG_LIFECYCLE_STATUS_UNAVAILABLE == INT32_C(1), "lifecycle status changed");
_Static_assert(AG_LIFECYCLE_STATUS_CONFLICT == INT32_C(2), "lifecycle status changed");
_Static_assert(AG_LIFECYCLE_STATUS_INTERNAL == INT32_C(3), "lifecycle status changed");

_Static_assert(AG_BEGIN_STATUS_OK == INT32_C(0), "begin status changed");
_Static_assert(AG_BEGIN_STATUS_UNAVAILABLE == INT32_C(1), "begin status changed");
_Static_assert(AG_BEGIN_STATUS_CONFLICT == INT32_C(2), "begin status changed");
_Static_assert(AG_BEGIN_STATUS_INTERNAL == INT32_C(3), "begin status changed");
_Static_assert(AG_BEGIN_STATUS_NOT_FOUND == INT32_C(10), "begin status changed");
_Static_assert(AG_BEGIN_STATUS_EXPIRED == INT32_C(11), "begin status changed");
_Static_assert(AG_BEGIN_STATUS_ALREADY_CONSUMED == INT32_C(12), "begin status changed");
_Static_assert(AG_BEGIN_STATUS_BINDING_MISMATCH == INT32_C(13), "begin status changed");
_Static_assert(AG_BEGIN_STATUS_NONCE_MISMATCH == INT32_C(14), "begin status changed");
_Static_assert(AG_BEGIN_STATUS_ATTEMPTS_EXHAUSTED == INT32_C(15), "begin status changed");

_Static_assert(AG_KEY_STATUS_OK == INT32_C(0), "key status changed");
_Static_assert(AG_KEY_STATUS_UNAVAILABLE == INT32_C(1), "key status changed");
_Static_assert(AG_KEY_STATUS_NOT_FOUND == INT32_C(2), "key status changed");
_Static_assert(AG_KEY_STATUS_INVALID_MATERIAL == INT32_C(3), "key status changed");

_Static_assert(AG_ATTEMPT_OUTCOME_ACCEPTED == INT32_C(1), "attempt outcome changed");
_Static_assert(AG_ATTEMPT_OUTCOME_REJECTED == INT32_C(2), "attempt outcome changed");
_Static_assert(AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE == INT32_C(3), "attempt outcome changed");
_Static_assert(AG_ATTEMPT_LIMIT_ONE == UINT32_C(1), "attempt limit changed");
_Static_assert(AG_ATTEMPT_LIMIT_TWO == UINT32_C(2), "attempt limit changed");

static void AG_CALL release_host(void *user_data, uint8_t *data, size_t len) {
    (void)user_data;
    (void)data;
    (void)len;
}

static int32_t AG_CALL store_issued(
    void *user_data,
    ag_byte_slice private_json,
    ag_byte_slice binding,
    uint32_t attempt_limit
) {
    (void)user_data;
    (void)private_json;
    (void)binding;
    (void)attempt_limit;
    return AG_LIFECYCLE_STATUS_OK;
}

static int32_t AG_CALL begin_attempt(
    void *user_data,
    ag_byte_slice identity_json,
    ag_byte_slice binding,
    int64_t server_time,
    ag_host_buffer *material_out,
    ag_host_buffer *token_out
) {
    (void)user_data;
    (void)identity_json;
    (void)binding;
    (void)server_time;
    (void)material_out;
    (void)token_out;
    return AG_BEGIN_STATUS_NOT_FOUND;
}

static int32_t AG_CALL finish_attempt(
    void *user_data,
    ag_byte_slice token,
    int32_t outcome
) {
    (void)user_data;
    (void)token;
    (void)outcome;
    return AG_LIFECYCLE_STATUS_OK;
}

static int32_t AG_CALL active_key(
    void *user_data,
    ag_host_buffer *key_id_out,
    ag_host_buffer *key_out
) {
    (void)user_data;
    (void)key_id_out;
    (void)key_out;
    return AG_KEY_STATUS_UNAVAILABLE;
}

static int32_t AG_CALL key_by_id(
    void *user_data,
    ag_byte_slice key_id,
    ag_host_buffer *key_out
) {
    (void)user_data;
    (void)key_id;
    (void)key_out;
    return AG_KEY_STATUS_NOT_FOUND;
}

static void AG_CALL observe(void *user_data, ag_byte_slice event_json) {
    (void)user_data;
    (void)event_json;
}

void agentgate_header_smoke(void) {
    ag_byte_slice borrowed = {NULL, 0u};
    ag_owned_buffer owned = {NULL, 0u, 0u};
    ag_host_buffer host = {NULL, 0u, NULL, release_host};
    ag_callback_header header = {
        (uint32_t)sizeof(ag_callback_header),
        AG_ABI_VERSION_1
    };
    ag_lifecycle_callbacks lifecycle = {
        (uint32_t)sizeof(ag_lifecycle_callbacks),
        AG_ABI_VERSION_1,
        NULL,
        store_issued,
        begin_attempt,
        finish_attempt
    };
    ag_key_callbacks keys = {
        (uint32_t)sizeof(ag_key_callbacks),
        AG_ABI_VERSION_1,
        NULL,
        active_key,
        key_by_id
    };
    ag_observer_callbacks observer = {
        (uint32_t)sizeof(ag_observer_callbacks),
        AG_ABI_VERSION_1,
        NULL,
        observe
    };
    ag_service *service = NULL;

    (void)borrowed;
    (void)host;
    (void)header;
    if (0) {
        (void)ag_abi_version();
        (void)ag_core_version();
        (void)ag_service_create(&lifecycle, &keys, &observer, &service);
        (void)ag_service_issue(service, borrowed, borrowed, AG_ATTEMPT_LIMIT_ONE, &owned);
        (void)ag_service_verify(service, borrowed, borrowed, &owned);
        (void)ag_buffer_free(&owned);
        (void)ag_service_destroy(service);
    }
}
