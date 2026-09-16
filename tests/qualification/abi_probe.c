#include <stddef.h>
#include <stdint.h>
#include "agentgate.h"

_Static_assert(sizeof(ag_byte_slice) == 16, "ag_byte_slice size");
_Static_assert(offsetof(ag_byte_slice, len) == 8, "ag_byte_slice.len");
_Static_assert(sizeof(ag_owned_buffer) == 24, "ag_owned_buffer size");
_Static_assert(offsetof(ag_owned_buffer, capacity) == 16, "ag_owned_buffer.capacity");
_Static_assert(sizeof(ag_host_buffer) == 32, "ag_host_buffer size");
_Static_assert(offsetof(ag_host_buffer, release) == 24, "ag_host_buffer.release");
_Static_assert(sizeof(ag_callback_header) == 8, "ag_callback_header size");
_Static_assert(sizeof(ag_lifecycle_callbacks) == 40, "ag_lifecycle_callbacks size");
_Static_assert(sizeof(ag_key_callbacks) == 32, "ag_key_callbacks size");
_Static_assert(sizeof(ag_observer_callbacks) == 24, "ag_observer_callbacks size");

static uint32_t (AG_CALL *const ABI_VERSION)(void) = ag_abi_version;
static ag_byte_slice (AG_CALL *const CORE_VERSION)(void) = ag_core_version;
static ag_status (AG_CALL *const BUFFER_FREE)(ag_owned_buffer *) = ag_buffer_free;
static ag_status (AG_CALL *const SERVICE_CREATE)(
    const ag_lifecycle_callbacks *,
    const ag_key_callbacks *,
    const ag_observer_callbacks *,
    ag_service **
) = ag_service_create;
static ag_status (AG_CALL *const SERVICE_DESTROY)(ag_service *) = ag_service_destroy;
static ag_status (AG_CALL *const SERVICE_ISSUE)(
    ag_service *, ag_byte_slice, ag_byte_slice, ag_attempt_limit, ag_owned_buffer *
) = ag_service_issue;
static ag_status (AG_CALL *const SERVICE_VERIFY)(
    ag_service *, ag_byte_slice, ag_byte_slice, ag_owned_buffer *
) = ag_service_verify;

static volatile int link_all_exports;

int main(void) {
    if (AG_ABI_VERSION_1 != UINT32_C(1)) return 10;
    if (ABI_VERSION() != AG_ABI_VERSION_1) return 11;
    if (link_all_exports) {
        (void)CORE_VERSION();
        (void)BUFFER_FREE(NULL);
        (void)SERVICE_CREATE(NULL, NULL, NULL, NULL);
        (void)SERVICE_DESTROY(NULL);
        (void)SERVICE_ISSUE(
            NULL, (ag_byte_slice){NULL, 0}, (ag_byte_slice){NULL, 0},
            AG_ATTEMPT_LIMIT_ONE, NULL
        );
        (void)SERVICE_VERIFY(
            NULL, (ag_byte_slice){NULL, 0}, (ag_byte_slice){NULL, 0}, NULL
        );
    }
    return 0;
}
