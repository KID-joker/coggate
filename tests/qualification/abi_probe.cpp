#include <cstddef>
#include <cstdint>
#include <type_traits>
#include "coggate.h"

static_assert(std::is_standard_layout_v<ag_owned_buffer>);
static_assert(sizeof(ag_byte_slice) == 16);
static_assert(sizeof(ag_owned_buffer) == 24);
static_assert(sizeof(ag_host_buffer) == 32);
static_assert(sizeof(ag_lifecycle_callbacks) == 40);

using AbiVersion = std::uint32_t (COGGATE_CALL *)(void);
using CoreVersion = ag_byte_slice (COGGATE_CALL *)(void);
using BufferFree = ag_status (COGGATE_CALL *)(ag_owned_buffer *);
using ServiceCreate = ag_status (COGGATE_CALL *)(
    const ag_lifecycle_callbacks *,
    const ag_key_callbacks *,
    const ag_observer_callbacks *,
    ag_service **
);
using ServiceDestroy = ag_status (COGGATE_CALL *)(ag_service *);
using ServiceIssue = ag_status (COGGATE_CALL *)(
    ag_service *, ag_byte_slice, ag_byte_slice, ag_attempt_limit, ag_owned_buffer *
);
using ServiceVerify = ag_status (COGGATE_CALL *)(
    ag_service *, ag_byte_slice, ag_byte_slice, ag_owned_buffer *
);

static AbiVersion const ABI_VERSION = &ag_abi_version;
static CoreVersion const CORE_VERSION = &ag_core_version;
static BufferFree const BUFFER_FREE = &ag_buffer_free;
static ServiceCreate const SERVICE_CREATE = &ag_service_create;
static ServiceDestroy const SERVICE_DESTROY = &ag_service_destroy;
static ServiceIssue const SERVICE_ISSUE = &ag_service_issue;
static ServiceVerify const SERVICE_VERIFY = &ag_service_verify;
static volatile bool link_all_exports = false;

int main() {
  if (link_all_exports) {
    (void)CORE_VERSION();
    (void)BUFFER_FREE(nullptr);
    (void)SERVICE_CREATE(nullptr, nullptr, nullptr, nullptr);
    (void)SERVICE_DESTROY(nullptr);
    (void)SERVICE_ISSUE(
        nullptr, ag_byte_slice{nullptr, 0}, ag_byte_slice{nullptr, 0},
        AG_ATTEMPT_LIMIT_ONE, nullptr
    );
    (void)SERVICE_VERIFY(
        nullptr, ag_byte_slice{nullptr, 0}, ag_byte_slice{nullptr, 0}, nullptr
    );
  }
  return ABI_VERSION() == AG_ABI_VERSION_1 ? 0 : 12;
}
