#ifndef COGGATE_GO_NATIVE_BRIDGE_H
#define COGGATE_GO_NATIVE_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && !defined(COGGATE_STATIC)
#define COGGATE_STATIC
#define AG_GO_UNDEF_COGGATE_STATIC
#endif
#include "coggate.h"
#if defined(AG_GO_UNDEF_COGGATE_STATIC)
#undef COGGATE_STATIC
#undef AG_GO_UNDEF_COGGATE_STATIC
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ag_go_layout {
    size_t size;
    size_t offsets[6];
} ag_go_layout;

typedef struct ag_go_callback_statuses {
    int32_t store_issued;
    int32_t begin_attempt;
    int32_t finish_attempt;
    int32_t active_key;
    int32_t key_by_id;
} ag_go_callback_statuses;

typedef enum ag_go_host_release_tag {
    AG_GO_HOST_RELEASE_MATERIAL = 1,
    AG_GO_HOST_RELEASE_TOKEN = 2,
    AG_GO_HOST_RELEASE_ACTIVE_KEY_ID = 3,
    AG_GO_HOST_RELEASE_ACTIVE_KEY = 4,
    AG_GO_HOST_RELEASE_KEY = 5
} ag_go_host_release_tag;

#define AG_GO_EXPORT_COUNT 7

typedef uintptr_t ag_go_symbol;
typedef void *ag_go_module_handle;

typedef struct ag_go_loader_vtable {
    void *context;
    ag_go_module_handle (*load_library)(void *context, const uint16_t *path,
                                        uint32_t load_flags);
    ag_go_symbol (*lookup_symbol)(void *context, ag_go_module_handle module,
                                  const char *name);
    void (*unload_library)(void *context, ag_go_module_handle module);
    uint32_t (*abi_version)(void *context, ag_go_symbol symbol);
} ag_go_loader_vtable;

typedef struct ag_go_resolved_exports {
    ag_go_symbol symbols[AG_GO_EXPORT_COUNT];
} ag_go_resolved_exports;

typedef struct ag_go_resolver_test_result {
    int32_t status;
    uint32_t loads;
    uint32_t lookups;
    uint32_t abi_calls;
    uint32_t unloads;
    int retained;
} ag_go_resolver_test_result;

ag_go_layout ag_go_layout_byte_slice(void);
ag_go_layout ag_go_layout_owned_buffer(void);
ag_go_layout ag_go_layout_host_buffer(void);
ag_go_layout ag_go_layout_callback_header(void);
ag_go_layout ag_go_layout_lifecycle_callbacks(void);
ag_go_layout ag_go_layout_key_callbacks(void);
ag_go_layout ag_go_layout_observer_callbacks(void);

uint32_t COGGATE_CALL ag_go_abi_version(void);
ag_byte_slice COGGATE_CALL ag_go_core_version(void);
ag_status COGGATE_CALL ag_go_service_create(const ag_lifecycle_callbacks *lifecycle,
                                       const ag_key_callbacks *keys,
                                       const ag_observer_callbacks *observer,
                                       ag_service **out);
ag_status COGGATE_CALL ag_go_service_destroy(ag_service *service);
ag_status COGGATE_CALL ag_go_service_issue(ag_service *service, ag_byte_slice version,
                                      ag_byte_slice binding, ag_attempt_limit attempt_limit,
                                      ag_owned_buffer *out);
ag_status COGGATE_CALL ag_go_service_verify(ag_service *service, ag_byte_slice submission_json,
                                       ag_byte_slice binding, ag_owned_buffer *out);
ag_status COGGATE_CALL ag_go_buffer_free(ag_owned_buffer *buffer);

ag_lifecycle_callbacks ag_go_make_lifecycle_callbacks(uintptr_t user_data);
ag_key_callbacks ag_go_make_key_callbacks(uintptr_t user_data);
ag_observer_callbacks ag_go_make_observer_callbacks(uintptr_t user_data);

int ag_go_host_buffer_assign(ag_host_buffer *out, const uint8_t *data, size_t len, int present,
                             uintptr_t handle, ag_go_host_release_tag tag);
void ag_go_host_buffer_discard(ag_host_buffer *buffer);
int ag_go_test_host_buffer_oversized_assign(void);
void ag_go_host_allocation_counters_reset(void);
size_t ag_go_host_allocation_count(void);
size_t ag_go_host_release_count(void);
ag_go_callback_statuses ag_go_test_invalid_handle_callbacks(void);
ag_status ag_go_resolve_exports(const ag_go_loader_vtable *loader,
                                const uint16_t *path,
                                uint32_t load_flags,
                                ag_go_resolved_exports *exports_out,
                                ag_go_module_handle *module_out);
ag_go_resolver_test_result ag_go_test_resolve_exports(int missing_library,
                                                       int missing_symbol,
                                                       uint32_t abi_version);

#if defined(_WIN32)
#include <windows.h>

typedef struct ag_go_windows_loader_vtable {
    HMODULE (WINAPI *load_library)(LPCWSTR, HANDLE, DWORD);
    FARPROC (WINAPI *lookup_symbol)(HMODULE, LPCSTR);
    BOOL (WINAPI *unload_library)(HMODULE);
} ag_go_windows_loader_vtable;

typedef struct ag_go_native_exports ag_go_native_exports;
ag_status ag_go_windows_resolve_exports(const ag_go_windows_loader_vtable *loader,
                                        const uint16_t *path,
                                        DWORD load_flags,
                                        ag_go_native_exports *exports_out,
                                        HMODULE *module_out);
ag_status ag_go_windows_init(const uint16_t *path, int include_dll_directory);
#endif

#ifdef __cplusplus
}
#endif

#endif
