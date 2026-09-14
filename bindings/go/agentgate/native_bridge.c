#include "native_bridge.h"

#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER) && !defined(__clang__)
#include <windows.h>
typedef volatile LONG64 ag_go_atomic_size;
static void ag_go_counter_increment(ag_go_atomic_size *counter) {
    (void)InterlockedIncrement64(counter);
}
static void ag_go_counter_reset(ag_go_atomic_size *counter) {
    (void)InterlockedExchange64(counter, 0);
}
static size_t ag_go_counter_load(ag_go_atomic_size *counter) {
    return (size_t)InterlockedCompareExchange64(counter, 0, 0);
}
#else
#include <stdatomic.h>
typedef _Atomic size_t ag_go_atomic_size;
static void ag_go_counter_increment(ag_go_atomic_size *counter) {
    (void)atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
}
static void ag_go_counter_reset(ag_go_atomic_size *counter) {
    atomic_store_explicit(counter, 0, memory_order_relaxed);
}
static size_t ag_go_counter_load(ag_go_atomic_size *counter) {
    return atomic_load_explicit(counter, memory_order_relaxed);
}
#endif

#define AG_GO_LAYOUT_2(type, a, b) \
    (ag_go_layout){sizeof(type), {offsetof(type, a), offsetof(type, b), 0, 0, 0, 0}}
#define AG_GO_LAYOUT_3(type, a, b, c) \
    (ag_go_layout){sizeof(type), {offsetof(type, a), offsetof(type, b), offsetof(type, c), 0, 0, 0}}
#define AG_GO_LAYOUT_4(type, a, b, c, d) \
    (ag_go_layout){sizeof(type), {offsetof(type, a), offsetof(type, b), offsetof(type, c), offsetof(type, d), 0, 0}}
#define AG_GO_LAYOUT_5(type, a, b, c, d, e) \
    (ag_go_layout){sizeof(type), {offsetof(type, a), offsetof(type, b), offsetof(type, c), offsetof(type, d), offsetof(type, e), 0}}
#define AG_GO_LAYOUT_6(type, a, b, c, d, e, f) \
    (ag_go_layout){sizeof(type), {offsetof(type, a), offsetof(type, b), offsetof(type, c), offsetof(type, d), offsetof(type, e), offsetof(type, f)}}

ag_go_layout ag_go_layout_byte_slice(void) { return AG_GO_LAYOUT_2(ag_byte_slice, data, len); }
ag_go_layout ag_go_layout_owned_buffer(void) { return AG_GO_LAYOUT_3(ag_owned_buffer, data, len, capacity); }
ag_go_layout ag_go_layout_host_buffer(void) { return AG_GO_LAYOUT_4(ag_host_buffer, data, len, release_data, release); }
ag_go_layout ag_go_layout_callback_header(void) { return AG_GO_LAYOUT_2(ag_callback_header, struct_size, abi_version); }
ag_go_layout ag_go_layout_lifecycle_callbacks(void) { return AG_GO_LAYOUT_6(ag_lifecycle_callbacks, struct_size, abi_version, user_data, store_issued, begin_attempt, finish_attempt); }
ag_go_layout ag_go_layout_key_callbacks(void) { return AG_GO_LAYOUT_5(ag_key_callbacks, struct_size, abi_version, user_data, active_key, key_by_id); }
ag_go_layout ag_go_layout_observer_callbacks(void) { return AG_GO_LAYOUT_4(ag_observer_callbacks, struct_size, abi_version, user_data, observe); }

extern int32_t agGoStoreIssued(uintptr_t, const uint8_t *, size_t, const uint8_t *, size_t, uint32_t);
extern int32_t agGoBeginAttempt(uintptr_t, const uint8_t *, size_t, const uint8_t *, size_t,
                               int64_t, ag_host_buffer *, ag_host_buffer *);
extern int32_t agGoFinishAttempt(uintptr_t, const uint8_t *, size_t, int32_t);
extern int32_t agGoActiveKey(uintptr_t, ag_host_buffer *, ag_host_buffer *);
extern int32_t agGoKeyByID(uintptr_t, const uint8_t *, size_t, ag_host_buffer *);
extern void agGoObserve(uintptr_t, const uint8_t *, size_t);

static ag_lifecycle_status AG_CALL ag_go_store_issued_trampoline(void *user_data,
                                                                 ag_byte_slice private_json,
                                                                 ag_byte_slice binding,
                                                                 ag_attempt_limit attempt_limit) {
    return agGoStoreIssued((uintptr_t)user_data, private_json.data, private_json.len,
                           binding.data, binding.len, attempt_limit);
}

static ag_begin_status AG_CALL ag_go_begin_attempt_trampoline(void *user_data,
                                                               ag_byte_slice identity_json,
                                                               ag_byte_slice binding,
                                                               int64_t server_time,
                                                               ag_host_buffer *material_out,
                                                               ag_host_buffer *token_out) {
    return agGoBeginAttempt((uintptr_t)user_data, identity_json.data, identity_json.len,
                            binding.data, binding.len, server_time, material_out, token_out);
}

static ag_lifecycle_status AG_CALL ag_go_finish_attempt_trampoline(void *user_data,
                                                                    ag_byte_slice token,
                                                                    ag_attempt_outcome outcome) {
    return agGoFinishAttempt((uintptr_t)user_data, token.data, token.len, outcome);
}

static ag_key_status AG_CALL ag_go_active_key_trampoline(void *user_data,
                                                          ag_host_buffer *key_id_out,
                                                          ag_host_buffer *key_out) {
    return agGoActiveKey((uintptr_t)user_data, key_id_out, key_out);
}

static ag_key_status AG_CALL ag_go_key_by_id_trampoline(void *user_data,
                                                         ag_byte_slice key_id,
                                                         ag_host_buffer *key_out) {
    return agGoKeyByID((uintptr_t)user_data, key_id.data, key_id.len, key_out);
}

static void AG_CALL ag_go_observe_trampoline(void *user_data, ag_byte_slice event_json) {
    agGoObserve((uintptr_t)user_data, event_json.data, event_json.len);
}

ag_go_callback_statuses ag_go_test_invalid_handle_callbacks(void) {
    ag_go_callback_statuses statuses;
    ag_host_buffer first = {0};
    ag_host_buffer second = {0};
    ag_byte_slice empty = {0};
    statuses.store_issued = ag_go_store_issued_trampoline(NULL, empty, empty,
                                                          AG_ATTEMPT_LIMIT_ONE);
    statuses.begin_attempt = ag_go_begin_attempt_trampoline(NULL, empty, empty, 0,
                                                             &first, &second);
    statuses.finish_attempt = ag_go_finish_attempt_trampoline(
        NULL, empty, AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE);
    statuses.active_key = ag_go_active_key_trampoline(NULL, &first, &second);
    statuses.key_by_id = ag_go_key_by_id_trampoline(NULL, empty, &first);
    ag_go_observe_trampoline(NULL, empty);
    return statuses;
}

ag_lifecycle_callbacks ag_go_make_lifecycle_callbacks(uintptr_t user_data) {
    ag_lifecycle_callbacks callbacks = {0};
    callbacks.struct_size = (uint32_t)sizeof(callbacks);
    callbacks.abi_version = AG_ABI_VERSION_1;
    callbacks.user_data = (void *)user_data;
    callbacks.store_issued = ag_go_store_issued_trampoline;
    callbacks.begin_attempt = ag_go_begin_attempt_trampoline;
    callbacks.finish_attempt = ag_go_finish_attempt_trampoline;
    return callbacks;
}

ag_key_callbacks ag_go_make_key_callbacks(uintptr_t user_data) {
    ag_key_callbacks callbacks = {0};
    callbacks.struct_size = (uint32_t)sizeof(callbacks);
    callbacks.abi_version = AG_ABI_VERSION_1;
    callbacks.user_data = (void *)user_data;
    callbacks.active_key = ag_go_active_key_trampoline;
    callbacks.key_by_id = ag_go_key_by_id_trampoline;
    return callbacks;
}

ag_observer_callbacks ag_go_make_observer_callbacks(uintptr_t user_data) {
    ag_observer_callbacks callbacks = {0};
    callbacks.struct_size = (uint32_t)sizeof(callbacks);
    callbacks.abi_version = AG_ABI_VERSION_1;
    callbacks.user_data = (void *)user_data;
    callbacks.observe = ag_go_observe_trampoline;
    return callbacks;
}

/* Callback releases can arrive from multiple services, so shared test
 * instrumentation must be atomic even though one service serializes calls. */
static ag_go_atomic_size ag_go_allocations;
static ag_go_atomic_size ag_go_releases;

static void AG_CALL ag_go_host_release(void *release_data, uint8_t *data, size_t len) {
    (void)release_data;
    (void)len;
    free(data);
    ag_go_counter_increment(&ag_go_releases);
}

int ag_go_host_buffer_assign(ag_host_buffer *out, const uint8_t *data, size_t len, int present) {
    uint8_t *copy;
    if (out == NULL) return 0;
    memset(out, 0, sizeof(*out));
    if (!present) return 1;
    if (len != 0 && data == NULL) return 0;
    copy = (uint8_t *)malloc(len == 0 ? 1 : len);
    if (copy == NULL) return 0;
    if (len != 0) memcpy(copy, data, len);
    out->data = copy;
    out->len = len;
    out->release = ag_go_host_release;
    ag_go_counter_increment(&ag_go_allocations);
    return 1;
}

void ag_go_host_buffer_discard(ag_host_buffer *buffer) {
    if (buffer == NULL) return;
    if (buffer->data != NULL && buffer->release != NULL) {
        buffer->release(buffer->release_data, buffer->data, buffer->len);
    }
    memset(buffer, 0, sizeof(*buffer));
}

void ag_go_host_allocation_counters_reset(void) {
    ag_go_counter_reset(&ag_go_allocations);
    ag_go_counter_reset(&ag_go_releases);
}
size_t ag_go_host_allocation_count(void) { return ag_go_counter_load(&ag_go_allocations); }
size_t ag_go_host_release_count(void) { return ag_go_counter_load(&ag_go_releases); }

static const char *ag_go_export_names[AG_GO_EXPORT_COUNT] = {
    "ag_abi_version", "ag_core_version", "ag_service_create", "ag_service_destroy",
    "ag_service_issue", "ag_service_verify", "ag_buffer_free"
};

ag_status ag_go_resolve_exports(const ag_go_loader_vtable *loader,
                                const uint16_t *path,
                                uint32_t load_flags,
                                ag_go_resolved_exports *exports_out,
                                ag_go_module_handle *module_out) {
    ag_go_module_handle module;
    size_t i;
    if (loader == NULL || loader->load_library == NULL || loader->lookup_symbol == NULL ||
        loader->unload_library == NULL || loader->abi_version == NULL || path == NULL ||
        exports_out == NULL || module_out == NULL) {
        return AG_STATUS_INVALID_ARGUMENT;
    }
    memset(exports_out, 0, sizeof(*exports_out));
    *module_out = NULL;
    module = loader->load_library(loader->context, path, load_flags);
    if (module == NULL) return AG_STATUS_INTERNAL_ERROR;
    for (i = 0; i < AG_GO_EXPORT_COUNT; i++) {
        exports_out->symbols[i] = loader->lookup_symbol(loader->context, module,
                                                        ag_go_export_names[i]);
        if (exports_out->symbols[i] == 0) {
            memset(exports_out, 0, sizeof(*exports_out));
            loader->unload_library(loader->context, module);
            return AG_STATUS_INTERNAL_ERROR;
        }
    }
    if (loader->abi_version(loader->context, exports_out->symbols[0]) != AG_ABI_VERSION_1) {
        memset(exports_out, 0, sizeof(*exports_out));
        loader->unload_library(loader->context, module);
        return AG_STATUS_INTERNAL_ERROR;
    }
    *module_out = module;
    return AG_STATUS_OK;
}

typedef struct ag_go_mock_loader {
    int missing_library;
    int missing_symbol;
    uint32_t reported_abi;
    uint32_t loads;
    uint32_t lookups;
    uint32_t abi_calls;
    uint32_t unloads;
} ag_go_mock_loader;

static ag_go_module_handle ag_go_mock_load(void *context, const uint16_t *path,
                                            uint32_t load_flags) {
    ag_go_mock_loader *mock = (ag_go_mock_loader *)context;
    (void)path;
    (void)load_flags;
    mock->loads++;
    return mock->missing_library ? NULL : context;
}

static ag_go_symbol ag_go_mock_lookup(void *context, ag_go_module_handle module,
                                      const char *name) {
    ag_go_mock_loader *mock = (ag_go_mock_loader *)context;
    uint32_t index = mock->lookups++;
    (void)module;
    (void)name;
    if ((int)index == mock->missing_symbol) return 0;
    return (ag_go_symbol)(index + 1);
}

static void ag_go_mock_unload(void *context, ag_go_module_handle module) {
    ag_go_mock_loader *mock = (ag_go_mock_loader *)context;
    (void)module;
    mock->unloads++;
}

static uint32_t ag_go_mock_abi_version(void *context, ag_go_symbol symbol) {
    ag_go_mock_loader *mock = (ag_go_mock_loader *)context;
    (void)symbol;
    mock->abi_calls++;
    return mock->reported_abi;
}

ag_go_resolver_test_result ag_go_test_resolve_exports(int missing_library,
                                                       int missing_symbol,
                                                       uint32_t abi_version) {
    static const uint16_t path[] = {'t', 'e', 's', 't', 0};
    ag_go_mock_loader mock = {missing_library, missing_symbol, abi_version, 0, 0, 0, 0};
    ag_go_loader_vtable loader = {
        &mock, ag_go_mock_load, ag_go_mock_lookup, ag_go_mock_unload,
        ag_go_mock_abi_version
    };
    ag_go_resolved_exports exports;
    ag_go_module_handle module = NULL;
    ag_status status = ag_go_resolve_exports(&loader, path, 0, &exports, &module);
    ag_go_resolver_test_result result = {
        status, mock.loads, mock.lookups, mock.abi_calls, mock.unloads, module != NULL
    };
    return result;
}

#if defined(_WIN32)

typedef uint32_t (AG_CALL *ag_go_abi_version_fn)(void);
typedef ag_byte_slice (AG_CALL *ag_go_core_version_fn)(void);
typedef ag_status (AG_CALL *ag_go_service_create_fn)(const ag_lifecycle_callbacks *, const ag_key_callbacks *, const ag_observer_callbacks *, ag_service **);
typedef ag_status (AG_CALL *ag_go_service_destroy_fn)(ag_service *);
typedef ag_status (AG_CALL *ag_go_service_issue_fn)(ag_service *, ag_byte_slice, ag_byte_slice, ag_attempt_limit, ag_owned_buffer *);
typedef ag_status (AG_CALL *ag_go_service_verify_fn)(ag_service *, ag_byte_slice, ag_byte_slice, ag_owned_buffer *);
typedef ag_status (AG_CALL *ag_go_buffer_free_fn)(ag_owned_buffer *);

struct ag_go_native_exports {
    ag_go_abi_version_fn abi_version;
    ag_go_core_version_fn core_version;
    ag_go_service_create_fn service_create;
    ag_go_service_destroy_fn service_destroy;
    ag_go_service_issue_fn service_issue;
    ag_go_service_verify_fn service_verify;
    ag_go_buffer_free_fn buffer_free;
};

typedef struct ag_go_windows_loader_context {
    const ag_go_windows_loader_vtable *loader;
} ag_go_windows_loader_context;

static ag_go_module_handle ag_go_windows_load_adapter(void *context,
                                                       const uint16_t *path,
                                                       uint32_t load_flags) {
    ag_go_windows_loader_context *windows = (ag_go_windows_loader_context *)context;
    return (ag_go_module_handle)windows->loader->load_library((LPCWSTR)path, NULL,
                                                               (DWORD)load_flags);
}

static ag_go_symbol ag_go_windows_lookup_adapter(void *context,
                                                  ag_go_module_handle module,
                                                  const char *name) {
    ag_go_windows_loader_context *windows = (ag_go_windows_loader_context *)context;
    return (ag_go_symbol)(uintptr_t)windows->loader->lookup_symbol((HMODULE)module, name);
}

static void ag_go_windows_unload_adapter(void *context, ag_go_module_handle module) {
    ag_go_windows_loader_context *windows = (ag_go_windows_loader_context *)context;
    (void)windows->loader->unload_library((HMODULE)module);
}

static uint32_t ag_go_windows_abi_adapter(void *context, ag_go_symbol symbol) {
    ag_go_abi_version_fn abi_version = (ag_go_abi_version_fn)(uintptr_t)symbol;
    (void)context;
    return abi_version();
}

ag_status ag_go_windows_resolve_exports(const ag_go_windows_loader_vtable *loader,
                                        const uint16_t *path,
                                        DWORD load_flags,
                                        ag_go_native_exports *exports_out,
                                        HMODULE *module_out) {
    ag_go_windows_loader_context windows_context;
    ag_go_loader_vtable portable_loader;
    ag_go_resolved_exports resolved;
    ag_go_module_handle module = NULL;
    ag_status status;
    if (loader == NULL || loader->load_library == NULL || loader->lookup_symbol == NULL ||
        loader->unload_library == NULL || path == NULL || exports_out == NULL || module_out == NULL) {
        return AG_STATUS_INVALID_ARGUMENT;
    }
    memset(exports_out, 0, sizeof(*exports_out));
    *module_out = NULL;
    windows_context.loader = loader;
    portable_loader.context = &windows_context;
    portable_loader.load_library = ag_go_windows_load_adapter;
    portable_loader.lookup_symbol = ag_go_windows_lookup_adapter;
    portable_loader.unload_library = ag_go_windows_unload_adapter;
    portable_loader.abi_version = ag_go_windows_abi_adapter;
    status = ag_go_resolve_exports(&portable_loader, path, (uint32_t)load_flags,
                                   &resolved, &module);
    if (status != AG_STATUS_OK) return status;
    exports_out->abi_version = (ag_go_abi_version_fn)(uintptr_t)resolved.symbols[0];
    exports_out->core_version = (ag_go_core_version_fn)(uintptr_t)resolved.symbols[1];
    exports_out->service_create = (ag_go_service_create_fn)(uintptr_t)resolved.symbols[2];
    exports_out->service_destroy = (ag_go_service_destroy_fn)(uintptr_t)resolved.symbols[3];
    exports_out->service_issue = (ag_go_service_issue_fn)(uintptr_t)resolved.symbols[4];
    exports_out->service_verify = (ag_go_service_verify_fn)(uintptr_t)resolved.symbols[5];
    exports_out->buffer_free = (ag_go_buffer_free_fn)(uintptr_t)resolved.symbols[6];
    *module_out = (HMODULE)module;
    return AG_STATUS_OK;
}

static INIT_ONCE ag_go_init_once = INIT_ONCE_STATIC_INIT;
static ag_status ag_go_init_status = AG_STATUS_INTERNAL_ERROR;
static ag_go_native_exports ag_go_exports;
static HMODULE ag_go_module;

typedef struct ag_go_init_context {
    const uint16_t *path;
    DWORD load_flags;
} ag_go_init_context;

static BOOL CALLBACK ag_go_initialize_once(PINIT_ONCE once, PVOID parameter, PVOID *context) {
    ag_go_windows_loader_vtable loader = {LoadLibraryExW, GetProcAddress, FreeLibrary};
    ag_go_init_context *init = (ag_go_init_context *)parameter;
    (void)once;
    (void)context;
    ag_go_init_status = ag_go_windows_resolve_exports(&loader, init->path, init->load_flags,
                                                       &ag_go_exports, &ag_go_module);
    return TRUE;
}

ag_status ag_go_windows_init(const uint16_t *path, int include_dll_directory) {
    DWORD flags = LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;
    ag_go_init_context context;
    if (path == NULL) return AG_STATUS_INVALID_ARGUMENT;
    if (include_dll_directory) flags |= LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR;
    context.path = path;
    context.load_flags = flags;
    if (!InitOnceExecuteOnce(&ag_go_init_once, ag_go_initialize_once, &context, NULL)) {
        return AG_STATUS_INTERNAL_ERROR;
    }
    return ag_go_init_status;
}

uint32_t AG_CALL ag_go_abi_version(void) { return ag_go_exports.abi_version ? ag_go_exports.abi_version() : 0; }
ag_byte_slice AG_CALL ag_go_core_version(void) { ag_byte_slice empty = {0}; return ag_go_exports.core_version ? ag_go_exports.core_version() : empty; }
ag_status AG_CALL ag_go_service_create(const ag_lifecycle_callbacks *a, const ag_key_callbacks *b, const ag_observer_callbacks *c, ag_service **d) { return ag_go_exports.service_create ? ag_go_exports.service_create(a, b, c, d) : AG_STATUS_INTERNAL_ERROR; }
ag_status AG_CALL ag_go_service_destroy(ag_service *a) { return ag_go_exports.service_destroy ? ag_go_exports.service_destroy(a) : AG_STATUS_INTERNAL_ERROR; }
ag_status AG_CALL ag_go_service_issue(ag_service *a, ag_byte_slice b, ag_byte_slice c, ag_attempt_limit d, ag_owned_buffer *e) { return ag_go_exports.service_issue ? ag_go_exports.service_issue(a, b, c, d, e) : AG_STATUS_INTERNAL_ERROR; }
ag_status AG_CALL ag_go_service_verify(ag_service *a, ag_byte_slice b, ag_byte_slice c, ag_owned_buffer *d) { return ag_go_exports.service_verify ? ag_go_exports.service_verify(a, b, c, d) : AG_STATUS_INTERNAL_ERROR; }
ag_status AG_CALL ag_go_buffer_free(ag_owned_buffer *a) { return ag_go_exports.buffer_free ? ag_go_exports.buffer_free(a) : AG_STATUS_INTERNAL_ERROR; }

#else

uint32_t AG_CALL ag_go_abi_version(void) { return ag_abi_version(); }
ag_byte_slice AG_CALL ag_go_core_version(void) { return ag_core_version(); }
ag_status AG_CALL ag_go_service_create(const ag_lifecycle_callbacks *a, const ag_key_callbacks *b, const ag_observer_callbacks *c, ag_service **d) { return ag_service_create(a, b, c, d); }
ag_status AG_CALL ag_go_service_destroy(ag_service *a) { return ag_service_destroy(a); }
ag_status AG_CALL ag_go_service_issue(ag_service *a, ag_byte_slice b, ag_byte_slice c, ag_attempt_limit d, ag_owned_buffer *e) { return ag_service_issue(a, b, c, d, e); }
ag_status AG_CALL ag_go_service_verify(ag_service *a, ag_byte_slice b, ag_byte_slice c, ag_owned_buffer *d) { return ag_service_verify(a, b, c, d); }
ag_status AG_CALL ag_go_buffer_free(ag_owned_buffer *a) { return ag_buffer_free(a); }

#endif
