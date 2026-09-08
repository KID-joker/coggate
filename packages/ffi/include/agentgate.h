#ifndef AGENTGATE_H
#define AGENTGATE_H

#include <stddef.h>
#include <stdint.h>

/*
 * AgentGate stable synchronous C ABI, version 1.
 *
 * Define AGENTGATE_STATIC when linking a static library on Windows. Define
 * AGENTGATE_BUILDING_DLL only while building the AgentGate DLL. All callbacks
 * and exports use the platform C calling convention selected by AG_CALL.
 */
#if defined(_WIN32)
#  if defined(AGENTGATE_STATIC)
#    define AG_API
#  elif defined(AGENTGATE_BUILDING_DLL)
#    define AG_API __declspec(dllexport)
#  else
#    define AG_API __declspec(dllimport)
#  endif
#  define AG_CALL __cdecl
#elif defined(__GNUC__) || defined(__clang__)
#  define AG_API __attribute__((visibility("default")))
#  define AG_CALL
#else
#  define AG_API
#  define AG_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ABI values are fixed-width integers, never C enum objects. */
typedef int32_t ag_status;
typedef int32_t ag_lifecycle_status;
typedef int32_t ag_begin_status;
typedef int32_t ag_key_status;
typedef int32_t ag_attempt_outcome;
typedef uint32_t ag_attempt_limit;

#define AG_ABI_VERSION_1 UINT32_C(1)

/*
 * Top-level status values. Values 1-7 map the identically named Rust
 * ServiceError categories. INVALID_ARGUMENT reports caller ABI/input errors;
 * CALLBACK_FAILED reports a callback protocol violation (including unknown
 * callback status values); PANIC_CAUGHT reports a contained Rust panic. Status
 * values carry no message or request/provider data.
 */
#define AG_STATUS_OK INT32_C(0)
#define AG_STATUS_INVALID_CONFIGURATION INT32_C(1)
#define AG_STATUS_GENERATION_FAILED INT32_C(2)
#define AG_STATUS_INVALID_CHALLENGE_MATERIAL INT32_C(3)
#define AG_STATUS_INVALID_ANSWER_ENCODING INT32_C(4)
#define AG_STATUS_ANSWER_MISMATCH INT32_C(5)
#define AG_STATUS_UNSUPPORTED_GENERATOR_VERSION INT32_C(6)
#define AG_STATUS_INTERNAL_ERROR INT32_C(7)
#define AG_STATUS_INVALID_ARGUMENT INT32_C(100)
#define AG_STATUS_CALLBACK_FAILED INT32_C(101)
#define AG_STATUS_PANIC_CAUGHT INT32_C(102)

/* Return values for store_issued and finish_attempt. */
#define AG_LIFECYCLE_STATUS_OK INT32_C(0)
#define AG_LIFECYCLE_STATUS_UNAVAILABLE INT32_C(1)
#define AG_LIFECYCLE_STATUS_CONFLICT INT32_C(2)
#define AG_LIFECYCLE_STATUS_INTERNAL INT32_C(3)

/* Return values for begin_attempt. Values 10-15 are normal rejections. */
#define AG_BEGIN_STATUS_OK INT32_C(0)
#define AG_BEGIN_STATUS_UNAVAILABLE INT32_C(1)
#define AG_BEGIN_STATUS_CONFLICT INT32_C(2)
#define AG_BEGIN_STATUS_INTERNAL INT32_C(3)
#define AG_BEGIN_STATUS_NOT_FOUND INT32_C(10)
#define AG_BEGIN_STATUS_EXPIRED INT32_C(11)
#define AG_BEGIN_STATUS_ALREADY_CONSUMED INT32_C(12)
#define AG_BEGIN_STATUS_BINDING_MISMATCH INT32_C(13)
#define AG_BEGIN_STATUS_NONCE_MISMATCH INT32_C(14)
#define AG_BEGIN_STATUS_ATTEMPTS_EXHAUSTED INT32_C(15)

/* Return values for active_key and key_by_id. */
#define AG_KEY_STATUS_OK INT32_C(0)
#define AG_KEY_STATUS_UNAVAILABLE INT32_C(1)
#define AG_KEY_STATUS_NOT_FOUND INT32_C(2)
#define AG_KEY_STATUS_INVALID_MATERIAL INT32_C(3)

/* Values passed to finish_attempt. */
#define AG_ATTEMPT_OUTCOME_ACCEPTED INT32_C(1)
#define AG_ATTEMPT_OUTCOME_REJECTED INT32_C(2)
#define AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE INT32_C(3)

/* Accepted issue attempt limits. */
#define AG_ATTEMPT_LIMIT_ONE UINT32_C(1)
#define AG_ATTEMPT_LIMIT_TWO UINT32_C(2)

/*
 * Borrowed bytes. A null data pointer is valid only when len is zero. A
 * non-null pointer must remain readable and unmodified for the synchronous
 * call or callback receiving it. AgentGate never retains borrowed inputs.
 */
typedef struct ag_byte_slice {
    const uint8_t *data;
    size_t len;
} ag_byte_slice;

/*
 * Rust-owned output. Initialize all fields to zero before an issue or verify
 * call. On success, release exactly once with ag_buffer_free; never use the
 * host allocator. After a canonical-empty value is accepted, failures leave it
 * empty; a nonempty value is rejected without overwrite. ag_buffer_free resets
 * a valid buffer to canonical empty and leaves malformed buffers unchanged.
 */
typedef struct ag_owned_buffer {
    uint8_t *data;
    size_t len;
    size_t capacity;
} ag_owned_buffer;

/*
 * Releases host-owned callback output. The exact release_data/data/len tuple
 * is returned once after AgentGate's last read when the producing callback
 * returns its OK status. The function must accept len == 0 and must not throw,
 * unwind, longjmp, or reenter the same service.
 */
typedef void (AG_CALL *ag_host_release)(
    void *release_data,
    uint8_t *data,
    size_t len
);

/*
 * Host-owned callback output. Ownership transfers to AgentGate only when the
 * callback returns OK. Otherwise AgentGate neither reads nor releases it.
 * After transfer, every non-null data pointer requires a release callback,
 * including for len == 0. Required outputs must be nonempty; optional outputs
 * may use {NULL, 0, NULL, NULL}.
 */
typedef struct ag_host_buffer {
    uint8_t *data;
    size_t len;
    void *release_data;
    ag_host_release release;
} ag_host_buffer;

/*
 * store_issued returns AG_LIFECYCLE_STATUS_OK only after durable commit.
 * Documented non-OK lifecycle values map to AG_STATUS_INTERNAL_ERROR; unknown
 * values map to AG_STATUS_CALLBACK_FAILED.
 */
typedef ag_lifecycle_status (AG_CALL *ag_store_issued_callback)(
    void *user_data,
    ag_byte_slice private_json,
    ag_byte_slice binding,
    ag_attempt_limit attempt_limit
);

/*
 * begin_attempt rejection values 10-15 become normal rejected outcome JSON.
 * Its infrastructure values 1-3 map to AG_STATUS_INTERNAL_ERROR; an unknown
 * value or malformed successful output maps to AG_STATUS_CALLBACK_FAILED.
 */
typedef ag_begin_status (AG_CALL *ag_begin_attempt_callback)(
    void *user_data,
    ag_byte_slice identity_json,
    ag_byte_slice binding,
    int64_t server_time,
    ag_host_buffer *material_out,
    ag_host_buffer *token_out
);

/*
 * finish_attempt values 1-3 override the pending result with
 * AG_STATUS_INTERNAL_ERROR; an unknown value overrides it with
 * AG_STATUS_CALLBACK_FAILED. AgentGate never retries lifecycle callbacks.
 */
typedef ag_lifecycle_status (AG_CALL *ag_finish_attempt_callback)(
    void *user_data,
    ag_byte_slice token,
    ag_attempt_outcome outcome
);

/*
 * Known key errors are mapped through the closed provider model. During issue,
 * INVALID_MATERIAL maps to AG_STATUS_INVALID_CONFIGURATION and UNAVAILABLE or
 * NOT_FOUND maps to AG_STATUS_INTERNAL_ERROR. Verification lookup failures map
 * to AG_STATUS_INTERNAL_ERROR. Unknown values and malformed successful outputs
 * map to AG_STATUS_CALLBACK_FAILED.
 */
typedef ag_key_status (AG_CALL *ag_active_key_callback)(
    void *user_data,
    ag_host_buffer *key_id_out,
    ag_host_buffer *key_out
);

typedef ag_key_status (AG_CALL *ag_key_by_id_callback)(
    void *user_data,
    ag_byte_slice key_id,
    ag_host_buffer *key_out
);

typedef void (AG_CALL *ag_observe_callback)(
    void *user_data,
    ag_byte_slice event_json
);

/* Common prefix for every versioned callback table. */
typedef struct ag_callback_header {
    uint32_t struct_size;
    uint32_t abi_version;
} ag_callback_header;

/*
 * All three lifecycle callbacks are required. Inputs and output pointers are
 * valid only for the synchronous callback. store_issued must durably commit
 * before returning OK. begin_attempt transfers material_out and token_out only
 * on AG_BEGIN_STATUS_OK; material is required private-material JSON and token
 * is opaque and optional. finish_attempt receives the exact copied token.
 */
typedef struct ag_lifecycle_callbacks {
    uint32_t struct_size;
    uint32_t abi_version;
    void *user_data;
    ag_store_issued_callback store_issued;
    ag_begin_attempt_callback begin_attempt;
    ag_finish_attempt_callback finish_attempt;
} ag_lifecycle_callbacks;

/*
 * Both key callbacks are required. Successful active_key returns a nonempty
 * UTF-8 key ID and at least 32 key bytes. Successful key_by_id returns at least
 * 32 bytes for exactly the requested ID and must not fall back to active_key.
 * Outputs transfer only on AG_KEY_STATUS_OK.
 */
typedef struct ag_key_callbacks {
    uint32_t struct_size;
    uint32_t abi_version;
    void *user_data;
    ag_active_key_callback active_key;
    ag_key_by_id_callback key_by_id;
} ag_key_callbacks;

/*
 * Optional best-effort observer. Event JSON is borrowed for the callback only
 * and is restricted to secret-safe metadata: it excludes answers, bindings,
 * nonces, MACs, key bytes, key IDs, private material, tokens, and full prompts.
 * Observer failures must be handled inside the callback and must not cross the
 * ABI boundary or change service results.
 */
typedef struct ag_observer_callbacks {
    uint32_t struct_size;
    uint32_t abi_version;
    void *user_data;
    ag_observe_callback observe;
} ag_observer_callbacks;

/*
 * Callback table rules:
 * - struct_size is the caller's actual table size; abi_version is version 1.
 * - Tables are copied by ag_service_create, but function pointers and user_data
 *   must remain valid until ag_service_destroy returns.
 * - user_data must be host-synchronized for serialized calls from arbitrary
 *   threads. Callback invocations on one service are serialized.
 * - No callback or release function may throw, unwind, longjmp, or reenter the
 *   same service. Reentry can deadlock. Foreign runtimes must catch exceptions
 *   inside their callback and return a documented closed status.
 * - Callback output pointers are writable only during their callback and must
 *   not be retained. Host code must not access a top-level output buffer while
 *   its AgentGate call is in progress.
 */

/* Opaque synchronized service handle. */
typedef struct ag_service ag_service;

/* Returns AG_ABI_VERSION_1. */
AG_API uint32_t AG_CALL ag_abi_version(void);

/*
 * Returns the core package version as immutable borrowed UTF-8 bytes. The
 * storage is valid for the process lifetime, is not NUL-terminated, and must
 * not be released.
 */
AG_API ag_byte_slice AG_CALL ag_core_version(void);

/*
 * Creates a service. lifecycle, keys, and out are required; observer may be
 * NULL. Callback tables are copied synchronously. On every return after a valid
 * out pointer is accepted, *out is NULL unless creation succeeds.
 *
 * A non-NULL out pointer must be aligned and writable for ag_service*. Table
 * pointers must be aligned and readable for their advertised initialized
 * prefix. The caller owns callback user_data and function lifetimes described
 * above.
 */
AG_API ag_status AG_CALL ag_service_create(
    const ag_lifecycle_callbacks *lifecycle,
    const ag_key_callbacks *keys,
    const ag_observer_callbacks *observer,
    ag_service **out
);

/*
 * Destroys one live service returned by ag_service_create. service must be
 * non-NULL, must not have been destroyed already, and must not be used after
 * this call begins. Destruction is prohibited while any call or callback is in
 * progress. All callback state must remain valid until destruction returns.
 */
AG_API ag_status AG_CALL ag_service_destroy(ag_service *service);

/*
 * Issues and durably stores a challenge. version is strict UTF-8; binding is
 * 1..256 opaque bytes; attempt_limit is AG_ATTEMPT_LIMIT_ONE or TWO. out is
 * required and must be canonical empty. A nonempty out is rejected unchanged.
 * On success it owns PublicChallenge JSON and must be freed exactly once with
 * ag_buffer_free. After empty validation, errors leave out empty. Public output
 * is not published until store_issued reports success.
 *
 * service must be a live handle. out must be aligned, writable, disjoint from
 * service storage, and inaccessible to callbacks during this call. Input
 * pointers are borrowed only until return. Calls through one handle are
 * serialized; callbacks must not reenter that handle.
 */
AG_API ag_status AG_CALL ag_service_issue(
    ag_service *service,
    ag_byte_slice version,
    ag_byte_slice binding,
    ag_attempt_limit attempt_limit,
    ag_owned_buffer *out
);

/*
 * Verifies strict Submission JSON with no unknown fields against a 1..256 byte
 * binding. out is required and must be canonical empty; a nonempty out is
 * rejected unchanged. On success it owns VerificationOutcome JSON, including
 * normal lifecycle rejections, and must be freed exactly once with
 * ag_buffer_free. After empty validation, errors leave out canonical empty;
 * answer encoding and mismatch remain distinct stable error statuses.
 *
 * service must be a live handle. out must be aligned, writable, disjoint from
 * service storage, and inaccessible to callbacks during this call. Input
 * pointers are borrowed only until return. A successful begin_attempt is always
 * followed by one finish_attempt request; finish failure overrides the result.
 */
AG_API ag_status AG_CALL ag_service_verify(
    ag_service *service,
    ag_byte_slice submission_json,
    ag_byte_slice binding,
    ag_owned_buffer *out
);

/*
 * Releases one Rust-owned output and resets it to canonical empty. buffer may
 * not be NULL. A non-null data pointer requires the exact unchanged
 * data/len/capacity tuple returned by AgentGate, unique ownership, and no prior
 * free. Null data with nonzero metadata and len > capacity are rejected without
 * changing the buffer. Never pass host allocations to this function.
 */
AG_API ag_status AG_CALL ag_buffer_free(ag_owned_buffer *buffer);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AGENTGATE_H */
