#include <node_api.h>

#include "agentgate.h"

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <string>

namespace {

struct State {
  napi_env env{};
  napi_ref lifecycle{};
  napi_ref keys{};
  napi_ref observer{};
  ag_service* service{};
  bool closed{};
  bool callback_active{};
};

struct HostAllocation {
  std::uint8_t* data;
  std::size_t size;
  State* state;
  const char* tag;
};
std::atomic<std::uint64_t> allocations{0};
std::atomic<std::uint64_t> releases{0};
std::atomic<std::uint64_t> destroys{0};
std::atomic<std::uint64_t> wipes{0};
std::atomic<std::uint64_t> observations{0};

void secure_zero(void* pointer, std::size_t length) noexcept {
  auto* bytes = static_cast<volatile std::uint8_t*>(pointer);
  while (length-- != 0) *bytes++ = 0;
}

bool ok(napi_status status) noexcept { return status == napi_ok; }

void clear_exception(napi_env env) noexcept {
  bool pending = false;
  if (!ok(napi_is_exception_pending(env, &pending)) || !pending) return;
  napi_value ignored{};
  (void)napi_get_and_clear_last_exception(env, &ignored);
}

void close_scope(napi_env env, napi_handle_scope scope) noexcept {
  if (!ok(napi_close_handle_scope(env, scope))) clear_exception(env);
}

bool get_ref(napi_env env, napi_ref ref, napi_value* value) noexcept {
  return ref != nullptr && ok(napi_get_reference_value(env, ref, value)) && *value != nullptr;
}

bool uint32_value(napi_env env, napi_value value, std::uint32_t* output) noexcept {
  napi_valuetype type{};
  if (value == nullptr || !ok(napi_typeof(env, value, &type)) || type != napi_number ||
      !ok(napi_get_value_uint32(env, value, output))) {
    clear_exception(env);
    return false;
  }
  return true;
}

bool named(napi_env env, napi_value object, const char* name, napi_value* value) noexcept {
  if (!ok(napi_get_named_property(env, object, name, value))) {
    clear_exception(env);
    return false;
  }
  return true;
}

bool bytes(napi_env env, napi_value value, const std::uint8_t** data,
    std::size_t* length) noexcept {
  bool typed = false;
  napi_typedarray_type type{};
  std::size_t count = 0;
  void* raw = nullptr;
  napi_value buffer{};
  std::size_t offset = 0;
  if (value == nullptr || !ok(napi_is_typedarray(env, value, &typed)) || !typed ||
      !ok(napi_get_typedarray_info(env, value, &type, &count, &raw, &buffer, &offset)) ||
      type != napi_uint8_array) {
    clear_exception(env);
    return false;
  }
  *data = static_cast<const std::uint8_t*>(raw);
  *length = count;
  return true;
}

napi_value byte_array(napi_env env, ag_byte_slice input) noexcept {
  void* copied = nullptr;
  napi_value buffer{};
  napi_value array{};
  if (!ok(napi_create_arraybuffer(env, input.len, &copied, &buffer))) {
    clear_exception(env);
    return nullptr;
  }
  if (input.len != 0) std::memcpy(copied, input.data, input.len);
  if (!ok(napi_create_typedarray(env, napi_uint8_array, input.len, buffer, 0, &array))) {
    clear_exception(env);
    return nullptr;
  }
  return array;
}

bool call_method(State* state, napi_ref target_ref, const char* method,
    std::size_t argc, napi_value* argv, napi_value* result) noexcept {
  napi_value target{};
  napi_value function{};
  if (!get_ref(state->env, target_ref, &target) ||
      !named(state->env, target, method, &function) ||
      !ok(napi_call_function(state->env, target, function, argc, argv, result))) {
    clear_exception(state->env);
    return false;
  }
  bool pending = false;
  if (!ok(napi_is_exception_pending(state->env, &pending)) || pending) {
    clear_exception(state->env);
    return false;
  }
  return true;
}

class CallbackGuard {
 public:
  explicit CallbackGuard(State* value) noexcept : state_(value) {
    if (state_ != nullptr && !state_->callback_active && !state_->closed) {
      state_->callback_active = true;
      entered_ = true;
    }
  }
  ~CallbackGuard() { if (entered_) state_->callback_active = false; }
  bool entered() const noexcept { return entered_; }
 private:
  State* state_;
  bool entered_{};
};

void AG_CALL release_host(void* release_data, std::uint8_t* data, std::size_t len) {
  try {
    (void)len;
    auto* allocation = static_cast<HostAllocation*>(release_data);
    if (allocation == nullptr || allocation->data != data) return;
    secure_zero(data, allocation->size);
    wipes.fetch_add(1, std::memory_order_relaxed);
    CallbackGuard callback(allocation->state);
    napi_handle_scope scope{};
    if (callback.entered() &&
        ok(napi_open_handle_scope(allocation->state->env, &scope))) {
      napi_value target{};
      napi_value function{};
      bool present = false;
      if (get_ref(allocation->state->env, allocation->state->lifecycle, &target) &&
          ok(napi_has_named_property(allocation->state->env, target, "released", &present)) && present &&
          named(allocation->state->env, target, "released", &function)) {
        napi_value argument{};
        napi_value ignored{};
        if (ok(napi_create_string_utf8(allocation->state->env, allocation->tag, NAPI_AUTO_LENGTH,
                &argument))) {
          (void)napi_call_function(allocation->state->env, target, function, 1, &argument, &ignored);
        }
        clear_exception(allocation->state->env);
      }
      close_scope(allocation->state->env, scope);
    }
    std::free(data);
    delete allocation;
    releases.fetch_add(1, std::memory_order_relaxed);
  } catch (...) {}
}

bool output_buffer(State* state, napi_value value, ag_host_buffer* output,
    const char* tag) noexcept {
  napi_env env = state->env;
  const std::uint8_t* source = nullptr;
  std::size_t length = 0;
  if (!bytes(env, value, &source, &length)) return false;
  const std::size_t size = length == 0 ? 1 : length;
  auto* copy = static_cast<std::uint8_t*>(std::malloc(size));
  if (copy == nullptr) return false;
  auto* allocation = new (std::nothrow) HostAllocation{copy, size, state, tag};
  if (allocation == nullptr) { std::free(copy); return false; }
  if (length != 0) std::memcpy(copy, source, length);
  output->data = copy;
  output->len = length;
  output->release_data = allocation;
  output->release = release_host;
  allocations.fetch_add(1, std::memory_order_relaxed);
  return true;
}

ag_lifecycle_status AG_CALL store_issued(void* opaque, ag_byte_slice private_json,
    ag_byte_slice binding, ag_attempt_limit limit) {
  try {
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return AG_LIFECYCLE_STATUS_INTERNAL;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return AG_LIFECYCLE_STATUS_INTERNAL;
    napi_value argv[3]{byte_array(state->env, private_json), byte_array(state->env, binding), {}};
    napi_value result{};
    std::uint32_t status = AG_LIFECYCLE_STATUS_INTERNAL;
    const bool success = argv[0] != nullptr && argv[1] != nullptr &&
        ok(napi_create_uint32(state->env, limit, &argv[2])) &&
        call_method(state, state->lifecycle, "storeIssued", 3, argv, &result) &&
        uint32_value(state->env, result, &status);
    close_scope(state->env, scope);
    return success ? static_cast<ag_lifecycle_status>(status) : AG_LIFECYCLE_STATUS_INTERNAL;
  } catch (...) { return AG_LIFECYCLE_STATUS_INTERNAL; }
}

ag_begin_status AG_CALL begin_attempt(void* opaque, ag_byte_slice identity,
    ag_byte_slice binding, std::int64_t server_time, ag_host_buffer* material_out,
    ag_host_buffer* token_out) {
  try {
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return AG_BEGIN_STATUS_INTERNAL;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return AG_BEGIN_STATUS_INTERNAL;
    napi_value argv[3]{byte_array(state->env, identity), byte_array(state->env, binding), {}};
    napi_value result{};
    std::uint32_t status = AG_BEGIN_STATUS_INTERNAL;
    bool success = argv[0] != nullptr && argv[1] != nullptr &&
        ok(napi_create_int64(state->env, server_time, &argv[2])) &&
        call_method(state, state->lifecycle, "beginAttempt", 3, argv, &result);
    napi_value status_value{};
    success = success && named(state->env, result, "status", &status_value) &&
        uint32_value(state->env, status_value, &status);
    if (success && status == AG_BEGIN_STATUS_OK) {
      napi_value material{};
      napi_value token{};
      success = named(state->env, result, "material", &material) &&
          named(state->env, result, "token", &token) &&
          output_buffer(state, material, material_out, "material") &&
          output_buffer(state, token, token_out, "token");
      if (!success) {
        if (material_out->data != nullptr) release_host(material_out->release_data, material_out->data, material_out->len);
        if (token_out->data != nullptr) release_host(token_out->release_data, token_out->data, token_out->len);
        *material_out = {};
        *token_out = {};
      }
    }
    close_scope(state->env, scope);
    return success ? static_cast<ag_begin_status>(status) : AG_BEGIN_STATUS_INTERNAL;
  } catch (...) { return AG_BEGIN_STATUS_INTERNAL; }
}

ag_lifecycle_status AG_CALL finish_attempt(void* opaque, ag_byte_slice token,
    ag_attempt_outcome outcome) {
  try {
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return AG_LIFECYCLE_STATUS_INTERNAL;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return AG_LIFECYCLE_STATUS_INTERNAL;
    napi_value argv[2]{byte_array(state->env, token), {}};
    napi_value result{};
    std::uint32_t status = AG_LIFECYCLE_STATUS_INTERNAL;
    const bool success = argv[0] != nullptr && ok(napi_create_uint32(state->env, outcome, &argv[1])) &&
        call_method(state, state->lifecycle, "finishAttempt", 2, argv, &result) &&
        uint32_value(state->env, result, &status);
    close_scope(state->env, scope);
    return success ? static_cast<ag_lifecycle_status>(status) : AG_LIFECYCLE_STATUS_INTERNAL;
  } catch (...) { return AG_LIFECYCLE_STATUS_INTERNAL; }
}

ag_key_status AG_CALL active_key(void* opaque, ag_host_buffer* key_id_out,
    ag_host_buffer* key_out) {
  try {
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return AG_KEY_STATUS_UNAVAILABLE;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return AG_KEY_STATUS_UNAVAILABLE;
    napi_value result{};
    std::uint32_t status = AG_KEY_STATUS_UNAVAILABLE;
    bool success = call_method(state, state->keys, "activeKey", 0, nullptr, &result);
    napi_value status_value{};
    success = success && named(state->env, result, "status", &status_value) &&
        uint32_value(state->env, status_value, &status);
    if (success && status == AG_KEY_STATUS_OK) {
      napi_value key_id{};
      napi_value key{};
      success = named(state->env, result, "keyId", &key_id) && named(state->env, result, "key", &key) &&
          output_buffer(state, key_id, key_id_out, "key_id") &&
          output_buffer(state, key, key_out, "key");
      if (!success) {
        if (key_id_out->data != nullptr) release_host(key_id_out->release_data, key_id_out->data, key_id_out->len);
        if (key_out->data != nullptr) release_host(key_out->release_data, key_out->data, key_out->len);
        *key_id_out = {};
        *key_out = {};
      }
    }
    close_scope(state->env, scope);
    return success ? static_cast<ag_key_status>(status) : AG_KEY_STATUS_UNAVAILABLE;
  } catch (...) { return AG_KEY_STATUS_UNAVAILABLE; }
}

ag_key_status AG_CALL key_by_id(void* opaque, ag_byte_slice key_id, ag_host_buffer* key_out) {
  try {
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return AG_KEY_STATUS_UNAVAILABLE;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return AG_KEY_STATUS_UNAVAILABLE;
    napi_value argv[1]{byte_array(state->env, key_id)};
    napi_value result{};
    std::uint32_t status = AG_KEY_STATUS_UNAVAILABLE;
    bool success = argv[0] != nullptr && call_method(state, state->keys, "keyById", 1, argv, &result);
    napi_value status_value{};
    success = success && named(state->env, result, "status", &status_value) &&
        uint32_value(state->env, status_value, &status);
    if (success && status == AG_KEY_STATUS_OK) {
      napi_value key{};
      success = named(state->env, result, "key", &key) &&
          output_buffer(state, key, key_out, "key");
    }
    close_scope(state->env, scope);
    return success ? static_cast<ag_key_status>(status) : AG_KEY_STATUS_UNAVAILABLE;
  } catch (...) { return AG_KEY_STATUS_UNAVAILABLE; }
}

void AG_CALL observe(void* opaque, ag_byte_slice event_json) {
  try {
    observations.fetch_add(1, std::memory_order_relaxed);
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return;
    napi_value argv[1]{byte_array(state->env, event_json)};
    napi_value ignored{};
    if (argv[0] != nullptr) (void)call_method(state, state->observer, "observe", 1, argv, &ignored);
    clear_exception(state->env);
    close_scope(state->env, scope);
  } catch (...) {}
}

void delete_state(napi_env env, State* state) noexcept {
  if (state == nullptr) return;
  if (!state->closed && state->service != nullptr) {
    (void)ag_service_destroy(state->service);
    state->closed = true;
    state->service = nullptr;
    destroys.fetch_add(1, std::memory_order_relaxed);
  }
  if (state->lifecycle != nullptr) (void)napi_delete_reference(env, state->lifecycle);
  if (state->keys != nullptr) (void)napi_delete_reference(env, state->keys);
  if (state->observer != nullptr) (void)napi_delete_reference(env, state->observer);
  delete state;
}

void finalize(napi_env env, void* data, void*) noexcept { delete_state(env, static_cast<State*>(data)); }

State* state_arg(napi_env env, napi_callback_info info, std::size_t expected,
    napi_value* argv) noexcept {
  std::size_t argc = expected;
  if (!ok(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr)) || argc != expected) return nullptr;
  void* value = nullptr;
  if (!ok(napi_get_value_external(env, argv[0], &value))) return nullptr;
  return static_cast<State*>(value);
}

napi_value status_result(napi_env env, ag_status status, ag_owned_buffer* output) noexcept {
  napi_value result{};
  napi_value status_value{};
  napi_value data_value{};
  napi_value buffer{};
  void* bytes_copy = nullptr;
  if (!ok(napi_create_object(env, &result)) || !ok(napi_create_int32(env, status, &status_value)) ||
      !ok(napi_set_named_property(env, result, "status", status_value))) return nullptr;
  if (status == AG_STATUS_OK && output != nullptr) {
    if (!ok(napi_create_arraybuffer(env, output->len, &bytes_copy, &buffer))) return nullptr;
    if (output->len != 0) std::memcpy(bytes_copy, output->data, output->len);
    if (!ok(napi_create_typedarray(env, napi_uint8_array, output->len, buffer, 0, &data_value)) ||
        !ok(napi_set_named_property(env, result, "data", data_value))) return nullptr;
  }
  return result;
}

napi_value create(napi_env env, napi_callback_info info) {
  try {
    napi_value argv[3]{};
    std::size_t argc = 3;
    if (!ok(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr)) || argc < 2 || argc > 3 ||
        ag_abi_version() != AG_ABI_VERSION_1) return nullptr;
    auto* state = new (std::nothrow) State();
    if (state == nullptr) return nullptr;
    state->env = env;
    if (!ok(napi_create_reference(env, argv[0], 1, &state->lifecycle)) ||
        !ok(napi_create_reference(env, argv[1], 1, &state->keys))) { delete_state(env, state); return nullptr; }
    napi_valuetype observer_type = napi_undefined;
    if (argc == 3 && ok(napi_typeof(env, argv[2], &observer_type)) && observer_type != napi_null &&
        observer_type != napi_undefined && !ok(napi_create_reference(env, argv[2], 1, &state->observer))) {
      delete_state(env, state); return nullptr;
    }
    ag_lifecycle_callbacks lifecycle{sizeof(lifecycle), AG_ABI_VERSION_1, state,
      store_issued, begin_attempt, finish_attempt};
    ag_key_callbacks keys{sizeof(keys), AG_ABI_VERSION_1, state, active_key, key_by_id};
    ag_observer_callbacks observer{sizeof(observer), AG_ABI_VERSION_1, state, observe};
    const ag_status status = ag_service_create(&lifecycle, &keys,
        state->observer == nullptr ? nullptr : &observer, &state->service);
    if (status != AG_STATUS_OK) { delete_state(env, state); return status_result(env, status, nullptr); }
    napi_value external{};
    if (!ok(napi_create_external(env, state, finalize, nullptr, &external))) {
      delete_state(env, state); return nullptr;
    }
    napi_value result{};
    napi_value zero{};
    if (!ok(napi_create_object(env, &result)) || !ok(napi_create_int32(env, 0, &zero)) ||
        !ok(napi_set_named_property(env, result, "status", zero)) ||
        !ok(napi_set_named_property(env, result, "handle", external))) return nullptr;
    return result;
  } catch (...) { clear_exception(env); return nullptr; }
}

napi_value destroy(napi_env env, napi_callback_info info) {
  try {
    napi_value argv[1]{};
    State* state = state_arg(env, info, 1, argv);
    ag_status status = AG_STATUS_INVALID_ARGUMENT;
    if (state != nullptr && !state->callback_active) {
      if (state->closed) status = AG_STATUS_OK;
      else {
        status = ag_service_destroy(state->service);
        if (status == AG_STATUS_OK) {
          state->closed = true;
          state->service = nullptr;
          destroys.fetch_add(1, std::memory_order_relaxed);
        }
      }
    }
    return status_result(env, status, nullptr);
  } catch (...) { return status_result(env, AG_STATUS_INTERNAL_ERROR, nullptr); }
}

napi_value issue(napi_env env, napi_callback_info info) {
  try {
    napi_value argv[4]{};
    State* state = state_arg(env, info, 4, argv);
    if (state == nullptr || state->closed || state->callback_active) return status_result(env, AG_STATUS_INVALID_ARGUMENT, nullptr);
    const std::uint8_t* version = nullptr;
    const std::uint8_t* binding = nullptr;
    std::size_t version_length = 0;
    std::size_t binding_length = 0;
    std::uint32_t limit = 0;
    if (!bytes(env, argv[1], &version, &version_length) || !bytes(env, argv[2], &binding, &binding_length) ||
        !uint32_value(env, argv[3], &limit)) return status_result(env, AG_STATUS_INVALID_ARGUMENT, nullptr);
    ag_owned_buffer output{};
    const ag_status status = ag_service_issue(state->service, {version, version_length},
        {binding, binding_length}, limit, &output);
    napi_value result = status_result(env, status, &output);
    if (output.data != nullptr) (void)ag_buffer_free(&output);
    return result;
  } catch (...) { return status_result(env, AG_STATUS_INTERNAL_ERROR, nullptr); }
}

napi_value verify(napi_env env, napi_callback_info info) {
  try {
    napi_value argv[3]{};
    State* state = state_arg(env, info, 3, argv);
    if (state == nullptr || state->closed || state->callback_active) return status_result(env, AG_STATUS_INVALID_ARGUMENT, nullptr);
    const std::uint8_t* submission = nullptr;
    const std::uint8_t* binding = nullptr;
    std::size_t submission_length = 0;
    std::size_t binding_length = 0;
    if (!bytes(env, argv[1], &submission, &submission_length) || !bytes(env, argv[2], &binding, &binding_length))
      return status_result(env, AG_STATUS_INVALID_ARGUMENT, nullptr);
    ag_owned_buffer output{};
    const ag_status status = ag_service_verify(state->service, {submission, submission_length},
        {binding, binding_length}, &output);
    napi_value result = status_result(env, status, &output);
    if (output.data != nullptr) (void)ag_buffer_free(&output);
    return result;
  } catch (...) { return status_result(env, AG_STATUS_INTERNAL_ERROR, nullptr); }
}

napi_value count(napi_env env, std::uint64_t value) noexcept {
  napi_value result{};
  return ok(napi_create_bigint_uint64(env, value, &result)) ? result : nullptr;
}
napi_value allocation_count(napi_env env, napi_callback_info) { return count(env, allocations.load()); }
napi_value release_count(napi_env env, napi_callback_info) { return count(env, releases.load()); }
napi_value destroy_count(napi_env env, napi_callback_info) { return count(env, destroys.load()); }
napi_value wipe_count(napi_env env, napi_callback_info) { return count(env, wipes.load()); }
napi_value observation_count(napi_env env, napi_callback_info) { return count(env, observations.load()); }

napi_value init(napi_env env, napi_value exports) {
  napi_property_descriptor properties[] = {
    {"create", nullptr, create, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"destroy", nullptr, destroy, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"issue", nullptr, issue, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"verify", nullptr, verify, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"allocationCount", nullptr, allocation_count, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"releaseCount", nullptr, release_count, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"destroyCount", nullptr, destroy_count, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"wipeCount", nullptr, wipe_count, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"observationCount", nullptr, observation_count, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  if (!ok(napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties))) return nullptr;
  napi_value version{};
  if (!ok(napi_create_uint32(env, NAPI_VERSION, &version)) ||
      !ok(napi_set_named_property(env, exports, "napiVersion", version))) return nullptr;
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
