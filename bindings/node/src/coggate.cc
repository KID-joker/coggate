#include <node_api.h>

#include "coggate.h"

#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <mutex>
#include <string>

namespace {

struct State {
  napi_env env{};
  napi_ref lifecycle{};
  napi_ref keys{};
  napi_ref observer{};
  ag_service* service{};
  std::mutex mutex;
  bool closed{};
  bool callback_active{};
  std::size_t in_flight{};
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
std::atomic<std::uint64_t> napi_failures{0};
std::atomic<bool> fail_next_named_property{false};

void secure_zero(void* pointer, std::size_t length) noexcept {
  auto* bytes = static_cast<volatile std::uint8_t*>(pointer);
  while (length-- != 0) *bytes++ = 0;
}

bool ok(napi_status status) noexcept {
  if (status == napi_ok) return true;
  napi_failures.fetch_add(1, std::memory_order_relaxed);
  return false;
}

void clear_exception(napi_env env) noexcept {
  bool pending = false;
  if (!ok(napi_is_exception_pending(env, &pending)) || !pending) return;
  napi_value ignored{};
  if (!ok(napi_get_and_clear_last_exception(env, &ignored))) return;
}

void close_scope(napi_env env, napi_handle_scope scope) noexcept {
  if (!ok(napi_close_handle_scope(env, scope))) clear_exception(env);
}

bool get_ref(napi_env env, napi_ref ref, napi_value* value) noexcept {
  if (ref == nullptr || !ok(napi_get_reference_value(env, ref, value)) || *value == nullptr) {
    clear_exception(env);
    return false;
  }
  return true;
}

bool number_value(napi_env env, napi_value value, std::int32_t* output) noexcept {
  napi_valuetype type{};
  double number = 0;
  if (value == nullptr || !ok(napi_typeof(env, value, &type)) || type != napi_number ||
      !ok(napi_get_value_double(env, value, &number)) || !std::isfinite(number) ||
      std::trunc(number) != number || number < std::numeric_limits<std::int32_t>::min() ||
      number > std::numeric_limits<std::int32_t>::max()) {
    clear_exception(env);
    return false;
  }
  *output = static_cast<std::int32_t>(number);
  return true;
}

bool lifecycle_value(napi_env env, napi_value value, std::int32_t* output) noexcept {
  return number_value(env, value, output) && *output >= 0 && *output <= 3;
}

bool begin_value(napi_env env, napi_value value, std::int32_t* output) noexcept {
  return number_value(env, value, output) && ((*output >= 0 && *output <= 3) ||
      (*output >= 10 && *output <= 15));
}

bool key_value(napi_env env, napi_value value, std::int32_t* output) noexcept {
  return number_value(env, value, output) && *output >= 0 && *output <= 3;
}

bool named(napi_env env, napi_value object, const char* name, napi_value* value) noexcept {
  if (fail_next_named_property.exchange(false, std::memory_order_relaxed)) {
    napi_failures.fetch_add(1, std::memory_order_relaxed);
    return false;
  }
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

class TransientArray {
 public:
  TransientArray(napi_env env, ag_byte_slice input) noexcept : env_(env), size_(input.len) {
    napi_value buffer{};
    if (!ok(napi_create_arraybuffer(env_, size_, &data_, &buffer))) {
      clear_exception(env_);
      return;
    }
    if (size_ != 0) std::memcpy(data_, input.data, size_);
    if (!ok(napi_create_typedarray(env_, napi_uint8_array, size_, buffer, 0, &value_))) {
      clear_exception(env_);
      secure_zero(data_, size_);
      value_ = nullptr;
    }
  }
  ~TransientArray() { wipe(); }
  TransientArray(const TransientArray&) = delete;
  TransientArray& operator=(const TransientArray&) = delete;
  napi_value value() const noexcept { return value_; }
  void wipe() noexcept {
    if (data_ != nullptr) {
      secure_zero(data_, size_);
      data_ = nullptr;
    }
  }
 private:
  napi_env env_;
  napi_value value_{};
  void* data_{};
  std::size_t size_{};
};

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
    if (state_ == nullptr) return;
    std::lock_guard<std::mutex> lock(state_->mutex);
    if (!state_->callback_active && !state_->closed) {
      state_->callback_active = true;
      entered_ = true;
    }
  }
  ~CallbackGuard() {
    if (entered_) {
      std::lock_guard<std::mutex> lock(state_->mutex);
      state_->callback_active = false;
    }
  }
  bool entered() const noexcept { return entered_; }
 private:
  State* state_;
  bool entered_{};
};

class CallGuard {
 public:
  explicit CallGuard(State* state) noexcept : state_(state) {
    if (state_ == nullptr) return;
    std::lock_guard<std::mutex> lock(state_->mutex);
    if (!state_->closed && !state_->callback_active && state_->service != nullptr) {
      ++state_->in_flight;
      entered_ = true;
    }
  }
  ~CallGuard() {
    if (entered_) {
      std::lock_guard<std::mutex> lock(state_->mutex);
      --state_->in_flight;
    }
  }
  bool entered() const noexcept { return entered_; }
 private:
  State* state_;
  bool entered_{};
};

void COGGATE_CALL release_host(void* release_data, std::uint8_t* data, std::size_t len) {
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
          if (!ok(napi_call_function(allocation->state->env, target, function, 1, &argument,
                  &ignored))) clear_exception(allocation->state->env);
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

ag_lifecycle_status COGGATE_CALL store_issued(void* opaque, ag_byte_slice private_json,
    ag_byte_slice binding, ag_attempt_limit limit) {
  try {
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return AG_LIFECYCLE_STATUS_INTERNAL;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return AG_LIFECYCLE_STATUS_INTERNAL;
    TransientArray private_value(state->env, private_json);
    TransientArray binding_value(state->env, binding);
    napi_value argv[3]{private_value.value(), binding_value.value(), {}};
    napi_value result{};
    std::int32_t status = AG_LIFECYCLE_STATUS_INTERNAL;
    const bool called = argv[0] != nullptr && argv[1] != nullptr &&
        ok(napi_create_uint32(state->env, limit, &argv[2])) &&
        call_method(state, state->lifecycle, "storeIssued", 3, argv, &result);
    const bool valid = called && lifecycle_value(state->env, result, &status);
    private_value.wipe();
    binding_value.wipe();
    close_scope(state->env, scope);
    return !called ? AG_LIFECYCLE_STATUS_INTERNAL
        : valid ? static_cast<ag_lifecycle_status>(status) : INT32_MAX;
  } catch (...) { return AG_LIFECYCLE_STATUS_INTERNAL; }
}

ag_begin_status COGGATE_CALL begin_attempt(void* opaque, ag_byte_slice identity,
    ag_byte_slice binding, std::int64_t server_time, ag_host_buffer* material_out,
    ag_host_buffer* token_out) {
  try {
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return AG_BEGIN_STATUS_INTERNAL;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return AG_BEGIN_STATUS_INTERNAL;
    TransientArray identity_value(state->env, identity);
    TransientArray binding_value(state->env, binding);
    napi_value argv[3]{identity_value.value(), binding_value.value(), {}};
    napi_value result{};
    std::int32_t status = AG_BEGIN_STATUS_INTERNAL;
    const bool called = argv[0] != nullptr && argv[1] != nullptr &&
        ok(napi_create_int64(state->env, server_time, &argv[2])) &&
        call_method(state, state->lifecycle, "beginAttempt", 3, argv, &result);
    napi_value status_value{};
    bool success = called && named(state->env, result, "status", &status_value) &&
        begin_value(state->env, status_value, &status);
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
    identity_value.wipe();
    binding_value.wipe();
    close_scope(state->env, scope);
    return !called ? AG_BEGIN_STATUS_INTERNAL
        : success ? static_cast<ag_begin_status>(status) : INT32_MAX;
  } catch (...) { return AG_BEGIN_STATUS_INTERNAL; }
}

ag_lifecycle_status COGGATE_CALL finish_attempt(void* opaque, ag_byte_slice token,
    ag_attempt_outcome outcome) {
  try {
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return AG_LIFECYCLE_STATUS_INTERNAL;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return AG_LIFECYCLE_STATUS_INTERNAL;
    TransientArray token_value(state->env, token);
    napi_value argv[2]{token_value.value(), {}};
    napi_value result{};
    std::int32_t status = AG_LIFECYCLE_STATUS_INTERNAL;
    const bool called = argv[0] != nullptr && ok(napi_create_uint32(state->env, outcome, &argv[1])) &&
        call_method(state, state->lifecycle, "finishAttempt", 2, argv, &result);
    const bool valid = called && lifecycle_value(state->env, result, &status);
    token_value.wipe();
    close_scope(state->env, scope);
    return !called ? AG_LIFECYCLE_STATUS_INTERNAL
        : valid ? static_cast<ag_lifecycle_status>(status) : INT32_MAX;
  } catch (...) { return AG_LIFECYCLE_STATUS_INTERNAL; }
}

ag_key_status COGGATE_CALL active_key(void* opaque, ag_host_buffer* key_id_out,
    ag_host_buffer* key_out) {
  try {
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return AG_KEY_STATUS_UNAVAILABLE;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return AG_KEY_STATUS_UNAVAILABLE;
    napi_value result{};
    std::int32_t status = AG_KEY_STATUS_UNAVAILABLE;
    const bool called = call_method(state, state->keys, "activeKey", 0, nullptr, &result);
    napi_value status_value{};
    bool success = called && named(state->env, result, "status", &status_value) &&
        key_value(state->env, status_value, &status);
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
    return !called ? AG_KEY_STATUS_UNAVAILABLE
        : success ? static_cast<ag_key_status>(status) : INT32_MAX;
  } catch (...) { return AG_KEY_STATUS_UNAVAILABLE; }
}

ag_key_status COGGATE_CALL key_by_id(void* opaque, ag_byte_slice key_id, ag_host_buffer* key_out) {
  try {
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return AG_KEY_STATUS_UNAVAILABLE;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return AG_KEY_STATUS_UNAVAILABLE;
    TransientArray key_id_value(state->env, key_id);
    napi_value argv[1]{key_id_value.value()};
    napi_value result{};
    std::int32_t status = AG_KEY_STATUS_UNAVAILABLE;
    const bool called = argv[0] != nullptr && call_method(state, state->keys, "keyById", 1, argv, &result);
    napi_value status_value{};
    bool success = called && named(state->env, result, "status", &status_value) &&
        key_value(state->env, status_value, &status);
    if (success && status == AG_KEY_STATUS_OK) {
      napi_value key{};
      success = named(state->env, result, "key", &key) &&
          output_buffer(state, key, key_out, "key");
    }
    key_id_value.wipe();
    close_scope(state->env, scope);
    return !called ? AG_KEY_STATUS_UNAVAILABLE
        : success ? static_cast<ag_key_status>(status) : INT32_MAX;
  } catch (...) { return AG_KEY_STATUS_UNAVAILABLE; }
}

void COGGATE_CALL observe(void* opaque, ag_byte_slice event_json) {
  try {
    observations.fetch_add(1, std::memory_order_relaxed);
    auto* state = static_cast<State*>(opaque);
    CallbackGuard guard(state);
    if (!guard.entered()) return;
    napi_handle_scope scope{};
    if (!ok(napi_open_handle_scope(state->env, &scope))) return;
    TransientArray event_value(state->env, event_json);
    napi_value argv[1]{event_value.value()};
    napi_value ignored{};
    if (argv[0] != nullptr) (void)call_method(state, state->observer, "observe", 1, argv, &ignored);
    clear_exception(state->env);
    event_value.wipe();
    close_scope(state->env, scope);
  } catch (...) {}
}

void delete_state(napi_env env, State* state) noexcept {
  if (state == nullptr) return;
  ag_service* service = nullptr;
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    if (!state->closed && state->service != nullptr && state->in_flight == 0 &&
        !state->callback_active) {
      service = state->service;
      state->closed = true;
      state->service = nullptr;
    }
  }
  if (service != nullptr) {
    (void)ag_service_destroy(service);
    destroys.fetch_add(1, std::memory_order_relaxed);
  }
  if (state->lifecycle != nullptr && !ok(napi_delete_reference(env, state->lifecycle))) clear_exception(env);
  if (state->keys != nullptr && !ok(napi_delete_reference(env, state->keys))) clear_exception(env);
  if (state->observer != nullptr && !ok(napi_delete_reference(env, state->observer))) clear_exception(env);
  delete state;
}

void finalize(napi_env env, void* data, void*) noexcept { delete_state(env, static_cast<State*>(data)); }

State* state_arg(napi_env env, napi_callback_info info, std::size_t expected,
    napi_value* argv) noexcept {
  std::size_t argc = expected;
  if (!ok(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr)) || argc != expected) {
    clear_exception(env);
    return nullptr;
  }
  void* value = nullptr;
  if (!ok(napi_get_value_external(env, argv[0], &value))) {
    clear_exception(env);
    return nullptr;
  }
  return static_cast<State*>(value);
}

napi_value status_result(napi_env env, ag_status status, ag_owned_buffer* output) noexcept {
  napi_value result{};
  napi_value status_value{};
  napi_value data_value{};
  napi_value buffer{};
  void* bytes_copy = nullptr;
  if (!ok(napi_create_object(env, &result)) || !ok(napi_create_int32(env, status, &status_value)) ||
      !ok(napi_set_named_property(env, result, "status", status_value))) {
    clear_exception(env);
    return nullptr;
  }
  if (status == AG_STATUS_OK && output != nullptr) {
    if (!ok(napi_create_arraybuffer(env, output->len, &bytes_copy, &buffer))) {
      clear_exception(env);
      return nullptr;
    }
    if (output->len != 0) std::memcpy(bytes_copy, output->data, output->len);
    if (!ok(napi_create_typedarray(env, napi_uint8_array, output->len, buffer, 0, &data_value)) ||
        !ok(napi_set_named_property(env, result, "data", data_value))) {
      secure_zero(bytes_copy, output->len);
      clear_exception(env);
      return nullptr;
    }
  }
  return result;
}

napi_value create(napi_env env, napi_callback_info info) {
  try {
    napi_value argv[3]{};
    std::size_t argc = 3;
    if (!ok(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr)) || argc < 2 || argc > 3 ||
        ag_abi_version() != AG_ABI_VERSION_1) {
      clear_exception(env);
      return nullptr;
    }
    auto* state = new (std::nothrow) State();
    if (state == nullptr) return nullptr;
    state->env = env;
    if (!ok(napi_create_reference(env, argv[0], 1, &state->lifecycle)) ||
        !ok(napi_create_reference(env, argv[1], 1, &state->keys))) {
      clear_exception(env); delete_state(env, state); return nullptr;
    }
    napi_valuetype observer_type = napi_undefined;
    if (argc == 3) {
      if (!ok(napi_typeof(env, argv[2], &observer_type))) {
        clear_exception(env); delete_state(env, state); return nullptr;
      }
      if (observer_type != napi_null && observer_type != napi_undefined &&
          !ok(napi_create_reference(env, argv[2], 1, &state->observer))) {
        clear_exception(env); delete_state(env, state); return nullptr;
      }
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
      clear_exception(env); delete_state(env, state); return nullptr;
    }
    napi_value result{};
    napi_value zero{};
    if (!ok(napi_create_object(env, &result)) || !ok(napi_create_int32(env, 0, &zero)) ||
        !ok(napi_set_named_property(env, result, "status", zero)) ||
        !ok(napi_set_named_property(env, result, "handle", external))) {
      clear_exception(env);
      return nullptr;
    }
    return result;
  } catch (...) { clear_exception(env); return nullptr; }
}

napi_value destroy(napi_env env, napi_callback_info info) {
  try {
    napi_value argv[1]{};
    State* state = state_arg(env, info, 1, argv);
    ag_status status = AG_STATUS_INVALID_ARGUMENT;
    ag_service* service = nullptr;
    if (state != nullptr) {
      std::lock_guard<std::mutex> lock(state->mutex);
      if (state->closed) status = AG_STATUS_OK;
      else if (!state->callback_active && state->in_flight == 0 && state->service != nullptr) {
        service = state->service;
        state->closed = true;
        state->service = nullptr;
      }
    }
    if (service != nullptr) {
      status = ag_service_destroy(service);
      if (status == AG_STATUS_OK) destroys.fetch_add(1, std::memory_order_relaxed);
    }
    return status_result(env, status, nullptr);
  } catch (...) { return status_result(env, AG_STATUS_INTERNAL_ERROR, nullptr); }
}

napi_value issue(napi_env env, napi_callback_info info) {
  try {
    napi_value argv[4]{};
    State* state = state_arg(env, info, 4, argv);
    CallGuard call(state);
    if (!call.entered()) return status_result(env, AG_STATUS_INVALID_ARGUMENT, nullptr);
    const std::uint8_t* version = nullptr;
    const std::uint8_t* binding = nullptr;
    std::size_t version_length = 0;
    std::size_t binding_length = 0;
    std::int32_t limit = 0;
    if (!bytes(env, argv[1], &version, &version_length) || !bytes(env, argv[2], &binding, &binding_length) ||
        !number_value(env, argv[3], &limit) || (limit != 1 && limit != 2))
      return status_result(env, AG_STATUS_INVALID_ARGUMENT, nullptr);
    ag_owned_buffer output{};
    const ag_status status = ag_service_issue(state->service, {version, version_length},
        {binding, binding_length}, static_cast<ag_attempt_limit>(limit), &output);
    napi_value result = status_result(env, status, &output);
    if (output.data != nullptr) (void)ag_buffer_free(&output);
    return result;
  } catch (...) { return status_result(env, AG_STATUS_INTERNAL_ERROR, nullptr); }
}

napi_value verify(napi_env env, napi_callback_info info) {
  try {
    napi_value argv[3]{};
    State* state = state_arg(env, info, 3, argv);
    CallGuard call(state);
    if (!call.entered()) return status_result(env, AG_STATUS_INVALID_ARGUMENT, nullptr);
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
napi_value fail_next_napi(napi_env env, napi_callback_info info) {
  std::size_t argc = 0;
  if (!ok(napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr)) || argc != 0) {
    clear_exception(env);
    return nullptr;
  }
  fail_next_named_property.store(true, std::memory_order_relaxed);
  napi_value result{};
  if (!ok(napi_get_undefined(env, &result))) {
    clear_exception(env);
    return nullptr;
  }
  return result;
}

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
    {"failNextNapi", nullptr, fail_next_napi, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  if (!ok(napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties))) {
    clear_exception(env);
    return nullptr;
  }
  napi_value version{};
  if (!ok(napi_create_uint32(env, NAPI_VERSION, &version)) ||
      !ok(napi_set_named_property(env, exports, "napiVersion", version))) {
    clear_exception(env);
    return nullptr;
  }
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
