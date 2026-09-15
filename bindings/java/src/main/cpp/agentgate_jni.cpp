#include <jni.h>

#include "agentgate.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <thread>
#include <vector>

namespace {

JavaVM* g_vm = nullptr;
jclass g_service_class = nullptr;
jclass g_error_class = nullptr;
jmethodID g_enter_callback = nullptr;
jmethodID g_exit_callback = nullptr;
jmethodID g_released = nullptr;
jmethodID g_error_from_status = nullptr;
jmethodID g_store_issued = nullptr;
jmethodID g_begin_attempt = nullptr;
jmethodID g_finish_attempt = nullptr;
jmethodID g_active_key = nullptr;
jmethodID g_key_by_id = nullptr;
jmethodID g_observe = nullptr;
jmethodID g_lifecycle_status_value = nullptr;
jmethodID g_begin_status_value = nullptr;
jmethodID g_attempt_outcome_value = nullptr;
jmethodID g_begin_result_status = nullptr;
jmethodID g_begin_result_material = nullptr;
jmethodID g_begin_result_token = nullptr;
jmethodID g_key_status_value = nullptr;
jmethodID g_active_result_status = nullptr;
jmethodID g_active_result_key_id = nullptr;
jmethodID g_active_result_key = nullptr;
jmethodID g_result_status = nullptr;
jmethodID g_result_key = nullptr;
jobject g_attempt_one = nullptr;
jobject g_attempt_two = nullptr;
jobject g_outcome_accepted = nullptr;
jobject g_outcome_rejected = nullptr;
jobject g_outcome_system_failure = nullptr;

std::atomic<std::uint64_t> g_allocations{0};
std::atomic<std::uint64_t> g_releases{0};
std::atomic<std::uint64_t> g_destroys{0};
std::atomic<std::uint64_t> g_attaches{0};
std::atomic<std::uint64_t> g_detaches{0};
std::atomic<std::uint64_t> g_wipes{0};
std::atomic<std::uint64_t> g_wipe_failures{0};

struct NativeState {
  jweak lifecycle = nullptr;
  jweak keys = nullptr;
  jweak observer = nullptr;
  ag_service* service = nullptr;
};

struct HostAllocation {
  std::uint8_t* data;
  jint tag;
};

class EnvScope {
 public:
  EnvScope() noexcept {
    if (g_vm == nullptr) return;
    void* value = nullptr;
    const jint result = g_vm->GetEnv(&value, JNI_VERSION_1_8);
    if (result == JNI_OK) {
      env_ = static_cast<JNIEnv*>(value);
    } else if (result == JNI_EDETACHED
        && g_vm->AttachCurrentThread(reinterpret_cast<void**>(&env_), nullptr) == JNI_OK) {
      attached_ = true;
      g_attaches.fetch_add(1, std::memory_order_relaxed);
    }
  }

  ~EnvScope() {
    if (attached_ && g_vm != nullptr) {
      (void)g_vm->DetachCurrentThread();
      g_detaches.fetch_add(1, std::memory_order_relaxed);
    }
  }

  JNIEnv* get() const noexcept { return env_; }

 private:
  JNIEnv* env_ = nullptr;
  bool attached_ = false;
};

class CallbackScope {
 public:
  explicit CallbackScope(JNIEnv* env) noexcept : env_(env) {
    env_->CallStaticVoidMethod(g_service_class, g_enter_callback);
    entered_ = !clear_exception(env_);
  }

  ~CallbackScope() {
    if (env_->ExceptionCheck()) env_->ExceptionClear();
    if (entered_) {
      env_->CallStaticVoidMethod(g_service_class, g_exit_callback);
      (void)clear_exception(env_);
    }
  }

  bool entered() const noexcept { return entered_; }
  static bool clear_exception(JNIEnv* env) noexcept {
    if (!env->ExceptionCheck()) return false;
    env->ExceptionClear();
    return true;
  }

 private:
  JNIEnv* env_;
  bool entered_ = false;
};

void throw_status(JNIEnv* env, ag_status status) noexcept {
  if (status == AG_STATUS_OK || env->ExceptionCheck()) return;
  jobject error = env->CallStaticObjectMethod(g_error_class, g_error_from_status, status);
  if (!env->ExceptionCheck() && error != nullptr) {
    (void)env->Throw(static_cast<jthrowable>(error));
  }
  if (error != nullptr) env->DeleteLocalRef(error);
}

jbyteArray byte_array(JNIEnv* env, ag_byte_slice value) noexcept {
  if (value.len > static_cast<std::size_t>(std::numeric_limits<jsize>::max())) return nullptr;
  jbyteArray result = env->NewByteArray(static_cast<jsize>(value.len));
  if (result != nullptr && value.len != 0) {
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(value.len),
        reinterpret_cast<const jbyte*>(value.data));
  }
  return result;
}

void secure_zero(void* pointer, std::size_t length) noexcept {
  auto* bytes = static_cast<volatile std::uint8_t*>(pointer);
  while (length-- != 0) *bytes++ = 0;
}

class SensitiveBuffer {
 public:
  SensitiveBuffer() = default;
  SensitiveBuffer(const SensitiveBuffer&) = delete;
  SensitiveBuffer& operator=(const SensitiveBuffer&) = delete;
  ~SensitiveBuffer() { secure_zero(value_.data(), value_.size()); }
  void resize(std::size_t size) { value_.resize(size); }
  std::uint8_t* data() noexcept { return value_.data(); }
  const std::uint8_t* data() const noexcept { return value_.data(); }
  std::size_t size() const noexcept { return value_.size(); }

 private:
  std::vector<std::uint8_t> value_;
};

bool copy_java_bytes(JNIEnv* env, jbyteArray input, SensitiveBuffer& output) {
  if (input == nullptr) return false;
  const jsize length = env->GetArrayLength(input);
  if (env->ExceptionCheck() || length < 0) return false;
  output.resize(static_cast<std::size_t>(length));
  if (length != 0) {
    env->GetByteArrayRegion(input, 0, length, reinterpret_cast<jbyte*>(output.data()));
  }
  return !env->ExceptionCheck();
}

void clear_java_bytes(JNIEnv* env, jbyteArray value) noexcept {
  if (value == nullptr) return;
  const jsize length = env->GetArrayLength(value);
  if (env->ExceptionCheck() || length <= 0) return;
  jbyte zero[256]{};
  for (jsize offset = 0; offset < length && !env->ExceptionCheck();) {
    const jsize remaining = length - offset;
    const jsize count = remaining < static_cast<jsize>(sizeof(zero))
        ? remaining : static_cast<jsize>(sizeof(zero));
    env->SetByteArrayRegion(value, offset, count, zero);
    offset += count;
  }
}

int enum_value(JNIEnv* env, jobject value, jmethodID method, int fallback) noexcept {
  if (value == nullptr) return fallback;
  const jint result = env->CallIntMethod(value, method);
  if (CallbackScope::clear_exception(env)) return fallback;
  return result;
}

void AG_CALL release_host(void* release_data, std::uint8_t* data, std::size_t len) {
  try {
    (void)len;
    auto* allocation = static_cast<HostAllocation*>(release_data);
    if (allocation == nullptr || allocation->data != data) return;
    secure_zero(data, len);
    bool wiped = true;
    for (std::size_t index = 0; index < len; ++index) {
      if (static_cast<volatile std::uint8_t*>(data)[index] != 0) wiped = false;
    }
    if (wiped) {
      g_wipes.fetch_add(1, std::memory_order_relaxed);
    } else {
      g_wipe_failures.fetch_add(1, std::memory_order_relaxed);
    }
    EnvScope scope;
    if (JNIEnv* env = scope.get(); env != nullptr) {
      env->CallStaticVoidMethod(g_service_class, g_released, allocation->tag);
      (void)CallbackScope::clear_exception(env);
    }
    std::free(data);
    delete allocation;
    g_releases.fetch_add(1, std::memory_order_relaxed);
  } catch (...) {
  }
}

bool host_buffer_from_array(JNIEnv* env, jbyteArray value, ag_host_buffer* output,
    jint tag) noexcept {
  if (value == nullptr) return true;
  const jsize length = env->GetArrayLength(value);
  if (env->ExceptionCheck() || length < 0) return false;
  const std::size_t allocation_size = length == 0 ? 1U : static_cast<std::size_t>(length);
  auto* bytes = static_cast<std::uint8_t*>(std::malloc(allocation_size));
  if (bytes == nullptr) return false;
  auto* allocation = new (std::nothrow) HostAllocation{bytes, tag};
  if (allocation == nullptr) {
    std::free(bytes);
    return false;
  }
  if (length != 0) {
    env->GetByteArrayRegion(value, 0, length, reinterpret_cast<jbyte*>(bytes));
    if (env->ExceptionCheck()) {
      secure_zero(bytes, allocation_size);
      delete allocation;
      std::free(bytes);
      return false;
    }
  }
  output->data = bytes;
  output->len = static_cast<std::size_t>(length);
  output->release_data = allocation;
  output->release = release_host;
  g_allocations.fetch_add(1, std::memory_order_relaxed);
  return true;
}

ag_lifecycle_status AG_CALL store_issued(void* user_data, ag_byte_slice private_json,
    ag_byte_slice binding, ag_attempt_limit limit) {
  try {
    EnvScope scope;
    JNIEnv* env = scope.get();
    if (env == nullptr) return AG_LIFECYCLE_STATUS_INTERNAL;
    CallbackScope callback(env);
    if (!callback.entered()) return AG_LIFECYCLE_STATUS_INTERNAL;
    if (env->PushLocalFrame(8) != JNI_OK) return AG_LIFECYCLE_STATUS_INTERNAL;
    auto* state = static_cast<NativeState*>(user_data);
    jobject lifecycle = env->NewLocalRef(state->lifecycle);
    jbyteArray private_value = byte_array(env, private_json);
    jbyteArray binding_value = byte_array(env, binding);
    jobject attempt = limit == AG_ATTEMPT_LIMIT_ONE ? g_attempt_one
        : limit == AG_ATTEMPT_LIMIT_TWO ? g_attempt_two : nullptr;
    jobject result = nullptr;
    if (lifecycle != nullptr && private_value != nullptr && binding_value != nullptr
        && attempt != nullptr) {
      result = env->CallObjectMethod(lifecycle, g_store_issued,
          private_value, binding_value, attempt);
    }
    const bool failed = CallbackScope::clear_exception(env);
    clear_java_bytes(env, private_value);
    clear_java_bytes(env, binding_value);
    (void)CallbackScope::clear_exception(env);
    const int status = failed ? AG_LIFECYCLE_STATUS_INTERNAL
        : enum_value(env, result, g_lifecycle_status_value, AG_LIFECYCLE_STATUS_INTERNAL);
    env->PopLocalFrame(nullptr);
    return status;
  } catch (...) {
    return AG_LIFECYCLE_STATUS_INTERNAL;
  }
}

ag_begin_status AG_CALL begin_attempt(void* user_data, ag_byte_slice identity,
    ag_byte_slice binding, std::int64_t server_time, ag_host_buffer* material_out,
    ag_host_buffer* token_out) {
  try {
    EnvScope scope;
    JNIEnv* env = scope.get();
    if (env == nullptr) return AG_BEGIN_STATUS_INTERNAL;
    CallbackScope callback(env);
    if (!callback.entered() || env->PushLocalFrame(12) != JNI_OK) return AG_BEGIN_STATUS_INTERNAL;
    auto* state = static_cast<NativeState*>(user_data);
    jobject lifecycle = env->NewLocalRef(state->lifecycle);
    jbyteArray identity_value = byte_array(env, identity);
    jbyteArray binding_value = byte_array(env, binding);
    jobject result = nullptr;
    if (lifecycle != nullptr && identity_value != nullptr && binding_value != nullptr) {
      result = env->CallObjectMethod(lifecycle, g_begin_attempt,
          identity_value, binding_value, static_cast<jlong>(server_time));
    }
    const bool callback_failed = CallbackScope::clear_exception(env);
    clear_java_bytes(env, identity_value);
    clear_java_bytes(env, binding_value);
    (void)CallbackScope::clear_exception(env);
    if (callback_failed || result == nullptr) {
      env->PopLocalFrame(nullptr);
      return AG_BEGIN_STATUS_INTERNAL;
    }
    jobject status_object = env->CallObjectMethod(result, g_begin_result_status);
    const int status = enum_value(env, status_object, g_begin_status_value, AG_BEGIN_STATUS_INTERNAL);
    if (status != AG_BEGIN_STATUS_OK) {
      env->PopLocalFrame(nullptr);
      return status;
    }
    auto* material = static_cast<jbyteArray>(env->CallObjectMethod(result, g_begin_result_material));
    auto* token = static_cast<jbyteArray>(env->CallObjectMethod(result, g_begin_result_token));
    if (CallbackScope::clear_exception(env)
        || !host_buffer_from_array(env, material, material_out, 1)
        || !host_buffer_from_array(env, token, token_out, 2)) {
      if (material_out->data != nullptr) release_host(material_out->release_data,
          material_out->data, material_out->len);
      *material_out = {};
      if (token_out->data != nullptr) release_host(token_out->release_data,
          token_out->data, token_out->len);
      *token_out = {};
      (void)CallbackScope::clear_exception(env);
      env->PopLocalFrame(nullptr);
      return AG_BEGIN_STATUS_INTERNAL;
    }
    clear_java_bytes(env, material);
    clear_java_bytes(env, token);
    (void)CallbackScope::clear_exception(env);
    env->PopLocalFrame(nullptr);
    return AG_BEGIN_STATUS_OK;
  } catch (...) {
    return AG_BEGIN_STATUS_INTERNAL;
  }
}

ag_lifecycle_status AG_CALL finish_attempt(void* user_data, ag_byte_slice token,
    ag_attempt_outcome outcome) {
  try {
    EnvScope scope;
    JNIEnv* env = scope.get();
    if (env == nullptr) return AG_LIFECYCLE_STATUS_INTERNAL;
    CallbackScope callback(env);
    if (!callback.entered() || env->PushLocalFrame(6) != JNI_OK) return AG_LIFECYCLE_STATUS_INTERNAL;
    auto* state = static_cast<NativeState*>(user_data);
    jobject lifecycle = env->NewLocalRef(state->lifecycle);
    jbyteArray token_value = byte_array(env, token);
    jobject outcome_value = outcome == AG_ATTEMPT_OUTCOME_ACCEPTED ? g_outcome_accepted
        : outcome == AG_ATTEMPT_OUTCOME_REJECTED ? g_outcome_rejected
        : outcome == AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE ? g_outcome_system_failure : nullptr;
    jobject result = nullptr;
    if (lifecycle != nullptr && token_value != nullptr && outcome_value != nullptr) {
      result = env->CallObjectMethod(lifecycle, g_finish_attempt, token_value, outcome_value);
    }
    const bool failed = CallbackScope::clear_exception(env);
    clear_java_bytes(env, token_value);
    (void)CallbackScope::clear_exception(env);
    const int status = failed ? AG_LIFECYCLE_STATUS_INTERNAL
        : enum_value(env, result, g_lifecycle_status_value, AG_LIFECYCLE_STATUS_INTERNAL);
    env->PopLocalFrame(nullptr);
    return status;
  } catch (...) {
    return AG_LIFECYCLE_STATUS_INTERNAL;
  }
}

ag_key_status AG_CALL active_key(void* user_data, ag_host_buffer* key_id_out,
    ag_host_buffer* key_out) {
  try {
    EnvScope scope;
    JNIEnv* env = scope.get();
    if (env == nullptr) return AG_KEY_STATUS_UNAVAILABLE;
    CallbackScope callback(env);
    if (!callback.entered() || env->PushLocalFrame(10) != JNI_OK) return AG_KEY_STATUS_UNAVAILABLE;
    auto* state = static_cast<NativeState*>(user_data);
    jobject keys = env->NewLocalRef(state->keys);
    jobject result = keys == nullptr ? nullptr : env->CallObjectMethod(keys, g_active_key);
    if (CallbackScope::clear_exception(env) || result == nullptr) {
      env->PopLocalFrame(nullptr);
      return AG_KEY_STATUS_UNAVAILABLE;
    }
    jobject status_object = env->CallObjectMethod(result, g_active_result_status);
    const int status = enum_value(env, status_object, g_key_status_value, AG_KEY_STATUS_UNAVAILABLE);
    if (status != AG_KEY_STATUS_OK) {
      env->PopLocalFrame(nullptr);
      return status;
    }
    auto* key_id = static_cast<jbyteArray>(env->CallObjectMethod(result, g_active_result_key_id));
    auto* key = static_cast<jbyteArray>(env->CallObjectMethod(result, g_active_result_key));
    if (CallbackScope::clear_exception(env) || !host_buffer_from_array(env, key_id, key_id_out, 3)
        || !host_buffer_from_array(env, key, key_out, 4)) {
      if (key_id_out->data != nullptr) release_host(key_id_out->release_data,
          key_id_out->data, key_id_out->len);
      *key_id_out = {};
      if (key_out->data != nullptr) release_host(key_out->release_data, key_out->data, key_out->len);
      *key_out = {};
      (void)CallbackScope::clear_exception(env);
      env->PopLocalFrame(nullptr);
      return AG_KEY_STATUS_UNAVAILABLE;
    }
    clear_java_bytes(env, key_id);
    clear_java_bytes(env, key);
    (void)CallbackScope::clear_exception(env);
    env->PopLocalFrame(nullptr);
    return AG_KEY_STATUS_OK;
  } catch (...) {
    return AG_KEY_STATUS_UNAVAILABLE;
  }
}

ag_key_status AG_CALL key_by_id(void* user_data, ag_byte_slice key_id, ag_host_buffer* key_out) {
  try {
    EnvScope scope;
    JNIEnv* env = scope.get();
    if (env == nullptr) return AG_KEY_STATUS_UNAVAILABLE;
    CallbackScope callback(env);
    if (!callback.entered() || env->PushLocalFrame(8) != JNI_OK) return AG_KEY_STATUS_UNAVAILABLE;
    auto* state = static_cast<NativeState*>(user_data);
    jobject keys = env->NewLocalRef(state->keys);
    jbyteArray id = byte_array(env, key_id);
    jobject result = keys == nullptr || id == nullptr ? nullptr
        : env->CallObjectMethod(keys, g_key_by_id, id);
    const bool callback_failed = CallbackScope::clear_exception(env);
    clear_java_bytes(env, id);
    (void)CallbackScope::clear_exception(env);
    if (callback_failed || result == nullptr) {
      env->PopLocalFrame(nullptr);
      return AG_KEY_STATUS_UNAVAILABLE;
    }
    jobject status_object = env->CallObjectMethod(result, g_result_status);
    const int status = enum_value(env, status_object, g_key_status_value, AG_KEY_STATUS_UNAVAILABLE);
    if (status != AG_KEY_STATUS_OK) {
      env->PopLocalFrame(nullptr);
      return status;
    }
    auto* key = static_cast<jbyteArray>(env->CallObjectMethod(result, g_result_key));
    if (CallbackScope::clear_exception(env) || !host_buffer_from_array(env, key, key_out, 4)) {
      (void)CallbackScope::clear_exception(env);
      env->PopLocalFrame(nullptr);
      return AG_KEY_STATUS_UNAVAILABLE;
    }
    clear_java_bytes(env, key);
    (void)CallbackScope::clear_exception(env);
    env->PopLocalFrame(nullptr);
    return AG_KEY_STATUS_OK;
  } catch (...) {
    return AG_KEY_STATUS_UNAVAILABLE;
  }
}

void AG_CALL observe(void* user_data, ag_byte_slice event_json) {
  try {
    EnvScope scope;
    JNIEnv* env = scope.get();
    if (env == nullptr) return;
    CallbackScope callback(env);
    if (!callback.entered() || env->PushLocalFrame(4) != JNI_OK) return;
    auto* state = static_cast<NativeState*>(user_data);
    jobject observer = env->NewLocalRef(state->observer);
    jbyteArray event = byte_array(env, event_json);
    if (observer != nullptr && event != nullptr) env->CallVoidMethod(observer, g_observe, event);
    (void)CallbackScope::clear_exception(env);
    env->PopLocalFrame(nullptr);
  } catch (...) {
  }
}

void delete_state(JNIEnv* env, NativeState* state) noexcept {
  if (state == nullptr) return;
  if (state->lifecycle != nullptr) env->DeleteWeakGlobalRef(state->lifecycle);
  if (state->keys != nullptr) env->DeleteWeakGlobalRef(state->keys);
  if (state->observer != nullptr) env->DeleteWeakGlobalRef(state->observer);
  delete state;
}

bool cache_class(JNIEnv* env, const char* name, jclass* destination) {
  jclass local = env->FindClass(name);
  if (local == nullptr) return false;
  *destination = static_cast<jclass>(env->NewGlobalRef(local));
  env->DeleteLocalRef(local);
  return *destination != nullptr;
}

jobject enum_constant(JNIEnv* env, const char* class_name, const char* field) {
  jclass type = env->FindClass(class_name);
  if (type == nullptr) return nullptr;
  const std::string signature = std::string("L") + class_name + ";";
  jfieldID id = env->GetStaticFieldID(type, field, signature.c_str());
  jobject local = id == nullptr ? nullptr : env->GetStaticObjectField(type, id);
  jobject global = local == nullptr ? nullptr : env->NewGlobalRef(local);
  if (local != nullptr) env->DeleteLocalRef(local);
  env->DeleteLocalRef(type);
  return global;
}

}  // namespace

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  try {
    g_vm = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8) != JNI_OK) return JNI_ERR;
    if (!cache_class(env, "io/agentgate/Service", &g_service_class)
        || !cache_class(env, "io/agentgate/AgentGateException", &g_error_class)) return JNI_ERR;
    g_enter_callback = env->GetStaticMethodID(g_service_class, "enterCallback", "()V");
    g_exit_callback = env->GetStaticMethodID(g_service_class, "exitCallback", "()V");
    g_released = env->GetStaticMethodID(g_service_class, "released", "(I)V");
    g_error_from_status = env->GetStaticMethodID(g_error_class, "fromStatus",
        "(I)Lio/agentgate/AgentGateException;");

    jclass lifecycle = env->FindClass("io/agentgate/Lifecycle");
    jclass lifecycle_status = env->FindClass("io/agentgate/Lifecycle$Status");
    jclass begin_status = env->FindClass("io/agentgate/Lifecycle$BeginStatus");
    jclass outcome = env->FindClass("io/agentgate/Lifecycle$AttemptOutcome");
    jclass begin_result = env->FindClass("io/agentgate/Lifecycle$BeginResult");
    jclass keys = env->FindClass("io/agentgate/KeyProvider");
    jclass key_status = env->FindClass("io/agentgate/KeyProvider$Status");
    jclass active_result = env->FindClass("io/agentgate/KeyProvider$ActiveResult");
    jclass key_result = env->FindClass("io/agentgate/KeyProvider$Result");
    jclass observer = env->FindClass("io/agentgate/Observer");
    if (lifecycle == nullptr || lifecycle_status == nullptr || begin_status == nullptr
        || outcome == nullptr || begin_result == nullptr || keys == nullptr || key_status == nullptr
        || active_result == nullptr || key_result == nullptr || observer == nullptr) return JNI_ERR;

    g_store_issued = env->GetMethodID(lifecycle, "storeIssued",
        "([B[BLio/agentgate/AttemptLimit;)Lio/agentgate/Lifecycle$Status;");
    g_begin_attempt = env->GetMethodID(lifecycle, "beginAttempt",
        "([B[BJ)Lio/agentgate/Lifecycle$BeginResult;");
    g_finish_attempt = env->GetMethodID(lifecycle, "finishAttempt",
        "([BLio/agentgate/Lifecycle$AttemptOutcome;)Lio/agentgate/Lifecycle$Status;");
    g_lifecycle_status_value = env->GetMethodID(lifecycle_status, "value", "()I");
    g_begin_status_value = env->GetMethodID(begin_status, "value", "()I");
    g_attempt_outcome_value = env->GetMethodID(outcome, "value", "()I");
    g_begin_result_status = env->GetMethodID(begin_result, "status",
        "()Lio/agentgate/Lifecycle$BeginStatus;");
    g_begin_result_material = env->GetMethodID(begin_result, "material", "()[B");
    g_begin_result_token = env->GetMethodID(begin_result, "token", "()[B");
    g_active_key = env->GetMethodID(keys, "activeKey", "()Lio/agentgate/KeyProvider$ActiveResult;");
    g_key_by_id = env->GetMethodID(keys, "keyById", "([B)Lio/agentgate/KeyProvider$Result;");
    g_key_status_value = env->GetMethodID(key_status, "value", "()I");
    g_active_result_status = env->GetMethodID(active_result, "status",
        "()Lio/agentgate/KeyProvider$Status;");
    g_active_result_key_id = env->GetMethodID(active_result, "keyId", "()[B");
    g_active_result_key = env->GetMethodID(active_result, "key", "()[B");
    g_result_status = env->GetMethodID(key_result, "status", "()Lio/agentgate/KeyProvider$Status;");
    g_result_key = env->GetMethodID(key_result, "key", "()[B");
    g_observe = env->GetMethodID(observer, "observe", "([B)V");

    g_attempt_one = enum_constant(env, "io/agentgate/AttemptLimit", "ONE");
    g_attempt_two = enum_constant(env, "io/agentgate/AttemptLimit", "TWO");
    g_outcome_accepted = enum_constant(env, "io/agentgate/Lifecycle$AttemptOutcome", "ACCEPTED");
    g_outcome_rejected = enum_constant(env, "io/agentgate/Lifecycle$AttemptOutcome", "REJECTED");
    g_outcome_system_failure = enum_constant(env,
        "io/agentgate/Lifecycle$AttemptOutcome", "SYSTEM_FAILURE");
    if (env->ExceptionCheck() || g_enter_callback == nullptr || g_exit_callback == nullptr
        || g_released == nullptr
        || g_error_from_status == nullptr || g_store_issued == nullptr || g_begin_attempt == nullptr
        || g_finish_attempt == nullptr || g_lifecycle_status_value == nullptr
        || g_begin_status_value == nullptr || g_attempt_outcome_value == nullptr
        || g_begin_result_status == nullptr || g_begin_result_material == nullptr
        || g_begin_result_token == nullptr || g_active_key == nullptr || g_key_by_id == nullptr
        || g_key_status_value == nullptr || g_active_result_status == nullptr
        || g_active_result_key_id == nullptr || g_active_result_key == nullptr
        || g_result_status == nullptr || g_result_key == nullptr || g_observe == nullptr
        || g_attempt_one == nullptr || g_attempt_two == nullptr || g_outcome_accepted == nullptr
        || g_outcome_rejected == nullptr || g_outcome_system_failure == nullptr) return JNI_ERR;
    return JNI_VERSION_1_8;
  } catch (...) {
    return JNI_ERR;
  }
}

JNIEXPORT jlong JNICALL Java_io_agentgate_Service_nativeCreate(
    JNIEnv* env, jclass, jobject lifecycle, jobject keys, jobject observer) {
  try {
    if (lifecycle == nullptr || keys == nullptr || ag_abi_version() != AG_ABI_VERSION_1) {
      throw_status(env, AG_STATUS_INVALID_ARGUMENT);
      return 0;
    }
    std::unique_ptr<NativeState> state(new (std::nothrow) NativeState());
    if (!state) {
      throw_status(env, AG_STATUS_INTERNAL_ERROR);
      return 0;
    }
    state->lifecycle = env->NewWeakGlobalRef(lifecycle);
    state->keys = env->NewWeakGlobalRef(keys);
    state->observer = observer == nullptr ? nullptr : env->NewWeakGlobalRef(observer);
    if (state->lifecycle == nullptr || state->keys == nullptr
        || (observer != nullptr && state->observer == nullptr)) {
      delete_state(env, state.release());
      if (!env->ExceptionCheck()) throw_status(env, AG_STATUS_INTERNAL_ERROR);
      return 0;
    }
    ag_lifecycle_callbacks lifecycle_callbacks{};
    lifecycle_callbacks.struct_size = sizeof(lifecycle_callbacks);
    lifecycle_callbacks.abi_version = AG_ABI_VERSION_1;
    lifecycle_callbacks.user_data = state.get();
    lifecycle_callbacks.store_issued = store_issued;
    lifecycle_callbacks.begin_attempt = begin_attempt;
    lifecycle_callbacks.finish_attempt = finish_attempt;
    ag_key_callbacks key_callbacks{};
    key_callbacks.struct_size = sizeof(key_callbacks);
    key_callbacks.abi_version = AG_ABI_VERSION_1;
    key_callbacks.user_data = state.get();
    key_callbacks.active_key = active_key;
    key_callbacks.key_by_id = key_by_id;
    ag_observer_callbacks observer_callbacks{};
    observer_callbacks.struct_size = sizeof(observer_callbacks);
    observer_callbacks.abi_version = AG_ABI_VERSION_1;
    observer_callbacks.user_data = state.get();
    observer_callbacks.observe = observe;
    const ag_status status = ag_service_create(&lifecycle_callbacks, &key_callbacks,
        observer == nullptr ? nullptr : &observer_callbacks, &state->service);
    if (status != AG_STATUS_OK) {
      throw_status(env, status);
      delete_state(env, state.release());
      return 0;
    }
    return reinterpret_cast<jlong>(state.release());
  } catch (...) {
    throw_status(env, AG_STATUS_INTERNAL_ERROR);
    return 0;
  }
}

JNIEXPORT jint JNICALL Java_io_agentgate_Service_nativeDestroy(JNIEnv* env, jclass, jlong handle) {
  try {
    auto* state = reinterpret_cast<NativeState*>(handle);
    if (state == nullptr) return AG_STATUS_INVALID_ARGUMENT;
    const ag_status status = ag_service_destroy(state->service);
    if (status == AG_STATUS_OK) {
      g_destroys.fetch_add(1, std::memory_order_relaxed);
      delete_state(env, state);
    }
    return status;
  } catch (...) {
    return AG_STATUS_INTERNAL_ERROR;
  }
}

JNIEXPORT jbyteArray JNICALL Java_io_agentgate_Service_nativeIssue(JNIEnv* env, jclass,
    jlong handle, jbyteArray version, jbyteArray binding, jint limit) {
  try {
    auto* state = reinterpret_cast<NativeState*>(handle);
    SensitiveBuffer version_bytes;
    SensitiveBuffer binding_bytes;
    if (state == nullptr || !copy_java_bytes(env, version, version_bytes)
        || !copy_java_bytes(env, binding, binding_bytes)) {
      if (!env->ExceptionCheck()) throw_status(env, AG_STATUS_INVALID_ARGUMENT);
      return nullptr;
    }
    ag_owned_buffer output{};
    const ag_status status = ag_service_issue(state->service,
        {version_bytes.data(), version_bytes.size()}, {binding_bytes.data(), binding_bytes.size()},
        static_cast<ag_attempt_limit>(limit), &output);
    if (status != AG_STATUS_OK) {
      throw_status(env, status);
      return nullptr;
    }
    jbyteArray result = byte_array(env, {output.data, output.len});
    secure_zero(output.data, output.len);
    const ag_status free_status = ag_buffer_free(&output);
    if (free_status != AG_STATUS_OK && !env->ExceptionCheck()) throw_status(env, free_status);
    return result;
  } catch (...) {
    throw_status(env, AG_STATUS_INTERNAL_ERROR);
    return nullptr;
  }
}

JNIEXPORT jbyteArray JNICALL Java_io_agentgate_Service_nativeVerify(JNIEnv* env, jclass,
    jlong handle, jbyteArray submission, jbyteArray binding) {
  try {
    auto* state = reinterpret_cast<NativeState*>(handle);
    SensitiveBuffer submission_bytes;
    SensitiveBuffer binding_bytes;
    if (state == nullptr || !copy_java_bytes(env, submission, submission_bytes)
        || !copy_java_bytes(env, binding, binding_bytes)) {
      if (!env->ExceptionCheck()) throw_status(env, AG_STATUS_INVALID_ARGUMENT);
      return nullptr;
    }
    ag_owned_buffer output{};
    const ag_status status = ag_service_verify(state->service,
        {submission_bytes.data(), submission_bytes.size()},
        {binding_bytes.data(), binding_bytes.size()}, &output);
    if (status != AG_STATUS_OK) {
      throw_status(env, status);
      return nullptr;
    }
    jbyteArray result = byte_array(env, {output.data, output.len});
    secure_zero(output.data, output.len);
    const ag_status free_status = ag_buffer_free(&output);
    if (free_status != AG_STATUS_OK && !env->ExceptionCheck()) throw_status(env, free_status);
    return result;
  } catch (...) {
    throw_status(env, AG_STATUS_INTERNAL_ERROR);
    return nullptr;
  }
}

JNIEXPORT jboolean JNICALL Java_io_agentgate_Service_nativeTestCallbackFromAttachedThread(
    JNIEnv* env, jclass, jobject lifecycle) {
  try {
    jobject global = env->NewGlobalRef(lifecycle);
    if (global == nullptr) return JNI_FALSE;
    bool result = false;
    std::thread worker([global, &result]() {
      EnvScope scope;
      JNIEnv* worker_env = scope.get();
      if (worker_env == nullptr) return;
      NativeState state{};
      state.lifecycle = global;
      const std::uint8_t value = 0;
      result = store_issued(&state, {&value, 1}, {&value, 1}, AG_ATTEMPT_LIMIT_ONE)
          == AG_LIFECYCLE_STATUS_OK;
      worker_env->DeleteGlobalRef(global);
    });
    worker.join();
    return result ? JNI_TRUE : JNI_FALSE;
  } catch (...) {
    return JNI_FALSE;
  }
}

JNIEXPORT jlong JNICALL Java_io_agentgate_Service_nativeTestAttachCount(JNIEnv*, jclass) {
  return static_cast<jlong>(g_attaches.load(std::memory_order_relaxed));
}
JNIEXPORT jlong JNICALL Java_io_agentgate_Service_nativeTestDetachCount(JNIEnv*, jclass) {
  return static_cast<jlong>(g_detaches.load(std::memory_order_relaxed));
}
JNIEXPORT jlong JNICALL Java_io_agentgate_Service_nativeTestAllocationCount(JNIEnv*, jclass) {
  return static_cast<jlong>(g_allocations.load(std::memory_order_relaxed));
}
JNIEXPORT jlong JNICALL Java_io_agentgate_Service_nativeTestReleaseCount(JNIEnv*, jclass) {
  return static_cast<jlong>(g_releases.load(std::memory_order_relaxed));
}
JNIEXPORT jlong JNICALL Java_io_agentgate_Service_nativeTestDestroyCount(JNIEnv*, jclass) {
  return static_cast<jlong>(g_destroys.load(std::memory_order_relaxed));
}
JNIEXPORT jlong JNICALL Java_io_agentgate_Service_nativeTestWipeCount(JNIEnv*, jclass) {
  return static_cast<jlong>(g_wipes.load(std::memory_order_relaxed));
}
JNIEXPORT jlong JNICALL Java_io_agentgate_Service_nativeTestWipeFailureCount(JNIEnv*, jclass) {
  return static_cast<jlong>(g_wipe_failures.load(std::memory_order_relaxed));
}
JNIEXPORT jboolean JNICALL Java_io_agentgate_Service_nativeTestPendingExceptionCleanup(
    JNIEnv* env, jclass) {
  try {
    {
      CallbackScope callback(env);
      if (!callback.entered()) return JNI_FALSE;
      (void)env->FindClass("io/agentgate/DeliberatelyMissingForPendingExceptionTest");
      if (!env->ExceptionCheck()) return JNI_FALSE;
    }
    return env->ExceptionCheck() ? JNI_FALSE : JNI_TRUE;
  } catch (...) {
    if (env->ExceptionCheck()) env->ExceptionClear();
    return JNI_FALSE;
  }
}

}  // extern "C"
