#ifndef COGGATE_CPP_COGGATE_HPP
#define COGGATE_CPP_COGGATE_HPP

#include "coggate.h"

#include <nlohmann/json.hpp>

#if !defined(NLOHMANN_JSON_VERSION_MAJOR) ||                                 \
    !defined(NLOHMANN_JSON_VERSION_MINOR) ||                                 \
    NLOHMANN_JSON_VERSION_MAJOR < 3 ||                                       \
    (NLOHMANN_JSON_VERSION_MAJOR == 3 && NLOHMANN_JSON_VERSION_MINOR < 11)
#error "CogGate C++ requires nlohmann/json 3.11 or newer"
#endif

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <atomic>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace coggate {

namespace detail {

using Json = nlohmann::ordered_json;

[[noreturn]] inline void invalid_json() {
  throw std::invalid_argument("invalid CogGate JSON");
}

template <typename Callable>
auto with_json_errors(Callable &&callable)
    -> decltype(std::forward<Callable>(callable)()) {
  try {
    return std::forward<Callable>(callable)();
  } catch (const std::invalid_argument &) {
    throw;
  } catch (const nlohmann::json::exception &) {
    invalid_json();
  }
}

inline Json parse_object(std::string_view input) {
  return with_json_errors([input] {
    bool duplicate_key = false;
    std::vector<std::unordered_set<std::string>> object_keys;
    const auto reject_duplicate_keys =
        [&duplicate_key, &object_keys](int, Json::parse_event_t event,
                                       Json &parsed) {
          if (event == Json::parse_event_t::object_start) {
            object_keys.emplace_back();
          } else if (event == Json::parse_event_t::key) {
            if (object_keys.empty() ||
                !object_keys.back().insert(parsed.get<std::string>()).second) {
              duplicate_key = true;
            }
          } else if (event == Json::parse_event_t::object_end) {
            object_keys.pop_back();
          }
          return true;
        };
    Json value = Json::parse(input.begin(), input.end(), reject_duplicate_keys);
    if (duplicate_key) {
      invalid_json();
    }
    if (!value.is_object()) {
      invalid_json();
    }
    return value;
  });
}

inline std::string dump_json(const Json &value) {
  return with_json_errors([&value] { return value.dump(); });
}

inline void require_keys(const Json &value,
                         std::initializer_list<const char *> keys) {
  if (!value.is_object() || value.size() != keys.size()) {
    invalid_json();
  }
  for (const char *key : keys) {
    if (!value.contains(key)) {
      invalid_json();
    }
  }
}

inline std::string require_string(const Json &value, const char *key) {
  const auto &field = value.at(key);
  if (!field.is_string()) {
    invalid_json();
  }
  return field.get<std::string>();
}

inline std::int64_t require_i64(const Json &value, const char *key) {
  return with_json_errors([&value, key] {
    const auto &field = value.at(key);
    if (field.is_number_unsigned()) {
      const auto unsigned_value = field.get<std::uint64_t>();
      if (unsigned_value > static_cast<std::uint64_t>(
                               std::numeric_limits<std::int64_t>::max())) {
        invalid_json();
      }
      return static_cast<std::int64_t>(unsigned_value);
    }
    if (!field.is_number_integer()) {
      invalid_json();
    }
    return field.get<std::int64_t>();
  });
}

inline const char *status_code(ag_status status) noexcept {
  switch (status) {
  case AG_STATUS_OK:
    return "ok";
  case AG_STATUS_INVALID_CONFIGURATION:
    return "invalid_configuration";
  case AG_STATUS_GENERATION_FAILED:
    return "generation_failed";
  case AG_STATUS_INVALID_CHALLENGE_MATERIAL:
    return "invalid_challenge_material";
  case AG_STATUS_INVALID_ANSWER_ENCODING:
    return "invalid_answer_encoding";
  case AG_STATUS_ANSWER_MISMATCH:
    return "answer_mismatch";
  case AG_STATUS_UNSUPPORTED_GENERATOR_VERSION:
    return "unsupported_generator_version";
  case AG_STATUS_INTERNAL_ERROR:
    return "internal_error";
  case AG_STATUS_INVALID_ARGUMENT:
    return "invalid_argument";
  case AG_STATUS_CALLBACK_FAILED:
    return "callback_failed";
  case AG_STATUS_PANIC_CAUGHT:
    return "panic_caught";
  default:
    return nullptr;
  }
}

inline const char *require_status_code(ag_status status) {
  const char *code = status_code(status);
  if (code == nullptr) {
    throw std::invalid_argument("invalid CogGate status");
  }
  return code;
}

} // namespace detail

enum class AttemptLimit : std::uint32_t {
  one = AG_ATTEMPT_LIMIT_ONE,
  two = AG_ATTEMPT_LIMIT_TWO,
};

class IssueRequest {
public:
  IssueRequest(std::string version, std::vector<std::uint8_t> binding,
               AttemptLimit attempt_limit)
      : version_(std::move(version)), binding_(std::move(binding)),
        attempt_limit_(attempt_limit) {
    if (binding_.empty() || binding_.size() > 256U ||
        (attempt_limit_ != AttemptLimit::one &&
         attempt_limit_ != AttemptLimit::two)) {
      throw std::invalid_argument("invalid CogGate binding");
    }
  }

  static IssueRequest v1(std::vector<std::uint8_t> binding,
                         AttemptLimit attempt_limit = AttemptLimit::one) {
    return IssueRequest("1.0", std::move(binding), attempt_limit);
  }

  const std::string &version() const noexcept { return version_; }
  const std::vector<std::uint8_t> &binding() const noexcept { return binding_; }
  AttemptLimit attempt_limit() const noexcept { return attempt_limit_; }

private:
  std::string version_;
  std::vector<std::uint8_t> binding_;
  AttemptLimit attempt_limit_;
};

struct Submission {
  std::string challenge_id;
  std::string nonce;
  std::string answer;

  static Submission from_json(std::string_view input) {
    return detail::with_json_errors([input] {
      const auto value = detail::parse_object(input);
      detail::require_keys(value, {"challenge_id", "nonce", "answer"});
      return Submission{detail::require_string(value, "challenge_id"),
                        detail::require_string(value, "nonce"),
                        detail::require_string(value, "answer")};
    });
  }

  std::string to_json() const {
    detail::Json value = detail::Json::object();
    value["challenge_id"] = challenge_id;
    value["nonce"] = nonce;
    value["answer"] = answer;
    return detail::dump_json(value);
  }
};

enum class AnswerEncoding { base64url };

class PublicChallenge {
public:
  std::string challenge_id;
  std::string generator_version;
  std::string nonce;
  std::int64_t issued_at;
  std::int64_t expires_at;
  std::string question;

  static PublicChallenge from_json(std::string_view input) {
    return detail::with_json_errors([input] {
      const auto value = detail::parse_object(input);
      detail::require_keys(value,
                           {"challenge_id", "generator_version", "nonce",
                            "issued_at", "expires_at", "question",
                            "answer_encoding"});
      const std::string answer_encoding =
          detail::require_string(value, "answer_encoding");
      if (answer_encoding != "base64url") {
        detail::invalid_json();
      }
      return PublicChallenge{
          detail::require_string(value, "challenge_id"),
          detail::require_string(value, "generator_version"),
          detail::require_string(value, "nonce"),
          detail::require_i64(value, "issued_at"),
          detail::require_i64(value, "expires_at"),
          detail::require_string(value, "question"),
          AnswerEncoding::base64url};
    });
  }

  AnswerEncoding answer_encoding() const noexcept { return answer_encoding_; }

  std::string to_json() const {
    detail::Json value = detail::Json::object();
    value["challenge_id"] = challenge_id;
    value["generator_version"] = generator_version;
    value["nonce"] = nonce;
    value["issued_at"] = issued_at;
    value["expires_at"] = expires_at;
    value["question"] = question;
    value["answer_encoding"] = answer_encoding_text(answer_encoding_);
    return detail::dump_json(value);
  }

private:
  PublicChallenge(std::string challenge_id_value,
                  std::string generator_version_value,
                  std::string nonce_value, std::int64_t issued_at_value,
                  std::int64_t expires_at_value, std::string question_value,
                  AnswerEncoding answer_encoding_value)
      : challenge_id(std::move(challenge_id_value)),
        generator_version(std::move(generator_version_value)),
        nonce(std::move(nonce_value)), issued_at(issued_at_value),
        expires_at(expires_at_value), question(std::move(question_value)),
        answer_encoding_(answer_encoding_value) {}

  static const char *answer_encoding_text(AnswerEncoding encoding) {
    if (encoding != AnswerEncoding::base64url) {
      throw std::invalid_argument("invalid CogGate answer encoding");
    }
    return "base64url";
  }

  AnswerEncoding answer_encoding_;
};

enum class VerificationStatus { accepted, rejected };

enum class RejectionReason {
  not_found,
  expired,
  already_consumed,
  binding_mismatch,
  nonce_mismatch,
  attempts_exhausted,
};

class VerificationOutcome {
public:
  static VerificationOutcome accepted() {
    return VerificationOutcome(VerificationStatus::accepted, std::nullopt);
  }

  static VerificationOutcome rejected(RejectionReason reason) {
    (void)reason_text(reason);
    return VerificationOutcome(VerificationStatus::rejected, reason);
  }

  static VerificationOutcome from_json(std::string_view input) {
    return detail::with_json_errors([input] {
      const auto value = detail::parse_object(input);
      const std::string status = detail::require_string(value, "status");
      if (status == "accepted") {
        detail::require_keys(value, {"status"});
        return accepted();
      }
      if (status != "rejected") {
        detail::invalid_json();
      }
      detail::require_keys(value, {"status", "reason"});
      const std::string reason = detail::require_string(value, "reason");
      if (reason == "not_found") {
        return rejected(RejectionReason::not_found);
      }
      if (reason == "expired") {
        return rejected(RejectionReason::expired);
      }
      if (reason == "already_consumed") {
        return rejected(RejectionReason::already_consumed);
      }
      if (reason == "binding_mismatch") {
        return rejected(RejectionReason::binding_mismatch);
      }
      if (reason == "nonce_mismatch") {
        return rejected(RejectionReason::nonce_mismatch);
      }
      if (reason == "attempts_exhausted") {
        return rejected(RejectionReason::attempts_exhausted);
      }
      detail::invalid_json();
    });
  }

  VerificationStatus status() const noexcept { return status_; }
  std::optional<RejectionReason> reason() const noexcept { return reason_; }

  std::string to_json() const {
    detail::Json value = detail::Json::object();
    value["status"] = status_ == VerificationStatus::accepted ? "accepted"
                                                               : "rejected";
    if (reason_) {
      value["reason"] = reason_text(*reason_);
    }
    return detail::dump_json(value);
  }

private:
  VerificationOutcome(VerificationStatus status,
                      std::optional<RejectionReason> reason)
      : status_(status), reason_(reason) {}

  static const char *reason_text(RejectionReason reason) {
    switch (reason) {
    case RejectionReason::not_found:
      return "not_found";
    case RejectionReason::expired:
      return "expired";
    case RejectionReason::already_consumed:
      return "already_consumed";
    case RejectionReason::binding_mismatch:
      return "binding_mismatch";
    case RejectionReason::nonce_mismatch:
      return "nonce_mismatch";
    case RejectionReason::attempts_exhausted:
      return "attempts_exhausted";
    }
    throw std::invalid_argument("invalid CogGate rejection reason");
  }

  VerificationStatus status_;
  std::optional<RejectionReason> reason_;
};

class CogGateError : public std::runtime_error {
public:
  explicit CogGateError(ag_status status)
      : CogGateError(status, detail::require_status_code(status)) {}

  ag_status status() const noexcept { return status_; }
  const std::string &code() const noexcept { return code_; }

private:
  CogGateError(ag_status status, const char *code)
      : std::runtime_error(code), status_(status), code_(code) {}

  ag_status status_;
  std::string code_;
};

#ifdef COGGATE_CPP_TESTING
namespace detail {
class OwnedBufferTestAccess;
}
#endif

class OwnedBuffer {
public:
  OwnedBuffer() noexcept = default;
  ~OwnedBuffer() noexcept { reset(); }

  OwnedBuffer(const OwnedBuffer &) = delete;
  OwnedBuffer &operator=(const OwnedBuffer &) = delete;

  OwnedBuffer(OwnedBuffer &&other) noexcept
      : raw_(std::exchange(other.raw_, ag_owned_buffer{})) {}

  OwnedBuffer &operator=(OwnedBuffer &&other) noexcept {
    if (this != &other) {
      reset();
      raw_ = std::exchange(other.raw_, ag_owned_buffer{});
    }
    return *this;
  }

  bool empty() const noexcept {
    return raw_.data == nullptr && raw_.len == 0U && raw_.capacity == 0U;
  }

  std::string string() const {
    validate(raw_);
    if (raw_.len == 0U) {
      return {};
    }
    return {reinterpret_cast<const char *>(raw_.data), raw_.len};
  }

  detail::Json json() const {
    const std::string contents = string();
    if (contents.empty()) {
      detail::invalid_json();
    }
    return detail::with_json_errors(
        [&contents] { return detail::Json::parse(contents); });
  }

  void reset() noexcept {
    if (allocated(raw_)) {
#ifdef COGGATE_CPP_TESTING
      ++test_free_calls();
#endif
      (void)ag_buffer_free(&raw_);
    }
  }

private:
  friend class Service;
#ifdef COGGATE_CPP_TESTING
  friend class detail::OwnedBufferTestAccess;
#endif

  static bool allocated(const ag_owned_buffer &raw) noexcept {
    return raw.data != nullptr && raw.len <= raw.capacity;
  }

  static void validate(const ag_owned_buffer &raw) {
    if (raw.data == nullptr) {
      if (raw.len != 0U || raw.capacity != 0U) {
        throw std::invalid_argument("invalid CogGate buffer");
      }
      return;
    }
    if (raw.len > raw.capacity) {
      throw std::invalid_argument("invalid CogGate buffer");
    }
  }

  static OwnedBuffer adopt(ag_owned_buffer &raw) {
    validate(raw);
    OwnedBuffer result;
    result.raw_ = std::exchange(raw, ag_owned_buffer{});
    return result;
  }

  ag_owned_buffer *output() {
    validate(raw_);
    if (!empty()) {
      throw std::invalid_argument("CogGate output buffer is not empty");
    }
    return &raw_;
  }

#ifdef COGGATE_CPP_TESTING
  static std::size_t &test_free_calls() noexcept {
    static std::size_t calls = 0U;
    return calls;
  }
#endif

  ag_owned_buffer raw_{};
};

#ifdef COGGATE_CPP_TESTING
namespace detail {
class OwnedBufferTestAccess {
public:
  static OwnedBuffer adopt(ag_owned_buffer &raw) {
    return OwnedBuffer::adopt(raw);
  }

  static ag_owned_buffer *output(OwnedBuffer &buffer) {
    return buffer.output();
  }

  static ag_owned_buffer *raw(OwnedBuffer &buffer) noexcept {
    return &buffer.raw_;
  }

  static std::size_t free_calls() noexcept {
    return OwnedBuffer::test_free_calls();
  }

  static void reset_free_calls() noexcept {
    OwnedBuffer::test_free_calls() = 0U;
  }
};
} // namespace detail
#endif

struct BeginAttemptResult {
  ag_begin_status status = AG_BEGIN_STATUS_OK;
  std::vector<std::uint8_t> material;
  std::vector<std::uint8_t> token;
};

struct ActiveKeyResult {
  ag_key_status status = AG_KEY_STATUS_OK;
  std::string key_id;
  std::vector<std::uint8_t> key;
};

struct KeyResult {
  ag_key_status status = AG_KEY_STATUS_OK;
  std::vector<std::uint8_t> key;
};

class Lifecycle {
public:
  virtual ~Lifecycle() noexcept = default;
  virtual ag_lifecycle_status
  store_issued(std::string_view private_json,
               const std::vector<std::uint8_t> &binding,
               AttemptLimit attempt_limit) = 0;
  virtual BeginAttemptResult
  begin_attempt(std::string_view identity_json,
                const std::vector<std::uint8_t> &binding,
                std::int64_t server_time) = 0;
  virtual ag_lifecycle_status
  finish_attempt(const std::vector<std::uint8_t> &token,
                 ag_attempt_outcome outcome) = 0;
};

class KeyProvider {
public:
  virtual ~KeyProvider() noexcept = default;
  virtual ActiveKeyResult active_key() = 0;
  virtual KeyResult key_by_id(std::string_view key_id) = 0;
};

class Observer {
public:
  virtual ~Observer() noexcept = default;
  virtual void observe(std::string_view event_json) = 0;
};

namespace detail {

inline std::string_view slice_view(ag_byte_slice slice) noexcept {
  return slice.len == 0U
             ? std::string_view{}
             : std::string_view(reinterpret_cast<const char *>(slice.data),
                                slice.len);
}

inline std::vector<std::uint8_t> slice_bytes(ag_byte_slice slice) {
  if (slice.len == 0U) {
    return {};
  }
  return {slice.data, slice.data + slice.len};
}

#ifdef COGGATE_CPP_TESTING
using CallbackReleaseHook = void (*)(const char *, void *) noexcept;

inline std::atomic<std::size_t> &callback_buffer_outstanding() noexcept {
  static std::atomic<std::size_t> count{0U};
  return count;
}

inline CallbackReleaseHook &callback_release_hook() noexcept {
  static CallbackReleaseHook hook = nullptr;
  return hook;
}

inline void *&callback_release_hook_data() noexcept {
  static void *data = nullptr;
  return data;
}

inline std::atomic<int> &callback_allocations_before_failure() noexcept {
  static std::atomic<int> count{-1};
  return count;
}

inline std::atomic<std::size_t> &service_destroy_calls() noexcept {
  static std::atomic<std::size_t> count{0U};
  return count;
}
#endif

struct CallbackBufferState {
  explicit CallbackBufferState(std::vector<std::uint8_t> value,
                               const char *value_label)
      : bytes(std::move(value)), label(value_label) {
#ifdef COGGATE_CPP_TESTING
    ++callback_buffer_outstanding();
#endif
  }

  ~CallbackBufferState() noexcept {
#ifdef COGGATE_CPP_TESTING
    --callback_buffer_outstanding();
#endif
  }

  std::vector<std::uint8_t> bytes;
  const char *label;
};

inline void COGGATE_CALL release_callback_buffer(void *release_data,
                                            std::uint8_t *data,
                                            std::size_t len) noexcept {
  std::unique_ptr<CallbackBufferState> state(
      static_cast<CallbackBufferState *>(release_data));
  if (!state) {
    return;
  }
#ifdef COGGATE_CPP_TESTING
  if (callback_release_hook() != nullptr && data == state->bytes.data() &&
      len == state->bytes.size()) {
    callback_release_hook()(state->label, callback_release_hook_data());
  }
#else
  (void)data;
  (void)len;
#endif
}

class PendingCallbackBuffer {
public:
  PendingCallbackBuffer(std::vector<std::uint8_t> bytes, const char *label) {
    if (!bytes.empty()) {
#ifdef COGGATE_CPP_TESTING
      int remaining = callback_allocations_before_failure().load();
      if (remaining == 0) {
        throw std::bad_alloc();
      }
      if (remaining > 0) {
        --callback_allocations_before_failure();
      }
#endif
      state_ = std::make_unique<CallbackBufferState>(std::move(bytes), label);
    }
  }

  void transfer_to(ag_host_buffer *out) noexcept {
    if (!state_) {
      *out = ag_host_buffer{};
      return;
    }
    out->data = state_->bytes.data();
    out->len = state_->bytes.size();
    out->release_data = state_.get();
    out->release = release_callback_buffer;
    (void)state_.release();
  }

private:
  std::unique_ptr<CallbackBufferState> state_;
};

struct CallbackBridge {
  CallbackBridge(std::shared_ptr<Lifecycle> lifecycle_value,
                 std::shared_ptr<KeyProvider> keys_value,
                 std::shared_ptr<Observer> observer_value)
      : lifecycle(std::move(lifecycle_value)), keys(std::move(keys_value)),
        observer(std::move(observer_value)) {
    lifecycle_callbacks = {
        static_cast<std::uint32_t>(sizeof(ag_lifecycle_callbacks)),
        AG_ABI_VERSION_1, this, store_issued, begin_attempt, finish_attempt};
    key_callbacks = {static_cast<std::uint32_t>(sizeof(ag_key_callbacks)),
                     AG_ABI_VERSION_1, this, active_key, key_by_id};
    observer_callbacks = {
        static_cast<std::uint32_t>(sizeof(ag_observer_callbacks)),
        AG_ABI_VERSION_1, this, observe};
  }

  static ag_lifecycle_status COGGATE_CALL
  store_issued(void *user_data, ag_byte_slice private_json,
               ag_byte_slice binding, ag_attempt_limit attempt_limit) noexcept {
    try {
      auto &self = *static_cast<CallbackBridge *>(user_data);
      return self.lifecycle->store_issued(
          slice_view(private_json), slice_bytes(binding),
          static_cast<AttemptLimit>(attempt_limit));
    } catch (...) {
      return AG_LIFECYCLE_STATUS_INTERNAL;
    }
  }

  static ag_begin_status COGGATE_CALL
  begin_attempt(void *user_data, ag_byte_slice identity_json,
                ag_byte_slice binding, std::int64_t server_time,
                ag_host_buffer *material_out,
                ag_host_buffer *token_out) noexcept {
    try {
      auto &self = *static_cast<CallbackBridge *>(user_data);
      BeginAttemptResult result = self.lifecycle->begin_attempt(
          slice_view(identity_json), slice_bytes(binding), server_time);
      if (result.status != AG_BEGIN_STATUS_OK) {
        return result.status;
      }
      PendingCallbackBuffer material(std::move(result.material), "material");
      PendingCallbackBuffer token(std::move(result.token), "token");
      material.transfer_to(material_out);
      token.transfer_to(token_out);
      return AG_BEGIN_STATUS_OK;
    } catch (...) {
      return AG_BEGIN_STATUS_INTERNAL;
    }
  }

  static ag_lifecycle_status COGGATE_CALL
  finish_attempt(void *user_data, ag_byte_slice token,
                 ag_attempt_outcome outcome) noexcept {
    try {
      auto &self = *static_cast<CallbackBridge *>(user_data);
      return self.lifecycle->finish_attempt(slice_bytes(token), outcome);
    } catch (...) {
      return AG_LIFECYCLE_STATUS_INTERNAL;
    }
  }

  static ag_key_status COGGATE_CALL active_key(void *user_data,
                                          ag_host_buffer *key_id_out,
                                          ag_host_buffer *key_out) noexcept {
    try {
      auto &self = *static_cast<CallbackBridge *>(user_data);
      ActiveKeyResult result = self.keys->active_key();
      if (result.status != AG_KEY_STATUS_OK) {
        return result.status;
      }
      std::vector<std::uint8_t> key_id(result.key_id.begin(),
                                       result.key_id.end());
      PendingCallbackBuffer key_id_buffer(std::move(key_id), "active_key_id");
      PendingCallbackBuffer key_buffer(std::move(result.key), "active_key");
      key_id_buffer.transfer_to(key_id_out);
      key_buffer.transfer_to(key_out);
      return AG_KEY_STATUS_OK;
    } catch (...) {
      return AG_KEY_STATUS_UNAVAILABLE;
    }
  }

  static ag_key_status COGGATE_CALL key_by_id(void *user_data,
                                         ag_byte_slice key_id,
                                         ag_host_buffer *key_out) noexcept {
    try {
      auto &self = *static_cast<CallbackBridge *>(user_data);
      KeyResult result = self.keys->key_by_id(slice_view(key_id));
      if (result.status != AG_KEY_STATUS_OK) {
        return result.status;
      }
      PendingCallbackBuffer key_buffer(std::move(result.key), "key");
      key_buffer.transfer_to(key_out);
      return AG_KEY_STATUS_OK;
    } catch (...) {
      return AG_KEY_STATUS_UNAVAILABLE;
    }
  }

  static void COGGATE_CALL observe(void *user_data,
                              ag_byte_slice event_json) noexcept {
    try {
      auto &self = *static_cast<CallbackBridge *>(user_data);
      if (self.observer) {
        self.observer->observe(slice_view(event_json));
      }
    } catch (...) {
    }
  }

  std::shared_ptr<Lifecycle> lifecycle;
  std::shared_ptr<KeyProvider> keys;
  std::shared_ptr<Observer> observer;
  ag_lifecycle_callbacks lifecycle_callbacks{};
  ag_key_callbacks key_callbacks{};
  ag_observer_callbacks observer_callbacks{};
};

struct ServiceControl {
  ServiceControl(std::shared_ptr<Lifecycle> lifecycle,
                 std::shared_ptr<KeyProvider> keys,
                 std::shared_ptr<Observer> observer)
      : bridge(std::make_shared<CallbackBridge>(
            std::move(lifecycle), std::move(keys), std::move(observer))) {}

  std::mutex mutex;
  std::shared_ptr<CallbackBridge> bridge;
  ag_service *handle = nullptr;
  std::atomic<bool> open{false};
};

struct ActiveCallFrame {
  const ServiceControl *control;
  ActiveCallFrame *previous;
};

inline ActiveCallFrame *&active_service_call() noexcept {
  static thread_local ActiveCallFrame *active = nullptr;
  return active;
}

inline bool is_active_service_call(const ServiceControl *control) noexcept {
  for (ActiveCallFrame *frame = active_service_call(); frame != nullptr;
       frame = frame->previous) {
    if (frame->control == control) {
      return true;
    }
  }
  return false;
}

class ActiveServiceCall {
public:
  explicit ActiveServiceCall(const ServiceControl *control) noexcept
      : frame_{control, active_service_call()} {
    active_service_call() = &frame_;
  }
  ~ActiveServiceCall() noexcept { active_service_call() = frame_.previous; }

private:
  ActiveCallFrame frame_;
};

#ifdef COGGATE_CPP_TESTING
class CallbackBufferTestAccess {
public:
  static std::size_t outstanding() noexcept {
    return callback_buffer_outstanding().load();
  }

  static void set_release_hook(CallbackReleaseHook hook,
                               void *data = nullptr) noexcept {
    callback_release_hook() = hook;
    callback_release_hook_data() = data;
  }

  static void fail_after(int successful_allocations) noexcept {
    callback_allocations_before_failure().store(successful_allocations);
  }
};

class ServiceTestAccess {
public:
  static std::size_t destroy_calls() noexcept {
    return service_destroy_calls().load();
  }
  static void reset_destroy_calls() noexcept { service_destroy_calls().store(0U); }
};
#endif

} // namespace detail

class Service {
public:
  Service() noexcept = default;

  Service(std::shared_ptr<Lifecycle> lifecycle,
          std::shared_ptr<KeyProvider> keys,
          std::shared_ptr<Observer> observer = {}) {
    if (!lifecycle || !keys) {
      throw std::invalid_argument("CogGate callbacks are required");
    }
    auto control = std::make_shared<detail::ServiceControl>(
        std::move(lifecycle), std::move(keys), std::move(observer));
    ag_service *handle = nullptr;
    const ag_observer_callbacks *observer_callbacks =
        control->bridge->observer
            ? &control->bridge->observer_callbacks
            : nullptr;
    const ag_status status = ag_service_create(
        &control->bridge->lifecycle_callbacks,
        &control->bridge->key_callbacks, observer_callbacks, &handle);
    if (status != AG_STATUS_OK) {
      throw CogGateError(status);
    }
    control->handle = handle;
    control->open.store(true);
    control_ = std::move(control);
  }

  ~Service() noexcept { (void)close_noexcept(); }

  Service(const Service &) = delete;
  Service &operator=(const Service &) = delete;
  Service(Service &&) noexcept = default;

  Service &operator=(Service &&other) noexcept {
    if (this != &other) {
      (void)close_noexcept();
      control_ = std::move(other.control_);
    }
    return *this;
  }

  bool is_open() const noexcept {
    return control_ && control_->open.load();
  }

  PublicChallenge issue(const IssueRequest &request) {
    const auto control = require_control();
    reject_reentry(control.get());
    std::lock_guard<std::mutex> lock(control->mutex);
    require_open(*control);
    detail::ActiveServiceCall active(control.get());
    OwnedBuffer output;
    const auto &version = request.version();
    const auto &binding = request.binding();
    const ag_status status = ag_service_issue(
        control->handle, bytes(version), bytes(binding),
        static_cast<ag_attempt_limit>(request.attempt_limit()), output.output());
    if (status != AG_STATUS_OK) {
      throw CogGateError(status);
    }
    return PublicChallenge::from_json(output.string());
  }

  VerificationOutcome verify(const Submission &submission,
                             const std::vector<std::uint8_t> &binding) {
    const auto control = require_control();
    reject_reentry(control.get());
    std::lock_guard<std::mutex> lock(control->mutex);
    require_open(*control);
    detail::ActiveServiceCall active(control.get());
    const std::string submission_json = submission.to_json();
    OwnedBuffer output;
    const ag_status status = ag_service_verify(
        control->handle, bytes(submission_json), bytes(binding),
        output.output());
    if (status != AG_STATUS_OK) {
      throw CogGateError(status);
    }
    return VerificationOutcome::from_json(output.string());
  }

  void close() {
    const ag_status status = close_noexcept();
    if (status != AG_STATUS_OK) {
      throw CogGateError(status);
    }
  }

private:
  ag_status close_noexcept() noexcept {
    const auto control = control_;
    if (!control || !control->open.load()) {
      return AG_STATUS_OK;
    }
    if (detail::is_active_service_call(control.get())) {
      return AG_STATUS_INVALID_ARGUMENT;
    }
    try {
      std::lock_guard<std::mutex> lock(control->mutex);
      if (!control->open.load()) {
        return AG_STATUS_OK;
      }
      ag_service *handle = std::exchange(control->handle, nullptr);
      control->open.store(false);
#ifdef COGGATE_CPP_TESTING
      ++detail::service_destroy_calls();
#endif
      return ag_service_destroy(handle);
    } catch (...) {
      return AG_STATUS_INTERNAL_ERROR;
    }
  }

  static ag_byte_slice bytes(std::string_view value) noexcept {
    return {reinterpret_cast<const std::uint8_t *>(value.data()), value.size()};
  }

  static ag_byte_slice bytes(const std::vector<std::uint8_t> &value) noexcept {
    return {value.data(), value.size()};
  }

  std::shared_ptr<detail::ServiceControl> require_control() const {
    if (!control_ || !control_->open.load()) {
      throw CogGateError(AG_STATUS_INVALID_ARGUMENT);
    }
    return control_;
  }

  static void reject_reentry(const detail::ServiceControl *control) {
    if (detail::is_active_service_call(control)) {
      throw CogGateError(AG_STATUS_INVALID_ARGUMENT);
    }
  }

  static void require_open(const detail::ServiceControl &control) {
    if (!control.open.load() || control.handle == nullptr) {
      throw CogGateError(AG_STATUS_INVALID_ARGUMENT);
    }
  }

  std::shared_ptr<detail::ServiceControl> control_;
};

} // namespace coggate

#endif /* COGGATE_CPP_COGGATE_HPP */
