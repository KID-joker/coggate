#ifndef AGENTGATE_CPP_AGENTGATE_HPP
#define AGENTGATE_CPP_AGENTGATE_HPP

#include "agentgate.h"

#include <nlohmann/json.hpp>

#if !defined(NLOHMANN_JSON_VERSION_MAJOR) ||                                 \
    !defined(NLOHMANN_JSON_VERSION_MINOR) ||                                 \
    NLOHMANN_JSON_VERSION_MAJOR < 3 ||                                       \
    (NLOHMANN_JSON_VERSION_MAJOR == 3 && NLOHMANN_JSON_VERSION_MINOR < 11)
#error "AgentGate C++ requires nlohmann/json 3.11 or newer"
#endif

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace agentgate {

namespace detail {

using Json = nlohmann::ordered_json;

[[noreturn]] inline void invalid_json() {
  throw std::invalid_argument("invalid AgentGate JSON");
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
    throw std::invalid_argument("invalid AgentGate status");
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
      throw std::invalid_argument("invalid AgentGate binding");
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
      throw std::invalid_argument("invalid AgentGate answer encoding");
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
    throw std::invalid_argument("invalid AgentGate rejection reason");
  }

  VerificationStatus status_;
  std::optional<RejectionReason> reason_;
};

class AgentGateError : public std::runtime_error {
public:
  explicit AgentGateError(ag_status status)
      : AgentGateError(status, detail::require_status_code(status)) {}

  ag_status status() const noexcept { return status_; }
  const std::string &code() const noexcept { return code_; }

private:
  AgentGateError(ag_status status, const char *code)
      : std::runtime_error(code), status_(status), code_(code) {}

  ag_status status_;
  std::string code_;
};

#ifdef AGENTGATE_CPP_TESTING
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
#ifdef AGENTGATE_CPP_TESTING
      ++test_free_calls();
#endif
      (void)ag_buffer_free(&raw_);
    }
  }

private:
  friend class Service;
#ifdef AGENTGATE_CPP_TESTING
  friend class detail::OwnedBufferTestAccess;
#endif

  static bool allocated(const ag_owned_buffer &raw) noexcept {
    return raw.data != nullptr && raw.len <= raw.capacity;
  }

  static void validate(const ag_owned_buffer &raw) {
    if (raw.data == nullptr) {
      if (raw.len != 0U || raw.capacity != 0U) {
        throw std::invalid_argument("invalid AgentGate buffer");
      }
      return;
    }
    if (raw.len > raw.capacity) {
      throw std::invalid_argument("invalid AgentGate buffer");
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
      throw std::invalid_argument("AgentGate output buffer is not empty");
    }
    return &raw_;
  }

#ifdef AGENTGATE_CPP_TESTING
  static std::size_t &test_free_calls() noexcept {
    static std::size_t calls = 0U;
    return calls;
  }
#endif

  ag_owned_buffer raw_{};
};

#ifdef AGENTGATE_CPP_TESTING
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

class Service {
public:
  Service() noexcept = default;
  ~Service() noexcept { (void)close(); }

  Service(const Service &) = delete;
  Service &operator=(const Service &) = delete;

  Service(Service &&other) noexcept
      : handle_(std::exchange(other.handle_, nullptr)) {}

  Service &operator=(Service &&other) noexcept {
    if (this != &other) {
      (void)close();
      handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
  }

  bool is_open() const noexcept { return handle_ != nullptr; }

  ag_status close() noexcept {
    if (handle_ == nullptr) {
      return AG_STATUS_OK;
    }
    ag_service *handle = std::exchange(handle_, nullptr);
    return ag_service_destroy(handle);
  }

private:
  ag_service *handle_ = nullptr;
};

} // namespace agentgate

#endif /* AGENTGATE_CPP_AGENTGATE_HPP */
