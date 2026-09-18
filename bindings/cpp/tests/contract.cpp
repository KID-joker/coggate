#define COGGATE_CPP_TESTING 1
#include <coggate/coggate.hpp>

#include "../fixture_support.hpp"

#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <cstdint>
#include <exception>
#include <future>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

ag_status issue_owned_buffer_for_test(ag_owned_buffer *out) noexcept;

namespace {

struct FixtureVectors {
  std::string challenge_id;
  std::string nonce;
  std::string answer;
  std::string wrong_answer;
  std::vector<std::uint8_t> binding;
  std::vector<std::uint8_t> token;
  std::string active_key_id;
  std::vector<std::uint8_t> active_key;
  std::string old_key_id;
  std::vector<std::uint8_t> old_key;
  std::string private_material_json;
  std::string observer_allowlist_json;
};

struct FixtureCase {
  std::string id;
  std::string operation;
  std::optional<std::string> submission_json;
  std::string lifecycle_json;
  std::string keys_json;
  ag_status expected_status;
  std::string expected_code;
  std::optional<std::string> expected_outcome_json;
  std::string expected_trace_json;
  std::uint32_t expected_release_count;
  std::string forbidden_sentinels_json;
};

const FixtureVectors &fixture_vectors() {
  static const FixtureVectors value = [] {
    const auto &vectors = coggate_fixture::vectors();
    return FixtureVectors{
        vectors.at("challenge_id").get<std::string>(),
        vectors.at("nonce").get<std::string>(),
        vectors.at("answer").get<std::string>(),
        vectors.at("wrong_answer").get<std::string>(),
        coggate_fixture::vector_hex("binding_hex"),
        coggate_fixture::vector_hex("token_hex"),
        vectors.at("active_key_id").get<std::string>(),
        coggate_fixture::vector_hex("active_key_hex"),
        vectors.at("old_key_id").get<std::string>(),
        coggate_fixture::vector_hex("old_key_hex"),
        coggate_fixture::private_material_json(),
        vectors.at("observer_allowlist").dump()};
  }();
  return value;
}

const std::vector<FixtureCase> &fixture_cases() {
  static const std::vector<FixtureCase> values = [] {
    std::vector<FixtureCase> parsed;
    for (const auto &fixture : coggate_fixture::manifest().at("cases")) {
      parsed.push_back(FixtureCase{
          fixture.at("id").get<std::string>(),
          fixture.at("operation").get<std::string>(),
          fixture.at("submission").is_null()
              ? std::optional<std::string>{}
              : std::optional<std::string>{fixture.at("submission").dump()},
          fixture.at("lifecycle").dump(), fixture.at("keys").dump(),
          fixture.at("expected_status").get<ag_status>(),
          fixture.at("expected_code").get<std::string>(),
          fixture.at("expected_outcome").is_null()
              ? std::optional<std::string>{}
              : std::optional<std::string>{
                    fixture.at("expected_outcome").dump()},
          fixture.at("expected_trace").dump(),
          fixture.at("expected_release_count").get<std::uint32_t>(),
          fixture.at("forbidden_sentinels").dump()});
    }
    return parsed;
  }();
  return values;
}

#define CHECK(condition)                                                        \
  do {                                                                          \
    if (!(condition)) {                                                          \
      std::cerr << __FILE__ << ':' << __LINE__ << ": check failed: "           \
                << #condition << '\n';                                           \
      return false;                                                              \
    }                                                                            \
  } while (false)

template <typename Callable>
bool rejects_invalid_argument(Callable &&callable) {
  try {
    std::forward<Callable>(callable)();
  } catch (const std::invalid_argument &) {
    return true;
  } catch (...) {
  }
  return false;
}

template <typename Callable>
bool rejects_with_fixed_json_error(Callable &&callable) {
  try {
    std::forward<Callable>(callable)();
  } catch (const std::invalid_argument &error) {
    return std::string(error.what()) == "invalid CogGate JSON";
  } catch (...) {
  }
  return false;
}

bool model_contract() {
  using namespace coggate;

  try {
    (void)detail::with_json_errors([]() -> int { throw std::bad_alloc(); });
    return false;
  } catch (const std::bad_alloc &) {
  } catch (...) {
    return false;
  }

  const std::vector<std::uint8_t> binding{0x00, 0x11, 0x22};
  const IssueRequest request("1.0", binding, AttemptLimit::two);
  CHECK(request.version() == "1.0");
  CHECK(request.binding() == binding);
  CHECK(request.attempt_limit() == AttemptLimit::two);
  CHECK(IssueRequest::v1(binding).attempt_limit() == AttemptLimit::one);
  CHECK(rejects_invalid_argument(
      [] { IssueRequest("1.0", {}, AttemptLimit::one); }));
  CHECK(rejects_invalid_argument([] {
    IssueRequest("1.0", std::vector<std::uint8_t>(257), AttemptLimit::one);
  }));
  CHECK(rejects_invalid_argument([] {
    IssueRequest("1.0", {0x01}, static_cast<AttemptLimit>(99));
  }));

  const Submission submission = Submission::from_json(
      R"({"challenge_id":"id","nonce":"nonce","answer":"answer"})");
  CHECK(submission.challenge_id == "id");
  CHECK(submission.nonce == "nonce");
  CHECK(submission.answer == "answer");
  CHECK(submission.to_json() ==
        R"({"challenge_id":"id","nonce":"nonce","answer":"answer"})");
  CHECK(rejects_invalid_argument([] {
    Submission::from_json(
        R"({"challenge_id":"id","nonce":"nonce","answer":"SECRET","extra":true})");
  }));
  CHECK(rejects_invalid_argument([] {
    Submission::from_json(
        R"({"challenge_id":"id","nonce":7,"answer":"answer"})");
  }));
  CHECK(rejects_invalid_argument([] {
    Submission::from_json(R"({"challenge_id":"id","nonce":"nonce"})");
  }));
  CHECK(rejects_invalid_argument([] {
    Submission::from_json(
        R"({"challenge_id":"first","challenge_id":"second","nonce":"nonce","answer":"answer"})");
  }));
  std::string invalid_utf8 = "JSON_SECRET_SENTINEL_42";
  invalid_utf8.push_back(static_cast<char>(0xFF));
  Submission invalid_submission{"id", "nonce", invalid_utf8};
  CHECK(rejects_with_fixed_json_error(
      [&invalid_submission] { (void)invalid_submission.to_json(); }));

  const PublicChallenge challenge = PublicChallenge::from_json(
      R"({"challenge_id":"id","generator_version":"1.0","nonce":"nonce","issued_at":10,"expires_at":18,"question":"question","answer_encoding":"base64url"})");
  CHECK(challenge.challenge_id == "id");
  CHECK(challenge.generator_version == "1.0");
  CHECK(challenge.issued_at == 10);
  CHECK(challenge.answer_encoding() == AnswerEncoding::base64url);
  CHECK(challenge.to_json() ==
        R"({"challenge_id":"id","generator_version":"1.0","nonce":"nonce","issued_at":10,"expires_at":18,"question":"question","answer_encoding":"base64url"})");
  CHECK(rejects_invalid_argument([] {
    PublicChallenge::from_json(
        R"({"challenge_id":"id","generator_version":"1.0","nonce":"nonce","issued_at":10,"expires_at":18,"question":"SECRET","answer_encoding":"base64url","extra":0})");
  }));
  CHECK(rejects_invalid_argument([] {
    PublicChallenge::from_json(
        R"({"challenge_id":"id","generator_version":"1.0","nonce":"nonce","issued_at":"10","expires_at":18,"question":"question","answer_encoding":"base64url"})");
  }));
  CHECK(rejects_invalid_argument([] {
    PublicChallenge::from_json(
        R"({"challenge_id":"id","generator_version":"1.0","nonce":"nonce","issued_at":10,"expires_at":18,"question":"question","answer_encoding":"other"})");
  }));
  CHECK(rejects_invalid_argument([] {
    PublicChallenge::from_json(
        R"({"challenge_id":"first","challenge_id":"second","generator_version":"1.0","nonce":"nonce","issued_at":10,"expires_at":18,"question":"question","answer_encoding":"base64url"})");
  }));
  const PublicChallenge boundary_times = PublicChallenge::from_json(
      R"({"challenge_id":"id","generator_version":"1.0","nonce":"nonce","issued_at":-9223372036854775808,"expires_at":9223372036854775807,"question":"question","answer_encoding":"base64url"})");
  CHECK(boundary_times.issued_at == INT64_MIN);
  CHECK(boundary_times.expires_at == INT64_MAX);
  CHECK(rejects_invalid_argument([] {
    PublicChallenge::from_json(
        R"({"challenge_id":"id","generator_version":"1.0","nonce":"nonce","issued_at":18446744073709551615,"expires_at":18,"question":"question","answer_encoding":"base64url"})");
  }));
  PublicChallenge invalid_challenge = challenge;
  invalid_challenge.question = invalid_utf8;
  CHECK(rejects_with_fixed_json_error(
      [&invalid_challenge] { (void)invalid_challenge.to_json(); }));

  CHECK(VerificationOutcome::accepted().to_json() ==
        R"({"status":"accepted"})");
  CHECK(VerificationOutcome::from_json(
            R"({"status":"rejected","reason":"expired"})")
            .to_json() ==
        R"({"status":"rejected","reason":"expired"})");
  CHECK(rejects_invalid_argument([] {
    VerificationOutcome::from_json(
        R"({"status":"accepted","reason":"SECRET"})");
  }));
  CHECK(rejects_invalid_argument([] {
    VerificationOutcome::from_json(
        R"({"status":"rejected","reason":"unknown"})");
  }));
  CHECK(rejects_invalid_argument([] {
    (void)VerificationOutcome::rejected(static_cast<RejectionReason>(99));
  }));
  CHECK(rejects_invalid_argument([] {
    VerificationOutcome::from_json(
        R"({"status":"rejected","status":"accepted","reason":"expired"})");
  }));

  return true;
}

bool fixture_contract() {
  using namespace coggate;

  for (const FixtureCase &fixture : fixture_cases()) {
    if (fixture.submission_json) {
      const Submission submission = Submission::from_json(*fixture.submission_json);
      CHECK(!submission.challenge_id.empty());
      CHECK(!submission.nonce.empty());
      CHECK(!submission.answer.empty());
    }
    if (fixture.expected_outcome_json) {
      CHECK(VerificationOutcome::from_json(*fixture.expected_outcome_json)
                .to_json() == *fixture.expected_outcome_json);
    }
    if (fixture.expected_status != AG_STATUS_OK) {
      const CogGateError error(fixture.expected_status);
      CHECK(error.status() == fixture.expected_status);
      CHECK(error.code() == fixture.expected_code);
    }
  }
  return true;
}

bool status_contract() {
  using namespace coggate;
  const std::array<std::pair<ag_status, const char *>, 11> statuses{{
      {AG_STATUS_INVALID_CONFIGURATION, "invalid_configuration"},
      {AG_STATUS_GENERATION_FAILED, "generation_failed"},
      {AG_STATUS_INVALID_CHALLENGE_MATERIAL, "invalid_challenge_material"},
      {AG_STATUS_INVALID_ANSWER_ENCODING, "invalid_answer_encoding"},
      {AG_STATUS_ANSWER_MISMATCH, "answer_mismatch"},
      {AG_STATUS_UNSUPPORTED_GENERATOR_VERSION,
       "unsupported_generator_version"},
      {AG_STATUS_INTERNAL_ERROR, "internal_error"},
      {AG_STATUS_INVALID_ARGUMENT, "invalid_argument"},
      {AG_STATUS_CALLBACK_FAILED, "callback_failed"},
      {AG_STATUS_PANIC_CAUGHT, "panic_caught"},
      {AG_STATUS_OK, "ok"},
  }};
  for (const auto &entry : statuses) {
    const CogGateError error(entry.first);
    CHECK(error.status() == entry.first);
    CHECK(error.code() == entry.second);
    CHECK(std::string(error.what()) == entry.second);
  }
  try {
    (void)CogGateError(static_cast<ag_status>(-999));
    return false;
  } catch (const std::invalid_argument &error) {
    CHECK(std::string(error.what()) == "invalid CogGate status");
  } catch (...) {
    return false;
  }

  const std::string secret = "STATUS_INPUT_SECRET_48c2";
  try {
    Submission::from_json(secret);
  } catch (const std::invalid_argument &error) {
    CHECK(std::string(error.what()).find(secret) == std::string::npos);
    return true;
  }
  return false;
}

bool ownership_contract() {
  using namespace coggate;
  OwnedBuffer source;
  CHECK(source.empty());
  CHECK(source.string().empty());
  CHECK(rejects_invalid_argument([&source] { (void)source.json(); }));

  CHECK(issue_owned_buffer_for_test(
            detail::OwnedBufferTestAccess::output(source)) == AG_STATUS_OK);
  CHECK(!source.empty());
  CHECK(!source.string().empty());
  CHECK(source.json().is_object());
  ag_owned_buffer *source_raw = detail::OwnedBufferTestAccess::raw(source);
  std::uint8_t *const source_data = source_raw->data;
  const std::size_t source_len = source_raw->len;
  detail::OwnedBufferTestAccess::reset_free_calls();
  source_raw->data = nullptr;
  source.reset();
  CHECK(detail::OwnedBufferTestAccess::free_calls() == 0U);
  source_raw->data = source_data;
  source_raw->len = source_raw->capacity + 1U;
  CHECK(rejects_invalid_argument([&source] { (void)source.string(); }));
  source.reset();
  CHECK(detail::OwnedBufferTestAccess::free_calls() == 0U);
  source_raw->len = source_len;

  OwnedBuffer destination(std::move(source));
  CHECK(source.empty());
  CHECK(!destination.empty());

  OwnedBuffer assigned;
  CHECK(issue_owned_buffer_for_test(
            detail::OwnedBufferTestAccess::output(assigned)) == AG_STATUS_OK);
  const std::uint8_t *const old_data =
      detail::OwnedBufferTestAccess::raw(assigned)->data;
  const std::uint8_t *const incoming_data =
      detail::OwnedBufferTestAccess::raw(destination)->data;
  CHECK(old_data != incoming_data);
  detail::OwnedBufferTestAccess::reset_free_calls();
  assigned = std::move(destination);
  CHECK(destination.empty());
  CHECK(!assigned.empty());
  CHECK(detail::OwnedBufferTestAccess::free_calls() == 1U);
  CHECK(detail::OwnedBufferTestAccess::raw(assigned)->data == incoming_data);
  assigned.reset();
  CHECK(assigned.empty());
  CHECK(detail::OwnedBufferTestAccess::free_calls() == 2U);
  assigned.reset();
  CHECK(detail::OwnedBufferTestAccess::free_calls() == 2U);

  ag_owned_buffer raw = {};
  CHECK(issue_owned_buffer_for_test(&raw) == AG_STATUS_OK);
  const ag_owned_buffer original = raw;
  raw.len = raw.capacity + 1U;
  CHECK(rejects_invalid_argument([&raw] {
    (void)detail::OwnedBufferTestAccess::adopt(raw);
  }));
  raw = original;
  OwnedBuffer restored = detail::OwnedBufferTestAccess::adopt(raw);
  CHECK(raw.data == nullptr && raw.len == 0U && raw.capacity == 0U);
  CHECK(!restored.string().empty());
  restored.reset();

  CHECK(issue_owned_buffer_for_test(&raw) == AG_STATUS_OK);
  const ag_owned_buffer nonnull = raw;
  raw.data = nullptr;
  CHECK(rejects_invalid_argument([&raw] {
    (void)detail::OwnedBufferTestAccess::adopt(raw);
  }));
  raw = nonnull;
  restored = detail::OwnedBufferTestAccess::adopt(raw);
  CHECK(!restored.empty());
  return true;
}

struct FixtureState {
  const FixtureCase *fixture = nullptr;
  std::vector<std::string> trace;
  std::vector<std::string> observed;
  std::string requested_key_id;
  bool observer_throws = false;
};

ag_begin_status begin_status(std::string_view value) {
  if (value == "ok") return AG_BEGIN_STATUS_OK;
  if (value == "unavailable") return AG_BEGIN_STATUS_UNAVAILABLE;
  if (value == "conflict") return AG_BEGIN_STATUS_CONFLICT;
  if (value == "internal") return AG_BEGIN_STATUS_INTERNAL;
  if (value == "not_found") return AG_BEGIN_STATUS_NOT_FOUND;
  if (value == "expired") return AG_BEGIN_STATUS_EXPIRED;
  if (value == "already_consumed") return AG_BEGIN_STATUS_ALREADY_CONSUMED;
  if (value == "binding_mismatch") return AG_BEGIN_STATUS_BINDING_MISMATCH;
  if (value == "nonce_mismatch") return AG_BEGIN_STATUS_NONCE_MISMATCH;
  if (value == "attempts_exhausted") return AG_BEGIN_STATUS_ATTEMPTS_EXHAUSTED;
  return AG_BEGIN_STATUS_INTERNAL;
}

class FixtureLifecycle final : public coggate::Lifecycle {
public:
  explicit FixtureLifecycle(std::shared_ptr<FixtureState> state)
      : state_(std::move(state)) {}

  ag_lifecycle_status
  store_issued(std::string_view private_json,
               const std::vector<std::uint8_t> &binding,
               coggate::AttemptLimit attempt_limit) override {
    state_->trace.emplace_back("store_issued");
    stored_private.assign(private_json);
    stored_binding = binding;
    stored_limit = attempt_limit;
    if (throw_store) throw std::runtime_error("STORE_SECRET_SENTINEL");
    return AG_LIFECYCLE_STATUS_OK;
  }

  coggate::BeginAttemptResult
  begin_attempt(std::string_view, const std::vector<std::uint8_t> &,
                std::int64_t) override {
    const auto script = coggate::detail::Json::parse(state_->fixture->lifecycle_json);
    if (script.at("callback_exception").get<bool>()) {
      state_->trace.emplace_back("begin_attempt:exception");
      throw std::runtime_error("CALLBACK_EXCEPTION_SENTINEL");
    }
    state_->trace.emplace_back("begin_attempt");
    const ag_begin_status status =
        begin_status(script.at("begin_status").get<std::string>());
    if (status != AG_BEGIN_STATUS_OK) {
      return {status, {'M', 'A', 'T', 'E', 'R', 'I', 'A', 'L'},
              {'T', 'O', 'K', 'E', 'N'}};
    }
    const auto *material = reinterpret_cast<const std::uint8_t *>(
        fixture_vectors().private_material_json.data());
    return {status,
            {material,
             material +
                 fixture_vectors().private_material_json.size()},
            empty_token
                ? std::vector<std::uint8_t>{}
                : fixture_vectors().token};
  }

  ag_lifecycle_status
  finish_attempt(const std::vector<std::uint8_t> &token,
                 ag_attempt_outcome outcome) override {
    if ((!empty_token &&
         token != fixture_vectors().token) ||
        (empty_token && !token.empty())) {
      return AG_LIFECYCLE_STATUS_INTERNAL;
    }
    state_->trace.emplace_back(
        outcome == AG_ATTEMPT_OUTCOME_ACCEPTED
            ? "finish_attempt:accepted"
            : outcome == AG_ATTEMPT_OUTCOME_REJECTED
                  ? "finish_attempt:rejected"
                  : "finish_attempt:system_failure");
    if (throw_finish) throw std::runtime_error("FINISH_EXCEPTION_SENTINEL");
    const auto script = coggate::detail::Json::parse(state_->fixture->lifecycle_json);
    return script.at("finish_status").get<std::string>() == "internal"
               ? AG_LIFECYCLE_STATUS_INTERNAL
               : AG_LIFECYCLE_STATUS_OK;
  }

  bool throw_store = false;
  bool throw_finish = false;
  bool empty_token = false;
  std::string stored_private;
  std::vector<std::uint8_t> stored_binding;
  coggate::AttemptLimit stored_limit = coggate::AttemptLimit::one;

private:
  std::shared_ptr<FixtureState> state_;
};

class FixtureKeys final : public coggate::KeyProvider {
public:
  explicit FixtureKeys(std::shared_ptr<FixtureState> state)
      : state_(std::move(state)) {}

  coggate::ActiveKeyResult active_key() override {
    state_->trace.emplace_back("active_key");
    if (throw_active) throw std::runtime_error("KEY_EXCEPTION_SENTINEL");
    return {AG_KEY_STATUS_OK, fixture_vectors().active_key_id,
            fixture_vectors().active_key};
  }

  coggate::KeyResult key_by_id(std::string_view key_id) override {
    state_->requested_key_id.assign(key_id);
    state_->trace.emplace_back("key_by_id:old");
    if (throw_lookup) throw std::runtime_error("KEY_LOOKUP_SECRET_SENTINEL");
    return {AG_KEY_STATUS_OK, fixture_vectors().old_key};
  }

  bool throw_active = false;
  bool throw_lookup = false;

private:
  std::shared_ptr<FixtureState> state_;
};

class FixtureObserver final : public coggate::Observer {
public:
  explicit FixtureObserver(std::shared_ptr<FixtureState> state)
      : state_(std::move(state)) {}

  void observe(std::string_view event_json) override {
    state_->observed.emplace_back(event_json);
    const auto event = coggate::detail::Json::parse(event_json);
    state_->trace.emplace_back("observe:" + event.at("event").get<std::string>());
    if (state_->observer_throws) {
      throw std::runtime_error("OBSERVER_EXCEPTION_SENTINEL");
    }
  }

private:
  std::shared_ptr<FixtureState> state_;
};

void release_trace(const char *label, void *data) noexcept {
  auto *state = static_cast<FixtureState *>(data);
  try {
    state->trace.emplace_back(std::string("release:") +
                              (std::string_view(label) == "key" ? "key"
                               : std::string_view(label) == "material"
                                   ? "material"
                                   : std::string_view(label) == "token"
                                       ? "token"
                                       : label));
  } catch (...) {
  }
}

bool cpp_fixture_contract() {
  using namespace coggate;
  for (const auto &fixture : fixture_cases()) {
    auto state = std::make_shared<FixtureState>();
    state->fixture = &fixture;
    auto lifecycle = std::make_shared<FixtureLifecycle>(state);
    auto keys = std::make_shared<FixtureKeys>(state);
    auto observer = std::make_shared<FixtureObserver>(state);
    Service service(lifecycle, keys,
                    fixture.operation == "release"
                        ? std::shared_ptr<Observer>{}
                        : observer);
    if (fixture.operation == "close") {
      const auto before = detail::ServiceTestAccess::destroy_calls();
      service.close();
      service.close();
      CHECK(detail::ServiceTestAccess::destroy_calls() == before + 1U);
      state->trace.emplace_back("service_destroy");
      CHECK(state->trace ==
            detail::Json::parse(fixture.expected_trace_json)
                .get<std::vector<std::string>>());
      CHECK(fixture.expected_release_count == 0U);
      continue;
    }
    detail::CallbackBufferTestAccess::set_release_hook(release_trace,
                                                       state.get());
    std::optional<std::string> outcome;
    std::optional<CogGateError> error;
    try {
      outcome = service
                    .verify(Submission::from_json(*fixture.submission_json),
                            fixture_vectors().binding)
                    .to_json();
    } catch (const CogGateError &caught) {
      error = caught;
    }
    detail::CallbackBufferTestAccess::set_release_hook(nullptr);
    if (fixture.expected_status == AG_STATUS_OK) {
      CHECK(outcome.has_value());
      CHECK(outcome == fixture.expected_outcome_json);
      CHECK(!error.has_value());
    } else {
      CHECK(!outcome.has_value());
      CHECK(error.has_value());
      CHECK(error->status() == fixture.expected_status);
      CHECK(error->code() == fixture.expected_code);
      CHECK(std::string(error->what()).find("SENTINEL") == std::string::npos);
    }
    const auto expected =
        detail::Json::parse(fixture.expected_trace_json)
            .get<std::vector<std::string>>();
    CHECK(state->trace == expected);
    CHECK(static_cast<std::uint32_t>(std::count_if(
              state->trace.begin(), state->trace.end(),
              [](const std::string &entry) {
                return entry.rfind("release:", 0U) == 0U;
              })) == fixture.expected_release_count);
    CHECK(detail::CallbackBufferTestAccess::outstanding() == 0U);
    if (state->requested_key_id.size() != 0U) {
      CHECK(state->requested_key_id == fixture_vectors().old_key_id);
    }
    for (const auto &event_json : state->observed) {
      const auto event = detail::Json::parse(event_json);
      const auto allowlist = event.at("event") == "service_failed"
                                 ? std::vector<std::string>{
                                       "event", "challenge_id",
                                       "generator_version", "stage", "error",
                                       "attempts", "duration_us"}
                                 : detail::Json::parse(
                                       fixture_vectors().observer_allowlist_json)
                                       .get<std::vector<std::string>>();
      for (auto item = event.begin(); item != event.end(); ++item) {
        CHECK(std::find(allowlist.begin(), allowlist.end(), item.key()) !=
              allowlist.end());
      }
      CHECK(event_json.find(fixture_vectors().answer) ==
            std::string::npos);
      CHECK(event_json.find(fixture_vectors().nonce) ==
            std::string::npos);
      CHECK(event_json.find(fixture_vectors().old_key_id) ==
            std::string::npos);
    }
    std::string public_text = outcome.value_or("");
    if (error) public_text += error->what();
    for (const auto &event_json : state->observed) public_text += event_json;
    for (const auto &sentinel :
         detail::Json::parse(fixture.forbidden_sentinels_json)
             .get<std::vector<std::string>>()) {
      CHECK(public_text.find(sentinel) == std::string::npos);
    }
  }
  return true;
}

class ReentrantLifecycle final : public coggate::Lifecycle {
public:
  ag_lifecycle_status
  store_issued(std::string_view, const std::vector<std::uint8_t> &,
               coggate::AttemptLimit) override {
    return AG_LIFECYCLE_STATUS_OK;
  }

  coggate::BeginAttemptResult
  begin_attempt(std::string_view, const std::vector<std::uint8_t> &,
                std::int64_t) override {
    try {
      (void)service->verify(
          coggate::Submission::from_json(
              R"({"challenge_id":"id","nonce":"nonce","answer":"answer"})"),
          {0x01});
    } catch (const coggate::CogGateError &error) {
      rejected = error.status() == AG_STATUS_INVALID_ARGUMENT &&
                 std::string(error.what()) == "invalid_argument";
    }
    return {AG_BEGIN_STATUS_NOT_FOUND, {}, {}};
  }

  ag_lifecycle_status
  finish_attempt(const std::vector<std::uint8_t> &,
                 ag_attempt_outcome) override {
    return AG_LIFECYCLE_STATUS_OK;
  }

  coggate::Service *service = nullptr;
  bool rejected = false;
};

class BlockingLifecycle final : public coggate::Lifecycle {
public:
  ag_lifecycle_status
  store_issued(std::string_view, const std::vector<std::uint8_t> &,
               coggate::AttemptLimit) override {
    return AG_LIFECYCLE_STATUS_OK;
  }

  coggate::BeginAttemptResult
  begin_attempt(std::string_view, const std::vector<std::uint8_t> &,
                std::int64_t) override {
    std::unique_lock<std::mutex> lock(mutex);
    entered = true;
    entered_cv.notify_all();
    release_cv.wait(lock, [this] { return released; });
    return {AG_BEGIN_STATUS_NOT_FOUND, {}, {}};
  }

  ag_lifecycle_status
  finish_attempt(const std::vector<std::uint8_t> &,
                 ag_attempt_outcome) override {
    return AG_LIFECYCLE_STATUS_OK;
  }

  std::mutex mutex;
  std::condition_variable entered_cv;
  std::condition_variable release_cv;
  bool entered = false;
  bool released = false;
};

class NestedLifecycle final : public coggate::Lifecycle {
public:
  ag_lifecycle_status
  store_issued(std::string_view, const std::vector<std::uint8_t> &,
               coggate::AttemptLimit) override {
    return AG_LIFECYCLE_STATUS_OK;
  }
  coggate::BeginAttemptResult
  begin_attempt(std::string_view, const std::vector<std::uint8_t> &,
                std::int64_t) override {
    if (action) action();
    return {AG_BEGIN_STATUS_NOT_FOUND, {}, {}};
  }
  ag_lifecycle_status
  finish_attempt(const std::vector<std::uint8_t> &,
                 ag_attempt_outcome) override {
    return AG_LIFECYCLE_STATUS_OK;
  }
  std::function<void()> action;
};

class ReentrantKeys final : public coggate::KeyProvider {
public:
  coggate::ActiveKeyResult active_key() override {
    try {
      (void)service->issue(coggate::IssueRequest::v1({0x01}));
    } catch (const coggate::CogGateError &error) {
      rejected = error.status() == AG_STATUS_INVALID_ARGUMENT;
    }
    return {AG_KEY_STATUS_OK, fixture_vectors().active_key_id,
            fixture_vectors().active_key};
  }
  coggate::KeyResult key_by_id(std::string_view) override {
    return {AG_KEY_STATUS_NOT_FOUND, {}};
  }
  coggate::Service *service = nullptr;
  bool rejected = false;
};

class ReentrantObserver final : public coggate::Observer {
public:
  void observe(std::string_view) override {
    try {
      service->close();
    } catch (const coggate::CogGateError &error) {
      rejected = error.status() == AG_STATUS_INVALID_ARGUMENT &&
                 std::string(error.what()) == "invalid_argument";
    }
  }
  coggate::Service *service = nullptr;
  bool rejected = false;
};

bool service_lifecycle_contract() {
  using namespace coggate;
  const auto &accepted_case = coggate_fixture::fixture_by_id("accepted");
  const auto &accepted = *std::find_if(
      fixture_cases().begin(), fixture_cases().end(), [](const auto &fixture) {
        return fixture.id == "accepted";
      });
  CHECK(accepted.id == accepted_case.at("id").get<std::string>());
  auto state = std::make_shared<FixtureState>();
  state->fixture = &accepted;
  auto lifecycle = std::make_shared<FixtureLifecycle>(state);
  auto keys = std::make_shared<FixtureKeys>(state);
  auto observer = std::make_shared<FixtureObserver>(state);
  std::weak_ptr<FixtureLifecycle> lifecycle_lifetime = lifecycle;
  Service issued(lifecycle, keys, observer);
  lifecycle.reset();
  keys.reset();
  observer.reset();
  detail::CallbackBufferTestAccess::set_release_hook(release_trace,
                                                     state.get());
  const PublicChallenge challenge = issued.issue(IssueRequest::v1(
      fixture_vectors().binding,
      AttemptLimit::two));
  detail::CallbackBufferTestAccess::set_release_hook(nullptr);
  CHECK(!challenge.challenge_id.empty());
  CHECK(!lifecycle_lifetime.expired());
  const auto kept_lifecycle = lifecycle_lifetime.lock();
  CHECK(kept_lifecycle != nullptr);
  CHECK(!kept_lifecycle->stored_private.empty());
  CHECK(kept_lifecycle->stored_binding ==
        fixture_vectors().binding);
  CHECK(kept_lifecycle->stored_limit == AttemptLimit::two);
  CHECK(std::count_if(state->trace.begin(), state->trace.end(),
                      [](const std::string &entry) {
                        return entry.rfind("release:active_key", 0U) == 0U;
                      }) == 2);
  CHECK(detail::CallbackBufferTestAccess::outstanding() == 0U);

  auto reentrant = std::make_shared<ReentrantLifecycle>();
  auto reentrant_keys = std::make_shared<FixtureKeys>(state);
  Service reentry_service(reentrant, reentrant_keys);
  reentrant->service = &reentry_service;
  const auto rejected = reentry_service.verify(
      Submission::from_json(*accepted.submission_json), fixture_vectors().binding);
  CHECK(rejected.to_json() ==
        R"({"status":"rejected","reason":"not_found"})");
  CHECK(reentrant->rejected);
  reentry_service.close();

  auto nested_a = std::make_shared<NestedLifecycle>();
  auto nested_b = std::make_shared<NestedLifecycle>();
  Service service_a(nested_a, std::make_shared<FixtureKeys>(state));
  Service service_b(nested_b, std::make_shared<FixtureKeys>(state));
  bool cross_service_entered = false;
  bool cycle_rejected = false;
  nested_a->action = [&] {
    cross_service_entered =
        service_b
            .verify(Submission::from_json(*accepted.submission_json), {0x01})
            .status() == VerificationStatus::rejected;
  };
  nested_b->action = [&] {
    try {
      (void)service_a.verify(Submission::from_json(*accepted.submission_json),
                             {0x01});
    } catch (const CogGateError &error) {
      cycle_rejected = error.status() == AG_STATUS_INVALID_ARGUMENT;
    }
  };
  CHECK(service_a
            .verify(Submission::from_json(*accepted.submission_json), {0x01})
            .status() == VerificationStatus::rejected);
  CHECK(cross_service_entered);
  CHECK(cycle_rejected);
  service_a.close();
  service_b.close();

  auto reentrant_key = std::make_shared<ReentrantKeys>();
  Service key_reentry_service(std::make_shared<FixtureLifecycle>(state),
                              reentrant_key);
  reentrant_key->service = &key_reentry_service;
  CHECK(!key_reentry_service.issue(IssueRequest::v1({0x01})).challenge_id.empty());
  CHECK(reentrant_key->rejected);
  key_reentry_service.close();

  auto reentrant_observer = std::make_shared<ReentrantObserver>();
  Service observer_reentry_service(std::make_shared<FixtureLifecycle>(state),
                                   std::make_shared<FixtureKeys>(state),
                                   reentrant_observer);
  reentrant_observer->service = &observer_reentry_service;
  CHECK(!observer_reentry_service.issue(IssueRequest::v1({0x01}))
             .challenge_id.empty());
  CHECK(reentrant_observer->rejected);
  observer_reentry_service.close();

  state->observer_throws = true;
  auto throwing_lifecycle = std::make_shared<FixtureLifecycle>(state);
  auto throwing_keys = std::make_shared<FixtureKeys>(state);
  auto throwing_observer = std::make_shared<FixtureObserver>(state);
  Service observer_service(throwing_lifecycle, throwing_keys,
                           throwing_observer);
  CHECK(observer_service
            .verify(Submission::from_json(*accepted.submission_json),
                    fixture_vectors().binding)
            .status() == VerificationStatus::accepted);
  observer_service.close();

  auto store_exception = std::make_shared<FixtureLifecycle>(state);
  store_exception->throw_store = true;
  Service store_exception_service(store_exception,
                                  std::make_shared<FixtureKeys>(state));
  try {
    (void)store_exception_service.issue(IssueRequest::v1({0x01}));
    return false;
  } catch (const CogGateError &error) {
    CHECK(error.status() == AG_STATUS_INTERNAL_ERROR);
    CHECK(std::string(error.what()) == "internal_error");
  }
  store_exception_service.close();

  auto finish_exception = std::make_shared<FixtureLifecycle>(state);
  finish_exception->throw_finish = true;
  Service finish_exception_service(finish_exception,
                                   std::make_shared<FixtureKeys>(state));
  try {
    (void)finish_exception_service.verify(
        Submission::from_json(*accepted.submission_json), {0x01});
    return false;
  } catch (const CogGateError &error) {
    CHECK(error.status() == AG_STATUS_INTERNAL_ERROR);
    CHECK(std::string(error.what()).find("FINISH_EXCEPTION_SENTINEL") ==
          std::string::npos);
  }
  finish_exception_service.close();

  auto lookup_exception = std::make_shared<FixtureKeys>(state);
  lookup_exception->throw_lookup = true;
  state->trace.clear();
  Service lookup_exception_service(std::make_shared<FixtureLifecycle>(state),
                                   lookup_exception);
  detail::CallbackBufferTestAccess::set_release_hook(release_trace,
                                                     state.get());
  try {
    (void)lookup_exception_service.verify(
        Submission::from_json(*accepted.submission_json), {0x01});
    return false;
  } catch (const CogGateError &error) {
    detail::CallbackBufferTestAccess::set_release_hook(nullptr);
    CHECK(error.status() == AG_STATUS_INTERNAL_ERROR);
    CHECK(std::string(error.what()).find("KEY_LOOKUP_SECRET_SENTINEL") ==
          std::string::npos);
  }
  CHECK(state->trace ==
        std::vector<std::string>({"begin_attempt", "release:token",
                                  "release:material", "key_by_id:old",
                                  "finish_attempt:system_failure"}));
  CHECK(std::count(state->trace.begin(), state->trace.end(),
                   "finish_attempt:system_failure") == 1);
  CHECK(detail::CallbackBufferTestAccess::outstanding() == 0U);
  lookup_exception_service.close();

  auto active_exception = std::make_shared<FixtureKeys>(state);
  active_exception->throw_active = true;
  Service active_exception_service(std::make_shared<FixtureLifecycle>(state),
                                   active_exception);
  try {
    (void)active_exception_service.issue(IssueRequest::v1({0x01}));
    return false;
  } catch (const CogGateError &error) {
    CHECK(error.status() == AG_STATUS_INTERNAL_ERROR);
    CHECK(std::string(error.what()).find("KEY_EXCEPTION_SENTINEL") ==
          std::string::npos);
  }
  active_exception_service.close();

  auto allocation_lifecycle = std::make_shared<FixtureLifecycle>(state);
  Service allocation_service(allocation_lifecycle,
                             std::make_shared<FixtureKeys>(state));
  detail::CallbackBufferTestAccess::fail_after(1);
  try {
    (void)allocation_service.verify(
        Submission::from_json(*accepted.submission_json), {0x01});
    detail::CallbackBufferTestAccess::fail_after(-1);
    return false;
  } catch (const CogGateError &error) {
    detail::CallbackBufferTestAccess::fail_after(-1);
    CHECK(error.status() == AG_STATUS_INTERNAL_ERROR);
    CHECK(std::string(error.what()).find("SENTINEL") == std::string::npos);
  }
  CHECK(detail::CallbackBufferTestAccess::outstanding() == 0U);
  allocation_service.close();

  Service key_allocation_service(std::make_shared<FixtureLifecycle>(state),
                                 std::make_shared<FixtureKeys>(state));
  detail::CallbackBufferTestAccess::fail_after(1);
  try {
    (void)key_allocation_service.issue(IssueRequest::v1({0x01}));
    detail::CallbackBufferTestAccess::fail_after(-1);
    return false;
  } catch (const CogGateError &error) {
    detail::CallbackBufferTestAccess::fail_after(-1);
    CHECK(error.status() == AG_STATUS_INTERNAL_ERROR);
  }
  CHECK(detail::CallbackBufferTestAccess::outstanding() == 0U);
  key_allocation_service.close();

  auto empty_token_lifecycle = std::make_shared<FixtureLifecycle>(state);
  empty_token_lifecycle->empty_token = true;
  Service empty_token_service(empty_token_lifecycle,
                              std::make_shared<FixtureKeys>(state));
  CHECK(empty_token_service
            .verify(Submission::from_json(*accepted.submission_json), {0x01})
            .status() == VerificationStatus::accepted);
  CHECK(detail::CallbackBufferTestAccess::outstanding() == 0U);
  empty_token_service.close();

  auto blocking = std::make_shared<BlockingLifecycle>();
  auto blocking_keys = std::make_shared<FixtureKeys>(state);
  Service blocked_service(blocking, blocking_keys);
  auto verify_future = std::async(std::launch::async, [&] {
    return blocked_service.verify(Submission::from_json(*accepted.submission_json),
                                  {0x01});
  });
  bool entered_in_time = false;
  {
    std::unique_lock<std::mutex> lock(blocking->mutex);
    entered_in_time = blocking->entered_cv.wait_for(
        lock, std::chrono::seconds(2), [&] { return blocking->entered; });
  }
  if (!entered_in_time) {
    {
      std::lock_guard<std::mutex> lock(blocking->mutex);
      blocking->released = true;
    }
    blocking->release_cv.notify_all();
    try {
      (void)verify_future.get();
    } catch (...) {
    }
    blocked_service.close();
    return false;
  }
  auto close_future = std::async(std::launch::async,
                                 [&] { return blocked_service.close(); });
  const auto close_wait = close_future.wait_for(std::chrono::milliseconds(40));
  {
    std::lock_guard<std::mutex> lock(blocking->mutex);
    blocking->released = true;
  }
  blocking->release_cv.notify_all();
  if (close_wait != std::future_status::timeout) {
    try {
      (void)verify_future.get();
    } catch (...) {
    }
    (void)close_future.get();
    return false;
  }
  CHECK(verify_future.get().status() == VerificationStatus::rejected);
  close_future.get();
  CHECK(!blocked_service.is_open());

  detail::ServiceTestAccess::reset_destroy_calls();
  Service first(std::make_shared<FixtureLifecycle>(state),
                std::make_shared<FixtureKeys>(state));
  Service moved(std::move(first));
  CHECK(!first.is_open());
  CHECK(moved.is_open());
  try {
    (void)first.issue(IssueRequest::v1({0x01}));
    return false;
  } catch (const CogGateError &error) {
    CHECK(error.status() == AG_STATUS_INVALID_ARGUMENT);
  }
  Service assigned(std::make_shared<FixtureLifecycle>(state),
                   std::make_shared<FixtureKeys>(state));
  assigned = std::move(moved);
  CHECK(!moved.is_open());
  CHECK(assigned.is_open());
  CHECK(detail::ServiceTestAccess::destroy_calls() == 1U);
  CHECK(!assigned.issue(IssueRequest::v1({0x01})).challenge_id.empty());
  assigned.close();
  assigned.close();
  CHECK(detail::ServiceTestAccess::destroy_calls() == 2U);
  first.close();
  moved.close();
  CHECK(detail::ServiceTestAccess::destroy_calls() == 2U);
  issued.close();
  return true;
}

class RedLifecycle final : public coggate::Lifecycle {
public:
  ag_lifecycle_status
  store_issued(std::string_view, const std::vector<std::uint8_t> &,
               coggate::AttemptLimit) override {
    return AG_LIFECYCLE_STATUS_OK;
  }

  coggate::BeginAttemptResult
  begin_attempt(std::string_view, const std::vector<std::uint8_t> &,
                std::int64_t) override {
    return {AG_BEGIN_STATUS_INTERNAL, {0x53, 0x45, 0x43, 0x52, 0x45, 0x54},
            {0x54, 0x4f, 0x4b, 0x45, 0x4e}};
  }

  ag_lifecycle_status
  finish_attempt(const std::vector<std::uint8_t> &,
                 ag_attempt_outcome) override {
    return AG_LIFECYCLE_STATUS_OK;
  }
};

class RedKeys final : public coggate::KeyProvider {
public:
  coggate::ActiveKeyResult active_key() override {
    return {AG_KEY_STATUS_OK, "active-2026-09",
            std::vector<std::uint8_t>(32U, 0x11)};
  }

  coggate::KeyResult key_by_id(std::string_view) override {
    return {AG_KEY_STATUS_NOT_FOUND, {}};
  }
};

bool service_red_contract() {
  using namespace coggate;
  auto lifecycle = std::make_shared<RedLifecycle>();
  auto keys = std::make_shared<RedKeys>();
  Service service(lifecycle, keys);
  try {
    (void)service.verify(
        Submission::from_json(
            R"({"challenge_id":"id","nonce":"nonce","answer":"answer"})"),
        {0x01});
    return false;
  } catch (const CogGateError &error) {
    CHECK(error.status() == AG_STATUS_INTERNAL_ERROR);
  }
  CHECK(detail::CallbackBufferTestAccess::outstanding() == 0U);
  service.close();
  service.close();
  try {
    (void)service.issue(IssueRequest::v1({0x01}));
    return false;
  } catch (const CogGateError &error) {
    CHECK(error.status() == AG_STATUS_INVALID_ARGUMENT);
    CHECK(std::string(error.what()) == "invalid_argument");
  }
  return true;
}

} // namespace

static_assert(!std::is_copy_constructible_v<coggate::OwnedBuffer>);
static_assert(!std::is_copy_assignable_v<coggate::OwnedBuffer>);
static_assert(
    !std::is_constructible_v<coggate::OwnedBuffer, ag_owned_buffer>);
static_assert(std::is_nothrow_move_constructible_v<coggate::OwnedBuffer>);
static_assert(std::is_nothrow_move_assignable_v<coggate::OwnedBuffer>);
static_assert(std::is_nothrow_destructible_v<coggate::OwnedBuffer>);

static_assert(!std::is_aggregate_v<coggate::PublicChallenge>);
static_assert(std::is_same_v<
              decltype(std::declval<const coggate::PublicChallenge &>()
                           .answer_encoding()),
              coggate::AnswerEncoding>);
static_assert(!std::is_constructible_v<
              coggate::PublicChallenge, std::string, std::string,
              std::string, std::int64_t, std::int64_t, std::string,
              coggate::AnswerEncoding>);

static_assert(!std::is_copy_constructible_v<coggate::Service>);
static_assert(!std::is_copy_assignable_v<coggate::Service>);
static_assert(!std::is_constructible_v<coggate::Service, ag_service *>);
static_assert(std::is_nothrow_move_constructible_v<coggate::Service>);
static_assert(std::is_nothrow_move_assignable_v<coggate::Service>);
static_assert(std::is_nothrow_destructible_v<coggate::Service>);
static_assert(std::is_same_v<
              decltype(std::declval<coggate::Service &>().close()), void>);
static_assert(!noexcept(std::declval<coggate::Service &>().close()));
static_assert(std::has_virtual_destructor_v<coggate::Lifecycle>);
static_assert(std::has_virtual_destructor_v<coggate::KeyProvider>);
static_assert(std::has_virtual_destructor_v<coggate::Observer>);
static_assert(noexcept(coggate::detail::release_callback_buffer(
    nullptr, nullptr, 0U)));
static_assert(noexcept(coggate::detail::CallbackBridge::store_issued(
    nullptr, {}, {}, AG_ATTEMPT_LIMIT_ONE)));
static_assert(noexcept(coggate::detail::CallbackBridge::begin_attempt(
    nullptr, {}, {}, 0, nullptr, nullptr)));
static_assert(noexcept(coggate::detail::CallbackBridge::finish_attempt(
    nullptr, {}, AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE)));
static_assert(noexcept(coggate::detail::CallbackBridge::active_key(
    nullptr, nullptr, nullptr)));
static_assert(noexcept(coggate::detail::CallbackBridge::key_by_id(
    nullptr, {}, nullptr)));
static_assert(noexcept(
    coggate::detail::CallbackBridge::observe(nullptr, {})));

int main() {
  return model_contract() && fixture_contract() && status_contract() &&
                 ownership_contract() && service_red_contract() &&
                 cpp_fixture_contract() && service_lifecycle_contract()
             ? 0
             : 1;
}
