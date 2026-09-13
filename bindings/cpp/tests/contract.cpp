#define AGENTGATE_CPP_TESTING 1
#include <agentgate/agentgate.hpp>

#include "../../c/tests/generated_fixtures.h"

#include <array>
#include <cstdint>
#include <exception>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

ag_status issue_owned_buffer_for_test(ag_owned_buffer *out) noexcept;

namespace {

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
    return std::string(error.what()) == "invalid AgentGate JSON";
  } catch (...) {
  }
  return false;
}

bool model_contract() {
  using namespace agentgate;

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
  using namespace agentgate;

  for (std::size_t index = 0; index < AG_BINDING_FIXTURE_CASE_COUNT; ++index) {
    const ag_binding_fixture_case &fixture = AG_BINDING_FIXTURE_CASES[index];
    if (fixture.submission_json != nullptr) {
      const Submission submission = Submission::from_json(fixture.submission_json);
      CHECK(!submission.challenge_id.empty());
      CHECK(!submission.nonce.empty());
      CHECK(!submission.answer.empty());
    }
    if (fixture.expected_outcome_json != nullptr) {
      CHECK(VerificationOutcome::from_json(fixture.expected_outcome_json).to_json() ==
            fixture.expected_outcome_json);
    }
    if (fixture.expected_status != AG_STATUS_OK) {
      const AgentGateError error(fixture.expected_status);
      CHECK(error.status() == fixture.expected_status);
      CHECK(error.code() == fixture.expected_code);
    }
  }
  return true;
}

bool status_contract() {
  using namespace agentgate;
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
    const AgentGateError error(entry.first);
    CHECK(error.status() == entry.first);
    CHECK(error.code() == entry.second);
    CHECK(std::string(error.what()) == entry.second);
  }
  try {
    (void)AgentGateError(static_cast<ag_status>(-999));
    return false;
  } catch (const std::invalid_argument &error) {
    CHECK(std::string(error.what()) == "invalid AgentGate status");
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
  using namespace agentgate;
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

} // namespace

static_assert(!std::is_copy_constructible_v<agentgate::OwnedBuffer>);
static_assert(!std::is_copy_assignable_v<agentgate::OwnedBuffer>);
static_assert(
    !std::is_constructible_v<agentgate::OwnedBuffer, ag_owned_buffer>);
static_assert(std::is_nothrow_move_constructible_v<agentgate::OwnedBuffer>);
static_assert(std::is_nothrow_move_assignable_v<agentgate::OwnedBuffer>);
static_assert(std::is_nothrow_destructible_v<agentgate::OwnedBuffer>);

static_assert(!std::is_aggregate_v<agentgate::PublicChallenge>);
static_assert(std::is_same_v<
              decltype(std::declval<const agentgate::PublicChallenge &>()
                           .answer_encoding()),
              agentgate::AnswerEncoding>);
static_assert(!std::is_constructible_v<
              agentgate::PublicChallenge, std::string, std::string,
              std::string, std::int64_t, std::int64_t, std::string,
              agentgate::AnswerEncoding>);

static_assert(!std::is_copy_constructible_v<agentgate::Service>);
static_assert(!std::is_copy_assignable_v<agentgate::Service>);
static_assert(!std::is_constructible_v<agentgate::Service, ag_service *>);
static_assert(std::is_nothrow_move_constructible_v<agentgate::Service>);
static_assert(std::is_nothrow_move_assignable_v<agentgate::Service>);
static_assert(std::is_nothrow_destructible_v<agentgate::Service>);

int main() {
  return model_contract() && fixture_contract() && status_contract() &&
                 ownership_contract()
             ? 0
             : 1;
}
