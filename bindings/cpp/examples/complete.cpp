#include <coggate/coggate.hpp>

#include "../fixture_support.hpp"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct State {
  State()
      : vectors(coggate_fixture::vectors()),
        binding(coggate_fixture::vector_hex("binding_hex")),
        token(coggate_fixture::vector_hex("token_hex")),
        active_key(coggate_fixture::vector_hex("active_key_hex")),
        old_key(coggate_fixture::vector_hex("old_key_hex")),
        private_material(coggate_fixture::private_material_json()) {}

  const coggate_fixture::Json &vectors;
  std::vector<std::uint8_t> binding;
  std::vector<std::uint8_t> token;
  std::vector<std::uint8_t> active_key;
  std::vector<std::uint8_t> old_key;
  std::string private_material;
  std::size_t key_by_id_calls = 0U;
  std::size_t finish_calls = 0U;
  ag_attempt_outcome finish_outcome = 0;
};

class ExampleLifecycle final : public coggate::Lifecycle {
public:
  explicit ExampleLifecycle(std::shared_ptr<State> state)
      : state_(std::move(state)) {}

  ag_lifecycle_status
  store_issued(std::string_view, const std::vector<std::uint8_t> &binding,
               coggate::AttemptLimit) override {
    return binding == state_->binding ? AG_LIFECYCLE_STATUS_OK
                                      : AG_LIFECYCLE_STATUS_INTERNAL;
  }

  coggate::BeginAttemptResult
  begin_attempt(std::string_view, const std::vector<std::uint8_t> &binding,
                std::int64_t) override {
    if (binding != state_->binding) {
      return {AG_BEGIN_STATUS_BINDING_MISMATCH, {}, {}};
    }
    return {AG_BEGIN_STATUS_OK,
            {state_->private_material.begin(), state_->private_material.end()},
            state_->token};
  }

  ag_lifecycle_status
  finish_attempt(const std::vector<std::uint8_t> &token,
                 ag_attempt_outcome outcome) override {
    ++state_->finish_calls;
    state_->finish_outcome = outcome;
    return token == state_->token ? AG_LIFECYCLE_STATUS_OK
                                  : AG_LIFECYCLE_STATUS_INTERNAL;
  }

private:
  std::shared_ptr<State> state_;
};

class ExampleKeys final : public coggate::KeyProvider {
public:
  explicit ExampleKeys(std::shared_ptr<State> state)
      : state_(std::move(state)) {}

  coggate::ActiveKeyResult active_key() override {
    return {AG_KEY_STATUS_OK,
            state_->vectors.at("active_key_id").get<std::string>(),
            state_->active_key};
  }

  coggate::KeyResult key_by_id(std::string_view key_id) override {
    ++state_->key_by_id_calls;
    if (key_id != state_->vectors.at("old_key_id").get<std::string>()) {
      return {AG_KEY_STATUS_NOT_FOUND, {}};
    }
    return {AG_KEY_STATUS_OK, state_->old_key};
  }

private:
  std::shared_ptr<State> state_;
};

class ExampleObserver final : public coggate::Observer {
public:
  void observe(std::string_view) override {}
};

} // namespace

int main() {
  using namespace coggate;
  const auto &accepted = coggate_fixture::fixture_by_id("accepted");
  auto state = std::make_shared<State>();
  Service service(std::make_shared<ExampleLifecycle>(state),
                  std::make_shared<ExampleKeys>(state),
                  std::make_shared<ExampleObserver>());
  const PublicChallenge challenge =
      service.issue(IssueRequest::v1(state->binding));
  const VerificationOutcome outcome = service.verify(
      Submission::from_json(coggate_fixture::submission_json(accepted)),
      state->binding);
  service.close();

  const std::string expected_outcome = accepted.at("expected_outcome").dump();
  return !challenge.challenge_id.empty() &&
                 outcome.to_json() == expected_outcome &&
                 state->key_by_id_calls == 1U && state->finish_calls == 1U &&
                 state->finish_outcome == AG_ATTEMPT_OUTCOME_ACCEPTED
             ? 0
             : 1;
}
