#include "coggate.h"

#include <array>
#include <cstdint>
#include <cstring>

namespace {

struct TestState {
  std::array<std::uint8_t, 8> key_id{{'t', 'e', 's', 't', '-', 'k', 'e', 'y'}};
  std::array<std::uint8_t, 32> key{};

  TestState() { key.fill(0x11U); }
};

void COGGATE_CALL release_output(void *, std::uint8_t *, std::size_t) {}

ag_host_buffer host_buffer(std::uint8_t *data, std::size_t size) {
  return {data, size, nullptr, release_output};
}

ag_lifecycle_status COGGATE_CALL store_issued(void *, ag_byte_slice, ag_byte_slice,
                                         ag_attempt_limit) {
  return AG_LIFECYCLE_STATUS_OK;
}

ag_begin_status COGGATE_CALL begin_attempt(void *, ag_byte_slice, ag_byte_slice,
                                      std::int64_t, ag_host_buffer *,
                                      ag_host_buffer *) {
  return AG_BEGIN_STATUS_INTERNAL;
}

ag_lifecycle_status COGGATE_CALL finish_attempt(void *, ag_byte_slice,
                                            ag_attempt_outcome) {
  return AG_LIFECYCLE_STATUS_INTERNAL;
}

ag_key_status COGGATE_CALL active_key(void *user_data, ag_host_buffer *key_id_out,
                                 ag_host_buffer *key_out) {
  if (user_data == nullptr || key_id_out == nullptr || key_out == nullptr) {
    return AG_KEY_STATUS_INVALID_MATERIAL;
  }
  auto &state = *static_cast<TestState *>(user_data);
  *key_id_out = host_buffer(state.key_id.data(), state.key_id.size());
  *key_out = host_buffer(state.key.data(), state.key.size());
  return AG_KEY_STATUS_OK;
}

ag_key_status COGGATE_CALL key_by_id(void *, ag_byte_slice, ag_host_buffer *) {
  return AG_KEY_STATUS_NOT_FOUND;
}

} // namespace

ag_status issue_owned_buffer_for_test(ag_owned_buffer *out) noexcept {
  TestState state;
  ag_lifecycle_callbacks lifecycle{};
  lifecycle.struct_size = static_cast<std::uint32_t>(sizeof(lifecycle));
  lifecycle.abi_version = AG_ABI_VERSION_1;
  lifecycle.user_data = &state;
  lifecycle.store_issued = store_issued;
  lifecycle.begin_attempt = begin_attempt;
  lifecycle.finish_attempt = finish_attempt;

  ag_key_callbacks keys{};
  keys.struct_size = static_cast<std::uint32_t>(sizeof(keys));
  keys.abi_version = AG_ABI_VERSION_1;
  keys.user_data = &state;
  keys.active_key = active_key;
  keys.key_by_id = key_by_id;

  ag_service *service = nullptr;
  ag_status status = ag_service_create(&lifecycle, &keys, nullptr, &service);
  if (status != AG_STATUS_OK) {
    return status;
  }

  static constexpr char version[] = "1.0";
  static constexpr std::array<std::uint8_t, 3> binding{{0x01U, 0x02U, 0x03U}};
  status = ag_service_issue(
      service,
      {reinterpret_cast<const std::uint8_t *>(version), sizeof(version) - 1U},
      {binding.data(), binding.size()}, AG_ATTEMPT_LIMIT_ONE, out);
  const ag_status destroy_status = ag_service_destroy(service);
  return status == AG_STATUS_OK ? destroy_status : status;
}
