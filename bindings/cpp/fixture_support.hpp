#ifndef COGGATE_CPP_FIXTURE_SUPPORT_HPP
#define COGGATE_CPP_FIXTURE_SUPPORT_HPP

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifndef COGGATE_BINDING_FIXTURE_PATH
#error "COGGATE_BINDING_FIXTURE_PATH must name fixtures/bindings/v1.json"
#endif

namespace coggate_fixture {

using Json = nlohmann::ordered_json;

inline const Json &manifest() {
  static const Json value = [] {
    std::ifstream input(COGGATE_BINDING_FIXTURE_PATH,
                        std::ios::in | std::ios::binary);
    if (!input) {
      throw std::runtime_error("unable to open CogGate binding fixture");
    }
    Json parsed = Json::parse(input);
    if (!parsed.is_object() || parsed.value("fixture_version", 0) != 1 ||
        !parsed.contains("vectors") || !parsed.at("vectors").is_object() ||
        !parsed.contains("cases") || !parsed.at("cases").is_array()) {
      throw std::runtime_error("invalid CogGate binding fixture");
    }
    return parsed;
  }();
  return value;
}

inline const Json &vectors() { return manifest().at("vectors"); }

inline const Json &fixture_by_id(std::string_view id) {
  for (const auto &fixture : manifest().at("cases")) {
    if (fixture.at("id").get<std::string>() == id) {
      return fixture;
    }
  }
  throw std::runtime_error("CogGate binding fixture ID not found");
}

inline std::uint8_t hex_nibble(char value) {
  if (value >= '0' && value <= '9') {
    return static_cast<std::uint8_t>(value - '0');
  }
  if (value >= 'a' && value <= 'f') {
    return static_cast<std::uint8_t>(value - 'a' + 10);
  }
  if (value >= 'A' && value <= 'F') {
    return static_cast<std::uint8_t>(value - 'A' + 10);
  }
  throw std::runtime_error("invalid hex in CogGate binding fixture");
}

inline std::vector<std::uint8_t> hex_bytes(std::string_view encoded) {
  if (encoded.size() % 2U != 0U) {
    throw std::runtime_error("invalid hex in CogGate binding fixture");
  }
  std::vector<std::uint8_t> bytes;
  bytes.reserve(encoded.size() / 2U);
  for (std::size_t index = 0; index < encoded.size(); index += 2U) {
    bytes.push_back(static_cast<std::uint8_t>(
        (hex_nibble(encoded[index]) << 4U) | hex_nibble(encoded[index + 1U])));
  }
  return bytes;
}

inline std::vector<std::uint8_t> vector_hex(const char *field) {
  return hex_bytes(vectors().at(field).get<std::string>());
}

inline std::string private_material_json() {
  return vectors().at("private_material").dump();
}

inline std::string submission_json(const Json &fixture) {
  return fixture.at("submission").dump();
}

} // namespace coggate_fixture

#endif
