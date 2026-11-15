#pragma once

#include "nip/byte/ByteView.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nip {

// Decode hex text into bytes. Spaces, colons, dashes, and 0x prefixes are ignored.
// An odd number of digits or a non-hex character returns nullopt.
std::optional<std::vector<std::uint8_t>> decodeHex(std::string_view text);

// JSON object describing the Ethernet parse and, when the EtherType is IPv4,
// the IPv4 parse of the payload. Transport headers are not decoded.
std::string inspectFrameJson(ByteView frame);

// JSON array of built-in frames, each already inspected by inspectFrameJson.
std::string sampleCatalogJson();

}  // namespace nip
