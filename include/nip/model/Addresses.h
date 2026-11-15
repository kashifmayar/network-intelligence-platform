#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace nip {

struct MacAddress {
    std::array<std::uint8_t, 6> bytes{};

    std::string toString() const;

    bool operator==(const MacAddress& other) const noexcept { return bytes == other.bytes; }
    bool operator!=(const MacAddress& other) const noexcept { return !(*this == other); }
};

struct IPv4Address {
    std::array<std::uint8_t, 4> bytes{};

    std::string toString() const;

    // Decimal dotted quad. Leading zeros are decimal, so "192.168.001.010"
    // is 192.168.1.10. Returns nullopt when the text is not four 0-255 octets.
    static std::optional<IPv4Address> fromString(std::string_view text);

    bool operator==(const IPv4Address& other) const noexcept { return bytes == other.bytes; }
    bool operator!=(const IPv4Address& other) const noexcept { return !(*this == other); }
};

}  // namespace nip
