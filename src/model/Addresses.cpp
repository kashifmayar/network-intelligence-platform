#include "nip/model/Addresses.h"

#include <sstream>
#include <iomanip>

namespace nip {

std::string MacAddress::toString() const {
    std::ostringstream out;
    out << std::hex << std::uppercase << std::setfill('0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) {
            out << ':';
        }
        out << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return out.str();
}

std::string IPv4Address::toString() const {
    std::ostringstream out;
    out << static_cast<int>(bytes[0]) << '.' << static_cast<int>(bytes[1]) << '.'
        << static_cast<int>(bytes[2]) << '.' << static_cast<int>(bytes[3]);
    return out.str();
}

std::optional<IPv4Address> IPv4Address::fromString(std::string_view text) {
    if (text.empty()) {
        return std::nullopt;
    }

    IPv4Address address;
    std::size_t position = 0;
    for (int octet = 0; octet < 4; ++octet) {
        if (position >= text.size()) {
            return std::nullopt;
        }

        const std::size_t dot = text.find('.', position);
        const bool last = octet == 3;
        if (last) {
            if (dot != std::string_view::npos) {
                return std::nullopt;
            }
        } else if (dot == std::string_view::npos) {
            return std::nullopt;
        }

        const std::size_t end = last ? text.size() : dot;
        if (end == position) {
            return std::nullopt;
        }

        unsigned value = 0;
        for (std::size_t index = position; index < end; ++index) {
            const char ch = text[index];
            if (ch < '0' || ch > '9') {
                return std::nullopt;
            }
            value = value * 10u + static_cast<unsigned>(ch - '0');
            if (value > 255u) {
                return std::nullopt;
            }
        }

        address.bytes[static_cast<std::size_t>(octet)] = static_cast<std::uint8_t>(value);
        position = end + 1;
    }

    return address;
}

}  // namespace nip
