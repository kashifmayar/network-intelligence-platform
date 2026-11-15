#pragma once

#include <cstdint>

namespace nip {

enum class Protocol : std::uint8_t {
    Unknown = 0,
    IPv4,
    IPv6,
    Tcp,
    Udp,
    Icmp,
};

const char* toString(Protocol protocol) noexcept;

}  // namespace nip
