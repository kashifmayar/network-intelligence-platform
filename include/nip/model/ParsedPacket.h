#pragma once

#include "nip/model/Headers.h"
#include "nip/model/ParseResult.h"
#include "nip/model/Protocol.h"

#include <cstdint>
#include <optional>
#include <string>

namespace nip {

struct PacketTimestamp {
    std::int64_t seconds = 0;
    std::int64_t nanoseconds = 0;
};

// Owned fields copied out of a frame. Views into the capture buffer are not stored.
struct ParsedPacket {
    std::uint64_t number = 0;
    PacketTimestamp timestamp;
    std::uint32_t capturedLength = 0;
    std::uint32_t originalLength = 0;
    ParseStatus status = ParseStatus::Malformed;
    std::string detail;
    Protocol protocol = Protocol::Unknown;
    std::optional<EthernetHeader> ethernet;
    std::optional<IPv4Header> ipv4;
    std::optional<TcpHeader> tcp;
    std::optional<UdpHeader> udp;
    std::optional<IcmpHeader> icmp;

    bool hasTransportHeader() const noexcept {
        return tcp.has_value() || udp.has_value() || icmp.has_value();
    }
};

}  // namespace nip
