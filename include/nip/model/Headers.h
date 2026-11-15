#pragma once

#include "nip/model/Addresses.h"

#include <cstddef>
#include <cstdint>

namespace nip {

constexpr std::size_t kEthernetHeaderLength = 14;
constexpr std::size_t kIpv4MinHeaderLength = 20;
constexpr std::size_t kIpv4MaxHeaderLength = 60;
constexpr std::size_t kTcpMinHeaderLength = 20;
constexpr std::size_t kTcpMaxHeaderLength = 60;
constexpr std::size_t kUdpHeaderLength = 8;
constexpr std::size_t kIcmpMinHeaderLength = 8;

namespace ethertype {
constexpr std::uint16_t kIpv4 = 0x0800;
constexpr std::uint16_t kArp = 0x0806;
constexpr std::uint16_t kIpv6 = 0x86DD;
constexpr std::uint16_t kVlan = 0x8100;
}  // namespace ethertype

namespace ip_protocol {
constexpr std::uint8_t kIcmp = 1;
constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;
}  // namespace ip_protocol

// Low 8 bits of the TCP flags field, in on-wire order.
namespace tcp_flag {
constexpr std::uint8_t kFin = 1u << 0;
constexpr std::uint8_t kSyn = 1u << 1;
constexpr std::uint8_t kRst = 1u << 2;
constexpr std::uint8_t kPsh = 1u << 3;
constexpr std::uint8_t kAck = 1u << 4;
constexpr std::uint8_t kUrg = 1u << 5;
constexpr std::uint8_t kEce = 1u << 6;
constexpr std::uint8_t kCwr = 1u << 7;
}  // namespace tcp_flag

// IHL and the TCP data offset count 32-bit words, so the byte length is words * 4.
constexpr std::uint16_t ipv4HeaderLengthBytes(std::uint8_t ihl) noexcept {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(ihl) * 4u);
}

constexpr std::uint16_t tcpHeaderLengthBytes(std::uint8_t dataOffset) noexcept {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(dataOffset) * 4u);
}

struct EthernetHeader {
    MacAddress destination;
    MacAddress source;
    std::uint16_t etherType = 0;
};

inline bool operator==(const EthernetHeader& lhs, const EthernetHeader& rhs) noexcept {
    return lhs.destination == rhs.destination && lhs.source == rhs.source && lhs.etherType == rhs.etherType;
}

inline bool operator!=(const EthernetHeader& lhs, const EthernetHeader& rhs) noexcept { return !(lhs == rhs); }

struct IPv4Header {
    std::uint8_t version = 0;
    std::uint8_t ihl = 0;
    std::uint16_t headerLength = 0;
    std::uint16_t totalLength = 0;
    std::uint16_t identification = 0;
    bool reservedFlag = false;
    bool dontFragment = false;
    bool moreFragments = false;
    // Fragment offset in 8-byte units, not bytes.
    std::uint16_t fragmentOffset = 0;
    std::uint8_t ttl = 0;
    std::uint8_t protocol = 0;
    std::uint16_t headerChecksum = 0;
    IPv4Address source;
    IPv4Address destination;

    // Offset zero is the first fragment, including an unfragmented datagram.
    bool isInitialFragment() const noexcept { return fragmentOffset == 0; }
};

inline bool operator==(const IPv4Header& lhs, const IPv4Header& rhs) noexcept {
    return lhs.version == rhs.version && lhs.ihl == rhs.ihl && lhs.headerLength == rhs.headerLength &&
           lhs.totalLength == rhs.totalLength && lhs.identification == rhs.identification &&
           lhs.reservedFlag == rhs.reservedFlag && lhs.dontFragment == rhs.dontFragment &&
           lhs.moreFragments == rhs.moreFragments && lhs.fragmentOffset == rhs.fragmentOffset &&
           lhs.ttl == rhs.ttl && lhs.protocol == rhs.protocol && lhs.headerChecksum == rhs.headerChecksum &&
           lhs.source == rhs.source && lhs.destination == rhs.destination;
}

inline bool operator!=(const IPv4Header& lhs, const IPv4Header& rhs) noexcept { return !(lhs == rhs); }

struct TcpHeader {
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;
    std::uint32_t sequenceNumber = 0;
    std::uint32_t acknowledgmentNumber = 0;
    std::uint8_t dataOffset = 0;
    std::uint16_t headerLength = 0;
    bool ns = false;
    std::uint8_t flags = 0;
    std::uint16_t windowSize = 0;

    bool hasFlag(std::uint8_t flag) const noexcept { return (flags & flag) != 0; }
};

inline bool operator==(const TcpHeader& lhs, const TcpHeader& rhs) noexcept {
    return lhs.sourcePort == rhs.sourcePort && lhs.destinationPort == rhs.destinationPort &&
           lhs.sequenceNumber == rhs.sequenceNumber && lhs.acknowledgmentNumber == rhs.acknowledgmentNumber &&
           lhs.dataOffset == rhs.dataOffset && lhs.headerLength == rhs.headerLength && lhs.ns == rhs.ns &&
           lhs.flags == rhs.flags && lhs.windowSize == rhs.windowSize;
}

inline bool operator!=(const TcpHeader& lhs, const TcpHeader& rhs) noexcept { return !(lhs == rhs); }

struct UdpHeader {
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;
    std::uint16_t length = 0;
    std::uint16_t checksum = 0;
};

inline bool operator==(const UdpHeader& lhs, const UdpHeader& rhs) noexcept {
    return lhs.sourcePort == rhs.sourcePort && lhs.destinationPort == rhs.destinationPort && lhs.length == rhs.length &&
           lhs.checksum == rhs.checksum;
}

inline bool operator!=(const UdpHeader& lhs, const UdpHeader& rhs) noexcept { return !(lhs == rhs); }

struct IcmpHeader {
    std::uint8_t type = 0;
    std::uint8_t code = 0;
    std::uint16_t checksum = 0;
};

inline bool operator==(const IcmpHeader& lhs, const IcmpHeader& rhs) noexcept {
    return lhs.type == rhs.type && lhs.code == rhs.code && lhs.checksum == rhs.checksum;
}

inline bool operator!=(const IcmpHeader& lhs, const IcmpHeader& rhs) noexcept { return !(lhs == rhs); }

}  // namespace nip
