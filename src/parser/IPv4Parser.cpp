#include "nip/parser/IPv4Parser.h"

#include "nip/byte/ByteReader.h"

#include <algorithm>
#include <string>

namespace nip {
namespace {

constexpr std::uint8_t kOptionEnd = 0;
constexpr std::uint8_t kOptionNop = 1;
constexpr std::uint8_t kMinimumIhl = 5;
constexpr std::uint8_t kMaximumIhl = 15;

std::optional<IPv4Address> readAddress(ByteReader& reader) {
    const auto bytes = reader.readBytes(4);
    if (!bytes.has_value() || bytes->data() == nullptr) {
        return std::nullopt;
    }
    IPv4Address address;
    std::copy(bytes->data(), bytes->data() + address.bytes.size(), address.bytes.begin());
    return address;
}

std::optional<std::string> invalidOption(ByteView options) {
    std::size_t index = 0;
    while (index < options.size()) {
        const auto type = options.at(index);
        if (!type.has_value()) {
            return "truncated IPv4 option";
        }
        if (*type == kOptionEnd) {
            return std::nullopt;
        }
        if (*type == kOptionNop) {
            ++index;
            continue;
        }
        const auto length = options.at(index + 1);
        if (!length.has_value()) {
            return "truncated IPv4 option";
        }
        if (*length < 2) {
            return "IPv4 option length is too small";
        }
        if (index + *length > options.size()) {
            return "IPv4 option exceeds the header";
        }
        index += *length;
    }
    return std::nullopt;
}

}  // namespace

ParseResult<IPv4Parse> parseIPv4(ByteView packet) {
    if (packet.size() < kIpv4MinHeaderLength) {
        return parseMalformed<IPv4Parse>("truncated IPv4 header");
    }

    ByteReader reader{packet};
    const auto first = reader.readU8();
    if (!first.has_value()) {
        return parseMalformed<IPv4Parse>("truncated IPv4 header");
    }

    IPv4Parse parsed;
    parsed.header.version = static_cast<std::uint8_t>(*first >> 4);
    parsed.header.ihl = static_cast<std::uint8_t>(*first & 0x0F);
    if (parsed.header.version != 4) {
        return parseMalformed<IPv4Parse>("IPv4 version is not 4");
    }
    if (parsed.header.ihl < kMinimumIhl || parsed.header.ihl > kMaximumIhl) {
        return parseMalformed<IPv4Parse>("invalid IPv4 IHL");
    }

    parsed.header.headerLength = ipv4HeaderLengthBytes(parsed.header.ihl);
    if (packet.size() < parsed.header.headerLength) {
        return parseMalformed<IPv4Parse>("truncated IPv4 header");
    }

    if (!reader.skip(1)) {
        return parseMalformed<IPv4Parse>("truncated IPv4 header");
    }
    const auto totalLength = reader.readU16Be();
    const auto identification = reader.readU16Be();
    const auto flagsAndOffset = reader.readU16Be();
    const auto ttl = reader.readU8();
    const auto protocol = reader.readU8();
    const auto checksum = reader.readU16Be();
    const auto source = readAddress(reader);
    const auto destination = readAddress(reader);
    if (!totalLength.has_value() || !identification.has_value() || !flagsAndOffset.has_value() ||
        !ttl.has_value() || !protocol.has_value() || !checksum.has_value() || !source.has_value() ||
        !destination.has_value()) {
        return parseMalformed<IPv4Parse>("truncated IPv4 header");
    }

    if (*totalLength < parsed.header.headerLength) {
        return parseMalformed<IPv4Parse>("IPv4 total length is shorter than the header");
    }

    if (parsed.header.headerLength > kIpv4MinHeaderLength) {
        const auto options = packet.subview(kIpv4MinHeaderLength, parsed.header.headerLength - kIpv4MinHeaderLength);
        if (!options.has_value()) {
            return parseMalformed<IPv4Parse>("truncated IPv4 header");
        }
        if (const auto optionError = invalidOption(*options)) {
            return parseMalformed<IPv4Parse>(*optionError);
        }
    }

    parsed.header.totalLength = *totalLength;
    parsed.header.identification = *identification;
    parsed.header.reservedFlag = (*flagsAndOffset & 0x8000) != 0;
    parsed.header.dontFragment = (*flagsAndOffset & 0x4000) != 0;
    parsed.header.moreFragments = (*flagsAndOffset & 0x2000) != 0;
    parsed.header.fragmentOffset = static_cast<std::uint16_t>(*flagsAndOffset & 0x1FFF);
    parsed.header.ttl = *ttl;
    parsed.header.protocol = *protocol;
    parsed.header.headerChecksum = *checksum;
    parsed.header.source = *source;
    parsed.header.destination = *destination;

    const std::size_t capturedAfterHeader = packet.size() - parsed.header.headerLength;
    std::size_t payloadLength = capturedAfterHeader;
    if (*totalLength <= packet.size()) {
        payloadLength = static_cast<std::size_t>(*totalLength - parsed.header.headerLength);
    }
    parsed.payload = packet.subview(parsed.header.headerLength, payloadLength).value_or(ByteView{});
    return parseSuccess(std::move(parsed));
}

}  // namespace nip
