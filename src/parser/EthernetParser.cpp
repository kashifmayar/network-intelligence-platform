#include "nip/parser/EthernetParser.h"

#include "nip/byte/ByteReader.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace nip {
namespace {

constexpr std::uint16_t kEthernetIIMinimumEtherType = 0x0600;

std::optional<MacAddress> readMac(ByteReader& reader) {
    const auto bytes = reader.readBytes(MacAddress{}.bytes.size());
    if (!bytes.has_value() || bytes->data() == nullptr) {
        return std::nullopt;
    }
    MacAddress address;
    std::copy(bytes->data(), bytes->data() + address.bytes.size(), address.bytes.begin());
    return address;
}

std::string etherTypeText(std::uint16_t etherType) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
        << static_cast<unsigned>(etherType);
    return out.str();
}

}  // namespace

ParseResult<EthernetParse> parseEthernet(ByteView frame) {
    if (frame.size() < kEthernetHeaderLength) {
        return parseMalformed<EthernetParse>("truncated Ethernet header");
    }

    ByteReader reader{frame};
    const auto destination = readMac(reader);
    const auto source = readMac(reader);
    const auto etherType = reader.readU16Be();
    if (!destination.has_value() || !source.has_value() || !etherType.has_value()) {
        return parseMalformed<EthernetParse>("truncated Ethernet header");
    }

    EthernetParse parsed;
    parsed.header.destination = *destination;
    parsed.header.source = *source;
    parsed.header.etherType = *etherType;
    const auto payload = frame.suffix(kEthernetHeaderLength);
    parsed.payload = payload.value_or(ByteView{});

    if (*etherType < kEthernetIIMinimumEtherType) {
        return parseUnsupported<EthernetParse>(
            "IEEE 802.3 frames are not parsed in this milestone", parsed);
    }
    if (*etherType == ethertype::kIpv6) {
        return parseUnsupported<EthernetParse>(
            "IPv6 is recognized but not parsed in this milestone", parsed);
    }
    if (*etherType != ethertype::kIpv4) {
        return parseUnsupported<EthernetParse>("unsupported EtherType " + etherTypeText(*etherType), parsed);
    }
    return parseSuccess(parsed);
}

}  // namespace nip
