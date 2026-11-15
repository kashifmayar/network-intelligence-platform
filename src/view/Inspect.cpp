#include "nip/view/Inspect.h"

#include "nip/model/Headers.h"
#include "nip/model/ParseResult.h"
#include "nip/parser/EthernetParser.h"
#include "nip/parser/IPv4Parser.h"

#include <cctype>
#include <sstream>
#include <string>
#include <type_traits>

namespace nip {
namespace {

int hexValue(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

class Json {
public:
    void beginObject() { open('{'); }
    void endObject() { out_ << '}'; frames_.pop_back(); }
    void beginArray() { open('['); }
    void endArray() { out_ << ']'; frames_.pop_back(); }

    void key(std::string_view name) {
        separate();
        string(name);
        out_ << ':';
        expectingValue_ = true;
    }

    void value(std::string_view text) { startValue(); string(text); }
    void value(const char* text) { value(std::string_view{text}); }
    void value(bool flag) { startValue(); out_ << (flag ? "true" : "false"); }
    template <typename Number>
    std::enable_if_t<std::is_integral<Number>::value && !std::is_same<Number, bool>::value> value(Number number) {
        startValue();
        out_ << static_cast<unsigned long long>(number);
    }
    void raw(std::string_view json) { startValue(); out_ << json; }

    std::string str() const { return out_.str(); }

private:
    void separate() {
        if (frames_.empty()) {
            return;
        }
        if (!frames_.back()) {
            frames_.back() = true;
            return;
        }
        out_ << ',';
    }

    void startValue() {
        if (!expectingValue_) {
            separate();
        }
        expectingValue_ = false;
    }

    void open(char bracket) {
        startValue();
        out_ << bracket;
        frames_.push_back(false);
    }

    void string(std::string_view text) {
        out_ << '"';
        for (const unsigned char ch : text) {
            switch (ch) {
            case '"':
                out_ << "\\\"";
                break;
            case '\\':
                out_ << "\\\\";
                break;
            case '\n':
                out_ << "\\n";
                break;
            case '\r':
                out_ << "\\r";
                break;
            case '\t':
                out_ << "\\t";
                break;
            default:
                if (ch < 0x20) {
                    constexpr char kDigits[] = "0123456789abcdef";
                    out_ << "\\u00" << kDigits[ch >> 4] << kDigits[ch & 0x0F];
                } else {
                    out_ << static_cast<char>(ch);
                }
                break;
            }
        }
        out_ << '"';
    }

    std::ostringstream out_;
    std::vector<bool> frames_;
    bool expectingValue_ = false;
};

std::string hexByte(std::uint8_t byte) {
    constexpr char kDigits[] = "0123456789ABCDEF";
    std::string text(2, '0');
    text[0] = kDigits[byte >> 4];
    text[1] = kDigits[byte & 0x0F];
    return text;
}

std::string hexDump(ByteView frame) {
    std::string text;
    if (frame.data() == nullptr) {
        return text;
    }
    text.reserve(frame.size() * 2);
    for (std::size_t index = 0; index < frame.size(); ++index) {
        text += hexByte(frame.data()[index]);
    }
    return text;
}

const char* etherTypeName(std::uint16_t etherType) {
    switch (etherType) {
    case ethertype::kIpv4:
        return "IPv4";
    case ethertype::kIpv6:
        return "IPv6";
    case ethertype::kArp:
        return "ARP";
    case ethertype::kVlan:
        return "VLAN";
    default:
        return "Other";
    }
}

const char* ipProtocolName(std::uint8_t protocol) {
    switch (protocol) {
    case ip_protocol::kIcmp:
        return "ICMP";
    case ip_protocol::kTcp:
        return "TCP";
    case ip_protocol::kUdp:
        return "UDP";
    default:
        return "Other";
    }
}

void writeStatus(Json& json, ParseStatus status, const std::string& detail) {
    json.key("status");
    json.value(toString(status));
    json.key("detail");
    json.value(detail);
}

std::string inspectIpv4(ByteView packet) {
    const auto result = parseIPv4(packet);
    Json json;
    json.beginObject();
    writeStatus(json, result.status, result.detail);
    if (result.value.has_value()) {
        const IPv4Header& header = result.value->header;
        json.key("version");
        json.value(header.version);
        json.key("ihl");
        json.value(header.ihl);
        json.key("headerLength");
        json.value(header.headerLength);
        json.key("totalLength");
        json.value(header.totalLength);
        json.key("identification");
        json.value(header.identification);
        json.key("reservedFlag");
        json.value(header.reservedFlag);
        json.key("dontFragment");
        json.value(header.dontFragment);
        json.key("moreFragments");
        json.value(header.moreFragments);
        json.key("fragmentOffset");
        json.value(header.fragmentOffset);
        json.key("fragmentOffsetBytes");
        json.value(static_cast<unsigned long long>(header.fragmentOffset) * 8u);
        json.key("initialFragment");
        json.value(header.isInitialFragment());
        json.key("ttl");
        json.value(header.ttl);
        json.key("protocol");
        json.value(header.protocol);
        json.key("protocolName");
        json.value(ipProtocolName(header.protocol));
        json.key("headerChecksum");
        json.value(header.headerChecksum);
        json.key("source");
        json.value(header.source.toString());
        json.key("destination");
        json.value(header.destination.toString());
        json.key("payloadBytes");
        json.value(static_cast<unsigned long long>(result.value->payload.size()));
    }
    json.endObject();
    return json.str();
}

std::vector<std::uint8_t> ethernetFrame(std::uint16_t etherType, const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> frame = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                                       static_cast<std::uint8_t>(etherType >> 8),
                                       static_cast<std::uint8_t>(etherType & 0xFF)};
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

std::vector<std::uint8_t> ipv4Packet(std::uint8_t versionAndIhl, std::uint16_t totalLength, std::uint16_t flagsAndOffset,
                                     std::uint8_t protocol, std::vector<std::uint8_t> options = {},
                                     std::vector<std::uint8_t> payload = {}) {
    std::vector<std::uint8_t> packet = {versionAndIhl,
                                        0x00,
                                        static_cast<std::uint8_t>(totalLength >> 8),
                                        static_cast<std::uint8_t>(totalLength & 0xFF),
                                        0x12,
                                        0x34,
                                        static_cast<std::uint8_t>(flagsAndOffset >> 8),
                                        static_cast<std::uint8_t>(flagsAndOffset & 0xFF),
                                        64,
                                        protocol,
                                        0xAB,
                                        0xCD,
                                        192,
                                        168,
                                        1,
                                        10,
                                        192,
                                        168,
                                        1,
                                        1};
    packet.insert(packet.end(), options.begin(), options.end());
    packet.insert(packet.end(), payload.begin(), payload.end());
    return packet;
}

struct Sample {
    const char* id;
    const char* title;
    const char* note;
    std::vector<std::uint8_t> frame;
};

std::vector<Sample> samples() {
    const auto tcp = ipv4Packet(0x45, 20, 0x0000, ip_protocol::kTcp);
    const auto options = ipv4Packet(0x46, 24, 0x4000, ip_protocol::kUdp, {0x01, 0x01, 0x01, 0x00});
    const auto fragment = ipv4Packet(0x45, 28, 0x2005, ip_protocol::kTcp, {}, {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
    const auto badIhl = ipv4Packet(0x44, 20, 0x0000, ip_protocol::kTcp);
    return {
        {"ipv4-tcp", "IPv4 TCP header", "A 20-byte IPv4 header with no options.", ethernetFrame(ethertype::kIpv4, tcp)},
        {"ipv4-options", "IPv4 options", "IHL is 6, so the header is 24 bytes. Three NOPs and an end-of-list.",
         ethernetFrame(ethertype::kIpv4, options)},
        {"ipv4-fragment", "Non-initial fragment", "Fragment offset 5 means the transport header is not at the start.",
         ethernetFrame(ethertype::kIpv4, fragment)},
        {"ipv6", "IPv6 EtherType", "The EtherType is recognized. The IPv6 header is not parsed.",
         ethernetFrame(ethertype::kIpv6, {0x60, 0x00, 0x00, 0x00})},
        {"arp", "ARP EtherType", "ARP is a known EtherType and is unsupported in this milestone.",
         ethernetFrame(ethertype::kArp, {0x00, 0x01})},
        {"truncated", "Truncated Ethernet", "Thirteen bytes cannot hold a 14-byte Ethernet header.",
         std::vector<std::uint8_t>(13, 0x11)},
        {"bad-ihl", "Invalid IPv4 IHL", "IHL 4 is below the 20-byte minimum header.", ethernetFrame(ethertype::kIpv4, badIhl)},
    };
}

}  // namespace

std::optional<std::vector<std::uint8_t>> decodeHex(std::string_view text) {
    std::vector<int> nibbles;
    nibbles.reserve(text.size());
    for (std::size_t index = 0; index < text.size(); ++index) {
        const char ch = text[index];
        if (std::isspace(static_cast<unsigned char>(ch)) || ch == ':' || ch == '-' || ch == ',') {
            continue;
        }
        if (ch == '0' && index + 1 < text.size() && (text[index + 1] == 'x' || text[index + 1] == 'X')) {
            ++index;
            continue;
        }
        const int value = hexValue(ch);
        if (value < 0) {
            return std::nullopt;
        }
        nibbles.push_back(value);
    }
    if (nibbles.size() % 2 != 0) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(nibbles.size() / 2);
    for (std::size_t index = 0; index < nibbles.size(); index += 2) {
        bytes.push_back(static_cast<std::uint8_t>((nibbles[index] << 4) | nibbles[index + 1]));
    }
    return bytes;
}

std::string inspectFrameJson(ByteView frame) {
    const auto ethernet = parseEthernet(frame);
    Json json;
    json.beginObject();
    json.key("byteLength");
    json.value(static_cast<unsigned long long>(frame.size()));
    json.key("hex");
    json.value(hexDump(frame));
    json.key("ethernet");
    json.beginObject();
    writeStatus(json, ethernet.status, ethernet.detail);
    if (ethernet.value.has_value()) {
        const EthernetHeader& header = ethernet.value->header;
        json.key("destination");
        json.value(header.destination.toString());
        json.key("source");
        json.value(header.source.toString());
        json.key("etherType");
        json.value(header.etherType);
        json.key("etherTypeHex");
        json.value("0x" + hexByte(static_cast<std::uint8_t>(header.etherType >> 8)) +
                   hexByte(static_cast<std::uint8_t>(header.etherType & 0xFF)));
        json.key("etherTypeName");
        json.value(etherTypeName(header.etherType));
        json.key("payloadBytes");
        json.value(static_cast<unsigned long long>(ethernet.value->payload.size()));
    }
    json.endObject();
    if (ethernet.ok()) {
        json.key("ipv4");
        json.raw(inspectIpv4(ethernet.value->payload));
    } else {
        json.key("ipv4");
        json.raw("null");
    }
    json.endObject();
    return json.str();
}

std::string sampleCatalogJson() {
    Json json;
    json.beginArray();
    for (const Sample& sample : samples()) {
        json.beginObject();
        json.key("id");
        json.value(sample.id);
        json.key("title");
        json.value(sample.title);
        json.key("note");
        json.value(sample.note);
        json.key("inspection");
        json.raw(inspectFrameJson(ByteView{sample.frame.data(), sample.frame.size()}));
        json.endObject();
    }
    json.endArray();
    return json.str();
}

}  // namespace nip
