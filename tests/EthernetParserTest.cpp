#include "nip/parser/EthernetParser.h"

#include <gtest/gtest.h>

#include <vector>

namespace {

std::vector<std::uint8_t> ethernetFrame(std::uint16_t etherType, std::vector<std::uint8_t> payload) {
    std::vector<std::uint8_t> frame = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        static_cast<std::uint8_t>(etherType >> 8), static_cast<std::uint8_t>(etherType & 0xFF)};
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

nip::ByteView viewOf(const std::vector<std::uint8_t>& bytes) {
    return nip::ByteView{bytes.data(), bytes.size()};
}

}  // namespace

TEST(EthernetParser, ParsesAnIpv4Frame) {
    const auto frame = ethernetFrame(nip::ethertype::kIpv4, {0x45, 0x00});
    const auto result = nip::parseEthernet(viewOf(frame));

    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.value->header.destination.toString(), "FF:FF:FF:FF:FF:FF");
    EXPECT_EQ(result.value->header.source.toString(), "00:0A:0B:0C:0D:0E");
    EXPECT_EQ(result.value->header.etherType, nip::ethertype::kIpv4);
    ASSERT_EQ(result.value->payload.size(), 2u);
    EXPECT_EQ(result.value->payload.at(0), 0x45);
}

TEST(EthernetParser, AcceptsAnEmptyIpv4Payload) {
    const auto frame = ethernetFrame(nip::ethertype::kIpv4, {});
    const auto result = nip::parseEthernet(viewOf(frame));

    ASSERT_TRUE(result.ok());
    EXPECT_TRUE(result.value->payload.empty());
}

TEST(EthernetParser, RejectsATruncatedHeader) {
    const std::vector<std::uint8_t> frame(13, 0x11);
    const auto result = nip::parseEthernet(viewOf(frame));

    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.status, nip::ParseStatus::Malformed);
    EXPECT_FALSE(result.value.has_value());
    EXPECT_EQ(result.detail, "truncated Ethernet header");
}

TEST(EthernetParser, RecognizesIpv6WithoutParsingIt) {
    const auto frame = ethernetFrame(nip::ethertype::kIpv6, {0x60});
    const auto result = nip::parseEthernet(viewOf(frame));

    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.status, nip::ParseStatus::Unsupported);
    ASSERT_TRUE(result.value.has_value());
    EXPECT_EQ(result.value->header.etherType, nip::ethertype::kIpv6);
    EXPECT_EQ(result.detail, "IPv6 is recognized but not parsed in this milestone");
    EXPECT_EQ(result.value->payload.at(0), 0x60);
}

TEST(EthernetParser, RejectsIeee8023LengthFields) {
    const auto frame = ethernetFrame(1500, {0xAA});
    const auto result = nip::parseEthernet(viewOf(frame));

    EXPECT_EQ(result.status, nip::ParseStatus::Unsupported);
    ASSERT_TRUE(result.value.has_value());
    EXPECT_EQ(result.value->header.etherType, 1500);
    EXPECT_EQ(result.detail, "IEEE 802.3 frames are not parsed in this milestone");
}

TEST(EthernetParser, ReportsAnotherEtherTypeAsUnsupported) {
    const auto frame = ethernetFrame(nip::ethertype::kArp, {});
    const auto result = nip::parseEthernet(viewOf(frame));

    EXPECT_EQ(result.status, nip::ParseStatus::Unsupported);
    ASSERT_TRUE(result.value.has_value());
    EXPECT_EQ(result.value->header.etherType, nip::ethertype::kArp);
    EXPECT_EQ(result.detail, "unsupported EtherType 0x0806");
}
