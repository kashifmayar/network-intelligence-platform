#include "nip/parser/IPv4Parser.h"

#include <gtest/gtest.h>

#include <vector>

namespace {

nip::ByteView viewOf(const std::vector<std::uint8_t>& bytes) {
    return nip::ByteView{bytes.data(), bytes.size()};
}

std::vector<std::uint8_t> ipv4Header(std::uint8_t versionAndIhl, std::uint16_t totalLength, std::uint16_t flagsAndOffset,
                                     std::uint8_t protocol, std::vector<std::uint8_t> options = {},
                                     std::vector<std::uint8_t> payload = {}) {
    std::vector<std::uint8_t> packet = {
        versionAndIhl,
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

}  // namespace

TEST(IPv4Parser, ParsesAMinimumHeader) {
    const auto packet = ipv4Header(0x45, 20, 0x0000, nip::ip_protocol::kTcp);
    const auto result = nip::parseIPv4(viewOf(packet));

    ASSERT_TRUE(result.ok());
    const nip::IPv4Header& header = result.value->header;
    EXPECT_EQ(header.version, 4);
    EXPECT_EQ(header.ihl, 5);
    EXPECT_EQ(header.headerLength, 20);
    EXPECT_EQ(header.totalLength, 20);
    EXPECT_EQ(header.identification, 0x1234);
    EXPECT_FALSE(header.reservedFlag);
    EXPECT_FALSE(header.dontFragment);
    EXPECT_FALSE(header.moreFragments);
    EXPECT_EQ(header.fragmentOffset, 0);
    EXPECT_TRUE(header.isInitialFragment());
    EXPECT_EQ(header.ttl, 64);
    EXPECT_EQ(header.protocol, nip::ip_protocol::kTcp);
    EXPECT_EQ(header.headerChecksum, 0xABCD);
    EXPECT_EQ(header.source.toString(), "192.168.1.10");
    EXPECT_EQ(header.destination.toString(), "192.168.1.1");
    EXPECT_TRUE(result.value->payload.empty());
}

TEST(IPv4Parser, WalksAValidOptionsRegion) {
    const auto packet = ipv4Header(0x46, 24, 0x4000, nip::ip_protocol::kUdp, {0x01, 0x01, 0x01, 0x00});
    const auto result = nip::parseIPv4(viewOf(packet));

    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.value->header.ihl, 6);
    EXPECT_EQ(result.value->header.headerLength, 24);
    EXPECT_TRUE(result.value->header.dontFragment);
    EXPECT_TRUE(result.value->header.isInitialFragment());
    EXPECT_TRUE(result.value->payload.empty());
}

TEST(IPv4Parser, AcceptsALengthBearingOptionThatFits) {
    const auto packet = ipv4Header(0x46, 28, 0x0000, nip::ip_protocol::kIcmp, {0x07, 0x04, 0x00, 0x00}, {0x08, 0x00, 0x11, 0x22});
    const auto result = nip::parseIPv4(viewOf(packet));

    ASSERT_TRUE(result.ok());
    ASSERT_EQ(result.value->payload.size(), 4u);
    EXPECT_EQ(result.value->payload.at(0), 0x08);
    EXPECT_EQ(result.value->header.protocol, nip::ip_protocol::kIcmp);
}

TEST(IPv4Parser, StopsOptionWalkingAtEndOfOptionsList) {
    const auto packet = ipv4Header(0x46, 24, 0x0000, nip::ip_protocol::kTcp, {0x01, 0x00, 0xFF, 0xFF});
    const auto result = nip::parseIPv4(viewOf(packet));
    EXPECT_TRUE(result.ok());
}

TEST(IPv4Parser, RejectsAnOptionThatRunsPastTheHeader) {
    const auto packet = ipv4Header(0x46, 24, 0x0000, nip::ip_protocol::kTcp, {0x07, 0x05, 0x00, 0x00});
    const auto result = nip::parseIPv4(viewOf(packet));

    EXPECT_EQ(result.status, nip::ParseStatus::Malformed);
    EXPECT_FALSE(result.value.has_value());
    EXPECT_EQ(result.detail, "IPv4 option exceeds the header");
}

TEST(IPv4Parser, RejectsAnOptionLengthBelowTwo) {
    const auto packet = ipv4Header(0x46, 24, 0x0000, nip::ip_protocol::kTcp, {0x07, 0x01, 0x00, 0x00});
    const auto result = nip::parseIPv4(viewOf(packet));

    EXPECT_EQ(result.status, nip::ParseStatus::Malformed);
    EXPECT_EQ(result.detail, "IPv4 option length is too small");
}

TEST(IPv4Parser, RejectsHeaderLengthsOutsideTheLegalRange) {
    const auto tooSmall = ipv4Header(0x44, 20, 0x0000, nip::ip_protocol::kTcp);
    const auto zeroIhl = ipv4Header(0x40, 20, 0x0000, nip::ip_protocol::kTcp);

    EXPECT_EQ(nip::parseIPv4(viewOf(tooSmall)).detail, "invalid IPv4 IHL");
    EXPECT_EQ(nip::parseIPv4(viewOf(zeroIhl)).detail, "invalid IPv4 IHL");
}

TEST(IPv4Parser, RejectsAHeaderThatClaimsMoreBytesThanWereCaptured) {
    auto packet = ipv4Header(0x46, 24, 0x0000, nip::ip_protocol::kTcp);
    packet.resize(20);
    const auto result = nip::parseIPv4(viewOf(packet));

    EXPECT_EQ(result.status, nip::ParseStatus::Malformed);
    EXPECT_EQ(result.detail, "truncated IPv4 header");
}

TEST(IPv4Parser, RejectsATruncatedMinimumHeader) {
    const std::vector<std::uint8_t> packet(10, 0x45);
    const auto result = nip::parseIPv4(viewOf(packet));
    EXPECT_EQ(result.status, nip::ParseStatus::Malformed);
    EXPECT_EQ(result.detail, "truncated IPv4 header");
}

TEST(IPv4Parser, RejectsTheWrongVersion) {
    const auto packet = ipv4Header(0x65, 20, 0x0000, nip::ip_protocol::kTcp);
    const auto result = nip::parseIPv4(viewOf(packet));
    EXPECT_EQ(result.status, nip::ParseStatus::Malformed);
    EXPECT_EQ(result.detail, "IPv4 version is not 4");
}

TEST(IPv4Parser, RejectsATotalLengthShorterThanTheHeader) {
    const auto packet = ipv4Header(0x45, 10, 0x0000, nip::ip_protocol::kTcp);
    const auto result = nip::parseIPv4(viewOf(packet));
    EXPECT_EQ(result.status, nip::ParseStatus::Malformed);
    EXPECT_EQ(result.detail, "IPv4 total length is shorter than the header");
}

TEST(IPv4Parser, KeepsACompleteHeaderWhenThePayloadWasCutOff) {
    const auto packet = ipv4Header(0x45, 100, 0x0000, nip::ip_protocol::kUdp);
    const auto result = nip::parseIPv4(viewOf(packet));

    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.value->header.totalLength, 100);
    EXPECT_TRUE(result.value->payload.empty());
}

TEST(IPv4Parser, IgnoresBytesPastTheTotalLength) {
    auto packet = ipv4Header(0x45, 20, 0x0000, nip::ip_protocol::kTcp);
    packet.insert(packet.end(), {0xDE, 0xAD, 0xBE, 0xEF});
    const auto result = nip::parseIPv4(viewOf(packet));

    ASSERT_TRUE(result.ok());
    EXPECT_TRUE(result.value->payload.empty());
}

TEST(IPv4Parser, ParsesANonInitialFragmentWithoutRequiringATransportHeader) {
    const auto packet = ipv4Header(0x45, 28, 0x2005, nip::ip_protocol::kTcp, {}, {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
    const auto result = nip::parseIPv4(viewOf(packet));

    ASSERT_TRUE(result.ok());
    EXPECT_TRUE(result.value->header.moreFragments);
    EXPECT_EQ(result.value->header.fragmentOffset, 5);
    EXPECT_FALSE(result.value->header.isInitialFragment());
    EXPECT_EQ(result.value->header.protocol, nip::ip_protocol::kTcp);
    EXPECT_EQ(result.value->payload.size(), 8u);
}

TEST(IPv4Parser, RecordsTheReservedFlag) {
    const auto packet = ipv4Header(0x45, 20, 0x8000, nip::ip_protocol::kTcp);
    const auto result = nip::parseIPv4(viewOf(packet));

    ASSERT_TRUE(result.ok());
    EXPECT_TRUE(result.value->header.reservedFlag);
    EXPECT_FALSE(result.value->header.moreFragments);
    EXPECT_TRUE(result.value->header.isInitialFragment());
}
