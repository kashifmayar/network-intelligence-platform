#include "nip/model/Addresses.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

TEST(MacAddress, FormatsUppercaseHex) {
    const nip::MacAddress mac{{0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E}};
    EXPECT_EQ(mac.toString(), "00:0A:0B:0C:0D:0E");
}

TEST(IPv4Address, RoundTripsDottedDecimal) {
    const auto address = nip::IPv4Address::fromString("192.168.1.10");
    ASSERT_TRUE(address.has_value());
    EXPECT_EQ(address->bytes, (std::array<std::uint8_t, 4>{192, 168, 1, 10}));
    EXPECT_EQ(address->toString(), "192.168.1.10");
}

TEST(IPv4Address, AcceptsDecimalLeadingZerosAndExtremes) {
    const auto padded = nip::IPv4Address::fromString("192.168.001.010");
    ASSERT_TRUE(padded.has_value());
    EXPECT_EQ(padded->toString(), "192.168.1.10");

    EXPECT_EQ(nip::IPv4Address::fromString("0.0.0.0")->toString(), "0.0.0.0");
    EXPECT_EQ(nip::IPv4Address::fromString("255.255.255.255")->toString(), "255.255.255.255");
}

TEST(IPv4Address, RejectsMalformedText) {
    EXPECT_FALSE(nip::IPv4Address::fromString("").has_value());
    EXPECT_FALSE(nip::IPv4Address::fromString("192.168.1").has_value());
    EXPECT_FALSE(nip::IPv4Address::fromString("192.168.1.10.1").has_value());
    EXPECT_FALSE(nip::IPv4Address::fromString("192.168.1.256").has_value());
    EXPECT_FALSE(nip::IPv4Address::fromString("192.168.1.-1").has_value());
    EXPECT_FALSE(nip::IPv4Address::fromString("192.168.1.10 ").has_value());
    EXPECT_FALSE(nip::IPv4Address::fromString("192..1.10").has_value());
    EXPECT_FALSE(nip::IPv4Address::fromString(".168.1.10").has_value());
    EXPECT_FALSE(nip::IPv4Address::fromString("192.168.1.10.").has_value());
}
