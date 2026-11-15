#include "nip/view/Inspect.h"

#include <gtest/gtest.h>

#include <string>

TEST(DecodeHex, AcceptsSpacesAndAPrefix) {
    const auto bytes = nip::decodeHex("0xFF FF:00-0a");
    ASSERT_TRUE(bytes.has_value());
    EXPECT_EQ(*bytes, (std::vector<std::uint8_t>{0xFF, 0xFF, 0x00, 0x0A}));
}

TEST(DecodeHex, RejectsAnOddDigitAndGarbage) {
    EXPECT_FALSE(nip::decodeHex("abc").has_value());
    EXPECT_FALSE(nip::decodeHex("zz").has_value());
}

TEST(InspectFrame, ReportsIpv4FieldsFromTheRealParser) {
    const auto bytes = nip::decodeHex(
        "FF FF FF FF FF FF 00 0A 0B 0C 0D 0E 08 00 "
        "45 00 00 14 12 34 00 00 40 06 AB CD C0 A8 01 0A C0 A8 01 01");
    ASSERT_TRUE(bytes.has_value());
    const std::string json = nip::inspectFrameJson(nip::ByteView{bytes->data(), bytes->size()});
    EXPECT_NE(json.find("\"status\":\"success\""), std::string::npos);
    EXPECT_NE(json.find("192.168.1.10"), std::string::npos);
    EXPECT_NE(json.find("192.168.1.1"), std::string::npos);
    EXPECT_NE(json.find("\"protocolName\":\"TCP\""), std::string::npos);
    EXPECT_NE(json.find("\"initialFragment\":true"), std::string::npos);
}

TEST(InspectFrame, KeepsAnIpv6FrameUnsupported) {
    const auto bytes = nip::decodeHex("FF FF FF FF FF FF 00 0A 0B 0C 0D 0E 86 DD 60");
    ASSERT_TRUE(bytes.has_value());
    const std::string json = nip::inspectFrameJson(nip::ByteView{bytes->data(), bytes->size()});
    EXPECT_NE(json.find("\"status\":\"unsupported\""), std::string::npos);
    EXPECT_NE(json.find("IPv6 is recognized"), std::string::npos);
    EXPECT_NE(json.find("\"ipv4\":null"), std::string::npos);
}

TEST(SampleCatalog, IncludesTheBuiltInFrames) {
    const std::string json = nip::sampleCatalogJson();
    EXPECT_NE(json.find("\"id\":\"ipv4-tcp\""), std::string::npos);
    EXPECT_NE(json.find("\"id\":\"truncated\""), std::string::npos);
    EXPECT_NE(json.find("truncated Ethernet header"), std::string::npos);
}
