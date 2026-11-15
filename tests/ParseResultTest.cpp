#include "nip/model/ParseResult.h"

#include <gtest/gtest.h>

TEST(ParseResult, SuccessRequiresAValue) {
    const auto result = nip::parseSuccess<int>(7);
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(result.status, nip::ParseStatus::Success);
    EXPECT_EQ(result.value, 7);
    EXPECT_TRUE(result.detail.empty());
    EXPECT_STREQ(nip::toString(result.status), "success");
}

TEST(ParseResult, MalformedCarriesAReasonAndNoValue) {
    const auto result = nip::parseMalformed<int>("truncated ethernet header");
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.status, nip::ParseStatus::Malformed);
    EXPECT_FALSE(result.value.has_value());
    EXPECT_EQ(result.detail, "truncated ethernet header");
    EXPECT_STREQ(nip::toString(result.status), "malformed");
}

TEST(ParseResult, UnsupportedCanKeepAPartialValue) {
    const auto result = nip::parseUnsupported<int>("IPv6 is recognized but not parsed", 0x86DD);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.status, nip::ParseStatus::Unsupported);
    EXPECT_EQ(result.value, 0x86DD);
    EXPECT_EQ(result.detail, "IPv6 is recognized but not parsed");
    EXPECT_STREQ(nip::toString(result.status), "unsupported");
}
