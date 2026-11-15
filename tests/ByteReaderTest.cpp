#include "nip/byte/ByteReader.h"

#include <gtest/gtest.h>

#include <cstdint>

namespace {

nip::ByteReader readerFor(const std::uint8_t* data, std::size_t size) {
    return nip::ByteReader{nip::ByteView{data, size}};
}

}  // namespace

TEST(ByteView, RejectsOutOfRangeAccess) {
    const std::uint8_t bytes[] = {0x08, 0x00};
    const nip::ByteView view{bytes, sizeof(bytes)};

    EXPECT_EQ(view.at(0), 0x08);
    EXPECT_EQ(view.at(1), 0x00);
    EXPECT_FALSE(view.at(2).has_value());
    EXPECT_FALSE(view.subview(1, 2).has_value());
    EXPECT_FALSE(view.suffix(3).has_value());

    const auto tail = view.suffix(1);
    ASSERT_TRUE(tail.has_value());
    EXPECT_EQ(tail->size(), 1u);
    EXPECT_EQ(tail->at(0), 0x00);
}

TEST(ByteView, NullDataIsEmpty) {
    const nip::ByteView view{nullptr, 5};
    EXPECT_TRUE(view.empty());
    EXPECT_EQ(view.size(), 0u);
    EXPECT_FALSE(view.at(0).has_value());
}

TEST(ByteReader, ReadsNetworkByteOrder) {
    const std::uint8_t bytes[] = {0x08, 0x00, 0xC0, 0xA8, 0x01, 0x0A};
    auto reader = readerFor(bytes, sizeof(bytes));

    EXPECT_EQ(reader.readU16Be(), 0x0800);
    EXPECT_EQ(reader.readU32Be(), 0xC0A8010Au);
    EXPECT_EQ(reader.offset(), 6u);
    EXPECT_EQ(reader.remaining(), 0u);
    EXPECT_FALSE(reader.readU8().has_value());
    EXPECT_EQ(reader.offset(), 6u);
}

TEST(ByteReader, FailedReadDoesNotAdvance) {
    const std::uint8_t bytes[] = {0x01, 0x02, 0x03};
    auto reader = readerFor(bytes, sizeof(bytes));

    EXPECT_FALSE(reader.readU32Be().has_value());
    EXPECT_EQ(reader.offset(), 0u);

    EXPECT_EQ(reader.readU8(), 0x01);
    EXPECT_FALSE(reader.readU32Be().has_value());
    EXPECT_EQ(reader.offset(), 1u);
    EXPECT_EQ(reader.readU16Be(), 0x0203);
    EXPECT_EQ(reader.remaining(), 0u);
}

TEST(ByteReader, SkipAndSliceStayInsideTheBuffer) {
    const std::uint8_t bytes[] = {0xAA, 0xBB, 0xCC, 0xDD};
    auto reader = readerFor(bytes, sizeof(bytes));

    EXPECT_FALSE(reader.skip(5));
    EXPECT_EQ(reader.offset(), 0u);
    EXPECT_TRUE(reader.skip(1));

    const auto slice = reader.readBytes(2);
    ASSERT_TRUE(slice.has_value());
    EXPECT_EQ(slice->size(), 2u);
    EXPECT_EQ(slice->at(0), 0xBB);
    EXPECT_EQ(slice->at(1), 0xCC);
    EXPECT_EQ(reader.offset(), 3u);

    EXPECT_FALSE(reader.readBytes(2).has_value());
    EXPECT_EQ(reader.offset(), 3u);

    const auto rest = reader.remainder();
    EXPECT_EQ(rest.size(), 1u);
    EXPECT_EQ(rest.at(0), 0xDD);
}

TEST(ByteReader, EmptyReadSucceeds) {
    auto reader = readerFor(nullptr, 0);
    const auto slice = reader.readBytes(0);
    ASSERT_TRUE(slice.has_value());
    EXPECT_TRUE(slice->empty());
    EXPECT_TRUE(reader.skip(0));
    EXPECT_FALSE(reader.readU8().has_value());
}
