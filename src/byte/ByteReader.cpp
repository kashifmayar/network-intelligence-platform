#include "nip/byte/ByteReader.h"

namespace nip {

ByteReader::ByteReader(ByteView bytes) noexcept : bytes_(bytes) {}

std::size_t ByteReader::offset() const noexcept { return offset_; }

std::size_t ByteReader::remaining() const noexcept { return bytes_.size() - offset_; }

bool ByteReader::canRead(std::size_t count) const noexcept { return count <= remaining(); }

std::optional<std::uint8_t> ByteReader::readU8() noexcept {
    if (!canRead(1) || bytes_.data() == nullptr) {
        return std::nullopt;
    }
    const std::uint8_t value = bytes_.data()[offset_];
    ++offset_;
    return value;
}

std::optional<std::uint16_t> ByteReader::readU16Be() noexcept {
    if (!canRead(2) || bytes_.data() == nullptr) {
        return std::nullopt;
    }
    const auto hi = static_cast<std::uint16_t>(bytes_.data()[offset_]);
    const auto lo = static_cast<std::uint16_t>(bytes_.data()[offset_ + 1]);
    offset_ += 2;
    return static_cast<std::uint16_t>((hi << 8) | lo);
}

std::optional<std::uint32_t> ByteReader::readU32Be() noexcept {
    if (!canRead(4) || bytes_.data() == nullptr) {
        return std::nullopt;
    }
    const auto b0 = static_cast<std::uint32_t>(bytes_.data()[offset_]);
    const auto b1 = static_cast<std::uint32_t>(bytes_.data()[offset_ + 1]);
    const auto b2 = static_cast<std::uint32_t>(bytes_.data()[offset_ + 2]);
    const auto b3 = static_cast<std::uint32_t>(bytes_.data()[offset_ + 3]);
    offset_ += 4;
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

std::optional<ByteView> ByteReader::readBytes(std::size_t count) noexcept {
    if (!canRead(count)) {
        return std::nullopt;
    }
    const std::uint8_t* start = bytes_.data() == nullptr ? nullptr : bytes_.data() + offset_;
    offset_ += count;
    return ByteView{start, count};
}

bool ByteReader::skip(std::size_t count) noexcept {
    if (!canRead(count)) {
        return false;
    }
    offset_ += count;
    return true;
}

ByteView ByteReader::remainder() const noexcept {
    const std::uint8_t* start = bytes_.data() == nullptr ? nullptr : bytes_.data() + offset_;
    return ByteView{start, remaining()};
}

}  // namespace nip
