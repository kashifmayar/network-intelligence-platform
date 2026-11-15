#pragma once

#include "nip/byte/ByteView.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace nip {

// Cursor over a byte buffer. Multi-byte reads are big-endian (network order).
// A read or skip that would pass the end of the buffer fails and leaves the
// cursor where it was.
class ByteReader {
public:
    explicit ByteReader(ByteView bytes) noexcept;

    std::size_t offset() const noexcept;
    std::size_t remaining() const noexcept;
    bool canRead(std::size_t count) const noexcept;

    std::optional<std::uint8_t> readU8() noexcept;
    std::optional<std::uint16_t> readU16Be() noexcept;
    std::optional<std::uint32_t> readU32Be() noexcept;
    std::optional<ByteView> readBytes(std::size_t count) noexcept;
    bool skip(std::size_t count) noexcept;

    ByteView remainder() const noexcept;

private:
    ByteView bytes_{};
    std::size_t offset_ = 0;
};

}  // namespace nip
