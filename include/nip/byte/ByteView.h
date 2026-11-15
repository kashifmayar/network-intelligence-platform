#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace nip {

// Non-owning view of a packet buffer. Empty when data is null.
class ByteView {
public:
    ByteView() = default;

    ByteView(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data), size_(data == nullptr ? 0 : size) {}

    const std::uint8_t* data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }

    std::optional<std::uint8_t> at(std::size_t index) const noexcept {
        if (index >= size_ || data_ == nullptr) {
            return std::nullopt;
        }
        return data_[index];
    }

    std::optional<ByteView> subview(std::size_t offset, std::size_t length) const noexcept {
        if (offset > size_ || length > size_ - offset) {
            return std::nullopt;
        }
        const std::uint8_t* start = data_ == nullptr ? nullptr : data_ + offset;
        return ByteView{start, length};
    }

    std::optional<ByteView> suffix(std::size_t offset) const noexcept {
        if (offset > size_) {
            return std::nullopt;
        }
        return subview(offset, size_ - offset);
    }

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

}  // namespace nip
