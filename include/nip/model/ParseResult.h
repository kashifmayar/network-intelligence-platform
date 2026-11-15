#pragma once

#include <optional>
#include <string>
#include <utility>

namespace nip {

enum class ParseStatus {
    Success,
    Unsupported,
    Malformed,
};

inline const char* toString(ParseStatus status) noexcept {
    switch (status) {
    case ParseStatus::Success:
        return "success";
    case ParseStatus::Unsupported:
        return "unsupported";
    case ParseStatus::Malformed:
        return "malformed";
    }
    return "unknown";
}

// Distinguishes a decoded value, a protocol this milestone does not parse,
// and input that failed a length or structure check.
template <typename T>
struct ParseResult {
    ParseStatus status = ParseStatus::Malformed;
    std::optional<T> value;
    std::string detail;

    bool ok() const noexcept { return status == ParseStatus::Success && value.has_value(); }
};

template <typename T>
ParseResult<T> parseSuccess(T value) {
    ParseResult<T> result;
    result.status = ParseStatus::Success;
    result.value = std::move(value);
    return result;
}

template <typename T>
ParseResult<T> parseUnsupported(std::string detail, std::optional<T> partial = std::nullopt) {
    ParseResult<T> result;
    result.status = ParseStatus::Unsupported;
    result.value = std::move(partial);
    result.detail = std::move(detail);
    return result;
}

template <typename T>
ParseResult<T> parseMalformed(std::string detail) {
    ParseResult<T> result;
    result.status = ParseStatus::Malformed;
    result.detail = std::move(detail);
    return result;
}

}  // namespace nip
