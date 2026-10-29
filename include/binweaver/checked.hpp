#pragma once
// Overflow-checked arithmetic and bounds-checked byte access.
//
// Every parser offset in BinWeaver is attacker-controlled. The rule is:
// never compute `offset + length` or `count * size` with plain operators on
// untrusted values; use the helpers below, which return std::nullopt on
// overflow, and only index a span after range_within() has succeeded.
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace bw {

constexpr std::optional<std::uint64_t> checked_add(std::uint64_t a, std::uint64_t b) noexcept {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) return std::nullopt;
    return a + b;
}

constexpr std::optional<std::uint64_t> checked_mul(std::uint64_t a, std::uint64_t b) noexcept {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) return std::nullopt;
    return a * b;
}

// True when [offset, offset + length) lies inside [0, size). Never overflows.
constexpr bool range_within(std::uint64_t offset, std::uint64_t length, std::uint64_t size) noexcept {
    return offset <= size && length <= size - offset;
}

// True when [inner, inner + inner_len) lies inside [outer, outer + outer_len).
constexpr bool subrange_of(std::uint64_t outer, std::uint64_t outer_len,
                           std::uint64_t inner, std::uint64_t inner_len) noexcept {
    return inner >= outer && range_within(inner - outer, inner_len, outer_len);
}

// Round up to a power-of-two alignment; nullopt on overflow or invalid alignment.
constexpr std::optional<std::uint64_t> align_up(std::uint64_t value, std::uint64_t alignment) noexcept {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) return std::nullopt;
    auto bumped = checked_add(value, alignment - 1);
    if (!bumped) return std::nullopt;
    return *bumped & ~(alignment - 1);
}

constexpr bool is_power_of_two(std::uint64_t v) noexcept { return v != 0 && (v & (v - 1)) == 0; }

enum class Endian { Little, Big };

// A fixed-size record whose bounds were verified when it was created.
// Field reads past the record size return 0 instead of reading out of bounds;
// parsers create records with the exact structure size, so that branch is
// only reachable through a parser bug, never through file contents.
class Record {
public:
    Record() = default;
    Record(std::span<const std::uint8_t> bytes, Endian endian) noexcept : bytes_(bytes), endian_(endian) {}

    std::size_t size() const noexcept { return bytes_.size(); }
    std::span<const std::uint8_t> bytes() const noexcept { return bytes_; }

    std::uint8_t u8(std::size_t at) const noexcept { return at < bytes_.size() ? bytes_[at] : 0; }
    std::uint16_t u16(std::size_t at) const noexcept { return static_cast<std::uint16_t>(read(at, 2)); }
    std::uint32_t u32(std::size_t at) const noexcept { return static_cast<std::uint32_t>(read(at, 4)); }
    std::uint64_t u64(std::size_t at) const noexcept { return read(at, 8); }
    // Reads a 4- or 8-byte field depending on the ELF/PE class.
    std::uint64_t word(std::size_t at, bool wide) const noexcept { return wide ? u64(at) : u32(at); }

private:
    std::uint64_t read(std::size_t at, std::size_t width) const noexcept {
        if (at > bytes_.size() || width > bytes_.size() - at) return 0;
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < width; ++i) {
            const std::size_t idx = endian_ == Endian::Little ? at + width - 1 - i : at + i;
            v = (v << 8) | bytes_[idx];
        }
        return v;
    }

    std::span<const std::uint8_t> bytes_{};
    Endian endian_{Endian::Little};
};

// Bounds-checked view over an untrusted byte buffer.
class ByteView {
public:
    ByteView() = default;
    ByteView(std::span<const std::uint8_t> bytes, Endian endian = Endian::Little) noexcept
        : bytes_(bytes), endian_(endian) {}

    std::uint64_t size() const noexcept { return bytes_.size(); }
    Endian endian() const noexcept { return endian_; }
    bool has(std::uint64_t offset, std::uint64_t length) const noexcept { return range_within(offset, length, size()); }

    std::optional<std::span<const std::uint8_t>> slice(std::uint64_t offset, std::uint64_t length) const noexcept {
        if (!has(offset, length)) return std::nullopt;
        return bytes_.subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(length));
    }
    std::optional<Record> record(std::uint64_t offset, std::uint64_t length) const noexcept {
        auto s = slice(offset, length);
        if (!s) return std::nullopt;
        return Record(*s, endian_);
    }
    std::optional<std::uint16_t> u16(std::uint64_t offset) const noexcept {
        auto r = record(offset, 2);
        return r ? std::optional<std::uint16_t>(r->u16(0)) : std::nullopt;
    }
    std::optional<std::uint32_t> u32(std::uint64_t offset) const noexcept {
        auto r = record(offset, 4);
        return r ? std::optional<std::uint32_t>(r->u32(0)) : std::nullopt;
    }
    std::optional<std::uint64_t> u64(std::uint64_t offset) const noexcept {
        auto r = record(offset, 8);
        return r ? std::optional<std::uint64_t>(r->u64(0)) : std::nullopt;
    }

    // Reads a NUL-terminated string starting at `offset`. Returns nullopt when
    // the offset is outside the buffer or no terminator occurs within
    // `max_length` bytes (or before the end of the buffer).
    std::optional<std::string_view> cstring(std::uint64_t offset, std::uint64_t max_length) const noexcept {
        if (offset >= size()) return std::nullopt;
        const std::uint64_t available = size() - offset;
        const std::uint64_t limit = available < max_length ? available : max_length;
        const auto* start = bytes_.data() + static_cast<std::size_t>(offset);
        for (std::uint64_t i = 0; i < limit; ++i) {
            if (start[i] == 0)
                return std::string_view(reinterpret_cast<const char*>(start), static_cast<std::size_t>(i));
        }
        return std::nullopt;
    }

private:
    std::span<const std::uint8_t> bytes_{};
    Endian endian_{Endian::Little};
};

// Makes untrusted names printable: control and non-ASCII bytes become \xNN.
std::string printable(std::string_view raw);

} // namespace bw
