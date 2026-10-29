#include "binweaver/binweaver.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>

namespace bw {

double entropy(std::span<const std::uint8_t> b) {
    if (b.empty()) return 0;
    std::array<std::uint64_t, 256> c{};
    for (auto x : b) ++c[x];
    double h = 0;
    const double n = static_cast<double>(b.size());
    for (auto x : c)
        if (x) {
            const double p = static_cast<double>(x) / n;
            h -= p * std::log2(p);
        }
    return h;
}

std::vector<EntropyWindow> entropy_windows(std::span<const std::uint8_t> b, std::uint64_t window) {
    std::vector<EntropyWindow> out;
    if (window == 0 || b.empty()) return out;
    out.reserve(static_cast<std::size_t>((b.size() + window - 1) / window));
    for (std::uint64_t off = 0; off < b.size(); off += window) {
        const auto len = std::min<std::uint64_t>(window, b.size() - off);
        out.push_back({off, len, entropy(b.subspan(static_cast<std::size_t>(off), static_cast<std::size_t>(len)))});
        if (len < window) break;  // also guards `off += window` against overflow
    }
    return out;
}

Diff compare(std::span<const std::uint8_t> x, std::span<const std::uint8_t> y, std::size_t max_offsets,
             std::size_t max_ranges) {
    Diff d;
    d.size_a = x.size();
    d.size_b = y.size();
    d.compared = std::min(d.size_a, d.size_b);
    std::uint64_t eq = 0, chg = 0;
    const std::size_t n = static_cast<std::size_t>(d.compared);
    std::size_t i = 0;
    while (i < n) {
        // Skip equal blocks quickly; this dominates the cost for similar files.
        if (n - i >= 64 && std::memcmp(x.data() + i, y.data() + i, 64) == 0) {
            eq += 64;
            chg = 0;
            d.longest_equal = std::max(d.longest_equal, eq);
            i += 64;
            continue;
        }
        if (x[i] == y[i]) {
            d.longest_equal = std::max(d.longest_equal, ++eq);
            chg = 0;
        } else {
            ++d.changed;
            d.longest_changed = std::max(d.longest_changed, ++chg);
            eq = 0;
            if (d.offsets.size() < max_offsets) d.offsets.push_back(i);
            if (chg == 1) {
                if (d.ranges.size() < max_ranges) d.ranges.push_back({i, 1});
                else d.ranges_truncated = true;
            } else if (!d.ranges.empty() && d.ranges.back().offset + d.ranges.back().size == i) {
                ++d.ranges.back().size;  // a dropped (truncated) run is never adjacent to the last kept one
            }
        }
        ++i;
    }
    // Bytes beyond the shorter file count as changed but are not listed as ranges.
    d.changed += (d.size_a - d.compared) + (d.size_b - d.compared);
    const auto den = std::max(d.size_a, d.size_b);
    d.changed_percent = den ? 100.0 * static_cast<double>(d.changed) / static_cast<double>(den) : 0;
    return d;
}

Diff compare(const FileImage& a, const FileImage& b, std::size_t max_offsets, std::size_t max_ranges) {
    return compare(a.bytes(), b.bytes(), max_offsets, max_ranges);
}

std::optional<BytePattern> parse_pattern(std::string_view text, bool literal_text, std::string& error) {
    BytePattern p;
    if (literal_text) {
        for (char ch : text) {
            p.bytes.push_back(static_cast<std::uint8_t>(ch));
            p.mask.push_back(true);
        }
    } else {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        std::string digits;
        for (char c : text) {
            if (c == ' ' || c == '\t' || c == ',' || c == ':') continue;
            digits += c;
        }
        if (digits.size() >= 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) digits.erase(0, 2);
        if (digits.size() % 2) {
            error = "hex pattern has an odd number of digits";
            return std::nullopt;
        }
        for (std::size_t i = 0; i < digits.size(); i += 2) {
            if (digits[i] == '?' && digits[i + 1] == '?') {
                p.bytes.push_back(0);
                p.mask.push_back(false);
                continue;
            }
            const int hi = nibble(digits[i]), lo = nibble(digits[i + 1]);
            if (hi < 0 || lo < 0) {
                error = "invalid hex digit in pattern";
                return std::nullopt;
            }
            p.bytes.push_back(static_cast<std::uint8_t>(hi * 16 + lo));
            p.mask.push_back(true);
        }
    }
    if (p.bytes.empty()) {
        error = "empty pattern";
        return std::nullopt;
    }
    if (std::none_of(p.mask.begin(), p.mask.end(), [](bool m) { return m; })) {
        error = "pattern must contain at least one non-wildcard byte";
        return std::nullopt;
    }
    return p;
}

namespace {
bool matches_at(std::span<const std::uint8_t> h, const BytePattern& p, std::size_t at) {
    for (std::size_t j = 0; j < p.bytes.size(); ++j)
        if (p.mask[j] && h[at + j] != p.bytes[j]) return false;
    return true;
}
} // namespace

std::optional<std::uint64_t> find_pattern(std::span<const std::uint8_t> h, const BytePattern& p, std::uint64_t from,
                                          bool forward) {
    if (p.empty() || p.bytes.size() > h.size()) return std::nullopt;
    const std::size_t last = h.size() - p.bytes.size();  // last valid start
    // Anchor on the first non-wildcard byte so memchr can do the scanning.
    std::size_t anchor = 0;
    while (!p.mask[anchor]) ++anchor;
    const std::uint8_t key = p.bytes[anchor];

    if (forward) {
        if (from > last) return std::nullopt;
        std::size_t i = static_cast<std::size_t>(from);
        while (i <= last) {
            const void* hit = std::memchr(h.data() + i + anchor, key, last - i + 1);
            if (!hit) return std::nullopt;
            const std::size_t at = static_cast<std::size_t>(static_cast<const std::uint8_t*>(hit) - h.data()) - anchor;
            if (matches_at(h, p, at)) return at;
            i = at + 1;
        }
        return std::nullopt;
    }
    if (from == 0) return std::nullopt;
    std::size_t i = static_cast<std::size_t>(std::min<std::uint64_t>(from - 1, last));
    for (;;) {
        if (h[i + anchor] == key && matches_at(h, p, i)) return i;
        if (i == 0) return std::nullopt;
        --i;
    }
}

std::optional<std::uint64_t> find_pattern(std::span<const std::uint8_t> h, const BytePattern& p, std::uint64_t from,
                                          bool forward, const SearchProgress& progress, std::uint64_t chunk) {
    if (p.empty() || p.bytes.size() > h.size()) return std::nullopt;
    const std::uint64_t n = h.size(), len = p.bytes.size();
    chunk = std::max<std::uint64_t>(chunk, 1);
    if (forward) {
        if (from > n - len) return std::nullopt;
        for (std::uint64_t start = from; start <= n - len; start += chunk) {
            if (progress && !progress(start - from, n - from)) return std::nullopt;
            // Window of match starts [start, start + chunk), plus the tail bytes they need.
            const std::uint64_t end = std::min<std::uint64_t>(n, start + chunk + len - 1);
            const auto window = h.subspan(static_cast<std::size_t>(start), static_cast<std::size_t>(end - start));
            if (auto hit = find_pattern(window, p, 0, true)) return start + *hit;
            if (n - start - len < chunk) break;
        }
        return std::nullopt;
    }
    // Backward: windows of match starts [lo, hi) walking down from `from`.
    std::uint64_t hi = std::min<std::uint64_t>(from, n - len + 1);
    while (hi > 0) {
        if (progress && !progress(from - hi, from)) return std::nullopt;
        const std::uint64_t lo = hi > chunk ? hi - chunk : 0;
        const auto window = h.subspan(static_cast<std::size_t>(lo), static_cast<std::size_t>(hi - lo + len - 1));
        if (auto hit = find_pattern(window, p, hi - lo, false)) return lo + *hit;
        hi = lo;
    }
    return std::nullopt;
}

std::vector<std::uint64_t> find_all(std::span<const std::uint8_t> h, const BytePattern& p, std::size_t max_hits,
                                    const SearchProgress& progress, std::uint64_t chunk) {
    std::vector<std::uint64_t> hits;
    std::uint64_t from = 0;
    while (hits.size() < max_hits) {
        // Report progress relative to the whole buffer, not the remaining tail.
        const std::uint64_t base = from;
        const auto hit = find_pattern(h, p, from, true,
                                      progress ? SearchProgress([&](std::uint64_t done, std::uint64_t) {
                                          return progress(base + done, h.size());
                                      })
                                               : SearchProgress{},
                                      chunk);
        if (!hit) break;
        hits.push_back(*hit);
        from = *hit + 1;
    }
    return hits;
}

StringScan extract_strings(std::span<const std::uint8_t> b, const StringOptions& o) {
    StringScan out;
    static const auto printable = [] {
        std::array<bool, 256> t{};
        for (int c = 0x20; c < 0x7f; ++c) t[static_cast<std::size_t>(c)] = true;
        t['\t'] = true;
        return t;
    }();
    const std::uint64_t min_len = std::max<std::size_t>(o.min_length, 1);
    const std::size_t n = b.size();
    bool full = o.max_count == 0;
    auto emit = [&](std::uint64_t offset, std::uint64_t chars, bool wide) {
        ExtractedString s;
        s.offset = offset;
        s.size = chars * (wide ? 2 : 1);
        s.utf16 = wide;
        const std::uint64_t keep = std::min<std::uint64_t>(chars, o.max_text);
        s.text.resize(static_cast<std::size_t>(keep));
        for (std::uint64_t i = 0; i < keep; ++i)
            s.text[static_cast<std::size_t>(i)] = static_cast<char>(b[static_cast<std::size_t>(offset + i * (wide ? 2 : 1))]);
        out.strings.push_back(std::move(s));
        full = out.strings.size() >= o.max_count;
    };
    // One pass tracks the ASCII run and two UTF-16LE runs (even and odd
    // alignment). Index n flushes the ASCII run and one UTF-16 lane, n + 1 the other lane.
    std::uint64_t ascii_run = 0, wide_run[2] = {0, 0};
    std::size_t i = 0;
    for (; i <= n + 1 && !full; ++i) {
        if (o.ascii && i <= n) {
            if (i < n && printable[b[i]]) {
                ++ascii_run;
            } else {
                if (ascii_run >= min_len) emit(i - ascii_run, ascii_run, false);
                ascii_run = 0;
            }
        }
        if (o.utf16 && !full) {
            std::uint64_t& run = wide_run[i & 1];
            if (i + 1 < n && printable[b[i]] && b[i + 1] == 0) {
                ++run;
            } else {
                if (run >= min_len) emit(i - run * 2, run, true);
                run = 0;
            }
        }
    }
    // When the limit is hit, only strings that ended before `scanned` are reported.
    out.truncated = full && i <= n + 1;
    out.scanned = out.truncated ? std::min<std::uint64_t>(i, n) : n;
    std::sort(out.strings.begin(), out.strings.end(), [](const ExtractedString& x, const ExtractedString& y) {
        return x.offset != y.offset ? x.offset < y.offset : x.utf16 < y.utf16;
    });
    return out;
}

} // namespace bw
