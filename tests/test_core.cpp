#include "binweaver/binweaver.hpp"
#include "check.hpp"

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <limits>
#include <random>
#include <tuple>

using namespace bw;

namespace {
constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();

std::vector<std::uint64_t> interesting_values(std::mt19937_64& rng, std::size_t random_count) {
    std::vector<std::uint64_t> v = {0, 1, 2, 3, 7, 8, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffff, 0x80000000,
                                    0xffffffff, 0x100000000, kMax / 2, kMax / 2 + 1, kMax - 1, kMax};
    for (std::size_t i = 0; i < random_count; ++i) {
        const int bits = static_cast<int>(rng() % 64) + 1;
        v.push_back(bits == 64 ? rng() : rng() & ((std::uint64_t{1} << bits) - 1));
    }
    return v;
}

std::vector<std::uint8_t> bytes_of(std::string_view s) { return {s.begin(), s.end()}; }
} // namespace

TEST_CASE("core.sha256.vectors") {
    CHECK_EQ(sha256({}), std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(sha256(bytes_of("abc")), std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(sha256(bytes_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
             std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    std::vector<std::uint8_t> million(1000000, 'a');
    CHECK_EQ(sha256(million), std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

TEST_CASE("core.sha256.streaming_matches_one_shot") {
    std::mt19937_64 rng(1);
    for (std::size_t len : {0u, 1u, 55u, 56u, 63u, 64u, 65u, 119u, 120u, 128u, 1000u, 4099u}) {
        std::vector<std::uint8_t> data(len);
        for (auto& b : data) b = static_cast<std::uint8_t>(rng());
        Sha256 h;
        std::size_t at = 0;
        while (at < len) {
            const std::size_t chunk = std::min<std::size_t>(len - at, rng() % 70);
            h.update(std::span(data).subspan(at, chunk));
            at += chunk;
        }
        CHECK_EQ(h.hex_digest(), sha256(data));
    }
}

TEST_CASE("core.sha256.hardware_matches_portable") {
    std::cout << "  SHA extensions: " << (Sha256::hardware_available() ? "available" : "not available") << '\n';
    std::mt19937_64 rng(77);
    for (std::size_t len : {0u, 3u, 63u, 64u, 65u, 127u, 128u, 1000u, 65537u, 1u << 20}) {
        std::vector<std::uint8_t> data(len);
        for (auto& b : data) b = static_cast<std::uint8_t>(rng());
        const bool prev = Sha256::set_hardware_enabled(false);
        const auto portable = sha256(data);
        Sha256::set_hardware_enabled(true);
        const auto accelerated = sha256(data);
        Sha256::set_hardware_enabled(prev);
        CHECK_EQ(portable, accelerated);
    }
    Sha256::set_hardware_enabled(false);
    CHECK_EQ(sha256(bytes_of("abc")), std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    Sha256::set_hardware_enabled(true);
}

TEST_CASE("core.sha1.vectors") {
    // FIPS 180 examples.
    CHECK_EQ(sha1({}), std::string("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    CHECK_EQ(sha1(bytes_of("abc")), std::string("a9993e364706816aba3e25717850c26c9cd0d89d"));
    CHECK_EQ(sha1(bytes_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
             std::string("84983e441c3bd26ebaae4aa1f95129e5e54670f1"));
    std::vector<std::uint8_t> million(1000000, 'a');
    CHECK_EQ(sha1(million), std::string("34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
    Sha1 h;  // streaming in odd-sized pieces
    for (std::size_t at = 0; at < million.size(); at += 977)
        h.update(std::span(million).subspan(at, std::min<std::size_t>(977, million.size() - at)));
    CHECK_EQ(h.hex_digest(), std::string("34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
}

TEST_CASE("core.md5.vectors") {
    // RFC 1321 appendix A.5 test suite.
    CHECK_EQ(md5({}), std::string("d41d8cd98f00b204e9800998ecf8427e"));
    CHECK_EQ(md5(bytes_of("a")), std::string("0cc175b9c0f1b6a831c399e269772661"));
    CHECK_EQ(md5(bytes_of("abc")), std::string("900150983cd24fb0d6963f7d28e17f72"));
    CHECK_EQ(md5(bytes_of("message digest")), std::string("f96b697d7cb7938d525a2f31aaf161d0"));
    CHECK_EQ(md5(bytes_of("abcdefghijklmnopqrstuvwxyz")), std::string("c3fcd3d76192e4007dfb496cca67e13b"));
    CHECK_EQ(md5(bytes_of("12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
             std::string("57edf4a22be3c955ac49da2e2107b67a"));
}

TEST_CASE("core.entropy") {
    std::vector<std::uint8_t> zeros(128);
    CHECK(entropy(zeros) == 0.0);
    CHECK(entropy({}) == 0.0);
    std::vector<std::uint8_t> all(256);
    for (int i = 0; i < 256; ++i) all[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(i);
    CHECK(std::abs(entropy(all) - 8.0) < 1e-12);
    std::vector<std::uint8_t> two = {0, 1, 0, 1};
    CHECK(std::abs(entropy(two) - 1.0) < 1e-12);
}

TEST_CASE("core.entropy_windows") {
    std::vector<std::uint8_t> data(1000);
    for (std::size_t i = 500; i < 1000; ++i) data[i] = static_cast<std::uint8_t>(i);
    auto w = entropy_windows(data, 256);
    REQUIRE(w.size() == 4);
    CHECK_EQ(w[0].offset, 0u);
    CHECK_EQ(w[3].offset, 768u);
    CHECK_EQ(w[3].size, 232u);
    CHECK(w[0].entropy == 0.0);
    CHECK(w[3].entropy > 7.0);
    CHECK(entropy_windows(data, 0).empty());
    CHECK(entropy_windows({}, 16).empty());
    CHECK_EQ(entropy_windows(data, 5000).size(), 1u);
    CHECK_EQ(entropy_windows(data, 1000).size(), 1u);
}

// Property tests: checked arithmetic and range predicates against reference
// definitions over edge values and random values of every bit width.
TEST_CASE("core.checked_arithmetic.properties") {
    std::mt19937_64 rng(42);
    const auto values = interesting_values(rng, 300);
    for (auto a : values)
        for (auto b : values) {
            const auto s = checked_add(a, b);
            if (s) CHECK(*s - b == a && *s >= a && *s >= b);
            else CHECK(a > kMax - b);
            const auto m = checked_mul(a, b);
            if (m) CHECK(a == 0 || (*m / a == b && *m % a == 0));
            else CHECK(a != 0 && b > kMax / a);
        }
}

TEST_CASE("core.range_predicates.properties") {
    std::mt19937_64 rng(7);
    const auto values = interesting_values(rng, 60);
    for (auto off : values)
        for (auto len : values)
            for (auto size : {std::uint64_t{0}, std::uint64_t{1}, std::uint64_t{4096}, std::uint64_t{0xffffffff}, kMax}) {
                const auto end = checked_add(off, len);
                const bool reference = end && *end <= size;
                CHECK_EQ(range_within(off, len, size), reference);
                // subrange_of agrees with an explicit endpoint check.
                const std::uint64_t outer = size / 3;
                const bool sub = subrange_of(outer, size - outer, off, len);
                const bool sub_ref = off >= outer && end && *end <= size;
                CHECK_EQ(sub, sub_ref);
            }
    for (auto v : values)
        for (std::uint64_t align : {1ull, 2ull, 8ull, 0x200ull, 0x1000ull, 1ull << 63}) {
            const auto r = align_up(v, align);
            if (r) CHECK(*r >= v && *r % align == 0 && *r - v < align);
            else CHECK(v > kMax - (align - 1));
        }
    CHECK(!align_up(5, 3));
    CHECK(!align_up(5, 0));
}

TEST_CASE("core.byteview") {
    const std::vector<std::uint8_t> b = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 'h', 'i', 0, 'x'};
    ByteView le(b, Endian::Little), be(b, Endian::Big);
    CHECK_EQ(*le.u16(0), 0x2211u);
    CHECK_EQ(*be.u16(0), 0x1122u);
    CHECK_EQ(*le.u32(0), 0x44332211u);
    CHECK_EQ(*be.u32(0), 0x11223344u);
    CHECK_EQ(*le.u64(0), 0x8877665544332211ull);
    CHECK_EQ(*be.u64(0), 0x1122334455667788ull);
    CHECK(le.u16(10).has_value());
    CHECK(!le.u16(11).has_value());
    CHECK(!le.u32(9).has_value());
    CHECK(!le.u64(kMax).has_value());
    CHECK(!le.slice(kMax - 1, 4).has_value());
    CHECK_EQ(std::string(*le.cstring(8, 100)), std::string("hi"));
    CHECK(!le.cstring(8, 2).has_value());   // terminator beyond max_length
    CHECK(!le.cstring(11, 100).has_value());  // unterminated at end of buffer
    CHECK(!le.cstring(12, 100).has_value());
    auto r = le.record(0, 4);
    REQUIRE(r.has_value());
    CHECK_EQ(r->u32(0), 0x44332211u);
    CHECK_EQ(r->u32(1), 0u);  // read past the record: defined as 0, never out of bounds
    CHECK_EQ(r->u64(0), 0u);
}

TEST_CASE("core.printable") {
    CHECK_EQ(printable("abc"), std::string("abc"));
    CHECK_EQ(printable(std::string_view("a\0b", 3)), std::string("a\\x00b"));
    CHECK_EQ(printable("\x7f\xff\\"), std::string("\\x7f\\xff\\"));
    CHECK_EQ(printable("C:\\dir\\a.pdb"), std::string("C:\\dir\\a.pdb"));
}

TEST_CASE("core.pattern.parse") {
    std::string e;
    auto p = parse_pattern("4D 5a ?? 00", false, e);
    REQUIRE(p.has_value());
    CHECK_EQ(p->bytes.size(), 4u);
    CHECK(!p->mask[2]);
    CHECK(parse_pattern("0x4d5a", false, e).has_value());
    CHECK(!parse_pattern("4d5", false, e));
    CHECK(!parse_pattern("zz", false, e));
    CHECK(!parse_pattern("?? ??", false, e));
    CHECK(!parse_pattern("", false, e));
    auto t = parse_pattern("MZ", true, e);
    REQUIRE(t.has_value());
    CHECK(t->bytes == std::vector<std::uint8_t>({'M', 'Z'}));
}

TEST_CASE("core.pattern.find") {
    std::string e;
    const auto hay = bytes_of("abcabcXabc");
    auto p = *parse_pattern("abc", true, e);
    CHECK_EQ(*find_pattern(hay, p, 0), 0u);
    CHECK_EQ(*find_pattern(hay, p, 1), 3u);
    CHECK_EQ(*find_pattern(hay, p, 4), 7u);
    CHECK(!find_pattern(hay, p, 8));
    CHECK(!find_pattern(hay, p, kMax));
    CHECK_EQ(*find_pattern(hay, p, 10, false), 7u);
    CHECK_EQ(*find_pattern(hay, p, 7, false), 3u);
    CHECK(!find_pattern(hay, p, 0, false));
    auto wild = *parse_pattern("?? 62 63 58", false, e);  // "?bcX"
    CHECK_EQ(*find_pattern(hay, wild, 0), 3u);
    auto longer = *parse_pattern("abcabcXabcabc", true, e);
    CHECK(!find_pattern(hay, longer, 0));
    CHECK(!find_pattern({}, p, 0));
    // Property: agrees with a naive search on random data.
    std::mt19937_64 rng(3);
    std::vector<std::uint8_t> data(5000);
    for (auto& b : data) b = static_cast<std::uint8_t>(rng() % 4);
    auto q = *parse_pattern("01 ?? 02", false, e);
    std::uint64_t from = 0;
    for (std::size_t i = 0; i + 3 <= data.size(); ++i) {
        if (data[i] == 1 && data[i + 2] == 2) {
            auto hit = find_pattern(data, q, from);
            REQUIRE(hit.has_value());
            CHECK_EQ(*hit, i);
            from = i + 1;
        }
    }
    CHECK(!find_pattern(data, q, from));
}

TEST_CASE("core.compare.ranges") {
    std::vector<std::uint8_t> a(300, 1), b(300, 1);
    CHECK_EQ(compare(a, b).changed, 0u);
    CHECK(compare(a, b).ranges.empty());
    b[10] = 2; b[11] = 2; b[200] = 3; b[299] = 4;
    auto d = compare(a, b);
    CHECK_EQ(d.changed, 4u);
    REQUIRE(d.ranges.size() == 3);
    CHECK_EQ(d.ranges[0].offset, 10u);
    CHECK_EQ(d.ranges[0].size, 2u);
    CHECK_EQ(d.ranges[2].offset, 299u);
    CHECK_EQ(d.longest_changed, 2u);
    b.resize(310, 9);
    d = compare(a, b);
    CHECK_EQ(d.changed, 14u);
    auto t = compare(a, b, 1, 1);
    CHECK(t.ranges_truncated);
    CHECK_EQ(t.ranges.size(), 1u);
    CHECK_EQ(t.ranges[0].size, 2u);
    CHECK_EQ(t.offsets.size(), 1u);
}

TEST_CASE("core.compare.matches_naive") {
    std::mt19937_64 rng(11);
    for (int round = 0; round < 50; ++round) {
        std::vector<std::uint8_t> a(static_cast<std::size_t>(rng() % 3000)), b;
        for (auto& x : a) x = static_cast<std::uint8_t>(rng() % 3);
        b = a;
        for (int k = 0; k < 20 && !b.empty(); ++k) b[rng() % b.size()] ^= static_cast<std::uint8_t>(rng() % 2);
        b.resize(b.size() + rng() % 50, 0);
        const auto d = compare(a, b);
        std::uint64_t changed = 0, runs = 0;
        bool in_run = false;
        for (std::size_t i = 0; i < std::min(a.size(), b.size()); ++i) {
            const bool diff = a[i] != b[i];
            changed += diff;
            runs += diff && !in_run;
            in_run = diff;
        }
        changed += std::max(a.size(), b.size()) - std::min(a.size(), b.size());
        CHECK_EQ(d.changed, changed);
        CHECK_EQ(d.ranges.size(), runs);
    }
}

TEST_CASE("core.file_image") {
    std::string e;
    CHECK(!FileImage::open("definitely/not/here.bin", e));
    CHECK(!e.empty());
    CHECK(!FileImage::open(std::filesystem::temp_directory_path(), e));
    const auto p = std::filesystem::temp_directory_path() / "bw-file-image-test.bin";
    std::vector<std::uint8_t> data(70000);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i * 7);
    {
        std::ofstream f(p, std::ios::binary);
        f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    {
        auto mapped = FileImage::open(p, e, FileImage::kDefaultMaxSize, FileImage::Mode::MemoryMap);
        auto read = FileImage::open(p, e, FileImage::kDefaultMaxSize, FileImage::Mode::Read);
        REQUIRE(mapped && read);
        CHECK(mapped->memory_mapped());
        CHECK(!read->memory_mapped());
        CHECK(std::equal(mapped->bytes().begin(), mapped->bytes().end(), data.begin(), data.end()));
        CHECK(std::equal(read->bytes().begin(), read->bytes().end(), data.begin(), data.end()));
        FileImage moved = std::move(*mapped);  // the view must survive a move
        CHECK_EQ(moved.size(), data.size());
        CHECK_EQ(moved.bytes()[69999], data[69999]);
        CHECK(!FileImage::open(p, e, 1000));
        CHECK(e.find("safety limit") != std::string::npos);
    }
    std::filesystem::remove(p);
    {
        std::ofstream f(p, std::ios::binary);
    }
    auto empty = FileImage::open(p, e);
    REQUIRE(empty.has_value());
    CHECK_EQ(empty->size(), 0u);
    CHECK(analyze(*empty).format == Format::Unknown);
    empty.reset();
    std::filesystem::remove(p);
}

TEST_CASE("core.original_bad_pe_regression") {
    // Kept from the original suite: a two-byte "MZ" file must be reported, not crash.
    auto a = analyze(FileImage::from_bytes({'M', 'Z', 0, 0}));
    CHECK(a.format == Format::PE);
    CHECK(!a.structurally_valid);
    CHECK(!a.diagnostics.empty());
    CHECK_EQ(a.diagnostics[0].code, std::string("pe.dos.truncated"));
}

TEST_CASE("core.pattern.chunked_matches_unchunked") {
    // Property: chunked search (tiny chunks, so matches straddle boundaries)
    // finds exactly what the single-pass search finds, in both directions.
    std::mt19937_64 rng(21);
    std::string e;
    std::vector<std::uint8_t> data(700);
    for (auto& b : data) b = static_cast<std::uint8_t>(rng() % 3);
    for (const char* pat : {"01 02", "00 ?? 02 01", "02 02 02"}) {
        const auto p = *parse_pattern(pat, false, e);
        for (std::uint64_t chunk : {1ull, 2ull, 3ull, 7ull, 64ull, 1000ull})
            for (std::uint64_t from = 0; from <= data.size(); from += 13) {
                const SearchProgress none;
                CHECK(find_pattern(data, p, from, true, none, chunk) == find_pattern(data, p, from, true));
                CHECK(find_pattern(data, p, from, false, none, chunk) == find_pattern(data, p, from, false));
            }
        std::vector<std::uint64_t> expected;
        for (auto hit = find_pattern(data, p, 0); hit; hit = find_pattern(data, p, *hit + 1)) expected.push_back(*hit);
        CHECK(find_all(data, p, 100000, {}, 5) == expected);
        CHECK(find_all(data, p, 2).size() == std::min<std::size_t>(2, expected.size()));
    }
}

TEST_CASE("core.pattern.cancellation_and_progress") {
    std::vector<std::uint8_t> data(1000, 0);
    data[900] = 7;
    std::string e;
    const auto p = *parse_pattern("07", false, e);
    int calls = 0;
    CHECK(!find_pattern(data, p, 0, true, [&](std::uint64_t, std::uint64_t) { return ++calls < 3; }, 100));
    CHECK_EQ(calls, 3);  // stopped on the third chunk, before reaching offset 900
    std::uint64_t last_done = 0, total = 0;
    CHECK_EQ(*find_pattern(data, p, 0, true, [&](std::uint64_t d, std::uint64_t t) { last_done = d; total = t; return true; }, 100), 900u);
    CHECK_EQ(total, 1000u);
    CHECK(last_done <= 900);
    CHECK(find_all(data, p, 10, [](std::uint64_t, std::uint64_t) { return false; }, 100).empty());
}

TEST_CASE("core.strings") {
    std::vector<std::uint8_t> b = {'x', 0, 'H', 'e', 'l', 'l', 'o', '!', 0, 'a', 'b', 0xff};  // 0xff: not part of any string
    for (char c : std::string("Wide1")) {
        b.push_back(static_cast<std::uint8_t>(c));
        b.push_back(0);
    }
    const std::string tail = "tail!";
    b.insert(b.end(), tail.begin(), tail.end());  // run that ends at end of buffer
    auto scan = extract_strings(b);
    REQUIRE(scan.strings.size() == 3);
    CHECK_EQ(scan.strings[0].offset, 2u);
    CHECK_EQ(scan.strings[0].text, std::string("Hello!"));
    CHECK(!scan.strings[0].utf16);
    CHECK_EQ(scan.strings[1].offset, 12u);
    CHECK(scan.strings[1].utf16);
    CHECK_EQ(scan.strings[1].text, std::string("Wide1"));
    CHECK_EQ(scan.strings[1].size, 10u);
    CHECK_EQ(scan.strings[2].text, std::string("tail!"));
    StringOptions o;
    o.min_length = 6;
    CHECK_EQ(extract_strings(b, o).strings.size(), 1u);
    o.min_length = 1;
    o.max_count = 2;
    CHECK(extract_strings(b, o).truncated);
    o = {};
    o.max_text = 3;
    CHECK_EQ(extract_strings(b, o).strings[0].text, std::string("Hel"));
    CHECK_EQ(extract_strings(b, o).strings[0].size, 6u);
    CHECK(extract_strings({}).strings.empty());
    // Odd-aligned UTF-16 at the very end of the buffer.
    std::vector<std::uint8_t> odd = {0xff, 'A', 0, 'B', 0, 'C', 0, 'D', 0, 'E', 0};
    StringOptions w;
    w.ascii = false;
    auto ws = extract_strings(odd, w);
    REQUIRE(ws.strings.size() == 1);
    CHECK_EQ(ws.strings[0].offset, 1u);
    CHECK_EQ(ws.strings[0].text, std::string("ABCDE"));
}

namespace {
// Straightforward reference: three independent passes, no limits.
std::vector<std::tuple<std::uint64_t, std::uint64_t, bool>> naive_strings(const std::vector<std::uint8_t>& b, std::size_t min) {
    std::vector<std::tuple<std::uint64_t, std::uint64_t, bool>> out;
    auto ok = [](std::uint8_t c) { return (c >= 0x20 && c < 0x7f) || c == '\t'; };
    std::size_t run = 0;
    for (std::size_t i = 0; i <= b.size(); ++i) {
        if (i < b.size() && ok(b[i])) { ++run; continue; }
        if (run >= min) out.emplace_back(i - run, run, false);
        run = 0;
    }
    for (std::size_t parity = 0; parity < 2; ++parity) {
        run = 0;
        for (std::size_t i = parity; i <= b.size() + 1; i += 2) {
            if (i + 1 < b.size() && ok(b[i]) && b[i + 1] == 0) { ++run; continue; }
            if (run >= min) out.emplace_back(i - 2 * run, 2 * run, true);
            run = 0;
        }
    }
    std::sort(out.begin(), out.end(), [](const auto& x, const auto& y) {
        return std::get<0>(x) != std::get<0>(y) ? std::get<0>(x) < std::get<0>(y) : std::get<2>(x) < std::get<2>(y);
    });
    return out;
}
} // namespace

TEST_CASE("core.strings.matches_reference") {
    std::mt19937_64 rng(31);
    for (int round = 0; round < 40; ++round) {
        std::vector<std::uint8_t> b(static_cast<std::size_t>(rng() % 2000));
        for (auto& x : b) {
            const auto r = rng() % 4;  // bias towards text, NULs and UTF-16 patterns
            x = r == 0 ? 0 : r == 1 ? static_cast<std::uint8_t>('a' + rng() % 26) : static_cast<std::uint8_t>(rng());
        }
        StringOptions o;
        o.min_length = 1 + static_cast<std::size_t>(rng() % 6);
        o.max_count = 1000000;
        const auto got = extract_strings(b, o);
        const auto want = naive_strings(b, o.min_length);
        REQUIRE(got.strings.size() == want.size());
        for (std::size_t i = 0; i < want.size(); ++i) {
            CHECK_EQ(got.strings[i].offset, std::get<0>(want[i]));
            CHECK_EQ(got.strings[i].size, std::get<1>(want[i]));
            CHECK(got.strings[i].utf16 == std::get<2>(want[i]));
        }
        CHECK(!got.truncated);
        CHECK_EQ(got.scanned, b.size());
        // A truncated scan returns exactly the first max_count strings in the
        // order their runs end (ASCII before UTF-16 at the same end offset).
        o.max_count = 7;
        const auto cut = extract_strings(b, o);
        auto by_end = want;
        std::stable_sort(by_end.begin(), by_end.end(), [](const auto& x, const auto& y) {
            const auto ex = std::get<0>(x) + std::get<1>(x), ey = std::get<0>(y) + std::get<1>(y);
            return ex != ey ? ex < ey : std::get<2>(x) < std::get<2>(y);
        });
        if (by_end.size() > 7) by_end.resize(7);
        std::sort(by_end.begin(), by_end.end(), [](const auto& x, const auto& y) {
            return std::get<0>(x) != std::get<0>(y) ? std::get<0>(x) < std::get<0>(y) : std::get<2>(x) < std::get<2>(y);
        });
        REQUIRE(cut.strings.size() == by_end.size());
        for (std::size_t i = 0; i < by_end.size(); ++i) {
            CHECK_EQ(cut.strings[i].offset, std::get<0>(by_end[i]));
            CHECK(cut.strings[i].utf16 == std::get<2>(by_end[i]));
            CHECK(cut.strings[i].offset + cut.strings[i].size <= cut.scanned);
        }
        if (want.size() < 7) CHECK(!cut.truncated);  // limit never reached
        if (want.size() > 7) CHECK(cut.truncated);
    }
}
