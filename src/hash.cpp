#include "binweaver/binweaver.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#define BW_SHA_X86 1
#include <immintrin.h>
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

namespace bw {
namespace {
constexpr std::array<std::uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

constexpr std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

#ifdef BW_SHA_X86
#if defined(__GNUC__) || defined(__clang__)
#define BW_SHA_TARGET __attribute__((target("sha,sse4.1,ssse3")))
#else
#define BW_SHA_TARGET
#endif

bool cpu_has_sha() {
    unsigned a = 0, b = 0, c = 0, d = 0;
#ifdef _MSC_VER
    int r[4];
    __cpuid(r, 0);
    if (r[0] < 7) return false;
    __cpuid(r, 1);
    c = static_cast<unsigned>(r[2]);
    const bool sse = (c & (1u << 9)) && (c & (1u << 19));  // SSSE3, SSE4.1
    __cpuidex(r, 7, 0);
    b = static_cast<unsigned>(r[1]);
#else
    if (__get_cpuid_max(0, nullptr) < 7) return false;
    __cpuid(1, a, b, c, d);
    const bool sse = (c & (1u << 9)) && (c & (1u << 19));
    __cpuid_count(7, 0, a, b, c, d);
#endif
    return sse && (b & (1u << 29));  // SHA extensions
}

// SHA-256 compression with the x86 SHA extensions. State layout follows the
// instruction set's ABEF/CDGH convention; the message schedule is computed
// four words at a time: W[t..t+3] = msg2(msg1(W[t-16], W[t-12]) + W[t-7..t-4], W[t-4..t-1]).
BW_SHA_TARGET void compress_shani(std::uint32_t state[8], const std::uint8_t* data, std::size_t blocks) {
    const __m128i mask = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
    __m128i tmp = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[0]));
    __m128i s1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[4]));
    tmp = _mm_shuffle_epi32(tmp, 0xB1);         // CDAB
    s1 = _mm_shuffle_epi32(s1, 0x1B);           // EFGH
    __m128i s0 = _mm_alignr_epi8(tmp, s1, 8);   // ABEF
    s1 = _mm_blend_epi16(s1, tmp, 0xF0);        // CDGH
    for (; blocks; --blocks, data += 64) {
        const __m128i abef = s0, cdgh = s1;
        __m128i w[4];
        for (int g = 0; g < 16; ++g) {
            __m128i& cur = w[g & 3];
            if (g < 4) {
                cur = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 16 * g)), mask);
            } else {
                const __m128i prev = w[(g + 3) & 3], prev2 = w[(g + 2) & 3];
                cur = _mm_sha256msg2_epu32(
                    _mm_add_epi32(_mm_sha256msg1_epu32(cur, w[(g + 1) & 3]), _mm_alignr_epi8(prev, prev2, 4)), prev);
            }
            __m128i msg = _mm_add_epi32(cur, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&K[static_cast<std::size_t>(4 * g)])));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
        }
        s0 = _mm_add_epi32(s0, abef);
        s1 = _mm_add_epi32(s1, cdgh);
    }
    tmp = _mm_shuffle_epi32(s0, 0x1B);          // FEBA
    s1 = _mm_shuffle_epi32(s1, 0xB1);           // DCHG
    s0 = _mm_blend_epi16(tmp, s1, 0xF0);        // DCBA
    s1 = _mm_alignr_epi8(s1, tmp, 8);           // HGFE
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[0]), s0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[4]), s1);
}

const bool g_cpu_sha = cpu_has_sha();
#else
const bool g_cpu_sha = false;
#endif
std::atomic<bool> g_allow_hw{true};
} // namespace

bool Sha256::hardware_available() { return g_cpu_sha; }
bool Sha256::set_hardware_enabled(bool enabled) { return g_allow_hw.exchange(enabled); }
bool Sha256::hardware_active() { return g_cpu_sha && g_allow_hw.load(); }

Sha256::Sha256()
    : h_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
      buffer_{} {}

void Sha256::blocks(const std::uint8_t* p, std::size_t n) {
#ifdef BW_SHA_X86
    if (hardware_active()) {
        compress_shani(h_, p, n);
        return;
    }
#endif
    for (; n; --n, p += 64) block(p);
}

void Sha256::block(const std::uint8_t* p) {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t i = 0; i < 16; ++i)
        w[i] = (std::uint32_t(p[i * 4]) << 24) | (std::uint32_t(p[i * 4 + 1]) << 16) |
               (std::uint32_t(p[i * 4 + 2]) << 8) | std::uint32_t(p[i * 4 + 3]);
    for (std::size_t i = 16; i < 64; ++i) {
        const auto s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const auto s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    auto a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], q = h_[7];
    for (std::size_t i = 0; i < 64; ++i) {
        const auto t1 = q + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        const auto t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        q = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += q;
}

void Sha256::update(std::span<const std::uint8_t> in) {
    length_ += in.size();
    std::size_t i = 0;
    if (buffered_) {
        const std::size_t take = std::min(in.size(), 64 - buffered_);
        std::memcpy(buffer_ + buffered_, in.data(), take);
        buffered_ += take;
        i = take;
        if (buffered_ < 64) return;
        blocks(buffer_, 1);
        buffered_ = 0;
    }
    if (const std::size_t n = (in.size() - i) / 64) {
        blocks(in.data() + i, n);
        i += n * 64;
    }
    if (i < in.size()) {
        std::memcpy(buffer_, in.data() + i, in.size() - i);
        buffered_ = in.size() - i;
    }
}

std::string Sha256::hex_digest() {
    const std::uint64_t bits = length_ * 8;
    std::uint8_t pad[72]{};
    pad[0] = 0x80;
    const std::size_t pad_len = (buffered_ < 56 ? 56 - buffered_ : 120 - buffered_);
    for (int i = 0; i < 8; ++i) pad[pad_len + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
    update({pad, pad_len + 8});
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (auto v : h_)
        for (int s = 28; s >= 0; s -= 4) out += digits[(v >> s) & 0xf];
    return out;
}

std::string sha256(std::span<const std::uint8_t> in) {
    Sha256 h;
    h.update(in);
    return h.hex_digest();
}

} // namespace bw

namespace bw {

// MD5 (RFC 1321). Only used for interoperable fingerprints such as imphash;
// it is not a security primitive.
std::string md5(std::span<const std::uint8_t> in) {
    static const auto md5_k = [] {
        std::array<std::uint32_t, 64> k{};
        for (std::size_t i = 0; i < 64; ++i)
            k[i] = static_cast<std::uint32_t>(std::floor(std::fabs(std::sin(static_cast<double>(i + 1))) * 4294967296.0));
        return k;
    }();
    static constexpr std::uint32_t S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                            5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                                            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
    std::uint32_t h[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    auto rotl = [](std::uint32_t x, std::uint32_t c) { return (x << c) | (x >> (32 - c)); };
    auto process = [&](const std::uint8_t* p) {
        std::uint32_t m[16];
        for (std::size_t i = 0; i < 16; ++i)
            m[i] = std::uint32_t(p[i * 4]) | (std::uint32_t(p[i * 4 + 1]) << 8) | (std::uint32_t(p[i * 4 + 2]) << 16) |
                   (std::uint32_t(p[i * 4 + 3]) << 24);
        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        for (std::size_t i = 0; i < 64; ++i) {
            std::uint32_t f;
            std::size_t g;
            if (i < 16) { f = (b & c) | (~b & d); g = i; }
            else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
            else { f = c ^ (b | ~d); g = (7 * i) % 16; }
            const std::uint32_t t = d;
            d = c;
            c = b;
            b = b + rotl(a + f + md5_k[i] + m[g], S[i]);
            a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    };
    std::size_t i = 0;
    for (; in.size() - i >= 64; i += 64) process(in.data() + i);
    std::uint8_t tail[128]{};
    const std::size_t rest = in.size() - i;
    if (rest) std::memcpy(tail, in.data() + i, rest);
    tail[rest] = 0x80;
    const std::size_t tail_len = rest < 56 ? 64 : 128;
    const std::uint64_t bits = static_cast<std::uint64_t>(in.size()) * 8;
    for (std::size_t k = 0; k < 8; ++k) tail[tail_len - 8 + k] = static_cast<std::uint8_t>(bits >> (8 * k));
    for (std::size_t k = 0; k < tail_len; k += 64) process(tail + k);
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (auto v : h)
        for (int byte = 0; byte < 4; ++byte) {
            const auto x = (v >> (8 * byte)) & 0xff;
            out += digits[x >> 4];
            out += digits[x & 15];
        }
    return out;
}

} // namespace bw

namespace bw {

// SHA-1 (FIPS 180-4). Needed to check Authenticode digests made with SHA-1;
// not used for anything security-relevant on its own.
Sha1::Sha1() : h_{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}, buffer_{} {}

void Sha1::block(const std::uint8_t* p) {
    auto rotl = [](std::uint32_t x, int c) { return (x << c) | (x >> (32 - c)); };
    std::uint32_t w[80];
    for (std::size_t i = 0; i < 16; ++i)
        w[i] = (std::uint32_t(p[i * 4]) << 24) | (std::uint32_t(p[i * 4 + 1]) << 16) |
               (std::uint32_t(p[i * 4 + 2]) << 8) | std::uint32_t(p[i * 4 + 3]);
    for (std::size_t i = 16; i < 80; ++i) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
    for (std::size_t i = 0; i < 80; ++i) {
        std::uint32_t f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        const std::uint32_t t = rotl(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl(b, 30); b = a; a = t;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e;
}

void Sha1::update(std::span<const std::uint8_t> in) {
    length_ += in.size();
    std::size_t i = 0;
    if (buffered_) {
        const std::size_t take = std::min(in.size(), 64 - buffered_);
        std::memcpy(buffer_ + buffered_, in.data(), take);
        buffered_ += take;
        i = take;
        if (buffered_ < 64) return;
        block(buffer_);
        buffered_ = 0;
    }
    for (; in.size() - i >= 64; i += 64) block(in.data() + i);
    if (i < in.size()) {
        std::memcpy(buffer_, in.data() + i, in.size() - i);
        buffered_ = in.size() - i;
    }
}

std::string Sha1::hex_digest() {
    const std::uint64_t bits = length_ * 8;
    std::uint8_t pad[72]{};
    pad[0] = 0x80;
    const std::size_t pad_len = buffered_ < 56 ? 56 - buffered_ : 120 - buffered_;
    for (int i = 0; i < 8; ++i) pad[pad_len + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
    update({pad, pad_len + 8});
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (auto v : h_)
        for (int sh = 28; sh >= 0; sh -= 4) out += digits[(v >> sh) & 0xf];
    return out;
}

std::string sha1(std::span<const std::uint8_t> in) {
    Sha1 h;
    h.update(in);
    return h.hex_digest();
}

} // namespace bw
