#pragma once
// Deterministic builders for small but structurally complete PE and ELF
// images. Tests mutate the returned bytes using the documented offsets, so
// every malformed case is reproducible without committing binary blobs.
#include "binweaver/binweaver.hpp"

#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

namespace fixtures {

using Bytes = std::vector<std::uint8_t>;

class Writer {
public:
    explicit Writer(bool little = true) : little_(little) {}
    Bytes& bytes() { return b_; }
    std::size_t size() const { return b_.size(); }
    void ensure(std::size_t n) {
        if (b_.size() < n) b_.resize(n);
    }
    void put(std::size_t at, std::uint64_t v, int width) {
        ensure(at + static_cast<std::size_t>(width));
        for (int i = 0; i < width; ++i) {
            const int shift = little_ ? 8 * i : 8 * (width - 1 - i);
            b_[at + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> shift);
        }
    }
    void u8(std::size_t at, std::uint64_t v) { put(at, v, 1); }
    void u16(std::size_t at, std::uint64_t v) { put(at, v, 2); }
    void u32(std::size_t at, std::uint64_t v) { put(at, v, 4); }
    void u64(std::size_t at, std::uint64_t v) { put(at, v, 8); }
    void word(std::size_t at, std::uint64_t v, bool wide) { put(at, v, wide ? 8 : 4); }
    void str(std::size_t at, const std::string& s) {  // writes s plus a NUL
        ensure(at + s.size() + 1);
        std::memcpy(b_.data() + at, s.data(), s.size());
        b_[at + s.size()] = 0;
    }
    void fill(std::size_t at, std::size_t n, std::uint8_t v) {
        ensure(at + n);
        std::memset(b_.data() + at, v, n);
    }
    std::size_t align(std::size_t a) {
        ensure((b_.size() + a - 1) / a * a);
        return b_.size();
    }

private:
    Bytes b_;
    bool little_;
};

// ---------------------------------------------------------------- DER -----
// Tiny DER builder for test PKCS#7 structures (definite lengths only).
inline Bytes der(std::uint8_t tag, const Bytes& content) {
    Bytes b{tag};
    const std::size_t n = content.size();
    if (n < 0x80) b.push_back(static_cast<std::uint8_t>(n));
    else if (n < 0x100) b.insert(b.end(), {0x81, static_cast<std::uint8_t>(n)});
    else b.insert(b.end(), {0x82, static_cast<std::uint8_t>(n >> 8), static_cast<std::uint8_t>(n)});
    b.insert(b.end(), content.begin(), content.end());
    return b;
}
inline Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes b;
    for (const auto& p : parts) b.insert(b.end(), p.begin(), p.end());
    return b;
}
inline Bytes oid(std::initializer_list<std::uint32_t> arcs) {
    auto it = arcs.begin();
    const std::uint32_t first = *it++, second = *it++;
    Bytes b{static_cast<std::uint8_t>(first * 40 + second)};
    for (; it != arcs.end(); ++it) {
        Bytes enc;
        std::uint32_t v = *it;
        do {
            enc.insert(enc.begin(), static_cast<std::uint8_t>((v & 0x7f) | (enc.empty() ? 0 : 0x80)));
            v >>= 7;
        } while (v);
        b.insert(b.end(), enc.begin(), enc.end());
    }
    return der(0x06, b);
}
inline Bytes text(const std::string& s) { return der(0x0c, Bytes(s.begin(), s.end())); }
inline Bytes name(const std::string& cn, const std::string& o) {
    return der(0x30, cat({der(0x31, der(0x30, cat({oid({2, 5, 4, 6}), der(0x13, Bytes{'P', 'L'})}))),
                          der(0x31, der(0x30, cat({oid({2, 5, 4, 10}), text(o)}))),
                          der(0x31, der(0x30, cat({oid({2, 5, 4, 3}), text(cn)})))}));
}
inline Bytes ascii(const std::string& s) { return Bytes(s.begin(), s.end()); }

// Authenticode-shaped PKCS#7 SignedData: SHA-256 digest, one signer
// certificate. The signature bytes are dummies (BinWeaver does not verify them).
inline Bytes authenticode_blob(const Bytes& digest) {
    const Bytes sha256_alg = der(0x30, cat({oid({2, 16, 840, 1, 101, 3, 4, 2, 1}), der(0x05, {})}));
    const Bytes issuer = name("BinWeaver Test CA", "BinWeaver Tests");
    const Bytes serial = der(0x02, Bytes{0x01, 0x23, 0x45});
    const Bytes validity = der(0x30, cat({der(0x17, ascii("250101000000Z")), der(0x17, ascii("300101000000Z"))}));
    const Bytes rsa_sha256 = der(0x30, cat({oid({1, 2, 840, 113549, 1, 1, 11}), der(0x05, {})}));
    const Bytes tbs = der(0x30, cat({der(0xa0, der(0x02, Bytes{2})), serial, rsa_sha256, issuer, validity,
                                     name("BinWeaver Test Signer", "BinWeaver Tests"), der(0x30, {})}));
    const Bytes cert = der(0x30, cat({tbs, rsa_sha256, der(0x03, Bytes{0, 0})}));
    const Bytes spc = der(0x30, cat({der(0x30, oid({1, 3, 6, 1, 4, 1, 311, 2, 1, 15})),
                                     der(0x30, cat({sha256_alg, der(0x04, digest)}))}));
    const Bytes signer_info = der(0x30, cat({der(0x02, Bytes{1}), der(0x30, cat({issuer, serial})), sha256_alg,
                                             der(0x30, oid({1, 2, 840, 113549, 1, 1, 1})), der(0x04, Bytes(16, 0xee))}));
    const Bytes signed_data = der(0x30, cat({der(0x02, Bytes{1}), der(0x31, sha256_alg),
                                             der(0x30, cat({oid({1, 3, 6, 1, 4, 1, 311, 2, 1, 4}), der(0xa0, spc)})),
                                             der(0xa0, cert), der(0x31, signer_info)}));
    return der(0x30, cat({oid({1, 2, 840, 113549, 1, 7, 2}), der(0xa0, signed_data)}));
}

// ---------------------------------------------------------------- PE ------

namespace pe {
// One VS_VERSIONINFO-style block: header, UTF-16 key, value and children,
// each 32-bit aligned relative to the block start.
inline Bytes vs_block(const std::string& key, const Bytes& value, std::uint16_t type, std::uint16_t value_len,
                      const Bytes& children) {
    Bytes b(6);
    for (char c : key) {
        b.push_back(static_cast<std::uint8_t>(c));
        b.push_back(0);
    }
    b.push_back(0);
    b.push_back(0);
    while (b.size() % 4) b.push_back(0);
    b.insert(b.end(), value.begin(), value.end());
    while (b.size() % 4) b.push_back(0);
    b.insert(b.end(), children.begin(), children.end());
    b[0] = static_cast<std::uint8_t>(b.size());
    b[1] = static_cast<std::uint8_t>(b.size() >> 8);
    b[2] = static_cast<std::uint8_t>(value_len);
    b[3] = static_cast<std::uint8_t>(value_len >> 8);
    b[4] = static_cast<std::uint8_t>(type);
    return b;
}

inline Bytes version_info(const std::string& company) {
    Bytes text;
    for (char c : company) {
        text.push_back(static_cast<std::uint8_t>(c));
        text.push_back(0);
    }
    text.push_back(0);
    text.push_back(0);
    const auto str = vs_block("CompanyName", text, 1, static_cast<std::uint16_t>(company.size() + 1), {});
    const auto table = vs_block("040904b0", {}, 1, 0, str);
    const auto sfi = vs_block("StringFileInfo", {}, 1, 0, table);
    Writer ffi;
    ffi.u32(0, 0xfeef04bd);
    ffi.u32(4, 0x10000);
    ffi.u32(8, (1u << 16) | 2);   // file version 1.2.3.4
    ffi.u32(12, (3u << 16) | 4);
    ffi.u32(16, (1u << 16) | 2);  // product version 1.2.3.4
    ffi.u32(20, (3u << 16) | 4);
    ffi.ensure(52);
    return vs_block("VS_VERSION_INFO", ffi.bytes(), 0, 52, sfi);
}

// Minimal ECMA-335 metadata: BSJB root, #~ with Module/Assembly/AssemblyRef,
// #Strings, #GUID and #Blob. Offsets used by tests are listed in `dotnet_layout`.
namespace dotnet_layout {
constexpr std::size_t root = 0x48;         // metadata root, relative to the .clr section start
constexpr std::size_t tables = 96;         // #~ stream, relative to the root
constexpr std::size_t row_counts = tables + 24;
constexpr std::size_t strings = 184, guid = 216, blob = 232, size = 248;
} // namespace dotnet_layout

inline Bytes dotnet_metadata() {
    Bytes b;
    auto u8 = [&](std::uint32_t v) { b.push_back(static_cast<std::uint8_t>(v)); };
    auto u16 = [&](std::uint32_t v) { u8(v); u8(v >> 8); };
    auto u32 = [&](std::uint32_t v) { u16(v & 0xffff); u16(v >> 16); };
    auto str = [&](const std::string& s, std::size_t padded) {
        for (char c : s) u8(static_cast<unsigned char>(c));
        for (std::size_t i = s.size(); i < padded; ++i) u8(0);
    };
    using namespace dotnet_layout;
    u32(0x424a5342);  // "BSJB"
    u16(1);
    u16(1);
    u32(0);
    u32(12);
    str("v4.0.30319", 12);
    u16(0);
    u16(4);  // streams
    u32(tables); u32(strings - tables); str("#~", 4);
    u32(strings); u32(guid - strings); str("#Strings", 12);
    u32(guid); u32(blob - guid); str("#GUID", 8);
    u32(blob); u32(size - blob); str("#Blob", 8);
    // #~ header
    u32(0); u8(2); u8(0); u8(0); u8(1);
    const std::uint64_t valid = 1ull | (1ull << 0x20) | (1ull << 0x23);
    u32(static_cast<std::uint32_t>(valid)); u32(static_cast<std::uint32_t>(valid >> 32));
    u32(0); u32(0);  // sorted
    u32(1); u32(1); u32(1);  // rows: Module, Assembly, AssemblyRef
    u16(0); u16(1); u16(1); u16(0); u16(0);                                  // Module: "Fixture.dll", Mvid #1
    u32(0x8004); u16(1); u16(2); u16(3); u16(4); u32(1); u16(1); u16(13); u16(0);  // Assembly 1.2.3.4, full public key
    u16(4); u16(0); u16(0); u16(0); u32(0); u16(6); u16(21); u16(0); u16(0);   // AssemblyRef mscorlib 4.0.0.0, token
    // #Strings
    str(std::string("\0Fixture.dll\0Fixture\0mscorlib", 30), 32);
    // #GUID
    for (int i = 0; i < 16; ++i) u8(static_cast<std::uint32_t>(0xa0 + i));
    // #Blob: "", {01 02 03 04}, {b7 7a 5c 56 19 34 e0 89}
    for (std::uint32_t v : {0x00u, 0x04u, 0x01u, 0x02u, 0x03u, 0x04u, 0x08u, 0xb7u, 0x7au, 0x5cu, 0x56u, 0x19u, 0x34u,
                            0xe0u, 0x89u, 0x00u})
        u8(v);
    return b;
}

constexpr std::size_t rich_dans = 0x40, rich_marker = 0x58;
// Rich header with one (comp.id, count) entry and a correct checksum.
inline void write_rich(Writer& w) {
    const std::uint32_t comp = (0x0103u << 16) | 30159u, count = 7;
    auto rol = [](std::uint32_t v, std::uint32_t n) {
        n %= 32;
        return n ? (v << n) | (v >> (32 - n)) : v;
    };
    std::uint32_t key = static_cast<std::uint32_t>(rich_dans);
    for (std::size_t i = 0; i < rich_dans; ++i)
        if (i < 0x3c || i >= 0x40) key += rol(w.bytes()[i], static_cast<std::uint32_t>(i));
    key += rol(comp, count);
    w.u32(rich_dans, 0x536e6144u ^ key);
    for (std::size_t i = 4; i < 16; i += 4) w.u32(rich_dans + i, key);
    w.u32(rich_dans + 16, comp ^ key);
    w.u32(rich_dans + 20, count ^ key);
    w.u32(rich_marker, 0x68636952u);
    w.u32(rich_marker + 4, key);
}

constexpr std::size_t lfanew = 0x80;
constexpr std::size_t coff = lfanew + 4;
constexpr std::size_t optional = coff + 20;
inline std::size_t optional_size(bool plus) { return plus ? 240 : 224; }
inline std::size_t section_table(bool plus) { return optional + optional_size(plus); }
inline std::size_t data_directory(bool plus, int index) {
    return optional + (plus ? 112 : 96) + static_cast<std::size_t>(index) * 8;
}
// RVA -> file offset for the fixture's .rdata section.
constexpr std::size_t rdata_rva = 0x2000, rdata_raw = 0x600;
constexpr std::size_t rdata(std::size_t rva) { return rva - rdata_rva + rdata_raw; }
constexpr std::size_t import_descriptors = 0x2000;
constexpr std::size_t export_directory = 0x2200;
constexpr std::size_t export_functions = 0x2260;
constexpr std::size_t export_names = 0x2270;
constexpr std::size_t export_ordinals = 0x2280;
constexpr std::size_t debug_directory = 0x2300;
constexpr std::size_t text_raw = 0x400, data_raw = 0xa00;

struct Options {
    bool pe32plus = true;
    bool imports = true;
    bool exports = true;
    bool certificate = true;
    bool debug = true;
    std::size_t overlay = 0;          // bytes of overlay before the certificate table
    std::size_t data_padding = 0;     // extra bytes before .data (multiple of 0x200): moves it in the file
    std::uint8_t text_fill = 0xcc;    // body of .text
    bool second_user32_import = false;
    bool resources = true;            // VERSION resource (VS_VERSIONINFO) in .data
    bool rich = true;                 // Rich header in the DOS stub area
    bool dotnet = false;              // 4th section ".clr" with CLR header + ECMA-335 metadata
};

inline Bytes build(const Options& o = {}) {
    Writer w;
    const bool plus = o.pe32plus;
    const std::size_t thunk = plus ? 8 : 4;
    w.ensure(0x400);
    w.str(0, "MZ");
    w.u32(0x3c, lfanew);
    if (!o.rich) w.str(0x40, "DOS stub");
    w.u32(lfanew, 0x00004550);
    w.u16(coff, plus ? 0x8664 : 0x14c);
    w.u16(coff + 2, o.dotnet ? 4 : 3);  // sections
    w.u32(coff + 4, 0x5f5e100);
    w.u16(coff + 16, optional_size(plus));
    w.u16(coff + 18, 0x2022 | (plus ? 0 : 0x100));  // EXECUTABLE | LARGE_ADDRESS_AWARE | DLL (| 32BIT)
    // Optional header.
    w.u16(optional, plus ? 0x20b : 0x10b);
    w.u8(optional + 2, 14);
    w.u8(optional + 3, 36);
    w.u32(optional + 16, 0x1000);  // entry
    if (plus) w.u64(optional + 24, 0x180000000);
    else w.u32(optional + 28, 0x10000000);
    w.u32(optional + 32, 0x1000);  // SectionAlignment
    w.u32(optional + 36, 0x200);   // FileAlignment
    w.u16(optional + 40, 6);
    w.u32(optional + 56, o.dotnet ? 0x5000 : 0x4000);  // SizeOfImage
    w.u32(optional + 60, 0x400);   // SizeOfHeaders
    w.u16(optional + 68, 3);       // console
    w.u16(optional + 70, plus ? 0x160 : 0x140);
    w.u32(optional + (plus ? 108 : 92), 16);

    struct Sec { const char* name; std::uint32_t vsize, va, raw_size, raw; std::uint32_t chars; };
    const std::uint32_t data_raw_actual = static_cast<std::uint32_t>(data_raw + o.data_padding);
    const std::uint32_t clr_raw = data_raw_actual + 0x200;
    const Sec secs[4] = {{".text", 0x30, 0x1000, 0x200, static_cast<std::uint32_t>(text_raw), 0x60000020},
                         {".rdata", 0x400, 0x2000, 0x400, static_cast<std::uint32_t>(rdata_raw), 0x40000040},
                         {".data", 0x400, 0x3000, 0x200, data_raw_actual, 0xc0000040},
                         {".clr", 0x200, 0x4000, 0x200, clr_raw, 0x40000040}};
    for (int i = 0; i < (o.dotnet ? 4 : 3); ++i) {
        const std::size_t at = section_table(plus) + static_cast<std::size_t>(i) * 40;
        std::memcpy(w.bytes().data() + at, secs[i].name, std::strlen(secs[i].name));
        w.u32(at + 8, secs[i].vsize);
        w.u32(at + 12, secs[i].va);
        w.u32(at + 16, secs[i].raw_size);
        w.u32(at + 20, secs[i].raw);
        w.u32(at + 36, secs[i].chars);
    }
    w.fill(text_raw, 0x200, 0);
    w.fill(text_raw, 0x30, o.text_fill);
    w.u8(text_raw, 0xc3);
    w.fill(rdata_raw, 0x400, 0);
    w.fill(data_raw_actual, 0x200, 0);
    w.str(data_raw_actual, "initialized data");

    auto dir = [&](int index, std::uint64_t address, std::uint64_t size) {
        w.u32(data_directory(plus, index), address);
        w.u32(data_directory(plus, index) + 4, size);
    };
    if (o.imports) {
        // Descriptors: KERNEL32, USER32, null.
        const std::size_t ilt_k = 0x2040, ilt_u = 0x2060, iat_k = 0x2080, iat_u = 0x20a0;
        const std::size_t d0 = rdata(import_descriptors);
        w.u32(d0 + 0, ilt_k);
        w.u32(d0 + 12, 0x2140);
        w.u32(d0 + 16, iat_k);
        w.u32(d0 + 20, ilt_u);
        w.u32(d0 + 32, 0x2150);
        w.u32(d0 + 36, iat_u);
        const std::uint64_t ord_flag = plus ? (1ull << 63) : (1ull << 31);
        for (std::size_t base : {ilt_k, iat_k}) {
            w.word(rdata(base), 0x2100, plus);
            w.word(rdata(base) + thunk, ord_flag | 17, plus);
        }
        for (std::size_t base : {ilt_u, iat_u}) {
            w.word(rdata(base), 0x2120, plus);
            if (o.second_user32_import) w.word(rdata(base) + thunk, 0x2130, plus);
        }
        w.u16(rdata(0x2100), 5);
        w.str(rdata(0x2102), "ExitProcess");
        w.u16(rdata(0x2120), 0x1f);
        w.str(rdata(0x2122), "MessageBoxA");
        w.u16(rdata(0x2130), 0x20);
        w.str(rdata(0x2132), "MessageBoxW");
        w.str(rdata(0x2140), "KERNEL32.dll");
        w.str(rdata(0x2150), "USER32.dll");
        dir(1, import_descriptors, 60);
        dir(12, 0x2080, 0x40);
    }
    if (o.exports) {
        const std::size_t e = rdata(export_directory);
        w.u32(e + 12, 0x2240);
        w.u32(e + 16, 1);  // ordinal base
        w.u32(e + 20, 4);
        w.u32(e + 24, 3);
        w.u32(e + 28, export_functions);
        w.u32(e + 32, export_names);
        w.u32(e + 36, export_ordinals);
        w.str(rdata(0x2240), "fixture.dll");
        const std::uint32_t fns[4] = {0x1000, 0x1010, 0x1020, 0x22b0};
        for (std::size_t i = 0; i < 4; ++i) w.u32(rdata(export_functions) + i * 4, fns[i]);
        const std::uint32_t names[3] = {0x2290, 0x2298, 0x22a0};
        const std::uint16_t ords[3] = {0, 1, 3};
        for (std::size_t i = 0; i < 3; ++i) {
            w.u32(rdata(export_names) + i * 4, names[i]);
            w.u16(rdata(export_ordinals) + i * 2, ords[i]);
        }
        w.str(rdata(0x2290), "alpha");
        w.str(rdata(0x2298), "beta");
        w.str(rdata(0x22a0), "gamma");
        w.str(rdata(0x22b0), "KERNEL32.ExitProcess");
        dir(0, export_directory, 0x100);
    }
    if (o.debug) {
        const std::string pdb = "C:\\fixture\\fixture.pdb";
        const std::size_t cv_rva = 0x2320;
        const std::size_t d = rdata(debug_directory);
        w.u32(d + 12, 2);
        w.u32(d + 16, static_cast<std::uint32_t>(24 + pdb.size() + 1));
        w.u32(d + 20, cv_rva);
        w.u32(d + 24, rdata(cv_rva));
        w.str(rdata(cv_rva), "RSDS");
        for (std::size_t i = 0; i < 16; ++i) w.u8(rdata(cv_rva) + 4 + i, 0x10 + i);
        w.u32(rdata(cv_rva) + 20, 1);
        w.str(rdata(cv_rva) + 24, pdb);
        dir(6, debug_directory, 28);
    }
    if (o.resources) {
        const std::size_t base = data_raw_actual;  // .data: RVA 0x3000 <-> file data_raw_actual
        auto at = [&](std::size_t rva) { return base + rva - 0x3000; };
        // root -> type 16 (VERSION) -> name 1 -> language 0x409 -> data entry
        w.u16(at(0x3020) + 14, 1);
        w.u32(at(0x3020) + 16, 16);
        w.u32(at(0x3020) + 20, 0x80000000u | 0x18);
        w.u16(at(0x3038) + 14, 1);
        w.u32(at(0x3038) + 16, 1);
        w.u32(at(0x3038) + 20, 0x80000000u | 0x30);
        w.u16(at(0x3050) + 14, 1);
        w.u32(at(0x3050) + 16, 0x409);
        w.u32(at(0x3050) + 20, 0x48);
        const auto vi = version_info("BinWeaver Tests");
        w.u32(at(0x3068), 0x3080);
        w.u32(at(0x3068) + 4, vi.size());
        w.u32(at(0x3068) + 8, 1200);
        std::memcpy(w.bytes().data() + at(0x3080), vi.data(), vi.size());
        dir(2, 0x3020, 0x60);
    }
    if (o.dotnet) {
        w.fill(clr_raw, 0x200, 0);
        const auto md = dotnet_metadata();
        // IMAGE_COR20_HEADER at RVA 0x4000, metadata right after it.
        w.u32(clr_raw, 72);
        w.u16(clr_raw + 4, 2);
        w.u16(clr_raw + 6, 5);
        w.u32(clr_raw + 8, 0x4048);
        w.u32(clr_raw + 12, md.size());
        w.u32(clr_raw + 16, 1);  // ILONLY
        std::memcpy(w.bytes().data() + clr_raw + 0x48, md.data(), md.size());
        dir(14, 0x4000, 72);
    }
    if (o.rich) write_rich(w);
    std::size_t end = data_raw_actual + 0x200 + (o.dotnet ? 0x200 : 0);
    w.ensure(end);
    if (o.overlay) {
        w.fill(end, o.overlay, 0x5a);
        end += o.overlay;
    }
    if (o.certificate) {
        // Authenticode image digest: everything before the certificate table
        // except the CheckSum field and the security directory entry.
        const std::size_t cs = optional + 64, sd = data_directory(plus, 4);
        bw::Sha256 h;
        const auto& b = w.bytes();
        h.update(std::span(b).subspan(0, cs));
        h.update(std::span(b).subspan(cs + 4, sd - cs - 4));
        h.update(std::span(b).subspan(sd + 8, end - sd - 8));
        const auto hex_digest = h.hex_digest();
        Bytes digest;
        for (std::size_t i = 0; i < hex_digest.size(); i += 2)
            digest.push_back(static_cast<std::uint8_t>(std::stoul(hex_digest.substr(i, 2), nullptr, 16)));
        const Bytes blob = authenticode_blob(digest);
        const std::size_t length = 8 + blob.size(), padded = (length + 7) / 8 * 8;
        w.u32(end, length);
        w.u16(end + 4, 0x0200);
        w.u16(end + 6, 2);
        w.ensure(end + padded);
        std::memcpy(w.bytes().data() + end + 8, blob.data(), blob.size());
        dir(4, end, padded);
    }
    return w.bytes();
}
} // namespace pe

// ---------------------------------------------------------------- ELF -----

namespace elf {

struct Options {
    bool wide = true;
    bool little = true;
    std::string needed = "libc.so.6";
    std::string build_id = "0123456789abcdef0123456789abcdef01234567";  // hex, 20 bytes
    bool extended_numbering = false;  // store e_shnum/e_shstrndx/e_phnum in section 0
    bool relr = false;                // add a .relr.dyn section (address + bitmap)
    std::uint8_t text_fill = 0x90;
};

// Offsets of interesting structures, filled in by build().
struct Layout {
    std::size_t phoff{}, shoff{}, shnum{}, shentsize{}, phentsize{}, phnum{};
    std::size_t dynsym{}, dynstr{}, rela{}, text{}, dynamic{}, symtab{}, strtab{}, shstrtab{}, note{};
    std::size_t index_dynsym{}, index_symtab{}, index_rela{}, index_text{}, index_strtab{}, index_note{};
    std::size_t versym{}, verneed{}, index_versym{}, index_verneed{};
    std::size_t relr{}, index_relr{};
    std::uint64_t relr_address{};
    std::uint64_t base{};
};

inline Bytes build(const Options& o = {}, Layout* out = nullptr) {
    Writer w(o.little);
    Layout L;
    const bool W = o.wide;
    const std::uint64_t base = W ? 0x400000 : 0x8048000;
    const std::uint16_t machine = o.little ? (W ? 62 : 3) : (W ? 21 : 20);
    const std::size_t ehsize = W ? 64 : 52, phent = W ? 56 : 32, shent = W ? 64 : 40;
    const std::size_t syment = W ? 24 : 16, dynent = W ? 16 : 8, relent = W ? 24 : 12;
    const std::size_t nph = 6;
    L.base = base;
    L.phoff = ehsize;
    L.phentsize = phent;
    L.phnum = nph;
    w.ensure(ehsize + nph * phent);

    auto addr = [&](std::size_t off) { return base + off; };
    // .interp
    w.align(8);
    const std::size_t interp = w.size();
    const std::string interp_s = W ? "/lib64/ld-linux-x86-64.so.2" : "/lib/ld-linux.so.2";
    w.str(interp, interp_s);
    // .note.gnu.build-id
    w.align(4);
    L.note = w.size();
    const std::size_t idlen = o.build_id.size() / 2;
    w.u32(L.note, 4);
    w.u32(L.note + 4, idlen);
    w.u32(L.note + 8, 3);
    w.str(L.note + 12, "GNU");
    for (std::size_t i = 0; i < idlen; ++i)
        w.u8(L.note + 16 + i, std::stoul(o.build_id.substr(i * 2, 2), nullptr, 16));
    w.ensure(L.note + 16 + ((idlen + 3) / 4) * 4);
    // .dynstr
    const std::string dynstr = std::string("\0", 1) + o.needed + '\0' + "puts" + '\0' + "exported_fn" + '\0' + "libfixture.so" + '\0' + "GLIBC_2.2.5" + '\0';
    const std::uint32_t ds_needed = 1, ds_puts = static_cast<std::uint32_t>(1 + o.needed.size() + 1),
                        ds_exported = ds_puts + 5, ds_soname = ds_exported + 12, ds_glibc = ds_soname + 14;
    w.align(8);
    L.dynstr = w.size();
    w.ensure(L.dynstr + dynstr.size());
    std::memcpy(w.bytes().data() + L.dynstr, dynstr.data(), dynstr.size());
    // .dynsym: null, puts (UND), exported_fn (.text)
    w.align(8);
    L.dynsym = w.size();
    w.ensure(L.dynsym + 3 * syment);
    // .text placed later; index fixed below.
    const std::size_t text_index = 6;
    auto sym = [&](std::size_t at, std::uint32_t name, std::uint64_t value, std::uint64_t size, std::uint8_t info,
                   std::uint16_t shndx) {
        w.u32(at, name);
        if (W) {
            w.u8(at + 4, info);
            w.u16(at + 6, shndx);
            w.u64(at + 8, value);
            w.u64(at + 16, size);
        } else {
            w.u32(at + 4, value);
            w.u32(at + 8, size);
            w.u8(at + 12, info);
            w.u16(at + 14, shndx);
        }
    };
    // .rela.dyn: GLOB_DAT puts, RELATIVE
    w.align(8);
    L.rela = w.size();
    w.ensure(L.rela + 2 * relent);
    // .text
    w.align(16);
    L.text = w.size();
    w.fill(L.text, 0x20, o.text_fill);
    const std::uint64_t entry = addr(L.text);
    sym(L.dynsym + syment, ds_puts, 0, 0, 0x12, 0);
    sym(L.dynsym + 2 * syment, ds_exported, entry + 0x10, 0x10, 0x12, static_cast<std::uint16_t>(text_index));
    // Second PT_LOAD (RW) starts at the next page-congruent address.
    w.align(16);
    L.dynamic = w.size();
    const std::uint64_t rw_base = 0x1000;  // vaddr = base + rw_base + offset
    auto rwaddr = [&](std::size_t off) { return base + rw_base + off; };
    const std::uint64_t bss_addr = rwaddr(L.dynamic) + 0x100;
    {
        const std::uint64_t rinfo_glob = W ? ((1ull << 32) | 6) : ((1u << 8) | 6);
        const std::uint64_t rinfo_rel = 8;
        w.word(L.rela, bss_addr, W);
        w.word(L.rela + (W ? 8 : 4), rinfo_glob, W);
        w.word(L.rela + (W ? 16 : 8), 0, W);
        w.word(L.rela + relent, bss_addr + 8, W);
        w.word(L.rela + relent + (W ? 8 : 4), rinfo_rel, W);
        w.word(L.rela + relent + (W ? 16 : 8), entry + 0x10, W);
    }
    const std::pair<std::uint64_t, std::uint64_t> dyn[] = {
        {1, ds_needed}, {14, ds_soname}, {5, addr(L.dynstr)}, {10, dynstr.size()}, {6, addr(L.dynsym)},
        {11, syment}, {7, addr(L.rela)}, {8, 2 * relent}, {9, relent}, {0x6ffffffb, 0x08000001}, {0, 0}};
    for (std::size_t i = 0; i < std::size(dyn); ++i) {
        w.word(L.dynamic + i * dynent, dyn[i].first, W);
        w.word(L.dynamic + i * dynent + (W ? 8 : 4), dyn[i].second, W);
    }
    const std::size_t dynamic_size = std::size(dyn) * dynent;
    w.ensure(L.dynamic + dynamic_size);
    // .symtab: null, FILE, local FUNC, global FUNC
    const std::string strtab = std::string("\0", 1) + "fixture.c" + '\0' + "local_helper" + '\0' + "exported_fn" + '\0';
    w.align(8);
    L.symtab = w.size();
    w.ensure(L.symtab + 4 * syment);
    sym(L.symtab + syment, 1, 0, 0, 0x04, 0xfff1);
    sym(L.symtab + 2 * syment, 11, entry, 0x10, 0x02, static_cast<std::uint16_t>(text_index));
    sym(L.symtab + 3 * syment, 24, entry + 0x10, 0x10, 0x12, static_cast<std::uint16_t>(text_index));
    L.strtab = w.size();
    w.ensure(L.strtab + strtab.size());
    std::memcpy(w.bytes().data() + L.strtab, strtab.data(), strtab.size());

    // GNU symbol versioning: puts@GLIBC_2.2.5 (index 2), exported_fn global (index 1).
    w.align(8);
    L.versym = w.size();
    w.u16(L.versym, 0);
    w.u16(L.versym + 2, 2);
    w.u16(L.versym + 4, 1);
    w.align(8);
    L.verneed = w.size();
    w.u16(L.verneed, 1);                      // vn_version
    w.u16(L.verneed + 2, 1);                  // vn_cnt
    w.u32(L.verneed + 4, ds_needed);          // vn_file
    w.u32(L.verneed + 8, 16);                 // vn_aux
    w.u32(L.verneed + 12, 0);                 // vn_next
    w.u32(L.verneed + 16, 0x09691a75);        // vna_hash ("GLIBC_2.2.5")
    w.u16(L.verneed + 20, 0);                 // vna_flags
    w.u16(L.verneed + 22, 2);                 // vna_other: version index
    w.u32(L.verneed + 24, ds_glibc);          // vna_name
    w.u32(L.verneed + 28, 0);                 // vna_next

    // RELR: address A, then bitmap 0b1011 relocating A+word and A+3*word.
    if (o.relr) {
        w.align(8);
        L.relr = w.size();
        L.relr_address = base + 0x2000;
        const std::size_t word = W ? 8 : 4;
        w.word(L.relr, L.relr_address, W);
        w.word(L.relr + word, (0b101u << 1) | 1u, W);
    }

    // Section name table.
    std::vector<const char*> names = {"", ".interp", ".note.gnu.build-id", ".dynstr", ".dynsym", ".rela.dyn", ".text",
                                      ".dynamic", ".bss", ".symtab", ".strtab", ".shstrtab", ".gnu.version", ".gnu.version_r"};
    if (o.relr) names.push_back(".relr.dyn");
    const std::size_t nsec = names.size();
    std::string shstr;
    std::vector<std::uint32_t> name_off;
    for (const char* n : names) {
        name_off.push_back(static_cast<std::uint32_t>(shstr.size()));
        shstr += n;
        shstr += '\0';
    }
    L.shstrtab = w.size();
    w.ensure(L.shstrtab + shstr.size());
    std::memcpy(w.bytes().data() + L.shstrtab, shstr.data(), shstr.size());
    w.align(8);
    L.shoff = w.size();
    L.shnum = nsec;
    L.shentsize = shent;
    w.ensure(L.shoff + nsec * shent);
    L.index_note = 2; L.index_dynsym = 4; L.index_rela = 5; L.index_text = text_index; L.index_symtab = 9; L.index_strtab = 10;
    L.index_versym = 12; L.index_verneed = 13;

    auto shdr = [&](std::size_t i, std::uint32_t type, std::uint64_t flags, std::uint64_t a, std::size_t off,
                    std::uint64_t size, std::uint32_t link, std::uint32_t info, std::uint64_t align, std::uint64_t entsize) {
        const std::size_t at = L.shoff + i * shent;
        w.u32(at, name_off[i]);
        w.u32(at + 4, type);
        w.word(at + 8, flags, W);
        w.word(at + (W ? 16 : 12), a, W);
        w.word(at + (W ? 24 : 16), off, W);
        w.word(at + (W ? 32 : 20), size, W);
        w.u32(at + (W ? 40 : 24), link);
        w.u32(at + (W ? 44 : 28), info);
        w.word(at + (W ? 48 : 32), align, W);
        w.word(at + (W ? 56 : 36), entsize, W);
    };
    shdr(1, 1, 2, addr(interp), interp, interp_s.size() + 1, 0, 0, 1, 0);
    shdr(2, 7, 2, addr(L.note), L.note, 16 + ((idlen + 3) / 4) * 4, 0, 0, 4, 0);
    shdr(3, 3, 2, addr(L.dynstr), L.dynstr, dynstr.size(), 0, 0, 1, 0);
    shdr(4, 11, 2, addr(L.dynsym), L.dynsym, 3 * syment, 3, 1, 8, syment);
    shdr(5, 4, 2, addr(L.rela), L.rela, 2 * relent, 4, 0, 8, relent);
    shdr(6, 1, 6, entry, L.text, 0x20, 0, 0, 16, 0);
    shdr(7, 6, 3, rwaddr(L.dynamic), L.dynamic, dynamic_size, 3, 0, 8, dynent);
    shdr(8, 8, 3, bss_addr, L.dynamic + dynamic_size, 0x40, 0, 0, 8, 0);
    shdr(9, 2, 0, 0, L.symtab, 4 * syment, 10, 3, 8, syment);
    shdr(10, 3, 0, 0, L.strtab, strtab.size(), 0, 0, 1, 0);
    shdr(11, 3, 0, 0, L.shstrtab, shstr.size(), 0, 0, 1, 0);
    shdr(12, 0x6fffffff, 2, 0, L.versym, 6, 4, 0, 2, 2);
    shdr(13, 0x6ffffffe, 2, 0, L.verneed, 32, 3, 1, 8, 0);
    if (o.relr) {
        L.index_relr = 14;
        shdr(14, 19, 2, 0, L.relr, W ? 16 : 8, 0, 0, 8, W ? 8 : 4);
    }

    // Program headers.
    auto phdr = [&](std::size_t i, std::uint32_t type, std::uint32_t flags, std::size_t off, std::uint64_t va,
                    std::uint64_t filesz, std::uint64_t memsz, std::uint64_t align) {
        const std::size_t at = L.phoff + i * phent;
        w.u32(at, type);
        if (W) {
            w.u32(at + 4, flags);
            w.u64(at + 8, off);
            w.u64(at + 16, va);
            w.u64(at + 24, va);
            w.u64(at + 32, filesz);
            w.u64(at + 40, memsz);
            w.u64(at + 48, align);
        } else {
            w.u32(at + 4, off);
            w.u32(at + 8, va);
            w.u32(at + 12, va);
            w.u32(at + 16, filesz);
            w.u32(at + 20, memsz);
            w.u32(at + 24, flags);
            w.u32(at + 28, align);
        }
    };
    phdr(0, 3, 4, interp, addr(interp), interp_s.size() + 1, interp_s.size() + 1, 1);
    phdr(1, 1, 5, 0, base, L.text + 0x20, L.text + 0x20, 0x1000);
    phdr(2, 1, 6, L.dynamic, rwaddr(L.dynamic), dynamic_size, 0x100 + 0x40, 0x1000);
    phdr(3, 2, 6, L.dynamic, rwaddr(L.dynamic), dynamic_size, dynamic_size, 8);
    phdr(4, 4, 4, L.note, addr(L.note), 16 + ((idlen + 3) / 4) * 4, 16 + ((idlen + 3) / 4) * 4, 4);
    phdr(5, 0x6474e551, 6, 0, 0, 0, 0, 16);

    // ELF header.
    auto& b = w.bytes();
    b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = W ? 2 : 1;
    b[5] = o.little ? 1 : 2;
    b[6] = 1;
    w.u16(16, 3);  // ET_DYN
    w.u16(18, machine);
    w.u32(20, 1);
    w.word(24, entry, W);
    w.word(W ? 32 : 28, L.phoff, W);
    w.word(W ? 40 : 32, L.shoff, W);
    w.u16(W ? 52 : 40, ehsize);
    w.u16(W ? 54 : 42, phent);
    w.u16(W ? 56 : 44, nph);
    w.u16(W ? 58 : 46, shent);
    w.u16(W ? 60 : 48, nsec);
    w.u16(W ? 62 : 50, 11);
    if (o.extended_numbering) {
        w.u16(W ? 60 : 48, 0);       // e_shnum -> sh[0].sh_size
        w.u16(W ? 62 : 50, 0xffff);  // e_shstrndx -> sh[0].sh_link
        w.u16(W ? 56 : 44, 0xffff);  // e_phnum -> sh[0].sh_info
        const std::size_t s0 = L.shoff;
        w.word(s0 + (W ? 32 : 20), nsec, W);
        w.u32(s0 + (W ? 40 : 24), 11);
        w.u32(s0 + (W ? 44 : 28), nph);
    }
    if (out) *out = L;
    return w.bytes();
}

} // namespace elf
} // namespace fixtures
