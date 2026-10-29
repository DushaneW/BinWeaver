#include "binweaver/binweaver.hpp"
#include "check.hpp"
#include "fixtures.hpp"

#include <algorithm>
#include <random>

using namespace bw;
namespace pe = fixtures::pe;

namespace {
Analysis run(const fixtures::Bytes& b) { return analyze(FileImage::from_bytes(b, "fixture.dll")); }

bool has_code(const Analysis& a, std::string_view code) {
    return std::any_of(a.diagnostics.begin(), a.diagnostics.end(), [&](const Diagnostic& d) { return d.code == code; });
}

std::size_t count_at_least(const Analysis& a, Severity s) {
    return static_cast<std::size_t>(std::count_if(a.diagnostics.begin(), a.diagnostics.end(), [&](const Diagnostic& d) {
        return static_cast<int>(d.severity) >= static_cast<int>(s);
    }));
}

void put32(fixtures::Bytes& b, std::size_t at, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b[at + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> (8 * i));
}
void put16(fixtures::Bytes& b, std::size_t at, std::uint16_t v) {
    b[at] = static_cast<std::uint8_t>(v);
    b[at + 1] = static_cast<std::uint8_t>(v >> 8);
}
} // namespace

TEST_CASE("pe.fixture.clean") {
    for (bool plus : {true, false}) {
        pe::Options o;
        o.pe32plus = plus;
        const auto a = run(pe::build(o));
        CHECK(a.format == Format::PE);
        CHECK_EQ(a.architecture, std::string(plus ? "x86-64" : "x86"));
        CHECK_EQ(a.bitness, std::string(plus ? "64-bit" : "32-bit"));
        CHECK_EQ(a.file_type, std::string("DLL"));
        CHECK_EQ(a.entry_point, 0x1000u);
        CHECK_EQ(a.image_base, plus ? 0x180000000ull : 0x10000000ull);
        CHECK(a.structurally_valid);
        // A well-formed image produces no warnings or errors, only the
        // informational "certificates not verified" note.
        CHECK_EQ(count_at_least(a, Severity::Warning), 0u);
        CHECK(has_code(a, "pe.certificate.not_verified"));
        for (const auto& d : a.diagnostics)
            if (d.severity != Severity::Info) std::cerr << "  unexpected: " << d.code << " " << d.message << '\n';

        REQUIRE(a.sections.size() == 3);
        CHECK_EQ(a.sections[0].name, std::string(".text"));
        CHECK_EQ(a.sections[0].flags_text, std::string("R-X CODE"));
        CHECK_EQ(a.sections[1].id, std::string("section:.rdata"));
        CHECK(a.sections[2].entropy.has_value());

        REQUIRE(a.imports.size() == 3);
        CHECK_EQ(a.imports[0].library, std::string("KERNEL32.dll"));
        CHECK_EQ(a.imports[0].name, std::string("ExitProcess"));
        CHECK_EQ(a.imports[0].hint, 5u);
        CHECK_EQ(a.imports[0].thunk_rva, 0x2080u);
        CHECK(a.imports[1].ordinal.has_value() && *a.imports[1].ordinal == 17);
        CHECK_EQ(a.imports[2].library, std::string("USER32.dll"));
        CHECK_EQ(a.imports[2].name, std::string("MessageBoxA"));

        REQUIRE(a.exports.size() == 4);
        CHECK_EQ(a.exports[0].name, std::string("alpha"));
        CHECK_EQ(a.exports[0].ordinal, 1u);
        CHECK(a.exports[2].name.empty());  // ordinal-only
        CHECK_EQ(a.exports[2].ordinal, 3u);
        CHECK_EQ(a.exports[3].name, std::string("gamma"));
        CHECK_EQ(a.exports[3].forwarder, std::string("KERNEL32.ExitProcess"));
        CHECK(a.property("Export DLL name") && *a.property("Export DLL name") == "fixture.dll");

        REQUIRE(a.certificates.size() == 1);
        CHECK_EQ(a.certificates[0].type, 2u);
        CHECK_EQ(a.certificates[0].revision, 0x200u);
        CHECK(a.property("PDB path") && *a.property("PDB path") == "C:\\fixture\\fixture.pdb");
        CHECK(a.property("DEP (NX_COMPAT)") && *a.property("DEP (NX_COMPAT)") == "set");
        CHECK(!a.property("Overlay"));
    }
}

TEST_CASE("pe.rva_mapping") {
    const auto a = run(pe::build());
    auto m = address_to_offset(a, 0x2102);
    CHECK(m.status == MapStatus::FileBacked);
    CHECK_EQ(m.offset, pe::rdata(0x2102));
    CHECK_EQ(m.mapping, std::string(".rdata"));
    CHECK(address_to_offset(a, 0x10).status == MapStatus::FileBacked);  // headers map 1:1
    CHECK_EQ(address_to_offset(a, 0x10).offset, 0x10u);
    // .data: 0x200 bytes of file data, 0x400 bytes in memory.
    CHECK(address_to_offset(a, 0x3100).status == MapStatus::FileBacked);
    CHECK(address_to_offset(a, 0x3300).status == MapStatus::ZeroFill);
    CHECK(address_to_offset(a, 0x9000).status == MapStatus::Unmapped);
    // .text: VirtualSize 0x30 < SizeOfRawData; bytes past 0x30 are not mapped from the file.
    CHECK(address_to_offset(a, 0x1040).status == MapStatus::Unmapped);
    const auto back = offset_to_addresses(a, pe::rdata(0x2102));
    CHECK(std::find(back.begin(), back.end(), 0x2102u) != back.end());
    // locate(): the import descriptor offset is inside .rdata and the Import directory.
    const auto regions = locate(a, pe::rdata(pe::import_descriptors) + 4);
    REQUIRE(regions.size() >= 2);
    CHECK_EQ(regions[0].name, std::string("Import"));
    CHECK(std::any_of(regions.begin(), regions.end(), [](const Region& r) { return r.name == ".rdata"; }));
}

TEST_CASE("pe.directories.validation") {
    const auto a = run(pe::build());
    REQUIRE(a.directories.size() == 16);
    CHECK_EQ(a.directories[1].status, std::string("ok"));
    CHECK(a.directories[1].file_offset && *a.directories[1].file_offset == pe::rdata(pe::import_descriptors));
    CHECK_EQ(a.directories[2].status, std::string("ok"));  // resources
    CHECK_EQ(a.directories[3].status, std::string("empty"));
    CHECK_EQ(a.directories[4].status, std::string("ok"));  // security: file offset
}

TEST_CASE("pe.malformed.headers") {
    CHECK(has_code(run({'M', 'Z'}), "pe.dos.truncated"));
    auto b = pe::build();
    put32(b, 0x3c, 0xfffffff0);
    auto a = run(b);
    CHECK(has_code(a, "pe.nt.out_of_range"));
    CHECK(!a.structurally_valid);

    b = pe::build();
    b[pe::lfanew] = 'X';
    CHECK(has_code(run(b), "pe.nt.signature"));

    b = pe::build();
    put16(b, pe::optional, 0x1234);
    a = run(b);
    CHECK(has_code(a, "pe.optional.magic"));
    CHECK_EQ(a.sections.size(), 3u);  // the section table is still readable

    b = pe::build();
    put16(b, pe::coff + 16, 0xffff);  // SizeOfOptionalHeader beyond the file
    CHECK(has_code(run(b), "pe.optional.out_of_range"));

    b = pe::build();
    put16(b, pe::coff + 16, 0x50);  // too short for the standard fields
    CHECK(has_code(run(b), "pe.optional.short"));

    b = pe::build();
    put32(b, pe::optional + 108, 0xffffffff);  // NumberOfRvaAndSizes
    a = run(b);
    CHECK(has_code(a, "pe.directories.count"));
    CHECK_EQ(a.directories.size(), 16u);
    CHECK_EQ(a.imports.size(), 3u);

    b = pe::build();
    put32(b, pe::optional + 36, 3);  // FileAlignment not a power of two
    CHECK(has_code(run(b), "pe.optional.alignment"));

    b = pe::build();
    put16(b, pe::coff + 2, 2000);  // section count beyond the file
    a = run(b);
    CHECK(has_code(a, "pe.sections.count_high"));
    CHECK(has_code(a, "pe.sections.out_of_range"));
}

TEST_CASE("pe.malformed.sections") {
    auto b = pe::build();
    const std::size_t data_hdr = pe::section_table(true) + 2 * 40;
    put32(b, data_hdr + 20, 0x7ffffe00);  // PointerToRawData far beyond EOF
    auto a = run(b);
    CHECK(has_code(a, "pe.section.raw_out_of_range"));
    CHECK(!a.sections[2].file_range_valid);
    CHECK(!a.sections[2].entropy.has_value());

    b = pe::build();
    put32(b, pe::section_table(true) + 40 + 12, 0x1010);  // .rdata VA overlaps .text
    a = run(b);
    CHECK(has_code(a, "pe.section.virtual_overlap"));
    CHECK(has_code(a, "pe.section.va_misaligned"));

    b = pe::build();
    put32(b, pe::section_table(true) + 40 + 20, 0x610);  // not 512-aligned: loader rounds down
    a = run(b);
    CHECK(has_code(a, "pe.section.raw_pointer_rounded"));
    CHECK_EQ(a.sections[1].offset, 0x600u);

    b = pe::build();
    put32(b, pe::optional + 16, 0x2000);  // entry point in non-executable .rdata
    CHECK(has_code(run(b), "pe.entry.not_executable"));
    put32(b, pe::optional + 16, 0x9000);
    CHECK(has_code(run(b), "pe.entry.outside_sections"));
}

TEST_CASE("pe.malformed.imports") {
    // Descriptor DLL name RVA pointing nowhere.
    auto b = pe::build();
    put32(b, pe::rdata(pe::import_descriptors) + 12, 0x7fff0000);
    auto a = run(b);
    CHECK(has_code(a, "pe.import.library_name"));
    CHECK(std::any_of(a.imports.begin(), a.imports.end(), [](const Import& i) { return i.library == "<invalid>"; }));

    // Hint/name RVA outside the image.
    b = pe::build();
    put32(b, pe::rdata(0x2040), 0x00ffff00);
    a = run(b);
    CHECK(has_code(a, "pe.import.name_invalid"));

    // Unterminated lookup table: fill the rest of .rdata after the ILT with non-zero thunks.
    b = pe::build(pe::Options{.exports = false, .debug = false});
    std::fill(b.begin() + static_cast<std::ptrdiff_t>(pe::rdata(0x2060)),
              b.begin() + static_cast<std::ptrdiff_t>(pe::rdata(0x2060) + 0x3a0), 0x41);
    a = run(b);
    CHECK(has_code(a, "pe.import.thunk_unmapped") || has_code(a, "pe.import.name_invalid"));

    // Descriptor table running off the end of its section without a terminator.
    b = pe::build(pe::Options{.exports = false, .debug = false});
    put32(b, pe::data_directory(true, 1), 0x23f0);
    put32(b, pe::data_directory(true, 1) + 4, 0x10);
    std::fill(b.begin() + static_cast<std::ptrdiff_t>(pe::rdata(0x23f0)),
              b.begin() + static_cast<std::ptrdiff_t>(pe::rdata(0x2400)), 0x01);
    a = run(b);
    CHECK(has_code(a, "pe.import.unterminated"));
}

TEST_CASE("pe.malformed.exports") {
    auto b = pe::build();
    put32(b, pe::rdata(pe::export_directory) + 20, 0x7fffffff);  // NumberOfFunctions
    CHECK(has_code(run(b), "pe.export.limit"));

    b = pe::build();
    put32(b, pe::rdata(pe::export_directory) + 20, 0x10000);  // table would run beyond the section
    CHECK(has_code(run(b), "pe.export.table_unmapped"));

    b = pe::build();
    put16(b, pe::rdata(pe::export_ordinals) + 2, 99);  // name ordinal out of range
    auto a = run(b);
    CHECK(has_code(a, "pe.export.ordinal_range"));
    CHECK_EQ(a.exports.size(), 4u);
    CHECK(a.exports[1].name.empty());  // "beta" lost its name, the slot remains

    b = pe::build();
    b[pe::rdata(0x22b0) + 20] = 'X';  // forwarder string loses its terminator...
    std::fill(b.begin() + static_cast<std::ptrdiff_t>(pe::rdata(0x22b0)),
              b.begin() + static_cast<std::ptrdiff_t>(pe::rdata(0x2400)), 'X');  // ...to the end of .rdata
    a = run(b);
    CHECK(has_code(a, "pe.export.forwarder_invalid"));
}

TEST_CASE("pe.malformed.certificates") {
    auto b = pe::build();
    const std::size_t cert = pe::data_raw + 0x200;
    put32(b, cert, 0);
    CHECK(has_code(run(b), "pe.certificate.length"));

    b = pe::build();
    put32(b, cert, 0x7fffffff);
    CHECK(has_code(run(b), "pe.certificate.length"));

    b = pe::build();
    put32(b, pe::data_directory(true, 4) + 4, 0x10000);  // size beyond the file
    auto a = run(b);
    CHECK(has_code(a, "pe.directory.out_of_range"));
    CHECK(a.certificates.empty());

    b = pe::build();
    put16(b, cert + 4, 0x0300);
    CHECK(has_code(run(b), "pe.certificate.revision"));

    pe::Options o;
    o.overlay = 0x20;
    a = run(pe::build(o));
    CHECK(has_code(a, "pe.overlay"));
    CHECK(a.property("Overlay") && a.property("Overlay")->find("0x20 bytes") == 0);
    CHECK(!has_code(a, "pe.certificate.not_at_end"));
}

TEST_CASE("pe.checksum") {
    auto b = pe::build();
    put32(b, pe::optional + 64, 0x1234);
    auto a = run(b);
    CHECK(has_code(a, "pe.checksum.mismatch"));
    // Write the computed value back: the mismatch must disappear.
    const std::string* p = a.property("Checksum");
    REQUIRE(p != nullptr);
    const auto computed = std::stoul(p->substr(p->find(", ") + 2), nullptr, 16);
    put32(b, pe::optional + 64, static_cast<std::uint32_t>(computed));
    CHECK(!has_code(run(b), "pe.checksum.mismatch"));
}

TEST_CASE("pe.limits_are_enforced") {
    AnalyzeOptions o;
    o.limits.max_imports = 2;
    const auto a = analyze(FileImage::from_bytes(pe::build()), o);
    CHECK_EQ(a.imports.size(), 2u);
    CHECK(has_code(a, "pe.import.limit"));
}

TEST_CASE("pe.resources_and_version_info") {
    for (bool plus : {true, false}) {
        pe::Options o;
        o.pe32plus = plus;
        const auto a = run(pe::build(o));
        REQUIRE(a.resources.size() == 1);
        const auto& r = a.resources[0];
        CHECK_EQ(r.type, std::string("VERSION"));
        CHECK_EQ(r.name, std::string("#1"));
        CHECK_EQ(r.language, std::string("0x409"));
        CHECK_EQ(r.codepage, 1200u);
        CHECK(r.offset && *r.offset == pe::data_raw + 0x80);
        CHECK(a.property("File version") && *a.property("File version") == "1.2.3.4");
        CHECK(a.property("Product version") && *a.property("Product version") == "1.2.3.4");
        CHECK(a.property("Version: CompanyName") && *a.property("Version: CompanyName") == "BinWeaver Tests");
        CHECK(a.property("Resources") && *a.property("Resources") == "1 (VERSION x1)");
    }
}

TEST_CASE("pe.malformed.resources") {
    const std::size_t d = pe::data_raw;  // .data RVA 0x3000
    auto b = pe::build();
    put32(b, d + 0x38 + 20, 0x80000000u);  // type subdirectory entry points back at the root
    auto a = run(b);
    CHECK(has_code(a, "pe.resource.loop"));
    CHECK(a.resources.empty());

    b = pe::build();
    put32(b, d + 0x68, 0x9000);  // data RVA outside the image
    a = run(b);
    CHECK(has_code(a, "pe.resource.data_unmapped"));
    REQUIRE(a.resources.size() == 1);
    CHECK(!a.resources[0].offset.has_value());
    CHECK(!a.property("File version"));

    b = pe::build();
    put32(b, d + 0x80 + 40, 0);  // VS_FIXEDFILEINFO signature
    a = run(b);
    CHECK(has_code(a, "pe.version.malformed"));
    CHECK(a.property("Version: CompanyName") != nullptr);  // string table still readable

    b = pe::build();
    put16(b, d + 0x80, 3);  // VS_VERSIONINFO wLength smaller than its header
    CHECK(has_code(run(b), "pe.version.malformed"));

    b = pe::build();
    put32(b, d + 0x20 + 16, 0x80000000u | 0x7fff0000u);  // named entry with an unmapped string
    CHECK(has_code(run(b), "pe.resource.name_invalid"));

    b = pe::build();
    put16(b, d + 0x20 + 14, 0xffff);  // entry count far beyond the section
    a = run(b);
    CHECK(has_code(a, "pe.resource.unmapped") || has_code(a, "pe.resource.loop"));
}

TEST_CASE("pe.rich_header") {
    auto a = run(pe::build());
    REQUIRE(a.rich.size() == 1);
    CHECK_EQ(a.rich[0].product_id, 0x103u);
    CHECK_EQ(a.rich[0].build, 30159u);
    CHECK_EQ(a.rich[0].count, 7u);
    CHECK(a.property("Rich header") && a.property("Rich header")->find("checksum valid") != std::string::npos);
    CHECK(!has_code(a, "pe.rich.checksum"));

    auto b = pe::build();
    b[pe::rich_dans + 20] ^= 1;  // count changed without updating the checksum
    a = run(b);
    CHECK(has_code(a, "pe.rich.checksum"));
    CHECK_EQ(a.rich[0].count, 6u);

    b = pe::build();
    put32(b, pe::rich_dans, 0);  // "DanS" destroyed
    CHECK(has_code(run(b), "pe.rich.malformed"));

    pe::Options none;
    none.rich = false;
    a = run(pe::build(none));
    CHECK(a.rich.empty());
    CHECK(!a.property("Rich header"));
}

TEST_CASE("pe.authenticode") {
    for (bool plus : {true, false}) {
        pe::Options o;
        o.pe32plus = plus;
        auto b = pe::build(o);
        auto a = run(b);
        REQUIRE(a.signatures.size() == 1);
        const auto& s = a.signatures[0];
        CHECK_EQ(s.digest_algorithm, std::string("SHA-256"));
        CHECK_EQ(s.digest_status, std::string("match"));
        CHECK_EQ(s.computed_digest, s.signed_digest);
        CHECK_EQ(s.signer_subject, std::string("CN=BinWeaver Test Signer, O=BinWeaver Tests, C=PL"));
        CHECK_EQ(s.signer_issuer, std::string("CN=BinWeaver Test CA, O=BinWeaver Tests, C=PL"));
        CHECK_EQ(s.signer_serial, std::string("012345"));
        CHECK_EQ(s.valid_from, std::string("2025-01-01 00:00:00 UTC"));
        CHECK_EQ(s.valid_to, std::string("2030-01-01 00:00:00 UTC"));
        CHECK_EQ(s.certificates.size(), 1u);
        CHECK(!has_code(a, "pe.signature.malformed"));

        // Any byte change in the hashed ranges breaks the digest...
        auto t = b;
        t[pe::text_raw + 5] ^= 0xff;
        CHECK_EQ(run(t).signatures[0].digest_status, std::string("mismatch"));
        CHECK(has_code(run(t), "pe.signature.digest_mismatch"));
        // ...but the CheckSum field is excluded by design.
        t = b;
        put32(t, pe::optional + 64, 0x12345678);
        CHECK_EQ(run(t).signatures[0].digest_status, std::string("match"));
    }
    // Malformed PKCS#7 contents are reported, never crash.
    auto b = pe::build();
    const std::size_t blob = pe::data_raw + 0x200 + 8;
    b[blob + 4] = 0x05;  // ContentInfo OID tag damaged
    CHECK(has_code(run(b), "pe.signature.malformed"));
    b = pe::build();
    b[blob + 1] = 0x80;  // indefinite length (BER)
    CHECK(has_code(run(b), "pe.signature.malformed"));
}

TEST_CASE("pe.heuristics") {
    auto heur = [](const Analysis& a) {
        std::vector<std::string> codes;
        for (const auto& d : a.diagnostics)
            if (d.code.rfind("heur.", 0) == 0) codes.push_back(d.code);
        return codes;
    };
    CHECK(heur(run(pe::build())).empty());  // clean fixture: no observations

    const std::size_t text_hdr = pe::section_table(true), data_hdr = pe::section_table(true) + 80;
    auto b = pe::build();
    put32(b, data_hdr + 36, 0xe0000040);  // .data: R W X
    CHECK(has_code(run(b), "heur.section.writable_executable"));

    b = pe::build();
    std::copy_n("UPX1\0\0\0\0", 8, b.begin() + static_cast<std::ptrdiff_t>(text_hdr));
    auto a = run(b);
    CHECK(has_code(a, "heur.section.packer_name"));
    CHECK(std::any_of(a.diagnostics.begin(), a.diagnostics.end(), [](const Diagnostic& d) {
        return d.code == "heur.section.packer_name" && d.message.find("UPX") != std::string::npos;
    }));

    b = pe::build();
    put32(b, pe::optional + 16, 0x3010);  // entry point in writable .data
    CHECK(has_code(run(b), "heur.entry.writable_section"));

    b = pe::build();
    put32(b, text_hdr + 16, 0);  // .text: no raw data, still executable with VirtualSize
    CHECK(has_code(run(b), "heur.section.virtual_only_code"));

    b = pe::build();
    std::copy_n("GetProcAddress", 15, b.begin() + static_cast<std::ptrdiff_t>(pe::rdata(0x2102)));
    put16(b, pe::coff + 18, 0x0022);  // executable, not a DLL
    CHECK(has_code(run(b), "heur.imports.dynamic_resolution"));

    AnalyzeOptions off;
    off.heuristics = false;
    b = pe::build();
    put32(b, data_hdr + 36, 0xe0000040);
    CHECK(!has_code(analyze(FileImage::from_bytes(b), off), "heur.section.writable_executable"));
}

TEST_CASE("pe.dotnet_metadata") {
    pe::Options o;
    o.dotnet = true;
    const auto b = pe::build(o);
    const auto a = run(b);
    REQUIRE(a.dotnet.has_value());
    const auto& n = *a.dotnet;
    CHECK_EQ(n.metadata_version, std::string("v4.0.30319"));
    CHECK_EQ(n.runtime_header, std::string("2.5"));
    CHECK_EQ(n.flags_text, std::string("ILONLY"));
    REQUIRE(n.streams.size() == 4);
    CHECK_EQ(n.streams[0].name, std::string("#~"));
    CHECK_EQ(n.streams[3].name, std::string("#Blob"));
    REQUIRE(n.tables.size() == 3);
    CHECK_EQ(n.tables[1].name, std::string("Assembly"));
    CHECK_EQ(n.module_name, std::string("Fixture.dll"));
    CHECK_EQ(n.assembly_name, std::string("Fixture"));
    CHECK_EQ(n.assembly_version, std::string("1.2.3.4"));
    // Token of a full public key: last 8 bytes of SHA-1(key), reversed.
    const std::vector<std::uint8_t> key = {1, 2, 3, 4};
    const auto h = sha1(key);
    std::string expected;
    for (std::size_t i = 40; i > 24; i -= 2) expected += h.substr(i - 2, 2);
    CHECK_EQ(n.public_key_token, expected);
    REQUIRE(n.references.size() == 1);
    CHECK_EQ(n.references[0].name, std::string("mscorlib"));
    CHECK_EQ(n.references[0].version, std::string("4.0.0.0"));
    CHECK_EQ(n.references[0].public_key_token, std::string("b77a5c561934e089"));
    CHECK(has_code(a, "pe.clr.partial"));
    CHECK(a.structurally_valid);

    const std::size_t md = pe::data_raw + 0x200 + pe::dotnet_layout::root;
    auto t = b;
    t[md] = 'X';
    CHECK(has_code(run(t), "pe.clr.metadata_signature"));
    t = b;
    put32(t, md + 12, 0x10000);  // version string length
    CHECK(has_code(run(t), "pe.clr.metadata_root"));
    t = b;
    put32(t, md + pe::dotnet_layout::row_counts, 0x7fffffff);  // Module rows
    CHECK(has_code(run(t), "pe.clr.tables"));
    t = b;
    put32(t, md + 32, 0xfff0);  // #~ stream offset beyond the metadata
    CHECK(has_code(run(t), "pe.clr.streams"));
    t = b;
    put32(t, pe::data_raw + 0x200 + 8, 0x9000);  // metadata RVA unmapped
    CHECK(has_code(run(t), "pe.clr.metadata_range"));
}

TEST_CASE("rules.parse_errors") {
    std::vector<std::string> errors;
    const auto rules = parse_rules(R"(rule ok
  text $a = "x"
end
rule broken
  hex $b = 4D 5
  bogus line
  condition 3
end
text $c = "outside"
rule unclosed
  import $i = kernel32.dll
)", errors);
    CHECK_EQ(rules.size(), 1u);
    CHECK_EQ(rules[0].name, std::string("ok"));
    const auto joined = [&] {
        std::string s;
        for (const auto& e : errors) s += e + "\n";
        return s;
    }();
    CHECK(joined.find("line 5: $b: hex pattern has an odd number of digits") != std::string::npos);
    CHECK(joined.find("line 6: unknown keyword 'bogus'") != std::string::npos);
    CHECK(joined.find("requires 3 matches but has 0 patterns") != std::string::npos ||
          joined.find("has no patterns") != std::string::npos);
    CHECK(joined.find("line 9: 'text' outside a rule") != std::string::npos);
    CHECK(joined.find("$i: expected library!function") != std::string::npos);
    CHECK(joined.find("'unclosed' is not closed") != std::string::npos);
    errors.clear();
    parse_rules("rule d\n text $x = \"a\"\n text $x = \"b\"\nend\n", errors);
    CHECK(!errors.empty() && errors[0].find("duplicate pattern id $x") != std::string::npos);
}

TEST_CASE("rules.matching") {
    const auto b = pe::build();
    const auto f = FileImage::from_bytes(b);
    const auto a = analyze(f);
    std::vector<std::string> errors;
    const auto rules = parse_rules(R"(
rule in_rdata          # scope restricts byte search to one section
  scope section .rdata
  text $fwd = "KERNEL32.ExitProcess"
end
rule not_in_text
  scope section .text
  text $fwd = "KERNEL32.ExitProcess"
end
rule wide_and_import
  wide $key = "CompanyName"
  import $exit = kernel32.dll!exitprocess
  import $ord = KERNEL32!#17
  condition all
end
rule property_atom
  property $v = Version: CompanyName contains "binweaver"
end
rule two_of_three
  hex $mz = 4D 5A
  text $missing = "definitely not in the file"
  text $pdb = "fixture.pdb"
  condition 2
end
rule all_fails
  hex $mz = 4D 5A
  import $nope = user32.dll!DefinitelyMissing
  condition all
end
rule escapes
  text $tab = "\x4d\x5a"
end
)", errors);
    for (const auto& e : errors) std::cerr << "  " << e << '\n';
    REQUIRE(errors.empty());
    const auto hits = match_rules(rules, a, f);
    auto find = [&](std::string_view n) -> const RuleMatch* {
        for (const auto& h : hits)
            if (h.rule == n) return &h;
        return nullptr;
    };
    const auto* in_rdata = find("in_rdata");
    REQUIRE(in_rdata != nullptr);
    CHECK(in_rdata->matched[0].offset && *in_rdata->matched[0].offset == pe::rdata(0x22b0));
    CHECK(find("not_in_text") == nullptr);
    CHECK(find("wide_and_import") != nullptr);
    CHECK(find("property_atom") != nullptr);
    const auto* two = find("two_of_three");
    REQUIRE(two != nullptr);
    CHECK_EQ(two->matched.size(), 2u);
    CHECK(find("all_fails") == nullptr);
    REQUIRE(find("escapes") != nullptr);
    CHECK(*find("escapes")->matched[0].offset == 0u);
}

TEST_CASE("rules.parser_robustness") {
    // Mutated rule texts must never crash the parser or the matcher.
    const std::string base = "rule r\n tags a b\n scope section .text\n hex $h = 4D ?? 5A\n text $t = \"a\x41\\\"b\"\n"
                             " wide $w = \"W\"\n import $i = k.dll!*\n property $p = k contains \"v\"\n condition 2\nend\n";
    const auto f = FileImage::from_bytes(pe::build());
    const auto a = analyze(f);
    std::mt19937_64 rng(5);
    for (int iter = 0; iter < 3000; ++iter) {
        std::string t = base;
        for (int m = 0; m < 4; ++m) {
            const auto at = static_cast<std::size_t>(rng() % t.size());
            if (rng() % 3 == 0) t.erase(at, 1);
            else t[at] = static_cast<char>(rng() % 128);
        }
        std::vector<std::string> errors;
        (void)match_rules(parse_rules(t, errors), a, f);
    }
}

TEST_CASE("pe.header_fields") {
    for (bool plus : {true, false}) {
        pe::Options o;
        o.pe32plus = plus;
        const auto f = FileImage::from_bytes(pe::build(o));
        const auto a = analyze(f);
        const auto fields = header_fields(a, f);
        REQUIRE(!fields.empty());
        // Sorted and non-overlapping.
        for (std::size_t i = 1; i < fields.size(); ++i) CHECK(fields[i - 1].offset + fields[i - 1].size <= fields[i].offset);
        const auto* entry = field_at(fields, pe::optional + 17);  // inside the 4-byte field
        REQUIRE(entry != nullptr);
        CHECK_EQ(entry->structure, std::string(plus ? "IMAGE_OPTIONAL_HEADER64" : "IMAGE_OPTIONAL_HEADER32"));
        CHECK_EQ(entry->name, std::string("AddressOfEntryPoint"));
        CHECK_EQ(entry->value, 0x1000u);
        CHECK_EQ(field_at(fields, 0x3c)->name, std::string("e_lfanew"));
        CHECK_EQ(field_at(fields, 0x3c)->value, pe::lfanew);
        CHECK_EQ(field_at(fields, pe::coff + 2)->value, 3u);  // NumberOfSections
        const auto* base_of_data = field_at(fields, pe::optional + 24);
        REQUIRE(base_of_data != nullptr);
        CHECK_EQ(base_of_data->name, std::string(plus ? "ImageBase" : "BaseOfData"));
        const auto* imp = field_at(fields, pe::data_directory(plus, 1));
        REQUIRE(imp != nullptr);
        CHECK_EQ(imp->structure, std::string("DataDirectory[1] Import"));
        CHECK_EQ(imp->value, pe::import_descriptors);
        const auto* name = field_at(fields, pe::section_table(plus) + 40);
        REQUIRE(name != nullptr);
        CHECK_EQ(name->structure, std::string("IMAGE_SECTION_HEADER[1] .rdata"));
        CHECK_EQ(name->text, std::string("\".rdata\""));
        CHECK(field_at(fields, pe::text_raw) == nullptr);  // code bytes are not header fields
    }
    // Truncated headers: only existing bytes are described.
    auto b = pe::build();
    b.resize(pe::optional + 20);
    const auto f = FileImage::from_bytes(b);
    const auto fields = header_fields(analyze(f), f);
    for (const auto& fld : fields) CHECK(fld.offset + fld.size <= b.size());
}

TEST_CASE("pe.html_report") {
    auto b = pe::build();
    // Hostile section name: must be escaped, never interpreted as markup.
    std::copy_n("<b>&'\"x", 8, b.begin() + static_cast<std::ptrdiff_t>(pe::section_table(true)));
    const auto html = html_report(run(b));
    CHECK(html.rfind("<!doctype html>", 0) == 0);
    CHECK(html.find("&lt;b&gt;&amp;&#39;&quot;x") != std::string::npos);
    CHECK(html.find("<b>&") == std::string::npos);
    CHECK(html.find("<script") == std::string::npos);
    std::size_t open = 0, close = 0;
    for (std::size_t at = 0; (at = html.find("<table>", at)) != std::string::npos; ++at) ++open;
    for (std::size_t at = 0; (at = html.find("</table>", at)) != std::string::npos; ++at) ++close;
    CHECK(open == close);
    CHECK(open >= 3);
    CHECK(html.find("KERNEL32.dll") != std::string::npos);
}
