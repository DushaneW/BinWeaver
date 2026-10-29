#include "binweaver/binweaver.hpp"
#include "check.hpp"
#include "fixtures.hpp"

#include <algorithm>

using namespace bw;
namespace elf = fixtures::elf;

namespace {
Analysis run(const fixtures::Bytes& b) { return analyze(FileImage::from_bytes(b, "fixture.so")); }

bool has_code(const Analysis& a, std::string_view code) {
    return std::any_of(a.diagnostics.begin(), a.diagnostics.end(), [&](const Diagnostic& d) { return d.code == code; });
}

void put(fixtures::Bytes& b, std::size_t at, std::uint64_t v, int width) {
    for (int i = 0; i < width; ++i) b[at + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> (8 * i));
}

const Symbol* find_symbol(const Analysis& a, std::string_view table, std::string_view name) {
    for (const auto& s : a.symbols)
        if (s.table == table && s.name == name) return &s;
    return nullptr;
}
} // namespace

TEST_CASE("elf.fixture.clean_all_classes") {
    for (bool wide : {true, false})
        for (bool little : {true, false}) {
            elf::Options o;
            o.wide = wide;
            o.little = little;
            elf::Layout L;
            const auto a = run(elf::build(o, &L));
            CHECK(a.format == Format::ELF);
            CHECK_EQ(a.bitness, std::string(wide ? "64-bit" : "32-bit"));
            CHECK_EQ(a.byte_order, std::string(little ? "little-endian" : "big-endian"));
            CHECK(a.structurally_valid);
            for (const auto& d : a.diagnostics) {
                CHECK(d.severity == Severity::Info);
                if (d.severity != Severity::Info) std::cerr << "  unexpected: " << d.code << " " << d.message << '\n';
            }
            CHECK_EQ(a.sections.size(), 14u);
            CHECK_EQ(a.segments.size(), 6u);
            CHECK_EQ(a.sections[6].name, std::string(".text"));
            CHECK_EQ(a.sections[6].flags_text, std::string("AX"));
            CHECK_EQ(a.sections[8].size, 0u);  // .bss has no file bytes
            CHECK_EQ(a.segments[1].kind, std::string("PT_LOAD"));
            CHECK_EQ(a.segments[1].flags_text, std::string("R-X"));
            CHECK_EQ(a.file_type, std::string("PIE executable"));
            CHECK(a.property("Interpreter") != nullptr);
            CHECK(a.property("Needed libraries") && *a.property("Needed libraries") == "libc.so.6");
            CHECK(a.property("SONAME") && *a.property("SONAME") == "libfixture.so");
            CHECK(a.property("BIND_NOW") != nullptr);
            CHECK(a.property("Stack") && *a.property("Stack") == "non-executable");
            CHECK(a.property("Build ID") && *a.property("Build ID") == o.build_id);

            CHECK(find_symbol(a, ".dynsym", "puts") != nullptr);
            CHECK(find_symbol(a, ".dynsym", "exported_fn") != nullptr);
            const Symbol* local = find_symbol(a, ".symtab", "local_helper");
            REQUIRE(local != nullptr);
            CHECK_EQ(local->bind, std::string("LOCAL"));
            CHECK_EQ(local->type, std::string("FUNC"));
            CHECK_EQ(local->section_index, 6u);
            CHECK_EQ(local->value, a.entry_point);

            REQUIRE(a.relocations.size() == 2);
            CHECK_EQ(a.relocations[0].symbol, std::string("puts"));
            CHECK(a.relocations[0].has_addend);
            CHECK_EQ(a.relocations[1].addend, static_cast<std::int64_t>(a.entry_point + 0x10));
            if (wide && little) {
                CHECK_EQ(a.relocations[0].type_name, std::string("R_X86_64_GLOB_DAT"));
                CHECK_EQ(a.relocations[1].type_name, std::string("R_X86_64_RELATIVE"));
                CHECK_EQ(a.architecture, std::string("x86-64"));
            }
            REQUIRE(a.notes.size() == 1);
            CHECK_EQ(a.notes[0].owner, std::string("GNU"));
            CHECK_EQ(a.notes[0].type_name, std::string("NT_GNU_BUILD_ID"));
            CHECK_EQ(a.dynamic.size(), 10u);
            CHECK_EQ(a.dynamic[0].tag_name, std::string("DT_NEEDED"));
            CHECK_EQ(a.dynamic[0].text, std::string("libc.so.6"));

            // Virtual address <-> offset.
            const auto m = address_to_offset(a, a.entry_point);
            CHECK(m.status == MapStatus::FileBacked);
            CHECK_EQ(m.offset, L.text);
            const auto bss = address_to_offset(a, L.base + 0x1000 + L.dynamic + 0x100);
            CHECK(bss.status == MapStatus::ZeroFill);
            const auto regions = locate(a, L.text + 1);
            CHECK(std::any_of(regions.begin(), regions.end(), [](const Region& r) { return r.name == ".text"; }));
        }
}

TEST_CASE("elf.extended_numbering") {
    for (bool wide : {true, false}) {
        elf::Options o;
        o.wide = wide;
        o.extended_numbering = true;
        const auto a = run(elf::build(o));
        CHECK(has_code(a, "elf.extnum.used"));
        CHECK(a.structurally_valid);
        CHECK_EQ(a.sections.size(), 14u);
        CHECK_EQ(a.segments.size(), 6u);
        CHECK_EQ(a.sections[6].name, std::string(".text"));
        CHECK(!a.relocations.empty());
    }
    // PN_XNUM without a readable section header 0.
    elf::Layout L;
    auto b = elf::build({}, &L);
    put(b, 56, 0xffff, 2);   // e_phnum
    put(b, 40, 0, 8);        // e_shoff = 0
    const auto a = run(b);
    CHECK(has_code(a, "elf.extnum.unreadable"));
    CHECK(a.segments.empty());
}

TEST_CASE("elf.malformed.headers") {
    CHECK(has_code(run({0x7f, 'E', 'L', 'F'}), "elf.ident.truncated"));
    auto b = elf::build();
    b[4] = 9;
    CHECK(has_code(run(b), "elf.ident.class"));

    b = elf::build();
    b.resize(40);
    CHECK(has_code(run(b), "elf.header.truncated"));

    elf::Layout L;
    b = elf::build({}, &L);
    put(b, 40, 0xfffffffffffff000ull, 8);  // e_shoff near 2^64
    auto a = run(b);
    CHECK(has_code(a, "elf.shdr.out_of_range"));
    CHECK(a.sections.empty());
    CHECK_EQ(a.segments.size(), 6u);  // program headers still parsed
    CHECK(a.property("Needed libraries") != nullptr);  // dynamic info recovered via PT_DYNAMIC + DT_STRTAB

    b = elf::build({}, &L);
    put(b, 58, 8, 2);  // e_shentsize too small
    CHECK(has_code(run(b), "elf.shdr.entsize"));

    b = elf::build({}, &L);
    put(b, 54, 4, 2);  // e_phentsize too small
    CHECK(has_code(run(b), "elf.phdr.entsize"));

    b = elf::build({}, &L);
    put(b, 62, 200, 2);  // e_shstrndx out of range
    a = run(b);
    CHECK(has_code(a, "elf.shstrndx.range"));
    CHECK_EQ(a.sections[6].name, std::string("<unnamed>"));

    b = elf::build({}, &L);
    put(b, 56, 0x8000, 2);  // e_phnum huge: table beyond file
    CHECK(has_code(run(b), "elf.phdr.out_of_range"));
}

TEST_CASE("elf.malformed.sections") {
    elf::Layout L;
    auto b = elf::build({}, &L);
    const std::size_t text_hdr = L.shoff + L.index_text * L.shentsize;
    put(b, text_hdr + 24, 0x7ffffffff000ull, 8);  // sh_offset beyond EOF
    auto a = run(b);
    CHECK(has_code(a, "elf.section.out_of_range"));
    CHECK(!a.sections[6].file_range_valid);

    b = elf::build({}, &L);
    const std::size_t symtab_hdr = L.shoff + L.index_symtab * L.shentsize;
    put(b, symtab_hdr + 56, 0, 8);  // sh_entsize = 0 must not divide by zero
    a = run(b);
    CHECK(has_code(a, "elf.symtab.entsize"));
    CHECK(find_symbol(a, ".symtab", "local_helper") == nullptr);

    b = elf::build({}, &L);
    put(b, symtab_hdr + 40, 99, 4);  // sh_link to nowhere
    a = run(b);
    CHECK(has_code(a, "elf.section.link"));
    CHECK(has_code(a, "elf.symtab.strtab"));

    b = elf::build({}, &L);
    put(b, L.symtab + 2 * 24, 0xfffffff0, 4);  // symbol name offset beyond .strtab
    CHECK(has_code(run(b), "elf.symbol.name"));

    b = elf::build({}, &L);
    put(b, L.symtab + 2 * 24 + 6, 0xffff, 2);  // SHN_XINDEX without SHT_SYMTAB_SHNDX
    CHECK(has_code(run(b), "elf.symbol.xindex"));

    b = elf::build({}, &L);
    const std::size_t rela_hdr = L.shoff + L.index_rela * L.shentsize;
    put(b, rela_hdr + 40, 1, 4);  // sh_link to .interp (not a symbol table)
    CHECK(has_code(run(b), "elf.reloc.symtab"));

    b = elf::build({}, &L);
    put(b, L.rela + 8, (std::uint64_t{500} << 32) | 6, 8);  // symbol index beyond .dynsym
    CHECK(has_code(run(b), "elf.reloc.symbol_range"));

    b = elf::build({}, &L);
    const std::size_t dynstr_hdr = L.shoff + 3 * L.shentsize;
    put(b, dynstr_hdr + 24, L.dynsym, 8);  // .dynstr overlaps .dynsym
    CHECK(has_code(run(b), "elf.section.overlap"));
}

TEST_CASE("elf.malformed.notes_and_dynamic") {
    elf::Layout L;
    auto b = elf::build({}, &L);
    put(b, L.note, 0xffffffff, 4);  // namesz overflowing the section
    auto a = run(b);
    CHECK(has_code(a, "elf.note.truncated"));
    CHECK(a.notes.empty());

    b = elf::build({}, &L);
    put(b, L.note + 4, 0xfffffff0, 4);  // descsz
    CHECK(has_code(run(b), "elf.note.truncated"));

    b = elf::build({}, &L);
    // Replace DT_NULL with another entry: no terminator inside the section.
    put(b, L.dynamic + 10 * 16, 21, 8);
    CHECK(has_code(run(b), "elf.dynamic.unterminated"));

    b = elf::build({}, &L);
    put(b, L.dynamic + 8, 0xffffff, 8);  // DT_NEEDED string offset beyond DT_STRSZ
    a = run(b);
    CHECK(has_code(a, "elf.dynamic.string"));

    b = elf::build({}, &L);
    put(b, L.dynamic + 2 * 16 + 8, 0x7f0000000000ull, 8);  // DT_STRTAB unmapped -> fall back to sh_link
    a = run(b);
    CHECK(has_code(a, "elf.dynamic.strtab"));
    CHECK(a.property("Needed libraries") && *a.property("Needed libraries") == "libc.so.6");
}

TEST_CASE("elf.malformed.segments") {
    elf::Layout L;
    auto b = elf::build({}, &L);
    const std::size_t load1 = L.phoff + 1 * L.phentsize;
    put(b, load1 + 32, 0x100000, 8);  // p_filesz beyond EOF and > p_memsz
    auto a = run(b);
    CHECK(has_code(a, "elf.segment.out_of_range"));
    CHECK(has_code(a, "elf.segment.filesz"));

    b = elf::build({}, &L);
    put(b, load1 + 16, 0x400010, 8);  // p_vaddr not congruent with p_offset
    CHECK(has_code(run(b), "elf.segment.congruence"));

    b = elf::build({}, &L);
    put(b, 24, 0x10, 8);  // entry outside every PT_LOAD
    CHECK(has_code(run(b), "elf.entry.outside_segments"));
}

TEST_CASE("elf.symbol_versions") {
    for (bool wide : {true, false})
        for (bool little : {true, false}) {
            elf::Options o;
            o.wide = wide;
            o.little = little;
            const auto a = run(elf::build(o));
            const Symbol* puts = find_symbol(a, ".dynsym", "puts");
            const Symbol* exported = find_symbol(a, ".dynsym", "exported_fn");
            REQUIRE(puts && exported);
            CHECK_EQ(puts->version, std::string("GLIBC_2.2.5"));
            CHECK(exported->version.empty());
            CHECK(a.property("Required versions: libc.so.6") &&
                  *a.property("Required versions: libc.so.6") == "GLIBC_2.2.5");
        }
}

TEST_CASE("elf.malformed.symbol_versions") {
    elf::Layout L;
    auto b = elf::build({}, &L);
    put(b, L.versym + 2, 9, 2);  // undefined version index
    auto a = run(b);
    CHECK(has_code(a, "elf.version.index"));
    CHECK(find_symbol(a, ".dynsym", "puts")->version.empty());

    b = elf::build({}, &L);
    put(b, L.versym + 2, 0x8002, 2);  // hidden version
    CHECK_EQ(find_symbol(run(b), ".dynsym", "puts")->version, std::string("GLIBC_2.2.5 (hidden)"));

    b = elf::build({}, &L);
    put(b, L.verneed + 8, 0x7ffffff0, 4);  // vn_aux outside the section
    CHECK(has_code(run(b), "elf.version.chain"));

    b = elf::build({}, &L);
    put(b, L.verneed + 12, 0x7ffffff0, 4);  // vn_next outside the section
    CHECK(has_code(run(b), "elf.version.chain"));

    b = elf::build({}, &L);
    const std::size_t versym_hdr = L.shoff + L.index_versym * L.shentsize;
    put(b, versym_hdr + 32, 4, 8);  // two entries for three symbols
    CHECK(has_code(run(b), "elf.version.count"));
    put(b, versym_hdr + 40, 1, 4);  // sh_link -> .interp
    CHECK(has_code(run(b), "elf.version.versym_link"));

    b = elf::build({}, &L);
    const std::size_t verneed_hdr = L.shoff + L.index_verneed * L.shentsize;
    put(b, verneed_hdr + 40, 6, 4);  // sh_link -> .text (not a string table)
    CHECK(has_code(run(b), "elf.version.strtab"));
}

TEST_CASE("elf.heuristics") {
    elf::Layout L;
    auto b = elf::build({}, &L);
    for (const auto& d : run(b).diagnostics) CHECK(d.code.rfind("heur.", 0) != 0);  // clean fixture
    put(b, L.phoff + 1 * L.phentsize + 4, 7, 4);  // first PT_LOAD: R W X
    CHECK(has_code(run(b), "heur.segment.writable_executable"));
    b = elf::build({}, &L);
    put(b, L.phoff + 5 * L.phentsize + 4, 7, 4);  // PT_GNU_STACK with PF_X
    auto a = run(b);
    CHECK(has_code(a, "heur.stack.executable"));
    CHECK(a.property("Stack")->find("executable (PT_GNU_STACK has PF_X)") == 0);
    b = elf::build({}, &L);
    put(b, 40, 0, 8);   // e_shoff = 0
    put(b, 60, 0, 2);   // e_shnum = 0
    CHECK(has_code(run(b), "heur.elf.no_section_headers"));
}

TEST_CASE("elf.relr_expansion") {
    for (bool wide : {true, false}) {
        elf::Options o;
        o.wide = wide;
        o.relr = true;
        elf::Layout L;
        const auto a = run(elf::build(o, &L));
        const std::uint64_t word = wide ? 8 : 4;
        std::vector<std::uint64_t> relr;
        for (const auto& r : a.relocations)
            if (r.section == ".relr.dyn") relr.push_back(r.offset);
        REQUIRE(relr.size() == 3);
        CHECK_EQ(relr[0], L.relr_address);
        CHECK_EQ(relr[1], L.relr_address + word);
        CHECK_EQ(relr[2], L.relr_address + 3 * word);
        if (wide) CHECK_EQ(a.relocations.back().type_name, std::string("R_X86_64_RELATIVE (RELR)"));
        CHECK(!has_code(a, "elf.relr.not_expanded"));
    }
    elf::Options o;
    o.relr = true;
    elf::Layout L;
    auto b = elf::build(o, &L);
    put(b, L.relr, 0xb, 8);  // bitmap first
    CHECK(has_code(run(b), "elf.relr.bitmap_first"));
    b = elf::build(o, &L);
    put(b, L.shoff + L.index_relr * L.shentsize + 56, 4, 8);  // wrong sh_entsize for ELF64
    CHECK(has_code(run(b), "elf.relr.entsize"));
}

TEST_CASE("elf.header_fields") {
    for (bool wide : {true, false})
        for (bool little : {true, false}) {
            elf::Options o;
            o.wide = wide;
            o.little = little;
            elf::Layout L;
            const auto f = FileImage::from_bytes(elf::build(o, &L));
            const auto a = analyze(f);
            const auto fields = header_fields(a, f);
            const auto* entry = field_at(fields, 24);
            REQUIRE(entry != nullptr);
            CHECK_EQ(entry->name, std::string("e_entry"));
            CHECK_EQ(entry->value, a.entry_point);  // byte order handled
            const auto* load = field_at(fields, L.phoff + L.phentsize);
            REQUIRE(load != nullptr);
            CHECK_EQ(load->name, std::string("p_type"));
            CHECK_EQ(load->value, 1u);  // PT_LOAD
            CHECK(load->structure.find("PT_LOAD") != std::string::npos);
            const auto* sh = field_at(fields, L.shoff + L.index_text * L.shentsize + 4);
            REQUIRE(sh != nullptr);
            CHECK_EQ(sh->name, std::string("sh_type"));
            CHECK(sh->structure.find(".text") != std::string::npos);
        }
}
