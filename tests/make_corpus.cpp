// Regenerates tests/corpus from the fixture builders:
//   binweaver-make-corpus <tests/corpus>
// Each malformed file targets one parser path; the name says which.
#include "fixtures.hpp"

#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>

namespace {
using fixtures::Bytes;

void put(Bytes& b, std::size_t at, std::uint64_t v, int width) {
    for (int i = 0; i < width; ++i) b[at + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> (8 * i));
}

void write(const std::filesystem::path& p, const Bytes& b) {
    std::filesystem::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
}

Bytes mutate(Bytes b, const std::function<void(Bytes&)>& fn) {
    fn(b);
    return b;
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: binweaver-make-corpus <output-dir>\n";
        return 2;
    }
    namespace pe = fixtures::pe;
    namespace elf = fixtures::elf;
    const std::filesystem::path out = argv[1];
    const Bytes pe64 = pe::build();
    pe::Options o32;
    o32.pe32plus = false;
    write(out / "pe/clean-pe32plus.dll", pe64);
    write(out / "pe/clean-pe32.dll", pe::build(o32));
    write(out / "pe/bad-lfanew.exe", mutate(pe64, [](Bytes& b) { put(b, 0x3c, 0xfffffff0, 4); }));
    write(out / "pe/bad-optional-magic.exe", mutate(pe64, [](Bytes& b) { put(b, pe::optional, 0x1234, 2); }));
    write(out / "pe/huge-rva-count.exe", mutate(pe64, [](Bytes& b) { put(b, pe::optional + 108, 0xffffffff, 4); }));
    write(out / "pe/section-beyond-eof.exe",
          mutate(pe64, [](Bytes& b) { put(b, pe::section_table(true) + 80 + 20, 0x7ffffe00, 4); }));
    write(out / "pe/section-count-65535.exe", mutate(pe64, [](Bytes& b) { put(b, pe::coff + 2, 0xffff, 2); }));
    write(out / "pe/import-name-unmapped.exe",
          mutate(pe64, [](Bytes& b) { put(b, pe::rdata(pe::import_descriptors) + 12, 0x7fff0000, 4); }));
    write(out / "pe/export-count-huge.dll",
          mutate(pe64, [](Bytes& b) { put(b, pe::rdata(pe::export_directory) + 20, 0x7fffffff, 4); }));
    write(out / "pe/cert-length-zero.exe", mutate(pe64, [](Bytes& b) { put(b, pe::data_raw + 0x200, 0, 4); }));
    write(out / "pe/truncated-headers.exe", Bytes(pe64.begin(), pe64.begin() + 0x120));
    pe::Options dn;
    dn.dotnet = true;
    const Bytes net = pe::build(dn);
    write(out / "pe/dotnet-clean.dll", net);
    write(out / "pe/dotnet-bad-bsjb.dll", mutate(net, [](Bytes& b) { b[pe::data_raw + 0x200 + 0x48] = 'X'; }));
    write(out / "pe/dotnet-rows-huge.dll", mutate(net, [](Bytes& b) {
              put(b, pe::data_raw + 0x200 + 0x48 + pe::dotnet_layout::row_counts, 0x7fffffff, 4);
          }));

    elf::Layout L;
    const Bytes e64 = elf::build({}, &L);
    write(out / "elf/clean-elf64le.so", e64);
    elf::Options v;
    v.needed = "libm.so.6";
    write(out / "elf/variant-elf64le.so", elf::build(v));
    elf::Options be32;
    be32.wide = false;
    be32.little = false;
    write(out / "elf/clean-elf32be.so", elf::build(be32));
    elf::Options ext;
    ext.extended_numbering = true;
    write(out / "elf/extended-numbering.so", elf::build(ext));
    write(out / "elf/shoff-overflow.so", mutate(e64, [](Bytes& b) { put(b, 40, 0xfffffffffffff000ull, 8); }));
    write(out / "elf/symtab-entsize-zero.so",
          mutate(e64, [&](Bytes& b) { put(b, L.shoff + L.index_symtab * L.shentsize + 56, 0, 8); }));
    write(out / "elf/note-namesz-huge.so", mutate(e64, [&](Bytes& b) { put(b, L.note, 0xffffffff, 4); }));
    write(out / "elf/phnum-xnum-no-sh0.so", mutate(e64, [](Bytes& b) {
              put(b, 56, 0xffff, 2);
              put(b, 40, 0, 8);
          }));
    write(out / "elf/dynamic-unterminated.so", mutate(e64, [&](Bytes& b) { put(b, L.dynamic + 160, 21, 8); }));
    write(out / "elf/truncated-ident.so", Bytes(e64.begin(), e64.begin() + 10));

    write(out / "misc/empty.bin", {});
    write(out / "misc/mz-only.bin", {'M', 'Z'});
    write(out / "misc/random-text.bin", Bytes{'h', 'e', 'l', 'l', 'o', '\n'});
    std::cout << "corpus written to " << out.string() << '\n';
    return 0;
}
