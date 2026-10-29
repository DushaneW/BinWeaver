// Field-level map of the fixed-layout headers: every byte of the DOS/COFF/
// optional headers, data directories and section table (PE), and of the ELF
// header and program/section header tables, labelled with its field name and
// value. Locations come from Analysis::structures, so only tables that the
// parser located and bounds-checked are described.
#include "binweaver/binweaver.hpp"

#include <algorithm>

namespace bw {
namespace {

struct Def {
    const char* name;
    std::uint32_t offset;
    std::uint32_t size;
    bool bytes = false;  // byte array (names, magic, reserved), not an integer
};

class Builder {
public:
    Builder(const FileImage& f, Endian e, std::vector<HeaderField>& out) : v_(f.bytes(), e), out_(out) {}
    // Adds the fields of one structure instance at `base`.
    void add(const std::string& structure, std::uint64_t base, std::initializer_list<Def> defs) {
        for (const auto& d : defs) {
            if (out_.size() >= kMaxFields) return;
            const std::uint64_t at = base + d.offset;
            auto r = v_.record(at, d.size);
            if (!r) continue;  // truncated structure: describe only what exists
            HeaderField f{structure, d.name, at, d.size, 0, {}};
            if (!d.bytes && (d.size == 1 || d.size == 2 || d.size == 4 || d.size == 8)) {
                f.value = d.size == 1 ? r->u8(0) : d.size == 2 ? r->u16(0) : d.size == 4 ? r->u32(0) : r->u64(0);
                f.text = hex(f.value);
            } else {
                std::string printable_text;
                bool ascii = true;
                for (auto c : r->bytes()) {
                    if (c == 0) break;
                    if (c < 0x20 || c >= 0x7f) ascii = false;
                    printable_text += static_cast<char>(c);
                }
                f.text = ascii && !printable_text.empty() ? "\"" + printable_text + "\"" : detail_hex(r->bytes());
            }
            out_.push_back(std::move(f));
        }
    }
    static constexpr std::size_t kMaxFields = 200000;

private:
    static std::string detail_hex(std::span<const std::uint8_t> b) {
        static constexpr char digits[] = "0123456789abcdef";
        std::string s;
        for (std::size_t i = 0; i < b.size() && i < 32; ++i) {
            if (i) s += ' ';
            s += digits[b[i] >> 4];
            s += digits[b[i] & 15];
        }
        return s;
    }
    ByteView v_;
    std::vector<HeaderField>& out_;
};

const Region* find_structure(const Analysis& a, std::string_view name) {
    for (const auto& r : a.structures)
        if (r.name == name) return &r;
    return nullptr;
}

void pe_fields(const Analysis& a, Builder& b) {
    const bool plus = a.bitness == "64-bit";
    b.add("IMAGE_DOS_HEADER", 0,
          {{"e_magic", 0, 2}, {"e_cblp", 2, 2}, {"e_cp", 4, 2}, {"e_crlc", 6, 2}, {"e_cparhdr", 8, 2},
           {"e_minalloc", 10, 2}, {"e_maxalloc", 12, 2}, {"e_ss", 14, 2}, {"e_sp", 16, 2}, {"e_csum", 18, 2},
           {"e_ip", 20, 2}, {"e_cs", 22, 2}, {"e_lfarlc", 24, 2}, {"e_ovno", 26, 2}, {"e_res", 28, 8, true},
           {"e_oemid", 36, 2}, {"e_oeminfo", 38, 2}, {"e_res2", 40, 20, true}, {"e_lfanew", 60, 4}});
    if (const auto* nt = find_structure(a, "PE signature + COFF header")) {
        b.add("PE signature", nt->offset, {{"Signature", 0, 4}});
        b.add("IMAGE_FILE_HEADER", nt->offset + 4,
              {{"Machine", 0, 2}, {"NumberOfSections", 2, 2}, {"TimeDateStamp", 4, 4}, {"PointerToSymbolTable", 8, 4},
               {"NumberOfSymbols", 12, 4}, {"SizeOfOptionalHeader", 16, 2}, {"Characteristics", 18, 2}});
    }
    if (const auto* oh = find_structure(a, "Optional header")) {
        const std::string s = plus ? "IMAGE_OPTIONAL_HEADER64" : "IMAGE_OPTIONAL_HEADER32";
        b.add(s, oh->offset,
              {{"Magic", 0, 2}, {"MajorLinkerVersion", 2, 1}, {"MinorLinkerVersion", 3, 1}, {"SizeOfCode", 4, 4},
               {"SizeOfInitializedData", 8, 4}, {"SizeOfUninitializedData", 12, 4}, {"AddressOfEntryPoint", 16, 4},
               {"BaseOfCode", 20, 4}});
        if (plus) b.add(s, oh->offset, {{"ImageBase", 24, 8}});
        else b.add(s, oh->offset, {{"BaseOfData", 24, 4}, {"ImageBase", 28, 4}});
        b.add(s, oh->offset,
              {{"SectionAlignment", 32, 4}, {"FileAlignment", 36, 4}, {"MajorOperatingSystemVersion", 40, 2},
               {"MinorOperatingSystemVersion", 42, 2}, {"MajorImageVersion", 44, 2}, {"MinorImageVersion", 46, 2},
               {"MajorSubsystemVersion", 48, 2}, {"MinorSubsystemVersion", 50, 2}, {"Win32VersionValue", 52, 4},
               {"SizeOfImage", 56, 4}, {"SizeOfHeaders", 60, 4}, {"CheckSum", 64, 4}, {"Subsystem", 68, 2},
               {"DllCharacteristics", 70, 2}});
        if (plus)
            b.add(s, oh->offset,
                  {{"SizeOfStackReserve", 72, 8}, {"SizeOfStackCommit", 80, 8}, {"SizeOfHeapReserve", 88, 8},
                   {"SizeOfHeapCommit", 96, 8}, {"LoaderFlags", 104, 4}, {"NumberOfRvaAndSizes", 108, 4}});
        else
            b.add(s, oh->offset,
                  {{"SizeOfStackReserve", 72, 4}, {"SizeOfStackCommit", 76, 4}, {"SizeOfHeapReserve", 80, 4},
                   {"SizeOfHeapCommit", 84, 4}, {"LoaderFlags", 88, 4}, {"NumberOfRvaAndSizes", 92, 4}});
        const std::uint64_t dirs = oh->offset + (plus ? 112 : 96);
        for (const auto& d : a.directories)
            b.add("DataDirectory[" + std::to_string(d.index) + "] " + d.name, dirs + std::uint64_t{d.index} * 8,
                  {{"VirtualAddress", 0, 4}, {"Size", 4, 4}});
    }
    if (const auto* st = find_structure(a, "Section table"))
        for (std::uint64_t i = 0; i < st->size / 40; ++i)
            b.add("IMAGE_SECTION_HEADER[" + std::to_string(i) + "]" + (i < a.sections.size() ? " " + a.sections[i].name : ""),
                  st->offset + i * 40,
                  {{"Name", 0, 8, true}, {"VirtualSize", 8, 4}, {"VirtualAddress", 12, 4}, {"SizeOfRawData", 16, 4},
                   {"PointerToRawData", 20, 4}, {"PointerToRelocations", 24, 4}, {"PointerToLinenumbers", 28, 4},
                   {"NumberOfRelocations", 32, 2}, {"NumberOfLinenumbers", 34, 2}, {"Characteristics", 36, 4}});
}

void elf_fields(const Analysis& a, Builder& b) {
    const bool w = a.bitness == "64-bit";
    const char* eh = w ? "Elf64_Ehdr" : "Elf32_Ehdr";
    b.add(eh, 0, {{"e_ident[EI_MAG]", 0, 4, true}, {"e_ident[EI_CLASS]", 4, 1}, {"e_ident[EI_DATA]", 5, 1},
                  {"e_ident[EI_VERSION]", 6, 1}, {"e_ident[EI_OSABI]", 7, 1}, {"e_ident[EI_ABIVERSION]", 8, 1},
                  {"e_ident[EI_PAD]", 9, 7, true}, {"e_type", 16, 2}, {"e_machine", 18, 2}, {"e_version", 20, 4}});
    if (w)
        b.add(eh, 0, {{"e_entry", 24, 8}, {"e_phoff", 32, 8}, {"e_shoff", 40, 8}, {"e_flags", 48, 4}, {"e_ehsize", 52, 2},
                      {"e_phentsize", 54, 2}, {"e_phnum", 56, 2}, {"e_shentsize", 58, 2}, {"e_shnum", 60, 2},
                      {"e_shstrndx", 62, 2}});
    else
        b.add(eh, 0, {{"e_entry", 24, 4}, {"e_phoff", 28, 4}, {"e_shoff", 32, 4}, {"e_flags", 36, 4}, {"e_ehsize", 40, 2},
                      {"e_phentsize", 42, 2}, {"e_phnum", 44, 2}, {"e_shentsize", 46, 2}, {"e_shnum", 48, 2},
                      {"e_shstrndx", 50, 2}});
    if (const auto* ph = find_structure(a, "Program header table"); ph && !a.segments.empty()) {
        const std::uint64_t entsize = ph->size / a.segments.size();
        for (std::uint64_t i = 0; i < a.segments.size(); ++i) {
            const std::string s = std::string(w ? "Elf64_Phdr[" : "Elf32_Phdr[") + std::to_string(i) + "] " + a.segments[i].kind;
            if (w)
                b.add(s, ph->offset + i * entsize, {{"p_type", 0, 4}, {"p_flags", 4, 4}, {"p_offset", 8, 8}, {"p_vaddr", 16, 8},
                                                     {"p_paddr", 24, 8}, {"p_filesz", 32, 8}, {"p_memsz", 40, 8}, {"p_align", 48, 8}});
            else
                b.add(s, ph->offset + i * entsize, {{"p_type", 0, 4}, {"p_offset", 4, 4}, {"p_vaddr", 8, 4}, {"p_paddr", 12, 4},
                                                     {"p_filesz", 16, 4}, {"p_memsz", 20, 4}, {"p_flags", 24, 4}, {"p_align", 28, 4}});
        }
    }
    if (const auto* sh = find_structure(a, "Section header table"); sh && !a.sections.empty()) {
        const std::uint64_t entsize = sh->size / a.sections.size();
        for (std::uint64_t i = 0; i < a.sections.size(); ++i) {
            const std::string s = std::string(w ? "Elf64_Shdr[" : "Elf32_Shdr[") + std::to_string(i) + "] " + a.sections[i].name;
            if (w)
                b.add(s, sh->offset + i * entsize, {{"sh_name", 0, 4}, {"sh_type", 4, 4}, {"sh_flags", 8, 8}, {"sh_addr", 16, 8},
                                                     {"sh_offset", 24, 8}, {"sh_size", 32, 8}, {"sh_link", 40, 4}, {"sh_info", 44, 4},
                                                     {"sh_addralign", 48, 8}, {"sh_entsize", 56, 8}});
            else
                b.add(s, sh->offset + i * entsize, {{"sh_name", 0, 4}, {"sh_type", 4, 4}, {"sh_flags", 8, 4}, {"sh_addr", 12, 4},
                                                     {"sh_offset", 16, 4}, {"sh_size", 20, 4}, {"sh_link", 24, 4}, {"sh_info", 28, 4},
                                                     {"sh_addralign", 32, 4}, {"sh_entsize", 36, 4}});
        }
    }
}

} // namespace

std::vector<HeaderField> header_fields(const Analysis& a, const FileImage& f) {
    std::vector<HeaderField> out;
    Builder b(f, a.byte_order == "big-endian" ? Endian::Big : Endian::Little, out);
    if (a.format == Format::PE) pe_fields(a, b);
    else if (a.format == Format::ELF) elf_fields(a, b);
    std::stable_sort(out.begin(), out.end(), [](const HeaderField& x, const HeaderField& y) { return x.offset < y.offset; });
    return out;
}

const HeaderField* field_at(const std::vector<HeaderField>& fields, std::uint64_t offset) {
    // Fields are sorted and do not overlap; find the last one starting at or before offset.
    auto it = std::upper_bound(fields.begin(), fields.end(), offset,
                               [](std::uint64_t o, const HeaderField& f) { return o < f.offset; });
    if (it == fields.begin()) return nullptr;
    --it;
    return offset < it->offset + it->size ? &*it : nullptr;
}

} // namespace bw
