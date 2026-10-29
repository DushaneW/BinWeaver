// ELF32/ELF64 parser. References: System V gABI (ELF), LSB and GNU
// extensions for notes, dynamic tags and symbol bindings.
#include "internal.hpp"

#include <algorithm>
#include <map>

namespace bw::detail {
namespace {

constexpr std::uint32_t SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_RELA = 4, SHT_HASH = 5, SHT_DYNAMIC = 6, SHT_NOTE = 7,
                        SHT_NOBITS = 8, SHT_REL = 9, SHT_DYNSYM = 11, SHT_SYMTAB_SHNDX = 18, SHT_RELR = 19,
                        SHT_GNU_HASH = 0x6ffffff6;
constexpr std::uint32_t PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3, PT_NOTE = 4, PT_GNU_STACK = 0x6474e551,
                        PT_GNU_RELRO = 0x6474e552;
constexpr std::uint16_t SHN_UNDEF = 0, SHN_LORESERVE = 0xff00, SHN_XINDEX = 0xffff, PN_XNUM = 0xffff;

std::string section_type_name(std::uint32_t t) {
    switch (t) {
    case 0: return "SHT_NULL";
    case 1: return "SHT_PROGBITS";
    case 2: return "SHT_SYMTAB";
    case 3: return "SHT_STRTAB";
    case 4: return "SHT_RELA";
    case 5: return "SHT_HASH";
    case 6: return "SHT_DYNAMIC";
    case 7: return "SHT_NOTE";
    case 8: return "SHT_NOBITS";
    case 9: return "SHT_REL";
    case 10: return "SHT_SHLIB";
    case 11: return "SHT_DYNSYM";
    case 14: return "SHT_INIT_ARRAY";
    case 15: return "SHT_FINI_ARRAY";
    case 16: return "SHT_PREINIT_ARRAY";
    case 17: return "SHT_GROUP";
    case 18: return "SHT_SYMTAB_SHNDX";
    case 19: return "SHT_RELR";
    case 0x6ffffff5: return "SHT_GNU_ATTRIBUTES";
    case 0x6ffffff6: return "SHT_GNU_HASH";
    case 0x6ffffffd: return "SHT_GNU_verdef";
    case 0x6ffffffe: return "SHT_GNU_verneed";
    case 0x6fffffff: return "SHT_GNU_versym";
    default:
        if (t >= 0x70000000 && t <= 0x7fffffff) return "SHT_LOPROC+" + hex(t - 0x70000000);
        if (t >= 0x60000000 && t <= 0x6fffffff) return "SHT_LOOS+" + hex(t - 0x60000000);
        return "SHT " + hex(t);
    }
}

std::string segment_type_name(std::uint32_t t) {
    switch (t) {
    case 0: return "PT_NULL";
    case 1: return "PT_LOAD";
    case 2: return "PT_DYNAMIC";
    case 3: return "PT_INTERP";
    case 4: return "PT_NOTE";
    case 5: return "PT_SHLIB";
    case 6: return "PT_PHDR";
    case 7: return "PT_TLS";
    case 0x6474e550: return "PT_GNU_EH_FRAME";
    case 0x6474e551: return "PT_GNU_STACK";
    case 0x6474e552: return "PT_GNU_RELRO";
    case 0x6474e553: return "PT_GNU_PROPERTY";
    default:
        if (t >= 0x70000000 && t <= 0x7fffffff) return "PT_LOPROC+" + hex(t - 0x70000000);
        if (t >= 0x60000000 && t <= 0x6fffffff) return "PT_LOOS+" + hex(t - 0x60000000);
        return "PT " + hex(t);
    }
}

const char* machine_name(std::uint16_t m) {
    switch (m) {
    case 2: return "SPARC";
    case 3: return "x86";
    case 8: return "MIPS";
    case 20: return "PowerPC";
    case 21: return "PowerPC64";
    case 22: return "S390";
    case 40: return "ARM";
    case 43: return "SPARC V9";
    case 50: return "IA-64";
    case 62: return "x86-64";
    case 183: return "AArch64";
    case 243: return "RISC-V";
    case 247: return "BPF";
    case 258: return "LoongArch";
    default: return nullptr;
    }
}

std::string dynamic_tag_name(std::int64_t t) {
    static const std::map<std::int64_t, const char*> names = {
        {0, "NULL"}, {1, "NEEDED"}, {2, "PLTRELSZ"}, {3, "PLTGOT"}, {4, "HASH"}, {5, "STRTAB"}, {6, "SYMTAB"},
        {7, "RELA"}, {8, "RELASZ"}, {9, "RELAENT"}, {10, "STRSZ"}, {11, "SYMENT"}, {12, "INIT"}, {13, "FINI"},
        {14, "SONAME"}, {15, "RPATH"}, {16, "SYMBOLIC"}, {17, "REL"}, {18, "RELSZ"}, {19, "RELENT"},
        {20, "PLTREL"}, {21, "DEBUG"}, {22, "TEXTREL"}, {23, "JMPREL"}, {24, "BIND_NOW"}, {25, "INIT_ARRAY"},
        {26, "FINI_ARRAY"}, {27, "INIT_ARRAYSZ"}, {28, "FINI_ARRAYSZ"}, {29, "RUNPATH"}, {30, "FLAGS"},
        {32, "PREINIT_ARRAY"}, {33, "PREINIT_ARRAYSZ"}, {34, "SYMTAB_SHNDX"}, {35, "RELRSZ"}, {36, "RELR"},
        {37, "RELRENT"}, {0x6ffffef5, "GNU_HASH"}, {0x6ffffff0, "VERSYM"}, {0x6ffffff9, "RELACOUNT"},
        {0x6ffffffa, "RELCOUNT"}, {0x6ffffffb, "FLAGS_1"}, {0x6ffffffc, "VERDEF"}, {0x6ffffffd, "VERDEFNUM"},
        {0x6ffffffe, "VERNEED"}, {0x6fffffff, "VERNEEDNUM"}};
    auto it = names.find(t);
    return it != names.end() ? std::string("DT_") + it->second : "DT " + hex(static_cast<std::uint64_t>(t));
}

std::string relocation_type_name(std::uint16_t machine, std::uint32_t type) {
    static const std::map<std::uint32_t, const char*> x86_64 = {
        {0, "NONE"}, {1, "64"}, {2, "PC32"}, {3, "GOT32"}, {4, "PLT32"}, {5, "COPY"}, {6, "GLOB_DAT"},
        {7, "JUMP_SLOT"}, {8, "RELATIVE"}, {9, "GOTPCREL"}, {10, "32"}, {11, "32S"}, {16, "DTPMOD64"},
        {17, "DTPOFF64"}, {18, "TPOFF64"}, {37, "IRELATIVE"}, {41, "GOTPCRELX"}, {42, "REX_GOTPCRELX"}};
    static const std::map<std::uint32_t, const char*> i386 = {
        {0, "NONE"}, {1, "32"}, {2, "PC32"}, {3, "GOT32"}, {4, "PLT32"}, {5, "COPY"}, {6, "GLOB_DAT"},
        {7, "JMP_SLOT"}, {8, "RELATIVE"}, {14, "TLS_TPOFF"}, {35, "TLS_DTPMOD32"}, {36, "TLS_DTPOFF32"},
        {42, "IRELATIVE"}};
    static const std::map<std::uint32_t, const char*> aarch64 = {
        {0, "NONE"}, {257, "ABS64"}, {1024, "COPY"}, {1025, "GLOB_DAT"}, {1026, "JUMP_SLOT"}, {1027, "RELATIVE"},
        {1028, "TLS_DTPMOD"}, {1029, "TLS_DTPREL"}, {1030, "TLS_TPREL"}, {1031, "TLSDESC"}, {1032, "IRELATIVE"}};
    const std::map<std::uint32_t, const char*>* table = machine == 62 ? &x86_64 : machine == 3 ? &i386
                                                       : machine == 183 ? &aarch64 : nullptr;
    const char* prefix = machine == 62 ? "R_X86_64_" : machine == 3 ? "R_386_" : "R_AARCH64_";
    if (table)
        if (auto it = table->find(type); it != table->end()) return std::string(prefix) + it->second;
    return "type " + std::to_string(type);
}

std::string flag_letters(std::uint64_t flags, std::initializer_list<std::pair<std::uint64_t, char>> letters) {
    std::string out;
    for (const auto& [bit, c] : letters)
        if (flags & bit) out += c;
    return out;
}

struct Shdr {
    std::uint32_t name{}, type{};
    std::uint64_t flags{}, addr{}, offset{}, size{};
    std::uint32_t link{}, info{};
    std::uint64_t addralign{}, entsize{};
    std::string name_text;
    bool in_file{};  // non-NOBITS data lies inside the file
};

struct Phdr {
    std::uint32_t type{}, flags{};
    std::uint64_t offset{}, vaddr{}, paddr{}, filesz{}, memsz{}, align{};
};

class ElfParser {
public:
    ElfParser(const FileImage& f, Analysis& a, const AnalyzeOptions& o) : f_(f), a_(a), o_(o), limited_(a) {}
    void run();

private:
    bool read_header();
    void read_section_headers();
    void name_sections();
    void read_program_headers();
    void validate_layout();
    void parse_symbols();
    void parse_versions();
    void parse_symbol_table(std::size_t index);
    void parse_dynamic();
    void parse_relocations();
    std::uint64_t expand_relr(std::size_t section_index);
    void parse_notes();
    void parse_note_area(const std::string& source, std::uint64_t offset, std::uint64_t size, std::uint64_t align);
    std::string describe_note(const std::string& owner, std::uint32_t type, std::span<const std::uint8_t> desc,
                              std::string& type_name);
    std::optional<std::string> string_at(std::uint64_t table_offset, std::uint64_t table_size, std::uint64_t index) const;

    const FileImage& f_;
    ByteView v_;
    Analysis& a_;
    const AnalyzeOptions& o_;
    DiagLimiter limited_;

    bool wide_{};
    std::uint16_t type_{}, machine_{};
    std::uint64_t phoff_{}, shoff_{};
    std::uint16_t phentsize_{}, shentsize_{};
    std::uint64_t phnum_{}, shnum_{}, shstrndx_{};
    std::vector<Shdr> sh_;
    std::vector<Phdr> ph_;
    // For each symbol table section: [first index in a_.symbols, count).
    std::map<std::size_t, std::pair<std::size_t, std::size_t>> symbol_ranges_;
};

void ElfParser::run() {
    if (!read_header()) return;
    read_section_headers();
    name_sections();
    read_program_headers();
    validate_layout();
    parse_symbols();
    parse_versions();
    parse_dynamic();
    parse_relocations();
    parse_notes();
    add_property(a_, "Program headers", std::to_string(phnum_));
    add_property(a_, "Section headers", std::to_string(shnum_));
}

bool ElfParser::read_header() {
    const auto b = f_.bytes();
    if (b.size() < 16) {
        diag(a_, "elf.ident.truncated", "File is shorter than the 16-byte ELF identification.", 0);
        return false;
    }
    if ((b[4] != 1 && b[4] != 2) || (b[5] != 1 && b[5] != 2)) {
        diag(a_, "elf.ident.class", "Unsupported ELF class (" + std::to_string(b[4]) + ") or data encoding (" +
                                        std::to_string(b[5]) + ").", 4);
        return false;
    }
    wide_ = b[4] == 2;
    const bool le = b[5] == 1;
    v_ = ByteView(b, le ? Endian::Little : Endian::Big);
    a_.bitness = wide_ ? "64-bit" : "32-bit";
    a_.byte_order = le ? "little-endian" : "big-endian";
    if (b[6] != 1) diag(a_, "elf.ident.version", "EI_VERSION is " + std::to_string(b[6]) + ", expected 1.", 6);
    const std::uint8_t osabi = b[7];
    add_property(a_, "OS ABI", osabi == 0 ? "System V" : osabi == 3 ? "GNU/Linux" : osabi == 6 ? "Solaris"
                             : osabi == 9 ? "FreeBSD" : osabi == 12 ? "OpenBSD" : osabi == 97 ? "ARM"
                             : osabi == 255 ? "Standalone" : std::to_string(osabi));

    const std::uint64_t header_size = wide_ ? 64 : 52;
    auto h = v_.record(0, header_size);
    if (!h) {
        diag(a_, "elf.header.truncated", "File is shorter than the " + std::to_string(header_size) + "-byte ELF header.", 0);
        return false;
    }
    a_.structures.push_back({"ELF header", "header", 0, header_size});
    type_ = h->u16(16);
    machine_ = h->u16(18);
    if (const char* m = machine_name(machine_)) a_.architecture = m;
    else diag(a_, "elf.header.machine_unknown", "Unknown e_machine " + std::to_string(machine_) + ".", 18);
    a_.file_type = type_ == 1 ? "Relocatable object" : type_ == 2 ? "Executable" : type_ == 3 ? "Shared object"
                 : type_ == 4 ? "Core dump" : "type " + std::to_string(type_);
    if (h->u32(20) != 1) diag(a_, "elf.header.version", "e_version is not 1.", 20);
    a_.entry_point = h->word(24, wide_);
    phoff_ = h->word(wide_ ? 32 : 28, wide_);
    shoff_ = h->word(wide_ ? 40 : 32, wide_);
    add_property(a_, "e_flags", hex(h->u32(wide_ ? 48 : 36)));
    const std::uint16_t ehsize = h->u16(wide_ ? 52 : 40);
    phentsize_ = h->u16(wide_ ? 54 : 42);
    phnum_ = h->u16(wide_ ? 56 : 44);
    shentsize_ = h->u16(wide_ ? 58 : 46);
    shnum_ = h->u16(wide_ ? 60 : 48);
    shstrndx_ = h->u16(wide_ ? 62 : 50);
    if (ehsize != header_size)
        diag(a_, "elf.header.ehsize", "e_ehsize is " + std::to_string(ehsize) + ", expected " +
                                          std::to_string(header_size) + ".", wide_ ? 52u : 40u);

    // Extended numbering: when the real values do not fit in the header,
    // they are stored in section header 0 (gABI "Extended Section Numbering").
    const std::uint16_t min_sh = wide_ ? 64 : 40;
    const bool needs_ext = (shnum_ == 0 && shoff_ != 0) || shstrndx_ == SHN_XINDEX || phnum_ == PN_XNUM;
    if (needs_ext) {
        auto s0 = (shoff_ != 0 && shentsize_ >= min_sh) ? v_.record(shoff_, min_sh) : std::nullopt;
        if (!s0) {
            diag(a_, "elf.extnum.unreadable", "Header requires extended numbering but section header 0 is unreadable.", shoff_);
            if (shstrndx_ == SHN_XINDEX) shstrndx_ = 0;
            if (phnum_ == PN_XNUM) phnum_ = 0;
        } else {
            const std::uint64_t s0_size = s0->word(wide_ ? 32 : 20, wide_);
            const std::uint32_t s0_link = s0->u32(wide_ ? 40 : 24);
            const std::uint32_t s0_info = s0->u32(wide_ ? 44 : 28);
            std::string used;
            if (shnum_ == 0 && shoff_ != 0) {
                shnum_ = s0_size;
                used += " e_shnum=" + std::to_string(shnum_);
            }
            if (shstrndx_ == SHN_XINDEX) {
                shstrndx_ = s0_link;
                used += " e_shstrndx=" + std::to_string(shstrndx_);
            }
            if (phnum_ == PN_XNUM) {
                phnum_ = s0_info;
                used += " e_phnum=" + std::to_string(phnum_);
            }
            diag(a_, "elf.extnum.used", "Extended numbering in section header 0:" + used + ".", shoff_);
            add_property(a_, "Extended numbering", used.substr(1));
        }
    }
    return true;
}

void ElfParser::read_section_headers() {
    if (shnum_ == 0) {
        if (shoff_ != 0) diag(a_, "elf.shdr.offset_without_count", "e_shoff is set but there are no section headers.", shoff_);
        return;
    }
    const std::uint16_t min_sh = wide_ ? 64 : 40;
    if (shentsize_ < min_sh) {
        diag(a_, "elf.shdr.entsize", "e_shentsize " + std::to_string(shentsize_) + " is smaller than " +
                                         std::to_string(min_sh) + ".", wide_ ? 58u : 46u);
        return;
    }
    if (shnum_ > o_.limits.max_sections) {
        diag(a_, "elf.shdr.limit", std::to_string(shnum_) + " section headers exceed the configured limit.", shoff_);
        return;
    }
    auto table = checked_mul(shentsize_, shnum_);
    if (!table || !f_.contains(shoff_, *table)) {
        diag(a_, "elf.shdr.out_of_range", "Section header table extends beyond the file.", shoff_);
        return;
    }
    a_.structures.push_back({"Section header table", "table", shoff_, *table});
    sh_.reserve(static_cast<std::size_t>(shnum_));
    for (std::uint64_t i = 0; i < shnum_; ++i) {
        const auto r = *v_.record(shoff_ + i * shentsize_, min_sh);
        Shdr s;
        s.name = r.u32(0);
        s.type = r.u32(4);
        s.flags = r.word(8, wide_);
        s.addr = r.word(wide_ ? 16 : 12, wide_);
        s.offset = r.word(wide_ ? 24 : 16, wide_);
        s.size = r.word(wide_ ? 32 : 20, wide_);
        s.link = r.u32(wide_ ? 40 : 24);
        s.info = r.u32(wide_ ? 44 : 28);
        s.addralign = r.word(wide_ ? 48 : 32, wide_);
        s.entsize = r.word(wide_ ? 56 : 36, wide_);
        s.in_file = s.type != SHT_NOBITS && f_.contains(s.offset, s.size);
        sh_.push_back(s);
    }
    if (sh_[0].type != 0) diag(a_, "elf.shdr.first_not_null", "Section header 0 is not SHT_NULL.", shoff_);
}

void ElfParser::name_sections() {
    std::optional<Shdr> strtab;
    if (!sh_.empty() && shstrndx_ != SHN_UNDEF) {
        if (shstrndx_ >= sh_.size()) {
            diag(a_, "elf.shstrndx.range", "e_shstrndx " + std::to_string(shstrndx_) + " is not a valid section index.", 0);
        } else if (!sh_[shstrndx_].in_file) {
            diag(a_, "elf.shstrndx.out_of_range", "Section name string table lies outside the file.", sh_[shstrndx_].offset);
        } else {
            strtab = sh_[shstrndx_];
            if (strtab->type != SHT_STRTAB)
                diag(a_, "elf.shstrndx.type", "Section name table is not SHT_STRTAB.", strtab->offset);
        }
    }
    for (std::size_t i = 0; i < sh_.size(); ++i) {
        auto& s = sh_[i];
        if (strtab) {
            if (auto n = string_at(strtab->offset, strtab->size, s.name)) s.name_text = *n;
            else limited_("elf.section.name", "Section " + std::to_string(i) + " name offset is invalid.", shoff_);
        }
        Section out;
        out.index = static_cast<std::uint32_t>(i);
        out.name = s.name_text.empty() ? (i == 0 ? "<null>" : "<unnamed>") : s.name_text;
        out.kind = section_type_name(s.type);
        out.type = s.type;
        out.offset = s.offset;
        out.size = s.type == SHT_NOBITS ? 0 : s.size;
        out.address = s.addr;
        out.virtual_size = s.size;
        out.flags = s.flags;
        out.flags_text = flag_letters(s.flags, {{0x1, 'W'}, {0x2, 'A'}, {0x4, 'X'}, {0x10, 'M'}, {0x20, 'S'},
                                                {0x40, 'I'}, {0x80, 'L'}, {0x100, 'O'}, {0x200, 'G'}, {0x400, 'T'},
                                                {0x800, 'C'}});
        out.alignment = s.addralign;
        out.link = s.link;
        out.info = s.info;
        out.entry_size = s.entsize;
        if (s.type != SHT_NOBITS && s.size && !s.in_file) {
            out.file_range_valid = false;
            diag(a_, "elf.section.out_of_range", "Section '" + out.name + "' [" + hex(s.offset) + ", +" + hex(s.size) +
                                                    ") extends beyond the file.", s.offset);
        }
        if (s.addralign > 1 && !is_power_of_two(s.addralign))
            limited_("elf.section.alignment", "Section '" + out.name + "' alignment is not a power of two.", shoff_);
        const bool uses_link = s.type == SHT_SYMTAB || s.type == SHT_DYNSYM || s.type == SHT_REL ||
                               s.type == SHT_RELA || s.type == SHT_DYNAMIC || s.type == SHT_HASH ||
                               s.type == SHT_GNU_HASH || s.type == SHT_SYMTAB_SHNDX;
        if (uses_link && s.link >= sh_.size())
            limited_("elf.section.link", "Section '" + out.name + "' sh_link " + std::to_string(s.link) +
                                             " is not a valid section index.", shoff_);
        if (o_.section_entropy && out.size && s.in_file) out.entropy = entropy(*v_.slice(s.offset, s.size));
        a_.sections.push_back(std::move(out));
    }
    assign_section_ids(a_.sections);
}

void ElfParser::read_program_headers() {
    if (phnum_ == 0) return;
    const std::uint16_t min_ph = wide_ ? 56 : 32;
    if (phentsize_ < min_ph) {
        diag(a_, "elf.phdr.entsize", "e_phentsize " + std::to_string(phentsize_) + " is smaller than " +
                                         std::to_string(min_ph) + ".", wide_ ? 54u : 42u);
        return;
    }
    if (phnum_ > o_.limits.max_segments) {
        diag(a_, "elf.phdr.limit", std::to_string(phnum_) + " program headers exceed the configured limit.", phoff_);
        return;
    }
    auto table = checked_mul(phentsize_, phnum_);
    if (!table || !f_.contains(phoff_, *table)) {
        diag(a_, "elf.phdr.out_of_range", "Program header table extends beyond the file.", phoff_);
        return;
    }
    a_.structures.push_back({"Program header table", "table", phoff_, *table});
    std::map<std::uint32_t, std::size_t> seen;
    for (std::uint64_t i = 0; i < phnum_; ++i) {
        const auto r = *v_.record(phoff_ + i * phentsize_, min_ph);
        Phdr p;
        p.type = r.u32(0);
        if (wide_) {
            p.flags = r.u32(4);
            p.offset = r.u64(8);
            p.vaddr = r.u64(16);
            p.paddr = r.u64(24);
            p.filesz = r.u64(32);
            p.memsz = r.u64(40);
            p.align = r.u64(48);
        } else {
            p.offset = r.u32(4);
            p.vaddr = r.u32(8);
            p.paddr = r.u32(12);
            p.filesz = r.u32(16);
            p.memsz = r.u32(20);
            p.flags = r.u32(24);
            p.align = r.u32(28);
        }
        ph_.push_back(p);

        Section out;
        out.index = static_cast<std::uint32_t>(i);
        out.kind = segment_type_name(p.type);
        out.name = out.kind + "[" + std::to_string(i) + "]";
        out.id = "segment:" + out.kind + "#" + std::to_string(seen[p.type]++);
        out.type = p.type;
        out.offset = p.offset;
        out.size = p.filesz;
        out.address = p.vaddr;
        out.virtual_size = p.memsz;
        out.flags = p.flags;
        out.flags_text = std::string(p.flags & 4 ? "R" : "-") + (p.flags & 2 ? "W" : "-") + (p.flags & 1 ? "X" : "-");
        out.alignment = p.align;
        out.info = p.paddr;
        if (p.filesz && !f_.contains(p.offset, p.filesz)) {
            out.file_range_valid = false;
            diag(a_, "elf.segment.out_of_range", out.name + " [" + hex(p.offset) + ", +" + hex(p.filesz) +
                                                     ") extends beyond the file.", p.offset);
        }
        if (o_.section_entropy && p.filesz && f_.contains(p.offset, p.filesz))
            out.entropy = entropy(*v_.slice(p.offset, p.filesz));
        if (p.type == PT_LOAD) {
            if (p.filesz > p.memsz)
                diag(a_, "elf.segment.filesz", out.name + " has p_filesz larger than p_memsz.", phoff_ + i * phentsize_);
            if (p.align > 1 && !is_power_of_two(p.align))
                diag(a_, "elf.segment.alignment", out.name + " alignment is not a power of two.", phoff_ + i * phentsize_);
            else if (p.align > 1 && (p.vaddr % p.align) != (p.offset % p.align))
                diag(a_, "elf.segment.congruence", out.name + ": p_vaddr and p_offset are not congruent modulo p_align.",
                     phoff_ + i * phentsize_);
            a_.mappings.push_back({out.name, p.vaddr, p.memsz, p.offset, std::min(p.filesz, p.memsz)});
        } else if (p.type == PT_INTERP) {
            if (auto s = v_.slice(p.offset, p.filesz)) {
                auto interp = ByteView(*s).cstring(0, p.filesz);
                if (interp) add_property(a_, "Interpreter", printable(*interp));
                else diag(a_, "elf.interp.unterminated", "PT_INTERP string is not NUL-terminated.", p.offset);
            }
        } else if (p.type == PT_GNU_STACK) {
            add_property(a_, "Stack", (p.flags & 1) ? "executable (PT_GNU_STACK has PF_X)" : "non-executable");
        } else if (p.type == PT_GNU_RELRO) {
            add_property(a_, "RELRO", "present");
        }
        a_.segments.push_back(std::move(out));
    }
    if (seen[PT_INTERP] > 1) diag(a_, "elf.segment.duplicate", "More than one PT_INTERP segment.", phoff_);
    if (seen[PT_DYNAMIC] > 1) diag(a_, "elf.segment.duplicate", "More than one PT_DYNAMIC segment.", phoff_);
}

void ElfParser::validate_layout() {
    // PT_LOAD segments must be sorted by p_vaddr (gABI).
    std::uint64_t last = 0;
    bool first = true;
    for (const auto& p : ph_) {
        if (p.type != PT_LOAD) continue;
        if (!first && p.vaddr < last) {
            diag(a_, "elf.segment.order", "PT_LOAD segments are not in ascending p_vaddr order.", phoff_);
            break;
        }
        last = p.vaddr;
        first = false;
    }
    // File-backed sections must not overlap each other.
    std::vector<std::size_t> order;
    for (std::size_t i = 1; i < sh_.size(); ++i)
        if (sh_[i].in_file && sh_[i].size) order.push_back(i);
    std::sort(order.begin(), order.end(), [&](std::size_t x, std::size_t y) { return sh_[x].offset < sh_[y].offset; });
    std::optional<std::size_t> furthest;
    for (std::size_t i : order) {
        if (furthest) {
            const auto end = sh_[*furthest].offset + sh_[*furthest].size;
            if (sh_[i].offset < end)
                limited_("elf.section.overlap", "Sections '" + a_.sections[*furthest].name + "' and '" +
                                                    a_.sections[i].name + "' overlap in the file.", sh_[i].offset);
            if (sh_[i].offset + sh_[i].size <= end) continue;
        }
        furthest = i;
    }
    // Entry point should be in an executable PT_LOAD.
    if ((type_ == 2 || type_ == 3) && a_.entry_point != 0 && !ph_.empty()) {
        bool found = false, exec = false;
        for (const auto& p : ph_)
            if (p.type == PT_LOAD && subrange_of(p.vaddr, p.memsz, a_.entry_point, 1)) {
                found = true;
                exec = exec || (p.flags & 1);
            }
        if (!found)
            diag(a_, "elf.entry.outside_segments", "Entry point " + hex(a_.entry_point) + " is not inside any PT_LOAD segment.", 24);
        else if (!exec)
            diag(a_, "elf.entry.not_executable", "Entry point lies in a PT_LOAD segment without PF_X.", 24);
    }
}

std::optional<std::string> ElfParser::string_at(std::uint64_t table_offset, std::uint64_t table_size,
                                                std::uint64_t index) const {
    if (index >= table_size) return std::nullopt;
    auto s = v_.cstring(table_offset + index, std::min<std::uint64_t>(table_size - index, o_.limits.max_string));
    if (!s) return std::nullopt;
    return printable(*s);
}

void ElfParser::parse_symbols() {
    for (std::size_t i = 0; i < sh_.size(); ++i)
        if (sh_[i].type == SHT_SYMTAB || sh_[i].type == SHT_DYNSYM) parse_symbol_table(i);
    std::size_t defined = 0, undefined = 0;
    for (const auto& s : a_.symbols) (s.section_index == SHN_UNDEF ? undefined : defined)++;
    if (!a_.symbols.empty())
        add_property(a_, "Symbols", std::to_string(a_.symbols.size()) + " (" + std::to_string(defined) + " defined, " +
                                        std::to_string(undefined) + " undefined)");
}

void ElfParser::parse_symbol_table(std::size_t index) {
    const auto& s = sh_[index];
    const std::string& table = a_.sections[index].name;
    const std::uint64_t min_entry = wide_ ? 24 : 16;
    if (!s.in_file) return;  // already reported as out of range
    if (s.entsize < min_entry) {
        diag(a_, "elf.symtab.entsize", table + ": sh_entsize " + std::to_string(s.entsize) + " is smaller than " +
                                           std::to_string(min_entry) + ".", s.offset);
        return;
    }
    std::optional<Shdr> strtab;
    if (s.link < sh_.size() && sh_[s.link].in_file && sh_[s.link].type == SHT_STRTAB) strtab = sh_[s.link];
    else diag(a_, "elf.symtab.strtab", table + ": linked string table is missing or invalid; names omitted.", s.offset);
    // Extended section indices for symbols whose st_shndx is SHN_XINDEX.
    std::optional<Shdr> xindex;
    for (const auto& x : sh_)
        if (x.type == SHT_SYMTAB_SHNDX && x.link == index && x.in_file) xindex = x;

    const std::uint64_t count = s.size / s.entsize;
    if (s.size % s.entsize)
        diag(a_, "elf.symtab.size", table + ": size is not a multiple of sh_entsize.", s.offset);
    const std::size_t first = a_.symbols.size();
    for (std::uint64_t i = 0; i < count; ++i) {
        if (a_.symbols.size() >= o_.limits.max_symbols) {
            diag(a_, "elf.symtab.limit", "Symbol count reached the configured limit; remaining symbols skipped.", s.offset);
            break;
        }
        const auto r = *v_.record(s.offset + i * s.entsize, min_entry);
        Symbol sym;
        sym.table = table;
        sym.index = static_cast<std::uint32_t>(i);
        const std::uint32_t name = r.u32(0);
        std::uint8_t info, other;
        std::uint16_t shndx;
        if (wide_) {
            info = r.u8(4);
            other = r.u8(5);
            shndx = r.u16(6);
            sym.value = r.u64(8);
            sym.size = r.u64(16);
        } else {
            sym.value = r.u32(4);
            sym.size = r.u32(8);
            info = r.u8(12);
            other = r.u8(13);
            shndx = r.u16(14);
        }
        if (strtab && name) {
            if (auto n = string_at(strtab->offset, strtab->size, name)) sym.name = *n;
            else limited_("elf.symbol.name", table + ": symbol " + std::to_string(i) + " name offset is invalid.", s.offset);
        }
        const int t = info & 0xf, bnd = info >> 4;
        sym.type = t == 0 ? "NOTYPE" : t == 1 ? "OBJECT" : t == 2 ? "FUNC" : t == 3 ? "SECTION" : t == 4 ? "FILE"
                 : t == 5 ? "COMMON" : t == 6 ? "TLS" : t == 10 ? "GNU_IFUNC" : std::to_string(t);
        sym.bind = bnd == 0 ? "LOCAL" : bnd == 1 ? "GLOBAL" : bnd == 2 ? "WEAK" : bnd == 10 ? "GNU_UNIQUE" : std::to_string(bnd);
        const int vis = other & 3;
        sym.visibility = vis == 0 ? "DEFAULT" : vis == 1 ? "INTERNAL" : vis == 2 ? "HIDDEN" : "PROTECTED";
        sym.section_index = shndx;
        if (shndx == SHN_XINDEX) {
            auto x = xindex ? v_.u32(xindex->offset + i * 4) : std::nullopt;
            if (x && xindex->size / 4 > i) sym.section_index = *x;
            else limited_("elf.symbol.xindex", table + ": symbol " + std::to_string(i) +
                                                   " uses SHN_XINDEX but no SHT_SYMTAB_SHNDX entry is available.", s.offset);
        } else if (shndx < SHN_LORESERVE && shndx >= sh_.size() && !sh_.empty()) {
            limited_("elf.symbol.section", table + ": symbol " + std::to_string(i) + " refers to section " +
                                               std::to_string(shndx) + ", which does not exist.", s.offset);
        }
        a_.symbols.push_back(std::move(sym));
    }
    symbol_ranges_[index] = {first, a_.symbols.size() - first};
}

// GNU symbol versioning: SHT_GNU_verdef / SHT_GNU_verneed define version
// indices; SHT_GNU_versym assigns one index per dynamic symbol.
void ElfParser::parse_versions() {
    constexpr std::uint32_t SHT_VERDEF = 0x6ffffffd, SHT_VERNEED = 0x6ffffffe, SHT_VERSYM = 0x6fffffff;
    std::map<std::uint32_t, std::string> names;  // version index -> name
    std::map<std::string, std::string> required;  // library -> "V1, V2"
    auto strtab_of = [&](const Shdr& s) -> std::optional<Shdr> {
        if (s.link < sh_.size() && sh_[s.link].in_file && sh_[s.link].type == SHT_STRTAB) return sh_[s.link];
        return std::nullopt;
    };
    for (std::size_t si = 0; si < sh_.size(); ++si) {
        const auto& s = sh_[si];
        if ((s.type != SHT_VERDEF && s.type != SHT_VERNEED) || !s.in_file) continue;
        const auto strtab = strtab_of(s);
        const std::string& table = a_.sections[si].name;
        if (!strtab) {
            diag(a_, "elf.version.strtab", table + ": linked string table is missing or invalid.", s.offset);
            continue;
        }
        auto str = [&](std::uint32_t off) { return string_at(strtab->offset, strtab->size, off).value_or("<invalid>"); };
        const bool def = s.type == SHT_VERDEF;
        const std::uint64_t entry = def ? 20 : 16, aux_size = def ? 8 : 16;
        std::uint64_t at = 0;
        // Each step must move forward inside the section, which bounds the walk.
        for (std::uint64_t n = 0; n < s.size / entry + 1; ++n) {
            auto e = range_within(at, entry, s.size) ? v_.record(s.offset + at, entry) : std::nullopt;
            if (!e) {
                limited_("elf.version.chain", table + ": entry at +" + hex(at) + " lies outside the section.", s.offset);
                break;
            }
            const std::uint16_t count = e->u16(def ? 6 : 2);
            std::uint64_t aux = at + e->u32(def ? 12 : 8);
            const std::string file = def ? std::string() : str(e->u32(4));
            for (std::uint16_t k = 0; k < count && k < 1024; ++k) {
                auto x = range_within(aux, aux_size, s.size) ? v_.record(s.offset + aux, aux_size) : std::nullopt;
                if (!x) {
                    limited_("elf.version.chain", table + ": auxiliary entry lies outside the section.", s.offset + aux);
                    break;
                }
                if (def) {
                    // The first Verdaux names the version; later ones name its parents.
                    if (k == 0) names[e->u16(4)] = str(x->u32(0));
                } else {
                    const std::string vname = str(x->u32(8));
                    names[x->u16(6)] = vname;
                    auto& list = required[file];
                    list += (list.empty() ? "" : ", ") + vname;
                }
                const std::uint32_t next_aux = x->u32(def ? 4 : 12);
                if (next_aux == 0) break;
                aux += next_aux;
            }
            const std::uint32_t next = e->u32(def ? 16 : 12);
            if (next == 0) break;
            at += next;
        }
    }
    for (const auto& [lib, versions] : required) add_property(a_, "Required versions: " + lib, versions);

    for (std::size_t si = 0; si < sh_.size(); ++si) {
        const auto& s = sh_[si];
        if (s.type != SHT_VERSYM || !s.in_file) continue;
        auto it = symbol_ranges_.find(s.link);
        if (it == symbol_ranges_.end()) {
            diag(a_, "elf.version.versym_link", a_.sections[si].name + ": sh_link is not a parsed symbol table.", s.offset);
            continue;
        }
        const auto [first, count] = it->second;
        if (s.size / 2 != count)
            diag(a_, "elf.version.count", a_.sections[si].name + " has " + std::to_string(s.size / 2) +
                                              " entries for " + std::to_string(count) + " symbols.", s.offset);
        const std::uint64_t n = std::min<std::uint64_t>(s.size / 2, count);
        for (std::uint64_t i = 0; i < n; ++i) {
            const std::uint16_t v = *v_.u16(s.offset + i * 2);
            const std::uint16_t idx = v & 0x7fff;
            if (idx <= 1) continue;  // local / global base version
            auto name = names.find(idx);
            if (name == names.end()) {
                limited_("elf.version.index", "Symbol " + std::to_string(i) + " uses undefined version index " +
                                                  std::to_string(idx) + ".", s.offset + i * 2);
                continue;
            }
            a_.symbols[first + static_cast<std::size_t>(i)].version = name->second + ((v & 0x8000) ? " (hidden)" : "");
        }
    }
}

void ElfParser::parse_dynamic() {
    std::uint64_t offset = 0, size = 0;
    std::optional<std::uint32_t> link;
    bool found = false;
    for (const auto& s : sh_)
        if (s.type == SHT_DYNAMIC && s.in_file) {
            offset = s.offset;
            size = s.size;
            link = s.link;
            found = true;
            break;
        }
    if (!found)
        for (const auto& p : ph_)
            if (p.type == PT_DYNAMIC && f_.contains(p.offset, p.filesz)) {
                offset = p.offset;
                size = p.filesz;
                found = true;
                break;
            }
    if (!found) return;
    const std::uint64_t entry = wide_ ? 16 : 8;
    std::vector<std::pair<std::int64_t, std::uint64_t>> raw;
    bool terminated = false;
    for (std::uint64_t at = 0; at + entry <= size; at += entry) {
        if (raw.size() >= o_.limits.max_dynamic) {
            diag(a_, "elf.dynamic.limit", "Dynamic section exceeds the configured entry limit.", offset);
            break;
        }
        const auto r = *v_.record(offset + at, entry);
        const auto tag = wide_ ? static_cast<std::int64_t>(r.u64(0)) : static_cast<std::int64_t>(static_cast<std::int32_t>(r.u32(0)));
        const auto val = r.word(wide_ ? 8 : 4, wide_);
        if (tag == 0) {
            terminated = true;
            break;
        }
        raw.emplace_back(tag, val);
    }
    if (!terminated) diag(a_, "elf.dynamic.unterminated", "Dynamic array has no DT_NULL terminator.", offset);

    // String table: DT_STRTAB (an address) bounded by DT_STRSZ, else the section link.
    std::optional<std::pair<std::uint64_t, std::uint64_t>> strtab;
    std::uint64_t strtab_addr = 0, strsz = 0;
    bool has_strtab = false;
    for (const auto& [t, v] : raw) {
        if (t == 5) { strtab_addr = v; has_strtab = true; }
        if (t == 10) strsz = v;
    }
    if (has_strtab) {
        auto m = address_to_offset(a_, strtab_addr);
        if (m.status == MapStatus::FileBacked && f_.contains(m.offset, strsz)) strtab = {{m.offset, strsz}};
        else diag(a_, "elf.dynamic.strtab", "DT_STRTAB/DT_STRSZ do not describe a file-backed range.", offset);
    }
    if (!strtab && link && *link < sh_.size() && sh_[*link].in_file) strtab = {{sh_[*link].offset, sh_[*link].size}};

    std::string needed, flags_text;
    for (const auto& [t, v] : raw) {
        DynamicEntry d;
        d.tag = t;
        d.tag_name = dynamic_tag_name(t);
        d.value = v;
        if (t == 1 || t == 14 || t == 15 || t == 29) {
            if (strtab) {
                if (auto s = string_at(strtab->first, strtab->second, v)) d.text = *s;
                else limited_("elf.dynamic.string", d.tag_name + " string offset " + hex(v) + " is invalid.", offset);
            }
            if (t == 1) needed += (needed.empty() ? "" : ", ") + d.text;
            if (t == 14) add_property(a_, "SONAME", d.text);
            if (t == 15) add_property(a_, "RPATH", d.text);
            if (t == 29) add_property(a_, "RUNPATH", d.text);
        } else if (t == 30) {
            d.text = join_flags_text(v, {{1, "ORIGIN"}, {2, "SYMBOLIC"}, {4, "TEXTREL"}, {8, "BIND_NOW"}, {0x10, "STATIC_TLS"}});
            if (v & 8) add_property(a_, "BIND_NOW", "set (DT_FLAGS)");
        } else if (t == 0x6ffffffb) {
            d.text = join_flags_text(v, {{1, "NOW"}, {2, "GLOBAL"}, {4, "GROUP"}, {8, "NODELETE"}, {0x10, "LOADFLTR"},
                                         {0x20, "INITFIRST"}, {0x40, "NOOPEN"}, {0x80, "ORIGIN"}, {0x100, "DIRECT"},
                                         {0x400, "INTERPOSE"}, {0x800, "NODEFLIB"}, {0x1000, "NODUMP"},
                                         {0x08000000, "PIE"}});
            if (v & 1) add_property(a_, "BIND_NOW", "set (DF_1_NOW)");
            if (v & 0x08000000) a_.file_type = "PIE executable";
        } else if (t == 24) {
            add_property(a_, "BIND_NOW", "set (DT_BIND_NOW)");
        } else if (t == 22) {
            diag(a_, "elf.dynamic.textrel", "DT_TEXTREL: the image needs writable text relocations.", offset);
        }
        a_.dynamic.push_back(std::move(d));
    }
    if (!needed.empty()) add_property(a_, "Needed libraries", needed);
    if (type_ == 3 && a_.file_type == "Shared object" && a_.property("Interpreter"))
        a_.file_type = "PIE executable (inferred from PT_INTERP)";
}

// SHT_RELR (gABI): a word with the low bit clear is an address to relocate;
// a word with the low bit set is a bitmap whose bit k (k >= 1) relocates
// `where + (k - 1) * wordsize`, after which `where` advances by (bits - 1) words.
std::uint64_t ElfParser::expand_relr(std::size_t index) {
    const auto& s = sh_[index];
    const std::uint64_t word = wide_ ? 8 : 4, bits = word * 8;
    if (s.entsize != word) {
        diag(a_, "elf.relr.entsize", a_.sections[index].name + ": sh_entsize must be " + std::to_string(word) + ".", s.offset);
        return 0;
    }
    const std::uint32_t type = machine_ == 62 ? 8 : machine_ == 3 ? 8 : machine_ == 183 ? 1027 : 0;
    const std::string type_name = (type ? relocation_type_name(machine_, type) : std::string("relative")) + " (RELR)";
    const std::uint64_t count = s.size / word;
    std::optional<std::uint64_t> where;
    auto emit = [&](std::uint64_t address) {
        if (a_.relocations.size() >= o_.limits.max_relocations) return false;
        Relocation r;
        r.section = a_.sections[index].name;
        r.offset = address;
        r.type = type;
        r.type_name = type_name;
        a_.relocations.push_back(std::move(r));
        return true;
    };
    for (std::uint64_t k = 0; k < count; ++k) {
        const std::uint64_t entry = s.offset + k * word;
        const std::uint64_t v = wide_ ? *v_.u64(entry) : *v_.u32(entry);
        if ((v & 1) == 0) {
            if (!emit(v)) break;
            where = v + word;
        } else if (!where) {
            limited_("elf.relr.bitmap_first", a_.sections[index].name + ": RELR bitmap entry without a preceding address.", entry);
        } else {
            for (std::uint64_t b = 1; b < bits; ++b)
                if ((v >> b) & 1)
                    if (!emit(*where + (b - 1) * word)) break;
            *where += (bits - 1) * word;
        }
        if (a_.relocations.size() >= o_.limits.max_relocations) {
            diag(a_, "elf.reloc.limit", "Relocation count reached the configured limit; remaining entries skipped.", s.offset);
            break;
        }
    }
    return count;
}

void ElfParser::parse_relocations() {
    std::uint64_t relr_words = 0;
    for (std::size_t i = 0; i < sh_.size(); ++i) {
        const auto& s = sh_[i];
        if (s.type == SHT_RELR && s.in_file) {
            relr_words += expand_relr(i);
            continue;
        }
        if ((s.type != SHT_REL && s.type != SHT_RELA) || !s.in_file) continue;
        const bool rela = s.type == SHT_RELA;
        const std::uint64_t min_entry = wide_ ? (rela ? 24 : 16) : (rela ? 12 : 8);
        const std::string& name = a_.sections[i].name;
        if (s.entsize < min_entry) {
            diag(a_, "elf.reloc.entsize", name + ": sh_entsize " + std::to_string(s.entsize) + " is too small.", s.offset);
            continue;
        }
        std::optional<std::pair<std::size_t, std::size_t>> symbols;
        if (s.link != 0) {
            if (auto it = symbol_ranges_.find(s.link); it != symbol_ranges_.end()) symbols = it->second;
            else limited_("elf.reloc.symtab", name + ": sh_link does not refer to a parsed symbol table.", s.offset);
        }
        const std::uint64_t count = s.size / s.entsize;
        for (std::uint64_t k = 0; k < count; ++k) {
            if (a_.relocations.size() >= o_.limits.max_relocations) {
                diag(a_, "elf.reloc.limit", "Relocation count reached the configured limit; remaining entries skipped.", s.offset);
                return;
            }
            const auto r = *v_.record(s.offset + k * s.entsize, min_entry);
            Relocation rel;
            rel.section = name;
            rel.offset = r.word(0, wide_);
            const std::uint64_t info = r.word(wide_ ? 8 : 4, wide_);
            rel.type = wide_ ? static_cast<std::uint32_t>(info & 0xffffffffu) : static_cast<std::uint32_t>(info & 0xff);
            rel.symbol_index = wide_ ? (info >> 32) : (info >> 8);
            rel.type_name = relocation_type_name(machine_, rel.type);
            if (rela) {
                rel.has_addend = true;
                rel.addend = wide_ ? static_cast<std::int64_t>(r.u64(16)) : static_cast<std::int64_t>(static_cast<std::int32_t>(r.u32(8)));
            }
            if (symbols && rel.symbol_index) {
                if (rel.symbol_index < symbols->second) rel.symbol = a_.symbols[symbols->first + rel.symbol_index].name;
                else limited_("elf.reloc.symbol_range", name + ": relocation refers to symbol " +
                                                            std::to_string(rel.symbol_index) + ", beyond the symbol table.", s.offset);
            }
            a_.relocations.push_back(std::move(rel));
        }
    }
    if (relr_words) add_property(a_, "RELR relocations", std::to_string(relr_words) + " packed words");
}

void ElfParser::parse_notes() {
    bool from_sections = false;
    for (std::size_t i = 0; i < sh_.size(); ++i)
        if (sh_[i].type == SHT_NOTE && sh_[i].in_file) {
            from_sections = true;
            parse_note_area(a_.sections[i].name, sh_[i].offset, sh_[i].size, sh_[i].addralign);
        }
    if (from_sections) return;
    for (std::size_t i = 0; i < ph_.size(); ++i)
        if (ph_[i].type == PT_NOTE && f_.contains(ph_[i].offset, ph_[i].filesz))
            parse_note_area(a_.segments[i].name, ph_[i].offset, ph_[i].filesz, ph_[i].align);
}

void ElfParser::parse_note_area(const std::string& source, std::uint64_t offset, std::uint64_t size, std::uint64_t align) {
    const std::uint64_t a = align == 8 ? 8 : 4;
    std::uint64_t at = 0;
    while (at < size) {
        if (a_.notes.size() >= o_.limits.max_notes) {
            diag(a_, "elf.note.limit", "Note count reached the configured limit.", offset + at);
            return;
        }
        if (size - at < 12) {
            limited_("elf.note.truncated", source + ": trailing bytes too short for a note header.", offset + at);
            return;
        }
        const auto h = *v_.record(offset + at, 12);
        const std::uint32_t namesz = h.u32(0), descsz = h.u32(4), type = h.u32(8);
        auto name_end = align_up(12 + std::uint64_t{namesz}, a);
        auto desc_end = name_end ? checked_add(*name_end, descsz) : std::nullopt;
        if (!desc_end || *desc_end > size - at) {
            limited_("elf.note.truncated", source + ": note sizes exceed the containing area.", offset + at);
            return;
        }
        Note n;
        n.source = source;
        n.type = type;
        n.offset = offset + at;
        n.size = *desc_end;
        n.descriptor_size = descsz;
        const auto name_bytes = *v_.slice(offset + at + 12, namesz);
        std::string owner(name_bytes.begin(), name_bytes.end());
        while (!owner.empty() && owner.back() == '\0') owner.pop_back();
        n.owner = printable(owner);
        const auto desc = *v_.slice(offset + at + *name_end, descsz);
        n.description = describe_note(owner, type, desc, n.type_name);
        a_.notes.push_back(std::move(n));
        auto next = align_up(*desc_end, a);  // relative to this note; always >= 12
        if (!next) return;
        at += *next;
    }
}

std::string ElfParser::describe_note(const std::string& owner, std::uint32_t type, std::span<const std::uint8_t> desc,
                                     std::string& type_name) {
    ByteView d(desc, v_.endian());
    if (owner == "GNU") {
        switch (type) {
        case 1: {
            type_name = "NT_GNU_ABI_TAG";
            if (desc.size() < 16) return "truncated";
            const auto os = *d.u32(0);
            const char* osn = os == 0 ? "Linux" : os == 1 ? "Hurd" : os == 2 ? "Solaris" : os == 3 ? "FreeBSD" : "OS?";
            return std::string(osn) + " " + std::to_string(*d.u32(4)) + "." + std::to_string(*d.u32(8)) + "." +
                   std::to_string(*d.u32(12));
        }
        case 3: {
            type_name = "NT_GNU_BUILD_ID";
            auto id = hex_bytes(desc, 64);
            add_property(a_, "Build ID", id);
            return id;
        }
        case 4: {
            type_name = "NT_GNU_GOLD_VERSION";
            auto s = d.cstring(0, desc.size());
            return s ? printable(*s) : printable(std::string_view(reinterpret_cast<const char*>(desc.data()), desc.size()));
        }
        case 5: {
            type_name = "NT_GNU_PROPERTY_TYPE_0";
            std::string out;
            const std::uint64_t pa = wide_ ? 8 : 4;
            for (std::uint64_t at = 0; at + 8 <= desc.size();) {
                const auto pr_type = *d.u32(at), pr_size = *d.u32(at + 4);
                if (pr_size > desc.size() - at - 8) {
                    out += (out.empty() ? "" : "; ") + std::string("truncated property");
                    break;
                }
                std::string item;
                if ((pr_type == 0xc0000002 || pr_type == 0xc0000000) && pr_size >= 4) {
                    const auto bits = *d.u32(at + 8);
                    item = pr_type == 0xc0000002
                               ? "x86 feature: " + join_flags_text(bits, {{1, "IBT"}, {2, "SHSTK"}})
                               : "AArch64 feature: " + join_flags_text(bits, {{1, "BTI"}, {2, "PAC"}});
                } else {
                    item = "property " + hex(pr_type) + " (" + std::to_string(pr_size) + " bytes)";
                }
                out += (out.empty() ? "" : "; ") + item;
                auto next = align_up(at + 8 + pr_size, pa);
                if (!next || *next <= at) break;
                at = *next;
            }
            return out;
        }
        default: break;
        }
    }
    if (owner == "Go" && type == 4) {
        type_name = "Go build ID";
        return printable(std::string_view(reinterpret_cast<const char*>(desc.data()), desc.size()));
    }
    if (owner == "FDO" && type == 0xcafe1a7e) {
        type_name = "FDO packaging metadata";
        auto s = d.cstring(0, desc.size());
        return s ? printable(*s) : "unterminated";
    }
    type_name = "type " + hex(type);
    return hex_bytes(desc, 32);
}

} // namespace

void parse_elf(const FileImage& f, Analysis& a, const AnalyzeOptions& o) { ElfParser(f, a, o).run(); }

} // namespace bw::detail
