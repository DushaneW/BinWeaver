// PE/COFF image parser. References: Microsoft "PE Format" specification;
// loader behaviour noted where BinWeaver deliberately mirrors it.
#include "internal.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>

namespace bw::detail {
namespace {

constexpr std::uint64_t kHardcodedFileAlignment = 0x200;
constexpr std::uint32_t kMaxImportDescriptors = 4096;
constexpr std::uint32_t kMaxThunksPerLibrary = 1u << 16;

constexpr std::array<const char*, 16> kDirectoryNames = {
    "Export", "Import", "Resource", "Exception", "Security", "Base relocation", "Debug", "Architecture",
    "Global pointer", "TLS", "Load config", "Bound import", "IAT", "Delay import", "CLR", "Reserved"};

enum DirIndex : std::uint32_t {
    kDirExport = 0, kDirImport = 1, kDirResource = 2, kDirException = 3, kDirSecurity = 4, kDirBaseReloc = 5,
    kDirDebug = 6, kDirArchitecture = 7, kDirGlobalPtr = 8, kDirTls = 9, kDirLoadConfig = 10,
    kDirBoundImport = 11, kDirIat = 12, kDirDelayImport = 13, kDirClr = 14, kDirReserved = 15
};

const char* machine_name(std::uint16_t m) {
    switch (m) {
    case 0x14c: return "x86";
    case 0x8664: return "x86-64";
    case 0xaa64: return "ARM64";
    case 0xa641: return "ARM64EC";
    case 0x1c0: return "ARM";
    case 0x1c4: return "ARMv7 (Thumb-2)";
    case 0x200: return "IA-64";
    case 0x5032: return "RISC-V 32";
    case 0x5064: return "RISC-V 64";
    case 0xebc: return "EFI byte code";
    default: return nullptr;
    }
}

const char* subsystem_name(std::uint16_t s) {
    switch (s) {
    case 1: return "Native";
    case 2: return "Windows GUI";
    case 3: return "Windows console";
    case 5: return "OS/2 console";
    case 7: return "POSIX console";
    case 9: return "Windows CE GUI";
    case 10: return "EFI application";
    case 11: return "EFI boot service driver";
    case 12: return "EFI runtime driver";
    case 13: return "EFI ROM";
    case 14: return "Xbox";
    case 16: return "Windows boot application";
    default: return nullptr;
    }
}

std::string section_flags(std::uint32_t c) {
    std::string rwx;
    rwx += (c & 0x40000000u) ? 'R' : '-';
    rwx += (c & 0x80000000u) ? 'W' : '-';
    rwx += (c & 0x20000000u) ? 'X' : '-';
    std::string extra;
    if (c & 0x20) extra += " CODE";
    if (c & 0x40) extra += " IDATA";
    if (c & 0x80) extra += " UDATA";
    if (c & 0x02000000u) extra += " DISCARDABLE";
    if (c & 0x10000000u) extra += " SHARED";
    return rwx + extra;
}

struct PeSection {
    std::string name;
    std::uint32_t virtual_size{}, virtual_address{}, raw_size{}, raw_pointer{}, characteristics{};
    std::uint64_t effective_raw_pointer{};
};

class PeParser {
public:
    PeParser(const FileImage& f, Analysis& a, const AnalyzeOptions& o)
        : f_(f), v_(f.bytes(), Endian::Little), a_(a), o_(o), limited_(a) {}
    void run();

private:
    // Translates [rva, rva + length) to a file offset when the whole range is
    // file-backed inside a single mapping.
    std::optional<std::uint64_t> rva_offset(std::uint64_t rva, std::uint64_t length) const;
    std::optional<std::string> rva_string(std::uint64_t rva) const;
    std::optional<Record> rva_record(std::uint64_t rva, std::uint64_t length) const {
        auto off = rva_offset(rva, length);
        return off ? v_.record(*off, length) : std::nullopt;
    }
    bool parse_optional_header(std::uint64_t at, std::uint16_t size);
    void parse_section_table(std::uint64_t at, std::uint16_t count, std::uint32_t symtab_ptr, std::uint32_t nsyms);
    void build_mappings();
    void validate_directories();
    void parse_imports(const Directory&);
    void parse_delay_imports(const Directory&);
    // Reads an import lookup table; returns false if it could not be read.
    bool read_thunks(const std::string& library, std::uint64_t lookup_rva, std::uint64_t iat_rva, bool delayed);
    void parse_exports(const Directory&);
    void parse_certificates(const Directory&);
    void parse_debug(const Directory&);
    void parse_base_relocations(const Directory&);
    void parse_tls(const Directory&);
    void compute_checksum();
    void parse_resources(const Directory&);
    void parse_version_info(std::uint64_t offset, std::uint64_t size);
    void parse_manifest(std::uint64_t offset, std::uint64_t size);
    void parse_load_config(const Directory&);
    void parse_rich(std::uint32_t lfanew);
    void parse_exceptions(const Directory&);
    void parse_string_tables();
    void find_overlay();
    void validate_entry_point();

    const FileImage& f_;
    ByteView v_;
    Analysis& a_;
    const AnalyzeOptions& o_;
    DiagLimiter limited_;

    bool pe32plus_{};
    std::uint64_t optional_offset_{};
    std::uint32_t size_of_image_{}, size_of_headers_{}, file_alignment_{}, section_alignment_{}, checksum_{};
    std::vector<PeSection> sections_;
    std::uint64_t imports_total_{};
};

void PeParser::run() {
    auto dos = v_.record(0, 64);
    if (!dos) {
        diag(a_, "pe.dos.truncated", "File is shorter than the 64-byte DOS header.", 0);
        return;
    }
    a_.structures.push_back({"DOS header", "header", 0, 64});
    const std::uint32_t lfanew = dos->u32(0x3c);
    if (lfanew < 64)
        diag(a_, "pe.dos.lfanew_overlap", "e_lfanew (" + hex(lfanew) + ") points inside the DOS header.", 0x3c);
    auto coff = v_.record(lfanew, 24);
    if (!coff) {
        diag(a_, "pe.nt.out_of_range", "PE signature and COFF header at " + hex(lfanew) + " lie outside the file.", lfanew);
        return;
    }
    if (lfanew > 64) a_.structures.push_back({"DOS stub", "header", 64, lfanew - 64u});
    if (coff->u32(0) != 0x00004550) {
        diag(a_, "pe.nt.signature", "Missing 'PE\\0\\0' signature at " + hex(lfanew) + ".", lfanew);
        return;
    }
    a_.structures.push_back({"PE signature + COFF header", "header", lfanew, 24});
    parse_rich(lfanew);

    const std::uint16_t machine = coff->u16(4);
    const std::uint16_t nsections = coff->u16(6);
    const std::uint32_t timestamp = coff->u32(8);
    const std::uint32_t symtab_ptr = coff->u32(12);
    const std::uint32_t nsyms = coff->u32(16);
    const std::uint16_t optional_size = coff->u16(20);
    const std::uint16_t characteristics = coff->u16(22);

    if (const char* m = machine_name(machine)) a_.architecture = m;
    else diag(a_, "pe.coff.machine_unknown", "Unknown machine type " + hex(machine) + ".", lfanew + 4u);
    a_.file_type = (characteristics & 0x2000) ? "DLL" : (characteristics & 0x0002) ? "Executable image" : "Not an image";
    add_property(a_, "Machine", hex(machine));
    add_property(a_, "COFF timestamp", hex(timestamp) + " (may be a reproducible-build hash, not a date)");
    add_property(a_, "COFF characteristics",
                 join_flags_text(characteristics, {{0x0001, "RELOCS_STRIPPED"}, {0x0002, "EXECUTABLE_IMAGE"},
                                              {0x0004, "LINE_NUMS_STRIPPED"}, {0x0008, "LOCAL_SYMS_STRIPPED"},
                                              {0x0020, "LARGE_ADDRESS_AWARE"}, {0x0100, "32BIT_MACHINE"},
                                              {0x0200, "DEBUG_STRIPPED"}, {0x1000, "SYSTEM"}, {0x2000, "DLL"}}));
    if (!(characteristics & 0x0002))
        diag(a_, "pe.coff.not_image", "IMAGE_FILE_EXECUTABLE_IMAGE is not set; this may be an object file or a broken image.",
             lfanew + 22u);

    optional_offset_ = std::uint64_t{lfanew} + 24;
    if (optional_size == 0) {
        diag(a_, "pe.optional.absent", "SizeOfOptionalHeader is 0; image-specific metadata is unavailable.", lfanew + 20u);
    } else if (!f_.contains(optional_offset_, optional_size)) {
        diag(a_, "pe.optional.out_of_range", "Optional header extends beyond the end of the file.", optional_offset_);
        return;
    } else {
        a_.structures.push_back({"Optional header", "header", optional_offset_, optional_size});
        parse_optional_header(optional_offset_, optional_size);
    }

    if (nsections > 96)
        diag(a_, "pe.sections.count_high",
             std::to_string(nsections) + " sections; older Windows loaders reject more than 96.", lfanew + 6u);
    parse_section_table(optional_offset_ + optional_size, nsections, symtab_ptr, nsyms);
    add_property(a_, "Section count", std::to_string(nsections));
    build_mappings();
    if (optional_size == 0) return;

    validate_entry_point();
    validate_directories();
    for (const auto& d : std::vector<Directory>(a_.directories)) {
        if (d.size == 0 && d.address == 0) continue;
        switch (d.index) {
        case kDirExport: parse_exports(d); break;
        case kDirImport: parse_imports(d); break;
        case kDirDelayImport: parse_delay_imports(d); break;
        case kDirSecurity: parse_certificates(d); break;
        case kDirDebug: parse_debug(d); break;
        case kDirBaseReloc: parse_base_relocations(d); break;
        case kDirTls: parse_tls(d); break;
        case kDirResource: parse_resources(d); break;
        case kDirClr: decode_clr(f_, a_, d.address, d.size); break;
        case kDirLoadConfig: parse_load_config(d); break;
        case kDirException: parse_exceptions(d); break;
        default: break;
        }
    }
    if (o_.pe_checksum) compute_checksum();
    find_overlay();
}

bool PeParser::parse_optional_header(std::uint64_t at, std::uint16_t size) {
    auto oh = v_.record(at, size);
    const std::uint16_t magic = oh->u16(0);
    if (magic == 0x107) {
        diag(a_, "pe.optional.unsupported_magic", "ROM image optional header (0x107) is not supported.", at);
        return false;
    }
    if (magic != 0x10b && magic != 0x20b) {
        diag(a_, "pe.optional.magic", "Unknown optional header magic " + hex(magic) + ".", at);
        return false;
    }
    pe32plus_ = magic == 0x20b;
    a_.bitness = pe32plus_ ? "64-bit" : "32-bit";
    a_.byte_order = "little-endian";
    const std::uint32_t fixed = pe32plus_ ? 112 : 96;  // bytes before the data directory array
    if (size < fixed) {
        diag(a_, "pe.optional.short", "Optional header is " + std::to_string(size) + " bytes; " +
                                          std::to_string(fixed) + " are required for the standard fields.", at);
        return false;
    }
    a_.entry_point = oh->u32(16);
    a_.image_base = pe32plus_ ? oh->u64(24) : oh->u32(28);
    section_alignment_ = oh->u32(32);
    file_alignment_ = oh->u32(36);
    size_of_image_ = oh->u32(56);
    size_of_headers_ = oh->u32(60);
    checksum_ = oh->u32(64);
    const std::uint16_t subsystem = oh->u16(68);
    const std::uint16_t dll_chars = oh->u16(70);

    add_property(a_, "Optional header", pe32plus_ ? "PE32+" : "PE32");
    add_property(a_, "Image base", hex(a_.image_base));
    add_property(a_, "Linker version", std::to_string(oh->u8(2)) + "." + std::to_string(oh->u8(3)));
    add_property(a_, "OS version", std::to_string(oh->u16(40)) + "." + std::to_string(oh->u16(42)));
    add_property(a_, "Section alignment", hex(section_alignment_));
    add_property(a_, "File alignment", hex(file_alignment_));
    add_property(a_, "Size of image", hex(size_of_image_));
    add_property(a_, "Size of headers", hex(size_of_headers_));
    const char* sub = subsystem_name(subsystem);
    add_property(a_, "Subsystem", sub ? sub : "unknown (" + std::to_string(subsystem) + ")");
    add_property(a_, "DllCharacteristics",
                 join_flags_text(dll_chars, {{0x20, "HIGH_ENTROPY_VA"}, {0x40, "DYNAMIC_BASE"}, {0x80, "FORCE_INTEGRITY"},
                                        {0x100, "NX_COMPAT"}, {0x200, "NO_ISOLATION"}, {0x400, "NO_SEH"},
                                        {0x800, "NO_BIND"}, {0x1000, "APPCONTAINER"}, {0x2000, "WDM_DRIVER"},
                                        {0x4000, "GUARD_CF"}, {0x8000, "TERMINAL_SERVER_AWARE"}}));
    add_property(a_, "ASLR (DYNAMIC_BASE)", (dll_chars & 0x40) ? "set" : "not set");
    add_property(a_, "DEP (NX_COMPAT)", (dll_chars & 0x100) ? "set" : "not set");

    if (!is_power_of_two(section_alignment_) || !is_power_of_two(file_alignment_))
        diag(a_, "pe.optional.alignment", "SectionAlignment and FileAlignment must be powers of two.", at + 32);
    else if (section_alignment_ < file_alignment_)
        diag(a_, "pe.optional.alignment", "SectionAlignment is smaller than FileAlignment.", at + 32);
    else if (file_alignment_ < 512 && file_alignment_ != section_alignment_)
        diag(a_, "pe.optional.alignment",
             "FileAlignment below 512 is only valid when it equals SectionAlignment.", at + 36);
    if (size_of_headers_ > f_.size())
        diag(a_, "pe.optional.headers_size", "SizeOfHeaders (" + hex(size_of_headers_) + ") exceeds the file size.", at + 60);
    if (section_alignment_ && size_of_image_ % section_alignment_)
        diag(a_, "pe.optional.image_size", "SizeOfImage is not a multiple of SectionAlignment.", at + 56);

    // Data directories.
    const std::uint32_t declared = oh->u32(fixed - 4);
    const std::uint32_t fits = (size - fixed) / 8;
    std::uint32_t count = declared;
    if (count > 16) {
        diag(a_, "pe.directories.count", "NumberOfRvaAndSizes is " + std::to_string(declared) +
                                             "; only the 16 defined directories are read.", at + fixed - 4);
        count = 16;
    }
    if (count > fits) {
        diag(a_, "pe.directories.truncated", "Optional header holds " + std::to_string(fits) + " of " +
                                                 std::to_string(count) + " declared data directories.", at + fixed - 4);
        count = fits;
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::size_t o = fixed + std::size_t{i} * 8;
        a_.directories.push_back({kDirectoryNames[i], i, oh->u32(o), oh->u32(o + 4), std::nullopt, ""});
    }
    return true;
}

void PeParser::parse_section_table(std::uint64_t at, std::uint16_t count, std::uint32_t symtab_ptr,
                                   std::uint32_t nsyms) {
    if (count == 0) return;
    if (!f_.contains(at, std::uint64_t{count} * 40)) {
        diag(a_, "pe.sections.out_of_range", "Section table (" + std::to_string(count) + " entries) extends beyond the file.", at);
        return;
    }
    a_.structures.push_back({"Section table", "table", at, std::uint64_t{count} * 40});
    // COFF string table follows the symbol table; used for "/123" long names.
    std::optional<std::uint64_t> strtab;
    if (symtab_ptr) {
        auto s = checked_add(symtab_ptr, std::uint64_t{nsyms} * 18);
        if (s && f_.contains(*s, 4)) strtab = s;
    }
    std::uint32_t previous_va = 0;
    for (std::uint16_t i = 0; i < count; ++i) {
        const auto rec = *v_.record(at + std::uint64_t{i} * 40, 40);
        PeSection s;
        for (std::size_t j = 0; j < 8 && rec.u8(j); ++j) s.name += static_cast<char>(rec.u8(j));
        if (s.name.size() > 1 && s.name[0] == '/' && strtab &&
            std::all_of(s.name.begin() + 1, s.name.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)); })) {
            const auto offset = std::stoull(s.name.substr(1));
            if (auto str = v_.cstring(*strtab + offset, o_.limits.max_string)) s.name = std::string(*str);
        }
        s.name = printable(s.name);
        s.virtual_size = rec.u32(8);
        s.virtual_address = rec.u32(12);
        s.raw_size = rec.u32(16);
        s.raw_pointer = rec.u32(20);
        s.characteristics = rec.u32(36);
        // The Windows loader rounds PointerToRawData down to 512 when
        // FileAlignment >= 512; mirror that for offset translation.
        s.effective_raw_pointer = (file_alignment_ >= kHardcodedFileAlignment)
                                      ? (s.raw_pointer & ~std::uint64_t{kHardcodedFileAlignment - 1})
                                      : s.raw_pointer;
        if (s.effective_raw_pointer != s.raw_pointer && s.raw_size)
            diag(a_, "pe.section.raw_pointer_rounded",
                 "Section '" + s.name + "' PointerToRawData " + hex(s.raw_pointer) + " is not 512-aligned; the loader reads from " +
                     hex(s.effective_raw_pointer) + ".", at + std::uint64_t{i} * 40 + 20);

        Section out;
        out.index = i;
        out.name = s.name.empty() ? "<unnamed>" : s.name;
        out.kind = "PE section";
        out.offset = s.effective_raw_pointer;
        out.size = s.raw_size;
        out.address = s.virtual_address;
        out.virtual_size = s.virtual_size;
        out.flags = s.characteristics;
        out.flags_text = section_flags(s.characteristics);
        out.alignment = section_alignment_;
        if (s.raw_size && !f_.contains(out.offset, s.raw_size)) {
            out.file_range_valid = false;
            diag(a_, "pe.section.raw_out_of_range",
                 "Section '" + out.name + "' raw data [" + hex(out.offset) + ", +" + hex(s.raw_size) + ") exceeds the file.",
                 out.offset);
        }
        if (section_alignment_ && is_power_of_two(section_alignment_) && s.virtual_address % section_alignment_)
            diag(a_, "pe.section.va_misaligned", "Section '" + out.name + "' address is not SectionAlignment-aligned.",
                 at + std::uint64_t{i} * 40 + 12);
        if (i > 0 && s.virtual_address < previous_va)
            diag(a_, "pe.section.order", "Section '" + out.name + "' is not in ascending address order.",
                 at + std::uint64_t{i} * 40 + 12);
        previous_va = s.virtual_address;
        if (o_.section_entropy && out.size && out.offset < f_.size()) {
            const auto len = std::min<std::uint64_t>(out.size, f_.size() - out.offset);
            out.entropy = entropy(*v_.slice(out.offset, len));
        }
        sections_.push_back(std::move(s));
        a_.sections.push_back(std::move(out));
    }
    assign_section_ids(a_.sections);
    // Overlapping virtual ranges make RVA translation ambiguous. Sort by
    // start address and compare with the furthest end seen so far: O(n log n).
    std::vector<std::size_t> order(sections_.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
    auto span_of = [&](std::size_t i) {
        const auto& s = sections_[i];
        return std::uint64_t{s.virtual_size ? s.virtual_size : s.raw_size};
    };
    std::sort(order.begin(), order.end(),
              [&](std::size_t x, std::size_t y) { return sections_[x].virtual_address < sections_[y].virtual_address; });
    std::optional<std::size_t> furthest;
    for (std::size_t i : order) {
        if (span_of(i) == 0) continue;
        if (furthest) {
            const auto& f = sections_[*furthest];
            const std::uint64_t f_end = std::uint64_t{f.virtual_address} + span_of(*furthest);
            if (sections_[i].virtual_address < f_end)
                limited_("pe.section.virtual_overlap", "Sections '" + a_.sections[*furthest].name + "' and '" +
                                                           a_.sections[i].name + "' overlap in memory.", at);
            if (std::uint64_t{sections_[i].virtual_address} + span_of(i) <= f_end) continue;
        }
        furthest = i;
    }
}

void PeParser::build_mappings() {
    const std::uint64_t headers = size_of_headers_ ? size_of_headers_ : std::min<std::uint64_t>(f_.size(), 0x1000);
    a_.mappings.push_back({"headers", 0, headers, 0, std::min<std::uint64_t>(headers, f_.size())});
    for (std::size_t i = 0; i < sections_.size(); ++i) {
        const auto& s = sections_[i];
        // The loader maps VirtualSize bytes (SizeOfRawData when VirtualSize is
        // 0); only the first min(SizeOfRawData, VirtualSize) come from the file.
        const std::uint64_t mem = s.virtual_size ? s.virtual_size : s.raw_size;
        const std::uint64_t file = std::min<std::uint64_t>(s.raw_size, mem);
        a_.mappings.push_back({a_.sections[i].name, s.virtual_address, mem, s.effective_raw_pointer, file});
    }
}

std::optional<std::uint64_t> PeParser::rva_offset(std::uint64_t rva, std::uint64_t length) const {
    for (auto it = a_.mappings.rbegin(); it != a_.mappings.rend(); ++it) {
        if (!subrange_of(it->address, it->memory_size, rva, 1)) continue;
        const auto delta = rva - it->address;
        if (!range_within(delta, length, it->file_size)) return std::nullopt;
        auto off = checked_add(it->offset, delta);
        if (!off || !f_.contains(*off, length)) return std::nullopt;
        return off;
    }
    return std::nullopt;
}

std::optional<std::string> PeParser::rva_string(std::uint64_t rva) const {
    for (auto it = a_.mappings.rbegin(); it != a_.mappings.rend(); ++it) {
        if (!subrange_of(it->address, it->memory_size, rva, 1)) continue;
        const auto delta = rva - it->address;
        if (delta >= it->file_size) return std::nullopt;
        auto off = checked_add(it->offset, delta);
        if (!off) return std::nullopt;
        // A string must terminate inside the file-backed part of its mapping.
        const auto room = std::min<std::uint64_t>(it->file_size - delta, o_.limits.max_string);
        auto s = v_.cstring(*off, room);
        if (!s) return std::nullopt;
        return printable(*s);
    }
    return std::nullopt;
}

void PeParser::validate_entry_point() {
    if (a_.entry_point == 0) {
        if (a_.file_type != "DLL") diag(a_, "pe.entry.zero", "AddressOfEntryPoint is 0 in a non-DLL image.", optional_offset_ + 16);
        return;
    }
    for (std::size_t i = 0; i < sections_.size(); ++i) {
        const auto& s = sections_[i];
        const std::uint64_t mem = s.virtual_size ? s.virtual_size : s.raw_size;
        if (subrange_of(s.virtual_address, mem, a_.entry_point, 1)) {
            if (!(s.characteristics & 0x20000000u))
                diag(a_, "pe.entry.not_executable",
                     "Entry point lies in section '" + a_.sections[i].name + "', which is not marked executable.",
                     optional_offset_ + 16);
            return;
        }
    }
    diag(a_, "pe.entry.outside_sections", "Entry point " + hex(a_.entry_point) + " is not inside any section.",
         optional_offset_ + 16);
}

void PeParser::validate_directories() {
    for (auto& d : a_.directories) {
        if (d.address == 0 && d.size == 0) {
            d.status = "empty";
            continue;
        }
        if (d.index == kDirSecurity) {  // file offset, not an RVA
            if (f_.contains(d.address, d.size)) {
                d.file_offset = d.address;
                d.status = "ok";
            } else {
                d.status = "outside file";
                diag(a_, "pe.directory.out_of_range", "Security directory [" + hex(d.address) + ", +" + hex(d.size) +
                                                          ") (a file offset) extends beyond the file.", d.address);
            }
            continue;
        }
        if (d.index == kDirReserved) {
            d.status = "reserved slot is non-zero";
            diag(a_, "pe.directory.reserved", "The reserved data directory entry is non-zero.", 0);
            continue;
        }
        if (d.address == 0 || d.size == 0) {
            d.status = "zero address or size";
            diag(a_, "pe.directory.partial", d.name + " directory has a zero address or size but not both.", 0);
            continue;
        }
        if (size_of_image_ && !range_within(d.address, d.size, size_of_image_)) {
            d.status = "beyond SizeOfImage";
            diag(a_, "pe.directory.out_of_image", d.name + " directory [" + hex(d.address) + ", +" + hex(d.size) +
                                                       ") extends beyond SizeOfImage.", 0);
            continue;
        }
        if (auto off = rva_offset(d.address, d.size)) {
            d.file_offset = off;
            d.status = "ok";
        } else if (auto start = rva_offset(d.address, 1)) {
            d.file_offset = start;
            d.status = "partly file-backed";
            diag(a_, "pe.directory.partial_backing",
                 d.name + " directory is only partly backed by file data.", *start);
        } else {
            d.status = "not file-backed";
            // Bound import tables live in the headers on old images and the
            // IAT may legitimately be in a zero-filled region only if empty;
            // everything else must be file-backed to be parsed.
            diag(a_, "pe.directory.unmapped", d.name + " directory RVA " + hex(d.address) +
                                                   " does not map to file data.", 0);
        }
    }
}

bool PeParser::read_thunks(const std::string& library, std::uint64_t lookup_rva, std::uint64_t iat_rva, bool delayed) {
    const std::uint64_t width = pe32plus_ ? 8 : 4;
    const std::uint64_t ordinal_flag = pe32plus_ ? (std::uint64_t{1} << 63) : (std::uint64_t{1} << 31);
    for (std::uint32_t n = 0;; ++n) {
        if (n >= kMaxThunksPerLibrary) {
            diag(a_, "pe.import.limit", library + ": more than " + std::to_string(kMaxThunksPerLibrary) +
                                            " imports; the lookup table is probably unterminated.", 0);
            return true;
        }
        auto slot_rva = checked_add(lookup_rva, std::uint64_t{n} * width);
        auto rec = slot_rva ? rva_record(*slot_rva, width) : std::nullopt;
        if (!rec) {
            limited_("pe.import.thunk_unmapped", library + ": import lookup entry " + std::to_string(n) +
                                                    " at RVA " + hex(slot_rva.value_or(0)) + " is not file-backed.", 0);
            return n > 0;
        }
        const std::uint64_t thunk = rec->word(0, pe32plus_);
        if (thunk == 0) return true;
        if (imports_total_ >= o_.limits.max_imports) {
            diag(a_, "pe.import.limit", "Import count reached the configured limit; remaining imports skipped.", 0);
            return true;
        }
        Import imp;
        imp.library = library;
        imp.delayed = delayed;
        imp.thunk_rva = iat_rva + std::uint64_t{n} * width;
        if (thunk & ordinal_flag) {
            imp.ordinal = static_cast<std::uint16_t>(thunk & 0xffff);
            if ((thunk & ~ordinal_flag) > 0xffff)
                limited_("pe.import.ordinal_reserved", library + ": ordinal import uses reserved bits.", 0);
        } else {
            const std::uint64_t hint_rva = thunk & 0x7fffffffu;
            if (pe32plus_ && (thunk & ~std::uint64_t{0x7fffffff}))
                limited_("pe.import.thunk_reserved", library + ": name import uses reserved high bits.", 0);
            auto hint = rva_record(hint_rva, 2);
            auto name = rva_string(hint_rva + 2);
            if (!hint || !name) {
                limited_("pe.import.name_invalid",
                         library + ": hint/name entry at RVA " + hex(hint_rva) + " is not readable.", 0);
                imp.name = "<invalid>";
            } else {
                imp.hint = hint->u16(0);
                imp.name = *name;
            }
        }
        a_.imports.push_back(std::move(imp));
        ++imports_total_;
    }
}

void PeParser::parse_imports(const Directory& d) {
    if (!d.file_offset) return;
    std::uint32_t libraries = 0;
    for (std::uint32_t i = 0;; ++i) {
        if (i >= kMaxImportDescriptors) {
            diag(a_, "pe.import.limit", "More than " + std::to_string(kMaxImportDescriptors) + " import descriptors.", 0);
            break;
        }
        const std::uint64_t rva = d.address + std::uint64_t{i} * 20;
        auto desc = rva_record(rva, 20);
        if (!desc) {
            diag(a_, "pe.import.unterminated", "Import descriptor table is not terminated by a null entry.",
                 *d.file_offset + std::uint64_t{i} * 20);
            break;
        }
        const auto lookup = desc->u32(0), stamp = desc->u32(4), name_rva = desc->u32(12), iat = desc->u32(16);
        if (lookup == 0 && name_rva == 0 && iat == 0) break;
        auto library = rva_string(name_rva);
        if (!library) {
            limited_("pe.import.library_name", "Import descriptor " + std::to_string(i) + " has an unreadable DLL name.",
                     *d.file_offset + std::uint64_t{i} * 20);
            library = "<invalid>";
        }
        ++libraries;
        if (lookup == 0 && stamp != 0)
            limited_("pe.import.bound_without_int",
                     *library + ": bound import with no lookup table; names come from a pre-bound IAT and may be addresses.",
                     0);
        if (!read_thunks(*library, lookup ? lookup : iat, iat, false))
            limited_("pe.import.library_unreadable", *library + ": import lookup table is unreadable.", 0);
    }
    add_property(a_, "Imported libraries", std::to_string(libraries));

    // Imphash, as defined by pefile: "<dll without .dll/.ocx/.sys>.<function>"
    // lowercased, comma-joined, MD5. Regular imports only (not delay-load).
    // Ordinals of oleaut32/ws2_32/wsock32 are named via pefile's tables;
    // other ordinals become "ord<N>".
    std::string joined;
    for (const auto& i : a_.imports) {
        if (i.delayed) continue;
        std::string lib = i.library;
        for (auto& ch : lib) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (const auto dot = lib.rfind('.'); dot != std::string::npos) {
            const auto ext = lib.substr(dot + 1);
            if (ext == "dll" || ext == "ocx" || ext == "sys") lib.resize(dot);
        }
        std::string full = i.library;
        for (auto& ch : full) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        const char* known = i.ordinal ? known_ordinal_name(full, *i.ordinal) : nullptr;
        std::string fn = known ? known : i.ordinal ? "ord" + std::to_string(*i.ordinal) : i.name;
        for (auto& ch : fn) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (!joined.empty()) joined += ',';
        joined += lib + "." + fn;
    }
    if (!joined.empty()) {
        a_.imphash = md5(std::span(reinterpret_cast<const std::uint8_t*>(joined.data()), joined.size()));
        add_property(a_, "Imphash", a_.imphash);
    }
}

void PeParser::parse_delay_imports(const Directory& d) {
    if (!d.file_offset) return;
    for (std::uint32_t i = 0; i < kMaxImportDescriptors; ++i) {
        auto desc = rva_record(d.address + std::uint64_t{i} * 32, 32);
        if (!desc) {
            diag(a_, "pe.delay_import.unterminated", "Delay-load descriptor table is not terminated by a null entry.",
                 *d.file_offset);
            return;
        }
        const auto attributes = desc->u32(0);
        std::uint64_t name = desc->u32(4), iat = desc->u32(12), lookup = desc->u32(16);
        if (name == 0 && iat == 0 && lookup == 0) return;
        if (!(attributes & 1)) {
            // Pre-VC7 delay-load descriptors store VAs instead of RVAs.
            limited_("pe.delay_import.va_format", "Delay-load descriptor uses the legacy VA format; converting with ImageBase.",
                     *d.file_offset);
            const auto base = a_.image_base;
            name = name >= base ? name - base : name;
            iat = iat >= base ? iat - base : iat;
            lookup = lookup >= base ? lookup - base : lookup;
        }
        auto library = rva_string(name);
        if (!library) {
            limited_("pe.import.library_name", "Delay-load descriptor " + std::to_string(i) + " has an unreadable DLL name.",
                     *d.file_offset);
            library = "<invalid>";
        }
        if (!read_thunks(*library, lookup ? lookup : iat, iat, true))
            limited_("pe.import.library_unreadable", *library + ": delay-load name table is unreadable.", 0);
    }
}

void PeParser::parse_exports(const Directory& d) {
    if (!d.file_offset) return;
    auto dir = rva_record(d.address, 40);
    if (!dir) {
        diag(a_, "pe.export.truncated", "Export directory is shorter than 40 bytes.", *d.file_offset);
        return;
    }
    const std::uint32_t base = dir->u32(16), nfunctions = dir->u32(20), nnames = dir->u32(24);
    const std::uint32_t functions = dir->u32(28), names = dir->u32(32), ordinals = dir->u32(36);
    if (auto name = rva_string(dir->u32(12))) add_property(a_, "Export DLL name", *name);
    if (nfunctions > o_.limits.max_exports || nnames > o_.limits.max_exports) {
        diag(a_, "pe.export.limit", "Export table declares " + std::to_string(nfunctions) + " functions and " +
                                        std::to_string(nnames) + " names; exceeds the configured limit.", *d.file_offset);
        return;
    }
    auto fn_table = rva_offset(functions, std::uint64_t{nfunctions} * 4);
    if (nfunctions && !fn_table) {
        diag(a_, "pe.export.table_unmapped", "Export address table is not file-backed.", *d.file_offset);
        return;
    }
    std::vector<std::string> by_index(nfunctions);
    auto name_table = rva_offset(names, std::uint64_t{nnames} * 4);
    auto ord_table = rva_offset(ordinals, std::uint64_t{nnames} * 2);
    if (nnames && (!name_table || !ord_table)) {
        diag(a_, "pe.export.table_unmapped", "Export name or ordinal table is not file-backed; exports listed by ordinal.",
             *d.file_offset);
    } else {
        for (std::uint32_t i = 0; i < nnames; ++i) {
            const auto idx = *v_.u16(*ord_table + std::uint64_t{i} * 2);
            auto name = rva_string(*v_.u32(*name_table + std::uint64_t{i} * 4));
            if (idx >= nfunctions) {
                limited_("pe.export.ordinal_range", "Export name ordinal " + std::to_string(idx) + " is out of range.",
                         *ord_table + std::uint64_t{i} * 2);
                continue;
            }
            if (!name) {
                limited_("pe.export.name_invalid", "Export name " + std::to_string(i) + " is unreadable.",
                         *name_table + std::uint64_t{i} * 4);
                continue;
            }
            if (!by_index[idx].empty()) by_index[idx] += ", ";  // aliases share an address slot
            by_index[idx] += *name;
        }
    }
    for (std::uint32_t i = 0; i < nfunctions; ++i) {
        const std::uint32_t rva = *v_.u32(*fn_table + std::uint64_t{i} * 4);
        if (rva == 0) continue;  // unused ordinal slot
        Export e;
        e.name = by_index[i];
        e.ordinal = base + i;
        e.rva = rva;
        if (subrange_of(d.address, d.size, rva, 1)) {
            // Forwarder: the "address" points at "OTHERDLL.Function" inside the export directory.
            if (auto fwd = rva_string(rva)) e.forwarder = *fwd;
            else limited_("pe.export.forwarder_invalid", "Unreadable forwarder string for ordinal " +
                                                             std::to_string(e.ordinal) + ".", 0);
        }
        a_.exports.push_back(std::move(e));
    }
}

void PeParser::parse_certificates(const Directory& d) {
    if (!d.file_offset) return;
    a_.structures.push_back({"Certificate table", "table", d.address, d.size});
    if (d.address % 8)
        diag(a_, "pe.certificate.misaligned", "Certificate table is not 8-byte aligned.", d.address);
    std::uint64_t at = d.address;
    const std::uint64_t end = d.address + d.size;  // contains() verified no overflow
    while (at < end) {
        if (a_.certificates.size() >= o_.limits.max_certificates) {
            diag(a_, "pe.certificate.limit", "More certificate entries than the configured limit.", at);
            break;
        }
        auto hdr = v_.record(at, 8);
        if (!hdr || end - at < 8) {
            diag(a_, "pe.certificate.truncated", "Certificate entry header is truncated.", at);
            break;
        }
        Certificate c;
        c.offset = at;
        c.length = hdr->u32(0);
        c.revision = hdr->u16(4);
        c.type = hdr->u16(6);
        switch (c.type) {
        case 1: c.type_name = "X.509"; break;
        case 2: c.type_name = "PKCS#7 SignedData (Authenticode)"; break;
        case 3: c.type_name = "reserved"; break;
        case 4: c.type_name = "terminal server protocol stack"; break;
        default: c.type_name = "unknown";
        }
        if (c.length < 8 || c.length > end - at) {
            diag(a_, "pe.certificate.length", "Certificate entry length " + std::to_string(c.length) +
                                                   " is invalid for the remaining table size.", at);
            break;
        }
        if (c.revision != 0x0100 && c.revision != 0x0200)
            diag(a_, "pe.certificate.revision", "Unknown WIN_CERTIFICATE revision " + hex(c.revision) + ".", at + 4);
        a_.certificates.push_back(c);
        auto next = align_up(at + c.length, 8);
        if (!next || *next <= at) break;
        at = *next;
    }
    for (const auto& c : a_.certificates)
        if (c.type == 2 && c.length > 8)
            decode_authenticode(f_, a_, c.offset + 8, c.length - 8, optional_offset_ + 64,
                                optional_offset_ + (pe32plus_ ? 112 : 96) + 4 * 8, d.address);
    if (!a_.certificates.empty())
        diag(a_, "pe.certificate.not_verified",
             "Certificate table parsed for metadata only; Authenticode signatures and chains are not verified.", d.address);
    if (end != f_.size())
        diag(a_, "pe.certificate.not_at_end", "Data follows the certificate table; signed images normally end with it.", end);
}

void PeParser::parse_debug(const Directory& d) {
    if (!d.file_offset) return;
    if (d.size % 28)
        diag(a_, "pe.debug.size", "Debug directory size is not a multiple of 28 bytes.", *d.file_offset);
    const std::uint64_t n = std::min<std::uint64_t>(d.size / 28, 64);
    for (std::uint64_t i = 0; i < n; ++i) {
        auto e = rva_record(d.address + i * 28, 28);
        if (!e) break;
        const auto type = e->u32(12), size = e->u32(16), pointer = e->u32(24);
        std::string type_name = type == 2 ? "CodeView" : type == 1 ? "COFF" : type == 3 ? "FPO" : type == 4 ? "Misc"
                              : type == 5 ? "Exception" : type == 6 ? "Fixup" : type == 9 ? "Borland" : type == 11 ? "CLSID"
                              : type == 12 ? "VC feature" : type == 13 ? "POGO" : type == 14 ? "ILTCG" : type == 15 ? "MPX"
                              : type == 16 ? "Repro" : type == 17 ? "Embedded portable PDB" : type == 19 ? "PDB checksum"
                              : type == 20 ? "Ex DLL characteristics" : "type " + std::to_string(type);
        DebugEntry entry{type, type_name, e->u32(4), size, e->u32(20), pointer, {}};
        if (size && pointer) {
            if (!f_.contains(pointer, size)) {
                limited_("pe.debug.data_out_of_range", "Debug entry (" + type_name + ") data extends beyond the file.", pointer);
                a_.debug_entries.push_back(std::move(entry));
                continue;
            }
            a_.structures.push_back({"Debug data: " + type_name, "debug", pointer, size});
            const auto data = *v_.record(pointer, size);
            if (type == 20 && size >= 4) {
                // IMAGE_DLLCHARACTERISTICS_EX_* (winnt.h)
                const auto ex = data.u32(0);
                entry.detail = join_flags_text(ex, {{0x1, "CET_COMPAT"}, {0x2, "CET_COMPAT_STRICT_MODE"},
                                                    {0x4, "CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE"},
                                                    {0x8, "CET_DYNAMIC_APIS_ALLOW_IN_PROC"}, {0x40, "FORWARD_CFI_COMPAT"},
                                                    {0x80, "HOTPATCH_COMPATIBLE"}});
                add_property(a_, "Ex DllCharacteristics", entry.detail);
                add_property(a_, "CET shadow stack (CET_COMPAT)", (ex & 1) ? "set" : "not set");
            } else if (type == 16) {
                // Repro: optional length-prefixed hash of the build inputs.
                if (size >= 4 && data.u32(0) && data.u32(0) <= size - 4) {
                    entry.detail = hex_bytes(data.bytes().subspan(4, data.u32(0)), 64);
                    add_property(a_, "Reproducible build hash", entry.detail);
                } else {
                    entry.detail = "deterministic build (no hash)";
                }
            } else if (type == 12 && size >= 20) {
                // VC feature counters: pre-VC++11, C/C++, /GS, /sdl, guardN.
                entry.detail = "pre-VC11 " + std::to_string(data.u32(0)) + ", C/C++ " + std::to_string(data.u32(4)) + ", /GS " +
                               std::to_string(data.u32(8)) + ", /sdl " + std::to_string(data.u32(12)) + ", guardN " +
                               std::to_string(data.u32(16));
                add_property(a_, "VC feature counters", entry.detail);
            } else if (type == 13 && size >= 4) {
                // POGO: signature, then {rva, size, name} records aligned to 4.
                const ByteView pv(data.bytes());
                std::uint64_t at = 4, count = 0;
                while (at + 8 < size && count < 100000) {
                    auto name = pv.cstring(at + 8, size - at - 8);
                    if (!name) break;
                    ++count;
                    at = *align_up(at + 8 + name->size() + 1, 4);
                }
                const std::uint32_t sig = data.u32(0);
                std::string tag;
                for (int k = 3; k >= 0; --k) {
                    const char ch = static_cast<char>(sig >> (8 * k));
                    if (ch >= 0x20 && ch < 0x7f) tag += ch;
                }
                entry.detail = "signature '" + tag + "', " + std::to_string(count) + " section contributions";
            }
        }
        if (type == 2 && size >= 24) {
            auto cv = v_.record(pointer, size);
            if (cv && cv->u32(0) == 0x53445352) {  // "RSDS"
                const auto g = cv->bytes().subspan(4, 16);
                add_property(a_, "PDB GUID", hex_bytes(g, 16) + " age " + std::to_string(cv->u32(20)));
                if (auto path = ByteView(cv->bytes()).cstring(24, size - 24)) {
                    add_property(a_, "PDB path", printable(*path));
                    entry.detail = printable(*path);
                } else {
                    limited_("pe.debug.codeview_path", "CodeView PDB path is not NUL-terminated.", pointer + 24u);
                }
            }
        }
        a_.debug_entries.push_back(std::move(entry));
    }
}

void PeParser::parse_base_relocations(const Directory& d) {
    if (!d.file_offset) return;
    std::uint64_t at = 0, blocks = 0, entries = 0;
    while (at + 8 <= d.size) {
        auto blk = rva_record(d.address + at, 8);
        if (!blk) break;
        const std::uint32_t size = blk->u32(4);
        if (size < 8 || size % 2 || size > d.size - at) {
            diag(a_, "pe.reloc.block_size", "Base relocation block size " + std::to_string(size) + " is invalid.",
                 *d.file_offset + at);
            break;
        }
        ++blocks;
        entries += (size - 8) / 2;
        at += size;
    }
    add_property(a_, "Base relocations", std::to_string(blocks) + " blocks, " + std::to_string(entries) + " entries");
}

void PeParser::parse_tls(const Directory& d) {
    if (!d.file_offset) return;
    const std::uint64_t width = pe32plus_ ? 8 : 4;
    auto tls = rva_record(d.address, pe32plus_ ? 40 : 24);
    if (!tls) {
        diag(a_, "pe.tls.truncated", "TLS directory is truncated.", *d.file_offset);
        return;
    }
    const std::uint64_t callbacks_va = tls->word(3 * width, pe32plus_);
    if (callbacks_va == 0) {
        add_property(a_, "TLS callbacks", "0");
        return;
    }
    if (callbacks_va < a_.image_base) {
        diag(a_, "pe.tls.callbacks_unmapped", "TLS callback array address is below ImageBase.", *d.file_offset);
        return;
    }
    std::string list;
    std::uint32_t n = 0;
    for (; n < 256; ++n) {
        auto slot_rva = checked_add(callbacks_va - a_.image_base, std::uint64_t{n} * width);
        auto slot = slot_rva ? rva_record(*slot_rva, width) : std::nullopt;
        if (!slot) {
            // The callback array is frequently relocated data; it may be zero-fill.
            diag(a_, "pe.tls.callbacks_unmapped", "TLS callback array is not file-backed; callbacks cannot be listed.",
                 *d.file_offset);
            break;
        }
        const auto va = slot->word(0, pe32plus_);
        if (va == 0) break;
        if (!list.empty()) list += ", ";
        list += va >= a_.image_base ? hex(va - a_.image_base) : hex(va) + " (below ImageBase)";
    }
    add_property(a_, "TLS callbacks", std::to_string(n) + (list.empty() ? "" : " (RVAs " + list + ")"));
}

void PeParser::compute_checksum() {
    const auto b = f_.bytes();
    const std::uint64_t field = optional_offset_ + 64;
    std::uint64_t sum = 0;
    const std::size_t n = b.size();
    // The 4-byte CheckSum field is treated as zero. e_lfanew may be odd, so
    // the field is excluded byte by byte rather than word by word.
    auto byte_at = [&](std::size_t i) -> std::uint64_t { return (i >= field && i < field + 4) ? 0 : b[i]; };
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        sum += byte_at(i) | (byte_at(i + 1) << 8);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if (n % 2) sum += byte_at(n - 1);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum + (sum >> 16)) & 0xffff;
    const std::uint32_t computed = static_cast<std::uint32_t>(sum + n);
    add_property(a_, "Checksum", hex(checksum_) + " stored, " + hex(computed) + " computed");
    if (checksum_ != 0 && checksum_ != computed)
        diag(a_, "pe.checksum.mismatch", "Stored checksum does not match the computed value (only drivers and some system DLLs require it).",
             field);
}

// Converts UTF-16LE code units to UTF-8; unpaired surrogates become U+FFFD and
// control characters are escaped.
std::string utf16_to_utf8(std::span<const std::uint8_t> b, std::size_t units) {
    std::string out;
    auto unit = [&](std::size_t i) { return static_cast<std::uint32_t>(b[2 * i] | (b[2 * i + 1] << 8)); };
    auto put = [&](std::uint32_t v) { out += static_cast<char>(static_cast<unsigned char>(v)); };
    for (std::size_t i = 0; i < units; ++i) {
        std::uint32_t cp = unit(i);
        if (cp >= 0xd800 && cp < 0xdc00 && i + 1 < units && unit(i + 1) >= 0xdc00 && unit(i + 1) < 0xe000) {
            cp = 0x10000 + ((cp - 0xd800) << 10) + (unit(i + 1) - 0xdc00);
            ++i;
        } else if (cp >= 0xd800 && cp < 0xe000) {
            cp = 0xfffd;
        }
        if (cp < 0x20 || cp == 0x7f) {
            const char c = static_cast<char>(cp);
            out += printable(std::string_view(&c, 1));
        } else if (cp < 0x80) {
            put(cp);
        } else if (cp < 0x800) {
            put(0xc0 | (cp >> 6));
            put(0x80 | (cp & 0x3f));
        } else if (cp < 0x10000) {
            put(0xe0 | (cp >> 12));
            put(0x80 | ((cp >> 6) & 0x3f));
            put(0x80 | (cp & 0x3f));
        } else {
            put(0xf0 | (cp >> 18));
            put(0x80 | ((cp >> 12) & 0x3f));
            put(0x80 | ((cp >> 6) & 0x3f));
            put(0x80 | (cp & 0x3f));
        }
    }
    return out;
}

const char* resource_type_name(std::uint32_t id) {
    switch (id) {
    case 1: return "CURSOR";
    case 2: return "BITMAP";
    case 3: return "ICON";
    case 4: return "MENU";
    case 5: return "DIALOG";
    case 6: return "STRING";
    case 7: return "FONTDIR";
    case 8: return "FONT";
    case 9: return "ACCELERATOR";
    case 10: return "RCDATA";
    case 11: return "MESSAGETABLE";
    case 12: return "GROUP_CURSOR";
    case 14: return "GROUP_ICON";
    case 16: return "VERSION";
    case 17: return "DLGINCLUDE";
    case 19: return "PLUGPLAY";
    case 20: return "VXD";
    case 21: return "ANICURSOR";
    case 22: return "ANIICON";
    case 23: return "HTML";
    case 24: return "MANIFEST";
    default: return nullptr;
    }
}

void PeParser::parse_resources(const Directory& d) {
    if (!d.file_offset) return;
    struct Frame {
        std::uint32_t rel;
        int depth;
        std::array<std::string, 3> path;
    };
    std::vector<Frame> stack{{0, 0, {}}};
    std::vector<std::uint32_t> visited;  // directory tables already walked (loop detection)
    std::uint64_t entries_seen = 0;
    while (!stack.empty()) {
        const Frame f = stack.back();
        stack.pop_back();
        if (std::find(visited.begin(), visited.end(), f.rel) != visited.end()) {
            limited_("pe.resource.loop", "Resource directory at +" + hex(f.rel) + " is referenced more than once (loop).",
                     *d.file_offset + f.rel);
            continue;
        }
        visited.push_back(f.rel);
        if (f.rel >= d.size)
            limited_("pe.resource.outside_directory",
                     "Resource table at +" + hex(f.rel) + " lies outside the directory size.", *d.file_offset);
        auto dir = rva_record(d.address + f.rel, 16);
        if (!dir) {
            limited_("pe.resource.unmapped", "Resource directory table at +" + hex(f.rel) + " is not file-backed.",
                     *d.file_offset);
            continue;
        }
        const std::uint32_t count = std::uint32_t{dir->u16(12)} + dir->u16(14);
        for (std::uint32_t i = 0; i < count; ++i) {
            if (++entries_seen > std::uint64_t{o_.limits.max_resources} * 4 ||
                a_.resources.size() >= o_.limits.max_resources) {
                diag(a_, "pe.resource.limit", "Resource tree exceeds the configured entry limit; remaining entries skipped.",
                     *d.file_offset);
                return;
            }
            auto e = rva_record(d.address + f.rel + 16 + std::uint64_t{i} * 8, 8);
            if (!e) {
                limited_("pe.resource.unmapped", "Resource directory entries run past file-backed data.",
                         *d.file_offset + f.rel);
                break;
            }
            const std::uint32_t name_field = e->u32(0), data_field = e->u32(4);
            std::string component;
            if (name_field & 0x80000000u) {
                const std::uint64_t at = d.address + (name_field & 0x7fffffffu);
                auto len = rva_record(at, 2);
                auto chars = len ? rva_record(at + 2, std::uint64_t{len->u16(0)} * 2) : std::nullopt;
                if (!chars) {
                    limited_("pe.resource.name_invalid", "Resource name string is not file-backed.", *d.file_offset);
                    component = "<invalid>";
                } else {
                    component = utf16_to_utf8(chars->bytes(), len->u16(0));
                }
            } else {
                const std::uint32_t id = name_field & 0xffffu;
                const char* t = f.depth == 0 ? resource_type_name(id) : nullptr;
                component = t ? std::string(t) : f.depth == 2 ? hex(id) : "#" + std::to_string(id);
            }
            Frame child = f;
            if (f.depth < 3) child.path[static_cast<std::size_t>(f.depth)] = component;
            if (data_field & 0x80000000u) {
                if (f.depth >= 7) {
                    limited_("pe.resource.depth", "Resource tree is deeper than 8 levels; subtree skipped.", *d.file_offset);
                    continue;
                }
                child.rel = data_field & 0x7fffffffu;
                child.depth = f.depth + 1;
                stack.push_back(child);
                continue;
            }
            auto leaf = rva_record(d.address + data_field, 16);
            if (!leaf) {
                limited_("pe.resource.unmapped", "Resource data entry is not file-backed.", *d.file_offset);
                continue;
            }
            Resource r;
            r.type = child.path[0];
            r.name = child.path[1];
            r.language = child.path[2];
            r.rva = leaf->u32(0);
            r.size = leaf->u32(4);
            r.codepage = leaf->u32(8);
            r.offset = rva_offset(r.rva, r.size);
            if (!r.offset && r.size)
                limited_("pe.resource.data_unmapped", "Resource " + r.type + "/" + r.name + " data [" + hex(r.rva) + ", +" +
                                                          hex(r.size) + ") is not file-backed.", *d.file_offset);
            a_.resources.push_back(std::move(r));
        }
    }
    // The stack walk visits subtrees in reverse; present them in file order.
    std::stable_sort(a_.resources.begin(), a_.resources.end(),
                     [](const Resource& x, const Resource& y) { return x.rva < y.rva; });
    parse_string_tables();
    std::map<std::string, std::size_t> types;
    for (const auto& r : a_.resources) ++types[r.type];
    std::string summary;
    for (const auto& [t, n] : types) summary += (summary.empty() ? "" : ", ") + t + " x" + std::to_string(n);
    add_property(a_, "Resources", std::to_string(a_.resources.size()) + (summary.empty() ? "" : " (" + summary + ")"));
    for (const auto& r : a_.resources) {
        if (!r.offset) continue;
        if (r.type == "VERSION" && !a_.property("File version")) parse_version_info(*r.offset, r.size);
        if (r.type == "MANIFEST" && !a_.property("Manifest execution level")) parse_manifest(*r.offset, r.size);
    }
}

// VS_VERSIONINFO: nested {wLength, wValueLength, wType, szKey, pad, Value, pad, Children} blocks.
void PeParser::parse_version_info(std::uint64_t offset, std::uint64_t size) {
    auto res = v_.slice(offset, size);
    if (!res) return;
    const ByteView rv(*res, Endian::Little);
    struct Block {
        std::uint64_t end{}, value{}, value_bytes{}, children{};
        std::uint16_t type{};
        std::string key;
    };
    auto read_block = [&](std::uint64_t at, std::uint64_t limit) -> std::optional<Block> {
        auto h = rv.record(at, 6);
        if (!h) return std::nullopt;
        Block b;
        const std::uint16_t len = h->u16(0), vlen = h->u16(2);
        b.type = h->u16(4);
        if (len < 6 || at + len > limit) return std::nullopt;
        b.end = at + len;
        std::uint64_t k = at + 6;
        std::size_t units = 0;
        while (k + 2 <= b.end && *rv.u16(k) != 0) {
            k += 2;
            ++units;
        }
        if (k + 2 > b.end) return std::nullopt;
        b.key = utf16_to_utf8(*rv.slice(at + 6, units * 2), units);
        b.value = *align_up(k + 2, 4);
        b.value_bytes = b.type == 1 ? std::uint64_t{vlen} * 2 : vlen;
        if (b.value > b.end) b.value = b.end;
        b.value_bytes = std::min(b.value_bytes, b.end - b.value);
        b.children = *align_up(b.value + b.value_bytes, 4);
        return b;
    };
    auto root = read_block(0, size);
    if (!root || root->key != "VS_VERSION_INFO") {
        diag(a_, "pe.version.malformed", "VERSION resource does not start with a valid VS_VERSION_INFO block.", offset);
        return;
    }
    auto ffi = rv.record(root->value, 52);
    if (ffi && root->value_bytes >= 52 && ffi->u32(0) == 0xfeef04bd) {
        auto ver = [&](std::size_t at) {
            const auto ms = ffi->u32(at), ls = ffi->u32(at + 4);
            return std::to_string(ms >> 16) + "." + std::to_string(ms & 0xffff) + "." + std::to_string(ls >> 16) + "." +
                   std::to_string(ls & 0xffff);
        };
        add_property(a_, "File version", ver(8));
        add_property(a_, "Product version", ver(16));
    } else {
        diag(a_, "pe.version.malformed", "VS_FIXEDFILEINFO is missing or has a bad signature.", offset + root->value);
    }
    // StringFileInfo -> StringTable(s) -> String entries.
    int strings = 0;
    for (std::uint64_t at = root->children; at + 6 <= root->end;) {
        auto sfi = read_block(at, root->end);
        if (!sfi) break;
        if (sfi->key == "StringFileInfo") {
            for (std::uint64_t t = sfi->children; t + 6 <= sfi->end;) {
                auto table = read_block(t, sfi->end);
                if (!table) break;
                for (std::uint64_t e = table->children; e + 6 <= table->end && strings < 32;) {
                    auto entry = read_block(e, table->end);
                    if (!entry) break;
                    std::size_t units = 0;
                    while (2 * (units + 1) <= entry->value_bytes && *rv.u16(entry->value + 2 * units) != 0) ++units;
                    const auto value = utf16_to_utf8(*rv.slice(entry->value, units * 2), units);
                    if (!entry->key.empty() && !value.empty()) {
                        add_property(a_, "Version: " + entry->key, value);
                        ++strings;
                    }
                    e = *align_up(entry->end, 4);
                }
                t = *align_up(table->end, 4);
            }
        }
        at = *align_up(sfi->end, 4);
    }
}

void PeParser::parse_manifest(std::uint64_t offset, std::uint64_t size) {
    auto m = v_.slice(offset, std::min<std::uint64_t>(size, 1 << 20));
    if (!m) return;
    const std::string_view text(reinterpret_cast<const char*>(m->data()), m->size());
    const auto at = text.find("requestedExecutionLevel");
    if (at == std::string_view::npos) {
        add_property(a_, "Manifest execution level", "not specified");
        return;
    }
    const auto end = text.find('>', at);
    const auto element = text.substr(at, end == std::string_view::npos ? 256 : end - at);
    auto attribute = [&](std::string_view name) -> std::string {
        const auto p = element.find(name);
        if (p == std::string_view::npos) return {};
        const auto q = element.find_first_of("\"'", p + name.size());
        if (q == std::string_view::npos) return {};
        const auto r = element.find(element[q], q + 1);
        return r == std::string_view::npos ? std::string{} : printable(element.substr(q + 1, r - q - 1));
    };
    const auto level = attribute("level=");
    const auto ui = attribute("uiAccess=");
    add_property(a_, "Manifest execution level", (level.empty() ? "unparsed" : level) + (ui.empty() ? "" : ", uiAccess=" + ui));
}

void PeParser::parse_load_config(const Directory& d) {
    if (!d.file_offset) return;
    auto head = rva_record(d.address, 4);
    if (!head) {
        diag(a_, "pe.load_config.truncated", "Load configuration directory is not file-backed.", *d.file_offset);
        return;
    }
    const std::uint32_t declared = head->u32(0);
    // Read as much of the declared structure as is file-backed (bounded).
    std::uint64_t n = std::min<std::uint64_t>(declared, 0x400) & ~std::uint64_t{3};
    std::optional<Record> lc;
    while (n >= 4 && !(lc = rva_record(d.address, n))) n -= 4;
    if (!lc) return;
    if (n < declared && declared <= 0x400)
        diag(a_, "pe.load_config.truncated", "Load configuration declares " + std::to_string(declared) + " bytes but only " +
                                                 std::to_string(n) + " are file-backed.", *d.file_offset);
    const std::size_t w = pe32plus_ ? 8 : 4;
    auto has = [&](std::size_t at, std::size_t width) { return at + width <= lc->size(); };
    add_property(a_, "Load config size", std::to_string(declared) + " bytes");
    const std::size_t cookie = pe32plus_ ? 88 : 60;
    if (has(cookie, w)) {
        const auto va = lc->word(cookie, pe32plus_);
        add_property(a_, "Security cookie (/GS)", va ? hex(va) : "none");
    }
    if (!pe32plus_ && has(68, 4)) add_property(a_, "SafeSEH handlers", lc->u32(64) ? std::to_string(lc->u32(68)) : "no table");
    const std::size_t cf_table = pe32plus_ ? 128 : 80, cf_count = pe32plus_ ? 136 : 84, flags = pe32plus_ ? 144 : 88;
    if (has(flags, 4)) {
        const std::uint32_t gf = lc->u32(flags);
        add_property(a_, "Guard flags",
                     join_flags_text(gf, {{0x100, "CF_INSTRUMENTED"}, {0x200, "CFW_INSTRUMENTED"},
                                          {0x400, "CF_FUNCTION_TABLE_PRESENT"}, {0x800, "SECURITY_COOKIE_UNUSED"},
                                          {0x1000, "PROTECT_DELAYLOAD_IAT"}, {0x2000, "DELAYLOAD_IAT_IN_ITS_OWN_SECTION"},
                                          {0x4000, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"},
                                          {0x8000, "CF_ENABLE_EXPORT_SUPPRESSION"}, {0x10000, "CF_LONGJUMP_TABLE_PRESENT"},
                                          {0x400000, "EH_CONTINUATION_TABLE_PRESENT"}}));
        if (has(cf_count, w) && lc->word(cf_table, pe32plus_))
            add_property(a_, "CFG function table", std::to_string(lc->word(cf_count, pe32plus_)) + " entries");
    }
}

// The undocumented MSVC linker "Rich" header between the DOS stub and the PE
// header: XOR-masked (comp.id, count) pairs framed by "DanS" ... "Rich" key.
void PeParser::parse_rich(std::uint32_t lfanew) {
    constexpr std::uint32_t kRich = 0x68636952, kDanS = 0x536e6144;
    for (std::uint64_t r = 0x40; r + 8 <= lfanew && f_.contains(r, 8); r += 4) {
        if (*v_.u32(r) != kRich) continue;
        const std::uint32_t key = *v_.u32(r + 4);
        std::optional<std::uint64_t> dans;
        for (std::uint64_t p = r; p >= 0x44 && r - p < 0x1000;) {
            p -= 4;
            if ((*v_.u32(p) ^ key) == kDanS) {
                dans = p;
                break;
            }
        }
        if (!dans || r - *dans < 16 || (r - *dans - 16) % 8) {
            diag(a_, "pe.rich.malformed", "'Rich' marker found but no matching 'DanS' start.", r);
            return;
        }
        auto rol = [](std::uint32_t v, std::uint32_t n) {
            n %= 32;
            return n ? (v << n) | (v >> (32 - n)) : v;
        };
        // Checksum: the DanS offset, every header byte before it (except
        // e_lfanew) rotated by its index, and each comp.id rotated by its count.
        std::uint32_t sum = static_cast<std::uint32_t>(*dans);
        for (std::uint64_t i = 0; i < *dans; ++i)
            if (i < 0x3c || i >= 0x40)
                sum += rol(f_.bytes()[static_cast<std::size_t>(i)], static_cast<std::uint32_t>(i));
        for (std::uint64_t e = *dans + 16; e + 8 <= r; e += 8) {
            const std::uint32_t comp = *v_.u32(e) ^ key, count = *v_.u32(e + 4) ^ key;
            a_.rich.push_back({static_cast<std::uint16_t>(comp >> 16), static_cast<std::uint16_t>(comp & 0xffff), count});
            sum += rol(comp, count);
        }
        a_.structures.push_back({"Rich header", "header", *dans, r + 8 - *dans});
        add_property(a_, "Rich header",
                     std::to_string(a_.rich.size()) + " tool entries, checksum " + (sum == key ? "valid" : "INVALID"));
        if (sum != key)
            diag(a_, "pe.rich.checksum", "Rich header checksum does not match its key; the header may have been edited.", r + 4);
        return;
    }
}

// x64 .pdata: RUNTIME_FUNCTION {BeginAddress, EndAddress, UnwindInfoAddress}.
// Other architectures use different layouts (ARM64 packs unwind data into 8
// bytes); those are only range-validated.
void PeParser::parse_exceptions(const Directory& d) {
    if (!d.file_offset || a_.architecture != "x86-64") return;
    if (d.size % 12)
        diag(a_, "pe.exception.size", "Exception directory size is not a multiple of 12 bytes.", *d.file_offset);
    const std::uint64_t n = d.size / 12;
    std::uint32_t previous_end = 0;
    for (std::uint64_t i = 0; i < n; ++i) {
        if (a_.functions.size() >= o_.limits.max_functions) {
            diag(a_, "pe.exception.limit", "Exception table exceeds the configured function limit.", *d.file_offset);
            break;
        }
        auto e = rva_record(d.address + i * 12, 12);
        if (!e) {
            diag(a_, "pe.exception.unmapped", "Exception table entries run past file-backed data.", *d.file_offset + i * 12);
            break;
        }
        FunctionRange f{e->u32(0), e->u32(4), e->u32(8)};
        if (f.begin == 0 && f.end == 0 && f.unwind == 0) continue;  // zero padding
        if (f.begin >= f.end || (size_of_image_ && f.end > size_of_image_))
            limited_("pe.exception.range", "RUNTIME_FUNCTION " + std::to_string(i) + " has an invalid range [" + hex(f.begin) +
                                               ", " + hex(f.end) + ").", *d.file_offset + i * 12);
        else if (f.begin < previous_end)
            limited_("pe.exception.order", "RUNTIME_FUNCTION entries are not sorted or overlap (required for binary search).",
                     *d.file_offset + i * 12);
        previous_end = std::max(previous_end, f.end);
        // UNWIND_INFO: version:3|flags:5, prolog size, code count, frame
        // register:4|offset:4, then UNWIND_CODE[count rounded up to even],
        // then a handler RVA or a chained RUNTIME_FUNCTION.
        if (auto u = rva_record(f.unwind, 4)) {
            f.unwind_decoded = true;
            f.unwind_version = u->u8(0) & 7;
            f.unwind_flags = static_cast<std::uint8_t>(u->u8(0) >> 3);
            f.prolog_size = u->u8(1);
            f.code_count = u->u8(2);
            f.frame_register = u->u8(3) & 15;
            f.frame_offset = static_cast<std::uint8_t>(u->u8(3) >> 4);
            if (f.unwind_version != 1 && f.unwind_version != 2)
                limited_("pe.unwind.version", "UNWIND_INFO at RVA " + hex(f.unwind) + " has version " +
                                                  std::to_string(f.unwind_version) + " (expected 1 or 2).", *d.file_offset + i * 12);
            const std::uint64_t tail = f.unwind + 4 + 2 * ((std::uint64_t{f.code_count} + 1) & ~std::uint64_t{1});
            if (f.unwind_flags & 4) {  // UNW_FLAG_CHAININFO
                if (auto c = rva_record(tail, 12)) f.chained_begin = c->u32(0);
                else limited_("pe.unwind.unmapped", "Chained RUNTIME_FUNCTION of UNWIND_INFO " + hex(f.unwind) + " is not file-backed.", 0);
            } else if (f.unwind_flags & 3) {  // UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER
                if (auto h = rva_record(tail, 4)) f.handler = h->u32(0);
                else limited_("pe.unwind.unmapped", "Handler of UNWIND_INFO " + hex(f.unwind) + " is not file-backed.", 0);
            }
        } else {
            limited_("pe.unwind.unmapped", "UNWIND_INFO at RVA " + hex(f.unwind) + " is not file-backed.", *d.file_offset + i * 12);
        }
        a_.functions.push_back(f);
    }
    std::size_t handlers = 0, chained = 0;
    for (const auto& fn : a_.functions) {
        handlers += fn.handler != 0;
        chained += fn.chained_begin != 0;
    }
    add_property(a_, "Exception functions", std::to_string(a_.functions.size()) + " (x64 .pdata; " + std::to_string(handlers) +
                                                " with handlers, " + std::to_string(chained) + " chained)");
}

// RT_STRING: resource #N holds strings (N-1)*16 .. (N-1)*16+15, each a
// length-prefixed UTF-16 string; empty slots have length 0.
void PeParser::parse_string_tables() {
    for (const auto& r : a_.resources) {
        if (r.type != "STRING" || !r.offset || r.name.size() < 2 || r.name[0] != '#') continue;
        const std::uint32_t block = static_cast<std::uint32_t>(std::stoul(r.name.substr(1)));
        if (block == 0 || block > 4096) {
            limited_("pe.string_table.block", "RT_STRING block id " + r.name + " is outside 1..4096.", *r.offset);
            continue;
        }
        std::uint64_t at = *r.offset;
        const std::uint64_t end = *r.offset + r.size;
        for (std::uint32_t k = 0; k < 16; ++k) {
            auto len = at + 2 <= end ? v_.u16(at) : std::nullopt;
            if (!len) {
                limited_("pe.string_table.truncated", "RT_STRING block " + r.name + " ends before its 16 entries.", at);
                break;
            }
            at += 2;
            if (*len == 0) continue;
            if (std::uint64_t{*len} * 2 > end - at) {
                limited_("pe.string_table.truncated", "RT_STRING entry exceeds its block.", at);
                break;
            }
            if (a_.resource_strings.size() >= o_.limits.max_resource_strings) {
                diag(a_, "pe.string_table.limit", "String table count reached the configured limit.", at);
                return;
            }
            a_.resource_strings.push_back({(block - 1) * 16 + k, r.language, utf16_to_utf8(*v_.slice(at, std::uint64_t{*len} * 2), *len)});
            at += std::uint64_t{*len} * 2;
        }
    }
    if (!a_.resource_strings.empty())
        add_property(a_, "Resource strings", std::to_string(a_.resource_strings.size()));
}

void PeParser::find_overlay() {
    std::uint64_t end = std::min<std::uint64_t>(size_of_headers_, f_.size());
    for (const auto& s : a_.sections)
        if (s.size && s.offset < f_.size()) end = std::max(end, std::min<std::uint64_t>(s.offset + s.size, f_.size()));
    std::uint64_t overlay_end = f_.size();
    for (const auto& d : a_.directories)
        if (d.index == kDirSecurity && d.file_offset && *d.file_offset >= end && *d.file_offset + d.size == f_.size())
            overlay_end = *d.file_offset;
    if (overlay_end > end) {
        a_.structures.push_back({"Overlay", "overlay", end, overlay_end - end});
        add_property(a_, "Overlay", hex(overlay_end - end) + " bytes at " + hex(end));
        diag(a_, "pe.overlay", "Data after the last section is not mapped by the loader (overlay).", end);
    }
}

} // namespace

void parse_pe(const FileImage& f, Analysis& a, const AnalyzeOptions& o) { PeParser(f, a, o).run(); }

} // namespace bw::detail
