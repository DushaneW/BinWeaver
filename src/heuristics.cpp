// Analyst heuristics: structural traits that are common in packed,
// self-modifying or tampered binaries. Each one is an observation with a
// stated reason, never a verdict; plenty of legitimate software triggers them
// (installers append archives, JIT runtimes map W+X memory, ...). They use
// the "heur." code prefix so they can be filtered as a group.
#include "internal.hpp"

#include <algorithm>
#include <array>

namespace bw::detail {
namespace {

constexpr double kHighEntropy = 7.2;  // bits/byte; compressed or encrypted data is typically > 7.5
constexpr std::uint64_t kMinEntropySample = 1024;

struct PackerName {
    const char* section;
    const char* tool;
};
// Section names emitted by common packers/protectors (exact match).
constexpr std::array<PackerName, 16> kPackerSections = {{{"UPX0", "UPX"}, {"UPX1", "UPX"}, {"UPX2", "UPX"},
                                                         {".aspack", "ASPack"}, {".adata", "ASPack"},
                                                         {".MPRESS1", "MPRESS"}, {".MPRESS2", "MPRESS"},
                                                         {".petite", "Petite"}, {".nsp0", "NsPack"}, {".nsp1", "NsPack"},
                                                         {".themida", "Themida"}, {".winlice", "WinLicense"},
                                                         {".vmp0", "VMProtect"}, {".vmp1", "VMProtect"},
                                                         {".enigma1", "Enigma Protector"}, {"PEC2", "PECompact"}}};

void pe_heuristics(const FileImage& f, Analysis& a) {
    constexpr std::uint64_t kExec = 0x20000000, kWrite = 0x80000000;
    for (const auto& s : a.sections) {
        const bool exec = s.flags & kExec, write = s.flags & kWrite;
        if (exec && write)
            diag(a, "heur.section.writable_executable",
                 "Section '" + s.name + "' is both writable and executable (self-modifying or unpacking code).", s.offset);
        if (exec && s.size == 0 && s.virtual_size > 0)
            diag(a, "heur.section.virtual_only_code",
                 "Executable section '" + s.name + "' has no file data but " + hex(s.virtual_size) +
                     " bytes in memory (typical target of an unpacking stub).", s.offset);
        if (exec && s.entropy && *s.entropy > kHighEntropy && s.size >= kMinEntropySample)
            diag(a, "heur.section.high_entropy_code",
                 "Executable section '" + s.name + "' has entropy " + std::to_string(*s.entropy).substr(0, 4) +
                     " bits/byte (compressed or encrypted code).", s.offset);
        for (const auto& p : kPackerSections)
            if (s.name == p.section)
                diag(a, "heur.section.packer_name",
                     "Section name '" + s.name + "' is commonly produced by " + p.tool + ".", s.offset);
    }
    // Entry point inside a writable section.
    for (const auto& s : a.sections) {
        const std::uint64_t mem = s.virtual_size ? s.virtual_size : s.size;
        if (a.entry_point && (s.flags & kWrite) && subrange_of(s.address, mem, a.entry_point, 1))
            diag(a, "heur.entry.writable_section",
                 "Entry point lies in writable section '" + s.name + "'.", s.offset);
    }
    // Few imports, including dynamic resolution: imports are probably resolved at run time.
    std::size_t regular = 0;
    bool resolver = false;
    for (const auto& i : a.imports) {
        if (i.delayed) continue;
        ++regular;
        resolver = resolver || i.name == "GetProcAddress" || i.name == "LdrGetProcedureAddress";
    }
    if (a.file_type != "DLL" && regular > 0 && regular <= 5 && resolver)
        diag(a, "heur.imports.dynamic_resolution",
             std::to_string(regular) + " imports including GetProcAddress: the real imports are probably resolved at run time.");
    // High-entropy overlay (the certificate table is excluded by the PE parser).
    for (const auto& r : a.structures)
        if (r.kind == "overlay" && r.size >= 4096 && f.contains(r.offset, r.size)) {
            const double e = entropy(f.bytes().subspan(static_cast<std::size_t>(r.offset), static_cast<std::size_t>(r.size)));
            if (e > 7.5)
                diag(a, "heur.overlay.high_entropy",
                     "Overlay of " + hex(r.size) + " bytes has entropy " + std::to_string(e).substr(0, 4) +
                         " (appended compressed or encrypted data, e.g. an installer payload).", r.offset);
        }
    if (const auto* tls = a.property("TLS callbacks"); tls && *tls != "0")
        diag(a, "heur.tls.callbacks", "TLS callbacks run before the entry point: " + *tls + ".");
}

void elf_heuristics(Analysis& a) {
    for (const auto& s : a.segments)
        if (s.kind == "PT_LOAD" && (s.flags & 1) && (s.flags & 2))
            diag(a, "heur.segment.writable_executable", s.name + " is mapped writable and executable.", s.offset);
    for (const auto& s : a.sections)
        if ((s.flags & 4) && s.entropy && *s.entropy > kHighEntropy && s.size >= kMinEntropySample)
            diag(a, "heur.section.high_entropy_code",
                 "Executable section '" + s.name + "' has entropy " + std::to_string(*s.entropy).substr(0, 4) +
                     " bits/byte (compressed or encrypted code).", s.offset);
    if (const auto* stack = a.property("Stack"); stack && stack->rfind("executable", 0) == 0)
        diag(a, "heur.stack.executable", "PT_GNU_STACK requests an executable stack.");
    if ((a.file_type == "Executable" || a.file_type.find("PIE") != std::string::npos) && a.sections.empty() &&
        !a.segments.empty())
        diag(a, "heur.elf.no_section_headers",
             "Executable without section headers (stripped with sstrip-like tools or packed).");
    for (const auto& s : a.sections)
        if (s.name == "UPX!" || s.name.rfind(".upx", 0) == 0)
            diag(a, "heur.section.packer_name", "Section name '" + s.name + "' is commonly produced by UPX.", s.offset);
}

} // namespace

void run_heuristics(const FileImage& f, Analysis& a) {
    if (a.format == Format::PE) pe_heuristics(f, a);
    else if (a.format == Format::ELF) elf_heuristics(a);
}

} // namespace bw::detail
