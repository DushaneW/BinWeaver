#include "internal.hpp"

#include <algorithm>

namespace bw {
namespace {
std::string utf8_path(const std::filesystem::path& p) {
    const auto u8 = p.u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
}
} // namespace

Analysis analyze(const std::filesystem::path& p, const AnalyzeOptions& options) {
    std::string e;
    auto f = FileImage::open(p, e);
    if (!f) {
        Analysis a;
        a.path = utf8_path(p);
        detail::diag(a, "file.open", e, 0);
        return a;
    }
    return analyze(*f, options);
}

Analysis analyze(const FileImage& f, const AnalyzeOptions& options) {
    Analysis a;
    a.path = utf8_path(f.path());
    a.file_size = f.size();
    a.sha256 = sha256(f.bytes());
    const auto b = f.bytes();
    if (b.size() >= 2 && b[0] == 'M' && b[1] == 'Z') {
        a.format = Format::PE;
        detail::parse_pe(f, a, options);
    } else if (b.size() >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
        a.format = Format::ELF;
        detail::parse_elf(f, a, options);
    }
    if (a.format != Format::Unknown) {
        if (options.heuristics) detail::run_heuristics(f, a);
    } else {
        detail::diag(a, "format.unknown", "Unrecognized PE/ELF signature.", 0);
    }
    return a;
}

MappedOffset address_to_offset(const Analysis& a, std::uint64_t address) {
    // Later mappings win for PE (sections override the header mapping), so
    // search in reverse insertion order.
    for (auto it = a.mappings.rbegin(); it != a.mappings.rend(); ++it) {
        const auto& m = *it;
        if (!subrange_of(m.address, m.memory_size, address, 1)) continue;
        const auto delta = address - m.address;
        if (delta >= m.file_size) return {MapStatus::ZeroFill, 0, m.name};
        auto off = checked_add(m.offset, delta);
        if (!off || *off >= a.file_size) return {MapStatus::ZeroFill, 0, m.name};
        return {MapStatus::FileBacked, *off, m.name};
    }
    return {};
}

std::vector<std::uint64_t> offset_to_addresses(const Analysis& a, std::uint64_t offset) {
    std::vector<std::uint64_t> out;
    for (const auto& m : a.mappings) {
        if (!subrange_of(m.offset, m.file_size, offset, 1)) continue;
        auto addr = checked_add(m.address, offset - m.offset);
        if (addr && std::find(out.begin(), out.end(), *addr) == out.end()) out.push_back(*addr);
    }
    return out;
}

std::vector<Region> locate(const Analysis& a, std::uint64_t offset) {
    std::vector<Region> out;
    auto consider = [&](const std::string& name, const std::string& kind, std::uint64_t off, std::uint64_t size) {
        if (size && subrange_of(off, size, offset, 1)) out.push_back({name, kind, off, size});
    };
    for (const auto& r : a.structures) consider(r.name, r.kind, r.offset, r.size);
    for (const auto& s : a.sections) consider(s.name, "section", s.offset, s.size);
    for (const auto& s : a.segments) consider(s.name, "segment", s.offset, s.size);
    for (const auto& d : a.directories)
        if (d.file_offset) consider(d.name, "directory", *d.file_offset, d.size);
    std::stable_sort(out.begin(), out.end(), [](const Region& x, const Region& y) { return x.size < y.size; });
    return out;
}

} // namespace bw
