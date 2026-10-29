// libFuzzer entry point. Exercises analysis, both report renderers, address
// translation, region lookup and the structural diff (input vs. a copy with
// its second half reversed).
#include "binweaver/binweaver.hpp"

#include <algorithm>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace bw;
    std::vector<std::uint8_t> bytes(data, data + size);
    const auto f = FileImage::from_bytes(bytes, "fuzz");
    const auto a = analyze(f);
    (void)json_report(a);
    (void)text_report(a);
    for (const auto& d : a.diagnostics)
        if (!find_diagnostic(d.code)) std::abort();  // every emitted code must be catalogued
    for (const auto& m : a.mappings) {
        const auto r = address_to_offset(a, m.address);
        if (r.status == MapStatus::FileBacked && r.offset >= a.file_size) std::abort();
    }
    if (size) {
        (void)locate(a, size / 2);
        (void)offset_to_addresses(a, size / 2);
    }
    std::reverse(bytes.begin() + static_cast<std::ptrdiff_t>(size / 2), bytes.end());
    const auto g = FileImage::from_bytes(std::move(bytes), "fuzz-b");
    const auto d = diff_structure(a, f, analyze(g), g);
    (void)json_report(d);
    return 0;
}
