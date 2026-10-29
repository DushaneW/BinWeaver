// Reports common exploit-mitigation flags for PE and ELF files and exits
// non-zero when a required one is missing; usable as a CI gate:
//   binweaver-hardening-check build/app.exe build/libfoo.so
// Only header-level flags are checked. A set flag says the loader is asked
// to apply the mitigation; it does not prove the code is free of bypasses.
#include "binweaver/binweaver.hpp"

#include <cstdio>

namespace {
bool report(const char* name, bool ok, const char* detail) {
    std::printf("  %-28s %-4s %s\n", name, ok ? "ok" : "MISS", detail);
    return ok;
}
bool property_is(const bw::Analysis& a, const char* key, std::string_view prefix) {
    const auto* v = a.property(key);
    return v && v->compare(0, prefix.size(), prefix) == 0;
}
} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <file>...\n", argv[0]);
        return 2;
    }
    int failures = 0;
    for (int i = 1; i < argc; ++i) {
        const auto a = bw::analyze(argv[i]);
        std::printf("%s (%s, %s)\n", argv[i], bw::format_name(a.format), a.file_type.c_str());
        if (a.has_errors()) {
            std::printf("  structural errors; flags below may be unreliable\n");
            ++failures;
        }
        bool ok = true;
        if (a.format == bw::Format::PE) {
            ok &= report("ASLR (DYNAMIC_BASE)", property_is(a, "ASLR (DYNAMIC_BASE)", "set"), "");
            ok &= report("DEP (NX_COMPAT)", property_is(a, "DEP (NX_COMPAT)", "set"), "");
            const auto* chars = a.property("DllCharacteristics");
            const bool cfg = chars && chars->find("GUARD_CF") != std::string::npos;
            report("Control Flow Guard", cfg, "(informational)");
            report("CET shadow stack", property_is(a, "CET shadow stack (CET_COMPAT)", "set"), "(informational)");
            if (a.bitness == "64-bit")
                ok &= report("High-entropy ASLR", chars && chars->find("HIGH_ENTROPY_VA") != std::string::npos, "");
        } else if (a.format == bw::Format::ELF) {
            const bool pie = a.file_type.find("PIE") != std::string::npos || a.file_type == "Shared object";
            ok &= report("PIE / position independent", pie, a.file_type.c_str());
            ok &= report("Non-executable stack", property_is(a, "Stack", "non-executable"), "(PT_GNU_STACK)");
            ok &= report("RELRO", a.property("RELRO") != nullptr, "(PT_GNU_RELRO)");
            report("BIND_NOW (full RELRO)", a.property("BIND_NOW") != nullptr, "(informational)");
        } else {
            std::printf("  not a PE or ELF file\n");
            ok = false;
        }
        failures += ok ? 0 : 1;
    }
    return failures ? 1 : 0;
}
