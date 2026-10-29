// Prints the libraries a PE or ELF file depends on, with the number of
// symbols imported from each (PE) or the DT_NEEDED order (ELF):
//   binweaver-deps app.exe
#include "binweaver/binweaver.hpp"

#include <cstdio>
#include <map>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }
    const auto a = bw::analyze(argv[1]);
    if (a.format == bw::Format::PE) {
        std::map<std::string, std::pair<std::size_t, bool>> libs;  // name -> (count, delay-loaded)
        for (const auto& i : a.imports) {
            auto& entry = libs[i.library];
            ++entry.first;
            entry.second = entry.second || i.delayed;
        }
        for (const auto& [name, info] : libs)
            std::printf("%-40s %5zu import(s)%s\n", name.c_str(), info.first, info.second ? "  [delay-load]" : "");
    } else if (a.format == bw::Format::ELF) {
        for (const auto& d : a.dynamic)
            if (d.tag == 1) std::printf("%s\n", d.text.c_str());
        if (const auto* runpath = a.property("RUNPATH")) std::printf("RUNPATH: %s\n", runpath->c_str());
    }
    for (const auto& d : a.diagnostics)
        if (d.severity == bw::Severity::Error) std::fprintf(stderr, "error [%s] %s\n", d.code.c_str(), d.message.c_str());
    return a.has_errors() ? 1 : 0;
}
