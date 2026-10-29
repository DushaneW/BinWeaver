// Checks against real toolchain output: the test binary itself, plus system
// libraries when present. These complement the synthetic fixtures with
// binaries produced by production linkers.
#include "binweaver/binweaver.hpp"
#include "check.hpp"

#include <algorithm>
#include <filesystem>

using namespace bw;

std::filesystem::path g_self;  // set by main

namespace {
bool has_error(const Analysis& a) { return a.has_errors(); }
void print_errors(const Analysis& a) {
    for (const auto& d : a.diagnostics)
        if (d.severity == Severity::Error) std::cerr << "  " << a.path << ": " << d.code << " " << d.message << '\n';
}
} // namespace

TEST_CASE("real.self") {
    REQUIRE(!g_self.empty());
    const auto a = analyze(g_self);
    print_errors(a);
    CHECK(!has_error(a));
#ifdef _WIN32
    CHECK(a.format == Format::PE);
    CHECK(!a.imports.empty());
    CHECK(std::any_of(a.sections.begin(), a.sections.end(), [](const Section& s) { return s.name == ".text"; }));
    // Every import's IAT slot must translate to a file offset.
    for (const auto& i : a.imports) CHECK(address_to_offset(a, i.thunk_rva).status == MapStatus::FileBacked);
#else
    CHECK(a.format == Format::ELF);
    CHECK(!a.segments.empty());
    CHECK(!a.sections.empty());
#endif
}

TEST_CASE("real.system_libraries") {
    std::size_t checked = 0;
#ifdef _WIN32
    const std::filesystem::path sys = "C:\\Windows\\System32";
    for (const char* name : {"kernel32.dll", "ntdll.dll", "user32.dll", "notepad.exe"}) {
        const auto p = sys / name;
        if (!std::filesystem::exists(p)) continue;
        const auto a = analyze(p);
        print_errors(a);
        CHECK(!has_error(a));
        CHECK(a.format == Format::PE);
        // Microsoft-linked binaries carry a Rich header whose checksum must verify,
        // plus VERSIONINFO and load configuration with CFG enabled.
        CHECK(a.property("Rich header") && a.property("Rich header")->find("checksum valid") != std::string::npos);
        CHECK(a.property("Version: CompanyName") && *a.property("Version: CompanyName") == "Microsoft Corporation");
        CHECK(a.property("Guard flags") && a.property("Guard flags")->find("CF_INSTRUMENTED") != std::string::npos);
        if (std::string(name) == "kernel32.dll") {
            CHECK(a.exports.size() > 500);
            // kernel32 forwards many exports to NTDLL / api-ms-win-* sets.
            CHECK(std::any_of(a.exports.begin(), a.exports.end(), [](const Export& e) { return !e.forwarder.empty(); }));
        }
        ++checked;
    }
    if (const std::filesystem::path wow = "C:\\Windows\\SysWOW64\\kernel32.dll"; std::filesystem::exists(wow)) {
        const auto a = analyze(wow);  // PE32: SafeSEH table
        CHECK(!has_error(a));
        CHECK(a.bitness == "32-bit");
        CHECK(a.property("SafeSEH handlers") != nullptr);
        ++checked;
    }
    // .NET Framework assembly: metadata, references and the well-known
    // Microsoft public key token computed from the full key.
    if (const std::filesystem::path sysdll = "C:/Windows/Microsoft.NET/Framework64/v4.0.30319/System.dll";
        std::filesystem::exists(sysdll)) {
        const auto a = analyze(sysdll);
        REQUIRE(a.dotnet.has_value());
        CHECK_EQ(a.dotnet->assembly_name, std::string("System"));
        CHECK_EQ(a.dotnet->public_key_token, std::string("b77a5c561934e089"));
        CHECK(std::any_of(a.dotnet->references.begin(), a.dotnet->references.end(),
                          [](const DotNetReference& r) { return r.name == "mscorlib" && r.public_key_token == "b77a5c561934e089"; }));
        ++checked;
    }
    // notepad.exe: x64 exception table and an extractable icon.
    if (const std::filesystem::path np = "C:/Windows/System32/notepad.exe"; std::filesystem::exists(np)) {
        std::string e;
        auto f = FileImage::open(np, e);
        REQUIRE(f.has_value());
        const auto a = analyze(*f);
        CHECK(a.functions.size() > 100);
        CHECK(std::is_sorted(a.functions.begin(), a.functions.end(),
                             [](const FunctionRange& x, const FunctionRange& y) { return x.begin < y.begin; }));
        const auto ico = extract_icon(a, *f);
        REQUIRE(ico.has_value());
        CHECK((*ico)[0] == 0 && (*ico)[1] == 0 && (*ico)[2] == 1 && (*ico)[3] == 0);
    }
    // Third-party binary with an embedded Authenticode signature: the image
    // digest must match, and must stop matching after a one-byte change.
    if (const std::filesystem::path git = "C:\\Program Files\\Git\\cmd\\git.exe"; std::filesystem::exists(git)) {
        const auto a = analyze(git);
        REQUIRE(!a.signatures.empty());
        CHECK_EQ(a.signatures[0].digest_status, std::string("match"));
        CHECK(!a.signatures[0].signer_subject.empty());
        std::string e;
        auto f = FileImage::open(git, e);
        REQUIRE(f.has_value());
        std::vector<std::uint8_t> copy(f->bytes().begin(), f->bytes().end());
        copy[copy.size() / 3] ^= 0x01;
        const auto t = analyze(FileImage::from_bytes(std::move(copy)));
        REQUIRE(!t.signatures.empty());
        CHECK_EQ(t.signatures[0].digest_status, std::string("mismatch"));
        ++checked;
    }
#else
    for (const char* p : {"/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6",
                          "/usr/lib/libc.so.6", "/bin/ls"}) {
        if (!std::filesystem::exists(p)) continue;
        const auto a = analyze(p);
        print_errors(a);
        CHECK(!has_error(a));
        CHECK(a.format == Format::ELF);
        CHECK(!a.dynamic.empty());
        if (std::string(p).find("libc.so.6") != std::string::npos) {
            CHECK(a.property("SONAME") && *a.property("SONAME") == "libc.so.6");
            CHECK(a.symbols.size() > 1000);
            // glibc defines versioned symbols (verdef).
            CHECK(std::any_of(a.symbols.begin(), a.symbols.end(),
                              [](const Symbol& s) { return s.version.rfind("GLIBC_", 0) == 0; }));
        }
        ++checked;
    }
#endif
    std::cout << "  analyzed " << checked << " system binaries\n";
}

int main(int argc, char** argv) {
    g_self = std::filesystem::absolute(argv[0]);
#ifdef _WIN32
    if (g_self.extension() != ".exe") g_self += ".exe";
#endif
    return bwtest::run_all(argc, argv);
}
