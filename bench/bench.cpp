// Benchmark for the core operations on real files.
//   binweaver-bench [--repeat N] [--synthetic-mib N] <file>...
// Each measurement is the median of N runs (default 5). The first run of
// each file also pays the OS page-cache cost; repeat >= 3 to see warm numbers.
// Results depend heavily on storage and cache state: report them together
// with the hardware, OS and compiler (see docs/BENCHMARKS.md).
#include "binweaver/binweaver.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <random>
#include <string>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;

double median_ms(int repeat, const std::function<void()>& fn) {
    std::vector<double> t;
    for (int i = 0; i < repeat; ++i) {
        const auto start = Clock::now();
        fn();
        t.push_back(std::chrono::duration<double, std::milli>(Clock::now() - start).count());
    }
    std::sort(t.begin(), t.end());
    return t[t.size() / 2];
}

void row(const char* what, double ms, std::uint64_t bytes) {
    if (bytes == 0) {  // throughput is meaningless for size-independent operations
        std::printf("  %-38s %10.2f ms\n", what, ms);
        return;
    }
    const double mibs = ms > 0 ? (static_cast<double>(bytes) / (1 << 20)) / (ms / 1000.0) : 0;
    std::printf("  %-38s %10.2f ms  %9.0f MiB/s\n", what, ms, mibs);
}

std::filesystem::path make_synthetic(std::uint64_t mib) {
    // Half zeros, half pseudo-random 1 MiB chunks: exercises both the
    // memcmp fast path of compare() and high-entropy windows.
    const auto p = std::filesystem::temp_directory_path() / ("binweaver-bench-" + std::to_string(mib) + "MiB.bin");
    if (std::filesystem::exists(p) && std::filesystem::file_size(p) == mib << 20) return p;
    std::ofstream f(p, std::ios::binary);
    std::vector<char> chunk(1 << 20);
    std::mt19937 rng(1);
    for (std::uint64_t i = 0; i < mib; ++i) {
        if (i % 2) for (auto& c : chunk) c = static_cast<char>(rng());
        else std::fill(chunk.begin(), chunk.end(), 0);
        f.write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
    }
    return p;
}
} // namespace

int main(int argc, char** argv) {
    int repeat = 5;
    std::vector<std::filesystem::path> files;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--repeat" && i + 1 < argc) repeat = std::max(1, std::atoi(argv[++i]));
        else if (a == "--synthetic-mib" && i + 1 < argc) files.push_back(make_synthetic(std::strtoull(argv[++i], nullptr, 10)));
        else files.emplace_back(a);
    }
    if (files.empty()) {
        std::cerr << "usage: binweaver-bench [--repeat N] [--synthetic-mib N] <file>...\n";
        return 2;
    }
    for (const auto& p : files) {
        std::string e;
        auto mapped = bw::FileImage::open(p, e, bw::FileImage::kDefaultMaxSize, bw::FileImage::Mode::MemoryMap);
        if (!mapped) {
            std::cerr << p.string() << ": " << e << '\n';
            continue;
        }
        const auto n = mapped->size();
        const auto a = bw::analyze(*mapped);
        std::printf("%s\n  %llu bytes, %s %s, %zu sections, %zu imports, %zu exports, %zu symbols, %zu relocations\n",
                    p.string().c_str(), static_cast<unsigned long long>(n), bw::format_name(a.format), a.architecture.c_str(),
                    a.sections.size(), a.imports.size(), a.exports.size(), a.symbols.size(), a.relocations.size());
        row("open (memory map)", median_ms(repeat, [&] { (void)bw::FileImage::open(p, e, bw::FileImage::kDefaultMaxSize, bw::FileImage::Mode::MemoryMap); }), 0);
        row("open (read into memory)", median_ms(repeat, [&] { (void)bw::FileImage::open(p, e, bw::FileImage::kDefaultMaxSize, bw::FileImage::Mode::Read); }), n);
        row("sha256", median_ms(repeat, [&] { (void)bw::sha256(mapped->bytes()); }), n);
        row("entropy windows (4096 max)", median_ms(repeat, [&] {
                (void)bw::entropy_windows(mapped->bytes(), std::max<std::uint64_t>(256, n / 4096));
            }), n);
        row("analyze (full, incl. sha256)", median_ms(repeat, [&] { (void)bw::analyze(*mapped); }), n);
        bw::AnalyzeOptions lean;
        lean.section_entropy = false;
        lean.pe_checksum = false;
        row("analyze (no section entropy/checksum)", median_ms(repeat, [&] { (void)bw::analyze(*mapped, lean); }), n);
        row("strings (ASCII + UTF-16, min 5)", median_ms(repeat, [&] { (void)bw::extract_strings(mapped->bytes()); }), n);
        {
            const bool prev = bw::Sha256::set_hardware_enabled(false);
            row("sha256 (portable, SHA-NI disabled)", median_ms(repeat, [&] { (void)bw::sha256(mapped->bytes()); }), n);
            bw::Sha256::set_hardware_enabled(prev);
        }
        row("json report",median_ms(repeat, [&] { (void)bw::json_report(a); }), 0);
        std::string err;
        const auto pattern = *bw::parse_pattern("de ad be ef ca fe ba be", false, err);  // usually absent: full scan
        row("find (8-byte pattern, full scan)", median_ms(repeat, [&] { (void)bw::find_pattern(mapped->bytes(), pattern, 0); }), n);
        row("raw compare, identical (best case)", median_ms(repeat, [&] { (void)bw::compare(*mapped, *mapped); }), n);
        row("structural diff, identical inputs", median_ms(repeat, [&] { (void)bw::diff_structure(a, *mapped, a, *mapped); }), n);
    }
    return 0;
}
