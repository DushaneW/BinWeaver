#include "binweaver/binweaver.hpp"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <map>
#include <thread>
#include <iomanip>
#include <iostream>

namespace {

constexpr const char* kUsage =
    "Usage:\n"
    "  binweaver-cli inspect <file> [--json | --html] [--no-mmap]\n"
    "  binweaver-cli fields <file>                    header field map (PE/ELF headers and tables)\n"
    "  binweaver-cli extract <file> <what> <out>      what: section:<name> segment:<n> resource:<n> overlay range:<off>:<size>\n"
    "  binweaver-cli compare <a> <b> [--json] [--all]\n"
    "  binweaver-cli hash <file>\n"
    "  binweaver-cli entropy <file> [--window <bytes>]\n"
    "  binweaver-cli locate <file> <offset>        regions containing a file offset\n"
    "  binweaver-cli map <file> <address>          PE RVA / ELF virtual address -> file offset\n"
    "  binweaver-cli find <file> <pattern> [--text] [--max <n>]\n"
    "  binweaver-cli strings <file> [--min <n>] [--ascii | --utf16] [--max <n>]\n"
    "  binweaver-cli icon <file> <out.ico> [--index <n>]   extract a PE icon group\n"
    "  binweaver-cli match <rules> <file-or-dir>... [--recursive]  run a rule file (docs/RULES.md)\n"
    "  binweaver-cli scan <dir-or-file>... [--recursive] [--csv <out.csv>] [--jobs <n>]\n"
    "  binweaver-cli diagnostics                   list stable diagnostic codes\n"
    "Numbers accept decimal or 0x-prefixed hex. Patterns are hex bytes with ?? wildcards.\n"
    "Exit status: 0 success, 1 failure or structural errors (inspect), 2 usage error.\n";

std::optional<std::uint64_t> parse_number(std::string_view s) {
    int base = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s.remove_prefix(2);
        base = 16;
    }
    std::uint64_t v{};
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
    if (ec != std::errc{} || p != s.data() + s.size() || s.empty()) return std::nullopt;
    return v;
}

bool has_flag(int argc, char** argv, int from, std::string_view flag) {
    for (int i = from; i < argc; ++i)
        if (argv[i] == flag) return true;
    return false;
}

std::optional<std::string_view> flag_value(int argc, char** argv, int from, std::string_view flag) {
    for (int i = from; i + 1 < argc; ++i)
        if (argv[i] == flag) return argv[i + 1];
    return std::nullopt;
}

std::string csv(std::string_view v) {
    std::string out = "\"";
    for (char ch : v) {
        if (ch == '"') out += '"';
        out += ch;
    }
    return out + '"';
}

struct ScanRow {
    std::string path, error;
    bw::Analysis a;
};

// Analyzes every regular file under the given paths on `jobs` threads and
// writes one CSV row per file (in path order) plus a summary to stdout.
int scan(const std::vector<std::filesystem::path>& inputs, bool recursive, const std::string& csv_path, unsigned jobs) {
    namespace fs = std::filesystem;
    std::vector<fs::path> files;
    std::error_code ec;
    for (const auto& in : inputs) {
        if (fs::is_regular_file(in, ec)) {
            files.push_back(in);
        } else if (fs::is_directory(in, ec)) {
            const auto opts = fs::directory_options::skip_permission_denied;
            if (recursive) {
                for (fs::recursive_directory_iterator it(in, opts, ec), end; it != end; it.increment(ec))
                    if (!ec && it->is_regular_file(ec)) files.push_back(it->path());
            } else {
                for (fs::directory_iterator it(in, opts, ec), end; it != end; it.increment(ec))
                    if (!ec && it->is_regular_file(ec)) files.push_back(it->path());
            }
        } else {
            std::cerr << in.string() << ": not found\n";
        }
    }
    std::sort(files.begin(), files.end());
    std::vector<ScanRow> rows(files.size());
    std::atomic<std::size_t> next{0};
    auto worker = [&] {
        for (std::size_t i; (i = next++) < files.size();) {
            const auto u8 = files[i].u8string();
            rows[i].path.assign(reinterpret_cast<const char*>(u8.data()), u8.size());
            std::string e;
            auto f = bw::FileImage::open(files[i], e);
            if (!f) {
                rows[i].error = e;
                continue;
            }
            rows[i].a = bw::analyze(*f);
        }
    };
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < std::max(1u, jobs); ++t) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    std::ofstream out;
    if (!csv_path.empty()) {
        out.open(csv_path, std::ios::binary);
        if (!out) {
            std::cerr << "cannot write " << csv_path << '\n';
            return 1;
        }
        out << "path,size,format,architecture,bitness,file_type,sha256,imphash,errors,warnings,heuristics,signer,signature_digest,open_error\n";
    }
    std::map<std::string, std::size_t> formats, heuristics;
    std::size_t with_errors = 0, unreadable = 0, signed_files = 0, digest_mismatch = 0;
    for (const auto& r : rows) {
        if (!r.error.empty()) ++unreadable;
        std::size_t errors = 0, warnings = 0;
        std::string heur;
        for (const auto& d : r.a.diagnostics) {
            errors += d.severity == bw::Severity::Error;
            warnings += d.severity == bw::Severity::Warning;
            if (d.code.rfind("heur.", 0) == 0 && heur.find(d.code) == std::string::npos) {
                heur += (heur.empty() ? "" : ";") + d.code;
                ++heuristics[d.code];
            }
        }
        if (r.error.empty()) ++formats[bw::format_name(r.a.format)];
        with_errors += errors > 0;
        const auto* sig = r.a.signatures.empty() ? nullptr : &r.a.signatures.front();
        signed_files += sig != nullptr;
        digest_mismatch += sig && sig->digest_status == "mismatch";
        if (out)
            out << csv(r.path) << ',' << r.a.file_size << ',' << bw::format_name(r.a.format) << ',' << csv(r.a.architecture)
                << ',' << csv(r.a.bitness) << ',' << csv(r.a.file_type) << ',' << r.a.sha256 << ',' << r.a.imphash << ','
                << errors << ',' << warnings << ',' << csv(heur) << ',' << csv(sig ? sig->signer_subject : "") << ','
                << csv(sig ? sig->digest_status : "") << ',' << csv(r.error) << '\n';
    }
    std::cout << "scanned " << rows.size() << " files (" << unreadable << " unreadable)\n";
    for (const auto& [k, v] : formats) std::cout << "  " << std::left << std::setw(10) << k << v << '\n';
    std::cout << "with structural errors: " << with_errors << "\nembedded Authenticode signatures: " << signed_files
              << " (" << digest_mismatch << " with digest mismatch)\n";
    if (!heuristics.empty()) {
        std::cout << "heuristic observations (files):\n";
        for (const auto& [k, v] : heuristics) std::cout << "  " << std::left << std::setw(36) << k << v << '\n';
    }
    return 0;
}

int usage() {
    std::cerr << kUsage;
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    using namespace bw;
    if (argc < 2) return usage();
    const std::string c = argv[1];
    std::string e;

    if (c == "diagnostics") {
        for (const auto& d : diagnostic_catalog())
            std::cout << std::left << std::setw(8) << severity_name(d.severity) << std::setw(36) << d.code << d.summary << '\n';
        return 0;
    }
    if (argc < 3) return usage();

    if (c == "match") {
        if (argc < 4) return usage();
        std::ifstream in(argv[2], std::ios::binary);
        if (!in) {
            std::cerr << "cannot read " << argv[2] << '\n';
            return 1;
        }
        const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::vector<std::string> errors;
        const auto rules = parse_rules(text, errors);
        for (const auto& er : errors) std::cerr << argv[2] << ": " << er << '\n';
        if (!errors.empty()) return 2;
        bool recursive = false;
        std::vector<std::filesystem::path> files;
        for (int i = 3; i < argc; ++i)
            if (std::string_view(argv[i]) == "--recursive") recursive = true;
        std::error_code ec;
        for (int i = 3; i < argc; ++i) {
            const std::filesystem::path p = argv[i];
            if (p == "--recursive") continue;
            if (std::filesystem::is_directory(p, ec)) {
                const auto opts = std::filesystem::directory_options::skip_permission_denied;
                if (recursive) {
                    for (std::filesystem::recursive_directory_iterator it(p, opts, ec), end; it != end; it.increment(ec))
                        if (!ec && it->is_regular_file(ec)) files.push_back(it->path());
                } else {
                    for (std::filesystem::directory_iterator it(p, opts, ec), end; it != end; it.increment(ec))
                        if (!ec && it->is_regular_file(ec)) files.push_back(it->path());
                }
            } else {
                files.push_back(p);
            }
        }
        std::sort(files.begin(), files.end());
        std::size_t matched_files = 0;
        for (const auto& p : files) {
            auto f = FileImage::open(p, e);
            if (!f) continue;
            const auto an = analyze(*f);
            const auto hits = match_rules(rules, an, *f);
            matched_files += !hits.empty();
            for (const auto& h : hits) {
                std::cout << h.rule << ' ' << p.string();
                for (const auto& m : h.matched) std::cout << ' ' << m.id << (m.offset ? "@" + hex(*m.offset) : std::string());
                std::cout << '\n';
            }
        }
        std::cerr << rules.size() << " rule(s), " << files.size() << " file(s), " << matched_files << " matched\n";
        return 0;
    }
    if (c == "scan") {
        std::vector<std::filesystem::path> inputs;
        std::string csv_path;
        bool recursive = false;
        unsigned jobs = std::max(1u, std::thread::hardware_concurrency());
        for (int i = 2; i < argc; ++i) {
            const std::string_view arg = argv[i];
            if (arg == "--recursive") recursive = true;
            else if (arg == "--csv" && i + 1 < argc) csv_path = argv[++i];
            else if (arg == "--jobs" && i + 1 < argc) {
                auto v = parse_number(argv[++i]);
                if (!v || *v == 0 || *v > 256) return usage();
                jobs = static_cast<unsigned>(*v);
            } else if (arg.rfind("--", 0) == 0) return usage();
            else inputs.emplace_back(argv[i]);
        }
        return inputs.empty() ? usage() : scan(inputs, recursive, csv_path, jobs);
    }

    if (c == "inspect") {
        const auto mode = has_flag(argc, argv, 3, "--no-mmap") ? FileImage::Mode::Read : FileImage::Mode::Auto;
        auto f = FileImage::open(argv[2], e, FileImage::kDefaultMaxSize, mode);
        Analysis a = f ? analyze(*f) : analyze(argv[2]);
        std::cout << (has_flag(argc, argv, 3, "--json") ? json_report(a) : has_flag(argc, argv, 3, "--html") ? html_report(a) : text_report(a));
        return a.has_errors() ? 1 : 0;
    }

    auto a = FileImage::open(argv[2], e);
    if (!a) {
        std::cerr << argv[2] << ": " << e << '\n';
        return 1;
    }
    if (c == "hash") {
        std::cout << sha256(a->bytes()) << '\n';
        return 0;
    }
    if (c == "entropy") {
        std::cout << std::fixed << std::setprecision(4) << entropy(a->bytes()) << " bits/byte\n";
        if (auto w = flag_value(argc, argv, 3, "--window")) {
            auto window = parse_number(*w);
            if (!window || *window == 0) return usage();
            for (const auto& x : entropy_windows(a->bytes(), *window))
                std::cout << std::setw(14) << hex(x.offset) << std::setw(12) << x.size << "  " << x.entropy << '\n';
        }
        return 0;
    }
    if (c == "compare") {
        if (argc < 4) return usage();
        auto b = FileImage::open(argv[3], e);
        if (!b) {
            std::cerr << argv[3] << ": " << e << '\n';
            return 1;
        }
        DiffOptions options;
        options.include_unchanged = has_flag(argc, argv, 4, "--all");
        const auto d = diff_structure(analyze(*a), *a, analyze(*b), *b, options);
        std::cout << (has_flag(argc, argv, 4, "--json") ? json_report(d) : text_report(d));
        return 0;
    }
    if (c == "locate" || c == "map") {
        if (argc < 4) return usage();
        auto n = parse_number(argv[3]);
        if (!n) return usage();
        const auto an = analyze(*a);
        if (c == "map") {
            const auto m = address_to_offset(an, *n);
            if (m.status == MapStatus::FileBacked) std::cout << hex(*n) << " -> file offset " << hex(m.offset) << " (" << m.mapping << ")\n";
            else if (m.status == MapStatus::ZeroFill) std::cout << hex(*n) << " is mapped by " << m.mapping << " but zero-filled (no file bytes)\n";
            else std::cout << hex(*n) << " is not mapped by any section or segment\n";
            return m.status == MapStatus::FileBacked ? 0 : 1;
        }
        if (*n >= an.file_size) {
            std::cerr << "offset is beyond the end of the file\n";
            return 1;
        }
        for (const auto& r : locate(an, *n))
            std::cout << std::left << std::setw(12) << r.kind << std::setw(32) << r.name << '[' << hex(r.offset) << ", +"
                      << hex(r.size) << ")\n";
        for (auto addr : offset_to_addresses(an, *n)) std::cout << "mapped at   " << hex(addr) << '\n';
        return 0;
    }
    if (c == "icon") {
        if (argc < 4) return usage();
        std::uint64_t index = 0;
        if (auto m = flag_value(argc, argv, 4, "--index")) {
            auto v = parse_number(*m);
            if (!v) return usage();
            index = *v;
        }
        const auto an = analyze(*a);
        std::string why;
        auto ico = extract_icon(an, *a, static_cast<std::size_t>(index), &why);
        if (!ico) {
            std::cerr << "no icon: " << why << " (" << icon_group_count(an) << " icon group(s))\n";
            return 1;
        }
        std::ofstream out(argv[3], std::ios::binary);
        out.write(reinterpret_cast<const char*>(ico->data()), static_cast<std::streamsize>(ico->size()));
        if (!out) {
            std::cerr << "cannot write " << argv[3] << '\n';
            return 1;
        }
        std::cout << "wrote " << ico->size() << " bytes, " << ((*ico)[4] | ((*ico)[5] << 8)) << " image(s), group " << index
                  << " of " << icon_group_count(an) << '\n';
        return 0;
    }
    if (c == "fields") {
        const auto an = analyze(*a);
        for (const auto& fld : header_fields(an, *a))
            std::cout << std::setw(10) << hex(fld.offset) << "  " << std::left << std::setw(44) << (fld.structure + "." + fld.name)
                      << std::right << fld.text << '\n';
        return 0;
    }
    if (c == "extract") {
        if (argc < 5) return usage();
        const auto an = analyze(*a);
        const std::string what = argv[3];
        std::optional<ByteRange> r;
        auto index_of = [&](std::size_t prefix) { return parse_number(std::string_view(what).substr(prefix)); };
        if (what.rfind("section:", 0) == 0) {
            for (const auto& s : an.sections)
                if (s.name == what.substr(8) && s.file_range_valid && s.size) { r = ByteRange{s.offset, s.size}; break; }
        } else if (what.rfind("segment:", 0) == 0) {
            if (auto i = index_of(8); i && *i < an.segments.size() && an.segments[*i].file_range_valid)
                r = ByteRange{an.segments[*i].offset, an.segments[*i].size};
        } else if (what.rfind("resource:", 0) == 0) {
            if (auto i = index_of(9); i && *i < an.resources.size() && an.resources[*i].offset)
                r = ByteRange{*an.resources[*i].offset, an.resources[*i].size};
        } else if (what == "overlay") {
            for (const auto& s : an.structures)
                if (s.kind == "overlay") r = ByteRange{s.offset, s.size};
        } else if (what.rfind("range:", 0) == 0) {
            const auto colon = what.find(':', 6);
            if (colon != std::string::npos) {
                auto off = parse_number(std::string_view(what).substr(6, colon - 6));
                auto len = parse_number(std::string_view(what).substr(colon + 1));
                if (off && len) r = ByteRange{*off, *len};
            }
        } else {
            return usage();
        }
        if (!r || !a->contains(r->offset, r->size)) {
            std::cerr << "nothing to extract for '" << what << "' (missing, not file-backed or outside the file)\n";
            return 1;
        }
        std::ofstream out(argv[4], std::ios::binary);
        out.write(reinterpret_cast<const char*>(a->bytes().data() + r->offset), static_cast<std::streamsize>(r->size));
        if (!out) {
            std::cerr << "cannot write " << argv[4] << '\n';
            return 1;
        }
        std::cout << "wrote " << r->size << " bytes from [" << hex(r->offset) << ", +" << hex(r->size) << ")\n";
        return 0;
    }
    if (c == "strings") {
        StringOptions o;
        if (auto m = flag_value(argc, argv, 3, "--min")) {
            auto v = parse_number(*m);
            if (!v || *v == 0) return usage();
            o.min_length = static_cast<std::size_t>(*v);
        }
        if (auto m = flag_value(argc, argv, 3, "--max")) {
            auto v = parse_number(*m);
            if (!v) return usage();
            o.max_count = static_cast<std::size_t>(*v);
        }
        if (has_flag(argc, argv, 3, "--ascii")) o.utf16 = false;
        if (has_flag(argc, argv, 3, "--utf16")) o.ascii = false;
        const auto scan = extract_strings(a->bytes(), o);
        for (const auto& s : scan.strings)
            std::cout << std::setw(12) << hex(s.offset) << (s.utf16 ? "  u16  " : "  asc  ") << printable(s.text) << '\n';
        if (scan.truncated) std::cerr << "output truncated at " << o.max_count << " strings (--max)\n";
        return 0;
    }
    if (c == "find") {
        if (argc < 4) return usage();
        auto p = parse_pattern(argv[3], has_flag(argc, argv, 4, "--text"), e);
        if (!p) {
            std::cerr << e << '\n';
            return 2;
        }
        std::uint64_t max = 100;
        if (auto m = flag_value(argc, argv, 4, "--max")) {
            auto v = parse_number(*m);
            if (!v) return usage();
            max = *v;
        }
        std::uint64_t from = 0, found = 0;
        while (found < max) {
            auto hit = find_pattern(a->bytes(), *p, from);
            if (!hit) break;
            std::cout << hex(*hit) << '\n';
            ++found;
            from = *hit + 1;
        }
        return found ? 0 : 1;
    }
    return usage();
}
