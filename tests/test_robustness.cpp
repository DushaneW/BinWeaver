// Robustness: deterministic mutation fuzzing, truncation sweeps, report
// well-formedness and diagnostic-catalog consistency. Run these under
// -DBINWEAVER_SANITIZE=address;undefined to turn silent memory errors into
// failures.
#include "binweaver/binweaver.hpp"
#include "check.hpp"
#include "fixtures.hpp"

#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <regex>
#include <set>
#include <sstream>

using namespace bw;

namespace {

// Strict recursive-descent JSON validator (RFC 8259 grammar, no extensions).
class JsonValidator {
public:
    explicit JsonValidator(std::string_view s) : s_(s) {}
    bool valid() {
        ws();
        if (!value()) return false;
        ws();
        return i_ == s_.size();
    }

private:
    bool value() {
        if (i_ >= s_.size()) return false;
        switch (s_[i_]) {
        case '{': return object();
        case '[': return array();
        case '"': return string();
        case 't': return literal("true");
        case 'f': return literal("false");
        case 'n': return literal("null");
        default: return number();
        }
    }
    bool object() {
        ++i_;
        ws();
        if (peek('}')) return ++i_, true;
        for (;;) {
            ws();
            if (!string()) return false;
            ws();
            if (!peek(':')) return false;
            ++i_;
            ws();
            if (!value()) return false;
            ws();
            if (peek('}')) return ++i_, true;
            if (!peek(',')) return false;
            ++i_;
        }
    }
    bool array() {
        ++i_;
        ws();
        if (peek(']')) return ++i_, true;
        for (;;) {
            ws();
            if (!value()) return false;
            ws();
            if (peek(']')) return ++i_, true;
            if (!peek(',')) return false;
            ++i_;
        }
    }
    bool string() {
        if (!peek('"')) return false;
        ++i_;
        while (i_ < s_.size()) {
            const unsigned char c = static_cast<unsigned char>(s_[i_++]);
            if (c == '"') return true;
            if (c < 0x20) return false;
            if (c == '\\') {
                if (i_ >= s_.size()) return false;
                const char e = s_[i_++];
                if (e == 'u') {
                    for (int k = 0; k < 4; ++k)
                        if (i_ >= s_.size() || !std::isxdigit(static_cast<unsigned char>(s_[i_++]))) return false;
                } else if (std::string_view("\"\\/bfnrt").find(e) == std::string_view::npos) {
                    return false;
                }
            }
        }
        return false;
    }
    bool number() {
        const std::size_t start = i_;
        if (peek('-')) ++i_;
        while (i_ < s_.size() && (std::isdigit(static_cast<unsigned char>(s_[i_])) || s_[i_] == '.' || s_[i_] == 'e' ||
                                  s_[i_] == 'E' || s_[i_] == '+' || s_[i_] == '-'))
            ++i_;
        return i_ > start;
    }
    bool literal(std::string_view lit) {
        if (s_.substr(i_, lit.size()) != lit) return false;
        i_ += lit.size();
        return true;
    }
    bool peek(char c) const { return i_ < s_.size() && s_[i_] == c; }
    void ws() {
        while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\n' || s_[i_] == '\r' || s_[i_] == '\t')) ++i_;
    }
    std::string_view s_;
    std::size_t i_{};
};

// Exercises every public entry point on one input; any crash or sanitizer
// report fails the run. Returns the analysis for further checks.
Analysis exercise(const fixtures::Bytes& bytes) {
    const auto f = FileImage::from_bytes(bytes, "mutant");
    auto a = analyze(f);
    CHECK(JsonValidator(json_report(a)).valid());
    (void)text_report(a);
    for (const auto& d : a.diagnostics) {
        if (!find_diagnostic(d.code)) {
            CHECK(find_diagnostic(d.code) != nullptr);
            std::cerr << "  uncatalogued code: " << d.code << '\n';
        }
    }
    for (const auto& s : a.sections)
        if (s.entropy) CHECK(s.file_range_valid || s.size == 0 || f.contains(s.offset, 1));
    // Address translation must only return in-file offsets.
    for (const auto& m : a.mappings) {
        const auto r = address_to_offset(a, m.address);
        if (r.status == MapStatus::FileBacked) CHECK(r.offset < a.file_size);
    }
    if (a.file_size) (void)locate(a, a.file_size - 1);
    return a;
}

std::vector<fixtures::Bytes> seeds() {
    std::vector<fixtures::Bytes> s;
    s.push_back(fixtures::pe::build());
    s.push_back(fixtures::pe::build(fixtures::pe::Options{.pe32plus = false}));
    for (bool wide : {true, false})
        for (bool little : {true, false}) {
            fixtures::elf::Options o;
            o.wide = wide;
            o.little = little;
            s.push_back(fixtures::elf::build(o));
        }
    fixtures::pe::Options dn;
    dn.dotnet = true;
    s.push_back(fixtures::pe::build(dn));
    fixtures::elf::Options ext;
    ext.extended_numbering = true;
    s.push_back(fixtures::elf::build(ext));
    return s;
}

std::string slurp(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream o;
    o << f.rdbuf();
    return o.str();
}

} // namespace

TEST_CASE("robust.json_is_valid") {
    for (const auto& s : seeds()) CHECK(JsonValidator(json_report(analyze(FileImage::from_bytes(s)))).valid());
    CHECK(JsonValidator("{\"a\": [1, 2.5, -3e2, true, null, \"x\\u0001\"]}").valid());
    CHECK(!JsonValidator("{\"a\": [1, 2,]}").valid());
    CHECK(!JsonValidator("{\"a\": \"\x01\"}").valid());
}

TEST_CASE("robust.truncation_sweep") {
    // Every prefix of every seed must be handled without crashing; prefixes
    // that cut through a required structure must produce an error.
    for (const auto& s : seeds()) {
        for (std::size_t n = 0; n < s.size(); n += (n < 1024 ? 1 : 7)) {
            fixtures::Bytes cut(s.begin(), s.begin() + static_cast<std::ptrdiff_t>(n));
            const auto a = exercise(cut);
            if (n >= 4 && n < 52) CHECK(a.has_errors());
        }
    }
}

TEST_CASE("robust.mutation_fuzz") {
    // Deterministic mutational fuzzing: byte flips, interesting-value writes
    // and splices on structurally valid seeds. Iteration count is modest so
    // the suite stays fast; the libFuzzer harness in fuzz/ runs open-ended.
    std::mt19937_64 rng(0xb1a5ed);
    const auto base = seeds();
    const std::uint32_t interesting[] = {0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff};
    std::set<std::string> codes;
    // BW_FUZZ_ITERATIONS raises the count for long sanitizer campaigns.
    int iterations = 6000;
    if (const char* env = std::getenv("BW_FUZZ_ITERATIONS")) iterations = std::max(1, std::atoi(env));
    for (int iter = 0; iter < iterations; ++iter) {
        auto b = base[static_cast<std::size_t>(rng() % base.size())];
        const int mutations = 1 + static_cast<int>(rng() % 8);
        for (int m = 0; m < mutations; ++m) {
            const std::size_t at = static_cast<std::size_t>(rng() % b.size());
            switch (rng() % 4) {
            case 0: b[at] ^= static_cast<std::uint8_t>(1u << (rng() % 8)); break;
            case 1: b[at] = static_cast<std::uint8_t>(rng()); break;
            case 2: {
                const auto v = interesting[rng() % std::size(interesting)];
                for (std::size_t k = 0; k < 4 && at + k < b.size(); ++k) b[at + k] = static_cast<std::uint8_t>(v >> (8 * k));
                break;
            }
            default: b.resize(at + 1); break;
            }
            if (b.empty()) break;
        }
        for (const auto& d : exercise(b).diagnostics) codes.insert(d.code);
    }
    // The fuzz loop must reach a broad set of diagnostics, otherwise the
    // mutations are not exercising the parsers.
    CHECK(codes.size() > 40);
    std::cout << "  mutation fuzz reached " << codes.size() << " distinct diagnostic codes\n";
}

TEST_CASE("robust.diff_on_mutants") {
    std::mt19937_64 rng(99);
    const auto base = seeds();
    for (int iter = 0; iter < 400; ++iter) {
        auto x = base[static_cast<std::size_t>(rng() % base.size())];
        auto y = base[static_cast<std::size_t>(rng() % base.size())];
        for (int m = 0; m < 6; ++m) {
            y[static_cast<std::size_t>(rng() % y.size())] = static_cast<std::uint8_t>(rng());
            x[static_cast<std::size_t>(rng() % x.size())] = static_cast<std::uint8_t>(rng());
        }
        const auto fa = FileImage::from_bytes(x), fb = FileImage::from_bytes(y);
        const auto d = diff_structure(analyze(fa), fa, analyze(fb), fb);
        CHECK(JsonValidator(json_report(d)).valid());
        (void)text_report(d);
    }
}

TEST_CASE("robust.diagnostic_catalog") {
    const auto& catalog = diagnostic_catalog();
    std::set<std::string_view> unique;
    for (const auto& d : catalog) {
        CHECK(unique.insert(d.code).second);
        CHECK(!d.summary.empty());
    }
    // Every code literal used in the sources is catalogued...
    const std::filesystem::path root = BINWEAVER_SOURCE_DIR;
    const std::regex code_re("\"((?:pe|elf|file|format|diag|heur)\\.[a-z0-9_]+(?:\\.[a-z0-9_]+)*)\"");
    std::set<std::string> used;
    for (const auto& entry : std::filesystem::directory_iterator(root / "src")) {
        if (entry.path().extension() != ".cpp" || entry.path().filename() == "diagnostics.cpp") continue;
        const auto text = slurp(entry.path());
        for (std::sregex_iterator it(text.begin(), text.end(), code_re), end; it != end; ++it) used.insert((*it)[1]);
    }
    CHECK(used.size() > 50);
    for (const auto& c : used) {
        if (!find_diagnostic(c)) std::cerr << "  not in catalog: " << c << '\n';
        CHECK(find_diagnostic(c) != nullptr);
    }
    // ...and every catalogued code is documented and used.
    const auto doc = slurp(root / "docs" / "DIAGNOSTICS.md");
    for (const auto& d : catalog) {
        const std::string code(d.code);
        if (doc.find("`" + code + "`") == std::string::npos) std::cerr << "  undocumented: " << code << '\n';
        CHECK(doc.find("`" + code + "`") != std::string::npos);
        // Retired codes stay catalogued (never reused) but must not be emitted.
        if (d.retired != (used.count(code) == 0)) std::cerr << "  catalog/usage mismatch: " << code << '\n';
        CHECK(d.retired == (used.count(code) == 0));
    }
}
