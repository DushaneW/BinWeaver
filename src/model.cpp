#include "internal.hpp"

#include <algorithm>
#include <map>

namespace bw {

std::string printable(std::string_view raw) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size());
    for (char ch : raw) {
        const auto c = static_cast<unsigned char>(ch);
        // Backslashes are kept so Windows paths stay readable; the result is
        // for display, not a reversible encoding.
        if (c >= 0x20 && c < 0x7f) {
            out += static_cast<char>(c);
        } else {
            out += "\\x";
            out += digits[c >> 4];
            out += digits[c & 15];
        }
    }
    return out;
}

std::string hex(std::uint64_t value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    do {
        out.insert(out.begin(), digits[value & 15]);
        value >>= 4;
    } while (value);
    return "0x" + out;
}

const char* format_name(Format f) { return f == Format::PE ? "PE" : f == Format::ELF ? "ELF" : "Unknown"; }
const char* severity_name(Severity s) {
    return s == Severity::Error ? "error" : s == Severity::Warning ? "warning" : "info";
}
const char* change_kind_name(ChangeKind k) {
    switch (k) {
    case ChangeKind::Added: return "added";
    case ChangeKind::Removed: return "removed";
    case ChangeKind::Modified: return "modified";
    case ChangeKind::Unchanged: return "unchanged";
    }
    return "?";
}
const char* confidence_name(Confidence c) {
    switch (c) {
    case Confidence::Exact: return "exact";
    case Confidence::Heuristic: return "heuristic";
    case Confidence::NotComparable: return "not-comparable";
    }
    return "?";
}

const std::string* Analysis::property(std::string_view key) const {
    for (const auto& [k, v] : properties)
        if (k == key) return &v;
    return nullptr;
}

bool Analysis::has_errors() const {
    return std::any_of(diagnostics.begin(), diagnostics.end(),
                       [](const Diagnostic& d) { return d.severity == Severity::Error; });
}

std::size_t StructuralDiff::count(ChangeKind k) const {
    return static_cast<std::size_t>(
        std::count_if(changes.begin(), changes.end(), [k](const StructuralChange& c) { return c.kind == k; }));
}

namespace detail {

void diag(Analysis& a, std::string_view code, std::string message, std::uint64_t offset) {
    const auto* info = find_diagnostic(code);
    // An uncatalogued code is a programming error; it is reported as an error
    // so the catalog test and fuzzing notice it.
    const Severity severity = info ? info->severity : Severity::Error;
    if (severity == Severity::Error) a.structurally_valid = false;
    a.diagnostics.push_back({severity, std::string(code), std::move(message), offset});
}

void DiagLimiter::operator()(std::string_view code, std::string message, std::uint64_t offset) {
    auto it = std::find_if(counts_.begin(), counts_.end(), [&](const auto& p) { return p.first == code; });
    if (it == counts_.end()) {
        counts_.emplace_back(std::string(code), 0);
        it = counts_.end() - 1;
    }
    if (it->second++ < per_code_) diag(a_, code, std::move(message), offset);
}

DiagLimiter::~DiagLimiter() {
    for (const auto& [code, n] : counts_)
        if (n > per_code_)
            a_.diagnostics.push_back({Severity::Info, "diag.suppressed",
                                      std::to_string(n - per_code_) + " further '" + code + "' diagnostics suppressed.",
                                      0});
}

void add_property(Analysis& a, std::string key, std::string value) {
    a.properties.emplace_back(std::move(key), std::move(value));
}

std::string hex_bytes(std::span<const std::uint8_t> b, std::size_t max_bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    const auto n = std::min(b.size(), max_bytes);
    for (std::size_t i = 0; i < n; ++i) {
        out += digits[b[i] >> 4];
        out += digits[b[i] & 15];
    }
    if (b.size() > n) out += "...";
    return out;
}

std::string join_flags_text(std::uint64_t value, std::initializer_list<std::pair<std::uint64_t, const char*>> names) {
    std::string out;
    for (const auto& [bit, name] : names)
        if (value & bit) {
            if (!out.empty()) out += ' ';
            out += name;
            value &= ~bit;
        }
    if (value) out += (out.empty() ? "" : " ") + hex(value);
    return out.empty() ? "none" : out;
}

void assign_section_ids(std::vector<Section>& sections) {
    std::map<std::string, std::size_t> seen;
    for (auto& s : sections) {
        const std::size_t dup = seen[s.name]++;
        s.id = "section:" + s.name + (dup ? "#" + std::to_string(dup) : "");
    }
}

} // namespace detail
} // namespace bw
