// A small, dependency-free rule language for byte patterns and structural
// facts. It is deliberately much simpler than YARA (see docs/RULES.md):
//
//   rule NAME
//     tags a b c                      (optional)
//     scope file | section <name> | overlay
//     hex      $id = 4D 5A ?? 00
//     text     $id = "literal"        (ASCII; \\ \" \n \t \xNN escapes)
//     wide     $id = "literal"        (UTF-16LE of an ASCII literal)
//     import   $id = kernel32.dll!VirtualAlloc   (case-insensitive; "*" as function = any)
//     property $id = <key> contains <text>
//     condition any | all | <N>       (N = at least N atoms match)
//   end
#include "binweaver/binweaver.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace bw {
namespace {

std::string trim(std::string_view s) {
    std::size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return std::string(s.substr(a, b - a));
}

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Parses a double-quoted literal with escapes; returns nullopt on error.
std::optional<std::string> quoted(std::string_view s, std::string& error) {
    if (s.size() < 2 || s.front() != '"' || s.back() != '"') {
        error = "expected a double-quoted string";
        return std::nullopt;
    }
    std::string out;
    for (std::size_t i = 1; i + 1 < s.size(); ++i) {
        char c = s[i];
        if (c != '\\') {
            out += c;
            continue;
        }
        if (++i + 1 > s.size() - 1) {
            error = "dangling backslash";
            return std::nullopt;
        }
        switch (s[i]) {
        case '\\': out += '\\'; break;
        case '"': out += '"'; break;
        case 'n': out += '\n'; break;
        case 't': out += '\t'; break;
        case 'x': {
            if (i + 3 > s.size() - 1 || !std::isxdigit(static_cast<unsigned char>(s[i + 1])) ||
                !std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
                error = "\\x needs two hex digits";
                return std::nullopt;
            }
            out += static_cast<char>(std::stoi(std::string(s.substr(i + 1, 2)), nullptr, 16));
            i += 2;
            break;
        }
        default:
            error = std::string("unknown escape \\") + s[i];
            return std::nullopt;
        }
    }
    if (out.empty()) {
        error = "empty string";
        return std::nullopt;
    }
    return out;
}

} // namespace

std::vector<Rule> parse_rules(std::string_view text, std::vector<std::string>& errors) {
    std::vector<Rule> rules;
    std::optional<Rule> cur;
    std::istringstream in{std::string(text)};
    std::string raw;
    int line_no = 0;
    auto err = [&](const std::string& m) { errors.push_back("line " + std::to_string(line_no) + ": " + m); };
    while (std::getline(in, raw)) {
        ++line_no;
        // Strip comments: '#' at the start of a line or after whitespace, outside
        // quotes (so "lib!#17" ordinals and "#" inside strings are kept).
        bool in_quote = false;
        for (std::size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] == '"' && (i == 0 || raw[i - 1] != '\\')) in_quote = !in_quote;
            if (raw[i] == '#' && !in_quote && (i == 0 || std::isspace(static_cast<unsigned char>(raw[i - 1])))) {
                raw.resize(i);
                break;
            }
        }
        const std::string line = trim(raw);
        if (line.empty()) continue;
        std::istringstream words(line);
        std::string keyword;
        words >> keyword;
        if (keyword == "rule") {
            if (cur) err("'rule' inside rule '" + cur->name + "' (missing 'end')");
            std::string name;
            words >> name;
            if (name.empty()) {
                err("rule needs a name");
                continue;
            }
            cur = Rule{};
            cur->name = name;
            cur->line = line_no;
            continue;
        }
        if (!cur) {
            err("'" + keyword + "' outside a rule");
            continue;
        }
        if (keyword == "end") {
            if (cur->atoms.empty()) err("rule '" + cur->name + "' has no patterns");
            else if (cur->min_matches > cur->atoms.size())
                err("rule '" + cur->name + "' requires " + std::to_string(cur->min_matches) + " matches but has " +
                    std::to_string(cur->atoms.size()) + " patterns");
            else rules.push_back(std::move(*cur));
            cur.reset();
            continue;
        }
        if (keyword == "tags") {
            for (std::string t; words >> t;) cur->tags.push_back(t);
        } else if (keyword == "scope") {
            std::string what;
            words >> what;
            if (what == "file" || what == "overlay") {
                cur->scope = what;
            } else if (what == "section") {
                std::string name;
                words >> name;
                if (name.empty()) err("scope section needs a section name");
                cur->scope = "section";
                cur->scope_section = name;
            } else {
                err("unknown scope '" + what + "' (file, section <name>, overlay)");
            }
        } else if (keyword == "condition") {
            std::string c;
            words >> c;
            if (c == "any") cur->min_matches = 1;
            else if (c == "all") cur->min_matches = 0;  // resolved at match time
            else if (!c.empty() && std::all_of(c.begin(), c.end(), [](char ch) { return std::isdigit(static_cast<unsigned char>(ch)); }) && c.size() < 6)
                cur->min_matches = static_cast<std::size_t>(std::stoul(c));
            else err("condition must be any, all or a number");
            cur->all = c == "all";
        } else if (keyword == "hex" || keyword == "text" || keyword == "wide" || keyword == "import" || keyword == "property") {
            const auto eq = line.find('=');
            const std::string id = trim(std::string_view(line).substr(keyword.size(), eq == std::string::npos ? std::string::npos : eq - keyword.size()));
            if (eq == std::string::npos || id.size() < 2 || id[0] != '$') {
                err("expected: " + keyword + " $id = ...");
                continue;
            }
            const std::string value = trim(std::string_view(line).substr(eq + 1));
            RuleAtom atom;
            atom.id = id;
            atom.kind = keyword;
            std::string e;
            if (keyword == "hex") {
                auto p = parse_pattern(value, false, e);
                if (!p) { err(id + ": " + e); continue; }
                atom.pattern = *p;
            } else if (keyword == "text" || keyword == "wide") {
                auto q = quoted(value, e);
                if (!q) { err(id + ": " + e); continue; }
                std::string bytes = *q;
                if (keyword == "wide") {
                    bytes.clear();
                    for (char ch : *q) {
                        bytes += ch;
                        bytes += '\0';
                    }
                }
                atom.pattern = *parse_pattern(bytes, true, e);
            } else if (keyword == "import") {
                const auto bang = value.find('!');
                if (bang == std::string::npos || bang == 0 || bang + 1 == value.size()) {
                    err(id + ": expected library!function");
                    continue;
                }
                atom.library = lower(value.substr(0, bang));
                atom.value = value.substr(bang + 1);
            } else {
                const auto at = value.find(" contains ");
                if (at == std::string::npos) {
                    err(id + ": expected <key> contains <text>");
                    continue;
                }
                atom.key = trim(std::string_view(value).substr(0, at));
                auto q = value.substr(at + 10);
                atom.value = trim(q);
                if (atom.value.size() >= 2 && atom.value.front() == '"') {
                    auto v = quoted(atom.value, e);
                    if (!v) { err(id + ": " + e); continue; }
                    atom.value = *v;
                }
            }
            if (std::any_of(cur->atoms.begin(), cur->atoms.end(), [&](const RuleAtom& a) { return a.id == id; })) {
                err("duplicate pattern id " + id);
                continue;
            }
            if (cur->atoms.size() >= 256) {
                err("too many patterns in rule '" + cur->name + "' (max 256)");
                continue;
            }
            cur->atoms.push_back(std::move(atom));
        } else {
            err("unknown keyword '" + keyword + "'");
        }
    }
    if (cur) err("rule '" + cur->name + "' is not closed with 'end'");
    return rules;
}

std::vector<RuleMatch> match_rules(const std::vector<Rule>& rules, const Analysis& a, const FileImage& f) {
    std::vector<RuleMatch> out;
    for (const auto& rule : rules) {
        // Resolve the byte range the rule searches.
        std::optional<ByteRange> scope{ByteRange{0, f.size()}};
        if (rule.scope == "section") {
            scope.reset();
            for (const auto& s : a.sections)
                if (s.name == rule.scope_section && s.file_range_valid && s.size) scope = ByteRange{s.offset, s.size};
        } else if (rule.scope == "overlay") {
            scope.reset();
            for (const auto& r : a.structures)
                if (r.kind == "overlay") scope = ByteRange{r.offset, r.size};
        }
        RuleMatch m;
        m.rule = rule.name;
        m.tags = rule.tags;
        for (const auto& atom : rule.atoms) {
            std::optional<std::uint64_t> where;
            bool hit = false;
            if (atom.kind == "import") {
                for (const auto& i : a.imports) {
                    std::string lib = lower(i.library);
                    if (lib != atom.library && lib != atom.library + ".dll") continue;
                    if (atom.value == "*" || lower(i.name) == lower(atom.value) ||
                        (i.ordinal && atom.value == "#" + std::to_string(*i.ordinal))) {
                        hit = true;
                        break;
                    }
                }
            } else if (atom.kind == "property") {
                const auto* v = a.property(atom.key);
                hit = v && lower(*v).find(lower(atom.value)) != std::string::npos;
            } else if (scope && f.contains(scope->offset, scope->size)) {
                const auto span = f.bytes().subspan(static_cast<std::size_t>(scope->offset), static_cast<std::size_t>(scope->size));
                if (auto at = find_pattern(span, atom.pattern, 0)) {
                    hit = true;
                    where = scope->offset + *at;
                }
            }
            if (hit) m.matched.push_back({atom.id, where});
        }
        const std::size_t need = rule.all ? rule.atoms.size() : std::max<std::size_t>(rule.min_matches, 1);
        if (m.matched.size() >= need) out.push_back(std::move(m));
    }
    return out;
}

} // namespace bw
