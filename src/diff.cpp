// Structural comparison of two analyses. Every change carries a confidence:
//   exact          - both sides were matched by an unambiguous key;
//   heuristic      - matching relied on order or position (duplicate names,
//                    unnamed sections, segments);
//   not-comparable - the two sides cannot be meaningfully compared.
#include "binweaver/binweaver.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <set>

namespace bw {
namespace {

class Builder {
public:
    Builder(StructuralDiff& d, const DiffOptions& o) : d_(d), o_(o) {}
    void add(ChangeKind kind, Confidence confidence, std::string category, std::string subject, std::string detail,
             std::optional<ByteRange> ra = std::nullopt, std::optional<ByteRange> rb = std::nullopt) {
        if (kind == ChangeKind::Unchanged && !o_.include_unchanged) return;
        if (d_.changes.size() >= o_.max_changes) {
            d_.truncated = true;
            return;
        }
        d_.changes.push_back({std::move(category), std::move(subject), kind, confidence, std::move(detail), ra, rb});
    }
    void caveat(std::string text) {
        if (std::find(d_.caveats.begin(), d_.caveats.end(), text) == d_.caveats.end()) d_.caveats.push_back(std::move(text));
    }

private:
    StructuralDiff& d_;
    const DiffOptions& o_;
};

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::optional<std::span<const std::uint8_t>> file_bytes(const FileImage& f, const Section& s) {
    if (!s.size || !s.file_range_valid || !f.contains(s.offset, s.size)) return std::nullopt;
    return f.bytes().subspan(static_cast<std::size_t>(s.offset), static_cast<std::size_t>(s.size));
}

std::map<std::string, std::size_t> name_counts(const std::vector<Section>& all) {
    std::map<std::string, std::size_t> n;
    for (const auto& s : all) ++n[s.name];
    return n;
}

bool ambiguous_name(const Section& s, const std::map<std::string, std::size_t>& counts) {
    if (s.name == "<unnamed>" || s.name == "<null>") return true;
    auto it = counts.find(s.name);
    return it != counts.end() && it->second > 1;
}

// Compares two lists of sections/segments matched by Section::id.
void diff_sections(Builder& out, const char* category, const std::vector<Section>& as, const FileImage& fa,
                   const std::vector<Section>& bs, const FileImage& fb, bool positional, std::size_t& moved) {
    std::map<std::string, const Section*> bmap;
    for (const auto& s : bs) bmap[s.id] = &s;
    std::set<std::string> matched;
    const auto counts_a = name_counts(as), counts_b = name_counts(bs);
    for (const auto& x : as) {
        auto it = bmap.find(x.id);
        const auto ra = x.size ? std::optional<ByteRange>({x.offset, x.size}) : std::nullopt;
        if (it == bmap.end()) {
            out.add(ChangeKind::Removed, positional ? Confidence::Heuristic : Confidence::Exact, category, x.name,
                    "present only in A (" + std::to_string(x.size) + " file bytes at " + hex(x.offset) + ")", ra);
            continue;
        }
        matched.insert(x.id);
        const Section& y = *it->second;
        const auto rb = y.size ? std::optional<ByteRange>({y.offset, y.size}) : std::nullopt;
        const bool heuristic = positional || ambiguous_name(x, counts_a) || ambiguous_name(y, counts_b);
        const Confidence conf = heuristic ? Confidence::Heuristic : Confidence::Exact;
        std::vector<std::string> parts;
        if (x.kind != y.kind) parts.push_back("type " + x.kind + " -> " + y.kind);
        if (x.address != y.address) parts.push_back("address " + hex(x.address) + " -> " + hex(y.address));
        if (x.virtual_size != y.virtual_size)
            parts.push_back("memory size " + hex(x.virtual_size) + " -> " + hex(y.virtual_size));
        if (x.size != y.size) parts.push_back("file size " + hex(x.size) + " -> " + hex(y.size));
        if (x.flags != y.flags) parts.push_back("flags " + x.flags_text + " -> " + y.flags_text);

        const auto bx = file_bytes(fa, x), by = file_bytes(fb, y);
        bool content_same = false;
        if (x.size == 0 && y.size == 0) {
            content_same = true;
        } else if (!bx || !by) {
            if (x.size || y.size) {
                parts.push_back("content not compared (data outside file)");
                out.caveat(std::string(category) + " '" + x.name + "': file data is out of range on one side; content not compared.");
            }
        } else if (bx->size() == by->size()) {
            content_same = std::memcmp(bx->data(), by->data(), bx->size()) == 0;
            if (!content_same) {
                const auto d = compare(*bx, *by, 0, 0);
                parts.push_back("content: " + std::to_string(d.changed) + " of " + std::to_string(bx->size()) +
                                " bytes differ");
            }
        } else {
            parts.push_back("content differs (sizes differ; no byte alignment attempted)");
        }
        if (x.offset != y.offset && (x.size || y.size)) {
            if (content_same) ++moved;
            parts.push_back("file offset " + hex(x.offset) + " -> " + hex(y.offset) +
                            (content_same ? " (content identical)" : ""));
        }
        if (parts.empty()) {
            out.add(ChangeKind::Unchanged, conf, category, x.name, "identical", ra, rb);
            continue;
        }
        std::string detail;
        for (const auto& p : parts) detail += (detail.empty() ? "" : "; ") + p;
        if (heuristic)
            detail += positional ? " [matched by type and position]" : " [matched by occurrence order of a duplicate or missing name]";
        out.add(ChangeKind::Modified, conf, category, x.name, detail, ra, rb);
    }
    for (const auto& y : bs)
        if (!matched.count(y.id))
            out.add(ChangeKind::Added, positional ? Confidence::Heuristic : Confidence::Exact, category, y.name,
                    "present only in B (" + std::to_string(y.size) + " file bytes at " + hex(y.offset) + ")", std::nullopt,
                    y.size ? std::optional<ByteRange>({y.offset, y.size}) : std::nullopt);
}

// Set difference over keyed items; duplicate keys are compared by count.
void diff_keys(Builder& out, const char* category, const std::multiset<std::string>& a,
               const std::multiset<std::string>& b) {
    for (auto it = a.begin(); it != a.end(); it = a.upper_bound(*it)) {
        const auto ca = a.count(*it), cb = b.count(*it);
        if (cb == 0) out.add(ChangeKind::Removed, ca > 1 ? Confidence::Heuristic : Confidence::Exact, category, *it, "present only in A");
        else if (ca != cb)
            out.add(ChangeKind::Modified, Confidence::Heuristic, category, *it,
                    "occurs " + std::to_string(ca) + " times in A and " + std::to_string(cb) + " times in B");
        else out.add(ChangeKind::Unchanged, Confidence::Exact, category, *it, "present in both");
    }
    for (auto it = b.begin(); it != b.end(); it = b.upper_bound(*it))
        if (!a.count(*it)) out.add(ChangeKind::Added, b.count(*it) > 1 ? Confidence::Heuristic : Confidence::Exact, category, *it, "present only in B");
}

std::string import_key(const Import& i) {
    return lower(i.library) + "!" + (i.ordinal ? "#" + std::to_string(*i.ordinal) : i.name) + (i.delayed ? " (delay-load)" : "");
}

} // namespace

StructuralDiff diff_structure(const Analysis& a, const FileImage& fa, const Analysis& b, const FileImage& fb,
                              const DiffOptions& options) {
    StructuralDiff d;
    d.path_a = a.path;
    d.path_b = b.path;
    d.raw = compare(fa, fb);
    Builder out(d, options);

    if (d.raw.size_a != d.raw.size_b)
        out.caveat("Files differ in size. The raw comparison is positional: bytes after an insertion or deletion are "
                   "not realigned, so the raw change count overstates edits that shift data.");
    if (a.has_errors()) out.caveat("A has structural errors; metadata derived from malformed structures may be incomplete.");
    if (b.has_errors()) out.caveat("B has structural errors; metadata derived from malformed structures may be incomplete.");

    if (a.format != b.format) {
        out.add(ChangeKind::Modified, Confidence::NotComparable, "header", "format",
                std::string(format_name(a.format)) + " -> " + format_name(b.format));
        out.caveat("The files have different formats; only the raw byte comparison is meaningful.");
        return d;
    }
    if (a.format == Format::Unknown) {
        out.caveat("Neither file is a recognized PE or ELF image; only the raw byte comparison was performed.");
        return d;
    }

    auto field = [&](const char* name, const std::string& x, const std::string& y) {
        out.add(x == y ? ChangeKind::Unchanged : ChangeKind::Modified, Confidence::Exact, "header", name,
                x == y ? x : x + " -> " + y);
    };
    field("architecture", a.architecture, b.architecture);
    field("bitness", a.bitness, b.bitness);
    field("byte order", a.byte_order, b.byte_order);
    field("file type", a.file_type, b.file_type);
    field("entry point", hex(a.entry_point), hex(b.entry_point));
    if (a.format == Format::PE) field("image base", hex(a.image_base), hex(b.image_base));
    if (a.architecture != b.architecture)
        out.caveat("Architectures differ; code and relocation changes are not comparable.");

    // Properties are compared by key; values are display strings.
    std::map<std::string, std::string> pa, pb;
    for (const auto& [k, v] : a.properties) pa.emplace(k, v);
    for (const auto& [k, v] : b.properties) pb.emplace(k, v);
    for (const auto& [k, v] : pa) {
        auto it = pb.find(k);
        if (it == pb.end()) out.add(ChangeKind::Removed, Confidence::Exact, "property", k, v);
        else if (it->second != v) out.add(ChangeKind::Modified, Confidence::Exact, "property", k, v + " -> " + it->second);
        else out.add(ChangeKind::Unchanged, Confidence::Exact, "property", k, v);
    }
    for (const auto& [k, v] : pb)
        if (!pa.count(k)) out.add(ChangeKind::Added, Confidence::Exact, "property", k, v);
    if (pa.count("COFF timestamp") && pa["COFF timestamp"] != pb["COFF timestamp"])
        out.caveat("COFF timestamps differ; this is expected for any rebuild and says nothing about code changes.");

    std::size_t moved = 0;
    diff_sections(out, "section", a.sections, fa, b.sections, fb, false, moved);
    diff_sections(out, "segment", a.segments, fa, b.segments, fb, true, moved);
    if (moved)
        out.caveat(std::to_string(moved) + " section(s)/segment(s) moved to a different file offset with identical "
                   "content; the raw byte comparison counts every shifted byte as changed.");

    for (const auto& x : a.directories) {
        auto it = std::find_if(b.directories.begin(), b.directories.end(), [&](const Directory& y) { return y.name == x.name; });
        if (it == b.directories.end()) {
            if (x.status != "empty") out.add(ChangeKind::Removed, Confidence::Exact, "directory", x.name, "only in A");
            continue;
        }
        if (x.address == it->address && x.size == it->size)
            out.add(ChangeKind::Unchanged, Confidence::Exact, "directory", x.name, x.status);
        else
            out.add(ChangeKind::Modified, Confidence::Exact, "directory", x.name,
                    "[" + hex(x.address) + ", +" + hex(x.size) + ") -> [" + hex(it->address) + ", +" + hex(it->size) + ")");
    }

    std::multiset<std::string> ia, ib;
    for (const auto& i : a.imports) ia.insert(import_key(i));
    for (const auto& i : b.imports) ib.insert(import_key(i));
    diff_keys(out, "import", ia, ib);

    // Exports: keyed by name, or by ordinal when unnamed. RVA moves are
    // expected after any rebuild and are summarized instead of listed.
    std::map<std::string, const Export*> ea, eb;
    for (const auto& e : a.exports) ea.emplace(e.name.empty() ? "#" + std::to_string(e.ordinal) : e.name, &e);
    for (const auto& e : b.exports) eb.emplace(e.name.empty() ? "#" + std::to_string(e.ordinal) : e.name, &e);
    std::size_t export_moves = 0;
    for (const auto& [k, x] : ea) {
        auto it = eb.find(k);
        if (it == eb.end()) {
            out.add(ChangeKind::Removed, Confidence::Exact, "export", k, "present only in A");
            continue;
        }
        const Export& y = *it->second;
        std::string detail;
        if (x->ordinal != y.ordinal) detail += "ordinal " + std::to_string(x->ordinal) + " -> " + std::to_string(y.ordinal);
        if (x->forwarder != y.forwarder)
            detail += (detail.empty() ? "" : "; ") + std::string("forwarder '") + x->forwarder + "' -> '" + y.forwarder + "'";
        if (x->rva != y.rva) ++export_moves;
        out.add(detail.empty() ? ChangeKind::Unchanged : ChangeKind::Modified, Confidence::Exact, "export", k,
                detail.empty() ? "same ordinal and forwarder" : detail);
    }
    for (const auto& [k, y] : eb)
        if (!ea.count(k)) out.add(ChangeKind::Added, Confidence::Exact, "export", k, "present only in B");
    if (export_moves)
        out.caveat(std::to_string(export_moves) + " export(s) changed RVA; address changes are expected after relinking "
                   "and are not listed individually.");

    std::multiset<std::string> sa, sb;
    auto symbol_key = [](const Symbol& s) {
        return s.table + ":" + s.name + (s.version.empty() ? "" : "@" + s.version) + " (" + s.type + ", " + s.bind + ")";
    };
    for (const auto& s : a.symbols)
        if (!s.name.empty() && s.type != "SECTION" && s.type != "FILE") sa.insert(symbol_key(s));
    for (const auto& s : b.symbols)
        if (!s.name.empty() && s.type != "SECTION" && s.type != "FILE") sb.insert(symbol_key(s));
    diff_keys(out, "symbol", sa, sb);
    if (!sa.empty() || !sb.empty())
        out.caveat("Symbols are compared by table, name, type and binding; value (address) changes are not reported "
                   "because they change on almost every relink.");

    std::multiset<std::string> na, nb;
    for (const auto& e : a.dynamic)
        if (e.tag == 1) na.insert(e.text);
    for (const auto& e : b.dynamic)
        if (e.tag == 1) nb.insert(e.text);
    diff_keys(out, "dynamic", na, nb);

    std::map<std::string, std::string> notes_a, notes_b;
    for (const auto& n : a.notes) notes_a[n.owner + " " + n.type_name] = n.description;
    for (const auto& n : b.notes) notes_b[n.owner + " " + n.type_name] = n.description;
    for (const auto& [k, v] : notes_a) {
        auto it = notes_b.find(k);
        if (it == notes_b.end()) out.add(ChangeKind::Removed, Confidence::Exact, "note", k, v);
        else out.add(it->second == v ? ChangeKind::Unchanged : ChangeKind::Modified, Confidence::Exact, "note", k,
                     it->second == v ? v : v + " -> " + it->second);
    }
    for (const auto& [k, v] : notes_b)
        if (!notes_a.count(k)) out.add(ChangeKind::Added, Confidence::Exact, "note", k, v);

    // .NET assembly references (name + version + token).
    if (a.dotnet || b.dotnet) {
        std::multiset<std::string> ra_, rb_;
        if (a.dotnet)
            for (const auto& r : a.dotnet->references) ra_.insert(r.name + " " + r.version + " " + r.public_key_token);
        if (b.dotnet)
            for (const auto& r : b.dotnet->references) rb_.insert(r.name + " " + r.version + " " + r.public_key_token);
        diff_keys(out, "dotnet-reference", ra_, rb_);
    }

    // Resources: keyed by type/name/language; content compared byte-wise.
    std::map<std::string, const Resource*> ra, rb;
    auto resource_key = [](const Resource& r) { return r.type + "/" + r.name + "/" + r.language; };
    for (const auto& r : a.resources) ra.emplace(resource_key(r), &r);
    for (const auto& r : b.resources) rb.emplace(resource_key(r), &r);
    auto resource_range = [](const Resource& r) {
        return r.offset ? std::optional<ByteRange>({*r.offset, r.size}) : std::nullopt;
    };
    for (const auto& [k, x] : ra) {
        auto it = rb.find(k);
        if (it == rb.end()) {
            out.add(ChangeKind::Removed, Confidence::Exact, "resource", k, std::to_string(x->size) + " bytes", resource_range(*x));
            continue;
        }
        const Resource& y = *it->second;
        if (!x->offset || !y.offset) {
            out.add(ChangeKind::Modified, Confidence::NotComparable, "resource", k, "data not file-backed on one side");
            continue;
        }
        const auto bx = fa.bytes().subspan(static_cast<std::size_t>(*x->offset), static_cast<std::size_t>(x->size));
        const auto by = fb.bytes().subspan(static_cast<std::size_t>(*y.offset), static_cast<std::size_t>(y.size));
        const bool same = bx.size() == by.size() && std::memcmp(bx.data(), by.data(), bx.size()) == 0;
        out.add(same ? ChangeKind::Unchanged : ChangeKind::Modified, Confidence::Exact, "resource", k,
                same ? "identical" : "size " + std::to_string(x->size) + " -> " + std::to_string(y.size) + ", content differs",
                resource_range(*x), resource_range(y));
    }
    for (const auto& [k, y] : rb)
        if (!ra.count(k))
            out.add(ChangeKind::Added, Confidence::Exact, "resource", k, std::to_string(y->size) + " bytes", std::nullopt,
                    resource_range(*y));
    if (!a.rich.empty() || !b.rich.empty()) {
        auto rich_text = [](const Analysis& x) {
            std::string s;
            for (const auto& r : x.rich)
                s += (s.empty() ? "" : ", ") + hex(r.product_id) + "." + std::to_string(r.build) + "x" + std::to_string(r.count);
            return s.empty() ? std::string("none") : s;
        };
        const auto ta = rich_text(a), tb = rich_text(b);
        out.add(ta == tb ? ChangeKind::Unchanged : ChangeKind::Modified, Confidence::Exact, "header", "Rich header",
                ta == tb ? "same toolchain entries" : "toolchain entries differ: " + ta + " -> " + tb);
    }

    if (!a.certificates.empty() || !b.certificates.empty()) {
        const auto describe = [](const Analysis& x) {
            std::string s;
            for (const auto& c : x.certificates) s += (s.empty() ? "" : ", ") + c.type_name + " " + std::to_string(c.length) + " bytes";
            return s.empty() ? std::string("none") : s;
        };
        const auto da = describe(a), db = describe(b);
        out.add(da == db ? ChangeKind::Unchanged : ChangeKind::Modified, Confidence::NotComparable, "certificate",
                "certificate table", da == db ? da : da + " -> " + db);
        out.caveat("Certificate tables are compared by entry type and length only; signatures are not verified, so "
                   "equal metadata does not imply the same signer.");
    }
    if (d.truncated)
        out.caveat("The change list was truncated at " + std::to_string(options.max_changes) + " entries.");
    return d;
}

} // namespace bw
