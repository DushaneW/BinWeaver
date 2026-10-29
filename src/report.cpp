#include "binweaver/binweaver.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace bw {
namespace {

std::string esc(std::string_view s) {
    std::string o = "\"";
    for (char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        if (c == '"') o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else if (c < 32 || c == 0x7f) {
            static constexpr char h[] = "0123456789abcdef";
            o += "\\u00";
            o += h[c >> 4];
            o += h[c & 15];
        } else o += static_cast<char>(c);
    }
    return o + "\"";
}

// Minimal streaming JSON writer: tracks whether a separator is needed.
class Json {
public:
    explicit Json(std::ostringstream& o) : o_(o) {}
    Json& key(std::string_view k) {
        sep();
        o_ << esc(k) << ": ";
        pending_value_ = true;
        return *this;
    }
    Json& str(std::string_view v) { return raw(esc(v)); }
    Json& num(std::uint64_t v) { return raw(std::to_string(v)); }
    Json& snum(std::int64_t v) { return raw(std::to_string(v)); }
    Json& real(double v) {
        std::ostringstream t;
        t << std::fixed << std::setprecision(4) << v;
        return raw(t.str());
    }
    Json& boolean(bool v) { return raw(v ? "true" : "false"); }
    Json& null() { return raw("null"); }
    Json& begin_object() { return open('{'); }
    Json& end_object() { return close('}'); }
    Json& begin_array() { return open('['); }
    Json& end_array() { return close(']'); }

private:
    Json& raw(const std::string& v) {
        sep();
        o_ << v;
        return *this;
    }
    void sep() {
        if (pending_value_) {
            pending_value_ = false;
            return;
        }
        if (!first_.empty()) {
            if (!first_.back()) o_ << ',';
            first_.back() = false;
            o_ << '\n' << std::string(first_.size() * 2, ' ');
        }
    }
    Json& open(char c) {
        sep();
        o_ << c;
        first_.push_back(true);
        return *this;
    }
    Json& close(char c) {
        const bool empty = first_.back();
        first_.pop_back();
        if (!empty) o_ << '\n' << std::string(first_.size() * 2, ' ');
        o_ << c;
        return *this;
    }
    std::ostringstream& o_;
    std::vector<bool> first_;
    bool pending_value_{};
};

void section_json(Json& j, const Section& s) {
    j.begin_object();
    j.key("id").str(s.id).key("index").num(s.index).key("name").str(s.name).key("kind").str(s.kind).key("type").num(s.type);
    j.key("offset").num(s.offset).key("size").num(s.size).key("address").num(s.address);
    j.key("virtual_size").num(s.virtual_size).key("flags").num(s.flags).key("flags_text").str(s.flags_text);
    j.key("alignment").num(s.alignment).key("file_range_valid").boolean(s.file_range_valid);
    j.key("entropy");
    if (s.entropy) j.real(*s.entropy); else j.null();
    j.end_object();
}

std::string pad(std::string s, std::size_t w) {
    s.append(s.size() < w ? w - s.size() : 1, ' ');  // always keep columns separated
    return s;
}

} // namespace

std::string json_report(const Analysis& a) {
    std::ostringstream o;
    Json j(o);
    j.begin_object();
    j.key("schema_version").num(kJsonSchemaVersion);
    j.key("path").str(a.path).key("file_size").num(a.file_size).key("sha256").str(a.sha256);
    j.key("format").str(format_name(a.format)).key("architecture").str(a.architecture).key("bitness").str(a.bitness);
    j.key("byte_order").str(a.byte_order).key("file_type").str(a.file_type);
    if (a.format == Format::PE) j.key("imphash").str(a.imphash);
    j.key("entry_point").num(a.entry_point).key("image_base").num(a.image_base);
    j.key("structurally_valid").boolean(a.structurally_valid);
    j.key("properties").begin_object();
    for (const auto& [k, v] : a.properties) j.key(k).str(v);
    j.end_object();
    j.key("sections").begin_array();
    for (const auto& s : a.sections) section_json(j, s);
    j.end_array();
    j.key("segments").begin_array();
    for (const auto& s : a.segments) section_json(j, s);
    j.end_array();
    j.key("structures").begin_array();
    for (const auto& r : a.structures)
        j.begin_object().key("name").str(r.name).key("kind").str(r.kind).key("offset").num(r.offset).key("size").num(r.size).end_object();
    j.end_array();
    j.key("directories").begin_array();
    for (const auto& d : a.directories) {
        j.begin_object().key("index").num(d.index).key("name").str(d.name).key("address").num(d.address).key("size").num(d.size);
        j.key("file_offset");
        if (d.file_offset) j.num(*d.file_offset); else j.null();
        j.key("status").str(d.status).end_object();
    }
    j.end_array();
    j.key("imports").begin_array();
    for (const auto& i : a.imports) {
        j.begin_object().key("library").str(i.library).key("name").str(i.name).key("ordinal");
        if (i.ordinal) j.num(*i.ordinal); else j.null();
        j.key("hint").num(i.hint).key("delayed").boolean(i.delayed).key("thunk_rva").num(i.thunk_rva).end_object();
    }
    j.end_array();
    j.key("exports").begin_array();
    for (const auto& e : a.exports)
        j.begin_object().key("name").str(e.name).key("ordinal").num(e.ordinal).key("rva").num(e.rva).key("forwarder").str(e.forwarder).end_object();
    j.end_array();
    j.key("symbols").begin_array();
    for (const auto& s : a.symbols)
        j.begin_object().key("table").str(s.table).key("index").num(s.index).key("name").str(s.name).key("value").num(s.value)
            .key("size").num(s.size).key("type").str(s.type).key("bind").str(s.bind).key("visibility").str(s.visibility)
            .key("section_index").num(s.section_index).key("version").str(s.version).end_object();
    j.end_array();
    j.key("dynamic").begin_array();
    for (const auto& d : a.dynamic)
        j.begin_object().key("tag").snum(d.tag).key("tag_name").str(d.tag_name).key("value").num(d.value).key("text").str(d.text).end_object();
    j.end_array();
    j.key("relocations").begin_array();
    for (const auto& r : a.relocations) {
        j.begin_object().key("section").str(r.section).key("offset").num(r.offset).key("type").num(r.type)
            .key("type_name").str(r.type_name).key("symbol_index").num(r.symbol_index).key("symbol").str(r.symbol).key("addend");
        if (r.has_addend) j.snum(r.addend); else j.null();
        j.end_object();
    }
    j.end_array();
    j.key("notes").begin_array();
    for (const auto& n : a.notes)
        j.begin_object().key("source").str(n.source).key("owner").str(n.owner).key("type").num(n.type).key("type_name").str(n.type_name)
            .key("offset").num(n.offset).key("size").num(n.size).key("descriptor_size").num(n.descriptor_size).key("description").str(n.description).end_object();
    j.end_array();
    j.key("resources").begin_array();
    for (const auto& r : a.resources) {
        j.begin_object().key("type").str(r.type).key("name").str(r.name).key("language").str(r.language)
            .key("rva").num(r.rva).key("size").num(r.size).key("codepage").num(r.codepage).key("offset");
        if (r.offset) j.num(*r.offset); else j.null();
        j.end_object();
    }
    j.end_array();
    j.key("signatures").begin_array();
    for (const auto& s : a.signatures) {
        j.begin_object().key("certificate_offset").num(s.certificate_offset).key("digest_algorithm").str(s.digest_algorithm)
            .key("signed_digest").str(s.signed_digest).key("computed_digest").str(s.computed_digest)
            .key("digest_status").str(s.digest_status).key("signer_subject").str(s.signer_subject)
            .key("signer_issuer").str(s.signer_issuer).key("signer_serial").str(s.signer_serial)
            .key("valid_from").str(s.valid_from).key("valid_to").str(s.valid_to).key("certificates").begin_array();
        for (const auto& c : s.certificates) j.str(c);
        j.end_array().end_object();
    }
    j.end_array();
    j.key("functions").begin_array();
    for (const auto& f : a.functions)
        j.begin_object().key("begin").num(f.begin).key("end").num(f.end).key("unwind").num(f.unwind)
            .key("unwind_version").num(f.unwind_version).key("unwind_flags").num(f.unwind_flags).key("prolog_size").num(f.prolog_size)
            .key("code_count").num(f.code_count).key("frame_register").num(f.frame_register).key("frame_offset").num(f.frame_offset)
            .key("handler").num(f.handler).key("chained_begin").num(f.chained_begin).end_object();
    j.end_array();
    j.key("debug_entries").begin_array();
    for (const auto& e : a.debug_entries)
        j.begin_object().key("type").num(e.type).key("type_name").str(e.type_name).key("timestamp").num(e.timestamp)
            .key("size").num(e.size).key("rva").num(e.rva).key("pointer").num(e.pointer).key("detail").str(e.detail).end_object();
    j.end_array();
    j.key("resource_strings").begin_array();
    for (const auto& r : a.resource_strings)
        j.begin_object().key("id").num(r.id).key("language").str(r.language).key("text").str(r.text).end_object();
    j.end_array();
    j.key("dotnet");
    if (!a.dotnet) {
        j.null();
    } else {
        const auto& n = *a.dotnet;
        j.begin_object().key("runtime_header").str(n.runtime_header).key("metadata_version").str(n.metadata_version)
            .key("flags").num(n.flags).key("flags_text").str(n.flags_text).key("entry_point_token").num(n.entry_point_token)
            .key("module").str(n.module_name).key("assembly").str(n.assembly_name).key("version").str(n.assembly_version)
            .key("culture").str(n.assembly_culture).key("public_key_token").str(n.public_key_token);
        j.key("streams").begin_array();
        for (const auto& s : n.streams) j.begin_object().key("name").str(s.name).key("offset").num(s.offset).key("size").num(s.size).end_object();
        j.end_array().key("tables").begin_object();
        for (const auto& t : n.tables) j.key(t.name).num(t.rows);
        j.end_object().key("references").begin_array();
        for (const auto& r : n.references)
            j.begin_object().key("name").str(r.name).key("version").str(r.version).key("culture").str(r.culture)
                .key("public_key_token").str(r.public_key_token).end_object();
        j.end_array().key("module_references").begin_array();
        for (const auto& m : n.module_references) j.str(m);
        j.end_array().end_object();
    }
    j.key("rich").begin_array();
    for (const auto& r : a.rich)
        j.begin_object().key("product_id").num(r.product_id).key("build").num(r.build).key("count").num(r.count).end_object();
    j.end_array();
    j.key("certificates").begin_array();
    for (const auto& c : a.certificates)
        j.begin_object().key("offset").num(c.offset).key("length").num(c.length).key("revision").num(c.revision)
            .key("type").num(c.type).key("type_name").str(c.type_name).end_object();
    j.end_array();
    j.key("diagnostics").begin_array();
    for (const auto& d : a.diagnostics)
        j.begin_object().key("severity").str(severity_name(d.severity)).key("code").str(d.code).key("message").str(d.message)
            .key("offset").num(d.offset).end_object();
    j.end_array();
    j.end_object();
    o << '\n';
    return o.str();
}

std::string text_report(const Analysis& a) {
    constexpr std::size_t kListLimit = 200;
    std::ostringstream o;
    o << "BinWeaver report\n"
      << "File: " << a.path << "\nSize: " << a.file_size << " bytes\nSHA-256: " << a.sha256 << "\nFormat: "
      << format_name(a.format) << " (" << a.file_type << ")\nArchitecture: " << a.architecture << " / " << a.bitness
      << " / " << a.byte_order << "\nEntry point: " << hex(a.entry_point)
      << (a.format == Format::PE ? " (RVA)" : "") << "\nStructural checks: "
      << (a.structurally_valid ? "no structural errors detected" : "structural errors detected") << "\n";
    if (!a.properties.empty()) {
        o << "\nProperties\n";
        for (const auto& [k, v] : a.properties) o << "  " << pad(k, std::max<std::size_t>(24, k.size() + 2)) << v << '\n';
    }
    auto table = [&](const char* title, const std::vector<Section>& list) {
        if (list.empty()) return;
        o << '\n' << title << "\n  " << pad("name", 22) << pad("kind", 18) << pad("offset", 12) << pad("size", 12)
          << pad("address", 20) << pad("vsize", 12) << pad("flags", 14) << "entropy\n";
        for (const auto& s : list) {
            std::ostringstream e;
            if (s.entropy) e << std::fixed << std::setprecision(3) << *s.entropy;
            o << "  " << pad(s.name, 22) << pad(s.kind, 18) << pad(hex(s.offset), 12) << pad(hex(s.size), 12)
              << pad(hex(s.address), 20) << pad(hex(s.virtual_size), 12) << pad(s.flags_text, 14) << e.str()
              << (s.file_range_valid ? "" : "  [outside file]") << '\n';
        }
    };
    table("Sections", a.sections);
    table("Segments", a.segments);
    if (!a.directories.empty()) {
        o << "\nData directories\n";
        for (const auto& d : a.directories)
            if (d.status != "empty")
                o << "  " << pad(d.name, 18) << pad(hex(d.address), 12) << pad(hex(d.size), 12)
                  << (d.file_offset ? "file " + hex(*d.file_offset) + "  " : "") << d.status << '\n';
    }
    if (!a.imports.empty()) {
        o << "\nImports (" << a.imports.size() << ")\n";
        std::size_t n = 0;
        for (const auto& i : a.imports) {
            if (n++ == kListLimit) { o << "  ... " << a.imports.size() - kListLimit << " more (use --json)\n"; break; }
            o << "  " << i.library << '!' << (i.ordinal ? "#" + std::to_string(*i.ordinal) : i.name)
              << (i.delayed ? "  [delay-load]" : "") << '\n';
        }
    }
    if (!a.exports.empty()) {
        o << "\nExports (" << a.exports.size() << ")\n";
        std::size_t n = 0;
        for (const auto& e : a.exports) {
            if (n++ == kListLimit) { o << "  ... " << a.exports.size() - kListLimit << " more (use --json)\n"; break; }
            o << "  #" << pad(std::to_string(e.ordinal), 6) << pad(hex(e.rva), 12) << (e.name.empty() ? "<ordinal only>" : e.name)
              << (e.forwarder.empty() ? "" : "  -> " + e.forwarder) << '\n';
        }
    }
    if (!a.dynamic.empty()) {
        o << "\nDynamic entries (" << a.dynamic.size() << ")\n";
        for (const auto& d : a.dynamic) o << "  " << pad(d.tag_name, 20) << pad(hex(d.value), 20) << d.text << '\n';
    }
    if (!a.symbols.empty()) o << "\nSymbols: " << a.symbols.size() << " (listed in --json output)\n";
    if (!a.relocations.empty()) o << "Relocations: " << a.relocations.size() << " (listed in --json output)\n";
    if (!a.notes.empty()) {
        o << "\nNotes\n";
        for (const auto& n : a.notes) o << "  " << pad(n.owner, 8) << pad(n.type_name, 26) << n.description << '\n';
    }
    if (!a.certificates.empty()) {
        o << "\nCertificate table (metadata only; signatures not verified)\n";
        for (const auto& c : a.certificates)
            o << "  offset " << hex(c.offset) << "  length " << c.length << "  revision " << hex(c.revision) << "  " << c.type_name << '\n';
    }
    if (!a.resources.empty()) {
        o << "\nResources (" << a.resources.size() << ")\n";
        std::size_t n = 0;
        for (const auto& r : a.resources) {
            if (n++ == kListLimit) { o << "  ... " << a.resources.size() - kListLimit << " more (use --json)\n"; break; }
            o << "  " << pad(r.type, 16) << pad(r.name, 22) << pad(r.language, 8) << pad(hex(r.size), 10)
              << (r.offset ? "file " + hex(*r.offset) : std::string("not file-backed")) << '\n';
        }
    }
    for (const auto& s : a.signatures) {
        o << "\nAuthenticode signature (metadata and image digest only; signature and chain NOT verified)\n"
          << "  signer   " << s.signer_subject << "\n  issuer   " << s.signer_issuer << "\n  serial   " << s.signer_serial
          << "\n  validity " << s.valid_from << " .. " << s.valid_to << "\n  digest   " << s.digest_algorithm << " "
          << s.digest_status << "\n";
        for (const auto& c : s.certificates) o << "  cert     " << c << '\n';
    }
    if (a.dotnet) {
        const auto& n = *a.dotnet;
        o << "\n.NET metadata (IL, signatures and custom attributes not decoded)\n  runtime  " << n.metadata_version
          << " (CLR header " << n.runtime_header << "), flags " << n.flags_text << "\n  module   " << n.module_name << '\n';
        if (!n.assembly_name.empty())
            o << "  assembly " << n.assembly_name << " " << n.assembly_version << " token " << n.public_key_token << '\n';
        o << "  streams ";
        for (const auto& s : n.streams) o << ' ' << s.name << " (" << s.size << ")";
        o << "\n  tables  ";
        for (const auto& t : n.tables) o << ' ' << t.name << "=" << t.rows;
        o << '\n';
        for (const auto& r : n.references)
            o << "  ref      " << r.name << " " << r.version << " token " << r.public_key_token << '\n';
        for (const auto& m : n.module_references) o << "  pinvoke  " << m << '\n';
    }
    if (!a.rich.empty()) {
        o << "\nRich header (product id / build / count; product ids are not mapped to tool names)\n";
        for (const auto& r : a.rich)
            o << "  " << pad(hex(r.product_id), 10) << pad(std::to_string(r.build), 10) << r.count << '\n';
    }
    o << "\nDiagnostics (" << a.diagnostics.size() << ")\n";
    for (const auto& d : a.diagnostics)
        o << "  " << pad(severity_name(d.severity), 8) << pad("[" + d.code + "]", 34) << pad(hex(d.offset), 12) << d.message << '\n';
    o << "\nStructural analysis is not a malware verdict.\n";
    return o.str();
}

namespace {
std::string html(std::string_view s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&': o += "&amp;"; break;
        case '<': o += "&lt;"; break;
        case '>': o += "&gt;"; break;
        case '"': o += "&quot;"; break;
        case '\'': o += "&#39;"; break;
        default: o += c;
        }
    }
    return o;
}

struct HtmlTable {
    std::ostringstream& o;
    HtmlTable(std::ostringstream& out, const std::string& title, std::initializer_list<const char*> head, std::size_t rows)
        : o(out) {
        o << "<h2>" << html(title) << " <small>(" << rows << ")</small></h2>\n<table><thead><tr>";
        for (const char* h : head) o << "<th>" << h << "</th>";
        o << "</tr></thead><tbody>\n";
    }
    void row(std::initializer_list<std::string> cells) {
        o << "<tr>";
        for (const auto& c : cells) o << "<td>" << html(c) << "</td>";
        o << "</tr>\n";
    }
    ~HtmlTable() { o << "</tbody></table>\n"; }
};
} // namespace

std::string html_report(const Analysis& a) {
    constexpr std::size_t kRows = 5000;  // per table; the JSON report has everything
    std::ostringstream o;
    o << "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<title>BinWeaver report: " << html(a.path)
      << "</title>\n<style>\n"
         ":root{--bg:#fff;--fg:#1d2329;--muted:#5c6773;--line:#d8dde3;--head:#f2f4f7;--bad:#b42318;--warn:#9a6700}\n"
         "@media (prefers-color-scheme:dark){:root{--bg:#15191e;--fg:#e2e6ea;--muted:#98a2ad;--line:#2c333b;--head:#1d232a;"
         "--bad:#ff8f84;--warn:#e3b341}}\n"
         "body{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif;margin:24px;max-width:1400px}\n"
         "h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}small{color:var(--muted);font-weight:normal}\n"
         "table{border-collapse:collapse;width:100%;font:12px/1.4 ui-monospace,Consolas,monospace}\n"
         "th,td{border-bottom:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top;word-break:break-all}\n"
         "th{background:var(--head);position:sticky;top:0}.error{color:var(--bad)}.warning{color:var(--warn)}\n"
         "p.note{color:var(--muted)}\n</style></head><body>\n";
    o << "<h1>" << html(a.path) << "</h1>\n<p class=\"note\">" << html(format_name(a.format)) << " · " << html(a.file_type)
      << " · " << html(a.architecture) << " · " << html(a.bitness) << " · " << a.file_size << " bytes · "
      << (a.structurally_valid ? "no structural errors" : "<span class=\"error\">structural errors</span>")
      << "<br>Generated by BinWeaver. Structural analysis is not a malware verdict; signatures are not verified.</p>\n";
    {
        HtmlTable t(o, "Summary", {"Property", "Value"}, a.properties.size() + 3);
        t.row({"SHA-256", a.sha256});
        t.row({"Entry point", hex(a.entry_point)});
        if (!a.imphash.empty()) t.row({"Imphash", a.imphash});
        for (const auto& [k, v] : a.properties) t.row({k, v});
    }
    if (!a.diagnostics.empty()) {
        o << "<h2>Diagnostics <small>(" << a.diagnostics.size() << ")</small></h2>\n<table><thead><tr><th>Severity</th><th>Code</th>"
             "<th>Offset</th><th>Message</th></tr></thead><tbody>\n";
        std::size_t n = 0;
        for (const auto& d : a.diagnostics) {
            if (n++ == kRows) break;
            o << "<tr class=\"" << severity_name(d.severity) << "\"><td>" << severity_name(d.severity) << "</td><td>"
              << html(d.code) << "</td><td>" << hex(d.offset) << "</td><td>" << html(d.message) << "</td></tr>\n";
        }
        o << "</tbody></table>\n";
    }
    auto sections = [&](const char* title, const std::vector<Section>& list) {
        if (list.empty()) return;
        HtmlTable t(o, title, {"Name", "Type", "File offset", "File size", "Address", "Memory size", "Flags", "Entropy"}, list.size());
        std::size_t n = 0;
        for (const auto& s : list) {
            if (n++ == kRows) break;
            std::ostringstream e;
            if (s.entropy) e << std::fixed << std::setprecision(3) << *s.entropy;
            t.row({s.name, s.kind, hex(s.offset), hex(s.size), hex(s.address), hex(s.virtual_size), s.flags_text, e.str()});
        }
    };
    sections("Sections", a.sections);
    sections("Segments", a.segments);
    if (!a.imports.empty()) {
        HtmlTable t(o, "Imports", {"Library", "Name / ordinal", "Load"}, a.imports.size());
        std::size_t n = 0;
        for (const auto& i : a.imports) {
            if (n++ == kRows) break;
            t.row({i.library, i.ordinal ? "#" + std::to_string(*i.ordinal) : i.name, i.delayed ? "delay-load" : "startup"});
        }
    }
    if (!a.exports.empty()) {
        HtmlTable t(o, "Exports", {"Ordinal", "Name", "RVA", "Forwarder"}, a.exports.size());
        std::size_t n = 0;
        for (const auto& e : a.exports) {
            if (n++ == kRows) break;
            t.row({std::to_string(e.ordinal), e.name, hex(e.rva), e.forwarder});
        }
    }
    if (!a.dynamic.empty()) {
        HtmlTable t(o, "Dynamic", {"Tag", "Value", "Meaning"}, a.dynamic.size());
        for (const auto& d : a.dynamic) t.row({d.tag_name, hex(d.value), d.text});
    }
    for (const auto& s : a.signatures) {
        HtmlTable t(o, "Authenticode signature (not verified)", {"Field", "Value"}, 6);
        t.row({"Signer", s.signer_subject});
        t.row({"Issuer", s.signer_issuer});
        t.row({"Serial", s.signer_serial});
        t.row({"Validity", s.valid_from + " .. " + s.valid_to});
        t.row({"Digest", s.digest_algorithm + ": " + s.digest_status});
        t.row({"Certificates", std::to_string(s.certificates.size())});
    }
    if (a.dotnet) {
        HtmlTable t(o, ".NET references", {"Assembly", "Version", "Public key token"}, a.dotnet->references.size());
        for (const auto& r : a.dotnet->references) t.row({r.name, r.version, r.public_key_token});
    }
    o << "</body></html>\n";
    return o.str();
}

std::string json_report(const StructuralDiff& d) {
    std::ostringstream o;
    Json j(o);
    j.begin_object();
    j.key("schema_version").num(kJsonSchemaVersion);
    j.key("path_a").str(d.path_a).key("path_b").str(d.path_b);
    j.key("raw").begin_object();
    j.key("size_a").num(d.raw.size_a).key("size_b").num(d.raw.size_b).key("compared").num(d.raw.compared);
    j.key("changed").num(d.raw.changed).key("changed_percent").real(d.raw.changed_percent);
    j.key("longest_equal").num(d.raw.longest_equal).key("longest_changed").num(d.raw.longest_changed);
    j.key("changed_ranges").num(d.raw.ranges.size()).key("ranges_truncated").boolean(d.raw.ranges_truncated);
    j.end_object();
    j.key("summary").begin_object();
    for (auto k : {ChangeKind::Added, ChangeKind::Removed, ChangeKind::Modified, ChangeKind::Unchanged})
        j.key(change_kind_name(k)).num(d.count(k));
    j.key("truncated").boolean(d.truncated).end_object();
    j.key("changes").begin_array();
    for (const auto& c : d.changes) {
        j.begin_object().key("category").str(c.category).key("subject").str(c.subject).key("kind").str(change_kind_name(c.kind))
            .key("confidence").str(confidence_name(c.confidence)).key("detail").str(c.detail);
        for (auto [name, r] : {std::pair{"range_a", &c.range_a}, std::pair{"range_b", &c.range_b}}) {
            j.key(name);
            if (*r) j.begin_object().key("offset").num((*r)->offset).key("size").num((*r)->size).end_object();
            else j.null();
        }
        j.end_object();
    }
    j.end_array();
    j.key("caveats").begin_array();
    for (const auto& c : d.caveats) j.str(c);
    j.end_array();
    j.end_object();
    o << '\n';
    return o.str();
}

std::string text_report(const StructuralDiff& d) {
    std::ostringstream o;
    o << "BinWeaver structural comparison\nA: " << d.path_a << "\nB: " << d.path_b << "\n\nRaw bytes\n"
      << "  sizes " << d.raw.size_a << " / " << d.raw.size_b << ", " << d.raw.changed << " bytes differ ("
      << std::fixed << std::setprecision(2) << d.raw.changed_percent << "%), " << d.raw.ranges.size()
      << (d.raw.ranges_truncated ? "+" : "") << " changed runs in the common prefix\n"
      << "  longest equal run " << d.raw.longest_equal << ", longest changed run " << d.raw.longest_changed << "\n\n"
      << "Structure: " << d.count(ChangeKind::Added) << " added, " << d.count(ChangeKind::Removed) << " removed, "
      << d.count(ChangeKind::Modified) << " modified" << (d.truncated ? " (truncated)" : "") << "\n";
    std::string category;
    for (const auto& c : d.changes) {
        if (c.kind == ChangeKind::Unchanged) continue;
        if (c.category != category) {
            category = c.category;
            o << '\n' << category << '\n';
        }
        const char mark = c.kind == ChangeKind::Added ? '+' : c.kind == ChangeKind::Removed ? '-' : '~';
        o << "  " << mark << ' ' << pad(c.subject, 30) << c.detail
          << (c.confidence == Confidence::Exact ? "" : std::string("  (") + confidence_name(c.confidence) + ")") << '\n';
    }
    if (!d.caveats.empty()) {
        o << "\nWhat could not be compared reliably\n";
        for (const auto& c : d.caveats) o << "  * " << c << '\n';
    }
    return o.str();
}

} // namespace bw
