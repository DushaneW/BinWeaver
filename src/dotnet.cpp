// .NET (CLI) metadata, ECMA-335 partition II: CLR header (§II.25.3.3),
// metadata root and streams (§II.24.2), and the #~ table stream (§II.24.2.6)
// far enough to compute every table's row size, which is what reading the
// Module, Assembly and AssemblyRef rows requires. IL, signatures, custom
// attributes and resources are not decoded.
#include "internal.hpp"

#include <algorithm>
#include <array>

namespace bw::detail {
namespace {

// Table ids (§II.22).
enum : std::uint8_t {
    Module = 0x00, TypeRef = 0x01, TypeDef = 0x02, FieldPtr = 0x03, Field = 0x04, MethodPtr = 0x05, MethodDef = 0x06,
    ParamPtr = 0x07, Param = 0x08, InterfaceImpl = 0x09, MemberRef = 0x0a, Constant = 0x0b, CustomAttribute = 0x0c,
    FieldMarshal = 0x0d, DeclSecurity = 0x0e, ClassLayout = 0x0f, FieldLayout = 0x10, StandAloneSig = 0x11,
    EventMap = 0x12, EventPtr = 0x13, Event = 0x14, PropertyMap = 0x15, PropertyPtr = 0x16, Property = 0x17,
    MethodSemantics = 0x18, MethodImpl = 0x19, ModuleRef = 0x1a, TypeSpec = 0x1b, ImplMap = 0x1c, FieldRVA = 0x1d,
    EncLog = 0x1e, EncMap = 0x1f, Assembly = 0x20, AssemblyProcessor = 0x21, AssemblyOS = 0x22, AssemblyRef = 0x23,
    AssemblyRefProcessor = 0x24, AssemblyRefOS = 0x25, File = 0x26, ExportedType = 0x27, ManifestResource = 0x28,
    NestedClass = 0x29, GenericParam = 0x2a, MethodSpec = 0x2b, GenericParamConstraint = 0x2c, kTableCount = 0x2d
};

constexpr std::array<const char*, kTableCount> kTableNames = {
    "Module", "TypeRef", "TypeDef", "FieldPtr", "Field", "MethodPtr", "MethodDef", "ParamPtr", "Param",
    "InterfaceImpl", "MemberRef", "Constant", "CustomAttribute", "FieldMarshal", "DeclSecurity", "ClassLayout",
    "FieldLayout", "StandAloneSig", "EventMap", "EventPtr", "Event", "PropertyMap", "PropertyPtr", "Property",
    "MethodSemantics", "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA", "EncLog", "EncMap", "Assembly",
    "AssemblyProcessor", "AssemblyOS", "AssemblyRef", "AssemblyRefProcessor", "AssemblyRefOS", "File",
    "ExportedType", "ManifestResource", "NestedClass", "GenericParam", "MethodSpec", "GenericParamConstraint"};

// Column kinds. Coded indexes (§II.24.2.6) list their target tables; 0xff
// marks unused tags (CustomAttributeType).
enum class Col : std::uint8_t { U8x2, U16, U32, Str, Guid, Blob, Index, Coded };
struct Column {
    Col kind;
    std::uint8_t table = 0;            // for Index
    const std::uint8_t* coded = nullptr;  // for Coded: {count, tables...}
};

constexpr std::uint8_t kTypeDefOrRef[] = {3, TypeDef, TypeRef, TypeSpec};
constexpr std::uint8_t kHasConstant[] = {3, Field, Param, Property};
constexpr std::uint8_t kHasCustomAttribute[] = {22, MethodDef, Field, TypeRef, TypeDef, Param, InterfaceImpl, MemberRef,
                                               Module, DeclSecurity, Property, Event, StandAloneSig, ModuleRef, TypeSpec,
                                               Assembly, AssemblyRef, File, ExportedType, ManifestResource, GenericParam,
                                               GenericParamConstraint, MethodSpec};
constexpr std::uint8_t kHasFieldMarshal[] = {2, Field, Param};
constexpr std::uint8_t kHasDeclSecurity[] = {3, TypeDef, MethodDef, Assembly};
constexpr std::uint8_t kMemberRefParent[] = {5, TypeDef, TypeRef, ModuleRef, MethodDef, TypeSpec};
constexpr std::uint8_t kHasSemantics[] = {2, Event, Property};
constexpr std::uint8_t kMethodDefOrRef[] = {2, MethodDef, MemberRef};
constexpr std::uint8_t kMemberForwarded[] = {2, Field, MethodDef};
constexpr std::uint8_t kImplementation[] = {3, File, AssemblyRef, ExportedType};
constexpr std::uint8_t kCustomAttributeType[] = {5, 0xff, 0xff, MethodDef, MemberRef, 0xff};
constexpr std::uint8_t kResolutionScope[] = {4, Module, ModuleRef, AssemblyRef, TypeRef};
constexpr std::uint8_t kTypeOrMethodDef[] = {2, TypeDef, MethodDef};

constexpr Column U16{Col::U16}, U32{Col::U32}, STR{Col::Str}, GUID{Col::Guid}, BLOB{Col::Blob};
constexpr Column idx(std::uint8_t t) { return {Col::Index, t, nullptr}; }
constexpr Column coded(const std::uint8_t* c) { return {Col::Coded, 0, c}; }

const std::vector<std::vector<Column>>& schema() {
    static const std::vector<std::vector<Column>> s = {
        /*Module*/ {U16, STR, GUID, GUID, GUID},
        /*TypeRef*/ {coded(kResolutionScope), STR, STR},
        /*TypeDef*/ {U32, STR, STR, coded(kTypeDefOrRef), idx(Field), idx(MethodDef)},
        /*FieldPtr*/ {idx(Field)},
        /*Field*/ {U16, STR, BLOB},
        /*MethodPtr*/ {idx(MethodDef)},
        /*MethodDef*/ {U32, U16, U16, STR, BLOB, idx(Param)},
        /*ParamPtr*/ {idx(Param)},
        /*Param*/ {U16, U16, STR},
        /*InterfaceImpl*/ {idx(TypeDef), coded(kTypeDefOrRef)},
        /*MemberRef*/ {coded(kMemberRefParent), STR, BLOB},
        /*Constant*/ {{Col::U8x2}, coded(kHasConstant), BLOB},
        /*CustomAttribute*/ {coded(kHasCustomAttribute), coded(kCustomAttributeType), BLOB},
        /*FieldMarshal*/ {coded(kHasFieldMarshal), BLOB},
        /*DeclSecurity*/ {U16, coded(kHasDeclSecurity), BLOB},
        /*ClassLayout*/ {U16, U32, idx(TypeDef)},
        /*FieldLayout*/ {U32, idx(Field)},
        /*StandAloneSig*/ {BLOB},
        /*EventMap*/ {idx(TypeDef), idx(Event)},
        /*EventPtr*/ {idx(Event)},
        /*Event*/ {U16, STR, coded(kTypeDefOrRef)},
        /*PropertyMap*/ {idx(TypeDef), idx(Property)},
        /*PropertyPtr*/ {idx(Property)},
        /*Property*/ {U16, STR, BLOB},
        /*MethodSemantics*/ {U16, idx(MethodDef), coded(kHasSemantics)},
        /*MethodImpl*/ {idx(TypeDef), coded(kMethodDefOrRef), coded(kMethodDefOrRef)},
        /*ModuleRef*/ {STR},
        /*TypeSpec*/ {BLOB},
        /*ImplMap*/ {U16, coded(kMemberForwarded), STR, idx(ModuleRef)},
        /*FieldRVA*/ {U32, idx(Field)},
        /*EncLog*/ {U32, U32},
        /*EncMap*/ {U32},
        /*Assembly*/ {U32, U16, U16, U16, U16, U32, BLOB, STR, STR},
        /*AssemblyProcessor*/ {U32},
        /*AssemblyOS*/ {U32, U32, U32},
        /*AssemblyRef*/ {U16, U16, U16, U16, U32, BLOB, STR, STR, BLOB},
        /*AssemblyRefProcessor*/ {U32, idx(AssemblyRef)},
        /*AssemblyRefOS*/ {U32, U32, U32, idx(AssemblyRef)},
        /*File*/ {U32, STR, BLOB},
        /*ExportedType*/ {U32, U32, STR, STR, coded(kImplementation)},
        /*ManifestResource*/ {U32, U32, STR, coded(kImplementation)},
        /*NestedClass*/ {idx(TypeDef), idx(TypeDef)},
        /*GenericParam*/ {U16, U16, coded(kTypeOrMethodDef), STR},
        /*MethodSpec*/ {coded(kMethodDefOrRef), BLOB},
        /*GenericParamConstraint*/ {idx(GenericParam), coded(kTypeDefOrRef)},
    };
    return s;
}

// File-backed bytes for [rva, rva + size), only if contiguous in one mapping.
std::optional<std::span<const std::uint8_t>> rva_span(const FileImage& f, const Analysis& a, std::uint64_t rva,
                                                      std::uint64_t size) {
    if (size == 0) return std::nullopt;
    const auto first = address_to_offset(a, rva);
    const auto last = address_to_offset(a, rva + size - 1);
    if (first.status != MapStatus::FileBacked || last.status != MapStatus::FileBacked || first.mapping != last.mapping ||
        last.offset - first.offset != size - 1)
        return std::nullopt;
    return ByteView(f.bytes()).slice(first.offset, size);
}

class TableReader {
public:
    TableReader(std::span<const std::uint8_t> tables, std::uint8_t heap_sizes, const std::array<std::uint32_t, 64>& rows)
        : rows_(rows), heap_sizes_(heap_sizes), v_(tables) {}

    std::uint32_t width(const Column& c) const {
        switch (c.kind) {
        case Col::U8x2:
        case Col::U16: return 2;
        case Col::U32: return 4;
        case Col::Str: return (heap_sizes_ & 1) ? 4 : 2;
        case Col::Guid: return (heap_sizes_ & 2) ? 4 : 2;
        case Col::Blob: return (heap_sizes_ & 4) ? 4 : 2;
        case Col::Index: return rows_[c.table] > 0xffff ? 4 : 2;
        case Col::Coded: {
            const std::uint8_t n = c.coded[0];
            std::uint32_t bits = 0;
            while ((1u << bits) < n) ++bits;
            std::uint32_t max_rows = 0;
            for (std::uint8_t k = 1; k <= n; ++k)
                if (c.coded[k] != 0xff) max_rows = std::max(max_rows, rows_[c.coded[k]]);
            return max_rows < (1u << (16 - bits)) ? 2 : 4;
        }
        }
        return 2;
    }
    std::uint32_t row_size(std::uint8_t table) const {
        std::uint32_t s = 0;
        for (const auto& c : schema()[table]) s += width(c);
        return s;
    }
    // Reads column `col` of `row` (0-based) of `table`, given the table's byte offset.
    std::optional<std::uint32_t> cell(std::uint64_t table_offset, std::uint8_t table, std::uint32_t row, std::size_t col) const {
        const auto& cols = schema()[table];
        std::uint64_t at = table_offset + std::uint64_t{row} * row_size(table);
        for (std::size_t k = 0; k < col; ++k) at += width(cols[k]);
        const auto w = width(cols[col]);
        if (w == 2) {
            auto v = v_.u16(at);
            return v ? std::optional<std::uint32_t>(*v) : std::nullopt;
        }
        return v_.u32(at);
    }

private:
    const std::array<std::uint32_t, 64>& rows_;
    std::uint8_t heap_sizes_;
    ByteView v_;
};

} // namespace

void decode_clr(const FileImage& f, Analysis& a, std::uint64_t clr_rva, std::uint64_t clr_size) {
    DotNetInfo net;
    auto fail = [&](std::string_view code, const std::string& why) {
        diag(a, code, why, 0);
        a.dotnet = std::move(net);
    };
    const auto header = rva_span(f, a, clr_rva, std::min<std::uint64_t>(clr_size, 72));
    if (!header || header->size() < 72) return fail("pe.clr.header", "CLR header is shorter than 72 bytes or not file-backed.");
    const Record h(*header, Endian::Little);
    net.runtime_header = std::to_string(h.u16(4)) + "." + std::to_string(h.u16(6));
    net.flags = h.u32(16);
    net.flags_text = join_flags_text(net.flags, {{0x1, "ILONLY"}, {0x2, "32BITREQUIRED"}, {0x4, "IL_LIBRARY"},
                                                 {0x8, "STRONGNAMESIGNED"}, {0x10, "NATIVE_ENTRYPOINT"},
                                                 {0x10000, "TRACKDEBUGDATA"}, {0x20000, "32BITPREFERRED"}});
    net.entry_point_token = h.u32(20);
    const std::uint32_t md_rva = h.u32(8), md_size = h.u32(12);

    const auto md = rva_span(f, a, md_rva, md_size);
    if (!md) return fail("pe.clr.metadata_range", "Metadata [" + hex(md_rva) + ", +" + hex(md_size) + ") is not file-backed.");
    const ByteView m(*md, Endian::Little);
    if (m.u32(0).value_or(0) != 0x424a5342)
        return fail("pe.clr.metadata_signature", "Metadata root does not start with the 'BSJB' signature.");
    const std::uint32_t version_len = m.u32(12).value_or(0);
    auto version = m.slice(16, version_len);
    if (!version || version_len > 255) return fail("pe.clr.metadata_root", "Metadata version string is out of range.");
    const auto v = ByteView(*version).cstring(0, version_len);
    net.metadata_version = printable(v ? *v : std::string_view(reinterpret_cast<const char*>(version->data()), version->size()));
    std::uint64_t at = 16 + ((std::uint64_t{version_len} + 3) & ~std::uint64_t{3});
    const auto stream_count = m.u16(at + 2);
    if (!stream_count) return fail("pe.clr.metadata_root", "Metadata root is truncated before the stream count.");
    at += 4;
    std::optional<std::span<const std::uint8_t>> tables, strings, blobs;
    for (std::uint16_t i = 0; i < *stream_count && i < 16; ++i) {
        const auto off = m.u32(at), size = m.u32(at + 4);
        const auto name = m.cstring(at + 8, 32);
        if (!off || !size || !name) return fail("pe.clr.streams", "Stream header " + std::to_string(i) + " is truncated.");
        at += 8 + ((name->size() + 4) & ~std::size_t{3});
        auto data = m.slice(*off, *size);
        net.streams.push_back({printable(*name), *off, *size});
        if (!data) {
            diag(a, "pe.clr.streams", "Stream '" + printable(*name) + "' extends beyond the metadata.", 0);
            continue;
        }
        if (*name == "#~" || *name == "#-") tables = data;
        else if (*name == "#Strings") strings = data;
        else if (*name == "#Blob") blobs = data;
    }
    if (!tables) {
        a.dotnet = std::move(net);
        return;
    }

    // #~ header: row counts for each present table, then the tables.
    const ByteView t(*tables, Endian::Little);
    const std::uint8_t heap_sizes = t.record(6, 1) ? t.record(6, 1)->u8(0) : 0;
    const std::uint64_t valid = t.u64(8).value_or(0);
    std::array<std::uint32_t, 64> rows{};
    std::uint64_t p = 24;
    for (std::uint32_t bit = 0; bit < 64; ++bit) {
        if (!((valid >> bit) & 1)) continue;
        const auto n = t.u32(p);
        if (!n) return fail("pe.clr.tables", "#~ row counts are truncated.");
        rows[bit] = *n;
        p += 4;
    }
    if (heap_sizes & 0x40) p += 4;  // "extra data" field (non-standard, emitted by some compilers)
    for (std::uint32_t bit = 0; bit < kTableCount; ++bit)
        if (rows[bit]) net.tables.push_back({kTableNames[bit], rows[bit]});
    if (valid >> kTableCount)
        diag(a, "pe.clr.unknown_tables", "#~ declares tables beyond GenericParamConstraint (0x2c); they are not decoded.", 0);

    TableReader reader(*tables, heap_sizes, rows);
    std::array<std::uint64_t, kTableCount> table_offset{};
    std::uint64_t cursor = p;
    for (std::uint32_t bit = 0; bit < kTableCount; ++bit) {
        table_offset[bit] = cursor;
        const auto bytes = checked_mul(rows[bit], reader.row_size(static_cast<std::uint8_t>(bit)));
        if (!bytes || !t.has(cursor, *bytes)) return fail("pe.clr.tables", std::string("Table ") + kTableNames[bit] + " extends beyond the #~ stream.");
        cursor += *bytes;
    }

    auto str = [&](std::optional<std::uint32_t> index) -> std::string {
        if (!strings || !index) return {};
        auto s = ByteView(*strings).cstring(*index, 1024);
        return s ? printable(*s) : std::string("<invalid>");
    };
    // Blob heap entries carry a compressed length (§II.24.2.4).
    auto blob = [&](std::optional<std::uint32_t> index) -> std::optional<std::span<const std::uint8_t>> {
        if (!blobs || !index || *index >= blobs->size()) return std::nullopt;
        const ByteView b(*blobs);
        const std::uint8_t b0 = (*blobs)[*index];
        std::uint64_t len, hdr;
        if ((b0 & 0x80) == 0) { len = b0; hdr = 1; }
        else if ((b0 & 0xc0) == 0x80) { auto x = b.record(*index, 2); if (!x) return std::nullopt; len = ((b0 & 0x3fu) << 8) | x->u8(1); hdr = 2; }
        else if ((b0 & 0xe0) == 0xc0) {
            auto x = b.record(*index, 4);
            if (!x) return std::nullopt;
            len = (std::uint64_t{b0 & 0x1fu} << 24) | (std::uint64_t{x->u8(1)} << 16) | (std::uint64_t{x->u8(2)} << 8) | x->u8(3);
            hdr = 4;
        } else return std::nullopt;
        return b.slice(*index + hdr, len);
    };
    // Public key token: last 8 bytes of SHA-1(public key), reversed (§II.6.3).
    auto token = [&](std::span<const std::uint8_t> key, bool is_full_key) -> std::string {
        if (key.empty()) return "null";
        if (!is_full_key) return hex_bytes(key, 8);
        const auto digest = sha1(key);
        std::string out;
        for (std::size_t i = digest.size(); i >= 2 && out.size() < 16; i -= 2) out += digest.substr(i - 2, 2);
        return out;
    };
    auto version4 = [&](std::uint8_t table, std::uint32_t row, std::size_t first) {
        std::string s;
        for (std::size_t k = 0; k < 4; ++k)
            s += (k ? "." : "") + std::to_string(reader.cell(table_offset[table], table, row, first + k).value_or(0));
        return s;
    };

    if (rows[Module]) net.module_name = str(reader.cell(table_offset[Module], Module, 0, 1));
    if (rows[Assembly]) {
        net.assembly_name = str(reader.cell(table_offset[Assembly], Assembly, 0, 7));
        net.assembly_version = version4(Assembly, 0, 1);
        net.assembly_culture = str(reader.cell(table_offset[Assembly], Assembly, 0, 8));
        auto key = blob(reader.cell(table_offset[Assembly], Assembly, 0, 6));
        net.public_key_token = key ? token(*key, true) : "null";
    }
    for (std::uint32_t r = 0; r < rows[AssemblyRef] && r < 4096; ++r) {
        DotNetReference ref;
        ref.name = str(reader.cell(table_offset[AssemblyRef], AssemblyRef, r, 6));
        ref.version = version4(AssemblyRef, r, 0);
        ref.culture = str(reader.cell(table_offset[AssemblyRef], AssemblyRef, r, 7));
        const auto flags = reader.cell(table_offset[AssemblyRef], AssemblyRef, r, 4).value_or(0);
        auto key = blob(reader.cell(table_offset[AssemblyRef], AssemblyRef, r, 5));
        ref.public_key_token = key ? token(*key, flags & 1) : "null";
        net.references.push_back(std::move(ref));
    }
    for (std::uint32_t r = 0; r < rows[ModuleRef] && r < 4096; ++r)
        net.module_references.push_back(str(reader.cell(table_offset[ModuleRef], ModuleRef, r, 0)));

    add_property(a, ".NET runtime", net.metadata_version + " (CLR header " + net.runtime_header + ")");
    add_property(a, ".NET flags", net.flags_text);
    if (!net.assembly_name.empty())
        add_property(a, ".NET assembly", net.assembly_name + ", Version=" + net.assembly_version + ", Culture=" +
                                             (net.assembly_culture.empty() ? "neutral" : net.assembly_culture) +
                                             ", PublicKeyToken=" + net.public_key_token);
    diag(a, "pe.clr.partial", "Managed metadata decoded: header, streams, table row counts, Module/Assembly/AssemblyRef/ModuleRef. "
                              "IL, signatures and custom attributes are not decoded.", 0);
    a.dotnet = std::move(net);
}

} // namespace bw::detail
