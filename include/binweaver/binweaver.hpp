#pragma once
// BinWeaver core API. The core has no Qt dependency; the CLI and the Qt UI
// both render the plain data model defined here.
#include "binweaver/checked.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace bw {

inline constexpr int kJsonSchemaVersion = 2;

enum class Format { Unknown, PE, ELF };
enum class Severity { Info, Warning, Error };

struct Diagnostic {
    Severity severity{Severity::Info};
    std::string code;     // stable identifier, see docs/DIAGNOSTICS.md
    std::string message;  // human-readable detail; may change between versions
    std::uint64_t offset{};
};

// Catalog entry for a stable diagnostic code.
struct DiagnosticInfo {
    std::string_view code;
    Severity severity;
    std::string_view summary;
    bool retired = false;  // no longer emitted; kept so the code is never reused
};
const std::vector<DiagnosticInfo>& diagnostic_catalog();
const DiagnosticInfo* find_diagnostic(std::string_view code);

// A PE section, an ELF section, or an ELF segment.
struct Section {
    std::string id;     // stable identity used by the structural diff, e.g. "section:.text"
    std::string name;
    std::string kind;   // "PE section", "SHT_PROGBITS", "PT_LOAD", ...
    std::uint32_t index{};
    std::uint32_t type{};
    std::uint64_t offset{};        // file offset of file-backed data
    std::uint64_t size{};          // bytes backed by the file (0 for NOBITS / uninitialized)
    std::uint64_t address{};       // PE: RVA, ELF: virtual address
    std::uint64_t virtual_size{};  // size in memory
    std::uint64_t flags{};
    std::string flags_text;
    std::uint64_t alignment{};
    std::uint64_t link{};
    std::uint64_t info{};
    std::uint64_t entry_size{};
    bool file_range_valid{true};
    std::optional<double> entropy; // over the file-backed bytes that lie inside the file
};

// A named file-backed byte range (headers, tables, overlay, directories).
struct Region {
    std::string name;
    std::string kind;
    std::uint64_t offset{};
    std::uint64_t size{};
};

// Maps an address range (PE RVA or ELF virtual address) to file bytes.
struct AddressMapping {
    std::string name;
    std::uint64_t address{};
    std::uint64_t memory_size{};
    std::uint64_t offset{};
    std::uint64_t file_size{};  // bytes past file_size (up to memory_size) are zero-filled
};

struct Directory {
    std::string name;
    std::uint32_t index{};
    std::uint64_t address{};  // RVA, except the security directory which stores a file offset
    std::uint64_t size{};
    std::optional<std::uint64_t> file_offset;
    std::string status;       // "ok", "empty", or a short reason the range is unusable
};

struct Import {
    std::string library;
    std::string name;  // empty for ordinal imports
    std::optional<std::uint16_t> ordinal;
    std::uint16_t hint{};
    bool delayed{};
    std::uint64_t thunk_rva{};  // RVA of the IAT slot
};

struct Export {
    std::string name;  // empty when exported by ordinal only
    std::uint32_t ordinal{};
    std::uint64_t rva{};
    std::string forwarder;  // "DLL.Function" when the export is forwarded
};

struct Symbol {
    std::string table;  // ".symtab", ".dynsym", ...
    std::uint32_t index{};
    std::string name;
    std::uint64_t value{};
    std::uint64_t size{};
    std::string type;
    std::string bind;
    std::string visibility;
    std::uint32_t section_index{};
    std::string version;  // GNU symbol version name, e.g. "GLIBC_2.34"; " (hidden)" marks non-default versions
};

struct DynamicEntry {
    std::int64_t tag{};
    std::string tag_name;
    std::uint64_t value{};
    std::string text;  // resolved string or decoded flags, when applicable
};

struct Relocation {
    std::string section;
    std::uint64_t offset{};
    std::uint32_t type{};
    std::string type_name;
    std::uint64_t symbol_index{};
    std::string symbol;
    std::int64_t addend{};
    bool has_addend{};
};

struct Note {
    std::string source;  // section or segment that contained the note
    std::string owner;
    std::uint32_t type{};
    std::string type_name;
    std::uint64_t offset{};
    std::uint64_t size{};  // whole note entry: header, padded name and padded descriptor
    std::uint64_t descriptor_size{};
    std::string description;
};

struct Certificate {
    std::uint64_t offset{};
    std::uint32_t length{};
    std::uint16_t revision{};
    std::uint16_t type{};
    std::string type_name;
};

// One leaf of the PE resource tree (type / name / language).
struct Resource {
    std::string type;      // "ICON", "VERSION", "#123" or a string name
    std::string name;      // "#1" or a string name
    std::string language;  // "0x409" etc.
    std::uint64_t rva{};
    std::uint64_t size{};
    std::optional<std::uint64_t> offset;  // file offset when the data is file-backed
    std::uint32_t codepage{};
};

// Authenticode signature metadata from a PKCS#7 certificate entry. The
// signature itself and the certificate chain are NOT verified; see
// docs/LIMITATIONS.md.
struct Signature {
    std::uint64_t certificate_offset{};  // WIN_CERTIFICATE entry in the file
    std::string digest_algorithm;        // "SHA-256", "SHA-1", or an OID
    std::string signed_digest;           // hex, from SpcIndirectDataContent
    std::string computed_digest;         // hex image digest, empty if not computed
    std::string digest_status;           // "match", "mismatch", or "not computed: <reason>"
    std::string signer_subject, signer_issuer, signer_serial, valid_from, valid_to;
    std::vector<std::string> certificates;  // subjects of all embedded certificates
};

// x64 exception-table entry (RUNTIME_FUNCTION): one function's code range.
struct FunctionRange {
    std::uint32_t begin{};   // RVA
    std::uint32_t end{};     // RVA, exclusive
    std::uint32_t unwind{};  // RVA of UNWIND_INFO
    // Decoded UNWIND_INFO (valid when unwind_decoded is true).
    bool unwind_decoded{};
    std::uint8_t unwind_version{}, unwind_flags{}, prolog_size{}, code_count{}, frame_register{}, frame_offset{};
    std::uint32_t handler{};        // exception/termination handler RVA (UNW_FLAG_EHANDLER/UHANDLER), else 0
    std::uint32_t chained_begin{};  // BeginAddress of the parent function (UNW_FLAG_CHAININFO), else 0
};

// One IMAGE_DEBUG_DIRECTORY entry.
struct DebugEntry {
    std::uint32_t type{};
    std::string type_name;
    std::uint32_t timestamp{};
    std::uint32_t size{};
    std::uint32_t rva{};
    std::uint32_t pointer{};  // file offset of the data
    std::string detail;       // decoded summary (PDB path, CET flags, POGO count, ...)
};

// One string from an RT_STRING resource block.
struct ResourceString {
    std::uint32_t id{};
    std::string language;
    std::string text;
};

// .NET (ECMA-335) metadata summary.
struct DotNetStream {
    std::string name;
    std::uint32_t offset{}, size{};  // relative to the metadata root
};
struct DotNetTable {
    std::string name;
    std::uint32_t rows{};
};
struct DotNetReference {
    std::string name, version, culture, public_key_token;
};
struct DotNetInfo {
    std::string runtime_header;    // CLR header version, e.g. "2.5"
    std::string metadata_version;  // e.g. "v4.0.30319"
    std::uint32_t flags{};
    std::string flags_text;
    std::uint32_t entry_point_token{};
    std::vector<DotNetStream> streams;
    std::vector<DotNetTable> tables;
    std::string module_name, assembly_name, assembly_version, assembly_culture, public_key_token;
    std::vector<DotNetReference> references;
    std::vector<std::string> module_references;  // native DLLs used through P/Invoke
};

// Entry of the undocumented MSVC "Rich" header (linker/compiler tool versions).
struct RichEntry {
    std::uint16_t product_id{};
    std::uint16_t build{};
    std::uint32_t count{};
};

struct Analysis {
    std::string path, sha256, architecture{"unknown"}, bitness{"unknown"}, byte_order{"unknown"};
    std::string file_type{"unknown"};
    std::string imphash;  // PE: pefile-compatible import hash (MD5), empty without imports
    std::uint64_t file_size{}, entry_point{}, image_base{};
    Format format{Format::Unknown};
    bool structurally_valid{true};

    std::vector<Section> sections;
    std::vector<Section> segments;  // ELF program headers
    std::vector<Region> structures; // headers and tables with file offsets
    std::vector<AddressMapping> mappings;
    std::vector<Directory> directories;
    std::vector<Import> imports;
    std::vector<Export> exports;
    std::vector<Symbol> symbols;
    std::vector<DynamicEntry> dynamic;
    std::vector<Relocation> relocations;
    std::vector<Note> notes;
    std::vector<Certificate> certificates;
    std::vector<Resource> resources;
    std::vector<Signature> signatures;
    std::vector<FunctionRange> functions;          // PE x64 .pdata
    std::vector<DebugEntry> debug_entries;         // PE debug directory
    std::optional<DotNetInfo> dotnet;              // PE with a CLR header
    std::vector<ResourceString> resource_strings;  // PE RT_STRING
    std::vector<RichEntry> rich;
    std::vector<Diagnostic> diagnostics;
    std::vector<std::pair<std::string, std::string>> properties;

    const std::string* property(std::string_view key) const;
    bool has_errors() const;
};

// Upper bounds that keep hostile inputs from exhausting memory. Exceeding a
// limit truncates the affected table and emits a "*.limit" diagnostic.
struct Limits {
    std::uint32_t max_sections = 65536;
    std::uint32_t max_segments = 65536;
    std::uint32_t max_imports = 1u << 20;
    std::uint32_t max_exports = 1u << 20;
    std::uint32_t max_symbols = 1u << 21;
    std::uint32_t max_relocations = 1u << 21;
    std::uint32_t max_dynamic = 1u << 16;
    std::uint32_t max_notes = 4096;
    std::uint32_t max_certificates = 64;
    std::uint32_t max_string = 4096;
    std::uint32_t max_resources = 1u << 16;
    std::uint32_t max_functions = 1u << 21;
    std::uint32_t max_resource_strings = 1u << 17;
};

struct AnalyzeOptions {
    Limits limits{};
    bool section_entropy = true;
    bool pe_checksum = true;
    bool heuristics = true;  // "heur.*" observations (see docs/DIAGNOSTICS.md)
};

// Read-only file contents. Files are memory-mapped when possible so that
// large inputs are paged in on demand rather than copied into memory.
class FileImage {
public:
    static constexpr std::uint64_t kDefaultMaxSize = std::uint64_t{64} << 30;  // 64 GiB
    enum class Mode { Auto, MemoryMap, Read };

    static std::optional<FileImage> open(const std::filesystem::path&, std::string& error,
                                         std::uint64_t max_size = kDefaultMaxSize, Mode mode = Mode::Auto);
    static FileImage from_bytes(std::vector<std::uint8_t> bytes, std::string label = "<memory>");

    FileImage(FileImage&&) noexcept;
    FileImage& operator=(FileImage&&) noexcept;
    FileImage(const FileImage&) = delete;
    FileImage& operator=(const FileImage&) = delete;
    ~FileImage();

    std::span<const std::uint8_t> bytes() const { return view_; }
    std::uint64_t size() const { return view_.size(); }
    const std::filesystem::path& path() const { return path_; }
    bool contains(std::uint64_t offset, std::uint64_t length) const { return range_within(offset, length, size()); }
    bool memory_mapped() const { return mapping_ != nullptr; }

    struct Mapping;  // platform mapping handle (defined in file_image.cpp)

private:
    FileImage() = default;
    std::filesystem::path path_;
    std::vector<std::uint8_t> owned_;
    std::unique_ptr<Mapping> mapping_;
    std::span<const std::uint8_t> view_;
};

Analysis analyze(const std::filesystem::path&, const AnalyzeOptions& = {});
Analysis analyze(const FileImage&, const AnalyzeOptions& = {});

// --- address and offset helpers -------------------------------------------

enum class MapStatus { FileBacked, ZeroFill, Unmapped };
struct MappedOffset {
    MapStatus status{MapStatus::Unmapped};
    std::uint64_t offset{};
    std::string mapping;  // name of the section/segment that maps the address
};
// Translates a PE RVA or ELF virtual address using Analysis::mappings.
MappedOffset address_to_offset(const Analysis&, std::uint64_t address);
// Translates a file offset back to the address(es) at which it is mapped.
std::vector<std::uint64_t> offset_to_addresses(const Analysis&, std::uint64_t offset);
// Every structure, section, segment and directory that covers `offset`,
// ordered from the most specific (smallest) region to the largest.
std::vector<Region> locate(const Analysis&, std::uint64_t offset);

// --- hashing, entropy, search ---------------------------------------------

class Sha256 {
public:
    Sha256();
    void update(std::span<const std::uint8_t>);
    std::string hex_digest();  // finalizes; the object must not be updated afterwards

    // x86 SHA extensions are used when the CPU has them. Disabling forces the
    // portable implementation (used by tests to cross-check both paths).
    static bool hardware_available();
    static bool hardware_active();
    static bool set_hardware_enabled(bool enabled);  // returns the previous setting

private:
    void blocks(const std::uint8_t*, std::size_t n);
    void block(const std::uint8_t*);
    std::uint32_t h_[8];
    std::uint8_t buffer_[64];
    std::size_t buffered_{};
    std::uint64_t length_{};
};
std::string sha256(std::span<const std::uint8_t>);
// SHA-1, for checking legacy Authenticode digests only.
class Sha1 {
public:
    Sha1();
    void update(std::span<const std::uint8_t>);
    std::string hex_digest();  // finalizes
private:
    void block(const std::uint8_t*);
    std::uint32_t h_[5];
    std::uint8_t buffer_[64];
    std::size_t buffered_{};
    std::uint64_t length_{};
};
std::string sha1(std::span<const std::uint8_t>);
// MD5, for interoperable fingerprints (imphash) only; not a security primitive.
std::string md5(std::span<const std::uint8_t>);

double entropy(std::span<const std::uint8_t>);
struct EntropyWindow {
    std::uint64_t offset{};
    std::uint64_t size{};
    double entropy{};
};
// Splits the input into consecutive windows of `window` bytes (the last one
// may be shorter) and measures each. window == 0 returns an empty vector.
std::vector<EntropyWindow> entropy_windows(std::span<const std::uint8_t>, std::uint64_t window);

// Byte pattern with optional wildcards; parsed from "4D 5A ?? 00" or "MZ".
struct BytePattern {
    std::vector<std::uint8_t> bytes;
    std::vector<bool> mask;  // true = byte must match
    bool empty() const { return bytes.empty(); }
};
// Parses hex ("4d5a", "4D 5A ?? 00") or, when prefixed with a double quote or
// given with `text = true`, a literal ASCII string.
std::optional<BytePattern> parse_pattern(std::string_view text, bool literal_text, std::string& error);
// Forward search starting at `from`; backward search finds the last match
// starting strictly before `from`.
std::optional<std::uint64_t> find_pattern(std::span<const std::uint8_t>, const BytePattern&, std::uint64_t from,
                                          bool forward = true);

// Chunked search with progress/cancellation. `progress(done, total)` is
// called before each chunk; returning false cancels (the result is then
// nullopt / the hits found so far). Matches spanning chunk boundaries are found.
using SearchProgress = std::function<bool(std::uint64_t done, std::uint64_t total)>;
std::optional<std::uint64_t> find_pattern(std::span<const std::uint8_t>, const BytePattern&, std::uint64_t from,
                                          bool forward, const SearchProgress& progress,
                                          std::uint64_t chunk = std::uint64_t{64} << 20);
// All non-overlapping-start matches in file order, at most `max_hits`.
std::vector<std::uint64_t> find_all(std::span<const std::uint8_t>, const BytePattern&, std::size_t max_hits,
                                    const SearchProgress& progress = {}, std::uint64_t chunk = std::uint64_t{64} << 20);

// Printable string extraction ("strings"): runs of printable ASCII
// (0x20-0x7e and tab) and of UTF-16LE code units in that same range.
struct ExtractedString {
    std::uint64_t offset{};
    std::uint64_t size{};   // bytes in the file
    bool utf16{};
    std::string text;       // truncated to StringOptions::max_text characters
};
struct StringOptions {
    std::size_t min_length = 5;      // characters
    std::size_t max_count = 200000;  // stop after this many strings
    std::size_t max_text = 512;
    bool ascii = true;
    bool utf16 = true;
};
struct StringScan {
    std::vector<ExtractedString> strings;  // sorted by offset
    bool truncated{};         // max_count reached: scanning stopped early
    std::uint64_t scanned{};  // strings ending before this offset are complete
};
StringScan extract_strings(std::span<const std::uint8_t>, const StringOptions& = {});

// --- header field map -----------------------------------------------------

// One field of a fixed-layout header (DOS/COFF/optional header, data
// directory, section table entry; ELF header, program/section header).
struct HeaderField {
    std::string structure;  // e.g. "IMAGE_OPTIONAL_HEADER64", "Elf64_Phdr[2] PT_LOAD"
    std::string name;       // e.g. "AddressOfEntryPoint"
    std::uint64_t offset{};
    std::uint64_t size{};
    std::uint64_t value{};  // integer fields (1/2/4/8 bytes)
    std::string text;       // display value (hex, quoted ASCII or bytes)
};
// All header fields that lie in tables the parser located, sorted by offset.
std::vector<HeaderField> header_fields(const Analysis&, const FileImage&);
// The field covering `offset`, or nullptr.
const HeaderField* field_at(const std::vector<HeaderField>& sorted_fields, std::uint64_t offset);

// --- PE icons -------------------------------------------------------------

// Number of file-backed RT_GROUP_ICON resources.
std::size_t icon_group_count(const Analysis&);
// Builds a standalone .ico file from the `group`-th icon group and the RT_ICON
// resources it references. Returns nullopt (and a reason) when they are
// missing or malformed. The image payloads (BMP/PNG) are copied, not decoded.
std::optional<std::vector<std::uint8_t>> extract_icon(const Analysis&, const FileImage&, std::size_t group = 0,
                                                      std::string* error = nullptr);

// --- rules (docs/RULES.md) -------------------------------------------------

struct RuleAtom {
    std::string id;    // "$name"
    std::string kind;  // hex, text, wide, import, property
    BytePattern pattern;
    std::string library, key, value;
};
struct Rule {
    std::string name;
    int line{};
    std::vector<std::string> tags;
    std::string scope{"file"};  // file, section, overlay
    std::string scope_section;
    std::vector<RuleAtom> atoms;
    std::size_t min_matches{1};
    bool all{};
};
struct RuleMatch {
    struct Hit {
        std::string id;
        std::optional<std::uint64_t> offset;  // first match for byte patterns
    };
    std::string rule;
    std::vector<std::string> tags;
    std::vector<Hit> matched;
};
// Parses the rule language; problems are appended to `errors` with line
// numbers, and rules with errors are dropped.
std::vector<Rule> parse_rules(std::string_view text, std::vector<std::string>& errors);
std::vector<RuleMatch> match_rules(const std::vector<Rule>&, const Analysis&, const FileImage&);

// --- comparison -----------------------------------------------------------

struct ByteRange {
    std::uint64_t offset{};
    std::uint64_t size{};
};

struct Diff {
    std::uint64_t size_a{}, size_b{}, compared{}, changed{}, longest_equal{}, longest_changed{};
    double changed_percent{};
    std::vector<std::uint64_t> offsets;  // first changed offsets (bounded)
    std::vector<ByteRange> ranges;       // changed runs within the compared prefix (bounded)
    bool ranges_truncated{};
};
Diff compare(const FileImage&, const FileImage&, std::size_t max_offsets = 2048, std::size_t max_ranges = 100000);
Diff compare(std::span<const std::uint8_t>, std::span<const std::uint8_t>, std::size_t max_offsets = 2048,
             std::size_t max_ranges = 100000);

enum class ChangeKind { Added, Removed, Modified, Unchanged };
enum class Confidence { Exact, Heuristic, NotComparable };

struct StructuralChange {
    std::string category;  // header, property, section, segment, directory, import, export, symbol, dynamic, note, certificate
    std::string subject;
    ChangeKind kind{ChangeKind::Modified};
    Confidence confidence{Confidence::Exact};
    std::string detail;
    std::optional<ByteRange> range_a, range_b;  // file ranges, when the subject is file-backed
};

struct StructuralDiff {
    std::string path_a, path_b;
    Diff raw;
    std::vector<StructuralChange> changes;
    std::vector<std::string> caveats;  // what could not be compared reliably and why
    bool truncated{};
    std::size_t count(ChangeKind) const;
};

struct DiffOptions {
    bool include_unchanged = false;
    std::size_t max_changes = 20000;
};
StructuralDiff diff_structure(const Analysis& a, const FileImage& fa, const Analysis& b, const FileImage& fb,
                              const DiffOptions& = {});

// --- reports --------------------------------------------------------------

std::string json_report(const Analysis&);
std::string text_report(const Analysis&);
std::string json_report(const StructuralDiff&);
std::string text_report(const StructuralDiff&);
// Self-contained HTML (inline CSS, no scripts); every file-derived string is escaped.
std::string html_report(const Analysis&);

const char* format_name(Format);
const char* severity_name(Severity);
const char* change_kind_name(ChangeKind);
const char* confidence_name(Confidence);
std::string hex(std::uint64_t value);

} // namespace bw
