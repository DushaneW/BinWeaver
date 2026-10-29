#pragma once
// Helpers shared by the format parsers. Not part of the public API.
#include "binweaver/binweaver.hpp"

#include <initializer_list>
#include <string>
#include <string_view>

namespace bw::detail {

// Appends a diagnostic whose severity comes from the catalog. Error-severity
// diagnostics clear Analysis::structurally_valid.
void diag(Analysis&, std::string_view code, std::string message, std::uint64_t offset = 0);

// Adds a diagnostic once per code; used for per-entry problems in large tables
// so a hostile file cannot produce millions of identical messages.
class DiagLimiter {
public:
    explicit DiagLimiter(Analysis& a, std::size_t per_code = 16) : a_(a), per_code_(per_code) {}
    void operator()(std::string_view code, std::string message, std::uint64_t offset = 0);
    ~DiagLimiter();
private:
    Analysis& a_;
    std::size_t per_code_;
    std::vector<std::pair<std::string, std::size_t>> counts_;
};

void parse_pe(const FileImage&, Analysis&, const AnalyzeOptions&);
void parse_elf(const FileImage&, Analysis&, const AnalyzeOptions&);
void run_heuristics(const FileImage&, Analysis&);
void decode_clr(const FileImage&, Analysis&, std::uint64_t clr_rva, std::uint64_t clr_size);

void add_property(Analysis&, std::string key, std::string value);
// pefile's ordinal -> name tables (oleaut32/ws2_32/wsock32), for imphash.
const char* known_ordinal_name(std::string_view dll_lower, std::uint16_t ordinal);
bool has_ordinal_table(std::string_view dll_lower);
// Decodes one Authenticode PKCS#7 blob (pkcs7_offset/size inside the file).
void decode_authenticode(const FileImage&, Analysis&, std::uint64_t pkcs7_offset, std::uint64_t pkcs7_size,
                         std::uint64_t checksum_field, std::uint64_t security_entry, std::uint64_t certificate_table);
std::string hex_bytes(std::span<const std::uint8_t>, std::size_t max_bytes = 64);
// "A B 0x40" style rendering of a bit set; unknown bits are shown in hex.
std::string join_flags_text(std::uint64_t value, std::initializer_list<std::pair<std::uint64_t, const char*>> names);
// Sets Section::id to "section:<name>", adding "#n" for the n-th duplicate name.
void assign_section_ids(std::vector<Section>&);

} // namespace bw::detail
