#include "binweaver/binweaver.hpp"
#include "check.hpp"
#include "fixtures.hpp"

#include <algorithm>

using namespace bw;

namespace {
struct Pair {
    FileImage fa, fb;
    Analysis a, b;
    StructuralDiff d;
};

Pair diff(fixtures::Bytes x, fixtures::Bytes y, DiffOptions o = {}) {
    Pair p{FileImage::from_bytes(std::move(x), "a"), FileImage::from_bytes(std::move(y), "b"), {}, {}, {}};
    p.a = analyze(p.fa);
    p.b = analyze(p.fb);
    p.d = diff_structure(p.a, p.fa, p.b, p.fb, o);
    return p;
}

const StructuralChange* find(const StructuralDiff& d, std::string_view category, std::string_view subject) {
    for (const auto& c : d.changes)
        if (c.category == category && c.subject == subject) return &c;
    return nullptr;
}

bool caveat_contains(const StructuralDiff& d, std::string_view text) {
    return std::any_of(d.caveats.begin(), d.caveats.end(), [&](const std::string& c) { return c.find(text) != std::string::npos; });
}
} // namespace

TEST_CASE("diff.identical") {
    const auto p = diff(fixtures::pe::build(), fixtures::pe::build());
    CHECK_EQ(p.d.raw.changed, 0u);
    CHECK_EQ(p.d.count(ChangeKind::Added) + p.d.count(ChangeKind::Removed) + p.d.count(ChangeKind::Modified), 0u);
    DiffOptions all;
    all.include_unchanged = true;
    const auto q = diff(fixtures::pe::build(), fixtures::pe::build(), all);
    CHECK(q.d.count(ChangeKind::Unchanged) > 10);
    const auto* text = find(q.d, "section", ".text");
    REQUIRE(text != nullptr);
    CHECK(text->kind == ChangeKind::Unchanged);
    CHECK(text->confidence == Confidence::Exact);
}

TEST_CASE("diff.pe.content_and_tables") {
    fixtures::pe::Options ob;
    ob.text_fill = 0x90;               // .text body changes
    ob.exports = false;                // exports removed
    ob.second_user32_import = true;    // one import added
    const auto p = diff(fixtures::pe::build(), fixtures::pe::build(ob));
    const auto* text = find(p.d, "section", ".text");
    REQUIRE(text != nullptr);
    CHECK(text->kind == ChangeKind::Modified);
    CHECK(text->detail.find("bytes differ") != std::string::npos);
    CHECK(text->range_a.has_value() && text->range_b.has_value());
    const auto* alpha = find(p.d, "export", "alpha");
    REQUIRE(alpha != nullptr);
    CHECK(alpha->kind == ChangeKind::Removed);
    const auto* added = find(p.d, "import", "user32.dll!MessageBoxW");
    REQUIRE(added != nullptr);
    CHECK(added->kind == ChangeKind::Added);
    CHECK(added->confidence == Confidence::Exact);
    CHECK(find(p.d, "directory", "Export") != nullptr);
    CHECK(caveat_contains(p.d, "Certificate tables are compared"));
}

TEST_CASE("diff.pe.moved_section_is_explained") {
    fixtures::pe::Options ob;
    ob.data_padding = 0x200;  // .data moves by 0x200 in the file with identical content
    const auto p = diff(fixtures::pe::build(), fixtures::pe::build(ob));
    const auto* data = find(p.d, "section", ".data");
    REQUIRE(data != nullptr);
    CHECK(data->kind == ChangeKind::Modified);
    CHECK(data->detail.find("content identical") != std::string::npos);
    CHECK(caveat_contains(p.d, "moved to a different file offset"));
    CHECK(caveat_contains(p.d, "Files differ in size"));
    CHECK(p.d.raw.changed > 0);
}

TEST_CASE("diff.elf.dynamic_and_notes") {
    fixtures::elf::Options ob;
    ob.needed = "libm.so.6";
    ob.build_id = "ffffffffffffffffffffffffffffffffffffffff";
    const auto p = diff(fixtures::elf::build(), fixtures::elf::build(ob));
    const auto* removed = find(p.d, "dynamic", "libc.so.6");
    const auto* added = find(p.d, "dynamic", "libm.so.6");
    REQUIRE(removed && added);
    CHECK(removed->kind == ChangeKind::Removed);
    CHECK(added->kind == ChangeKind::Added);
    const auto* note = find(p.d, "note", "GNU NT_GNU_BUILD_ID");
    REQUIRE(note != nullptr);
    CHECK(note->kind == ChangeKind::Modified);
    // Segments have no names: they are matched by type and position.
    for (const auto& c : p.d.changes)
        if (c.category == "segment") CHECK(c.confidence == Confidence::Heuristic);
}

TEST_CASE("diff.duplicate_names_are_heuristic") {
    auto b = fixtures::pe::build();
    // Rename .rdata to .text: two sections now share a name.
    std::copy_n(".text\0\0\0", 8, b.begin() + static_cast<std::ptrdiff_t>(fixtures::pe::section_table(true) + 40));
    const auto p = diff(b, b, DiffOptions{true, 20000});
    const auto* dup = find(p.d, "section", ".text");
    REQUIRE(dup != nullptr);
    CHECK(dup->confidence == Confidence::Heuristic);
    CHECK_EQ(p.a.sections[1].id, std::string("section:.text#1"));
}

TEST_CASE("diff.format_mismatch_is_not_comparable") {
    const auto p = diff(fixtures::pe::build(), fixtures::elf::build());
    const auto* fmt = find(p.d, "header", "format");
    REQUIRE(fmt != nullptr);
    CHECK(fmt->confidence == Confidence::NotComparable);
    CHECK(caveat_contains(p.d, "different formats"));
    CHECK_EQ(p.d.changes.size(), 1u);
}

TEST_CASE("diff.truncation") {
    fixtures::pe::Options ob;
    ob.exports = false;
    const auto p = diff(fixtures::pe::build(), fixtures::pe::build(ob), DiffOptions{false, 2});
    CHECK(p.d.truncated);
    CHECK_EQ(p.d.changes.size(), 2u);
    CHECK(caveat_contains(p.d, "truncated"));
}

TEST_CASE("diff.reports") {
    fixtures::pe::Options ob;
    ob.text_fill = 0x90;
    const auto p = diff(fixtures::pe::build(), fixtures::pe::build(ob));
    const auto text = text_report(p.d);
    CHECK(text.find("~ .text") != std::string::npos);
    CHECK(text.find("What could not be compared reliably") != std::string::npos);
    const auto json = json_report(p.d);
    CHECK(json.find("\"schema_version\": 2") != std::string::npos);
    CHECK(json.find("\"category\": \"section\"") != std::string::npos);
}
