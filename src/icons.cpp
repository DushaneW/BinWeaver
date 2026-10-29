// Rebuilds a standalone .ico file from a PE icon group: RT_GROUP_ICON holds a
// GRPICONDIR whose 14-byte entries reference RT_ICON resources by id; an .ico
// file uses the same header with 16-byte entries that carry file offsets.
#include "binweaver/binweaver.hpp"

#include <algorithm>

namespace bw {

std::size_t icon_group_count(const Analysis& a) {
    return static_cast<std::size_t>(std::count_if(a.resources.begin(), a.resources.end(),
                                                  [](const Resource& r) { return r.type == "GROUP_ICON" && r.offset; }));
}

std::optional<std::vector<std::uint8_t>> extract_icon(const Analysis& a, const FileImage& f, std::size_t group,
                                                      std::string* error) {
    auto fail = [&](std::string why) -> std::optional<std::vector<std::uint8_t>> {
        if (error) *error = std::move(why);
        return std::nullopt;
    };
    const Resource* g = nullptr;
    for (const auto& r : a.resources)
        if (r.type == "GROUP_ICON" && r.offset && group-- == 0) {
            g = &r;
            break;
        }
    if (!g) return fail("no such icon group");
    const ByteView v(f.bytes());
    auto dir = v.record(*g->offset, 6);
    if (!dir || g->size < 6 || dir->u16(0) != 0 || dir->u16(2) != 1) return fail("GRPICONDIR header is invalid");
    const std::uint16_t count = dir->u16(4);
    if (count == 0 || std::uint64_t{count} * 14 + 6 > g->size) return fail("GRPICONDIR entry count exceeds the resource");

    struct Image {
        std::span<const std::uint8_t> entry;  // first 12 bytes of the group entry
        std::span<const std::uint8_t> data;
    };
    std::vector<Image> images;
    for (std::uint16_t i = 0; i < count; ++i) {
        const auto e = *v.record(*g->offset + 6 + std::uint64_t{i} * 14, 14);
        const std::string id = "#" + std::to_string(e.u16(12));
        // Prefer the icon in the group's language, else any language.
        const Resource* icon = nullptr;
        for (const auto& r : a.resources)
            if (r.type == "ICON" && r.name == id && r.offset && (!icon || r.language == g->language)) icon = &r;
        if (!icon) return fail("icon " + id + " referenced by the group is missing or not file-backed");
        auto data = v.slice(*icon->offset, icon->size);
        if (!data) return fail("icon " + id + " data is outside the file");
        images.push_back({e.bytes().subspan(0, 12), *data});
    }
    std::vector<std::uint8_t> out(6 + images.size() * 16);
    std::copy_n(dir->bytes().begin(), 6, out.begin());
    std::uint64_t offset = out.size();
    for (std::size_t i = 0; i < images.size(); ++i) {
        auto* e = out.data() + 6 + i * 16;
        std::copy_n(images[i].entry.begin(), 8, e);  // width, height, colors, reserved, planes, bit count
        const auto size = static_cast<std::uint32_t>(images[i].data.size());  // actual size, not dwBytesInRes
        for (int k = 0; k < 4; ++k) e[8 + k] = static_cast<std::uint8_t>(size >> (8 * k));
        for (int k = 0; k < 4; ++k) e[12 + k] = static_cast<std::uint8_t>(offset >> (8 * k));
        offset += size;
    }
    for (const auto& img : images) out.insert(out.end(), img.data.begin(), img.data.end());
    return out;
}

} // namespace bw
