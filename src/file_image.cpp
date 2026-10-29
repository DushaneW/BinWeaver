#include "binweaver/binweaver.hpp"

#include <fstream>
#include <limits>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace bw {

// Owns a read-only mapping of a whole file. The view's size is fixed at open
// time; parsers bounds-check against that size.
struct FileImage::Mapping {
#ifdef _WIN32
    HANDLE file{INVALID_HANDLE_VALUE};
    HANDLE section{nullptr};
    const void* base{nullptr};
    ~Mapping() {
        if (base) UnmapViewOfFile(base);
        if (section) CloseHandle(section);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
#else
    int fd{-1};
    void* base{MAP_FAILED};
    std::size_t length{};
    ~Mapping() {
        if (base != MAP_FAILED) munmap(base, length);
        if (fd >= 0) close(fd);
    }
#endif
};

namespace {

// Returns nullptr (and leaves `error` untouched) when mapping is not possible,
// so the caller can fall back to reading the file.
std::unique_ptr<FileImage::Mapping> map_file(const std::filesystem::path& path, std::uint64_t size) {
    if (size == 0 || size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return nullptr;
    auto m = std::make_unique<FileImage::Mapping>();
#ifdef _WIN32
    // FILE_SHARE_WRITE is deliberately not granted: while mapped, other
    // processes cannot open the file for writing, which prevents the view
    // from changing underneath the parser.
    m->file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, nullptr);
    if (m->file == INVALID_HANDLE_VALUE) return nullptr;
    LARGE_INTEGER actual{};
    if (!GetFileSizeEx(m->file, &actual) || static_cast<std::uint64_t>(actual.QuadPart) != size) return nullptr;
    m->section = CreateFileMappingW(m->file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!m->section) return nullptr;
    m->base = MapViewOfFile(m->section, FILE_MAP_READ, 0, 0, 0);
    if (!m->base) return nullptr;
#else
    m->fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (m->fd < 0) return nullptr;
    struct stat st {};
    if (fstat(m->fd, &st) != 0 || !S_ISREG(st.st_mode) || static_cast<std::uint64_t>(st.st_size) != size)
        return nullptr;
    m->length = static_cast<std::size_t>(size);
    m->base = mmap(nullptr, m->length, PROT_READ, MAP_PRIVATE, m->fd, 0);
    if (m->base == MAP_FAILED) return nullptr;
#endif
    return m;
}

} // namespace

FileImage::FileImage(FileImage&&) noexcept = default;
FileImage& FileImage::operator=(FileImage&&) noexcept = default;
FileImage::~FileImage() = default;

std::optional<FileImage> FileImage::open(const std::filesystem::path& p, std::string& e, std::uint64_t cap, Mode mode) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(p, ec)) {
        e = ec ? "cannot stat file: " + ec.message() : "not a regular file";
        return std::nullopt;
    }
    const auto n = std::filesystem::file_size(p, ec);
    if (ec) {
        e = "cannot stat file: " + ec.message();
        return std::nullopt;
    }
    if (n > cap || n > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        e = "file exceeds safety limit (" + std::to_string(n) + " > " + std::to_string(cap) + " bytes)";
        return std::nullopt;
    }

    FileImage x;
    x.path_ = p;
    if (mode != Mode::Read) {
        x.mapping_ = map_file(p, n);
        if (x.mapping_) {
            x.view_ = {static_cast<const std::uint8_t*>(x.mapping_->base), static_cast<std::size_t>(n)};
            return x;
        }
        if (mode == Mode::MemoryMap && n != 0) {
            e = "memory mapping failed";
            return std::nullopt;
        }
    }

    std::ifstream f(p, std::ios::binary);
    if (!f) {
        e = "cannot open file";
        return std::nullopt;
    }
    x.owned_.resize(static_cast<std::size_t>(n));
    if (n) {
        f.read(reinterpret_cast<char*>(x.owned_.data()), static_cast<std::streamsize>(n));
        if (!f || static_cast<std::uint64_t>(f.gcount()) != n) {
            e = "short read";
            return std::nullopt;
        }
    }
    x.view_ = x.owned_;
    return x;
}

FileImage FileImage::from_bytes(std::vector<std::uint8_t> bytes, std::string label) {
    FileImage x;
    x.path_ = std::move(label);
    x.owned_ = std::move(bytes);
    x.view_ = x.owned_;
    return x;
}

} // namespace bw
