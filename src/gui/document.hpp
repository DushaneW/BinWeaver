#pragma once
// A loaded file: the mapped bytes plus everything derived from them. Built on
// a worker thread and then shared read-only with the UI.
#include "binweaver/binweaver.hpp"

#include <QString>

#include <memory>

struct Document {
    std::shared_ptr<const bw::FileImage> file;
    bw::Analysis analysis;
    std::vector<bw::EntropyWindow> entropy;
    std::uint64_t entropy_window{};
    bw::StringScan strings;
    std::vector<bw::HeaderField> fields;  // header field map, sorted by offset  // printable ASCII / UTF-16 strings (capped, see StringOptions)
    QString path;
    QString error;  // non-empty when the file could not be opened
    double load_seconds{};

    bool ok() const { return file != nullptr; }
    std::span<const std::uint8_t> bytes() const { return file ? file->bytes() : std::span<const std::uint8_t>{}; }

    // Opens and analyzes `path`; safe to call from any thread.
    static std::shared_ptr<const Document> load(const QString& path);
    // Entropy window size that yields at most ~4096 windows.
    static std::uint64_t entropy_window_for(std::uint64_t size);
};

using DocumentPtr = std::shared_ptr<const Document>;
