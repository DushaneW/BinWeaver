#include "document.hpp"

#include <QElapsedTimer>

std::uint64_t Document::entropy_window_for(std::uint64_t size) {
    std::uint64_t window = 256;
    while (window < (std::uint64_t{1} << 30) && size / window > 4096) window *= 2;
    return window;
}

std::shared_ptr<const Document> Document::load(const QString& path) {
    QElapsedTimer timer;
    timer.start();
    auto doc = std::make_shared<Document>();
    doc->path = path;
    std::string error;
    auto image = bw::FileImage::open(std::filesystem::path(path.toStdWString()), error);
    if (!image) {
        doc->error = QString::fromStdString(error);
        return doc;
    }
    doc->file = std::make_shared<const bw::FileImage>(std::move(*image));
    doc->analysis = bw::analyze(*doc->file);
    doc->entropy_window = entropy_window_for(doc->file->size());
    doc->entropy = bw::entropy_windows(doc->file->bytes(), doc->entropy_window);
    doc->strings = bw::extract_strings(doc->file->bytes());
    doc->fields = bw::header_fields(doc->analysis, *doc->file);
    doc->load_seconds = static_cast<double>(timer.nsecsElapsed()) / 1e9;
    return doc;
}
