#pragma once
// Hex/ASCII viewer that paints only the visible rows straight from the
// (memory-mapped) file, so opening a multi-gigabyte file costs nothing here.
#include "binweaver/binweaver.hpp"

#include <QAbstractScrollArea>

#include <memory>
#include <optional>

class HexView : public QAbstractScrollArea {
    Q_OBJECT
public:
    static constexpr int kBytesPerRow = 16;

    explicit HexView(QWidget* parent = nullptr);
    void setFile(std::shared_ptr<const bw::FileImage> file);
    std::uint64_t size() const { return data_.size(); }

    std::uint64_t cursor() const { return cursor_; }
    // Selected range [start, start + length); length 0 when nothing is selected.
    bw::ByteRange selection() const;
    // Moves the cursor to `offset`, selects `length` bytes and scrolls into view.
    void goTo(std::uint64_t offset, std::uint64_t length = 0);
    // Range drawn with the "structure" background (the active table row).
    void setStructureHighlight(std::optional<bw::ByteRange> range);
    // Ranges drawn with the "changed" background (comparison mode). Sorted, non-overlapping.
    void setDiffRanges(std::vector<bw::ByteRange> ranges);
    // Search-match highlight.
    void setMatch(std::optional<bw::ByteRange> match);

    std::uint64_t topOffset() const { return topRow() * kBytesPerRow; }
    void setTopOffset(std::uint64_t offset);  // used to keep two views in step

signals:
    void cursorMoved(quint64 offset);
    void selectionChanged(quint64 start, quint64 length);
    void topOffsetChanged(quint64 offset);

protected:
    void paintEvent(QPaintEvent*) override;
    void resizeEvent(QResizeEvent*) override;
    void keyPressEvent(QKeyEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;
    void scrollContentsBy(int dx, int dy) override;
    void changeEvent(QEvent*) override;

private:
    std::uint64_t rowCount() const { return (size() + kBytesPerRow - 1) / kBytesPerRow; }
    std::uint64_t topRow() const;
    int visibleRows() const;
    void updateScrollBar();
    void updateMetrics();
    void ensureVisible(std::uint64_t offset);
    void setCursor(std::uint64_t offset, bool extend);
    std::optional<std::uint64_t> offsetAt(const QPoint& p) const;
    bool inDiff(std::uint64_t offset, std::size_t& hint) const;
    void copySelection() const;

    std::shared_ptr<const bw::FileImage> file_;
    std::span<const std::uint8_t> data_;
    std::uint64_t cursor_{}, anchor_{};
    bool has_selection_{};
    std::optional<bw::ByteRange> structure_, match_;
    std::vector<bw::ByteRange> diff_;
    std::uint64_t scroll_scale_{1};  // rows per scrollbar step for files beyond INT_MAX rows

    int char_w_{8}, line_h_{16}, offset_digits_{8};
    int x_hex_{}, x_ascii_{};
};
