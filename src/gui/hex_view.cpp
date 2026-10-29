#include "hex_view.hpp"

#include <QApplication>
#include <QClipboard>
#include <QFontDatabase>
#include <QKeyEvent>
#include <QPainter>
#include <QScrollBar>

#include <algorithm>
#include <climits>

namespace {
QColor blend(const QColor& a, const QColor& b, double t) {
    return QColor::fromRgbF(static_cast<float>(a.redF() * (1 - t) + b.redF() * t),
                            static_cast<float>(a.greenF() * (1 - t) + b.greenF() * t),
                            static_cast<float>(a.blueF() * (1 - t) + b.blueF() * t));
}
} // namespace

HexView::HexView(QWidget* parent) : QAbstractScrollArea(parent) {
    setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    setFocusPolicy(Qt::StrongFocus);
    viewport()->setCursor(Qt::IBeamCursor);
    updateMetrics();
}

void HexView::setFile(std::shared_ptr<const bw::FileImage> file) {
    file_ = std::move(file);
    data_ = file_ ? file_->bytes() : std::span<const std::uint8_t>{};
    cursor_ = anchor_ = 0;
    has_selection_ = false;
    structure_.reset();
    match_.reset();
    diff_.clear();
    updateMetrics();
    updateScrollBar();
    verticalScrollBar()->setValue(0);
    viewport()->update();
}

void HexView::updateMetrics() {
    const QFontMetrics fm(font());
    char_w_ = fm.horizontalAdvance(QLatin1Char('0'));
    line_h_ = fm.height() + 2;
    offset_digits_ = 8;
    for (std::uint64_t s = size(); s >> (4 * offset_digits_); ) ++offset_digits_;
    x_hex_ = (offset_digits_ + 3) * char_w_;
    x_ascii_ = x_hex_ + (kBytesPerRow * 3 + 2) * char_w_;
}

void HexView::changeEvent(QEvent* e) {
    if (e->type() == QEvent::FontChange) {
        updateMetrics();
        updateScrollBar();
    }
    QAbstractScrollArea::changeEvent(e);
}

int HexView::visibleRows() const { return std::max(1, viewport()->height() / line_h_); }

std::uint64_t HexView::topRow() const {
    return std::min<std::uint64_t>(static_cast<std::uint64_t>(verticalScrollBar()->value()) * scroll_scale_,
                                   rowCount() ? rowCount() - 1 : 0);
}

void HexView::updateScrollBar() {
    const std::uint64_t rows = rowCount();
    const std::uint64_t page = static_cast<std::uint64_t>(visibleRows());
    const std::uint64_t max_row = rows > page ? rows - page : 0;
    scroll_scale_ = 1;
    while (max_row / scroll_scale_ > static_cast<std::uint64_t>(INT_MAX / 2)) scroll_scale_ *= 2;
    verticalScrollBar()->setRange(0, static_cast<int>((max_row + scroll_scale_ - 1) / scroll_scale_));
    verticalScrollBar()->setPageStep(std::max(1, static_cast<int>(page / scroll_scale_)));
    verticalScrollBar()->setSingleStep(1);
    horizontalScrollBar()->setRange(0, std::max(0, x_ascii_ + (kBytesPerRow + 2) * char_w_ - viewport()->width()));
    horizontalScrollBar()->setPageStep(viewport()->width());
}

void HexView::resizeEvent(QResizeEvent* e) {
    QAbstractScrollArea::resizeEvent(e);
    updateScrollBar();
}

void HexView::scrollContentsBy(int, int) {
    viewport()->update();
    emit topOffsetChanged(topOffset());
}

void HexView::setTopOffset(std::uint64_t offset) {
    const auto row = offset / kBytesPerRow;
    const QSignalBlocker block(this);
    verticalScrollBar()->setValue(static_cast<int>(row / scroll_scale_));
    viewport()->update();
}

bw::ByteRange HexView::selection() const {
    if (!has_selection_) return {cursor_, 0};
    const auto lo = std::min(cursor_, anchor_), hi = std::max(cursor_, anchor_);
    return {lo, hi - lo + 1};
}

void HexView::ensureVisible(std::uint64_t offset) {
    const std::uint64_t row = offset / kBytesPerRow, top = topRow();
    const std::uint64_t rows = static_cast<std::uint64_t>(visibleRows());
    if (row < top) verticalScrollBar()->setValue(static_cast<int>(row / scroll_scale_));
    else if (row >= top + rows) verticalScrollBar()->setValue(static_cast<int>((row - rows + 1 + scroll_scale_ - 1) / scroll_scale_));
}

void HexView::goTo(std::uint64_t offset, std::uint64_t length) {
    if (size() == 0) return;
    offset = std::min<std::uint64_t>(offset, size() - 1);
    anchor_ = offset;
    cursor_ = length > 1 ? std::min<std::uint64_t>(offset + length - 1, size() - 1) : offset;
    has_selection_ = length > 1;
    // Show the start of the range, keeping a little context above it.
    const std::uint64_t row = offset / kBytesPerRow;
    const std::uint64_t context = std::min<std::uint64_t>(row, 2);
    verticalScrollBar()->setValue(static_cast<int>((row - context) / scroll_scale_));
    emit cursorMoved(anchor_);
    const auto sel = selection();
    emit selectionChanged(sel.offset, sel.size);
    viewport()->update();
}

void HexView::setStructureHighlight(std::optional<bw::ByteRange> range) {
    structure_ = range;
    viewport()->update();
}

void HexView::setDiffRanges(std::vector<bw::ByteRange> ranges) {
    diff_ = std::move(ranges);
    viewport()->update();
}

void HexView::setMatch(std::optional<bw::ByteRange> match) {
    match_ = match;
    viewport()->update();
}

void HexView::setCursor(std::uint64_t offset, bool extend) {
    if (size() == 0) return;
    offset = std::min<std::uint64_t>(offset, size() - 1);
    if (!extend) {
        anchor_ = offset;
        has_selection_ = false;
    } else {
        has_selection_ = offset != anchor_ || has_selection_;
    }
    cursor_ = offset;
    ensureVisible(cursor_);
    emit cursorMoved(cursor_);
    const auto sel = selection();
    emit selectionChanged(sel.offset, sel.size);
    viewport()->update();
}

bool HexView::inDiff(std::uint64_t offset, std::size_t& hint) const {
    // Ranges are sorted; painting walks offsets in order, so the hint advances monotonically.
    while (hint < diff_.size() && diff_[hint].offset + diff_[hint].size <= offset) ++hint;
    return hint < diff_.size() && diff_[hint].offset <= offset;
}

void HexView::paintEvent(QPaintEvent*) {
    QPainter p(viewport());
    const QPalette& pal = palette();
    const QColor base = pal.color(QPalette::Base), text = pal.color(QPalette::Text);
    const QColor dim = blend(base, text, 0.45);
    const QColor sel = pal.color(QPalette::Highlight), sel_text = pal.color(QPalette::HighlightedText);
    const QColor structure = blend(base, sel, 0.18);
    const QColor changed = blend(base, QColor(220, 60, 60), 0.35);
    const QColor match = blend(base, QColor(230, 180, 30), 0.55);
    p.fillRect(viewport()->rect(), base);
    p.setFont(font());
    p.translate(-horizontalScrollBar()->value(), 0);
    if (size() == 0) {
        p.setPen(dim);
        p.drawText(QRect(0, 0, viewport()->width(), line_h_ * 2), Qt::AlignCenter, tr("No file"));
        return;
    }
    // Gutter.
    p.fillRect(QRect(0, 0, x_hex_ - char_w_, viewport()->height()), blend(base, text, 0.04));

    const auto sel_range = selection();
    const std::uint64_t first = topRow();
    const int rows = visibleRows() + 1;
    const int ascent = QFontMetrics(font()).ascent() + 1;
    std::size_t hint = 0;
    if (!diff_.empty()) {
        const auto it = std::lower_bound(diff_.begin(), diff_.end(), first * kBytesPerRow,
                                         [](const bw::ByteRange& r, std::uint64_t o) { return r.offset + r.size <= o; });
        hint = static_cast<std::size_t>(it - diff_.begin());
    }
    for (int r = 0; r < rows; ++r) {
        const std::uint64_t row = first + static_cast<std::uint64_t>(r);
        if (row >= rowCount()) break;
        const int y = r * line_h_;
        const std::uint64_t row_off = row * kBytesPerRow;
        p.setPen(dim);
        p.drawText(char_w_, y + ascent, QStringLiteral("%1").arg(row_off, offset_digits_, 16, QLatin1Char('0')));
        for (int i = 0; i < kBytesPerRow; ++i) {
            const std::uint64_t off = row_off + static_cast<std::uint64_t>(i);
            if (off >= size()) break;
            const std::uint8_t b = data_[static_cast<std::size_t>(off)];
            const int hx = x_hex_ + (i * 3 + (i >= 8 ? 1 : 0)) * char_w_;
            const int ax = x_ascii_ + i * char_w_;
            QColor bg;
            QColor fg = b == 0 ? dim : text;
            if (structure_ && bw::subrange_of(structure_->offset, structure_->size, off, 1)) bg = structure;
            if (inDiff(off, hint)) bg = changed;
            if (match_ && bw::subrange_of(match_->offset, match_->size, off, 1)) bg = match;
            const bool selected = sel_range.size ? bw::subrange_of(sel_range.offset, sel_range.size, off, 1) : off == cursor_;
            if (selected) {
                bg = sel;
                fg = sel_text;
            }
            if (bg.isValid()) {
                p.fillRect(QRect(hx - char_w_ / 2, y, char_w_ * 3, line_h_), bg);
                p.fillRect(QRect(ax, y, char_w_, line_h_), bg);
            }
            if (off == cursor_ && hasFocus()) {
                p.setPen(text);
                p.drawRect(QRect(hx - char_w_ / 2, y, char_w_ * 3 - 1, line_h_ - 1));
            }
            p.setPen(fg);
            static constexpr char digits[] = "0123456789abcdef";
            const QChar pair[2] = {QLatin1Char(digits[b >> 4]), QLatin1Char(digits[b & 15])};
            p.drawText(hx, y + ascent, QString(pair, 2));
            p.drawText(ax, y + ascent, QString(QChar(b >= 0x20 && b < 0x7f ? QLatin1Char(static_cast<char>(b)) : QLatin1Char('.'))));
        }
    }
}

std::optional<std::uint64_t> HexView::offsetAt(const QPoint& pos) const {
    if (size() == 0) return std::nullopt;
    const int x = pos.x() + horizontalScrollBar()->value();
    const std::uint64_t row = topRow() + static_cast<std::uint64_t>(std::max(0, pos.y()) / line_h_);
    int col = -1;
    if (x >= x_hex_ - char_w_ / 2 && x < x_ascii_ - char_w_) {
        int cell = (x - x_hex_ + char_w_ / 2) / char_w_;
        if (cell >= 8 * 3) cell -= 1;  // gap between the two 8-byte groups
        col = std::clamp(cell / 3, 0, kBytesPerRow - 1);
    } else if (x >= x_ascii_) {
        col = std::clamp((x - x_ascii_) / char_w_, 0, kBytesPerRow - 1);
    }
    if (col < 0) col = 0;
    return std::min<std::uint64_t>(row * kBytesPerRow + static_cast<std::uint64_t>(col), size() - 1);
}

void HexView::mousePressEvent(QMouseEvent* e) {
    if (e->button() != Qt::LeftButton) return;
    if (auto off = offsetAt(e->position().toPoint())) setCursor(*off, e->modifiers() & Qt::ShiftModifier);
}

void HexView::mouseMoveEvent(QMouseEvent* e) {
    if (!(e->buttons() & Qt::LeftButton)) return;
    if (auto off = offsetAt(e->position().toPoint())) setCursor(*off, true);
}

void HexView::keyPressEvent(QKeyEvent* e) {
    if (e->matches(QKeySequence::Copy)) {
        copySelection();
        return;
    }
    if (size() == 0) return;
    const bool extend = e->modifiers() & Qt::ShiftModifier;
    const std::uint64_t page = static_cast<std::uint64_t>(visibleRows()) * kBytesPerRow;
    const std::uint64_t c = cursor_;
    const std::uint64_t last = size() - 1;
    switch (e->key()) {
    case Qt::Key_Left: setCursor(c ? c - 1 : 0, extend); break;
    case Qt::Key_Right: setCursor(std::min(c + 1, last), extend); break;
    case Qt::Key_Up: setCursor(c >= kBytesPerRow ? c - kBytesPerRow : c, extend); break;
    case Qt::Key_Down: setCursor(c + kBytesPerRow <= last ? c + kBytesPerRow : c, extend); break;
    case Qt::Key_PageUp: setCursor(c >= page ? c - page : 0, extend); break;
    case Qt::Key_PageDown: setCursor(std::min(c + page, last), extend); break;
    case Qt::Key_Home:
        setCursor(e->modifiers() & Qt::ControlModifier ? 0 : c - c % kBytesPerRow, extend);
        break;
    case Qt::Key_End:
        setCursor(e->modifiers() & Qt::ControlModifier ? last : std::min(c - c % kBytesPerRow + kBytesPerRow - 1, last), extend);
        break;
    default: QAbstractScrollArea::keyPressEvent(e); return;
    }
}

void HexView::copySelection() const {
    const auto sel = selection();
    const std::uint64_t n = std::min<std::uint64_t>(sel.size ? sel.size : 1, 1 << 20);
    if (size() == 0) return;
    QString out;
    out.reserve(static_cast<qsizetype>(n * 3));
    for (std::uint64_t i = 0; i < n && sel.offset + i < size(); ++i) {
        if (i) out += QLatin1Char(' ');
        out += QStringLiteral("%1").arg(data_[static_cast<std::size_t>(sel.offset + i)], 2, 16, QLatin1Char('0'));
    }
    QApplication::clipboard()->setText(out);
}
