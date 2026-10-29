#include "entropy_view.hpp"
#include "table_model.hpp"

#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QToolTip>

#include <algorithm>

EntropyView::EntropyView(QWidget* parent) : QWidget(parent) {
    setMouseTracking(true);
    setCursor(Qt::PointingHandCursor);
}

void EntropyView::setDocument(DocumentPtr doc) {
    doc_ = std::move(doc);
    cursor_ = 0;
    update();
}

void EntropyView::setCursorOffset(std::uint64_t offset) {
    cursor_ = offset;
    update();
}

QRect EntropyView::plotRect() const {
    const int left = fontMetrics().horizontalAdvance(QStringLiteral("8.0")) + 10;
    return rect().adjusted(left, 6, -8, -fontMetrics().height() - 6);
}

std::uint64_t EntropyView::offsetAtX(int x) const {
    if (!doc_ || !doc_->ok() || doc_->file->size() == 0) return 0;
    const QRect r = plotRect();
    const double t = std::clamp(static_cast<double>(x - r.left()) / std::max(1, r.width()), 0.0, 1.0);
    const auto size = doc_->file->size();
    return std::min<std::uint64_t>(static_cast<std::uint64_t>(t * static_cast<double>(size)), size - 1);
}

void EntropyView::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const QPalette& pal = palette();
    const QColor text = pal.color(QPalette::WindowText);
    QColor grid = text;
    grid.setAlphaF(0.15f);
    QColor muted = text;
    muted.setAlphaF(0.6f);
    const QRect r = plotRect();
    p.fillRect(r, pal.color(QPalette::Base));
    p.setPen(grid);
    for (int level : {0, 2, 4, 6, 8}) {
        const int y = r.bottom() - r.height() * level / 8;
        p.drawLine(r.left(), y, r.right(), y);
        p.setPen(muted);
        p.drawText(QRect(0, y - 8, r.left() - 4, 16), Qt::AlignRight | Qt::AlignVCenter, QString::number(level));
        p.setPen(grid);
    }
    if (!doc_ || !doc_->ok() || doc_->entropy.empty()) {
        p.setPen(muted);
        p.drawText(r, Qt::AlignCenter, tr("Entropy per window (bits/byte) appears here"));
        return;
    }
    const double size = static_cast<double>(doc_->file->size());
    auto xOf = [&](std::uint64_t off) { return r.left() + static_cast<double>(r.width()) * static_cast<double>(off) / size; };

    // Section boundaries (file-backed sections only).
    QColor boundary = pal.color(QPalette::Highlight);
    boundary.setAlphaF(0.35f);
    p.setPen(QPen(boundary, 1, Qt::DashLine));
    for (const auto& s : doc_->analysis.sections)
        if (s.size && s.file_range_valid) p.drawLine(QPointF(xOf(s.offset), r.top()), QPointF(xOf(s.offset), r.bottom()));

    // Entropy as a filled step plot.
    QPainterPath path;
    path.moveTo(r.left(), r.bottom());
    for (const auto& w : doc_->entropy) {
        const double y = r.bottom() - r.height() * w.entropy / 8.0;
        path.lineTo(xOf(w.offset), y);
        path.lineTo(xOf(w.offset + w.size), y);
    }
    path.lineTo(r.right(), r.bottom());
    QColor fill = pal.color(QPalette::Highlight);
    fill.setAlphaF(0.30f);
    p.fillPath(path, fill);
    p.setPen(QPen(pal.color(QPalette::Highlight), 1.2));
    p.drawPath(path);

    // Hex cursor.
    p.setPen(QPen(text, 1.5));
    p.drawLine(QPointF(xOf(cursor_), r.top()), QPointF(xOf(cursor_), r.bottom()));

    p.setPen(muted);
    p.drawText(QRect(r.left(), r.bottom() + 3, r.width(), fontMetrics().height()), Qt::AlignLeft,
               tr("0x0"));
    p.drawText(QRect(r.left(), r.bottom() + 3, r.width(), fontMetrics().height()), Qt::AlignRight,
               hexText(doc_->file->size()));
    p.drawText(QRect(r.left(), r.bottom() + 3, r.width(), fontMetrics().height()), Qt::AlignHCenter,
               tr("window %1 bytes").arg(doc_->entropy_window));
}

void EntropyView::mousePressEvent(QMouseEvent* e) {
    if (e->button() == Qt::LeftButton && doc_ && doc_->ok()) emit offsetActivated(offsetAtX(e->position().toPoint().x()));
}

void EntropyView::mouseMoveEvent(QMouseEvent* e) {
    if (!doc_ || !doc_->ok() || doc_->entropy.empty()) return;
    const auto off = offsetAtX(e->position().toPoint().x());
    const auto idx = std::min<std::size_t>(static_cast<std::size_t>(off / doc_->entropy_window), doc_->entropy.size() - 1);
    const auto& w = doc_->entropy[idx];
    QToolTip::showText(e->globalPosition().toPoint(),
                       tr("%1 – %2\n%3 bits/byte").arg(hexText(w.offset), hexText(w.offset + w.size)).arg(w.entropy, 0, 'f', 3),
                       this);
    if (e->buttons() & Qt::LeftButton) emit offsetActivated(off);
}
