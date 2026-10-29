#include "compare_window.hpp"

#include "hex_view.hpp"
#include "table_model.hpp"

#include <QFileInfo>
#include <QInputDialog>
#include <QLabel>
#include <QListWidget>
#include <QMenuBar>
#include <QSplitter>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>

namespace {
QString qs(const std::string& s) { return QString::fromStdString(s); }

QWidget* titled(const QString& title, QWidget* w, const QString& tooltip = {}) {
    auto* box = new QWidget;
    auto* l = new QVBoxLayout(box);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(2);
    auto* label = new QLabel(title);
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    QFont f = label->font();
    f.setBold(true);
    label->setFont(f);
    label->setToolTip(tooltip);
    l->addWidget(label);
    l->addWidget(w, 1);
    return box;
}
} // namespace

CompareWindow::CompareWindow(DocumentPtr a, DocumentPtr b, QWidget* parent)
    : QMainWindow(parent), a_(std::move(a)), b_(std::move(b)) {
    setWindowTitle(tr("Compare %1 ↔ %2 — BinWeaver").arg(QFileInfo(a_->path).fileName(), QFileInfo(b_->path).fileName()));
    resize(1500, 900);

    summary_ = new QLabel(tr("Comparing…"));
    summary_->setWordWrap(true);
    summary_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    changes_ = new TablePanel;
    caveats_ = new QListWidget;
    caveats_->setWordWrap(true);
    hex_a_ = new HexView;
    hex_b_ = new HexView;
    hex_a_->setFile(a_->file);
    hex_b_->setFile(b_->file);

    auto* top = new QSplitter(Qt::Horizontal);
    top->addWidget(titled(tr("Structural changes"), changes_));
    top->addWidget(titled(tr("What could not be compared reliably"), caveats_));
    top->setStretchFactor(0, 3);
    top->setStretchFactor(1, 1);
    auto* bottom = new QSplitter(Qt::Horizontal);
    bottom->addWidget(titled(tr("A: %1").arg(QFileInfo(a_->path).fileName()), hex_a_, a_->path));
    bottom->addWidget(titled(tr("B: %1").arg(QFileInfo(b_->path).fileName()), hex_b_, b_->path));
    auto* vertical = new QSplitter(Qt::Vertical);
    vertical->addWidget(top);
    vertical->addWidget(bottom);
    vertical->setStretchFactor(0, 2);
    vertical->setStretchFactor(1, 3);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);
    layout->addWidget(summary_);
    layout->addWidget(vertical, 1);
    setCentralWidget(central);

    // Scroll and cursor stay in step; the views share file offsets because the
    // raw comparison is positional.
    connect(hex_a_, &HexView::topOffsetChanged, hex_b_, [this](quint64 o) { hex_b_->setTopOffset(o); });
    connect(hex_b_, &HexView::topOffsetChanged, hex_a_, [this](quint64 o) { hex_a_->setTopOffset(o); });

    auto* go = menuBar()->addMenu(tr("&Go"));
    go->addAction(tr("Next Change"), QKeySequence::FindNext, this, [this] { jumpToChange(true); });
    go->addAction(tr("Previous Change"), QKeySequence::FindPrevious, this, [this] { jumpToChange(false); });
    go->addAction(tr("Go to &Offset…"), QKeySequence(Qt::CTRL | Qt::Key_G), this, [this] {
        bool ok = false;
        const auto t = QInputDialog::getText(this, tr("Go to offset"), tr("File offset (0x… or decimal):"), QLineEdit::Normal,
                                             hexText(hex_a_->cursor()), &ok).trimmed();
        if (!ok) return;
        const quint64 v = t.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? t.mid(2).toULongLong(&ok, 16) : t.toULongLong(&ok);
        if (!ok) return;
        hex_a_->goTo(v);
        hex_b_->goTo(v);
    });
    go->addAction(tr("Close"), QKeySequence::Close, this, &QWidget::close);

    connect(changes_, &TablePanel::rowActivated, this, [this](int row) {
        if (!diff_ || row < 0 || static_cast<std::size_t>(row) >= diff_->changes.size()) return;
        const auto& c = diff_->changes[static_cast<std::size_t>(row)];
        if (c.range_a) {
            hex_a_->setStructureHighlight(c.range_a);
            hex_a_->goTo(c.range_a->offset, c.range_a->size);
        }
        if (c.range_b) {
            hex_b_->setStructureHighlight(c.range_b);
            hex_b_->goTo(c.range_b->offset, c.range_b->size);
        }
    });

    connect(&watcher_, &QFutureWatcher<std::shared_ptr<const bw::StructuralDiff>>::finished, this,
            [this] { showDiff(watcher_.result()); });
    const auto da = a_, db = b_;
    watcher_.setFuture(QtConcurrent::run([da, db] {
        return std::shared_ptr<const bw::StructuralDiff>(
            std::make_shared<bw::StructuralDiff>(bw::diff_structure(da->analysis, *da->file, db->analysis, *db->file)));
    }));
    statusBar()->showMessage(tr("F3 / Shift+F3: next / previous changed bytes. Select a structural change to show it in both files."));
}

CompareWindow::~CompareWindow() { watcher_.waitForFinished(); }

void CompareWindow::showDiff(std::shared_ptr<const bw::StructuralDiff> d) {
    diff_ = std::move(d);
    const auto& r = diff_->raw;
    summary_->setText(tr("<b>%1</b> added · <b>%2</b> removed · <b>%3</b> modified%4 &nbsp;&nbsp;|&nbsp;&nbsp; raw bytes: "
                         "%5 of %6 differ (%7%), %8 changed run(s)%9")
                          .arg(diff_->count(bw::ChangeKind::Added))
                          .arg(diff_->count(bw::ChangeKind::Removed))
                          .arg(diff_->count(bw::ChangeKind::Modified))
                          .arg(diff_->truncated ? tr(" (truncated)") : QString())
                          .arg(r.changed)
                          .arg(std::max(r.size_a, r.size_b))
                          .arg(r.changed_percent, 0, 'f', 2)
                          .arg(r.ranges.size())
                          .arg(r.ranges_truncated ? tr(" (list truncated)") : QString()));
    const auto dd = diff_;
    auto at = [dd](int i) -> const bw::StructuralChange& { return dd->changes[static_cast<std::size_t>(i)]; };
    auto rangeText = [](const std::optional<bw::ByteRange>& x) {
        return x ? QStringLiteral("%1 +%2").arg(hexText(x->offset), hexText(x->size)) : QString();
    };
    changes_->setModel(new RecordModel(
        static_cast<int>(diff_->changes.size()),
        {Column{tr("Category"), [at](int i) { return QVariant(qs(at(i).category)); }},
         Column{tr("Subject"), [at](int i) { return QVariant(qs(at(i).subject)); }},
         Column{tr("Change"), [at](int i) { return QVariant(QString::fromLatin1(bw::change_kind_name(at(i).kind))); }},
         Column{tr("Confidence"), [at](int i) { return QVariant(QString::fromLatin1(bw::confidence_name(at(i).confidence))); }},
         Column{tr("Range A"), [at, rangeText](int i) { return QVariant(rangeText(at(i).range_a)); }},
         Column{tr("Range B"), [at, rangeText](int i) { return QVariant(rangeText(at(i).range_b)); }},
         Column{tr("Detail"), [at](int i) { return QVariant(qs(at(i).detail)); }}}));
    caveats_->clear();
    for (const auto& c : diff_->caveats) caveats_->addItem(qs(c));
    if (diff_->caveats.empty()) caveats_->addItem(tr("No caveats."));
    hex_a_->setDiffRanges(diff_->raw.ranges);
    hex_b_->setDiffRanges(diff_->raw.ranges);
    emit diffReady();
}

bool CompareWindow::jumpToChange(bool forward) {
    if (!diff_ || diff_->raw.ranges.empty()) {
        statusBar()->showMessage(tr("No changed bytes in the common prefix."), 3000);
        return false;
    }
    const auto& ranges = diff_->raw.ranges;
    const std::uint64_t cur = hex_a_->cursor();
    const bw::ByteRange* target = nullptr;
    if (forward) {
        auto it = std::upper_bound(ranges.begin(), ranges.end(), cur, [](std::uint64_t o, const bw::ByteRange& r) { return o < r.offset; });
        target = it != ranges.end() ? &*it : &ranges.front();
    } else {
        auto it = std::lower_bound(ranges.begin(), ranges.end(), cur, [](const bw::ByteRange& r, std::uint64_t o) { return r.offset < o; });
        target = it != ranges.begin() ? &*(it - 1) : &ranges.back();
    }
    hex_a_->goTo(target->offset, target->size);
    hex_b_->goTo(target->offset, target->size);
    statusBar()->showMessage(tr("Changed run at %1, %2 byte(s)").arg(hexText(target->offset)).arg(target->size), 4000);
    return true;
}
