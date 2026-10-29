#include "main_window.hpp"

#include "compare_window.hpp"
#include "entropy_view.hpp"
#include "hex_view.hpp"
#include "table_model.hpp"

#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDockWidget>
#include <QDragEnterEvent>
#include <QFileDialog>
#include <QFile>
#include <QFileInfo>
#include <QFontDatabase>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QMimeData>
#include <QPointer>
#include <QProgressBar>
#include <QSaveFile>
#include <QSettings>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTableWidget>
#include <QToolBar>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <climits>

namespace {

QString qs(const std::string& s) { return QString::fromStdString(s); }

std::optional<std::uint64_t> parseNumber(QString text) {
    text = text.trimmed().remove(QLatin1Char('_'));
    bool ok = false;
    std::uint64_t v = 0;
    if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) v = text.mid(2).toULongLong(&ok, 16);
    else if (text.endsWith(QLatin1Char('h'), Qt::CaseInsensitive)) v = text.chopped(1).toULongLong(&ok, 16);
    else v = text.toULongLong(&ok, 10);
    return ok ? std::optional<std::uint64_t>(v) : std::nullopt;
}

// Range of file bytes an address occupies, if it is file-backed.
std::optional<bw::ByteRange> mappedRange(const bw::Analysis& a, std::uint64_t address, std::uint64_t length) {
    const auto m = bw::address_to_offset(a, address);
    if (m.status != bw::MapStatus::FileBacked) return std::nullopt;
    return bw::ByteRange{m.offset, std::max<std::uint64_t>(1, std::min<std::uint64_t>(length, a.file_size - m.offset))};
}

std::optional<bw::ByteRange> fileRange(std::uint64_t offset, std::uint64_t size, std::uint64_t file_size) {
    if (size == 0 || offset >= file_size) return std::nullopt;
    return bw::ByteRange{offset, std::min(size, file_size - offset)};
}

Column textColumn(const QString& title, std::function<QString(int)> fn) {
    auto shared = std::make_shared<std::function<QString(int)>>(std::move(fn));
    return Column{title, [shared](int r) { return QVariant((*shared)(r)); }};
}

Column hexColumn(const QString& title, std::function<std::uint64_t(int)> fn) {
    auto shared = std::make_shared<std::function<std::uint64_t(int)>>(std::move(fn));
    return Column{title, [shared](int r) { return QVariant::fromValue<quint64>((*shared)(r)); },
                  [shared](int r) { return hexText((*shared)(r)); }, true};
}

Column numColumn(const QString& title, std::function<std::uint64_t(int)> fn) {
    auto shared = std::make_shared<std::function<std::uint64_t(int)>>(std::move(fn));
    return Column{title, [shared](int r) { return QVariant::fromValue<quint64>((*shared)(r)); }, {}, true};
}

int rows(std::size_t n) { return static_cast<int>(std::min<std::size_t>(n, INT_MAX)); }

} // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(tr("BinWeaver"));
    setAcceptDrops(true);
    resize(1400, 880);

    // Left: categories. Center: tables over hex. Docks: inspector, entropy.
    nav_ = new QListWidget;
    nav_->setMinimumWidth(150);
    pages_ = new QStackedWidget;
    hex_ = new HexView;
    buildFindBar();

    auto* hex_container = new QWidget;
    auto* hex_layout = new QVBoxLayout(hex_container);
    hex_layout->setContentsMargins(0, 0, 0, 0);
    hex_layout->setSpacing(0);
    hex_layout->addWidget(find_bar_);
    hex_layout->addWidget(hex_, 1);

    auto* right = new QSplitter(Qt::Vertical);
    right->setObjectName(QStringLiteral("tablesHexSplitter"));
    right->addWidget(pages_);
    right->addWidget(hex_container);
    right->setStretchFactor(0, 1);
    right->setStretchFactor(1, 1);
    right->setSizes({380, 420});
    icon_label_ = new QLabel;
    icon_label_->setAlignment(Qt::AlignCenter);
    icon_label_->setToolTip(tr("Application icon (first RT_GROUP_ICON)"));
    icon_label_->hide();
    auto* left = new QWidget;
    auto* left_layout = new QVBoxLayout(left);
    left_layout->setContentsMargins(0, 0, 0, 0);
    left_layout->addWidget(icon_label_);
    left_layout->addWidget(nav_, 1);
    auto* main = new QSplitter(Qt::Horizontal);
    main->setObjectName(QStringLiteral("navSplitter"));
    main->addWidget(left);
    main->addWidget(right);
    main->setStretchFactor(1, 1);
    main->setSizes({180, 1200});
    setCentralWidget(main);

    inspector_ = new QTreeWidget;
    inspector_->setColumnCount(2);
    inspector_->setHeaderLabels({tr("Field"), tr("Value")});
    inspector_->setRootIsDecorated(true);
    inspector_->setUniformRowHeights(true);
    inspector_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    auto* inspector_dock = new QDockWidget(tr("Inspector"));
    inspector_dock->setObjectName(QStringLiteral("inspectorDock"));
    inspector_dock->setWidget(inspector_);
    addDockWidget(Qt::RightDockWidgetArea, inspector_dock);

    entropy_ = new EntropyView;
    auto* entropy_dock = new QDockWidget(tr("Entropy"));
    entropy_dock->setObjectName(QStringLiteral("entropyDock"));
    entropy_dock->setWidget(entropy_);
    addDockWidget(Qt::BottomDockWidgetArea, entropy_dock);

    status_file_ = new QLabel;
    status_offset_ = new QLabel;
    busy_ = new QProgressBar;
    busy_->setRange(0, 0);
    busy_->setMaximumWidth(160);
    busy_->hide();
    statusBar()->addWidget(status_file_, 1);
    statusBar()->addPermanentWidget(status_offset_);
    statusBar()->addPermanentWidget(busy_);
    statusBar()->showMessage(tr("Open a PE or ELF file (Ctrl+O) or drop it here. Files are never executed."));

    connect(nav_, &QListWidget::currentRowChanged, pages_, &QStackedWidget::setCurrentIndex);
    connect(hex_, &HexView::cursorMoved, this, &MainWindow::onCursorMoved);
    connect(hex_, &HexView::selectionChanged, this, &MainWindow::onSelectionChanged);
    connect(entropy_, &EntropyView::offsetActivated, this, [this](quint64 off) {
        navigate(off);
        hex_->setFocus();
    });
    connect(inspector_, &QTreeWidget::itemActivated, this, [this](QTreeWidgetItem* item) {
        const auto off = item->data(0, Qt::UserRole);
        if (off.isValid()) hex_->goTo(off.toULongLong(), item->data(0, Qt::UserRole + 1).toULongLong());
    });
    connect(&loader_, &QFutureWatcher<DocumentPtr>::finished, this, [this] {
        clearBusy();
        showDocument(loader_.result());
    });
    connect(&compare_loader_, &QFutureWatcher<DocumentPtr>::finished, this, [this] {
        clearBusy();
        auto b = compare_loader_.result();
        if (!b->ok()) {
            QMessageBox::warning(this, tr("Compare"), tr("Cannot open %1:\n%2").arg(b->path, b->error));
            return;
        }
        auto* w = new CompareWindow(doc_, b);
        w->setAttribute(Qt::WA_DeleteOnClose);
        last_compare_ = w;
        connect(w, &QObject::destroyed, this, [this, w] {
            if (last_compare_ == w) last_compare_ = nullptr;
        });
        w->show();
        emit compareWindowOpened(w);
    });

    connect(&search_, &QFutureWatcher<std::optional<quint64>>::finished, this, [this] {
        find_cancel_->setEnabled(false);
        const bool cancelled = search_cancel_ && search_cancel_->load();
        const auto hit = search_.result();
        if (!hit) {
            find_status_->setText(cancelled ? tr("  cancelled") : tr("  not found"));
            hex_->setMatch(std::nullopt);
            emit searchFinished(false);
            return;
        }
        find_status_->setText(tr("  match at %1").arg(hexText(*hit)));
        const bw::ByteRange m{*hit, search_length_};
        hex_->setMatch(m);
        navigate(m.offset, m.size);
        emit searchFinished(true);
    });
    connect(&search_all_, &QFutureWatcher<std::vector<std::uint64_t>>::finished, this, [this] {
        find_cancel_->setEnabled(false);
        const auto hits = search_all_.result();
        const bool cancelled = search_cancel_ && search_cancel_->load();
        find_status_->setText(tr("  %n match(es)", nullptr, static_cast<int>(hits.size())) +
                              (cancelled ? tr(" (cancelled)") : hits.size() >= 100000 ? tr(" (limit reached)") : QString()));
        showSearchResults(hits);
        emit searchFinished(!hits.empty());
    });

    buildActions();
    QSettings settings;
    restoreGeometry(settings.value(QStringLiteral("geometry")).toByteArray());
    restoreState(settings.value(QStringLiteral("state")).toByteArray());
    main->restoreState(settings.value(QStringLiteral("navSplitter")).toByteArray());
    right->restoreState(settings.value(QStringLiteral("tablesHexSplitter")).toByteArray());
}

MainWindow::~MainWindow() {
    cancelSearch();
    search_.waitForFinished();
    search_all_.waitForFinished();
    loader_.waitForFinished();
    compare_loader_.waitForFinished();
}

void MainWindow::buildActions() {
    auto* file = menuBar()->addMenu(tr("&File"));
    auto* open = file->addAction(tr("&Open…"), this, [this] {
        const auto p = QFileDialog::getOpenFileName(this, tr("Open binary"));
        if (!p.isEmpty()) openFile(p);
    });
    open->setShortcut(QKeySequence::Open);
    recent_menu_ = file->addMenu(tr("Open &Recent"));
    rebuildRecentMenu();
    auto* cmp = file->addAction(tr("&Compare With…"), this, [this] {
        if (!doc_ || !doc_->ok()) return;
        const auto p = QFileDialog::getOpenFileName(this, tr("Compare %1 with").arg(QFileInfo(doc_->path).fileName()));
        if (!p.isEmpty()) compareWith(p);
    });
    cmp->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_O));
    file->addAction(tr("Run &Rules…"), this, [this] {
        if (!doc_ || !doc_->ok()) return;
        const auto p = QFileDialog::getOpenFileName(this, tr("Rule file"), {}, tr("Rules (*.rules *.txt);;All files (*)"));
        if (p.isEmpty()) return;
        const auto errors = runRules(p);
        if (!errors.isEmpty()) QMessageBox::warning(this, tr("Rules"), errors.join(QLatin1Char('\n')));
    });
    auto* save_sel = file->addAction(tr("&Save Selection As…"), this, [this] {
        if (!doc_ || !doc_->ok()) return;
        const auto sel = hex_->selection();
        const quint64 len = std::max<quint64>(sel.size, 1);
        const auto path = QFileDialog::getSaveFileName(this, tr("Save %1 bytes from %2").arg(len).arg(hexText(sel.offset)),
                                                       QStringLiteral("selection-%1.bin").arg(sel.offset, 0, 16));
        if (path.isEmpty()) return;
        QString error;
        if (!saveSelection(path, &error)) QMessageBox::warning(this, tr("Save selection"), error);
    });
    save_sel->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_S));
    auto* exp = file->addAction(tr("&Export Report…"), this, &MainWindow::exportReport);
    exp->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_E));
    auto* csv = file->addAction(tr("Export Current &Table as CSV…"), this, &MainWindow::exportTableCsv);
    csv->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_E));
    file->addSeparator();
    auto* quit = file->addAction(tr("&Quit"), this, &QWidget::close);
    quit->setShortcut(QKeySequence::Quit);

    auto* go = menuBar()->addMenu(tr("&Go"));
    go->addAction(tr("Go to &Offset…"), QKeySequence(Qt::CTRL | Qt::Key_G), this, &MainWindow::goToOffsetDialog);
    go->addAction(tr("Go to &Address (RVA / VA)…"), QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_G), this,
                  &MainWindow::goToAddressDialog);
    go->addAction(tr("Go to &Entry Point"), QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_P), this, [this] { goToEntryPoint(); });
    go->addAction(tr("&Back"), QKeySequence(Qt::ALT | Qt::Key_Left), this, [this] { goBack(); });
    go->addAction(tr("For&ward"), QKeySequence(Qt::ALT | Qt::Key_Right), this, [this] { goForward(); });
    go->addSeparator();
    go->addAction(tr("Add &Bookmark…"), QKeySequence(Qt::CTRL | Qt::Key_D), this, [this] {
        if (!doc_ || !doc_->ok()) return;
        const auto sel = hex_->selection();
        bool ok = false;
        const auto note = QInputDialog::getText(this, tr("Add bookmark"), tr("Note for %1:").arg(hexText(sel.offset)),
                                                QLineEdit::Normal, {}, &ok);
        if (ok) addBookmark(sel.offset, std::max<quint64>(sel.size, 1), note);
    });
    go->addAction(tr("Remove Bookmark at Cursor"), QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_D), this,
                  [this] { removeBookmarkAt(hex_->cursor()); });
    go->addAction(tr("Next Bookmark"), QKeySequence(Qt::Key_F2), this, [this] { nextBookmark(true); });
    go->addAction(tr("Previous Bookmark"), QKeySequence(Qt::SHIFT | Qt::Key_F2), this, [this] { nextBookmark(false); });
    go->addSeparator();
    go->addAction(tr("&Find Bytes…"), QKeySequence::Find, this, [this] {
        find_bar_->show();
        find_text_->setFocus();
        find_text_->selectAll();
    });
    go->addAction(tr("Find &Next"), QKeySequence::FindNext, this, [this] { findNext(true); });
    go->addAction(tr("Find &Previous"), QKeySequence::FindPrevious, this, [this] { findNext(false); });
    go->addSeparator();
    go->addAction(tr("Focus &Hex View"), QKeySequence(Qt::CTRL | Qt::Key_H), this, [this] { hex_->setFocus(); });
    go->addAction(tr("Focus Table &Filter"), QKeySequence(Qt::CTRL | Qt::Key_L), this, [this] {
        if (auto* p = qobject_cast<TablePanel*>(pages_->currentWidget())) p->filter()->setFocus();
    });
    go->addAction(tr("Next Category"), QKeySequence(Qt::CTRL | Qt::Key_PageDown), this, [this] {
        for (int r = nav_->currentRow() + 1; r < nav_->count(); ++r)
            if (!nav_->item(r)->isHidden()) return nav_->setCurrentRow(r);
    });
    go->addAction(tr("Previous Category"), QKeySequence(Qt::CTRL | Qt::Key_PageUp), this, [this] {
        for (int r = nav_->currentRow() - 1; r >= 0; --r)
            if (!nav_->item(r)->isHidden()) return nav_->setCurrentRow(r);
    });

    auto* view = menuBar()->addMenu(tr("&View"));
    for (auto* dock : findChildren<QDockWidget*>()) view->addAction(dock->toggleViewAction());
    view->addAction(tr("Reset &Layout"), this, [this] {
        for (auto* dock : findChildren<QDockWidget*>()) {
            dock->setFloating(false);
            dock->show();
        }
    });

    auto* help = menuBar()->addMenu(tr("&Help"));
    help->addAction(tr("&Keyboard Shortcuts"), QKeySequence(Qt::Key_F1), this, &MainWindow::showShortcuts);
    help->addAction(tr("&About BinWeaver"), this, [this] {
        QMessageBox::about(this, tr("About BinWeaver"),
                           tr("<b>BinWeaver %1</b><p>Static PE/ELF structure inspector. Files are mapped read-only and "
                              "never executed. Structural findings are not a malware verdict.</p>")
                               .arg(QStringLiteral(BINWEAVER_VERSION)));
    });
}

void MainWindow::buildFindBar() {
    find_bar_ = new QToolBar;
    find_bar_->setIconSize({16, 16});
    find_mode_ = new QComboBox;
    find_mode_->addItems({tr("Hex"), tr("Text")});
    find_mode_->setToolTip(tr("Hex: bytes like 4D 5A ?? 00 (?? matches any byte). Text: literal ASCII/UTF-8."));
    find_text_ = new QLineEdit;
    find_text_->setPlaceholderText(tr("Find bytes, e.g. 50 45 00 00"));
    find_text_->setClearButtonEnabled(true);
    find_status_ = new QLabel;
    find_bar_->addWidget(new QLabel(tr(" Find ")));
    find_bar_->addWidget(find_mode_);
    find_bar_->addWidget(find_text_);
    find_bar_->addAction(tr("Previous"), this, [this] { findNext(false); });
    find_bar_->addAction(tr("Next"), this, [this] { findNext(true); });
    find_bar_->addAction(tr("Find All"), this, [this] { findAll(); });
    find_cancel_ = find_bar_->addAction(tr("Cancel"), this, &MainWindow::cancelSearch);
    find_cancel_->setShortcut(QKeySequence(Qt::Key_Escape));
    find_cancel_->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    find_cancel_->setEnabled(false);
    find_bar_->addWidget(find_status_);
    connect(find_text_, &QLineEdit::returnPressed, this, [this] { findNext(true); });
}

void MainWindow::setFindPattern(const QString& text, bool hex) {
    find_mode_->setCurrentIndex(hex ? 0 : 1);
    find_text_->setText(text);
}

std::optional<bw::BytePattern> MainWindow::currentPattern() {
    std::string error;
    auto pattern = bw::parse_pattern(find_text_->text().toStdString(), find_mode_->currentIndex() == 1, error);
    if (!pattern) find_status_->setText(QStringLiteral("  ") + qs(error));
    return pattern;
}

// Progress callback for the worker thread: posts percentages to the UI and
// stops when the user cancels.
bw::SearchProgress MainWindow::progressReporter() {
    search_cancel_ = std::make_shared<std::atomic<bool>>(false);
    auto cancel = search_cancel_;
    QPointer<QLabel> status = find_status_;
    return [cancel, status](std::uint64_t done, std::uint64_t total) {
        if (status && total) {
            const int pct = static_cast<int>(100.0 * static_cast<double>(done) / static_cast<double>(total));
            QMetaObject::invokeMethod(status, [status, pct] {
                if (status) status->setText(QObject::tr("  searching… %1%").arg(pct));
            }, Qt::QueuedConnection);
        }
        return !cancel->load();
    };
}

void MainWindow::cancelSearch() {
    if (search_cancel_) search_cancel_->store(true);
}

bool MainWindow::findNext(bool forward) {
    if (!doc_ || !doc_->ok() || searchRunning()) return false;
    const auto pattern = currentPattern();
    if (!pattern) return false;
    const auto sel = hex_->selection();
    // Continue after the current match/selection; start at 0 on a fresh document.
    const std::uint64_t from = forward ? (sel.size || hex_->cursor() ? hex_->cursor() + 1 : 0) : sel.offset;
    search_length_ = pattern->bytes.size();
    find_cancel_->setEnabled(true);
    find_status_->setText(tr("  searching…"));
    const auto doc = doc_;
    const auto progress = progressReporter();
    search_.setFuture(QtConcurrent::run([doc, p = *pattern, from, forward, progress]() -> std::optional<quint64> {
        auto hit = bw::find_pattern(doc->bytes(), p, from, forward, progress);
        if (!hit && progress(0, 0)) hit = bw::find_pattern(doc->bytes(), p, forward ? 0 : doc->file->size(), forward, progress);  // wrap
        return hit;
    }));
    return true;
}

bool MainWindow::findAll() {
    if (!doc_ || !doc_->ok() || searchRunning()) return false;
    const auto pattern = currentPattern();
    if (!pattern) return false;
    search_length_ = pattern->bytes.size();
    find_cancel_->setEnabled(true);
    find_status_->setText(tr("  searching…"));
    const auto doc = doc_;
    const auto progress = progressReporter();
    search_all_.setFuture(QtConcurrent::run([doc, p = *pattern, progress] {
        return bw::find_all(doc->bytes(), p, 100000, progress);
    }));
    return true;
}

void MainWindow::showSearchResults(const std::vector<std::uint64_t>& hits) {
    const QString name = tr("Search results");
    if (auto* old = panel(name)) {
        for (int r = 0; r < nav_->count(); ++r)
            if (nav_->item(r)->data(Qt::UserRole).toString() == name) delete nav_->takeItem(r);
        pages_->removeWidget(old);
        old->deleteLater();
        panels_.erase(name);
    }
    auto shared = std::make_shared<const std::vector<std::uint64_t>>(hits);
    const auto d = doc_;
    const std::uint64_t len = search_length_;
    auto* p = new TablePanel;
    p->setModel(new RecordModel(
        static_cast<int>(shared->size()),
        {Column{tr("Offset"), [shared](int r) { return QVariant::fromValue<quint64>((*shared)[static_cast<std::size_t>(r)]); },
                [shared](int r) { return hexText((*shared)[static_cast<std::size_t>(r)]); }, true},
         Column{tr("Inside"), [shared, d](int r) {
                    const auto regions = bw::locate(d->analysis, (*shared)[static_cast<std::size_t>(r)]);
                    return QVariant(regions.empty() ? QString() : qs(regions.front().name));
                }},
         Column{tr("Address"), [shared, d](int r) {
                    const auto addrs = bw::offset_to_addresses(d->analysis, (*shared)[static_cast<std::size_t>(r)]);
                    return QVariant(addrs.empty() ? QString() : hexText(addrs.front()));
                }}},
        [shared, len](int r) { return std::optional<bw::ByteRange>(bw::ByteRange{(*shared)[static_cast<std::size_t>(r)], len}); }));
    addPanel(name, p);
    nav_->setCurrentRow(nav_->count() - 1);
}

void MainWindow::openFile(const QString& path) {
    if (loader_.isRunning()) return;
    setBusy(tr("Analyzing %1…").arg(QFileInfo(path).fileName()));
    loader_.setFuture(QtConcurrent::run([path] { return Document::load(path); }));
}

void MainWindow::compareWith(const QString& path) {
    if (!doc_ || !doc_->ok() || compare_loader_.isRunning()) return;
    setBusy(tr("Analyzing %1 for comparison…").arg(QFileInfo(path).fileName()));
    compare_loader_.setFuture(QtConcurrent::run([path] { return Document::load(path); }));
}

void MainWindow::setBusy(const QString& message) {
    busy_->show();
    statusBar()->showMessage(message);
}

void MainWindow::clearBusy() {
    busy_->hide();
    statusBar()->clearMessage();
}

void MainWindow::showDocument(DocumentPtr doc) {
    cancelSearch();
    search_.waitForFinished();
    search_all_.waitForFinished();
    if (!doc->ok()) {
        QMessageBox::warning(this, tr("Open"), tr("Cannot open %1:\n%2").arg(doc->path, doc->error));
        return;
    }
    doc_ = std::move(doc);
    const auto& a = doc_->analysis;
    setWindowTitle(tr("%1 — BinWeaver").arg(QFileInfo(doc_->path).fileName()));
    hex_->setFile(doc_->file);
    entropy_->setDocument(doc_);
    back_.clear();
    forward_.clear();
    loadBookmarks();
    icon_label_->hide();
    icon_label_->setPixmap({});
    if (auto ico = bw::extract_icon(a, *doc_->file)) {
        QPixmap pm;
        if (pm.loadFromData(ico->data(), static_cast<uint>(ico->size()), "ICO")) {
            icon_label_->setPixmap(pm.scaled(48, 48, Qt::KeepAspectRatio, Qt::SmoothTransformation));
            icon_label_->show();
        }
    }
    populatePanels();
    const int errors = static_cast<int>(std::count_if(a.diagnostics.begin(), a.diagnostics.end(),
                                                      [](const bw::Diagnostic& d) { return d.severity == bw::Severity::Error; }));
    status_file_->setText(tr("%1 · %2 %3 %4 · %5 bytes · %6 · analyzed in %7 s")
                              .arg(QFileInfo(doc_->path).fileName(), qs(bw::format_name(a.format)), qs(a.architecture),
                                   qs(a.bitness))
                              .arg(a.file_size)
                              .arg(errors ? tr("%n structural error(s)", nullptr, errors) : tr("no structural errors"))
                              .arg(doc_->load_seconds, 0, 'f', 2));
    addRecent(doc_->path);
    hex_->goTo(0);
    hex_->setFocus();
    emit documentLoaded();
}

void MainWindow::addPanel(const QString& name, TablePanel* panel) {
    panels_[name] = panel;
    pages_->addWidget(panel);
    auto* item = new QListWidgetItem(QStringLiteral("%1  (%2)").arg(name).arg(panel->model()->rowCount()));
    item->setData(Qt::UserRole, name);
    nav_->addItem(item);
    connect(panel, &TablePanel::rangeActivated, this, [this](quint64 off, quint64 len) {
        hex_->setStructureHighlight(bw::ByteRange{off, len});
        navigate(off, len);
    });
}

TablePanel* MainWindow::panel(const QString& name) const {
    auto it = panels_.find(name);
    return it == panels_.end() ? nullptr : it->second;
}

void MainWindow::populatePanels() {
    for (auto& [name, p] : panels_) {
        pages_->removeWidget(p);
        p->deleteLater();
    }
    panels_.clear();
    nav_->clear();
    const auto d = doc_;  // captured by value: models stay valid while their panel lives
    const auto& a = d->analysis;
    const auto fs = a.file_size;
    auto make = [](int n, std::vector<Column> cols, RecordModel::RangeFn range = {}) {
        auto* p = new TablePanel;
        p->setModel(new RecordModel(n, std::move(cols), std::move(range)));
        return p;
    };

    // Overview: the fixed fields followed by format-specific properties.
    auto overview = std::make_shared<std::vector<std::pair<QString, QString>>>();
    overview->push_back({tr("Path"), d->path});
    overview->push_back({tr("Size"), tr("%1 bytes (%2)").arg(a.file_size).arg(hexText(a.file_size))});
    overview->push_back({tr("SHA-256"), qs(a.sha256)});
    overview->push_back({tr("Format"), qs(bw::format_name(a.format)) + QStringLiteral(" · ") + qs(a.file_type)});
    overview->push_back({tr("Architecture"), qs(a.architecture + " · " + a.bitness + " · " + a.byte_order)});
    overview->push_back({tr("Entry point"), hexText(a.entry_point) + (a.format == bw::Format::PE ? tr(" (RVA)") : QString())});
    overview->push_back({tr("Structurally valid"), a.structurally_valid ? tr("yes") : tr("no — see Diagnostics")});
    overview->push_back({tr("Whole-file entropy"), QString::number(bw::entropy(d->bytes()), 'f', 4) + tr(" bits/byte")});
    overview->push_back({tr("Reader"), d->file->memory_mapped() ? tr("memory-mapped") : tr("read into memory")});
    overview->push_back({tr("Strings (min. 5 chars)"),
                          d->strings.truncated
                              ? tr("first %1, scan stopped at offset %2 (limit reached)")
                                    .arg(d->strings.strings.size())
                                    .arg(hexText(d->strings.scanned))
                              : QString::number(d->strings.strings.size())});
    for (const auto& [k, v] : a.properties) overview->push_back({qs(k), qs(v)});
    addPanel(tr("Overview"), make(rows(overview->size()),
                                  {textColumn(tr("Property"), [overview](int r) { return (*overview)[static_cast<std::size_t>(r)].first; }),
                                   textColumn(tr("Value"), [overview](int r) { return (*overview)[static_cast<std::size_t>(r)].second; })}));

    auto diag = [d](int r) -> const bw::Diagnostic& { return d->analysis.diagnostics[static_cast<std::size_t>(r)]; };
    addPanel(tr("Diagnostics"),
             make(rows(a.diagnostics.size()),
                  {textColumn(tr("Severity"), [diag](int r) { return qs(bw::severity_name(diag(r).severity)); }),
                   textColumn(tr("Code"), [diag](int r) { return qs(diag(r).code); }),
                   hexColumn(tr("Offset"), [diag](int r) { return diag(r).offset; }),
                   textColumn(tr("Message"), [diag](int r) { return qs(diag(r).message); })},
                  [diag, fs](int r) { return fileRange(diag(r).offset, 1, fs); }));

    auto sectionPanel = [&](const std::vector<bw::Section>* list, bool segments) {
        auto at = [list](int r) -> const bw::Section& { return (*list)[static_cast<std::size_t>(r)]; };
        std::vector<Column> cols = {
            numColumn(tr("#"), [at](int r) { return at(r).index; }),
            textColumn(tr("Name"), [at](int r) { return qs(at(r).name); }),
            textColumn(tr("Type"), [at](int r) { return qs(at(r).kind); }),
            hexColumn(tr("File offset"), [at](int r) { return at(r).offset; }),
            hexColumn(tr("File size"), [at](int r) { return at(r).size; }),
            hexColumn(segments ? tr("Virtual address") : tr("Address"), [at](int r) { return at(r).address; }),
            hexColumn(tr("Memory size"), [at](int r) { return at(r).virtual_size; }),
            textColumn(tr("Flags"), [at](int r) { return qs(at(r).flags_text); }),
            Column{tr("Entropy"), [at](int r) { return at(r).entropy ? QVariant(*at(r).entropy) : QVariant(-1.0); },
                   [at](int r) { return at(r).entropy ? QString::number(*at(r).entropy, 'f', 3) : QString(); }, true},
            textColumn(tr("Status"), [at](int r) { return at(r).file_range_valid ? QString() : tr("outside file"); })};
        return make(rows(list->size()), std::move(cols), [at, fs](int r) {
            return at(r).file_range_valid ? fileRange(at(r).offset, at(r).size, fs) : std::nullopt;
        });
    };
    addPanel(tr("Sections"), sectionPanel(&d->analysis.sections, false));
    if (!a.segments.empty()) addPanel(tr("Segments"), sectionPanel(&d->analysis.segments, true));

    if (!d->fields.empty()) {
        auto hf = [d](int r) -> const bw::HeaderField& { return d->fields[static_cast<std::size_t>(r)]; };
        addPanel(tr("Header fields"), make(rows(d->fields.size()),
                                           {textColumn(tr("Structure"), [hf](int r) { return qs(hf(r).structure); }),
                                            textColumn(tr("Field"), [hf](int r) { return qs(hf(r).name); }),
                                            hexColumn(tr("Offset"), [hf](int r) { return hf(r).offset; }),
                                            numColumn(tr("Size"), [hf](int r) { return hf(r).size; }),
                                            textColumn(tr("Value"), [hf](int r) { return qs(hf(r).text); })},
                                           [hf](int r) { return std::optional<bw::ByteRange>(bw::ByteRange{hf(r).offset, hf(r).size}); }));
    }
    auto st = [d](int r) -> const bw::Region& { return d->analysis.structures[static_cast<std::size_t>(r)]; };
    addPanel(tr("Structures"), make(rows(a.structures.size()),
                                    {textColumn(tr("Name"), [st](int r) { return qs(st(r).name); }),
                                     textColumn(tr("Kind"), [st](int r) { return qs(st(r).kind); }),
                                     hexColumn(tr("Offset"), [st](int r) { return st(r).offset; }),
                                     hexColumn(tr("Size"), [st](int r) { return st(r).size; })},
                                    [st, fs](int r) { return fileRange(st(r).offset, st(r).size, fs); }));

    if (!a.directories.empty()) {
        auto dir = [d](int r) -> const bw::Directory& { return d->analysis.directories[static_cast<std::size_t>(r)]; };
        addPanel(tr("Directories"),
                 make(rows(a.directories.size()),
                      {numColumn(tr("#"), [dir](int r) { return dir(r).index; }),
                       textColumn(tr("Name"), [dir](int r) { return qs(dir(r).name); }),
                       hexColumn(tr("RVA / offset"), [dir](int r) { return dir(r).address; }),
                       hexColumn(tr("Size"), [dir](int r) { return dir(r).size; }),
                       textColumn(tr("File offset"), [dir](int r) { return dir(r).file_offset ? hexText(*dir(r).file_offset) : QString(); }),
                       textColumn(tr("Status"), [dir](int r) { return qs(dir(r).status); })},
                      [dir, fs](int r) { return dir(r).file_offset ? fileRange(*dir(r).file_offset, dir(r).size, fs) : std::nullopt; }));
    }
    if (!a.imports.empty()) {
        auto im = [d](int r) -> const bw::Import& { return d->analysis.imports[static_cast<std::size_t>(r)]; };
        const std::uint64_t slot = a.bitness == "64-bit" ? 8 : 4;
        addPanel(tr("Imports"),
                 make(rows(a.imports.size()),
                      {textColumn(tr("Library"), [im](int r) { return qs(im(r).library); }),
                       textColumn(tr("Name"), [im](int r) { return im(r).ordinal ? QStringLiteral("#%1").arg(*im(r).ordinal) : qs(im(r).name); }),
                       numColumn(tr("Hint"), [im](int r) { return im(r).hint; }),
                       hexColumn(tr("IAT RVA"), [im](int r) { return im(r).thunk_rva; }),
                       textColumn(tr("Load"), [im](int r) { return im(r).delayed ? tr("delayed") : tr("startup"); })},
                      [im, d, slot](int r) { return mappedRange(d->analysis, im(r).thunk_rva, slot); }));
    }
    if (!a.exports.empty()) {
        auto ex = [d](int r) -> const bw::Export& { return d->analysis.exports[static_cast<std::size_t>(r)]; };
        addPanel(tr("Exports"),
                 make(rows(a.exports.size()),
                      {numColumn(tr("Ordinal"), [ex](int r) { return ex(r).ordinal; }),
                       textColumn(tr("Name"), [ex](int r) { return qs(ex(r).name); }),
                       hexColumn(tr("RVA"), [ex](int r) { return ex(r).rva; }),
                       textColumn(tr("Forwarder"), [ex](int r) { return qs(ex(r).forwarder); })},
                      [ex, d](int r) { return mappedRange(d->analysis, ex(r).rva, 1); }));
    }
    if (!a.symbols.empty()) {
        auto sy = [d](int r) -> const bw::Symbol& { return d->analysis.symbols[static_cast<std::size_t>(r)]; };
        addPanel(tr("Symbols"),
                 make(rows(a.symbols.size()),
                      {textColumn(tr("Table"), [sy](int r) { return qs(sy(r).table); }),
                       numColumn(tr("#"), [sy](int r) { return sy(r).index; }),
                       textColumn(tr("Name"), [sy](int r) { return qs(sy(r).name); }),
                       hexColumn(tr("Value"), [sy](int r) { return sy(r).value; }),
                       numColumn(tr("Size"), [sy](int r) { return sy(r).size; }),
                       textColumn(tr("Type"), [sy](int r) { return qs(sy(r).type); }),
                       textColumn(tr("Bind"), [sy](int r) { return qs(sy(r).bind); }),
                       textColumn(tr("Visibility"), [sy](int r) { return qs(sy(r).visibility); }),
                       textColumn(tr("Version"), [sy](int r) { return qs(sy(r).version); }),
                       numColumn(tr("Section"), [sy](int r) { return sy(r).section_index; })},
                      [sy, d](int r) {
                          return sy(r).section_index == 0 ? std::nullopt : mappedRange(d->analysis, sy(r).value, sy(r).size);
                      }));
    }
    if (!a.dynamic.empty()) {
        auto dy = [d](int r) -> const bw::DynamicEntry& { return d->analysis.dynamic[static_cast<std::size_t>(r)]; };
        addPanel(tr("Dynamic"), make(rows(a.dynamic.size()),
                                     {textColumn(tr("Tag"), [dy](int r) { return qs(dy(r).tag_name); }),
                                      hexColumn(tr("Value"), [dy](int r) { return dy(r).value; }),
                                      textColumn(tr("Meaning"), [dy](int r) { return qs(dy(r).text); })}));
    }
    if (!a.relocations.empty()) {
        auto re = [d](int r) -> const bw::Relocation& { return d->analysis.relocations[static_cast<std::size_t>(r)]; };
        const std::uint64_t width = a.bitness == "64-bit" ? 8 : 4;
        addPanel(tr("Relocations"),
                 make(rows(a.relocations.size()),
                      {textColumn(tr("Section"), [re](int r) { return qs(re(r).section); }),
                       hexColumn(tr("Offset (address)"), [re](int r) { return re(r).offset; }),
                       textColumn(tr("Type"), [re](int r) { return qs(re(r).type_name); }),
                       textColumn(tr("Symbol"), [re](int r) { return qs(re(r).symbol); }),
                       textColumn(tr("Addend"), [re](int r) { return re(r).has_addend ? QString::number(re(r).addend) : QString(); })},
                      [re, d, width](int r) { return mappedRange(d->analysis, re(r).offset, width); }));
    }
    if (!a.notes.empty()) {
        auto no = [d](int r) -> const bw::Note& { return d->analysis.notes[static_cast<std::size_t>(r)]; };
        addPanel(tr("Notes"), make(rows(a.notes.size()),
                                   {textColumn(tr("Source"), [no](int r) { return qs(no(r).source); }),
                                    textColumn(tr("Owner"), [no](int r) { return qs(no(r).owner); }),
                                    textColumn(tr("Type"), [no](int r) { return qs(no(r).type_name); }),
                                    hexColumn(tr("Offset"), [no](int r) { return no(r).offset; }),
                                    textColumn(tr("Description"), [no](int r) { return qs(no(r).description); })},
                                   [no, fs](int r) { return fileRange(no(r).offset, no(r).size, fs); }));
    }
    if (!a.debug_entries.empty()) {
        auto de = [d](int r) -> const bw::DebugEntry& { return d->analysis.debug_entries[static_cast<std::size_t>(r)]; };
        addPanel(tr("Debug"), make(rows(a.debug_entries.size()),
                                   {textColumn(tr("Type"), [de](int r) { return qs(de(r).type_name); }),
                                    hexColumn(tr("Timestamp"), [de](int r) { return de(r).timestamp; }),
                                    numColumn(tr("Size"), [de](int r) { return de(r).size; }),
                                    hexColumn(tr("File offset"), [de](int r) { return de(r).pointer; }),
                                    textColumn(tr("Detail"), [de](int r) { return qs(de(r).detail); })},
                                   [de, fs](int r) { return fileRange(de(r).pointer, de(r).size, fs); }));
    }
    if (!a.functions.empty()) {
        auto fn = [d](int r) -> const bw::FunctionRange& { return d->analysis.functions[static_cast<std::size_t>(r)]; };
        addPanel(tr("Functions"),
                 make(rows(a.functions.size()),
                      {hexColumn(tr("Begin RVA"), [fn](int r) { return fn(r).begin; }),
                       hexColumn(tr("End RVA"), [fn](int r) { return fn(r).end; }),
                       numColumn(tr("Size"), [fn](int r) { return fn(r).end > fn(r).begin ? fn(r).end - fn(r).begin : 0u; }),
                       hexColumn(tr("Unwind info RVA"), [fn](int r) { return fn(r).unwind; }),
                       numColumn(tr("Prolog"), [fn](int r) { return fn(r).prolog_size; }),
                       numColumn(tr("Unwind codes"), [fn](int r) { return fn(r).code_count; }),
                       textColumn(tr("Handler / chain"), [fn](int r) {
                           return fn(r).handler ? tr("handler %1").arg(hexText(fn(r).handler))
                                : fn(r).chained_begin ? tr("chained to %1").arg(hexText(fn(r).chained_begin)) : QString();
                       }),
                       textColumn(tr("Section"), [fn, d](int r) { return qs(bw::address_to_offset(d->analysis, fn(r).begin).mapping); })},
                      [fn, d](int r) {
                          return mappedRange(d->analysis, fn(r).begin, fn(r).end > fn(r).begin ? fn(r).end - fn(r).begin : 1);
                      }));
    }
    if (a.dotnet) {
        const auto& n = *a.dotnet;
        auto rows_net = std::make_shared<std::vector<std::pair<QString, QString>>>();
        rows_net->push_back({tr("Runtime"), qs(n.metadata_version + " (CLR header " + n.runtime_header + ")")});
        rows_net->push_back({tr("Flags"), qs(n.flags_text)});
        rows_net->push_back({tr("Entry point token"), hexText(n.entry_point_token)});
        rows_net->push_back({tr("Module"), qs(n.module_name)});
        if (!n.assembly_name.empty())
            rows_net->push_back({tr("Assembly"), qs(n.assembly_name + ", Version=" + n.assembly_version + ", Culture=" +
                                                    (n.assembly_culture.empty() ? "neutral" : n.assembly_culture) +
                                                    ", PublicKeyToken=" + n.public_key_token)});
        for (const auto& s : n.streams) rows_net->push_back({tr("Stream"), qs(s.name) + tr("  %1 bytes at +%2").arg(s.size).arg(hexText(s.offset))});
        for (const auto& t : n.tables) rows_net->push_back({tr("Table"), qs(t.name) + tr(": %1 rows").arg(t.rows)});
        for (const auto& r : n.references)
            rows_net->push_back({tr("Reference"), qs(r.name + ", Version=" + r.version + ", PublicKeyToken=" + r.public_key_token)});
        for (const auto& m : n.module_references) rows_net->push_back({tr("P/Invoke DLL"), qs(m)});
        addPanel(tr(".NET"), make(rows(rows_net->size()),
                                  {textColumn(tr("Field"), [rows_net](int r) { return (*rows_net)[static_cast<std::size_t>(r)].first; }),
                                   textColumn(tr("Value"), [rows_net](int r) { return (*rows_net)[static_cast<std::size_t>(r)].second; })}));
    }
    if (!a.resource_strings.empty()) {
        auto rsx = [d](int r) -> const bw::ResourceString& { return d->analysis.resource_strings[static_cast<std::size_t>(r)]; };
        addPanel(tr("Resource strings"),
                 make(rows(a.resource_strings.size()),
                      {numColumn(tr("Id"), [rsx](int r) { return rsx(r).id; }),
                       textColumn(tr("Language"), [rsx](int r) { return qs(rsx(r).language); }),
                       textColumn(tr("Text"), [rsx](int r) { return qs(rsx(r).text); })}));
    }
    if (!a.resources.empty()) {
        auto rs = [d](int r) -> const bw::Resource& { return d->analysis.resources[static_cast<std::size_t>(r)]; };
        addPanel(tr("Resources"),
                 make(rows(a.resources.size()),
                      {textColumn(tr("Type"), [rs](int r) { return qs(rs(r).type); }),
                       textColumn(tr("Name"), [rs](int r) { return qs(rs(r).name); }),
                       textColumn(tr("Language"), [rs](int r) { return qs(rs(r).language); }),
                       hexColumn(tr("RVA"), [rs](int r) { return rs(r).rva; }),
                       numColumn(tr("Size"), [rs](int r) { return rs(r).size; }),
                       textColumn(tr("File offset"), [rs](int r) { return rs(r).offset ? hexText(*rs(r).offset) : tr("not file-backed"); }),
                       numColumn(tr("Code page"), [rs](int r) { return rs(r).codepage; })},
                      [rs, fs](int r) { return rs(r).offset ? fileRange(*rs(r).offset, rs(r).size, fs) : std::nullopt; }));
    }
    if (!a.rich.empty()) {
        auto ri = [d](int r) -> const bw::RichEntry& { return d->analysis.rich[static_cast<std::size_t>(r)]; };
        addPanel(tr("Rich header"), make(rows(a.rich.size()),
                                         {hexColumn(tr("Product id"), [ri](int r) { return ri(r).product_id; }),
                                          numColumn(tr("Build"), [ri](int r) { return ri(r).build; }),
                                          numColumn(tr("Count"), [ri](int r) { return ri(r).count; })}));
    }
    if (!d->strings.strings.empty()) {
        auto st2 = [d](int r) -> const bw::ExtractedString& { return d->strings.strings[static_cast<std::size_t>(r)]; };
        addPanel(tr("Strings"),
                 make(rows(d->strings.strings.size()),
                      {hexColumn(tr("Offset"), [st2](int r) { return st2(r).offset; }),
                       textColumn(tr("Encoding"), [st2](int r) { return st2(r).utf16 ? tr("UTF-16LE") : tr("ASCII"); }),
                       numColumn(tr("Length"), [st2](int r) { return st2(r).size / (st2(r).utf16 ? 2 : 1); }),
                       textColumn(tr("Inside"), [st2, d](int r) {
                           const auto regions = bw::locate(d->analysis, st2(r).offset);
                           return regions.empty() ? QString() : qs(regions.front().name);
                       }),
                       textColumn(tr("Text"), [st2](int r) { return qs(bw::printable(st2(r).text)); })},
                      [st2, fs](int r) { return fileRange(st2(r).offset, st2(r).size, fs); }));
    }
    if (!a.signatures.empty()) {
        auto rows_sig = std::make_shared<std::vector<std::pair<QString, QString>>>();
        for (const auto& sg : a.signatures) {
            rows_sig->push_back({tr("Signer"), qs(sg.signer_subject)});
            rows_sig->push_back({tr("Issuer"), qs(sg.signer_issuer)});
            rows_sig->push_back({tr("Serial"), qs(sg.signer_serial)});
            rows_sig->push_back({tr("Valid"), qs(sg.valid_from + " .. " + sg.valid_to)});
            rows_sig->push_back({tr("Digest"), qs(sg.digest_algorithm + ": " + sg.digest_status)});
            rows_sig->push_back({tr("Signed digest"), qs(sg.signed_digest)});
            rows_sig->push_back({tr("Computed digest"), qs(sg.computed_digest)});
            for (const auto& c : sg.certificates) rows_sig->push_back({tr("Certificate"), qs(c)});
            rows_sig->push_back({tr("Verification"), tr("signature, chain and revocation NOT verified")});
        }
        addPanel(tr("Signatures"), make(rows(rows_sig->size()),
                                        {textColumn(tr("Field"), [rows_sig](int r) { return (*rows_sig)[static_cast<std::size_t>(r)].first; }),
                                         textColumn(tr("Value"), [rows_sig](int r) { return (*rows_sig)[static_cast<std::size_t>(r)].second; })}));
    }
    if (!a.certificates.empty()) {
        auto ce = [d](int r) -> const bw::Certificate& { return d->analysis.certificates[static_cast<std::size_t>(r)]; };
        addPanel(tr("Certificates"),
                 make(rows(a.certificates.size()),
                      {hexColumn(tr("Offset"), [ce](int r) { return ce(r).offset; }),
                       numColumn(tr("Length"), [ce](int r) { return ce(r).length; }),
                       hexColumn(tr("Revision"), [ce](int r) { return ce(r).revision; }),
                       textColumn(tr("Type"), [ce](int r) { return qs(ce(r).type_name); }),
                       textColumn(tr("Verified"), [](int) { return tr("no (metadata only)"); })},
                      [ce, fs](int r) { return fileRange(ce(r).offset, ce(r).length, fs); }));
    }
    refreshBookmarkPanel();
    nav_->setCurrentRow(a.has_errors() ? 1 : 0);
}

void MainWindow::onCursorMoved(quint64 offset) {
    entropy_->setCursorOffset(offset);
    // Keep the structural tables in step with the byte under the cursor.
    for (const char* name : {"Sections", "Segments", "Structures", "Directories"}) {
        if (auto* p = panel(tr(name))) {
            if (p->view()->hasFocus()) continue;  // never move the selection the user is working in
            p->selectSourceRow(p->rowContaining(offset));
        }
    }
    updateInspector();
}

void MainWindow::onSelectionChanged(quint64, quint64) { updateInspector(); }

void MainWindow::loadBookmarks() {
    bookmarks_.clear();
    if (!doc_ || !doc_->ok()) return;
    QSettings s;
    const int n = s.beginReadArray(QStringLiteral("bookmarks/") + qs(doc_->analysis.sha256));
    for (int i = 0; i < n; ++i) {
        s.setArrayIndex(i);
        const quint64 off = s.value(QStringLiteral("offset")).toULongLong();
        if (off < doc_->file->size())
            bookmarks_.push_back({off, s.value(QStringLiteral("length")).toULongLong(), s.value(QStringLiteral("note")).toString()});
    }
    s.endArray();
}

void MainWindow::saveBookmarks() {
    if (!doc_ || !doc_->ok()) return;
    QSettings s;
    const QString group = QStringLiteral("bookmarks/") + qs(doc_->analysis.sha256);
    s.remove(group);
    s.beginWriteArray(group, static_cast<int>(bookmarks_.size()));
    for (int i = 0; i < static_cast<int>(bookmarks_.size()); ++i) {
        s.setArrayIndex(i);
        s.setValue(QStringLiteral("offset"), bookmarks_[static_cast<std::size_t>(i)].offset);
        s.setValue(QStringLiteral("length"), bookmarks_[static_cast<std::size_t>(i)].length);
        s.setValue(QStringLiteral("note"), bookmarks_[static_cast<std::size_t>(i)].note);
    }
    s.endArray();
}

void MainWindow::refreshBookmarkPanel() {
    const QString name = tr("Bookmarks");
    if (auto* old = panel(name)) {
        for (int r = 0; r < nav_->count(); ++r)
            if (nav_->item(r)->data(Qt::UserRole).toString() == name) delete nav_->takeItem(r);
        pages_->removeWidget(old);
        old->deleteLater();
        panels_.erase(name);
    }
    if (bookmarks_.empty() || !doc_) return;
    auto shared = std::make_shared<const std::vector<Bookmark>>(bookmarks_);
    const auto d = doc_;
    auto* p = new TablePanel;
    p->setModel(new RecordModel(
        static_cast<int>(shared->size()),
        {Column{tr("Offset"), [shared](int r) { return QVariant::fromValue<quint64>((*shared)[static_cast<std::size_t>(r)].offset); },
                [shared](int r) { return hexText((*shared)[static_cast<std::size_t>(r)].offset); }, true},
         Column{tr("Length"), [shared](int r) { return QVariant::fromValue<quint64>((*shared)[static_cast<std::size_t>(r)].length); }, {}, true},
         Column{tr("Inside"), [shared, d](int r) {
                    const auto regions = bw::locate(d->analysis, (*shared)[static_cast<std::size_t>(r)].offset);
                    return QVariant(regions.empty() ? QString() : qs(regions.front().name));
                }},
         Column{tr("Note"), [shared](int r) { return QVariant((*shared)[static_cast<std::size_t>(r)].note); }}},
        [shared](int r) {
            const auto& b = (*shared)[static_cast<std::size_t>(r)];
            return std::optional<bw::ByteRange>(bw::ByteRange{b.offset, std::max<quint64>(b.length, 1)});
        }));
    addPanel(name, p);
}

void MainWindow::addBookmark(quint64 offset, quint64 length, const QString& note) {
    if (!doc_ || !doc_->ok() || offset >= doc_->file->size()) return;
    bookmarks_.push_back({offset, length, note});
    std::sort(bookmarks_.begin(), bookmarks_.end(), [](const Bookmark& x, const Bookmark& y) { return x.offset < y.offset; });
    saveBookmarks();
    refreshBookmarkPanel();
}

bool MainWindow::removeBookmarkAt(quint64 offset) {
    const auto it = std::find_if(bookmarks_.begin(), bookmarks_.end(), [&](const Bookmark& b) {
        return offset >= b.offset && offset < b.offset + std::max<quint64>(b.length, 1);
    });
    if (it == bookmarks_.end()) return false;
    bookmarks_.erase(it);
    saveBookmarks();
    refreshBookmarkPanel();
    return true;
}

bool MainWindow::nextBookmark(bool forward) {
    if (bookmarks_.empty()) return false;
    const quint64 cur = hex_->cursor();
    const Bookmark* target = nullptr;
    if (forward) {
        for (const auto& b : bookmarks_)
            if (b.offset > cur) { target = &b; break; }
        if (!target) target = &bookmarks_.front();  // wrap
    } else {
        for (auto it = bookmarks_.rbegin(); it != bookmarks_.rend(); ++it)
            if (it->offset < cur) { target = &*it; break; }
        if (!target) target = &bookmarks_.back();
    }
    navigate(target->offset, target->length);
    statusBar()->showMessage(tr("Bookmark %1: %2").arg(hexText(target->offset), target->note), 4000);
    return true;
}

QStringList MainWindow::runRules(const QString& path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {tr("Cannot read %1").arg(path)};
    std::vector<std::string> errors;
    const auto rules = bw::parse_rules(file.readAll().toStdString(), errors);
    QStringList out;
    for (const auto& e : errors) out << qs(e);
    if (!out.isEmpty() || !doc_ || !doc_->ok()) return out;
    struct Row {
        QString rule, id, tags;
        std::optional<quint64> offset;
    };
    auto rows_hits = std::make_shared<std::vector<Row>>();
    for (const auto& m : bw::match_rules(rules, doc_->analysis, *doc_->file)) {
        QString tags;
        for (const auto& t : m.tags) tags += (tags.isEmpty() ? QString() : QStringLiteral(" ")) + qs(t);
        for (const auto& h : m.matched) rows_hits->push_back({qs(m.rule), qs(h.id), tags, h.offset});
    }
    const QString name = tr("Rule matches");
    if (auto* old = panel(name)) {
        for (int r = 0; r < nav_->count(); ++r)
            if (nav_->item(r)->data(Qt::UserRole).toString() == name) delete nav_->takeItem(r);
        pages_->removeWidget(old);
        old->deleteLater();
        panels_.erase(name);
    }
    auto* p = new TablePanel;
    p->setModel(new RecordModel(
        static_cast<int>(rows_hits->size()),
        {Column{tr("Rule"), [rows_hits](int r) { return QVariant((*rows_hits)[static_cast<std::size_t>(r)].rule); }},
         Column{tr("Pattern"), [rows_hits](int r) { return QVariant((*rows_hits)[static_cast<std::size_t>(r)].id); }},
         Column{tr("Offset"), [rows_hits](int r) {
                    const auto& o = (*rows_hits)[static_cast<std::size_t>(r)].offset;
                    return o ? QVariant(hexText(*o)) : QVariant(tr("(structural)"));
                }},
         Column{tr("Tags"), [rows_hits](int r) { return QVariant((*rows_hits)[static_cast<std::size_t>(r)].tags); }}},
        [rows_hits](int r) {
            const auto& o = (*rows_hits)[static_cast<std::size_t>(r)].offset;
            return o ? std::optional<bw::ByteRange>(bw::ByteRange{*o, 1}) : std::nullopt;
        }));
    addPanel(name, p);
    nav_->setCurrentRow(nav_->count() - 1);
    statusBar()->showMessage(tr("%n rule pattern hit(s)", nullptr, static_cast<int>(rows_hits->size())), 5000);
    return {};
}

bool MainWindow::saveSelection(const QString& path, QString* error) {
    if (!doc_ || !doc_->ok()) return false;
    const auto sel = hex_->selection();
    const quint64 len = std::max<quint64>(sel.size, 1);
    if (!doc_->file->contains(sel.offset, len)) return false;
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly) ||
        f.write(reinterpret_cast<const char*>(doc_->bytes().data() + sel.offset), static_cast<qint64>(len)) != static_cast<qint64>(len) ||
        !f.commit()) {
        if (error) *error = tr("Could not write %1.").arg(path);
        return false;
    }
    statusBar()->showMessage(tr("%1 bytes written to %2").arg(len).arg(path), 5000);
    return true;
}

void MainWindow::navigate(quint64 offset, quint64 length) {
    if (doc_ && doc_->ok() && hex_->cursor() != offset) {
        back_.push_back(hex_->cursor());
        if (back_.size() > 256) back_.erase(back_.begin());
        forward_.clear();
    }
    hex_->goTo(offset, length);
}

bool MainWindow::goBack() {
    if (back_.empty()) return false;
    forward_.push_back(hex_->cursor());
    const auto to = back_.back();
    back_.pop_back();
    hex_->goTo(to);
    return true;
}

bool MainWindow::goForward() {
    if (forward_.empty()) return false;
    back_.push_back(hex_->cursor());
    const auto to = forward_.back();
    forward_.pop_back();
    hex_->goTo(to);
    return true;
}

bool MainWindow::goToEntryPoint() {
    if (!doc_ || !doc_->ok() || doc_->analysis.entry_point == 0) return false;
    const auto m = bw::address_to_offset(doc_->analysis, doc_->analysis.entry_point);
    if (m.status != bw::MapStatus::FileBacked) {
        statusBar()->showMessage(tr("The entry point %1 has no file bytes.").arg(hexText(doc_->analysis.entry_point)), 5000);
        return false;
    }
    navigate(m.offset);
    hex_->setFocus();
    statusBar()->showMessage(tr("Entry point %1 → file offset %2").arg(hexText(doc_->analysis.entry_point), hexText(m.offset)), 5000);
    return true;
}

QPixmap MainWindow::fileIcon() const { return icon_label_->pixmap(); }

void MainWindow::updateInspector() {
    inspector_->clear();
    if (!doc_ || !doc_->ok()) return;
    const auto& a = doc_->analysis;
    const auto bytes = doc_->bytes();
    const std::uint64_t off = hex_->cursor();
    const auto sel = hex_->selection();
    auto add = [](QTreeWidgetItem* parent, const QString& k, const QString& v) {
        auto* it = new QTreeWidgetItem(parent, {k, v});
        it->setToolTip(1, v);
        return it;
    };

    if (const auto* fld = bw::field_at(doc_->fields, off)) {
        auto* hf = new QTreeWidgetItem(inspector_, {tr("Header field")});
        auto* it = new QTreeWidgetItem(hf, {qs(fld->name), qs(fld->text)});
        it->setToolTip(1, qs(fld->structure + "." + fld->name));
        new QTreeWidgetItem(hf, {tr("Structure"), qs(fld->structure)});
        new QTreeWidgetItem(hf, {tr("Bytes"), tr("%1 at %2").arg(fld->size).arg(hexText(fld->offset))});
    }
    auto* pos = new QTreeWidgetItem(inspector_, {tr("Position")});
    add(pos, tr("File offset"), hexText(off) + QStringLiteral("  (%1)").arg(off));
    const auto addrs = bw::offset_to_addresses(a, off);
    for (auto x : addrs) add(pos, a.format == bw::Format::PE ? tr("RVA") : tr("Virtual address"), hexText(x));
    if (a.format == bw::Format::PE && !addrs.empty()) add(pos, tr("VA"), hexText(a.image_base + addrs.front()));
    if (addrs.empty() && a.format != bw::Format::Unknown) add(pos, tr("Mapped"), tr("not mapped into memory"));

    auto* in = new QTreeWidgetItem(inspector_, {tr("Inside")});
    for (const auto& r : bw::locate(a, off)) {
        auto* it = add(in, qs(r.kind), tr("%1  [%2, +%3)  +%4").arg(qs(r.name), hexText(r.offset), hexText(r.size), hexText(off - r.offset)));
        it->setData(0, Qt::UserRole, QVariant::fromValue<quint64>(r.offset));
        it->setData(0, Qt::UserRole + 1, QVariant::fromValue<quint64>(r.size));
        it->setToolTip(0, tr("Double-click or press Enter to select this region"));
    }
    if (in->childCount() == 0) add(in, tr("—"), tr("no known structure"));

    auto* val = new QTreeWidgetItem(inspector_, {tr("Value at cursor")});
    const bw::ByteView le(bytes, bw::Endian::Little), be(bytes, bw::Endian::Big);
    if (auto v = le.record(off, 1)) {
        add(val, tr("u8 / i8"), QStringLiteral("%1 / %2").arg(v->u8(0)).arg(static_cast<std::int8_t>(v->u8(0))));
    }
    auto both = [&](const QString& label, int width) {
        auto l = le.record(off, static_cast<std::uint64_t>(width));
        auto b = be.record(off, static_cast<std::uint64_t>(width));
        if (!l) return;
        const auto lv = width == 2 ? l->u16(0) : width == 4 ? l->u32(0) : l->u64(0);
        const auto bv = width == 2 ? b->u16(0) : width == 4 ? b->u32(0) : b->u64(0);
        add(val, label + tr(" LE"), QStringLiteral("%1  (%2)").arg(hexText(lv)).arg(lv));
        add(val, label + tr(" BE"), QStringLiteral("%1  (%2)").arg(hexText(bv)).arg(bv));
    };
    both(QStringLiteral("u16"), 2);
    both(QStringLiteral("u32"), 4);
    both(QStringLiteral("u64"), 8);
    if (auto s = le.slice(off, std::min<std::uint64_t>(64, bytes.size() - std::min<std::uint64_t>(off, bytes.size())))) {
        QString ascii;
        for (auto c : *s) {
            if (c == 0) break;
            ascii += QChar(static_cast<char16_t>((c >= 0x20 && c < 0x7f) ? c : 0xb7));
        }
        add(val, tr("ASCII"), ascii.isEmpty() ? tr("(empty)") : QStringLiteral("\"%1\"").arg(ascii));
    }

    if (sel.size > 1) {
        auto* s = new QTreeWidgetItem(inspector_, {tr("Selection")});
        add(s, tr("Range"), tr("%1 – %2").arg(hexText(sel.offset), hexText(sel.offset + sel.size - 1)));
        add(s, tr("Length"), tr("%1 bytes").arg(sel.size));
        if (sel.size <= (std::uint64_t{64} << 20)) {
            const auto span = bytes.subspan(static_cast<std::size_t>(sel.offset), static_cast<std::size_t>(sel.size));
            add(s, tr("Entropy"), QString::number(bw::entropy(span), 'f', 4) + tr(" bits/byte"));
            add(s, tr("SHA-256"), qs(bw::sha256(span)));
        } else {
            add(s, tr("Entropy / hash"), tr("not computed for selections over 64 MiB"));
        }
    }
    inspector_->expandAll();

    // Status bar: offset plus the most specific enclosing region.
    QString where;
    if (auto regions = bw::locate(a, off); !regions.empty())
        where = QStringLiteral("  ·  %1 + %2").arg(qs(regions.front().name), hexText(off - regions.front().offset));
    status_offset_->setText(tr("offset %1%2%3").arg(hexText(off), where,
                                                    sel.size > 1 ? tr("  ·  %1 bytes selected").arg(sel.size) : QString()));
}

void MainWindow::goToOffsetDialog() {
    if (!doc_ || !doc_->ok()) return;
    bool ok = false;
    const auto text = QInputDialog::getText(this, tr("Go to offset"),
                                            tr("File offset (decimal, 0x… or …h), 0 – %1:").arg(hexText(doc_->file->size() - 1)),
                                            QLineEdit::Normal, hexText(hex_->cursor()), &ok);
    if (!ok) return;
    auto v = parseNumber(text);
    if (!v || *v >= doc_->file->size()) {
        QMessageBox::information(this, tr("Go to offset"), tr("'%1' is not an offset inside the file.").arg(text));
        return;
    }
    navigate(*v);
    hex_->setFocus();
}

void MainWindow::goToAddressDialog() {
    if (!doc_ || !doc_->ok()) return;
    const bool pe = doc_->analysis.format == bw::Format::PE;
    bool ok = false;
    const auto text = QInputDialog::getText(this, tr("Go to address"),
                                            pe ? tr("RVA (relative to ImageBase %1):").arg(hexText(doc_->analysis.image_base))
                                               : tr("Virtual address:"),
                                            QLineEdit::Normal, QString(), &ok);
    if (!ok) return;
    auto v = parseNumber(text);
    if (!v) return;
    const auto m = bw::address_to_offset(doc_->analysis, *v);
    if (m.status == bw::MapStatus::FileBacked) {
        navigate(m.offset);
        hex_->setFocus();
        statusBar()->showMessage(tr("%1 → file offset %2 in %3").arg(hexText(*v), hexText(m.offset), qs(m.mapping)), 5000);
    } else {
        QMessageBox::information(this, tr("Go to address"),
                                 m.status == bw::MapStatus::ZeroFill
                                     ? tr("%1 is inside %2 but has no file bytes (zero-filled at load time).").arg(hexText(*v), qs(m.mapping))
                                     : tr("%1 is not mapped by any section or segment.").arg(hexText(*v)));
    }
}

void MainWindow::exportReport() {
    if (!doc_ || !doc_->ok()) return;
    QString selected;
    const auto path = QFileDialog::getSaveFileName(this, tr("Export report"), QFileInfo(doc_->path).completeBaseName() + QStringLiteral(".json"),
                                                   tr("JSON report (*.json);;HTML report (*.html);;Text report (*.txt)"), &selected);
    if (path.isEmpty()) return;
    QSaveFile f(path);
    const auto text = path.endsWith(QStringLiteral(".txt"), Qt::CaseInsensitive)    ? bw::text_report(doc_->analysis)
                      : path.endsWith(QStringLiteral(".html"), Qt::CaseInsensitive) ? bw::html_report(doc_->analysis)
                                                                                    : bw::json_report(doc_->analysis);
    if (!f.open(QIODevice::WriteOnly) || f.write(text.data(), static_cast<qint64>(text.size())) < 0 || !f.commit())
        QMessageBox::warning(this, tr("Export report"), tr("Could not write %1.").arg(path));
    else statusBar()->showMessage(tr("Report written to %1").arg(path), 5000);
}

// Writes the visible table exactly as shown: current filter, sort order and
// column order (RFC 4180 quoting).
void MainWindow::exportTableCsv() {
    auto* p = qobject_cast<TablePanel*>(pages_->currentWidget());
    if (!p || !doc_) return;
    const QString name = nav_->currentItem() ? nav_->currentItem()->data(Qt::UserRole).toString() : QStringLiteral("table");
    const auto path = QFileDialog::getSaveFileName(this, tr("Export table"),
                                                   QFileInfo(doc_->path).completeBaseName() + QLatin1Char('-') +
                                                       name.toLower().replace(QLatin1Char(' '), QLatin1Char('-')) +
                                                       QStringLiteral(".csv"),
                                                   tr("CSV (*.csv)"));
    if (path.isEmpty()) return;
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, tr("Export table"), tr("Could not write %1.").arg(path));
        return;
    }
    f.write(tableToCsv(p).toUtf8());
    if (!f.commit()) QMessageBox::warning(this, tr("Export table"), tr("Could not write %1.").arg(path));
    else statusBar()->showMessage(tr("Table written to %1").arg(path), 5000);
}

QString tableToCsv(TablePanel* p) {
    auto quote = [](QString v) {
        if (v.contains(QLatin1Char(',')) || v.contains(QLatin1Char('"')) || v.contains(QLatin1Char('\n')))
            v = QLatin1Char('"') + v.replace(QLatin1Char('"'), QStringLiteral("\"\"")) + QLatin1Char('"');
        return v;
    };
    const auto* m = p->view()->model();
    const auto* header = p->view()->horizontalHeader();
    QString out;
    QStringList cells;
    for (int v = 0; v < header->count(); ++v) cells << quote(m->headerData(header->logicalIndex(v), Qt::Horizontal).toString());
    out += cells.join(QLatin1Char(',')) + QStringLiteral("\r\n");
    for (int r = 0; r < m->rowCount(); ++r) {
        cells.clear();
        for (int v = 0; v < header->count(); ++v) cells << quote(m->index(r, header->logicalIndex(v)).data().toString());
        out += cells.join(QLatin1Char(',')) + QStringLiteral("\r\n");
    }
    return out;
}

void MainWindow::showShortcuts() {
    // Built from the live actions so the list can never drift from the menus.
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Keyboard shortcuts"));
    auto* table = new QTableWidget(0, 2, &dialog);
    table->setHorizontalHeaderLabels({tr("Action"), tr("Shortcut")});
    table->verticalHeader()->hide();
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    for (auto* action : findChildren<QAction*>()) {
        if (action->shortcut().isEmpty()) continue;
        const int r = table->rowCount();
        table->insertRow(r);
        table->setItem(r, 0, new QTableWidgetItem(action->text().remove(QLatin1Char('&')).remove(QStringLiteral("…"))));
        table->setItem(r, 1, new QTableWidgetItem(action->shortcut().toString(QKeySequence::NativeText)));
    }
    const QStringList hex_keys = {tr("Hex view: arrows / PgUp / PgDn"), tr("Move cursor"),
                                  tr("Hex view: Shift + movement or drag"), tr("Extend selection"),
                                  tr("Hex view: Home / End, Ctrl+Home / Ctrl+End"), tr("Row start/end, file start/end"),
                                  tr("Hex view: Ctrl+C"), tr("Copy selection as hex (up to 1 MiB)")};
    for (int i = 0; i < hex_keys.size(); i += 2) {
        const int r = table->rowCount();
        table->insertRow(r);
        table->setItem(r, 0, new QTableWidgetItem(hex_keys[i + 1]));
        table->setItem(r, 1, new QTableWidgetItem(hex_keys[i]));
    }
    table->resizeColumnsToContents();
    table->horizontalHeader()->setStretchLastSection(true);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(table);
    layout->addWidget(buttons);
    dialog.resize(560, 480);
    dialog.exec();
}

void MainWindow::addRecent(const QString& path) {
    QSettings s;
    auto list = s.value(QStringLiteral("recent")).toStringList();
    list.removeAll(path);
    list.prepend(path);
    while (list.size() > 8) list.removeLast();
    s.setValue(QStringLiteral("recent"), list);
    rebuildRecentMenu();
}

void MainWindow::rebuildRecentMenu() {
    recent_menu_->clear();
    const auto list = QSettings().value(QStringLiteral("recent")).toStringList();
    for (const auto& p : list) recent_menu_->addAction(p, this, [this, p] { openFile(p); });
    recent_menu_->setEnabled(!list.isEmpty());
}

void MainWindow::closeEvent(QCloseEvent* e) {
    QSettings s;
    s.setValue(QStringLiteral("geometry"), saveGeometry());
    s.setValue(QStringLiteral("state"), saveState());
    if (auto* split = findChild<QSplitter*>(QStringLiteral("navSplitter"))) s.setValue(QStringLiteral("navSplitter"), split->saveState());
    if (auto* split = findChild<QSplitter*>(QStringLiteral("tablesHexSplitter")))
        s.setValue(QStringLiteral("tablesHexSplitter"), split->saveState());
    e->accept();
}

void MainWindow::dragEnterEvent(QDragEnterEvent* e) {
    if (e->mimeData()->hasUrls()) e->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent* e) {
    const auto urls = e->mimeData()->urls();
    if (urls.isEmpty() || !urls.front().isLocalFile()) return;
    // Dropping two files compares them; one file opens it.
    if (urls.size() >= 2 && urls[1].isLocalFile()) {
        const QString b = urls[1].toLocalFile();
        connect(this, &MainWindow::documentLoaded, this, [this, b] { compareWith(b); }, Qt::SingleShotConnection);
    }
    openFile(urls.front().toLocalFile());
}
