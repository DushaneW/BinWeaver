// Drives the real UI widgets: loading, table <-> hex synchronization, search,
// filtering, comparison navigation and a large mapped file. Runs headless with
// QT_QPA_PLATFORM=offscreen. Set BW_SCREENSHOT_DIR to save window captures.
#include "compare_window.hpp"
#include "hex_view.hpp"
#include "main_window.hpp"
#include "table_model.hpp"

#include <QDir>
#include <QFile>
#include <QSettings>
#include <QFileInfo>
#include <QElapsedTimer>
#include <QLineEdit>
#include <QSignalSpy>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QTemporaryDir>
#include <QTest>
#include <QTreeWidget>

#include <fstream>
#include <random>

namespace {
const QString kCorpus = QStringLiteral(BINWEAVER_SOURCE_DIR "/tests/corpus");

void screenshot(QWidget* w, const QString& name) {
    const QString dir = qEnvironmentVariable("BW_SCREENSHOT_DIR");
    if (dir.isEmpty()) return;
    QDir().mkpath(dir);
    QTest::qWait(150);
    w->grab().save(dir + QLatin1Char('/') + name);
}

bool inspectorMentions(QTreeWidget* tree, const QString& text) {
    for (QTreeWidgetItemIterator it(tree); *it; ++it)
        if ((*it)->text(1).contains(text)) return true;
    return false;
}

int selectedSourceRow(TablePanel* p) {
    const auto idx = p->view()->currentIndex();
    if (!idx.isValid()) return -1;
    return static_cast<QSortFilterProxyModel*>(p->view()->model())->mapToSource(idx).row();
}
} // namespace

class GuiTests : public QObject {
    Q_OBJECT
private slots:
    void initTestCase() {
        QCoreApplication::setOrganizationName(QStringLiteral("BinWeaverTests"));
        QCoreApplication::setApplicationName(QStringLiteral("BinWeaverTests"));
    }

    void loadsPeAndBuildsPanels() {
        MainWindow w;
        w.resize(1400, 880);
        w.show();
        QSignalSpy loaded(&w, &MainWindow::documentLoaded);
        w.openFile(kCorpus + QStringLiteral("/pe/clean-pe32plus.dll"));
        QVERIFY(loaded.wait(10000));
        QVERIFY(w.document() && w.document()->ok());
        for (const char* name : {"Overview", "Diagnostics", "Sections", "Structures", "Directories", "Imports", "Exports", "Certificates"})
            QVERIFY2(w.panel(QString::fromLatin1(name)) != nullptr, name);
        QVERIFY(w.panel(QStringLiteral("Symbols")) == nullptr);  // PE: no ELF-only panels
        QCOMPARE(w.panel(QStringLiteral("Imports"))->model()->rowCount(), 3);
        QCOMPARE(w.panel(QStringLiteral("Exports"))->model()->rowCount(), 4);
        screenshot(&w, QStringLiteral("main-pe.png"));
    }

    void tableSelectionDrivesHexView() {
        MainWindow w;
        w.show();
        QSignalSpy loaded(&w, &MainWindow::documentLoaded);
        w.openFile(kCorpus + QStringLiteral("/pe/clean-pe32plus.dll"));
        QVERIFY(loaded.wait(10000));
        auto* sections = w.panel(QStringLiteral("Sections"));
        auto* view = sections->view();
        view->setFocus();
        view->setCurrentIndex(view->model()->index(1, 0));  // .rdata
        const auto sel = w.hexView()->selection();
        QCOMPARE(sel.offset, quint64(0x600));
        QCOMPARE(sel.size, quint64(0x400));

        // An import row selects its IAT slot (RVA 0x2080 -> file 0x680, 8 bytes).
        auto* imports = w.panel(QStringLiteral("Imports"));
        imports->view()->setCurrentIndex(imports->view()->model()->index(0, 0));
        QCOMPARE(w.hexView()->selection().offset, quint64(0x680));
        QCOMPARE(w.hexView()->selection().size, quint64(8));
    }

    void hexCursorDrivesTablesAndInspector() {
        MainWindow w;
        w.show();
        QSignalSpy loaded(&w, &MainWindow::documentLoaded);
        w.openFile(kCorpus + QStringLiteral("/pe/clean-pe32plus.dll"));
        QVERIFY(loaded.wait(10000));
        w.hexView()->setFocus();
        w.hexView()->goTo(0x405);
        QCOMPARE(selectedSourceRow(w.panel(QStringLiteral("Sections"))), 0);  // .text
        QVERIFY(inspectorMentions(w.inspector(), QStringLiteral(".text")));
        QVERIFY(inspectorMentions(w.inspector(), QStringLiteral("0x1005")));  // RVA of offset 0x405
        w.hexView()->goTo(0x90);
        QCOMPARE(selectedSourceRow(w.panel(QStringLiteral("Sections"))), -1);  // headers: no section
        QVERIFY(inspectorMentions(w.inspector(), QStringLiteral("COFF header")));
        w.hexView()->goTo(0x98 + 16);  // optional header + 16 (PE32+)
        bool field = false;
        for (QTreeWidgetItemIterator it(w.inspector()); *it; ++it) field = field || (*it)->text(0) == QStringLiteral("AddressOfEntryPoint");
        QVERIFY(field);
        QVERIFY(w.panel(QStringLiteral("Header fields")));
        w.hexView()->goTo(0x90);
        // Keyboard navigation moves the cursor.
        QTest::keyClick(w.hexView(), Qt::Key_Down);
        QCOMPARE(w.hexView()->cursor(), quint64(0xa0));
        QTest::keyClick(w.hexView(), Qt::Key_Right, Qt::ShiftModifier);
        QCOMPARE(w.hexView()->selection().size, quint64(2));
    }

    void findFilterAndSort() {
        MainWindow w;
        w.show();
        QSignalSpy loaded(&w, &MainWindow::documentLoaded);
        w.openFile(kCorpus + QStringLiteral("/pe/clean-pe32plus.dll"));
        QVERIFY(loaded.wait(10000));
        // Searches run on a worker thread; wait for searchFinished(found).
        QSignalSpy done(&w, &MainWindow::searchFinished);
        auto search = [&](const QString& text, bool hex) {
            w.setFindPattern(text, hex);
            done.clear();
            if (!w.findNext(true)) return false;
            if (!done.wait(10000)) return false;
            return done.takeFirst().at(0).toBool();
        };
        QVERIFY(search(QStringLiteral("50 45 ?? 00"), true));
        QCOMPARE(w.hexView()->cursor(), quint64(0x80 + 3));  // selection end of the 4-byte match
        QCOMPARE(w.hexView()->selection().offset, quint64(0x80));
        QVERIFY(search(QStringLiteral("MessageBoxA"), false));
        QCOMPARE(w.hexView()->selection().offset, quint64(0x722));
        QVERIFY(!search(QStringLiteral("not present anywhere"), false));

        // Find All fills a results panel; selecting a row selects the match.
        w.setFindPattern(QStringLiteral("00 00 00 00 00 00 00 00"), true);
        done.clear();
        QVERIFY(w.findAll());
        QVERIFY(done.wait(10000));
        auto* results = w.panel(QStringLiteral("Search results"));
        QVERIFY(results);
        QVERIFY(results->model()->rowCount() > 10);
        results->view()->setFocus();
        results->view()->setCurrentIndex(results->view()->model()->index(2, 0));
        QCOMPARE(w.hexView()->selection().size, quint64(8));

        auto* imports = w.panel(QStringLiteral("Imports"));
        imports->filter()->setText(QStringLiteral("user32"));
        QCOMPARE(imports->view()->model()->rowCount(), 1);
        imports->filter()->clear();
        imports->view()->sortByColumn(1, Qt::DescendingOrder);
        QCOMPARE(imports->view()->model()->index(0, 1).data().toString(), QStringLiteral("MessageBoxA"));
    }

    void resourcesStringsAndVersions() {
        MainWindow w;
        w.show();
        QSignalSpy loaded(&w, &MainWindow::documentLoaded);
        w.openFile(kCorpus + QStringLiteral("/pe/clean-pe32plus.dll"));
        QVERIFY(loaded.wait(10000));
        auto* res = w.panel(QStringLiteral("Resources"));
        QVERIFY(res);
        QCOMPARE(res->model()->rowCount(), 1);
        res->view()->setFocus();
        res->view()->setCurrentIndex(res->view()->model()->index(0, 0));
        QCOMPARE(w.hexView()->selection().offset, quint64(0xa80));  // VERSION data in .data
        QVERIFY(w.panel(QStringLiteral("Rich header")));
        auto* sig = w.panel(QStringLiteral("Signatures"));
        QVERIFY(sig);
        QCOMPARE(sig->model()->index(0, 1).data().toString(), QStringLiteral("CN=BinWeaver Test Signer, O=BinWeaver Tests, C=PL"));
        // CSV export follows the visible filter.
        auto* imports = w.panel(QStringLiteral("Imports"));
        imports->filter()->setText(QStringLiteral("kernel32"));
        const QString csv = tableToCsv(imports);
        QCOMPARE(csv.count(QStringLiteral("\r\n")), 3);  // header + 2 rows
        QVERIFY(csv.startsWith(QStringLiteral("Library,Name,Hint,IAT RVA,Load\r\n")));
        QVERIFY(csv.contains(QStringLiteral("KERNEL32.dll,ExitProcess,5,0x2080,startup")));
        auto* strings = w.panel(QStringLiteral("Strings"));
        QVERIFY(strings);
        strings->filter()->setText(QStringLiteral("KERNEL32.ExitProcess"));
        QCOMPARE(strings->view()->model()->rowCount(), 1);
        auto* overview = w.panel(QStringLiteral("Overview"));
        overview->filter()->setText(QStringLiteral("File version"));
        QCOMPARE(overview->view()->model()->index(0, 1).data().toString(), QStringLiteral("1.2.3.4"));

        QSignalSpy loaded2(&w, &MainWindow::documentLoaded);
        w.openFile(kCorpus + QStringLiteral("/elf/clean-elf64le.so"));
        QVERIFY(loaded2.wait(10000));
        auto* symbols = w.panel(QStringLiteral("Symbols"));
        QVERIFY(symbols);
        symbols->filter()->setText(QStringLiteral("GLIBC_2.2.5"));
        QCOMPARE(symbols->view()->model()->rowCount(), 1);
        screenshot(&w, QStringLiteral("main-elf-symbols.png"));
    }

    void navigationHistoryAndEntryPoint() {
        MainWindow w;
        w.show();
        QSignalSpy loaded(&w, &MainWindow::documentLoaded);
        w.openFile(kCorpus + QStringLiteral("/pe/clean-pe32plus.dll"));
        QVERIFY(loaded.wait(10000));
        QVERIFY(!w.goBack());  // empty history
        QVERIFY(w.goToEntryPoint());
        QCOMPARE(w.hexView()->cursor(), quint64(0x400));  // entry RVA 0x1000 -> .text raw 0x400
        w.navigate(0x700);
        w.navigate(0x900);
        QVERIFY(w.goBack());
        QCOMPARE(w.hexView()->cursor(), quint64(0x700));
        QVERIFY(w.goBack());
        QCOMPARE(w.hexView()->cursor(), quint64(0x400));
        QVERIFY(w.goForward());
        QCOMPARE(w.hexView()->cursor(), quint64(0x700));
        w.navigate(0x10);  // a new jump clears the forward stack
        QVERIFY(!w.goForward());
    }

    void bookmarksPersistAndRulesRun() {
        QSettings().remove(QStringLiteral("bookmarks"));
        const QString file = kCorpus + QStringLiteral("/pe/clean-pe32plus.dll");
        {
            MainWindow w;
            w.show();
            QSignalSpy loaded(&w, &MainWindow::documentLoaded);
            w.openFile(file);
            QVERIFY(loaded.wait(10000));
            w.addBookmark(0x700, 4, QStringLiteral("hint/name"));
            w.addBookmark(0x80, 4, QStringLiteral("PE signature"));
            QCOMPARE(w.panel(QStringLiteral("Bookmarks"))->model()->rowCount(), 2);
            w.hexView()->goTo(0);
            QVERIFY(w.nextBookmark(true));
            QCOMPARE(w.hexView()->selection().offset, quint64(0x80));
            QVERIFY(w.nextBookmark(true));
            QCOMPARE(w.hexView()->selection().offset, quint64(0x700));
            QVERIFY(w.nextBookmark(true));  // wraps
            QCOMPARE(w.hexView()->selection().offset, quint64(0x80));

            QTemporaryDir dir;
            const QString rules = dir.filePath(QStringLiteral("t.rules"));
            QFile out(rules);
            QVERIFY(out.open(QIODevice::WriteOnly));
            out.write("rule fwd\n  text $f = \"KERNEL32.ExitProcess\"\n  import $i = kernel32!ExitProcess\n  condition all\nend\n");
            out.close();
            QVERIFY(w.runRules(rules).isEmpty());
            auto* hits = w.panel(QStringLiteral("Rule matches"));
            QVERIFY(hits);
            QCOMPARE(hits->model()->rowCount(), 2);
            QFile bad(dir.filePath(QStringLiteral("bad.rules")));
            QVERIFY(bad.open(QIODevice::WriteOnly));
            bad.write("rule x\n  hex $h = 4\nend\n");
            bad.close();
            QVERIFY(!w.runRules(dir.filePath(QStringLiteral("bad.rules"))).isEmpty());
        }
        // A new window on the same content restores the bookmarks.
        MainWindow w2;
        w2.show();
        QSignalSpy loaded2(&w2, &MainWindow::documentLoaded);
        w2.openFile(file);
        QVERIFY(loaded2.wait(10000));
        QCOMPARE(static_cast<int>(w2.bookmarks().size()), 2);
        QCOMPARE(w2.bookmarks()[1].note, QStringLiteral("hint/name"));
        QVERIFY(w2.removeBookmarkAt(0x701));
        QCOMPARE(static_cast<int>(w2.bookmarks().size()), 1);
        QSettings().remove(QStringLiteral("bookmarks"));
    }

    void realFileIconAndDotNet() {
        const QString notepad = QStringLiteral("C:/Windows/System32/notepad.exe");
        const QString system_dll = QStringLiteral("C:/Windows/Microsoft.NET/Framework64/v4.0.30319/System.dll");
        if (!QFileInfo::exists(notepad) || !QFileInfo::exists(system_dll)) QSKIP("Windows system files not available");
        MainWindow w;
        w.show();
        QSignalSpy loaded(&w, &MainWindow::documentLoaded);
        w.openFile(notepad);
        QVERIFY(loaded.wait(20000));
        QVERIFY(!w.fileIcon().isNull());
        QVERIFY(w.panel(QStringLiteral("Functions")) && w.panel(QStringLiteral("Functions"))->model()->rowCount() > 100);
        QSignalSpy loaded2(&w, &MainWindow::documentLoaded);
        w.openFile(system_dll);
        QVERIFY(loaded2.wait(20000));
        auto* net = w.panel(QStringLiteral(".NET"));
        QVERIFY(net);
        net->filter()->setText(QStringLiteral("PublicKeyToken=b77a5c561934e089"));
        QVERIFY(net->view()->model()->rowCount() >= 2);  // the assembly itself and its mscorlib reference
        screenshot(&w, QStringLiteral("main-dotnet.png"));
    }

    void compareWindowNavigatesChanges() {
        MainWindow w;
        w.show();
        QSignalSpy loaded(&w, &MainWindow::documentLoaded);
        w.openFile(kCorpus + QStringLiteral("/elf/clean-elf64le.so"));
        QVERIFY(loaded.wait(10000));
        QSignalSpy opened(&w, &MainWindow::compareWindowOpened);
        w.compareWith(kCorpus + QStringLiteral("/elf/variant-elf64le.so"));
        QVERIFY(opened.wait(10000));
        auto* cw = qobject_cast<CompareWindow*>(w.lastCompareWindow());
        QVERIFY(cw);
        QSignalSpy ready(cw, &CompareWindow::diffReady);
        if (!cw->diff()) QVERIFY(ready.wait(10000));
        bool found = false;
        auto* m = cw->changes()->model();
        for (int r = 0; r < m->rowCount(); ++r)
            found = found || m->index(r, 1).data().toString() == QStringLiteral("libm.so.6");
        QVERIFY(found);
        QVERIFY(!cw->diff()->raw.ranges.empty());
        QVERIFY(cw->jumpToChange(true));
        QCOMPARE(cw->hexA()->selection().offset, cw->diff()->raw.ranges.front().offset);
        QCOMPARE(cw->hexB()->cursor(), cw->hexA()->cursor());
        cw->resize(1500, 900);
        screenshot(cw, QStringLiteral("compare-elf.png"));
        screenshot(&w, QStringLiteral("main-elf.png"));
        cw->close();
    }

    void largeFileStaysResponsive() {
        // 256 MiB file: mapped, analyzed off the UI thread, hex view paints
        // only visible rows. Reports the measured times.
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath(QStringLiteral("large.bin"));
        {
            std::ofstream f(path.toStdString(), std::ios::binary);
            std::vector<char> chunk(1 << 20);
            std::mt19937 rng(5);
            for (int i = 0; i < 256; ++i) {
                if (i % 2) for (auto& c : chunk) c = static_cast<char>(rng());
                else std::fill(chunk.begin(), chunk.end(), 0);
                f.write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
            }
        }
        MainWindow w;
        w.show();
        QSignalSpy loaded(&w, &MainWindow::documentLoaded);
        QElapsedTimer t;
        t.start();
        w.openFile(path);
        // The event loop must keep running while the worker analyzes the file.
        int ticks = 0;
        while (loaded.isEmpty() && t.elapsed() < 60000) {
            QTest::qWait(20);
            ++ticks;
        }
        QVERIFY(!loaded.isEmpty());
        qInfo("256 MiB load+analysis: %lld ms, UI event-loop ticks while loading: %d", t.elapsed(), ticks);
        QVERIFY(w.document()->file->memory_mapped());
        QVERIFY(w.document()->entropy.size() <= 4096);
        QElapsedTimer paint;
        paint.start();
        w.hexView()->goTo((std::uint64_t{256} << 20) - 1);
        w.hexView()->repaint();
        qInfo("goTo(end) + repaint: %lld ms", paint.elapsed());
        QCOMPARE(w.hexView()->cursor(), (quint64{256} << 20) - 1);

        // A full-file search can be cancelled while it runs on the worker thread.
        QSignalSpy done(&w, &MainWindow::searchFinished);
        w.hexView()->goTo(0);
        w.setFindPattern(QStringLiteral("de ad be ef 01 02 03 04"), true);  // absent: would scan everything
        QVERIFY(w.findAll());
        w.cancelSearch();
        QVERIFY(done.wait(10000));
        QCOMPARE(done.takeFirst().at(0).toBool(), false);
    }
};

QTEST_MAIN(GuiTests)
#include "gui_tests.moc"
