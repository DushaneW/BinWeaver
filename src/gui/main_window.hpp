#pragma once
#include "document.hpp"

#include <QFutureWatcher>
#include <QMainWindow>

#include <atomic>
#include <map>
#include <optional>

class EntropyView;
class HexView;
class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QProgressBar;
class QStackedWidget;
class QToolBar;
class QTreeWidget;
class TablePanel;

// CSV of a table as currently displayed (filter, sort and column order).
QString tableToCsv(TablePanel* panel);

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    void openFile(const QString& path);            // asynchronous; emits documentLoaded
    void compareWith(const QString& path);          // opens a comparison window when B is loaded

    // Accessors used by the GUI tests.
    DocumentPtr document() const { return doc_; }
    HexView* hexView() const { return hex_; }
    TablePanel* panel(const QString& name) const;
    QTreeWidget* inspector() const { return inspector_; }
    QWidget* lastCompareWindow() const { return last_compare_; }
    // Starts a background search with the find bar's pattern; emits searchFinished.
    bool findNext(bool forward);
    // Starts a background search for every match; fills the "Search results" panel.
    bool findAll();
    void cancelSearch();
    void setFindPattern(const QString& text, bool hex);
    // Moves the hex view and records the previous position for Back/Forward.
    void navigate(quint64 offset, quint64 length = 0);
    bool goBack();
    bool goForward();
    bool goToEntryPoint();
    QPixmap fileIcon() const;  // null when the file has no usable icon

    struct Bookmark {
        quint64 offset{}, length{};
        QString note;
    };
    // Bookmarks are stored per file content (SHA-256) in the application settings.
    void addBookmark(quint64 offset, quint64 length, const QString& note);
    bool removeBookmarkAt(quint64 offset);
    bool nextBookmark(bool forward);
    const std::vector<Bookmark>& bookmarks() const { return bookmarks_; }
    // Runs a rule file against the open document; returns parse errors (empty on success).
    QStringList runRules(const QString& path);
    // Writes the hex selection (or the byte under the cursor) to `path`.
    bool saveSelection(const QString& path, QString* error = nullptr);

signals:
    void documentLoaded();
    void searchFinished(bool found);
    void compareWindowOpened(QWidget* window);

protected:
    void closeEvent(QCloseEvent*) override;
    void dragEnterEvent(QDragEnterEvent*) override;
    void dropEvent(QDropEvent*) override;

private:
    void buildActions();
    void buildFindBar();
    void showDocument(DocumentPtr doc);
    void populatePanels();
    void addPanel(const QString& name, TablePanel* panel);
    void onCursorMoved(quint64 offset);
    void onSelectionChanged(quint64 start, quint64 length);
    void updateInspector();
    void goToOffsetDialog();
    void goToAddressDialog();
    void exportReport();
    void exportTableCsv();
    void showShortcuts();
    void addRecent(const QString& path);
    void rebuildRecentMenu();
    void setBusy(const QString& message);
    void clearBusy();

    DocumentPtr doc_;
    QFutureWatcher<DocumentPtr> loader_;
    QFutureWatcher<DocumentPtr> compare_loader_;
    QFutureWatcher<std::optional<quint64>> search_;
    QFutureWatcher<std::vector<std::uint64_t>> search_all_;
    std::shared_ptr<std::atomic<bool>> search_cancel_;
    std::size_t search_length_{};
    bool searchRunning() const { return search_.isRunning() || search_all_.isRunning(); }
    std::optional<bw::BytePattern> currentPattern();
    bw::SearchProgress progressReporter();
    void showSearchResults(const std::vector<std::uint64_t>& hits);

    QListWidget* nav_{};
    QStackedWidget* pages_{};
    std::map<QString, TablePanel*> panels_;
    HexView* hex_{};
    EntropyView* entropy_{};
    QTreeWidget* inspector_{};
    QToolBar* find_bar_{};
    QLineEdit* find_text_{};
    QComboBox* find_mode_{};
    QLabel* find_status_{};
    QAction* find_cancel_{};
    QLabel* status_offset_{};
    QLabel* status_file_{};
    QProgressBar* busy_{};
    QMenu* recent_menu_{};
    QWidget* last_compare_{};
    QLabel* icon_label_{};
    std::vector<quint64> back_, forward_;
    std::vector<Bookmark> bookmarks_;
    void loadBookmarks();
    void saveBookmarks();
    void refreshBookmarkPanel();
};
