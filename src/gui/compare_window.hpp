#pragma once
// Side-by-side comparison: structural changes (with confidence) and caveats
// on top, two synchronized hex views with changed bytes highlighted below.
#include "document.hpp"

#include <QFutureWatcher>
#include <QMainWindow>

class HexView;
class QLabel;
class QListWidget;
class TablePanel;

class CompareWindow : public QMainWindow {
    Q_OBJECT
public:
    CompareWindow(DocumentPtr a, DocumentPtr b, QWidget* parent = nullptr);
    ~CompareWindow() override;

    const bw::StructuralDiff* diff() const { return diff_ ? diff_.get() : nullptr; }
    HexView* hexA() const { return hex_a_; }
    HexView* hexB() const { return hex_b_; }
    TablePanel* changes() const { return changes_; }
    bool jumpToChange(bool forward);  // next/previous raw changed run relative to the cursor

signals:
    void diffReady();

private:
    void showDiff(std::shared_ptr<const bw::StructuralDiff> d);

    DocumentPtr a_, b_;
    std::shared_ptr<const bw::StructuralDiff> diff_;
    QFutureWatcher<std::shared_ptr<const bw::StructuralDiff>> watcher_;
    QLabel* summary_{};
    TablePanel* changes_{};
    QListWidget* caveats_{};
    HexView* hex_a_{};
    HexView* hex_b_{};
};
