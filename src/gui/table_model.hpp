#pragma once
// Table model whose cells are computed on demand from the analysis, so a
// table with millions of symbols costs no per-cell storage. Each row may map
// to a file byte range, which drives hex-view synchronization.
#include "binweaver/binweaver.hpp"

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QWidget>

#include <cstdint>
#include <functional>
#include <optional>

class QLabel;
class QLineEdit;
class QTableView;

namespace roles {
constexpr int Sort = Qt::UserRole + 1;     // raw value used for sorting
constexpr int Offset = Qt::UserRole + 2;   // quint64 file offset of the row's range, if any
constexpr int Length = Qt::UserRole + 3;   // quint64 length of that range
} // namespace roles

struct Column {
    QString title;
    std::function<QVariant(int row)> value;  // sort key; also displayed when `text` is empty
    std::function<QString(int row)> text = {};
    bool numeric = false;
};

class RecordModel : public QAbstractTableModel {
    Q_OBJECT
public:
    using RangeFn = std::function<std::optional<bw::ByteRange>(int row)>;
    RecordModel(int rows, std::vector<Column> columns, RangeFn range = {}, QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    std::optional<bw::ByteRange> range(int row) const { return range_ ? range_(row) : std::nullopt; }

private:
    int rows_;
    std::vector<Column> columns_;
    RangeFn range_;
};

// Filter box + sortable table + row count, used for every metadata list.
class TablePanel : public QWidget {
    Q_OBJECT
public:
    explicit TablePanel(QWidget* parent = nullptr);
    void setModel(RecordModel* model);  // takes ownership
    RecordModel* model() const { return model_; }
    QTableView* view() const { return view_; }
    QLineEdit* filter() const { return filter_; }
    // Selects the row (in source-model coordinates) without emitting rangeActivated.
    void selectSourceRow(int row);
    // Source row whose range contains `offset` and is the smallest such range, or -1.
    int rowContaining(std::uint64_t offset) const;

signals:
    void rangeActivated(quint64 offset, quint64 length);
    void rowActivated(int source_row);

private:
    void updateCount();
    QLineEdit* filter_;
    QLabel* count_;
    QTableView* view_;
    QSortFilterProxyModel* proxy_;
    RecordModel* model_{};
    bool syncing_{};
};

QString hexText(std::uint64_t v);
