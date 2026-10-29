#include "table_model.hpp"

#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QTableView>
#include <QVBoxLayout>

QString hexText(std::uint64_t v) { return QStringLiteral("0x") + QString::number(v, 16); }

RecordModel::RecordModel(int rows, std::vector<Column> columns, RangeFn range, QObject* parent)
    : QAbstractTableModel(parent), rows_(rows), columns_(std::move(columns)), range_(std::move(range)) {}

int RecordModel::rowCount(const QModelIndex& parent) const { return parent.isValid() ? 0 : rows_; }
int RecordModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(columns_.size());
}

QVariant RecordModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rows_) return {};
    const auto& c = columns_[static_cast<std::size_t>(index.column())];
    switch (role) {
    case Qt::DisplayRole:
    case Qt::ToolTipRole:
        return c.text ? QVariant(c.text(index.row())) : c.value(index.row());
    case roles::Sort:
        return c.value(index.row());
    case Qt::TextAlignmentRole:
        return c.numeric ? QVariant(Qt::AlignRight | Qt::AlignVCenter) : QVariant(Qt::AlignLeft | Qt::AlignVCenter);
    case roles::Offset:
    case roles::Length: {
        auto r = range(index.row());
        if (!r) return {};
        return QVariant::fromValue<quint64>(role == roles::Offset ? r->offset : r->size);
    }
    default:
        return {};
    }
}

QVariant RecordModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role != Qt::DisplayRole) return {};
    if (orientation == Qt::Vertical) return section + 1;
    return columns_[static_cast<std::size_t>(section)].title;
}

TablePanel::TablePanel(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(4);
    auto* top = new QHBoxLayout;
    filter_ = new QLineEdit;
    filter_->setPlaceholderText(tr("Filter rows (all columns, case-insensitive)"));
    filter_->setClearButtonEnabled(true);
    count_ = new QLabel;
    top->addWidget(filter_, 1);
    top->addWidget(count_);
    layout->addLayout(top);

    proxy_ = new QSortFilterProxyModel(this);
    proxy_->setSortRole(roles::Sort);
    proxy_->setFilterKeyColumn(-1);
    proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    view_ = new QTableView;
    view_->setModel(proxy_);
    view_->setSortingEnabled(true);
    view_->setSelectionBehavior(QAbstractItemView::SelectRows);
    view_->setSelectionMode(QAbstractItemView::SingleSelection);
    view_->setAlternatingRowColors(true);
    view_->setWordWrap(false);
    view_->verticalHeader()->setDefaultSectionSize(view_->fontMetrics().height() + 6);
    view_->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    view_->horizontalHeader()->setStretchLastSection(true);
    view_->horizontalHeader()->setSectionsMovable(true);
    layout->addWidget(view_, 1);

    connect(filter_, &QLineEdit::textChanged, this, [this](const QString& text) {
        proxy_->setFilterFixedString(text);
        updateCount();
    });
    connect(view_->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](const QModelIndex& current) {
                if (syncing_ || !current.isValid() || !model_) return;
                const auto src = proxy_->mapToSource(current);
                emit rowActivated(src.row());
                if (auto r = model_->range(src.row())) emit rangeActivated(r->offset, r->size);
            });
}

void TablePanel::setModel(RecordModel* model) {
    if (model_) model_->deleteLater();
    model_ = model;
    model_->setParent(this);
    proxy_->setSourceModel(model_);
    view_->sortByColumn(-1, Qt::AscendingOrder);  // keep file order until the user sorts
    view_->resizeColumnsToContents();
    for (int c = 0; c < model_->columnCount(); ++c)
        if (view_->columnWidth(c) > 420) view_->setColumnWidth(c, 420);
    updateCount();
}

void TablePanel::updateCount() {
    if (!model_) return;
    const int total = model_->rowCount(), shown = proxy_->rowCount();
    count_->setText(shown == total ? tr("%n row(s)", nullptr, total) : tr("%1 of %2").arg(shown).arg(total));
}

void TablePanel::selectSourceRow(int row) {
    if (!model_) return;
    const auto idx = proxy_->mapFromSource(model_->index(row, 0));
    syncing_ = true;
    if (idx.isValid()) {
        view_->selectionModel()->setCurrentIndex(idx, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        view_->scrollTo(idx);
    } else {
        view_->selectionModel()->clearCurrentIndex();  // clearSelection() alone leaves a stale current row
        view_->clearSelection();
    }
    syncing_ = false;
}

int TablePanel::rowContaining(std::uint64_t offset) const {
    if (!model_) return -1;
    int best = -1;
    std::uint64_t best_size = 0;
    for (int r = 0; r < model_->rowCount(); ++r) {
        auto range = model_->range(r);
        if (!range || range->size == 0 || !bw::subrange_of(range->offset, range->size, offset, 1)) continue;
        if (best < 0 || range->size < best_size) {
            best = r;
            best_size = range->size;
        }
    }
    return best;
}
