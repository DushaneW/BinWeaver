#pragma once
// Plot of Shannon entropy per fixed-size window across the whole file, with
// section boundaries and the hex cursor. Clicking navigates the hex view.
#include "document.hpp"

#include <QWidget>

class EntropyView : public QWidget {
    Q_OBJECT
public:
    explicit EntropyView(QWidget* parent = nullptr);
    void setDocument(DocumentPtr doc);
    void setCursorOffset(std::uint64_t offset);
    QSize sizeHint() const override { return {600, 120}; }
    QSize minimumSizeHint() const override { return {200, 70}; }

signals:
    void offsetActivated(quint64 offset);

protected:
    void paintEvent(QPaintEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;

private:
    QRect plotRect() const;
    std::uint64_t offsetAtX(int x) const;
    DocumentPtr doc_;
    std::uint64_t cursor_{};
};
