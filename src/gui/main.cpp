#include "main_window.hpp"

#include <QApplication>
#include <QCommandLineParser>

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("BinWeaver"));
    QApplication::setApplicationName(QStringLiteral("BinWeaver"));
    QApplication::setApplicationVersion(QStringLiteral(BINWEAVER_VERSION));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Static PE/ELF structure inspector"));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addPositionalArgument(QStringLiteral("file"), QStringLiteral("File to open"), QStringLiteral("[file]"));
    parser.addPositionalArgument(QStringLiteral("other"), QStringLiteral("Second file: open a comparison"), QStringLiteral("[other]"));
    parser.process(app);

    MainWindow w;
    w.show();
    const auto args = parser.positionalArguments();
    if (args.size() >= 2) {
        const QString other = args[1];
        QObject::connect(&w, &MainWindow::documentLoaded, &w, [&w, other] { w.compareWith(other); },
                         Qt::SingleShotConnection);
    }
    if (!args.isEmpty()) w.openFile(args[0]);
    return app.exec();
}
