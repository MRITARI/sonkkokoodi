// Renders the installer window headlessly:  screenshots_installer <output.png>
#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QProgressBar>
#include <QTextEdit>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QProcess>
#include <QPainter>
#include <QPolygon>
#include <QMouseEvent>
#include <QDateTime>
#include <QSpacerItem>
#include <QCryptographicHash>
#include <QDirIterator>
#include <QFileInfo>
#include <QProcessEnvironment>
#include <QElapsedTimer>
#include <QThread>
#include <functional>

#define main sk_installer_main
#include "../installer.cpp"
#undef main

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    if (argc < 2) return 1;
    app.setStyleSheet(sk::theme::styleSheet(100));
    InstallerApp w;
    w.show();
    QElapsedTimer t; t.start();
    while (t.elapsed() < 2500) { QCoreApplication::processEvents(QEventLoop::AllEvents, 20); QThread::msleep(10); }
    w.grab().save(argv[1]);
    return 0;
}
