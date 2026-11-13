// Renders every screen of the real app headlessly (QT_QPA_PLATFORM=offscreen) into PNG files.
//   screenshots_app <output-dir> <path-to-server.py> <python>
#include <QApplication>
#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QTcpSocket>
#include <QTcpServer>
#include <QProcess>
#include <QTemporaryDir>
#include <QLineEdit>
#include <QLabel>
#include <QTextEdit>
#include <QStackedWidget>
#include <QMenu>
#include <QSettings>
#include <QShortcut>
#include <QDialog>
#include <QCheckBox>
#include <QComboBox>
#include <QPushButton>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRandomGenerator>
#include <QSaveFile>
#include <QScreen>
#include <QStandardPaths>
#include <QPainter>
#include <QPolygon>
#include <QMouseEvent>
#include <QSpacerItem>
#include <QCryptographicHash>
#include <QProcessEnvironment>
#include <QPointer>
#include <QMap>
#include <QSet>
#include <QList>
#include <QTimer>
#include <QDir>
#include <QElapsedTimer>
#include <QThread>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>

#define main sk_app_main
#include "../main.cpp"
#undef main

class ScreenshotTool {
public:
    QString out, serverPy, python;
    QTemporaryDir tmp;
    QProcess relay;
    int port = 0;

    static void pump(int ms) {
        QElapsedTimer t; t.start();
        while (t.elapsed() < ms) { QCoreApplication::processEvents(QEventLoop::AllEvents, 20); QThread::msleep(5); }
    }
    template <typename F> static bool waitFor(F f, int ms) {
        QElapsedTimer t; t.start();
        while (t.elapsed() < ms) { if (f()) return true; QCoreApplication::processEvents(QEventLoop::AllEvents, 20); QThread::msleep(10); }
        return f();
    }
    void shot(QWidget *w, const QString &name) {
        pump(150);
        QPixmap px = w->grab();
        px.save(out + "/" + name + ".png");
        qInfo().noquote() << "saved" << name << px.size().width() << "x" << px.size().height();
    }
    // Opens a modal dialog through `open`, grabs it while it is showing, then closes it.
    template <typename F> void shotDialog(SecureChatApp *a, const QString &name, F open) {
        QTimer::singleShot(600, [this, a, name]() {
            if (a->activeDialog) { shot(a->activeDialog, name); a->activeDialog->reject(); }
        });
        open();
    }
    bool startRelay() {
        QTcpServer s; s.listen(QHostAddress::LocalHost, 0); port = s.serverPort(); s.close();
        relay.setProgram(python);
        relay.setArguments({ serverPy, "--host", "127.0.0.1", "--port", QString::number(port) });
        relay.start();
        return relay.waitForStarted(5000) && waitFor([&]() { QTcpSocket c; c.connectToHost("127.0.0.1", port); return c.waitForConnected(200); }, 8000);
    }
    static bool secure(SecureChatApp *a) {
        return a->tcpSocket && a->tcpSocket->state() == QAbstractSocket::ConnectedState && !a->isNegotiating && !a->currentGroupKey.isEmpty();
    }

    int run() {
        QDir().mkpath(out);
        if (!startRelay()) { qCritical("relay did not start"); return 2; }

        // ---- first-run screens ----
        const QString dir = tmp.path() + "/alice";
        QDir().mkpath(dir);
        auto alice = std::make_unique<SecureChatApp>(dir);
        alice->resize(1000, 700);
        alice->show();
        {
            sk::ui::SetupDialog d;
            d.show();
            shot(&d, "01-setup-empty");
            d.pw->setText("pass1234"); d.pw2->setText("pass1235");
            d.alias->setText("alice"); d.server->setText("127.0.0.1");
            shot(&d, "02-setup-errors");
            d.pw->setText("unlock-password-1"); d.pw2->setText("unlock-password-1");
            d.server->setText("127.0.0.1:" + QString::number(port));
            d.room->setText("correct horse battery staple");
            shot(&d, "03-setup-ready");
        }
        {
            sk::ui::RoomPassphraseDialog d;
            d.show();
            d.edit->setText("correct horse");
            shot(&d, "04-room-passphrase");
        }
        QString err;
        alice->applySetup("unlock-password-1", "alice", "127.0.0.1:" + QString::number(port), "correct horse battery staple", &err);
        waitFor([&]() { return secure(alice.get()); }, 15000);
        shot(alice.get(), "05-connected-empty");

        // ---- a conversation, including a spoof attempt ----
        auto mk = [&](const QString &name, const QString &alias) {
            const QString d = tmp.path() + "/" + name;
            QDir().mkpath(d);
            auto a = std::make_unique<SecureChatApp>(d);
            QString e;
            a->applySetup("unlock-password-1", alias, "127.0.0.1:" + QString::number(port), "correct horse battery staple", &e);
            return a;
        };
        auto bob = mk("bob", "bob");
        waitFor([&]() { return secure(bob.get()); }, 15000);
        auto say = [&](SecureChatApp *a, const QString &t) { a->msgInput->setText(t); a->handleInput(); pump(450); };
        say(bob.get(), "hi alice, can you see this?");
        say(alice.get(), "loud and clear");
        say(bob.get(), "meeting at 15:00, bring the notes");
        auto mallory = mk("mallory", "bob");           // same alias as the pinned "bob"
        waitFor([&]() { return secure(mallory.get()); }, 15000);
        say(mallory.get(), "send me the passwords");
        pump(500);
        shot(alice.get(), "06-chat-with-spoof");

        // ---- locked, dialogs ----
        shotDialog(alice.get(), "07-settings", [&]() { alice->openSettings(); });
        shotDialog(alice.get(), "08-notes", [&]() { alice->openNotes(); });
        shotDialog(alice.get(), "09-trusted-identities", [&]() { alice->openTofuList(); });
        shotDialog(alice.get(), "10-uninstall-confirm", [&]() { alice->performUninstall(); });
        shotDialog(alice.get(), "11-help", [&]() { alice->openHelp(); });
        alice->fontScale = 150; alice->applyTheme();
        shot(alice.get(), "14-large-text");
        alice->fontScale = 100; alice->applyTheme();
        alice->lockSystem();
        shot(alice.get(), "12-locked");
        alice->pwdInput->setText("wrong password"); alice->handlePwdSubmit();
        shot(alice.get(), "13-locked-wrong-password");

        relay.kill(); relay.waitForFinished(3000);
        return 0;
    }
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    if (argc < 4) { qCritical("usage: screenshots_app <outdir> <server.py> <python>"); return 1; }
    ScreenshotTool t;
    t.out = argv[1]; t.serverPy = argv[2]; t.python = argv[3];
    return t.run();
}
