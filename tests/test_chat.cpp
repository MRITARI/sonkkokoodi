// End-to-end tests: real SecureChatApp instances (headless) talking through the real Python relay.
// Run with QT_QPA_PLATFORM=offscreen. Needs a Python interpreter (env SK_PYTHON, default "python").
#include <QtTest>
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

class ChatE2ETest : public QObject {
    Q_OBJECT
    QTemporaryDir tmp;
    std::unique_ptr<QProcess> relay;
    int port = 0;

    static int freePort() {
        QTcpServer s;
        s.listen(QHostAddress::LocalHost, 0);
        return s.serverPort();
    }
    void startRelay() {
        relay = std::make_unique<QProcess>();
        const QString py = qEnvironmentVariable("SK_PYTHON", "python");
        relay->setProgram(py);
        relay->setArguments({ QString(SK_SOURCE_DIR "/server.py"), "--host", "127.0.0.1", "--port", QString::number(port) });
        relay->start();
        QVERIFY(relay->waitForStarted(5000));
        QTRY_VERIFY_WITH_TIMEOUT(canConnect(), 8000);
    }
    void stopRelay() {
        if (relay) { relay->kill(); relay->waitForFinished(3000); relay.reset(); }
    }
    bool canConnect() {
        QTcpSocket s;
        s.connectToHost("127.0.0.1", port);
        return s.waitForConnected(300);
    }
    std::unique_ptr<SecureChatApp> makeApp(const QString &name, const QString &alias, const QString &room, int negotiationMs = -1) {
        const QString dir = tmp.path() + "/" + name;
        QDir().mkpath(dir);
        auto app = std::make_unique<SecureChatApp>(dir);
        app->pwdInput->setText("unlock-password-1");  app->handlePwdSubmit();   // step 1
        app->msgInput->setText(alias);                app->handleInput();       // step 2
        app->msgInput->setText("127.0.0.1:" + QString::number(port)); app->handleInput();   // step 3
        app->negotiationTimeoutOverrideMs = negotiationMs;
        app->msgInput->setText(room);                 app->handleInput();       // step 4 -> connects
        return app;
    }
    static bool secure(SecureChatApp *a) {
        return a->tcpSocket && a->tcpSocket->state() == QAbstractSocket::ConnectedState
               && !a->isNegotiating && !a->currentGroupKey.isEmpty();
    }
    static void say(SecureChatApp *a, const QString &t) { a->msgInput->setText(t); a->handleInput(); }
    static bool saw(SecureChatApp *a, const QString &needle) {
        for (const ChatMsg &m : a->history) if (!m.isSystem && m.plainText.contains(needle)) return true;
        return false;
    }
    static int gcmFailures(SecureChatApp *a) {
        int n = 0;
        for (const ChatMsg &m : a->history) if (m.isError) ++n;
        return n;
    }

private slots:
    void initTestCase() {
        QVERIFY(tmp.isValid());
        port = freePort();
        startRelay();
    }
    void cleanupTestCase() { stopRelay(); }

    void twoClientsShareKeyAndChatPastRatchet() {
        auto a = makeApp("a1", "alice", "correct horse battery staple");
        QTRY_VERIFY_WITH_TIMEOUT(secure(a.get()), 15000);
        auto b = makeApp("b1", "bob", "correct horse battery staple");
        QTRY_VERIFY_WITH_TIMEOUT(secure(b.get()), 15000);
        QCOMPARE(a->currentGroupKey, b->currentGroupKey);

        // 45 messages alternating = three ratchet boundaries (every 15), all must arrive and decrypt
        for (int i = 0; i < 45; ++i) {
            SecureChatApp *from = (i % 2) ? b.get() : a.get();
            SecureChatApp *to = (i % 2) ? a.get() : b.get();
            say(from, QString("msg-%1").arg(i));
            QTRY_VERIFY_WITH_TIMEOUT(saw(to, QString("msg-%1").arg(i)), 3000);
            QTest::qWait(120);          // stay under the relay's rate limit
        }
        QCOMPARE(gcmFailures(a.get()), 0);
        QCOMPARE(gcmFailures(b.get()), 0);
        QVERIFY(a->keyEpoch >= 2);
        QCOMPARE(a->keyEpoch, b->keyEpoch);
        QCOMPARE(a->currentGroupKey, b->currentGroupKey);
    }

    void wrongPassphraseNeverReceivesTheKey() {
        auto a = makeApp("a2", "alice2", "the real room passphrase");
        QTRY_VERIFY_WITH_TIMEOUT(secure(a.get()), 15000);
        auto evil = makeApp("e2", "mallory", "a different guess 123");
        // Mallory times out and creates its OWN key; it never gets alice's.
        QTRY_VERIFY_WITH_TIMEOUT(secure(evil.get()), 15000);
        QTest::qWait(1500);
        QVERIFY(evil->currentGroupKey != a->currentGroupKey);
        say(evil.get(), "can you read this?");
        QTest::qWait(800);
        QVERIFY(!saw(a.get(), "can you read this?"));
    }

    void simultaneousJoinConverges() {
        // Two fresh clients starting at the same moment on an EMPTY room must end up with one key.
        // (Uses its own relay so no other client interferes.)
        stopRelay();
        port = freePort();
        startRelay();
        for (int round = 0; round < 3; ++round) {
            auto a = makeApp(QString("sa%1").arg(round), "sim-a", "simultaneous room passphrase");
            auto b = makeApp(QString("sb%1").arg(round), "sim-b", "simultaneous room passphrase");
            QTRY_VERIFY_WITH_TIMEOUT(secure(a.get()) && secure(b.get()), 20000);
            QTest::qWait(1500);   // allow a late tie-break WELCOME to land
            QCOMPARE(a->currentGroupKey, b->currentGroupKey);
            say(a.get(), "hello-from-a");
            QTRY_VERIFY_WITH_TIMEOUT(saw(b.get(), "hello-from-a"), 3000);
            a.reset(); b.reset();
            QTest::qWait(300);
        }
    }

    // Deterministic collision: both clients give up waiting at the same instant, each creates its own key
    // and each welcomes the other. Without a tie-break the two would swap keys and stay split.
    void forcedSimultaneousKeyCreationConverges() {
        stopRelay();
        port = freePort();
        startRelay();
        for (int round = 0; round < 3; ++round) {
            auto a = makeApp(QString("fa%1").arg(round), "force-a", "forced collision passphrase", 1500);
            auto b = makeApp(QString("fb%1").arg(round), "force-b", "forced collision passphrase", 1500);
            QTRY_VERIFY_WITH_TIMEOUT(secure(a.get()) && secure(b.get()), 20000);
            QTest::qWait(2500);
            QVERIFY2(a->currentGroupKey == b->currentGroupKey, "split room: clients hold different keys");
            say(a.get(), "ping-a");
            say(b.get(), "ping-b");
            QTRY_VERIFY_WITH_TIMEOUT(saw(b.get(), "ping-a") && saw(a.get(), "ping-b"), 4000);
            a.reset(); b.reset();
            QTest::qWait(300);
        }
    }

    void relayKilledThenAutoReconnect() {
        auto a = makeApp("ar", "alice3", "reconnect room passphrase");
        QTRY_VERIFY_WITH_TIMEOUT(secure(a.get()), 15000);
        auto b = makeApp("br", "bob3", "reconnect room passphrase");
        QTRY_VERIFY_WITH_TIMEOUT(secure(b.get()), 15000);
        say(a.get(), "before-crash");
        QTRY_VERIFY_WITH_TIMEOUT(saw(b.get(), "before-crash"), 3000);

        stopRelay();
        QTRY_VERIFY_WITH_TIMEOUT(!a->tcpSocket || a->tcpSocket->state() != QAbstractSocket::ConnectedState, 5000);
        QTRY_VERIFY_WITH_TIMEOUT(!b->tcpSocket || b->tcpSocket->state() != QAbstractSocket::ConnectedState, 5000);
        startRelay();

        QTRY_VERIFY_WITH_TIMEOUT(secure(a.get()) && secure(b.get()), 40000);
        QTest::qWait(1500);
        QCOMPARE(a->currentGroupKey, b->currentGroupKey);
        say(b.get(), "after-restart");
        QTRY_VERIFY_WITH_TIMEOUT(saw(a.get(), "after-restart"), 3000);
    }

    void noReconnectAfterUserDisconnect() {
        auto a = makeApp("nd", "alice4", "no reconnect passphrase");
        QTRY_VERIFY_WITH_TIMEOUT(secure(a.get()), 15000);
        say(a.get(), "disconnect");
        QTRY_VERIFY_WITH_TIMEOUT(!a->tcpSocket, 5000);
        QTest::qWait(6000);
        QVERIFY(!a->tcpSocket);
    }

    void replayedPacketIsIgnored() {
        auto a = makeApp("ra", "alice5", "replay room passphrase");
        QTRY_VERIFY_WITH_TIMEOUT(secure(a.get()), 15000);
        auto b = makeApp("rb", "bob5", "replay room passphrase");
        QTRY_VERIFY_WITH_TIMEOUT(secure(b.get()), 15000);

        // A recording attacker: a raw socket that captures what the relay forwards, then replays it.
        QTcpSocket spy;
        spy.connectToHost("127.0.0.1", port);
        QVERIFY(spy.waitForConnected(2000));
        QTest::qWait(200);
        say(a.get(), "unique-replay-marker");
        QTRY_VERIFY_WITH_TIMEOUT(spy.bytesAvailable() > 0, 3000);
        QByteArray captured = spy.readAll();
        QTRY_VERIFY_WITH_TIMEOUT(saw(b.get(), "unique-replay-marker"), 3000);

        auto count = [&]() { int n = 0; for (const ChatMsg &m : b->history) if (m.plainText.contains("unique-replay-marker")) ++n; return n; };
        QCOMPARE(count(), 1);
        spy.write(captured);
        spy.flush();
        QTest::qWait(1200);
        QCOMPARE(count(), 1);     // the identical signed packet is not shown again
    }
};

QTEST_MAIN(ChatE2ETest)
#include "test_chat.moc"
