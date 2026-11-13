#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QSpacerItem>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QPainter>
#include <QPolygon>
#include <QMouseEvent>
#include <QTcpSocket>
#include <QDateTime>
#include <QShortcut>
#include <QKeySequence>
#include <QList>
#include <QSet>
#include <QSettings>
#include <QCryptographicHash>
#include <QScrollBar>
#include <QCoreApplication>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QStandardPaths>
#include <QScreen>
#include <QShowEvent>
#include <QKeyEvent>
#include <QEvent>
#include <QTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QRandomGenerator>
#include <QMap>
#include <QStackedWidget>
#include <QColor>
#include <QDialog>
#include <QCheckBox>
#include <QComboBox>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPointer>

#include <memory>

// --- OPENSSL CRYPTOGRAPHY ---
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>
#include "sk_crypto.h"
#include "sk_protocol.h"

// --- Limits ---
static const qint64 kMaxLineBytes     = 16384;  // max size of one incoming network line
static const int    kMaxMessageBytes  = 3000;   // keeps the signed envelope under the relay's 8 KB limit
static const int    kMaxHistory       = 1000;   // messages kept in memory / vault
static const int    kSendIntervalMs   = 130;        // ~7.7 packets/s; the relay limit is 10/s
static const int    kMaxOutQueue      = 100;    // refuse new input beyond this many queued packets
static const int    kRatchetEvery     = 15;     // messages per group-key epoch
static const int    kMaxEpochJump     = 256;    // how far a peer may be ahead of us

struct ChatMsg {
    QString time;
    QString prefix;
    QString plainText;
    QByteArray cipherText;
    bool isSystem;
    bool isSelf;
    bool isVerified;
    bool isTransient;
    bool isError = false;
};

using sk::pkeyToDER;
using sk::derToPkey;
using sk::privKeyToPEM;
using sk::pemToPrivKey;
using sk::constTimeEqual;

// Password check value derived from the (slow, salted) PBKDF2 key - never from the raw password.
static QByteArray makeVerifier(const QByteArray &vaultKey) {
    return QCryptographicHash::hash(QByteArray("sk-verify-v1") + vaultKey, QCryptographicHash::Sha256).toHex();
}

// --- Alias helpers ---
static bool isValidNick(const QString &n) {
    if (n.isEmpty() || n.size() > 24) return false;
    for (QChar c : n) {
        if (!(c.isLetterOrNumber() || c == QLatin1Char('_') || c == QLatin1Char('-') || c == QLatin1Char('.')))
            return false;
    }
    return true;
}

// Case/punctuation-insensitive form used to detect look-alike aliases.
static QString normNick(const QString &n) {
    QString out;
    for (QChar c : n) if (c.isLetterOrNumber()) out += c.toCaseFolded();
    return out;
}

// "host" or "host:port". portGiven tells whether a port was part of the text.
static bool parseEndpoint(const QString &text, QString &host, int &port, bool &portGiven) {
    QString t = text.trimmed();
    portGiven = false;
    if (t.isEmpty() || t.contains(QLatin1Char(' '))) return false;
    if (t.count(QLatin1Char(':')) == 1) {
        int i = t.indexOf(QLatin1Char(':'));
        bool ok = false;
        int p = t.mid(i + 1).toInt(&ok);
        if (!ok || p < 1 || p > 65535) return false;
        host = t.left(i);
        port = p;
        portGiven = true;
    } else {
        host = t;
    }
    return !host.isEmpty();
}

// --- UI Components ---
class TechTopBar : public QWidget {
    Q_OBJECT
public:
    TechTopBar(QWidget *parent = nullptr) : QWidget(parent), m_parent(parent) {
        setFixedHeight(45);
        QHBoxLayout *layout = new QHBoxLayout(this);
        layout->setContentsMargins(20, 0, 20, 0);

        QLabel *title = new QLabel("SÖNKKÖKOODI", this);
        title->setStyleSheet("color: #55FF55; font-weight: bold; font-family: 'Arial'; font-size: 16px;");
        layout->addWidget(title);
        layout->addSpacerItem(new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum));

        QString btnStyle = "QPushButton { background-color: transparent; color: #666666; font-weight: bold; border: none; font-size: 20px; padding-bottom: 5px; } QPushButton:hover { color: #FFFFFF; }";

        QPushButton *btnHelp = new QPushButton("?", this);
        btnHelp->setStyleSheet(btnStyle);
        connect(btnHelp, &QPushButton::clicked, [this](){ emit requestHelp(); });
        layout->addWidget(btnHelp);

        QPushButton *btnMenu = new QPushButton("≡", this);
        btnMenu->setStyleSheet(btnStyle);
        layout->addWidget(btnMenu);

        QMenu *settingsMenu = new QMenu(this);
        settingsMenu->setStyleSheet("QMenu { background-color: #111111; color: #FFFFFF; font-family: Arial; font-weight: bold; border: 1px solid #55FF55; } QMenu::item:selected { background-color: #333333; }");

        QAction *notesAction = new QAction("Sönkkö Notes", this);
        connect(notesAction, &QAction::triggered, this, [this](){ emit requestNotes(); });
        QAction *tofuAction = new QAction("TOFU List", this);
        connect(tofuAction, &QAction::triggered, this, [this](){ emit requestTofuList(); });
        QAction *settingsAction = new QAction("Settings", this);
        connect(settingsAction, &QAction::triggered, this, [this](){ emit requestSettings(); });
        QAction *lockAction = new QAction("Lock App", this);
        connect(lockAction, &QAction::triggered, this, [this](){ emit requestLock(); });
        QAction *clearAction = new QAction("Clear Screen", this);
        connect(clearAction, &QAction::triggered, this, [this](){ emit requestClear(); });
        QAction *quitAction = new QAction("Shutdown", this);
        connect(quitAction, &QAction::triggered, this, [this](){ emit requestQuit(); });

        settingsMenu->addAction(notesAction);
        settingsMenu->addAction(tofuAction);
        settingsMenu->addAction(settingsAction);
        settingsMenu->addSeparator();
        settingsMenu->addAction(lockAction);
        settingsMenu->addAction(clearAction);
        settingsMenu->addSeparator();
        settingsMenu->addAction(quitAction);

        connect(btnMenu, &QPushButton::clicked, [btnMenu, settingsMenu]() {
            settingsMenu->popup(btnMenu->mapToGlobal(QPoint(0, btnMenu->height())));
        });

        QPushButton *btnClose = new QPushButton("X", this);
        btnClose->setStyleSheet(btnStyle + "QPushButton:hover { color: #55FF55; }");
        connect(btnClose, &QPushButton::clicked, [this]() { emit requestClose(); });
        layout->addWidget(btnClose);
    }

signals:
    void requestLock();
    void requestClear();
    void requestHelp();
    void requestNotes();
    void requestTofuList();
    void requestSettings();
    void requestQuit();
    void requestClose();

protected:
    void paintEvent(QPaintEvent *event) override {
        Q_UNUSED(event);
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        int cut = 15;
        QPolygon polygon;
        polygon << QPoint(cut, 0) << QPoint(width() - cut, 0)
                << QPoint(width(), height()) << QPoint(0, height());

        painter.setBrush(QColor(15, 15, 15));
        painter.setPen(Qt::NoPen);
        painter.drawPolygon(polygon);
        painter.setPen(QColor(40, 40, 40));
        painter.drawLine(0, height() - 1, width(), height() - 1);
    }
    void mousePressEvent(QMouseEvent *event) override { if (event->button() == Qt::LeftButton) startPos = event->globalPosition().toPoint(); }
    void mouseMoveEvent(QMouseEvent *event) override {
        if (!startPos.isNull()) {
            m_parent->move(m_parent->pos() + (event->globalPosition().toPoint() - startPos));
            startPos = event->globalPosition().toPoint();
        }
    }
    void mouseReleaseEvent(QMouseEvent *event) override { Q_UNUSED(event); startPos = QPoint(); }
private:
    QWidget *m_parent;
    QPoint startPos;
};

// --- Main Application ---
class ChatE2ETest;   // tests/test_chat.cpp drives the real class headlessly

class SecureChatApp : public QMainWindow {
    Q_OBJECT
    friend class ChatE2ETest;
public:
    // dataDirIn: where config/vault live. Empty = next to the executable (portable layout).
    explicit SecureChatApp(const QString &dataDirIn = QString()) : dataDir(dataDirIn) {
        setWindowFlags(Qt::FramelessWindowHint | Qt::Tool);
        setAttribute(Qt::WA_TranslucentBackground);
        resize(1200, 800);

        myIdentityKey = nullptr;
        myEphemeralKey = nullptr;
        msgCount = 0;
        autoLockMinutes = 1;

        QWidget *centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);
        QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
        mainLayout->setContentsMargins(0, 0, 0, 0);
        mainLayout->setSpacing(0);

        TechTopBar *topBar = new TechTopBar(this);
        mainLayout->addWidget(topBar);
        connect(topBar, &TechTopBar::requestLock, this, &SecureChatApp::lockSystem);
        connect(topBar, &TechTopBar::requestClear, this, [this](){
            history.clear();
            chatDisplay->clear();
            saveVault();
        });
        connect(topBar, &TechTopBar::requestHelp, this, &SecureChatApp::printHelp);
        connect(topBar, &TechTopBar::requestNotes, this, &SecureChatApp::openNotes);
        connect(topBar, &TechTopBar::requestTofuList, this, &SecureChatApp::openTofuList);
        connect(topBar, &TechTopBar::requestSettings, this, &SecureChatApp::openSettings);
        connect(topBar, &TechTopBar::requestQuit, this, &SecureChatApp::gracefulShutdown);
        connect(topBar, &TechTopBar::requestClose, this, [this]() {
            // Without a tray icon there would be no way to bring a hidden window back.
            if (trayAvailable) hide();
            else gracefulShutdown();
        });

        contentArea = new QWidget(this);
        contentArea->setObjectName("mainContent");
        contentArea->setStyleSheet("#mainContent { background-color: #000000; border: 2px solid #FF3333; border-top: none; }");

        QVBoxLayout *contentLayout = new QVBoxLayout(contentArea);
        contentLayout->setContentsMargins(15, 15, 15, 15);
        contentLayout->setSpacing(0);

        mainStack = new QStackedWidget(this);

        chatDisplay = new QTextEdit(this);
        chatDisplay->setReadOnly(true);
        chatDisplay->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        chatDisplay->setStyleSheet("background: transparent; color: #FFFFFF; border: none; font-family: 'Arial'; font-weight: bold; font-size: 16px;");
        mainStack->addWidget(chatDisplay);

        QWidget *loadingWidget = new QWidget(this);
        QVBoxLayout *loadingLayout = new QVBoxLayout(loadingWidget);
        loadingLabel = new QLabel("[*] LOADING...", loadingWidget);
        loadingLabel->setAlignment(Qt::AlignCenter);
        loadingLabel->setStyleSheet("color: #55FF55; font-weight: bold; font-family: 'Arial'; font-size: 20px; letter-spacing: 2px;");
        loadingLayout->addWidget(loadingLabel);
        mainStack->addWidget(loadingWidget);

        contentLayout->addWidget(mainStack);

        msgContainer = new QWidget(this);
        QHBoxLayout *msgLayout = new QHBoxLayout(msgContainer);
        msgLayout->setContentsMargins(5, 0, 0, 5);

        promptLabel = new QLabel(">", this);
        promptLabel->setStyleSheet("color: #55FF55; font-weight: bold; font-family: 'Arial'; font-size: 16px;");

        msgInput = new QLineEdit(this);
        msgInput->setStyleSheet("background: transparent; color: #FFFFFF; border: none; font-family: 'Arial'; font-weight: bold; font-size: 16px;");
        connect(msgInput, &QLineEdit::returnPressed, this, &SecureChatApp::handleInput);

        msgLayout->addWidget(promptLabel);
        msgLayout->addWidget(msgInput);
        contentLayout->addWidget(msgContainer);

        pinContainer = new QWidget(this);
        QHBoxLayout *pinLayout = new QHBoxLayout(pinContainer);
        pinLayout->setContentsMargins(5, 0, 0, 5);

        QLabel *lockLabel = new QLabel("[LOCKED] >", this);
        lockLabel->setStyleSheet("color: #FF3333; font-weight: bold; font-family: 'Arial'; font-size: 16px;");

        pwdInput = new QLineEdit(this);
        pwdInput->setEchoMode(QLineEdit::Password);
        pwdInput->setStyleSheet("background: transparent; color: #FF3333; border: none; font-family: 'Arial'; font-weight: bold; font-size: 16px;");
        connect(pwdInput, &QLineEdit::returnPressed, this, &SecureChatApp::handlePwdSubmit);

        pinLayout->addWidget(lockLabel);
        pinLayout->addWidget(pwdInput);
        contentLayout->addWidget(pinContainer);

        mainLayout->addWidget(contentArea);

        tcpSocket = nullptr;

        QShortcut *lockShortcut = new QShortcut(QKeySequence("Alt+L"), this);
        connect(lockShortcut, &QShortcut::activated, this, &SecureChatApp::lockSystem);

        vaultTimer = new QTimer(this);
        vaultTimer->setSingleShot(true);
        connect(vaultTimer, &QTimer::timeout, this, [this]() { saveVault(); });

        reconnectTimer = new QTimer(this);
        reconnectTimer->setSingleShot(true);
        connect(reconnectTimer, &QTimer::timeout, this, [this]() {
            if (!userDisconnected && !uninstalling && myIdentityKey && !tcpSocket) connectToPeer();
        });

        autoLockTimer = new QTimer(this);
        autoLockTimer->setSingleShot(true);
        connect(autoLockTimer, &QTimer::timeout, this, &SecureChatApp::lockSystem);

        setupSystemTray();
        loadConfiguration();

        // Any key press / click anywhere in the app counts as activity (including inside dialogs).
        qApp->installEventFilter(this);
    }

    ~SecureChatApp() {
        if (qApp) qApp->removeEventFilter(this);
        // Child widgets are destroyed in an unspecified order; make sure the socket can no longer call
        // back into half-destroyed members (its 'disconnected' handler touches timers).
        if (tcpSocket) { tcpSocket->disconnect(this); tcpSocket->abort(); tcpSocket = nullptr; }
        if (myIdentityKey) EVP_PKEY_free(myIdentityKey);
        if (myEphemeralKey) EVP_PKEY_free(myEphemeralKey);
    }

    // Start hidden in the tray only when there is nothing to set up and a tray exists to restore from.
    bool shouldStartHidden() const {
        return setupStep == 0 && trayAvailable;
    }

protected:
    void showEvent(QShowEvent *event) override {
        QMainWindow::showEvent(event);
        static bool firstShow = true;
        if (firstShow) {
            QScreen *screen = QGuiApplication::primaryScreen();
            if (screen) {
                QRect screenGeometry = screen->availableGeometry();
                this->move(screenGeometry.x() + (screenGeometry.width() - this->width()) / 2,
                           screenGeometry.y() + (screenGeometry.height() - this->height()) / 2);
            }
            firstShow = false;
        }
    }

    void closeEvent(QCloseEvent *event) override {
        gracefulShutdown();
        QMainWindow::closeEvent(event);
    }

    bool eventFilter(QObject *obj, QEvent *event) override {
        switch (event->type()) {
            case QEvent::KeyPress:
            case QEvent::MouseButtonPress:
            case QEvent::Wheel:
                if (!isLocked && autoLockMinutes > 0 && autoLockTimer) autoLockTimer->start();
                break;
            default:
                break;
        }
        return QMainWindow::eventFilter(obj, event);
    }

    void keyPressEvent(QKeyEvent *event) override {
        bool printable = !event->text().isEmpty() && event->text().at(0).isPrint();
        if (isLocked && setupStep != 2 && setupStep != 3) {
            if (printable && !pwdInput->hasFocus()) {
                pwdInput->setFocus();
                QApplication::sendEvent(pwdInput, event);
            }
        } else {
            if (printable && !msgInput->hasFocus()) {
                msgInput->setFocus();
                QApplication::sendEvent(msgInput, event);
            }
        }
        QMainWindow::keyPressEvent(event);
    }

private slots:
    void gracefulShutdown() {
        flushVault();
        QTcpSocket *s = tcpSocket;
        if (s && s->state() == QAbstractSocket::ConnectedState && myIdentityKey) {
            QJsonObject leaveObj;
            leaveObj["type"] = "LEAVE";
            leaveObj["nick"] = myNickname;
            sendSignedPacket(leaveObj);
            s->flush();
            s->waitForBytesWritten(500);
        }
        if (s) {
            s->disconnect(this);
            s->disconnectFromHost();
            if (s->state() != QAbstractSocket::UnconnectedState) s->waitForDisconnected(500);
        }
        QApplication::quit();
    }

    void printHelp() {
        log("--- SÖNKKÖKOODI COMMANDS ---", "[ * ]", true);
        log("nick <alias>   : Change your alias (1-24 letters, digits, _ - .)", "[ * ]", true);
        log("who            : Display all active users in the room", "[ * ]", true);
        log("clear          : Clear the terminal display", "[ * ]", true);
        log("disconnect     : Disconnect from the current server", "[ * ]", true);
        log("connect        : Connect to the saved server", "[ * ]", true);
        log("passphrase     : Set the room passphrase (must match everyone in the room)", "[ * ]", true);
        log("server <ip>    : Change the target server (ip or ip:port)", "[ * ]", true);
        log("port <num>     : Change the target server port", "[ * ]", true);
        log("help           : Show this list", "[ * ]", true);
        log("Alt+L          : Force lock application", "[ * ]", true);
    }

    void openSettings() {
        if (isLocked) {
            log("Cannot access Settings while system is locked.", "[ ! ]", true);
            return;
        }

        QDialog dlg(this);
        dlg.setWindowFlags(Qt::FramelessWindowHint | Qt::Dialog);
        dlg.resize(450, 470);
        dlg.setStyleSheet("background-color: #000000; border: 2px solid #55FF55; color: #55FF55; font-family: 'Arial'; font-weight: bold; font-size: 16px;");

        QVBoxLayout *l = new QVBoxLayout(&dlg);
        QLabel *lbl = new QLabel("SETTINGS", &dlg);
        lbl->setStyleSheet("border: none; margin-bottom: 10px;");
        l->addWidget(lbl);

        QString chkStyle = "QCheckBox { color: #FFFFFF; font-weight: bold; font-family: 'Arial'; border: none; padding-top: 5px; padding-bottom: 5px; }"
                           "QCheckBox::indicator { width: 18px; height: 18px; border: 2px solid #55FF55; background: #111111; }"
                           "QCheckBox::indicator:checked { background: #55FF55; }";

        QCheckBox *chkConnect = new QCheckBox("Desktop Alert: User Connect", &dlg);
        chkConnect->setChecked(notifyConnect);
        chkConnect->setStyleSheet(chkStyle);
        l->addWidget(chkConnect);

        QCheckBox *chkDisconnect = new QCheckBox("Desktop Alert: User Disconnect", &dlg);
        chkDisconnect->setChecked(notifyDisconnect);
        chkDisconnect->setStyleSheet(chkStyle);
        l->addWidget(chkDisconnect);

        QCheckBox *chkMessage = new QCheckBox("Desktop Alert: New Messages", &dlg);
        chkMessage->setChecked(notifyMessage);
        chkMessage->setStyleSheet(chkStyle);
        l->addWidget(chkMessage);

        QCheckBox *chkAutoStart = new QCheckBox("Start with Windows", &dlg);
        chkAutoStart->setChecked(autoStart);
        chkAutoStart->setStyleSheet(chkStyle);
#ifdef Q_OS_WIN
        l->addWidget(chkAutoStart);
#else
        chkAutoStart->hide();
#endif

        QLabel *lblTimeout = new QLabel("Auto-Lock Timeout:", &dlg);
        lblTimeout->setStyleSheet("color: #FFFFFF; font-weight: bold; border: none; margin-top: 15px;");
        l->addWidget(lblTimeout);

        QComboBox *comboTimeout = new QComboBox(&dlg);
        comboTimeout->setStyleSheet("QComboBox { background-color: #111111; color: #FFFFFF; font-weight: bold; font-family: 'Arial'; border: 1px solid #55FF55; padding: 5px; }"
                                    "QComboBox::drop-down { border: none; }"
                                    "QComboBox QAbstractItemView { background-color: #111111; color: #FFFFFF; selection-background-color: #333333; }");
        comboTimeout->addItem("1 Minute", 1);
        comboTimeout->addItem("5 Minutes", 5);
        comboTimeout->addItem("15 Minutes", 15);
        comboTimeout->addItem("60 Minutes", 60);
        comboTimeout->addItem("Never", 0);

        int idx = comboTimeout->findData(autoLockMinutes);
        if (idx != -1) comboTimeout->setCurrentIndex(idx);
        l->addWidget(comboTimeout);

        l->addSpacerItem(new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding));

        QPushButton *btnUninstall = new QPushButton("UNINSTALL SÖNKKÖKOODI", &dlg);
        btnUninstall->setStyleSheet("QPushButton { background-color: #220000; border: 1px solid #FF3333; padding: 10px; color: #FF3333; } QPushButton:hover { background-color: #440000; color: #FFFFFF; }");
        bool uninstallRequested = false;
        connect(btnUninstall, &QPushButton::clicked, &dlg, [&dlg, &uninstallRequested]() {
            uninstallRequested = true;
            dlg.reject();
        });
        l->addWidget(btnUninstall);

        QPushButton *btn = new QPushButton("SAVE & CLOSE", &dlg);
        btn->setStyleSheet("QPushButton { background-color: #222222; border: 1px solid #55FF55; padding: 10px; color: #FFFFFF; } QPushButton:hover { background-color: #333333; }");
        connect(btn, &QPushButton::clicked, &dlg, &QDialog::accept);
        l->addWidget(btn);

        activeDialog = &dlg;
        int result = dlg.exec();
        activeDialog = nullptr;

        if (uninstallRequested) {
            performUninstall();
            return;
        }

        if (result == QDialog::Accepted) {
            notifyConnect = chkConnect->isChecked();
            notifyDisconnect = chkDisconnect->isChecked();
            notifyMessage = chkMessage->isChecked();
            autoLockMinutes = comboTimeout->currentData().toInt();

            QSettings settings(iniPath(), QSettings::IniFormat);
            settings.setValue("notify_connect", notifyConnect);
            settings.setValue("notify_disconnect", notifyDisconnect);
            settings.setValue("notify_message", notifyMessage);
            settings.setValue("auto_lock_minutes", autoLockMinutes);

#ifdef Q_OS_WIN
            if (chkAutoStart->isChecked() != autoStart) {
                autoStart = chkAutoStart->isChecked();
                settings.setValue("autostart", autoStart);
                enableAutoStart(autoStart);
            }
#endif

            if (autoLockMinutes > 0) {
                autoLockTimer->setInterval(autoLockMinutes * 60000);
                autoLockTimer->start();
            } else {
                autoLockTimer->stop();
            }

            log("Settings saved locally.", "[ * ]", true);
        }
    }

    // The whole folder may only be removed if the installer created it (marker file) or it carries the
    // installer's own folder name. Anything else (a zip unpacked next to other files, a dev tree) is
    // left alone apart from our own data files.
    static bool isManagedInstallDir(const QString &dirPath) {
        const QDir d(dirPath);
        if (d.exists(".sonkkokoodi-install")) return true;
        return d.dirName().compare("Sonkkokoodi", Qt::CaseInsensitive) == 0;
    }
    static bool looksLikeDevTree(const QDir &d) {
        return d.exists("CMakeLists.txt") || d.exists("CMakeCache.txt") || d.exists(".git");
    }

    void performUninstall() {
        const QString plannedDir = QDir::cleanPath(QCoreApplication::applicationDirPath());
        const bool plannedWholeFolder = isManagedInstallDir(plannedDir)
                                        && !looksLikeDevTree(QDir(plannedDir))
                                        && !looksLikeDevTree(QDir(plannedDir + "/.."))
                                        && plannedDir.length() >= 4
                                        && !QDir(plannedDir).isRoot()
                                        && plannedDir != QDir::cleanPath(QDir::homePath());
        QDialog warnDlg(this);
        warnDlg.setWindowFlags(Qt::FramelessWindowHint | Qt::Dialog);
        warnDlg.resize(560, 360);
        warnDlg.setStyleSheet("background-color: #000000; border: 2px solid #FF3333; color: #FF3333; font-family: 'Arial'; font-weight: bold; font-size: 16px;");

        QVBoxLayout *l = new QVBoxLayout(&warnDlg);
        QLabel *lbl = new QLabel("CRITICAL WARNING", &warnDlg);
        lbl->setAlignment(Qt::AlignCenter);
        lbl->setStyleSheet("border: none; font-size: 22px;");
        l->addWidget(lbl);

        QLabel *desc = new QLabel(QString("This will permanently delete:\n"
                                       "  - your identity key, chat vault, notes and settings\n"
                                       "  - the desktop shortcut and the autostart entry\n")
                              + (plannedWholeFolder
                                     ? QString("  - the folder %1 and EVERYTHING inside it\n").arg(QDir::toNativeSeparators(plannedDir))
                                     : QString("\nThe program files in %1 will NOT be deleted (this folder was not created by the installer). Remove them by hand if you want.\n").arg(QDir::toNativeSeparators(plannedDir)))
                              + "\nThis cannot be undone.", &warnDlg);
        desc->setWordWrap(true);
        desc->setAlignment(Qt::AlignCenter);
        desc->setStyleSheet("border: none; color: #FFFFFF; font-size: 14px;");
        l->addWidget(desc);

        QHBoxLayout *btnLayout = new QHBoxLayout();
        QPushButton *btnCancel = new QPushButton("CANCEL", &warnDlg);
        btnCancel->setStyleSheet("QPushButton { background-color: #222222; border: 1px solid #55FF55; color: #55FF55; padding: 10px; } QPushButton:hover { background-color: #333333; }");
        connect(btnCancel, &QPushButton::clicked, &warnDlg, &QDialog::reject);

        QPushButton *btnConfirm = new QPushButton("ERASE EVERYTHING", &warnDlg);
        btnConfirm->setStyleSheet("QPushButton { background-color: #330000; border: 1px solid #FF3333; color: #FF3333; padding: 10px; } QPushButton:hover { background-color: #660000; color: #FFFFFF; }");
        connect(btnConfirm, &QPushButton::clicked, &warnDlg, &QDialog::accept);

        btnLayout->addWidget(btnCancel);
        btnLayout->addWidget(btnConfirm);
        l->addLayout(btnLayout);

        activeDialog = &warnDlg;
        int result = warnDlg.exec();
        activeDialog = nullptr;
        if (result != QDialog::Accepted) return;

        // Stop all activity so nothing re-creates files while we delete them.
        uninstalling = true;
        autoLockTimer->stop();
        reconnectTimer->stop();
        vaultTimer->stop();
        if (tcpSocket) {
            tcpSocket->disconnect(this);
            tcpSocket->abort();
        }

#ifdef Q_OS_WIN
        enableAutoStart(false);
#endif
        QFile::remove(QStandardPaths::writableLocation(QStandardPaths::DesktopLocation) + "/Sönkkökoodi.lnk");

        const QString appDirPath = QDir::cleanPath(QCoreApplication::applicationDirPath());
        const QStringList dataFiles = { "sonkkokoodi.ini", "sonkkokoodi.vault", "sonkkokoodi.notes",
                                        "sonkkokoodi.vault.corrupt", "sonkkokoodi.notes.corrupt",
                                        "sonkkokoodi.vault.old", "sonkkokoodi.notes.old" };
        for (const QString &f : dataFiles) QFile::remove(appDirPath + "/" + f);

        const bool hasExe = QFileInfo::exists(appDirPath + "/sonkkokoodi.exe") || QFileInfo::exists(appDirPath + "/sonkkokoodi");
        if (plannedWholeFolder && hasExe) {
#ifdef Q_OS_WIN
            // The path travels in an environment variable, so quotes in it can never break out of the command.
            QProcess p;
            QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
            env.insert("SK_TARGET", QDir::toNativeSeparators(appDirPath));
            env.insert("SK_PID", QString::number(QCoreApplication::applicationPid()));
            p.setProcessEnvironment(env);
            p.setProgram("powershell.exe");
            // Wait for this process to exit (the exe and DLLs are locked until then), then retry the delete.
            p.setArguments(QStringList() << "-NoProfile" << "-WindowStyle" << "Hidden" << "-Command"
                           << "Wait-Process -Id $env:SK_PID -Timeout 30 -ErrorAction SilentlyContinue; "
                              "for ($i = 0; $i -lt 20; $i++) { "
                              "try { Remove-Item -LiteralPath $env:SK_TARGET -Recurse -Force -ErrorAction Stop; break } "
                              "catch { Start-Sleep -Seconds 1 } }");
            p.setWorkingDirectory(QDir::tempPath());
            p.startDetached();
#elif defined(Q_OS_LINUX)
            QProcess p;
            p.setProgram("sh");
            p.setArguments(QStringList() << "-c" << "sleep 2 && rm -rf -- \"$1\"" << "sh" << appDirPath);
            p.setWorkingDirectory(QDir::tempPath());
            p.startDetached();
#endif
        }

        QApplication::quit();
    }

    void openNotes() {
        if (isLocked || vaultKey.isEmpty()) {
            log("Cannot access Sönkkö Notes while system is locked.", "[ ! ]", true);
            return;
        }

        QDialog notesDlg(this);
        notesDlg.setWindowFlags(Qt::FramelessWindowHint | Qt::Dialog);
        notesDlg.resize(600, 500);
        notesDlg.setStyleSheet("background-color: #000000; border: 2px solid #55FF55; color: #55FF55; font-family: 'Arial'; font-weight: bold; font-size: 16px;");

        QVBoxLayout *l = new QVBoxLayout(&notesDlg);
        QLabel *lbl = new QLabel("SÖNKKÖ NOTES (Encrypted Locally)", &notesDlg);
        lbl->setStyleSheet("border: none;");
        l->addWidget(lbl);

        QTextEdit *te = new QTextEdit(&notesDlg);
        te->setStyleSheet("background-color: #111111; border: 1px solid #55FF55; color: #FFFFFF;");
        l->addWidget(te);

        QPushButton *btn = new QPushButton("SAVE & CLOSE", &notesDlg);
        btn->setStyleSheet("QPushButton { background-color: #222222; border: 1px solid #55FF55; padding: 10px; color: #FFFFFF; } QPushButton:hover { background-color: #333333; }");
        connect(btn, &QPushButton::clicked, &notesDlg, &QDialog::accept);
        l->addWidget(btn);

        const QString notesPath = dataPath("sonkkokoodi.notes");
        bool canSave = true;
        if (QFileInfo::exists(notesPath)) {
            QFile file(notesPath);
            bool decrypted = false;
            if (file.open(QIODevice::ReadOnly)) {
                QByteArray all = file.readAll();
                file.close();
                QByteArray plain = decryptGCM(all.mid(12), vaultKey, all.left(12), &decrypted);
                if (decrypted) te->setPlainText(QString::fromUtf8(plain));
            }
            if (!decrypted) {
                // Never silently overwrite something we could not read: keep it aside.
                QFile::remove(notesPath + ".corrupt");
                if (QFile::rename(notesPath, notesPath + ".corrupt")) {
                    te->setPlaceholderText("The previous notes could not be decrypted and were moved to sonkkokoodi.notes.corrupt");
                } else {
                    te->setPlaceholderText("The existing notes file could not be read. Saving is disabled to protect it.");
                    te->setReadOnly(true);
                    canSave = false;
                }
            }
        }

        // Saved on ANY close (button, auto-lock, Alt+L). 'finished' fires synchronously inside
        // accept()/reject(), i.e. before lockSystem() wipes the vault key.
        connect(&notesDlg, &QDialog::finished, &notesDlg, [this, te, notesPath, canSave](int) {
            if (!canSave || isLocked || vaultKey.isEmpty()) return;
            if (!writeEncryptedFile(notesPath, te->toPlainText().toUtf8(), vaultKey))
                log("Failed to save notes.", "[ ! ]", true);
        });

        activeDialog = &notesDlg;
        notesDlg.exec();
        activeDialog = nullptr;
    }

    void openTofuList() {
        if (isLocked) {
            log("Cannot access TOFU List while system is locked.", "[ ! ]", true);
            return;
        }

        QDialog tofuDlg(this);
        tofuDlg.setWindowFlags(Qt::FramelessWindowHint | Qt::Dialog);
        tofuDlg.resize(450, 500);
        tofuDlg.setStyleSheet("background-color: #000000; border: 2px solid #55FF55; color: #55FF55; font-family: 'Arial'; font-weight: bold; font-size: 16px;");

        QVBoxLayout *l = new QVBoxLayout(&tofuDlg);
        QLabel *lbl = new QLabel("TRUSTED IDENTITIES (TOFU PINS)", &tofuDlg);
        lbl->setStyleSheet("border: none;");
        l->addWidget(lbl);

        QTextEdit *te = new QTextEdit(&tofuDlg);
        te->setReadOnly(true);
        te->setStyleSheet("background-color: #111111; border: 1px solid #55FF55; color: #FFFFFF; font-size: 14px;");

        QString listText;
        for (auto it = trustedIdentities.begin(); it != trustedIdentities.end(); ++it) {
            listText += "ID: " + (it.key().size() > 16 ? it.key().left(16) + "..." : it.key()) + (it.key().size() == 8 ? " (legacy short pin)" : "") + "\nALIAS: " + it.value() + "\n--------------------------------\n";
        }
        te->setPlainText(listText);
        l->addWidget(te);

        QPushButton *btn = new QPushButton("CLOSE", &tofuDlg);
        btn->setStyleSheet("QPushButton { background-color: #222222; border: 1px solid #55FF55; padding: 10px; color: #FFFFFF;} QPushButton:hover { background-color: #333333; }");
        connect(btn, &QPushButton::clicked, &tofuDlg, &QDialog::accept);
        l->addWidget(btn);

        activeDialog = &tofuDlg;
        tofuDlg.exec();
        activeDialog = nullptr;
    }

    void showLoadingScreen(const QString &text, int timeoutMs = 0) {
        loadingLabel->setText(text);
        mainStack->setCurrentIndex(1);
        if (timeoutMs > 0) {
            QTimer::singleShot(timeoutMs, this, [this]() {
                if (!isNegotiating) mainStack->setCurrentIndex(0);
            });
        }
    }

    void loadConfiguration() {
        QSettings settings(iniPath(), QSettings::IniFormat);

        targetIp = settings.value("server_ip", "").toString();
        targetPort = settings.value("server_port", 9999).toInt();
        storedPinHash = settings.value("pin_hash").toString();      // legacy (unsalted SHA-256), migrated on first unlock
        pinCheck = settings.value("pin_check").toByteArray();
        myNickname = settings.value("nickname").toString();
        legacyPem = settings.value("ecdsa_identity").toString();    // legacy plaintext key, migrated on first unlock
        identityEnc = settings.value("ecdsa_identity_enc").toByteArray();
        vaultSalt = settings.value("vault_salt").toByteArray();
        roomEnc = settings.value("room_enc").toByteArray();
        kdfIterations = settings.value("kdf_iter", sk::kLegacyPbkdf2Iterations).toInt();   // absent = pre-existing install

        notifyConnect = settings.value("notify_connect", true).toBool();
        notifyDisconnect = settings.value("notify_disconnect", true).toBool();
        notifyMessage = settings.value("notify_message", false).toBool();
        autoStart = settings.value("autostart", false).toBool();

        autoLockMinutes = settings.value("auto_lock_minutes", 1).toInt();
        if (autoLockMinutes > 0) {
            autoLockTimer->setInterval(autoLockMinutes * 60000);
        }

        settings.beginGroup("TrustedIdentities");
        for (const QString &uid : settings.childKeys()) {
            trustedIdentities.insert(uid, settings.value(uid).toString());
        }
        settings.endGroup();

        bool hasPin = !pinCheck.isEmpty() || !storedPinHash.isEmpty();
        bool hasIdentity = !identityEnc.isEmpty() || !legacyPem.isEmpty();

        isLocked = true;
        msgContainer->hide();
        pinContainer->show();
        if (!hasPin || myNickname.isEmpty() || !hasIdentity || vaultSalt.isEmpty() || targetIp.isEmpty()) {
            setupStep = 1;
            pwdInput->setPlaceholderText("SETUP: CREATE NEW PASSWORD (min 8 chars)...");
            log("INITIALIZATION: No credentials found. Step 1: Create a secure password.", "[ * ]", true);
        } else {
            setupStep = 0;
            pwdInput->setPlaceholderText("ENTER PASSWORD...");
            log("Locked. Enter password.", "[ * ]", true);
        }
    }

    void setupSystemTray() {
        trayAvailable = QSystemTrayIcon::isSystemTrayAvailable();
        trayIcon = new QSystemTrayIcon(this);
        QPixmap trayPix(32, 32);
        trayPix.fill(Qt::transparent);
        QPainter p(&trayPix);
        p.setPen(QColor("#55FF55"));
        p.setFont(QFont("Arial", 14, QFont::Bold));
        p.drawText(trayPix.rect(), Qt::AlignCenter, "SK");
        p.end();
        trayIcon->setIcon(QIcon(trayPix));

        QMenu *trayMenu = new QMenu(this);
        QAction *showAction = new QAction("Show Terminal", this);
        connect(showAction, &QAction::triggered, this, [this](){ this->showNormal(); this->activateWindow(); });
        QAction *quitAction = new QAction("Shutdown Core", this);
        connect(quitAction, &QAction::triggered, this, [this](){ gracefulShutdown(); });

        trayMenu->addAction(showAction);
        trayMenu->addAction(quitAction);
        trayIcon->setContextMenu(trayMenu);
        if (trayAvailable) trayIcon->show();

        connect(trayIcon, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason){
            if (reason == QSystemTrayIcon::DoubleClick || reason == QSystemTrayIcon::Trigger) {
                if (this->isVisible()) this->hide();
                else { this->showNormal(); this->activateWindow(); }
            }
        });
    }

    void enableAutoStart(bool enable) {
#ifdef Q_OS_WIN
        QSettings bootSettings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
        if (enable) {
            // Quoted so paths containing spaces start correctly.
            QString appPath = "\"" + QDir::toNativeSeparators(QCoreApplication::applicationFilePath()) + "\"";
            bootSettings.setValue("Sonkkokoodi", appPath);
            log("Autostart enabled (change it any time in Settings).", "[ * ]", true);
        } else {
            bootSettings.remove("Sonkkokoodi");
        }
#else
        Q_UNUSED(enable);
#endif
    }

    void handlePwdSubmit() {
        QString input = pwdInput->text();
        if (input.isEmpty()) return;
        pwdInput->clear();

        QSettings settings(iniPath(), QSettings::IniFormat);

        if (setupStep == 1) {
            if (input.size() < 8) {
                log("Password too short (minimum 8 characters).", "[ ! ]", true);
                return;
            }

            // Fresh setup: anything left over from a previous, incomplete setup cannot be decrypted
            // with the new password. Keep it aside instead of deleting it.
            for (const QString &n : { QString("sonkkokoodi.vault"), QString("sonkkokoodi.notes") }) {
                QString p = dataPath(n);
                if (QFileInfo::exists(p)) {
                    QFile::remove(p + ".old");
                    QFile::rename(p, p + ".old");
                }
            }
            settings.remove("pin_hash");
            settings.remove("ecdsa_identity");
            settings.remove("ecdsa_identity_enc");
            storedPinHash.clear();
            legacyPem.clear();
            identityEnc.clear();
            if (myIdentityKey) { EVP_PKEY_free(myIdentityKey); myIdentityKey = nullptr; }
            myUid.clear();

            vaultSalt.resize(16);
            if (RAND_bytes((unsigned char*)vaultSalt.data(), 16) != 1) {
                log("Secure random generator failed.", "[ ! ]", true);
                return;
            }
            settings.setValue("vault_salt", vaultSalt);

            kdfIterations = sk::kPbkdf2Iterations;
            settings.setValue("kdf_iter", kdfIterations);
            vaultKey = derivePBKDF2(input, vaultSalt, kdfIterations);
            if (vaultKey.isEmpty()) {
                log("Key derivation failed - nothing was saved. Please try again.", "[ ! ]", true);
                return;
            }
            pinCheck = makeVerifier(vaultKey);
            settings.setValue("pin_check", pinCheck);
            vaultLoaded = true;

            setupStep = 2;
            pinContainer->hide();
            msgContainer->show();
            msgInput->clear();
            msgInput->setPlaceholderText("SETUP: ENTER ALIAS...");
            promptLabel->setText("alias >");
            msgInput->setFocus();
            log("Password saved. Step 2: Enter your network alias/nickname.", "[ * ]", true);
        } else if (setupStep == 0) {
            QByteArray key = derivePBKDF2(input, vaultSalt, kdfIterations);
            bool ok = false;
            if (key.isEmpty()) {
                log("Key derivation failed. Please try again.", "[ ! ]", true);
                return;
            }

            if (!pinCheck.isEmpty()) {
                ok = constTimeEqual(makeVerifier(key), pinCheck);
            } else {
                // Legacy install: verify with the old hash once, then upgrade to the PBKDF2 verifier.
                QByteArray legacy = QCryptographicHash::hash(input.toUtf8(), QCryptographicHash::Sha256).toHex();
                ok = constTimeEqual(legacy, storedPinHash.toUtf8());
                if (ok) {
                    pinCheck = makeVerifier(key);
                    settings.setValue("pin_check", pinCheck);
                    settings.remove("pin_hash");
                    storedPinHash.clear();
                }
            }

            if (!ok) {
                failedAttempts++;
                log("Invalid password.", "[ ! ]", true);
                // Simple back-off against rapid guessing.
                int delaySec = qMin(failedAttempts, 10);
                pwdInput->setEnabled(false);
                QTimer::singleShot(delaySec * 1000, this, [this]() {
                    pwdInput->setEnabled(true);
                    pwdInput->setFocus();
                });
                return;
            }

            failedAttempts = 0;
            vaultKey = key;

            if (!loadIdentityKey()) {
                vaultKey.fill(0);
                log("Could not load your identity key (settings file damaged?).", "[ ! ]", true);
                return;
            }

            if (!vaultLoaded) {
                loadVault();
                vaultLoaded = true;
            } else {
                saveVault();
            }

            unlockSystem();
        }
    }

    void lockSystem() {
        if (setupStep != 0 || isLocked) return;

        // Close any open Notes/Settings/TOFU dialog first. Notes are saved synchronously
        // while the vault key is still valid.
        if (activeDialog) activeDialog->reject();
        flushVault();

        isLocked = true;
        msgContainer->hide();
        pinContainer->show();
        pwdInput->clear();
        pwdInput->setFocus();
        contentArea->setStyleSheet("#mainContent { background-color: #000000; border: 2px solid #FF3333; border-top: none; }");
        log("Locked. Displaying raw AES-GCM sönkkökoodi.", "[ * ]", true);
        refreshChatDisplay();

        vaultKey.fill(0);
    }

    void unlockSystem() {
        isLocked = false;
        pinContainer->hide();
        msgContainer->show();
        msgInput->clear();
        msgInput->setPlaceholderText("");
        msgInput->setFocus();
        contentArea->setStyleSheet("#mainContent { background-color: #000000; border: 2px solid #55FF55; border-top: none; }");

        if (autoLockMinutes > 0) autoLockTimer->start();

        if (!roomKeys.valid()) loadRoomKeys();
        if (!roomKeys.valid()) {            // new install, or an install from before protocol v2
            refreshChatDisplay();
            beginRoomPassphraseStep();
            return;
        }

        if (tcpSocket && tcpSocket->state() == QAbstractSocket::ConnectedState) {
            promptLabel->setText("chat >");
        } else {
            promptLabel->setText(">");
            if (!userDisconnected) connectToPeer();
        }
        refreshChatDisplay();
    }

    bool loadRoomKeys() {
        roomKeys.wipe();
        if (roomEnc.size() <= 12 || vaultKey.isEmpty()) return false;
        bool ok = false;
        QByteArray plain = decryptGCM(roomEnc.mid(12), vaultKey, roomEnc.left(12), &ok);
        if (!ok || plain.size() != 64) return false;
        roomKeys.auth = plain.left(32);
        roomKeys.wrap = plain.mid(32, 32);
        plain.fill(0);
        return roomKeys.valid();
    }

    void beginRoomPassphraseStep() {
        setupStep = 4;
        msgInput->clear();
        msgInput->setEchoMode(QLineEdit::Password);
        msgInput->setPlaceholderText("ROOM PASSPHRASE (shared out-of-band with the people you chat with)...");
        promptLabel->setText("room >");
        msgInput->setFocus();
        log("Room passphrase: everyone in the room must enter the SAME passphrase. It authenticates the key exchange, so the relay or a stranger cannot obtain the room key. Use 12+ characters.", "[ * ]", true);
    }

    void handleRoomPassphrase(const QString &pass) {
        msgInput->clear();
        if (pass.size() < 8) {
            log("Passphrase too short (minimum 8 characters, 12+ recommended).", "[ ! ]", true);
            return;
        }
        static const char *hints[] = { "weak", "fair", "good", "strong" };
        log(QString("Passphrase strength: %1 (length/variety estimate only).").arg(hints[sk::passphraseStrength(pass)]), "[ * ]", true);
        sk::RoomKeys rk = sk::deriveRoomKeys(pass);
        if (!rk.valid()) { log("Key derivation failed. Please try again.", "[ ! ]", true); return; }
        QByteArray packed = rk.auth + rk.wrap;
        QByteArray iv;
        QByteArray c = encryptGCM(packed, vaultKey, iv);
        packed.fill(0);
        if (c.isEmpty()) { rk.wipe(); log("Could not store the room key.", "[ ! ]", true); return; }
        roomEnc = iv + c;
        QSettings(iniPath(), QSettings::IniFormat).setValue("room_enc", roomEnc);
        roomKeys.wipe();
        roomKeys = rk;

        msgInput->setEchoMode(QLineEdit::Normal);
        msgInput->setPlaceholderText("");
        setupStep = 0;
        log("Room passphrase saved.", "[ * ]", true);
        const bool reconnect = roomChangeRequested;
        roomChangeRequested = false;
        if (reconnect) {
            userDisconnected = false;
            dropSocket(QString());
            promptLabel->setText(">");
            connectToPeer();
        } else {
            unlockSystem();
        }
    }

    bool storeIdentity(const QByteArray &pem) {
        QByteArray iv;
        QByteArray c = encryptGCM(pem, vaultKey, iv);
        if (c.isEmpty()) return false;
        identityEnc = iv + c;
        QSettings settings(iniPath(), QSettings::IniFormat);
        settings.setValue("ecdsa_identity_enc", identityEnc);
        settings.remove("ecdsa_identity");
        legacyPem.clear();
        return true;
    }

    // Loads (and, for legacy installs, encrypts) the identity key. Requires vaultKey.
    bool loadIdentityKey() {
        if (myIdentityKey) return true;

        QByteArray pem;
        if (identityEnc.size() > 12) {
            bool ok = false;
            pem = decryptGCM(identityEnc.mid(12), vaultKey, identityEnc.left(12), &ok);
            if (!ok) pem.clear();
        } else if (!legacyPem.isEmpty()) {
            pem = legacyPem.toUtf8();
            if (storeIdentity(pem)) log("Identity key is now stored encrypted.", "[ * ]", true);
        }

        EVP_PKEY *key = pemToPrivKey(pem);
        if (!key) return false;
        myIdentityKey = key;
        myUid = fingerprintOf(pkeyToDER(myIdentityKey));
        return true;
    }

    bool generateIdentityKey() {
        log("Generating secp256r1 ECDSA Identity...", "[ * ]", true);
        EVP_PKEY *key = generateEphemeralKey();
        if (!key) return false;

        QByteArray pem = privKeyToPEM(key);
        if (pem.isEmpty()) { EVP_PKEY_free(key); return false; }

        if (myIdentityKey) EVP_PKEY_free(myIdentityKey);
        myIdentityKey = key;
        if (!storeIdentity(pem)) {
            EVP_PKEY_free(myIdentityKey);
            myIdentityKey = nullptr;
            return false;
        }

        myUid = fingerprintOf(pkeyToDER(myIdentityKey));
        log("Identity generated. ID: " + shortId(myUid), "[ * ]", true);
        return true;
    }

    void handleInput() {
        if (setupStep == 4) { if (!msgInput->text().isEmpty()) handleRoomPassphrase(msgInput->text()); return; }
        QString text = msgInput->text().trimmed();
        if (text.isEmpty()) return;
        msgInput->clear();

        if (setupStep == 2) {
            if (!isValidNick(text)) {
                log("Invalid alias. Use 1-24 letters, digits, '_', '-' or '.'.", "[ ! ]", true);
                return;
            }
            log("alias > " + text, "", true);
            if (!generateIdentityKey()) {
                log("Identity generation failed.", "[ ! ]", true);
                return;
            }
            QSettings settings(iniPath(), QSettings::IniFormat);
            settings.setValue("nickname", text);
            myNickname = text;

            setupStep = 3;
            msgInput->clear();
            msgInput->setPlaceholderText("SETUP: ENTER SERVER IP (e.g. 192.168.1.50:9999)...");
            promptLabel->setText("server >");
            msgInput->setFocus();
            log("Alias saved. Step 3: Enter target server IP and port.", "[ * ]", true);
            return;
        }

        if (setupStep == 3) {
            QString ip;
            int port = 9999;
            bool portGiven = false;
            if (!parseEndpoint(text, ip, port, portGiven)) {
                log("Invalid server address. Use host or host:port (port 1-65535).", "[ ! ]", true);
                return;
            }
            log("server > " + text, "", true);

            QSettings settings(iniPath(), QSettings::IniFormat);
            settings.setValue("server_ip", ip);
            settings.setValue("server_port", port);
            settings.setValue("autostart", autoStart);
            targetIp = ip;
            targetPort = port;

            if (autoStart) enableAutoStart(true);
            setupStep = 0;
            unlockSystem();
            return;
        }

        QString lowerText = text.toLower();
        bool connected = tcpSocket && tcpSocket->state() == QAbstractSocket::ConnectedState;

        if (lowerText == "clear") {
            history.clear(); chatDisplay->clear();
            saveVault();
            return;
        } else if (lowerText == "help") {
            printHelp();
            return;
        } else if (lowerText == "passphrase") {
            roomChangeRequested = true;
            beginRoomPassphraseStep();
            return;
        } else if (lowerText == "disconnect") {
            userDisconnected = true;
            reconnectTimer->stop();
            if (connected) {
                QJsonObject leaveObj;
                leaveObj["type"] = "LEAVE";
                leaveObj["nick"] = myNickname;
                sendSignedPacket(leaveObj);
                tcpSocket->flush();
                tcpSocket->disconnectFromHost();
            } else {
                log("Not connected.", "[ * ]", true);
            }
            return;
        } else if (lowerText == "connect") {
            userDisconnected = false;
            reconnectTimer->stop();
            reconnectDelaySec = 2;
            if (connected || (tcpSocket && tcpSocket->state() != QAbstractSocket::UnconnectedState)) log("Already connected / connecting.", "[ * ]", true);
            else connectToPeer();
            return;
        } else if (lowerText == "who") {
            if (connected && !isNegotiating) {
                QJsonObject reqObj;
                reqObj["type"] = "WHO_REQ";
                sendSignedPacket(reqObj);
                log("Locating active peers...", "[ * ]", true);
            } else {
                log("Not connected.", "[ * ]", true);
            }
            return;
        } else if (lowerText.startsWith("nick ")) {
            QString newNick = text.mid(5).trimmed();
            if (!isValidNick(newNick)) {
                log("Invalid alias. Use 1-24 letters, digits, '_', '-' or '.'.", "[ ! ]", true);
            } else {
                myNickname = newNick;
                QSettings(iniPath(), QSettings::IniFormat).setValue("nickname", myNickname);
                log("Alias changed to " + myNickname, "[ * ]", true);
            }
            return;
        } else if (lowerText.startsWith("server ")) {
            QString ip; int port = targetPort; bool portGiven = false;
            if (!parseEndpoint(text.mid(7), ip, port, portGiven)) {
                log("Invalid server address. Use host or host:port.", "[ ! ]", true);
                return;
            }
            targetIp = ip;
            QSettings s(iniPath(), QSettings::IniFormat);
            s.setValue("server_ip", targetIp);
            if (portGiven) { targetPort = port; s.setValue("server_port", targetPort); }
            log("Target saved: " + targetIp + ":" + QString::number(targetPort) + (connected ? " (applies on next connect)" : ""), "[ * ]", true);
            return;
        } else if (lowerText.startsWith("port ")) {
            bool ok = false;
            int p = text.mid(5).trimmed().toInt(&ok);
            if (!ok || p < 1 || p > 65535) {
                log("Invalid port (1-65535).", "[ ! ]", true);
                return;
            }
            targetPort = p;
            QSettings(iniPath(), QSettings::IniFormat).setValue("server_port", targetPort);
            log("Target Port saved: " + QString::number(targetPort) + (connected ? " (applies on next connect)" : ""), "[ * ]", true);
            return;
        }

        if (!connected) {
            log("Not connected. Type 'connect' (or 'help').", "[ ! ]", true);
            msgInput->setText(text);
            return;
        }

        if (isNegotiating || currentGroupKey.isEmpty()) {
            log("Still negotiating keys - try again in a moment.", "[ * ]", true);
            msgInput->setText(text);
            return;
        }

        if (outQueue.size() >= kMaxOutQueue) {
            log("Sending too fast - wait a moment.", "[ ! ]", true);
            msgInput->setText(text);
            return;
        }

        QString payloadText = "<" + myNickname + "> " + text;
        QByteArray plainBytes = payloadText.toUtf8();
        if (plainBytes.size() > kMaxMessageBytes) {
            log("Message too long (max " + QString::number(kMaxMessageBytes) + " bytes).", "[ ! ]", true);
            msgInput->setText(text);
            return;
        }

        QByteArray iv;
        QByteArray cipherBytes = encryptGCM(plainBytes, currentGroupKey, iv);
        if (cipherBytes.isEmpty()) {
            log("Encryption failed - message not sent.", "[ ! ]", true);
            msgInput->setText(text);
            return;
        }

        QJsonObject chatObj;
        chatObj["type"] = "CHAT";
        chatObj["epoch"] = keyEpoch;
        chatObj["iv"] = QString(iv.toBase64());
        chatObj["ciphertext"] = QString(cipherBytes.toBase64());

        sendSignedPacket(chatObj);

        selfGeneratedKey = false;
        saveMessage("", payloadText, cipherBytes, false, true, true);

        msgCount++;
        maybeRatchet();
    }

    void connectToPeer() {
        if (targetIp.isEmpty()) {
            log("No target IP defined. Use 'server <ip>' command first.", "[ ! ]", true);
            return;
        }

        dropSocket(QString());   // tear down any previous socket completely (no stale handlers survive)

        QTcpSocket *sock = new QTcpSocket(this);
        tcpSocket = sock;
        const int myToken = ++connectToken;

        connect(sock, &QTcpSocket::connected, this, [this, sock]() {
            if (sock != tcpSocket) return;
            mySid.resize(8);
            if (RAND_bytes((unsigned char*)mySid.data(), 8) != 1) { dropSocket("Secure random generator failed."); return; }
            sendCtr = 0;
            promptLabel->setText("chat >");
            startKeyNegotiation();
        });
        connect(sock, &QTcpSocket::readyRead, this, &SecureChatApp::receiveData);
        connect(sock, &QTcpSocket::errorOccurred, this, [this, sock](QAbstractSocket::SocketError) {
            if (sock != tcpSocket) return;
            dropSocket("Connection error: " + sock->errorString());
        });
        connect(sock, &QTcpSocket::disconnected, this, [this, sock]() {
            if (sock != tcpSocket) return;
            dropSocket("Disconnected.");
        });

        QTimer::singleShot(10000, this, [this, myToken]() {
            if (myToken == connectToken && tcpSocket && tcpSocket->state() != QAbstractSocket::ConnectedState)
                dropSocket("Connection timed out.");
        });

        tcpSocket->connectToHost(targetIp, targetPort);
    }

    // Single place that tears a connection down and resets all per-session state.
    void dropSocket(const QString &reason) {
        QTcpSocket *s = tcpSocket;
        tcpSocket = nullptr;
        if (s) {
            s->disconnect(this);
            s->abort();
            s->deleteLater();
        }

        if (reconnectTimer) reconnectTimer->stop();
        isNegotiating = false;
        ++negotiationToken;          // cancels any pending negotiation timer
        ++connectToken;
        currentGroupKey.fill(0); currentGroupKey.clear();
        prevGroupKey.fill(0);    prevGroupKey.clear();
        msgCount = 0;
        keyEpoch = 0;
        selfGeneratedKey = false;
        pendingHellos.clear();
        outQueue.clear();
        lastSendMs = 0;
        seenSigs.clear();
        seenOrder.clear();

        mainStack->setCurrentIndex(0);
        if (setupStep == 0) promptLabel->setText(">");
        if (!reason.isEmpty()) {
            log(reason, "[ * ]", true);
            if (!userDisconnected && !uninstalling && myIdentityKey && setupStep == 0) {
                log("Reconnecting in " + QString::number(reconnectDelaySec) + " s (type 'disconnect' to stop).", "[ * ]", true);
                reconnectTimer->start(reconnectDelaySec * 1000);
                reconnectDelaySec = qMin(reconnectDelaySec * 2, 60);
            }
        }
    }

    void sendNativeNotification(const QString &title, const QString &msg) {
#ifdef Q_OS_LINUX
        QProcess::startDetached("notify-send", QStringList() << "-a" << "Sönkkökoodi" << "-i" << "utilities-terminal" << title << msg);
#else
        if (trayIcon && trayAvailable) {
            trayIcon->showMessage(title, msg, QSystemTrayIcon::NoIcon, 3000);
        }
#endif
    }

private:

    QString baseDir() const { return dataDir.isEmpty() ? QCoreApplication::applicationDirPath() : dataDir; }
    QString iniPath() const { return baseDir() + "/sonkkokoodi.ini"; }
    QString dataPath(const QString &name) const { return baseDir() + "/" + name; }

    // Empty result = failure; callers must abort rather than continue with a weak key.
    QByteArray derivePBKDF2(const QString &pwd, const QByteArray &salt, int iterations) {
        return sk::pbkdf2(pwd.toUtf8(), salt, iterations);
    }

    // Atomic (temp file + rename) encrypted write: iv(12) | ciphertext | tag(16)
    bool writeEncryptedFile(const QString &path, const QByteArray &plain, const QByteArray &key) {
        QByteArray iv;
        QByteArray cipher = encryptGCM(plain, key, iv);
        if (cipher.isEmpty()) return false;
        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly)) return false;
        if (file.write(iv) != iv.size() || file.write(cipher) != cipher.size()) { file.cancelWriting(); return false; }
        return file.commit();
    }

    // Coalesces bursts of messages into one write. Always flushed before lock / quit.
    void scheduleSaveVault() {
        if (vaultTimer && !vaultTimer->isActive()) vaultTimer->start(400);
    }
    void flushVault() {
        if (vaultTimer && vaultTimer->isActive()) { vaultTimer->stop(); saveVault(); }
    }

    void saveVault() {
        if (vaultKey.isEmpty() || isLocked || uninstalling) return;

        QJsonArray arr;
        for (const ChatMsg &m : history) {
            if (m.isTransient) continue;

            QJsonObject obj;
            obj["time"] = m.time;
            obj["prefix"] = m.prefix;
            obj["plainText"] = m.plainText;
            obj["cipherText"] = QString(m.cipherText.toBase64());
            obj["isSystem"] = m.isSystem;
            obj["isSelf"] = m.isSelf;
            obj["isVerified"] = m.isVerified;
            obj["isError"] = m.isError;
            arr.append(obj);
        }

        QByteArray jsonData = QJsonDocument(arr).toJson(QJsonDocument::Compact);
        if (!writeEncryptedFile(dataPath("sonkkokoodi.vault"), jsonData, vaultKey)) {
            if (!vaultWriteWarned) {
                vaultWriteWarned = true;
                log("Failed to write the vault - history may not be saved.", "[ ! ]", true);
            }
        } else {
            vaultWriteWarned = false;
        }
    }

    void loadVault() {
        const QString path = dataPath("sonkkokoodi.vault");
        if (!QFileInfo::exists(path)) return;

        QFile file(path);
        QByteArray all;
        if (file.open(QIODevice::ReadOnly)) {
            all = file.readAll();
            file.close();
        }

        bool ok = false;
        QByteArray jsonData = decryptGCM(all.mid(12), vaultKey, all.left(12), &ok);
        if (!ok) {
            // Keep the unreadable vault instead of letting the next save overwrite it.
            QFile::remove(path + ".corrupt");
            QFile::copy(path, path + ".corrupt");
            log("Vault Decryption Failed. A copy was kept as sonkkokoodi.vault.corrupt.", "[ ! ]", true);
            return;
        }

        history.clear();
        QJsonArray arr = QJsonDocument::fromJson(jsonData).array();
        int startIdx = qMax(0, arr.size() - kMaxHistory);
        for (int i = startIdx; i < arr.size(); ++i) {
            QJsonObject obj = arr[i].toObject();
            ChatMsg m;
            m.time = obj["time"].toString();
            m.prefix = obj["prefix"].toString();
            m.plainText = obj["plainText"].toString();
            m.cipherText = QByteArray::fromBase64(obj["cipherText"].toString().toUtf8());
            m.isSystem = obj["isSystem"].toBool();
            m.isSelf = obj["isSelf"].toBool();
            m.isVerified = obj["isVerified"].toBool();
            m.isError = obj["isError"].toBool();
            m.isTransient = false;
            history.append(m);
        }
    }

    QByteArray signData(const QByteArray &data) { return sk::sign(data, myIdentityKey); }

    bool verifySignature(const QByteArray &data, const QByteArray &sig, EVP_PKEY *pubKey) { return sk::verify(data, sig, pubKey); }

    QByteArray encryptGCM(const QByteArray &plaintext, const QByteArray &key, QByteArray &iv) { return sk::encryptGCM(plaintext, key, iv); }

    QByteArray decryptGCM(const QByteArray &c, const QByteArray &key, const QByteArray &iv, bool *ok = nullptr) { return sk::decryptGCM(c, key, iv, ok); }

    EVP_PKEY* generateEphemeralKey() { return sk::generateP256Key(); }

    QByteArray deriveSharedSecret(EVP_PKEY *myPriv, EVP_PKEY *peerPub) { return sk::deriveSharedSecret(myPriv, peerPub); }

    void sendSignedPacket(const QJsonObject &payload) {
        if (!tcpSocket) return;
        // Protocol v2: every signed payload carries version, session id, counter and timestamp (replay protection).
        QJsonObject stamped = payload;
        stamped["v"] = sk::kProtocolVersion;
        stamped["sid"] = QString(mySid.toBase64());
        stamped["ctr"] = QString::number(++sendCtr);
        stamped["ts"] = QString::number(QDateTime::currentMSecsSinceEpoch());
        QByteArray data = QJsonDocument(stamped).toJson(QJsonDocument::Compact);
        QByteArray sig = signData(data);
        if (sig.isEmpty()) return;

        QJsonObject envelope;
        envelope["data"] = QString(data.toBase64());
        envelope["sig"] = QString(sig.toBase64());
        envelope["sender_pub"] = QString(pkeyToDER(myIdentityKey).toBase64());

        QByteArray networkPacket = QJsonDocument(envelope).toJson(QJsonDocument::Compact) + "\n";
        outQueue.append(networkPacket);
        pumpOutQueue();
    }

    // The relay silently drops anything above 10 packets/s. Send at a steady pace below that (one packet
    // per kSendIntervalMs, no bursts that network jitter could clump together) and queue the rest,
    // otherwise a burst of messages "sends" fine locally and is lost on the way.
    void pumpOutQueue() {
        if (outQueue.isEmpty() || !tcpSocket) return;
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        const qint64 due = lastSendMs + kSendIntervalMs;
        if (now >= due) {
            tcpSocket->write(outQueue.takeFirst());
            lastSendMs = now;
            if (outQueue.isEmpty()) return;
            QTimer::singleShot(kSendIntervalMs, this, [this]() { pumpOutQueue(); });
        } else {
            QTimer::singleShot(int(due - now) + 1, this, [this]() { pumpOutQueue(); });
        }
    }

    // --- Group key handling ---------------------------------------------------------------

    void ratchetKey() {
        prevGroupKey = currentGroupKey;
        currentGroupKey = sk::ratchetStep(currentGroupKey);
        keyEpoch++;
        msgCount = 0;
    }

    void maybeRatchet() {
        if (msgCount >= kRatchetEvery) {
            ratchetKey();
            showLoadingScreen("[*] REGENERATING SECRECY KEYS...", 1200);
        }
    }

    void startKeyNegotiation() {
        if (!roomKeys.valid()) { dropSocket("No room passphrase set. Type 'passphrase' to set one."); return; }
        isNegotiating = true;
        selfGeneratedKey = false;
        pendingHellos.clear();
        showLoadingScreen("[*] NEGOTIATING CRYPTOGRAPHIC KEYS...");

        if (myEphemeralKey) EVP_PKEY_free(myEphemeralKey);
        myEphemeralKey = generateEphemeralKey();
        if (!myEphemeralKey) {
            dropSocket("Key generation failed.");
            return;
        }

        QJsonObject helloObj;
        helloObj["type"] = "HELLO";
        helloObj["nick"] = myNickname;
        const QByteArray myEcdhDer = pkeyToDER(myEphemeralKey);
        myHelloNonce.resize(16);
        if (RAND_bytes((unsigned char*)myHelloNonce.data(), 16) != 1) { dropSocket("Secure random generator failed."); return; }
        helloObj["ecdh_pub"] = QString(myEcdhDer.toBase64());
        helloObj["nonce"] = QString(myHelloNonce.toBase64());
        helloObj["mac"] = QString(sk::helloMac(roomKeys, myEcdhDer, myHelloNonce, pkeyToDER(myIdentityKey)).toBase64());
        sendSignedPacket(helloObj);

        // Randomised timeout so that two peers joining an empty room at the same moment do not
        // both give up simultaneously: the first one to time out creates the key and then answers
        // the HELLOs it queued from the other.
        const int token = ++negotiationToken;
        const int timeoutMs = negotiationTimeoutOverrideMs >= 0 ? negotiationTimeoutOverrideMs
                                                                 : 2500 + int(QRandomGenerator::global()->bounded(2000));
        QTimer::singleShot(timeoutMs, this, [this, token]() {
            if (token != negotiationToken || !isNegotiating) return;
            isNegotiating = false;
            selfGeneratedKey = true;
            currentGroupKey.resize(32);
            if (RAND_bytes((unsigned char*)currentGroupKey.data(), 32) != 1) {
                dropSocket("Secure random generator failed.");
                return;
            }
            prevGroupKey.clear();
            keyEpoch = 0;
            msgCount = 0;
            reconnectDelaySec = 2;
                showLoadingScreen("[*] SECURE TUNNEL ESTABLISHED", 1000);

            const QList<PendingHello> queued = pendingHellos;
            pendingHellos.clear();
            for (const PendingHello &h : queued) scheduleWelcome(h.der, h.nonce);
        });
    }

    void scheduleWelcome(const QByteArray &targetEcdhDer, const QByteArray &joinerNonce) {
        QTimer::singleShot(int(QRandomGenerator::global()->bounded(300)) + 50, this, [this, targetEcdhDer, joinerNonce]() {
            sendWelcome(targetEcdhDer, joinerNonce);
        });
    }

    void sendWelcome(const QByteArray &targetEcdhDer, const QByteArray &joinerNonce) {
        if (!tcpSocket || currentGroupKey.isEmpty() || isNegotiating || !roomKeys.valid()) return;

        EVP_PKEY *peerEcdh = derToPkey(targetEcdhDer);
        if (!peerEcdh) return;
        EVP_PKEY *tempEcdh = generateEphemeralKey();
        if (!tempEcdh) { EVP_PKEY_free(peerEcdh); return; }

        const QByteArray tempDer = pkeyToDER(tempEcdh);
        QByteArray secret = deriveSharedSecret(tempEcdh, peerEcdh);
        EVP_PKEY_free(peerEcdh);
        EVP_PKEY_free(tempEcdh);
        if (secret.isEmpty()) return;
        // The wrapping key depends on the ephemeral ECDH secret AND the room secret.
        QByteArray kek = sk::welcomeKek(roomKeys, secret, targetEcdhDer, tempDer, joinerNonce);
        secret.fill(0);
        if (kek.isEmpty()) return;

        QByteArray iv;
        QByteArray encKey = encryptGCM(currentGroupKey, kek, iv);
        kek.fill(0);
        if (encKey.isEmpty()) return;

        sk::WelcomeFields f;
        f.target = QCryptographicHash::hash(targetEcdhDer, QCryptographicHash::Sha256).toHex();
        f.welcomerEcdhPub = tempDer;
        f.iv = iv;
        f.encKey = encKey;
        f.joinerNonce = joinerNonce;
        f.senderPub = pkeyToDER(myIdentityKey);
        f.epoch = keyEpoch;
        f.msgCount = msgCount;

        QJsonObject welcomeObj;
        welcomeObj["type"] = "WELCOME";
        welcomeObj["target"] = QString::fromLatin1(f.target);
        welcomeObj["ecdh_pub"] = QString(tempDer.toBase64());
        welcomeObj["iv"] = QString(iv.toBase64());
        welcomeObj["enc_key"] = QString(encKey.toBase64());
        welcomeObj["nonce"] = QString(joinerNonce.toBase64());
        welcomeObj["msg_count"] = msgCount;
        welcomeObj["epoch"] = keyEpoch;
        welcomeObj["mac"] = QString(sk::welcomeMac(roomKeys, f).toBase64());
        sendSignedPacket(welcomeObj);
    }

    // --- Incoming data --------------------------------------------------------------------

    // Identities are keyed by the FULL SHA-256 of the public key (256 bits). Only a short prefix is ever shown.
    static QString fingerprintOf(const QByteArray &der) {
        return QString::fromLatin1(QCryptographicHash::hash(der, QCryptographicHash::Sha256).toHex());
    }
    static QString shortId(const QString &fp) { return fp.left(8); }

    // Pins made by older versions were keyed by the 8-character prefix. Upgrade one in place the first
    // time its owner is seen again (the prefix match is what the old version relied on anyway).
    void migrateLegacyPin(const QString &fp) {
        const QString legacy = fp.left(8);
        if (trustedIdentities.contains(fp) || !trustedIdentities.contains(legacy)) return;
        const QString nick = trustedIdentities.take(legacy);
        trustedIdentities.insert(fp, nick);
        QSettings settings(iniPath(), QSettings::IniFormat);
        settings.remove("TrustedIdentities/" + legacy);
        settings.setValue("TrustedIdentities/" + fp, nick);
    }

    // Rate-limited notice (at most one per 30 s) so a hostile peer cannot flood the log.
    void noteIgnored(const QString &msg) {
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        if (now - lastIgnoredLogMs < 30000) return;
        lastIgnoredLogMs = now;
        log(msg, "[ ! ]", true);
    }

    QString displayNameFor(const QString &uid, const QJsonValue &claimedNick) {
        if (trustedIdentities.contains(uid)) return trustedIdentities.value(uid);
        QString c = claimedNick.toString();
        if (isValidNick(c)) return c + " (unverified)";
        return "Unknown peer";
    }

    void pinIdentity(const QString &uid, const QString &nick) {
        trustedIdentities.insert(uid, nick);
        QSettings settings(iniPath(), QSettings::IniFormat);
        settings.setValue("TrustedIdentities/" + uid, nick);
    }

    void receiveData() {
        if (!tcpSocket) return;
        QTcpSocket *sock = tcpSocket;

        while (sock == tcpSocket && sock->canReadLine()) {
            QByteArray line = sock->readLine(kMaxLineBytes);
            if (!line.endsWith('\n')) {
                dropSocket("Peer sent an oversized packet - connection closed.");
                return;
            }
            line = line.trimmed();
            QJsonDocument doc = QJsonDocument::fromJson(line);
            if (!doc.isObject()) continue;

            QJsonObject env = doc.object();
            QByteArray dataBytes = QByteArray::fromBase64(env["data"].toString().toUtf8());
            QByteArray sigBytes = QByteArray::fromBase64(env["sig"].toString().toUtf8());
            QByteArray pubBytes = QByteArray::fromBase64(env["sender_pub"].toString().toUtf8());

            EVP_PKEY *senderPub = derToPkey(pubBytes);
            if (!senderPub) continue;
            bool sigOk = verifySignature(dataBytes, sigBytes, senderPub);
            EVP_PKEY_free(senderPub);
            if (!sigOk) continue;

            // Replay protection: ECDSA signatures are randomised, so an identical signature means a replayed packet.
            if (seenSigs.contains(sigBytes)) continue;
            seenSigs.insert(sigBytes);
            seenOrder.append(sigBytes);
            if (seenOrder.size() > 2048) seenSigs.remove(seenOrder.takeFirst());

            QString senderUid = fingerprintOf(pubBytes);
            migrateLegacyPin(senderUid);
            if (senderUid == myUid) continue;

            QJsonObject payload = QJsonDocument::fromJson(dataBytes).object();
            QString type = payload["type"].toString();

            // --- Protocol v2 gate: version, session id, counter, timestamp ---
            bool okNum1 = false, okNum2 = false;
            const quint64 pktCtr = payload["ctr"].toString().toULongLong(&okNum1);
            const qint64 pktTs = payload["ts"].toString().toLongLong(&okNum2);
            const QByteArray pktSid = QByteArray::fromBase64(payload["sid"].toString().toUtf8());
            if (payload["v"].toInt(0) != sk::kProtocolVersion || !okNum1 || !okNum2) {
                noteIgnored("A client running an older, incompatible version is in the room (its packets are ignored).");
                continue;
            }
            if (replayGuard.check(senderUid, pktSid, pktCtr, pktTs, QDateTime::currentMSecsSinceEpoch()) != sk::ReplayGuard::Ok) continue;

            if (type == "HELLO") {
                QByteArray targetEcdhDer = QByteArray::fromBase64(payload["ecdh_pub"].toString().toUtf8());
                QByteArray nonce = QByteArray::fromBase64(payload["nonce"].toString().toUtf8());
                QByteArray mac = QByteArray::fromBase64(payload["mac"].toString().toUtf8());
                if (targetEcdhDer.isEmpty() || targetEcdhDer.size() > 1024) continue;
                // Only someone who knows the room passphrase can solicit the group key.
                if (!sk::verifyHelloMac(roomKeys, targetEcdhDer, nonce, pubBytes, mac)) {
                    noteIgnored("Ignored a join request that did not prove knowledge of the room passphrase (ID " + shortId(senderUid) + ").");
                    continue;
                }

                if (isNegotiating) {
                    // We have no key yet; answer once we do (see startKeyNegotiation).
                    bool dup = false;
                    for (const PendingHello &h : pendingHellos) if (h.der == targetEcdhDer) dup = true;
                    if (pendingHellos.size() < 16 && !dup) pendingHellos.append({targetEcdhDer, nonce});
                    continue;
                }
                if (currentGroupKey.isEmpty()) continue;

                QString joinNick = displayNameFor(senderUid, payload["nick"]);
                log(joinNick + " is negotiating a connection (ID " + shortId(senderUid) + ")...", "[ * ]", true);
                if (notifyConnect) {
                    sendNativeNotification("Connection", joinNick + " is joining the room.");
                }
                scheduleWelcome(targetEcdhDer, nonce);
            }
            else if (type == "WELCOME" && (isNegotiating || selfGeneratedKey) && myEphemeralKey && roomKeys.valid()) {
                // Two peers that both created a key (simultaneous join) converge on the lower fingerprint's key.
                if (!isNegotiating && !sk::adoptWelcomeWhileSelfKeyed(myUid, senderUid)) continue;
                if (QByteArray::fromBase64(payload["nonce"].toString().toUtf8()) != myHelloNonce) continue;   // not an answer to OUR hello

                QByteArray myEcdhDer = pkeyToDER(myEphemeralKey);
                QString myHash = QString(QCryptographicHash::hash(myEcdhDer, QCryptographicHash::Sha256).toHex());

                if (payload["target"].toString() != myHash) continue;

                int epoch = payload["epoch"].toInt(-1);
                int count = payload["msg_count"].toInt(-1);
                if (epoch < 0 || epoch > 1000000 || count < 0 || count >= kRatchetEvery) continue;

                QByteArray peerEcdhDer = QByteArray::fromBase64(payload["ecdh_pub"].toString().toUtf8());
                EVP_PKEY *peerEcdh = derToPkey(peerEcdhDer);
                if (!peerEcdh) continue;
                QByteArray secret = deriveSharedSecret(myEphemeralKey, peerEcdh);
                EVP_PKEY_free(peerEcdh);
                if (secret.isEmpty()) continue;

                QByteArray iv = QByteArray::fromBase64(payload["iv"].toString().toUtf8());
                QByteArray encKey = QByteArray::fromBase64(payload["enc_key"].toString().toUtf8());

                // Authenticate BEFORE decrypting: only a passphrase holder can produce this MAC.
                sk::WelcomeFields wf;
                wf.target = payload["target"].toString().toLatin1();
                wf.welcomerEcdhPub = peerEcdhDer;
                wf.iv = iv;
                wf.encKey = encKey;
                wf.joinerNonce = myHelloNonce;
                wf.senderPub = pubBytes;
                wf.epoch = epoch;
                wf.msgCount = count;
                if (!sk::verifyWelcomeMac(roomKeys, wf, QByteArray::fromBase64(payload["mac"].toString().toUtf8()))) {
                    noteIgnored("Rejected a key delivery that failed room authentication (ID " + shortId(senderUid) + ").");
                    continue;
                }
                QByteArray kek = sk::welcomeKek(roomKeys, secret, myEcdhDer, peerEcdhDer, myHelloNonce);
                secret.fill(0);
                if (kek.isEmpty()) continue;
                bool ok = false;
                QByteArray decKey = decryptGCM(encKey, kek, iv, &ok);
                kek.fill(0);
                if (!ok || decKey.size() != 32) continue;

                // The key is only as trustworthy as whoever delivered it - make that visible.
                if (!trustedIdentities.contains(senderUid)) {
                    log("Group key received from UNPINNED identity ID " + shortId(senderUid) + ". Verify it out-of-band if this matters.", "[ ! ]", true);
                }

                currentGroupKey = decKey;
                prevGroupKey.clear();
                keyEpoch = epoch;
                msgCount = count;
                isNegotiating = false;
                selfGeneratedKey = false;
                ++negotiationToken;            // cancel the fallback timer
                pendingHellos.clear();
                reconnectDelaySec = 2;
                showLoadingScreen("[*] SECURE TUNNEL ESTABLISHED", 1000);
            }
            else if (type == "LEAVE") {
                QString leaveNick = displayNameFor(senderUid, payload["nick"]);
                log(leaveNick + " has left the room.", "[ * ]", true);

                if (notifyDisconnect) {
                    sendNativeNotification("Disconnection", leaveNick + " has left the room.");
                }
            }
            else if (type == "WHO_REQ") {
                if (isNegotiating) continue;
                QJsonObject repObj;
                repObj["type"] = "WHO_REP";
                repObj["nick"] = myNickname;
                sendSignedPacket(repObj);
            }
            else if (type == "WHO_REP") {
                log("Online: " + displayNameFor(senderUid, payload["nick"]) + " (ID: " + shortId(senderUid) + ")", "[ * ]", true);
            }
            else if (type == "CHAT" && !currentGroupKey.isEmpty() && !isNegotiating) {
                handleChat(payload, senderUid);
            }
        }

        // A partial line that already exceeds the limit will never become a valid packet.
        if (sock == tcpSocket && sock->bytesAvailable() > kMaxLineBytes) {
            dropSocket("Peer sent an oversized packet - connection closed.");
        }
    }

    void handleChat(const QJsonObject &payload, const QString &senderUid) {
        QByteArray iv = QByteArray::fromBase64(payload["iv"].toString().toUtf8());
        QByteArray cipherBytes = QByteArray::fromBase64(payload["ciphertext"].toString().toUtf8());

        // Pick the key by the sender's epoch instead of assuming we are perfectly in step.
        int epoch = payload.contains("epoch") ? payload["epoch"].toInt(-1) : keyEpoch;
        QByteArray key;
        QByteArray prevForAdvance;
        int advance = 0;
        if (epoch == keyEpoch) {
            key = currentGroupKey;
        } else if (epoch == keyEpoch - 1 && !prevGroupKey.isEmpty()) {
            key = prevGroupKey;
        } else if (epoch > keyEpoch && epoch - keyEpoch <= kMaxEpochJump) {
            advance = epoch - keyEpoch;
            key = currentGroupKey;
            for (int i = 0; i < advance; ++i) {
                prevForAdvance = key;
                key = sk::ratchetStep(key);
            }
        }

        bool decOk = false;
        QByteArray plainBytes;
        if (!key.isEmpty()) plainBytes = decryptGCM(cipherBytes, key, iv, &decOk);

        if (!decOk) {
            saveMessage("[ ! ]", "<GCM AUTHENTICATION FAILED - DROPPED>", cipherBytes, false, false, false, true, true);
            return;
        }

        if (advance > 0) {          // the peer is ahead of us and proved it with a valid tag: catch up
            prevGroupKey = prevForAdvance;
            currentGroupKey = key;
            keyEpoch = epoch;
            msgCount = 0;
        }
        selfGeneratedKey = false;

        QString text = QString::fromUtf8(plainBytes);
        bool isVerified = false;
        bool isSpoofed = false;
        QString senderNick = "Unknown";

        int end = text.indexOf('>');
        if (text.startsWith('<') && end > 1) {
            senderNick = text.mid(1, end - 1);

            if (isValidNick(senderNick)) {
                const QString norm = normNick(senderNick);
                bool nickTaken = (norm == normNick(myNickname));
                if (!nickTaken) {
                    for (auto it = trustedIdentities.begin(); it != trustedIdentities.end(); ++it) {
                        if (it.key() != senderUid && normNick(it.value()) == norm) {
                            nickTaken = true;
                            break;
                        }
                    }
                }

                if (!trustedIdentities.contains(senderUid)) {
                    if (nickTaken) {
                        isSpoofed = true;
                        if (norm == normNick(myNickname)) {
                            log("SPOOFING WARNING: ID " + shortId(senderUid) + " is attempting to impersonate YOU!", "[ ! ]");
                        } else {
                            log("SPOOFING WARNING: ID " + shortId(senderUid) + " is attempting to impersonate pinned alias '" + senderNick + "'!", "[ ! ]");
                        }
                    } else {
                        pinIdentity(senderUid, senderNick);
                        log("TOFU: Pinned new identity '" + senderNick + "' (ID: " + shortId(senderUid) + ")");
                        isVerified = true;
                    }
                } else {
                    if (trustedIdentities.value(senderUid) == senderNick) {
                        isVerified = true;
                    } else if (nickTaken) {
                        isSpoofed = true;
                        log("SPOOFING WARNING: Known ID " + shortId(senderUid) + " is attempting to change alias to already taken name '" + senderNick + "'!", "[ ! ]");
                    } else {
                        QString oldNick = trustedIdentities.value(senderUid);
                        pinIdentity(senderUid, senderNick);
                        log("Identity update: '" + oldNick + "' changed alias to '" + senderNick + "' (ID: " + shortId(senderUid) + ")");
                        isVerified = true;
                    }
                }
            }
            // An invalid alias (spaces, symbols, look-alike tricks, ...) is displayed but never pinned or verified.

            if (isSpoofed) {
                text = "<" + senderNick + " (SPOOFER)>" + text.mid(end + 1);
            }
        }

        saveMessage("", text, cipherBytes, false, false, isVerified);

        if (notifyMessage && !isSpoofed && !isLocked) {
            sendNativeNotification("New Message", "Message from " + senderNick);
        }

        if (epoch >= keyEpoch) {    // messages from the previous epoch do not count towards the next ratchet
            msgCount++;
            maybeRatchet();
        }
    }

    // --- Rendering ------------------------------------------------------------------------

    QString getColorForNick(const QString &nick) {
        if (nick == myNickname) return "#55FF55";

        quint32 hash = 0;
        for (int i = 0; i < nick.length(); ++i) {
            hash = (hash << 5) + hash + nick[i].unicode();
        }

        int hue = hash % 360;
        QColor color = QColor::fromHsv(hue, 200, 255);
        return color.name();
    }

    QString getTime() { return QDateTime::currentDateTime().toString("HH:mm:ss"); }

    void log(const QString &text, const QString &prefix = "[ * ]", bool isTransient = false) {
        saveMessage(prefix, text, QByteArray(), true, false, false, isTransient);
    }

    void saveMessage(const QString& prefix, const QString& plain, const QByteArray& cipher, bool isSystem, bool isSelf,
                     bool isVerified = false, bool isTransient = false, bool isError = false) {
        history.append(ChatMsg{getTime(), prefix, plain, cipher, isSystem, isSelf, isVerified, isTransient, isError});
        while (history.size() > kMaxHistory) history.removeFirst();

        QString line = renderLine(history.last());
        if (!line.isEmpty()) {
            chatDisplay->append(line);
            chatDisplay->moveCursor(QTextCursor::End);
        }

        if (!isSystem && !isTransient && !isLocked) scheduleSaveVault();
    }

    // Returns the HTML for one message, or an empty string if it must not be shown right now.
    QString renderLine(const ChatMsg &msg) {
        QString prefixStr = msg.prefix.isEmpty() ? "" : msg.prefix.toHtmlEscaped() + " ";

        if (msg.isSystem) {
            // The lock screen must not leak who joined/left/was pinned.
            if (isLocked && setupStep == 0 &&
                !(msg.plainText.startsWith("Locked") || msg.plainText.startsWith("Invalid password"))) {
                return QString();
            }
            return "<span style='color:#888888;'>[" + msg.time + "] " + prefixStr + msg.plainText.toHtmlEscaped() + "</span>";
        }

        QString lineColor = "#FFFFFF";
        QString displayContent;

        if (isLocked) {
            lineColor = "#AA3333";
            displayContent = QString(msg.cipherText.toHex(' ').toUpper());
        }
        else if (msg.isError) {
            lineColor = "#FF3333";
            displayContent = msg.plainText.toHtmlEscaped();
        }
        else {
            QString text = msg.plainText;
            int end = text.startsWith("<") ? text.indexOf('>') : -1;
            if (end != -1) {
                QString rawNick = text.mid(1, end - 1);
                QString cleanNick = rawNick;
                cleanNick.replace(" (SPOOFER)", "");

                QString nickColor = getColorForNick(cleanNick);
                bool spoofed = rawNick.endsWith(" (SPOOFER)");
                if (spoofed) nickColor = "#FF9900";

                QString nickPart = text.left(end + 1).toHtmlEscaped();
                QString restOfMessage = text.mid(end + 1).toHtmlEscaped();

                if ((msg.isVerified || msg.isSelf) && !spoofed) {
                    int bracketIndex = nickPart.lastIndexOf("&gt;");
                    if (bracketIndex != -1) {
                        nickPart.insert(bracketIndex, " <span style='color:#55FF55;'>✓</span>");
                    }
                }

                displayContent = "<span style='color:" + nickColor + ";'>" + nickPart + "</span><span style='color:#FFFFFF;'>" + restOfMessage + "</span>";
            } else {
                displayContent = text.toHtmlEscaped();
            }
        }

        return "<span style='color:" + lineColor + ";'>[" + msg.time + "] " + prefixStr + displayContent + "</span>";
    }

    void refreshChatDisplay() {
        chatDisplay->clear();
        for (const ChatMsg& msg : history) {
            QString line = renderLine(msg);
            if (!line.isEmpty()) chatDisplay->append(line);
        }
        chatDisplay->moveCursor(QTextCursor::End);
    }

    QStackedWidget *mainStack;
    QLabel *loadingLabel;
    QTextEdit *chatDisplay;
    QLineEdit *msgInput, *pwdInput;
    QLabel *promptLabel;
    QWidget *msgContainer, *pinContainer, *contentArea;
    QSystemTrayIcon *trayIcon;
    QTimer *autoLockTimer;
    QTimer *vaultTimer = nullptr;
    QTimer *reconnectTimer = nullptr;
    int reconnectDelaySec = 2;
    QPointer<QDialog> activeDialog;

    QTcpSocket *tcpSocket;
    EVP_PKEY *myIdentityKey;
    EVP_PKEY *myEphemeralKey;
    QByteArray currentGroupKey;
    QByteArray prevGroupKey;
    int keyEpoch = 0;
    int msgCount;
    bool selfGeneratedKey = false;
    int negotiationToken = 0;
    int connectToken = 0;
    struct PendingHello { QByteArray der; QByteArray nonce; };
    QList<PendingHello> pendingHellos;
    QList<QByteArray> outQueue;
    qint64 lastSendMs = 0;
    sk::RoomKeys roomKeys;
    QByteArray roomEnc;
    QByteArray myHelloNonce;
    QByteArray mySid;
    quint64 sendCtr = 0;
    sk::ReplayGuard replayGuard;
    qint64 lastIgnoredLogMs = 0;
    bool roomChangeRequested = false;
    QSet<QByteArray> seenSigs;
    QList<QByteArray> seenOrder;

    QByteArray vaultSalt;
    int kdfIterations = sk::kLegacyPbkdf2Iterations;
    QByteArray vaultKey;
    bool vaultLoaded = false;
    bool vaultWriteWarned = false;

    bool notifyConnect = true;
    bool notifyDisconnect = true;
    bool notifyMessage = false;
    bool autoStart = false;
    int autoLockMinutes;
    bool trayAvailable = false;
    bool userDisconnected = false;
    bool uninstalling = false;
    int failedAttempts = 0;

    QString dataDir;
    int negotiationTimeoutOverrideMs = -1;   // tests only: removes the random jitter to force collisions
    QString targetIp;
    int targetPort = 9999;
    QList<ChatMsg> history;

    int setupStep = 1;
    bool isLocked = true, isNegotiating = false;
    QString storedPinHash, myNickname, myUid, legacyPem;
    QByteArray pinCheck, identityEnc;

    QMap<QString, QString> trustedIdentities;
};

#include "main.moc"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // The main window is a Qt::Tool window and lives in the tray. Without this, Qt quits the whole
    // app as soon as a dialog (Settings, Notes, ...) closes. We quit explicitly instead.
    app.setQuitOnLastWindowClosed(false);

    // --- LINUX FIX: Tell GNOME which .desktop file belongs to us ---
    QGuiApplication::setDesktopFileName("sonkkokoodi.desktop");

    SecureChatApp window;

    // --- STARTUP LOGIC: Hide in the tray if setup is complete (and a tray exists), otherwise show UI ---
    if (!window.shouldStartHidden()) {
        window.show();
    }

    return app.exec();
}
