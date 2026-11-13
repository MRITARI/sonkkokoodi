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
#include <QMenuBar>
#include <QStatusBar>
#include <QMessageBox>
#include <QFrame>

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
#include "sk_validate.h"
#include "theme.h"
#include "sk_dialogs.h"

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

// --- UI Components ---
class ChatE2ETest;   // tests/test_chat.cpp drives the real class headlessly
class ScreenshotTool; // tools/screenshots_app.cpp renders every screen

class SecureChatApp : public QMainWindow {
    Q_OBJECT
    friend class ChatE2ETest;
    friend class ScreenshotTool;
public:
    // dataDirIn: where config/vault live. Empty = next to the executable (portable layout).
    explicit SecureChatApp(const QString &dataDirIn = QString()) : dataDir(dataDirIn) {
        setWindowTitle("Sönkkökoodi");
        resize(920, 660);
        setMinimumSize(520, 400);

        myIdentityKey = nullptr;
        myEphemeralKey = nullptr;
        msgCount = 0;
        autoLockMinutes = 5;
        tcpSocket = nullptr;

        QWidget *central = new QWidget(this);
        setCentralWidget(central);
        QVBoxLayout *root = new QVBoxLayout(central);
        root->setContentsMargins(0, 0, 0, 0);
        root->setSpacing(0);

        // Warning banner: used for impersonation and unpinned key delivery. Stays until dismissed.
        banner = new QFrame(this);
        banner->setObjectName("banner");
        banner->setProperty("level", "warning");
        banner->hide();
        QHBoxLayout *bl = new QHBoxLayout(banner);
        bl->setContentsMargins(sk::theme::kS4, sk::theme::kS2, sk::theme::kS4, sk::theme::kS2);
        bannerLabel = new QLabel(banner);
        bannerLabel->setWordWrap(true);
        bannerLabel->setTextFormat(Qt::PlainText);
        QPushButton *bannerClose = new QPushButton("Dismiss", banner);
        bannerClose->setProperty("flat", true);
        bl->addWidget(bannerLabel, 1);
        bl->addWidget(bannerClose);
        connect(bannerClose, &QPushButton::clicked, banner, &QWidget::hide);
        root->addWidget(banner);

        mainStack = new QStackedWidget(this);

        // Page 0: chat
        QWidget *chatPage = new QWidget(this);
        QVBoxLayout *cl = new QVBoxLayout(chatPage);
        cl->setContentsMargins(0, 0, 0, sk::theme::kS3);
        cl->setSpacing(sk::theme::kS2);
        chatDisplay = new QTextEdit(this);
        chatDisplay->setObjectName("chatView");
        chatDisplay->setReadOnly(true);
        chatDisplay->setAccessibleName("Messages");
        cl->addWidget(chatDisplay, 1);

        msgContainer = new QWidget(this);
        QHBoxLayout *ml = new QHBoxLayout(msgContainer);
        ml->setContentsMargins(sk::theme::kS4, 0, sk::theme::kS4, 0);
        ml->setSpacing(sk::theme::kS2);
        msgInput = new QLineEdit(this);
        msgInput->setPlaceholderText("Message   (Enter sends, Esc clears or locks)");
        msgInput->setAccessibleName("Message");
        QPushButton *sendBtn = new QPushButton("Send", this);
        sendBtn->setProperty("primary", true);
        connect(msgInput, &QLineEdit::returnPressed, this, &SecureChatApp::handleInput);
        connect(sendBtn, &QPushButton::clicked, this, &SecureChatApp::handleInput);
        ml->addWidget(msgInput, 1);
        ml->addWidget(sendBtn);
        cl->addWidget(msgContainer);
        mainStack->addWidget(chatPage);

        // Page 1: locked
        QWidget *lockPage = new QWidget(this);
        QVBoxLayout *ll = new QVBoxLayout(lockPage);
        ll->addStretch(1);
        QFrame *card = new QFrame(lockPage);
        card->setObjectName("card");
        QVBoxLayout *kl = new QVBoxLayout(card);
        kl->setSizeConstraint(QLayout::SetFixedSize);
        kl->setContentsMargins(sk::theme::kS5, sk::theme::kS5, sk::theme::kS5, sk::theme::kS5);
        kl->setSpacing(sk::theme::kS3);
        QLabel *lockTitle = new QLabel("Locked", card);
        lockTitle->setProperty("role", "title");
        QLabel *lockHint = new sk::ui::WrapLabel("Enter your password to unlock. Chat stays connected in the background.", 332, card);
        lockHint->setProperty("role", "muted");
        pwdInput = new QLineEdit(card);
        pwdInput->setEchoMode(QLineEdit::Password);
        pwdInput->setPlaceholderText("Password");
        pwdInput->setAccessibleName("Password");
        connect(pwdInput, &QLineEdit::returnPressed, this, &SecureChatApp::handlePwdSubmit);
        lockError = new sk::ui::WrapLabel(QString(), 332, card);
        lockError->setProperty("role", "error");
        kl->addWidget(lockTitle);
        kl->addWidget(lockHint);
        kl->addWidget(pwdInput);
        kl->addWidget(lockError);
        ll->addWidget(card, 0, Qt::AlignHCenter);
        ll->addStretch(2);
        mainStack->addWidget(lockPage);
        pinContainer = lockPage;

        root->addWidget(mainStack, 1);

        // Menu
        QMenu *menu = menuBar()->addMenu("&Menu");
        auto addAct = [this, menu](const QString &text, const QKeySequence &key, auto slot) {
            QAction *a = menu->addAction(text);
            if (!key.isEmpty()) a->setShortcut(key);
            connect(a, &QAction::triggered, this, slot);
            return a;
        };
        addAct("Notes", QKeySequence(), [this]() { openNotes(); });
        addAct("Trusted identities", QKeySequence(), [this]() { openTofuList(); });
        addAct("Room passphrase...", QKeySequence(), [this]() { askRoomPassphrase(); });
        addAct("Settings", QKeySequence("Ctrl+,"), [this]() { openSettings(); });
        menu->addSeparator();
        addAct("Lock", QKeySequence("Ctrl+L"), [this]() { lockSystem(); });
        addAct("Delete chat history...", QKeySequence(), [this]() { confirmClearHistory(); });
        menu->addSeparator();
        addAct("Help", QKeySequence(Qt::Key_F1), [this]() { openHelp(); });
        addAct("Quit", QKeySequence("Ctrl+Q"), [this]() { gracefulShutdown(); });

        // Status chip: always visible, text + glyph (never color alone)
        statusLabel = new QLabel(this);
        statusLabel->setObjectName("statusChip");
        statusLabel->setAccessibleName("Connection status");
        statusBar()->addPermanentWidget(statusLabel);
        statusBar()->setSizeGripEnabled(true);

        QShortcut *lockShortcut = new QShortcut(QKeySequence("Alt+L"), this);
        connect(lockShortcut, &QShortcut::activated, this, &SecureChatApp::lockSystem);
        QShortcut *escShortcut = new QShortcut(QKeySequence(Qt::Key_Escape), this);
        connect(escShortcut, &QShortcut::activated, this, [this]() {
            if (isLocked || setupStep != 0) return;
            if (!msgInput->text().isEmpty()) msgInput->clear();
            else lockSystem();
        });

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

        statusTimer = new QTimer(this);
        connect(statusTimer, &QTimer::timeout, this, [this]() { updateStatus(); });
        statusTimer->start(500);

        setupSystemTray();
        loadConfiguration();
        applyTheme();
        updateStatus();

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
    void startFirstRun() { runSetupIfNeeded(); }

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
        // With a tray the X button hides the window and keeps the connection; without one it quits
        // (otherwise there would be no way to bring the window back).
        if (!quitting && trayAvailable && !uninstalling) {
            event->ignore();
            hide();
            if (!trayHintShown) {
                trayHintShown = true;
                trayIcon->showMessage("Still running", "Sönkkökoodi stays connected in the system tray. Use Menu > Quit to exit.",
                                      QSystemTrayIcon::Information, 4000);
            }
            return;
        }
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

    // Typing anywhere starts typing in the active input.
    void keyPressEvent(QKeyEvent *event) override {
        const bool printable = !event->text().isEmpty() && event->text().at(0).isPrint();
        QLineEdit *target = isLocked ? pwdInput : msgInput;
        if (printable && setupStep == 0 && !target->hasFocus()) {
            target->setFocus();
            QApplication::sendEvent(target, event);
            return;
        }
        QMainWindow::keyPressEvent(event);
    }

private slots:
    void gracefulShutdown() {
        quitting = true;
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

    void openHelp() {
        sk::ui::HelpDialog dlg(this);
        activeDialog = &dlg;
        dlg.exec();
        activeDialog = nullptr;
    }
    void printHelp() { openHelp(); }

    void applyTheme() {
        qApp->setStyleSheet(sk::theme::styleSheet(fontScale));
    }

    void openSettings() {
        if (isLocked) return;
        sk::ui::SettingsValues cur;
        cur.notifyConnect = notifyConnect; cur.notifyDisconnect = notifyDisconnect; cur.notifyMessage = notifyMessage;
        cur.autoStart = autoStart; cur.autoLockMinutes = autoLockMinutes; cur.fontScale = fontScale;
#ifdef Q_OS_WIN
        const bool showAutoStart = true;
#else
        const bool showAutoStart = false;
#endif
        sk::ui::SettingsDialog dlg(cur, showAutoStart, this);
        activeDialog = &dlg;
        const int result = dlg.exec();
        activeDialog = nullptr;

        if (dlg.uninstallRequested) {
            performUninstall();
            return;
        }
        if (result != QDialog::Accepted) return;

        const sk::ui::SettingsValues v = dlg.values();
        notifyConnect = v.notifyConnect;
        notifyDisconnect = v.notifyDisconnect;
        notifyMessage = v.notifyMessage;
        autoLockMinutes = v.autoLockMinutes;
        fontScale = v.fontScale;

        QSettings settings(iniPath(), QSettings::IniFormat);
        settings.setValue("notify_connect", notifyConnect);
        settings.setValue("notify_disconnect", notifyDisconnect);
        settings.setValue("notify_message", notifyMessage);
        settings.setValue("auto_lock_minutes", autoLockMinutes);
        settings.setValue("font_scale", fontScale);

#ifdef Q_OS_WIN
        if (v.autoStart != autoStart) {
            autoStart = v.autoStart;
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
        applyTheme();
        log("Settings saved.", "", true);
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

        sk::ui::UninstallDialog warnDlg(QDir::toNativeSeparators(plannedDir), plannedWholeFolder, this);
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

    void confirmClearHistory() {
        if (isLocked) return;
        const auto answer = QMessageBox::question(this, "Delete chat history?",
            "This permanently deletes the saved chat history on this device. It cannot be undone.",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (answer != QMessageBox::Yes) return;
        history.clear();
        chatDisplay->clear();
        saveVault();
    }

    void openNotes() {
        if (isLocked || vaultKey.isEmpty()) return;

        QDialog notesDlg(this);
        notesDlg.setWindowTitle("Notes");
        notesDlg.resize(620, 480);
        QVBoxLayout *l = new QVBoxLayout(&notesDlg);
        l->setContentsMargins(sk::theme::kS5, sk::theme::kS5, sk::theme::kS5, sk::theme::kS5);
        l->setSpacing(sk::theme::kS3);
        l->addWidget(sk::ui::makeLabel("Notes", "title"));
        l->addWidget(sk::ui::makeLabel("Encrypted on this device with your password. Saved when you close this window.", "muted"));

        QTextEdit *te = new QTextEdit(&notesDlg);
        te->setAccessibleName("Notes");
        l->addWidget(te, 1);
        QPushButton *btn = sk::ui::makeButton("Save and close", &notesDlg, true);
        QHBoxLayout *row = new QHBoxLayout();
        row->addStretch(1);
        row->addWidget(btn);
        l->addLayout(row);
        connect(btn, &QPushButton::clicked, &notesDlg, &QDialog::accept);

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
        if (isLocked) return;
        sk::ui::TrustedDialog dlg(trustedIdentities, myUid, myNickname, this);
        activeDialog = &dlg;
        dlg.exec();
        activeDialog = nullptr;
    }

    // Kept for call sites; the connection state now lives in the always-visible status chip.
    void showLoadingScreen(const QString &, int = 0) { updateStatus(); }

    QString statusText() const { return statusLabel ? statusLabel->text() : QString(); }

    void updateStatus() {
        if (!statusLabel) return;
        QString text, state, tip;
        if (setupStep != 0) {
            text = QString::fromUtf8("◌ Setting up"); state = "off"; tip = "First-run setup is not finished.";
        } else if (isLocked) {
            const bool up = tcpSocket && tcpSocket->state() == QAbstractSocket::ConnectedState;
            text = QString::fromUtf8("■ Locked"); state = "off";
            tip = up ? "Locked. Still connected in the background; messages are held until you unlock."
                     : "Locked and not connected.";
        } else if (!roomKeys.valid()) {
            text = QString::fromUtf8("✖ No room passphrase"); state = "off";
            tip = "Set one under Menu > Room passphrase to connect.";
        } else if (!tcpSocket) {
            if (reconnectTimer && reconnectTimer->isActive()) {
                text = QString::fromUtf8("◐ Reconnecting..."); state = "working"; tip = "The connection was lost. Retrying automatically.";
            } else {
                text = QString::fromUtf8("✖ Disconnected"); state = "off"; tip = "Type 'connect' to join the relay.";
            }
        } else if (tcpSocket->state() != QAbstractSocket::ConnectedState) {
            text = QString::fromUtf8("◐ Connecting..."); state = "working"; tip = "Reaching the relay server.";
        } else if (isNegotiating || currentGroupKey.isEmpty()) {
            text = QString::fromUtf8("◐ Negotiating keys..."); state = "working"; tip = "Waiting for the room key from another member.";
        } else {
            text = QString::fromUtf8("✔ Secure"); state = "secure"; tip = "Connected, end-to-end encrypted with the room key.";
        }
        if (statusLabel->text() == text && statusLabel->property("state").toString() == state) return;
        statusLabel->setText(text);
        statusLabel->setToolTip(tip);
        statusLabel->setProperty("state", state);
        sk::ui::repolish(statusLabel);
    }

    void showBanner(const char *level, const QString &text) {
        banner->setProperty("level", level);
        bannerLabel->setText(text);
        sk::ui::repolish(banner);
        banner->show();
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

        autoLockMinutes = settings.value("auto_lock_minutes", 5).toInt();
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

        fontScale = settings.value("font_scale", 100).toInt();
        if (fontScale < 100 || fontScale > 200) fontScale = 100;

        isLocked = true;
        mainStack->setCurrentIndex(1);
        setupStep = (!hasPin || myNickname.isEmpty() || !hasIdentity || vaultSalt.isEmpty() || targetIp.isEmpty()) ? 1 : 0;
    }

    void setupSystemTray() {
        trayAvailable = QSystemTrayIcon::isSystemTrayAvailable();
        trayIcon = new QSystemTrayIcon(this);
        QPixmap trayPix(32, 32);
        trayPix.fill(Qt::transparent);
        QPainter p(&trayPix);
        p.setRenderHint(QPainter::Antialiasing);
        p.setBrush(QColor(sk::theme::kAccent));
        p.setPen(Qt::NoPen);
        p.drawEllipse(trayPix.rect().adjusted(1, 1, -1, -1));
        p.setPen(QColor(sk::theme::kOnAccent));
        p.setFont(QFont(sk::theme::kFontFamily, 15, QFont::Bold));
        p.drawText(trayPix.rect(), Qt::AlignCenter, "S");
        p.end();
        trayIcon->setIcon(QIcon(trayPix));

        QMenu *trayMenu = new QMenu(this);
        QAction *showAction = new QAction("Show Sönkkökoodi", this);
        connect(showAction, &QAction::triggered, this, [this](){ this->showNormal(); this->activateWindow(); });
        QAction *quitAction = new QAction("Quit", this);
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

    // Unlock with the password. (First-run setup lives in applySetup / SetupDialog.)
    void handlePwdSubmit() {
        QString input = pwdInput->text();
        if (input.isEmpty()) return;
        pwdInput->clear();
        lockError->clear();
        if (setupStep != 0) return;

        QSettings settings(iniPath(), QSettings::IniFormat);
        QByteArray key = derivePBKDF2(input, vaultSalt, kdfIterations);
        if (key.isEmpty()) {
            lockError->setText("Key derivation failed. Please try again.");
            return;
        }
        bool ok = false;

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
            const int delaySec = qMin(failedAttempts, 10);
            lockError->setText(QString("Wrong password. You can try again in %1 s.").arg(delaySec));
            pwdInput->setEnabled(false);
            QTimer::singleShot(delaySec * 1000, this, [this]() {
                pwdInput->setEnabled(true);
                lockError->setText("Wrong password.");
                if (isLocked) pwdInput->setFocus();
            });
            return;
        }

        failedAttempts = 0;
        vaultKey = key;

        if (!loadIdentityKey()) {
            vaultKey.fill(0);
            lockError->setText("Could not load your identity key (settings file damaged?).");
            return;
        }

        // Messages that arrived while locked live only in memory; merge them into the reloaded vault.
        QList<ChatMsg> pending;
        for (const ChatMsg &m : history) if (!m.isTransient) pending.append(m);
        if (!vaultLoaded) {
            loadVault();
            vaultLoaded = true;
        }
        for (const ChatMsg &m : pending) history.append(m);
        while (history.size() > kMaxHistory) history.removeFirst();
        if (!pending.isEmpty()) saveVault();

        unlockSystem();
    }

    void lockSystem() {
        if (setupStep != 0 || isLocked) return;

        // Close any open dialog first. Notes are saved synchronously while the vault key is still valid.
        if (activeDialog) activeDialog->reject();
        flushVault();

        isLocked = true;
        mainStack->setCurrentIndex(1);
        banner->hide();
        pwdInput->clear();
        lockError->clear();
        pwdInput->setEnabled(true);
        pwdInput->setFocus();

        // Decrypted history leaves memory and the widget; it is reloaded from the vault on unlock.
        chatDisplay->clear();
        history.clear();
        vaultLoaded = false;

        vaultKey.fill(0);
        updateStatus();
    }

    void unlockSystem() {
        isLocked = false;
        mainStack->setCurrentIndex(0);
        msgInput->clear();
        msgInput->setFocus();
        if (autoLockMinutes > 0) autoLockTimer->start();

        if (!roomKeys.valid()) loadRoomKeys();
        refreshChatDisplay();
        if (!roomKeys.valid()) {            // new install, or an install from before protocol v2
            updateStatus();
            QTimer::singleShot(0, this, &SecureChatApp::askRoomPassphrase);
            return;
        }

        if (!(tcpSocket && tcpSocket->state() == QAbstractSocket::ConnectedState) && !userDisconnected) connectToPeer();
        updateStatus();
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

    // Derives and stores (encrypted under the vault key) the room keys. No UI.
    bool storeRoomPassphrase(const QString &pass, QString *err = nullptr) {
        auto fail = [&](const QString &m) { if (err) *err = m; return false; };
        if (pass.size() < 8) return fail("The room passphrase must be at least 8 characters (12+ recommended).");
        if (vaultKey.isEmpty()) return fail("The vault is locked.");
        sk::RoomKeys rk = sk::deriveRoomKeys(pass);
        if (!rk.valid()) return fail("Key derivation failed.");
        QByteArray packed = rk.auth + rk.wrap;
        QByteArray iv;
        QByteArray c = encryptGCM(packed, vaultKey, iv);
        packed.fill(0);
        if (c.isEmpty()) { rk.wipe(); return fail("Could not store the room key."); }
        roomEnc = iv + c;
        QSettings(iniPath(), QSettings::IniFormat).setValue("room_enc", roomEnc);
        roomKeys.wipe();
        roomKeys = rk;
        return true;
    }

    // Asks for the room passphrase (upgrade from an older version, or a deliberate change) and reconnects.
    void askRoomPassphrase() {
        if (isLocked || setupStep != 0) return;
        sk::ui::RoomPassphraseDialog dlg(this);
        activeDialog = &dlg;
        const int r = dlg.exec();
        activeDialog = nullptr;
        if (r == QDialog::Accepted) {
            QString err;
            if (!storeRoomPassphrase(dlg.passphrase(), &err)) { log(err, "[ ! ]", true); return; }
            log("Room passphrase saved.", "", true);
            userDisconnected = false;
            connectToPeer();
        } else if (!roomKeys.valid()) {
            log("No room passphrase is set, so you are not connected. Use Menu > Room passphrase.", "[ ! ]", true);
        }
        updateStatus();
    }

    // --- First-run setup ------------------------------------------------------------------------
    bool createVaultKey(const QString &password, QString *err) {
        auto fail = [&](const QString &m) { if (err) *err = m; return false; };
        if (password.size() < 8) return fail("The password must be at least 8 characters.");
        QSettings settings(iniPath(), QSettings::IniFormat);

        // Anything left over from a previous, incomplete setup cannot be decrypted with the new
        // password. Keep it aside instead of deleting it.
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
        settings.remove("room_enc");
        storedPinHash.clear();
        legacyPem.clear();
        identityEnc.clear();
        roomEnc.clear();
        roomKeys.wipe();
        if (myIdentityKey) { EVP_PKEY_free(myIdentityKey); myIdentityKey = nullptr; }
        myUid.clear();

        vaultSalt.resize(16);
        if (RAND_bytes((unsigned char*)vaultSalt.data(), 16) != 1) return fail("The secure random generator failed.");
        QByteArray key = derivePBKDF2(password, vaultSalt, sk::kPbkdf2Iterations);
        if (key.isEmpty()) return fail("Key derivation failed.");
        kdfIterations = sk::kPbkdf2Iterations;
        vaultKey = key;
        pinCheck = makeVerifier(vaultKey);
        settings.setValue("vault_salt", vaultSalt);
        settings.setValue("kdf_iter", kdfIterations);
        settings.setValue("pin_check", pinCheck);
        vaultLoaded = true;
        return true;
    }

    // Everything the first-run dialog collects, applied in one go. On success the app is unlocked and connecting.
    bool applySetup(const QString &password, const QString &alias, const QString &server, const QString &room,
                    QString *err = nullptr, int negotiationMs = -1) {
        auto fail = [&](const QString &m) { if (err) *err = m; return false; };
        if (!isValidNick(alias)) return fail("The alias must be 1-24 letters, digits, '_', '-' or '.'.");
        QString host; int port = 9999; bool portGiven = false;
        if (!parseEndpoint(server, host, port, portGiven)) return fail("The server must be a host or host:port (port 1-65535).");
        if (room.size() < 8) return fail("The room passphrase must be at least 8 characters.");

        if (!createVaultKey(password, err)) return false;
        if (!generateIdentityKey()) return fail("Creating your identity key failed.");
        if (!storeRoomPassphrase(room, err)) return false;

        QSettings settings(iniPath(), QSettings::IniFormat);
        settings.setValue("nickname", alias);
        settings.setValue("server_ip", host);
        settings.setValue("server_port", port);
        settings.setValue("autostart", false);
        myNickname = alias;
        targetIp = host;
        targetPort = port;

        negotiationTimeoutOverrideMs = negotiationMs;
        setupStep = 0;
        unlockSystem();
        return true;
    }

    void runSetupIfNeeded() {
        if (setupStep == 0) return;
        sk::ui::SetupDialog dlg(this);
        activeDialog = &dlg;
        const int r = dlg.exec();
        activeDialog = nullptr;
        if (r != QDialog::Accepted) { gracefulShutdown(); return; }
        const sk::ui::SetupValues v = dlg.values();
        QString err;
        if (!applySetup(v.password, v.alias, v.server, v.room, &err)) {
            QMessageBox::warning(this, "Setup failed", err);
            QTimer::singleShot(0, this, &SecureChatApp::runSetupIfNeeded);
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
        return true;
    }

    void handleInput() {
        QString text = msgInput->text().trimmed();
        if (text.isEmpty() || isLocked || setupStep != 0) return;
        msgInput->clear();

        QString lowerText = text.toLower();
        bool connected = tcpSocket && tcpSocket->state() == QAbstractSocket::ConnectedState;

        if (lowerText == "clear") {
            confirmClearHistory();
            return;
        } else if (lowerText == "help") {
            printHelp();
            return;
        } else if (lowerText == "passphrase") {
            QTimer::singleShot(0, this, &SecureChatApp::askRoomPassphrase);
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
            updateStatus();
            mySid.resize(8);
            if (RAND_bytes((unsigned char*)mySid.data(), 8) != 1) { dropSocket("Secure random generator failed."); return; }
            sendCtr = 0;
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

        if (!reason.isEmpty()) {
            log(reason, "[ * ]", true);
            if (!userDisconnected && !uninstalling && myIdentityKey && setupStep == 0) {
                log("Reconnecting in " + QString::number(reconnectDelaySec) + " s (type 'disconnect' to stop).", "[ * ]", true);
                reconnectTimer->start(reconnectDelaySec * 1000);
                reconnectDelaySec = qMin(reconnectDelaySec * 2, 60);
            }
        }
        updateStatus();
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

    // Announces us to the room with a fresh ephemeral key and nonce. Used for the initial join and for the
    // re-announcements a self-keyed node makes (see scheduleProbes). Only the LATEST hello can be answered.
    bool sendHello() {
        if (myEphemeralKey) EVP_PKEY_free(myEphemeralKey);
        myEphemeralKey = generateEphemeralKey();
        if (!myEphemeralKey) { dropSocket("Key generation failed."); return false; }

        QJsonObject helloObj;
        helloObj["type"] = "HELLO";
        helloObj["nick"] = myNickname;
        const QByteArray myEcdhDer = pkeyToDER(myEphemeralKey);
        myHelloNonce.resize(16);
        if (RAND_bytes((unsigned char*)myHelloNonce.data(), 16) != 1) { dropSocket("Secure random generator failed."); return false; }
        helloObj["ecdh_pub"] = QString(myEcdhDer.toBase64());
        helloObj["nonce"] = QString(myHelloNonce.toBase64());
        helloObj["mac"] = QString(sk::helloMac(roomKeys, myEcdhDer, myHelloNonce, pkeyToDER(myIdentityKey)).toBase64());
        sendSignedPacket(helloObj);
        return true;
    }

    // A node that had to create the room key itself cannot know whether another keyed node exists that never
    // saw its HELLO (e.g. it connected a moment later). It re-announces a few times; any keyed member answers,
    // and the node with the HIGHER fingerprint adopts the other's key (adoptWelcomeWhileSelfKeyed).
    void scheduleProbes() {
        static const int delaysMs[] = { 1000, 4000, 9000, 16000, 30000 };
        const int session = connectToken;
        for (int d : delaysMs) {
            QTimer::singleShot(d, this, [this, session]() {
                if (session != connectToken || !tcpSocket || !selfGeneratedKey || isNegotiating) return;
                sendHello();
            });
        }
    }

    void startKeyNegotiation() {
        if (!roomKeys.valid()) { dropSocket("No room passphrase set. Type 'passphrase' to set one."); return; }
        isNegotiating = true;
        selfGeneratedKey = false;
        pendingHellos.clear();
        showLoadingScreen("[*] NEGOTIATING CRYPTOGRAPHIC KEYS...");

        if (!sendHello()) return;

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
            scheduleProbes();
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
                log(joinNick + " is joining (ID " + shortId(senderUid) + ")...", "[ * ]", true);
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
                    showBanner("warning", "You received the room key from an identity you have not verified (ID " + shortId(senderUid) + "). If this matters, compare fingerprints under Menu > Trusted identities.");
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
                        showBanner("error", "Possible impersonation: someone using the name '" + senderNick + "' is NOT the identity you know under that name. Do not trust their messages.");
                        if (norm == normNick(myNickname)) {
                            log("SPOOFING WARNING: ID " + shortId(senderUid) + " is attempting to impersonate YOU!", "[ ! ]");
                        } else {
                            log("SPOOFING WARNING: ID " + shortId(senderUid) + " is attempting to impersonate pinned alias '" + senderNick + "'!", "[ ! ]");
                        }
                    } else {
                        pinIdentity(senderUid, senderNick);
                        log("Remembered '" + senderNick + "' (ID " + shortId(senderUid) + ") the first time they were seen");
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

    // Returns the HTML for one message, or an empty string if nothing should be shown right now.
    // State is always spelled out in text/glyphs (verified / unverified / impersonation), never by color alone.
    QString renderLine(const ChatMsg &msg) {
        if (isLocked) return QString();          // nothing decrypted is ever drawn while locked
        namespace T = sk::theme;
        const QString time = "<span style='color:" + QString(T::kTextMuted) + ";'>" + msg.time.toHtmlEscaped() + "</span>&nbsp;&nbsp;";

        if (msg.isSystem) {
            const bool warn = msg.prefix.contains('!');
            const QString color = warn ? T::kWarning : T::kTextMuted;
            return time + "<span style='color:" + color + ";'>" + (warn ? QString::fromUtf8("⚠ ") : QString())
                   + msg.plainText.toHtmlEscaped() + "</span>";
        }
        if (msg.isError) {
            return time + "<span style='color:" + QString(T::kError) + ";'>" + QString::fromUtf8("⚠ ")
                   + "A message could not be authenticated and was dropped.</span>";
        }

        const QString text = msg.plainText;
        const int end = text.startsWith("<") ? text.indexOf('>') : -1;
        if (end <= 1) return time + text.toHtmlEscaped();

        QString nick = text.mid(1, end - 1);
        const bool spoofed = nick.endsWith(" (SPOOFER)");
        if (spoofed) nick.chop(10);
        const QString body = text.mid(end + 1).trimmed().toHtmlEscaped();

        QString nickHtml = "<b style='color:" + QString(msg.isSelf ? T::kAccent : T::kText) + ";'>" + nick.toHtmlEscaped() + "</b>";
        QString badge;
        QString bodyColor = T::kText;
        if (spoofed) {
            badge = " <b style='color:" + QString(T::kError) + ";'>" + QString::fromUtf8("⚠ IMPERSONATION") + "</b>";
            bodyColor = T::kTextMuted;
        } else if (msg.isSelf) {
            badge = "";
        } else if (msg.isVerified) {
            badge = " <span style='color:" + QString(T::kSuccess) + ";'>" + QString::fromUtf8("✓ verified") + "</span>";
        } else {
            badge = " <span style='color:" + QString(T::kTextMuted) + ";'>(unverified)</span>";
        }
        return time + nickHtml + badge + "&nbsp;&nbsp;<span style='color:" + bodyColor + ";'>" + body + "</span>";
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
    QFrame *banner = nullptr;
    QLabel *bannerLabel = nullptr;
    QLabel *lockError = nullptr;
    QLabel *statusLabel = nullptr;
    QTimer *statusTimer = nullptr;
    int fontScale = 100;
    bool quitting = false;
    bool trayHintShown = false;
    QTextEdit *chatDisplay;
    QLineEdit *msgInput, *pwdInput;
    QWidget *msgContainer, *pinContainer;
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
    QTimer::singleShot(0, &window, [&window]() { window.startFirstRun(); });

    // --- STARTUP LOGIC: Hide in the tray if setup is complete (and a tray exists), otherwise show UI ---
    if (!window.shouldStartHidden()) {
        window.show();
    }

    return app.exec();
}
