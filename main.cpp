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
#include <QSettings>
#include <QCryptographicHash>
#include <QScrollBar>
#include <QCoreApplication>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QDir>
#include <QStandardPaths>
#include <QFile>
#include <QScreen>
#include <QShowEvent>
#include <QKeyEvent>
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

// --- OPENSSL CRYPTOGRAPHY ---
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

struct ChatMsg {
    QString time;
    QString prefix; 
    QString plainText;
    QByteArray cipherText; 
    bool isSystem;
    bool isSelf; 
    bool isVerified;
    bool isTransient;
};

// --- OpenSSL Helper Functions ---
QByteArray pkeyToDER(EVP_PKEY *key) {
    unsigned char *der = nullptr;
    int len = i2d_PUBKEY(key, &der);
    if (len < 0) return QByteArray();
    QByteArray res((char*)der, len);
    OPENSSL_free(der);
    return res;
}

EVP_PKEY* derToPkey(const QByteArray &der) {
    const unsigned char *p = (const unsigned char*)der.data();
    return d2i_PUBKEY(nullptr, &p, der.size());
}

QByteArray privKeyToPEM(EVP_PKEY *key) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    char *data;
    long len = BIO_get_mem_data(bio, &data);
    QByteArray res(data, len);
    BIO_free(bio);
    return res;
}

EVP_PKEY* pemToPrivKey(const QByteArray &pem) {
    BIO *bio = BIO_new_mem_buf(pem.data(), pem.size());
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
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
        connect(btnClose, &QPushButton::clicked, [this]() { m_parent->hide(); });
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

protected:
    void paintEvent(QPaintEvent *event) override {
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
    void mouseReleaseEvent(QMouseEvent *event) override { startPos = QPoint(); }
private:
    QWidget *m_parent;
    QPoint startPos;
};

// --- Main Application ---
class SecureChatApp : public QMainWindow {
    Q_OBJECT
public:
    SecureChatApp() {
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
        
        autoLockTimer = new QTimer(this);
        connect(autoLockTimer, &QTimer::timeout, this, &SecureChatApp::lockSystem);

        setupSystemTray();
        loadConfiguration();
    }

    ~SecureChatApp() {
        if (myIdentityKey) EVP_PKEY_free(myIdentityKey);
        if (myEphemeralKey) EVP_PKEY_free(myEphemeralKey);
    }

    // --- CHECK FOR MINIMIZED START ---
    bool isSetupComplete() const {
        return setupStep == 0;
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

    void keyPressEvent(QKeyEvent *event) override {
        if (autoLockMinutes > 0) autoLockTimer->start(); 
        
        if (isLocked && setupStep != 2 && setupStep != 3) {
            if (!event->text().isEmpty() && !pwdInput->hasFocus()) {
                pwdInput->setFocus();
                QApplication::sendEvent(pwdInput, event);
            }
        } else {
            if (!event->text().isEmpty() && !msgInput->hasFocus()) {
                msgInput->setFocus();
                QApplication::sendEvent(msgInput, event);
            }
        }
        QMainWindow::keyPressEvent(event);
    }

private slots:
    void gracefulShutdown() {
        if (tcpSocket && tcpSocket->state() == QAbstractSocket::ConnectedState) {
            QJsonObject leaveObj; leaveObj["type"] = "LEAVE";
            sendSignedPacket(leaveObj);
            tcpSocket->flush();
            tcpSocket->disconnectFromHost();
        }
        QApplication::quit();
    }

    void printHelp() {
        log("--- SÖNKKÖKOODI COMMANDS ---", "[ * ]", true);
        log("nick <alias>   : Change your cryptographic alias", "[ * ]", true);
        log("who            : Display all active users in the room", "[ * ]", true);
        log("clear          : Clear the terminal display", "[ * ]", true);
        log("disconnect     : Disconnect from the current server", "[ * ]", true);
        log("connect        : Connect to the saved server", "[ * ]", true);
        log("server <ip>    : Change the target server IP", "[ * ]", true);
        log("port <num>     : Change the target server port", "[ * ]", true);
        log("Alt+L          : Force lock application", "[ * ]", true);
    }

    void openSettings() {
        if (isLocked) {
            log("Cannot access Settings while system is locked.", "[ ! ]", true);
            return;
        }
        
        QDialog dlg(this);
        dlg.setWindowFlags(Qt::FramelessWindowHint | Qt::Dialog);
        dlg.resize(450, 420);
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
        connect(btnUninstall, &QPushButton::clicked, &dlg, [&dlg, this]() {
            dlg.reject(); 
            QTimer::singleShot(100, this, &SecureChatApp::performUninstall);
        });
        l->addWidget(btnUninstall);

        QPushButton *btn = new QPushButton("SAVE & CLOSE", &dlg);
        btn->setStyleSheet("QPushButton { background-color: #222222; border: 1px solid #55FF55; padding: 10px; color: #FFFFFF; } QPushButton:hover { background-color: #333333; }");
        connect(btn, &QPushButton::clicked, &dlg, &QDialog::accept);
        l->addWidget(btn);
        
        if (dlg.exec() == QDialog::Accepted) {
            notifyConnect = chkConnect->isChecked();
            notifyDisconnect = chkDisconnect->isChecked();
            notifyMessage = chkMessage->isChecked();
            autoLockMinutes = comboTimeout->currentData().toInt();
            
            QSettings settings(QCoreApplication::applicationDirPath() + "/sonkkokoodi.ini", QSettings::IniFormat);
            settings.setValue("notify_connect", notifyConnect);
            settings.setValue("notify_disconnect", notifyDisconnect);
            settings.setValue("notify_message", notifyMessage);
            settings.setValue("auto_lock_minutes", autoLockMinutes);
            
            if (autoLockMinutes > 0) {
                autoLockTimer->setInterval(autoLockMinutes * 60000);
                autoLockTimer->start();
            } else {
                autoLockTimer->stop();
            }
            
            log("Settings saved locally.", "[ * ]", true);
        }
    }

    void performUninstall() {
        QDialog warnDlg(this);
        warnDlg.setWindowFlags(Qt::FramelessWindowHint | Qt::Dialog);
        warnDlg.resize(450, 250);
        warnDlg.setStyleSheet("background-color: #000000; border: 2px solid #FF3333; color: #FF3333; font-family: 'Arial'; font-weight: bold; font-size: 16px;");
        
        QVBoxLayout *l = new QVBoxLayout(&warnDlg);
        QLabel *lbl = new QLabel("CRITICAL WARNING", &warnDlg);
        lbl->setAlignment(Qt::AlignCenter);
        lbl->setStyleSheet("border: none; font-size: 22px;");
        l->addWidget(lbl);
        
        QLabel *desc = new QLabel("This will permanently delete Sönkkökoodi, your cryptographic keys, your local vault, and all settings.\n\nProceed with self-destruct?", &warnDlg);
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
        
        if (warnDlg.exec() == QDialog::Accepted) {
            
#ifdef Q_OS_WIN
            QSettings bootSettings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
            bootSettings.remove("Sonkkokoodi");
#endif
            
            QString shortcutPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation) + "/Sönkkökoodi.lnk";
            QFile::remove(shortcutPath);
            
            QDir appDir(QCoreApplication::applicationDirPath());
            if (appDir.dirName().toLower() == "build") {
                appDir.cdUp();
            }
            
            QString targetDir = appDir.absolutePath();
            
            if (targetDir.contains("Sonkkokoodi", Qt::CaseInsensitive)) {
#ifdef Q_OS_WIN
                QString psCmd = QString("Start-Sleep -Seconds 2; Remove-Item -Path '%1' -Recurse -Force").arg(targetDir);
                QProcess::startDetached("powershell.exe", QStringList() << "-WindowStyle" << "Hidden" << "-Command" << psCmd, QDir::tempPath());
#elif defined(Q_OS_LINUX)
                QString cmd = QString("sh -c \"sleep 2 && rm -rf '%1'\"").arg(targetDir);
                QProcess::startDetached(cmd, QStringList(), QDir::tempPath());
#endif
            }
            
            QApplication::quit();
        }
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
        
        QFile file(QCoreApplication::applicationDirPath() + "/sonkkokoodi.notes");
        if (file.open(QIODevice::ReadOnly)) {
            QByteArray iv = file.read(12);
            QByteArray cipher = file.readAll();
            QByteArray plain = decryptGCM(cipher, vaultKey, iv);
            te->setPlainText(QString::fromUtf8(plain));
            file.close();
        }
        
        notesDlg.exec();
        
        QByteArray plain = te->toPlainText().toUtf8();
        QByteArray iv;
        QByteArray cipher = encryptGCM(plain, vaultKey, iv);
        if (file.open(QIODevice::WriteOnly)) {
            file.write(iv);
            file.write(cipher);
            file.close();
        }
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
            listText += "UID: " + it.key() + "\nALIAS: " + it.value() + "\n--------------------------------\n";
        }
        te->setPlainText(listText);
        l->addWidget(te);
        
        QPushButton *btn = new QPushButton("CLOSE", &tofuDlg);
        btn->setStyleSheet("QPushButton { background-color: #222222; border: 1px solid #55FF55; padding: 10px; color: #FFFFFF;} QPushButton:hover { background-color: #333333; }");
        connect(btn, &QPushButton::clicked, &tofuDlg, &QDialog::accept);
        l->addWidget(btn);
        
        tofuDlg.exec();
    }

    void showLoadingScreen(const QString &text, int timeoutMs = 0) {
        loadingLabel->setText(text);
        mainStack->setCurrentIndex(1);
        if (timeoutMs > 0) {
            QTimer::singleShot(timeoutMs, this, [this]() {
                mainStack->setCurrentIndex(0);
            });
        }
    }

    void loadConfiguration() {
        QString configPath = QCoreApplication::applicationDirPath() + "/sonkkokoodi.ini";
        QSettings settings(configPath, QSettings::IniFormat);
        
        targetIp = settings.value("server_ip", "").toString();
        targetPort = settings.value("server_port", 9999).toInt();
        storedPinHash = settings.value("pin_hash").toString();
        myNickname = settings.value("nickname").toString();
        QString pemData = settings.value("ecdsa_identity").toString();
        vaultSalt = settings.value("vault_salt").toByteArray();
        
        notifyConnect = settings.value("notify_connect", true).toBool();
        notifyDisconnect = settings.value("notify_disconnect", true).toBool();
        notifyMessage = settings.value("notify_message", false).toBool();
        
        autoLockMinutes = settings.value("auto_lock_minutes", 1).toInt();
        if (autoLockMinutes > 0) {
            autoLockTimer->setInterval(autoLockMinutes * 60000);
        }

        if (!pemData.isEmpty()) {
            myIdentityKey = pemToPrivKey(pemData.toUtf8());
            myUid = QString(QCryptographicHash::hash(pkeyToDER(myIdentityKey), QCryptographicHash::Sha256).toHex()).left(8);
        }

        settings.beginGroup("TrustedIdentities");
        for (const QString &uid : settings.childKeys()) {
            trustedIdentities.insert(uid, settings.value(uid).toString());
        }
        settings.endGroup();

        if (storedPinHash.isEmpty() || myNickname.isEmpty() || !myIdentityKey || vaultSalt.isEmpty() || targetIp.isEmpty()) {
            setupStep = 1;
            isLocked = true;
            msgContainer->hide();
            pinContainer->show();
            pwdInput->setPlaceholderText("SETUP: CREATE NEW PASSWORD...");
            log("INITIALIZATION: No credentials found. Step 1: Create a secure password.", "[ * ]", true);
        } else {
            setupStep = 0;
            isLocked = true;
            msgContainer->hide();
            pinContainer->show();
            pwdInput->setPlaceholderText("ENTER PASSWORD...");
            log("Locked. Enter password.", "[ * ]", true);
        }
    }

    void setupSystemTray() {
        trayIcon = new QSystemTrayIcon(this);
        QPixmap trayPix(32, 32);
        trayPix.fill(Qt::transparent);
        QPainter p(&trayPix);
        p.setPen(QColor("#55FF55"));
        p.setFont(QFont("Arial", 14, QFont::Bold));
        p.drawText(trayPix.rect(), Qt::AlignCenter, "SK");
        trayIcon->setIcon(QIcon(trayPix));

        QMenu *trayMenu = new QMenu(this);
        QAction *showAction = new QAction("Show Terminal", this);
        connect(showAction, &QAction::triggered, this, [this](){ this->showNormal(); this->activateWindow(); });
        QAction *quitAction = new QAction("Shutdown Core", this);
        connect(quitAction, &QAction::triggered, this, [this](){ gracefulShutdown(); });

        trayMenu->addAction(showAction);
        trayMenu->addAction(quitAction);
        trayIcon->setContextMenu(trayMenu);
        trayIcon->show();

        connect(trayIcon, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason){
            if (reason == QSystemTrayIcon::DoubleClick || reason == QSystemTrayIcon::Trigger) {
                if (this->isVisible()) this->hide();
                else { this->showNormal(); this->activateWindow(); }
            }
        });
    }

    void enableAutoStart() {
        QString appPath = QCoreApplication::applicationFilePath();
#ifdef Q_OS_WIN
        QSettings bootSettings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
        bootSettings.setValue("Sonkkokoodi", QDir::toNativeSeparators(appPath));
        log("Windows Boot Sequence Injected.", "[ * ]", true);
#endif
    }

    void handlePwdSubmit() {
        QString input = pwdInput->text();
        if (input.isEmpty()) return;
        pwdInput->clear();

        chatDisplay->append("<span style='color:#FF3333;'>[LOCKED] > ****</span>");
        QString inputHash = QString(QCryptographicHash::hash(input.toUtf8(), QCryptographicHash::Sha256).toHex());

        QString configPath = QCoreApplication::applicationDirPath() + "/sonkkokoodi.ini";
        QSettings settings(configPath, QSettings::IniFormat);

        if (setupStep == 1) {
            settings.setValue("pin_hash", inputHash);
            storedPinHash = inputHash;
            
            vaultSalt.resize(16);
            RAND_bytes((unsigned char*)vaultSalt.data(), 16);
            settings.setValue("vault_salt", vaultSalt);
            
            vaultKey = derivePBKDF2(input, vaultSalt);
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
            if (inputHash == storedPinHash) {
                vaultKey = derivePBKDF2(input, vaultSalt);
                
                if (!vaultLoaded) {
                    loadVault();
                    vaultLoaded = true;
                } else {
                    saveVault(); 
                }
                
                unlockSystem();
            }
            else log("Invalid password.", "[ ! ]", true);
        }
    }

    void lockSystem() {
        if (setupStep != 0 || isLocked) return; 
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
        
        if (tcpSocket && tcpSocket->state() == QAbstractSocket::ConnectedState) {
            promptLabel->setText("chat >");
        } else {
            promptLabel->setText(">");
            connectToPeer();
        }
        refreshChatDisplay();
    }

    void generateIdentityKey() {
        log("Generating secp256r1 ECDSA Identity...", "[ * ]", true);
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
        EVP_PKEY_keygen(pctx, &myIdentityKey);
        EVP_PKEY_CTX_free(pctx);

        QByteArray pemBytes = privKeyToPEM(myIdentityKey);
        QString configPath = QCoreApplication::applicationDirPath() + "/sonkkokoodi.ini";
        QSettings settings(configPath, QSettings::IniFormat);
        settings.setValue("ecdsa_identity", pemBytes);

        myUid = QString(QCryptographicHash::hash(pkeyToDER(myIdentityKey), QCryptographicHash::Sha256).toHex()).left(8);
        log("Identity generated. UID: " + myUid, "[ * ]", true);
    }

    void handleInput() {
        QString text = msgInput->text().trimmed();
        if (text.isEmpty()) return;
        msgInput->clear();

        if (setupStep == 2) {
            chatDisplay->append("<span style='color:#55FF55;'>alias > </span><span style='color:#FFFFFF;'>" + text + "</span>");
            QString configPath = QCoreApplication::applicationDirPath() + "/sonkkokoodi.ini";
            QSettings settings(configPath, QSettings::IniFormat);
            settings.setValue("nickname", text);
            myNickname = text;
            
            generateIdentityKey();
            
            setupStep = 3;
            msgInput->clear();
            msgInput->setPlaceholderText("SETUP: ENTER SERVER IP (e.g. 192.168.1.50:9999)...");
            promptLabel->setText("server >");
            msgInput->setFocus();
            log("Alias saved. Step 3: Enter target server IP and port.", "[ * ]", true);
            return;
        }

        if (setupStep == 3) {
            chatDisplay->append("<span style='color:#55FF55;'>server > </span><span style='color:#FFFFFF;'>" + text + "</span>");
            
            QString ip = text;
            int port = 9999;
            if (text.contains(":")) {
                QStringList parts = text.split(":");
                ip = parts[0];
                port = parts[1].toInt();
            }
            
            QString configPath = QCoreApplication::applicationDirPath() + "/sonkkokoodi.ini";
            QSettings settings(configPath, QSettings::IniFormat);
            settings.setValue("server_ip", ip);
            settings.setValue("server_port", port);
            targetIp = ip;
            targetPort = port;
            
            enableAutoStart();
            setupStep = 0;
            unlockSystem();
            return;
        }

        QString lowerText = text.toLower();

        if (lowerText == "clear") {
            history.clear(); chatDisplay->clear(); 
            saveVault(); 
            return;
        } else if (lowerText == "disconnect") {
            if (tcpSocket && tcpSocket->state() == QAbstractSocket::ConnectedState) {
                QJsonObject leaveObj; leaveObj["type"] = "LEAVE";
                sendSignedPacket(leaveObj);
                tcpSocket->flush();
                tcpSocket->disconnectFromHost();
            }
            return;
        } else if (lowerText == "who") {
            if (tcpSocket && tcpSocket->state() == QAbstractSocket::ConnectedState) {
                QJsonObject reqObj; reqObj["type"] = "WHO_REQ";
                sendSignedPacket(reqObj);
                log("Locating active peers...", "[ * ]", true);
            }
            return;
        } else if (lowerText.startsWith("nick ")) {
            QString newNick = text.mid(5).trimmed();
            if (!newNick.isEmpty()) {
                myNickname = newNick;
                QSettings(QCoreApplication::applicationDirPath() + "/sonkkokoodi.ini", QSettings::IniFormat).setValue("nickname", myNickname);
            }
            return;
        }

        if (!tcpSocket || tcpSocket->state() != QAbstractSocket::ConnectedState) {
            chatDisplay->append("<span style='color:#55FF55;'>> </span><span style='color:#FFFFFF;'>" + text + "</span>");
            if (lowerText == "connect") connectToPeer();
            else if (lowerText.startsWith("server ")) {
                targetIp = text.mid(7).trimmed();
                QSettings(QCoreApplication::applicationDirPath() + "/sonkkokoodi.ini", QSettings::IniFormat).setValue("server_ip", targetIp);
                log("Target IP saved: " + targetIp, "[ * ]", true);
            } else if (lowerText.startsWith("port ")) {
                targetPort = text.mid(5).trimmed().toInt();
                QSettings(QCoreApplication::applicationDirPath() + "/sonkkokoodi.ini", QSettings::IniFormat).setValue("server_port", targetPort);
                log("Target Port saved: " + QString::number(targetPort), "[ * ]", true);
            } else log("Unknown command: " + text, "[ ! ]", true);
            return;
        }

        if (isNegotiating) return;

        QString payloadText = "<" + myNickname + "> " + text;
        QByteArray iv;
        QByteArray cipherBytes = encryptGCM(payloadText.toUtf8(), currentGroupKey, iv);
        
        QJsonObject chatObj;
        chatObj["type"] = "CHAT";
        chatObj["iv"] = QString(iv.toBase64());
        chatObj["ciphertext"] = QString(cipherBytes.toBase64());

        sendSignedPacket(chatObj);
        
        saveMessage("", payloadText, cipherBytes, false, true, true);
        
        msgCount++;
        if (msgCount >= 15) {
            currentGroupKey = QCryptographicHash::hash(currentGroupKey, QCryptographicHash::Sha256);
            msgCount = 0;
            showLoadingScreen("[*] REGENERATING SECRECY KEYS...", 1200);
        }
    }

    void connectToPeer() {
        if (targetIp.isEmpty()) {
            log("No target IP defined. Use 'server <ip>' command first.", "[ ! ]", true);
            return;
        }
        
        if (tcpSocket) tcpSocket->deleteLater();
        tcpSocket = new QTcpSocket(this);
        
        connect(tcpSocket, &QTcpSocket::connected, this, [this]() {
            promptLabel->setText("chat >");
            startKeyNegotiation();
        });
        connect(tcpSocket, &QTcpSocket::readyRead, this, &SecureChatApp::receiveData);
        connect(tcpSocket, &QTcpSocket::errorOccurred, this, [this](QTcpSocket::SocketError) {
            log("Connection failed.", "[ ! ]", true); 
            tcpSocket->deleteLater(); 
            tcpSocket = nullptr; 
            promptLabel->setText(">");
        });
        connect(tcpSocket, &QTcpSocket::disconnected, this, [this](){
            log("Disconnected.", "[ * ]", true); 
            tcpSocket->deleteLater(); 
            tcpSocket = nullptr; 
            promptLabel->setText(">");
            currentGroupKey.clear();
            msgCount = 0;
        });

        tcpSocket->connectToHost(targetIp, targetPort);
    }

    void sendNativeNotification(const QString &title, const QString &msg) {
#ifdef Q_OS_LINUX
        QProcess::startDetached("notify-send", QStringList() << "-a" << "Sönkkökoodi" << "-i" << "utilities-terminal" << title << msg);
#else
        if (trayIcon) {
            trayIcon->showMessage(title, msg, QSystemTrayIcon::NoIcon, 3000);
        }
#endif
    }

private: 

    QByteArray derivePBKDF2(const QString &pwd, const QByteArray &salt) {
        QByteArray key;
        key.resize(32);
        PKCS5_PBKDF2_HMAC(pwd.toUtf8().constData(), pwd.toUtf8().size(), 
                          (const unsigned char*)salt.constData(), salt.size(), 
                          100000, EVP_sha256(), 32, (unsigned char*)key.data());
        return key;
    }

    void saveVault() {
        if (vaultKey.isEmpty() || isLocked) return;

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
            arr.append(obj);
        }
        
        QByteArray jsonData = QJsonDocument(arr).toJson(QJsonDocument::Compact);
        QByteArray iv;
        QByteArray cipher = encryptGCM(jsonData, vaultKey, iv);
        
        QFile file(QCoreApplication::applicationDirPath() + "/sonkkokoodi.vault");
        if (file.open(QIODevice::WriteOnly)) {
            file.write(iv);
            file.write(cipher);
            file.close();
        }
    }

    void loadVault() {
        QFile file(QCoreApplication::applicationDirPath() + "/sonkkokoodi.vault");
        if (!file.open(QIODevice::ReadOnly)) return;
        
        QByteArray iv = file.read(12);
        QByteArray cipher = file.readAll();
        file.close();

        QByteArray jsonData = decryptGCM(cipher, vaultKey, iv);
        if (jsonData.isEmpty()) {
            log("Vault Decryption Failed. History corrupted or wrong key.", "[ ! ]", true);
            return;
        }

        history.clear();
        QJsonArray arr = QJsonDocument::fromJson(jsonData).array();
        for (QJsonValue v : arr) {
            QJsonObject obj = v.toObject();
            ChatMsg m;
            m.time = obj["time"].toString();
            m.prefix = obj["prefix"].toString();
            m.plainText = obj["plainText"].toString();
            m.cipherText = QByteArray::fromBase64(obj["cipherText"].toString().toUtf8());
            m.isSystem = obj["isSystem"].toBool();
            m.isSelf = obj["isSelf"].toBool();
            m.isVerified = obj["isVerified"].toBool();
            m.isTransient = false; 
            history.append(m);
        }
    }

    QByteArray signData(const QByteArray &data) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, myIdentityKey);
        EVP_DigestSignUpdate(ctx, data.data(), data.size());
        size_t siglen;
        EVP_DigestSignFinal(ctx, nullptr, &siglen);
        QByteArray sig; sig.resize(siglen);
        EVP_DigestSignFinal(ctx, (unsigned char*)sig.data(), &siglen);
        sig.resize(siglen);
        EVP_MD_CTX_free(ctx);
        return sig;
    }

    bool verifySignature(const QByteArray &data, const QByteArray &sig, EVP_PKEY *pubKey) {
        if (!pubKey) return false;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubKey);
        EVP_DigestVerifyUpdate(ctx, data.data(), data.size());
        int ret = EVP_DigestVerifyFinal(ctx, (unsigned char*)sig.data(), sig.size());
        EVP_MD_CTX_free(ctx);
        return ret == 1;
    }

    QByteArray encryptGCM(const QByteArray &plaintext, const QByteArray &key, QByteArray &iv) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        
        iv.resize(12);
        RAND_bytes((unsigned char*)iv.data(), 12);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, (unsigned char*)key.data(), (unsigned char*)iv.data());
        
        QByteArray out; out.resize(plaintext.size() + 16);
        int len;
        EVP_EncryptUpdate(ctx, (unsigned char*)out.data(), &len, (unsigned char*)plaintext.data(), plaintext.size());
        int cipherLen = len;
        EVP_EncryptFinal_ex(ctx, (unsigned char*)out.data() + len, &len);
        cipherLen += len;
        
        QByteArray tag; tag.resize(16);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        EVP_CIPHER_CTX_free(ctx);

        out.resize(cipherLen);
        out.append(tag); 
        return out;
    }

    QByteArray decryptGCM(const QByteArray &ciphertextWithTag, const QByteArray &key, const QByteArray &iv) {
        if (ciphertextWithTag.size() < 16) return QByteArray();
        
        QByteArray tag = ciphertextWithTag.right(16);
        QByteArray ciphertext = ciphertextWithTag.left(ciphertextWithTag.size() - 16);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, (unsigned char*)key.data(), (unsigned char*)iv.data());

        QByteArray out; out.resize(ciphertext.size());
        int len, outLen;
        EVP_DecryptUpdate(ctx, (unsigned char*)out.data(), &len, (unsigned char*)ciphertext.data(), ciphertext.size());
        outLen = len;
        
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
        int ret = EVP_DecryptFinal_ex(ctx, (unsigned char*)out.data() + len, &len);
        EVP_CIPHER_CTX_free(ctx);

        if (ret > 0) {
            out.resize(outLen + len);
            return out;
        }
        return QByteArray(); 
    }

    EVP_PKEY* generateEphemeralKey() {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
        EVP_PKEY *key = nullptr;
        EVP_PKEY_keygen(pctx, &key);
        EVP_PKEY_CTX_free(pctx);
        return key;
    }

    QByteArray deriveSharedSecret(EVP_PKEY *myPriv, EVP_PKEY *peerPub) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(myPriv, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, peerPub);
        size_t len;
        EVP_PKEY_derive(ctx, nullptr, &len);
        QByteArray secret; secret.resize(len);
        EVP_PKEY_derive(ctx, (unsigned char*)secret.data(), &len);
        secret.resize(len);
        EVP_PKEY_CTX_free(ctx);
        return QCryptographicHash::hash(secret, QCryptographicHash::Sha256); 
    }

    void sendSignedPacket(const QJsonObject &payload) {
        QByteArray data = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        QByteArray sig = signData(data);
        
        QJsonObject envelope;
        envelope["data"] = QString(data.toBase64());
        envelope["sig"] = QString(sig.toBase64());
        envelope["sender_pub"] = QString(pkeyToDER(myIdentityKey).toBase64());

        QByteArray networkPacket = QJsonDocument(envelope).toJson(QJsonDocument::Compact) + "\n";
        if (tcpSocket) tcpSocket->write(networkPacket);
    }

    void startKeyNegotiation() {
        isNegotiating = true;
        showLoadingScreen("[*] NEGOTIATING CRYPTOGRAPHIC KEYS...");
        
        if (myEphemeralKey) EVP_PKEY_free(myEphemeralKey);
        myEphemeralKey = generateEphemeralKey();
        
        QJsonObject helloObj;
        helloObj["type"] = "HELLO";
        helloObj["ecdh_pub"] = QString(pkeyToDER(myEphemeralKey).toBase64());
        sendSignedPacket(helloObj);

        QTimer::singleShot(3000, this, [this]() {
            if (isNegotiating) {
                isNegotiating = false;
                currentGroupKey.resize(32);
                RAND_bytes((unsigned char*)currentGroupKey.data(), 32);
                msgCount = 0; 
                showLoadingScreen("[*] SECURE TUNNEL ESTABLISHED", 1000);
            }
        });
    }

    void receiveData() {
        if (!tcpSocket) return;

        while (tcpSocket->canReadLine()) {
            QByteArray line = tcpSocket->readLine().trimmed();
            QJsonDocument doc = QJsonDocument::fromJson(line);
            if (!doc.isObject()) continue;

            QJsonObject env = doc.object();
            QByteArray dataBytes = QByteArray::fromBase64(env["data"].toString().toUtf8());
            QByteArray sigBytes = QByteArray::fromBase64(env["sig"].toString().toUtf8());
            QByteArray pubBytes = QByteArray::fromBase64(env["sender_pub"].toString().toUtf8());

            EVP_PKEY *senderPub = derToPkey(pubBytes);
            if (!senderPub || !verifySignature(dataBytes, sigBytes, senderPub)) {
                if (senderPub) EVP_PKEY_free(senderPub);
                continue; 
            }

            QString senderUid = QString(QCryptographicHash::hash(pubBytes, QCryptographicHash::Sha256).toHex()).left(8);
            EVP_PKEY_free(senderPub);

            if (senderUid == myUid) continue; 

            QJsonObject payload = QJsonDocument::fromJson(dataBytes).object();
            QString type = payload["type"].toString();

            if (type == "HELLO" && !currentGroupKey.isEmpty() && !isNegotiating) {
                QString joinNick = trustedIdentities.value(senderUid, "Unknown peer");
                log(joinNick + " is negotiating a connection...", "[ * ]", true);
                
                if (notifyConnect) {
                    sendNativeNotification("Connection", joinNick + " is joining the room.");
                }
                
                QByteArray targetEcdhDer = QByteArray::fromBase64(payload["ecdh_pub"].toString().toUtf8());
                QString targetHash = QString(QCryptographicHash::hash(targetEcdhDer, QCryptographicHash::Sha256).toHex());
                
                QTimer::singleShot(QRandomGenerator::global()->bounded(300) + 50, this, [this, targetEcdhDer, targetHash]() {
                    EVP_PKEY *peerEcdh = derToPkey(targetEcdhDer);
                    if (!peerEcdh) return;
                    
                    EVP_PKEY *tempEcdh = generateEphemeralKey();
                    QByteArray kek = deriveSharedSecret(tempEcdh, peerEcdh);
                    EVP_PKEY_free(peerEcdh);

                    QByteArray iv;
                    QByteArray encKey = encryptGCM(currentGroupKey, kek, iv);

                    QJsonObject welcomeObj;
                    welcomeObj["type"] = "WELCOME";
                    welcomeObj["target"] = targetHash;
                    welcomeObj["ecdh_pub"] = QString(pkeyToDER(tempEcdh).toBase64());
                    welcomeObj["iv"] = QString(iv.toBase64());
                    welcomeObj["enc_key"] = QString(encKey.toBase64());
                    welcomeObj["msg_count"] = msgCount; 
                    
                    sendSignedPacket(welcomeObj);
                    EVP_PKEY_free(tempEcdh);
                });
            } 
            else if (type == "WELCOME" && isNegotiating) {
                QByteArray myEcdhDer = pkeyToDER(myEphemeralKey);
                QString myHash = QString(QCryptographicHash::hash(myEcdhDer, QCryptographicHash::Sha256).toHex());
                
                if (payload["target"].toString() == myHash) {
                    QByteArray peerEcdhDer = QByteArray::fromBase64(payload["ecdh_pub"].toString().toUtf8());
                    EVP_PKEY *peerEcdh = derToPkey(peerEcdhDer);
                    if (peerEcdh) {
                        QByteArray kek = deriveSharedSecret(myEphemeralKey, peerEcdh);
                        EVP_PKEY_free(peerEcdh);

                        QByteArray iv = QByteArray::fromBase64(payload["iv"].toString().toUtf8());
                        QByteArray encKey = QByteArray::fromBase64(payload["enc_key"].toString().toUtf8());
                        
                        QByteArray decKey = decryptGCM(encKey, kek, iv);
                        if (!decKey.isEmpty() && decKey.size() == 32) {
                            currentGroupKey = decKey;
                            msgCount = payload["msg_count"].toInt();
                            isNegotiating = false;
                            showLoadingScreen("[*] SECURE TUNNEL ESTABLISHED", 1000);
                        }
                    }
                }
            }
            else if (type == "LEAVE") {
                QString leaveNick = trustedIdentities.value(senderUid, "Unknown peer");
                log(leaveNick + " has left the room.", "[ * ]", true);
                
                if (notifyDisconnect) {
                    sendNativeNotification("Disconnection", leaveNick + " has left the room.");
                }
            }
            else if (type == "WHO_REQ") {
                QJsonObject repObj;
                repObj["type"] = "WHO_REP";
                sendSignedPacket(repObj);
            }
            else if (type == "WHO_REP") {
                log("Online: " + trustedIdentities.value(senderUid, "Unknown") + " (UID: " + senderUid + ")", "[ * ]", true);
            }
            else if (type == "CHAT" && !currentGroupKey.isEmpty() && !isNegotiating) {
                QByteArray iv = QByteArray::fromBase64(payload["iv"].toString().toUtf8());
                QByteArray cipherBytes = QByteArray::fromBase64(payload["ciphertext"].toString().toUtf8());
                
                QByteArray plainBytes = decryptGCM(cipherBytes, currentGroupKey, iv);
                
                if (plainBytes.isEmpty()) {
                    saveMessage("[ ! ]", "<GCM AUTHENTICATION FAILED - DROPPED>", cipherBytes, false, false);
                } else {
                    QString text = QString::fromUtf8(plainBytes);
                    bool isVerified = false;
                    bool isSpoofed = false;
                    QString senderNick = "Unknown";

                    int start = text.indexOf('<');
                    int end = text.indexOf('>');
                    if (start != -1 && end != -1 && end > start) {
                        senderNick = text.mid(start + 1, end - start - 1);

                        bool nickTaken = (senderNick == myNickname);
                        if (!nickTaken) {
                            for (auto it = trustedIdentities.begin(); it != trustedIdentities.end(); ++it) {
                                if (it.value() == senderNick && it.key() != senderUid) {
                                    nickTaken = true;
                                    break;
                                }
                            }
                        }
                        
                        if (!trustedIdentities.contains(senderUid)) {
                            if (nickTaken) {
                                isSpoofed = true;
                                if (senderNick == myNickname) {
                                    log("SPOOFING WARNING: UID " + senderUid + " is attempting to impersonate YOU!", "[ ! ]");
                                } else {
                                    log("SPOOFING WARNING: UID " + senderUid + " is attempting to impersonate pinned alias '" + senderNick + "'!", "[ ! ]");
                                }
                            } else {
                                trustedIdentities.insert(senderUid, senderNick);
                                QSettings settings(QCoreApplication::applicationDirPath() + "/sonkkokoodi.ini", QSettings::IniFormat);
                                settings.setValue("TrustedIdentities/" + senderUid, senderNick);
                                log("TOFU: Pinned new identity '" + senderNick + "' (UID: " + senderUid + ")");
                                isVerified = true;
                            }
                        } else {
                            if (trustedIdentities.value(senderUid) == senderNick) {
                                isVerified = true;
                            } else {
                                if (nickTaken) {
                                    isSpoofed = true;
                                    log("SPOOFING WARNING: Known UID " + senderUid + " is attempting to change alias to already taken name '" + senderNick + "'!", "[ ! ]");
                                } else {
                                    QString oldNick = trustedIdentities.value(senderUid);
                                    trustedIdentities[senderUid] = senderNick;
                                    QSettings settings(QCoreApplication::applicationDirPath() + "/sonkkokoodi.ini", QSettings::IniFormat);
                                    settings.setValue("TrustedIdentities/" + senderUid, senderNick);
                                    log("Identity update: '" + oldNick + "' changed alias to '" + senderNick + "' (UID: " + senderUid + ")");
                                    isVerified = true;
                                }
                            }
                        }

                        if (isSpoofed) {
                            text.replace("<" + senderNick + ">", "<" + senderNick + " (SPOOFER)>");
                        }
                    }

                    saveMessage("", text, cipherBytes, false, false, isVerified);
                    
                    if (notifyMessage && !isSpoofed && !isLocked) {
                        sendNativeNotification("New Message", "Message from " + senderNick);
                    }
                    
                    msgCount++;
                    if (msgCount >= 15) {
                        currentGroupKey = QCryptographicHash::hash(currentGroupKey, QCryptographicHash::Sha256);
                        msgCount = 0;
                        showLoadingScreen("[*] REGENERATING SECRECY KEYS...", 1200);
                    }
                }
            }
        }
    }

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

    void saveMessage(const QString& prefix, const QString& plain, const QByteArray& cipher, bool isSystem, bool isSelf, bool isVerified = false, bool isTransient = false) {
        history.append({getTime(), prefix, plain, cipher, isSystem, isSelf, isVerified, isTransient});
        refreshChatDisplay();
        
        if (!isSystem && !isLocked) saveVault();
    }

    void refreshChatDisplay() {
        chatDisplay->clear();
        for (const ChatMsg& msg : history) {
            QString displayContent;
            QString prefixStr = msg.prefix.isEmpty() ? "" : msg.prefix.toHtmlEscaped() + " ";
            
            if (msg.isSystem) {
                displayContent = msg.plainText.toHtmlEscaped();
                chatDisplay->append("<span style='color:#888888;'>[" + msg.time + "] " + prefixStr + displayContent + "</span>");
            } else {
                QString lineColor = "#FFFFFF"; 

                if (isLocked) {
                    lineColor = "#AA3333"; 
                    displayContent = QString(msg.cipherText.toHex(' ').toUpper());
                } 
                else if (msg.plainText.contains("FAILED")) {
                    lineColor = "#FF3333";
                    displayContent = msg.plainText.toHtmlEscaped();
                } 
                else {
                    QString text = msg.plainText;
                    if (text.startsWith("<")) {
                        int end = text.indexOf('>');
                        if (end != -1) {
                            QString rawNick = text.mid(1, end - 1);
                            QString cleanNick = rawNick;
                            cleanNick.replace(" (SPOOFER)", "");
                            
                            QString nickColor = getColorForNick(cleanNick);
                            if (rawNick.contains("(SPOOFER)")) {
                                nickColor = "#FF9900"; 
                            }
                            
                            QString nickPart = text.left(end + 1).toHtmlEscaped(); 
                            QString restOfMessage = text.mid(end + 1).toHtmlEscaped(); 
                            
                            if (msg.isVerified || msg.isSelf) {
                                int bracketIndex = nickPart.indexOf("&gt;");
                                if (bracketIndex != -1) {
                                    nickPart.insert(bracketIndex, " <span style='color:#55FF55;'>✓</span>");
                                }
                            }
                            
                            displayContent = "<span style='color:" + nickColor + ";'>" + nickPart + "</span><span style='color:#FFFFFF;'>" + restOfMessage + "</span>";
                        } else {
                            displayContent = text.toHtmlEscaped();
                        }
                    } else {
                        displayContent = text.toHtmlEscaped();
                    }
                }

                chatDisplay->append("<span style='color:" + lineColor + ";'>[" + msg.time + "] " + prefixStr + displayContent + "</span>");
            }
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
    
    QTcpSocket *tcpSocket;
    EVP_PKEY *myIdentityKey;
    EVP_PKEY *myEphemeralKey;
    QByteArray currentGroupKey;
    int msgCount; 
    
    QByteArray vaultSalt;
    QByteArray vaultKey;
    bool vaultLoaded = false;
    
    bool notifyConnect;
    bool notifyDisconnect;
    bool notifyMessage;
    int autoLockMinutes;
    
    QString targetIp;
    int targetPort;
    QList<ChatMsg> history; 
    
    int setupStep; 
    bool isLocked, isNegotiating = false;
    QString storedPinHash, myNickname, myUid;
    
    QMap<QString, QString> trustedIdentities; 
};

#include "main.moc"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    // --- LINUX FIX: Tell GNOME which .desktop file belongs to us ---
    QGuiApplication::setDesktopFileName("sonkkokoodi.desktop");
    
    SecureChatApp window;
    
    // --- STARTUP LOGIC: Hide if setup is complete, otherwise show UI ---
    if (!window.isSetupComplete()) {
        window.show();
    }
    
    return app.exec();
}
