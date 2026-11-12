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

// =========================================================================
// CONFIGURATION: CHANGE THIS TO YOUR GITHUB REPOSITORY
// Format: "Username/Repository"
const QString GITHUB_REPO = "MRITARI/sonkkokoodi"; 
// =========================================================================

// --- Custom Top Bar ---
class InstallerTopBar : public QWidget {
    Q_OBJECT
public:
    InstallerTopBar(QWidget *parent = nullptr) : QWidget(parent), m_parent(parent) {
        setFixedHeight(45);
        QHBoxLayout *layout = new QHBoxLayout(this);
        layout->setContentsMargins(20, 0, 20, 0);

        QLabel *title = new QLabel("SÖNKKÖKOODI INSTALLER", this);
        title->setStyleSheet("color: #55FF55; font-weight: bold; font-family: 'Arial'; font-size: 16px;");
        layout->addWidget(title);
        layout->addSpacerItem(new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum));

        QString btnStyle = "QPushButton { background-color: transparent; color: #666666; font-weight: bold; border: none; font-size: 20px; padding-bottom: 5px; } QPushButton:hover { color: #FF3333; }";
        
        QPushButton *btnClose = new QPushButton("X", this);
        btnClose->setStyleSheet(btnStyle);
        connect(btnClose, &QPushButton::clicked, [this]() { QApplication::quit(); });
        layout->addWidget(btnClose);
    }

protected:
    void paintEvent(QPaintEvent *event) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        int cut = 15;
        QPolygon polygon;
        polygon << QPoint(cut, 0) << QPoint(width() - cut, 0) << QPoint(width(), height()) << QPoint(0, height());
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

// --- Main Installer App ---
class InstallerApp : public QMainWindow {
    Q_OBJECT
public:
    InstallerApp() {
        setWindowFlags(Qt::FramelessWindowHint | Qt::WindowSystemMenuHint | Qt::WindowMinimizeButtonHint);
        setAttribute(Qt::WA_TranslucentBackground);
        resize(700, 500);

        networkManager = new QNetworkAccessManager(this);
        downloadReply = nullptr;
        zipFile = nullptr;

        QWidget *centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);
        QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
        mainLayout->setContentsMargins(0, 0, 0, 0);
        mainLayout->setSpacing(0);

        mainLayout->addWidget(new InstallerTopBar(this));

        QWidget *contentArea = new QWidget(this);
        contentArea->setStyleSheet("background-color: #000000; border: 2px solid #55FF55; border-top: none;");
        QVBoxLayout *contentLayout = new QVBoxLayout(contentArea);
        contentLayout->setContentsMargins(20, 20, 20, 20);

        QLabel *lblSelect = new QLabel("SELECT VERSION:", this);
        lblSelect->setStyleSheet("color: #FFFFFF; font-weight: bold; font-family: 'Arial'; font-size: 14px; border: none;");
        contentLayout->addWidget(lblSelect);

        releaseCombo = new QComboBox(this);
        releaseCombo->setStyleSheet("QComboBox { background-color: #111111; color: #55FF55; font-weight: bold; font-family: 'Arial'; border: 1px solid #55FF55; padding: 5px; font-size: 16px; }"
                                    "QComboBox::drop-down { border: none; }"
                                    "QComboBox QAbstractItemView { background-color: #111111; color: #55FF55; selection-background-color: #333333; }");
        releaseCombo->addItem("Fetching releases from GitHub...");
        releaseCombo->setDisabled(true);
        contentLayout->addWidget(releaseCombo);

        contentLayout->addSpacing(15);

        progressBar = new QProgressBar(this);
        progressBar->setStyleSheet("QProgressBar { border: 1px solid #55FF55; background-color: #111111; color: #FFFFFF; text-align: center; font-weight: bold; font-family: 'Arial'; }"
                                   "QProgressBar::chunk { background-color: #55FF55; }");
        progressBar->setValue(0);
        contentLayout->addWidget(progressBar);

        contentLayout->addSpacing(15);

        logDisplay = new QTextEdit(this);
        logDisplay->setReadOnly(true);
        logDisplay->setStyleSheet("background-color: #0A0A0A; color: #CCCCCC; border: 1px solid #333333; font-family: 'Consolas'; font-size: 14px;");
        contentLayout->addWidget(logDisplay);

        contentLayout->addSpacing(15);

        btnInstall = new QPushButton("INSTALL SÖNKKÖKOODI", this);
        btnInstall->setStyleSheet("QPushButton { background-color: #111111; color: #55FF55; border: 2px solid #55FF55; font-weight: bold; font-family: 'Arial'; font-size: 18px; padding: 10px; }"
                                  "QPushButton:hover { background-color: #225522; color: #FFFFFF; }"
                                  "QPushButton:disabled { border: 2px solid #555555; color: #555555; background-color: #000000; }");
        btnInstall->setDisabled(true);
        connect(btnInstall, &QPushButton::clicked, this, &InstallerApp::startInstall);
        contentLayout->addWidget(btnInstall);

        mainLayout->addWidget(contentArea);

        log("Starting installer...");
        fetchReleases();
    }

    ~InstallerApp() {
        // Closing the window mid-download must not leave a half-written zip behind.
        if (downloadReply) {
            downloadReply->disconnect(this);
            downloadReply->abort();
        }
        if (zipFile) {
            zipFile->close();
            delete zipFile;
            zipFile = nullptr;
            QFile::remove(tempZipPath);
        }
    }

private slots:
    void fetchReleases() {
        QString apiUrl = "https://api.github.com/repos/" + GITHUB_REPO + "/releases?per_page=100";
        QNetworkRequest request((QUrl(apiUrl)));
        request.setRawHeader("User-Agent", "Sonkkokoodi-Installer-v1.0");

        log("Fetching releases from: " + apiUrl);
        QNetworkReply *reply = networkManager->get(request);
        connect(reply, &QNetworkReply::finished, this, [this, reply]() {
            reply->deleteLater();
            if (reply->error() != QNetworkReply::NoError) {
                log("GitHub API Error: " + reply->errorString());
                releaseCombo->setItemText(0, "Failed to fetch releases.");
                return;
            }

            QJsonDocument jsonResponse = QJsonDocument::fromJson(reply->readAll());
            if (!jsonResponse.isArray()) {
                // e.g. rate limiting returns an object with a "message"
                QString msg = jsonResponse.isObject() ? jsonResponse.object()["message"].toString() : QString("unexpected response");
                log("GitHub API returned an unexpected answer: " + msg);
                releaseCombo->setItemText(0, "Failed to fetch releases.");
                return;
            }
            QJsonArray releasesArray = jsonResponse.array();

            releaseCombo->clear();
            if (releasesArray.isEmpty()) {
                log("No releases found in repository.");
                releaseCombo->addItem("No releases available.");
                return;
            }

            log("Successfully retrieved " + QString::number(releasesArray.size()) + " releases.");

            for (const QJsonValue &value : releasesArray) {
                QJsonObject releaseObj = value.toObject();
                if (releaseObj["draft"].toBool()) continue;
                QString tagName = releaseObj["tag_name"].toString();
                QString releaseName = releaseObj["name"].toString();

                QJsonArray assets = releaseObj["assets"].toArray();
                QString downloadUrl = "";
                QString digest = "";

                for (const QJsonValue &assetVal : assets) {
                    QJsonObject assetObj = assetVal.toObject();
                    if (assetObj["name"].toString().endsWith(".zip", Qt::CaseInsensitive)) {
                        downloadUrl = assetObj["browser_download_url"].toString();
                        digest = assetObj["digest"].toString();   // "sha256:<hex>" when GitHub provides it
                        break;
                    }
                }

                if (!downloadUrl.isEmpty() && downloadUrl.startsWith("https://")) {
                    QString display = tagName + " - " + releaseName;
                    if (releaseObj["prerelease"].toBool()) display += " (pre-release)";
                    releaseCombo->addItem(display, downloadUrl);
                    releaseCombo->setItemData(releaseCombo->count() - 1, digest, Qt::UserRole + 1);
                }
            }

            if (releaseCombo->count() > 0) {
                releaseCombo->setEnabled(true);
                btnInstall->setEnabled(true);
                log("Ready to install.");
            } else {
                releaseCombo->addItem("No valid .zip assets found.");
                log("Releases found, but no .zip asset is attached.");
            }
        });
    }

    void startInstall() {
        btnInstall->setEnabled(false);
        releaseCombo->setEnabled(false);
        
        QString downloadUrl = releaseCombo->currentData().toString();
        expectedDigest = releaseCombo->currentData(Qt::UserRole + 1).toString().toLower();
        tempZipPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/sonkko_install.zip";
        writeFailed = false;
        progressBar->setValue(0);

        log("Starting download...");
        log("Target URL: " + downloadUrl);

        QNetworkRequest request((QUrl(downloadUrl)));
        request.setRawHeader("User-Agent", "Sonkkokoodi-Installer-v1.0");
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

        zipFile = new QFile(tempZipPath);
        if (!zipFile->open(QIODevice::WriteOnly)) {
            log("Error: Cannot write to temporary directory.");
            delete zipFile;
            zipFile = nullptr;
            btnInstall->setEnabled(true);
            releaseCombo->setEnabled(true);
            return;
        }

        downloadReply = networkManager->get(request);

        connect(downloadReply, &QNetworkReply::readyRead, this, [this]() {
            writeChunk(downloadReply->readAll());
        });
        
        connect(downloadReply, &QNetworkReply::downloadProgress, this, [this](qint64 bytesRead, qint64 totalBytes) {
            if (totalBytes > 0) {
                int percentage = static_cast<int>((bytesRead * 100) / totalBytes);
                progressBar->setValue(percentage);
            }
        });

        connect(downloadReply, &QNetworkReply::finished, this, &InstallerApp::onDownloadFinished);
    }

    void writeChunk(const QByteArray &data) {
        if (!zipFile || data.isEmpty() || writeFailed) return;
        if (zipFile->write(data) != data.size()) writeFailed = true;   // e.g. disk full
    }

    void resetUi() {
        btnInstall->setEnabled(true);
        releaseCombo->setEnabled(true);
    }

    void onDownloadFinished() {
        QNetworkReply *reply = downloadReply;
        downloadReply = nullptr;

        // Data that arrived without a final readyRead must not be lost.
        writeChunk(reply->readAll());

        zipFile->close();
        delete zipFile;
        zipFile = nullptr;

        QNetworkReply::NetworkError err = reply->error();
        QString errText = reply->errorString();
        reply->deleteLater();

        if (err != QNetworkReply::NoError || writeFailed) {
            log(writeFailed ? QString("Download failed: could not write to disk.") : "Download failed: " + errText);
            QFile::remove(tempZipPath);
            resetUi();
            return;
        }

        log("Download complete.");

        // Integrity check against the digest published by GitHub for this asset.
        if (expectedDigest.startsWith("sha256:")) {
            QFile f(tempZipPath);
            QByteArray actual;
            if (f.open(QIODevice::ReadOnly)) {
                QCryptographicHash h(QCryptographicHash::Sha256);
                h.addData(&f);
                actual = h.result().toHex();
            }
            if (actual.isEmpty() || QString::fromLatin1(actual) != expectedDigest.mid(7)) {
                log("SHA-256 mismatch - the download is corrupt or has been tampered with. Aborting.");
                f.close();
                QFile::remove(tempZipPath);
                resetUi();
                return;
            }
            log("SHA-256 verified.");
        } else {
            log("Warning: GitHub published no checksum for this release, integrity could not be verified.");
        }

        log("Extracting files...");

        QString legacyDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/Sonkkokoodi";
        QString installDir = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/Sonkkokoodi";
        // Keep upgrading an existing installation in place so its settings and vault stay with it.
        if (QFileInfo::exists(legacyDir + "/sonkkokoodi.exe")) installDir = legacyDir;
        QDir().mkpath(installDir);

        // Paths are passed through the environment, never spliced into the command text,
        // so quotes/apostrophes in a user name cannot break (or inject into) the command.
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        env.insert("SK_ZIP", QDir::toNativeSeparators(tempZipPath));
        env.insert("SK_DEST", QDir::toNativeSeparators(installDir));

        QProcess *process = new QProcess(this);
        process->setProcessEnvironment(env);

        connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, [this, installDir, process](int exitCode, QProcess::ExitStatus) {
            process->deleteLater();
            QFile::remove(tempZipPath);

            if (exitCode != 0) {
                log("Extraction failed. If Sönkkökoodi is running, close it and try again; otherwise the zip may be corrupted.");
                resetUi();
                return;
            }

            // The zip may contain a top-level folder; find the real executable.
            QString exePath;
            if (QFileInfo::exists(installDir + "/sonkkokoodi.exe")) {
                exePath = installDir + "/sonkkokoodi.exe";
            } else {
                QDirIterator it(installDir, QStringList() << "sonkkokoodi.exe", QDir::Files, QDirIterator::Subdirectories);
                if (it.hasNext()) exePath = it.next();
            }
            if (exePath.isEmpty()) {
                log("Extraction finished, but sonkkokoodi.exe was not found in the package.");
                resetUi();
                return;
            }

            log("Extraction successful.");
            createShortcut(exePath);
        });

        process->start("powershell.exe", QStringList() << "-NoProfile" << "-Command"
                       << "Expand-Archive -LiteralPath $env:SK_ZIP -DestinationPath $env:SK_DEST -Force");
    }

    void createShortcut(const QString &exePath) {
        log("Creating desktop shortcut...");

        const QString installDir = QFileInfo(exePath).absolutePath();
        QString shortcutPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation) + "/Sönkkökoodi.lnk";

        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        env.insert("SK_LNK", QDir::toNativeSeparators(shortcutPath));
        env.insert("SK_EXE", QDir::toNativeSeparators(exePath));
        env.insert("SK_DIR", QDir::toNativeSeparators(installDir));

        QProcess *process = new QProcess(this);
        process->setProcessEnvironment(env);
        connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, [this, process, exePath, installDir](int exitCode, QProcess::ExitStatus) {
            process->deleteLater();
            log("------------------------------------------");
            if (exitCode == 0) {
                log("Installation complete.");
                log("You can now launch the app from your Desktop.");
            } else {
                log("Installation complete, but the desktop shortcut could not be created.");
                log("Launch the app from: " + QDir::toNativeSeparators(exePath));
            }

            // --- UPDATED LOGIC: LAUNCH APP & EXIT ---
            btnInstall->setText("LAUNCH SÖNKKÖKOODI & EXIT");
            btnInstall->setEnabled(true);
            
            disconnect(btnInstall, &QPushButton::clicked, this, &InstallerApp::startInstall);
            connect(btnInstall, &QPushButton::clicked, [exePath, installDir]() { 
                QProcess::startDetached(exePath, QStringList(), installDir);
                QApplication::quit(); 
            });
        });

        process->start("powershell.exe", QStringList() << "-NoProfile" << "-Command"
                       << "$w = New-Object -ComObject WScript.Shell; $s = $w.CreateShortcut($env:SK_LNK); "
                          "$s.TargetPath = $env:SK_EXE; $s.WorkingDirectory = $env:SK_DIR; $s.Save()");
    }

    void log(const QString &text) {
        QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
        logDisplay->append("<span style='color:#777777;'>[" + timestamp + "]</span> <span style='color:#55FF55;'>" + text.toHtmlEscaped() + "</span>");
    }

private:
    QNetworkAccessManager *networkManager;
    QNetworkReply *downloadReply;
    QFile *zipFile;
    QString tempZipPath;
    QString expectedDigest;
    bool writeFailed = false;

    QComboBox *releaseCombo;
    QProgressBar *progressBar;
    QTextEdit *logDisplay;
    QPushButton *btnInstall;
};

#include "installer.moc"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    InstallerApp window;
    window.show();
    return app.exec();
}
