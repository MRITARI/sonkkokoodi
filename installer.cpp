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

private slots:
    void fetchReleases() {
        QString apiUrl = "https://api.github.com/repos/" + GITHUB_REPO + "/releases";
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
                QString tagName = releaseObj["tag_name"].toString();
                QString releaseName = releaseObj["name"].toString();
                
                QJsonArray assets = releaseObj["assets"].toArray();
                QString downloadUrl = "";
                
                for (const QJsonValue &assetVal : assets) {
                    QJsonObject assetObj = assetVal.toObject();
                    if (assetObj["name"].toString().endsWith(".zip")) {
                        downloadUrl = assetObj["browser_download_url"].toString();
                        break;
                    }
                }

                if (!downloadUrl.isEmpty()) {
                    QString display = tagName + " - " + releaseName;
                    releaseCombo->addItem(display, downloadUrl); 
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
        tempZipPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/sonkko_install.zip";

        log("Starting download...");
        log("Target URL: " + downloadUrl);

        QNetworkRequest request((QUrl(downloadUrl)));
        request.setRawHeader("User-Agent", "Sonkkokoodi-Installer-v1.0");
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

        zipFile = new QFile(tempZipPath);
        if (!zipFile->open(QIODevice::WriteOnly)) {
            log("Error: Cannot write to temporary directory.");
            btnInstall->setEnabled(true);
            releaseCombo->setEnabled(true);
            return;
        }

        downloadReply = networkManager->get(request);
        
        connect(downloadReply, &QNetworkReply::readyRead, this, [this]() {
            if (zipFile) zipFile->write(downloadReply->readAll());
        });
        
        connect(downloadReply, &QNetworkReply::downloadProgress, this, [this](qint64 bytesRead, qint64 totalBytes) {
            if (totalBytes > 0) {
                int percentage = static_cast<int>((bytesRead * 100) / totalBytes);
                progressBar->setValue(percentage);
            }
        });

        connect(downloadReply, &QNetworkReply::finished, this, &InstallerApp::onDownloadFinished);
    }

    void onDownloadFinished() {
        zipFile->close();
        delete zipFile;
        zipFile = nullptr;

        if (downloadReply->error() != QNetworkReply::NoError) {
            log("Download failed: " + downloadReply->errorString());
            downloadReply->deleteLater();
            btnInstall->setEnabled(true);
            releaseCombo->setEnabled(true);
            return;
        }
        
        downloadReply->deleteLater();
        log("Download complete.");
        log("Extracting files...");

        QString installDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/Sonkkokoodi";
        QDir().mkpath(installDir);

        QProcess *process = new QProcess(this);
        QString psCommand = QString("Expand-Archive -Path '%1' -DestinationPath '%2' -Force").arg(tempZipPath, installDir);
        
        connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, [this, installDir, process](int exitCode, QProcess::ExitStatus exitStatus) {
            process->deleteLater();
            QFile::remove(tempZipPath); 

            if (exitCode == 0) {
                log("Extraction successful.");
                createShortcut(installDir);
            } else {
                log("Extraction failed. The zip file may be corrupted.");
                btnInstall->setEnabled(true);
                releaseCombo->setEnabled(true);
            }
        });

        process->start("powershell.exe", QStringList() << "-NoProfile" << "-Command" << psCommand);
    }

    void createShortcut(const QString &installDir) {
        log("Creating desktop shortcut...");
        
        QString exePath = installDir + "/sonkkokoodi.exe";
        QString shortcutPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation) + "/Sönkkökoodi.lnk";

        QString psCommand = QString("$wshell = New-Object -ComObject WScript.Shell; $s = $wshell.CreateShortcut('%1'); $s.TargetPath = '%2'; $s.WorkingDirectory = '%3'; $s.Save();")
                            .arg(shortcutPath, exePath, installDir);

        QProcess *process = new QProcess(this);
        connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, [this, process](int exitCode, QProcess::ExitStatus) {
            process->deleteLater();
            log("------------------------------------------");
            log("Installation complete.");
            log("You can now launch the app from your Desktop.");
            btnInstall->setText("INSTALLATION COMPLETE. EXIT.");
            btnInstall->setEnabled(true);
            
            disconnect(btnInstall, &QPushButton::clicked, this, &InstallerApp::startInstall);
            connect(btnInstall, &QPushButton::clicked, [this]() { QApplication::quit(); });
        });

        process->start("powershell.exe", QStringList() << "-NoProfile" << "-Command" << psCommand);
    }

    void log(const QString &text) {
        QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
        logDisplay->append("<span style='color:#777777;'>[" + timestamp + "]</span> <span style='color:#55FF55;'>" + text + "</span>");
    }

private:
    QNetworkAccessManager *networkManager;
    QNetworkReply *downloadReply;
    QFile *zipFile;
    QString tempZipPath;

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