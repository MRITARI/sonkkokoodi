// Dialogs for Sönkkökoodi. No colors or fonts are set here: everything is styled by theme.h through
// objectName / dynamic properties. Dialogs are built but not exec'd, so they can be shown, tested and screenshotted.
#pragma once
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QComboBox>
#include <QTableWidget>
#include <QHeaderView>
#include <QTextBrowser>
#include <QMap>
#include <functional>
#include "theme.h"
#include "sk_protocol.h"
#include "sk_validate.h"

namespace sk::ui {

// A word-wrapped label of a known width. Qt's layouts ignore height-for-width in nested/fixed-size layouts and
// would give such a label a single line of height (clipped text), so the size hint reports the real wrapped height.
class WrapLabel : public QLabel {
public:
    WrapLabel(const QString &text, int width, QWidget *parent = nullptr) : QLabel(text, parent), m_width(width) {
        setWordWrap(true);
        setFixedWidth(width);
    }
    QSize sizeHint() const override { return QSize(m_width, qMax(heightForWidth(m_width), fontMetrics().height())); }
    QSize minimumSizeHint() const override { return sizeHint(); }
private:
    int m_width;
};

inline QLabel *makeLabel(const QString &text, const char *role = nullptr, QWidget *parent = nullptr, int fixedWidth = 0) {
    QLabel *l = fixedWidth > 0 ? new WrapLabel(text, fixedWidth, parent) : new QLabel(text, parent);
    l->setWordWrap(true);
    l->setTextFormat(Qt::PlainText);
    if (role) l->setProperty("role", role);
    return l;
}
inline QPushButton *makeButton(const QString &text, QWidget *parent, bool primary = false, bool danger = false) {
    auto *b = new QPushButton(text, parent);
    if (primary) b->setProperty("primary", true);
    if (danger) b->setProperty("danger", true);
    return b;
}
inline void repolish(QWidget *w) { w->style()->unpolish(w); w->style()->polish(w); }

inline QString strengthWord(int s) {
    static const char *w[] = { "too weak", "fair", "good", "strong" };
    return w[qBound(0, s, 3)];
}

// ------------------------------------------------------------------------------------------------
// First run: everything on one page, with specific inline errors. Create stays disabled until valid.
// ------------------------------------------------------------------------------------------------
struct SetupValues { QString password, alias, server, room; };

class SetupDialog : public QDialog {
public:
    explicit SetupDialog(QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("Welcome to Sönkkökoodi");
        setModal(true);
        setFixedWidth(480);
        auto *root = new QVBoxLayout(this);
        root->setSizeConstraint(QLayout::SetFixedSize);
        root->setContentsMargins(theme::kS5, theme::kS5, theme::kS5, theme::kS5);
        root->setSpacing(theme::kS3);
        const int W = 432;

        root->addWidget(makeLabel("Set up your secure chat", "title", this, W));
        root->addWidget(makeLabel("Your password protects this device's chat history, notes and identity key. "
                                  "It is never sent anywhere and cannot be recovered if you forget it.", "muted", this, W));

        pw = field("Password (8+ characters)", true);
        pwStrength = makeLabel("", "muted", this, W);
        pw2 = field("Repeat password", true);
        alias = field("Your alias (letters, digits, _ - .  up to 24)", false);
        server = field("Relay server, e.g. chat.example.org or 203.0.113.5:9999", false);
        room = field("Room passphrase (the same one everybody in your room uses)", true);
        roomStrength = makeLabel("", "muted", this, W);
        showRoom = new QCheckBox("Show room passphrase", this);

        add(root, "Password", pw); root->addWidget(pwStrength);
        add(root, "Repeat password", pw2);
        add(root, "Alias", alias);
        add(root, "Server", server);
        add(root, "Room passphrase", room); root->addWidget(roomStrength);
        root->addWidget(showRoom);
        root->addWidget(makeLabel("The room passphrase authenticates the key exchange, so the relay or a stranger "
                                  "cannot obtain your room key. Share it in person or over another trusted channel. "
                                  "Use 12+ characters.", "muted", this, W));

        error = makeLabel("", "error", this, W);
        root->addWidget(error);

        auto *row = new QHBoxLayout();
        row->addStretch(1);
        auto *cancel = makeButton("Quit", this);
        create = makeButton("Create", this, true);
        create->setDefault(true);
        row->addWidget(cancel);
        row->addWidget(create);
        root->addLayout(row);

        connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
        connect(create, &QPushButton::clicked, this, &QDialog::accept);
        connect(showRoom, &QCheckBox::toggled, this, [this](bool on) { room->setEchoMode(on ? QLineEdit::Normal : QLineEdit::Password); });
        for (QLineEdit *e : { pw, pw2, alias, server, room }) connect(e, &QLineEdit::textChanged, this, [this]() { validate(); });
        validate();
    }

    SetupValues values() const { return { pw->text(), alias->text().trimmed(), server->text().trimmed(), room->text() }; }

    // The first problem found, or an empty string. Shared with tests.
    static QString problem(const SetupValues &v, const QString &password2) {
        if (v.password.size() < 8) return "Password must be at least 8 characters.";
        if (v.password != password2) return "The two passwords do not match.";
        if (!isValidNick(v.alias)) return "Alias: 1-24 characters, letters, digits, '_', '-' or '.' only.";
        QString h; int p = 0; bool g = false;
        if (!parseEndpoint(v.server, h, p, g)) return "Server: enter a host or host:port (port 1-65535).";
        if (v.room.size() < 8) return "Room passphrase must be at least 8 characters (12+ recommended).";
        return QString();
    }

    QLineEdit *pw, *pw2, *alias, *server, *room;
    QLabel *error, *pwStrength, *roomStrength;
    QPushButton *create;
    QCheckBox *showRoom;

private:
    QLineEdit *field(const QString &placeholder, bool secret) {
        auto *e = new QLineEdit(this);
        e->setPlaceholderText(placeholder);
        e->setAccessibleName(placeholder);
        if (secret) e->setEchoMode(QLineEdit::Password);
        return e;
    }
    void add(QVBoxLayout *l, const QString &caption, QLineEdit *e) {
        auto *cap = makeLabel(caption, "muted", this, 432);
        cap->setBuddy(e);
        l->addWidget(cap);
        l->addWidget(e);
    }
    void validate() {
        pwStrength->setText(pw->text().isEmpty() ? QString() : "Strength: " + strengthWord(passphraseStrengthOf(pw->text())));
        roomStrength->setText(room->text().isEmpty() ? QString() : "Strength: " + strengthWord(passphraseStrengthOf(room->text())));
        const QString p = problem(values(), pw2->text());
        // Only nag about a field once the user has typed something into the last one they touched.
        const bool anythingTyped = !pw->text().isEmpty() || !alias->text().isEmpty() || !server->text().isEmpty() || !room->text().isEmpty();
        error->setText(anythingTyped ? p : QString());
        create->setEnabled(p.isEmpty());
    }
    static int passphraseStrengthOf(const QString &s) { return sk::passphraseStrength(s); }
};

// ------------------------------------------------------------------------------------------------
// Room passphrase prompt (upgrade from an older version, or changing the room).
// ------------------------------------------------------------------------------------------------
class RoomPassphraseDialog : public QDialog {
public:
    explicit RoomPassphraseDialog(QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("Room passphrase");
        setModal(true);
        setFixedWidth(460);
        const int W = 412;
        auto *root = new QVBoxLayout(this);
        root->setSizeConstraint(QLayout::SetFixedSize);
        root->setContentsMargins(theme::kS5, theme::kS5, theme::kS5, theme::kS5);
        root->setSpacing(theme::kS3);
        root->addWidget(makeLabel("Room passphrase", "title", this, W));
        root->addWidget(makeLabel("Everybody in your room must enter the same passphrase. It proves you belong to the "
                                  "room, so the relay or a stranger cannot obtain the room key. Changing it "
                                  "disconnects you from people who still use the old one.", "muted", this, W));
        edit = new QLineEdit(this);
        edit->setEchoMode(QLineEdit::Password);
        edit->setPlaceholderText("Room passphrase (8+ characters, 12+ recommended)");
        edit->setAccessibleName("Room passphrase");
        root->addWidget(edit);
        strength = makeLabel("", "muted", this, W);
        root->addWidget(strength);
        auto *show = new QCheckBox("Show passphrase", this);
        root->addWidget(show);
        error = makeLabel("", "error", this, W);
        root->addWidget(error);
        auto *row = new QHBoxLayout();
        row->addStretch(1);
        auto *cancel = makeButton("Cancel", this);
        ok = makeButton("Save", this, true);
        ok->setDefault(true);
        ok->setEnabled(false);
        row->addWidget(cancel);
        row->addWidget(ok);
        root->addLayout(row);
        connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
        connect(ok, &QPushButton::clicked, this, &QDialog::accept);
        connect(show, &QCheckBox::toggled, this, [this](bool on) { edit->setEchoMode(on ? QLineEdit::Normal : QLineEdit::Password); });
        connect(edit, &QLineEdit::textChanged, this, [this](const QString &t) {
            strength->setText(t.isEmpty() ? QString() : "Strength: " + strengthWord(sk::passphraseStrength(t)));
            error->setText(!t.isEmpty() && t.size() < 8 ? "At least 8 characters." : QString());
            ok->setEnabled(t.size() >= 8);
        });
    }
    QString passphrase() const { return edit->text(); }
    QLineEdit *edit;
    QLabel *strength, *error;
    QPushButton *ok;
};

// ------------------------------------------------------------------------------------------------
// Settings. Nothing is applied until Save; Cancel discards; Restore defaults only changes the controls.
// ------------------------------------------------------------------------------------------------
struct SettingsValues {
    bool notifyConnect = true, notifyDisconnect = true, notifyMessage = false, autoStart = false;
    int autoLockMinutes = 5;
    int fontScale = 100;
};

class SettingsDialog : public QDialog {
public:
    SettingsDialog(const SettingsValues &v, bool showAutoStart, QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("Settings");
        setModal(true);
        setMinimumWidth(440);
        auto *root = new QVBoxLayout(this);
        root->setContentsMargins(theme::kS5, theme::kS5, theme::kS5, theme::kS5);
        root->setSpacing(theme::kS2);
        root->addWidget(makeLabel("Settings", "title"));

        root->addWidget(makeLabel("Notifications", "muted"));
        cConnect = new QCheckBox("Alert when someone joins", this);
        cDisconnect = new QCheckBox("Alert when someone leaves", this);
        cMessage = new QCheckBox("Alert on new messages", this);
        root->addWidget(cConnect); root->addWidget(cDisconnect); root->addWidget(cMessage);

        cAutoStart = new QCheckBox("Start with Windows", this);
        if (showAutoStart) root->addWidget(cAutoStart); else cAutoStart->hide();

        root->addSpacing(theme::kS2);
        root->addWidget(makeLabel("Lock automatically after", "muted"));
        lock = new QComboBox(this);
        lock->setAccessibleName("Auto-lock timeout");
        lock->addItem("1 minute", 1); lock->addItem("5 minutes", 5); lock->addItem("15 minutes", 15);
        lock->addItem("60 minutes", 60); lock->addItem("Never", 0);
        root->addWidget(lock);

        root->addWidget(makeLabel("Text size", "muted"));
        font = new QComboBox(this);
        font->setAccessibleName("Text size");
        font->addItem("Standard", 100); font->addItem("Large", 125); font->addItem("Extra large", 150);
        root->addWidget(font);

        set(v);

        root->addSpacing(theme::kS3);
        uninstall = makeButton("Uninstall...", this, false, true);
        auto *restore = makeButton("Restore defaults", this);
        auto *cancel = makeButton("Cancel", this);
        save = makeButton("Save", this, true);
        save->setDefault(true);
        auto *row = new QHBoxLayout();
        row->addWidget(uninstall);
        row->addStretch(1);
        row->addWidget(restore);
        row->addWidget(cancel);
        row->addWidget(save);
        root->addLayout(row);

        connect(restore, &QPushButton::clicked, this, [this]() { set(SettingsValues()); });
        connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
        connect(save, &QPushButton::clicked, this, &QDialog::accept);
        connect(uninstall, &QPushButton::clicked, this, [this]() { uninstallRequested = true; reject(); });
    }
    SettingsValues values() const {
        SettingsValues v;
        v.notifyConnect = cConnect->isChecked(); v.notifyDisconnect = cDisconnect->isChecked();
        v.notifyMessage = cMessage->isChecked(); v.autoStart = cAutoStart->isChecked();
        v.autoLockMinutes = lock->currentData().toInt(); v.fontScale = font->currentData().toInt();
        return v;
    }
    bool uninstallRequested = false;
    QCheckBox *cConnect, *cDisconnect, *cMessage, *cAutoStart;
    QComboBox *lock, *font;
    QPushButton *uninstall, *save;

private:
    void set(const SettingsValues &v) {
        cConnect->setChecked(v.notifyConnect); cDisconnect->setChecked(v.notifyDisconnect);
        cMessage->setChecked(v.notifyMessage); cAutoStart->setChecked(v.autoStart);
        int i = lock->findData(v.autoLockMinutes); lock->setCurrentIndex(i < 0 ? 1 : i);
        int j = font->findData(v.fontScale); font->setCurrentIndex(j < 0 ? 0 : j);
    }
};

// ------------------------------------------------------------------------------------------------
// Trusted identities (pins): alias + full fingerprint so it can be compared over another channel.
// ------------------------------------------------------------------------------------------------
class TrustedDialog : public QDialog {
public:
    TrustedDialog(const QMap<QString, QString> &pins, const QString &myFingerprint, const QString &myAlias, QWidget *parent = nullptr)
        : QDialog(parent) {
        setWindowTitle("Trusted identities");
        setModal(true);
        resize(640, 440);
        auto *root = new QVBoxLayout(this);
        root->setContentsMargins(theme::kS5, theme::kS5, theme::kS5, theme::kS5);
        root->setSpacing(theme::kS3);
        root->addWidget(makeLabel("Trusted identities", "title"));
        root->addWidget(makeLabel("The first identity seen using an alias is remembered (trust on first use). "
                                  "To be sure a person is who they claim, compare the fingerprint with them over another channel.", "muted"));
        root->addWidget(makeLabel("You: " + myAlias + "   fingerprint " + groups(myFingerprint), "muted"));
        table = new QTableWidget(pins.size(), 2, this);
        table->setHorizontalHeaderLabels({ "Alias", "Fingerprint" });
        table->horizontalHeader()->setStretchLastSection(true);
        table->verticalHeader()->hide();
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        int r = 0;
        for (auto it = pins.begin(); it != pins.end(); ++it, ++r) {
            table->setItem(r, 0, new QTableWidgetItem(it.value()));
            const QString fp = it.key();
            auto *item = new QTableWidgetItem(fp.size() == 8 ? fp + "  (short legacy pin)" : groups(fp));
            item->setToolTip(fp);
            table->setItem(r, 1, item);
        }
        table->resizeColumnToContents(0);
        table->setColumnWidth(0, qMax(table->columnWidth(0) + theme::kS5, 150));
        root->addWidget(table, 1);
        if (pins.isEmpty()) root->addWidget(makeLabel("Nobody has been pinned yet.", "muted"));
        auto *row = new QHBoxLayout();
        row->addStretch(1);
        auto *close = makeButton("Close", this, true);
        row->addWidget(close);
        root->addLayout(row);
        connect(close, &QPushButton::clicked, this, &QDialog::accept);
    }
    static QString groups(const QString &fp) {   // "ab12 cd34 ..." in blocks of 4, first 32 hex chars
        QString out;
        const QString f = fp.left(32);
        for (int i = 0; i < f.size(); i += 4) out += f.mid(i, 4) + (i + 4 < f.size() ? " " : "");
        return out;
    }
    QTableWidget *table;
};

// ------------------------------------------------------------------------------------------------
// Help: shortcuts and how the window behaves.
// ------------------------------------------------------------------------------------------------
class HelpDialog : public QDialog {
public:
    explicit HelpDialog(QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("Help");
        setModal(true);
        resize(560, 560);
        auto *root = new QVBoxLayout(this);
        root->setContentsMargins(theme::kS5, theme::kS5, theme::kS5, theme::kS5);
        root->setSpacing(theme::kS3);
        root->addWidget(makeLabel("Help", "title"));
        auto *b = new QTextBrowser(this);
        b->setFrameShape(QFrame::NoFrame);
        b->setHtml(
            "<h3>Keyboard</h3><table cellspacing='6'>"
            "<tr><td><b>Enter</b></td><td>Send the message</td></tr>"
            "<tr><td><b>Esc</b></td><td>Clear the message box; if it is empty, lock the app</td></tr>"
            "<tr><td><b>Ctrl+L</b> or <b>Alt+L</b></td><td>Lock now</td></tr>"
            "<tr><td><b>Ctrl+,</b></td><td>Settings</td></tr>"
            "<tr><td><b>F1</b></td><td>This help</td></tr>"
            "<tr><td><b>Ctrl+Q</b></td><td>Quit</td></tr></table>"
            "<h3>Commands (type in the message box)</h3><table cellspacing='6'>"
            "<tr><td><b>nick NAME</b></td><td>Change your alias</td></tr>"
            "<tr><td><b>who</b></td><td>List people in the room</td></tr>"
            "<tr><td><b>connect</b> / <b>disconnect</b></td><td>Join or leave the relay</td></tr>"
            "<tr><td><b>server HOST[:PORT]</b></td><td>Change the relay</td></tr>"
            "<tr><td><b>passphrase</b></td><td>Change the room passphrase</td></tr>"
            "<tr><td><b>clear</b></td><td>Delete the chat history (asks first)</td></tr></table>"
            "<h3>Closing, minimizing, quitting</h3>"
            "<p><b>Minimize</b> keeps the app running in the taskbar. <b>Close (X)</b> hides the window to the "
            "system tray and keeps you connected, if your system has a tray; without a tray, closing quits. "
            "<b>Menu &gt; Quit</b> (Ctrl+Q) always disconnects and exits.</p>"
            "<h3>What the badges mean</h3>"
            "<p><b>verified</b>: this alias is pinned to this identity. <b>unverified</b>: first time seen. "
            "<b>IMPERSONATION</b>: someone else is using an alias pinned to a different identity; do not trust them.</p>"
            "<p>This is an experimental, unreviewed cryptography project. Do not use it for secrets.</p>");
        root->addWidget(b, 1);
        auto *row = new QHBoxLayout();
        row->addStretch(1);
        auto *close = makeButton("Close", this, true);
        row->addWidget(close);
        root->addLayout(row);
        connect(close, &QPushButton::clicked, this, &QDialog::accept);
    }
};

// ------------------------------------------------------------------------------------------------
// Uninstall confirmation: states exactly what will be deleted. Cancel is the default button.
// ------------------------------------------------------------------------------------------------
class UninstallDialog : public QDialog {
public:
    UninstallDialog(const QString &folder, bool wholeFolder, QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("Uninstall Sönkkökoodi");
        setModal(true);
        setFixedWidth(520);
        const int W = 472;
        auto *root = new QVBoxLayout(this);
        root->setSizeConstraint(QLayout::SetFixedSize);
        root->setContentsMargins(theme::kS5, theme::kS5, theme::kS5, theme::kS5);
        root->setSpacing(theme::kS3);
        root->addWidget(makeLabel("Delete everything?", "title", this, W));
        QString list = "This will permanently delete:\n"
                       "  • your identity key, chat vault, notes and settings\n"
                       "  • the desktop shortcut and the autostart entry\n";
        if (wholeFolder) list += "  • the folder " + folder + " and EVERYTHING inside it\n";
        root->addWidget(makeLabel(list, "warn", this, W));
        if (!wholeFolder)
            root->addWidget(makeLabel("The program files in " + folder + " will NOT be deleted because this folder was "
                                      "not created by the installer. Remove them by hand if you want.", "muted", this, W));
        root->addWidget(makeLabel("This cannot be undone.", "error", this, W));
        auto *row = new QHBoxLayout();
        row->addStretch(1);
        auto *cancel = makeButton("Cancel", this, true);
        auto *erase = makeButton("Delete everything", this, false, true);
        cancel->setDefault(true);
        row->addWidget(erase);
        row->addWidget(cancel);
        root->addLayout(row);
        connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
        connect(erase, &QPushButton::clicked, this, &QDialog::accept);
        cancel->setFocus();
    }
};

} // namespace sk::ui
