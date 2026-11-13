#include <QtTest>
#include <QApplication>
#include "sk_dialogs.h"
#include "theme.h"

using namespace sk::ui;

class DialogTests : public QObject {
    Q_OBJECT
    // Regression test for the clipped-text bug: every word-wrapped label must be at least as tall as its
    // text needs at its current width (Qt under-allocates this in nested/fixed-size layouts).
    static void expectNoClippedLabels(QWidget *w, const char *what) {
        QCoreApplication::processEvents();
        for (QLabel *l : w->findChildren<QLabel *>()) {
            if (!l->wordWrap() || l->text().isEmpty() || !l->isVisible()) continue;
            const int need = l->heightForWidth(l->width());
            QVERIFY2(l->height() >= need, qPrintable(QString("%1: label '%2...' is %3px tall but needs %4px")
                                                         .arg(what, l->text().left(30)).arg(l->height()).arg(need)));
        }
    }
private slots:
    void initTestCase() { qApp->setStyleSheet(sk::theme::styleSheet(100)); }

    void setupProblemsAreSpecific() {
        SetupValues ok{ "unlock-password-1", "alice", "chat.example.org:9999", "a long room passphrase" };
        QVERIFY(SetupDialog::problem(ok, "unlock-password-1").isEmpty());
        QVERIFY(SetupDialog::problem({ "short", "alice", "h", "a long room passphrase" }, "short").contains("Password"));
        QVERIFY(SetupDialog::problem(ok, "different-password").contains("do not match"));
        auto bad = ok; bad.alias = "not valid!";
        QVERIFY(SetupDialog::problem(bad, ok.password).contains("Alias"));
        bad = ok; bad.server = "host:99999";
        QVERIFY(SetupDialog::problem(bad, ok.password).contains("Server"));
        bad = ok; bad.room = "short";
        QVERIFY(SetupDialog::problem(bad, ok.password).contains("Room passphrase"));
    }
    void setupCreateButtonFollowsValidity() {
        SetupDialog d;
        d.show();
        QVERIFY(!d.create->isEnabled());
        d.pw->setText("unlock-password-1"); d.pw2->setText("unlock-password-1");
        d.alias->setText("alice"); d.server->setText("127.0.0.1");
        QVERIFY(!d.create->isEnabled());                     // room passphrase missing
        d.room->setText("a long room passphrase");
        QVERIFY(d.create->isEnabled());
        d.pw2->setText("nope");
        QVERIFY(!d.create->isEnabled());
        QVERIFY(d.error->text().contains("do not match"));
        // strength is stated in words, not only by color
        QVERIFY(d.pwStrength->text().startsWith("Strength: "));
    }
    void setupDialogsHaveNoClippedText() {
        SetupDialog s; s.show();
        s.pw->setText("pass1234"); s.pw2->setText("pass1235");           // error line visible
        expectNoClippedLabels(&s, "setup");
        RoomPassphraseDialog r; r.show(); r.edit->setText("short");
        expectNoClippedLabels(&r, "room");
        UninstallDialog u("C:/some/folder", true); u.show();
        expectNoClippedLabels(&u, "uninstall (whole folder)");
        UninstallDialog u2("C:/some/folder", false); u2.show();
        expectNoClippedLabels(&u2, "uninstall (data only)");
        SettingsDialog st(SettingsValues(), true); st.show();
        expectNoClippedLabels(&st, "settings");
        HelpDialog h; h.show();
        expectNoClippedLabels(&h, "help");
        TrustedDialog t({}, "ab", "me"); t.show();
        expectNoClippedLabels(&t, "trusted");
    }
    void largeTextStillFits() {
        qApp->setStyleSheet(sk::theme::styleSheet(150));
        SetupDialog s; s.show();
        s.pw->setText("pass1234"); s.pw2->setText("pass1235");
        expectNoClippedLabels(&s, "setup @150%");
        UninstallDialog u("C:/some/folder", true); u.show();
        expectNoClippedLabels(&u, "uninstall @150%");
        qApp->setStyleSheet(sk::theme::styleSheet(100));
    }
    void uninstallDefaultsToCancelAndNamesThePath() {
        UninstallDialog d("C:/Users/x/AppData/Local/Sonkkokoodi", true);
        d.show();
        bool namesPath = false;
        for (QLabel *l : d.findChildren<QLabel *>()) if (l->text().contains("C:/Users/x/AppData/Local/Sonkkokoodi")) namesPath = true;
        QVERIFY(namesPath);
        QPushButton *def = nullptr;
        for (QPushButton *b : d.findChildren<QPushButton *>()) if (b->isDefault()) def = b;
        QVERIFY(def);
        QCOMPARE(def->text(), QString("Cancel"));            // Enter must never confirm a deletion
    }
    void uninstallDataOnlyVariantSaysFilesRemain() {
        UninstallDialog d("C:/Users/x/Downloads", false);
        QString all;
        for (QLabel *l : d.findChildren<QLabel *>()) all += l->text() + "\n";
        QVERIFY(all.contains("will NOT be deleted"));
        QVERIFY(!all.contains("EVERYTHING"));
    }
    void settingsCancelAndRestoreDefaults() {
        SettingsValues v; v.notifyMessage = true; v.autoLockMinutes = 15; v.fontScale = 150;
        SettingsDialog d(v, true);
        QCOMPARE(d.values().autoLockMinutes, 15);
        QCOMPARE(d.values().fontScale, 150);
        QVERIFY(d.values().notifyMessage);
        // Restore defaults only changes the controls (Cancel still discards)
        QTest::mouseClick(d.findChildren<QPushButton *>().at(1), Qt::LeftButton);
        QCOMPARE(d.values().fontScale, 100);
        QCOMPARE(d.values().autoLockMinutes, 5);
        QVERIFY(!d.values().notifyMessage);
        QVERIFY(!d.uninstallRequested);
    }
    void trustedShowsFullFingerprintAsTooltip() {
        const QString fp = QString(64, 'a');
        TrustedDialog d({ { fp, "bob" } }, QString(64, 'b'), "alice");
        QCOMPARE(d.table->rowCount(), 1);
        QCOMPARE(d.table->item(0, 0)->text(), QString("bob"));
        QCOMPARE(d.table->item(0, 1)->toolTip(), fp);
    }
};

QTEST_MAIN(DialogTests)
#include "test_dialogs.moc"
