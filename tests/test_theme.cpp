#include <QtTest>
#include "theme.h"
using namespace sk::theme;

class ThemeTests : public QObject {
    Q_OBJECT
private slots:
    void contrastMathIsRight() {
        QCOMPARE(qRound(contrastRatio(QColor("#000000"), QColor("#FFFFFF")) * 10), 210);   // 21:1
        QCOMPARE(qRound(contrastRatio(QColor("#777777"), QColor("#777777")) * 10), 10);    // 1:1
    }
    // Accessibility requirement: every text/background pair that the UI uses must reach 4.5:1.
    void textMeetsAA_data() {
        QTest::addColumn<QString>("fg");
        QTest::addColumn<QString>("bg");
        const char *backgrounds[] = { kBg, kSurface, kSurface2 };
        const char *foregrounds[] = { kText, kTextMuted, kAccent, kSuccess, kWarning, kError };
        for (const char *b : backgrounds)
            for (const char *f : foregrounds)
                QTest::newRow(qPrintable(QString("%1 on %2").arg(f, b))) << f << b;
        QTest::newRow("on-accent text on accent button") << kOnAccent << kAccent;
        // banners use dedicated dark tints behind the same text colors
        QTest::newRow("text on error banner") << kText << "#3A1F22";
        QTest::newRow("text on warning banner") << kText << "#38301A";
        QTest::newRow("error on error banner") << kError << "#3A1F22";
        QTest::newRow("warning on warning banner") << kWarning << "#38301A";
    }
    void textMeetsAA() {
        QFETCH(QString, fg);
        QFETCH(QString, bg);
        const double r = contrastRatio(QColor(fg), QColor(bg));
        QVERIFY2(r >= 4.5, qPrintable(QString("contrast %1 < 4.5").arg(r)));
    }
    void stylesheetHasNoUnresolvedPlaceholders() {
        const QString q = styleSheet(100);
        QVERIFY(!q.contains('%'));
        QVERIFY(q.contains(kAccent));
    }
    void fontScales() {
        QVERIFY(styleSheet(100).contains("font-size: 14px"));
        QVERIFY(styleSheet(150).contains("font-size: 21px"));
        QVERIFY(styleSheet(50).contains("font-size: 11px"));   // never below a readable floor
    }
};

QTEST_MAIN(ThemeTests)
#include "test_theme.moc"
