// The one place that defines how Sönkkökoodi looks: palette, spacing scale, font and the single stylesheet.
// No widget sets its own colors; it uses objectName / dynamic properties that this stylesheet targets.
#pragma once
#include <QColor>
#include <QString>
#include <algorithm>
#include <cmath>

namespace sk::theme {

// ---- Palette: calm dark neutrals, ONE accent, semantic colors only for status ----
inline constexpr const char *kBg        = "#14161A";   // window
inline constexpr const char *kSurface   = "#1B1E24";   // inputs, cards
inline constexpr const char *kSurface2  = "#242831";   // buttons, hover
inline constexpr const char *kBorder    = "#363C48";
inline constexpr const char *kText      = "#E7E9EE";
inline constexpr const char *kTextMuted = "#A4ABB8";
inline constexpr const char *kAccent    = "#6CB0FF";   // the single accent
inline constexpr const char *kOnAccent  = "#0B1220";   // text drawn on the accent
inline constexpr const char *kSuccess   = "#52C98F";
inline constexpr const char *kWarning   = "#E8B94F";
inline constexpr const char *kError     = "#F48A83";

// ---- Spacing scale (px) ----
inline constexpr int kS1 = 4, kS2 = 8, kS3 = 12, kS4 = 16, kS5 = 24;
inline constexpr int kRadius = 6;

inline constexpr const char *kFontFamily = "Segoe UI";   // single family; Qt falls back to the platform sans
inline constexpr int kBaseFontPx = 14;

// ---- WCAG contrast ----
inline double luminance(const QColor &c) {
    auto ch = [](double v) { v /= 255.0; return v <= 0.03928 ? v / 12.92 : std::pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * ch(c.red()) + 0.7152 * ch(c.green()) + 0.0722 * ch(c.blue());
}
inline double contrastRatio(const QColor &a, const QColor &b) {
    const double la = luminance(a), lb = luminance(b);
    return (std::max(la, lb) + 0.05) / (std::min(la, lb) + 0.05);
}

// fontScalePercent: 100..200 (user setting). Returns the application-wide stylesheet.
inline QString styleSheet(int fontScalePercent = 100) {
    const int px = std::max(11, kBaseFontPx * fontScalePercent / 100);
    QString q = QStringLiteral(R"(
* { font-family: "%FONT%", sans-serif; font-size: %PX%px; }
QWidget { background-color: %BG%; color: %TEXT%; }
QMainWindow, QDialog { background-color: %BG%; }
QLabel { background: transparent; }
QLabel[role="title"] { font-size: %TITLE%px; font-weight: 600; }
QLabel[role="muted"] { color: %MUTED%; }
QLabel[role="error"] { color: %ERROR%; }
QLabel[role="ok"] { color: %SUCCESS%; }
QLabel[role="warn"] { color: %WARNING%; }

QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QTableWidget, QListWidget {
    background-color: %SURFACE%; border: 1px solid %BORDER%; border-radius: %R%px; padding: %S2%px %S3%px;
    selection-background-color: %ACCENT%; selection-color: %ONACCENT%;
}
QTextEdit#chatView { border: none; padding: %S2%px %S4%px; }
QLineEdit:focus, QTextEdit:focus, QComboBox:focus { border: 1px solid %ACCENT%; }
QLineEdit:disabled { color: %MUTED%; }
QComboBox::drop-down { border: none; width: %S5%px; }
QComboBox QAbstractItemView { background-color: %SURFACE%; border: 1px solid %BORDER%; selection-background-color: %SURFACE2%; selection-color: %TEXT%; }
QHeaderView::section { background-color: %SURFACE%; color: %MUTED%; border: none; border-bottom: 1px solid %BORDER%; padding: %S2%px; }
QTableWidget { gridline-color: %BORDER%; }

QPushButton { background-color: %SURFACE2%; border: 1px solid %BORDER%; border-radius: %R%px; padding: %S2%px %S4%px; }
QPushButton:hover { border-color: %MUTED%; }
QPushButton:focus { border: 1px solid %ACCENT%; }
QPushButton:disabled { color: %MUTED%; background-color: %SURFACE%; }
QPushButton[primary="true"] { background-color: %ACCENT%; color: %ONACCENT%; border: 1px solid %ACCENT%; font-weight: 600; }
QPushButton[primary="true"]:disabled { background-color: %SURFACE2%; color: %MUTED%; border-color: %BORDER%; }
QPushButton[danger="true"] { color: %ERROR%; border-color: %ERROR%; }
QPushButton[flat="true"] { background: transparent; border: none; color: %MUTED%; padding: %S1%px %S2%px; }
QPushButton[flat="true"]:hover { color: %TEXT%; }

QCheckBox { spacing: %S2%px; padding: %S1%px 0; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid %MUTED%; border-radius: 3px; background: %SURFACE%; }
QCheckBox::indicator:checked { background: %ACCENT%; border-color: %ACCENT%; }
QCheckBox:focus { color: %ACCENT%; }

QMenuBar { background-color: %BG%; border-bottom: 1px solid %BORDER%; }
QMenuBar::item { padding: %S2%px %S3%px; background: transparent; }
QMenuBar::item:selected { background: %SURFACE2%; }
QMenu { background-color: %SURFACE%; border: 1px solid %BORDER%; padding: %S1%px; }
QMenu::item { padding: %S2%px %S5%px %S2%px %S3%px; }
QMenu::item:selected { background-color: %SURFACE2%; }
QMenu::separator { height: 1px; background: %BORDER%; margin: %S1%px %S2%px; }

QStatusBar { background-color: %BG%; border-top: 1px solid %BORDER%; }
QStatusBar::item { border: none; }
QLabel#statusChip { padding: 2px %S3%px; border: 1px solid %BORDER%; border-radius: 10px; }
QLabel#statusChip[state="secure"] { color: %SUCCESS%; border-color: %SUCCESS%; }
QLabel#statusChip[state="working"] { color: %WARNING%; border-color: %WARNING%; }
QLabel#statusChip[state="off"] { color: %MUTED%; }

QFrame#banner { border: none; border-bottom: 1px solid %BORDER%; }
QFrame#banner[level="error"] { background-color: #3A1F22; border-bottom: 2px solid %ERROR%; }
QFrame#banner[level="warning"] { background-color: #38301A; border-bottom: 2px solid %WARNING%; }
QFrame#banner QLabel { background: transparent; }
QFrame#card { background-color: %SURFACE%; border: 1px solid %BORDER%; border-radius: %S2%px; }
QFrame#card QLabel { background: transparent; }

QProgressBar { background-color: %SURFACE%; border: 1px solid %BORDER%; border-radius: %R%px; text-align: center; padding: 1px; }
QProgressBar::chunk { background-color: %ACCENT%; border-radius: 4px; }

QToolTip { background-color: %SURFACE2%; color: %TEXT%; border: 1px solid %BORDER%; padding: %S1%px; }
QScrollBar:vertical { background: %BG%; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: %BORDER%; border-radius: 5px; min-height: 24px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
)");
    const QString rep[][2] = {
        {"%FONT%", kFontFamily}, {"%PX%", QString::number(px)}, {"%TITLE%", QString::number(px * 3 / 2)},
        {"%BG%", kBg}, {"%SURFACE2%", kSurface2}, {"%SURFACE%", kSurface}, {"%BORDER%", kBorder},
        {"%TEXT%", kText}, {"%MUTED%", kTextMuted}, {"%ONACCENT%", kOnAccent}, {"%ACCENT%", kAccent},
        {"%SUCCESS%", kSuccess}, {"%WARNING%", kWarning}, {"%ERROR%", kError},
        {"%R%", QString::number(kRadius)}, {"%S1%", QString::number(kS1)}, {"%S2%", QString::number(kS2)},
        {"%S3%", QString::number(kS3)}, {"%S4%", QString::number(kS4)}, {"%S5%", QString::number(kS5)},
    };
    for (const auto &r : rep) q.replace(r[0], r[1]);
    return q;
}

} // namespace sk::theme
