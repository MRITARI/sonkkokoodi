// Input validation shared by the UI and the network code (unit tested in tests/test_protocol.cpp).
#pragma once
#include <QString>
#include <QChar>

// --- Alias helpers ---
inline bool isValidNick(const QString &n) {
    if (n.isEmpty() || n.size() > 24) return false;
    for (QChar c : n) {
        if (!(c.isLetterOrNumber() || c == QLatin1Char('_') || c == QLatin1Char('-') || c == QLatin1Char('.')))
            return false;
    }
    return true;
}

// "Skeleton" of an alias used to detect look-alikes: Unicode-decomposed, diacritics and punctuation removed,
// case-folded, and common visually confusable letters (Cyrillic/Greek homoglyphs, 0/o, 1/l/i) mapped together.
// Two aliases with the same skeleton are treated as the same name for spoof detection.
inline QString normNick(const QString &n) {
    static const struct { ushort from; QChar to; } map[] = {
        {0x0430, 'a'}, {0x0435, 'e'}, {0x043E, 'o'}, {0x0440, 'p'}, {0x0441, 'c'}, {0x0445, 'x'}, {0x0443, 'y'},
        {0x0456, 'l'}, {0x0458, 'j'}, {0x0455, 's'}, {0x0501, 'd'}, {0x04BB, 'h'}, {0x051B, 'q'}, {0x051D, 'w'},
        {0x03BF, 'o'}, {0x03B1, 'a'}, {0x03BD, 'v'}, {0x03B9, 'l'}, {0x03C1, 'p'}, {0x03C5, 'u'},
        {0x0131, 'l'}, {0x0142, 'l'},
    };
    QString out;
    for (QChar c : n.normalized(QString::NormalizationForm_KD)) {
        if (c.category() == QChar::Mark_NonSpacing) continue;      // combining accents
        if (!c.isLetterOrNumber()) continue;
        QChar f = c.toCaseFolded();
        for (const auto &m : map) if (f.unicode() == m.from) { f = m.to; break; }
        if (f == QLatin1Char('0')) f = QLatin1Char('o');
        else if (f == QLatin1Char('1') || f == QLatin1Char('i')) f = QLatin1Char('l');
        out += f;
    }
    return out;
}

// "host" or "host:port". portGiven tells whether a port was part of the text.
inline bool parseEndpoint(const QString &text, QString &host, int &port, bool &portGiven) {
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

