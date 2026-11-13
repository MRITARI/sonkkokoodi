#include "sk_protocol.h"
#include "sk_crypto.h"
#include <QMessageAuthenticationCode>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

namespace sk {

RoomKeys deriveRoomKeys(const QString &passphrase) {
    RoomKeys rk;
    const QByteArray pass = passphrase.toUtf8();
    if (pass.isEmpty()) return rk;
    const QByteArray salt = "sonkkokoodi-room-v2";
    uint64_t n = 1u << 15;
    uint32_t r = 8, p = 1;
    uint64_t maxmem = 128ull * 1024 * 1024;

    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "SCRYPT", nullptr);
    if (!kdf) return rk;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return rk;

    QByteArray out(64, '\0');
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<char *>(pass.constData()), size_t(pass.size())),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<char *>(salt.constData()), size_t(salt.size())),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &p),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem),
        OSSL_PARAM_construct_end()
    };
    const bool ok = EVP_KDF_derive(ctx, reinterpret_cast<unsigned char *>(out.data()), size_t(out.size()), params) == 1;
    EVP_KDF_CTX_free(ctx);
    if (!ok) return rk;
    rk.auth = out.left(32);
    rk.wrap = out.mid(32, 32);
    out.fill(0);
    return rk;
}

int passphraseStrength(const QString &p) {
    if (p.size() < 8) return 0;
    int classes = 0;
    bool lo = false, up = false, dg = false, sy = false;
    for (QChar c : p) {
        if (c.isLower()) lo = true; else if (c.isUpper()) up = true;
        else if (c.isDigit()) dg = true; else sy = true;
    }
    classes = int(lo) + int(up) + int(dg) + int(sy);
    if (p.size() >= 20 || (p.size() >= 14 && classes >= 3)) return 3;
    if (p.size() >= 12 || (p.size() >= 10 && classes >= 3)) return 2;
    return 1;
}

QByteArray hmacSha256(const QByteArray &key, const QByteArray &msg) {
    return QMessageAuthenticationCode::hash(msg, key, QCryptographicHash::Sha256);
}

// Length-prefixed concatenation so field boundaries cannot be shifted.
static QByteArray lp(const QByteArray &b) {
    QByteArray n(4, '\0');
    const quint32 len = quint32(b.size());
    for (int i = 0; i < 4; ++i) n[i] = char((len >> (24 - 8 * i)) & 0xff);
    return n + b;
}

QByteArray helloMac(const RoomKeys &rk, const QByteArray &ecdhPub, const QByteArray &nonce, const QByteArray &senderPub) {
    if (!rk.valid()) return QByteArray();
    return hmacSha256(rk.auth, lp("sk2-hello") + lp(ecdhPub) + lp(nonce) + lp(senderPub));
}

bool verifyHelloMac(const RoomKeys &rk, const QByteArray &ecdhPub, const QByteArray &nonce,
                    const QByteArray &senderPub, const QByteArray &mac) {
    if (!rk.valid() || nonce.size() != 16 || mac.size() != 32) return false;
    return constTimeEqual(helloMac(rk, ecdhPub, nonce, senderPub), mac);
}

QByteArray welcomeKek(const RoomKeys &rk, const QByteArray &ecdhSecret, const QByteArray &joinerEcdhPub,
                      const QByteArray &welcomerEcdhPub, const QByteArray &joinerNonce) {
    if (!rk.valid() || ecdhSecret.isEmpty()) return QByteArray();
    return hmacSha256(rk.wrap, lp("sk2-kek") + lp(ecdhSecret) + lp(joinerEcdhPub) + lp(welcomerEcdhPub) + lp(joinerNonce));
}

QByteArray welcomeMac(const RoomKeys &rk, const WelcomeFields &f) {
    if (!rk.valid()) return QByteArray();
    QByteArray n(8, '\0');
    n[0] = char((f.epoch >> 24) & 0xff); n[1] = char((f.epoch >> 16) & 0xff);
    n[2] = char((f.epoch >> 8) & 0xff);  n[3] = char(f.epoch & 0xff);
    n[4] = char((f.msgCount >> 24) & 0xff); n[5] = char((f.msgCount >> 16) & 0xff);
    n[6] = char((f.msgCount >> 8) & 0xff);  n[7] = char(f.msgCount & 0xff);
    return hmacSha256(rk.auth, lp("sk2-welcome") + lp(f.target) + lp(f.welcomerEcdhPub) + lp(f.iv) + lp(f.encKey)
                                   + lp(f.joinerNonce) + lp(f.senderPub) + lp(n));
}

bool verifyWelcomeMac(const RoomKeys &rk, const WelcomeFields &f, const QByteArray &mac) {
    if (!rk.valid() || mac.size() != 32) return false;
    return constTimeEqual(welcomeMac(rk, f), mac);
}

bool adoptWelcomeWhileSelfKeyed(const QString &myFp, const QString &senderFp) {
    return !myFp.isEmpty() && !senderFp.isEmpty() && senderFp < myFp;
}

ReplayGuard::Result ReplayGuard::check(const QString &senderFp, const QByteArray &sid, quint64 ctr, qint64 tsMs, qint64 nowMs) {
    if (sid.size() != 8 || ctr == 0 || senderFp.isEmpty()) return Invalid;
    if (tsMs < nowMs - m_windowMs) return Stale;
    if (tsMs > nowMs + m_windowMs) return FromFuture;

    const QByteArray key = senderFp.toLatin1() + ':' + sid;
    auto it = m_sessions.find(key);
    if (it == m_sessions.end()) {
        if (m_sessions.size() >= m_maxSessions && !m_order.isEmpty()) m_sessions.remove(m_order.takeFirst());
        Win w; w.highest = ctr; w.bitmap = 1;
        m_sessions.insert(key, w);
        m_order.append(key);
        return Ok;
    }
    Win &w = it.value();
    if (ctr > w.highest) {
        const quint64 shift = ctr - w.highest;
        w.bitmap = shift >= 64 ? 0 : (w.bitmap << shift);
        w.bitmap |= 1;
        w.highest = ctr;
        return Ok;
    }
    const quint64 back = w.highest - ctr;
    if (back >= 64) return Replay;                 // older than the window: cannot be proven fresh
    const quint64 bit = quint64(1) << back;
    if (w.bitmap & bit) return Replay;
    w.bitmap |= bit;
    return Ok;
}

} // namespace sk
