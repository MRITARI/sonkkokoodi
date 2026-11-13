// Protocol v2 building blocks (GUI-free, unit tested). See docs/THREAT_MODEL.md.
#pragma once
#include <QByteArray>
#include <QHash>
#include <QList>
#include <QString>

namespace sk {

constexpr int kProtocolVersion = 2;

// Keys derived from the room passphrase. Only holders of the passphrase can produce valid MACs.
struct RoomKeys {
    QByteArray auth;   // 32 bytes: MAC key for HELLO / WELCOME
    QByteArray wrap;   // 32 bytes: mixed into the key-wrapping key
    bool valid() const { return auth.size() == 32 && wrap.size() == 32; }
    void wipe() { auth.fill(0); wrap.fill(0); auth.clear(); wrap.clear(); }
};

// scrypt(N=2^15, r=8, p=1) of the passphrase with a fixed domain-separation salt. Invalid keys on failure.
RoomKeys deriveRoomKeys(const QString &passphrase);
// Rough strength estimate for the setup screen: 0 (weak) .. 3 (good). Length/variety only, not a guarantee.
int passphraseStrength(const QString &p);

QByteArray hmacSha256(const QByteArray &key, const QByteArray &msg);

// HELLO: proves the joiner knows the room passphrase. Binds the ECDH key, a fresh nonce and the identity.
QByteArray helloMac(const RoomKeys &rk, const QByteArray &ecdhPub, const QByteArray &nonce, const QByteArray &senderPub);
bool verifyHelloMac(const RoomKeys &rk, const QByteArray &ecdhPub, const QByteArray &nonce,
                    const QByteArray &senderPub, const QByteArray &mac);

// Key that wraps the group key in a WELCOME: depends on the ephemeral ECDH secret AND the room secret.
QByteArray welcomeKek(const RoomKeys &rk, const QByteArray &ecdhSecret, const QByteArray &joinerEcdhPub,
                      const QByteArray &welcomerEcdhPub, const QByteArray &joinerNonce);

struct WelcomeFields {
    QByteArray target;          // SHA-256 of the joiner's ECDH public key (hex)
    QByteArray welcomerEcdhPub;
    QByteArray iv;
    QByteArray encKey;
    QByteArray joinerNonce;
    QByteArray senderPub;
    int epoch = 0;
    int msgCount = 0;
};
QByteArray welcomeMac(const RoomKeys &rk, const WelcomeFields &f);
bool verifyWelcomeMac(const RoomKeys &rk, const WelcomeFields &f, const QByteArray &mac);

// Two peers that both generated a key (simultaneous join) converge on the key of the LOWER fingerprint.
// Returns true if a self-keyed node should adopt a WELCOME from `senderFp`.
bool adoptWelcomeWhileSelfKeyed(const QString &myFp, const QString &senderFp);

// Sliding-window replay protection keyed by (sender fingerprint, session id) with a signed timestamp.
class ReplayGuard {
public:
    enum Result { Ok, Stale, FromFuture, Replay, Invalid };
    explicit ReplayGuard(qint64 windowMs = 120000, int maxSessions = 256)
        : m_windowMs(windowMs), m_maxSessions(maxSessions) {}
    Result check(const QString &senderFp, const QByteArray &sid, quint64 ctr, qint64 tsMs, qint64 nowMs);
    void clear() { m_sessions.clear(); m_order.clear(); }
    int sessionCount() const { return m_sessions.size(); }

private:
    struct Win { quint64 highest = 0; quint64 bitmap = 0; };   // bit i = (highest - i) seen
    qint64 m_windowMs;
    int m_maxSessions;
    QHash<QByteArray, Win> m_sessions;
    QList<QByteArray> m_order;
};

} // namespace sk
