#include <QtTest>
#include "sk_protocol.h"
#include "sk_crypto.h"

using namespace sk;

class ProtocolTests : public QObject {
    Q_OBJECT
private slots:
    void roomKeysDeterministicAndPassphraseSensitive() {
        RoomKeys a = deriveRoomKeys("correct horse battery staple");
        RoomKeys b = deriveRoomKeys("correct horse battery staple");
        RoomKeys c = deriveRoomKeys("correct horse battery stapl3");
        QVERIFY(a.valid() && b.valid() && c.valid());
        QCOMPARE(a.auth, b.auth);
        QCOMPARE(a.wrap, b.wrap);
        QVERIFY(a.auth != c.auth);
        QVERIFY(a.auth != a.wrap);
        QVERIFY(!deriveRoomKeys(QString()).valid());
    }
    void helloMacBindsEveryField() {
        RoomKeys rk = deriveRoomKeys("pass-one-1234");
        RoomKeys other = deriveRoomKeys("pass-two-1234");
        QByteArray ecdh = "ecdh-pub", nonce(16, 'n'), pub = "identity-pub";
        QByteArray mac = helloMac(rk, ecdh, nonce, pub);
        QVERIFY(verifyHelloMac(rk, ecdh, nonce, pub, mac));
        QVERIFY(!verifyHelloMac(other, ecdh, nonce, pub, mac));              // wrong passphrase
        QVERIFY(!verifyHelloMac(rk, "ecdh-pug", nonce, pub, mac));           // swapped ECDH key
        QVERIFY(!verifyHelloMac(rk, ecdh, QByteArray(16, 'm'), pub, mac));   // other nonce
        QVERIFY(!verifyHelloMac(rk, ecdh, nonce, "someone-else", mac));      // other identity
        QVERIFY(!verifyHelloMac(rk, ecdh, nonce, pub, QByteArray()));
        QVERIFY(!verifyHelloMac(rk, ecdh, nonce, pub, mac.left(31)));
        QVERIFY(!verifyHelloMac(rk, ecdh, QByteArray(8, 'n'), pub, mac));    // short nonce
        QVERIFY(!verifyHelloMac(RoomKeys(), ecdh, nonce, pub, mac));
    }
    void lengthPrefixPreventsFieldShifting() {
        RoomKeys rk = deriveRoomKeys("pass-one-1234");
        // "ab"+"c" must not authenticate as "a"+"bc"
        QVERIFY(helloMac(rk, "ab", QByteArray(16, 'x'), "c") != helloMac(rk, "a", QByteArray(16, 'x'), "bc"));
    }
    void welcomeMacBindsEveryField() {
        RoomKeys rk = deriveRoomKeys("pass-one-1234");
        WelcomeFields f;
        f.target = "t"; f.welcomerEcdhPub = "w"; f.iv = "iv"; f.encKey = "ek"; f.joinerNonce = QByteArray(16, 'n');
        f.senderPub = "sp"; f.epoch = 3; f.msgCount = 7;
        QByteArray mac = welcomeMac(rk, f);
        QVERIFY(verifyWelcomeMac(rk, f, mac));
        auto mutated = [&](auto fn) { WelcomeFields g = f; fn(g); return verifyWelcomeMac(rk, g, mac); };
        QVERIFY(!mutated([](WelcomeFields &g) { g.target = "x"; }));
        QVERIFY(!mutated([](WelcomeFields &g) { g.welcomerEcdhPub = "x"; }));
        QVERIFY(!mutated([](WelcomeFields &g) { g.iv = "x"; }));
        QVERIFY(!mutated([](WelcomeFields &g) { g.encKey = "x"; }));
        QVERIFY(!mutated([](WelcomeFields &g) { g.joinerNonce = QByteArray(16, 'z'); }));
        QVERIFY(!mutated([](WelcomeFields &g) { g.senderPub = "x"; }));
        QVERIFY(!mutated([](WelcomeFields &g) { g.epoch = 4; }));
        QVERIFY(!mutated([](WelcomeFields &g) { g.msgCount = 8; }));
        QVERIFY(!verifyWelcomeMac(deriveRoomKeys("pass-two-1234"), f, mac));
    }
    // End-to-end: member delivers a group key to a joiner; an attacker without the passphrase cannot.
    void keyDeliveryEndToEnd() {
        RoomKeys room = deriveRoomKeys("shared room passphrase");
        RoomKeys attackerGuess = deriveRoomKeys("wrong guess 123");
        QByteArray groupKey(32, 'G');

        PkeyPtr identJ(generateP256Key()), identM(generateP256Key()), eJ(generateP256Key()), eM(generateP256Key());
        QByteArray nonceJ(16, 'N');
        QByteArray eJpub = pkeyToDER(eJ.get()), eMpub = pkeyToDER(eM.get());

        // joiner HELLO -> member verifies
        QByteArray hmac = helloMac(room, eJpub, nonceJ, pkeyToDER(identJ.get()));
        QVERIFY(verifyHelloMac(room, eJpub, nonceJ, pkeyToDER(identJ.get()), hmac));
        // attacker without the passphrase cannot solicit a key
        QByteArray forged = helloMac(attackerGuess, eJpub, nonceJ, pkeyToDER(identJ.get()));
        QVERIFY(!verifyHelloMac(room, eJpub, nonceJ, pkeyToDER(identJ.get()), forged));

        // member builds WELCOME
        QByteArray secretM = deriveSharedSecret(eM.get(), PkeyPtr(derToPkey(eJpub)).get());
        QByteArray kekM = welcomeKek(room, secretM, eJpub, eMpub, nonceJ);
        QByteArray iv;
        QByteArray enc = encryptGCM(groupKey, kekM, iv);
        WelcomeFields f;
        f.target = "tgt"; f.welcomerEcdhPub = eMpub; f.iv = iv; f.encKey = enc; f.joinerNonce = nonceJ;
        f.senderPub = pkeyToDER(identM.get()); f.epoch = 1; f.msgCount = 2;
        QByteArray wmac = welcomeMac(room, f);

        // joiner verifies and decrypts
        QVERIFY(verifyWelcomeMac(room, f, wmac));
        QByteArray secretJ = deriveSharedSecret(eJ.get(), PkeyPtr(derToPkey(eMpub)).get());
        QByteArray kekJ = welcomeKek(room, secretJ, eJpub, eMpub, nonceJ);
        bool ok = false;
        QCOMPARE(decryptGCM(enc, kekJ, iv, &ok), groupKey);
        QVERIFY(ok);

        // an attacker who forged a WELCOME with its own room guess is rejected by the joiner
        QVERIFY(!verifyWelcomeMac(room, f, welcomeMac(attackerGuess, f)));
        // even knowing the ECDH secret, the wrong room secret yields a different KEK
        QVERIFY(welcomeKek(attackerGuess, secretJ, eJpub, eMpub, nonceJ) != kekJ);
    }
    void tieBreakIsAntisymmetric() {
        QString a = "0aaa", b = "0bbb";
        QVERIFY(adoptWelcomeWhileSelfKeyed(b, a));    // higher adopts lower's key
        QVERIFY(!adoptWelcomeWhileSelfKeyed(a, b));   // lower keeps its own
        QVERIFY(!adoptWelcomeWhileSelfKeyed(a, a));
        QVERIFY(!adoptWelcomeWhileSelfKeyed(QString(), a));
    }
    void replayGuardBasics() {
        ReplayGuard g;
        const qint64 now = 1000000;
        QByteArray sid(8, 's');
        QCOMPARE(g.check("fp", sid, 1, now, now), ReplayGuard::Ok);
        QCOMPARE(g.check("fp", sid, 1, now, now), ReplayGuard::Replay);
        QCOMPARE(g.check("fp", sid, 3, now, now), ReplayGuard::Ok);
        QCOMPARE(g.check("fp", sid, 2, now, now), ReplayGuard::Ok);       // late but unseen, inside window
        QCOMPARE(g.check("fp", sid, 2, now, now), ReplayGuard::Replay);
        QCOMPARE(g.check("fp", sid, 3, now, now), ReplayGuard::Replay);
        QCOMPARE(g.check("other", sid, 1, now, now), ReplayGuard::Ok);    // independent per sender
        QCOMPARE(g.check("fp", QByteArray(8, 't'), 1, now, now), ReplayGuard::Ok);   // independent per session
    }
    void replayGuardWindowAndTime() {
        ReplayGuard g(1000);
        const qint64 now = 5000000;
        QByteArray sid(8, 's');
        QCOMPARE(g.check("fp", sid, 100, now, now), ReplayGuard::Ok);
        QCOMPARE(g.check("fp", sid, 30, now, now), ReplayGuard::Replay);              // >63 behind: refused
        QCOMPARE(g.check("fp", sid, 101, now - 1001, now), ReplayGuard::Stale);
        QCOMPARE(g.check("fp", sid, 102, now + 1001, now), ReplayGuard::FromFuture);
        QCOMPARE(g.check("fp", sid, 0, now, now), ReplayGuard::Invalid);
        QCOMPARE(g.check("fp", QByteArray(3, 's'), 5, now, now), ReplayGuard::Invalid);
        QCOMPARE(g.check("", sid, 5, now, now), ReplayGuard::Invalid);
        QCOMPARE(g.check("fp", sid, 100 + 64, now, now), ReplayGuard::Ok);            // big jump clears the bitmap
        QCOMPARE(g.check("fp", sid, 100, now, now), ReplayGuard::Replay);             // 64 behind now
        QCOMPARE(g.check("fp", sid, 101 + 60, now, now), ReplayGuard::Ok);            // 3 behind, unseen
    }
    void replayGuardIsBounded() {
        ReplayGuard g(120000, 8);
        for (int i = 0; i < 100; ++i)
            QCOMPARE(g.check(QString::number(i), QByteArray(8, 'x'), 1, 10, 10), ReplayGuard::Ok);
        QVERIFY(g.sessionCount() <= 8);
    }
    void strengthHint() {
        QCOMPARE(passphraseStrength("short"), 0);
        QVERIFY(passphraseStrength("password") <= 1);
        QCOMPARE(passphraseStrength("correct horse battery staple"), 3);
    }
};

QTEST_APPLESS_MAIN(ProtocolTests)
#include "test_protocol.moc"
