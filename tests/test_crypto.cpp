#include <QtTest>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include "sk_crypto.h"

using namespace sk;

class CryptoTests : public QObject {
    Q_OBJECT
private slots:
    void gcmRoundTrip() {
        QByteArray key(32, 'k'), iv;
        QByteArray pt = "hello \xc3\xb6 world";
        QByteArray ct = encryptGCM(pt, key, iv);
        QCOMPARE(iv.size(), 12);
        QCOMPARE(ct.size(), pt.size() + 16);
        bool ok = false;
        QCOMPARE(decryptGCM(ct, key, iv, &ok), pt);
        QVERIFY(ok);
    }
    void gcmEmptyPlaintextIsValid() {
        QByteArray key(32, 'k'), iv;
        QByteArray ct = encryptGCM(QByteArray(), key, iv);
        bool ok = false;
        QVERIFY(decryptGCM(ct, key, iv, &ok).isEmpty());
        QVERIFY(ok);
    }
    void gcmFreshIvEachTime() {
        QByteArray key(32, 'k'), a, b;
        encryptGCM("x", key, a);
        encryptGCM("x", key, b);
        QVERIFY(a != b);
    }
    void gcmRejectsTamperingAndWrongInputs() {
        QByteArray key(32, 'k'), iv;
        QByteArray ct = encryptGCM("secret message", key, iv);
        bool ok = true;
        for (int i = 0; i < ct.size(); ++i) {           // flip every single byte
            QByteArray bad = ct;
            bad[i] = char(bad[i] ^ 1);
            decryptGCM(bad, key, iv, &ok);
            QVERIFY2(!ok, "tampered ciphertext accepted");
        }
        decryptGCM(ct, QByteArray(32, 'z'), iv, &ok);   QVERIFY(!ok);   // wrong key
        QByteArray badIv = iv; badIv[0] = char(badIv[0] ^ 1);
        decryptGCM(ct, key, badIv, &ok);                QVERIFY(!ok);   // wrong iv
        decryptGCM(ct.left(10), key, iv, &ok);          QVERIFY(!ok);   // truncated below tag size
        decryptGCM(QByteArray(), key, iv, &ok);         QVERIFY(!ok);
        decryptGCM(ct, QByteArray(16, 'k'), iv, &ok);   QVERIFY(!ok);   // wrong key length
        QByteArray dummy;
        QVERIFY(encryptGCM("x", QByteArray(16, 'k'), dummy).isEmpty());
        QVERIFY(dummy.isEmpty());
    }
    void pbkdf2Behaviour() {
        QByteArray salt(16, 's');
        QByteArray a = pbkdf2("password", salt, 2000);
        QCOMPARE(a.size(), 32);
        QCOMPARE(pbkdf2("password", salt, 2000), a);
        QVERIFY(pbkdf2("passwore", salt, 2000) != a);
        QVERIFY(pbkdf2("password", QByteArray(16, 't'), 2000) != a);
        QVERIFY(pbkdf2("password", salt, 2001) != a);
        // known answer computed independently with Python hashlib.pbkdf2_hmac
        QCOMPARE(pbkdf2("password", QByteArray("0123456789abcdef"), 1000).toHex(), QByteArray("8514638175a45bc45eb1f22f04ff7d27f4f8be480498c455ff4b494ce8d1e7d2"));
    }
    void pbkdf2RejectsWeakParameters() {
        QVERIFY(pbkdf2("pw", QByteArray(8, 's'), 2000).isEmpty());   // salt too short
        QVERIFY(pbkdf2("pw", QByteArray(16, 's'), 10).isEmpty());    // too few iterations
    }
    void signVerify() {
        PkeyPtr k(generateP256Key());
        QVERIFY(k);
        QByteArray msg = "payload";
        QByteArray sig = sign(msg, k.get());
        QVERIFY(!sig.isEmpty());
        QVERIFY(verify(msg, sig, k.get()));
        QVERIFY(!verify("payloae", sig, k.get()));
        QByteArray bad = sig; bad[bad.size() - 1] = char(bad[bad.size() - 1] ^ 1);
        QVERIFY(!verify(msg, bad, k.get()));
        PkeyPtr other(generateP256Key());
        QVERIFY(!verify(msg, sig, other.get()));
        QVERIFY(!verify(msg, QByteArray(), k.get()));
        QVERIFY(!verify(msg, sig, nullptr));
    }
    void derRoundTripAndValidation() {
        PkeyPtr k(generateP256Key());
        QByteArray der = pkeyToDER(k.get());
        PkeyPtr back(derToPkey(der));
        QVERIFY(back);
        QCOMPARE(pkeyToDER(back.get()), der);
        QVERIFY(!derToPkey(QByteArray()));
        QVERIFY(!derToPkey(QByteArray("garbage not der")));
        QVERIFY(!derToPkey(der.left(der.size() - 3)));                  // truncated
        QVERIFY(!derToPkey(der + QByteArray("x")));                     // trailing bytes
        QVERIFY(!derToPkey(QByteArray(2000, 'a')));                     // oversize
    }
    void derRejectsOtherCurves() {
        for (int nid : { NID_secp384r1, NID_secp256k1 }) {
            EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            EVP_PKEY_keygen_init(c);
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, nid);
            EVP_PKEY *raw = nullptr;
            QVERIFY(EVP_PKEY_keygen(c, &raw) > 0);
            EVP_PKEY_CTX_free(c);
            PkeyPtr k(raw);
            QVERIFY2(!derToPkey(pkeyToDER(k.get())), "non-P-256 curve accepted");
        }
    }
    void privatePemRoundTrip() {
        PkeyPtr k(generateP256Key());
        QByteArray pem = privKeyToPEM(k.get());
        PkeyPtr back(pemToPrivKey(pem));
        QVERIFY(back);
        QCOMPARE(pkeyToDER(back.get()), pkeyToDER(k.get()));
        QVERIFY(!pemToPrivKey("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"));
        QVERIFY(!pemToPrivKey(QByteArray()));
    }
    void ecdhAgrees() {
        PkeyPtr a(generateP256Key()), b(generateP256Key()), c(generateP256Key());
        QByteArray ab = deriveSharedSecret(a.get(), b.get());
        QByteArray ba = deriveSharedSecret(b.get(), a.get());
        QCOMPARE(ab.size(), 32);
        QCOMPARE(ab, ba);
        QVERIFY(deriveSharedSecret(a.get(), c.get()) != ab);
        QVERIFY(deriveSharedSecret(nullptr, b.get()).isEmpty());
    }
    void ratchetIsDeterministicAndOneWay() {
        QByteArray k0(32, 'a');
        QByteArray k1 = ratchetStep(k0), k2 = ratchetStep(k1);
        QCOMPARE(ratchetStep(k0), k1);
        QVERIFY(k1 != k0 && k2 != k1 && k2 != k0);
        QCOMPARE(k1.size(), 32);
    }
    void constantTimeEqual() {
        QVERIFY(constTimeEqual("abc", "abc"));
        QVERIFY(!constTimeEqual("abc", "abd"));
        QVERIFY(!constTimeEqual("abc", "ab"));
        QVERIFY(constTimeEqual(QByteArray(), QByteArray()));
    }
};

QTEST_APPLESS_MAIN(CryptoTests)
#include "test_crypto.moc"
