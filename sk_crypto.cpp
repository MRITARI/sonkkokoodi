#include "sk_crypto.h"
#include <QCryptographicHash>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>
#include <memory>

namespace sk {

using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using MdCtxPtr     = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using PkeyCtxPtr   = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

bool constTimeEqual(const QByteArray &a, const QByteArray &b) {
    if (a.size() != b.size()) return false;
    if (a.isEmpty()) return true;
    return CRYPTO_memcmp(a.constData(), b.constData(), a.size()) == 0;
}

QByteArray pkeyToDER(EVP_PKEY *key) {
    if (!key) return QByteArray();
    unsigned char *der = nullptr;
    int len = i2d_PUBKEY(key, &der);
    if (len <= 0 || !der) return QByteArray();
    QByteArray res(reinterpret_cast<char *>(der), len);
    OPENSSL_free(der);
    return res;
}

// Accepts only an EC key on the *named* curve prime256v1 (no other curves, no explicit parameters).
EVP_PKEY *derToPkey(const QByteArray &der) {
    if (der.isEmpty() || der.size() > 1024) return nullptr;
    const unsigned char *p = reinterpret_cast<const unsigned char *>(der.constData());
    PkeyPtr key(d2i_PUBKEY(nullptr, &p, der.size()));
    if (!key || EVP_PKEY_base_id(key.get()) != EVP_PKEY_EC) return nullptr;
    if (p != reinterpret_cast<const unsigned char *>(der.constData()) + der.size()) return nullptr; // trailing bytes
    char name[64] = {0};
    size_t nlen = 0;
    if (EVP_PKEY_get_utf8_string_param(key.get(), "group", name, sizeof(name), &nlen) != 1) return nullptr;
    if (QByteArray(name, int(nlen)) != "prime256v1") return nullptr;
    return key.release();
}

QByteArray privKeyToPEM(EVP_PKEY *key) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return QByteArray();
    QByteArray res;
    if (PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1) {
        char *data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        if (len > 0 && data) res = QByteArray(data, int(len));
    }
    BIO_free(bio);
    return res;
}

EVP_PKEY *pemToPrivKey(const QByteArray &pem) {
    if (pem.isEmpty()) return nullptr;
    BIO *bio = BIO_new_mem_buf(pem.constData(), pem.size());
    if (!bio) return nullptr;
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
}

EVP_PKEY *generateP256Key() {
    PkeyCtxPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    if (!pctx) return nullptr;
    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) return nullptr;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0) return nullptr;
    EVP_PKEY *key = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &key) <= 0) return nullptr;
    return key;
}

QByteArray pbkdf2(const QByteArray &password, const QByteArray &salt, int iterations) {
    if (salt.size() < 16 || iterations < 1000) return QByteArray();
    QByteArray key(32, '\0');
    if (PKCS5_PBKDF2_HMAC(password.constData(), password.size(),
                          reinterpret_cast<const unsigned char *>(salt.constData()), salt.size(),
                          iterations, EVP_sha256(), 32,
                          reinterpret_cast<unsigned char *>(key.data())) != 1)
        return QByteArray();
    return key;
}

QByteArray encryptGCM(const QByteArray &plaintext, const QByteArray &key, QByteArray &iv) {
    iv.clear();
    if (key.size() != 32) return QByteArray();

    QByteArray newIv(12, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char *>(newIv.data()), 12) != 1) return QByteArray();

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) return QByteArray();
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return QByteArray();
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) return QByteArray();
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                           reinterpret_cast<const unsigned char *>(key.constData()),
                           reinterpret_cast<const unsigned char *>(newIv.constData())) != 1) return QByteArray();

    QByteArray out(plaintext.size() + 16, '\0');
    int len = 0;
    if (EVP_EncryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(out.data()), &len,
                          reinterpret_cast<const unsigned char *>(plaintext.constData()), plaintext.size()) != 1) return QByteArray();
    int cipherLen = len;
    if (EVP_EncryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(out.data()) + len, &len) != 1) return QByteArray();
    cipherLen += len;

    QByteArray tag(16, '\0');
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) return QByteArray();

    out.resize(cipherLen);
    out.append(tag);
    iv = newIv;
    return out;
}

QByteArray decryptGCM(const QByteArray &ciphertextWithTag, const QByteArray &key, const QByteArray &iv, bool *ok) {
    if (ok) *ok = false;
    if (ciphertextWithTag.size() < 16 || key.size() != 32 || iv.size() != 12) return QByteArray();

    QByteArray tag = ciphertextWithTag.right(16);
    QByteArray ciphertext = ciphertextWithTag.left(ciphertextWithTag.size() - 16);

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) return QByteArray();
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return QByteArray();
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) return QByteArray();
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                           reinterpret_cast<const unsigned char *>(key.constData()),
                           reinterpret_cast<const unsigned char *>(iv.constData())) != 1) return QByteArray();

    QByteArray out(ciphertext.size(), '\0');
    int len = 0;
    if (EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(out.data()), &len,
                          reinterpret_cast<const unsigned char *>(ciphertext.constData()), ciphertext.size()) != 1) return QByteArray();
    int outLen = len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) return QByteArray();
    if (EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(out.data()) + len, &len) > 0) {
        out.resize(outLen + len);
        if (ok) *ok = true;
        return out;
    }
    return QByteArray();
}

QByteArray sign(const QByteArray &data, EVP_PKEY *priv) {
    if (!priv) return QByteArray();
    MdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) return QByteArray();
    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, priv) != 1) return QByteArray();
    if (EVP_DigestSignUpdate(ctx.get(), data.constData(), data.size()) != 1) return QByteArray();
    size_t siglen = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &siglen) != 1 || siglen == 0) return QByteArray();
    QByteArray sig(int(siglen), '\0');
    if (EVP_DigestSignFinal(ctx.get(), reinterpret_cast<unsigned char *>(sig.data()), &siglen) != 1) return QByteArray();
    sig.resize(int(siglen));
    return sig;
}

bool verify(const QByteArray &data, const QByteArray &sig, EVP_PKEY *pub) {
    if (!pub || sig.isEmpty()) return false;
    MdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) return false;
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pub) != 1) return false;
    if (EVP_DigestVerifyUpdate(ctx.get(), data.constData(), data.size()) != 1) return false;
    return EVP_DigestVerifyFinal(ctx.get(), reinterpret_cast<const unsigned char *>(sig.constData()), sig.size()) == 1;
}

QByteArray deriveSharedSecret(EVP_PKEY *myPriv, EVP_PKEY *peerPub) {
    if (!myPriv || !peerPub) return QByteArray();
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new(myPriv, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) return QByteArray();
    if (EVP_PKEY_derive_init(ctx.get()) <= 0) return QByteArray();
    if (EVP_PKEY_derive_set_peer(ctx.get(), peerPub) <= 0) return QByteArray();
    size_t len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &len) <= 0 || len == 0 || len > 128) return QByteArray();
    QByteArray secret(int(len), '\0');
    if (EVP_PKEY_derive(ctx.get(), reinterpret_cast<unsigned char *>(secret.data()), &len) <= 0) return QByteArray();
    secret.resize(int(len));
    return QCryptographicHash::hash(secret, QCryptographicHash::Sha256);
}

QByteArray ratchetStep(const QByteArray &key) {
    return QCryptographicHash::hash(key, QCryptographicHash::Sha256);
}

} // namespace sk
