// GUI-free crypto primitives for Sönkkökoodi (QtCore + OpenSSL only), so they can be unit tested.
#pragma once
#include <QByteArray>
#include <openssl/evp.h>
#include <memory>

namespace sk {

// RAII owner for EVP_PKEY.
struct PkeyDeleter { void operator()(EVP_PKEY *k) const { EVP_PKEY_free(k); } };
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

constexpr int kPbkdf2Iterations = 600000;   // OWASP guidance for PBKDF2-HMAC-SHA256
constexpr int kLegacyPbkdf2Iterations = 100000;

bool constTimeEqual(const QByteArray &a, const QByteArray &b);

// Key (de)serialisation. derToPkey only accepts a NAMED prime256v1 EC public key.
QByteArray pkeyToDER(EVP_PKEY *key);
EVP_PKEY *derToPkey(const QByteArray &der);
QByteArray privKeyToPEM(EVP_PKEY *key);
EVP_PKEY *pemToPrivKey(const QByteArray &pem);
EVP_PKEY *generateP256Key();

// Empty result = failure (never a weak/zero key).
QByteArray pbkdf2(const QByteArray &password, const QByteArray &salt, int iterations);

// Output: ciphertext||tag(16); iv receives the 12 random bytes. Empty = failure.
QByteArray encryptGCM(const QByteArray &plaintext, const QByteArray &key, QByteArray &iv);
// ok distinguishes "valid empty plaintext" from authentication failure.
QByteArray decryptGCM(const QByteArray &ciphertextWithTag, const QByteArray &key, const QByteArray &iv, bool *ok = nullptr);

QByteArray sign(const QByteArray &data, EVP_PKEY *priv);
bool verify(const QByteArray &data, const QByteArray &sig, EVP_PKEY *pub);

// ECDH, then SHA-256 of the shared secret. Empty = failure.
QByteArray deriveSharedSecret(EVP_PKEY *myPriv, EVP_PKEY *peerPub);

// One step of the group-key hash ratchet.
QByteArray ratchetStep(const QByteArray &key);

} // namespace sk
