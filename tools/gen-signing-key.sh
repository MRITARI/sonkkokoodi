#!/bin/sh
# Generates the Ed25519 key that signs SHA256SUMS.txt in releases.
#   1. Run this script (needs OpenSSL 3).
#   2. Put the contents of release-signing-private.pem into the GitHub secret RELEASE_SIGNING_KEY
#      (Settings > Secrets and variables > Actions), then DELETE the file. Never commit it.
#   3. Paste the printed 64-hex public key into SIGNING_PUBLIC_KEY_HEX in installer.cpp.
set -eu
umask 077
openssl genpkey -algorithm ed25519 -out release-signing-private.pem
echo "Public key (paste into installer.cpp):"
openssl pkey -in release-signing-private.pem -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'
echo
echo "Private key written to release-signing-private.pem -> store it as a secret, then delete it."
