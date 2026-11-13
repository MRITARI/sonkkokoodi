# Threat model (draft)

This is **unreviewed cryptography**. The README disclaimer stays. This document is the intended
model, not a guarantee. Items marked *current* describe the code as it is today.

## Assets
Message plaintext; identity private key; local history and notes; the room key; who talks to whom.

## Adversaries

| Adversary | Can do | Current state |
|-----------|--------|---------------|
| **Passive network observer** | See IPs, timing, packet sizes. Transport is plain TCP. | Content protected by AES-GCM. Metadata not protected. |
| **Malicious relay operator** | Everything the observer can, plus drop, delay, reorder, replay and inject packets, and connect as a client. | **Not protected against key theft.** The operator connects, sends HELLO, and any member answers with the room key (audit #1). Replay is possible across reconnects (#7). |
| **Malicious room member** | Holds the room key. Can read everything after joining, flood, spoof names, send bogus ciphertext. | Reads all traffic by design. Name spoofing is flagged via TOFU, but UID is only 32 bits (#2). |
| **Local attacker, disk access, device off** | Copy vault/ini/notes. | Vault, notes and identity key are AES-GCM under a PBKDF2 key (100k iterations). Strength is bounded by the password. Pins and settings are unauthenticated (#20). |
| **Local attacker, memory dump / running session** | Read process memory. | Not protected. Only the vault key is zeroed on lock; history plaintext and identity key stay resident (#13). |
| **Supply-chain attacker** (GitHub release, CI) | Replace the zip. | Installer verifies GitHub's digest only when present, and that shares the trust root with the asset (#3, #16). |

## Proposed: authenticated key delivery (needs your approval, changes the wire protocol)

**Design.** Each room has a passphrase, shared out-of-band.
1. `room_key = scrypt(passphrase, salt = "sk-room-v2" || room name, N=2^17, r=8, p=1)` (OpenSSL 3 `EVP_KDF`, no new dependency). Split with HKDF into `auth_key` and `wrap_key`.
2. **HELLO** carries the ephemeral ECDH public key, a fresh nonce, and `HMAC(auth_key, "hello" || ecdh_pub || nonce || sender_identity_pub)`. Members ignore HELLOs with a bad MAC, so a non-member cannot solicit the room key.
3. **WELCOME** wraps the room key under `HKDF(ECDH_secret || wrap_key, transcript)` and carries a MAC over the transcript. A joiner accepts a WELCOME only if the MAC verifies, so only passphrase holders can deliver a key.
4. The relay learns nothing it can use without the passphrase, and cannot inject a key.

**Limits (stated plainly).**
- The HELLO MAC lets an observer who recorded it run an **offline guessing attack** on the passphrase. scrypt slows this; only a strong passphrase (or a real PAKE such as CPace/OPAQUE, which is a new dependency) removes it.
- Everyone who knows the passphrase is fully trusted; there is no per-member revocation.
- If the passphrase leaks later, recorded past traffic stays safe because the wrap key also depends on an ephemeral ECDH secret (key delivery has forward secrecy with respect to the passphrase). A leaked passphrase does let an attacker join **future** sessions.
- It does not hide metadata.

## Forward secrecy and recovery: what the ratchet actually gives
The room key is hashed forward every 15 messages. That means: someone who steals the key at epoch N
cannot derive epochs before N (hashing is one way) **if the old keys are really gone**. It does not give
post-compromise recovery (anyone with epoch N derives all later epochs), and a joiner is handed the current
key. The vault stores decrypted history, so the on-disk history is only as safe as the password. A
per-sender chain with fresh DH input (Double Ratchet / MLS style) would add recovery; that is a large
redesign and is not proposed unless you want it.

## What is and is not protected (protocol v2, as implemented)

**Protected, and tested**
- A stranger or the relay **cannot obtain the room key** without the room passphrase: HELLO and WELCOME carry MACs keyed from it, and the wrapping key also depends on it (`test_protocol` keyDeliveryEndToEnd, `test_chat` wrongPassphraseNeverReceivesTheKey).
- Captured packets **cannot be replayed** to a connected peer (session id + counter + signed timestamp, 120 s window; `replayedPacketIsIgnored`).
- Tampered ciphertext is rejected (AES-256-GCM; every byte flip tested in `test_crypto`).
- Two clients joining at the same instant end up with one key (`forcedSimultaneousKeyCreationConverges`).

**Protected by design, not tested end to end**
- Vault, notes and identity key are encrypted at rest under a password-derived key (PBKDF2-HMAC-SHA256, 600k iterations for new installs). Strength is bounded by the password.
- Identity pins use the full 256-bit key fingerprint.

**NOT protected**
- **Metadata**: the relay sees IPs, timing and message sizes. The transport is plain TCP.
- **Anyone who knows the passphrase** is fully trusted and reads everything. No per-member revocation. A leaked passphrase lets an attacker join future sessions.
- **Offline passphrase guessing**: a recorded HELLO lets an attacker test guesses (scrypt N=2^15 slows it). Use a long random passphrase.
- **Forward secrecy is limited**: the key is hashed forward every 15 messages. Stealing the current key reveals all later messages; there is no post-compromise recovery. A new member receives the current key.
- **Ratchet desync** (audit #6) is mostly fixed (clients pace sends so the relay no longer drops messages). A client that misses more than 256 epochs, or a message more than one epoch old, still cannot decrypt until it reconnects.
- **Memory / running machine**: only the vault key is wiped on lock. Identity key, room keys, group key and decrypted history remain in memory while locked.
- **Replay beyond the window or across a restarted peer**: a packet older than 120 s is rejected, but a malicious relay can still delay or drop messages, and clocks must agree within ~2 minutes.
- **Local attacker with disk access** can edit the unauthenticated settings file (e.g. add a pin).
- **Supply chain**: release checksums can be Ed25519-signed and verified by the installer, but this is **inactive until you create the key** (`tools/gen-signing-key.sh`). Until then the installer trusts GitHub's own digest, which a compromised GitHub account defeats. The installer's own binary is not signed either (Windows SmartScreen will warn).
- This is still unreviewed cryptography written by an LLM; see the README disclaimer.
