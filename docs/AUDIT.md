# Audit: ranked bug list

**How this was produced.** Everything below comes from reading the source. The C++ (`main.cpp`,
`installer.cpp`) was **not compiled or run**, because this machine has no Qt6 and no OpenSSL headers.
Every C++ item is therefore "found by reading", not "reproduced". `server.py` items were reproduced
with the tests in `tests/test_server.py`.

Status values: **fixed** (verified by a test or run), **not fixed**, **could not verify** (code changed or
claimed without being able to build and run it).

Line numbers refer to `main.cpp` / `installer.cpp` at commit `aa675a8`.

## Critical / High

| # | Where | Failure scenario | Fix | Status |
|---|-------|------------------|-----|--------|
| 1 | main.cpp:1697-1714 (HELLO), 1715-1752 (WELCOME) | Any connected socket, including the relay operator, sends a signed HELLO. An existing member answers automatically and hands over the room key. Likewise a joining client accepts a WELCOME from **any** identity. The relay can read or MITM the whole room. | Bind key delivery to a room secret (see THREAT_MODEL.md, "Authenticated key delivery"). **Changes the wire protocol.** | not fixed (needs your decision) |
| 2 | main.cpp:1691 (`left(8)`), 829, 1842-1866 | A UID is 32 bits of SHA-256. An attacker can grind a keypair whose UID collides with a pinned user. Pins are keyed by UID, so the attacker then shows the verified tick under the victim's name. | Key pins by the full fingerprint (>=128 bits); show a short form only for display. Local data migration, no wire change. | not fixed |
| 3 | installer.cpp:336-338 | When GitHub provides no `digest`, the installer only warns and installs anyway (fail-open). The digest comes from the same API response as the asset URL, so a compromised release replaces both. `SHA256SUMS.txt` is published but never used. | Fail closed. Verify against a signed checksum file (minisign/Ed25519 public key embedded in the installer). | not fixed |
| 4 | main.cpp:1343 | If `PKCS5_PBKDF2_HMAC` fails, it returns 32 zero bytes. The caller then encrypts the vault and identity key with an all-zero key. | Return an error and abort setup/unlock. | not fixed |
| 5 | main.cpp:599-694 | Uninstall deletes the entire application folder (`Remove-Item -Recurse`) if it contains `sonkkokoodi.exe` and is not a dev tree. If the user unpacked the zip into e.g. `Downloads\stuff`, everything else in that folder is deleted. The confirmation dialog does not name the path. | Delete only files listed in an install manifest; show the exact path and file list in the dialog. | not fixed |

## Medium

| # | Where | Failure scenario | Fix | Status |
|---|-------|------------------|-----|--------|
| 6 | main.cpp:1786-1802, 1559-1564 | The ratchet is driven by each client counting messages it sees. A packet dropped by the relay's rate limiter (or a GCM failure) desynchronises the count. A peer more than 16 epochs apart can never recover until it reconnects. | Resync request, or make epochs explicit and sender-driven. | not fixed |
| 7 | main.cpp:1686-1689, 1305-1315 | Replay: the seen-signature set is cleared on every reconnect and there are no timestamps or counters. A malicious relay replays old CHAT packets to a client that reconnects to the same room key, and they are displayed as new. | Signed per-sender counters plus bounded window (Phase 2). Wire change. | not fixed |
| 8 | main.cpp:1809, 1920 | Each GCM failure is stored as a **persistent** error message and triggers a full vault rewrite. A room member can flush the 1000-message history and cause disk churn. Every message already rewrites the whole vault on the UI thread. | Make decrypt failures transient; debounce the vault save. | not fixed |
| 9 | main.cpp:97-106 | `derToPkey` accepts any EC key, including other curves and explicit-parameter keys. | Require the named curve prime256v1. | not fixed |
| 10 | installer.cpp:385-386 | `Expand-Archive -Force` over a running install: locked DLLs fail mid-way and leave a mix of old and new files. | Extract to a staging folder, then swap; refuse while the app runs. | not fixed |
| 11 | main.cpp:1133-1137 | Autostart is switched on silently at the end of setup (default true). | Default off; ask on the setup screen. | not fixed |
| 12 | main.cpp:1281-1284 | No auto-reconnect. After the server dies the user has to type `connect`. | Reconnect with exponential back-off, visible state. | not fixed |
| 13 | main.cpp:1006-1015 | While locked, decrypted `history` plaintext, the identity key, and the group key all stay in memory. Only the vault key is zeroed. The README claim is accurate only for the vault key. | Clear plaintext on lock; document the limit. | not fixed |
| 14 | main.cpp:1610-1613, 1590-1607 | Suspected: two clients joining an empty room within ~0.4 s of each other can each generate their own key and then swap WELCOMEs, ending with a split room (each holds the other's key). | Needs a two-client test; deterministic tie-break (lowest UID wins). | could not verify |
| 15 | main.cpp:281 | `Qt::Tool` + frameless + translucent: no taskbar entry, no Alt-Tab, no resize, no snap. | Native frame (UX phase). | not fixed |
| 16 | release.yml | Actions are pinned to tags, not commit SHAs. `msys2 update: true` is unpinned. Release checksum file is unsigned. Job-wide `contents: write`. | Pin by SHA, split build and release jobs, sign checksums. | not fixed |

## Low

| # | Where | Note | Status |
|---|-------|------|--------|
| 17 | main.cpp:966-977 | Wrong-password back-off is in memory only (restart resets it) and capped at 10 s. Offline guessing is limited only by PBKDF2 at 100k iterations. | not fixed |
| 18 | main.cpp:1342 | PBKDF2 at 100,000 iterations is below current guidance (OWASP: 600,000 for PBKDF2-HMAC-SHA256). | not fixed |
| 19 | main.cpp:1532 | The ECDH output is hashed with a bare SHA-256 and no context string. Use HKDF with transcript binding. | not fixed |
| 20 | main.cpp:1332-1334, 827 | Settings and trust pins live in an unauthenticated INI file next to the exe; a local attacker can add a pin. | not fixed |
| 21 | main.cpp:1017-1036 | Messages that arrive while locked are shown only in memory and can be lost on quit. | not fixed |
| 22 | installer.cpp:248 | Fixed temp filename `sonkko_install.zip` in the shared temp folder. | not fixed |

## Relay (`server.py`), all reproduced by tests

| # | Problem | Status |
|---|---------|--------|
| R1 | No per-IP limit: one address could take all 50 slots. | fixed, `test_per_ip_limit` |
| R2 | Broadcast ran inside the sender's read loop. A slow receiver stalled the *sender* for up to 5 s per message, and unsent data buffered without bound. | fixed (bounded per-client queue plus own writer task), `test_slow_reader_does_not_block_others_and_is_dropped` |
| R3 | `writer.close()` on a stalled peer never completes (the transport waits to flush data nobody reads), so the stalled connection and its slot leaked. Found while writing R2's test. | fixed (`transport.abort()`) |
| R4 | Rate-limited packets were dropped forever with no cut-off; a flooder stayed connected. | fixed (disconnect after 50 consecutive drops), `test_flooding_gets_disconnected` |
| R5 | Slowloris: a client that started a packet could hold its slot for the full 1 h idle timeout. | fixed (30 s to finish a packet), `test_partial_line_times_out` |
| R6 | Empty-line spam used rate budget and was relayed. | fixed, `test_empty_lines_are_ignored_not_relayed` |
| R7 | Oversize handling and exact-limit packet. | verified, `test_oversized_*`, `test_packet_exactly_at_limit_is_relayed` |
| R8 | TLS was not available. | added behind `--cert/--key`; **not tested** (no client support, no cert available) |

Not checked against the old server: I did not run the new tests against the previous `server.py`, so I
cannot say which of them failed before. R3 was seen directly while the new code was being written.
