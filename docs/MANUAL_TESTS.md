# Manual test script and results

Result column: **PASS** (run and observed), **FAIL**, **NOT RUN** (with the reason).

Environment: MSYS2 UCRT64 (Qt 6.12, OpenSSL 3.6). "Automated" rows drive the real `SecureChatApp` headless
(`QT_QPA_PLATFORM=offscreen`) against the real `server.py`. **Headless is not a real screen.** Anything that needs
a human at a display, an installed copy, or the system tray is NOT RUN. Please run those by hand.

Automated part: `python -m pytest tests -q` and `ctest --test-dir build --output-on-failure`.

| # | Step | Expected | Result |
|---|------|----------|--------|
| 1 | First run: launch with no config; fill the setup dialog and press Create. | App unlocks and connects; status reaches Secure. | **PASS** for the logic (automated: `applySetup` in every `test_chat` scenario). **NOT RUN** interactively: the dialog itself was only exercised programmatically and rendered to PNG |
| 2 | Setup with a short password, mismatched repeat, bad alias, bad server, short passphrase. | Create stays disabled; the first problem is named in words. | **PASS** (automated: `test_dialogs` setupProblemsAreSpecific, setupCreateButtonFollowsValidity) |
| 3 | Quit during setup, relaunch. | Setup restarts cleanly, no crash. | NOT RUN (Cancel in the dialog quits; leftover files are moved to `.old` on the next setup, by code reading only) |
| 4 | Lock, unlock with the right password. | History returns; connection stays up. | **PASS** (automated: `lockWipesPlaintextAndWrongPasswordIsRejected`, `statusChipNamesEveryState`) |
| 5 | Wrong password. | "Wrong password", growing delay, input re-enabled. | **PASS** (automated, same test) |
| 5b | Restart the app, unlock with the same password. | History is still there. | **PASS** (automated: `lockedAppStillReadsAfterRestartWithTheSameVault`) |
| 6 | Notes: write, close, reopen; lock while the dialog is open. | Text persists. | NOT RUN (the dialog was rendered, not used) |
| 7 | Two clients and the relay: 45 messages in alternation. | All delivered, no decrypt failures, across 3 ratchet boundaries. | **PASS** (automated: `twoClientsShareKeyAndChatPastRatchet`) |
| 8 | One client sends a 60-message burst. | All delivered, ratchets stay in step. | **PASS** (automated: `burstSendIsDeliveredAndStaysInSync`; failed before the pacing fix) |
| 9 | Kill the relay mid-session. | Both clients show disconnected/reconnecting; no crash. | **PASS** (automated: `relayKilledThenAutoReconnect`, `statusChipNamesEveryState`) |
| 10 | Restart the relay. | Clients reconnect on their own and renegotiate. | **PASS** (automated, same tests) |
| 11 | Two clients start within a fraction of a second; and staggered starts. | They end up with one key. | **PASS** (automated: `forcedSimultaneousKeyCreationConverges`, `staggeredJoinConverges`; both failed with the old tie-break) |
| 11b | A member with a different passphrase tries to join. | It never gets the key and cannot read or be read. | **PASS** (automated: `wrongPassphraseNeverReceivesTheKey`) |
| 11c | A captured packet is replayed to a connected peer. | Not shown a second time. | **PASS** (automated: `replayedPacketIsIgnored`) |
| 12 | Uninstall from an installed copy (`%LOCALAPPDATA%\Sonkkokoodi`). | Folder, shortcut and autostart entry removed. | NOT RUN (never executed; destructive) |
| 13 | Uninstall from a zip unpacked next to other files. | Only data files removed; dialog says program files stay. | **PASS** for the dialog text (automated: `uninstallDataOnlyVariantSaysFilesRemain`, `uninstallDefaultsToCancelAndNamesThePath`). NOT RUN for the actual deletion |
| 14 | Upgrade: run the installer over an installed copy, closed and running. | Closed: settings and vault preserved. Running: refused. | NOT RUN |
| 14b | Installer with signed releases. | Refuses unsigned or badly signed releases. | NOT RUN (needs a live signed release; only the Ed25519 check itself is unit tested) |
| 15 | Relay limits (size, rate, flood, per-IP, total, slow reader, partial line, idle, empty lines). | See `tests/test_server.py`. | **PASS** (11/11) |
| 16 | Close (X) hides to the tray and stays connected; with no tray it quits; Quit exits. | As described in the README. | NOT RUN (offscreen has no tray) |
| 17 | Keyboard: Enter sends, Esc clears then locks, Ctrl+L / Alt+L lock, F1 help, Ctrl+, settings, Ctrl+Q quit. | Each works with the window focused. | NOT RUN (Enter and the lock path are exercised through code; the shortcuts themselves were not pressed) |
| 18 | Contrast of every text/background pair. | At least 4.5:1. | **PASS** (automated: `test_theme`, 28 pairs) |
| 19 | Text size 150%: no clipped text in dialogs or the lock screen. | Nothing cut off. | **PASS** (automated: `largeTextStillFits`, `lockScreenTextIsNotClipped`; also viewed in 14-large-text.png) |
| 20 | Window drag, resize, snap, minimize on a real display. | Native behaviour. | NOT RUN (native frame is used, but nobody dragged it) |
| 21 | Screen reader / tab order. | Fields have names and a sensible tab order. | NOT RUN (accessible names are set; no screen reader was used) |
