# Manual test script and results

Result column: **PASS** (run and observed), **FAIL**, **NOT RUN** (could not run here, with the reason).
Environment: this machine cannot build the GUI (no Qt6, no OpenSSL dev files), so every GUI item is
NOT RUN. Relay items were run against `server.py` through the pytest suite.

Run the automated part: `python -m pytest tests -q` (11 relay tests, all passing as of this commit).

| # | Step | Expected | Result |
|---|------|----------|--------|
| 1 | First run: launch with no `sonkkokoodi.ini`. Enter password >=8 chars, alias, server. | Setup finishes, status shows connecting, then secure. | NOT RUN (no build) |
| 2 | First run with a 7-char password, bad alias (`a b`), bad server (`host:99999`). | A clear error each time; nothing is saved. | NOT RUN |
| 3 | Close the app mid-setup (after password), relaunch. | Setup restarts cleanly, no crash. | NOT RUN |
| 4 | Lock (Alt+L), unlock with the right password. | History returns; connection stays up. | NOT RUN |
| 5 | Unlock with a wrong password three times. | "Invalid password", growing delay, input re-enabled. | NOT RUN |
| 6 | Notes: write text, close, reopen. Then write text and lock while the dialog is open. | Text persists in both cases. | NOT RUN |
| 7 | Two clients and `python server.py`: send 40 messages in alternation. | All delivered, no `GCM AUTHENTICATION FAILED`, across 2+ ratchet boundaries (every 15). | NOT RUN |
| 8 | Same, but one client sends 40 messages in a burst. | Peer stays in sync or recovers. (Audit #6 predicts possible desync under relay rate limiting.) | NOT RUN |
| 9 | Kill the relay mid-session. | Both clients show disconnected; no crash. | NOT RUN |
| 10 | Restart the relay, type `connect` on both. | Keys renegotiate, chat resumes. (Audit #12: no auto-reconnect yet.) | NOT RUN |
| 11 | Start two clients within 0.3 s on an empty relay. | They end up in one room and can read each other. (Audit #14 suspects a split.) | NOT RUN |
| 12 | Uninstall from an installed copy (`%LOCALAPPDATA%\Sonkkokoodi`). | App exits; folder, shortcut and autostart entry are removed. | NOT RUN |
| 13 | Uninstall from a zip unpacked next to other files. | Only app files removed. (Audit #5 predicts the whole folder is deleted.) | NOT RUN |
| 14 | Upgrade: run the installer over an installed copy while the app is closed, then while it is open. | Closed: settings and vault preserved. Open: refused or clean failure. (Audit #10.) | NOT RUN |
| 15 | Relay: broadcast, size limit, exact-limit packet, rate limit, flood cut-off, per-IP and total caps, slow reader, partial line, idle timeout, empty lines. | See `tests/test_server.py`. | **PASS** (11/11) |
