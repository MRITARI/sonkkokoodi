# Screenshots

`before/` is the UI at commit `6844fbd` (green-on-black terminal look, frameless window). `after/` is the redesigned UI.
Both sets are rendered by `tools/screenshots_app.cpp` and `tools/screenshots_installer.cpp`, which drive the real
application headless (`QT_QPA_PLATFORM=offscreen`) against the real relay. They are **not** captures of a physical
screen, so native window chrome (title bar, borders) is not included, and fonts follow what the Qt offscreen
platform resolves.

| Screen | before | after |
|---|---|---|
| First run: password, alias, server | 01-setup-password, 02-setup-alias, 03-setup-server (typed into a terminal-style prompt) | 01-setup-empty, 02-setup-errors, 03-setup-ready (one page, inline errors, strength hint) |
| Room passphrase | 04-setup-room | 04-room-passphrase |
| Connected, empty | 05-connected-empty | 05-connected-empty |
| Chat with impersonation attempt | 06-chat-with-spoof | 06-chat-with-spoof |
| Settings | 07-settings | 07-settings |
| Notes | 08-notes | 08-notes |
| Trusted identities | 09-trusted-identities | 09-trusted-identities |
| Uninstall confirmation | 10-uninstall-confirm | 10-uninstall-confirm |
| Help | 11-help (a dump of log lines) | 11-help (a dialog) |
| Locked | 12-locked | 12-locked, 13-locked-wrong-password |
| Large text (150%) | not available | 14-large-text |
| Installer | 13-installer | 15-installer |

Not captured: the tray menu and tray notifications, the native title bar, and any behaviour that needs a real
display (drag, snap, resize). See `docs/MANUAL_TESTS.md`.
