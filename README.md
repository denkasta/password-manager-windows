# Password Manager

A small offline password manager for Windows (Rust + WebView2). Sections for sites, accounts with login / password / note, themes, 4 languages (RU, EN, UK, PL). Made by denkasta.

## Build

Needs Rust (GNU toolchain with `windres`) and the WebView2 runtime.

```
cargo build --release
```

Copy `target/release/PasswordManager.exe` and `WebView2Loader.dll` (from `~/.cargo/registry/src/*/webview2-com-sys-*/x64/`) into one folder.

Tests: `cargo test`, `node tests/import.test.js` and `node tests/sha.test.js`.

## How your data is stored

- The vault is `%APPDATA%\PasswordManager\vault.json`, encrypted with AES-256-GCM. The key comes from your **master password** (Argon2id, exactly 12 characters, not a trivial one) and is never stored, so the file is useless without it, even from another PC or a boot stick. A forgotten master password cannot be recovered: keep a backup. The app makes no automatic copies: use **Backup** yourself.
- An old vault (Windows DPAPI + PIN, versions before this) is moved under a master password on first start; old DPAPI copies are deleted. The key lives in process memory while the app runs.

## Backup and import

- **Backup** writes `Backups\passwords-<date>.zip` next to the exe: `passwords.txt` (to read) and `backup.json` (to restore), both AES-256 encrypted with a password you choose (exactly 12 characters, not a trivial one; ZIP key derivation is light, short passwords are cracked fast). Open it with 7-Zip, WinRAR or a phone archiver app (Windows Explorer and iOS Files cannot open AES zips).
- **Import** takes that zip, a `.json`, a browser password export (`.csv`) or a text list and sorts everything into sections. Duplicates are skipped.
- Keep backups off this computer.

## License

MIT, see `LICENSE`.
