# Password Manager

A small offline password manager for Windows (Rust + WebView2). Sections for sites, accounts with login / password / note, themes, 4 languages (RU, EN, UK, PL). Works without internet: nothing is ever sent anywhere. Made by denkasta.

## Features

- Master password with strong encryption (see below), auto-lock after 5 minutes of inactivity or when the window is minimised.
- Sections you can reorder by dragging, custom or built-in icons, themes.
- Encrypted backup (ZIP) and import of a backup, a browser export (`.csv`), `.json` or a text list. Drop a file on the window to import it.
- Copied passwords are removed from the clipboard after 30 seconds and kept out of Windows clipboard history.

## Build

Needs Rust (GNU toolchain with `windres`) and the WebView2 runtime.

```
cargo build --release
```

Copy `target/release/PasswordManager.exe` and `WebView2Loader.dll` (from `~/.cargo/registry/src/*/webview2-com-sys-*/x64/`) into one folder.

Tests: `cargo test` and `node tests/import.test.js`.

## How your data is stored

- The vault is `%APPDATA%\PasswordManager\vault.json`, encrypted with AES-256-GCM. The key comes from your **master password** through Argon2id (256 MiB, 3 passes) and is never stored, so the file is useless without the password, even on another PC or from a boot stick. Windows account passwords play no role.
- The master password is exactly 12 characters. Trivial ones (few different characters, a straight run like `123456789012`, common words) are refused. Use 12 random characters.
- A forgotten master password cannot be recovered: keep a backup. The app makes no automatic copies, use **Backup** yourself.
- Section order, groups and own icons are stored inside the encrypted vault too.
- The key lives in process memory while the app is unlocked.
- An old vault (Windows DPAPI + PIN, versions before this) is moved under a master password on first start. The old files are overwritten with zeros and deleted. The old `%APPDATA%\passvault` folder is renamed to `PasswordManager`.

## Backup and import

- **Backup** writes `Backups\passwords-<date>.zip` next to the exe: `passwords.txt` (to read) and `backup.json` (to restore), both AES-256 encrypted with a password you choose (exactly 12 characters, not a trivial one). The ZIP key derivation is light, so use a random password and keep the file **off this computer** (USB stick, phone). Open it with 7-Zip, WinRAR or a phone archiver app (Windows Explorer and iOS Files cannot open AES zips).
- **Import** takes that zip, a `.json`, a browser password export (`.csv`) or a text list and sorts everything into sections. Duplicates are skipped. Files over 50 MB are refused.

## Security notes

- The master password protects the vault file. It does not protect against someone who can replace the program itself or read memory files (`hiberfil.sys`, pagefile) from your disk. Disk encryption is the only defence against that, so turn on **BitLocker**:
  1. Windows 11 Pro: Start → type "BitLocker" → **Manage BitLocker** → **Turn on BitLocker** for the system drive (C:). On many PCs it is also under Settings → Privacy & security → **Device encryption**.
  2. Save the recovery key somewhere **off this PC** (Microsoft account, a USB stick or paper). Without it a locked disk cannot be recovered.
  3. Optional: `powercfg /h off` in an administrator terminal disables hibernation, so no copy of memory is written to `hiberfil.sys`.
- The page has a strict Content-Security-Policy and cannot make any network request.

## License

MIT, see `LICENSE`.
