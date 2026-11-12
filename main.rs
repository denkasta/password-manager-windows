#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::{borrow::Cow, error::Error, fs, path::{Path, PathBuf}, process::Command, sync::Mutex};
use tao::{platform::windows::{IconExtWindows, WindowBuilderExtWindows}, window::Icon, dpi::LogicalSize, event::{Event, WindowEvent}, event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy}, window::WindowBuilder};
use wry::{http::Response, PageLoadEvent, WebContext, WebViewBuilder};

const HTML: &str = include_str!("index.html");
const ORIGIN: &str = "http://app.localhost";
type R<T> = Result<T, Box<dyn Error>>;
// exact origin, not a prefix: "http://app.localhost.evil.com" must not pass
fn ours(u: &str) -> bool { u == ORIGIN || u.strip_prefix(ORIGIN).is_some_and(|r| r.starts_with('/')) }

fn appdata() -> PathBuf { PathBuf::from(std::env::var("APPDATA").unwrap_or_default()) }
fn dir() -> PathBuf { appdata().join("PasswordManager") }
// Earlier versions kept the vault in "passvault" (the name the old Electron build used): move it once to the project's own folder.
fn migrate_dir() {
    let (old, new) = (appdata().join("passvault"), dir());
    if !new.exists() && old.join("vault.json").exists() { let _ = fs::rename(old, new); }
}

// DPAPI is only used to read the old (v3) vault once and move it under the master password.
fn dpapi(data: &[u8], protect: bool) -> R<Vec<u8>> {
    use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB}};
    unsafe {
        let inp = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = if protect {
            CryptProtectData(&inp, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out)
        } else {
            CryptUnprotectData(&inp, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out)
        };
        if ok == 0 { return Err("DPAPI failed".into()); }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Ok(v)
    }
}

// Vault v5: AES-256-GCM, key = Argon2id(master password, random salt). The key is kept only in memory while the app runs.
// shortcut: key is not zeroized on exit, only the process memory holds it; upgrade if a memory-dump threat matters.
static KEY: Mutex<Option<([u8; 32], [u8; 16])>> = Mutex::new(None);
const KDF: (u32, u32) = (262144, 3); // memory KiB (256 MiB), passes: about a second per guess; older files keep their own numbers and are upgraded on the next unlock
const MIN_PW: usize = 12;
const MIN_BACKUP_PW: usize = 12; // exactly 12 (the page limits it to 12): the ZIP key derivation is light, so the password must be random, not a phrase

fn rnd<const N: usize>() -> R<[u8; N]> { let mut b = [0u8; N]; getrandom::fill(&mut b).map_err(|e| e.to_string())?; Ok(b) }
fn derive(pw: &str, salt: &[u8], m: u32, t: u32) -> R<[u8; 32]> {
    let p = argon2::Params::new(m, t, 1, Some(32)).map_err(|e| e.to_string())?;
    let mut k = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p).hash_password_into(pw.as_bytes(), salt, &mut k).map_err(|e| e.to_string())?;
    Ok(k)
}
// The whole vault rests on this password: refuse the ones an attacker tries first (few distinct characters, one run
// like 123456789012, or a common word). Same rule as the page (weakPw in index.html).
fn weak(pw: &str) -> bool {
    let c: Vec<char> = pw.chars().collect();
    let distinct = { let mut d = c.clone(); d.sort(); d.dedup(); d.len() };
    let run = c.windows(2).all(|w| w[1] as i64 - w[0] as i64 == 1) || c.windows(2).all(|w| w[0] as i64 - w[1] as i64 == 1);
    let low = pw.to_lowercase();
    distinct < 7 || run || ["123456", "qwerty", "password", "пароль", "йцукен", "abcdef", "000000", "111111"].iter().any(|w| low.contains(w))
}
fn new_key(pw: &str) -> R<([u8; 32], [u8; 16])> {
    if pw.chars().count() < MIN_PW { return Err("password too short".into()); }
    if weak(pw) { return Err("password too simple".into()); }
    let salt = rnd::<16>()?;
    Ok((derive(pw, &salt, KDF.0, KDF.1)?, salt))
}
fn set_key(pw: &str) -> R<()> { *KEY.lock().unwrap() = Some(new_key(pw)?); Ok(()) }
fn seal(key: &[u8; 32], salt: &[u8; 16], data: &Value) -> R<Value> {
    let n = rnd::<12>()?;
    let ct = Aes256Gcm::new(key.into()).encrypt(Nonce::from_slice(&n), data.to_string().as_bytes()).map_err(|_| "encrypt failed")?;
    Ok(json!({ "v": 5, "m": KDF.0, "t": KDF.1, "s": B64.encode(salt), "n": B64.encode(n), "d": B64.encode(ct) }))
}
fn unseal(v: &Value, pw: &str) -> R<([u8; 32], [u8; 16], Value)> {
    let field = |k: &str| -> R<Vec<u8>> { Ok(B64.decode(v[k].as_str().ok_or("corrupted file")?)?) };
    let (salt, n, ct) = (field("s")?, field("n")?, field("d")?);
    if n.len() != 12 { return Err("corrupted file".into()); }
    let (m, t) = (v["m"].as_u64().ok_or("corrupted file")?, v["t"].as_u64().ok_or("corrupted file")?);
    if !(8..=1 << 20).contains(&m) || !(1..=10).contains(&t) { return Err("corrupted file".into()); } // a damaged file must not ask for gigabytes
    let key = derive(pw, &salt, m as u32, t as u32)?;
    let plain = Aes256Gcm::new((&key).into()).decrypt(Nonce::from_slice(&n), ct.as_slice()).map_err(|_| "wrong password")?;
    Ok((key, salt.try_into().map_err(|_| "corrupted file")?, serde_json::from_slice(&plain)?))
}

// The payload is a list of entries (older files) or {"e": entries, "m": settings}: section order, groups and own icons live
// inside the encrypted vault, not in the window's plain-text profile.
fn valid(data: &Value) -> bool { data.is_array() || (data["e"].is_array() && data["m"].is_object()) }

// Overwrite a file with zeros in place (no truncation, so the same disk blocks are hit), then delete it. Best effort: on an SSD only disk
// encryption (BitLocker) really guarantees that old data is gone.
fn zero(p: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let n = fs::metadata(p)?.len() as usize;
    let mut f = fs::OpenOptions::new().write(true).open(p)?;
    f.write_all(&vec![0u8; n])?;
    f.sync_all()
}
fn wipe(p: &Path) { let _ = zero(p); let _ = fs::remove_file(p); }

// Atomic write (tmp + rename): a crash mid-save can't corrupt the vault.
// wipe_old: the file being replaced is an old DPAPI vault, so it is zeroed and deleted instead of left to be undeleted.
fn write_vault(key: &[u8; 32], salt: &[u8; 16], data: &Value, wipe_old: bool) -> R<()> {
    if !valid(data) { return Err("vault has a wrong shape".into()); } // a malformed message must never replace the vault
    fs::create_dir_all(dir())?;
    let tmp = dir().join("vault.json.tmp");
    fs::write(&tmp, seal(key, salt, data)?.to_string())?;
    let f = dir().join("vault.json");
    if wipe_old {
        let old = dir().join("vault.json.v3old");
        fs::rename(&f, &old)?;
        if let Err(e) = fs::rename(&tmp, &f) { let _ = fs::rename(&old, &f); return Err(e.into()); } // never end up without a vault
        wipe(&old);
    } else {
        fs::rename(tmp, f)?;
    }
    Ok(())
}
// The key lock is held for the whole write, so a save and a password change can never write the same temp file at once.
fn save(data: &Value) -> R<()> {
    let g = KEY.lock().unwrap();
    let (key, salt) = (*g).ok_or("vault is locked")?;
    write_vault(&key, &salt, data, false)
}
// New master password: the file is rewritten first, the in-memory key changes only if that worked.
fn rekey(pw: &str, data: &Value) -> R<()> {
    let (key, salt) = new_key(pw)?;
    let mut g = KEY.lock().unwrap();
    if g.is_none() { return Err("vault is locked".into()); }
    write_vault(&key, &salt, data, false)?;
    *g = Some((key, salt));
    Ok(())
}
fn lock() { *KEY.lock().unwrap() = None; }

// "new" (no vault), "old" (v3, DPAPI only: will be moved under a master password) or "locked".
fn state() -> &'static str {
    let b = match fs::read(dir().join("vault.json")) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return "new",
        Err(_) => return "locked", // locked by another program: never offer to create a new vault over it
    };
    if serde_json::from_slice::<Value>(&b).is_ok_and(|v| v["v"] == 3) { "old" } else { "locked" }
}

// Old DPAPI copies would still open without the master password: delete them after the upgrade.
fn purge_old(dir: &Path) {
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "bak") && fs::read(&p).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).is_some_and(|v| v["v"] == 3) { wipe(&p); }
    }
}

fn open(pw: &str) -> R<Value> {
    let f = dir().join("vault.json");
    if !f.exists() { set_key(pw)?; save(&json!([]))?; return Ok(json!([])); }
    let v: Value = serde_json::from_slice(&fs::read(&f)?)?;
    match v["v"].as_i64() {
        Some(3) => {
            let data: Value = serde_json::from_slice(&dpapi(&B64.decode(v["d"].as_str().ok_or("corrupted file")?)?, false)?)?;
            let (k, s) = new_key(pw)?;
            { let mut g = KEY.lock().unwrap(); write_vault(&k, &s, &data, true)?; *g = Some((k, s)); }
            purge_old(&dir());
            Ok(data)
        }
        Some(5) => {
            let (k, s, d) = unseal(&v, pw)?;
            *KEY.lock().unwrap() = Some((k, s));
            if v["m"].as_u64() != Some(KDF.0 as u64) || v["t"].as_u64() != Some(KDF.1 as u64) { let _ = rekey(pw, &d); } // older, cheaper settings: upgrade now
            Ok(d)
        }
        _ => Err("unsupported vault format".into()),
    }
}

// Backup: a text file inside a ZIP encrypted with AES-256 and the user's password, saved in "Backups" next to the exe
// (falls back to the data folder). Returns the file path.
fn backup(text: String, json: String, name: String, pw: String) -> Result<String, String> {
    if pw.chars().count() < MIN_BACKUP_PW || weak(&pw) { return Err("password too short or too simple".into()); } // ZIP key derivation is light: short or simple passwords are easy to brute-force
    let name: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || "-_".contains(*c)).collect();
    let dir = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.join("Backups")))
        .filter(|d| fs::create_dir_all(d).is_ok() && fs::write(d.join(".w"), b"").is_ok())
        .or_else(|| { let d = dir().join("Backups"); fs::create_dir_all(&d).ok().map(|_| d) })
        .ok_or("no writable folder")?;
    let _ = fs::remove_file(dir.join(".w"));
    let out = dir.join(format!("{}.zip", if name.is_empty() { "passwords" } else { &name }));
    let part = out.with_extension("zip.part"); // a failed write must never delete an older good backup of the same name
    write_zip(&part, &text, &json, &pw).map_err(|e| { let _ = fs::remove_file(&part); e })?;
    fs::rename(&part, &out).map_err(|e| e.to_string())?;
    Ok(out.display().to_string())
}

fn write_zip(out: &Path, text: &str, json: &str, pw: &str) -> Result<(), String> {
    use std::io::Write;
    use zip::{write::SimpleFileOptions, AesMode, ZipWriter};
    let e = |x: &dyn std::fmt::Display| x.to_string();
    let mut z = ZipWriter::new(fs::File::create(out).map_err(|x| e(&x))?);
    let o = || SimpleFileOptions::default().with_aes_encryption(AesMode::Aes256, pw);
    z.start_file("passwords.txt", o()).map_err(|x| e(&x))?;
    z.write_all(&[0xEF, 0xBB, 0xBF]).and_then(|_| z.write_all(text.as_bytes())).map_err(|x| e(&x))?; // BOM: phones show UTF-8 right
    z.start_file("backup.json", o()).map_err(|x| e(&x))?; // machine-readable copy for "Import"
    z.write_all(json.as_bytes()).map_err(|x| e(&x))?;
    z.finish().map_err(|x| e(&x))?;
    Ok(())
}

// Import: pick a file (.zip backup, .json, .csv, .txt) and return its text; encrypted zips ask for the password first.
fn import(path: String, pw: String) -> Value {
    use std::io::{Cursor, Read};
    let path = if path.is_empty() {
        match rfd::FileDialog::new().add_filter("Backup / list", &["zip", "json", "csv", "txt"]).pick_file() { Some(f) => f.display().to_string(), None => return json!({"cancel": true}) }
    } else { path };
    if fs::metadata(&path).map(|m| m.len() > 50_000_000).unwrap_or(false) { return json!({"e": "file too large"}); } // also for dropped files
    let Ok(bytes) = fs::read(&path) else { return json!({"e": "cannot read the file"}) };
    let raw = if path.to_lowercase().ends_with(".zip") {
        let Ok(mut z) = zip::ZipArchive::new(Cursor::new(bytes)) else { return json!({"e": "not a valid zip"}) };
        let name = ["backup.json", "passwords.txt"].into_iter().find(|n| z.index_for_name(n).is_some()).map(String::from)
            .or_else(|| z.name_for_index(0).and_then(|r| r.ok()).map(|c| c.to_string()));
        let Some(name) = name else { return json!({"e": "empty archive"}) };
        const MAX: u64 = 50_000_000; // a "zip bomb" must not eat all memory
        let mut buf = Vec::new();
        let ok = if pw.is_empty() { z.by_name(&name).map(|f| f.take(MAX + 1).read_to_end(&mut buf)).is_ok_and(|r| r.is_ok()) }
                 else { z.by_name_decrypt(&name, pw.as_bytes()).map(|f| f.take(MAX + 1).read_to_end(&mut buf)).is_ok_and(|r| r.is_ok()) };
        if !ok { return json!({"need": true, "path": path, "bad": !pw.is_empty()}); }
        if buf.len() as u64 > MAX { return json!({"e": "file too large"}); }
        buf
    } else { bytes };
    let raw = raw.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(&raw);
    json!({"text": String::from_utf8_lossy(raw)})
}

// Clipboard via the OS (the web clipboard API makes WebView2 ask for permission).
// Passwords are wiped after 30s, but only if the clipboard still holds that exact text.
fn copy(t: String, wipe: bool) {
    let Ok(mut cb) = arboard::Clipboard::new() else { return };
    use arboard::SetExtWindows;
    // keep passwords out of Win+V history and the cloud clipboard (the 30 s wipe can't clear those copies)
    let set = if wipe { cb.set().exclude_from_history().exclude_from_cloud().text(t.clone()) } else { cb.set_text(t.clone()) };
    if set.is_err() || !wipe { return; }
    std::thread::sleep(std::time::Duration::from_secs(30));
    if let Ok(mut cb) = arboard::Clipboard::new() {
        if cb.get_text().ok().as_deref() == Some(t.as_str()) { let _ = cb.clear(); }
    }
}

enum Ev { Reply(u64, String), Show, Title(String), Zoom(f64), Drop(String) }
fn reply(p: &EventLoopProxy<Ev>, id: u64, v: Value) { let _ = p.send_event(Ev::Reply(id, v.to_string())); }

fn main() {
    if let Err(e) = run() {
        rfd::MessageDialog::new().set_level(rfd::MessageLevel::Error).set_title("Password Manager").set_description(e.to_string()).show();
    }
}

fn run() -> R<()> {
    migrate_dir();
    let event_loop = EventLoopBuilder::<Ev>::with_user_event().build();
    let window = WindowBuilder::new()
        .with_title("Password Manager")
        .with_visible(false) // shown once the page is ready: no white/grey flash while WebView2 starts
        .with_window_icon(Icon::from_resource(1, Some(tao::dpi::PhysicalSize::new(32, 32))).ok()) // icon embedded by build.rs
        .with_taskbar_icon(Icon::from_resource(1, Some(tao::dpi::PhysicalSize::new(64, 64))).ok())
        .with_inner_size(LogicalSize::new(1100.0, 720.0))
        .with_min_inner_size(LogicalSize::new(820.0, 560.0))
        .build(&event_loop)?;
    let proxy = event_loop.create_proxy();
    let show = proxy.clone();
    let fallback = proxy.clone();
    std::thread::spawn(move || { std::thread::sleep(std::time::Duration::from_secs(3)); let _ = fallback.send_event(Ev::Show); }); // never stay invisible
    let mut ctx = WebContext::new(Some(PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_default()).join("PasswordManager")));

    let drop_p = proxy.clone();
    let webview = WebViewBuilder::new_with_web_context(&mut ctx)
        .with_background_color((31, 30, 29, 255))
        // served from http://app.localhost so clipboard / crypto get a secure context
        .with_custom_protocol("app".into(), |_, _| {
            Response::builder().header("Content-Type", "text/html; charset=utf-8").body(Cow::Borrowed(HTML.as_bytes())).unwrap()
        })
        .with_url(format!("{ORIGIN}/"))
        .with_navigation_handler(|u| ours(&u)) // a dropped file or link must not open with IPC access
        .with_drag_drop_handler(move |e| {
            // a dropped backup / list goes to the import flow (which asks for the archive password); the page itself never navigates to it
            if let wry::DragDropEvent::Drop { paths, .. } = e {
                let ok = |p: &PathBuf| p.extension().and_then(|x| x.to_str()).is_some_and(|x| ["zip", "json", "csv", "txt"].contains(&x.to_lowercase().as_str()));
                if let Some(p) = paths.iter().find(|p| ok(p)) { let _ = drop_p.send_event(Ev::Drop(p.display().to_string())); }
            }
            true
        })
        .with_on_page_load_handler(move |e, _| { if matches!(e, PageLoadEvent::Finished) { let _ = show.send_event(Ev::Show); } })
        .with_ipc_handler(move |req| {
            if !ours(&req.uri().to_string()) { return; }
            let m: Value = serde_json::from_str(req.body()).unwrap_or_default();
            let id = m["id"].as_u64().unwrap_or(0);
            let p = proxy.clone();
            match m["c"].as_str() {
                Some("state") => reply(&p, id, json!(state())),
                Some("open") => {
                    let pw = m["a"].as_str().unwrap_or("").to_string();
                    // Argon2 takes ~1 s: off the UI thread
                    std::thread::spawn(move || reply(&p, id, match open(&pw) {
                        Ok(d) => json!({ "data": d }),
                        Err(e) if e.to_string() == "wrong password" => json!({ "bad": true }),
                        Err(e) => json!({ "error": e.to_string() }),
                    }));
                }
                Some("rekey") => {
                    let (pw, data) = (m["a"].as_str().unwrap_or("").to_string(), m["w"].clone());
                    std::thread::spawn(move || reply(&p, id, json!(rekey(&pw, &data).is_ok())));
                }
                Some("lock") => { lock(); reply(&p, id, json!(true)); }
                Some("copy") => {
                    let (t, wipe) = (m["a"].as_str().unwrap_or("").to_string(), m["w"].as_bool().unwrap_or(false));
                    std::thread::spawn(move || copy(t, wipe));
                }
                Some("zoom") => { let _ = p.send_event(Ev::Zoom(m["a"].as_f64().unwrap_or(1.0))); }
                Some("title") => { let _ = p.send_event(Ev::Title(m["a"].as_str().unwrap_or("Password Manager").to_string())); }
                Some("save") => reply(&p, id, json!(save(&m["a"]).is_ok())),
                Some("backup") => {
                    let html = m["a"]["t"].as_str().unwrap_or("").to_string();
                    let json = m["a"]["j"].as_str().unwrap_or("").to_string();
                    let name = m["w"]["n"].as_str().unwrap_or("").to_string();
                    let pw = m["w"]["k"].as_str().unwrap_or("").to_string();
                    std::thread::spawn(move || reply(&p, id, match backup(html, json, name, pw) { Ok(f) => json!({"p": f}), Err(e) => json!({"e": e}) }));
                }
                Some("import") => {
                    let path = m["a"].as_str().unwrap_or("").to_string();
                    let pw = m["w"].as_str().unwrap_or("").to_string();
                    std::thread::spawn(move || reply(&p, id, import(path, pw)));
                }
                Some("reveal") => { let _ = Command::new("explorer").arg(format!("/select,{}", m["a"].as_str().unwrap_or(""))).spawn(); }
                _ => {}
            }
        })
        .build(&window)?;

    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(Ev::Reply(id, s)) => { let _ = webview.evaluate_script(&format!("__res({id},{s})")); }
            Event::UserEvent(Ev::Drop(p)) => { let _ = webview.evaluate_script(&format!("window.__drop&&window.__drop({})", Value::String(p))); }
            Event::UserEvent(Ev::Show) => window.set_visible(true),
            Event::UserEvent(Ev::Title(t)) => window.set_title(&t),
            Event::UserEvent(Ev::Zoom(z)) => { let _ = webview.zoom(z.clamp(0.7, 1.6)); }
            // minimised (Windows reports a 0x0 client area): wipe the key and show the sign-in screen again
            Event::WindowEvent { event: WindowEvent::Resized(sz), .. } if sz.width == 0 || sz.height == 0 => { lock(); let _ = webview.evaluate_script("location.reload()"); }
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => *flow = ControlFlow::Exit,
            _ => {}
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    static GLOBAL: Mutex<()> = Mutex::new(()); // tests that use the global key and APPDATA must not run at the same time
    #[test]
    fn backup_roundtrip() {
        let name = format!("test-{}", std::process::id());
        let p = backup("txt".into(), "[{\"site\":\"Ünï\"}]".into(), name, "Pässwört-12-zeichen".into()).unwrap();
        assert!(import(p.clone(), "".into())["need"].as_bool().unwrap()); // encrypted: asks for the password
        assert!(import(p.clone(), "wrong".into())["bad"].as_bool().unwrap());
        assert_eq!(import(p.clone(), "Pässwört-12-zeichen".into())["text"], "[{\"site\":\"Ünï\"}]");
        let _ = fs::remove_file(p);
    }
    #[test]
    fn short_or_simple_backup_password_is_refused() {
        for pw in ["short", "123456789012", "aaaaaaaaaaaa"] { assert!(backup("a".into(), "b".into(), "x".into(), pw.into()).is_err(), "{pw}"); }
    }
    #[test]
    fn vault_only_accepts_a_list_or_entries_and_settings() {
        assert!(save(&Value::Null).is_err()); assert!(save(&json!({"a": 1})).is_err());
        assert!(valid(&json!([])) && valid(&json!({"e": [], "m": {}})) && !valid(&json!({"e": [], "m": 1})));
    }
    #[test]
    fn weak_passwords_are_refused() {
        for w in ["aaaaaaaaaaaa", "123456789012", "abcdefghijkl", "zyxwvutsrqpo", "Qwerty-12345x", "MyPassword9876", "121212121212"] { assert!(weak(w), "{w}"); }
        for ok in ["pNUblQtKozml", "k3Rt9vXq2LmZ", "чайник-гитара-42"] { assert!(!weak(ok), "{ok}"); }
    }
    #[test]
    fn argon2_parameters_from_a_damaged_file_are_bounded() {
        let mut v = seal(&[1u8; 32], &[2u8; 16], &json!([])).unwrap();
        v["m"] = json!(4_000_000_000u64);
        assert_eq!(unseal(&v, "whatever-pass-12").unwrap_err().to_string(), "corrupted file");
    }
    // the whole path on disk: new vault, reopen, wrong password, all-or-nothing rekey, lock, migration of an old DPAPI vault
    #[test]
    fn open_save_migrate_rekey_lock() {
        let _g = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
        let d = std::env::temp_dir().join(format!("pm-open-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        std::env::set_var("APPDATA", &d);
        let pw = "Str0ng-Pass-77";
        assert_eq!(state(), "new");
        assert_eq!(open("short").unwrap_err().to_string(), "password too short");
        assert_eq!(open("aaaaaaaaaaaa").unwrap_err().to_string(), "password too simple");
        assert_eq!(open(pw).unwrap(), json!([]));
        save(&json!({"e": [{"site": "a"}], "m": {"pm-order": ["a"]}})).unwrap();
        lock();
        assert_eq!(state(), "locked");
        assert_eq!(open("Wrong-Pass-123").unwrap_err().to_string(), "wrong password");
        assert!(save(&json!([])).is_err()); // locked: nothing can be written
        assert_eq!(open(pw).unwrap()["e"][0]["site"], "a");
        assert!(rekey("aaaaaaaaaaaa", &json!([])).is_err()); // a bad new password changes nothing
        rekey("Other-Pass-9876", &json!({"e": [{"site": "b"}], "m": {}})).unwrap();
        lock();
        assert!(open(pw).is_err());
        assert_eq!(open("Other-Pass-9876").unwrap()["e"][0]["site"], "b");
        lock();
        let old = json!({"v": 3, "d": B64.encode(dpapi(br#"[{"site":"old"}]"#, true).unwrap())}).to_string();
        fs::write(dir().join("vault.json"), &old).unwrap();
        fs::write(dir().join("vault-2026-01-01.bak"), &old).unwrap();
        assert_eq!(state(), "old");
        assert_eq!(open(pw).unwrap()[0]["site"], "old");
        assert!(!dir().join("vault-2026-01-01.bak").exists() && !dir().join("vault.json.v3old").exists()); // old DPAPI copies are gone
        lock();
        assert_eq!(open(pw).unwrap()[0]["site"], "old"); // now a v5 file
        lock();
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn vault_roundtrip_wrong_password_and_tampering() {
        let (pw, salt) = ("correct horse battery", [7u8; 16]);
        let key = derive(pw, &salt, KDF.0, KDF.1).unwrap();
        let v = seal(&key, &salt, &json!([{"site": "a"}])).unwrap();
        assert!(!v.to_string().contains("site")); // only ciphertext on disk
        let (k2, _, d) = unseal(&v, pw).unwrap();
        assert_eq!((k2, d), (key, json!([{"site": "a"}])));
        assert_eq!(unseal(&v, "wrong password!!").unwrap_err().to_string(), "wrong password");
        let mut bad = v.clone();
        bad["d"] = json!(B64.encode(b"tampered-bytes-tampered-bytes!!"));
        assert!(unseal(&bad, pw).is_err());
        assert!(set_key("short").is_err());
    }
    #[test]
    fn the_old_passvault_folder_is_moved_once() {
        let _g = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
        let d = std::env::temp_dir().join(format!("pm-move-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("passvault")).unwrap();
        fs::write(d.join("passvault").join("vault.json"), "v").unwrap();
        std::env::set_var("APPDATA", &d);
        migrate_dir();
        assert!(dir().join("vault.json").exists() && !d.join("passvault").exists());
        fs::create_dir_all(d.join("passvault")).unwrap();
        fs::write(d.join("passvault").join("vault.json"), "other").unwrap();
        migrate_dir(); // the new folder already exists: nothing is overwritten
        assert_eq!(fs::read_to_string(dir().join("vault.json")).unwrap(), "v");
        let _ = fs::remove_dir_all(&d);
    }
    #[test]
    fn zero_overwrites_in_place_and_wipe_removes() {
        let d = std::env::temp_dir().join(format!("pm-zero-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let f = d.join("x");
        fs::write(&f, b"secret passwords").unwrap();
        zero(&f).unwrap();
        assert_eq!(fs::read(&f).unwrap(), vec![0u8; 16]); // same length, all zeros
        wipe(&f);
        assert!(!f.exists());
        let _ = fs::remove_dir_all(&d);
    }
    // vaults written with the older, cheaper Argon2 numbers still open and are upgraded in place
    #[test]
    fn old_argon2_settings_are_upgraded_on_unlock() {
        let _g = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
        let d = std::env::temp_dir().join(format!("pm-upg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        std::env::set_var("APPDATA", &d);
        fs::create_dir_all(dir()).unwrap();
        let (pw, salt) = ("Upgr4de-Pass-55", [9u8; 16]);
        let key = derive(pw, &salt, 65536, 3).unwrap();
        let mut v = seal(&key, &salt, &json!([{"site": "x"}])).unwrap();
        v["m"] = json!(65536u32);
        fs::write(dir().join("vault.json"), v.to_string()).unwrap();
        assert_eq!(open(pw).unwrap()[0]["site"], "x");
        let now: Value = serde_json::from_slice(&fs::read(dir().join("vault.json")).unwrap()).unwrap();
        assert_eq!(now["m"], json!(KDF.0));
        lock();
        assert_eq!(open(pw).unwrap()[0]["site"], "x"); // still opens with the same password
        lock();
        let _ = fs::remove_dir_all(&d);
    }
    #[test]
    fn old_dpapi_copies_are_purged() {
        let d = std::env::temp_dir().join(format!("pm-purge-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("vault-2026-01-01.bak"), r#"{"v":3,"d":"x"}"#).unwrap();
        fs::write(d.join("vault-2026-01-02.bak"), r#"{"v":5,"d":"x"}"#).unwrap();
        purge_old(&d);
        assert!(!d.join("vault-2026-01-01.bak").exists() && d.join("vault-2026-01-02.bak").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn only_our_own_origin_is_accepted() {
        assert!(ours(&format!("{ORIGIN}/")));
        assert!(ours(ORIGIN));
        assert!(!ours(&format!("{ORIGIN}.evil.com/")));
        assert!(!ours("file:///C:/x.html"));
    }
}
