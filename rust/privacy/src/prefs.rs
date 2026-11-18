//! The privacy pack's switches, one file per person: `$XDG_CONFIG_HOME/heimdall/privacy.json` (by default
//! `~/.config/heimdall/privacy.json`): `{"downloads_guard": bool, "folders_guard": bool, "remove_hidden_info": bool,
//! "lookalike_warnings": bool}`. `downloads_guard` switches the whole guard; `folders_guard` (added 2026-11-18) only the
//! watching of the person's own folders (Desktop, Documents, Pictures, Music, Videos) and the notice when a drive is
//! connected.
//! Settings > Security > Privacy writes it; the downloads guard, Minos, Agora, Settings and Labyrinth's network question read
//! it. Everything is on by default: a missing file, a missing key or a value that is not true or false counts as on.

use std::path::PathBuf;

/// The folder of the person's settings.
pub fn config_home() -> PathBuf {
    match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()).map(PathBuf::from) {
        Some(p) if p.is_absolute() => p,
        _ => home().join(".config"),
    }
}

/// The home folder ($HOME, else the account's).
pub fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    // SAFETY: getpwuid_r with our own buffer; the result is copied before the buffer goes
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; 4096];
        if libc::getpwuid_r(libc::getuid(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) == 0 && !out.is_null() {
            return PathBuf::from(std::ffi::CStr::from_ptr(pw.pw_dir).to_string_lossy().into_owned());
        }
    }
    PathBuf::from("/")
}

/// The switches file.
pub fn path() -> PathBuf {
    config_home().join("heimdall").join("privacy.json")
}

/// The switches this file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefs {
    pub downloads_guard: bool,
    pub folders_guard: bool,
    pub remove_hidden_info: bool,
    pub lookalike_warnings: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs { downloads_guard: true, folders_guard: true, remove_hidden_info: true, lookalike_warnings: true }
    }
}

impl Prefs {
    /// Reads the text of the file (anything unreadable is the default: on).
    pub fn parse(text: &[u8]) -> Prefs {
        let v: serde_json::Value = serde_json::from_slice(text).unwrap_or(serde_json::Value::Null);
        let on = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(true);
        Prefs {
            downloads_guard: on("downloads_guard"),
            folders_guard: on("folders_guard"),
            remove_hidden_info: on("remove_hidden_info"),
            lookalike_warnings: on("lookalike_warnings"),
        }
    }

    /// The person's switches now.
    pub fn load() -> Prefs {
        // a switches file is a few bytes; a bigger one is not ours
        let text = std::fs::File::open(path()).and_then(|f| {
            let mut b = vec![];
            std::io::Read::read_to_end(&mut std::io::Read::take(f, 64 * 1024), &mut b).map(|_| b)
        });
        text.map(|t| Prefs::parse(&t)).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_is_on_unless_switched_off() {
        assert_eq!(Prefs::parse(b""), Prefs::default());
        assert_eq!(Prefs::parse(b"[]"), Prefs::default());
        assert_eq!(Prefs::parse(b"{\"downloads_guard\": \"no\"}"), Prefs::default(), "not a boolean: on");
        let p = Prefs::parse(br#"{"downloads_guard": false, "lookalike_warnings": true, "other": 1}"#);
        assert!(!p.downloads_guard && p.folders_guard && p.remove_hidden_info && p.lookalike_warnings);
        assert!(!Prefs::parse(br#"{"folders_guard": false}"#).folders_guard);
    }
}
