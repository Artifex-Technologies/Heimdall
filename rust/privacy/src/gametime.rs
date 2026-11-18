//! Game time (Yggdrasil docs/GAME_TIME.md): while a game runs, the guard keeps checking new files with its own light checks,
//! and leaves the heavy part (an archive's dry run, ClamAV) for after the game. `yggdrasil-gametime status` exits 0 while a
//! game runs and 1 when none does; it reads /proc only. Without it (or when it fails or takes over 5 s) there is no game.

use std::path::Path;
use std::time::Duration;

/// Yggdrasil's game-time tool.
pub const COMMAND: &str = "/usr/bin/yggdrasil-gametime";

/// A game runs now (asks `tool status`).
pub fn playing_with(tool: &Path) -> bool {
    if !tool.is_file() {
        return false;
    }
    let child = std::process::Command::new(tool)
        .arg("status")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    match child {
        Ok(c) => {
            let out = crate::intake::wait_output(c, Duration::from_secs(5));
            !out.timed_out && out.status.is_some_and(|s| s.code() == Some(0))
        }
        Err(_) => false,
    }
}

/// A game runs now. HEIMDALL_GAMETIME names another tool (the daemon reads the same variable; tests use it).
pub fn playing() -> bool {
    match std::env::var_os("HEIMDALL_GAMETIME").filter(|v| !v.is_empty()) {
        Some(t) => playing_with(Path::new(&t)),
        None => playing_with(Path::new(COMMAND)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tool_decides() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("heimdall-gametime-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        for (code, want) in [(0, true), (1, false), (3, false)] {
            let t = d.join(format!("tool{code}"));
            std::fs::write(&t, format!("#!/bin/sh\n[ \"$1\" = status ] && exit {code}\nexit 9\n")).unwrap();
            std::fs::set_permissions(&t, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(playing_with(&t), want, "exit {code}");
        }
        assert!(!playing_with(&d.join("missing")), "no tool: no game");
        let _ = std::fs::remove_dir_all(&d);
    }
}
