//! Go's `log` package lines, for the commands that log as Go's do: the prefix first, then (with `log.LstdFlags`) the local date
//! and time ("2006/01/02 15:04:05 "), then the message, with a newline added when it has none. `log.Printf` is
//! `Logger::std()`; `log.New(os.Stderr, "heimdalld contain: ", 0)` is `Logger::new("heimdalld contain: ", false)`.

use crate::gotime::Time;
use std::io::Write;

pub struct Logger {
    prefix: String,
    stamp: bool,
}

impl Logger {
    /// The standard logger (`log.Printf`): no prefix, date and time.
    pub fn std() -> Logger {
        Logger { prefix: String::new(), stamp: true }
    }

    pub fn new(prefix: &str, stamp: bool) -> Logger {
        Logger { prefix: prefix.to_string(), stamp }
    }

    /// The line Go would write at `t`.
    pub fn line_at(&self, t: Time, msg: &str) -> String {
        let mut out = self.prefix.clone();
        if self.stamp {
            out.push_str(&t.local().format("2006/01/02 15:04:05 "));
        }
        out.push_str(msg);
        if !msg.ends_with('\n') {
            out.push('\n');
        }
        out
    }

    /// Writes the line to standard error, in one write as Go does.
    pub fn print(&self, msg: &str) {
        let _ = std::io::stderr().write_all(self.line_at(Time::now(), msg).as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_as_go() {
        let t = Time::parse_rfc3339("2026-11-10T20:01:02Z").unwrap();
        assert_eq!(Logger::new("heimdalld contain: ", false).line_at(t, "x"), "heimdalld contain: x\n");
        assert_eq!(Logger::new("", false).line_at(t, "y\n"), "y\n");
        let l = Logger::std().line_at(t, "z");
        assert!(l.len() == "2026/11/10 20:01:02 z\n".len() && l.ends_with(" z\n"), "{l}");
    }
}
