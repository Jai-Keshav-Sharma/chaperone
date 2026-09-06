//! Console access for the hook-local approval flow (flows/03 + flows/05).
//!
//! The hook's stdin carries the event JSON, so a REAL TTY must be opened
//! explicitly for the approve/deny prompt: `CONIN$`/`CONOUT$` on Windows,
//! `/dev/tty` on Unix. The prompt has a hard time bound (~30s) because the
//! host kills hooks on its own timeout (~60s).

use std::io::{BufRead, BufReader, Write};

/// Whether a real interactive console is available. False in a service or a
/// redirected non-interactive process → the hook denies with `DENY_NO_CONSOLE`
/// (review-2 ADOPT-6), leaving the escalation pending for the CLI/dashboard.
#[cfg(windows)]
pub fn console_available() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .open("CONIN$")
        .is_ok()
        && std::fs::OpenOptions::new()
            .write(true)
            .open("CONOUT$")
            .is_ok()
}

#[cfg(not(windows))]
pub fn console_available() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .is_ok()
}

/// Write the prompt to the real console.
pub fn write_prompt(text: &str) -> std::io::Result<()> {
    let mut out = open_output()?;
    out.write_all(text.as_bytes())?;
    out.flush()
}

/// Read one line from the real console (BLOCKING — the caller applies the time
/// bound by running this on a separate thread).
pub fn read_line_blocking() -> std::io::Result<String> {
    let input = open_input()?;
    let mut reader = BufReader::new(input);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(line.trim().to_string())
}

#[cfg(windows)]
fn open_output() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).open("CONOUT$")
}

#[cfg(not(windows))]
fn open_output() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).open("/dev/tty")
}

#[cfg(windows)]
fn open_input() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().read(true).open("CONIN$")
}

#[cfg(not(windows))]
fn open_input() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().read(true).open("/dev/tty")
}
