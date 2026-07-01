//! Minimal SUID-root shell-exec helper.
//!
//! Usage: `rootshell -c "<command>"`
//!
//! Meant to be installed setuid-root (`chown root:root && chmod 4755`) so
//! a lower-privilege invocation (e.g. an unprivileged `adb shell` session)
//! can still run maintenance commands with full root privileges, without
//! re-running a network exploit chain every time — install once via
//! whatever initial root access got the binary onto the device, then use
//! this for everything after.
//!
//! The privilege escalation itself comes from the SUID bit (a kernel
//! mechanism, not this program's logic) — `setuid`/`setgid` here just
//! explicitly collapse the real/effective/saved UID and GID to 0, since
//! some shells and libc versions leave the real UID unprivileged even
//! under an SUID effective UID, which would otherwise leak through to
//! whatever the spawned command execs next.
//!
//! There's genuinely one sane way to write this — accept a command
//! string, escalate, exec it — so this is a from-scratch, independent
//! implementation of that one shape, not a derivative of anything.

use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || args[1] != "-c" {
        eprintln!("usage: rootshell -c <command>");
        return ExitCode::FAILURE;
    }

    #[cfg(unix)]
    unsafe {
        if libc::setgid(0) != 0 || libc::setuid(0) != 0 {
            eprintln!("rootshell: failed to escalate to root (is the SUID bit set and owner root:root?)");
            return ExitCode::FAILURE;
        }
    }

    match Command::new("/bin/sh").arg("-c").arg(&args[2]).status() {
        Ok(status) => match status.code() {
            Some(code) => ExitCode::from(code as u8),
            None => ExitCode::FAILURE, // terminated by signal
        },
        Err(e) => {
            eprintln!("rootshell: failed to exec /bin/sh: {e}");
            ExitCode::FAILURE
        }
    }
}
