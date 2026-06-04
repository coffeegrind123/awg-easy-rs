//! Shared subprocess-supervision primitives.
//!
//! The Xray, telemt, DNS-bundle, and MasterDnsVPN supervisors each manage a
//! tokio-spawned child with the same low-level needs: POSIX liveness checks,
//! `SIGHUP`/`SIGTERM` delivery, and a capped exponential restart backoff.
//! Those three pieces were previously copy-pasted (byte-identical, including
//! the `unsafe libc::kill` block) into all four modules. They live here once.

use std::io;
use std::time::Duration;

/// POSIX `kill -0` liveness check. Returns 0 when the process exists and we
/// can signal it (alive); `ESRCH` when it doesn't exist (dead); `EPERM` when
/// it exists but we can't signal it (still alive).
pub fn pid_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    let err = io::Error::last_os_error();
    err.raw_os_error() == Some(libc::EPERM)
}

/// Deliver `signum` to `pid`.
pub fn send_signal(pid: u32, signum: libc::c_int) -> io::Result<()> {
    // SAFETY: kill(2) is async-signal-safe and accepts an arbitrary pid_t —
    // passing a non-existent PID returns ESRCH, which we surface via
    // io::Error rather than panicking.
    let rc = unsafe { libc::kill(pid as libc::pid_t, signum) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Capped exponential restart backoff: `2^(attempts-1)` seconds, doubling each
/// crash. `attempts` is the 1-based restart count. The exponent is capped at 5
/// (`attempts.min(6) - 1`), so the effective ceiling is 32s — this preserves
/// the exact formula the four supervisors shared. `saturating_sub` guards the
/// `attempts == 0` edge so the shift can never underflow.
pub fn restart_backoff(attempts: u32) -> Duration {
    Duration::from_secs((1u64 << (attempts.min(6).saturating_sub(1))).min(60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps_at_32s() {
        assert_eq!(restart_backoff(0).as_secs(), 1); // saturating: no underflow
        assert_eq!(restart_backoff(1).as_secs(), 1);
        assert_eq!(restart_backoff(2).as_secs(), 2);
        assert_eq!(restart_backoff(3).as_secs(), 4);
        assert_eq!(restart_backoff(4).as_secs(), 8);
        assert_eq!(restart_backoff(5).as_secs(), 16);
        assert_eq!(restart_backoff(6).as_secs(), 32);
        // Exponent is capped at 5, so the ceiling is 32s for all higher counts.
        assert_eq!(restart_backoff(7).as_secs(), 32);
        assert_eq!(restart_backoff(100).as_secs(), 32);
    }

    #[test]
    fn pid_alive_self_is_true_and_bogus_is_false() {
        assert!(pid_alive(std::process::id()));
        // PID 0x7FFF_FFFE is almost certainly not a live process.
        assert!(!pid_alive(2_147_483_646));
    }
}
