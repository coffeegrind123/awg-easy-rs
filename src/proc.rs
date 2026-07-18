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

/// Harden a supervised child before it `exec`s: set `PR_SET_NO_NEW_PRIVS` so
/// the daemon (and anything it spawns) can never gain privileges through a
/// set-uid / set-gid / file-capability binary for the rest of its lifetime.
///
/// The bundled daemons (Xray, tor, dnscrypt-proxy, telemt, MasterDnsVPN) are
/// large network-facing C/Go programs; this caps the blast radius of a
/// compromise in one of them — an attacker who gains code execution can no
/// longer escalate via a suid helper. Docker's `no-new-privileges` gives the
/// same guarantee, but only when the operator uses our compose file; applying
/// it here makes the property hold for bare-metal / systemd launches too.
/// `no_new_privs` is a one-way, inherited flag, so setting it per-child is
/// safe and idempotent.
///
/// Kept deliberately minimal (no uid/gid drop): the daemons bind privileged
/// ports (Xray :443, MasterDnsVPN :53) and would need a CAP_NET_BIND_SERVICE
/// ambient-capability dance to run unprivileged, which is left to the
/// container's capability confinement (`cap_drop: [ALL]` + `NET_ADMIN`).
pub fn harden_child(cmd: &mut tokio::process::Command) {
    // SAFETY: the closure runs in the forked child between fork and exec. It
    // performs a single async-signal-safe `prctl` and no allocation/locking,
    // as required for `pre_exec`. PR_SET_NO_NEW_PRIVS cannot fail on any kernel
    // ≥ 3.5; on the theoretical failure path we surface errno so the spawn
    // fails loudly rather than silently running unhardened.
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
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

/// A supervised child that stays up at least this long is considered to have
/// started healthily; when it later exits, the supervisor resets its
/// crash-loop counter so a single death after a long, healthy run gets a fresh
/// backoff budget. A child that dies faster than this keeps accumulating
/// attempts, so the exponential backoff escalates and the give-up cap is
/// actually reachable (without this, resetting the counter on every spawn
/// pinned a persistently-failing child at a ~1/s respawn loop forever).
pub const HEALTHY_UPTIME: Duration = Duration::from_secs(30);

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
