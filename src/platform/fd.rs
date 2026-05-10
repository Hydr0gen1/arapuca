//! Shared FD helpers for platform sandbox implementations.
//!
//! Provides extra_fds validation and the two-pass FD remapping used
//! inside pre_exec closures.

use std::os::unix::io::RawFd;

use crate::{Config, Error};

// Upper bound on caller-supplied extra FDs. The remap uses a Vec
// (via ManuallyDrop) so any count works; 16 is a practical limit
// that bounds pre_exec syscall overhead (~96 calls at n=16).
const MAX_EXTRA_FDS: usize = 16;

pub(super) fn validate_extra_fds(fds: &[RawFd], cfg: &Config) -> crate::Result<()> {
    if fds.len() > MAX_EXTRA_FDS {
        return Err(Error::Validation(format!(
            "extra_fds: too many FDs ({}, max {MAX_EXTRA_FDS})",
            fds.len()
        )));
    }
    for (i, &fd) in fds.iter().enumerate() {
        if fd < 0 {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: negative FD {fd}"
            )));
        }
        if fd <= 2 {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: FD {fd} is stdin/stdout/stderr \
                 (use cfg.stdin/stdout/stderr instead)"
            )));
        }
        if fds[..i].contains(&fd) {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: duplicate FD {fd}"
            )));
        }
        let stdio_fds = [cfg.stdin, cfg.stdout, cfg.stderr];
        if stdio_fds.contains(&Some(fd)) {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: FD {fd} overlaps with stdio config"
            )));
        }
    }
    Ok(())
}

/// Remap extra FDs to deterministic positions (3, 4, ...).
///
/// Must only be called inside a pre_exec closure (between fork and
/// exec). All operations are async-signal-safe. The ManuallyDrop
/// wrapper on the caller's Vec prevents free() from running in the
/// child process.
///
/// Uses a two-pass approach to avoid FD collisions when source FDs
/// overlap with the target range [3..3+N):
/// - Phase 1: evacuate sources in the target range to high FDs.
/// - Phase 2: dup2 to final positions and clear CLOEXEC.
pub(super) unsafe fn remap_fds(
    fds: &mut std::mem::ManuallyDrop<Vec<RawFd>>,
) -> std::io::Result<()> {
    let fds = fds.as_mut_slice();
    let base = 3i32;
    let ceiling = base + fds.len() as i32;

    // Phase 1: evacuate source FDs in [base..ceiling) to above
    // the target range.
    for slot in fds.iter_mut() {
        if *slot >= base && *slot < ceiling {
            // SAFETY: F_DUPFD_CLOEXEC returns a new FD >= ceiling
            // that we own, with CLOEXEC set atomically.
            let high = unsafe { libc::fcntl(*slot, libc::F_DUPFD_CLOEXEC, ceiling) };
            if high == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Non-fatal: original has CLOEXEC, kernel cleans up at exec.
            unsafe { libc::close(*slot) };
            *slot = high;
        }
    }

    // Phase 2: place into final positions.
    for (i, &fd) in fds.iter().enumerate() {
        let target = base + i as i32;
        if fd != target {
            // SAFETY: dup2 atomically copies fd to target.
            if unsafe { libc::dup2(fd, target) } == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Non-fatal: source has CLOEXEC, kernel cleans up at exec.
            unsafe { libc::close(fd) };
        }
        // Clear CLOEXEC so the FD survives exec.
        // SAFETY: fcntl F_GETFD/F_SETFD are simple flag operations.
        let flags = unsafe { libc::fcntl(target, libc::F_GETFD) };
        if flags == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_config() -> Config {
        Config {
            profile: crate::Profile::default(),
            socket_dir: PathBuf::from("/tmp"),
            task_id: "test".into(),
            phase: String::new(),
            work_dir: None,
            stdin: None,
            stdout: None,
            stderr: None,
            extra_fds: vec![],
            network_proxy_socket: None,
            env: vec![],
            audit_sink: None,
            audit_verbosity: crate::audit::AuditVerbosity::default(),
            audit_principal: None,
            audit_correlation_id: None,
        }
    }

    #[test]
    fn validate_empty() {
        assert!(validate_extra_fds(&[], &test_config()).is_ok());
    }

    #[test]
    fn validate_valid_fds() {
        assert!(validate_extra_fds(&[5, 10, 20], &test_config()).is_ok());
    }

    #[test]
    fn validate_fd_three_ok() {
        assert!(validate_extra_fds(&[3], &test_config()).is_ok());
    }

    #[test]
    fn validate_negative_fd() {
        let err = validate_extra_fds(&[-1], &test_config()).unwrap_err();
        assert!(err.to_string().contains("negative FD"));
    }

    #[test]
    fn validate_fd_zero() {
        let err = validate_extra_fds(&[0], &test_config()).unwrap_err();
        assert!(err.to_string().contains("stdin/stdout/stderr"));
    }

    #[test]
    fn validate_fd_one() {
        let err = validate_extra_fds(&[1], &test_config()).unwrap_err();
        assert!(err.to_string().contains("stdin/stdout/stderr"));
    }

    #[test]
    fn validate_fd_two() {
        let err = validate_extra_fds(&[2], &test_config()).unwrap_err();
        assert!(err.to_string().contains("stdin/stdout/stderr"));
    }

    #[test]
    fn validate_duplicate() {
        let err = validate_extra_fds(&[5, 5], &test_config()).unwrap_err();
        assert!(err.to_string().contains("duplicate FD 5"));
    }

    #[test]
    fn validate_stdio_overlap() {
        let mut cfg = test_config();
        cfg.stdin = Some(7);
        let err = validate_extra_fds(&[7], &cfg).unwrap_err();
        assert!(err.to_string().contains("overlaps with stdio"));
    }

    #[test]
    fn validate_too_many() {
        let fds: Vec<RawFd> = (3..3 + MAX_EXTRA_FDS as i32 + 1).collect();
        let err = validate_extra_fds(&fds, &test_config()).unwrap_err();
        assert!(err.to_string().contains("too many FDs"));
    }

    #[test]
    fn validate_exactly_max() {
        let fds: Vec<RawFd> = (3..3 + MAX_EXTRA_FDS as i32).collect();
        assert!(validate_extra_fds(&fds, &test_config()).is_ok());
    }
}
