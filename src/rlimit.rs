//! POSIX resource limits (rlimits).
//!
//! Sets hard resource limits on the sandboxed process:
//! - RLIMIT_NPROC: number of processes
//! - RLIMIT_CPU: CPU time in seconds
//! - RLIMIT_FSIZE: maximum file size
//!
//! Memory is enforced via cgroups v2 `memory.max` (Linux) or RSS
//! polling (macOS), not RLIMIT_AS. RLIMIT_AS limits virtual address
//! space, which breaks runtimes (Go, JVM, .NET) that reserve large
//! PROT_NONE mappings at startup. Explicit opt-in via the
//! `ARAPUCA_RLIMIT_AS` env var is still available in `apply_from_env()`.

use crate::{Error, Profile};

/// Apply resource limits from the profile to the current process.
///
/// Sets RLIMIT_NPROC and RLIMIT_FSIZE. Memory is intentionally NOT
/// limited via RLIMIT_AS here — use cgroups v2 `memory.max` instead.
/// RLIMIT_AS restricts virtual address space, which breaks Go, JVM,
/// and .NET runtimes that reserve large PROT_NONE mappings at startup.
///
/// Each limit is set as both soft and hard (identical values), meaning
/// the process cannot raise them. Limits of 0 mean "no limit" and are
/// skipped.
///
/// # Errors
///
/// Returns an error if any `prlimit64` call fails.
#[must_use = "rlimit errors must be handled"]
pub fn apply(profile: &Profile) -> crate::Result<()> {
    if profile.max_pids > 0 {
        set_rlimit(
            libc::RLIMIT_NPROC,
            u64::from(profile.max_pids),
            "RLIMIT_NPROC",
        )?;
    }
    if profile.max_file_size_mb > 0 {
        let bytes = profile.max_file_size_mb * 1024 * 1024;
        set_rlimit(libc::RLIMIT_FSIZE, bytes, "RLIMIT_FSIZE")?;
    }
    Ok(())
}

/// Apply resource limits parsed from environment variables.
///
/// Used by the binary. Reads `ARAPUCA_RLIMIT_AS`, `ARAPUCA_RLIMIT_NPROC`,
/// `ARAPUCA_RLIMIT_CPU`, `ARAPUCA_RLIMIT_FSIZE` from the environment.
pub fn apply_from_env() -> crate::Result<()> {
    if let Some(v) = parse_env_u64("ARAPUCA_RLIMIT_AS")? {
        set_rlimit(libc::RLIMIT_AS, v, "RLIMIT_AS")?;
    }
    if let Some(v) = parse_env_u64("ARAPUCA_RLIMIT_NPROC")? {
        set_rlimit(libc::RLIMIT_NPROC, v, "RLIMIT_NPROC")?;
    }
    if let Some(v) = parse_env_u64("ARAPUCA_RLIMIT_CPU")? {
        set_rlimit(libc::RLIMIT_CPU, v, "RLIMIT_CPU")?;
    }
    if let Some(v) = parse_env_u64("ARAPUCA_RLIMIT_FSIZE")? {
        set_rlimit(libc::RLIMIT_FSIZE, v, "RLIMIT_FSIZE")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_rlimit(resource: libc::__rlimit_resource_t, value: u64, name: &str) -> crate::Result<()> {
    let rlim = libc::rlimit64 {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: prlimit64 with pid=0 targets the calling process.
    // The rlimit struct is valid and on the stack.
    let ret = unsafe { libc::prlimit64(0, resource, &rlim, std::ptr::null_mut()) };
    if ret != 0 {
        return Err(Error::Rlimit(format!(
            "{name}: {}",
            std::io::Error::last_os_error()
        )));
    }
    log::debug!("rlimit: {name} = {value}");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_rlimit(resource: libc::c_int, value: u64, name: &str) -> crate::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: setrlimit with valid resource and rlimit struct.
    let ret = unsafe { libc::setrlimit(resource, &rlim) };
    if ret != 0 {
        return Err(Error::Rlimit(format!(
            "{name}: {}",
            std::io::Error::last_os_error()
        )));
    }
    log::debug!("rlimit: {name} = {value}");
    Ok(())
}

fn parse_env_u64(name: &str) -> crate::Result<Option<u64>> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => {
            let n = v
                .parse::<u64>()
                .map_err(|e| Error::Rlimit(format!("parse {name}: {e}")))?;
            if n > 0 { Ok(Some(n)) } else { Ok(None) }
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_limits_are_skipped() {
        let profile = Profile::default();
        assert!(apply(&profile).is_ok());
    }

    #[test]
    fn parse_env_missing() {
        assert!(parse_env_u64("ARAPUCA_TEST_NONEXISTENT").unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn apply_does_not_set_rlimit_as() {
        let before = {
            let mut rlim: libc::rlimit64 = unsafe { std::mem::zeroed() };
            // SAFETY: prlimit64 with pid=0 reads the current process limit.
            unsafe { libc::prlimit64(0, libc::RLIMIT_AS, std::ptr::null(), &mut rlim) };
            rlim.rlim_cur
        };

        let profile = Profile {
            max_memory_mb: 256,
            ..Default::default()
        };
        apply(&profile).unwrap();

        let after = {
            let mut rlim: libc::rlimit64 = unsafe { std::mem::zeroed() };
            // SAFETY: prlimit64 with pid=0 reads the current process limit.
            unsafe { libc::prlimit64(0, libc::RLIMIT_AS, std::ptr::null(), &mut rlim) };
            rlim.rlim_cur
        };

        assert_eq!(before, after, "apply() must not modify RLIMIT_AS");
    }

    #[test]
    fn apply_from_env_honors_explicit_rlimit_as() {
        // SAFETY: test-only env manipulation, no concurrent threads
        // reading this variable.
        unsafe { std::env::set_var("ARAPUCA_RLIMIT_AS", "17179869184") };
        let result = apply_from_env();
        unsafe { std::env::remove_var("ARAPUCA_RLIMIT_AS") };
        assert!(result.is_ok(), "explicit ARAPUCA_RLIMIT_AS must be honored");
    }
}
