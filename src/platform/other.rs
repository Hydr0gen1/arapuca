//! Degraded sandbox for non-Linux, non-macOS platforms.
//!
//! Provides no OS-level isolation — suitable for development only.
//! Stub for commit 7a; full implementation in 7c.

use std::os::unix::io::RawFd;

use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// Degraded sandbox (no OS-level isolation).
pub struct Other;

impl Sandbox for Other {
    fn launch(
        &self,
        _cfg: &Config,
        _cmd: &str,
        _args: &[&str],
        _extra_fds: &[RawFd],
    ) -> crate::Result<Process> {
        Err(Error::Process("not yet implemented".into()))
    }

    fn available(&self) -> crate::Result<()> {
        Err(Error::Process(format!(
            "platform {} has degraded sandbox security (development only)",
            std::env::consts::OS
        )))
    }

    fn netns_available(&self) -> bool {
        false
    }

    fn cgroups_available(&self) -> bool {
        false
    }
}
