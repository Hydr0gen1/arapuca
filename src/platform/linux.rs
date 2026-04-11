//! Linux sandbox implementation.
//!
//! Coordinates Landlock, seccomp, cgroups v2, and network namespace
//! isolation to launch fully sandboxed subprocesses.
//!
//! Full implementation in commit 7b.

use std::os::unix::io::RawFd;
use std::sync::Arc;

use crate::cgroup::CgroupManager;
use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// Linux sandbox implementation.
pub struct Linux {
    cgroup_mgr: Option<Arc<CgroupManager>>,
}

impl Linux {
    /// Create a new Linux sandbox, probing available features.
    pub fn new() -> crate::Result<Self> {
        let cgroup_mgr = CgroupManager::new()?.map(Arc::new);
        Ok(Self { cgroup_mgr })
    }
}

impl Sandbox for Linux {
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
        // Check that unshare is available.
        std::process::Command::new("unshare")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| {
                Error::Process(format!(
                    "unshare not found: {e} (required for network namespace isolation)"
                ))
            })?;
        Ok(())
    }

    fn netns_available(&self) -> bool {
        crate::netns::available()
    }

    fn cgroups_available(&self) -> bool {
        self.cgroup_mgr.is_some()
    }
}
