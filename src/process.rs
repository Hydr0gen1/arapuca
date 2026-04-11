//! Sandboxed process lifecycle.
//!
//! Represents a running sandboxed subprocess with methods for waiting,
//! reading resource usage, and cleanup.

use std::path::PathBuf;

use crate::ResourceUsage;

/// A running sandboxed subprocess.
pub struct Process {
    /// The child process handle.
    pub(crate) child: std::process::Child,
    /// Sandbox-created temp directory (HOME for the subprocess).
    pub(crate) tmp_dir: PathBuf,
    /// Cgroup cleanup closure (None if no cgroup).
    pub(crate) cgroup_path: Option<PathBuf>,
    /// Reference to the cgroup manager for stats/cleanup.
    pub(crate) cgroup_mgr: Option<std::sync::Arc<crate::cgroup::CgroupManager>>,
}

impl Process {
    /// Get the PID of the sandboxed process.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Wait for the process to exit and return the exit status.
    pub fn wait(&mut self) -> crate::Result<std::process::ExitStatus> {
        self.child
            .wait()
            .map_err(|e| crate::Error::Process(format!("wait: {e}")))
    }

    /// Read resource usage from the agent's cgroup.
    ///
    /// Must be called before `cleanup()` which destroys the cgroup.
    /// Returns zero values if cgroups are unavailable.
    pub fn resource_stats(&self) -> ResourceUsage {
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &self.cgroup_path) {
            mgr.read_stats(path)
        } else {
            ResourceUsage::default()
        }
    }

    /// Read the OOM kill count from the agent's cgroup.
    ///
    /// Must be called before `cleanup()` which destroys the cgroup.
    /// Returns 0 if cgroups are unavailable.
    pub fn oom_count(&self) -> u32 {
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &self.cgroup_path) {
            mgr.read_oom_events(path)
        } else {
            0
        }
    }

    /// Clean up the sandbox temp directory and cgroup.
    ///
    /// Must only be called after `wait()` returns.
    pub fn cleanup(self) {
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &self.cgroup_path) {
            let _ = mgr.destroy(path);
        }
        if self.tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.tmp_dir);
        }
    }
}
