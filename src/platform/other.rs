//! Degraded sandbox for non-Linux, non-macOS platforms.
//!
//! Provides minimal isolation — only environment hardening. No Landlock,
//! no seccomp, no cgroups, no network namespace. Suitable for development
//! and testing only. Production workloads should use Linux.

use std::os::unix::io::RawFd;
use std::process::{Command, Stdio};

use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// Degraded sandbox (no OS-level isolation).
pub struct Other;

impl Sandbox for Other {
    fn launch(
        &self,
        cfg: &Config,
        cmd: &str,
        args: &[&str],
        _extra_fds: &[RawFd],
    ) -> crate::Result<Process> {
        let tmp_dir = crate::env::make_tmp_dir(&cfg.task_id)?;

        let mut command = Command::new(cmd);
        command.args(args);

        if let Some(work_dir) = &cfg.work_dir {
            command.current_dir(work_dir);
        }

        let env_vars = crate::env::minimal_env(&tmp_dir);
        command.env_clear();
        for (k, v) in &env_vars {
            command.env(k, v);
        }

        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());

        let child = command.spawn().map_err(|e| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            Error::Process(format!("start process: {e}"))
        })?;

        Ok(Process {
            child,
            tmp_dir,
            cgroup_path: None,
            cgroup_mgr: None,
        })
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
