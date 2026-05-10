//! macOS sandbox implementation using Apple's Seatbelt (`sandbox-exec`).
//!
//! Provides kernel-enforced filesystem and network restrictions on macOS.
//! Unlike Linux (Landlock + seccomp + cgroups), macOS uses a single
//! Seatbelt profile for filesystem/network policy and relies on rlimits
//! for resource limits (no cgroups).
//!
//! Memory enforcement is best-effort via polling (500ms interval) since
//! macOS has no cgroup-based OOM killer. A parent-PID watchdog replaces
//! Linux's `PR_SET_PDEATHSIG`.
//!
//! `sandbox-exec` is deprecated by Apple but still works on macOS 15.

mod darwin_profile;

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// macOS sandbox implementation.
pub struct Darwin;

impl Darwin {
    /// Create a new macOS sandbox.
    pub fn new() -> crate::Result<Self> {
        Ok(Darwin)
    }

    /// Find the arapuca wrapper binary.
    fn wrapper_path() -> Option<PathBuf> {
        crate::env::wrapper_path()
    }

    /// Resolve the uv cache path on macOS.
    fn uv_cache_path() -> Option<PathBuf> {
        // uv uses ~/Library/Caches/uv on macOS.
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library/Caches/uv"))
    }

    /// Convert CPU percentage and max duration to RLIMIT_CPU seconds.
    ///
    /// The Go implementation uses: cpu_pct / 100 * duration_seconds.
    /// Example: 200% for 30 minutes = 2.0 * 1800 = 3600 seconds.
    fn cpu_pct_to_seconds(cpu_pct: u32, duration_minutes: u64) -> u64 {
        if cpu_pct == 0 || duration_minutes == 0 {
            return 0;
        }
        let factor = f64::from(cpu_pct) / 100.0;
        let duration_secs = duration_minutes * 60;
        (factor * duration_secs as f64) as u64
    }

    /// Start a memory monitoring thread that polls RSS and kills the
    /// process group if it exceeds the limit.
    ///
    /// This is a best-effort mechanism — the 500ms polling window means
    /// a process can briefly exceed the limit before being killed.
    fn start_memory_monitor(pid: u32, limit_mb: u64) {
        if limit_mb == 0 {
            return;
        }
        let limit_kb = limit_mb * 1024;
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Check if process still exists.
                // SAFETY: kill with signal 0 checks process existence
                // without sending a signal.
                let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
                if !alive {
                    break;
                }

                // Read RSS via ps.
                let output = Command::new("ps")
                    .args(["-o", "rss=", "-p", &pid.to_string()])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .output();

                let rss_kb = match output {
                    Ok(out) => {
                        let s = String::from_utf8_lossy(&out.stdout);
                        s.trim().parse::<u64>().unwrap_or(0)
                    }
                    Err(_) => continue,
                };

                if rss_kb > limit_kb {
                    log::warn!(
                        "memory limit exceeded: {rss_kb}KB > {limit_kb}KB, \
                         killing process group {pid}"
                    );
                    // Kill the entire process group.
                    // SAFETY: Sending SIGKILL to a process group. The
                    // negative PID targets the group.
                    unsafe {
                        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
                    }
                    break;
                }
            }
        });
    }

    /// Start a parent-PID watchdog thread.
    ///
    /// On macOS there is no `PR_SET_PDEATHSIG`. Instead, we poll
    /// `getppid()` every 2 seconds. If the parent PID changes (process
    /// was reparented to init/launchd), the subprocess is killed.
    fn start_parent_watchdog(child_pid: u32) {
        let original_ppid = unsafe { libc::getppid() } as u32;
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                // SAFETY: getppid() is a simple getter with no arguments.
                let current_ppid = unsafe { libc::getppid() } as u32;
                if current_ppid != original_ppid {
                    log::warn!(
                        "parent died (ppid changed {} -> {}), killing child {}",
                        original_ppid,
                        current_ppid,
                        child_pid
                    );
                    // SAFETY: Sending SIGKILL to the child's process group.
                    unsafe {
                        libc::kill(-(child_pid as libc::pid_t), libc::SIGKILL);
                    }
                    break;
                }
                // Also check if child is still alive.
                let alive = unsafe { libc::kill(child_pid as libc::pid_t, 0) } == 0;
                if !alive {
                    break;
                }
            }
        });
    }
}

impl Sandbox for Darwin {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str]) -> crate::Result<Process> {
        // Validate task ID.
        crate::sanitize_task_id(&cfg.task_id)?;

        // Create tmpdir and canonicalize for Seatbelt profile paths.
        // On macOS, /tmp -> /private/tmp. TmpDirGuard holds the canonical
        // path so that guard cleanup, Seatbelt profiles, and Process.tmp_dir
        // all use the same resolved path.
        let raw_tmp = crate::env::make_tmp_dir(&cfg.task_id)?;
        let canonical_tmp = std::fs::canonicalize(&raw_tmp).unwrap_or(raw_tmp);
        let tmp_guard = crate::env::TmpDirGuard::new(canonical_tmp);
        let tmp_dir = tmp_guard.path().to_path_buf();

        // Helper: canonicalize a path for Seatbelt profile embedding.
        // Falls back to the original if canonicalization fails (path
        // may not exist yet, e.g. socket files).
        let canon = |p: &std::path::Path| -> String {
            std::fs::canonicalize(p)
                .unwrap_or_else(|_| p.to_path_buf())
                .to_string_lossy()
                .into_owned()
        };

        // Build profile data from config. All paths must be
        // canonicalized because Seatbelt resolves symlinks in access
        // paths but stores profile paths as-is.
        let mut read_paths: Vec<String> = cfg.profile.read_paths.iter().map(|p| canon(p)).collect();

        let mut write_paths: Vec<String> =
            cfg.profile.write_paths.iter().map(|p| canon(p)).collect();

        // Add socket dir to read paths so the agent can connect.
        let has_socket_dir = !cfg.socket_dir.as_os_str().is_empty();
        if has_socket_dir {
            read_paths.push(canon(&cfg.socket_dir));
        }

        // Add tmp_dir to write paths.
        write_paths.push(tmp_dir.to_string_lossy().into_owned());

        // Add uv cache to read paths if it exists.
        if let Some(uv_cache) = Self::uv_cache_path() {
            if uv_cache.exists() {
                read_paths.push(canon(&uv_cache));
            }
        }

        // Canonicalize cmd early so exec_paths and actual_cmd use
        // the same resolved path. Seatbelt does NOT resolve symlinks
        // in the target binary path for process-exec checks.
        let canonical_cmd = canon(std::path::Path::new(cmd));

        let mut exec_paths: Vec<String> = Vec::new();
        let cmd_canon_path = std::path::Path::new(&canonical_cmd);
        if let Some(parent) = cmd_canon_path.parent() {
            if !parent.as_os_str().is_empty() {
                exec_paths.push(parent.to_string_lossy().into_owned());
            }
        }

        let control_socket = if has_socket_dir {
            Some(canon(&cfg.socket_dir.join("control.sock")))
        } else {
            None
        };
        let llm_socket = cfg.network_proxy_socket.as_ref().map(|p| canon(p));

        let profile_data = darwin_profile::ProfileData {
            read_paths,
            write_paths,
            exec_paths,
            control_socket,
            llm_socket,
        };

        // Generate the Seatbelt profile.
        let profile_path = darwin_profile::generate_profile(&tmp_dir, &profile_data)?;

        // Build the command: sandbox-exec -f profile.sb -- cmd args...
        let mut actual_cmd = canonical_cmd;
        let mut actual_args: Vec<String> = args.iter().map(|a| a.to_string()).collect();

        // Wrap with sandbox-exec. Use the absolute path because the
        // arapuca wrapper binary calls execve(), which does NOT search
        // PATH. A bare "sandbox-exec" would fail with ENOENT.
        let sandbox_exec = which_sandbox_exec()
            .ok_or_else(|| Error::Process("sandbox-exec not found in PATH".into()))?;
        let sb_args = vec![
            "-f".to_string(),
            profile_path.to_string_lossy().into_owned(),
            "--".to_string(),
            actual_cmd,
        ];
        actual_cmd = sandbox_exec;
        let mut new_args = sb_args;
        new_args.extend(actual_args);
        actual_args = new_args;

        // Optionally wrap with arapuca binary for rlimits.
        // On macOS the wrapper only applies rlimits (Landlock/seccomp
        // are gated behind cfg(linux)).
        let wrapper = Self::wrapper_path();
        if let Some(ref wrapper_path) = wrapper {
            let mut wrapper_args = vec!["--".to_string(), actual_cmd];
            wrapper_args.extend(actual_args);
            actual_cmd = wrapper_path.to_string_lossy().into_owned();
            actual_args = wrapper_args;
        }

        let mut command = Command::new(&actual_cmd);
        command.args(&actual_args);

        // Set working directory.
        if let Some(ref work_dir) = cfg.work_dir {
            command.current_dir(work_dir);
        }

        // Build minimal environment with Homebrew PATH.
        let mut env_vars = crate::env::minimal_env(&tmp_dir);

        // Override PATH to include Homebrew.
        for entry in &mut env_vars {
            if entry.0 == "PATH" {
                entry.1 = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:\
                            /usr/local/sbin:/usr/sbin:/sbin"
                    .into();
            }
        }

        // Add rlimit env vars for the wrapper (if using it).
        if wrapper.is_some() {
            let wrapper_env = crate::env::wrapper_env(&cfg.profile);
            env_vars.extend(wrapper_env);

            // Add RLIMIT_CPU if cpu_pct is set (convert % to seconds).
            // Use 30 minutes as default max duration.
            let cpu_seconds = Self::cpu_pct_to_seconds(cfg.profile.max_cpu_pct, 30);
            if cpu_seconds > 0 {
                env_vars.push(("ARAPUCA_RLIMIT_CPU".into(), cpu_seconds.to_string()));
            }
        }

        // Add network proxy socket (non-ARAPUCA prefix, not stripped).
        if let Some(ref proxy) = cfg.network_proxy_socket {
            env_vars.push((
                "AGENT_NETWORK_PROXY".into(),
                proxy.to_string_lossy().into_owned(),
            ));
        }

        // Append caller-supplied env vars (filtered for safety).
        env_vars.extend(crate::env::filter_caller_env(&cfg.env).passed);

        command.env_clear();
        for (k, v) in &env_vars {
            command.env(k, v);
        }

        // stdin/stdout/stderr redirection.
        crate::platform::setup_stdio(&mut command, cfg.stdin, "stdin", Command::stdin)?;
        crate::platform::setup_stdio(&mut command, cfg.stdout, "stdout", Command::stdout)?;
        crate::platform::setup_stdio(&mut command, cfg.stderr, "stderr", Command::stderr)?;

        super::fd::validate_extra_fds(&cfg.extra_fds, cfg)?;
        let mut fds_to_inherit = std::mem::ManuallyDrop::new(cfg.extra_fds.clone());

        // SAFETY: pre_exec runs between fork and exec. Only async-signal-safe
        // functions are used (setsid, fcntl, dup2, close). ManuallyDrop
        // prevents free() on the Vec in the child process.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if !fds_to_inherit.is_empty() {
                    super::fd::remap_fds(&mut fds_to_inherit)?;
                }
                Ok(())
            });
        }

        let child = command
            .spawn()
            .map_err(|e| Error::Process(format!("start sandboxed process: {e}")))?;

        let pid = child.id();

        // Start memory monitor thread (best-effort RSS polling).
        Self::start_memory_monitor(pid, cfg.profile.max_memory_mb);

        // Start parent-PID watchdog (replaces PR_SET_PDEATHSIG).
        Self::start_parent_watchdog(pid);

        Ok(Process {
            child: crate::process::ChildHandle::Managed(child),
            tmp_dir: tmp_guard.defuse(),
            audit_ctx: None,
            final_stats: None,
        })
    }

    fn available(&self) -> crate::Result<()> {
        // Check that sandbox-exec exists.
        Command::new("sandbox-exec")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| {
                Error::Process(format!(
                    "sandbox-exec not found: {e} \
                     (required for macOS sandbox)"
                ))
            })?;
        Ok(())
    }

    fn netns_available(&self) -> bool {
        false
    }

    fn cgroups_available(&self) -> bool {
        false
    }
}

/// Resolve the absolute path to `sandbox-exec`.
///
/// The arapuca wrapper binary uses `execve()` (not `execvp()`), which
/// requires an absolute path. A bare `"sandbox-exec"` would fail with
/// ENOENT because `execve()` does not search PATH.
fn which_sandbox_exec() -> Option<String> {
    // Fast path: standard location on macOS.
    if std::path::Path::new("/usr/bin/sandbox-exec").is_file() {
        return Some("/usr/bin/sandbox-exec".into());
    }
    // Fallback: search PATH.
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let candidate = std::path::Path::new(dir).join("sandbox-exec");
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_pct_to_seconds_basic() {
        // 200% for 30 min = 3600 seconds.
        assert_eq!(Darwin::cpu_pct_to_seconds(200, 30), 3600);
        // 100% for 30 min = 1800 seconds.
        assert_eq!(Darwin::cpu_pct_to_seconds(100, 30), 1800);
        // 0% = no limit.
        assert_eq!(Darwin::cpu_pct_to_seconds(0, 30), 0);
        // 0 duration = no limit.
        assert_eq!(Darwin::cpu_pct_to_seconds(200, 0), 0);
    }

    fn test_config_with_extra_fds(fds: Vec<i32>) -> crate::Config {
        crate::Config {
            profile: crate::Profile::default(),
            socket_dir: std::path::PathBuf::new(),
            task_id: "test".into(),
            phase: "test".into(),
            work_dir: None,
            stdin: None,
            stdout: None,
            stderr: None,
            extra_fds: fds,
            network_proxy_socket: None,
            env: vec![],
            audit_sink: None,
            audit_verbosity: crate::audit::AuditVerbosity::default(),
            audit_principal: None,
            audit_correlation_id: None,
        }
    }

    #[test]
    fn darwin_extra_fds_rejects_stdin() {
        let cfg = test_config_with_extra_fds(vec![0]);
        let err = match Darwin.launch(&cfg, "/bin/true", &[]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for FD 0"),
        };
        assert!(err.contains("stdin/stdout/stderr"), "got: {err}");
    }

    #[test]
    fn darwin_extra_fds_rejects_duplicates() {
        let cfg = test_config_with_extra_fds(vec![5, 5]);
        let err = match Darwin.launch(&cfg, "/bin/true", &[]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for duplicate FDs"),
        };
        assert!(err.contains("duplicate FD"), "got: {err}");
    }

    #[test]
    fn darwin_extra_fds_rejects_too_many() {
        let fds: Vec<i32> = (3..20).collect();
        let cfg = test_config_with_extra_fds(fds);
        let err = match Darwin.launch(&cfg, "/bin/true", &[]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for too many FDs"),
        };
        assert!(err.contains("too many FDs"), "got: {err}");
    }
}
