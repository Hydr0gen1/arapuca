//! Integration tests for `arapuca run` subcommand.
//!
//! Tests exercise the binary via std::process::Command. Requires
//! Linux with Landlock (5.13+) for sandbox enforcement.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

fn arapuca_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove "deps"
    path.push("arapuca");
    path
}

// ─── Security property tests ─────────────────────────────────

#[test]
fn path_confinement_blocks_unallowed_reads() {
    // Create the file outside /tmp (which is a default write path).
    // Use the current directory (repo root) which is NOT in defaults.
    let dir = tempfile::Builder::new()
        .prefix("arapuca-confinement-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, "classified").unwrap();

    let output = Command::new(arapuca_bin())
        .args(["run", "--", "/bin/cat"])
        .arg(&secret)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "cat should fail on path outside allow list"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Permission denied") || stderr.contains("denied"),
        "expected permission denied, got: {stderr}"
    );
}

#[test]
fn read_only_enforcement() {
    // Use a directory outside defaults so the :ro flag is the only
    // access grant. /tmp is a default write path so it can't be used.
    let dir = tempfile::Builder::new()
        .prefix("arapuca-ro-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let dir_str = dir.path().to_str().unwrap();
    let vol = format!("{dir_str}:ro");

    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "-v",
            &vol,
            "--",
            "/bin/sh",
            "-c",
            &format!("touch {dir_str}/test-write"),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "write to read-only path should fail"
    );
}

#[test]
fn default_paths_sufficient_for_basic_commands() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--", "/bin/true"])
        .status()
        .unwrap();

    assert!(status.success(), "/bin/true should succeed with defaults");
}

// ─── Functional tests ────────────────────────────────────────

#[test]
fn exit_code_nonzero() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--", "/bin/false"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}

#[test]
fn path_access_with_volume() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, "hello from volume").unwrap();

    let dir_str = dir.path().to_str().unwrap();
    let vol = format!("{dir_str}:ro");

    let output = Command::new(arapuca_bin())
        .args(["run", "-v", &vol, "--", "/bin/cat"])
        .arg(&file)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "cat should succeed on allowed path"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello from volume"
    );
}

#[test]
fn combined_env_filtering() {
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--env",
            "MY_SAFE_VAR=present",
            "--env",
            "CUSTOM_TOKEN=secret123",
            "--",
            "/bin/sh",
            "-c",
            "echo safe=$MY_SAFE_VAR token=$CUSTOM_TOKEN ld=${LD_PRELOAD:-unset}",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("safe=present"),
        "safe var should be passed: {stdout}"
    );
    assert!(
        stdout.contains("token=secret123"),
        "custom token should be passed: {stdout}"
    );
    assert!(
        stdout.contains("ld=unset"),
        "LD_PRELOAD should not leak from host: {stdout}"
    );
}

#[test]
fn exec_chain_through_seccomp() {
    let output = Command::new(arapuca_bin())
        .args(["run", "--", "/bin/sh", "-c", "/bin/echo exec-ok"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "exec-ok");
}

#[test]
fn timeout_kills_process() {
    let start = std::time::Instant::now();
    let status = Command::new(arapuca_bin())
        .args(["run", "--timeout", "2", "--", "/bin/sleep", "60"])
        .status()
        .unwrap();
    let elapsed = start.elapsed();

    assert!(!status.success(), "sleep should have been killed");

    // Exit code should be 128 + signal (SIGTERM=15 → 143, SIGKILL=9 → 137).
    let code = status.code().unwrap_or(0);
    assert!(
        code == 137 || code == 143,
        "expected exit code 137 or 143, got {code}"
    );

    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "timeout should have fired within ~7s, took {elapsed:?}"
    );
}

#[test]
fn timeout_fast_exit_no_delay() {
    let start = std::time::Instant::now();
    let status = Command::new(arapuca_bin())
        .args(["run", "--timeout", "30", "--", "/bin/true"])
        .status()
        .unwrap();
    let elapsed = start.elapsed();

    assert!(status.success());
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "fast exit should not wait for timeout, took {elapsed:?}"
    );
}

#[test]
fn resource_limits_flag_accepted() {
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--memory",
            "256",
            "--cpus",
            "200",
            "--pids",
            "100",
            "--",
            "/bin/true",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

// ─── Error handling tests ────────────────────────────────────

#[test]
fn unknown_flag_exits_125() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--bogus", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn no_command_exits_125() {
    let status = Command::new(arapuca_bin()).args(["run"]).status().unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn missing_separator_shows_hint() {
    let output = Command::new(arapuca_bin())
        .args(["run", "/bin/ls"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("did you forget"),
        "should show hint about missing '--': {stderr}"
    );
}

#[test]
fn env_override_sandbox_managed_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--env", "HOME=/evil", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "overriding HOME should be rejected"
    );
}

// ─── Env injection tests ─────────────────────────────────────

#[test]
fn env_dangerous_var_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--env", "LD_PRELOAD=/evil.so", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "LD_PRELOAD should be rejected at CLI layer"
    );
}

#[test]
fn env_arapuca_prefix_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--env", "ARAPUCA_READ_PATHS=/", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "ARAPUCA_* vars should be rejected at CLI layer"
    );
}

#[test]
fn env_interpreter_injection_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--env", "BASH_ENV=/evil", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "BASH_ENV should be rejected at CLI layer"
    );
}

// ─── Validation edge case tests ──────────────────────────────

#[test]
fn volume_relative_path_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "-v", "relative/path", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn volume_empty_path_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "-v", ":ro", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn task_id_traversal_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--task-id", "../../etc", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn timeout_zero_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--timeout", "0", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn env_without_value_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--env", "NOVALUE", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}
