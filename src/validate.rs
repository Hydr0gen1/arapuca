use crate::Error;

/// Maximum length for a task ID.
const MAX_TASK_ID_LEN: usize = 128;

/// Validate and sanitize a task ID.
///
/// Task IDs are used in filesystem paths (cgroup directories, temp dirs),
/// so they must be safe for path construction. Allowed: `[a-zA-Z0-9-]`,
/// max 128 characters.
///
/// Returns the validated ID on success, or an error if the ID is invalid.
pub fn sanitize_task_id(id: &str) -> crate::Result<&str> {
    if id.is_empty() {
        return Err(Error::Validation("empty task ID".into()));
    }
    if id.len() > MAX_TASK_ID_LEN {
        return Err(Error::Validation(format!(
            "task ID too long ({} chars, max {MAX_TASK_ID_LEN})",
            id.len()
        )));
    }
    if !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(Error::Validation(format!(
            "task ID contains invalid characters: {id:?}"
        )));
    }
    Ok(id)
}

/// Reject paths that include `/sys/fs/cgroup`.
///
/// Defense-in-depth: prevents a sandboxed process from modifying its own
/// cgroup resource limits (memory.max, cpu.max, pids.max) if the path
/// were allowed through Landlock.
pub fn reject_cgroup_paths(paths: &[std::path::PathBuf]) -> crate::Result<()> {
    for p in paths {
        let s = p.to_string_lossy();
        if s.starts_with("/sys/fs/cgroup") {
            return Err(Error::Validation(format!(
                "path must not include /sys/fs/cgroup: {s}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn valid_task_ids() {
        assert!(sanitize_task_id("abc-123").is_ok());
        assert!(sanitize_task_id("A").is_ok());
        assert!(sanitize_task_id("task-with-dashes-42").is_ok());
    }

    #[test]
    fn empty_task_id() {
        assert!(sanitize_task_id("").is_err());
    }

    #[test]
    fn task_id_too_long() {
        let long = "a".repeat(MAX_TASK_ID_LEN + 1);
        assert!(sanitize_task_id(&long).is_err());
    }

    #[test]
    fn task_id_max_length_ok() {
        let max = "a".repeat(MAX_TASK_ID_LEN);
        assert!(sanitize_task_id(&max).is_ok());
    }

    #[test]
    fn task_id_bad_chars() {
        assert!(sanitize_task_id("../escape").is_err());
        assert!(sanitize_task_id("has space").is_err());
        assert!(sanitize_task_id("has/slash").is_err());
        assert!(sanitize_task_id("has_underscore").is_err());
        assert!(sanitize_task_id("has.dot").is_err());
    }

    #[test]
    fn cgroup_path_rejected() {
        let paths = vec![PathBuf::from("/sys/fs/cgroup/user.slice")];
        assert!(reject_cgroup_paths(&paths).is_err());
    }

    #[test]
    fn cgroup_exact_path_rejected() {
        let paths = vec![PathBuf::from("/sys/fs/cgroup")];
        assert!(reject_cgroup_paths(&paths).is_err());
    }

    #[test]
    fn normal_paths_ok() {
        let paths = vec![
            PathBuf::from("/usr/lib"),
            PathBuf::from("/tmp/agent-123"),
            PathBuf::from("/home/user/project"),
        ];
        assert!(reject_cgroup_paths(&paths).is_ok());
    }

    #[test]
    fn empty_paths_ok() {
        assert!(reject_cgroup_paths(&[]).is_ok());
    }
}
