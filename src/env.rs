//! Environment and directory utilities for sandboxed processes.
//!
//! Provides functions for constructing minimal environments, creating
//! temp directories, socket directories, and canonicalizing paths.

use std::path::{Path, PathBuf};

/// Construct a minimal environment for a sandboxed subprocess.
///
/// Only includes HOME, TMPDIR, PATH, and LANG. This prevents
/// information leakage from the host environment to the agent.
pub fn minimal_env(tmp_dir: &Path) -> Vec<(String, String)> {
    vec![
        ("HOME".into(), tmp_dir.to_string_lossy().into_owned()),
        ("TMPDIR".into(), tmp_dir.to_string_lossy().into_owned()),
        (
            "PATH".into(),
            "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin".into(),
        ),
        ("LANG".into(), "C.UTF-8".into()),
    ]
}

/// Create a temporary directory for the sandbox.
///
/// The directory is created under the system temp dir with a name
/// derived from the task ID. Returns the path to the created directory.
pub fn make_tmp_dir(task_id: &str) -> crate::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("arapuca-{task_id}"));
    std::fs::create_dir_all(&dir)?;
    // Restrict permissions to owner only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// Create a socket directory for JSON-RPC communication.
///
/// Creates a directory with mode 0700 for the control and LLM sockets.
pub fn make_socket_dir() -> crate::Result<PathBuf> {
    let dir = tempfile_dir("arapuca-sock")?;
    Ok(dir)
}

/// Canonicalize a list of paths, resolving symlinks and making them absolute.
///
/// Paths that don't exist are silently dropped (they can't be used
/// in Landlock rules anyway). This prevents symlink escape attacks
/// where a crafted symlink inside a writable path points outside it.
pub fn canonicalize_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect()
}

/// Parse colon-separated paths from a string.
///
/// Used by the binary to parse ARAPUCA_READ_PATHS and ARAPUCA_WRITE_PATHS
/// environment variables.
pub fn parse_paths(s: &str) -> Vec<PathBuf> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(':')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Create a temporary directory with a given prefix.
fn tempfile_dir(prefix: &str) -> crate::Result<PathBuf> {
    let tmp = std::env::temp_dir();
    // Use mkdtemp-style unique naming.
    let dir = tmp.join(format!("{prefix}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_env_contains_essentials() {
        let env = minimal_env(Path::new("/tmp/test"));
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"HOME"));
        assert!(keys.contains(&"TMPDIR"));
        assert!(keys.contains(&"PATH"));
        assert!(keys.contains(&"LANG"));
        assert_eq!(env.len(), 4);
    }

    #[test]
    fn parse_paths_empty() {
        assert!(parse_paths("").is_empty());
    }

    #[test]
    fn parse_paths_single() {
        let paths = parse_paths("/usr/lib");
        assert_eq!(paths, vec![PathBuf::from("/usr/lib")]);
    }

    #[test]
    fn parse_paths_multiple() {
        let paths = parse_paths("/usr:/lib:/etc");
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/usr"),
                PathBuf::from("/lib"),
                PathBuf::from("/etc"),
            ]
        );
    }

    #[test]
    fn parse_paths_trims_whitespace() {
        let paths = parse_paths(" /usr : /lib ");
        assert_eq!(paths, vec![PathBuf::from("/usr"), PathBuf::from("/lib")]);
    }

    #[test]
    fn canonicalize_existing_paths() {
        let paths = vec![PathBuf::from("/usr"), PathBuf::from("/nonexistent-xyz")];
        let result = canonicalize_paths(&paths);
        assert!(result.contains(&PathBuf::from("/usr")));
        assert!(
            !result
                .iter()
                .any(|p| p.to_string_lossy().contains("nonexistent"))
        );
    }
}
