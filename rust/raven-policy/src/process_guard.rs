//! Process guard — validates controlled process launch requests.
//!
//! INVARIANTS:
//! - Executable must be in the approved registry (never target-controlled).
//! - Arguments are validated (no shell=True equivalent).
//! - Working directory must be within authorized workspace.
//! - Sensitive env vars are not inherited.
//! - stdout/stderr are bounded.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

/// The approved executable registry.
///
/// Only executables explicitly registered here may be launched.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutableRegistry {
    approved: HashSet<PathBuf>,
}

impl ExecutableRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an approved executable path.
    pub fn register(&mut self, path: impl Into<PathBuf>) {
        self.approved.insert(path.into());
    }

    /// Check if an executable is approved.
    pub fn is_approved(&self, path: &PathBuf) -> bool {
        self.approved.contains(path)
    }
}

/// Environment variable names that must never be inherited by child processes.
pub const SENSITIVE_ENV_VARS: &[&str] = &[
    "AUTHORIZATION",
    "API_KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "COOKIE",
    "SESSION",
    "PRIVATE_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "RAVEN_API_KEY",
    "RAVEN_SESSION_TOKEN",
];

/// A validated, safe process launch specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeProcessSpec {
    /// Absolute path to the approved executable.
    pub executable: PathBuf,
    /// Argument vector (never interpolated through a shell).
    pub args: Vec<String>,
    /// Working directory (must be within authorized workspace).
    pub working_dir: PathBuf,
    /// Timeout in milliseconds.
    pub timeout_ms: u32,
    /// Maximum stdout+stderr bytes.
    pub max_output_bytes: u32,
    /// Whether to show a console window (Windows).
    pub create_no_window: bool,
}

/// Result of validating a process launch request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessVerdict {
    Approved,
    Denied(ProcessDenyReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessDenyReason {
    ExecutableNotRegistered,
    PathTraversal,
    ShellInterpolationDetected,
    TimeoutExceeded,
    OutputLimitExceeded,
}

/// Validate a proposed process launch.
pub fn validate_process_launch(
    spec: &SafeProcessSpec,
    registry: &ExecutableRegistry,
    workspace_root: &std::path::Path,
) -> ProcessVerdict {
    // 1. Executable must be in approved registry
    if !registry.is_approved(&spec.executable) {
        return ProcessVerdict::Denied(ProcessDenyReason::ExecutableNotRegistered);
    }

    // 2. Working directory must be within workspace
    if !spec.working_dir.starts_with(workspace_root) {
        return ProcessVerdict::Denied(ProcessDenyReason::PathTraversal);
    }

    // 3. Detect shell metacharacters in arguments
    for arg in &spec.args {
        if arg.contains(';')
            || arg.contains('|')
            || arg.contains('`')
            || arg.contains('$')
            || arg.contains('&')
            || arg.contains('>')
            || arg.contains('<')
            || arg.contains('\n')
        {
            return ProcessVerdict::Denied(ProcessDenyReason::ShellInterpolationDetected);
        }
    }

    // 4. Timeout bounds (max 60 seconds)
    if spec.timeout_ms > 60_000 {
        return ProcessVerdict::Denied(ProcessDenyReason::TimeoutExceeded);
    }

    // 5. Output bound (max 10 MB = 10_485_760 bytes)
    if spec.max_output_bytes > 10_485_760 {
        return ProcessVerdict::Denied(ProcessDenyReason::OutputLimitExceeded);
    }

    ProcessVerdict::Approved
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_registry() -> ExecutableRegistry {
        let mut r = ExecutableRegistry::new();
        r.register(PathBuf::from("/usr/bin/nmap"));
        r
    }

    fn make_spec(exe: &str) -> SafeProcessSpec {
        SafeProcessSpec {
            executable: PathBuf::from(exe),
            args: vec!["--help".into()],
            working_dir: PathBuf::from("/workspace/ws-test"),
            timeout_ms: 10_000,
            max_output_bytes: 1024 * 1024,
            create_no_window: true,
        }
    }

    #[test]
    fn approved_executable_passes() {
        let reg = make_registry();
        let spec = make_spec("/usr/bin/nmap");
        let v = validate_process_launch(&spec, &reg, std::path::Path::new("/workspace/ws-test"));
        assert_eq!(v, ProcessVerdict::Approved);
    }

    #[test]
    fn unapproved_executable_denied() {
        let reg = make_registry();
        let spec = make_spec("/bin/sh");
        let v = validate_process_launch(&spec, &reg, std::path::Path::new("/workspace/ws-test"));
        assert_eq!(
            v,
            ProcessVerdict::Denied(ProcessDenyReason::ExecutableNotRegistered)
        );
    }

    #[test]
    fn shell_metachar_denied() {
        let mut reg = make_registry();
        reg.register(PathBuf::from("/usr/bin/curl"));
        let mut spec = make_spec("/usr/bin/curl");
        spec.args = vec!["https://example.com; rm -rf /".into()];
        let v = validate_process_launch(&spec, &reg, std::path::Path::new("/workspace/ws-test"));
        assert_eq!(
            v,
            ProcessVerdict::Denied(ProcessDenyReason::ShellInterpolationDetected)
        );
    }

    #[test]
    fn path_traversal_in_working_dir_denied() {
        let reg = make_registry();
        let mut spec = make_spec("/usr/bin/nmap");
        spec.working_dir = PathBuf::from("/etc");
        let v = validate_process_launch(&spec, &reg, std::path::Path::new("/workspace/ws-test"));
        assert_eq!(v, ProcessVerdict::Denied(ProcessDenyReason::PathTraversal));
    }

    #[test]
    fn sensitive_env_vars_list_nonempty() {
        assert!(!SENSITIVE_ENV_VARS.is_empty());
        assert!(SENSITIVE_ENV_VARS.contains(&"PASSWORD"));
        assert!(SENSITIVE_ENV_VARS.contains(&"API_KEY"));
    }
}
