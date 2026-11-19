//! Workspace context — isolates each research engagement.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Context for a single research workspace.
///
/// All file operations must be resolved within `workspace_root`.
/// Escape via `..` or absolute paths is rejected by `safe_path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceContext {
    pub workspace_id: String,
    pub workspace_root: PathBuf,
    pub allowed_scope_hosts: Vec<String>,
    pub is_safe_lab: bool,
}

impl WorkspaceContext {
    pub fn new(id: impl Into<String>, root: impl AsRef<Path>) -> Self {
        Self {
            workspace_id: id.into(),
            workspace_root: root.as_ref().to_path_buf(),
            allowed_scope_hosts: Vec::new(),
            is_safe_lab: false,
        }
    }

    /// Resolve a relative path within the workspace, rejecting traversal.
    ///
    /// Returns `None` if the resolved path escapes `workspace_root`.
    pub fn safe_path(&self, relative: &str) -> Option<PathBuf> {
        if relative.is_empty() {
            return None;
        }
        // Reject obvious traversal attempts before resolution
        if relative.contains("..") {
            return None;
        }
        // Reject absolute paths and UNC paths
        if relative.starts_with('/') || relative.starts_with('\\') {
            return None;
        }
        if relative.len() >= 2 && &relative[1..2] == ":" {
            // Windows drive letter absolute path
            return None;
        }
        if relative.starts_with("//") || relative.starts_with("\\\\") {
            return None;
        }

        let candidate = self.workspace_root.join(relative);
        // Verify the canonical path starts with workspace_root
        let canonical_root = std::fs::canonicalize(&self.workspace_root).ok()?;
        let canonical_candidate = std::fs::canonicalize(&candidate).ok()?;
        if canonical_candidate.starts_with(&canonical_root) {
            Some(canonical_candidate)
        } else {
            None
        }
    }

    /// Check whether a hostname is in this workspace's authorized scope.
    pub fn is_in_scope(&self, host: &str) -> bool {
        if host.is_empty() {
            return false;
        }
        self.allowed_scope_hosts
            .iter()
            .any(|s| s == host || host.ends_with(&format!(".{}", s)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_ctx() -> WorkspaceContext {
        WorkspaceContext::new("test-ws", env::temp_dir())
    }

    #[test]
    fn dotdot_rejected() {
        let ctx = tmp_ctx();
        assert!(ctx.safe_path("../etc/passwd").is_none());
        assert!(ctx.safe_path("../../windows/system32").is_none());
    }

    #[test]
    fn absolute_path_rejected() {
        let ctx = tmp_ctx();
        assert!(ctx.safe_path("/etc/passwd").is_none());
        assert!(ctx.safe_path("C:\\Windows\\System32\\cmd.exe").is_none());
    }

    #[test]
    fn scope_check_exact() {
        let mut ctx = tmp_ctx();
        ctx.allowed_scope_hosts = vec!["example.com".into()];
        assert!(ctx.is_in_scope("example.com"));
        assert!(!ctx.is_in_scope("evil.com"));
    }

    #[test]
    fn scope_check_subdomain() {
        let mut ctx = tmp_ctx();
        ctx.allowed_scope_hosts = vec!["example.com".into()];
        assert!(ctx.is_in_scope("api.example.com"));
        assert!(!ctx.is_in_scope("notexample.com"));
    }

    #[test]
    fn empty_host_denied() {
        let ctx = tmp_ctx();
        assert!(!ctx.is_in_scope(""));
    }
}
