use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Fetch one pinned commit into the cache, or reuse an identical clean checkout.
/// Existing mismatched or dirty content is refused, never reset or removed.
pub fn ensure_checkout(name: &str, url: &str, sha: &str, cache: &Path) -> Result<PathBuf, String> {
    let dir = cache.join(name.replace('/', "__"));
    if dir.join(".git").is_dir() {
        let head = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["rev-parse", "HEAD"])
            .output();
        if let Ok(out) = head
            && out.status.success()
            && String::from_utf8_lossy(&out.stdout).trim() == sha
        {
            // The pinned SHA names only committed content; anything else in
            // the checkout would be analyzed under a false identity. Refuse
            // rather than discard someone's edits.
            let status = Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args([
                    "status",
                    "--porcelain",
                    "--untracked-files=all",
                    "--ignored",
                ])
                .output()
                .map_err(|e| format!("spawn git status: {e}"))?;
            let dirty = String::from_utf8_lossy(&status.stdout);
            if !status.status.success() || !dirty.trim().is_empty() {
                return Err(format!(
                    "checkout {} is not the pinned commit alone; remove it or clean it: {}",
                    dir.display(),
                    dirty.lines().take(3).collect::<Vec<_>>().join(" | ")
                ));
            }
            return Ok(dir);
        }
        return Err(format!(
            "checkout {} does not match pinned SHA {sha}; move it aside or use a different cache directory",
            dir.display()
        ));
    }
    if dir.exists() {
        return Err(format!(
            "checkout {} exists without a Git repository",
            dir.display()
        ));
    }
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    run_git(&dir, &["init", "-q"])?;
    run_git(&dir, &["remote", "add", "origin", url])?;
    run_git(&dir, &["fetch", "--depth", "1", "-q", "origin", sha])?;
    run_git(&dir, &["checkout", "-q", "FETCH_HEAD"])?;
    Ok(dir)
}

fn run_git(dir: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| format!("spawn git {args:?}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}
