//! Finds a `.nah/project.toml`, the file earlier nah releases read to turn on
//! rules for one project. Nah reads no project file now and only says so.

use std::path::{Path, PathBuf};

/// The project file under `project_root`, where one exists. Its contents are
/// never read.
pub fn ignored_project_file(project_root: &Path) -> Option<PathBuf> {
    let path = project_root.join(".nah").join("project.toml");
    std::fs::symlink_metadata(&path).is_ok().then_some(path)
}
