use std::path::Path;

/// Recreates the repository test fixture at `base/tag`, deleting whatever that
/// directory held first, then writes each `(relative path, content)` file.
/// `base` must be a disposable location the test owns (normally the calling
/// crate's `CARGO_TARGET_TMPDIR`), no concurrently running test may share `tag`,
/// and every relative path must stay inside the fixture root.
pub fn repo_test_fixture(base: &Path, tag: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let root = base.join(tag);
    let _ = std::fs::remove_dir_all(&root);
    for (relative, content) in files {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    root
}
