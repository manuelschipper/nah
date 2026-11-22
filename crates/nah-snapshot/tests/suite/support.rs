//! A temporary home, store and project for each test, and the comparisons
//! the tests make.

use nah_proto::ctx::{AbsolutePath, Platform};
use nah_snapshot::{Budget, Context, Manifest};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

pub struct Fixture {
    _dir: tempfile::TempDir,
    pub home: PathBuf,
    pub project: PathBuf,
    pub context: Context,
}

impl Fixture {
    /// An empty project folder and store under a fresh home.
    pub fn folder() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        let project = root.join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project).unwrap();
        let platform = if cfg!(target_os = "macos") {
            Platform::Macos
        } else {
            Platform::Linux
        };
        // The engine runs this git, which reads only the test home's
        // configuration, never the developer's.
        let git = home.join("git");
        fs::write(
            &git,
            format!(
                "#!/bin/sh\nHOME='{}' XDG_CONFIG_HOME='{}/.config' GIT_CONFIG_NOSYSTEM=1 exec git \"$@\"\n",
                home.display(),
                home.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).unwrap();
        let context = Context {
            snapshots_dir: home.join(".nah/snapshots"),
            home: AbsolutePath::new(platform, home.to_str().unwrap()).unwrap(),
            git,
            // On, so the safety tests prove a `core.fsmonitor` naming a program
            // still never runs.
            builtin_fsmonitor: true,
            labelled: Box::new(|| Ok(Vec::new())),
            may_publish: Box::new(|_| true),
            undo_for: None,
        };
        Fixture {
            _dir: dir,
            home,
            project,
            context,
        }
    }

    /// A project that is a fresh git repository on branch `main`.
    pub fn repository() -> Self {
        let fixture = Fixture::folder();
        fixture.git(&["init", "-q", "-b", "main"]);
        fixture
    }

    pub fn path(&self, relative: &str) -> PathBuf {
        self.project.join(relative)
    }

    pub fn write(&self, relative: &str, content: impl AsRef<[u8]>) {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    pub fn make_executable(&self, relative: &str) {
        fs::set_permissions(self.path(relative), fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Runs git in the project as the test's user would, and returns what it
    /// printed.
    pub fn git(&self, args: &[&str]) -> String {
        let output = self.run_git(args);
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    /// Runs git as `git` does, and says whether it succeeded: a merge that
    /// stops at a conflict fails.
    pub fn try_git(&self, args: &[&str]) -> bool {
        self.run_git(args).status.success()
    }

    /// `git` with its clock at `date`, `<seconds> <zone>`, for what it
    /// commits and logs.
    pub fn git_at(&self, date: &str, args: &[&str]) -> String {
        let output = self
            .command(args)
            .env("GIT_COMMITTER_DATE", date)
            .env("GIT_AUTHOR_DATE", date)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn run_git(&self, args: &[&str]) -> std::process::Output {
        self.command(args).output().unwrap()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new("git");
        command
            .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"])
            .args(["-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
            .args(args)
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE");
        command
    }

    pub fn commit_all(&self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", message]);
    }

    /// The store's pending snapshots: none should outlive a save.
    pub fn pending(&self) -> Vec<PathBuf> {
        let Ok(stores) = fs::read_dir(&self.context.snapshots_dir) else {
            return Vec::new();
        };
        stores
            .flat_map(|store| fs::read_dir(store.unwrap().path().join("tmp")).unwrap())
            .map(|entry| entry.unwrap().path())
            .collect()
    }

    pub fn snapshots(&self) -> Vec<Manifest> {
        nah_snapshot::list(&self.context, &self.project, far())
            .unwrap()
            .into_iter()
            .map(|listed| listed.snapshot)
            .collect()
    }
}

/// A budget no test save reaches.
pub fn generous() -> Budget {
    Budget {
        bytes: 1 << 40,
        deadline: far(),
    }
}

pub fn far() -> Instant {
    Instant::now() + Duration::from_secs(120)
}

/// Every file, link and folder under `root` with its bytes or link target
/// and its mode, skipping the top-level names in `skip`.
pub fn tree(root: &Path, skip: &[&str]) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let mut folders = vec![root.to_path_buf()];
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            if skip.contains(&relative.as_str()) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).unwrap();
            let mode = metadata.permissions().mode();
            let description = if metadata.file_type().is_symlink() {
                format!("link -> {}", fs::read_link(&path).unwrap().display())
            } else if metadata.is_dir() {
                folders.push(path);
                "folder".to_owned()
            } else {
                let digest = Sha256::digest(fs::read(&path).unwrap());
                format!("{mode:o} {digest:x}")
            };
            found.insert(relative, description);
        }
    }
    found
}
