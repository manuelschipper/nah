// UNDOCUMENTED-EFFINTERP: persists and scopes the private shadow-pipeline switch.

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use nah_proto::ctx::{AbsolutePath, Platform};
use serde::{Deserialize, Serialize};

const VERSION: u32 = 1;

thread_local! {
    static FORCED: Cell<bool> = const { Cell::new(false) };
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EffinterpState {
    v: u32,
    enabled: bool,
}

pub(crate) fn load(path: &Path) -> Result<bool, String> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("effinterp-state-io-failed".into()),
    };
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|_| "invalid-effinterp-state")?;
    let state: EffinterpState =
        serde_json::from_str(&contents).map_err(|_| "invalid-effinterp-state")?;
    let canonical = serde_json::to_string(&state).map_err(|_| "invalid-effinterp-state")?;
    if state.v != VERSION || contents != format!("{canonical}\n") {
        return Err("invalid-effinterp-state".into());
    }
    Ok(state.enabled)
}

pub(crate) fn set(path: &Path, enabled: bool) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-effinterp-state-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "effinterp-state-io-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(path.with_extension("lock"))
        .map_err(|_| "effinterp-state-io-failed")?;
    protect_file(&lock)?;
    lock.lock().map_err(|_| "effinterp-state-io-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "effinterp-state-io-failed")?;
    protect_file(temporary.as_file())?;
    serde_json::to_writer(
        &mut temporary,
        &EffinterpState {
            v: VERSION,
            enabled,
        },
    )
    .map_err(|_| "effinterp-state-io-failed")?;
    temporary
        .write_all(b"\n")
        .map_err(|_| "effinterp-state-io-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "effinterp-state-io-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "effinterp-state-io-failed")?;
    sync_parent(parent)
}

pub(crate) fn enabled(path: &Path) -> Result<bool, String> {
    if FORCED.with(Cell::get) {
        Ok(true)
    } else {
        load(path)
    }
}

pub(crate) fn with_forced<T>(forced: bool, run: impl FnOnce() -> T) -> T {
    if !forced {
        return run();
    }
    FORCED.with(|value| {
        let previous = value.replace(true);
        let output = run();
        value.set(previous);
        output
    })
}

pub(crate) fn state_path(home: &AbsolutePath, platform: Platform) -> PathBuf {
    let separator = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    PathBuf::from(format!(
        "{}{separator}.nah{separator}effinterp.json",
        home.as_str().trim_end_matches(['/', '\\'])
    ))
}

#[cfg(unix)]
fn protect_file(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "effinterp-state-io-failed".into())
}

#[cfg(not(unix))]
fn protect_file(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "effinterp-state-io-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}
