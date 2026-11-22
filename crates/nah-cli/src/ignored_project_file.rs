//! Nah is a per-user tool: no file in a repository changes what it enforces.
//! Earlier releases read a project's `.nah/project.toml` to turn on rules
//! there, so Nah says once per project file that it is not read: in the
//! first hook reply that shows the user a notice (`hook_adapter::once_report`)
//! or the first `nah hook <runtime> status`, whichever meets the file first.
//! A live decision only finds the file ([`find`]); a decision no reply
//! delivers, such as `nah test`'s, tells nothing and records nothing.
//!
//! Each told file is one empty file under `~/.nah/ignored-projects/`, named
//! by the SHA-256 of the project file's path bytes. Creating it is the
//! claim: `create_new` succeeds for exactly one of any processes racing on
//! the first meeting, and none of them waits on a lock.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nah_proto::ctx::{AbsolutePath, Platform, SchemaVersion};
use nah_proto::observation::{
    Observation, ObservationQuery, ObservationRequest, ObservationValue, Observed, RootKind,
};
use sha2::{Digest, Sha256};

use crate::live_state;
use crate::private_files::restrict_file_to_owner;
use crate::state_protection::nah_state_file_path;

/// How long a reply waits for the claim, which runs on `nah_observe`'s
/// bounded threads: a state directory that does not answer costs the reply
/// no more than this, and the notice is then given another time.
pub(crate) const CLAIM_WAIT: Duration = Duration::from_millis(250);

/// The project file of the project `observation` found, looked for on
/// `nah_observe`'s bounded threads and abandoned at `deadline`.
pub(crate) fn find(observation: &Observation, deadline: Instant) -> Option<PathBuf> {
    let root = project_root(observation)?;
    nah_observe::observe_within_deadline(deadline, move || {
        nah_observe::ignored_project_file(&root)
    })?
}

/// The notice for `file`, if this call is the first to claim it.
pub(crate) fn claim_notice(file: &Path) -> Option<String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform).ok()?;
    let told = nah_state_file_path(&home, platform, "ignored-projects");
    let marker = told.join(format!(
        "{:x}",
        Sha256::digest(file.as_os_str().as_encoded_bytes())
    ));
    let claimed =
        nah_observe::observe_within_deadline(Instant::now() + CLAIM_WAIT, move || claim(&marker))?;
    claimed.then(|| {
        format!(
            "{} is not read: nah 2.0 has no per-project rules. Turn on the rules it enabled for your user with `nah rule enable GUARD/RULE`",
            file.display()
        )
    })
}

/// The notice for the project file of the project `directory` is in, as a
/// call made there finds that project, if this is the first to claim it.
pub(crate) fn status_notice(directory: &Path, platform: Platform) -> Option<String> {
    let cwd = std::fs::canonicalize(directory).ok()?;
    let cwd = cwd.to_str()?;
    let cwd = if platform == Platform::Windows {
        nah_observe::normalize_windows_observed_path(cwd)
    } else {
        cwd.to_owned()
    };
    let request = ObservationRequest::new(
        SchemaVersion::V1,
        "ignored-project-file",
        vec![
            ObservationQuery::Cwd {
                key: "cwd".into(),
                requested: AbsolutePath::new(platform, cwd).ok()?,
            },
            ObservationQuery::Roots {
                key: "roots".into(),
                cwd_key: "cwd".into(),
            },
        ],
    )
    .ok()?;
    let observation = nah_observe::fulfill_observation_request(&request).ok()?;
    let file = nah_observe::ignored_project_file(&project_root(&observation)?)?;
    claim_notice(&file)
}

fn project_root(observation: &Observation) -> Option<PathBuf> {
    observation
        .facts()
        .iter()
        .find_map(|fact| match fact.value() {
            ObservationValue::Roots {
                observed: Observed::Ok { value },
            } => value
                .iter()
                .find(|root| root.kind() == RootKind::Project)
                .map(|root| PathBuf::from(root.path().as_str())),
            _ => None,
        })
}

/// Whether this call created `marker`. A marker that cannot be written for
/// another reason still tells, since telling twice is better than never.
pub(crate) fn claim(marker: &Path) -> bool {
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(marker) {
        Ok(file) => {
            let _ = restrict_file_to_owner(&file);
            true
        }
        Err(error) => error.kind() != std::io::ErrorKind::AlreadyExists,
    }
}
