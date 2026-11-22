//! The custom guards nah 1.x ran. Nah 2.0 runs none, so on upgrade they stop
//! blocking. Nah reads `~/.nah/activations.json`, the 1.x record of every
//! enabled custom guard, and nothing else, only to say which ones stopped:
//! after `nah hook <runtime> install`, at the end of `nah guards` and on the
//! TUI's Guards tab. It never runs, changes or deletes a guard or that file, so
//! the notice lasts until the operator deletes the file.

use std::path::PathBuf;

use nah_proto::ctx::{AbsolutePath, Platform};
use serde::Deserialize;

use crate::state_protection::nah_state_file_path;

/// The custom guards nah 1.x ran that 2.0 no longer runs.
pub(crate) struct StoppedCustomGuards {
    activations: PathBuf,
    /// `None` when the file is not a 1.x record nah can read, which still
    /// means guards may have stopped.
    guards: Option<Vec<StoppedGuard>>,
}

struct StoppedGuard {
    /// `custom/<name>`, as 2.0 would have named it.
    name: String,
    scope: Scope,
    /// The guard's files; unknown for a project guard whose record names no
    /// project.
    path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct Activations {
    records: Vec<Activation>,
}

#[derive(Deserialize)]
struct Activation {
    projection: Projection,
}

#[derive(Deserialize)]
struct Projection {
    identity: Identity,
}

#[derive(Deserialize)]
struct Identity {
    scope: Scope,
    /// For a project guard, `root:` and the project's absolute path.
    #[serde(default)]
    trusted_root: Option<String>,
    name: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Scope {
    User,
    Project,
}

impl Scope {
    const fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
        }
    }
}

impl StoppedCustomGuards {
    /// `None` when nah 1.x left no `activations.json`, or one that enables no
    /// guard.
    pub(crate) fn find(home: &AbsolutePath, platform: Platform) -> Option<Self> {
        let activations = nah_state_file_path(home, platform, "activations.json");
        let bytes = match std::fs::read(&activations) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(_) => {
                return Some(Self {
                    activations,
                    guards: None,
                });
            }
        };
        let guards = serde_json::from_slice::<Activations>(&bytes)
            .ok()
            .map(|record| {
                record
                    .records
                    .into_iter()
                    .map(|activation| {
                        let identity = activation.projection.identity;
                        let path = match identity.scope {
                            Scope::User => Some(nah_state_file_path(home, platform, "guards")),
                            Scope::Project => identity
                                .trusted_root
                                .as_deref()
                                .and_then(|root| root.strip_prefix("root:"))
                                .map(|root| PathBuf::from(root).join(".nah").join("guards")),
                        }
                        .map(|guards| guards.join(&identity.name));
                        StoppedGuard {
                            name: format!("custom/{}", identity.name),
                            scope: identity.scope,
                            path,
                        }
                    })
                    .collect::<Vec<_>>()
            });
        if guards.as_ref().is_some_and(Vec::is_empty) {
            return None;
        }
        Some(Self {
            activations,
            guards,
        })
    }

    /// The full notice: which guards stopped and what the operator should do.
    pub(crate) fn notice(&self) -> String {
        let mut notice =
            "Nah 2.0 no longer runs custom guards, so the blocks of these guards nah 1.x ran no longer apply:\n"
                .to_owned();
        match &self.guards {
            Some(guards) => {
                for guard in guards {
                    notice.push_str(&format!("- {} ({} guard", guard.name, guard.scope.name()));
                    if let Some(path) = &guard.path {
                        notice.push_str(&format!(" in {}", path.display()));
                    }
                    notice.push_str(")\n");
                }
            }
            None => notice.push_str(&format!(
                "- the guards {} lists, which nah cannot read\n",
                self.activations.display()
            )),
        }
        notice.push_str(&format!(
            "To keep what they protected, move it into your agent's own permission rules or another tool, then delete {} to clear this notice.\n",
            self.activations.display()
        ));
        notice
    }

    /// A shorter notice for the TUI, which points at the full one.
    pub(crate) fn banner(&self) -> String {
        match &self.guards {
            Some(guards) => format!(
                "Nah 2.0 no longer runs custom guards; the blocks of these nah 1.x guards no longer apply: {}. See `nah guards`.",
                guards
                    .iter()
                    .map(|guard| guard.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            None => format!(
                "Nah 2.0 no longer runs custom guards; the blocks of the nah 1.x guards {} lists no longer apply. See `nah guards`.",
                self.activations.display()
            ),
        }
    }
}
