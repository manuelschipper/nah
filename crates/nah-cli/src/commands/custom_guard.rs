//! Shared custom-guard creation, listing, and byte-pinned activation commands.

use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use nah_proto::ctx::{ActivationProjection, GuardIdentity, GuardScope};

use crate::catalog::shipped_names;
use crate::live_state::{home, host_platform};

use super::{
    GuardEntry, GuardSelector, GuardStatus, GuardTarget, canonical_project_root, scope_name,
};

pub(crate) fn new_guard(
    name: &str,
    selector: &GuardSelector,
) -> Result<std::path::PathBuf, String> {
    if shipped_names().contains(&name) {
        return Err(format!(
            "guard name `{name}` is reserved; choose another name"
        ));
    }
    let platform = host_platform();
    let home = home(platform)?;
    let created = match selector {
        GuardSelector::Any | GuardSelector::User => {
            nah_extensions::create_user_guard(&home, platform, name)
        }
        GuardSelector::Project(requested) => {
            let root = canonical_project_root(requested, platform)?;
            nah_extensions::create_project_guard(&root, platform, name)
        }
    };
    created.map_err(|error| {
        let error = error.to_string();
        if error == "invalid-policy-name" {
            format!(
                "invalid guard name {name:?}; use 1-64 lowercase letters or digits, with `.`, `_`, or `-` only between them"
            )
        } else {
            error
        }
    })
}

pub(crate) fn enable_custom_guard_scoped(
    name: &str,
    selector: &GuardSelector,
) -> Result<(), String> {
    let identity = scoped_identity(name, selector)?;
    let bundles = discovered_bundles()?;
    let bundle = bundles
        .iter()
        .find(|bundle| bundle.projection().identity() == &identity)
        .ok_or_else(|| scoped_not_found(name, selector))?;
    activate_projection(bundle.projection())
}

pub(crate) fn enable_custom_guard(name: &str) -> Result<(), String> {
    let bundles = discovered_bundles()?;
    let matches = bundles
        .iter()
        .filter(|bundle| bundle.projection().identity().name() == name)
        .collect::<Vec<_>>();
    let [bundle] = matches.as_slice() else {
        return Err(if matches.is_empty() {
            format!("guard `{name}` was not found")
        } else {
            format!("guard name `{name}` is ambiguous across scopes")
        });
    };
    activate_projection(bundle.projection())
}

pub(crate) fn enable_guard_identity(
    identity: &GuardIdentity,
    expected_hash: &str,
) -> Result<(), String> {
    let bundles = discovered_bundles()?;
    let bundle = bundles
        .iter()
        .find(|bundle| bundle.projection().identity() == identity)
        .ok_or_else(|| format!("guard `{}` was not found", identity.name()))?;
    if bundle.projection().bundle_hash().as_str() != expected_hash {
        return Err("guard bytes changed; review and approve them again".into());
    }
    activate_projection(bundle.projection())
}

fn discovered_bundles() -> Result<Vec<nah_extensions::ExtensionBundle>, String> {
    let platform = host_platform();
    let home = home(platform)?;
    let trust_path = nah_extensions::trust_database_path(&home, platform);
    let trust = nah_extensions::TrustDatabase::load(&trust_path, platform)
        .and_then(|database| database.projection())
        .map_err(|error| error.to_string())?;
    let reserved_names = shipped_names();
    nah_extensions::discover_bundles(&home, platform, &trust, &reserved_names)
        .map(|(bundles, _)| bundles)
        .map_err(|error| error.to_string())
}

fn activate_projection(projection: &ActivationProjection) -> Result<(), String> {
    let platform = host_platform();
    let home = home(platform)?;
    let trust_path = nah_extensions::trust_database_path(&home, platform);
    let actor = std::env::var("USER")
        .ok()
        .filter(|actor| !actor.is_empty())
        .unwrap_or_else(|| "human".into());
    let activated_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    let activation_path = nah_extensions::activation_database_path(&home, platform);
    match projection.identity().scope() {
        GuardScope::User => nah_extensions::record_activation(
            &activation_path,
            projection.clone(),
            actor,
            activated_unix_ms,
        )
        .map_err(|error| error.to_string()),
        GuardScope::Project => nah_extensions::record_project_activation(
            &trust_path,
            &activation_path,
            platform,
            projection.clone(),
            actor,
            activated_unix_ms,
        )
        .map_err(|error| error.to_string()),
    }
}

pub(crate) fn disable_custom_guard(name: &str) -> Result<(), String> {
    let platform = host_platform();
    let home = home(platform)?;
    let path = nah_extensions::activation_database_path(&home, platform);
    let activations =
        nah_extensions::ActivationDatabase::load(&path).map_err(|error| error.to_string())?;
    let matches = activations
        .records()
        .iter()
        .filter(|record| record.projection().identity().name() == name)
        .collect::<Vec<_>>();
    let [record] = matches.as_slice() else {
        return Err(if matches.is_empty() {
            format!("guard `{name}` was not found")
        } else {
            format!("guard name `{name}` is ambiguous across scopes")
        });
    };
    nah_extensions::remove_activation_by_identity(&path, record.projection().identity())
        .map_err(|error| error.to_string())
}

pub(crate) fn disable_custom_guard_scoped(
    name: &str,
    selector: &GuardSelector,
) -> Result<(), String> {
    let identity = scoped_identity(name, selector)?;
    match disable_guard_identity(&identity) {
        Err(error) if error == format!("guard `{name}` was not found") => {
            Err(scoped_not_found(name, selector))
        }
        result => result,
    }
}

pub(crate) fn disable_guard_identity(identity: &GuardIdentity) -> Result<(), String> {
    validate_guard_identity(identity, None)?;
    let platform = host_platform();
    let home = home(platform)?;
    nah_extensions::remove_activation_by_identity(
        &nah_extensions::activation_database_path(&home, platform),
        identity,
    )
    .map_err(|error| error.to_string())
}

pub(crate) fn validate_guard_identity(
    identity: &GuardIdentity,
    expected_hash: Option<&str>,
) -> Result<(), String> {
    if let Some(expected_hash) = expected_hash {
        let bundles = discovered_bundles()?;
        let bundle = bundles
            .iter()
            .find(|bundle| bundle.projection().identity() == identity)
            .ok_or_else(|| format!("guard `{}` was not found", identity.name()))?;
        return if bundle.projection().bundle_hash().as_str() == expected_hash {
            Ok(())
        } else {
            Err("guard bytes changed; review and approve them again".into())
        };
    }
    let platform = host_platform();
    let home = home(platform)?;
    let activations = nah_extensions::ActivationDatabase::load(
        &nah_extensions::activation_database_path(&home, platform),
    )
    .map_err(|error| error.to_string())?;
    if activations
        .records()
        .iter()
        .any(|record| record.projection().identity() == identity)
    {
        Ok(())
    } else {
        Err(format!("guard `{}` was not found", identity.name()))
    }
}

fn scoped_identity(name: &str, selector: &GuardSelector) -> Result<GuardIdentity, String> {
    match selector {
        GuardSelector::Any => Err("guard scope is required".into()),
        GuardSelector::User => GuardIdentity::user(name).map_err(|error| error.to_string()),
        GuardSelector::Project(requested) => {
            let platform = host_platform();
            let home = home(platform)?;
            let root = canonical_project_root(requested, platform)?;
            let trust = nah_extensions::TrustDatabase::load(
                &nah_extensions::trust_database_path(&home, platform),
                platform,
            )
            .and_then(|database| database.projection())
            .map_err(|error| error.to_string())?;
            let trusted = trust
                .trusted_roots()
                .iter()
                .find(|trusted| trusted.path() == &root)
                .ok_or_else(|| {
                    format!(
                        "project root {:?} is not trusted; run `nah trust <root>` first",
                        root.as_str()
                    )
                })?;
            GuardIdentity::project(trusted.identity().clone(), name)
                .map_err(|error| error.to_string())
        }
    }
}

fn scoped_not_found(name: &str, selector: &GuardSelector) -> String {
    match selector {
        GuardSelector::Any => format!("guard `{name}` was not found"),
        GuardSelector::User => {
            format!("guard `{name}` was not found in user scope; run `nah guards`")
        }
        GuardSelector::Project(root) => {
            format!("guard `{name}` was not found in project scope {root:?}; run `nah guards`")
        }
    }
}

/// One covered bundle file, projected for human review before approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuardSourceFile {
    pub(crate) name: String,
    /// File text, or a notice when the bytes cannot be shown as text.
    pub(crate) text: Result<String, String>,
}

/// The bundle bytes an approval hash covers, capped for display.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct GuardSource {
    pub(crate) files: Vec<GuardSourceFile>,
    /// Total covered bytes when the cap dropped part of the view.
    pub(crate) truncated: Option<u64>,
}

/// Reads the bytes the approval hash covers, at most `limit` of them. Review
/// is advisory: activation still validates the hash against the bundle.
pub(crate) fn guard_source(identity: &GuardIdentity, limit: usize) -> Result<GuardSource, String> {
    let bundles = discovered_bundles()?;
    let bundle = bundles
        .iter()
        .find(|bundle| bundle.projection().identity() == identity)
        .ok_or_else(|| format!("guard `{}` was not found", identity.name()))?;
    let mut source = GuardSource::default();
    let mut total = 0u64;
    let mut budget = limit;
    for name in bundle.covered_files() {
        let (size, text) = source_file(&bundle.directory().join(name), budget);
        total = total.saturating_add(size);
        budget -= usize::try_from(size).unwrap_or(usize::MAX).min(budget);
        source.files.push(GuardSourceFile {
            name: name.clone(),
            text,
        });
    }
    source.truncated = (total > limit as u64).then_some(total);
    Ok(source)
}

/// Reads one covered file's size and its first `budget` bytes as text.
fn source_file(path: &Path, budget: usize) -> (u64, Result<String, String>) {
    let size = std::fs::metadata(path).map_or(0, |metadata| metadata.len());
    let text = std::fs::File::open(path)
        .and_then(|file| {
            let mut bytes = Vec::new();
            file.take(budget as u64).read_to_end(&mut bytes)?;
            Ok(bytes)
        })
        .map_err(|error| format!("cannot be read ({error})"))
        .and_then(|bytes| decode(&bytes, (bytes.len() as u64) < size));
    (size, text)
}

/// Decodes reviewed bytes; a capped read can split the final character.
fn decode(bytes: &[u8], capped: bool) -> Result<String, String> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Ok(text.to_owned()),
        Err(error) if capped && error.error_len().is_none() => {
            Ok(String::from_utf8_lossy(&bytes[..error.valid_up_to()]).into_owned())
        }
        Err(_) => Err("is not UTF-8 text".to_owned()),
    }
}

pub(crate) fn list_custom_guards() -> Result<String, String> {
    let rows = custom_guard_entries()?;
    if rows.is_empty() {
        return Ok(
            "\nCustom:\nNo custom guards discovered. Create one with `nah guard new <name>`.\n"
                .to_owned(),
        );
    }

    let mut output = "\nCustom:\nNAME\tSCOPE\tSTATUS\tMATCH\n".to_owned();
    for entry in rows {
        let scope = scope_name(entry.target.scope().expect("custom guard has a scope"));
        let status = match entry.status {
            GuardStatus::Enabled => "active",
            GuardStatus::Disabled => "inactive",
            GuardStatus::NeedsReapproval { .. } => "needs-reapproval",
            GuardStatus::Missing { .. } => "missing",
        };
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            entry.target.name(),
            scope,
            status,
            entry.match_programs.join(",")
        ));
    }
    Ok(output)
}

pub(crate) fn custom_guard_entries() -> Result<Vec<GuardEntry>, String> {
    let platform = host_platform();
    let home = home(platform)?;
    let trust = nah_extensions::TrustDatabase::load(
        &nah_extensions::trust_database_path(&home, platform),
        platform,
    )
    .and_then(|database| database.projection())
    .map_err(|error| error.to_string())?;
    let activations = nah_extensions::ActivationDatabase::load(
        &nah_extensions::activation_database_path(&home, platform),
    )
    .map_err(|error| error.to_string())?;
    let reserved_names = shipped_names();
    let (bundles, _) = nah_extensions::discover_bundles(&home, platform, &trust, &reserved_names)
        .map_err(|error| error.to_string())?;

    let mut rows = bundles
        .iter()
        .map(|bundle| {
            let projection = bundle.projection();
            let status = activations
                .records()
                .iter()
                .find(|record| record.projection().identity() == projection.identity())
                .map_or(GuardStatus::Disabled, |record| {
                    if record.projection() == projection {
                        GuardStatus::Enabled
                    } else {
                        GuardStatus::NeedsReapproval {
                            approved_hash: record.projection().bundle_hash().as_str().to_owned(),
                            current_hash: projection.bundle_hash().as_str().to_owned(),
                        }
                    }
                });
            GuardEntry {
                target: GuardTarget::Custom {
                    identity: projection.identity().clone(),
                },
                family: None,
                default_enabled: None,
                operator_override: None,
                path: Some(bundle.directory().to_path_buf()),
                status,
                behavior: None,
                examples: vec![],
                match_programs: projection.match_programs().to_vec(),
                current_hash: Some(projection.bundle_hash().as_str().to_owned()),
            }
        })
        .collect::<Vec<_>>();
    rows.extend(
        activations
            .records()
            .iter()
            .filter(|record| {
                !bundles
                    .iter()
                    .any(|bundle| bundle.projection().identity() == record.projection().identity())
            })
            .map(|record| {
                let projection = record.projection();
                GuardEntry {
                    target: GuardTarget::Custom {
                        identity: projection.identity().clone(),
                    },
                    family: None,
                    default_enabled: None,
                    operator_override: None,
                    path: None,
                    status: GuardStatus::Missing {
                        approved_hash: projection.bundle_hash().as_str().to_owned(),
                    },
                    behavior: None,
                    examples: vec![],
                    match_programs: projection.match_programs().to_vec(),
                    current_hash: None,
                }
            }),
    );
    rows.sort_by(|left, right| left.target.cmp(&right.target));
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::{decode, source_file};

    #[test]
    fn capped_reads_keep_whole_characters_and_refuse_binary_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("run");
        std::fs::write(&run, "print(\"caf\u{e9}\")\n").unwrap();

        let (size, text) = source_file(&run, 1024);
        assert_eq!(size, 15);
        assert_eq!(text.unwrap(), "print(\"caf\u{e9}\")\n");

        // The cap lands inside the two-byte character; the split char is dropped.
        let (size, text) = source_file(&run, 11);
        assert_eq!(size, 15);
        assert_eq!(text.unwrap(), "print(\"caf");

        let data = temp.path().join("words.txt");
        std::fs::write(&data, [0x66, 0xff, 0x66]).unwrap();
        assert_eq!(source_file(&data, 1024).1.unwrap_err(), "is not UTF-8 text");

        let (size, text) = source_file(&temp.path().join("missing"), 1024);
        assert_eq!(size, 0);
        assert!(text.unwrap_err().starts_with("cannot be read"));

        // A whole file that ends mid-character is not text, only a cap is.
        assert!(decode(&[0x63, 0xc3], false).is_err());
    }
}
