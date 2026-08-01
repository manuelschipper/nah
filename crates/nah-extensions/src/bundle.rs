//! Discovers and validates extension bundles; it does not activate or execute them.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use nah_proto::ctx::{
    AbsolutePath, ActivationProjection, ContentHash, ExecProtocolVersion, GuardIdentity,
    GuardScope, Platform, TrustProjection, TrustedRootId,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::activation::ActivationDatabase;

#[derive(Clone, Debug)]
pub struct ExtensionBundle {
    directory: PathBuf,
    run: PathBuf,
    covered: Vec<String>,
    projection: ActivationProjection,
}

impl ExtensionBundle {
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn run(&self) -> &Path {
        &self.run
    }

    /// Bundle-relative paths the bundle hash covers, in hash order. A human
    /// reviewing an activation is approving exactly these bytes.
    pub fn covered_files(&self) -> &[String] {
        &self.covered
    }

    pub fn projection(&self) -> &ActivationProjection {
        &self.projection
    }
}

#[derive(Clone, Debug)]
pub struct ActiveExtensionCatalog {
    extensions: Vec<ExtensionBundle>,
    warnings: Vec<String>,
}

impl ActiveExtensionCatalog {
    /// The safe default when the catalog cannot be built: no extension runs.
    pub fn empty() -> Self {
        Self {
            extensions: vec![],
            warnings: vec![],
        }
    }

    pub fn extensions(&self) -> &[ExtensionBundle] {
        &self.extensions
    }

    pub fn activations(&self) -> Vec<ActivationProjection> {
        self.extensions
            .iter()
            .map(|extension| extension.projection.clone())
            .collect()
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// The one directory name a guard bundle can live in, under `~/.nah` or a
/// trusted project's `.nah`.
const GUARDS: &str = "guards";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    name: String,
    #[serde(rename = "match")]
    match_programs: Vec<String>,
    protocol: String,
    provenance: Provenance,
    #[serde(default)]
    data: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Provenance {
    User,
    Agent,
}

/// Returns the loadable bundles plus a warning for every bundle that was
/// skipped. One broken bundle never hides its healthy siblings.
pub fn discover_bundles(
    home: &AbsolutePath,
    platform: Platform,
    trust: &TrustProjection,
    reserved_names: &[&str],
) -> Result<(Vec<ExtensionBundle>, Vec<String>), BundleError> {
    let mut bundles = Vec::new();
    let mut warnings = Vec::new();
    discover_directory(
        &guard_directory_path(home, platform),
        GuardScope::User,
        None,
        reserved_names,
        &mut bundles,
        &mut warnings,
    )?;
    for root in trust.trusted_roots() {
        discover_directory(
            &Path::new(root.path().as_str()).join(".nah").join(GUARDS),
            GuardScope::Project,
            Some(root.identity().clone()),
            reserved_names,
            &mut bundles,
            &mut warnings,
        )?;
    }
    bundles.sort_by(|left, right| left.projection.identity().cmp(right.projection.identity()));
    let collisions = bundles
        .windows(2)
        .filter(|pair| pair[0].projection.identity() == pair[1].projection.identity())
        .map(|pair| pair[0].projection.identity().clone())
        .collect::<BTreeSet<_>>();
    if !collisions.is_empty() {
        bundles.retain(|bundle| {
            if !collisions.contains(bundle.projection.identity()) {
                return true;
            }
            let directory = bundle
                .directory()
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            warnings.push(format!(
                "inactive extension bundle `{directory}`: policy-identity-collision"
            ));
            false
        });
    }
    warnings.sort();
    Ok((bundles, warnings))
}

pub fn load_active_extensions(
    home: &AbsolutePath,
    platform: Platform,
    trust: &TrustProjection,
    activations: &ActivationDatabase,
    reserved_names: &[&str],
) -> Result<ActiveExtensionCatalog, BundleError> {
    let (discovered, mut warnings) = discover_bundles(home, platform, trust, reserved_names)?;
    let by_identity = discovered
        .iter()
        .map(|bundle| (bundle.projection.identity(), bundle))
        .collect::<BTreeMap<_, _>>();
    let trusted_ids = trust
        .trusted_roots()
        .iter()
        .map(|root| root.identity())
        .collect::<BTreeSet<_>>();
    let mut extensions = Vec::new();

    for record in activations.records() {
        let identity = record.projection().identity();
        if identity.scope() == GuardScope::Project
            && identity
                .trusted_root()
                .is_none_or(|root| !trusted_ids.contains(root))
        {
            warnings.push(format!(
                "inactive extension `{}`: project root is not trusted",
                identity.name()
            ));
            continue;
        }
        match by_identity.get(identity) {
            Some(bundle) if bundle.projection == *record.projection() => {
                extensions.push((*bundle).clone());
            }
            Some(_) => warnings.push(format!(
                "inactive extension `{}`: activated bundle bytes have changed",
                identity.name()
            )),
            None => warnings.push(format!(
                "inactive extension `{}`: activated bundle is missing",
                identity.name()
            )),
        }
    }
    extensions.sort_by(|left, right| left.projection.identity().cmp(right.projection.identity()));
    Ok(ActiveExtensionCatalog {
        extensions,
        warnings,
    })
}

fn discover_directory(
    directory: &Path,
    scope: GuardScope,
    trusted_root: Option<TrustedRootId>,
    reserved_names: &[&str],
    bundles: &mut Vec<ExtensionBundle>,
    warnings: &mut Vec<String>,
) -> Result<(), BundleError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(BundleError::Io),
    };
    for entry in entries {
        let entry = entry.map_err(|_| BundleError::Io)?;
        if !entry.file_type().map_err(|_| BundleError::Io)?.is_dir() {
            continue;
        }
        match load_bundle(&entry.path(), scope, trusted_root.clone(), reserved_names) {
            Ok(bundle) => bundles.push(bundle),
            Err(error) => warnings.push(format!(
                "inactive extension bundle `{}`: {error}",
                entry.file_name().to_string_lossy()
            )),
        }
    }
    Ok(())
}

fn load_bundle(
    directory: &Path,
    scope: GuardScope,
    trusted_root: Option<TrustedRootId>,
    reserved_names: &[&str],
) -> Result<ExtensionBundle, BundleError> {
    let manifest_path = directory.join("policy.toml");
    let run = directory.join("run");
    let manifest_bytes = read_regular_file(&manifest_path)?;
    let manifest: Manifest =
        toml::from_slice(&manifest_bytes).map_err(|_| BundleError::InvalidManifest)?;
    if manifest.protocol != "exec/v1" {
        return Err(BundleError::UnsupportedProtocol);
    }
    let _ = manifest.provenance;
    let identity = match (scope, trusted_root) {
        (GuardScope::User, None) => {
            GuardIdentity::user(&manifest.name).map_err(|_| BundleError::InvalidManifest)?
        }
        (GuardScope::Project, Some(root)) => GuardIdentity::project(root, &manifest.name)
            .map_err(|_| BundleError::InvalidManifest)?,
        _ => return Err(BundleError::InvalidIdentity),
    };
    if reserved_names.contains(&identity.name()) {
        return Err(BundleError::ReservedName);
    }
    let run_bytes = read_regular_file(&run)?;
    require_executable(&run)?;
    let data = validate_data_files(&manifest.data)?;
    let mut covered = vec![
        ("policy.toml".to_owned(), manifest_bytes),
        ("run".to_owned(), run_bytes),
    ];
    for relative in data {
        covered.push((
            relative.clone(),
            read_regular_file(&directory.join(&relative))?,
        ));
    }
    covered.sort_by(|left, right| left.0.cmp(&right.0));
    let bundle_hash = hash_bundle(&covered)?;
    let projection = ActivationProjection::new(
        identity,
        bundle_hash,
        ExecProtocolVersion::V1,
        manifest.match_programs,
    )
    .map_err(|_| BundleError::InvalidManifest)?;
    Ok(ExtensionBundle {
        directory: directory.to_owned(),
        run,
        covered: covered.into_iter().map(|(name, _)| name).collect(),
        projection,
    })
}

fn validate_data_files(data: &[String]) -> Result<Vec<String>, BundleError> {
    let mut files = data.to_vec();
    files.sort();
    if files.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(BundleError::InvalidManifest);
    }
    for file in &files {
        let path = Path::new(file);
        if file.is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || matches!(file.as_str(), "policy.toml" | "run")
        {
            return Err(BundleError::InvalidManifest);
        }
    }
    Ok(files)
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, BundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BundleError::MissingBundleFile)?;
    if !metadata.file_type().is_file() {
        return Err(BundleError::InvalidBundleFile);
    }
    fs::read(path).map_err(|_| BundleError::Io)
}

#[cfg(unix)]
fn require_executable(path: &Path) -> Result<(), BundleError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::symlink_metadata(path)
        .map_err(|_| BundleError::MissingBundleFile)?
        .permissions()
        .mode();
    (mode & 0o111 != 0)
        .then_some(())
        .ok_or(BundleError::RunNotExecutable)
}

#[cfg(not(unix))]
fn require_executable(_path: &Path) -> Result<(), BundleError> {
    Ok(())
}

fn hash_bundle(files: &[(String, Vec<u8>)]) -> Result<ContentHash, BundleError> {
    let mut hash = Sha256::new();
    hash.update(b"nah-policy-bundle-v1\0");
    for (name, bytes) in files {
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    ContentHash::new(format!("{:x}", hash.finalize())).map_err(|_| BundleError::InvalidManifest)
}

pub fn guard_directory_path(home: &AbsolutePath, platform: Platform) -> PathBuf {
    let separator = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    PathBuf::from(format!(
        "{}{separator}.nah{separator}{GUARDS}",
        home.as_str().trim_end_matches(['/', '\\'])
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleError {
    InvalidBundleFile,
    InvalidIdentity,
    InvalidManifest,
    Io,
    MissingBundleFile,
    RunNotExecutable,
    ReservedName,
    UnsupportedProtocol,
}

impl BundleError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidBundleFile => "invalid-policy-bundle-file",
            Self::InvalidIdentity => "invalid-policy-identity",
            Self::InvalidManifest => "invalid-policy-manifest",
            Self::Io => "policy-io-failed",
            Self::MissingBundleFile => "missing-policy-bundle-file",
            Self::RunNotExecutable => "policy-run-not-executable",
            Self::ReservedName => "reserved-policy-name",
            Self::UnsupportedProtocol => "unsupported-policy-protocol",
        }
    }
}

impl fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for BundleError {}
