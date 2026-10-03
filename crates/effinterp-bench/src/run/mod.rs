//! Durable bench runs. Every `measure` writes the untracked `bench/runs/<id>/`
//! as it goes:
//! an immutable manifest (what was selected and what identity measured it),
//! a state file, and one file per unit of work, so an interrupted run resumes
//! with only the missing units and a finished run gets its verdict or is
//! published without repeating any computation. `measure.rs` owns the
//! measuring verb; `publish.rs` owns verdicts and publication.
//!
//! Layout of one run:
//!
//! ```text
//! manifest.json            selection + identity, written once
//! state.json               running | complete | interrupted, rewritten per unit
//! lock                     flock held by the measuring process
//! correctness.json         Authored expectations, adversarial cases, and parity
//! coverage.json            Invocation coverage by source
//! repos/<owner__name>.json RepoUnit: row + bounded diagnostics
//! repos.json               ReposSection assembled from the units
//! nah-latency.json         LatencySection with only nah_p99_us measured
//! stress.json              LatencySection assembled from stress/** units
//! stress/**                the latency plane's own checkpoints
//! seal.json                byte hash of every record file, written last
//! verdicts/<key>.json      run verdicts, keyed by every input
//! ```
//!
//! Every file the bench writes here is an envelope `{schema, content_hash,
//! data}` whose hash is recomputed on read, so an edited unit is refused
//! rather than reused, and the seal ties the whole record together once a
//! run completes. `record.rs` owns that checked record codec.

pub mod measure;
pub mod publish;
mod record;

pub use record::{UNIT_SCHEMA, content_hash, read_bench_record, read_envelope, write_bench_record};

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::ValueEnum;
use effinterp_repo::IndexLimits;
use serde::{Deserialize, Serialize};

use crate::bench;
use crate::bench::score::Scoreboard;
use crate::fingerprint;
use crate::latency;
use crate::latency::checkpoint::STRESS_UNIT_SCHEMA;
use crate::latency::machine::Machine;
use crate::nah::corpus::{CaseLoad, fixture_corpus_digest, load_corpus};
use crate::repos::isolate::BinaryIdentity;
use crate::repos::score::{CHILD_TIMEOUT, Diagnostics, MAX_CHILD_MEMORY, REPOS_DIR, RepoRow};

pub const RUN_SCHEMA: &str = "effinterp/bench-run/v3";
pub const RUNS_DIR: &str = "bench/runs";
pub const BENCH_CORPUS: &str = "bench/invocation";
pub const NAH_CORPUS: &str = "corpus";
pub const SCOREBOARD: &str = "bench/scoreboard.json";
pub const SCOREBOARD_MD: &str = "bench/scoreboard.md";
pub const CEILINGS: &str = "bench/nah/ceilings.json";
/// Fingerprint of the source tree this binary was built from (`build.rs`).
pub const BUILT_FROM: &str = env!("EFFINTERP_SOURCE_FINGERPRINT");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Plane {
    /// Authored semantic cases, adversarial expectations, and nah parity.
    Correctness,
    /// Reported coverage over real invocation corpora.
    Coverage,
    /// Analysis completeness and honesty diagnostics over pinned public repositories.
    Repositories,
    /// Invocation latency and bounded engine stress.
    Performance,
}

impl Plane {
    pub const ALL: [Plane; 4] = [
        Plane::Correctness,
        Plane::Coverage,
        Plane::Repositories,
        Plane::Performance,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Plane::Coverage => "coverage",
            Plane::Correctness => "correctness",
            Plane::Repositories => "repositories",
            Plane::Performance => "performance",
        }
    }
}

/// Where the bench reads its inputs and writes its records. Production uses
/// the workspace root; tests point it at a fixture tree.
#[derive(Debug, Clone)]
pub struct BenchLayout {
    pub root: PathBuf,
    pub session_corpus: Option<PathBuf>,
    /// The fingerprint the running binary was built from.
    pub built_from: String,
}

impl BenchLayout {
    pub fn workspace() -> Self {
        BenchLayout {
            root: PathBuf::from("."),
            session_corpus: None,
            built_from: BUILT_FROM.to_string(),
        }
    }

    pub fn runs(&self) -> PathBuf {
        self.root.join(RUNS_DIR)
    }

    /// `bench/runs/<id>/`; the typed id keeps the join to one path component.
    pub fn run_directory(&self, id: &RunId) -> PathBuf {
        self.runs().join(&id.0)
    }

    pub fn scoreboard(&self) -> PathBuf {
        self.root.join(SCOREBOARD)
    }

    pub fn scoreboard_md(&self) -> PathBuf {
        self.root.join(SCOREBOARD_MD)
    }

    pub fn ceilings(&self) -> PathBuf {
        self.root.join(CEILINGS)
    }

    /// Fresh fingerprint of the tree, refused unless it is the one this
    /// binary was built from: an older binary must not measure, resume, or
    /// publish against a newer tree.
    pub fn verify_build_matches_tree(&self) -> Result<String, String> {
        let now = self.source_fingerprint()?;
        if now == self.built_from {
            Ok(now)
        } else {
            Err(format!(
                "this binary was built from source {} but the tree is now {now}: rebuild first",
                self.built_from
            ))
        }
    }

    pub fn source_fingerprint(&self) -> Result<String, String> {
        fingerprint::compute_source_fingerprint(&self.root)
            .map_err(|e| format!("source fingerprint: {e}"))
    }

    pub fn corpus_digests(&self) -> Result<CorpusDigests, String> {
        let digest = |dir: PathBuf| {
            fixture_corpus_digest(&dir).map_err(|e| format!("cannot digest {}: {e}", dir.display()))
        };
        Ok(CorpusDigests {
            invocation: self.coverage_digest()?,
            nah: digest(self.root.join(NAH_CORPUS))?,
            repos: crate::repos::score::repos_corpus_digest(&self.root.join(REPOS_DIR))
                .map_err(|e| format!("cannot digest {REPOS_DIR}: {e}"))?,
        })
    }

    pub fn coverage_digest(&self) -> Result<String, String> {
        let mut hash = blake3::Hasher::new();
        for path in [BENCH_CORPUS, NAH_CORPUS] {
            hash.update(
                fixture_corpus_digest(&self.root.join(path))
                    .map_err(|e| e.to_string())?
                    .as_bytes(),
            );
        }
        if let Some(path) = &self.session_corpus {
            hash.update(bench::sessions::session_corpus_digest(path)?.as_bytes());
        }
        Ok(hash.finalize().to_hex().to_string())
    }

    /// Everything a publication compares between the record and the tree.
    pub fn compat(&self, source_fingerprint: String) -> Result<RunCompat, String> {
        let mut config = MeasurementConfig::current();
        config.session_corpus = self
            .session_corpus
            .as_ref()
            .map(|path| {
                let bytes = fs::read(path.join("MANIFEST.json")).map_err(|e| e.to_string())?;
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())
            })
            .transpose()?;
        Ok(RunCompat {
            source_fingerprint,
            build: BuildInfo::current(),
            corpus: self.corpus_digests()?,
            config,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusDigests {
    pub invocation: String,
    pub nah: String,
    pub repos: String,
}

/// Effective limits that shape a measurement; part of compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementConfig {
    pub session_corpus: Option<serde_json::Value>,
    pub subject_deadline_secs: u64,
    pub repo_child_timeout_secs: u64,
    pub repo_child_memory_bytes: u64,
    pub memory_enforcement: String,
    pub index_limits: serde_json::Value,
    pub latency: serde_json::Value,
}

impl MeasurementConfig {
    pub fn current() -> Self {
        MeasurementConfig {
            session_corpus: None,
            subject_deadline_secs: bench::DEADLINE.as_secs(),
            repo_child_timeout_secs: CHILD_TIMEOUT.as_secs(),
            repo_child_memory_bytes: MAX_CHILD_MEMORY,
            memory_enforcement: crate::repos::isolate::MEMORY_ENFORCEMENT.into(),
            index_limits: serde_json::to_value(IndexLimits::default())
                .expect("index limits serialize"),
            latency: serde_json::to_value(latency::configuration())
                .expect("latency configuration serializes"),
        }
    }
}

/// Identity that must be equal between a record and the binary and tree that
/// publish it: the source, how it was compiled, the corpora, and the limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunCompat {
    pub source_fingerprint: String,
    pub build: BuildInfo,
    pub corpus: CorpusDigests,
    pub config: MeasurementConfig,
}

impl RunCompat {
    /// Human-readable differences, empty when compatible.
    pub fn mismatches(&self, current: &RunCompat) -> Vec<String> {
        let mut out = Vec::new();
        if self.source_fingerprint != current.source_fingerprint {
            out.push(format!(
                "source fingerprint {} != current {}",
                self.source_fingerprint, current.source_fingerprint
            ));
        }
        for (name, recorded, now) in [
            (
                "invocation",
                &self.corpus.invocation,
                &current.corpus.invocation,
            ),
            ("nah", &self.corpus.nah, &current.corpus.nah),
            ("repos", &self.corpus.repos, &current.corpus.repos),
        ] {
            if recorded != now {
                out.push(format!("{name} corpus digest {recorded} != current {now}"));
            }
        }
        if self.build != current.build {
            out.push(format!(
                "build {:?} != current {:?}",
                self.build, current.build
            ));
        }
        if self.config != current.config {
            out.push("measurement configuration differs from the current build".to_string());
        }
        out
    }
}

/// How the measuring binary was compiled, embedded by `build.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInfo {
    pub rustc: String,
    pub profile: String,
    pub opt_level: String,
    pub debug: String,
    pub target: String,
    pub rustflags: String,
}

impl BuildInfo {
    pub fn current() -> Self {
        BuildInfo {
            rustc: env!("EFFINTERP_BUILD_RUSTC").to_string(),
            profile: env!("EFFINTERP_BUILD_PROFILE").to_string(),
            opt_level: env!("EFFINTERP_BUILD_OPT_LEVEL").to_string(),
            debug: env!("EFFINTERP_BUILD_DEBUG").to_string(),
            target: env!("EFFINTERP_BUILD_TARGET").to_string(),
            rustflags: env!("EFFINTERP_BUILD_RUSTFLAGS").to_string(),
        }
    }
}

/// Recorded for the reader; never compared. `git_head` says where the tree
/// was, not what built the binary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunProvenance {
    pub binary: BinaryIdentity,
    pub engine_version: String,
    pub model_set: String,
    pub git_head: Option<String>,
    pub machine: Machine,
}

/// What one published plane of the scoreboard was measured by.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlaneProvenance {
    pub run_id: String,
    pub measured_at: String,
    pub source_fingerprint: String,
    pub binary_hash: String,
    pub engine_version: String,
    pub model_set: String,
    pub git_head: Option<String>,
    pub machine: Machine,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSelection {
    pub planes: Vec<Plane>,
    pub sources: Vec<String>,
    pub limit: Option<usize>,
    pub repos: Vec<String>,
    pub unlock_hidden: Option<String>,
}

impl RunSelection {
    /// A run that scored part of a plane without recording which part; never
    /// publishable, because its numbers would read as the whole plane's. A
    /// repository selection is not such a run: it is named in the published
    /// section (`ReposSection::selected`) and gated only over what it
    /// measured, so a bounded repository run publishes as the bounded scope
    /// it is.
    pub fn partial(&self) -> bool {
        !self.sources.is_empty() || self.limit.is_some()
    }
}

/// A measured run's `manifest.json` in `bench/runs/<id>/`: written once when
/// the run starts and read back unchanged on `--resume` and publication. The
/// repository corpus `corpus.toml` is `RepositoryCorpusManifest`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunManifest {
    pub schema: String,
    pub run_id: String,
    pub started_at: String,
    pub selection: RunSelection,
    pub compat: RunCompat,
    pub provenance: RunProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunStatus {
    Running,
    Complete,
    Interrupted,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Complete => "complete",
            RunStatus::Interrupted => "interrupted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunState {
    pub status: RunStatus,
    pub pid: u32,
    pub updated_at: String,
    pub completed_planes: Vec<Plane>,
    pub repo_units: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One repository's checkpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoUnit {
    pub row: RepoRow,
    pub diagnostics: Diagnostics,
}

pub fn repo_unit_name(repo: &str) -> String {
    format!("{}.json", repo.replace('/', "__"))
}

/// Write `bytes` to `path` through a temporary sibling, fsync, and rename,
/// then fsync the directory: a crash leaves the previous file or the new
/// one, never a mix, and a completed write survives power loss.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("{}: no file name", path.display()))?;
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()
    };
    write().map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("cannot write {}: {e}", path.display())
    })
}

/// Exclusive, non-blocking `flock` on a file, released on drop.
pub struct FileLock {
    _file: File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Closing alone leaves the lock held while a spawned child still has
        // its inherited descriptor open between fork and exec.
        // SAFETY: the descriptor remains owned and open until after drop returns.
        unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl FileLock {
    pub fn acquire(path: &Path) -> Result<Self, String> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        // SAFETY: flock on a valid, owned descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(format!(
                "{} is held by another process: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let _ = file.set_len(0);
        let _ = writeln!(file, "{}", std::process::id());
        Ok(FileLock { _file: file })
    }

    /// Lock probe: whether `path` exists and this process cannot take its
    /// exclusive lock. Not a read-only observation: when the probe acquires
    /// the lock it truncates the file and writes this process's PID, then
    /// releases it on drop. Any acquisition error, including an open or
    /// permission failure, counts as held, so a run is only reported
    /// interrupted when the lock was actually free. A missing file is not
    /// held and is left uncreated.
    pub fn is_held(path: &Path) -> bool {
        path.exists() && FileLock::acquire(path).is_err()
    }
}

/// The lock a measuring process holds on its run.
pub fn run_lock_path(dir: &Path) -> PathBuf {
    dir.join("lock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_lock_drop_releases_lock_with_an_inherited_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let lock = FileLock::acquire(&path).unwrap();
        // A child between fork and exec shares the same open file description.
        let inherited = lock._file.try_clone().unwrap();
        assert!(FileLock::acquire(&path).is_err());
        drop(lock);
        let next = FileLock::acquire(&path).unwrap();
        drop(inherited);
        assert!(FileLock::acquire(&path).is_err());
        drop(next);
        FileLock::acquire(&path).unwrap();
    }
}

/// A run id that is a single path component the bench itself produced:
/// accepted by `validate_run_id` or generated by `measure`. Manifests still
/// record it as the plain `run_id` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunId(String);

impl RunId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Parse a caller-supplied run id; the only way to build a `RunId` outside
/// `measure`.
pub fn validate_run_id(id: &str) -> Result<RunId, String> {
    let ok = !id.is_empty()
        && !id.starts_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '.'));
    if ok {
        Ok(RunId(id.to_string()))
    } else {
        Err(format!("{id:?} is not a run id"))
    }
}

/// Every completed stress checkpoint below `<run>/stress/`, each verified
/// against its own content hash. A live partial checkpoint means the plane
/// did not finish, whatever `stress.json` says.
pub fn stress_units(dir: &Path) -> Result<Vec<PathBuf>, String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))? {
            let path = entry.map_err(|e| e.to_string())?.path();
            let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "{} is a symbolic link inside a run record",
                    path.display()
                ));
            }
            if meta.is_dir() {
                walk(&path, out)?;
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') {
                continue;
            }
            if name.ends_with(".partial.json") {
                return Err(format!(
                    "{} is a live child checkpoint; the stress plane did not finish",
                    path.display()
                ));
            }
            if !name.ends_with(".json") {
                continue;
            }
            read_envelope(&path, STRESS_UNIT_SCHEMA)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            out.push(path);
        }
        Ok(())
    }
    let mut out = Vec::new();
    let root = dir.join("stress");
    if root.is_dir() {
        walk(&root, &mut out)?;
    }
    out.sort();
    Ok(out)
}

/// Every measurement file of a run with these planes: the manifest and the
/// plane files, with the repository and stress units below them. The seal
/// lists exactly this set.
pub fn record_files(dir: &Path, planes: &[Plane]) -> Result<Vec<PathBuf>, String> {
    let mut files = vec![dir.join("manifest.json")];
    for plane in planes {
        match plane {
            Plane::Coverage => files.push(dir.join("coverage.json")),
            Plane::Correctness => files.push(dir.join("correctness.json")),
            Plane::Repositories => {
                files.push(dir.join("repos.json"));
                let units = dir.join("repos");
                for entry in fs::read_dir(&units)
                    .map_err(|e| format!("cannot list {}: {e}", units.display()))?
                {
                    let path = entry.map_err(|e| e.to_string())?.path();
                    // A leftover `.x.json.<pid>.tmp` from a killed write is
                    // not a unit.
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if path.is_file() && name.ends_with(".json") && !name.starts_with('.') {
                        files.push(path);
                    }
                }
            }
            Plane::Performance => {
                files.push(dir.join("nah-latency.json"));
                files.push(dir.join("stress.json"));
                files.extend(stress_units(dir)?);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Read every record of a completed plane through its envelope checks.
fn verify_plane(dir: &Path, plane: Plane) -> Result<(), String> {
    match plane {
        Plane::Coverage => read_bench_record::<Scoreboard>(&dir.join("coverage.json")).map(drop),
        Plane::Correctness => {
            read_bench_record::<Scoreboard>(&dir.join("correctness.json")).map(drop)
        }
        Plane::Repositories => {
            let section: crate::repos::score::ReposSection =
                read_bench_record(&dir.join("repos.json"))?;
            for name in section.repos.keys() {
                read_bench_record::<RepoUnit>(&dir.join("repos").join(repo_unit_name(name)))?;
            }
            Ok(())
        }
        Plane::Performance => {
            read_bench_record::<latency::LatencySection>(&dir.join("nah-latency.json"))?;
            read_bench_record::<latency::LatencySection>(&dir.join("stress.json"))?;
            stress_units(dir).map(drop)
        }
    }
}

/// Byte hash of every record file, keyed by run-relative path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSeal {
    pub files: BTreeMap<String, String>,
}

pub fn seal(dir: &Path, planes: &[Plane]) -> Result<RunSeal, String> {
    let mut files = BTreeMap::new();
    for path in record_files(dir, planes)? {
        let bytes = fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let relative = path.strip_prefix(dir).unwrap_or(&path);
        files.insert(
            relative.to_string_lossy().into_owned(),
            effinterp_proto::content_digest(&bytes),
        );
    }
    Ok(RunSeal { files })
}

pub fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rest = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Proleptic Gregorian date of a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn git_head(root: &Path) -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn load_nah(layout: &BenchLayout) -> Result<(Vec<CaseLoad>, String, String), String> {
    let corpus = layout.root.join(NAH_CORPUS);
    let cases =
        load_corpus(&corpus).map_err(|e| format!("cannot read {}: {e}", corpus.display()))?;
    let digest = fixture_corpus_digest(&corpus)
        .map_err(|e| format!("cannot digest {}: {e}", corpus.display()))?;
    // Corpus bytes define freshness; HEAD records this repository as provenance.
    let commit = git_head(&layout.root).ok_or_else(|| {
        format!(
            "cannot resolve repository HEAD in {}",
            layout.root.display()
        )
    })?;
    Ok((cases, digest, commit))
}
