//! The `measure` verb: score the selected planes into a new or resumed run
//! record under `bench/runs/<id>/`. `publish.rs` owns what happens to a
//! finished record.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use effinterp_engine::Engine;
use effinterp_proto::Subject;

use super::{
    BENCH_CORPUS, BenchLayout, FileLock, Plane, RUN_SCHEMA, RepoUnit, RunId, RunManifest,
    RunProvenance, RunSelection, RunState, RunStatus, git_head, load_nah, read_bench_record,
    repo_unit_name, run_lock_path, seal, utc_now, validate_run_id, verify_plane,
    write_bench_record,
};
use crate::invocation;
use crate::invocation::corpus::{load_bench, nah_rows};
use crate::invocation::score::Scoreboard;
use crate::latency;
use crate::nah::report::{parity, run_corpus};
use crate::repos::isolate::binary_identity;
use crate::repos::score::{Checkpoints, Diagnostics, REPOS_DIR, RepoRow, cache_dir, score_repos};

fn provenance(root: &Path, engine: &Engine) -> Result<RunProvenance, String> {
    let probe = engine
        .analyze(&Subject::Exec {
            argv: vec!["true".to_string()],
            cwd: None,
            context: Default::default(),
        })
        .expect("probe analysis cannot fail");
    let exe = std::env::current_exe().map_err(|e| format!("current executable: {e}"))?;
    let binary = binary_identity(&exe);
    if binary.size == 0 {
        return Err(format!("cannot hash the running binary {}", exe.display()));
    }
    Ok(RunProvenance {
        binary,
        engine_version: probe.analysis.engine_version,
        model_set: probe.analysis.model_set,
        git_head: git_head(root),
        machine: latency::machine::identity().map_err(|e| format!("machine identity: {e}"))?,
    })
}

/// Score reported invocation coverage without running independent correctness oracles,
/// narrowed by `sources` and `limit` for exploratory partial runs.
pub fn score_coverage(
    layout: &BenchLayout,
    engine: Arc<Engine>,
    sources: &[String],
    limit: Option<usize>,
) -> Result<Scoreboard, String> {
    let corpus = layout.root.join(BENCH_CORPUS);
    let digest = layout.coverage_digest()?;
    let mut rows = load_bench(&corpus)?;
    rows.retain(|row| row.source != "adversarial");
    let (cases, _, _) = load_nah(layout)?;
    rows.extend(nah_rows(&cases));
    if let Some(path) = &layout.session_corpus
        && (sources.is_empty() || sources.iter().any(|source| source == "sessions"))
    {
        rows.extend(invocation::sessions::load_session_rows(path, limit)?);
    }
    if !sources.is_empty() {
        rows.retain(|row| sources.contains(&row.source));
    }
    if let Some(limit) = limit {
        let mut seen = BTreeMap::<String, usize>::new();
        rows.retain(|row| {
            let count = seen.entry(row.source.clone()).or_default();
            *count += 1;
            *count <= limit
        });
    }
    let mut board = invocation::score_corpus(engine, rows);
    board.coverage.corpus_digest = digest;
    Ok(board)
}

/// Correctness has independent expected answers; corpus coverage is measured separately.
pub fn score_correctness(layout: &BenchLayout, engine: Arc<Engine>) -> Result<Scoreboard, String> {
    let corpus = layout.root.join(BENCH_CORPUS);
    let rows = load_bench(&corpus)?
        .into_iter()
        .filter(|row| row.source == "adversarial")
        .collect();
    let mut board = invocation::score_corpus(engine.clone(), rows);
    board.correctness.corpus_digest =
        invocation::corpus::correctness_digest(&corpus).map_err(|e| e.to_string())?;
    let (cases, digest, commit) = load_nah(layout)?;
    board.correctness.parity = Some(parity(&run_corpus(&engine, cases, digest, commit)));
    board.correctness.semantic = Some(crate::layered::measure_semantic_score(
        &engine,
        &layout.root.join("crates/effinterp-bench/fixtures"),
    ));
    Ok(board)
}

/// Repository checkpoints under `<run>/repos/`, counting units into the state.
struct RunCheckpoints<'a> {
    dir: PathBuf,
    state_path: PathBuf,
    state: &'a mut RunState,
}

impl Checkpoints for RunCheckpoints<'_> {
    fn load(&self, name: &str) -> Result<Option<RepoRow>, String> {
        let path = self.dir.join(repo_unit_name(name));
        if !path.exists() {
            return Ok(None);
        }
        read_bench_record::<RepoUnit>(&path).map(|unit| Some(unit.row))
    }

    fn store(
        &mut self,
        name: &str,
        row: &RepoRow,
        diagnostics: &Diagnostics,
    ) -> Result<(), String> {
        let unit = RepoUnit {
            row: row.clone(),
            diagnostics: diagnostics.clone(),
        };
        write_bench_record(&self.dir.join(repo_unit_name(name)), &unit)?;
        self.state.repo_units += 1;
        self.state.updated_at = utc_now();
        write_bench_record(&self.state_path, self.state)
    }
}

pub struct MeasureRequest {
    pub selection: RunSelection,
    /// Continue this recorded run instead of starting a new one.
    pub resume: Option<String>,
    pub cache: Option<PathBuf>,
}

/// Measure the selected planes into a new or resumed run; returns the run id.
pub fn measure_run(layout: &BenchLayout, request: MeasureRequest) -> Result<RunId, String> {
    let source_fingerprint = layout.verify_build_matches_tree()?;
    let compat = layout.compat(source_fingerprint)?;
    let engine = Arc::new(Engine::new().with_causality_detail(true));
    let (run_id, dir, manifest) = match &request.resume {
        Some(id) => {
            if request.selection != RunSelection::default() {
                return Err("--resume takes its selection from the recorded manifest".to_string());
            }
            let run_id = validate_run_id(id)?;
            let dir = layout.run_directory(&run_id);
            let manifest: RunManifest = read_bench_record(&dir.join("manifest.json"))?;
            if manifest.schema != RUN_SCHEMA {
                return Err(format!("run {id}: unsupported schema {}", manifest.schema));
            }
            if &manifest.run_id != id {
                return Err(format!(
                    "run {id}: its manifest names run {}",
                    manifest.run_id
                ));
            }
            let state: RunState = read_bench_record(&dir.join("state.json"))?;
            if state.status == RunStatus::Complete {
                return Err(format!("run {id} is already complete"));
            }
            let mut mismatches = manifest.compat.mismatches(&compat);
            // A resumed run mixes new units with recorded ones, so the very
            // same binary on the very same machine must continue it. A
            // verdict has no such requirement.
            let now = provenance(&layout.root, &engine)?;
            if now.binary.hash != manifest.provenance.binary.hash {
                mismatches.push(format!(
                    "binary {} != recorded {}",
                    now.binary.hash, manifest.provenance.binary.hash
                ));
            }
            if now.machine != manifest.provenance.machine {
                mismatches.push("machine identity differs from the recorded one".to_string());
            }
            if !mismatches.is_empty() {
                return Err(format!(
                    "cannot resume {id}: the tree, binary, or machine no longer matches the record: {}",
                    mismatches.join("; ")
                ));
            }
            (run_id, dir, manifest)
        }
        None => {
            let mut selection = request.selection;
            selection.planes.sort();
            selection.planes.dedup();
            if selection.planes.is_empty() {
                return Err("select at least one --group".to_string());
            }
            if (!selection.sources.is_empty() || selection.limit.is_some())
                && !selection.planes.contains(&Plane::Coverage)
            {
                return Err("--source and --limit require --group coverage".into());
            }
            if (!selection.repos.is_empty() || selection.unlock_hidden.is_some())
                && !selection.planes.contains(&Plane::Repositories)
            {
                return Err("--repo and --unlock-hidden require --group repositories".into());
            }
            let provenance = provenance(&layout.root, &engine)?;
            let started_at = utc_now();
            // Timestamp plus pid keeps two runs started in the same second
            // apart; `create_dir` (not `create_dir_all`) refuses an existing
            // directory atomically. The generated form (digits, `T`, `Z`,
            // plane names, `-` and `+`) satisfies `validate_run_id`.
            let run_id = RunId(format!(
                "{}-{}-{}",
                started_at.replace(['-', ':'], ""),
                selection
                    .planes
                    .iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join("+"),
                std::process::id()
            ));
            let runs = layout.runs();
            fs::create_dir_all(&runs).map_err(|e| format!("mkdir {}: {e}", runs.display()))?;
            let dir = layout.run_directory(&run_id);
            fs::create_dir(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
            let manifest = RunManifest {
                schema: RUN_SCHEMA.to_string(),
                run_id: run_id.0.clone(),
                started_at,
                selection,
                compat,
                provenance,
            };
            write_bench_record(&dir.join("manifest.json"), &manifest)?;
            (run_id, dir, manifest)
        }
    };
    let lock = FileLock::acquire(&run_lock_path(&dir))?;
    let state_path = dir.join("state.json");
    let mut state = match request.resume {
        Some(_) => read_bench_record::<RunState>(&state_path)?,
        None => RunState {
            status: RunStatus::Running,
            pid: 0,
            updated_at: String::new(),
            completed_planes: Vec::new(),
            repo_units: 0,
            error: None,
        },
    };
    state.status = RunStatus::Running;
    state.pid = std::process::id();
    state.error = None;
    state.updated_at = utc_now();
    write_bench_record(&state_path, &state)?;
    let result = run_planes(layout, &dir, &manifest, &engine, request.cache, &mut state)
        .and_then(|()| {
            // Inputs edited while the run was measuring would make the
            // record describe a tree that never existed.
            let now = layout.compat(layout.verify_build_matches_tree()?)?;
            let mismatches = manifest.compat.mismatches(&now);
            if mismatches.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "inputs changed during the run: {}",
                    mismatches.join("; ")
                ))
            }
        })
        .and_then(|()| {
            write_bench_record(
                &dir.join("seal.json"),
                &seal(&dir, &manifest.selection.planes)?,
            )
        });
    state.status = match &result {
        Ok(()) => RunStatus::Complete,
        Err(error) => {
            state.error = Some(error.clone());
            RunStatus::Interrupted
        }
    };
    state.updated_at = utc_now();
    write_bench_record(&state_path, &state)?;
    drop(lock);
    result.map(|()| run_id)
}

fn run_planes(
    layout: &BenchLayout,
    dir: &Path,
    manifest: &RunManifest,
    engine: &Arc<Engine>,
    cache: Option<PathBuf>,
    state: &mut RunState,
) -> Result<(), String> {
    let state_path = dir.join("state.json");
    let selection = &manifest.selection;
    for plane in &selection.planes {
        if state.completed_planes.contains(plane) {
            // Damaged evidence must be reported, never silently replaced.
            verify_plane(dir, *plane)?;
            continue;
        }
        eprintln!("plane {}", plane.as_str());
        match plane {
            Plane::Correctness => {
                let board = score_correctness(layout, engine.clone())?;
                write_bench_record(&dir.join("correctness.json"), &board)?;
            }
            Plane::Coverage => {
                let board =
                    score_coverage(layout, engine.clone(), &selection.sources, selection.limit)?;
                write_bench_record(&dir.join("coverage.json"), &board)?;
            }
            Plane::Repositories => {
                let repos_dir = dir.join("repos");
                fs::create_dir_all(&repos_dir)
                    .map_err(|e| format!("mkdir {}: {e}", repos_dir.display()))?;
                // The unlock label of the committed baseline carries forward
                // through locked runs, as before run records existed.
                let scoreboard = layout.scoreboard();
                let previous = scoreboard
                    .exists()
                    .then(|| {
                        fs::read(&scoreboard)
                            .map_err(|e| e.to_string())
                            .and_then(|bytes| {
                                serde_json::from_slice::<Scoreboard>(&bytes)
                                    .map_err(|e| e.to_string())
                            })
                            .map_err(|e| format!("cannot load {}: {e}", scoreboard.display()))
                    })
                    .transpose()?
                    .and_then(|board| board.repos);
                let mut checkpoints = RunCheckpoints {
                    dir: repos_dir,
                    state_path: state_path.clone(),
                    state,
                };
                let section = score_repos(
                    &layout.root.join(REPOS_DIR),
                    &cache_dir(cache.clone()),
                    &selection.repos,
                    selection.unlock_hidden.as_deref(),
                    previous.as_ref(),
                    &mut checkpoints,
                )?;
                write_bench_record(&dir.join("repos.json"), &section)?;
            }
            Plane::Performance => {
                let section = latency::measure_nah(&load_nah(layout)?.0)?;
                write_bench_record(&dir.join("nah-latency.json"), &section)?;
                let section = latency::measure_stress(dir)?;
                write_bench_record(&dir.join("stress.json"), &section)?;
            }
        }
        state.completed_planes.push(*plane);
        state.updated_at = utc_now();
        write_bench_record(&state_path, state)?;
    }
    Ok(())
}
