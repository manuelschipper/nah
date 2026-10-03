//! Run verdicts over a recorded run and publication of an eligible one.
//!
//! A verdict reads only the record, the baseline scoreboard, and the ceilings:
//! no engine, child, network, or original binary is needed, so any complete
//! record stays checkable after the tree moves on. Three questions are
//! answered separately: did the rules pass against this baseline
//! (historical), does the record still describe the current tree
//! (compatibility), and may it become the baseline (eligibility). Every
//! verdict is stored under a key over all of its inputs and is recomputed on
//! every call; a stored verdict is evidence, never a shortcut.

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use effinterp_proto::content_digest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{
    BenchLayout, FileLock, Plane, PlaneProvenance, RUN_SCHEMA, RepoUnit, RunCompat, RunManifest,
    RunSeal, RunState, RunStatus, read_bench_record, record_files, repo_unit_name, run_lock_path,
    utc_now, validate_run_id, write_bench_record,
};
use crate::bench::gate::{self, RULES_VERSION, RuleResult};
use crate::bench::score::{self, Scoreboard};
use crate::latency::LatencySection;
use crate::nah::report::{Ceilings, write_ratchet_ceilings};
use crate::repos::score::ReposSection;

pub const VERDICT_SCHEMA: &str = "effinterp/bench-verdict/v2";

/// A complete, internally consistent run read from disk.
pub struct LoadedRun {
    pub dir: PathBuf,
    pub manifest: RunManifest,
    pub state: RunState,
    pub coverage: Option<Scoreboard>,
    pub correctness: Option<Scoreboard>,
    pub repos: Option<ReposSection>,
    pub nah_latency: Option<LatencySection>,
    pub stress: Option<LatencySection>,
    /// Content hash of the seal: every measurement file's byte hash.
    pub measurements_hash: String,
}

impl LoadedRun {
    pub fn planes(&self) -> &[Plane] {
        &self.manifest.selection.planes
    }
}

/// Read a run and refuse anything that is not a complete, consistent, sealed
/// record: every file must hash as the seal recorded it, every unit must
/// verify its own content hash, and the aggregates must agree with their
/// units.
pub fn load_recorded_run(layout: &BenchLayout, id: &str) -> Result<LoadedRun, String> {
    let run_id = validate_run_id(id)?;
    let dir = layout.run_directory(&run_id);
    let manifest: RunManifest = read_bench_record(&dir.join("manifest.json"))?;
    if manifest.schema != RUN_SCHEMA {
        return Err(format!(
            "run {id}: unsupported schema {}; this bench reads {RUN_SCHEMA}",
            manifest.schema
        ));
    }
    if manifest.run_id != id {
        return Err(format!(
            "run {id}: its manifest names run {}",
            manifest.run_id
        ));
    }
    let state: RunState = read_bench_record(&dir.join("state.json"))?;
    if state.status != RunStatus::Complete {
        let status =
            if state.status == RunStatus::Running && !FileLock::is_held(&run_lock_path(&dir)) {
                "interrupted (no process holds its lock)"
            } else {
                state.status.as_str()
            };
        return Err(format!(
            "run {id} is {status}: {} plane(s) and {} repository unit(s) recorded{}; resume it with `measure --resume {id}`",
            state.completed_planes.len(),
            state.repo_units,
            state
                .error
                .as_ref()
                .map(|e| format!(", last error: {e}"))
                .unwrap_or_default()
        ));
    }
    let seal_path = dir.join("seal.json");
    let seal: RunSeal = read_bench_record(&seal_path)?;
    let files = record_files(&dir, &manifest.selection.planes)?;
    let mut sealed: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for path in &files {
        let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let relative = path.strip_prefix(&dir).unwrap_or(path);
        sealed.insert(
            relative.to_string_lossy().into_owned(),
            content_digest(&bytes),
        );
    }
    if sealed != seal.files {
        let mut differing: Vec<&String> = seal
            .files
            .iter()
            .filter(|(path, hash)| sealed.get(*path) != Some(hash))
            .map(|(path, _)| path)
            .chain(sealed.keys().filter(|path| !seal.files.contains_key(*path)))
            .collect();
        differing.sort();
        differing.dedup();
        return Err(format!(
            "run {id}: record does not match its seal: {}",
            differing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let measurements_hash =
        super::content_hash(&serde_json::to_value(&seal).expect("seal serializes"));
    let mut run = LoadedRun {
        dir: dir.clone(),
        manifest,
        state,
        coverage: None,
        correctness: None,
        repos: None,
        nah_latency: None,
        stress: None,
        measurements_hash,
    };
    for plane in run.manifest.selection.planes.clone() {
        if !run.state.completed_planes.contains(&plane) {
            return Err(format!(
                "run {id}: plane {} is selected but not recorded as complete",
                plane.as_str()
            ));
        }
        match plane {
            Plane::Correctness => {
                run.correctness = Some(read_bench_record(&dir.join("correctness.json"))?);
            }
            Plane::Coverage => {
                run.coverage = Some(read_bench_record(&dir.join("coverage.json"))?);
            }
            Plane::Repositories => {
                let section: ReposSection = read_bench_record(&dir.join("repos.json"))?;
                let unit_files = files
                    .iter()
                    .filter(|path| path.parent() == Some(dir.join("repos").as_path()))
                    .count();
                if unit_files != section.repos.len() {
                    return Err(format!(
                        "run {id}: repos.json has {} rows but {unit_files} repository units are recorded",
                        section.repos.len()
                    ));
                }
                for (name, row) in &section.repos {
                    let path = dir.join("repos").join(repo_unit_name(name));
                    let recorded: RepoUnit = read_bench_record(&path)?;
                    if &recorded.row != row {
                        return Err(format!(
                            "run {id}: {} disagrees with repos.json for {name}",
                            path.display()
                        ));
                    }
                }
                run.repos = Some(section);
            }
            Plane::Performance => {
                run.nah_latency = Some(read_bench_record(&dir.join("nah-latency.json"))?);
                run.stress = Some(read_bench_record(&dir.join("stress.json"))?);
                if !files
                    .iter()
                    .any(|path| path.starts_with(dir.join("stress")))
                {
                    return Err(format!("run {id}: stress.json has no units under stress/"));
                }
            }
        }
    }
    Ok(run)
}

fn clone_json<T: Serialize + DeserializeOwned>(value: &T) -> T {
    serde_json::from_value(serde_json::to_value(value).expect("record serializes"))
        .expect("record round-trips")
}

/// The baseline with the run's measured planes replaced; nothing is invented
/// for a plane the run did not measure.
pub fn compose_scoreboard(
    baseline: Option<&Scoreboard>,
    run: &LoadedRun,
) -> Result<Scoreboard, String> {
    let mut board = match baseline {
        Some(baseline) => clone_json(baseline),
        None => Scoreboard {
            schema: score::SCOREBOARD_SCHEMA.into(),
            correctness: Default::default(),
            coverage: Default::default(),
            repos: None,
            performance: Default::default(),
            provenance: Default::default(),
        },
    };
    let manifest = &run.manifest;
    let provenance = PlaneProvenance {
        run_id: manifest.run_id.clone(),
        measured_at: manifest.started_at.clone(),
        source_fingerprint: manifest.compat.source_fingerprint.clone(),
        binary_hash: manifest.provenance.binary.hash.clone(),
        engine_version: manifest.provenance.engine_version.clone(),
        model_set: manifest.provenance.model_set.clone(),
        git_head: manifest.provenance.git_head.clone(),
        machine: manifest.provenance.machine.clone(),
    };
    for plane in run.planes() {
        match plane {
            Plane::Coverage => {
                let invocation = run.coverage.as_ref().expect("loaded");
                board.coverage.corpus_digest = invocation.coverage.corpus_digest.clone();
                board.coverage.sources = clone_json(&invocation.coverage.sources);
                board
                    .performance
                    .host
                    .retain(|source, _| source == "adversarial");
                board
                    .performance
                    .host
                    .extend(clone_json(&invocation.performance.host));
            }
            Plane::Correctness => {
                let measured = run.correctness.as_ref().expect("loaded");
                board.correctness.corpus_digest = measured.correctness.corpus_digest.clone();
                board.correctness.semantic = clone_json(&measured.correctness.semantic);
                board.correctness.parity = clone_json(&measured.correctness.parity);
                board.correctness.adversarial = clone_json(&measured.correctness.adversarial);
                board
                    .performance
                    .host
                    .extend(clone_json(&measured.performance.host));
            }
            Plane::Repositories => board.repos = run.repos.clone(),
            Plane::Performance => {
                let measured = run.nah_latency.as_ref().expect("loaded");
                let latency = board
                    .performance
                    .latency
                    .get_or_insert_with(LatencySection::default);
                latency.machine = measured.machine.clone();
                latency.nah_p99_us = measured.nah_p99_us;
                latency.cold_start = measured.cold_start.clone();
                let measured = run.stress.as_ref().expect("loaded");
                let latency = board
                    .performance
                    .latency
                    .get_or_insert_with(LatencySection::default);
                latency.machine = measured.machine.clone();
                latency.engine = measured.engine.clone();
                latency.omitted = measured.omitted.clone();
            }
        }
        board
            .provenance
            .insert(plane.as_str().to_string(), provenance.clone());
    }
    Ok(board)
}

/// Measured planes whose corpus the baseline does not carry. Their
/// baseline-relative rules have nothing to compare against and are skipped,
/// while every absolute rule still applies, and every plane of an unchanged
/// scope keeps all of its rules. Publication requires an explicit rebaseline.
fn new_scope(baseline: Option<&Scoreboard>, run: &LoadedRun) -> Vec<Plane> {
    let Some(baseline) = baseline else {
        return run.planes().to_vec();
    };
    let mut out = Vec::new();
    if let Some(invocation) = &run.coverage
        && baseline.coverage.corpus_digest != invocation.coverage.corpus_digest
    {
        out.push(Plane::Coverage);
    }
    if let Some(correctness) = &run.correctness {
        let parity = |board: &Scoreboard| {
            board
                .correctness
                .parity
                .as_ref()
                .map(|p| p.corpus_digest.clone())
        };
        if baseline.correctness.semantic.is_none()
            || parity(baseline) != parity(correctness)
            || baseline.correctness.corpus_digest != correctness.correctness.corpus_digest
        {
            out.push(Plane::Correctness);
        }
    }
    if let Some(repos) = &run.repos
        && baseline
            .repos
            .as_ref()
            .is_none_or(|base| base.corpus_digest != repos.corpus_digest)
    {
        out.push(Plane::Repositories);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inputs {
    pub measurements: String,
    pub baseline: Option<String>,
    pub ceilings: String,
    pub rules: String,
    /// Identity of the tree and binary computing the verdict; eligibility depends
    /// on it, so it is part of the key.
    pub current: RunCompat,
    pub checker_built_from: String,
    pub rebaseline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOutcome {
    pub rule: String,
    pub failures: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Historical {
    pub new_scope: Vec<Plane>,
    pub rules: Vec<RuleOutcome>,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Compatibility {
    /// The binary computing the verdict was built from the tree it runs in.
    pub build_matches_tree: bool,
    pub mismatches: Vec<String>,
    pub compatible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunVerdict {
    pub schema: String,
    pub run_id: String,
    pub computed_at: String,
    pub inputs: Inputs,
    pub partial: bool,
    pub historical: Historical,
    pub compatibility: Compatibility,
    pub eligible: bool,
    pub blockers: Vec<String>,
}

/// Every engine case the configuration declares must be accounted for in the
/// record: either it has a summary, or the record names it and says why it
/// has none. A case in neither map means the stress plane recorded less than
/// it measured, and that record must not become the baseline.
fn unaccounted_stress(stress: &LatencySection, compat: &RunCompat) -> Vec<String> {
    let mut out = Vec::new();
    let cases = compat.config.latency["engine"]["cases"]
        .as_u64()
        .unwrap_or(0) as usize;
    let accounted = stress.engine.len() + stress.omitted.len();
    if accounted < cases {
        out.push(format!(
            "stress: {accounted} of {cases} engine cases are accounted for; the rest are missing from the record"
        ));
    }
    out
}

pub struct Evaluation {
    pub verdict: RunVerdict,
    pub verdict_path: PathBuf,
    pub composed: Scoreboard,
    pub ceilings: Ceilings,
    /// Exact bytes the baseline had when read, for the publication race check.
    pub baseline_bytes: Option<Vec<u8>>,
}

/// Compute and store the verdict of `run` against the tracked baseline.
pub fn evaluate_run_verdict(
    layout: &BenchLayout,
    run: &LoadedRun,
    rebaseline: bool,
) -> Result<Evaluation, String> {
    let baseline_path = layout.scoreboard();
    let baseline_bytes = baseline_path
        .exists()
        .then(|| fs::read(&baseline_path))
        .transpose()
        .map_err(|e| format!("cannot read {}: {e}", baseline_path.display()))?;
    let baseline: Option<Scoreboard> = baseline_bytes
        .as_deref()
        .map(|bytes| {
            serde_json::from_slice(bytes)
                .map_err(|e| format!("cannot load {}: {e}", baseline_path.display()))
        })
        .transpose()?;
    let ceilings_bytes = fs::read(layout.ceilings())
        .map_err(|e| format!("cannot read {}: {e}", layout.ceilings().display()))?;
    let ceilings: Ceilings = serde_json::from_slice(&ceilings_bytes)
        .map_err(|e| format!("cannot load {}: {e}", layout.ceilings().display()))?;

    let composed = compose_scoreboard(baseline.as_ref(), run)?;
    let new_scope = new_scope(baseline.as_ref(), run);
    let results = gate::check_gate_rules(
        baseline.as_ref().unwrap_or(&composed),
        &composed,
        &ceilings,
        run.planes(),
        &new_scope,
    );
    let rules: Vec<RuleOutcome> = results
        .iter()
        .map(|r: &RuleResult| RuleOutcome {
            rule: r.rule.to_string(),
            failures: r.failures.clone(),
            skipped: r.skipped.map(str::to_string),
        })
        .collect();
    let passed = gate::gate_rules_passed(&results);

    let current_source = layout.source_fingerprint()?;
    let current = layout.compat(current_source.clone())?;
    let mismatches = run.manifest.compat.mismatches(&current);
    let compatibility = Compatibility {
        build_matches_tree: current_source == layout.built_from,
        compatible: mismatches.is_empty(),
        mismatches,
    };

    let partial = run.manifest.selection.partial();
    let mut blockers = Vec::new();
    let binary = &run.manifest.provenance.binary;
    if binary.size == 0
        || !binary
            .hash
            .strip_prefix("blake3:")
            .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        blockers.push("recorded binary identity is missing or invalid".to_string());
    }
    if partial {
        blockers.push("partial selection: the run scored only part of a plane".to_string());
    }
    if let Some(stress) = &run.stress {
        blockers.extend(unaccounted_stress(stress, &run.manifest.compat));
    }
    if !passed {
        blockers.push("rule failures".to_string());
    }
    if !rebaseline {
        for plane in &new_scope {
            let (baseline_digest, run_digest) = match plane {
                Plane::Coverage => (
                    baseline
                        .as_ref()
                        .map(|board| board.coverage.corpus_digest.clone())
                        .unwrap_or_else(|| "<none>".to_string()),
                    run.coverage
                        .as_ref()
                        .expect("new coverage scope was measured")
                        .coverage
                        .corpus_digest
                        .clone(),
                ),
                Plane::Correctness => (
                    baseline
                        .as_ref()
                        .map(|board| {
                            format!(
                                "{} (parity {})",
                                board.correctness.corpus_digest,
                                board
                                    .correctness
                                    .parity
                                    .as_ref()
                                    .map_or("<none>", |parity| parity.corpus_digest.as_str())
                            )
                        })
                        .unwrap_or_else(|| "<none>".to_string()),
                    run.correctness
                        .as_ref()
                        .map(|board| {
                            format!(
                                "{} (parity {})",
                                board.correctness.corpus_digest,
                                board
                                    .correctness
                                    .parity
                                    .as_ref()
                                    .map_or("<none>", |parity| parity.corpus_digest.as_str())
                            )
                        })
                        .expect("new correctness scope was measured"),
                ),
                Plane::Repositories => (
                    baseline
                        .as_ref()
                        .and_then(|board| board.repos.as_ref())
                        .map(|repos| repos.corpus_digest.clone())
                        .unwrap_or_else(|| "<none>".to_string()),
                    run.repos
                        .as_ref()
                        .expect("new repository scope was measured")
                        .corpus_digest
                        .clone(),
                ),
                Plane::Performance => ("<none>".to_string(), "<not corpus-scoped>".to_string()),
            };
            blockers.push(format!(
                "{} scope has no comparable baseline: baseline digest {baseline_digest}, run digest {run_digest}; pass `--rebaseline` to acknowledge its skipped drift rules and establish this run as the new baseline",
                plane.as_str()
            ));
        }
    }
    if !compatibility.build_matches_tree {
        blockers.push("this binary was not built from the current tree".to_string());
    }
    blockers.extend(
        compatibility
            .mismatches
            .iter()
            .map(|m| format!("stale: {m}")),
    );
    let inputs = Inputs {
        measurements: run.measurements_hash.clone(),
        baseline: baseline_bytes.as_deref().map(content_digest),
        ceilings: content_digest(&ceilings_bytes),
        rules: RULES_VERSION.to_string(),
        current,
        checker_built_from: layout.built_from.clone(),
        rebaseline,
    };
    let verdict = RunVerdict {
        schema: VERDICT_SCHEMA.to_string(),
        run_id: run.manifest.run_id.clone(),
        computed_at: utc_now(),
        inputs,
        partial,
        historical: Historical {
            new_scope,
            rules,
            passed,
        },
        compatibility,
        eligible: blockers.is_empty(),
        blockers,
    };
    let key = blake3::hash(
        serde_json::to_vec(&verdict.inputs)
            .expect("inputs serialize")
            .as_slice(),
    )
    .to_hex();
    let verdicts = run.dir.join("verdicts");
    fs::create_dir_all(&verdicts).map_err(|e| format!("mkdir {}: {e}", verdicts.display()))?;
    let verdict_path = verdicts.join(format!("{}.json", &key[..16]));
    write_bench_record(&verdict_path, &verdict)?;
    Ok(Evaluation {
        verdict,
        verdict_path,
        composed,
        ceilings,
        baseline_bytes,
    })
}

/// Make `run` the baseline. Every verdict input is read before any baseline byte is
/// touched. Publication then renames ceilings, markdown, and the scoreboard
/// json last, each staged file and its directory fsynced: the json is the
/// commit point, so a crash before it leaves the old baseline intact and the
/// same publication can simply run again, and ceilings only ever ratchet
/// down, so a renamed ceilings file never blocks that retry.
pub fn publish_run(layout: &BenchLayout, id: &str, rebaseline: bool) -> Result<Evaluation, String> {
    layout.verify_build_matches_tree()?;
    fs::create_dir_all(layout.runs())
        .map_err(|e| format!("mkdir {}: {e}", layout.runs().display()))?;
    // One publication at a time: evaluation, staging, and the renames all
    // happen under this lock, so two publications cannot interleave.
    let _publish = FileLock::acquire(&layout.runs().join("publish.lock"))?;
    let run = load_recorded_run(layout, id)?;
    let mut evaluation = evaluate_run_verdict(layout, &run, rebaseline)?;
    if !evaluation.verdict.eligible {
        return Err(format!(
            "run {id} is not eligible: {} (verdict {})",
            evaluation.verdict.blockers.join("; "),
            evaluation.verdict_path.display()
        ));
    }
    let scoreboard = layout.scoreboard();
    let pid = std::process::id();
    let staged = |path: &Path| {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("staged");
        path.with_file_name(format!(".{name}.{pid}.tmp"))
    };
    let mut renames: Vec<(PathBuf, PathBuf)> = Vec::new();
    if run.planes().contains(&Plane::Correctness) {
        let tmp = staged(&layout.ceilings());
        let parity = evaluation
            .composed
            .correctness
            .parity
            .as_ref()
            .ok_or("a full invocation run has a parity section")?;
        write_ratchet_ceilings(&tmp, parity, &mut evaluation.ceilings)
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        renames.push((tmp, layout.ceilings()));
    }
    let tmp_md = staged(&layout.scoreboard_md());
    fs::write(
        &tmp_md,
        score::render_scoreboard_markdown(&evaluation.composed),
    )
    .map_err(|e| format!("cannot write {}: {e}", tmp_md.display()))?;
    renames.push((tmp_md, layout.scoreboard_md()));
    let tmp_json = staged(&scoreboard);
    fs::write(&tmp_json, score::to_json(&evaluation.composed))
        .map_err(|e| format!("cannot write {}: {e}", tmp_json.display()))?;
    renames.push((tmp_json, scoreboard.clone()));
    let publish = || -> Result<(), String> {
        for (tmp, _) in &renames {
            File::open(tmp)
                .and_then(|f| f.sync_all())
                .map_err(|e| format!("cannot sync {}: {e}", tmp.display()))?;
        }
        let now = scoreboard
            .exists()
            .then(|| fs::read(&scoreboard))
            .transpose()
            .map_err(|e| format!("cannot re-read {}: {e}", scoreboard.display()))?;
        if now != evaluation.baseline_bytes {
            return Err(format!(
                "{} changed while run {id} was being published; publish it again",
                scoreboard.display()
            ));
        }
        let ceilings_now = fs::read(layout.ceilings()).map_err(|e| e.to_string())?;
        if content_digest(&ceilings_now) != evaluation.verdict.inputs.ceilings {
            return Err("ceilings changed during publication; publish the run again".to_string());
        }
        for (tmp, target) in &renames {
            fs::rename(tmp, target)
                .and_then(|()| File::open(target.parent().unwrap_or(Path::new(".")))?.sync_all())
                .map_err(|e| format!("cannot publish {}: {e}", target.display()))?;
        }
        Ok(())
    };
    if let Err(e) = publish() {
        for (tmp, _) in &renames {
            let _ = fs::remove_file(tmp);
        }
        return Err(e);
    }
    Ok(evaluation)
}

/// One line per rule for the terminal.
pub fn render_run_verdict(verdict: &RunVerdict) -> String {
    let mut out = String::new();
    for rule in &verdict.historical.rules {
        let mark = match (&rule.skipped, rule.failures.is_empty()) {
            (Some(_), _) => "skip",
            (None, true) => "ok  ",
            (None, false) => "FAIL",
        };
        out.push_str(&format!("{mark} {}", rule.rule));
        if let Some(why) = &rule.skipped {
            out.push_str(&format!(" ({why})"));
        }
        out.push('\n');
        for failure in &rule.failures {
            out.push_str(&format!("      {failure}\n"));
        }
    }
    if !verdict.historical.new_scope.is_empty() {
        out.push_str(&format!(
            "new scope: {}{}\n",
            verdict
                .historical
                .new_scope
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            if verdict.inputs.rebaseline {
                " (skipped drift rules acknowledged by --rebaseline)"
            } else {
                ""
            }
        ));
    }
    out.push_str(&format!(
        "historical: {}\ncompatible: {}\n",
        if verdict.historical.passed {
            "passed"
        } else {
            "failed"
        },
        if verdict.compatibility.compatible && verdict.compatibility.build_matches_tree {
            "yes".to_string()
        } else {
            let mut why = verdict.compatibility.mismatches.clone();
            if !verdict.compatibility.build_matches_tree {
                why.push("verdict binary not built from this tree".to_string());
            }
            format!("no ({})", why.join("; "))
        }
    ));
    out.push_str(&format!(
        "eligible: {}\n",
        if verdict.eligible {
            "yes".to_string()
        } else {
            format!("no ({})", verdict.blockers.join("; "))
        }
    ));
    out
}
