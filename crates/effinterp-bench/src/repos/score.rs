//! Score the repository plane: check out every selected pinned repository,
//! index each one in an isolated child process (`effinterp-bench repo-child`),
//! score its real entrypoints against the expectation file, and aggregate the
//! rows by language, era, and shape into the scoreboard's `repos` section.
//!
//! Hidden-split rows are never analyzed unless the run is unlocked with a
//! label; an unlocked run records the label and the opened repositories in
//! the section, and later locked runs carry that record forward.
//!
//! Every repository result goes through a [`Checkpoints`] sink as soon as its
//! child exits, and a repository the sink already holds is neither checked
//! out nor analyzed again, so an interrupted run resumes with only the
//! missing repositories.

use effinterp_testkit::checkout::ensure_checkout;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use effinterp_proto::{ExecutionRealm, Modality, display_resource};
use effinterp_repo::{IndexLimits, build_index, effective_surface, effects_of};
use serde::{Deserialize, Serialize};

use super::expectations::{
    EffectFacts, Expectations, Matched, load_expectations, score_expectations,
};
use super::isolate::{IsolateRequest, IsolateStatus, isolate_child_process};
use super::resource_mix;
use crate::invocation::max_rss_kb;
use crate::invocation::score::round4;
use crate::invocation::tiers::{Bucket, bucket_reasons};

pub const REPOS_DIR: &str = "bench/repos";
pub const CHILD_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CHILD_STDOUT: usize = 16 * 1024 * 1024;
const MAX_CHILD_STDERR: usize = 1024 * 1024;
pub const MAX_CHILD_MEMORY: u64 = 4 << 30;
/// Bytes of child stderr kept in a checkpoint.
const STDERR_TAIL: usize = 4096;

/// The pinned repository corpus, `bench/repos/corpus.toml`, as the repository
/// scorer reads it. A measured run's `manifest.json` is `RunManifest`.
#[derive(Debug, Deserialize)]
pub struct RepositoryCorpusManifest {
    pub repo: Vec<ManifestRepo>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestRepo {
    pub name: String,
    pub url: String,
    pub sha: String,
    pub language: String,
    pub shapes: Vec<String>,
    pub era: String,
    pub split: String,
    pub expectations: String,
    #[serde(default)]
    pub real_entries: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct EntryBuckets {
    pub complete: f64,
    pub dynamic: f64,
    pub unobservable: f64,
    pub gap: f64,
}

impl EntryBuckets {
    /// Entrypoints understood as far as the checkout allows. A failed
    /// repository has every share at 0, so this is 0 for it, not `1 - gap`.
    pub fn understood(&self) -> f64 {
        round4(self.complete + self.dynamic + self.unobservable)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMix {
    pub concrete: usize,
    pub symbolic: usize,
    pub unresolved: usize,
}

/// One repository's result. Everything except `wall_ms` and `peak_rss_kb` is
/// deterministic for a fixed checkout and analyzer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoRow {
    pub status: IsolateStatus,
    pub entrypoints: usize,
    pub effects: usize,
    pub diagnostics: Option<CoverageDiagnostics>,
    /// A known real entrypoint was discovered and its surface has an effect.
    pub real_entry_nonempty: bool,
    pub recall: Matched,
    pub facts: Matched,
    pub forbidden_hits: usize,
    /// Tier bucket shares over entrypoints; a failed surface is a gap.
    pub buckets: EntryBuckets,
    pub resource_mix: ResourceMix,
    pub wall_ms: u64,
    pub peak_rss_kb: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageDiagnostics {
    pub skipped_inputs: usize,
    pub failed_entrypoints: usize,
    pub silent_entrypoints: usize,
    pub boundary_reasons: BTreeMap<String, usize>,
}

/// How one repository's child ended: enough to explain a recorded failure
/// without keeping the full capture. The stderr tail is bounded and names the
/// checkout cache as `<cache>` so records stay portable across hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostics {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub stderr_tail: String,
    pub stderr_truncated: bool,
}

/// Where finished repository rows are recorded during a run. `load` returns a
/// row recorded by an earlier attempt; a corrupt record is an error, never a
/// silent rerun.
pub trait Checkpoints {
    fn load(&self, name: &str) -> Result<Option<RepoRow>, String>;
    fn store(&mut self, name: &str, row: &RepoRow, diagnostics: &Diagnostics)
    -> Result<(), String>;
}

/// Record nothing; every repository runs.
pub struct NoCheckpoints;

impl Checkpoints for NoCheckpoints {
    fn load(&self, _name: &str) -> Result<Option<RepoRow>, String> {
        Ok(None)
    }

    fn store(
        &mut self,
        _name: &str,
        _row: &RepoRow,
        _diagnostics: &Diagnostics,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stratum {
    pub repos: usize,
    /// Mean per-repository understood share; a failed repository counts 0.
    pub understood_share: f64,
    /// Mean per-repository complete share; a failed repository counts 0.
    pub complete_share: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unlocked {
    pub label: String,
    pub repos: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReposSection {
    pub corpus_digest: String,
    /// The repositories the run was asked to score, when it was asked for
    /// some of them. Empty means the whole public corpus, so a section is
    /// never read as corpus-wide when it is not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected: Vec<String>,
    pub repos: BTreeMap<String, RepoRow>,
    /// The headline: mean per-repository understood share over `repos`.
    pub understood_share: f64,
    /// `language`, `era`, `shape` -> value -> stratum.
    pub strata: BTreeMap<String, BTreeMap<String, Stratum>>,
    pub unlocked: Option<Unlocked>,
}

/// blake3 over `corpus.toml`, then every expectation file in sorted path order.
pub fn repos_corpus_digest(dir: &Path) -> std::io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&fs::read(dir.join("corpus.toml"))?);
    let mut files = fs::read_dir(dir.join("expectations"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<PathBuf>>>()?;
    files.sort();
    for file in files {
        hasher.update(&fs::read(file)?);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub fn load_manifest(dir: &Path) -> Result<RepositoryCorpusManifest, String> {
    let path = dir.join("corpus.toml");
    fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .and_then(|text| toml::from_str(&text).map_err(|e| e.to_string()))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// `--cache`, else `EI_STRESS_CACHE`, else `/tmp/ei-stress-cache`.
pub fn cache_dir(cache: Option<PathBuf>) -> PathBuf {
    cache
        .or_else(|| std::env::var_os("EI_STRESS_CACHE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/tmp/ei-stress-cache"))
}

/// What the parent sends a `repo-child` on stdin.
#[derive(Serialize, Deserialize)]
struct ChildRequest {
    root: PathBuf,
    real_entries: Vec<String>,
    expectations: Expectations,
}

/// Index one checkout and score it. Runs inside the isolated child.
fn analyze_repo(root: &Path, real_entries: &[String], expectations: &Expectations) -> RepoRow {
    let index = build_index(root, IndexLimits::default());
    let mut ids: Vec<&str> = index
        .entrypoints
        .iter()
        .map(|e| e.entrypoint.id.as_str())
        .collect();
    ids.sort_unstable();
    ids.dedup();

    let mut counts: BTreeMap<Bucket, usize> = BTreeMap::new();
    let mut mix = ResourceMix::default();
    let mut effects = 0;
    let mut diagnostics = CoverageDiagnostics {
        skipped_inputs: index.skipped.len(),
        ..Default::default()
    };
    for id in &ids {
        let Some(surface) = effective_surface(&index, id) else {
            diagnostics.failed_entrypoints += 1;
            *counts.entry(Bucket::Gap).or_default() += 1;
            continue;
        };
        effects += surface.effects.len();
        if surface.effects.is_empty() && surface.boundaries.is_empty() {
            diagnostics.silent_entrypoints += 1;
            *counts.entry(Bucket::Gap).or_default() += 1;
            continue;
        }
        for boundary in &surface.boundaries {
            *diagnostics
                .boundary_reasons
                .entry(boundary.reason.to_string())
                .or_default() += 1;
        }
        for effect in &surface.effects {
            *match resource_mix(&effect.resource) {
                "unresolved" => &mut mix.unresolved,
                "symbolic" => &mut mix.symbolic,
                _ => &mut mix.concrete,
            } += 1;
        }
        let bucket = bucket_reasons(surface.boundaries.iter().map(|b| b.reason.as_str()));
        *counts.entry(bucket).or_default() += 1;
    }
    let share = |bucket| {
        if ids.is_empty() {
            0.0
        } else {
            round4(counts.get(&bucket).copied().unwrap_or(0) as f64 / ids.len() as f64)
        }
    };

    // The product surface: every effect of every discovered real entrypoint.
    let mut product = Vec::new();
    let mut real_entry_nonempty = false;
    for entry in &index.entrypoints {
        if !real_entries.contains(&entry.entrypoint.source_file) {
            continue;
        }
        let Some(report) = effects_of(&index, &entry.entrypoint.id) else {
            continue;
        };
        let found = &report.payload.as_effects().unwrap().effects;
        real_entry_nonempty |= !found.is_empty();
        product.extend(found.iter().map(|effect| {
            EffectFacts {
                operation: effect.operation.0.clone(),
                resource: display_resource(&effect.resource),
                realm: match &effect.realm {
                    ExecutionRealm::Host => "host".to_string(),
                    realm => serde_json::to_string(realm).expect("realm serializes"),
                },
                modality: match effect.modality {
                    Modality::May => "may".to_string(),
                    Modality::MustOnSuccess => "must-on-success".to_string(),
                },
                origin_file: effect
                    .origin
                    .as_ref()
                    .map(|origin| origin.source_file.clone())
                    .unwrap_or_default(),
            }
        }));
    }
    let score = score_expectations(expectations, &product);
    RepoRow {
        status: IsolateStatus::Analyzed,
        entrypoints: ids.len(),
        effects,
        diagnostics: Some(diagnostics),
        real_entry_nonempty,
        recall: score.recall,
        facts: score.facts,
        forbidden_hits: score.forbidden_hits,
        buckets: EntryBuckets {
            complete: share(Bucket::Complete),
            dynamic: share(Bucket::Dynamic),
            unobservable: share(Bucket::Unobservable),
            gap: share(Bucket::Gap),
        },
        resource_mix: mix,
        wall_ms: 0,
        peak_rss_kb: max_rss_kb(),
    }
}

/// Entry point of the hidden `repo-child` subcommand: request on stdin, one
/// `{"status":"analyzed","row":...}` object on stdout.
pub fn child_main() -> std::process::ExitCode {
    let mut stdin = String::new();
    let request: ChildRequest = match std::io::stdin()
        .read_to_string(&mut stdin)
        .map_err(|e| e.to_string())
        .and_then(|_| serde_json::from_str(&stdin).map_err(|e| e.to_string()))
    {
        Ok(request) => request,
        Err(e) => {
            eprintln!("repo-child: bad request: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let row = analyze_repo(&request.root, &request.real_entries, &request.expectations);
    println!(
        "{}",
        serde_json::json!({"status": IsolateStatus::Analyzed.as_str(), "row": row})
    );
    std::process::ExitCode::SUCCESS
}

fn run_child(
    root: PathBuf,
    repo: &ManifestRepo,
    expectations: &Expectations,
    cache: &Path,
) -> (RepoRow, Diagnostics) {
    let binary = std::env::current_exe().expect("current executable path");
    let request = ChildRequest {
        root: root.clone(),
        real_entries: repo.real_entries.clone(),
        expectations: expectations.clone(),
    };
    let envelope = isolate_child_process(IsolateRequest {
        binary,
        args: vec!["repo-child".to_string()],
        stdin: serde_json::to_vec(&request).expect("child request serializes"),
        timeout: CHILD_TIMEOUT,
        max_stdout: MAX_CHILD_STDOUT,
        max_stderr: MAX_CHILD_STDERR,
        cache_path: root,
        extra_env: Vec::new(),
        max_memory_bytes: Some(MAX_CHILD_MEMORY),
    });
    let parsed = envelope
        .payload
        .as_ref()
        .and_then(|payload| payload.get("row"))
        .and_then(|row| serde_json::from_value::<RepoRow>(row.clone()).ok());
    let mut row = match (envelope.status, parsed) {
        (IsolateStatus::Analyzed, Some(row)) => row,
        (status, _) => {
            let status = if status == IsolateStatus::Analyzed {
                IsolateStatus::InvalidPlan
            } else {
                status
            };
            eprintln!(
                "  {}: exit={:?} signal={:?} {}",
                status.as_str(),
                envelope.process.exit_code,
                envelope.process.signal,
                envelope.process.stderr.lines().last().unwrap_or("")
            );
            RepoRow {
                status,
                entrypoints: 0,
                effects: 0,
                diagnostics: None,
                real_entry_nonempty: false,
                recall: Matched {
                    matched: 0,
                    total: expectations.should_find.len(),
                },
                facts: Matched {
                    matched: 0,
                    total: expectations.facts.len(),
                },
                forbidden_hits: 0,
                buckets: EntryBuckets::default(),
                resource_mix: ResourceMix::default(),
                wall_ms: 0,
                peak_rss_kb: 0,
            }
        }
    };
    row.wall_ms = envelope.elapsed_ms;
    let stderr = &envelope.process.stderr;
    let start = stderr.len().saturating_sub(STDERR_TAIL);
    let start = (start..stderr.len())
        .find(|&i| stderr.is_char_boundary(i))
        .unwrap_or(stderr.len());
    let diagnostics = Diagnostics {
        exit_code: envelope.process.exit_code,
        signal: envelope.process.signal,
        timed_out: envelope.process.timed_out,
        stderr_tail: stderr[start..].replace(&cache.display().to_string(), "<cache>"),
        stderr_truncated: envelope.process.stderr_truncated || start > 0,
    };
    (row, diagnostics)
}

/// Score the selected repositories (`only` empty = the whole corpus). Every
/// checkout happens before any analysis, so a network failure is an
/// operational error rather than a half-scored section. Repositories already
/// held by `checkpoints` are reused without a checkout.
pub fn score_repos(
    dir: &Path,
    cache: &Path,
    only: &[String],
    unlock_hidden: Option<&str>,
    previous: Option<&ReposSection>,
    checkpoints: &mut dyn Checkpoints,
) -> Result<ReposSection, String> {
    let manifest = load_manifest(dir)?;
    let corpus_digest =
        repos_corpus_digest(dir).map_err(|e| format!("cannot digest {}: {e}", dir.display()))?;
    if unlock_hidden.is_some() && !only.is_empty() {
        return Err("--unlock-hidden needs a full run so the unlock is recorded".to_string());
    }
    for name in only {
        let repo = manifest
            .repo
            .iter()
            .find(|repo| &repo.name == name)
            .ok_or_else(|| format!("no repository named {name:?} in the corpus"))?;
        if repo.split == "hidden" {
            return Err(format!(
                "{name} is in the hidden split; it opens only on a full run with --unlock-hidden"
            ));
        }
    }
    let selected: Vec<&ManifestRepo> = manifest
        .repo
        .iter()
        .filter(|repo| only.is_empty() || only.contains(&repo.name))
        .filter(|repo| repo.split != "hidden" || unlock_hidden.is_some())
        .collect();
    let mut rows = BTreeMap::new();
    let mut work = Vec::new();
    for repo in &selected {
        if let Some(row) = checkpoints.load(&repo.name)? {
            eprintln!("recorded {}", repo.name);
            rows.insert(repo.name.clone(), row);
            continue;
        }
        let expectations = load_expectations(&repo.expectations)?;
        eprintln!("checkout {} @ {}", repo.name, &repo.sha[..7]);
        let root = ensure_checkout(&repo.name, &repo.url, &repo.sha, cache)
            .map_err(|e| format!("{}: {e}", repo.name))?;
        work.push((*repo, root, expectations));
    }

    for (repo, root, expectations) in work {
        eprintln!("analyze {}", repo.name);
        let (row, diagnostics) = run_child(root, repo, &expectations, cache);
        checkpoints.store(&repo.name, &row, &diagnostics)?;
        rows.insert(repo.name.clone(), row);
    }
    let strata = strata(&selected, &rows);
    let understood_share = mean_understood(&rows);
    let unlocked = match unlock_hidden {
        Some(label) => Some(Unlocked {
            label: label.to_string(),
            repos: selected
                .iter()
                .filter(|repo| repo.split == "hidden")
                .map(|repo| repo.name.clone())
                .collect(),
        }),
        None => previous.and_then(|section| section.unlocked.clone()),
    };
    let mut selected_names = only.to_vec();
    selected_names.sort();
    Ok(ReposSection {
        corpus_digest,
        selected: selected_names,
        repos: rows,
        understood_share,
        strata,
        unlocked,
    })
}

fn mean_understood(rows: &BTreeMap<String, RepoRow>) -> f64 {
    if rows.is_empty() {
        return 0.0;
    }
    round4(
        rows.values()
            .map(|row| row.buckets.understood())
            .sum::<f64>()
            / rows.len() as f64,
    )
}

#[derive(Default)]
struct Tally {
    repos: usize,
    understood: f64,
    complete: f64,
}

fn strata(
    repos: &[&ManifestRepo],
    rows: &BTreeMap<String, RepoRow>,
) -> BTreeMap<String, BTreeMap<String, Stratum>> {
    let mut acc: BTreeMap<&str, BTreeMap<&str, Tally>> = BTreeMap::new();
    for repo in repos {
        let row = &rows[&repo.name];
        let axes = [
            ("language", std::slice::from_ref(&repo.language)),
            ("era", std::slice::from_ref(&repo.era)),
            ("shape", repo.shapes.as_slice()),
        ];
        for (axis, values) in axes {
            for value in values {
                let tally = acc.entry(axis).or_default().entry(value).or_default();
                tally.repos += 1;
                tally.understood += row.buckets.understood();
                tally.complete += row.buckets.complete;
            }
        }
    }
    acc.into_iter()
        .map(|(axis, values)| {
            let values = values
                .into_iter()
                .map(|(value, t)| {
                    let stratum = Stratum {
                        repos: t.repos,
                        understood_share: round4(t.understood / t.repos as f64),
                        complete_share: round4(t.complete / t.repos as f64),
                    };
                    (value.to_string(), stratum)
                })
                .collect();
            (axis.to_string(), values)
        })
        .collect()
}

fn pct(share: f64) -> String {
    format!("{:.2}%", share * 100.0)
}

/// `measured` is the section's provenance line, rendered by the scoreboard.
pub fn render_repository_coverage_markdown(section: &ReposSection, measured: &str) -> String {
    let mut md = String::new();
    md.push_str("## 3. Repository coverage\n\n");
    md.push_str(measured);
    let _ = writeln!(
        md,
        "Reported completeness over entrypoints; not a whole-repository accuracy score.\n\ncorpus `{}`\n",
        section.corpus_digest
    );
    if !section.selected.is_empty() {
        let _ = writeln!(
            md,
            "bounded run: {} of the corpus's repositories were scored — {}\n",
            section.selected.len(),
            section.selected.join(", ")
        );
    }
    if let Some(unlocked) = &section.unlocked {
        let _ = writeln!(
            md,
            "hidden split unlocked as `{}`: {}\n",
            unlocked.label,
            unlocked.repos.join(", ")
        );
    }
    let _ = writeln!(
        md,
        "**understood what it could: {}** (mean over {} repositories)\n",
        pct(section.understood_share),
        section.repos.len()
    );
    let _ = writeln!(
        md,
        "| stratum | value | repos | understood | complete |\n|---|---|---|---|---|"
    );
    for (axis, values) in &section.strata {
        for (value, s) in values {
            let _ = writeln!(
                md,
                "| {axis} | {value} | {} | {} | {} |",
                s.repos,
                pct(s.understood_share),
                pct(s.complete_share)
            );
        }
    }
    let _ = writeln!(
        md,
        "\n| repo | status | entrypoints | effects | real entry | understood | complete | dynamic | unobservable | gap | concrete/symbolic/unresolved | wall ms | peak RSS MB |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|"
    );
    for (name, r) in &section.repos {
        let _ = writeln!(
            md,
            "| {name} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {}/{}/{} | {} | {:.1} |",
            r.status.as_str(),
            r.entrypoints,
            r.effects,
            if r.real_entry_nonempty { "yes" } else { "no" },
            pct(r.buckets.understood()),
            pct(r.buckets.complete),
            pct(r.buckets.dynamic),
            pct(r.buckets.unobservable),
            pct(r.buckets.gap),
            r.resource_mix.concrete,
            r.resource_mix.symbolic,
            r.resource_mix.unresolved,
            r.wall_ms,
            r.peak_rss_kb as f64 / 1024.0
        );
    }
    md.push_str("\n| repo | skipped inputs | failed entrypoints | silent entrypoints |\n|---|---|---|---|\n");
    for (name, row) in &section.repos {
        if let Some(d) = &row.diagnostics {
            let _ = writeln!(
                md,
                "| {name} | {} | {} | {} |",
                d.skipped_inputs, d.failed_entrypoints, d.silent_entrypoints
            );
        }
    }
    // Repositories whose run recorded no diagnostics are named once instead
    // of filling the table with rows that carry no measurement.
    let undiagnosed: Vec<&str> = section
        .repos
        .iter()
        .filter(|(_, row)| row.diagnostics.is_none())
        .map(|(name, _)| name.as_str())
        .collect();
    if !undiagnosed.is_empty() {
        let _ = writeln!(
            md,
            "\n{} repositories without recorded diagnostics: {}",
            undiagnosed.len(),
            undiagnosed.join(", ")
        );
    }
    md.push_str("\n| repo | boundary reason | count |\n|---|---|---|\n");
    for (name, row) in &section.repos {
        if let Some(d) = &row.diagnostics {
            for (reason, count) in &d.boundary_reasons {
                let _ = writeln!(md, "| {name} | {reason} | {count} |");
            }
        }
    }
    md.push('\n');
    md
}
