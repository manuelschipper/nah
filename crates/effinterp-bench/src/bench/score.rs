//! Scoreboard metrics (schema `effinterp/bench-scoreboard/v4`) and their
//! markdown rendering. Everything except `host` is deterministic: maps are
//! ordered, shares are rounded to four decimals, ties break by name.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;

use effinterp_proto::{
    Boundary, BoundaryClass, CoverageLevel, Plan, ProvenanceKind, ProvenanceRef, Subject,
};
use serde::{Deserialize, Serialize};

use super::corpus::BenchRow;
use super::judge::{Verdict, judge_plan};
use super::tiers::{Bucket, Tier, bucket_of, bucket_reasons};
use super::{Analyzed, FailureKind, MutationSummary, Outcome};
use crate::latency::LatencySection;
use crate::nah::classify::ParityClass;
use crate::nah::mutate::MutationMeasurement;
use crate::nah::report::Parity;
use crate::repos::score::ReposSection;
use crate::run::{Plane, PlaneProvenance};

pub const SCOREBOARD_SCHEMA: &str = "effinterp/bench-scoreboard/v4";
const TOP_REASONS: usize = 30;
const TOP_UNMODELED: usize = 40;
const TOP_GAP_COMMANDS: usize = 5;

/// Every plane owns its own scope and identity: the engine version, model
/// set and corpus digest a section was measured under live in that section
/// and in its `provenance` entry, never in one board-wide field that
/// whichever plane published last would overwrite.
#[derive(Debug, Serialize, Deserialize)]
pub struct Scoreboard {
    pub schema: String,
    pub correctness: Correctness,
    pub coverage: Invocation,
    pub repos: Option<ReposSection>,
    pub performance: Performance,
    /// Which recorded run each plane was published from, keyed by plane name.
    /// A plane absent here predates run records; nothing is invented for it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provenance: BTreeMap<String, PlaneProvenance>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Invocation {
    /// Digest of the invocation corpora this plane was scored over.
    pub corpus_digest: String,
    #[serde(flatten)]
    pub sources: BTreeMap<String, SourceScore>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Correctness {
    pub corpus_digest: String,
    pub semantic: Option<crate::layered::SemanticScore>,
    pub adversarial: Option<AdversarialScore>,
    pub parity: Option<Parity>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Performance {
    pub latency: Option<LatencySection>,
    pub host: BTreeMap<String, HostStats>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Share {
    pub unique: usize,
    pub weighted_share: f64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Buckets {
    pub complete: Share,
    pub dynamic: Share,
    pub unobservable: Share,
    pub gap: Share,
}

impl Buckets {
    pub fn get(&self, bucket: Bucket) -> Share {
        match bucket {
            Bucket::Complete => self.complete,
            Bucket::Dynamic => self.dynamic,
            Bucket::Unobservable => self.unobservable,
            Bucket::Gap => self.gap,
        }
    }

    fn get_mut(&mut self, bucket: Bucket) -> &mut Share {
        match bucket {
            Bucket::Complete => &mut self.complete,
            Bucket::Dynamic => &mut self.dynamic,
            Bucket::Unobservable => &mut self.unobservable,
            Bucket::Gap => &mut self.gap,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GapByClass {
    pub unmodeled: Share,
    pub unresolved: Share,
    pub parse_failure: Share,
    pub limit: Share,
    pub unsupported: Share,
}

impl GapByClass {
    fn get_mut(&mut self, class: BoundaryClass) -> &mut Share {
        match class {
            BoundaryClass::Unmodeled => &mut self.unmodeled,
            BoundaryClass::Unresolved => &mut self.unresolved,
            BoundaryClass::ParseFailure => &mut self.parse_failure,
            BoundaryClass::Limit => &mut self.limit,
            BoundaryClass::Unsupported => &mut self.unsupported,
        }
    }

    fn entries(&self) -> [(&'static str, Share); 5] {
        [
            ("unmodeled", self.unmodeled),
            ("unresolved", self.unresolved),
            ("parse_failure", self.parse_failure),
            ("limit", self.limit),
            ("unsupported", self.unsupported),
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonShare {
    pub reason: String,
    pub any_share: f64,
    pub unique: usize,
    pub sole_share: f64,
    /// For a gap-tier reason, the commands its boundaries sit on, by the
    /// weighted share of rows where that command carries the reason. Empty
    /// for dynamic and unobservable reasons.
    pub commands: Vec<CommandShare>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandShare {
    pub command: String,
    pub weighted_share: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExeShare {
    pub exe: String,
    pub any_share: f64,
    pub unique: usize,
    pub sole_share: f64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KindShare {
    pub rows: usize,
    pub complete_share: Option<f64>,
}

/// Failure counts per kind plus the failing row ids, so a deadline or panic
/// can be chased without re-running the corpus. `deadline` is wall-clock and
/// therefore host-dependent: reported, never gated.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failures {
    pub panic: usize,
    pub deadline: usize,
    pub analysis: usize,
    pub invalid_subject: usize,
    pub ids: BTreeMap<String, Vec<String>>,
}

impl Failures {
    fn bump(&mut self, kind: FailureKind, id: &str) {
        let (name, count) = match kind {
            FailureKind::Panic => ("panic", &mut self.panic),
            FailureKind::Deadline => ("deadline", &mut self.deadline),
            FailureKind::Analysis => ("analysis", &mut self.analysis),
            FailureKind::InvalidSubject => ("invalid_subject", &mut self.invalid_subject),
        };
        *count += 1;
        self.ids
            .entry(name.to_string())
            .or_default()
            .push(id.to_string());
    }

    pub fn entries(&self) -> [(&'static str, usize); 4] {
        [
            ("panic", self.panic),
            ("deadline", self.deadline),
            ("analysis", self.analysis),
            ("invalid_subject", self.invalid_subject),
        ]
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SilentDrops {
    pub rows_tested: usize,
    pub mutants: usize,
    pub drops: Vec<Drop>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Drop {
    pub id: String,
    pub word: String,
    pub operation: String,
    pub domain: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SourceScore {
    pub rows: usize,
    pub weight_sum: u64,
    /// The headline: rows the engine understood as far as the fixture
    /// allows, i.e. complete, dynamic or unobservable. A failed row is not
    /// understood, so this is not `1 - gap` when a row fails.
    pub understood: Share,
    pub buckets: Buckets,
    pub any_domain_none_share: f64,
    pub all_full_share: f64,
    pub only_process_exec_share: f64,
    pub gap_by_class: GapByClass,
    pub top_reasons: Vec<ReasonShare>,
    /// Display ranking only: truncated to the executables with the most
    /// unmodeled weight. Gates read `unmodeled_sole_shares` instead.
    pub top_unmodeled: Vec<ExeShare>,
    /// Sole share of every executable that appears unmodeled in any row,
    /// untruncated, so a gate can compare any executable against the
    /// baseline. An executable absent here was unmodeled in no row.
    pub unmodeled_sole_shares: BTreeMap<String, f64>,
    pub by_kind: BTreeMap<String, KindShare>,
    pub failures: Failures,
    pub silent_drops: SilentDrops,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdicts {
    pub sound: usize,
    pub boundary_only: usize,
    pub silent_miss: usize,
    pub wrong_resource: usize,
    pub crash: usize,
    pub deadline: usize,
}

impl Verdicts {
    fn bump(&mut self, verdict: Verdict) {
        *match verdict {
            Verdict::Sound => &mut self.sound,
            Verdict::BoundaryOnly => &mut self.boundary_only,
            Verdict::SilentMiss => &mut self.silent_miss,
            Verdict::WrongResource => &mut self.wrong_resource,
            Verdict::Crash => &mut self.crash,
            Verdict::Deadline => &mut self.deadline,
        } += 1;
    }

    pub fn get(&self, verdict: Verdict) -> usize {
        match verdict {
            Verdict::Sound => self.sound,
            Verdict::BoundaryOnly => self.boundary_only,
            Verdict::SilentMiss => self.silent_miss,
            Verdict::WrongResource => self.wrong_resource,
            Verdict::Crash => self.crash,
            Verdict::Deadline => self.deadline,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VerdictIds {
    pub silent_miss: Vec<String>,
    pub wrong_resource: Vec<String>,
    pub crash: Vec<String>,
    pub deadline: Vec<String>,
}

impl VerdictIds {
    /// The gated verdicts; `deadline` is listed separately because it is
    /// wall-clock dependent.
    pub fn gated(&self) -> [(&'static str, &Vec<String>); 3] {
        [
            ("silent_miss", &self.silent_miss),
            ("wrong_resource", &self.wrong_resource),
            ("crash", &self.crash),
        ]
    }

    pub fn entries(&self) -> [(&'static str, &Vec<String>); 4] {
        let [a, b, c] = self.gated();
        [a, b, c, ("deadline", &self.deadline)]
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AdversarialScore {
    pub verdicts: Verdicts,
    pub by_category: BTreeMap<String, Verdicts>,
    pub ids: VerdictIds,
    pub silent_drops: SilentDrops,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HostStats {
    pub p50_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub max_rss_kb: u64,
}

pub fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn share(weight: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        round4(weight as f64 / total as f64)
    }
}

/// The executable named by an `unmodeled_command` boundary detail.
fn unmodeled_exe(detail: &str) -> Option<&str> {
    let rest = detail.strip_prefix("no model for command \"")?;
    let name = rest.strip_suffix('"')?;
    Some(name.rsplit('/').next().unwrap_or(name))
}

/// The command a boundary sits on: the executable an `unmodeled_command`
/// names, else the command word of the first model application its
/// provenance reaches (that model's id when it has no word), else the
/// boundary's own nearest command word, such as an unresolved `$CC`.
fn boundary_command(plan: &Plan, boundary: &Boundary) -> Option<String> {
    if boundary.reason.as_str() == "unmodeled_command" {
        return boundary
            .detail
            .as_deref()
            .and_then(unmodeled_exe)
            .map(str::to_string);
    }
    let reachable = |from: &[ProvenanceRef]| {
        let mut queue: VecDeque<u32> = from.iter().map(|p| p.0).collect();
        let mut seen = BTreeSet::new();
        std::iter::from_fn(move || {
            while let Some(index) = queue.pop_front() {
                if !seen.insert(index) {
                    continue;
                }
                if let Some(node) = plan.provenance.get(index as usize) {
                    queue.extend(node.antecedents.iter().map(|a| a.0));
                    return Some(node);
                }
            }
            None
        })
    };
    let model = reachable(&boundary.provenance).find_map(|node| match &node.kind {
        ProvenanceKind::ModelApplication { model } => Some((model, node)),
        _ => None,
    });
    // The model's nearest subject word is its command word. A span can cover
    // a whole call, so only its first command word is kept: leading
    // `NAME=value` assignments are skipped, and `x=$(cmd` names `cmd`.
    fn command_word(span: &str) -> Option<&str> {
        span.split_whitespace()
            .find_map(|word| match word.split_once('=') {
                Some((name, value)) if !name.is_empty() && !name.contains(['/', '$', '-']) => {
                    value.strip_prefix("$(")
                }
                _ => Some(
                    word.strip_prefix("$(")
                        .unwrap_or(word)
                        .trim_start_matches(['(', '`']),
                ),
            })
    }
    let from = model.map_or(&boundary.provenance[..], |(_, node)| &node.antecedents[..]);
    let word = reachable(from)
        .find_map(|node| match &node.kind {
            ProvenanceKind::SourceSpan { start, end } => {
                subject_text(&plan.subject).get(*start as usize..*end as usize)
            }
            ProvenanceKind::Argument { index } => match &plan.subject {
                Subject::Exec { argv, .. } => argv.get(*index as usize).map(String::as_str),
                _ => None,
            },
            _ => None,
        })
        .and_then(command_word)
        .map(|word| word.trim_matches(|c| c == '"' || c == '\''))
        .map(|word| word.rsplit('/').next().unwrap_or(word))
        .filter(|word| !word.is_empty());
    match (word, model) {
        (Some(word), _) => Some(word.to_string()),
        (None, Some((model, _))) => Some(model.split('@').next().unwrap_or(model).to_string()),
        (None, None) => None,
    }
}

fn subject_text(subject: &Subject) -> &str {
    match subject {
        Subject::Shell { source, .. } | Subject::Source { source, .. } => source,
        _ => "",
    }
}

/// Reduce one analyzed plan to what scoring reads. Runs in the worker so the
/// plan can be dropped before the next row is analyzed.
pub(super) fn summarize(
    row: &BenchRow,
    plan: &Plan,
    mutation: Option<MutationMeasurement>,
) -> Analyzed {
    let levels: Vec<CoverageLevel> = plan.coverage.0.values().map(|c| c.level).collect();
    let text = subject_text(&plan.subject);
    Analyzed {
        reasons: plan
            .boundaries
            .iter()
            .map(|b| b.reason.as_str().to_string())
            .collect(),
        gap_classes: plan
            .boundaries
            .iter()
            .filter(|b| bucket_of(b.reason.as_str()) == Tier::Gap)
            .map(|b| b.class)
            .collect(),
        gap_commands: plan
            .boundaries
            .iter()
            .filter(|b| bucket_of(b.reason.as_str()) == Tier::Gap)
            .filter_map(|b| Some((b.reason.as_str().to_string(), boundary_command(plan, b)?)))
            .collect(),
        unmodeled: plan
            .boundaries
            .iter()
            .filter(|b| b.reason.as_str() == "unmodeled_command")
            .filter_map(|b| b.detail.as_deref().and_then(unmodeled_exe))
            .map(str::to_string)
            .collect(),
        any_domain_none: levels.contains(&CoverageLevel::None),
        all_full: !levels.is_empty() && levels.iter().all(|l| *l == CoverageLevel::Full),
        only_process_exec: !plan.effects.is_empty()
            && plan.effects.iter().all(|e| e.operation.0 == "process.exec"),
        verdict: (row.source == "adversarial").then(|| judge_plan(plan, &row.expected_effects)),
        mutation: mutation.map(|measurement| MutationSummary {
            exercised: measurement.exercised,
            drops: measurement
                .findings
                .iter()
                .map(|finding| Drop {
                    id: row.id.clone(),
                    word: text[finding.source_start as usize..finding.source_end as usize]
                        .to_string(),
                    operation: finding.operation.clone(),
                    domain: finding.domain.clone(),
                })
                .collect(),
        }),
    }
}

fn silent_drops(outcomes: &[Outcome]) -> SilentDrops {
    let mut result = SilentDrops::default();
    for outcome in outcomes {
        let Ok(analyzed) = &outcome.result else {
            continue;
        };
        let Some(mutation) = &analyzed.mutation else {
            continue;
        };
        result.rows_tested += 1;
        result.mutants += mutation.exercised;
        result.drops.extend(mutation.drops.iter().cloned());
    }
    result.drops.sort();
    result.drops.dedup();
    result
}

pub fn host_stats(outcomes: &[Outcome], max_rss_kb: u64) -> HostStats {
    let mut wall: Vec<f64> = outcomes.iter().map(|o| o.elapsed_ms).collect();
    wall.sort_by(f64::total_cmp);
    let at = |fraction: f64| {
        if wall.is_empty() {
            0.0
        } else {
            wall[((wall.len() as f64 * fraction) as usize).min(wall.len() - 1)]
        }
    };
    HostStats {
        p50_ms: round4(at(0.5)),
        p99_ms: round4(at(0.99)),
        max_ms: round4(wall.last().copied().unwrap_or(0.0)),
        max_rss_kb,
    }
}

/// Aggregate one source's outcomes. `rows` and `outcomes` are index-aligned.
pub fn score_source(rows: &[BenchRow], outcomes: &[Outcome]) -> SourceScore {
    let total: u64 = rows.iter().map(|row| row.weight).sum();
    let mut score = SourceScore {
        rows: rows.len(),
        weight_sum: total,
        silent_drops: silent_drops(outcomes),
        ..Default::default()
    };
    // (weight, unique) accumulators; shares are divided out at the end.
    let mut buckets: BTreeMap<Bucket, (u64, usize)> = BTreeMap::new();
    let mut gap_class: BTreeMap<BoundaryClass, (u64, usize)> = BTreeMap::new();
    let mut none_w = 0;
    let mut full_w = 0;
    let mut only_exec_w = 0;
    let mut reason_any: BTreeMap<String, (u64, usize)> = BTreeMap::new();
    let mut reason_sole: BTreeMap<String, u64> = BTreeMap::new();
    let mut reason_commands: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let mut exe_any: BTreeMap<String, (u64, usize)> = BTreeMap::new();
    let mut exe_sole: BTreeMap<String, u64> = BTreeMap::new();
    let mut kinds: BTreeMap<String, (u64, u64, usize)> = BTreeMap::new();

    for (row, outcome) in rows.iter().zip(outcomes) {
        let kind = kinds.entry(row.kind.clone()).or_default();
        kind.0 += row.weight;
        kind.2 += 1;
        let analyzed = match &outcome.result {
            Ok(analyzed) => analyzed,
            Err(kind) => {
                score.failures.bump(*kind, &row.id);
                continue;
            }
        };
        let bucket = bucket_reasons(analyzed.reasons.iter().map(String::as_str));
        let entry = buckets.entry(bucket).or_default();
        entry.0 += row.weight;
        entry.1 += 1;
        if bucket == Bucket::Complete {
            kind.1 += row.weight;
        }
        for class in &analyzed.gap_classes {
            let entry = gap_class.entry(*class).or_default();
            entry.0 += row.weight;
            entry.1 += 1;
        }
        if analyzed.any_domain_none {
            none_w += row.weight;
        }
        if analyzed.all_full {
            full_w += row.weight;
        }
        if analyzed.only_process_exec {
            only_exec_w += row.weight;
        }
        for reason in &analyzed.reasons {
            let entry = reason_any.entry(reason.clone()).or_default();
            entry.0 += row.weight;
            entry.1 += 1;
        }
        for (reason, command) in &analyzed.gap_commands {
            *reason_commands
                .entry(reason.clone())
                .or_default()
                .entry(command.clone())
                .or_default() += row.weight;
        }
        if analyzed.reasons.len() == 1 {
            let reason = analyzed.reasons.iter().next().unwrap();
            *reason_sole.entry(reason.clone()).or_default() += row.weight;
        }
        for exe in &analyzed.unmodeled {
            let entry = exe_any.entry(exe.clone()).or_default();
            entry.0 += row.weight;
            entry.1 += 1;
        }
        if analyzed.unmodeled.len() == 1
            && analyzed.reasons.len() == 1
            && analyzed.reasons.contains("unmodeled_command")
        {
            let exe = analyzed.unmodeled.iter().next().unwrap();
            *exe_sole.entry(exe.clone()).or_default() += row.weight;
        }
    }

    let understood = buckets
        .iter()
        .filter(|(bucket, _)| **bucket != Bucket::Gap)
        .fold((0, 0), |acc, (_, (weight, unique))| {
            (acc.0 + weight, acc.1 + unique)
        });
    score.understood = Share {
        unique: understood.1,
        weighted_share: share(understood.0, total),
    };
    for (bucket, (weight, unique)) in buckets {
        *score.buckets.get_mut(bucket) = Share {
            unique,
            weighted_share: share(weight, total),
        };
    }
    for (class, (weight, unique)) in gap_class {
        *score.gap_by_class.get_mut(class) = Share {
            unique,
            weighted_share: share(weight, total),
        };
    }
    score.any_domain_none_share = share(none_w, total);
    score.all_full_share = share(full_w, total);
    score.only_process_exec_share = share(only_exec_w, total);
    score.top_reasons = top_shares(reason_any, reason_sole, total, TOP_REASONS)
        .into_iter()
        .map(|(reason, any_share, unique, sole_share)| {
            let mut commands: Vec<(String, u64)> = reason_commands
                .remove(&reason)
                .unwrap_or_default()
                .into_iter()
                .collect();
            commands.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            ReasonShare {
                commands: commands
                    .into_iter()
                    .take(TOP_GAP_COMMANDS)
                    .map(|(command, weight)| CommandShare {
                        command,
                        weighted_share: share(weight, total),
                    })
                    .collect(),
                reason,
                any_share,
                unique,
                sole_share,
            }
        })
        .collect();
    score.unmodeled_sole_shares = exe_any
        .keys()
        .map(|exe| {
            let sole = exe_sole.get(exe).copied().unwrap_or(0);
            (exe.clone(), share(sole, total))
        })
        .collect();
    score.top_unmodeled = top_shares(exe_any, exe_sole, total, TOP_UNMODELED)
        .into_iter()
        .map(|(exe, any_share, unique, sole_share)| ExeShare {
            exe,
            any_share,
            unique,
            sole_share,
        })
        .collect();
    score.by_kind = kinds
        .into_iter()
        .map(|(kind, (weight, complete, rows))| {
            (
                kind,
                KindShare {
                    rows,
                    complete_share: Some(share(complete, weight)),
                },
            )
        })
        .collect();
    score
}

/// (name, any_share, unique, sole_share) sorted by weight desc then name.
fn top_shares(
    any: BTreeMap<String, (u64, usize)>,
    sole: BTreeMap<String, u64>,
    total: u64,
    top: usize,
) -> Vec<(String, f64, usize, f64)> {
    let mut entries: Vec<_> = any.into_iter().collect();
    entries.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
    entries
        .into_iter()
        .take(top)
        .map(|(name, (weight, unique))| {
            let sole_share = share(sole.get(&name).copied().unwrap_or(0), total);
            (name, share(weight, total), unique, sole_share)
        })
        .collect()
}

pub fn score_adversarial(rows: &[BenchRow], outcomes: &[Outcome]) -> AdversarialScore {
    let mut score = AdversarialScore {
        silent_drops: silent_drops(outcomes),
        ..Default::default()
    };
    for (row, outcome) in rows.iter().zip(outcomes) {
        let verdict = match &outcome.result {
            Ok(analyzed) => analyzed
                .verdict
                .expect("adversarial rows are judged in the worker"),
            Err(FailureKind::Deadline) => Verdict::Deadline,
            Err(_) => Verdict::Crash,
        };
        score.verdicts.bump(verdict);
        score
            .by_category
            .entry(row.category.clone().unwrap_or_default())
            .or_default()
            .bump(verdict);
        let ids = match verdict {
            Verdict::SilentMiss => &mut score.ids.silent_miss,
            Verdict::WrongResource => &mut score.ids.wrong_resource,
            Verdict::Crash => &mut score.ids.crash,
            Verdict::Deadline => &mut score.ids.deadline,
            Verdict::Sound | Verdict::BoundaryOnly => continue,
        };
        ids.push(row.id.clone());
    }
    score.ids.silent_miss.sort();
    score.ids.wrong_resource.sort();
    score.ids.crash.sort();
    score.ids.deadline.sort();
    score
}

pub fn to_json(scoreboard: &Scoreboard) -> String {
    let mut out = serde_json::to_string_pretty(scoreboard).expect("scoreboard serializes");
    out.push('\n');
    out
}

/// `text` as a code span inside a table cell: the fence is one backtick
/// longer than any backtick run in it, and pipes are escaped so they do not
/// split the cell.
fn code_cell(text: &str) -> String {
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    let pad = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{}{pad}{fence}", text.replace('|', "\\|"))
}

fn pct(share: f64) -> String {
    format!("{:.2}%", share * 100.0)
}

/// The run a section's numbers come from. A plane with no recorded run says
/// so: numbers of unknown vintage are never presented as a current result.
fn measured_by(scoreboard: &Scoreboard, plane: Plane) -> String {
    match scoreboard.provenance.get(plane.as_str()) {
        Some(p) => format!("run `{}` measured {}\n\n", p.run_id, p.measured_at),
        None => "no run recorded: these numbers predate run records\n\n".to_string(),
    }
}

pub fn render_scoreboard_markdown(scoreboard: &Scoreboard) -> String {
    let mut md = String::new();
    let _ = writeln!(md, "# effinterp bench scoreboard\n");
    // Each plane is published on its own, so the masthead reports each one's
    // run, engine and model set separately instead of claiming one identity
    // for the whole document.
    let _ = writeln!(
        md,
        "| plane | run | measured | engine | models |\n|---|---|---|---|---|"
    );
    for plane in Plane::ALL {
        let _ = match scoreboard.provenance.get(plane.as_str()) {
            Some(p) => writeln!(
                md,
                "| {} | `{}` | {} | `{}` | `{}` |",
                plane.as_str(),
                p.run_id,
                p.measured_at,
                p.engine_version,
                p.model_set
            ),
            None => writeln!(md, "| {} | no run recorded | | | |", plane.as_str()),
        };
    }
    md.push('\n');
    md.push_str("## 1. Invocation correctness\n\n");
    md.push_str(&measured_by(scoreboard, Plane::Correctness));
    let _ = writeln!(
        md,
        "Independent effect, flow, and uncertainty expectations.\n\ncorpus `{}`\n",
        scoreboard.correctness.corpus_digest
    );
    if let Some(score) = &scoreboard.correctness.semantic {
        let _ = writeln!(
            md,
            "### Semantic fixtures\n\n{} cases: {} passed, {} known gaps, {} failures.\n",
            score.cases,
            score.passed,
            score.known_gaps.len(),
            score.failures.len()
        );
        for (id, failure) in &score.failures {
            let _ = writeln!(md, "- {id}: {failure}");
        }
    } else {
        md.push_str("Semantic fixtures: not measured.\n\n");
    }
    if let Some(adversarial) = &scoreboard.correctness.adversarial {
        let _ = writeln!(md, "### Adversarial\n");
        let _ = writeln!(
            md,
            "| category | sound | boundary_only | silent_miss | wrong_resource | crash | deadline |\n|---|---|---|---|---|---|---|"
        );
        let row = |md: &mut String, name: &str, v: &Verdicts| {
            let _ = writeln!(
                md,
                "| {name} | {} | {} | {} | {} | {} | {} |",
                v.sound, v.boundary_only, v.silent_miss, v.wrong_resource, v.crash, v.deadline
            );
        };
        row(&mut md, "all", &adversarial.verdicts);
        for (category, verdicts) in &adversarial.by_category {
            row(&mut md, category, verdicts);
        }
        for (name, ids) in adversarial.ids.entries() {
            if !ids.is_empty() {
                let _ = writeln!(md, "\n{name}: {}", ids.join(", "));
            }
        }
        let _ = writeln!(
            md,
            "\nsilent drops: {} rows tested, {} mutants, {} drops\n",
            adversarial.silent_drops.rows_tested,
            adversarial.silent_drops.mutants,
            adversarial.silent_drops.drops.len()
        );
    }
    if let Some(parity) = &scoreboard.correctness.parity {
        let _ = writeln!(
            md,
            "### nah parity\n\nnah `{}` / corpus `{}`\n",
            parity.nah_commit, parity.corpus_digest
        );
        let _ = writeln!(md, "| class | count |\n|---|---|");
        for (class, count) in &parity.classes {
            let _ = writeln!(md, "| {} | {count} |", class.as_str());
        }
        let classes: Vec<ParityClass> = parity.classes.keys().copied().collect();
        for (label, rows) in [("file", &parity.per_file), ("guard", &parity.per_guard)] {
            let _ = write!(md, "\n| {label} |");
            for class in &classes {
                let _ = write!(md, " {} |", class.as_str());
            }
            let _ = write!(md, "\n|---|");
            for _ in &classes {
                md.push_str("---|");
            }
            md.push('\n');
            for (name, counts) in rows {
                let _ = write!(md, "| {name} |");
                for class in &classes {
                    let _ = write!(md, " {} |", counts.get(class).copied().unwrap_or(0));
                }
                md.push('\n');
            }
        }
        md.push('\n');
    }
    md.push_str("## 2. Invocation coverage\n\n");
    md.push_str(&measured_by(scoreboard, Plane::Coverage));
    let _ = writeln!(
        md,
        "Reported completeness, not independently verified accuracy. Dynamic and unavailable inputs remain separate.\n\ncorpus `{}`\n",
        scoreboard.coverage.corpus_digest
    );
    for (source, score) in &scoreboard.coverage.sources {
        let _ = writeln!(
            md,
            "### {source}\n\n{} rows, weight {}\n\n**understood what it could: {}** ({} rows; complete {})\n",
            score.rows,
            score.weight_sum,
            pct(score.understood.weighted_share),
            score.understood.unique,
            pct(score.buckets.complete.weighted_share)
        );
        let _ = writeln!(md, "| bucket | unique | weighted |\n|---|---|---|");
        for bucket in Bucket::ALL {
            let s = score.buckets.get(bucket);
            let _ = writeln!(
                md,
                "| {} | {} | {} |",
                bucket.as_str(),
                s.unique,
                pct(s.weighted_share)
            );
        }
        let _ = writeln!(md, "| metric | weighted |\n|---|---|");
        let _ = writeln!(
            md,
            "| any domain coverage=none | {} |",
            pct(score.any_domain_none_share)
        );
        let _ = writeln!(
            md,
            "| all domains coverage=full | {} |",
            pct(score.all_full_share)
        );
        let _ = writeln!(
            md,
            "| effects only process.exec | {} |",
            pct(score.only_process_exec_share)
        );
        for (name, count) in score.failures.entries() {
            let ids = score
                .failures
                .ids
                .get(name)
                .map_or(String::new(), |ids| ids.join(", "));
            let _ = writeln!(md, "| failure {name} | {count} {ids} |");
        }
        let _ = writeln!(
            md,
            "| silent drops | {} rows tested, {} mutants, {} drops |\n",
            score.silent_drops.rows_tested,
            score.silent_drops.mutants,
            score.silent_drops.drops.len()
        );
        let _ = writeln!(md, "| gap class | unique | weighted |\n|---|---|---|");
        for (name, s) in score.gap_by_class.entries() {
            let _ = writeln!(md, "| {name} | {} | {} |", s.unique, pct(s.weighted_share));
        }
        let _ = writeln!(md, "\n| kind | rows | complete |\n|---|---|---|");
        for (kind, s) in &score.by_kind {
            let _ = writeln!(
                md,
                "| {kind} | {} | {} |",
                s.rows,
                s.complete_share.map_or("not measured".into(), pct)
            );
        }
        let _ = writeln!(
            md,
            "\n| reason | tier | any | unique | sole | top commands |\n|---|---|---|---|---|---|"
        );
        for r in &score.top_reasons {
            let commands: Vec<String> = r
                .commands
                .iter()
                .map(|c| format!("{} {}", code_cell(&c.command), pct(c.weighted_share)))
                .collect();
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} | {} |",
                r.reason,
                bucket_of(&r.reason).as_str(),
                pct(r.any_share),
                r.unique,
                pct(r.sole_share),
                commands.join(", ")
            );
        }
        let _ = writeln!(
            md,
            "\n| unmodeled exe | any | unique | sole |\n|---|---|---|---|"
        );
        for e in &score.top_unmodeled {
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} |",
                e.exe,
                pct(e.any_share),
                e.unique,
                pct(e.sole_share)
            );
        }
        if !score.silent_drops.drops.is_empty() {
            let _ = writeln!(md, "\n| drop id | word | operation |\n|---|---|---|");
            for d in &score.silent_drops.drops {
                let _ = writeln!(md, "| {} | `{}` | {} |", d.id, d.word, d.operation);
            }
        }
        md.push('\n');
    }
    match &scoreboard.repos {
        Some(repos) => md.push_str(&crate::repos::score::render_repository_coverage_markdown(
            repos,
            &measured_by(scoreboard, Plane::Repositories),
        )),
        None => md.push_str("## 3. Repository coverage\n\nnot measured.\n\n"),
    }
    md.push_str("## 4. Performance\n\n");
    md.push_str(&measured_by(scoreboard, Plane::Performance));
    match &scoreboard.performance.latency {
        Some(latency) => md.push_str(&crate::latency::render_latency_markdown(latency)),
        None => md.push_str("Latency and stress: not measured.\n\n"),
    }
    let _ = writeln!(md, "### Invocation host measurements\n");
    let _ = writeln!(
        md,
        "| source | p50 ms | p99 ms | max ms | max RSS MB |\n|---|---|---|---|---|"
    );
    for (source, h) in &scoreboard.performance.host {
        let _ = writeln!(
            md,
            "| {source} | {:.1} | {:.1} | {:.1} | {:.1} |",
            h.p50_ms,
            h.p99_ms,
            h.max_ms,
            h.max_rss_kb as f64 / 1024.0
        );
    }
    md
}
