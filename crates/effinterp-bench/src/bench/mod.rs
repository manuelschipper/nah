//! The effinterp bench over the invocation corpus: real coding-agent and CI subjects scored on
//! tier buckets, honesty (adversarial verdicts, silent-drop mutants) and
//! failures, with a committed scoreboard and a regression gate over it.

pub mod corpus;
pub mod gate;
pub mod judge;
pub mod score;
pub mod sessions;
pub mod tiers;

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use effinterp_engine::Engine;
use effinterp_proto::{BoundaryClass, validate_plan, validate_subject};

use crate::nah::goldens::{Req, ResourceMatch};
use crate::nah::mutate::measure_symbolic_mutations;
use corpus::BenchRow;
use judge::Verdict;
use score::{AdversarialScore, HostStats, Scoreboard, SourceScore};
use tiers::{Bucket, bucket_plan};

/// Wall-clock budget per subject; a slower analysis is a `deadline` failure.
/// It detects hangs only. The committed scoreboard must reproduce on any CI
/// machine, and the heaviest adversarial bounds rows take about 10 s in a debug
/// build on an M-series Mac (2026-09-30) and several times that on a CI runner.
pub const DEADLINE: Duration = Duration::from_secs(120);
/// Spawned threads default to a 2 MiB stack, while production analyzes on
/// the process's main thread, which gets 8 MiB. Workers match production so
/// a deeply nested row does not overflow here yet pass in production.
const WORKER_STACK_SIZE: usize = 8 * 1024 * 1024;
/// Sources whose complete rows skip silent-drop mutants (cost).
const SILENT_DROP_SKIP: &[&str] = &["swe"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    Panic,
    Deadline,
    Analysis,
    InvalidSubject,
}

/// What scoring reads from one analyzed plan. The worker builds it and drops
/// the plan, so a source's memory grows with its row count instead of holding
/// every plan at once (30k SWE plans held whole peaked near 10 GB).
#[derive(Debug)]
pub struct Analyzed {
    /// Distinct boundary reasons.
    pub reasons: BTreeSet<String>,
    /// Classes of the gap-tier boundaries.
    pub gap_classes: BTreeSet<BoundaryClass>,
    /// (reason, command) of each gap-tier boundary a model applied to.
    pub gap_commands: BTreeSet<(String, String)>,
    /// Executables named by `unmodeled_command` boundaries.
    pub unmodeled: BTreeSet<String>,
    pub any_domain_none: bool,
    pub all_full: bool,
    pub only_process_exec: bool,
    /// Adversarial verdict; only adversarial rows are judged.
    pub verdict: Option<Verdict>,
    /// Silent-drop result, when the row was in the mutant population.
    pub mutation: Option<MutationSummary>,
}

#[derive(Debug)]
pub struct MutationSummary {
    pub exercised: usize,
    pub drops: Vec<score::Drop>,
}

#[derive(Debug)]
pub struct SubjectOutcome {
    pub elapsed_ms: f64,
    pub result: Result<Analyzed, FailureKind>,
}

impl SubjectOutcome {
    fn failed(kind: FailureKind, elapsed: Duration) -> Self {
        SubjectOutcome {
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
            result: Err(kind),
        }
    }
}

/// Which rows of a source get silent-drop mutants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    None,
    Complete,
    All,
}

fn analyze_one(engine: &Engine, row: &BenchRow, mutation: Mutation) -> SubjectOutcome {
    let subject = &row.subject;
    if validate_subject(subject).is_err() {
        return SubjectOutcome::failed(FailureKind::InvalidSubject, Duration::ZERO);
    }
    let start = Instant::now();
    let analysis = catch_unwind(AssertUnwindSafe(|| engine.analyze(subject)));
    let elapsed = start.elapsed();
    let plan = match analysis {
        Err(_) => return SubjectOutcome::failed(FailureKind::Panic, elapsed),
        Ok(Err(_)) => return SubjectOutcome::failed(FailureKind::Analysis, elapsed),
        Ok(Ok(plan)) if validate_plan(&plan).is_err() => {
            return SubjectOutcome::failed(FailureKind::Analysis, elapsed);
        }
        Ok(Ok(plan)) => plan,
    };
    if elapsed > DEADLINE {
        return SubjectOutcome::failed(FailureKind::Deadline, elapsed);
    }
    let eligible = match mutation {
        Mutation::None => false,
        Mutation::Complete => bucket_plan(&plan) == Bucket::Complete,
        Mutation::All => true,
    };
    let mutation = if eligible {
        // Every effect domain of the plan is the oracle: any full-coverage
        // effect whose literal operand goes symbolic must survive symbolically.
        let oracle: Vec<Req> = plan
            .effects
            .iter()
            .map(|effect| effect.operation.domain().to_string())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|op| Req {
                attributes: Default::default(),
                op,
                resource: ResourceMatch::Any(true),
            })
            .collect();
        match catch_unwind(AssertUnwindSafe(|| {
            measure_symbolic_mutations(engine, &plan, &oracle, None, None)
        })) {
            Ok(measurement) => Some(measurement),
            Err(_) => return SubjectOutcome::failed(FailureKind::Panic, elapsed),
        }
    } else {
        None
    };
    SubjectOutcome {
        elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        result: Ok(score::summarize(row, &plan, mutation)),
    }
}

enum Message {
    Started(usize),
    Done(usize, Box<SubjectOutcome>),
}

/// Analyze every row on all available cores. A subject still running after
/// `DEADLINE` is recorded as a deadline failure and its thread abandoned; the
/// process exits without joining it.
pub fn analyze_rows(
    engine: &Arc<Engine>,
    rows: &Arc<Vec<BenchRow>>,
    mutation: Mutation,
) -> Vec<SubjectOutcome> {
    let n = rows.len();
    let next = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = mpsc::channel();
    let workers = std::thread::available_parallelism()
        .map_or(1, |p| p.get())
        .min(n.max(1));
    for _ in 0..workers {
        let engine = Arc::clone(engine);
        let rows = Arc::clone(rows);
        let next = Arc::clone(&next);
        let sender = sender.clone();
        std::thread::Builder::new()
            .stack_size(WORKER_STACK_SIZE)
            .spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    if index >= rows.len() {
                        break;
                    }
                    if sender.send(Message::Started(index)).is_err() {
                        break;
                    }
                    let outcome = analyze_one(&engine, &rows[index], mutation);
                    if sender
                        .send(Message::Done(index, Box::new(outcome)))
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .expect("spawn a bench analysis worker");
    }
    drop(sender);

    let mut outcomes: Vec<Option<SubjectOutcome>> = (0..n).map(|_| None).collect();
    let mut in_flight: BTreeMap<usize, Instant> = BTreeMap::new();
    let mut recorded = 0;
    while recorded < n {
        let wait = in_flight
            .values()
            .min()
            .map_or(DEADLINE, |oldest| DEADLINE.saturating_sub(oldest.elapsed()));
        let idle = in_flight.is_empty();
        let received = receiver.recv_timeout(wait);
        let silent = received.is_err();
        match received {
            Ok(Message::Started(index)) => {
                in_flight.insert(index, Instant::now());
            }
            Ok(Message::Done(index, outcome)) => {
                if in_flight.remove(&index).is_some() {
                    outcomes[index] = Some(*outcome);
                    recorded += 1;
                }
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
        }
        let expired: Vec<usize> = in_flight
            .iter()
            .filter(|(_, started)| started.elapsed() > DEADLINE)
            .map(|(index, _)| *index)
            .collect();
        for index in expired {
            in_flight.remove(&index);
            outcomes[index] = Some(SubjectOutcome::failed(FailureKind::Deadline, DEADLINE));
            recorded += 1;
        }
        // A full deadline of silence with nothing in flight means every
        // worker is stuck (or gone): the unclaimed rows can never start.
        if idle && silent {
            for slot in outcomes.iter_mut().filter(|slot| slot.is_none()) {
                *slot = Some(SubjectOutcome::failed(FailureKind::Deadline, DEADLINE));
                recorded += 1;
            }
        }
    }
    outcomes.into_iter().map(Option::unwrap).collect()
}

/// Process-lifetime high-water RSS in KiB on Linux and macOS.
pub fn max_rss_kb() -> u64 {
    crate::latency::machine::peak_rss_bytes().expect("getrusage(RUSAGE_SELF)") / 1024
}

/// Score every source of the loaded corpus. Sources run one after another so
/// each RSS reading is that source's high-water mark within the process.
/// The caller owns the digest: it names the scope of the plane being scored,
/// and each plane writes it into its own section.
pub fn score_corpus(engine: Arc<Engine>, rows: Vec<BenchRow>) -> Scoreboard {
    let mut by_source: BTreeMap<String, Vec<BenchRow>> = BTreeMap::new();
    for row in rows {
        by_source.entry(row.source.clone()).or_default().push(row);
    }
    let mut scoreboard = Scoreboard {
        schema: score::SCOREBOARD_SCHEMA.to_string(),
        correctness: Default::default(),
        coverage: Default::default(),
        repos: None,
        performance: Default::default(),
        provenance: BTreeMap::new(),
    };
    for (source, rows) in by_source {
        let adversarial = source == "adversarial";
        let mutation = if adversarial {
            Mutation::All
        } else if SILENT_DROP_SKIP.contains(&source.as_str()) {
            Mutation::None
        } else {
            Mutation::Complete
        };
        let rows = Arc::new(rows);
        let outcomes = analyze_rows(&engine, &rows, mutation);
        let host: HostStats = score::host_stats(&outcomes, max_rss_kb());
        if adversarial {
            let score: AdversarialScore = score::score_adversarial(&rows, &outcomes);
            scoreboard.correctness.adversarial = Some(score);
        } else {
            let score: SourceScore = score::score_source(&rows, &outcomes);
            scoreboard.coverage.sources.insert(source.clone(), score);
        }
        scoreboard.performance.host.insert(source, host);
    }
    scoreboard
}
