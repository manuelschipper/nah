//! Engine latency cases: `Engine::analyze` wall clock across representative
//! subjects with one engine reused across analyses (the realistic guard shape:
//! build the model catalog once, analyze many calls).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use effinterp_engine::Engine;
use effinterp_proto::{SourceDialect, Subject};
use serde::{Deserialize, Serialize};

use crate::invocation::score::round4;
use crate::repos::isolate::{IsolateRequest, IsolateStatus, isolate_child_process};

use super::checkpoint;

/// A named benchmark input.
struct Case {
    name: &'static str,
    subject: Subject,
    sample_budget: Duration,
}

fn cwd() -> Option<String> {
    Some("/work/repo".to_string())
}

fn exec(argv: &[&str]) -> Subject {
    Subject::Exec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        cwd: cwd(),
        context: Default::default(),
    }
}

fn shell(source: &str) -> Subject {
    Subject::Shell {
        source: source.to_string(),
        cwd: cwd(),
        context: Default::default(),
    }
}

fn shell_word_list(words: usize) -> Subject {
    shell(&format!("true {}", "x ".repeat(words)))
}

/// A large, deeply nested input to exercise the worst case under the engine's
/// limits: hundreds of top-level commands plus a deep wrapper chain.
fn pathological() -> Subject {
    let mut src = String::new();
    for i in 0..500 {
        src.push_str(&format!("rm -rf /tmp/dir{i} && cp /src/{i} /dst/{i}\n"));
    }
    // Deep sh -c nesting on top.
    let mut nested = String::from("rm -rf /deep");
    for _ in 0..40 {
        nested = format!("sh -c \"{}\"", nested.replace('"', "\\\""));
    }
    src.push_str(&nested);
    src.push('\n');
    shell(&src)
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "exec: rm -rf",
            subject: exec(&["rm", "-rf", "/tmp/cache"]),
            sample_budget: SAMPLE_BUDGET,
        },
        Case {
            name: "exec: unmodeled cmd",
            subject: exec(&["deploytool", "--prod", "--force"]),
            sample_budget: SAMPLE_BUDGET,
        },
        Case {
            name: "shell: small pipeline",
            subject: shell("rm -rf \"$TMPDIR/build\" && cp a.txt b.txt && curl http://x/y"),
            sample_budget: SAMPLE_BUDGET,
        },
        Case {
            name: "shell: substitution",
            subject: shell("rm -rf \"$(dirname \"$CONF\")/cache\""),
            sample_budget: SAMPLE_BUDGET,
        },
        Case {
            name: "shell word list (4096 words)",
            subject: shell_word_list(4096),
            sample_budget: SAMPLE_BUDGET,
        },
        Case {
            name: "nested: docker->psql->SQL",
            subject: exec(&[
                "docker",
                "exec",
                "postgres",
                "psql",
                "-c",
                "UPDATE public.users SET active = true",
            ]),
            sample_budget: SAMPLE_BUDGET,
        },
        Case {
            name: "python: os/shutil",
            subject: Subject::Source {
                dialect: None,
                language: "python".into(),
                source: "import os, shutil\n\
                         def wipe(root, t):\n    shutil.rmtree(os.path.join(root, t))\n\
                         wipe('/var/cache/app', name)\n"
                    .to_string(),
                cwd: cwd(),
                context: Default::default(),
            },
            sample_budget: SAMPLE_BUDGET,
        },
        Case {
            name: "js: fs/child_process",
            subject: Subject::Source {
                language: "js".into(),
                source: "const fs = require('fs');\n\
                         const cp = require('child_process');\n\
                         function wipe(p){ fs.rmSync(p, {recursive:true}); }\n\
                         wipe('/data'); cp.execSync('rm -rf /tmp/x');\n"
                    .to_string(),
                dialect: Some(SourceDialect::Js),
                cwd: cwd(),
                context: Default::default(),
            },
            sample_budget: SAMPLE_BUDGET,
        },
        Case {
            name: "go: os/exec",
            subject: Subject::Source {
                dialect: None,
                language: "go".to_string(),
                source: "package main\n\
                         import \"os\"\n\
                         func wipe(p string) { os.RemoveAll(p) }\n\
                         func main() { wipe(\"/data\") }\n"
                    .to_string(),
                cwd: cwd(),
                context: Default::default(),
            },
            sample_budget: SAMPLE_BUDGET,
        },
        Case {
            name: "pathological (500 cmds + deep)",
            subject: pathological(),
            sample_budget: PATHOLOGICAL_SAMPLE_BUDGET,
        },
    ]
}

/// Sorted-sample summary in microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct EngineStats {
    pub min: f64,
    pub median: f64,
    pub p95: f64,
    pub max: f64,
}

const ITERATIONS: usize = 200;
const WARMUP: usize = 20;
const MIN_SAMPLES: usize = 20;
const WARMUP_BUDGET: Duration = Duration::from_secs(1);
const SAMPLE_BUDGET: Duration = Duration::from_secs(5);
const PATHOLOGICAL_SAMPLE_BUDGET: Duration = Duration::from_secs(75);
const CHILD_DEADLINE_MARGIN: Duration = Duration::from_secs(10);

fn child_deadline(case: &Case) -> Duration {
    WARMUP_BUDGET + case.sample_budget + CHILD_DEADLINE_MARGIN
}

pub(super) fn configuration() -> serde_json::Value {
    let cases = cases();
    let sample_budget_ms_by_case: BTreeMap<_, _> = cases
        .iter()
        .map(|case| (case.name, case.sample_budget.as_millis() as u64))
        .collect();
    let child_deadline_ms_by_case: BTreeMap<_, _> = cases
        .iter()
        .map(|case| (case.name, child_deadline(case).as_millis() as u64))
        .collect();
    let max_stress_runtime_ms: u64 = cases
        .iter()
        .map(|case| child_deadline(case).as_millis() as u64)
        .sum();
    serde_json::json!({
        "max_samples": ITERATIONS, "max_warmups": WARMUP, "min_summary_samples": MIN_SAMPLES,
        "warmup_ms": WARMUP_BUDGET.as_millis(),
        "sample_budget_ms_by_case": sample_budget_ms_by_case,
        "child_deadline_ms_by_case": child_deadline_ms_by_case,
        "max_stress_runtime_ms": max_stress_runtime_ms, "cases": cases.len(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stop {
    Count,
    Budget,
    Deadline,
    Error,
}

impl Stop {
    fn as_str(self) -> &'static str {
        match self {
            Stop::Count => "the sample count",
            Stop::Budget => "the sampling budget",
            Stop::Deadline => "the child deadline",
            Stop::Error => "an error",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Progress {
    case: usize,
    name: String,
    warmups: usize,
    samples_ns: Vec<u64>,
    stopped_by: Option<Stop>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Measurement {
    progress: Progress,
    status: IsolateStatus,
    elapsed_ms: u64,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stderr: String,
}

fn summarize(samples: &[u64]) -> Option<EngineStats> {
    if samples.len() < MIN_SAMPLES {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let at = |p: usize| round4(sorted[((sorted.len() - 1) * p) / 100] as f64 / 1000.0);
    Some(EngineStats {
        min: at(0),
        median: at(50),
        p95: at(95),
        max: at(100),
    })
}

/// The parent enforces a hard process deadline, including an individual slow call.
/// Each completed sample is saved before another analysis starts.
pub fn sample_main(index: usize, path: &Path) -> Result<(), String> {
    let case = cases()
        .into_iter()
        .nth(index)
        .ok_or("unknown engine case")?;
    let engine = Engine::new();
    let mut progress = Progress {
        case: index,
        name: case.name.into(),
        warmups: 0,
        samples_ns: Vec::new(),
        stopped_by: None,
    };
    checkpoint::write(path, &progress)?;
    let start = Instant::now();
    while progress.warmups < WARMUP && start.elapsed() < WARMUP_BUDGET {
        std::hint::black_box(engine.analyze(&case.subject).map_err(|e| e.to_string())?);
        progress.warmups += 1;
        checkpoint::write(path, &progress)?;
    }
    let start = Instant::now();
    while progress.samples_ns.len() < ITERATIONS && start.elapsed() < case.sample_budget {
        let call = Instant::now();
        let plan = engine.analyze(&case.subject).map_err(|e| e.to_string())?;
        progress.samples_ns.push(call.elapsed().as_nanos() as u64);
        std::hint::black_box(&plan);
        checkpoint::write(path, &progress)?;
    }
    progress.stopped_by = Some(if progress.samples_ns.len() == ITERATIONS {
        Stop::Count
    } else {
        Stop::Budget
    });
    checkpoint::write(path, &progress)?;
    println!("{{\"status\":\"analyzed\"}}");
    Ok(())
}

/// Summaries by case, and the cases that could not produce one with the
/// reason why. Every case ends in exactly one of the two.
type Measured = (BTreeMap<String, EngineStats>, BTreeMap<String, String>);

pub fn measure_engine_stress(dir: &Path) -> Result<Measured, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let binary = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut result = BTreeMap::new();
    let mut omitted = BTreeMap::new();
    for (index, case) in cases().into_iter().enumerate() {
        let path = dir.join(format!("{index}.json"));
        let record: Measurement = match checkpoint::read(&path)? {
            Some(record) => record,
            None => {
                let partial = dir.join(format!("{index}.partial.json"));
                // An unfinished case restarts; finished cases are immutable checkpoints.
                checkpoint::write(
                    &partial,
                    &Progress {
                        case: index,
                        name: case.name.into(),
                        warmups: 0,
                        samples_ns: Vec::new(),
                        stopped_by: None,
                    },
                )?;
                let envelope = isolate_child_process(IsolateRequest {
                    binary: binary.clone(),
                    args: vec![
                        "stress-sample".into(),
                        "--case".into(),
                        index.to_string(),
                        "--json".into(),
                        partial.display().to_string(),
                    ],
                    stdin: Vec::new(),
                    timeout: child_deadline(&case),
                    max_stdout: 4096,
                    max_stderr: 4096,
                    cache_path: dir.into(),
                    extra_env: Vec::new(),
                    max_memory_bytes: Some(4 << 30),
                });
                let mut progress: Progress =
                    checkpoint::read(&partial)?.ok_or("missing stress checkpoint")?;
                if envelope.status == IsolateStatus::Timeout {
                    progress.stopped_by = Some(Stop::Deadline);
                } else if envelope.status != IsolateStatus::Analyzed {
                    progress.stopped_by = Some(Stop::Error);
                }
                let record = Measurement {
                    progress,
                    status: envelope.status,
                    elapsed_ms: envelope.elapsed_ms,
                    exit_code: envelope.process.exit_code,
                    signal: envelope.process.signal,
                    stderr: checkpoint::diagnostic(&envelope.process.stderr, dir),
                };
                checkpoint::write(&path, &record)?;
                std::fs::remove_file(&partial).map_err(|e| e.to_string())?;
                record
            }
        };
        let progress = &record.progress;
        let terminal = match (record.status, progress.stopped_by) {
            (IsolateStatus::Analyzed, Some(Stop::Count)) => progress.samples_ns.len() == ITERATIONS,
            (IsolateStatus::Analyzed, Some(Stop::Budget)) => progress.samples_ns.len() < ITERATIONS,
            (IsolateStatus::Timeout, Some(Stop::Deadline)) => true,
            (status, Some(Stop::Error)) => {
                status != IsolateStatus::Analyzed && status != IsolateStatus::Timeout
            }
            _ => false,
        };
        if progress.case != index
            || progress.name != case.name
            || !terminal
            || progress.warmups > WARMUP
            || progress.samples_ns.len() > ITERATIONS
        {
            return Err(format!("invalid engine checkpoint {}", path.display()));
        }
        // A crash can land after the terminal checkpoint but before partial cleanup.
        let partial = dir.join(format!("{index}.partial.json"));
        if partial.exists() {
            std::fs::remove_file(partial).map_err(|e| e.to_string())?;
        }
        if !matches!(
            record.status,
            IsolateStatus::Analyzed | IsolateStatus::Timeout
        ) {
            return Err(format!(
                "engine case {} failed: {:?}: {}",
                case.name, record.status, record.stderr
            ));
        }
        if let Some(stats) = summarize(&progress.samples_ns) {
            result.insert(case.name.into(), stats);
        } else {
            let why = format!(
                "{} samples, fewer than the {MIN_SAMPLES} a summary needs; stopped by {}",
                progress.samples_ns.len(),
                progress.stopped_by.map_or("nothing", Stop::as_str)
            );
            eprintln!("{}: {why}", case.name);
            omitted.insert(case.name.to_string(), why);
        }
    }
    Ok((result, omitted))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression: the shared five-second budget gave the pathological case only two
    // samples, hiding its latency. Its larger recorded budget must not lower the floor.
    #[test]
    fn short_samples_do_not_produce_quantiles() {
        assert!(summarize(&[]).is_none());
        assert!(summarize(&[1_000; MIN_SAMPLES - 1]).is_none());
        let samples: Vec<_> = (1..=MIN_SAMPLES as u64).map(|n| n * 1_000).collect();
        let stats = summarize(&samples).unwrap();
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 20.0);
        assert!(stats.p95 >= stats.median);

        let config = configuration();
        assert_eq!(config["min_summary_samples"], MIN_SAMPLES);
        assert_eq!(
            config["sample_budget_ms_by_case"]["pathological (500 cmds + deep)"],
            PATHOLOGICAL_SAMPLE_BUDGET.as_millis() as u64
        );
        assert_eq!(
            config["max_stress_runtime_ms"],
            cases()
                .iter()
                .map(|case| child_deadline(case).as_millis() as u64)
                .sum::<u64>()
        );
    }

    // Resuming finished work must not spawn analyzers, and damaged evidence must not be reused.
    #[test]
    fn completed_cases_are_reused_and_corruption_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        for (index, case) in cases().into_iter().enumerate() {
            let samples = if case.name == "pathological (500 cmds + deep)" {
                MIN_SAMPLES - 1
            } else {
                MIN_SAMPLES
            };
            checkpoint::write(
                &dir.path().join(format!("{index}.json")),
                &Measurement {
                    progress: Progress {
                        case: index,
                        name: case.name.into(),
                        warmups: 1,
                        samples_ns: vec![1000; samples],
                        stopped_by: Some(Stop::Budget),
                    },
                    status: IsolateStatus::Analyzed,
                    elapsed_ms: 1,
                    exit_code: Some(0),
                    signal: None,
                    stderr: String::new(),
                },
            )
            .unwrap();
        }
        // current_exe is the test harness, which cannot serve a stress-sample child.
        let partial = dir.path().join("0.partial.json");
        std::fs::write(&partial, b"interrupted cleanup").unwrap();
        let (results, omitted) = measure_engine_stress(dir.path()).unwrap();
        assert_eq!(results.len(), cases().len() - 1);
        assert_eq!(
            omitted["pathological (500 cmds + deep)"],
            "19 samples, fewer than the 20 a summary needs; stopped by the sampling budget"
        );
        assert!(!partial.exists());
        let path = dir.path().join("0.json");
        crate::run::read_envelope(&path, checkpoint::STRESS_UNIT_SCHEMA).unwrap();
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["data"]["progress"]["samples_ns"][0] = serde_json::json!(999);
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(
            measure_engine_stress(dir.path())
                .unwrap_err()
                .contains("identity mismatch")
        );
    }
}
