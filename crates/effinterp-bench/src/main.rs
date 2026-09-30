// Development bench: measures, spawns children, and records runs on disk.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use effinterp_bench::latency;
use effinterp_bench::nah::corpus::{CaseLoad, FixtureObservations, FixtureResolver, load_corpus};
use effinterp_bench::nah::goldens::seed_missing;
use effinterp_bench::nah::report::run_corpus;
use effinterp_bench::repos;
use effinterp_bench::run::publish;
use effinterp_bench::run::{self, Layout, MeasureRequest, NAH_CORPUS, Plane, Selection};
use effinterp_engine::{Engine, ObservationResolver, SourceResolver};

#[derive(Parser)]
#[command(name = "effinterp-bench")]
struct Cli {
    /// External session export to include in coverage. Use the same snapshot for measure, resume and publish.
    #[arg(long, global = true)]
    session_corpus: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Author effect and flow goldens from corpus/.
    Golden {
        #[command(subcommand)]
        command: GoldenCommand,
    },
    /// Print the full parity result and plan of one nah case.
    ShowCase { id: String },
    /// Measure groups into a durable record under bench/runs/<id>/ and print
    /// its verdict.
    ///
    /// The verdict is the one `publish --dry-run` reports, and the exit code
    /// follows it. Nothing else changes, and the record is local evidence,
    /// not a tracked file.
    ///
    /// Cadence. Correctness is the per-merge gate: measure it whenever the
    /// parity numbers move and publish the run. Coverage, repositories and
    /// performance are periodic, each published against the baseline its
    /// scoreboard section names: coverage when choosing which commands to
    /// model, repositories and performance when the engine changes shape or
    /// the measuring machine changes. Repositories is hours for the whole
    /// corpus, so it is usually bounded with `--repo`.
    ///
    /// A `--repo` selection publishes as the bounded scope it is: the
    /// section names the repositories it scored and is gated only over them.
    /// A `--source` or `--limit` selection is recorded as partial and can
    /// never become the baseline.
    Measure {
        /// Groups to measure: correctness, coverage, repositories, performance.
        /// Linux children use an address-space limit; macOS children use a
        /// resident-memory watchdog polled every 20 ms (transient overshoot is possible).
        #[arg(long = "group", value_enum, value_name = "GROUP")]
        planes: Vec<Plane>,
        /// Only these invocation sources (repeatable).
        #[arg(long)]
        source: Vec<String>,
        /// At most this many rows per invocation source.
        #[arg(long)]
        limit: Option<usize>,
        /// Only these repositories (repeatable).
        #[arg(long)]
        repo: Vec<String>,
        /// Open the hidden split on a full repos run, recording this label.
        #[arg(long)]
        unlock_hidden: Option<String>,
        /// Repository checkout cache; defaults to $EI_STRESS_CACHE, else
        /// /tmp/ei-stress-cache.
        #[arg(long)]
        cache: Option<PathBuf>,
        /// Continue an interrupted run, measuring only its missing units.
        #[arg(long, conflicts_with_all = ["planes", "source", "limit", "repo", "unlock_hidden"])]
        resume: Option<String>,
    },
    /// Make a recorded run the baseline for the planes it measured: compute its verdict,
    /// ratchet the ceilings, and rewrite the scoreboard. With `--rebaseline`,
    /// a plane whose corpus the baseline does not carry yet is published as a
    /// new comparison scope; every plane of an unchanged scope still gets
    /// every rule.
    /// Refuses a failed, partial, incomplete, or stale run before touching
    /// anything.
    ///
    /// With `--dry-run`, only compute and store the verdict from the record
    /// alone. Exit 0 when the run could be published, 1 on rule failures or a
    /// partial selection, 3 when the rules passed but another blocker remains.
    Publish {
        run: String,
        /// Establish the run as the baseline for any plane whose scope moved.
        /// Its skipped drift rules are acknowledged, not passed.
        #[arg(long)]
        rebaseline: bool,
        /// Report the verdict without touching the baseline.
        #[arg(long)]
        dry_run: bool,
    },
    /// Index one repository in an isolated child (request on stdin).
    #[command(hide = true)]
    RepoChild,
    /// Time one engine stress case in a fresh process.
    #[command(hide = true)]
    StressSample {
        #[arg(long)]
        case: usize,
        #[arg(long)]
        json: PathBuf,
    },
    /// Time first engine construction and analysis in this fresh process.
    #[command(hide = true)]
    ColdSample,
}

#[derive(Subcommand)]
enum GoldenCommand {
    /// Emit skeletons for expected-block shell cases lacking a golden.
    Seed {
        #[arg(long, default_value = NAH_CORPUS)]
        corpus: PathBuf,
        #[arg(long, default_value = "/dev/stdout")]
        out: PathBuf,
    },
}

/// Report an operational error: exit 2.
fn fail(error: String) -> ExitCode {
    eprintln!("effinterp-bench: {error}");
    ExitCode::from(2)
}

fn exit(result: Result<(), String>) -> ExitCode {
    result.map_or_else(fail, |()| ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut layout = Layout::workspace();
    layout.session_corpus = cli.session_corpus;
    match cli.command {
        Command::Golden {
            command: GoldenCommand::Seed { corpus, out },
        } => {
            let cases = match load_corpus(&corpus) {
                Ok(cases) => cases,
                Err(e) => return fail(format!("cannot read corpus {}: {e}", corpus.display())),
            };
            let seeded = seed_missing(&Engine::new().with_causality_detail(true), &cases);
            let mut json = serde_json::to_string_pretty(&seeded).unwrap();
            json.push('\n');
            exit(fs::write(&out, json).map_err(|e| format!("cannot write {}: {e}", out.display())))
        }
        Command::ShowCase { id } => show_nah_case(&layout, &id),
        Command::Measure {
            planes,
            source,
            limit,
            repo,
            unlock_hidden,
            cache,
            resume,
        } => {
            let request = MeasureRequest {
                selection: Selection {
                    planes,
                    sources: source,
                    limit,
                    repos: repo,
                    unlock_hidden,
                },
                resume,
                cache,
            };
            match run::measure(&layout, request) {
                Ok(id) => {
                    println!("recorded {}", layout.run_directory(&id).display());
                    report_verdict(&layout, id.as_str(), false)
                }
                Err(e) => fail(e),
            }
        }
        Command::Publish {
            run,
            rebaseline,
            dry_run: true,
        } => report_verdict(&layout, &run, rebaseline),
        Command::Publish {
            run,
            rebaseline,
            dry_run: false,
        } => run_publish(&layout, &run, rebaseline),
        Command::RepoChild => repos::score::child_main(),
        Command::StressSample { case, json } => exit(
            latency::engine::sample_main(case, &json).map_err(|e| format!("stress sample: {e}")),
        ),
        Command::ColdSample => {
            exit(latency::cold_sample_main().map_err(|e| format!("cold sample: {e}")))
        }
    }
}

/// Exit 0 when the run could be published, 1 on rule failures or a partial
/// selection, 3 when the rules passed but another eligibility blocker remains.
fn report_verdict(layout: &Layout, id: &str, rebaseline: bool) -> ExitCode {
    let run = match publish::load_recorded_run(layout, id) {
        Ok(run) => run,
        Err(e) => return fail(e),
    };
    let evaluation = match publish::evaluate_run_verdict(layout, &run, rebaseline) {
        Ok(evaluation) => evaluation,
        Err(e) => return fail(e),
    };
    print!("{}", publish::render_run_verdict(&evaluation.verdict));
    println!("verdict {}", evaluation.verdict_path.display());
    let verdict = &evaluation.verdict;
    if verdict.eligible {
        ExitCode::SUCCESS
    } else if !verdict.historical.passed || verdict.partial {
        ExitCode::from(1)
    } else {
        ExitCode::from(3)
    }
}

fn run_publish(layout: &Layout, id: &str, rebaseline: bool) -> ExitCode {
    match publish::publish_run(layout, id, rebaseline) {
        Ok(evaluation) => {
            print!("{}", publish::render_run_verdict(&evaluation.verdict));
            println!(
                "published {} from run {id}; commit the scoreboard and the ceilings",
                layout.scoreboard().display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

/// Print one nah case's parity result and the plan it was classified from.
fn show_nah_case(layout: &Layout, id: &str) -> ExitCode {
    let (cases, digest, nah_commit) = match run::load_nah(layout) {
        Ok(loaded) => loaded,
        Err(e) => return fail(e),
    };
    let cases: Vec<_> = cases
        .into_iter()
        .filter(|load| matches!(load, CaseLoad::Ok(case) if case.id == id))
        .collect();
    if cases.is_empty() {
        eprintln!("effinterp-bench: no case with id {id:?}");
        return ExitCode::from(1);
    }
    let engine = Engine::new().with_causality_detail(true);
    let analyses: Vec<_> = cases
        .iter()
        .filter_map(|load| match load {
            CaseLoad::Ok(case) => Some((case.analysis_subject(), case.observation.clone())),
            CaseLoad::Malformed { .. } => None,
        })
        .collect();
    let report = run_corpus(&engine, cases, digest, nah_commit);
    for (case, (subject, observation)) in report.cases.iter().zip(analyses) {
        println!("{}", serde_json::to_string_pretty(case).unwrap());
        let resolver = observation.as_deref().map(FixtureResolver::new);
        let observations = observation
            .clone()
            .map(|fixture| std::sync::Arc::new(FixtureObservations::new(fixture)));
        let plan = engine.analyze_with_observations(
            &subject,
            None,
            resolver
                .as_ref()
                .map(|resolver| resolver as &dyn SourceResolver),
            observations
                .clone()
                .map(|observations| observations as std::sync::Arc<dyn ObservationResolver>),
        );
        if let Ok(plan) = plan {
            println!("{}", serde_json::to_string_pretty(&plan).unwrap());
        }
        // The requests this case made and the fixture could not answer, in the
        // order the corpus owner needs them: source bytes and path facts alike.
        let undeclared: std::collections::BTreeSet<_> = resolver
            .iter()
            .flat_map(|resolver| resolver.undeclared())
            .chain(
                observations
                    .iter()
                    .flat_map(|observations| observations.undeclared()),
            )
            .collect();
        if !undeclared.is_empty() {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "undeclared": undeclared }))
                    .unwrap()
            );
        }
    }
    ExitCode::SUCCESS
}
