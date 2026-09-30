//! Durable run records: what a verdict may trust, what publication refuses,
//! and what a resume repeats. Every run here is a hand-built record in a
//! fixture tree; no analyzer, corpus, or network is touched.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use effinterp_bench::bench::score::{
    AdversarialScore, ExeShare, Invocation, SCOREBOARD_SCHEMA, Scoreboard, SourceScore, to_json,
};
use effinterp_bench::fingerprint;
use effinterp_bench::latency::machine::Machine;
use effinterp_bench::nah::report::{Ceilings, Parity};
use effinterp_bench::repos::expectations::Matched;
use effinterp_bench::repos::isolate::{BinaryIdentity, IsolateStatus};
use effinterp_bench::repos::score::{
    Checkpoints, Diagnostics, EntryBuckets, RepoRow, ReposSection, ResourceMix, score_repos,
};
use effinterp_bench::run::publish;
use effinterp_bench::run::{
    self, FileLock, Layout, Plane, Provenance, RUN_SCHEMA, RepoUnit, RunManifest, Selection, State,
    Status,
};
use tempfile::TempDir;

const REPO: &str = "owner/repo";

fn row() -> RepoRow {
    RepoRow {
        status: IsolateStatus::Analyzed,
        entrypoints: 2,
        effects: 3,
        diagnostics: Some(Default::default()),
        real_entry_nonempty: true,
        recall: Matched {
            matched: 1,
            total: 1,
        },
        facts: Matched {
            matched: 1,
            total: 2,
        },
        forbidden_hits: 0,
        buckets: EntryBuckets::default(),
        resource_mix: ResourceMix::default(),
        wall_ms: 10,
        peak_rss_kb: 10,
    }
}

fn repos(digest: &str, row: RepoRow) -> ReposSection {
    ReposSection {
        corpus_digest: digest.into(),
        selected: Vec::new(),
        repos: BTreeMap::from([(REPO.to_string(), row)]),
        understood_share: 0.0,
        strata: BTreeMap::new(),
        unlocked: None,
    }
}

fn board() -> Scoreboard {
    let mut source = SourceScore::default();
    source.buckets.complete.weighted_share = 0.5;
    source.buckets.gap.weighted_share = 0.5;
    source.top_unmodeled = (0..21)
        .map(|i| ExeShare {
            exe: format!("exe{i:02}"),
            any_share: 0.05,
            unique: 1,
            sole_share: 0.021 - 0.001 * i as f64,
        })
        .collect();
    Scoreboard {
        schema: SCOREBOARD_SCHEMA.into(),
        correctness: effinterp_bench::bench::score::Correctness {
            corpus_digest: "d".into(),
            semantic: Some(effinterp_bench::layered::SemanticScore {
                cases: 1,
                passed: 1,
                ..Default::default()
            }),
            adversarial: Some(AdversarialScore::default()),
            parity: Some(Parity::default()),
        },
        coverage: Invocation {
            corpus_digest: "d".into(),
            sources: BTreeMap::from([("swe".to_string(), source)]),
        },
        repos: Some(repos("r", row())),
        performance: Default::default(),
        provenance: BTreeMap::new(),
    }
}

struct Fixture {
    _dir: TempDir,
    layout: Layout,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        for (path, content) in [
            ("bench/invocation/FIXTURES.json", "{}\n"),
            ("corpus/FIXTURES.json", "{}\n"),
            ("bench/repos/corpus.toml", "repo = []\n"),
            ("bench/repos/expectations/.keep", ""),
        ] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        let ceilings = Ceilings {
            total: BTreeMap::from([("missing_effect".into(), 1)]),
            per_guard: BTreeMap::new(),
        };
        fs::create_dir_all(root.join("bench/nah")).unwrap();
        fs::write(
            root.join("bench/nah/ceilings.json"),
            serde_json::to_string_pretty(&ceilings).unwrap(),
        )
        .unwrap();
        fs::write(root.join("bench/scoreboard.json"), to_json(&board())).unwrap();
        fs::write(root.join("bench/scoreboard.md"), "baseline markdown\n").unwrap();
        let built_from = fingerprint::compute_source_fingerprint(&root).unwrap();
        Fixture {
            _dir: dir,
            layout: Layout {
                root,
                built_from,
                session_corpus: None,
            },
        }
    }

    fn baseline_bytes(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            fs::read(self.layout.scoreboard()).unwrap(),
            fs::read(self.layout.scoreboard_md()).unwrap(),
            fs::read(self.layout.ceilings()).unwrap(),
        )
    }

    fn run_directory(&self, id: &str) -> PathBuf {
        self.layout
            .run_directory(&run::validate_run_id(id).unwrap())
    }

    /// A complete, sealed invocation+repos run whose invocation and repos
    /// records are `edit`ed copies of the baseline board.
    fn run(&self, id: &str, edit: impl FnOnce(&mut Scoreboard)) -> PathBuf {
        self.run_groups(id, edit, vec![Plane::Coverage, Plane::Repositories])
    }

    fn run_groups(
        &self,
        id: &str,
        edit: impl FnOnce(&mut Scoreboard),
        planes: Vec<Plane>,
    ) -> PathBuf {
        let dir = self.run_directory(id);
        fs::create_dir_all(dir.join("repos")).unwrap();
        let mut measured = board();
        edit(&mut measured);
        let section = measured.repos.take().unwrap();
        let manifest = RunManifest {
            schema: RUN_SCHEMA.into(),
            run_id: id.into(),
            started_at: "2026-09-16T12:00:00Z".into(),
            selection: Selection {
                planes: planes.clone(),
                ..Default::default()
            },
            compat: self
                .layout
                .compat(self.layout.source_fingerprint().unwrap())
                .unwrap(),
            provenance: Provenance {
                // The binary that measured is gone; a verdict must not need it.
                binary: BinaryIdentity {
                    path: "/nonexistent/effinterp-bench".into(),
                    size: 123,
                    hash: effinterp_proto::content_digest(b"recorded binary"),
                },
                engine_version: "e".into(),
                model_set: "m".into(),
                git_head: None,
                machine: Machine::default(),
            },
        };
        run::write_bench_record(&dir.join("manifest.json"), &manifest).unwrap();
        if planes.contains(&Plane::Coverage) {
            run::write_bench_record(&dir.join("coverage.json"), &measured).unwrap();
        }
        if planes.contains(&Plane::Correctness) {
            run::write_bench_record(&dir.join("correctness.json"), &measured).unwrap();
        }
        for (name, row) in &section.repos {
            let unit = RepoUnit {
                row: row.clone(),
                diagnostics: Diagnostics {
                    exit_code: Some(0),
                    signal: None,
                    timed_out: false,
                    stderr_tail: String::new(),
                    stderr_truncated: false,
                },
            };
            run::write_bench_record(&dir.join("repos").join(run::repo_unit_name(name)), &unit)
                .unwrap();
        }
        run::write_bench_record(&dir.join("repos.json"), &section).unwrap();
        run::write_bench_record(&dir.join("seal.json"), &run::seal(&dir, &planes).unwrap())
            .unwrap();
        self.state(id, Status::Complete);
        dir
    }

    fn state(&self, id: &str, status: Status) {
        let state = State {
            status,
            pid: 1,
            updated_at: "2026-09-16T12:30:00Z".into(),
            completed_planes: run::read_bench_record::<RunManifest>(
                &self.run_directory(id).join("manifest.json"),
            )
            .unwrap()
            .selection
            .planes,
            repo_units: 1,
            error: None,
        };
        run::write_bench_record(&self.run_directory(id).join("state.json"), &state).unwrap();
    }
}

fn lose_real_entry(board: &mut Scoreboard) {
    board
        .repos
        .as_mut()
        .unwrap()
        .repos
        .get_mut(REPO)
        .unwrap()
        .real_entry_nonempty = false;
}

/// The bug this replaces: a failing gate still rewrote the baseline. Now a
/// failed publication leaves every baseline byte alone and still records the
/// verdict, computed without the analyzer that measured the run.
#[test]
fn failed_publication_preserves_baseline_bytes() {
    let fx = Fixture::new();
    fx.run("r1", lose_real_entry);
    let before = fx.baseline_bytes();
    let error = publish::publish_run(&fx.layout, "r1", false)
        .err()
        .expect("operation must fail");
    assert!(error.contains("not eligible"), "{error}");
    assert_eq!(fx.baseline_bytes(), before);
    let verdicts: Vec<_> = fs::read_dir(fx.run_directory("r1").join("verdicts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(verdicts.len(), 1);
    let verdict: publish::RunVerdict = run::read_bench_record(&verdicts[0]).unwrap();
    assert!(!verdict.eligible && !verdict.historical.passed);
    assert!(
        verdict
            .historical
            .rules
            .iter()
            .any(|r| r.rule.starts_with("(h)") && !r.failures.is_empty())
    );

    // The same record, unchanged, is published with its provenance.
    fx.run("r2", |_| {});
    publish::publish_run(&fx.layout, "r2", false).unwrap();
    let published: Scoreboard =
        serde_json::from_slice(&fs::read(fx.layout.scoreboard()).unwrap()).unwrap();
    assert_eq!(published.provenance["repositories"].run_id, "r2");
    assert_eq!(published.provenance["coverage"].run_id, "r2");
    assert!(
        published.provenance["repositories"].binary_hash
            == effinterp_proto::content_digest(b"recorded binary")
    );
    assert_ne!(fs::read(fx.layout.scoreboard_md()).unwrap(), before.1);
}

/// A record whose identity no longer matches the tree, or a binary not built
/// from the tree, passes historically but cannot publish.
#[test]
fn stale_identity_blocks_publication() {
    let fx = Fixture::new();
    // Running the session extractor creates bytecode, not a new analyzer build.
    let cache = fx.layout.root.join("bench/tools/__pycache__");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("session_calls.pyc"), b"generated bytecode").unwrap();
    fx.layout.verify_build_matches_tree().unwrap();
    let dir = fx.run("r1", |_| {});
    let mut manifest: RunManifest = run::read_bench_record(&dir.join("manifest.json")).unwrap();
    manifest.compat.source_fingerprint = "blake3:someone-else".into();
    run::write_bench_record(&dir.join("manifest.json"), &manifest).unwrap();
    let planes = [Plane::Coverage, Plane::Repositories];
    run::write_bench_record(&dir.join("seal.json"), &run::seal(&dir, &planes).unwrap()).unwrap();
    let error = publish::publish_run(&fx.layout, "r1", false)
        .err()
        .expect("operation must fail");
    assert!(error.contains("stale: source fingerprint"), "{error}");
    let run = publish::load_recorded_run(&fx.layout, "r1").unwrap();
    let verdict = publish::evaluate_run_verdict(&fx.layout, &run, false)
        .unwrap()
        .verdict;
    assert!(verdict.historical.passed && !verdict.compatibility.compatible);

    let stale_binary = Layout {
        built_from: "blake3:older".into(),
        ..fx.layout.clone()
    };
    let error = publish::publish_run(&stale_binary, "r1", false)
        .err()
        .expect("operation must fail");
    assert!(error.contains("rebuild first"), "{error}");

    // A Linux address-space cap and a sampled Mac resident-memory budget
    // must not be treated as the same measurement configuration.
    let dir = fx.run("other-memory-policy", |_| {});
    let mut manifest: RunManifest = run::read_bench_record(&dir.join("manifest.json")).unwrap();
    manifest.compat.config.memory_enforcement = "other-platform-policy".into();
    run::write_bench_record(&dir.join("manifest.json"), &manifest).unwrap();
    run::write_bench_record(&dir.join("seal.json"), &run::seal(&dir, &planes).unwrap()).unwrap();
    let measured = publish::load_recorded_run(&fx.layout, "other-memory-policy").unwrap();
    let verdict = publish::evaluate_run_verdict(&fx.layout, &measured, false)
        .unwrap()
        .verdict;
    assert!(verdict.historical.passed && !verdict.compatibility.compatible);
}

/// Incomplete, edited, or unsealed records are refused instead of read.
#[test]
fn incomplete_or_corrupt_records_are_refused() {
    let fx = Fixture::new();
    let dir = fx.run("r1", |_| {});
    fx.state("r1", Status::Interrupted);
    let error = publish::load_recorded_run(&fx.layout, "r1")
        .err()
        .expect("operation must fail");
    assert!(
        error.contains("interrupted") && error.contains("--resume r1"),
        "{error}"
    );
    fx.state("r1", Status::Complete);
    publish::load_recorded_run(&fx.layout, "r1").unwrap();

    // A unit rewritten after sealing, even to valid JSON, breaks the seal.
    let unit_path = dir.join("repos").join(run::repo_unit_name(REPO));
    let mut unit: RepoUnit = run::read_bench_record(&unit_path).unwrap();
    unit.row.facts.matched = 2;
    run::write_bench_record(&unit_path, &unit).unwrap();
    let error = publish::load_recorded_run(&fx.layout, "r1")
        .err()
        .expect("operation must fail");
    assert!(error.contains("seal"), "{error}");

    // A hand-edited envelope fails its own content hash.
    let text = fs::read_to_string(&unit_path).unwrap();
    fs::write(&unit_path, text.replace("\"matched\": 2", "\"matched\": 3")).unwrap();
    let error = run::read_bench_record::<RepoUnit>(&unit_path).expect_err("operation must fail");
    assert!(error.contains("corrupt"), "{error}");

    assert!(publish::load_recorded_run(&fx.layout, "../r1").is_err());
    assert!(publish::load_recorded_run(&fx.layout, "missing").is_err());
}

/// A moved scope used to be eligible because its drift rules all skipped.
/// Re-baselining must be explicit and cannot excuse a regression in an
/// unchanged plane; once acknowledged, the clean scope lands with provenance.
#[test]
fn a_new_scope_requires_rebaseline_and_cannot_bypass_other_failures() {
    let fx = Fixture::new();
    let new_scope = |board: &mut Scoreboard| {
        board.repos.as_mut().unwrap().corpus_digest = "r2".into();
    };
    fx.run("r1", |b| {
        new_scope(b);
        b.coverage.sources.get_mut("swe").unwrap().failures.panic = 1;
    });
    let before = fx.baseline_bytes();
    let error = publish::publish_run(&fx.layout, "r1", true)
        .err()
        .expect("operation must fail");
    assert!(error.contains("not eligible"), "{error}");
    assert_eq!(fx.baseline_bytes(), before);
    let run = publish::load_recorded_run(&fx.layout, "r1").unwrap();
    let verdict = publish::evaluate_run_verdict(&fx.layout, &run, true)
        .unwrap()
        .verdict;
    assert_eq!(verdict.historical.new_scope, vec![Plane::Repositories]);
    assert!(
        verdict
            .historical
            .rules
            .iter()
            .any(|r| r.rule.starts_with("(b)") && !r.failures.is_empty())
    );
    assert!(
        verdict
            .historical
            .rules
            .iter()
            .any(|r| r.rule.starts_with("(h)") && r.skipped.is_some())
    );

    fx.run("r2", new_scope);
    let before = fx.baseline_bytes();
    let run = publish::load_recorded_run(&fx.layout, "r2").unwrap();
    let verdict = publish::evaluate_run_verdict(&fx.layout, &run, false)
        .unwrap()
        .verdict;
    assert!(verdict.historical.passed && !verdict.eligible);
    let blocker = verdict.blockers.join("; ");
    assert!(
        blocker.contains("repositories")
            && blocker.contains("baseline digest r")
            && blocker.contains("run digest r2")
            && blocker.contains("--rebaseline"),
        "{blocker}"
    );
    let rendered = publish::render_run_verdict(&verdict);
    assert!(
        rendered.contains("skip (h)") && rendered.contains("eligible: no"),
        "{rendered}"
    );
    let error = publish::publish_run(&fx.layout, "r2", false)
        .err()
        .expect("new scope must require acknowledgment");
    assert!(error.contains("--rebaseline"), "{error}");
    assert_eq!(fx.baseline_bytes(), before);

    let preview = publish::evaluate_run_verdict(&fx.layout, &run, true)
        .unwrap()
        .verdict;
    assert!(preview.eligible);
    assert!(publish::render_run_verdict(&preview).contains("acknowledged by --rebaseline"));
    publish::publish_run(&fx.layout, "r2", true).unwrap();
    let published: Scoreboard =
        serde_json::from_slice(&fs::read(fx.layout.scoreboard()).unwrap()).unwrap();
    assert_eq!(published.repos.unwrap().corpus_digest, "r2");
    assert_eq!(published.provenance["repositories"].run_id, "r2");
    let ceilings: Ceilings =
        serde_json::from_slice(&fs::read(fx.layout.ceilings()).unwrap()).unwrap();
    assert_eq!(ceilings.total["missing_effect"], 1);
}

struct Recorded {
    saved: BTreeMap<String, RepoRow>,
    stored: Vec<String>,
}

impl Checkpoints for Recorded {
    fn load(&self, name: &str) -> Result<Option<RepoRow>, String> {
        Ok(self.saved.get(name).cloned())
    }

    fn store(&mut self, name: &str, row: &RepoRow, _: &Diagnostics) -> Result<(), String> {
        self.stored.push(name.to_string());
        self.saved.insert(name.to_string(), row.clone());
        Ok(())
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A resumed repos plane analyzes only the repositories without a recorded
/// unit, and never checks the recorded ones out again. The one repository
/// that does run ends as a recorded failure (this test binary is no
/// analyzer), which is a completed measurement, not an error of the run.
#[test]
fn resume_runs_only_missing_repositories() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let corpus = tmp.path().join("corpus");
    fs::create_dir_all(corpus.join("expectations")).unwrap();
    // Both repositories are already checked out at their pinned SHA.
    let mut toml = String::new();
    for name in ["a/one", "b/two"] {
        let checkout = cache.join(name.replace('/', "__"));
        fs::create_dir_all(&checkout).unwrap();
        git(&checkout, &["init", "-q"]);
        git(
            &checkout,
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "pin",
            ],
        );
        let sha = git(&checkout, &["rev-parse", "HEAD"]);
        toml.push_str(&format!(
            "[[repo]]\nname = \"{name}\"\nurl = \"{}\"\nsha = \"{sha}\"\nlanguage = \"python\"\nshapes = [\"cli\"]\nera = \"new\"\nsplit = \"public\"\nexpectations = \"none\"\n\n",
            checkout.display()
        ));
    }
    fs::write(corpus.join("corpus.toml"), toml).unwrap();
    let mut recorded = Recorded {
        saved: BTreeMap::from([("a/one".to_string(), row())]),
        stored: Vec::new(),
    };
    let modified = |name: &str| fs::metadata(cache.join(name)).unwrap().modified().unwrap();
    let one_before = modified("a__one");
    let section = score_repos(&corpus, &cache, &[], None, None, &mut recorded).unwrap();
    assert_eq!(recorded.stored, vec!["b/two".to_string()]);
    assert_eq!(section.repos["a/one"], row());
    assert!(section.repos["b/two"].status.is_failure());
    assert_eq!(modified("a__one"), one_before);

    // The run lock is exclusive: a second measuring process is refused.
    let lock = FileLock::acquire(&tmp.path().join("lock")).unwrap();
    assert!(FileLock::acquire(&tmp.path().join("lock")).is_err());
    drop(lock);
    FileLock::acquire(&tmp.path().join("lock")).unwrap();
}

/// Publishing one group must not publish incidental results or ratchet another group's gate.
#[test]
fn correctness_and_coverage_publish_independently() {
    let fx = Fixture::new();
    let baseline = board();
    let ceilings = fs::read(fx.layout.ceilings()).unwrap();
    fx.run_groups(
        "coverage-only",
        |b| {
            b.correctness
                .semantic
                .as_mut()
                .unwrap()
                .failures
                .insert("unmeasured".into(), "must not publish".into());
            b.correctness.parity.as_mut().unwrap().classes.insert(
                effinterp_bench::nah::classify::ParityClass::MissingEffect,
                99,
            );
        },
        vec![Plane::Coverage],
    );
    publish::publish_run(&fx.layout, "coverage-only", false).unwrap();
    let published: Scoreboard =
        serde_json::from_slice(&fs::read(fx.layout.scoreboard()).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(&published.correctness).unwrap(),
        serde_json::to_value(&baseline.correctness).unwrap()
    );
    assert_eq!(fs::read(fx.layout.ceilings()).unwrap(), ceilings);
    assert!(published.provenance.contains_key("coverage"));
    assert!(!published.provenance.contains_key("correctness"));

    fx.run_groups(
        "correctness-only",
        |b| {
            b.coverage.sources.clear();
            b.correctness.semantic.as_mut().unwrap().cases = 2;
            b.correctness.semantic.as_mut().unwrap().passed = 2;
        },
        vec![Plane::Correctness],
    );
    publish::publish_run(&fx.layout, "correctness-only", false).unwrap();
    let published: Scoreboard =
        serde_json::from_slice(&fs::read(fx.layout.scoreboard()).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(&published.coverage).unwrap(),
        serde_json::to_value(&baseline.coverage).unwrap()
    );
    assert_eq!(published.correctness.semantic.as_ref().unwrap().passed, 2);
    assert_eq!(published.provenance["coverage"].run_id, "coverage-only");
    assert_eq!(
        published.provenance["correctness"].run_id,
        "correctness-only"
    );
}
