#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use effinterp_proto::{AnalysisStatus, BoundaryReason, PartialReason};

use crate::origin_effects;
use effinterp_repo::{EntrypointOutcome, IndexLimits, RepositoryLimits, build_index, save_index};

struct TrackingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

fn record_allocation(bytes: usize) {
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let resized = unsafe { System.realloc(pointer, layout, new_size) };
        if !resized.is_null() {
            if new_size >= layout.size() {
                record_allocation(new_size - layout.size());
            } else {
                LIVE_BYTES.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        resized
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn temp_root(tag: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(tag);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn write(root: &Path, path: &str, content: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn dense_python(root: &Path, calls: usize) {
    let mut app = String::from("#!/usr/bin/env python3\nfrom dense import wipe\n");
    for index in 0..calls {
        app.push_str(&format!("wipe({index})\n"));
    }
    write(root, "app.py", &app);
    write(
        root,
        "dense.py",
        "import os\ndef wipe():\n    os.remove('/tmp/shared')\n",
    );
}

fn memo_graph(root: &Path, distinct_functions: usize) {
    write(
        root,
        "app.py",
        "#!/usr/bin/env python3\nfrom dense import run\nrun()\n",
    );
    let mut dense = String::from("import os\ndef leaf():\n    os.remove('/tmp/shared')\n");
    for index in 0..distinct_functions {
        dense.push_str(&format!("def branch_{index}():\n    leaf()\n"));
    }
    dense.push_str("def run():\n");
    for index in 0..distinct_functions {
        dense.push_str(&format!("    branch_{index}()\n"));
    }
    write(root, "dense.py", &dense);
}

fn limit_boundaries(index: &effinterp_repo::RepoIndex) -> Vec<&effinterp_repo::ComposedBoundary> {
    index
        .composition("app.py")
        .unwrap()
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason == BoundaryReason::LIMIT_SATURATED)
        .collect()
}

#[test]
fn composition_caps_emit_one_named_boundary() {
    let root = temp_root("index-budget-composition-caps");
    dense_python(&root, 12);
    let cases = [
        (
            "repository.max_compose_steps",
            RepositoryLimits {
                max_compose_steps: 3,
                ..RepositoryLimits::default()
            },
        ),
        (
            "repository.max_composed_occurrences",
            RepositoryLimits {
                max_composed_occurrences: 2,
                ..RepositoryLimits::default()
            },
        ),
        (
            "repository.max_composition_depth",
            RepositoryLimits {
                max_composition_depth: 1,
                ..RepositoryLimits::default()
            },
        ),
    ];

    for (expected, repository) in cases {
        let limits = IndexLimits {
            repository,
            ..IndexLimits::default()
        };
        let index = build_index(&root, limits);
        let boundaries = limit_boundaries(&index);
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].limit.as_deref(), Some(expected));
        assert!(matches!(
            &index.snapshot_state,
            AnalysisStatus::Partial { reasons }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    PartialReason::LimitReached { limit, scope }
                        if limit == expected && scope.entrypoints == ["app.py"]
                ))
        ));
    }
}

fn shell_repository(root: &Path, paths: &[&str]) {
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root).unwrap();
    for path in paths {
        write(root, path, &format!("#!/bin/sh\nrm -rf /tmp/{path}\n"));
    }
}

#[test]
fn shared_byte_budget_is_canonical_and_scoped() {
    let root = temp_root("index-budget-canonical-order");
    shell_repository(&root, &["c.sh", "a.sh", "b.sh"]);
    let reference = build_index(&root, IndexLimits::default());
    let first_plan_bytes =
        effinterp_proto::canonical_json(reference.entrypoints[0].plan().unwrap()).len() as u64;
    let first_composition_bytes = reference
        .composition(&reference.entrypoints[0].entrypoint.id)
        .map_or(0, |composition| composition.retained_bytes());
    let limits = IndexLimits {
        repository: RepositoryLimits {
            max_index_bytes: first_plan_bytes
                + first_composition_bytes
                + ["a.sh", "b.sh", "c.sh"]
                    .iter()
                    .map(|path| std::fs::metadata(root.join(path)).unwrap().len())
                    .sum::<u64>(),
            ..RepositoryLimits::default()
        },
        ..IndexLimits::default()
    };

    let first = build_index(&root, limits.clone());
    assert!(
        matches!(
            first.entrypoints[0].outcome,
            EntrypointOutcome::Analyzed { .. }
        ),
        "first canonical entrypoint was not retained at {first_plan_bytes}+{first_composition_bytes} bytes: {:?}",
        first.entrypoints[0].outcome,
    );
    assert!(first.entrypoints[1..].iter().all(|entrypoint| matches!(
        &entrypoint.outcome,
        EntrypointOutcome::LimitReached { limit } if limit == "repository.max_index_bytes"
    )));
    assert!(matches!(
        &first.snapshot_state,
        AnalysisStatus::Partial { reasons }
            if reasons.iter().any(|reason| matches!(
                reason,
                PartialReason::LimitReached { limit, scope }
                    if limit == "repository.max_index_bytes"
                        && !scope.entrypoints.is_empty()
            ))
    ));
    let first_bytes = save_index(&first);

    shell_repository(&root, &["b.sh", "c.sh", "a.sh"]);
    let second_bytes = save_index(&build_index(&root, limits));
    assert_eq!(second_bytes, first_bytes);
}

#[test]
fn total_source_byte_limit_is_reported() {
    let root = temp_root("index-budget-source-bytes");
    dense_python(&root, 2);
    let mut limits = IndexLimits::default();
    limits.crawl.max_total_source_bytes = 1;
    let index = build_index(&root, limits);
    assert!(index.skipped.iter().any(|skip| {
        skip.reason == "crawl.max_total_source_bytes"
            && skip.category == effinterp_repo::SkipCategory::Limit
    }));
}

#[test]
fn dense_composition_peak_live_bytes_stay_below_limit() {
    fn measure(size: usize) -> (usize, u64, usize) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "index_budget::allocator_child_dense_repository",
                "--nocapture",
            ])
            .env("EFFINTERP_ALLOCATOR_CHILD", "1")
            .env("EFFINTERP_DENSE_SIZE", size.to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "allocator child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| {
                let fields = line.strip_prefix("allocator-metrics:")?;
                let mut fields = fields.split(':');
                let actual_size = fields.next()?.parse::<usize>().ok()?;
                let peak = fields.next()?.parse::<usize>().ok()?;
                let steps = fields.next()?.parse::<u64>().ok()?;
                let occurrences = fields.next()?.parse::<usize>().ok()?;
                (actual_size == size).then_some((peak, steps, occurrences))
            })
            .unwrap()
    }

    let (peak_8, steps_8, occurrences_8) = measure(8);
    let (peak_16, steps_16, occurrences_16) = measure(16);
    let (peak_128, steps_128, occurrences_128) = measure(128);
    assert!(peak_16.saturating_mul(2) <= peak_8.saturating_mul(5));
    for (size, steps, occurrences) in [
        (8, steps_8, occurrences_8),
        (16, steps_16, occurrences_16),
        (128, steps_128, occurrences_128),
    ] {
        assert!(steps <= (size as u64 + 2) * 6);
        assert!(occurrences >= size);
    }
    assert!(peak_128 <= 256 << 20);
}

#[test]
fn allocator_child_dense_repository() {
    if std::env::var_os("EFFINTERP_ALLOCATOR_CHILD").is_none() {
        return;
    }
    let size = std::env::var("EFFINTERP_DENSE_SIZE")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let root = temp_root("index-budget-allocator-child");
    memo_graph(&root, size);
    let baseline = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(baseline, Ordering::Relaxed);

    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("app.py").unwrap();
    assert!(
        limit_boundaries(&index).is_empty(),
        "{:?}",
        limit_boundaries(&index)
    );
    assert_eq!(
        composition.occurrence_effects.len(),
        composition.occurrences
    );
    let peak = PEAK_BYTES.load(Ordering::Relaxed).saturating_sub(baseline);
    println!(
        "allocator-metrics:{size}:{peak}:{}:{}",
        composition.budget.steps, composition.occurrences
    );
}

#[test]
fn runaway_js_entrypoint_stays_below_peak_bytes() {
    const CHILD: &str = "EFFINTERP_RUNAWAY_JS_ALLOCATOR_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "index_budget::runaway_js_entrypoint_stays_below_peak_bytes",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let subject = effinterp_proto::Subject::Source { dialect: Some(effinterp_proto::SourceDialect::Js),
        language: "js".into(),
        source: r#"import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
const files = ["a.ts"]; const failures = [];
for (const file of files.sort()) {
	const sourceText = readFileSync(file, "utf8");
	const sourceFile = ts.createSourceFile(file, sourceText, ts.ScriptTarget.Latest, true);

	function checkSpecifier(node) {
		if (!isRelativeJavaScriptSpecifier(node.text)) return;
		const { line, character } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
		failures.push(`${file}:${line + 1}:${character + 1}: ${node.text}`);
	}

	function visit(node) {
		if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier)) {
			checkSpecifier(node.moduleSpecifier);
		} else if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier)) {
			checkSpecifier(node.moduleSpecifier);
		} else if (
			ts.isCallExpression(node) &&
			node.expression.kind === ts.SyntaxKind.ImportKeyword &&
			node.arguments[0] &&
			ts.isStringLiteralLike(node.arguments[0])
		) {
			checkSpecifier(node.arguments[0]);
		} else if (ts.isImportTypeNode(node)) {
			const specifier = getImportTypeSpecifier(node);
			if (specifier) checkSpecifier(specifier);
		}

		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
}
"#.into(),
        cwd: None,
        context: Default::default(),
    };
    let baseline = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(baseline, Ordering::Relaxed);
    let plan = effinterp_engine::Engine::new().analyze(&subject).unwrap();
    effinterp_proto::validate_plan(&plan).unwrap();
    let peak = PEAK_BYTES.load(Ordering::Relaxed).saturating_sub(baseline);
    assert!(peak < 256 * 1024 * 1024, "peak live bytes: {peak}");
}

#[test]
fn discovery_and_extraction_saturation_publish_valid_partial_snapshots() {
    let root = temp_root("index-budget-early-phases");
    dense_python(&root, 2);
    for units in [0, 2, 3] {
        let mut limits = IndexLimits::default();
        limits.repository.max_repo_work_units = units;
        let index = build_index(&root, limits);
        assert!(matches!(
            index.snapshot_state,
            AnalysisStatus::Partial { .. }
        ));
        assert!(
            index
                .skipped
                .iter()
                .any(|skip| skip.category == effinterp_repo::SkipCategory::Limit)
        );
        assert!(
            index
                .entrypoints
                .iter()
                .all(|entry| matches!(entry.outcome, EntrypointOutcome::LimitReached { .. }))
        );
    }
    shell_repository(&root, &["app.sh"]);
    let mut limits = IndexLimits::default();
    limits.crawl.max_skips = 0;
    limits.crawl.max_file_bytes = 100;
    let index = build_index(&root, limits);
    assert!(matches!(index.snapshot_state, AnalysisStatus::Complete));
}

#[test]
fn incremental_candidate_shares_unchanged_summaries_and_compositions() {
    use std::sync::Arc;
    let root = temp_root("index-budget-copy-on-write");
    write(
        &root,
        "a.py",
        "#!/usr/bin/env python3\nfrom util import run\nrun()\n",
    );
    write(&root, "util.py", "import os\ndef run(): os.remove('/a')\n");
    write(
        &root,
        "b.py",
        "#!/usr/bin/env python3\nfrom other import run\nrun()\n",
    );
    write(&root, "other.py", "import os\ndef run(): os.remove('/b')\n");
    let mut index = build_index(&root, IndexLimits::default());
    let module = index.registry.files["other.py"].clone();
    let composition = index.composed["b.py"].clone();
    write(
        &root,
        "util.py",
        "import os\ndef run(): os.remove('/changed')\n",
    );
    let report = effinterp_repo::apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[effinterp_repo::RepoChange::Modified("util.py".into())],
    );
    assert!(matches!(
        report.outcome,
        effinterp_repo::UpdateOutcome::Published
    ));
    assert!(Arc::ptr_eq(&module, &index.registry.files["other.py"]));
    assert!(Arc::ptr_eq(&composition, &index.composed["b.py"]));
}

#[test]
fn single_file_node_saturation_keeps_snapshot_partial() {
    for (language, path, source, expected) in [
        (
            "go",
            "main.go",
            format!(
                "package main\nimport \"os\"\nfunc big() {{ {} }}\nfunc sibling() {{ os.Remove(\"/kept\") }}\nfunc main() {{ sibling(); big() }}\n",
                "println(1);".repeat(300)
            ),
            "max_go_nodes",
        ),
        (
            "rust",
            "main.rs",
            format!(
                "fn big() {{ {} }}\nfn sibling() {{ std::fs::remove_file(\"/kept\"); }}\nfn main() {{ sibling(); big(); }}\n",
                "let x = 1;".repeat(300)
            ),
            "max_rust_nodes",
        ),
        (
            "java",
            "Main.java",
            format!(
                "class Main {{ static void big() {{ int x = 0; {} }} static void sibling() {{ new java.io.File(\"/kept\").delete(); }} \npublic static void main(String[] args) {{ sibling(); big(); }}\n}}",
                "x = 1;".repeat(300)
            ),
            "max_java_nodes",
        ),
    ] {
        let root = temp_root(&format!("index-budget-single-file-{language}"));
        write(&root, path, &source);
        let mut limits = IndexLimits::default();
        limits.engine.insert(expected.into(), 150);
        let index = build_index(&root, limits.clone());
        assert!(!index.entrypoints.is_empty(), "{language}");
        assert!(
            matches!(
                &index.snapshot_state,
                AnalysisStatus::Partial { reasons } if reasons.iter().any(|reason| matches!(
                    reason, PartialReason::LimitReached { limit, scope }
                        if limit == expected && !scope.entrypoints.is_empty()
                ))
            ),
            "{language}: {:?}",
            index.snapshot_state
        );
        let mut incremental = index;
        write(&root, path, &format!("{source}\n"));
        effinterp_repo::apply_changes(
            &mut incremental,
            &root,
            &limits,
            &[effinterp_repo::RepoChange::Modified(path.into())],
        );
        let rebuilt = build_index(&root, limits);
        assert_eq!(incremental.snapshot_state, rebuilt.snapshot_state);
        assert_eq!(
            effinterp_repo::normalize_surface(&incremental),
            effinterp_repo::normalize_surface(&rebuilt)
        );
    }
}

#[test]
fn composed_effect_cap_counts_distinct_identities() {
    let root = temp_root("index-budget-effect-identities");
    write(
        &root,
        "leaf.py",
        "import os\ndef run(): os.remove('/shared')\n",
    );
    write(
        &root,
        "other.py",
        "import os\ndef run(): os.remove('/shared')\ndef late(): os.remove('/late')\n",
    );
    let mut branches = String::from("import leaf, other\n");
    let mut app = String::from("#!/usr/bin/env python3\nimport branches\n");
    const PATHS: u32 = 12;
    for i in 0..PATHS {
        branches.push_str(&format!(
            "def branch_{i}(): {}.run()\n",
            if i % 2 == 0 { "leaf" } else { "other" }
        ));
        app.push_str(&format!("branches.branch_{i}()\n"));
    }
    write(&root, "branches.py", &branches);
    write(&root, "app.py", &app);
    let mut limits = IndexLimits::default();
    limits.repository.max_composed_effects = 1;
    let index = build_index(&root, limits.clone());
    let composition = index.composition("app.py").unwrap();
    assert!(
        limit_boundaries(&index).is_empty(),
        "{:?}",
        composition.boundaries
    );
    assert_eq!(composition.effects.len(), 1);
    assert!(composition.effects[0].effect.id.is_well_formed());
    assert_eq!(composition.effects[0].occurrences, PATHS);
    assert_eq!(composition.occurrence_effects.len(), PATHS as usize);
    assert_eq!(
        composition
            .occurrence_effects
            .iter()
            .map(|o| &o.source_file)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );

    let report = effinterp_repo::effects_of(&index, "app.py").unwrap();
    assert_eq!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .map(|effect| effect.occurrences)
            .sum::<u32>(),
        PATHS
    );
    for file in ["leaf.py", "other.py"] {
        let effects = origin_effects(&index, file, Some("run"));
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].occurrences, PATHS / 2);
        assert_eq!(effects[0].exemplar_paths.len(), 4);
    }

    // Different guards must retain their causal evidence without spending
    // another identity slot for each invocation of the same leaf.
    let guarded = app.replace("branches.branch_", "if gate:\n    branches.branch_");
    write(&root, "app.py", &guarded);
    let guarded_index = build_index(&root, limits.clone());
    let mut incremental = index;
    effinterp_repo::apply_changes(
        &mut incremental,
        &root,
        &limits,
        &[effinterp_repo::RepoChange::Modified("app.py".into())],
    );
    assert_eq!(
        effinterp_repo::normalize_surface(&incremental),
        effinterp_repo::normalize_surface(&guarded_index)
    );
    let guarded_comp = guarded_index.composition("app.py").unwrap();
    assert!(limit_boundaries(&guarded_index).is_empty());
    assert_eq!(guarded_comp.effects.len(), 1);
    assert_eq!(guarded_comp.effects[0].occurrences, PATHS);
    assert_eq!(
        guarded_comp.effects[0].effect.condition,
        Some(effinterp_proto::Condition::Widened)
    );
    let conditions: std::collections::BTreeSet<_> = guarded_comp
        .occurrence_effects
        .iter()
        .map(|occurrence| {
            let condition = occurrence.condition.as_ref().unwrap();
            assert!(!condition.is_widened());
            effinterp_proto::canonical_json(&condition.identity())
        })
        .collect();
    assert_eq!(conditions.len(), PATHS as usize);
    let report = effinterp_repo::effects_of(&guarded_index, "app.py").unwrap();
    let reported_conditions: std::collections::BTreeSet<_> = report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .map(|effect| {
            effinterp_proto::canonical_json(&effect.condition.as_ref().unwrap().identity())
        })
        .collect();
    assert_eq!(reported_conditions, conditions);
    effinterp_proto::validate_repo_query(&report).unwrap();

    // Occurrence truncation must not hide an identity first reached after the cap.
    app.push_str("import other\nother.late()\n");
    write(&root, "app.py", &app);
    limits.repository.max_composed_effects = 2;
    limits.repository.max_composed_occurrences = 3;
    let index = build_index(&root, limits.clone());
    let composition = index.composition("app.py").unwrap();
    assert_eq!(composition.effects.len(), 2);
    assert_eq!(composition.occurrence_effects.len(), 3);
    assert_eq!(composition.occurrences, PATHS as usize + 1);
    assert_eq!(
        composition
            .effects
            .iter()
            .map(|e| e.occurrences)
            .sum::<u32>(),
        PATHS + 1
    );
    assert_eq!(limit_boundaries(&index).len(), 1);
    assert_eq!(
        limit_boundaries(&index)[0].limit.as_deref(),
        Some("repository.max_composed_occurrences")
    );
    let report = effinterp_repo::effects_of(&index, "app.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| effinterp_proto::canonical_json(&e.resource).contains("/late"))
    );
    effinterp_proto::validate_repo_query(&report).unwrap();

    limits.repository.max_composed_effects = 1;
    let index = build_index(&root, limits);
    assert_eq!(index.composition("app.py").unwrap().effects.len(), 1);
    assert!(
        limit_boundaries(&index)
            .iter()
            .any(|b| b.limit.as_deref() == Some("repository.max_composed_effects"))
    );
}

#[test]
fn composed_boundaries_coalesce_with_counts() {
    let root = temp_root("index-budget-boundary-identities");
    write(
        &root,
        "leaf.py",
        "from opaque import stop, again\nimport os\ndef run():\n    stop()\n    again()\n    os.remove('/boundary-cap-effect')\n",
    );
    let mut branches = String::from("import leaf\n");
    let mut collector = String::from("import branches\ndef run():\n");
    for i in (0..8).rev() {
        branches.push_str(&format!("def branch_{i}(): leaf.run()\n"));
        collector.push_str(&format!("    branches.branch_{i}()\n"));
    }
    write(&root, "collector.py", &collector);
    write(
        &root,
        "wrappers.py",
        "import collector\ndef one(): collector.run()\ndef two(): collector.run()\n",
    );
    let app = "#!/usr/bin/env python3\nimport wrappers, leaf\nwrappers.one()\nwrappers.two()\nleaf.run()\n";
    write(&root, "branches.py", &branches);
    write(&root, "app.py", app);
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("app.py").unwrap();
    let boundary = composition
        .boundaries
        .iter()
        .find(|b| b.reason == BoundaryReason::CROSS_MODULE && b.detail.contains("opaque"))
        .unwrap();
    assert_eq!(boundary.occurrences, 34, "{boundary:?}");
    assert_eq!(boundary.exemplar_paths.len(), 4);
    assert_eq!(
        boundary.exemplar_paths,
        vec![
            vec!["app.py", "leaf.py:run", "leaf.py:again"],
            vec!["app.py", "leaf.py:run", "leaf.py:stop"],
            vec![
                "app.py",
                "wrappers.py:one",
                "collector.py:run",
                "branches.py:branch_0",
                "leaf.py:run",
                "leaf.py:again"
            ],
            vec![
                "app.py",
                "wrappers.py:one",
                "collector.py:run",
                "branches.py:branch_0",
                "leaf.py:run",
                "leaf.py:stop"
            ],
        ]
    );
    assert!(
        boundary
            .exemplar_paths
            .windows(2)
            .all(|pair| (pair[0].len(), &pair[0]) < (pair[1].len(), &pair[1]))
    );
    let report = effinterp_repo::effects_of(&index, "app.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|b| b
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("opaque"))
                && b.occurrences == 34
                && b.exemplar_paths.len() == 4)
    );

    let mut limits = IndexLimits::default();
    limits.repository.max_composed_boundaries = 0;
    let limited = build_index(&root, limits);
    let effects = &limited.composition("app.py").unwrap().effects;
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].occurrences, 17);
    let boundaries = &limited.composition("app.py").unwrap().boundaries;
    assert_eq!(boundaries.len(), 1);
    assert_eq!(
        boundaries[0].limit.as_deref(),
        Some("repository.max_composed_boundaries")
    );
}
