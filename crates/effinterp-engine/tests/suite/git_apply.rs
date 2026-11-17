//! Patch bytes must reach their actual worktree destination without inventing
//! writes in reporting/index-only modes or inventing complete file contents.

use std::collections::BTreeMap;
use std::sync::Arc;

use effinterp_engine::{
    Engine, ObservationBudget, ObservationResolver, SourceRefusal, SourceRequest, SourceResolver,
    SourceResponse, UnavailableReason,
};
use effinterp_proto::{
    AttrValue, Fact, ObservationOutcome, ObservationQuery, ObservationRefusal, PathFact, PathKind,
    PathTarget, Plan, ResourceExpr, ResourceIdentity, Subject,
};

struct Files(BTreeMap<String, String>);

impl SourceResolver for Files {
    fn siblings(&self, _: &str) -> Option<Vec<String>> {
        None
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.0.get(request.path).map_or_else(
            || SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
            |text| SourceResponse::Source(text.as_bytes().to_vec()),
        )
    }
}

impl ObservationResolver for Files {
    fn observe(&self, query: &ObservationQuery, _: ObservationBudget) -> ObservationOutcome {
        let ObservationQuery::Path { path } = query else {
            return ObservationOutcome::Refused(ObservationRefusal::Unobserved);
        };
        let kind = if path == "/w/.git" {
            PathKind::Directory
        } else if self.0.contains_key(path) {
            PathKind::File
        } else {
            PathKind::Missing
        };
        ObservationOutcome::Path(PathFact {
            entry: path.clone(),
            kind,
            executable: None,
            followed: Fact::Known(PathTarget {
                path: path.clone(),
                kind: Fact::Known(kind),
            }),
        })
    }
}

fn analyze(command: &str, cwd: &str, files: &[(&str, &str)]) -> Plan {
    let files = Arc::new(Files(
        files
            .iter()
            .map(|(path, text)| (path.to_string(), text.to_string()))
            .collect(),
    ));
    let plan = Engine::new()
        .analyze_with_observations(
            &Subject::Shell {
                source: command.into(),
                cwd: Some(cwd.into()),
                context: Default::default(),
            },
            None,
            Some(files.as_ref()),
            Some(files.clone()),
        )
        .unwrap();
    effinterp_proto::validate_plan(&plan).unwrap();
    plan
}

fn create(path: &str, text: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+{text}\n"
    )
}

fn inline(options: &str, patch: &str) -> String {
    format!("git apply {options} <<'EOF'\n{patch}EOF")
}

fn writes(plan: &Plan) -> Vec<(&str, &str)> {
    plan.effects
        .iter()
        .filter_map(|effect| {
            if !matches!(
                effect.operation.as_str(),
                "filesystem.create" | "filesystem.write" | "filesystem.delete" | "filesystem.move"
            ) {
                return None;
            }
            let ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } = &effect.resource
            else {
                panic!("patch target is not a file");
            };
            Some((effect.operation.as_str(), path.as_str()))
        })
        .collect()
}

#[test]
fn apply_modes_separate_worktree_index_and_reporting_effects() {
    let patch = create(".claude/settings.json", r#"{"disableAllHooks":true}"#);
    for options in [
        "",
        "--index",
        "-N",
        "--stat --apply",
        "--apply --stat",
        "--numstat --apply",
        "--apply --numstat",
        "--summary --apply",
        "--apply --summary",
        "--check --apply",
        "--apply --check",
        "--apply --stat --check",
        "--ap --sta",
        "--sta --ap",
    ] {
        let plan = analyze(&inline(options, &patch), "/w", &[]);
        assert_eq!(
            writes(&plan),
            [("filesystem.create", "/w/.claude/settings.json")],
            "{options}"
        );
        assert!(
            plan.boundaries.is_empty(),
            "{options}: {:?}",
            plan.boundaries
        );
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "git.index_write"),
            matches!(options, "--index" | "-N")
        );
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.as_str() == "filesystem.create")
            .unwrap();
        assert_eq!(
            effect.attributes.get("resulting_content"),
            Some(&AttrValue::String("{\"disableAllHooks\":true}\n".into()))
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.as_str() == "git.ref_update")
        );
    }
    for options in [
        "--check",
        "--stat",
        "--numstat",
        "--summary",
        "--index --check",
        "--cached --check",
        "--cached",
        "--cached --apply --check",
    ] {
        let plan = analyze(&inline(options, &patch), "/w", &[]);
        assert!(writes(&plan).is_empty(), "{options}");
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "git.index_write"),
            matches!(options, "--cached" | "--cached --apply --check")
        );
    }
    for options in [
        "--3way",
        "--reject",
        "--include=.claude/*",
        "--no-add",
        "--whitespace=fix",
        "--directory",
        "-p",
    ] {
        let plan = analyze(&inline(options, &patch), "/w", &[]);
        assert!(writes(&plan).is_empty(), "{options}");
        assert!(!plan.boundaries.is_empty(), "{options}");
    }
    for prefix in [
        "git --bare",
        "git -C /w -C sub",
        "git -c core.worktree=/other",
        "git --work-tree=/other",
    ] {
        let command = inline("", &patch).replacen("git", prefix, 1);
        let plan = analyze(&command, "/w", &[]);
        assert!(writes(&plan).is_empty(), "{prefix}");
        assert!(!plan.boundaries.is_empty(), "{prefix}");
    }
    let cached = analyze(
        &inline("--cached", &patch).replacen("git", "git -C /w -C sub", 1),
        "/w",
        &[],
    );
    assert!(
        !cached
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "git.index_write")
    );
    assert!(!cached.boundaries.is_empty());
}

#[test]
fn strip_directory_reverse_and_repository_prefix_select_the_file() {
    for (options, path, cwd, expected) in [
        ("-p0", "src/file", "/w", "/w/b/src/file"),
        (
            "-p2 --directory=.claude",
            "ignored/settings.json",
            "/w",
            "/w/.claude/settings.json",
        ),
        ("--directory=sub", "file", "/w/sub", "/w/sub/file"),
        ("", "sub/file", "/w/sub", "/w/sub/file"),
    ] {
        let plan = analyze(&inline(options, &create(path, "new")), cwd, &[]);
        assert_eq!(
            writes(&plan),
            [("filesystem.create", expected)],
            "{options}"
        );
    }
    let ignored = analyze(&inline("", &create("file", "new")), "/w/sub", &[]);
    assert!(writes(&ignored).is_empty());
    for (options, path, cwd, expected) in [
        ("", "b/file", "/w/sub", "/w/sub/file"),
        ("", "b/sub/file", "/w/sub", "/w/sub/file"),
        ("", "sub/file", "/w/sub", "/w/sub/file"),
        ("", "file", "/w/sub", "/w/sub/file"),
        ("", "b/sub/deep/file", "/w/sub/deep", "/w/sub/deep/file"),
        ("-p0", "b/file", "/w/sub", "/w/sub/b/file"),
        ("-p1", "b/sub/file", "/w/sub", "/w/sub/sub/file"),
        ("-p2", "b/sub/file", "/w/sub", "/w/sub/file"),
        ("--directory=other", "b/file", "/w/sub", "/w/sub/other/file"),
        (
            "--directory=sub",
            "b/sub/file",
            "/w/sub",
            "/w/sub/sub/sub/file",
        ),
    ] {
        let patch = format!("--- /dev/null\n+++ {path}\n@@ -0,0 +1 @@\n+new\n");
        let plan = analyze(&inline(options, &patch), cwd, &[]);
        assert_eq!(
            writes(&plan),
            [("filesystem.create", expected)],
            "{options}: {path}"
        );
        assert!(plan.boundaries.is_empty(), "{options}: {path}");
    }
    let delete = "diff --git a/file b/file\ndeleted file mode 100644\n--- a/file\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n";
    let forward = analyze(&inline("", delete), "/w", &[]);
    assert_eq!(writes(&forward), [("filesystem.delete", "/w/file")]);
    let reverse = analyze(&inline("-R", delete), "/w", &[]);
    assert_eq!(writes(&reverse), [("filesystem.create", "/w/file")]);
    assert!(
        reverse
            .effects
            .iter()
            .any(|effect| effect.attributes.get("resulting_content")
                == Some(&AttrValue::String("old\n".into())))
    );
    let rename = "diff --git a/old b/new\nsimilarity index 100%\nrename from old\nrename to new\n";
    assert_eq!(
        writes(&analyze(&inline("-R", rename), "/w", &[])),
        [
            ("filesystem.move", "/w/new"),
            ("filesystem.write", "/w/old")
        ]
    );
    let renamed = analyze(&inline("-R", rename), "/w", &[("/w/new", "retained\n")]);
    assert!(
        renamed
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.write"
                && effect.attributes.get("resulting_content")
                    == Some(&AttrValue::String("retained\n".into())))
    );
}

#[test]
fn observed_patch_and_preimage_prove_the_postimage_without_losing_context() {
    let patch = "--- a/settings.json\n+++ b/settings.json\n@@ -1,3 +1,3 @@\n {\n-  \"disableAllHooks\": false\n+  \"disableAllHooks\": true\n }\n\\ No newline at end of file\n";
    let old = "{\n  \"disableAllHooks\": false\n}";
    for command in [
        "git apply change.patch",
        "git apply < change.patch",
        "git -C /w apply change.patch",
        "git apply --ap --sta change.patch",
    ] {
        let plan = analyze(
            command,
            "/w",
            &[("/w/change.patch", patch), ("/w/settings.json", old)],
        );
        assert_eq!(writes(&plan), [("filesystem.write", "/w/settings.json")]);
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.as_str() == "filesystem.write")
            .unwrap();
        assert_eq!(
            effect.attributes.get("resulting_content"),
            Some(&AttrValue::String(old.replace("false", "true"))),
            "{command}"
        );
    }
    let mismatch = analyze(
        "git apply change.patch",
        "/w",
        &[
            ("/w/change.patch", patch),
            ("/w/settings.json", "different\n"),
        ],
    );
    assert!(
        mismatch
            .effects
            .iter()
            .all(|effect| !effect.attributes.contains_key("resulting_content"))
    );
    let checked = analyze(
        "git apply --check change.patch",
        "/w",
        &[("/w/change.patch", patch)],
    );
    assert!(writes(&checked).is_empty());
    assert!(checked.effects.iter().any(|effect| effect.operation.as_str() == "filesystem.read"
        && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/w/settings.json")));
    let crlf = analyze(&inline("", &create("file", "new\r")), "/w", &[]);
    assert!(
        crlf.effects
            .iter()
            .any(|effect| effect.attributes.get("resulting_content")
                == Some(&AttrValue::String("new\r\n".into())))
    );
    let multi = format!("{}{}", create("one", "first"), create("two", "second"));
    assert_eq!(
        writes(&analyze(&inline("", &multi), "/w", &[])),
        [
            ("filesystem.create", "/w/one"),
            ("filesystem.create", "/w/two")
        ]
    );
    let guessed = analyze(
        "git apply first.patch second.patch",
        "/w/sub",
        &[
            (
                "/w/sub/first.patch",
                "--- /dev/null\n+++ b/sub/one\n@@ -0,0 +1 @@\n+first\n",
            ),
            (
                "/w/sub/second.patch",
                "--- /dev/null\n+++ b/other/two\n@@ -0,0 +1 @@\n+second\n",
            ),
        ],
    );
    assert_eq!(
        writes(&guessed),
        [
            ("filesystem.create", "/w/sub/one"),
            ("filesystem.create", "/w/sub/two")
        ]
    );
}
