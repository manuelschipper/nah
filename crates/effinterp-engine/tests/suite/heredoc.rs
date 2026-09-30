#![allow(clippy::disallowed_macros)]

use effinterp_engine::{Engine, default_limits};
use effinterp_proto::{
    AttrValue, BoundaryClass, ExecutionRealm, ExecutionStream, Plan, ProvenanceKind, ResourceExpr,
    ResourceIdentity, Subject, validate_plan,
};

fn shell(source: &str, cwd: Option<&str>) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: cwd.map(str::to_string),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|error| panic!("invalid plan for {source:?}: {error:?}"));
    plan
}

fn has_fs_effect(plan: &Plan, operation: &str, path: &str) -> bool {
    plan.effects.iter().any(|effect| {
        effect.operation.0 == operation
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
    })
}

fn has_exec(plan: &Plan, prefix: &[&str]) -> bool {
    plan.execution_graph.nodes.iter().any(|node| {
        matches!(
            &node.subject,
            Subject::Exec { argv, .. }
                if argv.iter().map(String::as_str).take(prefix.len()).eq(prefix.iter().copied())
        )
    })
}

fn has_process_exec_effect(plan: &Plan, executable: &str) -> bool {
    plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable: actual,
                        ..
                    }
                } if actual == executable
            )
    })
}

fn exec_count(plan: &Plan, executable: &str) -> usize {
    plan.execution_graph
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                &node.subject,
                Subject::Exec { argv, .. }
                    if argv.first().map(String::as_str) == Some(executable)
            )
        })
        .count()
}

fn exec_node<'a>(plan: &'a Plan, executable: &str) -> &'a effinterp_proto::ExecutionNode {
    plan.execution_graph
        .nodes
        .iter()
        .find(|node| {
            matches!(
                &node.subject,
                Subject::Exec { argv, .. }
                    if argv.first().map(String::as_str) == Some(executable)
            )
        })
        .unwrap_or_else(|| panic!("missing execution node for {executable}"))
}

fn assert_no_parse_error(plan: &Plan) {
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "parse_error"),
        "boundaries: {:?}",
        plan.boundaries
    );
}

#[test]
fn heredoc_brief_reproductions_preserve_effects() {
    let plan = shell("cat <<EOF > /etc/motd\nhi\nEOF", None);
    assert!(has_fs_effect(&plan, "filesystem.write", "/etc/motd"));
    assert_no_parse_error(&plan);

    let plan = shell(
        "python3 - <<PY\nimport shutil; shutil.rmtree(\"/tmp/x\")\nPY",
        None,
    );
    assert!(has_exec(&plan, &["python3", "-"]));
    assert_no_parse_error(&plan);

    let plan = shell("cat > /tmp/out.txt <<'EOF'\nhello $HOME\nEOF", None);
    assert!(has_fs_effect(&plan, "filesystem.write", "/tmp/out.txt"));
    assert!(
        plan.effects
            .iter()
            .all(|effect| effect.operation.0 != "environment.read")
    );
    assert_no_parse_error(&plan);

    let plan = shell(
        "f(){ cat <<EOF\nwe're here\nEOF\nrm -rf /tmp/x\ncat <<EOF\ndon't\nEOF\napt-get install -y docker; }; f",
        None,
    );
    let delete = plan
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if path == "/tmp/x"
                )
        })
        .unwrap();
    assert_eq!(
        delete.attributes.get("recursive"),
        Some(&AttrValue::Bool(true))
    );
    assert!(has_exec(&plan, &["apt-get", "install", "-y", "docker"]));
    assert_no_parse_error(&plan);

    for source in [
        "git commit -m \"$(cat <<'EOF'\nfix: x\nEOF\n)\"",
        "git commit -m \"$(cat <<'EOF'\nfix: ) isn't lost\nEOF\n)\"",
    ] {
        let plan = shell(source, Some("/repo"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "git.ref_update")
        );
        assert_no_parse_error(&plan);
    }

    let plan = shell("ssh host <<EOF\nrm -rf /srv/data\nEOF", None);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "network.connect"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                } if host == "host" && scheme.as_deref() == Some("ssh")
            )
    }));
    assert_no_parse_error(&plan);

    let plan = shell("cat <<\"E\\OF\"\nbody\nE\\OF\nrm -rf /tmp/x", None);
    assert!(has_fs_effect(&plan, "filesystem.delete", "/tmp/x"));
    assert_no_parse_error(&plan);

    for source in [
        "x=\"$(echo $((1<<2)))\"; rm -rf /tmp/x",
        "x=\"$(true # <<EOF\n)\"; rm -rf /tmp/x",
        "x=\"$(cat<<EOF\n)\nEOF\n)\"; rm -rf /tmp/x",
    ] {
        let plan = shell(source, None);
        assert!(has_fs_effect(&plan, "filesystem.delete", "/tmp/x"));
        assert_no_parse_error(&plan);
    }
}

#[test]
fn ansi_c_heredoc_delimiters_preserve_body_quoting_and_source_order() {
    for source in [
        "cat <<$'E\\x4fF'\nhello $HOME\nEOF\nrm -rf /tmp/after-ansi",
        "cat <<E$'\\117'\"F\"\nhello $HOME\nEOF\nrm -rf /tmp/after-ansi",
        "cat <<-$'E\\u004fF'\n\thello $HOME\n\tEOF\nrm -rf /tmp/after-ansi",
        "x=\"$(cat <<$'E\\x4fF'\nhello $HOME\nEOF\n)\"; rm -rf /tmp/after-ansi",
    ] {
        let plan = shell(source, None);
        assert_eq!(
            exec_node(&plan, "cat")
                .streams
                .stdin_value
                .as_ref()
                .map(|value| &value.value),
            Some(&ResourceExpr::Literal {
                value: "hello $HOME\n".to_string()
            }),
            "{source:?}"
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "environment.read"),
            "{source:?}"
        );
        assert!(
            has_fs_effect(&plan, "filesystem.delete", "/tmp/after-ansi"),
            "{source:?}"
        );
        assert_no_parse_error(&plan);
    }
}

#[test]
fn unsupported_ansi_c_heredoc_delimiters_do_not_reinterpret_body_as_commands() {
    for (operator, terminator) in [
        (r#"$'E\qOF'"#, r"E\qOF"),
        (r#"$'E\0OF'"#, "E"),
        (r#"$'\u00e9'"#, "é"),
        (r#"$'\xc3\xa9'"#, "é"),
        (r#"$'\cAEOF'"#, "\u{1}"),
    ] {
        let source = format!(
            "rm /tmp/before-opaque\ncat <<{operator}\nrm -rf /tmp/opaque-body\n{terminator}\nrm -rf /tmp/after-opaque"
        );
        let plan = shell(&source, None);
        assert!(
            !has_fs_effect(&plan, "filesystem.delete", "/tmp/opaque-body"),
            "{source:?}"
        );
        assert!(
            !has_fs_effect(&plan, "filesystem.delete", "/tmp/after-opaque"),
            "{source:?}"
        );
        assert!(has_fs_effect(
            &plan,
            "filesystem.delete",
            "/tmp/before-opaque"
        ));
        assert!(plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "parse_error"
                && boundary.detail.as_deref() == Some("unsupported ANSI-C heredoc delimiter")
        }));
    }

    let source = "rm -rf /tmp/before-malformed\ncat <<$'EOF\nrm -rf /tmp/not-a-command";
    let plan = shell(source, None);
    assert!(has_fs_effect(
        &plan,
        "filesystem.delete",
        "/tmp/before-malformed"
    ));
    assert!(!has_fs_effect(
        &plan,
        "filesystem.delete",
        "/tmp/not-a-command"
    ));
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "parse_error"
            && boundary.detail.as_deref() == Some("unterminated ANSI-C quote")
    }));
}

#[test]
fn crlf_heredoc_terminator_preserves_body_and_following_effect() {
    let plan = shell(
        "cat <<'EOF'\r\nbody\r\nEOF\r\nrm -rf /tmp/after-crlf\r\n",
        None,
    );
    assert_eq!(
        exec_node(&plan, "cat")
            .streams
            .stdin_value
            .as_ref()
            .map(|value| &value.value),
        Some(&ResourceExpr::Literal {
            value: "body\r\n".to_string()
        })
    );
    assert!(has_fs_effect(&plan, "filesystem.delete", "/tmp/after-crlf"));
    assert_no_parse_error(&plan);
}

struct HeredocRng(u64);

impl HeredocRng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545f4914f6cdd1d)
    }
}

fn generated_body(seed: u64) -> String {
    const PARTS: &[&str] = &[
        "'", "\"", "`", "$", "(", ")", "{", "}", "#", "\\", "\n", "EOF", " ", "\t",
    ];
    let mut rng = HeredocRng(seed ^ 0x9e3779b97f4a7c15);
    loop {
        let mut body = String::new();
        for _ in 0..(rng.next() % 32) {
            body.push_str(PARTS[(rng.next() as usize) % PARTS.len()]);
        }
        if !body
            .lines()
            .any(|line| line.trim_start_matches('\t') == "EOF")
        {
            return body;
        }
    }
}

#[test]
fn generated_heredocs_never_swallow_following_effects() {
    for seed in 0..2_000 {
        let body = generated_body(seed);
        let tabbed = body.replace('\n', "\n\t");
        for (source, literal_body) in [
            (format!("cat <<EOF\n{body}\nEOF\nrm -rf /tmp/x\n"), false),
            (format!("cat <<'EOF'\n{body}\nEOF\nrm -rf /tmp/x\n"), true),
            (
                format!("cat <<-EOF\n\t{tabbed}\n\tEOF\nrm -rf /tmp/x\n"),
                false,
            ),
            (
                format!("x=\"$(cat <<EOF\n{body}\nEOF\n)\"; rm -rf /tmp/x\n"),
                false,
            ),
        ] {
            let plan = shell(&source, None);
            assert!(
                has_fs_effect(&plan, "filesystem.delete", "/tmp/x"),
                "seed {seed}: {source:?}"
            );
            if literal_body {
                assert_no_parse_error(&plan);
            }
        }
    }
}

#[test]
fn invalid_heredocs_are_bounded_without_swallowing_prior_or_later_commands() {
    let source = "rm -rf /tmp/a\ncat <<EOF\nbody";
    let plan = shell(source, None);
    assert!(has_fs_effect(&plan, "filesystem.delete", "/tmp/a"));
    let parse_errors = plan
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason.as_str() == "parse_error")
        .collect::<Vec<_>>();
    assert_eq!(parse_errors.len(), 1);
    assert_eq!(parse_errors[0].class, BoundaryClass::ParseFailure);
    assert!(parse_errors[0].provenance.iter().any(|reference| matches!(
        plan.provenance[reference.0 as usize].kind,
        ProvenanceKind::SourceSpan { start, .. } if start == source.find("<<").unwrap() as u32
    )));

    let plan = shell("cat <<\nrm -rf /tmp/z", None);
    assert!(has_fs_effect(&plan, "filesystem.delete", "/tmp/z"));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "parse_error")
            .count(),
        1
    );

    let plan = shell("cat 3<<EOF\nx\nEOF\nrm -rf /tmp/w", None);
    assert!(has_fs_effect(&plan, "filesystem.delete", "/tmp/w"));
    assert!(exec_node(&plan, "cat").streams.stdin_value.is_none());
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unsupported_shell_syntax"
            && boundary.class == BoundaryClass::Unsupported
    }));
}

#[test]
fn multiple_heredoc_bodies_do_not_become_commands() {
    let plan = shell("cat <<A; cat <<B\na\nA\nb\nB", None);
    assert_eq!(exec_count(&plan, "cat"), 2);
    assert!(!has_exec(&plan, &["b"]));
    assert!(!has_exec(&plan, &["B"]));
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "unmodeled_command")
    );
}

#[test]
fn heredocs_work_on_shell_constructs_and_repeated_functions() {
    for source in [
        "<<EOF\n$(rm -rf /tmp/x)\nEOF",
        "EMPTY=\n$EMPTY <<EOF\n$(rm -rf /tmp/x)\nEOF",
        "while read l; do :; done <<EOF\nl\nEOF\nrm -rf /tmp/x",
        "if true; then cat <<EOF\n'\nEOF\nfi; rm -rf /tmp/x",
        "case x in x) cat <<EOF\n'\nEOF\n;; esac; rm -rf /tmp/x",
        "f(){ cat <<EOF\n'\nEOF\n}; f; f; rm -rf /tmp/x",
    ] {
        let plan = shell(source, None);
        assert!(
            has_fs_effect(&plan, "filesystem.delete", "/tmp/x"),
            "{source:?}"
        );
        assert_no_parse_error(&plan);
    }
}

#[test]
fn heredoc_redirections_preserve_pipeline_wiring() {
    let plan = shell("cat <<EOF | sh\nrm -f x\nEOF", None);
    // The heredoc body is executable input to the downstream shell, so
    // analyzing that recovered shell input may add nested execution nodes.
    // The pipeline contract is the stream edge, not a fixed node count.
    assert!(plan.execution_graph.nodes.len() >= 3);
    let cat = plan
        .execution_graph
        .nodes
        .iter()
        .position(|node| matches!(&node.subject, Subject::Exec { argv, .. } if argv[0] == "cat"))
        .unwrap();
    let sh = plan
        .execution_graph
        .nodes
        .iter()
        .position(|node| matches!(&node.subject, Subject::Exec { argv, .. } if argv[0] == "sh"))
        .unwrap();
    let stdin = plan.execution_graph.nodes[sh]
        .streams
        .stdin
        .as_ref()
        .unwrap();
    assert_eq!(stdin.node.0 as usize, cat);
    assert_eq!(stdin.stream, ExecutionStream::Stdout);

    let plan = shell("echo x | cat <<EOF\ny\nEOF", None);
    let cat = plan
        .execution_graph
        .nodes
        .iter()
        .position(|node| matches!(&node.subject, Subject::Exec { argv, .. } if argv[0] == "cat"))
        .unwrap();
    let streams = &plan.execution_graph.nodes[cat].streams;
    assert!(streams.stdin.is_none());
    assert_eq!(
        streams.stdin_value.as_ref().map(|value| &value.value),
        Some(&ResourceExpr::Literal {
            value: "y\n".to_string()
        })
    );
}

#[test]
fn heredoc_values_preserve_quoting_and_redirect_precedence() {
    let plan = shell("cat <<EOF > /etc/motd\nhi\nEOF", None);
    let streams = &exec_node(&plan, "cat").streams;
    assert!(streams.stdin.is_none());
    assert_eq!(
        streams.stdin_value.as_ref().map(|value| &value.value),
        Some(&ResourceExpr::Literal {
            value: "hi\n".to_string()
        })
    );

    let quoted = shell("cat > /tmp/out.txt <<'EOF'\nhello $HOME\nEOF", None);
    assert_eq!(
        exec_node(&quoted, "cat")
            .streams
            .stdin_value
            .as_ref()
            .map(|value| &value.value),
        Some(&ResourceExpr::Literal {
            value: "hello $HOME\n".to_string()
        })
    );
    assert!(
        quoted
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "environment.read")
    );

    let expanded = shell("cat > /tmp/out.txt <<EOF\nhello $HOME\nEOF", None);
    assert!(expanded.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name }
                } if name == "HOME"
            )
    }));
    assert!(matches!(
        exec_node(&expanded, "cat")
            .streams
            .stdin_value
            .as_ref()
            .map(|value| &value.value),
        Some(ResourceExpr::Join { parts })
            if matches!(parts.as_slice(), [
                ResourceExpr::Literal { value: prefix },
                ResourceExpr::Environment { name },
                ResourceExpr::Literal { value: suffix },
            ] if prefix == "hello " && name == "HOME" && suffix == "\n")
    ));

    let file_wins = shell("cat <<EOF </etc/passwd\nx\nEOF", None);
    assert!(exec_node(&file_wins, "cat").streams.stdin_value.is_none());
    assert!(has_fs_effect(&file_wins, "filesystem.read", "/etc/passwd"));

    let heredoc_wins = shell("cat </etc/passwd <<EOF\nx\nEOF", None);
    assert!(exec_node(&heredoc_wins, "cat").streams.stdin.is_none());
    assert!(
        exec_node(&heredoc_wins, "cat")
            .streams
            .stdin_value
            .is_some()
    );

    let here_string = shell("cat <<< hi > /tmp/y", None);
    assert_eq!(
        exec_node(&here_string, "cat")
            .streams
            .stdin_value
            .as_ref()
            .map(|value| &value.value),
        Some(&ResourceExpr::Literal {
            value: "hi\n".to_string()
        })
    );
}

#[test]
fn literal_heredoc_consumers_analyze_their_stdin_subjects() {
    for source in [
        "python3 - <<PY\nimport os; os.remove(\"/tmp/python-x\")\nPY",
        "python3 <<PY\nimport os; os.remove(\"/tmp/python-x\")\nPY",
        "bash <<EOF\nrm -rf /tmp/bash-x\nEOF",
        "node <<EOF\nrequire(\"fs\").rmSync(\"/tmp/node-x\",{recursive:true})\nEOF",
        "ruby - <<EOF\nFile.delete(\"/tmp/ruby-x\")\nEOF",
        "php <<EOF\n<?php unlink(\"/tmp/php-x\");\nEOF",
    ] {
        let plan = shell(source, None);
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "process.code_execution"
                    && effect.attributes.get("source")
                        == Some(&AttrValue::String("stdin".to_string()))),
            "{source:?}"
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            "{source:?}"
        );
        assert!(plan.boundaries.iter().enumerate().all(|(index, boundary)| {
            boundary.reason.as_str() != "dynamic_source"
                && (boundary.reason.as_str() != "unrecoverable_source"
                    || plan.execution_graph.nodes.iter().any(|node| {
                        node.boundary
                            .is_some_and(|reference| reference.0 as usize == index)
                            && node.input.is_some()
                    }))
        }));
    }

    let php_text = shell("php <<EOF\nunlink(\"/tmp/php-x\");\nEOF", None);
    assert!(
        php_text
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "filesystem.delete")
    );

    for source in [
        "psql <<SQL\nDROP TABLE t;\nSQL",
        "psql -h db.example -U app appdb <<SQL\nDROP TABLE t;\nSQL",
        "sqlite3 db.sqlite <<SQL\nDROP TABLE t;\nSQL",
    ] {
        let plan = shell(source, None);
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "database.schema_drop"),
            "{source:?}"
        );
        assert!(
            plan.boundaries
                .iter()
                .all(|boundary| boundary.reason.as_str() != "unrecoverable_source"),
            "{source:?}"
        );
    }

    let remote = shell("ssh host <<EOF\nrm -rf /srv/data\nEOF", Some("/w"));
    assert!(remote.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.realm
                == ExecutionRealm::Remote {
                    endpoint: "host".to_string(),
                }
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/srv/data"
            )
    }));
    assert!(
        remote
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "remote_command")
    );

    let relative = shell("ssh host <<EOF\nrm -rf data\nEOF", Some("/w"));
    let delete = relative
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        delete.realm,
        ExecutionRealm::Remote {
            endpoint: "host".to_string()
        }
    );
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Join { parts }
            if matches!(parts.first(), Some(ResourceExpr::Parameter { name }) if name == "cwd")
    ));

    let remote_bash = shell("ssh host bash <<EOF\nrm -rf /x\nEOF", Some("/w"));
    assert!(
        remote_bash
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecoverable_source")
    );
    assert!(
        !remote_bash
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "remote_command")
    );
    assert!(
        !remote_bash
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );

    let expanded = shell("ssh host <<EOF\nrm -rf $DIR\nEOF", Some("/w"));
    assert!(
        expanded
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "remote_command")
    );
    assert!(
        expanded
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "filesystem.delete")
    );
}

#[test]
fn symbolic_and_competing_heredoc_inputs_stay_bounded() {
    let symbolic = shell("python3 - <<EOF\nprint(\"$HOME\")\nEOF", None);
    assert!(symbolic.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name }
                } if name == "HOME"
            )
    }));
    assert!(
        symbolic
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecoverable_source")
    );
    assert!(symbolic.execution_graph.nodes.iter().all(|node| {
        !matches!(&node.subject, Subject::Source { language, .. } if language == "python")
    }));

    let substitutions = shell(
        "cmd <<A <<B\n$(rm -rf /tmp/a)\nA\n$(rm -rf /tmp/b)\nB",
        None,
    );
    assert!(has_fs_effect(&substitutions, "filesystem.delete", "/tmp/a"));
    assert!(has_fs_effect(&substitutions, "filesystem.delete", "/tmp/b"));
    assert!(
        exec_node(&substitutions, "cmd")
            .streams
            .stdin_value
            .is_some()
    );

    let quoted = shell("cat <<'EOF'\n$(rm -rf /tmp/z)\nEOF", None);
    assert!(!has_fs_effect(&quoted, "filesystem.delete", "/tmp/z"));

    let xargs = shell("xargs rm <<EOF\n/tmp/a\nEOF", None);
    assert!(exec_node(&xargs, "xargs").streams.stdin_value.is_some());
    assert!(exec_node(&xargs, "rm").streams.stdin_value.is_none());
}

#[test]
fn heredoc_consumers_and_here_strings_do_not_parse_error() {
    for source in [
        "bash <<EOF\nbody\nEOF",
        "psql <<SQL\nselect 1;\nSQL",
        "node <<EOF\nbody\nEOF",
        "ruby - <<EOF\nbody\nEOF",
        "cat <<< hello > /tmp/y",
    ] {
        assert_no_parse_error(&shell(source, None));
    }

    for source in [
        "sudo tee /etc/x <<EOF\nbody\nEOF",
        "env FOO=1 tee /etc/x <<EOF\nbody\nEOF",
    ] {
        let plan = shell(source, None);
        assert!(has_fs_effect(&plan, "filesystem.write", "/etc/x"));
        assert_eq!(
            exec_node(&plan, "tee")
                .streams
                .stdin_value
                .as_ref()
                .map(|value| &value.value),
            Some(&ResourceExpr::Literal {
                value: "body\n".to_string()
            }),
            "{source:?}"
        );
        assert_no_parse_error(&plan);
    }

    let plan = shell("cat <<< hello > /tmp/y", None);
    assert!(has_fs_effect(&plan, "filesystem.write", "/tmp/y"));
    assert!(
        plan.effects
            .iter()
            .all(|effect| effect.operation.0 != "filesystem.read")
    );
}

#[test]
fn installer_heredoc_fixtures_preserve_heredoc_regions() {
    const INSTALLERS: &[(&str, &str)] = &[
        (
            "get-docker.sh",
            include_str!("../fixtures/heredoc/installers/get-docker.sh"),
        ),
        (
            "ohmyzsh-install.sh",
            include_str!("../fixtures/heredoc/installers/ohmyzsh-install.sh"),
        ),
        (
            "nodesource-setup_22.sh",
            include_str!("../fixtures/heredoc/installers/nodesource-setup_22.sh"),
        ),
        (
            "ollama-install.sh",
            include_str!("../fixtures/heredoc/installers/ollama-install.sh"),
        ),
        (
            "homebrew-install.sh",
            include_str!("../fixtures/heredoc/installers/homebrew-install.sh"),
        ),
        (
            "volta-install.sh",
            include_str!("../fixtures/heredoc/installers/volta-install.sh"),
        ),
        (
            "ghcup-install.sh",
            include_str!("../fixtures/heredoc/installers/ghcup-install.sh"),
        ),
        (
            "rustup.sh",
            include_str!("../fixtures/heredoc/installers/rustup.sh"),
        ),
        (
            "uv-install.sh",
            include_str!("../fixtures/heredoc/installers/uv-install.sh"),
        ),
    ];
    let mut limits = default_limits();
    limits.insert("max_analysis_steps".to_string(), u64::MAX);
    let engine = Engine::with_limits(limits).unwrap();
    for (name, source) in INSTALLERS {
        let plan = engine
            .analyze(&Subject::Shell {
                source: (*source).to_string(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        match *name {
            "volta-install.sh" => {
                assert_no_parse_error(&plan);
                for command in ["curl", "tar", "mkdir", "mktemp"] {
                    assert!(has_process_exec_effect(&plan, command), "{command}");
                }
                assert!(
                    plan.effects
                        .iter()
                        .any(|effect| effect.operation.0 == "network.download")
                );
            }
            _ => assert_no_parse_error(&plan),
        }
        if *name == "get-docker.sh" {
            let start = source.find("do_install() {").unwrap() as u32;
            assert!(
                plan.execution_graph
                    .nodes
                    .iter()
                    .any(|node| node.source_span.is_some_and(|span| span.start >= start))
            );
        }
        if *name == "ohmyzsh-install.sh" {
            assert!(!has_exec(&plan, &["main"]));
            assert!(has_exec(&plan, &["git"]));
        }
        if *name == "nodesource-setup_22.sh" {
            assert!(has_fs_effect(
                &plan,
                "filesystem.write",
                "/etc/apt/preferences.d/nsolid"
            ));
        }
        if *name == "ollama-install.sh" {
            assert!(has_process_exec_effect(&plan, "systemctl"));
        }
        if *name == "homebrew-install.sh" {
            assert!(has_process_exec_effect(&plan, "uname"));
        }
    }
}

#[test]
fn installer_guards_preserve_effects_with_default_byte_budget() {
    for (name, source, minimum_effects) in [
        (
            "volta",
            include_str!("../fixtures/heredoc/installers/volta-install.sh"),
            90,
        ),
        (
            "rustup",
            include_str!("../fixtures/heredoc/installers/rustup.sh"),
            90,
        ),
        (
            "ollama",
            include_str!("../fixtures/heredoc/installers/ollama-install.sh"),
            480,
        ),
    ] {
        let subject = Subject::Shell {
            source: source.to_string(),
            cwd: None,
            context: Default::default(),
        };
        let (plan, stats) = Engine::new().analyze_with_stats(&subject).unwrap();
        validate_plan(&plan).unwrap();
        eprintln!(
            "{name}: {} effects, {} bytes, {} steps, limits {:?}",
            plan.effects.len(),
            stats.retained_bytes,
            stats.steps,
            plan.boundaries
                .iter()
                .filter_map(|b| b.limit.as_deref())
                .collect::<Vec<_>>()
        );
        assert!(
            plan.effects.len() >= minimum_effects,
            "{name}: {} effects",
            plan.effects.len()
        );
        assert!(
            plan.boundaries
                .iter()
                .all(|boundary| boundary.limit.as_deref() != Some("max_analysis_bytes")),
            "{name}: {:?}",
            plan.boundaries
        );
        assert!(stats.retained_bytes <= default_limits()["max_analysis_bytes"]);
        let mut limits = default_limits();
        limits.insert("max_analysis_bytes".to_string(), 96 * 1024 * 1024);
        let larger = Engine::with_limits(limits)
            .unwrap()
            .analyze(&subject)
            .unwrap();
        assert_eq!(
            plan.effects, larger.effects,
            "{name}: a larger byte budget must not recover lost effects"
        );
    }
}

#[test]
fn heredoc_probe_fixtures_have_no_parse_errors() {
    const PROBES: &[(&str, &str)] = &[
        (
            "heredoc_probes.txt",
            include_str!("../fixtures/heredoc/probes/heredoc_probes.txt"),
        ),
        (
            "heredoc_quote_probes.txt",
            include_str!("../fixtures/heredoc/probes/heredoc_quote_probes.txt"),
        ),
        (
            "heredoc_fn_probes.txt",
            include_str!("../fixtures/heredoc/probes/heredoc_fn_probes.txt"),
        ),
        (
            "silent2_probes.txt",
            include_str!("../fixtures/heredoc/probes/silent2_probes.txt"),
        ),
    ];
    let mut count = 0;
    for (file, contents) in PROBES {
        for block in contents.split("### ").skip(1) {
            let (name, source) = block.split_once('\n').unwrap();
            count += 1;
            let plan = shell(source, None);
            assert!(
                plan.boundaries
                    .iter()
                    .all(|boundary| boundary.reason.as_str() != "parse_error"),
                "{file}:{name}: {:?}",
                plan.boundaries
            );
            if source.contains("rm -rf /tmp/x") && name != "hd-bash-body" {
                assert!(
                    has_fs_effect(&plan, "filesystem.delete", "/tmp/x"),
                    "{file}:{name}"
                );
            }
        }
    }
    assert_eq!(count, 24);
}
