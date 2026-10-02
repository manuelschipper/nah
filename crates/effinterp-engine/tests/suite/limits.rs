//! Adversarial limit tests: every configured bound must produce a valid,
//! deterministically bounded plan — never a panic, unbounded output, or
//! silent truncation.
#![allow(clippy::disallowed_types)]

use effinterp_engine::{
    AnalysisLimits, Engine, EngineError, GITHUB_ACTIONS_DRIVER, LimitsError, default_limits,
};
use effinterp_proto::{
    CoverageLevel, ExecutionAssurance, Plan, ProvenanceKind, ResourceExpr, ResourceIdentity,
    Subject, validate_plan,
};

fn with(limit: &str, value: u64) -> Engine {
    let mut limits = default_limits();
    limits.insert(limit.to_string(), value);
    Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
}

fn shell(source: &str) -> Subject {
    Subject::Shell {
        source: source.to_string(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    }
}

fn source(language: &str, source: &str) -> Subject {
    Subject::Source {
        dialect: (language == "js").then_some(effinterp_proto::SourceDialect::Js),
        language: language.to_string(),
        source: source.to_string(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    }
}

fn saturated(plan: &Plan, limit: &str) -> bool {
    plan.boundaries
        .iter()
        .any(|b| b.reason.as_str() == "limit_saturated" && b.limit.as_deref() == Some(limit))
}

fn words(count: usize) -> String {
    "x ".repeat(count)
}

#[test]
fn max_effects_zero_is_bounded() {
    let plan = with("max_effects", 0)
        .analyze(&shell("rm -rf /a /b /c"))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.effects.is_empty());
    assert!(saturated(&plan, "max_effects"));
}

#[test]
fn max_provenance_nodes_one_is_bounded() {
    // Provenance was declared-but-unenforced before central limits landed.
    let plan = with("max_provenance_nodes", 1)
        .analyze(&shell("rm -rf /a && cp /b /c && curl http://x/y"))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.provenance.len() <= 2);
    assert!(saturated(&plan, "max_provenance_nodes"));
}

/// Every zero limit must still produce a valid plan: no effect or boundary may
/// reference a provenance node that was not retained. `max_provenance_nodes=0`
/// used to emit a dangling ProvenanceRef(0) into an empty provenance vector.
#[test]
fn every_zero_limit_is_valid() {
    for lim in default_limits().keys() {
        let plan = with(lim, 0)
            .analyze(&shell(
                "rm -rf /a && cp /b /c && docker exec pg psql -c 'DROP TABLE t'; kubectl delete namespace prod; terraform apply",
            ))
            .unwrap();
        validate_plan(&plan).unwrap_or_else(|e| panic!("{lim}=0 produced an invalid plan: {e:?}"));
        // Every provenance ref an effect carries is in bounds.
        for effect in &plan.effects {
            for r in &effect.provenance {
                assert!(
                    (r.0 as usize) < plan.provenance.len(),
                    "{lim}=0: dangling provenance ref {}",
                    r.0
                );
            }
        }
    }
}

#[test]
fn heredoc_expansion_and_source_limits_keep_valid_following_effects() {
    let plan = with("max_heredoc_expansions", 2)
        .analyze(&shell(
            "cat <<A\n$A $B\nA\ncat <<B\n$C\nB\nrm -rf /tmp/after-heredoc",
        ))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(saturated(&plan, "max_heredoc_expansions"));
    let values = plan
        .execution_graph
        .nodes
        .iter()
        .filter_map(|node| node.streams.stdin_value.as_ref())
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 2);
    assert!(matches!(
        &values[0].value,
        ResourceExpr::Join { parts }
            if !parts.iter().any(|part| matches!(part, ResourceExpr::Unresolved { .. }))
    ));
    assert!(matches!(&values[1].value, ResourceExpr::Unresolved { .. }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/tmp/after-heredoc"
            )
    }));

    let zero = with("max_heredoc_expansions", 0)
        .analyze(&shell("cat <<EOF\nliteral\nEOF"))
        .unwrap();
    validate_plan(&zero).unwrap();
    assert!(saturated(&zero, "max_heredoc_expansions"));
    assert!(zero.execution_graph.nodes.iter().any(|node| {
        matches!(
            node.streams.stdin_value.as_ref().map(|value| &value.value),
            Some(ResourceExpr::Unresolved { .. })
        )
    }));

    let source = with("max_source_bytes", 24)
        .analyze(&shell(
            "bash <<EOF\n0123456789012345678901234567890123456789\nEOF",
        ))
        .unwrap();
    validate_plan(&source).unwrap();
    assert!(saturated(&source, "max_source_bytes"));
}

#[test]
fn long_word_lists_saturate_the_word_budget() {
    let engine = Engine::new().with_causality_detail(true);
    for source in [
        format!("a=({})", words(12_000)),
        format!("true {}", words(12_000)),
    ] {
        let plan = engine.analyze(&shell(&source)).unwrap();
        validate_plan(&plan).unwrap();
        assert!(saturated(&plan, "max_shell_words"));
    }
}

#[test]
fn word_lists_at_the_cap_are_complete() {
    let cap = default_limits()["max_shell_words"] as usize;
    for source in [
        format!("a=({})", words(cap)),
        format!("true {}", words(cap - 1)),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&shell(&source))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(plan.boundaries.is_empty());
        assert!(
            plan.coverage
                .0
                .values()
                .all(|level| level.level == CoverageLevel::Full)
        );
    }
}

#[test]
fn over_cap_array_becomes_unknown() {
    for source in [
        format!("a=({}); rm -rf \"${{a[@]}}\"", words(100)),
        format!(
            "a=({}); a+=({}); rm -rf \"${{a[@]}}\"",
            words(10),
            words(10)
        ),
    ] {
        let plan = with("max_shell_words", 16)
            .analyze(&shell(&source))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(saturated(&plan, "max_shell_words"));
        assert!(plan.effects.len() <= 2);
        assert!(
            plan.execution_graph
                .nodes
                .iter()
                .all(|node| node.argv.len() <= 17)
        );
    }
}

#[test]
fn over_cap_argv_keeps_unknown_tail() {
    let plan = with("max_shell_words", 4)
        .analyze(&shell("rm -rf /a /b /c /d /e"))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(saturated(&plan, "max_shell_words"));
    assert!(plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            effinterp_proto::ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/a"
        )
    }));
    assert!(!plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            effinterp_proto::ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/e"
        )
    }));
}

#[test]
fn over_cap_word_lists_analyze_discarded_tail_substitutions() {
    for source in [
        format!("true {}\"$(rm /danger-after)\"", words(4)),
        format!("a=({}\"$(rm /danger-after)\")", words(5)),
    ] {
        let plan = with("max_shell_words", 4).analyze(&shell(&source)).unwrap();
        validate_plan(&plan).unwrap();
        assert!(saturated(&plan, "max_shell_words"));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    effinterp_proto::ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if path == "/danger-after"
                )
        }));
    }
}

#[test]
fn splices_count_toward_the_cap() {
    let source = format!("a=({}); true \"${{a[@]}}\" \"${{a[@]}}\"", words(10));
    let saturated_plan = with("max_shell_words", 15)
        .analyze(&shell(&source))
        .unwrap();
    validate_plan(&saturated_plan).unwrap();
    assert!(saturated(&saturated_plan, "max_shell_words"));

    let complete_plan = with("max_shell_words", 32)
        .analyze(&shell(&source))
        .unwrap();
    validate_plan(&complete_plan).unwrap();
    assert!(!saturated(&complete_plan, "max_shell_words"));
}

#[test]
fn array_element_provenance_is_the_element_span() {
    let source = "a=(/etc/passwd); cat \"${a[@]}\"";
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&shell(source))
        .unwrap();
    validate_plan(&plan).unwrap();
    let element_start = source.find("/etc/passwd").unwrap() as u32;
    let element_end = element_start + "/etc/passwd".len() as u32;
    let literal_start = source.find("(/etc/passwd)").unwrap() as u32;
    let literal_end = literal_start + "(/etc/passwd)".len() as u32;
    let spans: Vec<_> = plan
        .provenance
        .iter()
        .filter_map(|node| match node.kind {
            ProvenanceKind::SourceSpan { start, end } => Some((start, end)),
            _ => None,
        })
        .collect();
    assert!(spans.contains(&(element_start, element_end)));
    assert!(!spans.contains(&(literal_start, literal_end)));
}

#[test]
fn same_input_and_limits_are_byte_identical() {
    let subject = shell(&format!("a=({})", words(12_000)));
    let engine = Engine::new().with_causality_detail(true);
    let first = effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap());
    let second = effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap());
    assert_eq!(first, second);
}

#[test]
fn max_boundaries_one_is_bounded() {
    let plan = with("max_boundaries", 1)
        .analyze(&shell("mystery-one; mystery-two; mystery-three"))
        .unwrap();
    validate_plan(&plan).unwrap();
    // The cap holds except for the single saturation boundary it records
    // (which must always be emitted so truncation is never silent).
    assert!(plan.boundaries.len() <= 2);
    assert!(saturated(&plan, "max_boundaries"));
}

#[test]
fn max_execution_nodes_zero_is_bounded() {
    let plan = with("max_execution_nodes", 0)
        .analyze(&shell("rm /a; cp /b /c"))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| { boundary.limit.as_deref() == Some("max_execution_nodes") })
    );
}

#[test]
fn execution_fanout_retains_a_widened_node() {
    let plan = with("max_execution_fanout", 1)
        .analyze(&shell("rm /a; cp /b /c"))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.execution_graph.nodes.iter().any(|node| {
            node.assurance == ExecutionAssurance::Widened && node.boundary.is_some()
        })
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.limit.as_deref() == Some("max_execution_fanout"))
    );
}

#[test]
fn depth_refusal_does_not_consume_execution_node_budget() {
    let mut limits = default_limits();
    limits.insert("max_execution_depth".to_string(), 2);
    limits.insert("max_execution_nodes".to_string(), 2);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&shell("env env rm /deep\nrm /shallow"))
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(
        plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    effinterp_proto::ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path }
                    } if path == "/shallow"
                )
        }),
        "the shallow sibling must retain the refused deep transition's budget"
    );
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.limit.as_deref() == Some("max_execution_nodes"))
    );
}

#[test]
fn fanout_refusal_does_not_starve_parent_sibling() {
    let plan = with("max_execution_fanout", 2)
        .analyze(&shell("sh -c 'mystery1; mystery2; mystery3'\nrm /shallow"))
        .unwrap();
    validate_plan(&plan).unwrap();

    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                effinterp_proto::ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path }
                } if path == "/shallow"
            )
    }));
}

#[test]
fn very_large_argv_is_bounded_and_safe() {
    let mut argv = vec!["rm".to_string()];
    argv.extend((0..5000).map(|i| format!("/tmp/file{i}")));
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Exec {
            argv,
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    // max_effects default caps the output; the plan stays valid.
    let cap = default_limits().get("max_effects").copied().unwrap();
    assert!(plan.effects.len() as u64 <= cap + 1);
}

#[test]
fn very_large_source_saturates_bytes_limit() {
    // Over the default max_source_bytes (4 MiB): the whole source is opaque.
    let big = "rm /x\n".repeat(1_000_000);
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&shell(&big))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(saturated(&plan, "max_source_bytes"));

    for (language, code) in [
        ("ruby", "File.delete('/x')"),
        ("rust", r#"fn main() { std::fs::remove_file("/x"); }"#),
        ("js", "require('fs').unlinkSync('/x');"),
    ] {
        let subject = source(language, code);
        let at_limit = with("max_source_bytes", code.len() as u64)
            .analyze(&subject)
            .unwrap();
        validate_plan(&at_limit).unwrap();
        assert!(!saturated(&at_limit, "max_source_bytes"), "{language}");
        assert!(!at_limit.effects.is_empty(), "{language}");

        let over_limit = with("max_source_bytes", code.len() as u64 - 1)
            .analyze(&subject)
            .unwrap();
        validate_plan(&over_limit).unwrap();
        assert!(saturated(&over_limit, "max_source_bytes"), "{language}");
        assert!(over_limit.effects.is_empty(), "{language}");
        assert!(
            !over_limit
                .boundaries
                .iter()
                .any(|boundary| boundary.class == effinterp_proto::BoundaryClass::ParseFailure),
            "{language}"
        );
    }
}

#[test]
fn many_opaque_calls_are_bounded() {
    let source: String = (0..20_000).map(|i| format!("mystery{i}\n")).collect();
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&shell(&source))
        .unwrap();
    validate_plan(&plan).unwrap();
    // The first fan-out refusal widens the remainder instead of minting one
    // execution node for every refused command.
    let cap = default_limits()
        .get("max_execution_nodes")
        .copied()
        .unwrap();
    assert!(plan.execution_graph.nodes.len() as u64 <= cap + 2);
}

#[test]
fn deeply_nested_wrappers_terminate() {
    // env env env ... rm — each env nests the rest; depth-bounded.
    let mut argv: Vec<String> = std::iter::repeat_n("env".to_string(), 50).collect();
    argv.extend(["rm".to_string(), "/x".to_string()]);
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Exec {
            argv,
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.limit.as_deref() == Some("max_execution_depth"))
    );
}

/// The bench `pathological` shape: 500 top-level commands plus a deep
/// `sh -c` chain. Copied so the budget tests do not depend on the bench crate.
fn pathological_source() -> String {
    let mut source = String::new();
    for index in 0..500 {
        source.push_str(&format!(
            "rm -rf /tmp/dir{index} && cp /src/{index} /dst/{index}\n"
        ));
    }
    let mut nested = String::from("rm -rf /deep");
    for _ in 0..40 {
        nested = format!("sh -c \"{}\"", nested.replace('"', "\\\""));
    }
    source.push_str(&nested);
    source.push('\n');
    source
}

/// The shapes a whole-analysis budget has to survive: scale in commands,
/// list length, substitution depth, and redirection count.
fn budget_shapes() -> Vec<String> {
    vec![
        pathological_source(),
        (0..2000)
            .map(|index| format!("cmd{index} && "))
            .collect::<String>()
            + "true",
        {
            let list: String = (0..5000).map(|index| format!("f{index} ")).collect();
            format!("for f in {list}; do rm \"$f\"; done")
        },
        {
            let mut nested = String::from("echo deep");
            for _ in 0..40 {
                nested = format!("$( {nested} )");
            }
            format!("true {nested}")
        },
        (0..500)
            .map(|index| format!("cat <<EOF{index}\nbody\nEOF{index}\n"))
            .collect::<String>(),
    ]
}

/// Every domain reads partial: a refused charge could have belonged to any of
/// them, so absence must never read as safe.
fn all_domains_partial(plan: &Plan) -> bool {
    !plan.coverage.0.is_empty()
        && plan
            .coverage
            .0
            .values()
            .all(|level| level.level != CoverageLevel::Full)
}

fn boundary_with_limit<'a>(plan: &'a Plan, limit: &str) -> Option<&'a effinterp_proto::Boundary> {
    plan.boundaries
        .iter()
        .find(|b| b.reason.as_str() == "limit_saturated" && b.limit.as_deref() == Some(limit))
}

/// Steps count work, so doubling the input may not more than quadruple them:
/// a quadratic loop would show up here long before it stalls a run.
#[test]
fn steps_grow_linearly() {
    let mut limits = default_limits();
    limits.insert("max_analysis_steps".to_string(), u64::MAX);
    limits.insert("max_analysis_bytes".to_string(), u64::MAX);
    limits.insert("max_shell_words".to_string(), 32768);
    let engine = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true);
    let steps = |source: String| engine.analyze_with_stats(&shell(&source)).unwrap().1.steps;

    let chain = |count: usize| "true && ".repeat(count) + "true";
    assert!(steps(chain(16_000)) < 4 * steps(chain(8_000)));

    let array = |count: usize| format!("a=({})", words(count));
    assert!(steps(array(16_000)) < 4 * steps(array(8_000)));
}

/// A step budget too small for any of the pathological shapes saturates by
/// name, degrades every domain, and says in the plan where it stopped.
#[test]
fn tiny_step_budget_saturates_with_its_name() {
    for (index, source) in budget_shapes().into_iter().enumerate() {
        let plan = with("max_analysis_steps", 64)
            .analyze(&shell(&source))
            .unwrap();
        validate_plan(&plan).unwrap();
        let boundary = boundary_with_limit(&plan, "max_analysis_steps").unwrap_or_else(|| {
            panic!(
                "shape {index}: no step saturation boundary: {:?}",
                plan.boundaries
            )
        });
        assert!(!boundary.provenance.is_empty(), "saturation without a span");
        assert!(all_domains_partial(&plan), "a domain still reads complete");
    }
}

#[test]
fn tiny_byte_budget_saturates_with_its_name() {
    for (index, source) in budget_shapes()
        .into_iter()
        .chain([
            format!(
                "docker push registry.example/acme/{}:v2",
                "image".repeat(1000)
            ),
            format!("gh release create {} -R acme/api", "tag".repeat(1000)),
        ])
        .enumerate()
    {
        let plan = with("max_analysis_bytes", 256)
            .analyze(&shell(&source))
            .unwrap();
        validate_plan(&plan).unwrap();
        let boundary = boundary_with_limit(&plan, "max_analysis_bytes")
            .unwrap_or_else(|| panic!("shape {index}: no byte saturation boundary"));
        assert!(
            !boundary.provenance.is_empty(),
            "shape {index}: saturation without a span"
        );
        assert!(all_domains_partial(&plan), "a domain still reads complete");
    }
}

#[test]
fn final_bare_assignment_reports_byte_saturation() {
    let (plan, stats) = with("max_analysis_bytes", 0)
        .analyze_with_stats(&shell("a=x"))
        .unwrap();
    validate_plan(&plan).unwrap();
    let boundary = boundary_with_limit(&plan, "max_analysis_bytes").unwrap();
    assert!(!boundary.provenance.is_empty());
    assert_eq!(stats.retained_bytes, 0);
    assert!(all_domains_partial(&plan));
}

#[test]
fn subject_echo_is_not_charged_but_derived_retention_is() {
    let argument = "x".repeat(2_000_000);
    let subject = Subject::Exec {
        argv: vec![GITHUB_ACTIONS_DRIVER.to_string(), argument.clone()],
        cwd: None,
        context: Default::default(),
    };
    let (_, baseline) = Engine::new()
        .with_causality_detail(true)
        .analyze_with_stats(&Subject::Exec {
            argv: vec![GITHUB_ACTIONS_DRIVER.to_string(), "x".to_string()],
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    let (plan, stats) = with("max_analysis_bytes", baseline.retained_bytes)
        .analyze_with_stats(&subject)
        .unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(plan.subject, subject);
    assert_eq!(stats.retained_bytes, baseline.retained_bytes);
    assert!(stats.retained_bytes < argument.len() as u64);
    assert!(boundary_with_limit(&plan, "max_analysis_bytes").is_none());

    let subject = Subject::Exec {
        argv: vec!["/usr/bin/env".to_string(), argument.clone()],
        cwd: None,
        context: Default::default(),
    };
    let (plan, stats) = with("max_analysis_bytes", 1)
        .analyze_with_stats(&subject)
        .unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(plan.subject, subject);
    assert_eq!(plan.execution_graph.nodes.len(), 1);
    assert_eq!(stats.retained_bytes, 0);
    assert!(boundary_with_limit(&plan, "max_analysis_bytes").is_some());
    assert!(all_domains_partial(&plan));

    let plan = with("max_analysis_bytes", 1)
        .analyze(&Subject::Exec {
            argv: vec!["rm".to_string(), argument],
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(boundary_with_limit(&plan, "max_analysis_bytes").is_some());
    assert!(all_domains_partial(&plan));
}

#[test]
fn large_shell_function_body_spends_the_shared_step_budget() {
    let source = format!("f() {{\n{}}}\nf\n", "true\n".repeat(20_000));
    let plan = with("max_analysis_steps", 64)
        .analyze(&shell(&source))
        .unwrap();
    validate_plan(&plan).unwrap();
    let boundary = boundary_with_limit(&plan, "max_analysis_steps").unwrap();
    assert!(!boundary.provenance.is_empty());
    assert!(all_domains_partial(&plan));
}

#[test]
fn shell_function_expansion_refusal_is_valid() {
    for (limit, value, source) in [
        ("max_analysis_bytes", 0, "f(){ rm /x; }; f"),
        ("max_analysis_steps", 2, "g(){ cp $1 $2; }; g /a /b"),
        (
            "max_analysis_bytes",
            0,
            "f(){ rm /x; }; a=(1 2); f \"${a[@]}\"",
        ),
    ] {
        let plan = with(limit, value).analyze(&shell(source)).unwrap();
        validate_plan(&plan).unwrap();
        let boundary = boundary_with_limit(&plan, limit).unwrap();
        assert!(!boundary.provenance.is_empty());
        assert!(all_domains_partial(&plan));
    }
}

#[test]
fn zero_go_node_cap_saturates_summary_analysis() {
    let plan = with("max_go_nodes", 0)
        .analyze(&source(
            "go",
            "package main\nimport \"os\"\nfunc helper() { os.ReadFile(\"/tmp/x\") }\nfunc main() { helper() }",
        ))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries.iter().any(|boundary| {
            matches!(
                boundary.limit.as_deref(),
                Some("max_go_nodes" | "max_analysis_steps")
            )
        }),
        "Go summary analysis remained complete"
    );
}

#[test]
fn repeated_realm_names_saturate_retained_byte_budget() {
    let name = "x".repeat(10_000);
    let commands = (0..100)
        .map(|index| format!("rm /tmp/f{index}"))
        .collect::<Vec<_>>()
        .join("; ");
    let plan = with("max_analysis_bytes", 100_000)
        .analyze(&shell(&format!(
            "docker run --name {name} alpine sh -c '{commands}'"
        )))
        .unwrap();
    validate_plan(&plan).unwrap();
    let boundary = boundary_with_limit(&plan, "max_analysis_bytes").unwrap();
    assert!(!boundary.provenance.is_empty());
    assert!(all_domains_partial(&plan));
}

#[test]
fn final_python_value_walk_reports_step_saturation() {
    let plan = with("max_analysis_steps", 35)
        .analyze(&source(
            "python",
            "def f(x):\n    return x + x + x + x + x + x + x + x\np = f('/tmp/x')",
        ))
        .unwrap();
    validate_plan(&plan).unwrap();
    let boundary = boundary_with_limit(&plan, "max_analysis_steps").unwrap();
    assert!(!boundary.provenance.is_empty());
    assert!(all_domains_partial(&plan));
}

#[test]
fn shared_frontend_saturation_has_source_provenance_and_no_private_cap() {
    for (language, text, private_limit) in [
        (
            "python",
            "import os\nos.remove('/tmp/x')",
            "max_python_nodes",
        ),
        ("js", "require('fs').readFileSync('/tmp/x')", "max_js_nodes"),
        ("php", "<?php unlink('/tmp/x');", "max_php_nodes"),
        (
            "java",
            "class Main { public static void main(String[] args) { java.nio.file.Files.readString(java.nio.file.Path.of(\"/tmp/x\")); } }",
            "max_java_nodes",
        ),
        ("ruby", "File.read('/tmp/x')", "max_ruby_nodes"),
        (
            "rust",
            "fn main() { std::fs::read_to_string(\"/tmp/x\"); }",
            "max_rust_nodes",
        ),
        (
            "go",
            "package main\nimport \"os\"\nfunc helper() { os.ReadFile(\"/tmp/x\") }\nfunc main() { helper() }",
            "max_go_nodes",
        ),
    ] {
        let plan = with("max_analysis_steps", 0)
            .analyze(&source(language, text))
            .unwrap();
        validate_plan(&plan).unwrap();
        let boundary = boundary_with_limit(&plan, "max_analysis_steps").unwrap();
        assert!(
            boundary.provenance.iter().any(|reference| matches!(
                plan.provenance[reference.0 as usize].kind,
                ProvenanceKind::SourceSpan { .. }
            )),
            "{language} saturation has no source span"
        );
        assert!(
            plan.boundaries
                .iter()
                .all(|boundary| boundary.limit.as_deref() != Some(private_limit)),
            "{language} also named {private_limit}"
        );
    }
}

#[test]
fn default_step_budget_follows_the_pathological_benchmark_rule() {
    assert_eq!(default_limits()["max_analysis_steps"], 32_768);
}

/// A limits map is a closed contract: a forgotten name is not "unlimited" and
/// a misspelled one is not ignored.
#[test]
fn with_limits_rejects_missing_and_unknown_names() {
    let mut missing = default_limits();
    missing.remove("max_analysis_steps");
    assert_eq!(
        Engine::with_limits(missing).err(),
        Some(EngineError::InvalidLimits(LimitsError::Missing(
            "max_analysis_steps".to_string()
        )))
    );

    let mut unknown = default_limits();
    unknown.insert("max_wall_clock_ms".to_string(), 5);
    assert_eq!(
        Engine::with_limits(unknown).err(),
        Some(EngineError::InvalidLimits(LimitsError::Unknown(
            "max_wall_clock_ms".to_string()
        )))
    );

    assert!(Engine::with_limits(default_limits()).is_ok());
}

/// Wall clock is a process backstop, never an analysis limit: no limit name
/// mentions time, and repeated runs of one subject are byte-identical.
#[test]
fn deadline_is_not_a_limit() {
    for name in AnalysisLimits::NAMES {
        assert!(
            !name.contains("time") && !name.contains("deadline") && !name.contains("ms"),
            "{name} names wall clock"
        );
    }
    assert_eq!(default_limits().len(), AnalysisLimits::NAMES.len());

    let engine = Engine::new().with_causality_detail(true);
    let subject = shell(&pathological_source());
    let first = effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap());
    let second = effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap());
    assert_eq!(first, second);
}

#[test]
fn go_step_saturation_is_deterministic() {
    let subject = source(
        "go",
        r#"package main
import "os"
func alpha() { os.Remove("/a") }
func bravo() { os.Remove("/b") }
func charlie() { os.Remove("/c") }
func delta() { os.Remove("/d") }
func echo() { os.Remove("/e") }
func main() { alpha(); bravo(); charlie(); delta(); echo() }
"#,
    );
    let engine = with("max_analysis_steps", 20);
    let expected = effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap());

    for _ in 0..16 {
        let plan = engine.analyze(&subject).unwrap();
        assert!(saturated(&plan, "max_analysis_steps"));
        assert_eq!(effinterp_proto::canonical_json(&plan), expected);
    }
}

#[test]
fn final_gap_index_byte_saturation_rebinds_execution_boundaries() {
    // One simple command and no nested list: every list item draws its own
    // byte allowance past the limit this test sets one byte short.
    let subject = shell("docker exec \"$C\" ssh host \"$CMD\"");
    let (baseline, stats) = Engine::new()
        .with_causality_detail(true)
        .analyze_with_stats(&subject)
        .unwrap();
    assert!(baseline.boundaries.len() > 1);
    assert!(
        baseline
            .execution_graph
            .nodes
            .iter()
            .any(|node| node.boundary.is_some_and(|reference| reference.0 > 0))
    );
    let (plan, limited_stats) = with("max_analysis_bytes", stats.retained_bytes - 1)
        .analyze_with_stats(&subject)
        .unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(plan.boundaries.len(), 1);
    assert!(saturated(&plan, "max_analysis_bytes"));
    assert!(limited_stats.retained_bytes < stats.retained_bytes);
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .filter_map(|node| node.boundary)
            .all(|reference| reference.0 == 0)
    );
    for domain in effinterp_proto::DOMAINS {
        assert_eq!(
            plan.coverage.gaps(&effinterp_proto::Domain::new(domain)),
            &[effinterp_proto::BoundaryRef(0)]
        );
    }
}

const NESTED_FUNCTION_SOURCE: &str = r#"import { readdirSync, readFileSync } from "node:fs";
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
"#;

#[test]
fn nested_function_state_is_charged_to_max_analysis_bytes() {
    let subject = source("js", NESTED_FUNCTION_SOURCE);
    let (plan, stats) = Engine::new()
        .with_causality_detail(true)
        .analyze_with_stats(&subject)
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "no_entry_point")
    );
    let saturated: Vec<_> = plan
        .boundaries
        .iter()
        .filter(|b| b.reason.as_str() == "limit_saturated")
        .collect();
    assert!(saturated.len() <= 1);
    assert!(
        saturated
            .iter()
            .all(|b| b.limit.as_deref() == Some("max_analysis_bytes"))
    );
    assert!(stats.retained_bytes <= 32 * 1024 * 1024 + 4096);
    for engine in [
        Engine::new().with_causality_detail(true),
        with("max_analysis_bytes", 4096),
    ] {
        let first = engine.analyze(&subject).unwrap();
        let second = engine.analyze(&subject).unwrap();
        validate_plan(&first).unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        if engine.limits().max_analysis_bytes == 4096 {
            assert!(all_domains_partial(&first));
            let boundary = boundary_with_limit(&first, "max_analysis_bytes").unwrap();
            assert!(!boundary.provenance.is_empty());
            assert_eq!(
                first
                    .boundaries
                    .iter()
                    .filter(|b| b.reason.as_str() == "limit_saturated")
                    .count(),
                1
            );
        }
    }
}

#[test]
fn cancel_flag_ends_analysis_without_a_plan() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let flag = Arc::new(AtomicBool::new(true));
    let engine = Engine::new()
        .with_causality_detail(true)
        .with_cancel_flag(flag.clone());
    let subject = shell(&pathological_source());
    assert_eq!(
        engine.analyze_with_stats(&subject),
        Err(EngineError::Cancelled)
    );
    flag.store(false, Ordering::Relaxed);
    assert!(engine.analyze_with_stats(&subject).is_ok());
}

#[test]
fn cyclic_aggregate_alias_expansion_is_charged_to_max_analysis_bytes() {
    let subject = source(
        "js",
        "const object = {}; object.self = object; object.value = 1;",
    );
    let engine = with("max_analysis_bytes", 65536);
    let (first, stats) = engine.analyze_with_stats(&subject).unwrap();
    validate_plan(&first).unwrap();
    assert!(all_domains_partial(&first));
    let boundary = boundary_with_limit(&first, "max_analysis_bytes").unwrap();
    assert!(!boundary.provenance.is_empty());
    assert!(stats.retained_bytes <= 65536 + 4096);
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&engine.analyze(&subject).unwrap()).unwrap()
    );
}

/// Acceptance 5: when the causal-edge ceiling is reached, the endpoint effects
/// survive and the plan says so with the existing typed boundary. A saturated
/// graph must never read as complete causal evidence, and no pairing is
/// fabricated to fill the gap.
#[test]
fn saturated_causal_edges_retain_endpoints_and_report_the_boundary() {
    let plan = with("max_causal_edges", 0)
        .analyze(&shell("cp /w/a.txt /w/b.txt"))
        .unwrap();
    validate_plan(&plan).unwrap();
    let operations: Vec<_> = plan
        .effects
        .iter()
        .map(|effect| effect.operation.0.as_str())
        .collect();
    assert!(operations.contains(&"filesystem.read") && operations.contains(&"filesystem.write"));
    assert!(
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
            .is_empty()
    );
    assert!(saturated(&plan, "max_causal_edges"));
    assert_ne!(plan.causality.coverage.level, CoverageLevel::Full);
}

#[test]
fn summary_node_caps_use_configured_language_limits() {
    use effinterp_engine::{Lang, ScopeKey, SummaryBudget, module_summaries};
    let cases = [
        (Lang::Python, "import os\ndef run(): os.remove('/x')\n"),
        (
            Lang::Js(effinterp_proto::SourceDialect::Js),
            "export function run() { console.log('x'); }",
        ),
        (Lang::Go, "package main\nfunc main() { println(1) }"),
        (Lang::Ruby, "def run\n puts 'x'\nend\n"),
        (
            Lang::Rust,
            "fn main() { std::fs::remove_file(\"/x\").unwrap(); }",
        ),
        (
            Lang::Java,
            "class Main { public static void main(String[] args) { System.out.println(1); } }",
        ),
        (Lang::Php, "<?php function run() { unlink('/x'); }"),
    ];
    for (lang, source) in cases {
        let mut limits = default_limits();
        let limit = SummaryBudget::limit_name(lang);
        limits.insert(limit.into(), 1);
        let budget = SummaryBudget::for_lang(&limits, lang);
        let summary = module_summaries(
            source,
            lang,
            "file",
            ScopeKey::Module { key: "file".into() },
            &budget,
        );
        assert!(
            summary.functions.iter().any(|function| function
                .summary
                .boundaries
                .iter()
                .any(|boundary| boundary.limit.as_deref() == Some(limit))),
            "{lang:?}: {summary:?}"
        );
        let budget = SummaryBudget::for_lang(&default_limits(), lang);
        let summary = module_summaries(
            source,
            lang,
            "file",
            ScopeKey::Module { key: "file".into() },
            &budget,
        );
        assert!(summary.module_boundaries.is_empty(), "{lang:?}");
    }
}

#[test]
fn oversized_summary_walks_preserve_sibling_effects() {
    use effinterp_engine::{Lang, ScopeKey, SummaryBudget, module_summaries};
    let cases = [
        (
            Lang::Go,
            "app.go",
            "max_go_nodes",
            format!(
                "package main\nimport \"os\"\nfunc aaa() {{\n{}}}\nfunc sibling() {{ os.Remove(\"/kept\") }}\nfunc main() {{ sibling() }}\n",
                "_ = 1\n".repeat(200)
            ),
        ),
        (
            Lang::Python,
            "app.py",
            "max_python_nodes",
            format!(
                "import os\ndef aaa():\n{}def sibling():\n    os.remove('/kept')\nsibling()\n",
                "    x = 1\n".repeat(200)
            ),
        ),
        (
            Lang::Js(effinterp_proto::SourceDialect::Js),
            "app.js",
            "max_js_nodes",
            format!(
                "import fs from 'node:fs';\nfunction aaa() {{ {} }}\nfunction sibling() {{ fs.unlinkSync('/kept'); }}\nsibling();\n",
                "Math.abs(1);\n".repeat(200)
            ),
        ),
    ];
    for (lang, file, limit, source) in cases {
        let budget = SummaryBudget::new(64);
        let summary = module_summaries(
            &source,
            lang,
            file,
            ScopeKey::Module { key: file.into() },
            &budget,
        );
        let oversized = summary.functions.iter().find(|f| f.name == "aaa").unwrap();
        assert_eq!(
            oversized
                .summary
                .boundaries
                .iter()
                .filter(|b| b.limit.as_deref() == Some(limit))
                .count(),
            1,
            "{lang:?}: {:?}",
            oversized.summary.boundaries,
        );
        let sibling = summary
            .functions
            .iter()
            .find(|f| f.name == "sibling")
            .unwrap();
        assert!(
            !sibling.summary.effects.is_empty(),
            "{lang:?} sibling was starved"
        );
        assert!(
            !sibling
                .summary
                .boundaries
                .iter()
                .any(|b| b.limit.as_deref() == Some(limit))
        );
        assert!(
            summary.module_boundaries.is_empty(),
            "{lang:?}: {:?}",
            summary.module_boundaries
        );
        assert!(
            !summary.module_calls.is_empty() || !summary.main_calls.is_empty(),
            "{lang:?} roots were starved"
        );
        assert_eq!(
            summary,
            module_summaries(
                &source,
                lang,
                file,
                ScopeKey::Module { key: file.into() },
                &budget
            )
        );
    }
    assert_eq!(effinterp_engine::default_limits()["max_go_nodes"], 80_000);
}

#[test]
fn oversized_initializers_preserve_callable_summaries_and_report_truncation() {
    use effinterp_engine::{Lang, ScopeKey, SummaryBudget, module_summaries};
    for (lang, source) in [
        (
            Lang::Go,
            format!(
                "package main\nimport \"os\"\nvar values = []int{{{}}}\nfunc sibling() {{ os.Remove(\"/kept\") }}",
                "1,".repeat(200)
            ),
        ),
        (
            Lang::Go,
            format!(
                "package main\nimport \"os\"\nfunc init() {{ {} }}\nfunc sibling() {{ os.Remove(\"/kept\") }}",
                "_ = 1\n".repeat(200)
            ),
        ),
        (
            Lang::Python,
            format!(
                "import os\ndef sibling():\n    os.remove('/kept')\n{}",
                "x = 1\n".repeat(200)
            ),
        ),
        (
            Lang::Python,
            format!(
                "import os\ndef sibling():\n    os.remove('/kept')\nif __name__ == '__main__':\n{}",
                "    x = 1\n".repeat(200)
            ),
        ),
        (
            Lang::Js(effinterp_proto::SourceDialect::Js),
            format!(
                "import fs from 'node:fs';\nfunction sibling() {{ fs.unlinkSync('/kept'); }}\n{}",
                "Math.abs(1);\n".repeat(200)
            ),
        ),
    ] {
        let summary = module_summaries(
            &source,
            lang,
            "file",
            ScopeKey::Module { key: "file".into() },
            &SummaryBudget::new(64),
        );
        let limit = SummaryBudget::limit_name(lang);
        assert_eq!(
            summary
                .module_boundaries
                .iter()
                .filter(|b| b.limit.as_deref() == Some(limit))
                .count(),
            1,
            "{lang:?}: {:?}",
            summary.module_boundaries
        );
        let sibling = summary
            .functions
            .iter()
            .find(|f| f.name == "sibling")
            .unwrap();
        assert!(!sibling.summary.effects.is_empty(), "{lang:?}");
        assert!(
            !sibling
                .summary
                .boundaries
                .iter()
                .any(|b| b.limit.as_deref() == Some(limit)),
            "{lang:?}"
        );
    }
}

#[test]
fn python_summary_fanout_is_bounded_and_byte_charged() {
    // Recursive sibling calls previously copied boundaries geometrically and OOMed.
    let mut code = String::from("import json, subprocess\nclass Fanout:\n");
    for index in 0..10 {
        code.push_str(&format!(
            "    def m{index}(self):\n        subprocess.run(['ls'])\n        json.dumps(self)\n"
        ));
        for offset in 1..=5 {
            code.push_str(&format!("        self.m{}()\n", (index + offset) % 10));
        }
    }
    code.push_str("Fanout().m0()\n");
    let subject = source("python", &code);
    let plan = Engine::default().analyze(&subject).unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "process.exec")
    );
    assert!(plan.boundaries.len() <= 4096);
    let plan = with("max_analysis_bytes", 16_384)
        .analyze(&subject)
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(saturated(&plan, "max_analysis_bytes"));
}

#[test]
fn value_limits_are_required_and_recorded() {
    for (name, default) in [("max_value_depth", 24), ("max_value_cardinality", 64)] {
        let mut limits = default_limits();
        assert_eq!(limits[name], default);
        limits.remove(name);
        assert!(
            matches!(AnalysisLimits::from_map(&limits), Err(LimitsError::Missing(missing)) if missing == name)
        );
        let plan = with(name, 2).analyze(&shell("cat /a")).unwrap();
        assert_eq!(plan.analysis.limits[name], 2);
    }
}

#[test]
fn java_node_saturation_preserves_summary_boundary_limit() {
    use effinterp_engine::{Lang, ScopeKey, SummaryBudget, module_summaries};
    let source = format!(
        "class Main {{ static void big() {{ {} int x = 0; {} }} }}",
        "unknown();".repeat(40),
        "x = 1;".repeat(1000),
    );
    let summary = module_summaries(
        &source,
        Lang::Java,
        "Main.java",
        ScopeKey::Module {
            key: "Main.java".into(),
        },
        &SummaryBudget::new(1000),
    );
    let big = summary
        .functions
        .iter()
        .find(|function| function.name.ends_with("big"))
        .unwrap();
    assert!(
        big.summary
            .boundaries
            .iter()
            .any(|boundary| boundary.limit.as_deref() == Some("max_java_summary_boundaries")),
        "{:?}",
        big.summary.boundaries
    );
}
