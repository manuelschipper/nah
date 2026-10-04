#![allow(clippy::disallowed_types)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use effinterp_engine::{
    Engine, SourcePurpose, SourceRefusal, SourceRequest, SourceResolver, SourceResponse,
    UnavailableReason,
};
use effinterp_proto::{
    BoundaryReason, ExecutionAssurance, ExecutionContent, ExecutionInputRole, ExecutionPhase,
    ExecutionSelection, ExecutionSelector, HostContext, OccurrenceKind, Port, ResourceExpr,
    Subject,
};

#[derive(Clone)]
struct RuntimeResolver {
    sources: HashMap<String, (Vec<u8>, bool)>,
    requests: Arc<Mutex<Vec<String>>>,
    missing: UnavailableReason,
    python_suffixes: Option<Vec<String>>,
}

impl RuntimeResolver {
    fn new(sources: &[(&str, &str)]) -> Self {
        Self {
            sources: sources
                .iter()
                .map(|(path, source)| (path.to_string(), (source.as_bytes().to_vec(), false)))
                .collect(),
            requests: Default::default(),
            missing: UnavailableReason::Missing,
            python_suffixes: Some(vec![".so".to_string()]),
        }
    }

    fn executable(mut self, path: &str) -> Self {
        self.sources.get_mut(path).unwrap().1 = true;
        self
    }

    fn bytes(mut self, path: &str, bytes: &[u8]) -> Self {
        self.sources.get_mut(path).unwrap().0 = bytes.to_vec();
        self
    }

    fn missing_as(mut self, reason: UnavailableReason) -> Self {
        self.missing = reason;
        self
    }
}

impl SourceResolver for RuntimeResolver {
    fn source_mutation_disjoint(
        &self,
        _: &effinterp_proto::ResourceExpr,
        _: SourceRequest<'_>,
    ) -> bool {
        true
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.requests.lock().unwrap().push(request.path.to_string());
        self.sources.get(request.path).map_or_else(
            || SourceResponse::Refused(SourceRefusal::Unavailable(self.missing)),
            |(source, executable)| {
                if request.purpose == SourcePurpose::ExecutableInput && !executable {
                    SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::NotAFile))
                } else {
                    SourceResponse::Source(source.clone())
                }
            },
        )
    }

    fn python_extension_suffixes(&self, _: &str, _: Option<&str>) -> Option<Vec<String>> {
        self.python_suffixes.clone()
    }

    fn siblings(&self, _: &str) -> Option<Vec<String>> {
        None
    }
}

fn exec(argv: &[&str], env: &[(&str, &str)]) -> Subject {
    Subject::Exec {
        argv: argv.iter().map(|value| value.to_string()).collect(),
        cwd: Some("/w".to_string()),
        context: HostContext {
            env: env
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect::<BTreeMap<_, _>>(),
            ..Default::default()
        },
    }
}

fn analyze(subject: Subject, resolver: RuntimeResolver) -> effinterp_proto::Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&subject)
        .unwrap();
    effinterp_proto::validate_plan(&plan).unwrap();
    plan
}

fn assert_selected_source(
    plan: &effinterp_proto::Plan,
    path: &str,
    requester: &str,
    phase: ExecutionPhase,
    selector: ExecutionSelector,
    source: &str,
) {
    let (node_index, node) = plan
        .execution_graph
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| node.selected_source_path() == Some(path))
        .unwrap_or_else(|| panic!("missing selected input {path}"));
    let input = node.input.as_ref().unwrap();
    assert_eq!(input.role, ExecutionInputRole::UnexpectedSelected);
    assert_eq!(input.phase, phase);
    assert_eq!(input.requester_component, requester);
    assert_eq!(input.selector, selector);
    assert_eq!(input.assurance, ExecutionAssurance::Exact);
    match &input.selection {
        ExecutionSelection::Search {
            candidates,
            selected: Some(selected),
        } => assert_eq!(
            effinterp_proto::display_resource(&candidates[*selected as usize]),
            format!("fs:{path}")
        ),
        ExecutionSelection::Direct { request } => assert!(!request.is_empty()),
        ExecutionSelection::Search { selected: None, .. } => panic!("selected input has no winner"),
    }
    assert_eq!(
        input.content,
        ExecutionContent::Observed {
            digest: effinterp_proto::content_digest(source.as_bytes())
        }
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str().starts_with("filesystem.")
            && effinterp_proto::display_resource(&effect.resource).contains("selected-effect")
    }));
    let nested_role = if matches!(node.subject, Subject::Shell { .. }) {
        ExecutionInputRole::ExplicitInvocation
    } else {
        ExecutionInputRole::DependencyRequest
    };
    let follows_paths = matches!(&node.subject, Subject::Source { language, .. }
        if matches!(language.as_str(), "js" | "ruby" | "php"));
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        node.boundary.is_some()
            && node.input.as_ref().is_some_and(|input| {
                let path_request = matches!(&input.selector,
                    ExecutionSelector::Dependency { specifier }
                    if specifier.starts_with('.') || specifier.starts_with('/'));
                let reason = if nested_role == ExecutionInputRole::ExplicitInvocation
                    || follows_paths && path_request
                {
                    effinterp_proto::ExecutionInputReason::Missing
                } else {
                    effinterp_proto::ExecutionInputReason::DependencyNotTraversed
                };
                input.requester.0 as usize == node_index
                    && input.role == nested_role
                    && input.content == ExecutionContent::Unobserved { reason }
            })
    }));

    let read = plan.causality.graph.as_ref().expect("causality detail required").nodes.iter().find(|occurrence| {
        matches!(&occurrence.occurrence, OccurrenceKind::ResourceInteraction { operation, resource, .. }
                if operation.as_str() == "filesystem.read"
                    && effinterp_proto::display_resource(resource) == format!("fs:{path}"))
    }).unwrap();
    let mut reached = std::collections::BTreeSet::from([read.id.clone()]);
    loop {
        let before = reached.len();
        for edge in &plan
            .causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
        {
            if reached.contains(&edge.from) {
                reached.insert(edge.to.clone());
            }
        }
        if reached.len() == before {
            break;
        }
    }
    assert!(
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .any(|occurrence| {
                occurrence
                    .execution
                    .is_some_and(|execution| execution.0 as usize == node_index)
                    && reached.contains(&occurrence.id)
                    && matches!(
                        occurrence.occurrence,
                        OccurrenceKind::Port { port: Port::Code }
                    )
            })
    );
}

fn assert_no_unexpected_phase(plan: &effinterp_proto::Plan, phase: ExecutionPhase) {
    assert!(plan.execution_graph.nodes.iter().all(|node| {
        node.input.as_ref().is_none_or(|input| {
            input.role != ExecutionInputRole::UnexpectedSelected || input.phase != phase
        })
    }));
}

fn assert_selected_boundary(
    plan: &effinterp_proto::Plan,
    path: &str,
    requester: &str,
    phase: ExecutionPhase,
    selector: ExecutionSelector,
    bytes: &[u8],
) {
    let node = plan
        .execution_graph
        .nodes
        .iter()
        .find(|node| node.selected_source_path() == Some(path))
        .unwrap_or_else(|| panic!("missing selected input {path}"));
    let input = node.input.as_ref().unwrap();
    assert_eq!(input.role, ExecutionInputRole::UnexpectedSelected);
    assert_eq!(input.phase, phase);
    assert_eq!(input.requester_component, requester);
    assert_eq!(input.selector, selector);
    assert_eq!(input.assurance, ExecutionAssurance::Exact);
    assert_eq!(
        input.content,
        ExecutionContent::Observed {
            digest: effinterp_proto::content_digest(bytes),
        }
    );
    assert!(node.boundary.is_some());
}

#[test]
fn interpreter_runtime_selectors_analyze_one_source_and_stop_at_its_dependency() {
    let python = "import payload\nimport os\nos.remove('/selected-effect')\n";
    let resolver = RuntimeResolver::new(&[("/w/struct.py", python)]);
    let requests = resolver.requests.clone();
    let plan = analyze(exec(&["python3", "-c", "import base64"], &[]), resolver);
    assert_selected_source(
        &plan,
        "/w/struct.py",
        "python3",
        ExecutionPhase::Import,
        ExecutionSelector::Convention {
            name: "cpython-base64-imports-struct@3.8-3.14".to_string(),
        },
        python,
    );
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        &[
            "/w/base64/__init__.so",
            "/w/base64/__init__.py",
            "/w/base64/__init__.pyc",
            "/w/base64.so",
            "/w/base64.py",
            "/w/base64.pyc",
            "/w/struct/__init__.so",
            "/w/struct/__init__.py",
            "/w/struct/__init__.pyc",
            "/w/struct.so",
            "/w/struct.py"
        ]
    );
    assert!(plan.execution_graph.nodes.iter().all(|node| {
        node.input
            .as_ref()
            .is_none_or(|input| input.selector != ExecutionSelector::InvocationPath)
    }));
    let resolver = RuntimeResolver::new(&[
        ("/w/struct.py", "import os; os.remove('/losing-effect')"),
        ("/w/struct/__init__.py", python),
    ]);
    let requests = resolver.requests.clone();
    let package = analyze(
        exec(&["python3", "-S", "-c", "import base64"], &[]),
        resolver,
    );
    assert_selected_source(
        &package,
        "/w/struct/__init__.py",
        "python3",
        ExecutionPhase::Import,
        ExecutionSelector::Convention {
            name: "cpython-base64-imports-struct@3.8-3.14".to_string(),
        },
        python,
    );
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        &[
            "/w/base64/__init__.so",
            "/w/base64/__init__.py",
            "/w/base64/__init__.pyc",
            "/w/base64.so",
            "/w/base64.py",
            "/w/base64.pyc",
            "/w/struct/__init__.so",
            "/w/struct/__init__.py"
        ]
    );
    assert!(!package.effects.iter().any(|effect| {
        effinterp_proto::display_resource(&effect.resource).contains("losing-effect")
    }));
    let isolated = analyze(
        exec(&["python3", "-I", "-c", "import base64"], &[]),
        RuntimeResolver::new(&[("/w/struct.py", python)]),
    );
    assert_no_unexpected_phase(&isolated, ExecutionPhase::Import);
    let safe_path = analyze(
        exec(&["python3", "-P", "-c", "import base64"], &[]),
        RuntimeResolver::new(&[("/w/struct.py", python)]),
    );
    assert_no_unexpected_phase(&safe_path, ExecutionPhase::Import);
    let unknown_selector = analyze(
        exec(
            &["python3", "-X", "frozen_modules=off", "-c", "import base64"],
            &[],
        ),
        RuntimeResolver::new(&[("/w/struct.py", python)]),
    );
    assert_no_unexpected_phase(&unknown_selector, ExecutionPhase::Import);
    assert!(unknown_selector.execution_graph.nodes.iter().any(|node| {
        node.boundary.is_some()
            && node.input.as_ref().is_some_and(|input| {
                input.selector
                    == (ExecutionSelector::RuntimeOption {
                        option: "-X frozen_modules=off".to_string(),
                    })
                    && input.content
                        == ExecutionContent::Unobserved {
                            reason: effinterp_proto::ExecutionInputReason::Ambiguous,
                        }
            })
    }));

    // An explicit import is the program's own dependency, not a runtime selection.
    let resolver = RuntimeResolver::new(&[("/w/application.py", python)]);
    let explicit = analyze(
        exec(&["python3", "-c", "import application"], &[]),
        resolver,
    );
    assert_no_unexpected_phase(&explicit, ExecutionPhase::Import);
    assert!(explicit.execution_graph.nodes.iter().any(|node| {
        node.selected_source_path() == Some("/w/application.py")
            && node.input.as_ref().is_some_and(|input| {
                input.role == ExecutionInputRole::DependencyRequest
                    && matches!(input.content, ExecutionContent::Observed { .. })
            })
    }));

    let resolver = RuntimeResolver::new(&[(
        "/w/base64.py",
        "import payload\nimport os\nos.remove('/selected-effect')\n",
    )]);
    let requests = resolver.requests.clone();
    let shadowed_stdlib = analyze(exec(&["python3", "-c", "import base64"], &[]), resolver);
    assert_no_unexpected_phase(&shadowed_stdlib, ExecutionPhase::Import);
    assert!(shadowed_stdlib.execution_graph.nodes.iter().any(|node| {
        node.selected_source_path() == Some("/w/base64.py")
            && node.input.as_ref().is_some_and(|input| {
                input.role == ExecutionInputRole::DependencyRequest
                    && input.selector
                        == (ExecutionSelector::Dependency {
                            specifier: "base64".to_string(),
                        })
            })
    }));
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        &[
            "/w/base64/__init__.so",
            "/w/base64/__init__.py",
            "/w/base64/__init__.pyc",
            "/w/base64.so",
            "/w/base64.py"
        ]
    );

    let resolver = RuntimeResolver::new(&[("/w/struct.py", python)])
        .missing_as(UnavailableReason::NamespaceDenied);
    let requests = resolver.requests.clone();
    let unobserved_search = analyze(exec(&["python3", "-c", "import base64"], &[]), resolver);
    assert_no_unexpected_phase(&unobserved_search, ExecutionPhase::Import);
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        &["/w/base64/__init__.so"]
    );
    assert!(unobserved_search.execution_graph.nodes.iter().any(|node| {
        node.boundary.is_some()
            && node.input.as_ref().is_some_and(|input| {
                input.role == ExecutionInputRole::DependencyRequest
                    && input.content
                        == ExecutionContent::Unobserved {
                            reason: effinterp_proto::ExecutionInputReason::NamespaceDenied,
                        }
            })
    }));

    let resolver = RuntimeResolver::new(&[("/w/struct.py", python)]);
    let requests = resolver.requests.clone();
    let mut limits = Engine::new().with_causality_detail(true).limits().to_map();
    limits.insert("max_resolved_source_files".to_string(), 6);
    let limited = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&exec(&["python3", "-c", "import base64"], &[]))
        .unwrap();
    effinterp_proto::validate_plan(&limited).unwrap();
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        &[
            "/w/base64/__init__.so",
            "/w/base64/__init__.py",
            "/w/base64/__init__.pyc",
            "/w/base64.so",
            "/w/base64.py",
            "/w/base64.pyc"
        ]
    );
    assert!(limited.execution_graph.nodes.iter().any(|node| {
        node.boundary.is_some()
            && node.input.as_ref().is_some_and(|input| {
                input.role == ExecutionInputRole::UnexpectedSelected
                    && input.content
                        == ExecutionContent::Unobserved {
                            reason: effinterp_proto::ExecutionInputReason::BudgetRefused {
                                limit: "max_resolved_source_files".to_string(),
                            },
                        }
            })
    }));

    let unsupported = analyze(
        exec(&["python2", "-c", "import base64"], &[]),
        RuntimeResolver::new(&[("/w/struct.py", python)]),
    );
    assert_no_unexpected_phase(&unsupported, ExecutionPhase::Import);
    assert!(unsupported.execution_graph.nodes.iter().any(|node| {
        node.boundary.is_some()
            && node.input.as_ref().is_some_and(|input| {
                input.role == ExecutionInputRole::ExplicitInvocation
                    && input.content
                        == ExecutionContent::Unobserved {
                            reason: effinterp_proto::ExecutionInputReason::Mismatched,
                        }
            })
    }));
    for argv in [
        &["python", "-S", "-c", "pass"][..],
        &["python3", "-S", "-c", "pass"][..],
        &["py", "-3", "-S", "-c", "pass"][..],
        &["py", "-3.12", "-S", "-c", "pass"][..],
    ] {
        let reviewed = analyze(exec(argv, &[]), RuntimeResolver::new(&[]));
        assert!(reviewed.execution_graph.nodes.iter().all(|node| {
            node.input
                .as_ref()
                .is_none_or(|input| input.selector != ExecutionSelector::InvocationPath)
        }));
    }
    let ambiguous_launcher = analyze(
        exec(&["py", "-S", "-c", "pass"], &[]),
        RuntimeResolver::new(&[]),
    );
    assert!(ambiguous_launcher.execution_graph.nodes.iter().any(|node| {
        node.input.as_ref().is_some_and(|input| {
            input.selector == ExecutionSelector::InvocationPath
                && input.content
                    == ExecutionContent::Unobserved {
                        reason: effinterp_proto::ExecutionInputReason::Ambiguous,
                    }
        })
    }));
    let selector_inside_source = analyze(
        exec(&["py", "-S", "-c", "-3"], &[]),
        RuntimeResolver::new(&[]),
    );
    assert!(
        selector_inside_source
            .execution_graph
            .nodes
            .iter()
            .any(|node| {
                node.input.as_ref().is_some_and(|input| {
                    input.selector == ExecutionSelector::InvocationPath
                        && input.content
                            == ExecutionContent::Unobserved {
                                reason: effinterp_proto::ExecutionInputReason::Ambiguous,
                            }
                })
            })
    );

    let script = "import base64\n";
    let plan = analyze(
        exec(&["python3", "/app/main.py"], &[]),
        RuntimeResolver::new(&[("/app/main.py", script), ("/app/struct.py", python)]),
    );
    assert_selected_source(
        &plan,
        "/app/struct.py",
        "python3",
        ExecutionPhase::Import,
        ExecutionSelector::Convention {
            name: "cpython-base64-imports-struct@3.8-3.14".to_string(),
        },
        python,
    );
    assert!(plan.execution_graph.nodes.iter().all(|node| {
        node.input.as_ref().is_none_or(|input| {
            input.selector != ExecutionSelector::InvocationPath
                || matches!(input.content, ExecutionContent::Observed { .. })
        })
    }));

    let stdin = analyze(
        Subject::Shell {
            source: "printf 'pass\\n' | python3 -S -".to_string(),
            cwd: Some("/w".to_string()),
            context: HostContext::default(),
        },
        RuntimeResolver::new(&[]),
    );
    assert!(stdin.execution_graph.nodes.iter().all(|node| {
        node.input
            .as_ref()
            .is_none_or(|input| input.selector != ExecutionSelector::InvocationPath)
    }));

    let startup = "import payload\nimport os\nos.remove('/selected-effect')\n";
    let plan = analyze(
        exec(&["python3", "-c", "pass"], &[("PYTHONPATH", "/startup")]),
        RuntimeResolver::new(&[("/startup/sitecustomize.py", startup)]),
    );
    assert_selected_source(
        &plan,
        "/startup/sitecustomize.py",
        "python3",
        ExecutionPhase::Startup,
        ExecutionSelector::Environment {
            variable: "PYTHONPATH".to_string(),
        },
        startup,
    );
    let resolver = RuntimeResolver::new(&[
        ("/startup/sitecustomize/__init__.py", startup),
        (
            "/startup/sitecustomize.py",
            "import os\nos.remove('/losing-effect')",
        ),
    ]);
    let requests = resolver.requests.clone();
    let plan = analyze(
        exec(&["python3.12", "-c", "pass"], &[("PYTHONPATH", "/startup")]),
        resolver,
    );
    assert_selected_source(
        &plan,
        "/startup/sitecustomize/__init__.py",
        "python3.12",
        ExecutionPhase::Startup,
        ExecutionSelector::Environment {
            variable: "PYTHONPATH".to_string(),
        },
        startup,
    );
    assert_eq!(
        *requests.lock().unwrap(),
        [
            "/startup/sitecustomize/__init__.so",
            "/startup/sitecustomize/__init__.py",
            "/startup/usercustomize/__init__.so",
            "/startup/usercustomize/__init__.py",
            "/startup/usercustomize/__init__.pyc",
            "/startup/usercustomize.so",
            "/startup/usercustomize.py",
            "/startup/usercustomize.pyc",
        ]
    );
    let control = analyze(
        exec(
            &["python3", "-E", "-c", "pass"],
            &[("PYTHONPATH", "/startup")],
        ),
        RuntimeResolver::new(&[("/startup/sitecustomize.py", startup)]),
    );
    assert!(
        control
            .execution_graph
            .nodes
            .iter()
            .all(|node| node.selected_source_path() != Some("/startup/sitecustomize.py"))
    );
    assert!(control.boundaries.iter().any(|boundary| {
        boundary.reason == BoundaryReason::ENVIRONMENT_CONFIGURATION
            && boundary.domains.len() == 1
            && boundary.domains[0].0 == "environment"
    }));
    let no_site = analyze(
        exec(&["python3", "-S", "-c", "pass"], &[]),
        RuntimeResolver::new(&[("/startup/sitecustomize.py", startup)]),
    );
    assert_no_unexpected_phase(&no_site, ExecutionPhase::Startup);
    assert!(
        no_site
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != BoundaryReason::ENVIRONMENT_CONFIGURATION)
    );

    let isolated = analyze(
        exec(&["python3", "-I", "-c", "pass"], &[]),
        RuntimeResolver::new(&[]),
    );
    assert!(isolated.boundaries.iter().any(|boundary| {
        boundary.reason == BoundaryReason::ENVIRONMENT_CONFIGURATION
            && boundary.domains.len() == 1
            && boundary.domains[0].0 == "environment"
    }));
    let no_user_site = analyze(
        exec(&["python3", "-c", "pass"], &[("PYTHONNOUSERSITE", "1")]),
        RuntimeResolver::new(&[]),
    );
    let boundary = no_user_site
        .boundaries
        .iter()
        .find(|boundary| boundary.reason == BoundaryReason::ENVIRONMENT_CONFIGURATION)
        .unwrap();
    assert!(
        boundary
            .detail
            .as_deref()
            .is_some_and(|detail| !detail.contains("usercustomize"))
    );
    assert_eq!(
        boundary.affected_resource.clone(),
        Some(ResourceExpr::Union {
            alternatives: vec![
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::EnvironmentVariable {
                        name: "PYTHONHOME".to_string(),
                    },
                },
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::EnvironmentVariable {
                        name: "PYTHONPATH".to_string(),
                    },
                },
            ],
        })
    );
    assert_eq!(boundary.class, effinterp_proto::BoundaryClass::Unresolved);
    // Once every startup variable is observed, a value or unset, only the
    // installation's own site code remains: environment behavior, not an
    // unresolved input.
    let observed = analyze(
        Subject::Exec {
            argv: vec!["python3".into(), "-c".into(), "pass".into()],
            cwd: Some("/w".to_string()),
            context: HostContext {
                env: BTreeMap::from([("PYTHONPATH".to_string(), "/startup".to_string())]),
                env_unset: ["PYTHONHOME", "PYTHONNOUSERSITE", "PYTHONUSERBASE"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                ..Default::default()
            },
        },
        RuntimeResolver::new(&[]),
    );
    let boundary = observed
        .boundaries
        .iter()
        .find(|boundary| boundary.reason == BoundaryReason::ENVIRONMENT_CONFIGURATION)
        .unwrap();
    assert_eq!(boundary.class, effinterp_proto::BoundaryClass::Unmodeled);
    assert_eq!(boundary.affected_resource, None);

    let js = "import './payload.js'; require('fs').writeFileSync('/selected-effect', 'x');";
    let plan = analyze(
        exec(
            &["node", "app.js"],
            &[("NODE_OPTIONS", "--require=./preload.js")],
        ),
        RuntimeResolver::new(&[("/w/preload.js", js), ("/w/app.js", "true;")]),
    );
    assert_selected_source(
        &plan,
        "/w/preload.js",
        "node",
        ExecutionPhase::Preload,
        ExecutionSelector::Environment {
            variable: "NODE_OPTIONS".to_string(),
        },
        js,
    );
    let control = analyze(
        exec(&["node", "app.js"], &[]),
        RuntimeResolver::new(&[("/w/preload.js", js)]),
    );
    assert_no_unexpected_phase(&control, ExecutionPhase::Preload);
    let builtin = analyze(
        exec(&["node", "app.js"], &[("NODE_OPTIONS", "--require=fs")]),
        RuntimeResolver::new(&[("/w/app.js", "true;")]),
    );
    assert_no_unexpected_phase(&builtin, ExecutionPhase::Preload);

    for source in [
        "NODE_OPTIONS=--require=./preload.js node app.js",
        "export NODE_OPTIONS=--require=./preload.js; node app.js",
        "NODE_OPTIONS=--require=./preload.js; export NODE_OPTIONS; node app.js",
        "export NODE_OPTIONS=--require=./preload.js; sh -c 'node app.js'",
    ] {
        let plan = analyze(
            Subject::Shell {
                source: source.to_string(),
                cwd: Some("/w".to_string()),
                context: HostContext::default(),
            },
            RuntimeResolver::new(&[("/w/preload.js", js), ("/w/app.js", "true;")]),
        );
        assert_selected_source(
            &plan,
            "/w/preload.js",
            "node",
            ExecutionPhase::Preload,
            ExecutionSelector::Environment {
                variable: "NODE_OPTIONS".to_string(),
            },
            js,
        );
    }
    for source in [
        "NODE_OPTIONS=--require=./preload.js; node app.js",
        "export NODE_OPTIONS=--require=./preload.js; unset NODE_OPTIONS; node app.js",
        "export NODE_OPTIONS=--require=./preload.js; export -n NODE_OPTIONS; node app.js",
        "NODE_OPTIONS=--require=./preload.js true; node app.js",
        "export NODE_OPTIONS=--require=./preload.js; docker run image node app.js",
    ] {
        let resolver = RuntimeResolver::new(&[("/w/preload.js", js), ("/w/app.js", "true;")]);
        let requests = resolver.requests.clone();
        let plan = analyze(
            Subject::Shell {
                source: source.to_string(),
                cwd: Some("/w".to_string()),
                context: HostContext::default(),
            },
            resolver,
        );
        assert_no_unexpected_phase(&plan, ExecutionPhase::Preload);
        assert!(
            !requests
                .lock()
                .unwrap()
                .iter()
                .any(|path| path.ends_with("preload.js"))
        );
    }
    for env in [vec![], vec![("NODE_OPTIONS", "--require=./preload.js")]] {
        let resolver = RuntimeResolver::new(&[("/w/preload.js", js), ("/w/app.js", "true;")]);
        let requests = resolver.requests.clone();
        let plan = analyze(
            exec(
                &[
                    "node",
                    "-r",
                    "./preload.js",
                    "-r",
                    "/w/preload.js",
                    "--require",
                    "./preload",
                    "app.js",
                ],
                &env,
            ),
            resolver,
        );
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|path| path.as_str() == "/w/preload.js")
                .count(),
            1
        );
        assert_eq!(
            plan.execution_graph
                .nodes
                .iter()
                .filter(|node| node.selected_source_path() == Some("/w/preload.js"))
                .count(),
            1
        );
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.as_str() == "filesystem.write"
                    && effinterp_proto::display_resource(&effect.resource)
                        .contains("selected-effect"))
                .count(),
            1
        );
        let requester = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| node.selected_source_path() == Some("/w/preload.js"))
            .unwrap()
            .input
            .as_ref()
            .unwrap()
            .requester;
        assert!(
            matches!(&plan.execution_graph.nodes[requester.0 as usize].subject, Subject::Exec { argv, .. } if argv.len() == 8)
        );
    }
    let separate = analyze(
        Subject::Shell {
            source: "node -r ./preload.js app.js; node -r ./preload.js app.js".to_string(),
            cwd: Some("/w".to_string()),
            context: HostContext::default(),
        },
        RuntimeResolver::new(&[("/w/preload.js", js), ("/w/app.js", "true;")]),
    );
    assert_eq!(
        separate
            .execution_graph
            .nodes
            .iter()
            .filter(|node| node.selected_source_path() == Some("/w/preload.js"))
            .count(),
        2
    );

    let ruby = "require './payload'\nFile.write('/selected-effect', 'x')\n";
    let plan = analyze(
        exec(&["ruby", "app.rb"], &[("RUBYOPT", "-r./preload.rb")]),
        RuntimeResolver::new(&[("/w/preload.rb", ruby), ("/w/app.rb", "true")]),
    );
    assert_selected_source(
        &plan,
        "/w/preload.rb",
        "ruby",
        ExecutionPhase::Preload,
        ExecutionSelector::Environment {
            variable: "RUBYOPT".to_string(),
        },
        ruby,
    );
    let control = analyze(
        exec(&["ruby", "app.rb"], &[]),
        RuntimeResolver::new(&[("/w/preload.rb", ruby)]),
    );
    assert_no_unexpected_phase(&control, ExecutionPhase::Preload);
    let disabled = analyze(
        exec(
            &["ruby", "--disable=rubyopt", "app.rb"],
            &[("RUBYOPT", "-r./preload.rb")],
        ),
        RuntimeResolver::new(&[("/w/preload.rb", ruby)]),
    );
    assert_no_unexpected_phase(&disabled, ExecutionPhase::Preload);

    let php = "<?php require './payload.php'; unlink('/selected-effect');";
    let plan = analyze(
        exec(
            &["php", "-d", "auto_prepend_file=preload.php", "app.php"],
            &[],
        ),
        RuntimeResolver::new(&[("/w/preload.php", php), ("/w/app.php", "<?php true;")]),
    );
    assert_selected_source(
        &plan,
        "/w/preload.php",
        "php",
        ExecutionPhase::Preload,
        ExecutionSelector::RuntimeOption {
            option: "-d auto_prepend_file".to_string(),
        },
        php,
    );
    let control = analyze(
        exec(&["php", "app.php"], &[]),
        RuntimeResolver::new(&[("/w/preload.php", php)]),
    );
    assert_no_unexpected_phase(&control, ExecutionPhase::Preload);
    assert!(control.execution_graph.nodes.iter().any(|node| {
        node.boundary.is_some()
            && node.input.as_ref().is_some_and(|input| {
                input.phase == ExecutionPhase::Startup
                    && input.selector
                        == (ExecutionSelector::Convention {
                            name: "php-ini-startup-search@7-8".to_string(),
                        })
            })
    }));
    let no_ini = analyze(
        exec(&["php", "-n", "app.php"], &[]),
        RuntimeResolver::new(&[("/w/preload.php", php)]),
    );
    assert_no_unexpected_phase(&no_ini, ExecutionPhase::Startup);
}

#[test]
fn javascript_runtime_selectors_preserve_runtime_specific_controls() {
    let preload = "import './payload.ts'; require('fs').writeFileSync('/selected-effect', 'x');";
    let plan = analyze(
        exec(&["bun", "--preload", "./preload.ts", "app.ts"], &[]),
        RuntimeResolver::new(&[("/w/preload.ts", preload), ("/w/app.ts", "true;")]),
    );
    assert_selected_source(
        &plan,
        "/w/preload.ts",
        "bun",
        ExecutionPhase::Preload,
        ExecutionSelector::RuntimeOption {
            option: "--preload".to_string(),
        },
        preload,
    );
    let control = analyze(
        exec(&["bun", "app.ts"], &[]),
        RuntimeResolver::new(&[("/w/preload.ts", preload)]),
    );
    assert_no_unexpected_phase(&control, ExecutionPhase::Preload);

    let redirected = "import './payload.ts'; require('fs').writeFileSync('/selected-effect', 'x');";
    let plan = analyze(
        exec(
            &["deno", "run", "--import-map=import-map.json", "app.ts"],
            &[],
        ),
        RuntimeResolver::new(&[
            (
                "/w/import-map.json",
                r#"{"imports":{"alias":"./redirect.ts"}}"#,
            ),
            ("/w/app.ts", "import 'alias';"),
            ("/w/redirect.ts", redirected),
        ]),
    );
    assert_selected_source(
        &plan,
        "/w/redirect.ts",
        "deno",
        ExecutionPhase::Import,
        ExecutionSelector::RuntimeOption {
            option: "--import-map".to_string(),
        },
        redirected,
    );
    let control = analyze(
        exec(&["deno", "run", "app.ts"], &[]),
        RuntimeResolver::new(&[("/w/app.ts", "import 'alias';")]),
    );
    assert_no_unexpected_phase(&control, ExecutionPhase::Import);
    let config = analyze(
        exec(&["deno", "run", "--config=deno.json", "app.ts"], &[]),
        RuntimeResolver::new(&[
            ("/w/deno.json", r#"{"imports":{"alias":"./redirect.ts"}}"#),
            ("/w/app.ts", "import 'alias';"),
            ("/w/redirect.ts", redirected),
        ]),
    );
    assert_selected_source(
        &config,
        "/w/redirect.ts",
        "deno",
        ExecutionPhase::Import,
        ExecutionSelector::RuntimeOption {
            option: "--config".to_string(),
        },
        redirected,
    );
}

#[test]
fn shell_path_native_and_jvm_selections_are_structural() {
    let shell = ". ./payload.sh\nrm /selected-effect\n";
    let plan = analyze(
        exec(&["bash", "-c", "true"], &[("BASH_ENV", "./env.sh")]),
        RuntimeResolver::new(&[("/w/env.sh", shell)]),
    );
    assert_selected_source(
        &plan,
        "/w/env.sh",
        "bash",
        ExecutionPhase::Startup,
        ExecutionSelector::Environment {
            variable: "BASH_ENV".to_string(),
        },
        shell,
    );
    let control = analyze(
        exec(
            &["bash", "--posix", "-c", "true"],
            &[("BASH_ENV", "./env.sh")],
        ),
        RuntimeResolver::new(&[("/w/env.sh", shell)]),
    );
    assert_no_unexpected_phase(&control, ExecutionPhase::Startup);
    let clean = analyze(
        exec(&["bash", "-c", "true"], &[]),
        RuntimeResolver::new(&[("/w/env.sh", shell)]),
    );
    assert!(clean.execution_graph.nodes.iter().any(|node| node.boundary.is_some()
        && node.input.as_ref().is_some_and(|input| input.phase == ExecutionPhase::Startup
            && matches!(&input.selector, ExecutionSelector::Environment { variable } if variable == "BASH_ENV"))));

    let executable = "#!/bin/sh\n/bin/rm /selected-effect\n";
    for path in ["/w", "/w:/w"] {
        let source = "#!/bin/sh\nprintf selected-effect\n";
        let resolver = RuntimeResolver::new(&[("/w/tool", source)]).executable("/w/tool");
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&["tool"], &[("PATH", path)]), resolver);
        assert_eq!(*requests.lock().unwrap(), ["/w/tool"]);
        for operation in ["filesystem.read", "process.code_execution"] {
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effect.operation.as_str() == operation)
            );
        }
        let input = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| node.selected_source_path() == Some("/w/tool"))
            .unwrap()
            .input
            .as_ref()
            .unwrap();
        assert_eq!(input.assurance, ExecutionAssurance::Exact);
        assert_eq!(
            input.content,
            ExecutionContent::Observed {
                digest: effinterp_proto::content_digest(source.as_bytes()),
            }
        );
    }
    let resolver =
        RuntimeResolver::new(&[("/attacker/tool", executable), ("/lower/tool", executable)])
            .executable("/attacker/tool")
            .executable("/lower/tool");
    let requests = resolver.requests.clone();
    let plan = analyze(exec(&["tool"], &[("PATH", "/attacker:/lower")]), resolver);
    let input = plan
        .execution_graph
        .nodes
        .iter()
        .find_map(|node| node.input.as_ref())
        .unwrap();
    assert_eq!(input.role, ExecutionInputRole::ExplicitInvocation);
    assert_eq!(input.phase, ExecutionPhase::Main);
    assert_eq!(
        requests.lock().unwrap().first().map(String::as_str),
        Some("/attacker/tool")
    );
    assert!(
        !requests
            .lock()
            .unwrap()
            .iter()
            .any(|path| path == "/lower/tool")
    );
    assert!(plan.effects.iter().any(|effect| {
        effinterp_proto::display_resource(&effect.resource).contains("selected-effect")
    }));
    assert_eq!(requests.lock().unwrap().as_slice(), &["/attacker/tool"]);
    for path in [
        "/attacker:/attacker:/lower",
        "/attacker:/attacker/./:/lower",
        "/missing:/missing/../missing:/attacker:/attacker",
    ] {
        let resolver =
            RuntimeResolver::new(&[("/attacker/tool", executable)]).executable("/attacker/tool");
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&["tool"], &[("PATH", path)]), resolver);
        let node = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| node.selected_source_path() == Some("/attacker/tool"))
            .unwrap();
        let input = node.input.as_ref().unwrap();
        assert_eq!(input.assurance, ExecutionAssurance::Exact);
        assert_eq!(
            input.content,
            ExecutionContent::Observed {
                digest: effinterp_proto::content_digest(executable.as_bytes()),
            }
        );
        let expected = if path.starts_with("/missing") {
            vec!["/missing/tool", "/attacker/tool"]
        } else {
            vec!["/attacker/tool"]
        };
        assert_eq!(*requests.lock().unwrap(), expected);
        let ExecutionSelection::Search {
            candidates,
            selected: Some(selected),
        } = &input.selection
        else {
            panic!("missing PATH search evidence");
        };
        assert_eq!(*selected as usize, expected.len() - 1);
        let paths = candidates
            .iter()
            .map(effinterp_proto::display_resource)
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            if path.starts_with("/missing") {
                vec!["fs:/missing/tool", "fs:/attacker/tool"]
            } else {
                vec!["fs:/attacker/tool", "fs:/lower/tool"]
            }
        );
        assert!(plan.effects.iter().any(|effect| {
            effinterp_proto::display_resource(&effect.resource).contains("selected-effect")
        }));
    }
    for path in ["/w", "/w:/w"] {
        let source = "#!/bin/sh\nprintf selected-effect\n";
        let resolver = RuntimeResolver::new(&[("/w/tool", source)]).executable("/w/tool");
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&["tool"], &[("PATH", path)]), resolver);
        assert_eq!(*requests.lock().unwrap(), ["/w/tool"]);
        for operation in ["filesystem.read", "process.code_execution"] {
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effect.operation.as_str() == operation)
            );
        }
        let input = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| node.selected_source_path() == Some("/w/tool"))
            .unwrap()
            .input
            .as_ref()
            .unwrap();
        assert_eq!(input.assurance, ExecutionAssurance::Exact);
        assert_eq!(
            input.content,
            ExecutionContent::Observed {
                digest: effinterp_proto::content_digest(source.as_bytes()),
            }
        );
    }
    let resolver =
        RuntimeResolver::new(&[("/attacker/tool", executable), ("/lower/tool", executable)])
            .executable("/lower/tool");
    let requests = resolver.requests.clone();
    let lower = analyze(exec(&["tool"], &[("PATH", "/attacker:/lower")]), resolver);
    assert_eq!(
        lower
            .execution_graph
            .nodes
            .iter()
            .find_map(|node| node.selected_source_path()),
        Some("/lower/tool")
    );
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        &["/attacker/tool", "/lower/tool"]
    );
    let unresolved = analyze(
        exec(&["tool"], &[("PATH", "/missing")]),
        RuntimeResolver::new(&[]),
    );
    assert!(unresolved.execution_graph.nodes.iter().any(|node| {
        node.input.as_ref().is_some_and(|input| {
            input.role == ExecutionInputRole::ExplicitInvocation
                && input.phase == ExecutionPhase::Main
                && matches!(
                    input.selection,
                    ExecutionSelection::Search { selected: None, .. }
                )
        })
    }));
    let ambiguous = Engine::new()
        .with_causality_detail(true)
        .with_resolver(Box::new(RuntimeResolver::new(&[])))
        .analyze(&Subject::Shell {
            source: "PATH=\"$UNKNOWN\" tool".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    effinterp_proto::validate_plan(&ambiguous).unwrap();
    assert!(ambiguous.execution_graph.nodes.iter().any(|node| {
        node.boundary.is_some()
            && node.input.as_ref().is_some_and(|input| {
                input.role == ExecutionInputRole::ExplicitInvocation
                    && input.selector == ExecutionSelector::SearchPath
                    && input.content
                        == ExecutionContent::Unobserved {
                            reason: effinterp_proto::ExecutionInputReason::Ambiguous,
                        }
            })
    }));
    let modeled = analyze(
        exec(&["curl", "https://example.com/x"], &[]),
        RuntimeResolver::new(&[]),
    );
    assert!(
        modeled
            .effects
            .iter()
            .any(|effect| { effect.operation.as_str() == "process.exec" })
    );
    assert!(
        modeled
            .effects
            .iter()
            .any(|effect| { effect.operation.as_str() == "network.request" })
    );
    let assigned = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "PATH=/usr/bin curl https://example.com/x".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    effinterp_proto::validate_plan(&assigned).unwrap();
    assert!(
        !assigned
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "network.request")
    );
    assert!(
        assigned
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "process.exec")
    );

    for source in [
        "PATH=/tmp terraform destroy",
        "PATH=/tmp kubectl delete namespace production",
        "PATH=/tmp; terraform destroy",
        "PATH=/tmp; kubectl delete namespace production",
        "PATH=\"$UNKNOWN\"; terraform destroy",
        "PATH=/tmp eval 'terraform destroy'",
        "PATH=/tmp eval 'kubectl delete namespace production'",
        "PATH=\"$UNKNOWN\" eval 'terraform destroy'",
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.to_string(),
                cwd: Some("/w".to_string()),
                context: Default::default(),
            })
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        assert!(
            plan.effects.iter().all(|effect| matches!(
                effect.operation.as_str(),
                "environment.read" | "process.code_execution" | "process.exec"
            )),
            "basename model selected despite unresolved PATH: {source}"
        );
        let path_input = plan.execution_graph.nodes.iter().find_map(|node| {
            node.input
                .as_ref()
                .filter(|input| input.selector == ExecutionSelector::SearchPath)
        });
        assert!(path_input.is_some());
        if source.contains("$UNKNOWN") {
            assert_eq!(
                path_input.unwrap().content,
                ExecutionContent::Unobserved {
                    reason: effinterp_proto::ExecutionInputReason::Ambiguous,
                }
            );
        }
    }
    for source in [
        "MODE=dev; terraform destroy",
        "eval 'terraform destroy'",
        "eval \"eval 'terraform destroy'\"",
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.to_string(),
                cwd: Some("/w".to_string()),
                context: Default::default(),
            })
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "cloud.resource.delete"),
            "ordinary assignment or nested eval hid the basename model: {source}"
        );
    }
    for (source, deletes) in [
        ("PATH=/tmp eval 'true'; terraform destroy", 1),
        (
            "PATH=/tmp eval \"eval 'terraform destroy'\"; terraform destroy",
            1,
        ),
        ("PATH=/tmp eval 'PATH=/other'; terraform destroy", 1),
        ("PATH=/tmp eval 'unset PATH'; terraform destroy", 1),
        ("PATH=/tmp eval 'CMD=terraform'; \"$CMD\" destroy", 1),
        (
            "CMD=terraform; PATH=/tmp eval 'unset CMD'; \"$CMD\" destroy",
            0,
        ),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.to_string(),
                cwd: Some("/w".to_string()),
                context: Default::default(),
            })
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| {
                    effect.operation.as_str() == "cloud.resource.delete"
                        && matches!(
                            effect.attributes.get("whole_stack"),
                            Some(effinterp_proto::AttrValue::Bool(true))
                        )
                })
                .count(),
            deletes,
            "eval prefix scope changed later command analysis: {source}"
        );
    }
    for (source, deletes) in [
        (
            "TF_CLI_ARGS_apply=-destroy eval 'terraform apply'; terraform apply",
            1,
        ),
        (
            "TF_CLI_ARGS=-destroy=false eval 'terraform apply -destroy'",
            1,
        ),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.to_string(),
                cwd: Some("/w".to_string()),
                context: Default::default(),
            })
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| {
                    effect.operation.as_str() == "cloud.resource.delete"
                        && matches!(
                            effect.attributes.get("whole_stack"),
                            Some(effinterp_proto::AttrValue::Bool(true))
                        )
                })
                .count(),
            deletes,
            "eval prefix environment did not reach only its nested command: {source}"
        );
    }
    let scoped_environment = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "MODE=outer; MODE=inside eval 'unknown-tool'; unknown-tool".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    effinterp_proto::validate_plan(&scoped_environment).unwrap();
    let tool_environments = scoped_environment
        .execution_graph
        .nodes
        .iter()
        .filter(|node| {
            matches!(&node.subject, Subject::Exec { argv, .. }
                if argv.first().map(String::as_str) == Some("unknown-tool"))
        })
        .map(|node| node.environment.get("MODE").cloned())
        .collect::<Vec<_>>();
    assert_eq!(tool_environments.len(), 2);
    assert_eq!(
        tool_environments
            .iter()
            .filter(|value| {
                matches!(value, Some(Some(ResourceExpr::Literal { value })) if value == "inside")
            })
            .count(),
        1
    );
    assert_eq!(
        tool_environments
            .iter()
            .filter(|value| value.is_none())
            .count(),
        1
    );
    let exported = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "export PATH=/usr/bin\nrm -rf /data".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    effinterp_proto::validate_plan(&exported).unwrap();
    assert!(
        exported
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "process.exec")
    );
    assert!(
        !exported
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete")
    );
    for source in [
        "PATH=\"$FOO\" /bin/rm -rf /data",
        "PATH=\"$FOO\" rm -rf /data",
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.to_string(),
                cwd: Some("/w".to_string()),
                context: Default::default(),
            })
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "process.exec"),
            "{source}"
        );
        let delete = plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource(&effect.resource).contains("/data")
        });
        assert_eq!(delete, source.contains("/bin/rm"), "{source}");
    }
    let absolute = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "PATH=\"$FOO\" /bin/rm -rf /data".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    assert!(absolute.execution_graph.nodes.iter().all(|node| {
        node.input
            .as_ref()
            .is_none_or(|input| input.selector != ExecutionSelector::SearchPath)
    }));

    let native_bytes = b"\x7fELF\xff";
    let native = analyze(
        exec(&["true"], &[("LD_PRELOAD", "./local.so")]),
        RuntimeResolver::new(&[("/w/local.so", "")]).bytes("/w/local.so", native_bytes),
    );
    assert_selected_boundary(
        &native,
        "/w/local.so",
        "true",
        ExecutionPhase::NativeLoader,
        ExecutionSelector::Environment {
            variable: "LD_PRELOAD".to_string(),
        },
        native_bytes,
    );
    let resolver = RuntimeResolver::new(&[("/w/local.so", "")]).bytes("/w/local.so", native_bytes);
    let requests = resolver.requests.clone();
    let basename = analyze(exec(&["true"], &[("LD_PRELOAD", "local.so")]), resolver);
    assert!(requests.lock().unwrap().is_empty());
    assert!(basename.execution_graph.nodes.iter().any(|node| {
        node.boundary.is_some()
            && node.input.as_ref().is_some_and(|input| {
                input.phase == ExecutionPhase::NativeLoader
                    && input.selected.is_none()
                    && matches!(input.content, ExecutionContent::Unobserved { .. })
            })
    }));
    let clean = analyze(
        exec(&["true"], &[]),
        RuntimeResolver::new(&[("/w/local.so", "")]).bytes("/w/local.so", native_bytes),
    );
    assert_no_unexpected_phase(&clean, ExecutionPhase::NativeLoader);
    for subject in [
        exec(
            &["true"],
            &[
                ("LD_PRELOAD", "./local.so"),
                ("EFFECTINTERP_SECURE_EXECUTION", "1"),
            ],
        ),
        Subject::Shell {
            source: "EFFECTINTERP_SECURE_EXECUTION=true LD_PRELOAD=./local.so rm -rf /data"
                .to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        },
    ] {
        let plan = analyze(
            subject,
            RuntimeResolver::new(&[("/w/local.so", "")]).bytes("/w/local.so", native_bytes),
        );
        assert!(
            plan.execution_graph
                .nodes
                .iter()
                .any(|node| node.selected_source_path() == Some("/w/local.so"))
        );
    }
    let mut subject = exec(&["/bin/true"], &[("LD_PRELOAD", "./local.so")]);
    if let Subject::Exec { context, .. } = &mut subject {
        context
            .secure_execution
            .insert("/bin/true".to_string(), true);
    }
    let resolver = RuntimeResolver::new(&[("/w/local.so", "")]).bytes("/w/local.so", native_bytes);
    let requests = resolver.requests.clone();
    let secure = analyze(subject, resolver);
    assert!(requests.lock().unwrap().is_empty());
    assert!(secure.execution_graph.nodes.iter().any(|node| {
        node.boundary.is_some()
            && node.input.as_ref().is_some_and(|input| {
                input.phase == ExecutionPhase::NativeLoader
                    && input.assurance == ExecutionAssurance::Widened
            })
    }));
    assert!(
        secure
            .execution_graph
            .nodes
            .iter()
            .all(|node| node.selected_source_path() != Some("/w/local.so"))
    );

    for (command, observed, secure_value) in [
        ("/bin/true", "/bin/other", true),
        ("/bin/true", "/bin/true", false),
        ("true", "/bin/true", true),
    ] {
        let mut subject = exec(&[command], &[("LD_PRELOAD", "./local.so")]);
        if let Subject::Exec { context, .. } = &mut subject {
            context
                .secure_execution
                .insert(observed.to_string(), secure_value);
        }
        let plan = analyze(
            subject,
            RuntimeResolver::new(&[("/w/local.so", "")]).bytes("/w/local.so", native_bytes),
        );
        assert!(
            plan.execution_graph
                .nodes
                .iter()
                .any(|node| node.selected_source_path() == Some("/w/local.so"))
        );
    }

    for mut subject in [
        exec(&["env", "-i", "/bin/sh", "-c", "rm /x"], &[]),
        Subject::Shell {
            source: "env -i /bin/sh -c 'rm /x'".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        },
    ] {
        let baseline = analyze(subject.clone(), RuntimeResolver::new(&[]));
        assert!(
            baseline
                .boundaries
                .iter()
                .all(|boundary| { boundary.reason != BoundaryReason::UNRECOGNIZED_ARGUMENTS })
        );
        match &mut subject {
            Subject::Exec { context, .. } | Subject::Shell { context, .. } => {
                context
                    .secure_execution
                    .insert("/bin/true".to_string(), true);
            }
            _ => unreachable!(),
        }
        let secure_only = analyze(subject, RuntimeResolver::new(&[]));
        assert_eq!(secure_only.effects.len(), baseline.effects.len());
        for (secure, baseline) in secure_only.effects.iter().zip(&baseline.effects) {
            // Supplied context changes subject identity, not these modeled effects.
            let mut secure = secure.clone();
            secure.id = baseline.id.clone();
            assert_eq!(&secure, baseline);
        }
        assert_eq!(secure_only.boundaries, baseline.boundaries);
        assert_eq!(secure_only.coverage, baseline.coverage);
    }

    let jvm = analyze(
        exec(
            &["java", "Main"],
            &[("JAVA_TOOL_OPTIONS", "-javaagent:./agent.jar")],
        ),
        RuntimeResolver::new(&[("/w/agent.jar", "jar")]),
    );
    assert_selected_boundary(
        &jvm,
        "/w/agent.jar",
        "java",
        ExecutionPhase::Preload,
        ExecutionSelector::Environment {
            variable: "JAVA_TOOL_OPTIONS".to_string(),
        },
        b"jar",
    );
    let control = analyze(
        exec(&["java", "Main"], &[]),
        RuntimeResolver::new(&[("/w/agent.jar", "jar")]),
    );
    assert_no_unexpected_phase(&control, ExecutionPhase::Preload);
}

// A `.exe` spelling folds to the catalog model, but the PATH search, the file
// read and the process identity must still name the file actually invoked. A
// suffixed and an unsuffixed sibling are distinct files: reading the wrong one
// changes the verdict.
#[test]
fn folded_spelling_selects_the_invoked_file_not_the_unsuffixed_sibling() {
    let dangerous = "#!/bin/sh\n/bin/rm -rf /\n";
    let harmless = "#!/bin/sh\nprintf harmless\n";
    let resolver = RuntimeResolver::new(&[("/w/python3.exe", dangerous), ("/w/python3", harmless)])
        .executable("/w/python3.exe")
        .executable("/w/python3");
    let requests = resolver.requests.clone();
    let plan = analyze(exec(&["python3.exe"], &[("PATH", "/w")]), resolver);
    // The invoked file is read, never the unsuffixed sibling.
    assert_eq!(*requests.lock().unwrap(), ["/w/python3.exe"]);
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"),
        "{plan:?}"
    );
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|node| node.selected_source_path() == Some("/w/python3.exe"))
    );
}

// A folded Bun spelling selects the Bun package-manager model, reads the
// manifest, and keeps the script's effects, while the launcher identity stays
// the original argv[0].
#[test]
fn folded_bun_spelling_reads_the_manifest_and_keeps_the_script_effect() {
    let manifest = r#"{"scripts":{"wipe":"rm -rf /victim"}}"#;
    // A case-folded spelling resolves the manager on any platform; the `.exe`
    // spelling folds only where the platform supplies it (`program_name`), so
    // it is exercised by the Windows/DrvFs resolution test instead.
    for arg0 in ["BUN", "Bun", "bUN"] {
        let resolver = RuntimeResolver::new(&[("/w/package.json", manifest)]);
        let plan = analyze(exec(&[arg0, "run", "wipe"], &[]), resolver);
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete"),
            "{arg0}: manifest script effect should be kept: {plan:?}"
        );
        assert!(
            plan.effects.iter().any(|effect| matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::Process { executable, .. },
                } if executable == arg0
            )),
            "{arg0}: launcher identity should stay the original argv[0]"
        );
    }
}

#[test]
fn java_agents_respect_launcher_options_and_application_operands() {
    for argv in [
        vec!["java", "-javaagent:./agent.jar", "Main"],
        vec!["java", "-cp", "classes", "-javaagent:./agent.jar", "Main"],
        vec![
            "java",
            "--class-path=classes",
            "-javaagent:./agent.jar",
            "Main",
        ],
        vec![
            "java",
            "--source",
            "25",
            "-javaagent:./agent.jar",
            "Main.java",
        ],
        vec!["java", "-javaagent:./agent.jar", "-jar", "app.jar"],
        vec!["java", "-javaagent:./agent.jar", "-m", "app/Main"],
    ] {
        let resolver = RuntimeResolver::new(&[("/w/agent.jar", "jar")]);
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&argv, &[]), resolver);
        assert_selected_boundary(
            &plan,
            "/w/agent.jar",
            "java",
            ExecutionPhase::Preload,
            ExecutionSelector::RuntimeOption {
                option: "-javaagent".to_string(),
            },
            b"jar",
        );
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|path| *path == "/w/agent.jar")
                .count(),
            1
        );
    }
    for argv in [
        vec!["java", "Main", "-javaagent:./agent.jar"],
        vec!["java", "Main.java", "-javaagent:./agent.jar"],
        vec!["java", "-jar", "app.jar", "-javaagent:./agent.jar"],
        vec!["java", "-m", "app/Main", "-javaagent:./agent.jar"],
        vec!["java", "--module", "app/Main", "-javaagent:./agent.jar"],
        vec!["java", "--module=app/Main", "-javaagent:./agent.jar"],
        vec!["java", "-cp", "-javaagent:./agent.jar", "Main"],
        vec!["java", "--class-path=-javaagent:./agent.jar", "Main"],
        vec!["java", "--add-modules", "-javaagent:./agent.jar", "Main"],
        vec!["java", "--source", "-javaagent:./agent.jar", "Main"],
        vec!["java", "-jar", "-javaagent:./agent.jar"],
        vec!["java", "-m", "-javaagent:./agent.jar"],
    ] {
        let resolver = RuntimeResolver::new(&[("/w/agent.jar", "jar")]);
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&argv, &[]), resolver);
        assert_no_unexpected_phase(&plan, ExecutionPhase::Preload);
        assert!(
            !requests
                .lock()
                .unwrap()
                .iter()
                .any(|path| path == "/w/agent.jar")
        );
    }
}

#[test]
fn build_package_plugin_and_vcs_selectors_are_bounded() {
    let rust = "mod payload; fn main() { std::fs::remove_file(\"/selected-effect\").unwrap(); }";
    let wrapper = "#!/bin/sh\n. ./payload.sh\nrm /selected-effect\n";
    let resolver = RuntimeResolver::new(&[
        ("/w/Cargo.toml", "[package]\nname = \"app\"\n"),
        ("/w/build.rs", rust),
        ("/w/wrapper", wrapper),
    ])
    .executable("/w/wrapper");
    let plan = analyze(
        exec(&["cargo", "build"], &[("RUSTC_WRAPPER", "./wrapper")]),
        resolver,
    );
    assert_selected_source(
        &plan,
        "/w/build.rs",
        "cargo",
        ExecutionPhase::BuildHook,
        ExecutionSelector::Convention {
            name: "cargo-package-build-script@1".to_string(),
        },
        rust,
    );
    assert_selected_source(
        &plan,
        "/w/wrapper",
        "cargo",
        ExecutionPhase::BuildHook,
        ExecutionSelector::Environment {
            variable: "RUSTC_WRAPPER".to_string(),
        },
        wrapper,
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| { boundary.reason == BoundaryReason::UNRESOLVED_BUILD_TARGET })
    );
    let deselected = analyze(
        exec(&["cargo", "build", "--package", "other"], &[]),
        RuntimeResolver::new(&[
            ("/w/Cargo.toml", "[package]\nname = \"app\"\n"),
            ("/w/build.rs", rust),
        ]),
    );
    assert_no_unexpected_phase(&deselected, ExecutionPhase::BuildHook);
    assert!(
        deselected
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == BoundaryReason::UNRESOLVED_BUILD_TARGET })
    );
    let no_script = analyze(
        exec(&["cargo", "build"], &[]),
        RuntimeResolver::new(&[("/w/Cargo.toml", "[package]\nname = \"app\"\n")]),
    );
    assert_no_unexpected_phase(&no_script, ExecutionPhase::BuildHook);
    assert!(
        no_script
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == BoundaryReason::UNRESOLVED_BUILD_TARGET })
    );

    let go_tool = "#!/bin/sh\n. ./payload.sh\nrm /selected-effect\n";
    let plan = analyze(
        exec(&["go", "build", "-toolexec=./tool"], &[]),
        RuntimeResolver::new(&[("/w/tool", go_tool)]).executable("/w/tool"),
    );
    assert_selected_source(
        &plan,
        "/w/tool",
        "go",
        ExecutionPhase::BuildHook,
        ExecutionSelector::RuntimeOption {
            option: "-toolexec".to_string(),
        },
        go_tool,
    );
    let control = analyze(
        exec(&["go", "build"], &[]),
        RuntimeResolver::new(&[("/w/tool", go_tool)]).executable("/w/tool"),
    );
    assert_no_unexpected_phase(&control, ExecutionPhase::BuildHook);

    for flags in [
        vec!["-toolexec=./first", "-toolexec=./tool"],
        vec!["-toolexec", "./first", "-toolexec", "./tool"],
        vec!["-toolexec=./first", "-toolexec", "./tool"],
        vec!["-toolexec", "./first", "-toolexec=./tool"],
    ] {
        let mut argv = vec!["go", "build"];
        argv.extend(flags);
        let resolver = RuntimeResolver::new(&[("/w/first", go_tool), ("/w/tool", go_tool)])
            .executable("/w/first")
            .executable("/w/tool");
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&argv, &[]), resolver);
        assert_selected_source(
            &plan,
            "/w/tool",
            "go",
            ExecutionPhase::BuildHook,
            ExecutionSelector::RuntimeOption {
                option: "-toolexec".to_string(),
            },
            go_tool,
        );
        // The selected tool's sourced helper is searched; no losing tool is.
        assert_eq!(*requests.lock().unwrap(), vec!["/w/tool", "/w/payload.sh"]);
    }
    for flags in [
        vec!["-toolexec=./first", "-toolexec="],
        vec!["--", "-toolexec=./first"],
        vec!["main.go", "-toolexec=./first"],
    ] {
        let mut argv = vec!["go", "build"];
        argv.extend(flags);
        let resolver = RuntimeResolver::new(&[("/w/first", go_tool)]).executable("/w/first");
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&argv, &[]), resolver);
        assert_no_unexpected_phase(&plan, ExecutionPhase::BuildHook);
        assert!(requests.lock().unwrap().is_empty());
    }
    for flags in [
        vec!["-toolexec=./first", "-toolexec"],
        vec!["-toolexec=./first", "-toolexec='./with space'"],
    ] {
        let mut argv = vec!["go", "build"];
        argv.extend(flags);
        let resolver = RuntimeResolver::new(&[("/w/first", go_tool)]).executable("/w/first");
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&argv, &[]), resolver);
        assert!(requests.lock().unwrap().is_empty());
        assert!(
            plan.execution_graph
                .nodes
                .iter()
                .any(|node| node.boundary.is_some()
                    && node
                        .input
                        .as_ref()
                        .is_some_and(|input| input.phase == ExecutionPhase::BuildHook
                            && input.selected.is_none()))
        );
    }

    let javac = analyze(
        exec(
            &[
                "javac",
                "-processor",
                "LocalProcessor",
                "-processorpath",
                "./processor.jar",
                "Main.java",
            ],
            &[],
        ),
        RuntimeResolver::new(&[("/w/processor.jar", "jar")]),
    );
    assert_selected_boundary(
        &javac,
        "/w/processor.jar",
        "javac",
        ExecutionPhase::BuildHook,
        ExecutionSelector::RuntimeOption {
            option: "-processorpath".to_string(),
        },
        b"jar",
    );
    let control = analyze(
        exec(&["javac", "Main.java"], &[]),
        RuntimeResolver::new(&[("/w/processor.jar", "jar")]),
    );
    assert_no_unexpected_phase(&control, ExecutionPhase::BuildHook);

    let resolver = RuntimeResolver::new(&[("/w/processor.jar", "jar")]);
    let requests = resolver.requests.clone();
    let disabled = analyze(
        exec(
            &[
                "javac",
                "-proc:none",
                "-processor",
                "LocalProcessor",
                "-processorpath",
                "./processor.jar",
                "Main.java",
            ],
            &[],
        ),
        resolver,
    );
    assert_no_unexpected_phase(&disabled, ExecutionPhase::BuildHook);
    assert!(requests.lock().unwrap().is_empty());
    assert!(
        disabled
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == BoundaryReason::UNRESOLVED_BUILD_TARGET })
    );

    let lifecycle = "rm /selected-effect; . ./payload.sh";
    let package = format!(r#"{{"scripts":{{"preinstall":{lifecycle:?}}}}}"#);
    let resolver = RuntimeResolver::new(&[("/w/package.json", &package)]);
    let plan = analyze(
        exec(&["npm", "install", "--ignore-scripts=false"], &[]),
        resolver,
    );
    assert_selected_source(
        &plan,
        "/w/package.json",
        "npm",
        ExecutionPhase::PackageHook,
        ExecutionSelector::Convention {
            name: "npm-install-lifecycle@1".to_string(),
        },
        &package,
    );
    let control = analyze(
        exec(&["npm", "install", "--ignore-scripts"], &[]),
        RuntimeResolver::new(&[("/w/package.json", &package)]),
    );
    assert_no_unexpected_phase(&control, ExecutionPhase::PackageHook);

    for flags in [
        vec!["install", "--prefix", "./sub"],
        vec!["install", "--prefix=./sub"],
        vec!["--prefix", "./sub", "install"],
        vec!["--prefix=./sub", "install"],
    ] {
        let mut argv = vec!["npm"];
        argv.extend(flags);
        let resolver = RuntimeResolver::new(&[
            ("/w/package.json", &package),
            ("/w/sub/package.json", &package),
        ]);
        let requests = resolver.requests.clone();
        let plan = analyze(
            exec(&argv, &[("npm_config_ignore_scripts", "false")]),
            resolver,
        );
        assert!(requests.lock().unwrap().is_empty());
        assert!(
            plan.execution_graph
                .nodes
                .iter()
                .any(|node| node.boundary.is_some()
                    && node
                        .input
                        .as_ref()
                        .is_some_and(|input| input.phase == ExecutionPhase::PackageHook
                            && input.selected.is_none()))
        );
        assert!(!plan.effects.iter().any(|effect| {
            effinterp_proto::display_resource(&effect.resource).contains("selected-effect")
        }));
    }
    // A missing or current-directory prefix leaves npm on this package.
    for flags in [
        vec!["install", "--prefix"],
        vec!["install", "--prefix", "."],
    ] {
        let mut argv = vec!["npm"];
        argv.extend(flags);
        let plan = analyze(
            exec(&argv, &[("npm_config_ignore_scripts", "false")]),
            RuntimeResolver::new(&[("/w/package.json", &package)]),
        );
        assert_selected_source(
            &plan,
            "/w/package.json",
            "npm",
            ExecutionPhase::PackageHook,
            ExecutionSelector::Convention {
                name: "npm-install-lifecycle@1".to_string(),
            },
            &package,
        );
    }
    let resolver = RuntimeResolver::new(&[("/w/package.json", &package)]);
    let requests = resolver.requests.clone();
    let plan = analyze(
        exec(
            &[
                "npm",
                "install",
                "--ignore-scripts=false",
                "--prefix",
                "./sub",
            ],
            &[],
        ),
        resolver,
    );
    assert!(requests.lock().unwrap().is_empty());
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|node| node.input.as_ref().is_some_and(|input| input.phase
                == ExecutionPhase::PackageHook
                && input.selected.is_none()))
    );

    for (value, disabled) in [("false", false), ("true", true)] {
        let resolver = RuntimeResolver::new(&[("/w/package.json", &package)]);
        let requests = resolver.requests.clone();
        let plan = analyze(
            exec(
                &["npm", "install"],
                &[
                    ("npm_config_ignore_scripts", value),
                    ("npm_config_prefix", "./sub"),
                ],
            ),
            resolver,
        );
        assert!(requests.lock().unwrap().is_empty());
        if disabled {
            assert_no_unexpected_phase(&plan, ExecutionPhase::PackageHook);
        } else {
            assert!(
                plan.execution_graph
                    .nodes
                    .iter()
                    .any(|node| node.input.as_ref().is_some_and(|input| input.phase
                        == ExecutionPhase::PackageHook
                        && input.selected.is_none()
                        && input.selector
                            == ExecutionSelector::Environment {
                                variable: "npm_config_prefix".to_string()
                            }))
            );
        }
    }

    // The project npmrc decides ignore-scripts below the command line and the
    // environment, whose empty values npm ignores. When it does not, an
    // unobserved user or global npmrc still may: the ambiguity stays recorded
    // beside the lifecycle npm runs by default. A named install runs no root
    // lifecycle.
    for (npmrc, env, selected, ambiguous) in [
        ("ignore-scripts=true", vec![], false, false),
        (
            "ignore-scripts = true ; project policy",
            vec![],
            false,
            false,
        ),
        // A quoted or escaped key may reset it.
        (
            "ignore-scripts=true\n\"ignore-\\u0073cripts\"=false",
            vec![],
            true,
            true,
        ),
        ("ignore-scripts=false", vec![], true, false),
        ("", vec![], true, true),
        ("[section]\nignore-scripts=true", vec![], true, true),
        ("ignore-scripts=${CI}", vec![], true, true),
        (
            "ignore-scripts=true",
            vec![("npm_config_ignore_scripts", "")],
            false,
            false,
        ),
        (
            "ignore-scripts=true",
            vec![("npm_config_ignore_scripts", "false")],
            true,
            false,
        ),
        (
            "",
            vec![("NPM_CONFIG_IGNORE_SCRIPTS", "true")],
            false,
            false,
        ),
        ("", vec![("Npm_Config_Ignore_Scripts", "1")], false, false),
        ("", vec![("npm_config_ignore_scripts", "0x1")], true, true),
    ] {
        let resolver = RuntimeResolver::new(&[("/w/package.json", &package), ("/w/.npmrc", npmrc)]);
        let plan = analyze(exec(&["npm", "install"], &env), resolver);
        if selected {
            assert_selected_source(
                &plan,
                "/w/package.json",
                "npm",
                ExecutionPhase::PackageHook,
                ExecutionSelector::Convention {
                    name: "npm-install-lifecycle@1".to_string(),
                },
                &package,
            );
        } else {
            assert_no_unexpected_phase(&plan, ExecutionPhase::PackageHook);
        }
        let recorded = plan.execution_graph.nodes.iter().any(|node| {
            node.boundary.is_some()
                && node.input.as_ref().is_some_and(|input| {
                    input.phase == ExecutionPhase::PackageHook
                        && input.selected.is_none()
                        && matches!(
                            input.content,
                            ExecutionContent::Unobserved {
                                reason: effinterp_proto::ExecutionInputReason::Ambiguous
                            }
                        )
                })
        });
        assert_eq!(recorded, ambiguous, "{npmrc:?} {env:?}");
        if !ambiguous {
            continue;
        }
        let resolver = RuntimeResolver::new(&[("/w/package.json", &package), ("/w/.npmrc", npmrc)]);
        let requests = resolver.requests.clone();
        let named = analyze(exec(&["npm", "install", "lodash"], &env), resolver);
        assert!(requests.lock().unwrap().is_empty());
        assert!(!named.effects.iter().any(|effect| {
            effinterp_proto::display_resource(&effect.resource).contains("selected-effect")
        }));
    }

    for (flags, value, selected) in [
        (vec![], "true", false),
        (vec![], "false", true),
        (vec!["--ignore-scripts=false"], "", true),
        (vec!["--ignore-scripts=false"], "true", true),
        (vec!["--no-ignore-scripts"], "true", true),
        (vec!["--ignore-scripts", "false"], "true", true),
        (vec!["--ignore-scripts"], "false", false),
        (
            vec!["--ignore-scripts=false", "--ignore-scripts"],
            "false",
            false,
        ),
        (
            vec!["--ignore-scripts", "--ignore-scripts=false"],
            "true",
            true,
        ),
    ] {
        let mut argv = vec!["npm", "install"];
        argv.extend(flags);
        let resolver = RuntimeResolver::new(&[
            ("/w/package.json", &package),
            ("/w/.npmrc", "ignore-scripts=true"),
        ]);
        let requests = resolver.requests.clone();
        let plan = analyze(
            exec(&argv, &[("npm_config_ignore_scripts", value)]),
            resolver,
        );
        if selected {
            assert_selected_source(
                &plan,
                "/w/package.json",
                "npm",
                ExecutionPhase::PackageHook,
                ExecutionSelector::Convention {
                    name: "npm-install-lifecycle@1".to_string(),
                },
                &package,
            );
        } else {
            assert_no_unexpected_phase(&plan, ExecutionPhase::PackageHook);
            assert!(requests.lock().unwrap().is_empty());
            assert!(!plan.effects.iter().any(|effect| {
                effinterp_proto::display_resource(&effect.resource).contains("selected-effect")
            }));
        }
    }

    let plugin = "<?php namespace Vendor; require './payload.php'; unlink('/selected-effect'); class Plugin implements \\Composer\\Plugin\\PluginInterface { public function activate($composer, $io) {} public function deactivate($composer, $io) {} public function uninstall($composer, $io) {} }";
    let root = r#"{"require":{"vendor/local":"1.0.0"},"repositories":[{"type":"path","url":"plugins/local"}],"config":{"allow-plugins":{"vendor/local":true}}}"#;
    let installed = r#"{"packages":[{"name":"vendor/local","version":"1.0.0","type":"composer-plugin","install-path":"../vendor/local","require":{"composer-plugin-api":"^2.0"},"extra":{"class":"Vendor\\Plugin"},"autoload":{"psr-4":{"Vendor\\":"src/"}}}]}"#;
    let resolver = RuntimeResolver::new(&[
        ("/w/composer.json", root),
        ("/w/vendor/composer/installed.json", installed),
        ("/w/vendor/vendor/local/src/Plugin.php", plugin),
    ]);
    let plan = analyze(exec(&["composer", "install"], &[]), resolver.clone());
    assert_selected_source(
        &plan,
        "/w/vendor/vendor/local/src/Plugin.php",
        "composer",
        ExecutionPhase::Plugin,
        ExecutionSelector::Convention {
            name: "composer-installed-allow-plugins@2".to_string(),
        },
        plugin,
    );
    let control = analyze(
        exec(&["composer", "install", "--no-plugins"], &[]),
        resolver,
    );
    assert_no_unexpected_phase(&control, ExecutionPhase::Plugin);
    let denied = analyze(
        exec(&["composer", "install"], &[]),
        RuntimeResolver::new(&[
            ("/w/composer.json", &root.replace("true", "false")),
            ("/w/vendor/composer/installed.json", installed),
            ("/w/vendor/vendor/local/src/Plugin.php", plugin),
        ]),
    );
    assert_no_unexpected_phase(&denied, ExecutionPhase::Plugin);
    let resolver = RuntimeResolver::new(&[
        (
            "/w/composer.json",
            r#"{"repositories":[{"type":"path","url":"plugins/local"}],"config":{"allow-plugins":{"vendor/local":true}}}"#,
        ),
        (
            "/w/plugins/local/composer.json",
            r#"{"name":"vendor/local","type":"composer-plugin","extra":{"class":"Vendor\\Plugin"},"autoload":{"psr-4":{"Vendor\\":"src/"}}}"#,
        ),
        ("/w/plugins/local/src/Plugin.php", plugin),
    ]);
    let requests = resolver.requests.clone();
    let unused = analyze(exec(&["composer", "install"], &[]), resolver);
    assert_no_unexpected_phase(&unused, ExecutionPhase::Plugin);
    assert!(
        !requests
            .lock()
            .unwrap()
            .iter()
            .any(|path| path.contains("plugins/local"))
    );

    let hook = "#!/bin/sh\n. ./payload.sh\nrm /selected-effect\n";
    let plan = analyze(
        exec(&["git", "-c", "core.hooksPath=.git/hooks", "commit"], &[]),
        RuntimeResolver::new(&[("/w/.git/hooks/pre-commit", hook)])
            .executable("/w/.git/hooks/pre-commit"),
    );
    assert_selected_source(
        &plan,
        "/w/.git/hooks/pre-commit",
        "git",
        ExecutionPhase::VcsHook,
        ExecutionSelector::Convention {
            name: "git-pre-commit-hook@2".to_string(),
        },
        hook,
    );
    let control = analyze(
        exec(
            &[
                "git",
                "-c",
                "core.hooksPath=.git/hooks",
                "commit",
                "--no-verify",
            ],
            &[],
        ),
        RuntimeResolver::new(&[("/w/.git/hooks/pre-commit", hook)]),
    );
    assert!(control.execution_graph.nodes.iter().all(|node| {
        node.input
            .as_ref()
            .is_none_or(|input| input.phase != ExecutionPhase::VcsHook)
    }));
    assert!(
        control
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == BoundaryReason::UNMODELED_HOOKS })
    );
    let resolver = RuntimeResolver::new(&[
        ("/w/.git/config", "[core]\nhooksPath = custom-hooks\n"),
        ("/w/.git/hooks/pre-commit", hook),
        ("/w/custom-hooks/pre-commit", hook),
    ])
    .executable("/w/.git/hooks/pre-commit")
    .executable("/w/custom-hooks/pre-commit");
    let requests = resolver.requests.clone();
    let unknown_config = analyze(exec(&["git", "commit"], &[]), resolver.clone());
    assert!(unknown_config.execution_graph.nodes.iter().any(|node| {
        node.boundary.is_some()
            && node.input.as_ref().is_some_and(|input| {
                input.phase == ExecutionPhase::VcsHook
                    && input.selected.is_none()
                    && matches!(input.content, ExecutionContent::Unobserved { .. })
            })
    }));
    assert!(requests.lock().unwrap().is_empty());
    let configured = analyze(
        exec(&["git", "-c", "core.hooksPath=custom-hooks", "commit"], &[]),
        resolver,
    );
    assert_selected_source(
        &configured,
        "/w/custom-hooks/pre-commit",
        "git",
        ExecutionPhase::VcsHook,
        ExecutionSelector::Convention {
            name: "git-pre-commit-hook@2".to_string(),
        },
        hook,
    );
    assert!(
        configured
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == BoundaryReason::UNMODELED_HOOKS })
    );
    assert!(
        !requests
            .lock()
            .unwrap()
            .iter()
            .any(|path| path == "/w/.git/hooks/pre-commit")
    );
    let non_executable = analyze(
        exec(&["git", "-c", "core.hooksPath=.git/hooks", "commit"], &[]),
        RuntimeResolver::new(&[("/w/.git/hooks/pre-commit", hook)]),
    );
    assert_no_unexpected_phase(&non_executable, ExecutionPhase::VcsHook);
}

#[test]
fn node_preloads_respect_option_operands_terminators_and_environment_quotes() {
    let source = "require('./payload'); require('fs').unlinkSync('/selected-effect');";
    for argv in [
        vec!["node", "-e", "true", "-r", "./preload.js"],
        vec!["node", "-e", "true", "-r=./preload.js"],
        vec!["node", "--eval", "true", "--require=./preload.js"],
        vec!["node", "-p", "true", "-r", "./preload.js"],
        vec!["node", "--title", "a title", "-r", "./preload.js", "app.js"],
    ] {
        let resolver = RuntimeResolver::new(&[("/w/preload.js", source)]);
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&argv, &[]), resolver);
        assert_selected_source(
            &plan,
            "/w/preload.js",
            "node",
            ExecutionPhase::Preload,
            ExecutionSelector::RuntimeOption {
                option: if argv[1] == "--eval" {
                    "--require"
                } else {
                    "-r"
                }
                .to_string(),
            },
            source,
        );
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|path| *path == "/w/preload.js")
                .count(),
            1
        );
    }
    for argv in [
        vec!["node", "--", "-r", "./preload.js"],
        vec!["node", "-e", "true", "--", "-r", "./preload.js"],
        vec!["node", "app.js", "-r", "./preload.js"],
        vec!["node", "--title", "--require=./preload.js", "app.js"],
    ] {
        let resolver = RuntimeResolver::new(&[("/w/preload.js", source)]);
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&argv, &[]), resolver);
        assert_no_unexpected_phase(&plan, ExecutionPhase::Preload);
        assert!(
            !requests
                .lock()
                .unwrap()
                .iter()
                .any(|path| path == "/w/preload.js")
        );
    }
    for options in [
        "--require \"./with space.js\"",
        "--require=\"./with space.js\"",
    ] {
        let plan = analyze(
            exec(&["node", "app.js"], &[("NODE_OPTIONS", options)]),
            RuntimeResolver::new(&[("/w/with space.js", source)]),
        );
        assert_selected_source(
            &plan,
            "/w/with space.js",
            "node",
            ExecutionPhase::Preload,
            ExecutionSelector::Environment {
                variable: "NODE_OPTIONS".to_string(),
            },
            source,
        );
    }
    for options in [
        "--require \"./with space.js",
        "--require \"./with space.js\\",
    ] {
        let resolver = RuntimeResolver::new(&[("/w/with", source)]);
        let requests = resolver.requests.clone();
        let plan = analyze(
            exec(&["node", "-e", "true"], &[("NODE_OPTIONS", options)]),
            resolver,
        );
        assert!(requests.lock().unwrap().is_empty());
        assert!(plan.execution_graph.nodes.iter().any(|node| {
            node.boundary.is_some()
                && node.input.as_ref().is_some_and(|input| {
                    input.phase == ExecutionPhase::Preload
                        && matches!(
                            input.content,
                            ExecutionContent::Unobserved {
                                reason: effinterp_proto::ExecutionInputReason::Ambiguous
                            }
                        )
                })
        }));
    }
}

#[test]
fn node_require_file_search_excludes_esm_extensions_and_keeps_data_opaque() {
    let losing = "require('fs').unlinkSync('/losing-effect');";
    for (winner, bytes) in [("/w/choice.json", "{}"), ("/w/choice.node", "native bytes")] {
        let resolver = RuntimeResolver::new(&[
            ("/w/choice.mjs", losing),
            ("/w/choice.cjs", losing),
            (winner, bytes),
        ]);
        let requests = resolver.requests.clone();
        let plan = analyze(
            exec(&["node", "-r", "./choice", "-e", "true"], &[]),
            resolver,
        );
        assert_selected_boundary(
            &plan,
            winner,
            "node",
            ExecutionPhase::Preload,
            ExecutionSelector::RuntimeOption {
                option: "-r".to_string(),
            },
            bytes.as_bytes(),
        );
        let mut expected = vec!["/w/choice", "/w/choice.js", "/w/choice.json"];
        if winner.ends_with(".node") {
            expected.push("/w/choice.node");
        }
        assert_eq!(*requests.lock().unwrap(), expected);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete")
        );
    }
    for option in ["--import", "--loader", "--experimental-loader"] {
        let resolver = RuntimeResolver::new(&[("/w/choice.js", losing)]);
        let requests = resolver.requests.clone();
        let plan = analyze(
            exec(&["node", option, "./choice", "-e", "true"], &[]),
            resolver,
        );
        assert!(requests.lock().unwrap().is_empty());
        assert!(plan.execution_graph.nodes.iter().any(|node| {
            node.boundary.is_some()
                && node.input.as_ref().is_some_and(|input| {
                    input.phase == ExecutionPhase::Preload
                        && matches!(input.content, ExecutionContent::Unobserved { .. })
                })
        }));
    }
}

#[test]
fn python_runtime_import_demand_preserves_execution_and_uncertainty() {
    let source = "import payload\nimport os\nos.remove('/selected-effect')";
    for code in [
        "class C:\n import base64",
        "import base64",
        "from base64 import b64encode",
        "import base64, qa_missing_module",
        "'docstring'\nx = 1\nimport base64",
        "def f():\n return 1\nf()\nimport base64",
        "def f():\n import base64\nf()",
        "if True:\n import base64",
        "if False:\n pass\nelse:\n import base64",
        "def f():\n if True:\n  return\nf()\nimport base64",
    ] {
        let plan = analyze(
            exec(&["python3.12", "-S", "-c", code], &[]),
            RuntimeResolver::new(&[("/w/struct/__init__.py", source)]),
        );
        assert_selected_source(
            &plan,
            "/w/struct/__init__.py",
            "python3.12",
            ExecutionPhase::Import,
            ExecutionSelector::Convention {
                name: "cpython-base64-imports-struct@3.8-3.14".to_string(),
            },
            source,
        );
    }
    for code in [
        "if False:\n import base64",
        "if 0:\n import base64",
        "if '':\n import base64",
        "if True:\n pass\nelse:\n import base64",
        "def f():\n if True:\n  return\n import base64\nf()",
        "if True:\n raise Exception()\nimport base64",
        "class C:\n if True:\n  raise Exception()\nimport base64",
        "def f():\n if True:\n  raise Exception()\nf()\nimport base64",
        "def f():\n if False:\n  pass\n else:\n  if True:\n   return\n import base64\nf()",
    ] {
        let resolver = RuntimeResolver::new(&[("/w/struct/__init__.py", source)]);
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&["python3.12", "-S", "-c", code], &[]), resolver);
        assert_no_unexpected_phase(&plan, ExecutionPhase::Import);
        assert!(requests.lock().unwrap().is_empty());
    }
    for code in [
        "import qa_missing_module\nimport base64",
        "import qa_missing_module, base64",
        "from sys import qa_missing_attribute\nimport base64",
        "from . import payload\nimport base64",
        "def f():\n import qa_missing_module\nf()\nimport base64",
        "def f():\n from sys import qa_missing_attribute\n return\nf()\nimport base64",
        "class C:\n import qa_missing_module\nimport base64",
        "if missing_name:\n pass\nimport base64",
        "missing_name()\nimport base64",
        "x = missing_name\nimport base64",
        "missing_name\nimport base64",
        "x.y = 1\nimport base64",
        "assert missing_name\nimport base64",
        "del missing_name\nimport base64",
        "def f():\n missing_name()\nf()\nimport base64",
        "def f():\n x = missing_name\n return\nf()\nimport base64",
        "def f():\n if missing_name:\n  pass\nf()\nimport base64",
        "def f():\n return missing_name\nf()\nimport base64",
        "class C:\n missing_name()\nimport base64",
        "def f(x):\n import base64\nf(unknown)",
        "def f(x: missing_name):\n pass\nimport base64",
        "def f(x=missing_name):\n pass\nimport base64",
        "@missing_name\ndef f():\n pass\nimport base64",
        "class C(missing_name):\n import base64",
        "class C(metaclass=missing_name):\n import base64",
        "@missing_name\nclass C:\n pass\nimport base64",
        "def f(*x: missing_name):\n pass\nimport base64",
        "def f(**x: missing_name):\n pass\nimport base64",
        "def f(*, x=missing_name):\n pass\nimport base64",
        "def f(x: missing_name, /):\n pass\nimport base64",
        "async def f(x=missing_name):\n pass\nimport base64",
        "@missing_name\nasync def f():\n pass\nimport base64",
        "def f():\n class C(missing_name):\n  pass\nf()\nimport base64",
        "def f() -> missing_name:\n import base64\nf()",
        "def f() -> missing_name:\n pass\nimport base64",
        "def f() -> missing_name:\n pass\ndef g():\n import base64\ng()",
        "async def f() -> missing_name:\n pass\nimport base64",
        "def f():\n def g() -> missing_name:\n  pass\nf()\nimport base64",
        "from __future__ import annotations\ndef f() -> missing_name:\n import base64\nf()",
        "def f():\n import base64\nf = other\nf()",
        "if unknown:\n import base64",
        "def f():\n if unknown:\n  return\n if True:\n  raise Exception()\nf()\nimport base64",
        "if unknown:\n raise Exception()\nimport base64",
        "def f():\n if unknown:\n  raise Exception()\nf()\nimport base64",
        "class C:\n if unknown:\n  raise Exception()\nimport base64",
        "try:\n import base64\nexcept:\n pass",
    ] {
        let resolver = RuntimeResolver::new(&[("/w/struct/__init__.py", source)]);
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&["python3.12", "-S", "-c", code], &[]), resolver);
        // The program's own imports are searched; the runtime selection is not.
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|request| !request.contains("struct"))
        );
        assert!(plan.execution_graph.nodes.iter().any(|node| {
            node.boundary.is_some()
                && node.input.as_ref().is_some_and(|input| {
                    input.phase == ExecutionPhase::Import
                        && input.role == ExecutionInputRole::UnexpectedSelected
                        && matches!(
                            input.content,
                            ExecutionContent::Unobserved {
                                reason: effinterp_proto::ExecutionInputReason::Ambiguous
                            }
                        )
                })
        }));
    }
    let resolver = RuntimeResolver::new(&[("/w/struct/__init__.py", source)]);
    let requests = resolver.requests.clone();
    let mut limits = Engine::new().with_causality_detail(true).limits().to_map();
    limits.insert("max_python_nodes".to_string(), 1);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .with_resolver(Box::new(resolver))
        .analyze(&exec(
            &["python3.12", "-S", "-c", "class C:\n import base64"],
            &[],
        ))
        .unwrap();
    effinterp_proto::validate_plan(&plan).unwrap();
    assert!(requests.lock().unwrap().is_empty());
    assert!(plan.execution_graph.nodes.iter().any(|node| node.input.as_ref().is_some_and(|input|
        matches!(&input.content, ExecutionContent::Unobserved { reason: effinterp_proto::ExecutionInputReason::BudgetRefused { limit } } if limit == "max_python_nodes"))));
}

#[test]
fn python_safe_path_environment_respects_versions_and_environment_suppression() {
    let source = "import payload\nimport os\nos.remove('/selected-effect')";
    for (launcher, flags, value, selected) in [
        ("python3.12", vec!["-S"], "1", false),
        ("python3.12", vec!["-S"], "0", false),
        ("python3.12", vec!["-S"], "", true),
        ("python3.12", vec!["-S", "-E"], "1", true),
        ("python3.12", vec!["-S", "-I"], "1", false),
        ("python3.10", vec!["-S"], "1", true),
        ("python3", vec!["-S"], "1", false),
    ] {
        let mut argv = vec![launcher];
        argv.extend(flags);
        argv.extend(["-c", "import base64"]);
        let resolver = RuntimeResolver::new(&[("/w/struct/__init__.py", source)]);
        let requests = resolver.requests.clone();
        let plan = analyze(exec(&argv, &[("PYTHONSAFEPATH", value)]), resolver);
        if selected {
            assert_selected_source(
                &plan,
                "/w/struct/__init__.py",
                launcher,
                ExecutionPhase::Import,
                ExecutionSelector::Convention {
                    name: "cpython-base64-imports-struct@3.8-3.14".to_string(),
                },
                source,
            );
        } else {
            assert!(requests.lock().unwrap().is_empty());
            assert!(
                !plan
                    .effects
                    .iter()
                    .any(|effect| effect.operation.as_str() == "filesystem.delete")
            );
        }
    }
}

#[test]
fn python_native_precedence_requires_observed_build_suffixes() {
    let losing = "import os; os.remove('/losing-effect')";
    // UTF-8 native/bytecode buffers must remain opaque too.
    for (module, path, phase) in [
        ("struct", "/w/struct.so", ExecutionPhase::Import),
        (
            "struct",
            "/w/struct.cpython-312-x86_64-linux-gnu.so",
            ExecutionPhase::Import,
        ),
        ("struct", "/w/struct.abi3.so", ExecutionPhase::Import),
        ("struct", "/w/struct/__init__.so", ExecutionPhase::Import),
        ("struct", "/w/struct/__init__.pyc", ExecutionPhase::Import),
        ("base64", "/w/base64.so", ExecutionPhase::Import),
        (
            "sitecustomize",
            "/w/sitecustomize.so",
            ExecutionPhase::Startup,
        ),
    ] {
        let source_path = format!("/w/{module}.py");
        let mut resolver = RuntimeResolver::new(&[
            (path, losing),
            (&source_path, losing),
            ("/w/struct.py", losing),
        ]);
        resolver.python_suffixes = Some(vec![
            ".cpython-312-x86_64-linux-gnu.so".to_string(),
            ".abi3.so".to_string(),
            ".so".to_string(),
        ]);
        if path.contains("cpython-") || path.contains("abi3") {
            resolver.sources.insert(
                "/w/struct.so".to_string(),
                (losing.as_bytes().to_vec(), false),
            );
        }
        let requests = resolver.requests.clone();
        let plan = analyze(
            exec(
                &[
                    "python3.12",
                    "-c",
                    if module == "sitecustomize" {
                        "pass"
                    } else {
                        "import base64"
                    },
                ],
                &[("PYTHONPATH", "/w")],
            ),
            resolver,
        );
        let node = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| node.selected_source_path() == Some(path))
            .unwrap();
        let input = node.input.as_ref().unwrap();
        assert_eq!(input.phase, phase);
        assert_eq!(input.assurance, ExecutionAssurance::Exact);
        assert_eq!(
            input.content,
            ExecutionContent::Observed {
                digest: effinterp_proto::content_digest(losing.as_bytes())
            }
        );
        assert!(node.boundary.is_some());
        assert!(!requests.lock().unwrap().contains(&source_path));
        assert!(!plan.effects.iter().any(|effect| {
            effinterp_proto::display_resource(&effect.resource).contains("losing-effect")
        }));
    }
    for suffixes in [
        None,
        Some(vec!["../bad".to_string()]),
        Some(vec![".so".to_string(); 17]),
    ] {
        for launcher in ["python3", "python3.12"] {
            let mut resolver = RuntimeResolver::new(&[
                ("/w/struct.py", losing),
                ("/w/struct.so", losing),
                ("/w/struct.cpython-312-x86_64-linux-gnu.so", losing),
            ]);
            resolver.python_suffixes = suffixes.clone();
            let requests = resolver.requests.clone();
            let plan = analyze(
                exec(&[launcher, "-S", "-c", "import base64"], &[]),
                resolver,
            );
            assert!(requests.lock().unwrap().is_empty());
            assert!(plan.execution_graph.nodes.iter().all(|node| {
                node.selected_source_path() != Some("/w/struct.py")
                    && node.selected_source_path()
                        != Some("/w/struct.cpython-312-x86_64-linux-gnu.so")
            }));
            assert!(!plan.effects.iter().any(|effect| {
                effinterp_proto::display_resource(&effect.resource).contains("losing-effect")
            }));
            assert!(plan.execution_graph.nodes.iter().any(|node| {
                node.boundary.is_some()
                    && node.input.as_ref().is_some_and(|input| {
                        input.phase == ExecutionPhase::Import
                            && input.selected.is_none()
                            && matches!(input.content, ExecutionContent::Unobserved { .. })
                    })
            }));
        }
    }
}

use effinterp_testkit::selected_code;

#[test]
fn shared_selected_code_conformance() {
    for case in selected_code::selected_code_cases() {
        let (plan, requests) = selected_code::analyze_selected_code(&case);
        selected_code::check_selected_code(&case, &plan, &requests).unwrap();
    }
}

#[test]
fn go_environment_hooks_are_selected_or_scoped_to_process() {
    use effinterp_proto::{CoverageLevel, Domain};
    let tool = "#!/bin/sh\n. ./payload.sh\nrm /selected-effect\n";
    let plan = analyze(
        exec(&["go", "build", "."], &[("GOFLAGS", "-toolexec=/x/t")]),
        RuntimeResolver::new(&[("/x/t", tool)]).executable("/x/t"),
    );
    assert_selected_source(
        &plan,
        "/x/t",
        "go",
        ExecutionPhase::BuildHook,
        ExecutionSelector::Environment {
            variable: "GOFLAGS".to_string(),
        },
        tool,
    );
    let test = analyze(
        exec(&["go", "test", ".", "-toolexec=/x/t"], &[]),
        RuntimeResolver::new(&[("/x/t", tool)]).executable("/x/t"),
    );
    assert_selected_source(
        &test,
        "/x/t",
        "go",
        ExecutionPhase::BuildHook,
        ExecutionSelector::RuntimeOption {
            option: "-toolexec".to_string(),
        },
        tool,
    );
    for environment in [
        vec![("GOFLAGS", "$X")],
        vec![("GOENV", "/unknown/env")],
        vec![("GOFLAGS", "$X"), ("GOENV", "/unknown/env")],
    ] {
        let plan = analyze(
            exec(&["go", "build", "."], &environment),
            RuntimeResolver::new(&[]),
        );
        assert_eq!(plan.boundaries.len(), 1, "{:?}", plan.boundaries);
        assert_eq!(
            plan.boundaries[0].reason,
            BoundaryReason::UNRECOVERABLE_SOURCE
        );
        assert_eq!(plan.boundaries[0].domains, vec![Domain::new("process")]);
        for (domain, coverage) in &plan.coverage.0 {
            assert_eq!(
                coverage.level == CoverageLevel::Partial,
                domain == &Domain::new("process"),
                "{domain:?}"
            );
        }
    }
}

fn deleted(plan: &effinterp_proto::Plan) -> Vec<String> {
    let mut paths = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource(&effect.resource))
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn dependency_input<'a>(
    plan: &'a effinterp_proto::Plan,
    specifier: &str,
) -> (Option<&'a str>, &'a effinterp_proto::ExecutionInput) {
    plan.execution_graph
        .nodes
        .iter()
        .find_map(|node| {
            let input = node.input.as_ref()?;
            (input.selector
                == ExecutionSelector::Dependency {
                    specifier: specifier.to_string(),
                })
            .then(|| (node.selected_source_path(), input))
        })
        .unwrap_or_else(|| panic!("missing dependency input {specifier}"))
}

struct SharedResolver(Arc<Mutex<RuntimeResolver>>);

impl SourceResolver for SharedResolver {
    fn source_mutation_disjoint(
        &self,
        resource: &effinterp_proto::ResourceExpr,
        request: SourceRequest<'_>,
    ) -> bool {
        self.0
            .lock()
            .unwrap()
            .source_mutation_disjoint(resource, request)
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.0.lock().unwrap().resolve(request)
    }

    fn python_extension_suffixes(
        &self,
        executable: &str,
        cwd: Option<&str>,
    ) -> Option<Vec<String>> {
        self.0
            .lock()
            .unwrap()
            .python_extension_suffixes(executable, cwd)
    }

    fn siblings(&self, _: &str) -> Option<Vec<String>> {
        None
    }
}

#[test]
fn launched_python_establishes_the_effects_of_an_imported_helper() {
    // `python cleanup.py`: the entrypoint passes `~` into an imported helper
    // that deletes it and force-pushes through a nested shell.
    let sources = [
        (
            "/w/cleanup.py",
            "import os\nfrom util.disk import wipe_caches\n\ndef main():\n    wipe_caches(os.path.expanduser('~'))\n    wipe_caches('build')\n\nif __name__ == '__main__':\n    main()\n",
        ),
        ("/w/util/__init__.py", ""),
        (
            "/w/util/disk.py",
            "import shutil\nimport subprocess\n\ndef wipe_caches(root):\n    shutil.rmtree(root)\n    subprocess.run('git push --force origin HEAD:main', shell=True)\n",
        ),
    ];
    let plan = analyze(
        exec(&["python3", "cleanup.py"], &[("HOME", "/home/test")]),
        RuntimeResolver::new(&sources),
    );
    let effect = |operation: &str| {
        plan.effects
            .iter()
            .find(|effect| effect.operation.as_str() == operation)
            .unwrap()
    };
    let delete = effect("filesystem.delete");
    assert_eq!(
        effinterp_proto::display_resource(&delete.resource),
        "fs:/home/test"
    );
    assert!(delete.condition.is_none());
    // A relative path passed into the helper names a file under the cwd.
    assert_eq!(deleted(&plan), ["fs:/home/test", "fs:/w/build"]);
    assert!(effect("git.push_request").condition.is_none());
    // `python3 FILE` is the audited file selector, as for `bash FILE`.
    assert_eq!(
        effect("process.code_execution").request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    // The imported module is read and executed as program source.
    let attribute = |operation: &str, name: &str| {
        plan.effects
            .iter()
            .filter(|effect| effect.operation.as_str() == operation)
            .map(|effect| effect.attributes.get(name).cloned())
            .collect::<Vec<_>>()
    };
    let program_input = Some(effinterp_proto::AttrValue::String("program_input".into()));
    let file = Some(effinterp_proto::AttrValue::String("file".into()));
    assert_eq!(
        attribute("filesystem.read", "access_purpose"),
        [None, program_input.clone(), program_input]
    );
    assert_eq!(
        attribute("process.code_execution", "source"),
        [file.clone(), file]
    );
}

#[test]
fn invoked_python_composes_reachable_imports_across_launch_forms() {
    // `pkg` runs import-time code, `tools` and `base` import each other, and
    // `dormant` is never called.
    let sources = [
        (
            "/w/pkg/__init__.py",
            "import os\nos.remove('/pkg-import')\n",
        ),
        (
            "/w/pkg/tools.py",
            "import os\nfrom . import base\n\ndef wipe(path):\n    base.remove(path)\n\ndef dormant():\n    os.remove('/dormant')\n\nif __name__ == '__main__':\n    os.remove('/main-only')\nelse:\n    os.remove('/import-only')\n",
        ),
        (
            "/w/pkg/base.py",
            "import os\nfrom . import tools\n\ndef remove(path):\n    os.remove(path)\n",
        ),
        (
            "/w/main.py",
            "from pkg import tools\ntools.wipe('/script-arg')\n",
        ),
        (
            "/w/run.sh",
            "run() {\n  python3 -c \"from pkg import tools; tools.wipe('$1')\"\n}\nrun /helper-arg\n",
        ),
    ];
    for (argv, argument) in [
        (&["python3", "main.py"][..], "fs:/script-arg"),
        (
            &[
                "python3",
                "-c",
                "from pkg import tools; tools.wipe('/inline-arg')",
            ][..],
            "fs:/inline-arg",
        ),
        (&["bash", "run.sh"][..], "fs:/helper-arg"),
    ] {
        let plan = analyze(exec(argv, &[]), RuntimeResolver::new(&sources));
        let mut expected = [argument, "fs:/pkg-import", "fs:/import-only"];
        expected.sort();
        assert_eq!(deleted(&plan), expected, "{argv:?}");
        let (path, input) = dependency_input(&plan, "pkg");
        assert_eq!(path, Some("/w/pkg/__init__.py"));
        assert_eq!(input.role, ExecutionInputRole::DependencyRequest);
        assert_eq!(input.phase, ExecutionPhase::Import);
        let (_, input) = dependency_input(&plan, "pkg.tools");
        assert_eq!(
            input.content,
            ExecutionContent::Observed {
                digest: effinterp_proto::content_digest(sources[1].1.as_bytes()),
            }
        );
    }

    let inline = analyze(
        Subject::Source {
            language: "python".to_string(),
            source: "from pkg import tools; tools.wipe('/source-arg')".to_string(),
            dialect: None,
            cwd: Some("/w".to_string()),
            context: Default::default(),
        },
        RuntimeResolver::new(&sources),
    );
    // This resolver cannot rule out native candidates without an interpreter.
    assert!(deleted(&inline).is_empty());
    let (_, input) = dependency_input(&inline, "pkg");
    assert_eq!(
        input.content,
        ExecutionContent::Unobserved {
            reason: effinterp_proto::ExecutionInputReason::Ambiguous,
        }
    );
    let direct = analyze(
        exec(&["python3", "pkg/tools.py"], &[]),
        RuntimeResolver::new(&sources),
    );
    assert!(deleted(&direct).contains(&"fs:/main-only".to_string()));
    // Launched as `__main__`, the entrypoint guard selects its body alone and
    // unconditionally.
    assert!(!deleted(&direct).contains(&"fs:/import-only".to_string()));
    assert!(direct.effects.iter().any(|effect| {
        effinterp_proto::display_resource(&effect.resource) == "fs:/main-only"
            && effect.condition.is_none()
    }));

    let helper = |target: &str| format!("import os\ndef wipe():\n    os.remove('{target}')\n");
    let (first, second, package, module) = (
        helper("/first-root"),
        helper("/second-root"),
        helper("/package"),
        helper("/module"),
    );
    let competing = [
        ("/lib1/helper.py", first.as_str()),
        ("/lib2/helper.py", second.as_str()),
        ("/w/shadow/__init__.py", package.as_str()),
        ("/w/shadow.py", module.as_str()),
        ("/w/fast.so", "\x7fELF"),
        (
            "/w/fast.py",
            "import os\ndef wipe():\n    os.remove('/shadowed')\n",
        ),
    ];
    let pythonpath = analyze(
        exec(
            &["python3", "-c", "import helper; helper.wipe()"],
            &[("PYTHONPATH", "/lib1:/lib2")],
        ),
        RuntimeResolver::new(&competing),
    );
    assert_eq!(deleted(&pythonpath), ["fs:/first-root"]);
    assert_eq!(
        dependency_input(&pythonpath, "helper").0,
        Some("/lib1/helper.py")
    );
    let shadow = analyze(
        exec(&["python3", "-c", "import shadow; shadow.wipe()"], &[]),
        RuntimeResolver::new(&competing),
    );
    assert_eq!(deleted(&shadow), ["fs:/package"]);

    // A native extension wins its search but supplies no source.
    let native = analyze(
        exec(&["python3", "-c", "import fast; fast.wipe()"], &[]),
        RuntimeResolver::new(&competing),
    );
    assert!(deleted(&native).is_empty());
    assert_eq!(dependency_input(&native, "fast").0, Some("/w/fast.so"));
    assert!(
        native
            .boundaries
            .iter()
            .any(|b| b.reason == BoundaryReason::UNSUPPORTED_SOURCE)
    );
    let missing = analyze(
        exec(&["python3", "-c", "import absent; absent.wipe('/x')"], &[]),
        RuntimeResolver::new(&competing),
    );
    assert!(deleted(&missing).is_empty());
    assert_eq!(
        dependency_input(&missing, "absent").1.content,
        ExecutionContent::Unobserved {
            reason: effinterp_proto::ExecutionInputReason::Missing
        }
    );
    assert!(missing.boundaries.iter().any(|b| {
        b.reason == BoundaryReason::UNRESOLVED_CALL
            && b.callee
                .as_ref()
                .is_some_and(|callee| callee.symbol == "wipe")
    }));
    let dynamic = analyze(
        exec(
            &[
                "python3",
                "-c",
                "import importlib; importlib.import_module(name).wipe()",
            ],
            &[],
        ),
        RuntimeResolver::new(&competing),
    );
    assert!(deleted(&dynamic).is_empty());
    assert!(
        dynamic
            .boundaries
            .iter()
            .any(|b| b.reason == BoundaryReason::DYNAMIC_DISPATCH)
    );

    // Summaries are keyed by content, so a changed helper is never stale.
    let shared = Arc::new(Mutex::new(RuntimeResolver::new(&competing)));
    let engine = Engine::new().with_resolver(Box::new(SharedResolver(Arc::clone(&shared))));
    let subject = exec(&["python3", "-c", "import shadow; shadow.wipe()"], &[]);
    assert_eq!(deleted(&engine.analyze(&subject).unwrap()), ["fs:/package"]);
    let changed = helper("/changed");
    *shared.lock().unwrap() = RuntimeResolver::new(&[("/w/shadow/__init__.py", changed.as_str())]);
    assert_eq!(deleted(&engine.analyze(&subject).unwrap()), ["fs:/changed"]);
}

struct ExpiringResolver {
    inner: RuntimeResolver,
    expire_on: &'static str,
    expire_on_alias: bool,
    deadline: effinterp_engine::InvocationDeadline,
}

impl SourceResolver for ExpiringResolver {
    fn source_mutation_disjoint(
        &self,
        resource: &effinterp_proto::ResourceExpr,
        request: SourceRequest<'_>,
    ) -> bool {
        if self.expire_on_alias && request.path == self.expire_on {
            self.deadline.expire();
        }
        self.inner.source_mutation_disjoint(resource, request)
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        if !self.expire_on_alias && request.path == self.expire_on {
            self.deadline.expire();
        }
        self.inner.resolve(request)
    }

    fn siblings(&self, _: &str) -> Option<Vec<String>> {
        None
    }
}

#[test]
fn invoked_scripts_compose_path_dependencies_and_written_sources() {
    let sources = [
        (
            "/w/app.js",
            "const h = require('./lib/h');\nh.wipe('/js-arg');\n",
        ),
        (
            "/w/lib/h.js",
            "const fs = require('fs');\nfunction wipe(p) { fs.rmSync(p, { recursive: true }); }\nfunction dormant() { fs.rmSync('/js-dormant'); }\nmodule.exports = { wipe, dormant };\n",
        ),
        ("/w/app.rb", "require_relative 'lib/h'\nwipe('/rb-arg')\n"),
        (
            "/w/lib/h.rb",
            "require 'fileutils'\ndef wipe(p)\n  FileUtils.rm_rf(p)\nend\ndef dormant\n  FileUtils.rm_rf('/rb-dormant')\nend\n",
        ),
        (
            "/w/app.php",
            "<?php\ninclude 'lib/h.php';\nwipe('/php-arg');\n",
        ),
        (
            "/w/lib/h.php",
            "<?php\nfunction wipe($p) { unlink($p); }\nfunction dormant() { unlink('/php-dormant'); }\n",
        ),
        ("/w/app.sh", ". ./lib/h.sh\nwipe /sh-arg\n"),
        (
            "/w/lib/h.sh",
            "wipe() { rm -rf \"$1\"; }\ndormant() { rm -rf /sh-dormant; }\n",
        ),
        (
            "/w/args.sh",
            ". ./delete.sh /source-arg; rm -rf \"$1\"; source ./delete.sh /source-second\n",
        ),
        (
            "/w/noargs.sh",
            ". ./delete.sh /source-arg; source ./delete.sh /source-second\n",
        ),
        ("/w/delete.sh", "rm -rf \"$1\"\n"),
        (
            "/w/inherit.sh",
            ". ./delete.sh; source ./shift.sh; rm -rf \"$1\"\n",
        ),
        ("/w/shift.sh", "shift\n"),
        ("/w/setter.sh", "set -- /changed\n"),
        ("/w/same.sh", "set -- /source-arg\n"),
        ("/w/options.sh", "set -e\n"),
        ("/w/function-set.sh", "f() { set -- /local; }; f\n"),
        ("/w/nested-set.sh", ". ./setter.sh /nested\n"),
        ("/w/nested-inherit-set.sh", ". ./setter.sh\n"),
        (
            "/w/set-function.sh",
            "set -- /changed; f() { :; }; f /local\n",
        ),
        (
            "/w/set-function-set.sh",
            "set -- /changed; f() { set -- /local; }; f\n",
        ),
        ("/w/set-source.sh", "set -- /changed; . ./options.sh\n"),
        (
            "/w/set-source-args.sh",
            "set -- /changed; . ./options.sh /local\n",
        ),
        (
            "/w/set-source-shift.sh",
            "set -- /changed; . ./shift.sh /a /b\n",
        ),
        (
            "/w/set-builtins.sh",
            "set -- /changed; echo ok; true; /usr/bin/true\n",
        ),
        (
            "/w/function-then-set.sh",
            "f() { :; }; f; set -- /changed\n",
        ),
        (
            "/w/source-then-set.sh",
            ". ./options.sh /local; set -- /changed\n",
        ),
        (
            "/w/function-source-set.sh",
            "f() { . ./setter.sh /local; rm -rf \"$1\"; }; f /function\n",
        ),
        // Disk content that each written file replaces before it runs.
        ("/w/gen.sh", "rm -rf /stale-disk\n"),
        ("/w/self.sh", "echo 'rm -rf /changed' > self.sh\n"),
        ("/w/gen.py", "import os\nos.remove('/stale-disk')\n"),
        ("/w/helper.py", "import os\nos.remove('/stale-disk')\n"),
    ];
    for (argv, argument) in [
        (&["node", "app.js"][..], "fs:/js-arg"),
        (&["ruby", "app.rb"], "fs:/rb-arg"),
        (&["php", "app.php"], "fs:/php-arg"),
        (&["bash", "app.sh"], "fs:/sh-arg"),
    ] {
        let plan = analyze(exec(argv, &[]), RuntimeResolver::new(&sources));
        assert_eq!(deleted(&plan), [argument], "{argv:?}");
    }

    for (argv, expected) in [
        (
            &["bash", "noargs.sh"][..],
            vec!["fs:/source-arg", "fs:/source-second"],
        ),
        (
            &["bash", "args.sh", "/outer"][..],
            vec!["fs:/outer", "fs:/source-arg", "fs:/source-second"],
        ),
        (
            &["bash", "inherit.sh", "/outer", "/next"][..],
            vec!["fs:/next", "fs:/outer"],
        ),
    ] {
        let plan = analyze(exec(argv, &[]), RuntimeResolver::new(&sources));
        assert_eq!(deleted(&plan), expected, "{argv:?}");
    }

    for interpreter in ["bash", "sh"] {
        for (helper, expected) in [
            ("setter.sh", "fs:/changed"),
            ("same.sh", "fs:/source-arg"),
            ("nested-inherit-set.sh", "fs:/changed"),
            ("set-function.sh", "fs:/outer"),
            ("set-function-set.sh", "fs:/outer"),
            ("set-source.sh", "fs:/outer"),
            ("set-source-args.sh", "fs:/outer"),
            ("set-source-shift.sh", "fs:/outer"),
            ("set-builtins.sh", "fs:/changed"),
            ("function-then-set.sh", "fs:/changed"),
            ("source-then-set.sh", "fs:/changed"),
            ("shift.sh", "fs:/outer"),
            ("options.sh", "fs:/outer"),
            ("function-set.sh", "fs:/outer"),
        ] {
            let script = format!(". ./{helper} /source-arg /second; rm -rf \"$1\"\n");
            let mut sources = sources.to_vec();
            sources.push(("/w/set-args.sh", &script));
            let plan = analyze(
                exec(&[interpreter, "set-args.sh", "/outer"], &[]),
                RuntimeResolver::new(&sources),
            );
            assert_eq!(deleted(&plan), [expected], "{interpreter}: {helper}");
        }
    }

    for interpreter in ["bash", "sh"] {
        for (script, expected) in [
            (". ./nested-set.sh /source-arg; rm -rf \"$1\"", None),
            (
                ". ./function-source-set.sh /source-arg",
                Some("fs:/function"),
            ),
        ] {
            let mut sources = sources.to_vec();
            sources.push(("/w/reset-args.sh", script));
            let plan = analyze(
                exec(&[interpreter, "reset-args.sh", "/outer"], &[]),
                RuntimeResolver::new(&sources),
            );
            if let Some(expected) = expected {
                assert_eq!(deleted(&plan), [expected], "{interpreter}: {script}");
            } else {
                assert!(plan.boundaries.iter().any(|boundary| {
                    boundary.reason == BoundaryReason::UNSUPPORTED_SHELL_SYNTAX
                }));
                let deletes = deleted(&plan);
                assert_eq!(deletes.len(), 1);
                assert!(!deletes[0].starts_with("fs:"), "{deletes:?}");
            }
        }
    }

    // Optional calls must not silently choose the caller's argument list over
    // a sourced `set`: either branch can determine the later deletion target.
    for interpreter in ["bash", "sh"] {
        for call in [
            "if [ -n \"$DEBUG\" ]; then f; fi",
            "[ -n \"$DEBUG\" ] && f",
            "case \"$DEBUG\" in y) f;; esac",
            "for i in $DEBUG; do f; done",
            "while [ -n \"$DEBUG\" ]; do f; done",
            "if false; then f; fi",
            "if [ -n \"$DEBUG\" ]; then . ./options.sh; fi",
            "if [ -n \"$DEBUG\" ]; then . ./options.sh /local; fi",
            "[ -n \"$DEBUG\" ] && . ./options.sh",
            "case \"$DEBUG\" in y) . ./options.sh;; esac",
            "for i in $DEBUG; do . ./options.sh; done",
            "if [ -n \"$DEBUG\" ]; then f; else :; fi",
            "if [ -n \"$DEBUG\" ]; then g; fi",
        ] {
            for (suffix, expected) in [
                (
                    "",
                    (call == "if false; then f; fi").then_some("fs:/changed"),
                ),
                ("; set -- /recovered", Some("fs:/recovered")),
                ("; f", Some("fs:/outer")),
                ("; . ./options.sh", Some("fs:/outer")),
            ] {
                let helper =
                    format!("f() {{ :; }}; g() {{ f; }}; set -- /changed; {call}{suffix}\n");
                let mut sources = sources.to_vec();
                sources.push(("/w/optional.sh", &helper));
                sources.push((
                    "/w/optional-main.sh",
                    ". ./optional.sh /a /b; rm -rf \"$1\"",
                ));
                let plan = analyze(
                    exec(&[interpreter, "optional-main.sh", "/outer"], &[]),
                    RuntimeResolver::new(&sources),
                );
                let deletes = deleted(&plan);
                if let Some(expected) = expected {
                    assert_eq!(deletes, [expected], "{interpreter}: {helper}");
                } else {
                    assert!(
                        plan.boundaries.iter().any(|boundary| {
                            boundary.reason == BoundaryReason::UNSUPPORTED_SHELL_SYNTAX
                        }),
                        "{interpreter}: {helper}"
                    );
                    assert_eq!(deletes.len(), 1, "{interpreter}: {helper}");
                    assert!(
                        !deletes[0].starts_with("fs:"),
                        "{interpreter}: {helper}: {deletes:?}"
                    );
                }
            }
        }
    }

    let predicted = |plan: &effinterp_proto::Plan, path: &str, source: &str| {
        plan.execution_graph.nodes.iter().any(|node| {
            node.selected_source_path() == Some(path)
                && node.input.as_ref().is_some_and(|input| {
                    input.content
                        == ExecutionContent::Predicted {
                            digest: effinterp_proto::content_digest(source.as_bytes()),
                        }
                })
        })
    };
    let refused = |plan: &effinterp_proto::Plan,
                   path: &str,
                   reason: effinterp_proto::ExecutionInputReason| {
        let content = ExecutionContent::Unobserved { reason };
        plan.execution_graph.nodes.iter().any(|node| {
            node.selected_source_path() == Some(path)
                && node.boundary.is_some()
                && node
                    .input
                    .as_ref()
                    .is_some_and(|input| input.content == content)
        })
    };
    let shell = |source: &str| {
        analyze(
            Subject::Shell {
                source: source.to_string(),
                cwd: Some("/w".to_string()),
                context: Default::default(),
            },
            RuntimeResolver::new(&sources),
        )
    };
    let written = shell(
        "printf 'rm -rf /written\\n' > gen.sh\necho 'rm -rf /appended' >> gen.sh\nsh gen.sh\ncat > gen.py <<'EOF'\nimport os\nos.remove('/written-py')\nEOF\npython3 gen.py\n",
    );
    assert_eq!(
        deleted(&written),
        ["fs:/appended", "fs:/written", "fs:/written-py"]
    );
    assert!(predicted(
        &written,
        "/w/gen.sh",
        "rm -rf /written\nrm -rf /appended\n"
    ));
    assert!(predicted(
        &written,
        "/w/gen.py",
        "import os\nos.remove('/written-py')\n"
    ));
    for source in [
        "printf '%s' 'rm -rf /formatted' | sh",
        "printf '%s' rm ' -rf /formatted' | sh",
        "printf '%s\\n' 'rm -rf /formatted' | sh",
        "printf '%b' 'rm -rf /formatted\\n' | sh",
        "printf '%s' rm ' -rf /formatted' > gen.sh; sh gen.sh",
    ] {
        assert_eq!(deleted(&shell(source)), ["fs:/formatted"], "{source}");
    }
    for source in [
        "printf '%s' 'rm -rf /formatted' >/dev/null | sh",
        "printf(){ echo safe; }; printf '%s' 'rm -rf /formatted' | sh",
        "printf '%s' \"$UNKNOWN\" | sh",
        "printf -v code '%s' 'rm -rf /formatted' | sh",
        r#"printf '%b' 'rm -rf \"/\"' | sh"#,
    ] {
        assert!(deleted(&shell(source)).is_empty(), "{source}");
    }
    // A write inside the same branch is exact there; after the branch the
    // file holds either the written or the original bytes.
    let branch = shell(
        "if test -f flag; then printf 'rm -rf /branch\\n' > gen.sh; sh gen.sh; fi\nsh gen.sh\n",
    );
    assert_eq!(deleted(&branch), ["fs:/branch"]);
    assert!(refused(
        &branch,
        "/w/gen.sh",
        effinterp_proto::ExecutionInputReason::Ambiguous
    ));
    // Writes with unknown bytes invalidate scripts and imports alike.
    let unknown = shell(
        "cp other.sh gen.sh\nsh gen.sh\necho \"$X\" > helper.py\npython3 -c 'import helper'\n",
    );
    assert!(deleted(&unknown).is_empty());
    assert!(refused(
        &unknown,
        "/w/gen.sh",
        effinterp_proto::ExecutionInputReason::Stale
    ));
    assert_eq!(
        dependency_input(&unknown, "helper").1.content,
        ExecutionContent::Unobserved {
            reason: effinterp_proto::ExecutionInputReason::Stale
        }
    );

    // Concurrent writers and later loop iterations cannot establish source bytes.
    for source in [
        "echo 'rm -rf /predicted' > gen.sh & sh gen.sh",
        "echo 'rm -rf /predicted' > gen.sh | sh gen.sh",
        "for i in 1 2; do echo text > gen.sh & done; echo 'rm -rf /predicted' > gen.sh; sh gen.sh",
        "sh gen.sh | echo 'rm -rf /predicted' > gen.sh",
        "{ echo 'rm -rf /predicted' > gen.sh; } & sh gen.sh",
        "{ echo 'rm -rf /predicted' > gen.sh; exit; } & sh gen.sh",
        "true &&\n { echo 'rm -rf /predicted' > gen.sh; exit; } & sh gen.sh",
        "{ echo 'rm -rf /predicted' > gen.sh; exit; } | sh gen.sh",
        "{ echo 'rm -rf /predicted' > gen.sh; } 2>&1 | sh gen.sh",
        "sh gen.sh | { echo 'rm -rf /predicted' > gen.sh; exit; }",
        "for i in 1 2; do sh gen.sh; echo 'rm -rf /predicted' > gen.sh; done",
        "while true; do sh gen.sh; cp /x gen.sh; done",
        "write_script() { cp /x gen.sh; }; for i in 1 2; do sh gen.sh; write_script; done",
    ] {
        let plan = shell(source);
        assert!(deleted(&plan).is_empty(), "{source}: {:?}", deleted(&plan));
        assert!(
            refused(
                &plan,
                "/w/gen.sh",
                effinterp_proto::ExecutionInputReason::Ambiguous
            ),
            "{source}"
        );
    }
    // A runtime-allocated descriptor does not send stdout to the script.
    let named_fd = shell("echo 'rm -rf /predicted' {fd}> gen.sh; sh gen.sh");
    assert!(deleted(&named_fd).is_empty());
    assert!(refused(
        &named_fd,
        "/w/gen.sh",
        effinterp_proto::ExecutionInputReason::Stale
    ));

    // Unknown targets may alias either a script or an import candidate.
    for target in ["\"$F\"", "$(mktemp)"] {
        let plan = shell(&format!(
            "echo 'rm -rf /predicted' > {target}; sh gen.sh; python3 -c 'import helper'"
        ));
        assert!(deleted(&plan).is_empty());
        assert!(refused(
            &plan,
            "/w/gen.sh",
            effinterp_proto::ExecutionInputReason::Stale
        ));
        assert_eq!(
            dependency_input(&plan, "helper").1.content,
            ExecutionContent::Unobserved {
                reason: effinterp_proto::ExecutionInputReason::Stale
            }
        );
    }
    let self_write = shell("sh self.sh | true; sh self.sh");
    assert!(refused(
        &self_write,
        "/w/self.sh",
        effinterp_proto::ExecutionInputReason::Ambiguous
    ));
    assert!(refused(
        &self_write,
        "/w/self.sh",
        effinterp_proto::ExecutionInputReason::Stale
    ));
    let raced = shell("echo 'rm -rf /left' > gen.sh | echo 'rm -rf /right' > gen.sh; sh gen.sh");
    assert!(deleted(&raced).is_empty());
    assert!(refused(
        &raced,
        "/w/gen.sh",
        effinterp_proto::ExecutionInputReason::Stale
    ));
    let replaced = shell(
        "echo left > gen.sh | echo right > gen.sh; echo 'rm -rf /replacement' > gen.sh; sh gen.sh",
    );
    assert_eq!(deleted(&replaced), ["fs:/replacement"]);
    let symbolic = shell("echo text > \"$F/gen.sh\"; sh gen.sh");
    assert!(deleted(&symbolic).is_empty());
    assert!(refused(
        &symbolic,
        "/w/gen.sh",
        effinterp_proto::ExecutionInputReason::Stale
    ));
    // A disjoint writer does not obscure a source read, even in a loop or pipeline.
    for source in [
        "echo text > other.sh | sh gen.sh",
        "echo text > other.sh & sh gen.sh",
        "echo text > \"$F/other.sh\"; sh gen.sh",
    ] {
        assert_eq!(deleted(&shell(source)), ["fs:/stale-disk"], "{source}");
    }
    // A literal loop runs its body once per word, so the script's read and its
    // effect appear once per iteration.
    assert_eq!(
        deleted(&shell(
            "for i in 1 2; do sh gen.sh; echo text > other.sh; done"
        )),
        ["fs:/stale-disk", "fs:/stale-disk"]
    );

    // Source argument restoration and termination must coexist after composing
    // selected inputs: return stays local, while exit/exec stop the caller.
    for terminator in ["return 0", "exit 0", "exec true"] {
        let helper = format!("rm -rf \"$1\"; {terminator}; rm -rf /dead-helper");
        let mut terminating_sources = sources.to_vec();
        terminating_sources.push(("/w/stop.sh", &helper));
        terminating_sources.push(("/w/stop-main.sh", ". ./stop.sh /helper; rm -rf \"$1\""));
        let plan = analyze(
            exec(&["bash", "stop-main.sh", "/outer"], &[]),
            RuntimeResolver::new(&terminating_sources),
        );
        let expected = if terminator.starts_with("return") {
            vec!["fs:/helper", "fs:/outer"]
        } else {
            vec!["fs:/helper"]
        };
        assert_eq!(deleted(&plan), expected, "{terminator}");
    }

    // A deadline reached while loading a helper keeps earlier effects and
    // names the source left unanalyzed, including filesystem alias observations.
    for expire_on_alias in [false, true] {
        let deadline =
            effinterp_engine::InvocationDeadline::after(std::time::Duration::from_secs(60));
        let late = [
            (
                "/w/late.sh",
                "rm -rf /before\n. ./lib/slow.sh\nrm -rf /after\n",
            ),
            ("/w/lib/slow.sh", "rm -rf /slow\n"),
        ];
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(ExpiringResolver {
                inner: RuntimeResolver::new(&late),
                expire_on: "/w/lib/slow.sh",
                expire_on_alias,
                deadline: deadline.clone(),
            }))
            .analyze_with_deadline(&exec(&["bash", "late.sh"], &[]), &deadline, None)
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        assert_eq!(deleted(&plan), ["fs:/before"]);
        assert!(refused(
            &plan,
            "/w/lib/slow.sh",
            effinterp_proto::ExecutionInputReason::BudgetRefused {
                limit: "invocation_deadline".to_string()
            }
        ));
    }
}

/// Host path facts for a PATH search; anything undeclared is unobserved.
struct HostPaths(BTreeMap<String, effinterp_proto::ObservationOutcome>);

impl effinterp_engine::ObservationResolver for HostPaths {
    fn observe(
        &self,
        query: &effinterp_proto::ObservationQuery,
        _: effinterp_engine::ObservationBudget,
    ) -> effinterp_proto::ObservationOutcome {
        let effinterp_proto::ObservationQuery::Path { path } = query else {
            return effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Unobserved,
            );
        };
        self.0
            .get(path)
            .cloned()
            .unwrap_or(effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Unobserved,
            ))
    }
}

#[test]
fn a_host_observed_path_search_certifies_the_executable_it_selects() {
    use effinterp_proto::{
        Fact, ObservationOutcome, ObservationQuery, PathFact, PathKind, PathTarget, ProvenanceKind,
        ResourceIdentity,
    };
    let missing = |path: &str| {
        ObservationOutcome::Path(PathFact {
            entry: path.to_string(),
            kind: PathKind::Missing,
            followed: Fact::Unavailable(effinterp_proto::ObservationRefusal::Unobserved),
            executable: None,
        })
    };
    let file = |path: &str, target: &str, executable: bool| {
        ObservationOutcome::Path(PathFact {
            entry: path.to_string(),
            kind: if path == target {
                PathKind::File
            } else {
                PathKind::Symlink
            },
            followed: Fact::Known(PathTarget {
                path: target.to_string(),
                kind: Fact::Known(PathKind::File),
            }),
            executable: Some(executable),
        })
    };
    let analyze = |subject: Subject, facts: Vec<(&str, ObservationOutcome)>, sources: &[_]| {
        let resolver = sources
            .iter()
            .fold(RuntimeResolver::new(sources), |resolver, (path, _)| {
                resolver.executable(path)
            });
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(resolver))
            .analyze_with_observations(
                &subject,
                None,
                None,
                Some(Arc::new(HostPaths(
                    facts
                        .into_iter()
                        .map(|(path, outcome)| (path.to_string(), outcome))
                        .collect(),
                ))),
            )
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        plan
    };
    let shell = |source: &str, path: &str| Subject::Shell {
        source: source.to_string(),
        cwd: Some("/w".to_string()),
        context: HostContext {
            env: BTreeMap::from([("PATH".to_string(), path.to_string())]),
            ..Default::default()
        },
    };
    // The launched executable's path, and the observations its certificate
    // names in order.
    let launch = |plan: &effinterp_proto::Plan, name: &str| {
        let effect = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.as_str() == "process.exec"
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::Process { executable, .. }
                    } if executable == name)
            })
            .unwrap();
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { path, .. },
        } = &effect.resource
        else {
            unreachable!()
        };
        let proof = effect
            .provenance
            .iter()
            .map(|reference| &plan.provenance[reference.0 as usize])
            .find(|node| {
                matches!(&node.kind, ProvenanceKind::ModelApplication { model }
                    if model == effinterp_engine::PATH_SEARCH_MODEL)
            })
            .map(|certificate| {
                certificate
                    .antecedents
                    .iter()
                    .filter_map(
                        |reference| match &plan.provenance[reference.0 as usize].kind {
                            ProvenanceKind::HostObservation {
                                query: ObservationQuery::Path { path },
                                ..
                            } => Some(path.clone()),
                            _ => None,
                        },
                    )
                    .collect::<Vec<_>>()
            });
        (path.clone(), proof)
    };
    let unresolved = |plan: &effinterp_proto::Plan| {
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason == BoundaryReason::OBSERVATION_UNAVAILABLE)
            .filter_map(|boundary| boundary.detail.clone())
            .collect::<Vec<_>>()
    };
    let installed = || {
        (
            "/installed/nah",
            file("/installed/nah", "/opt/nah/bin/nah", true),
        )
    };

    // Order proof: the earlier decoy is observed absent, so the link on the
    // later directory certifies its realpath.
    let plan = analyze(
        shell("nah trust .", "/decoy:/installed"),
        vec![("/decoy/nah", missing("/decoy/nah")), installed()],
        &[],
    );
    assert_eq!(
        launch(&plan, "nah"),
        (
            Some("/opt/nah/bin/nah".to_string()),
            Some(vec!["/decoy/nah".to_string(), "/installed/nah".to_string()])
        )
    );
    assert!(unresolved(&plan).is_empty());

    // A present decoy is what the search selects; it is certified as itself.
    let plan = analyze(
        shell("nah trust .", "/decoy:/installed"),
        vec![
            ("/decoy/nah", file("/decoy/nah", "/decoy/nah", true)),
            installed(),
        ],
        &[],
    );
    assert_eq!(
        launch(&plan, "nah"),
        (
            Some("/decoy/nah".to_string()),
            Some(vec!["/decoy/nah".to_string()])
        )
    );

    // An earlier candidate that is not an executable file, one the host did
    // not answer, and one this plan wrote, created, moved or deleted before the
    // launch leave the identity unresolved with a named boundary. The mutating
    // commands are named by path so their own launch needs no search.
    for (source, decoy) in [
        ("nah trust .", Some(file("/decoy/nah", "/decoy/nah", false))),
        ("nah trust .", None),
        (
            "printf x > /decoy/nah; nah trust .",
            Some(missing("/decoy/nah")),
        ),
        (
            "/bin/ln -s /elsewhere /decoy/nah; nah trust .",
            Some(missing("/decoy/nah")),
        ),
        (
            "/bin/mv /decoy /elsewhere; nah trust .",
            Some(missing("/decoy/nah")),
        ),
        (
            "/bin/rm /decoy/nah; nah trust .",
            Some(missing("/decoy/nah")),
        ),
    ] {
        let mut facts = vec![installed()];
        facts.extend(decoy.map(|decoy| ("/decoy/nah", decoy)));
        let plan = analyze(shell(source, "/decoy:/installed"), facts, &[]);
        assert_eq!(launch(&plan, "nah"), (None, None), "{source}");
        assert!(
            unresolved(&plan)
                .iter()
                .any(|detail| detail.contains("/decoy/nah")),
            "{source}: {:?}",
            plan.boundaries
        );
    }

    // A launcher a witness finds on its own search: absent from /decoy and
    // installed as itself.
    let launcher = |decoy: &'static str, installed: &'static str| {
        [
            (decoy, missing(decoy)),
            (installed, file(installed, installed, true)),
        ]
    };

    // `touch` creates an absent operand, so a candidate it touched earlier in
    // the command may exist by the launch: the earlier absence no longer
    // proves the order.
    let plan = analyze(
        Subject::Shell {
            source: "touch ~/nah; nah trust .".to_string(),
            cwd: Some("/w".to_string()),
            context: HostContext {
                env: BTreeMap::from([
                    ("PATH".to_string(), "/decoy:/installed".to_string()),
                    ("HOME".to_string(), "/decoy".to_string()),
                ]),
                ..Default::default()
            },
        },
        [("/decoy/nah", missing("/decoy/nah")), installed()]
            .into_iter()
            .chain(launcher("/decoy/touch", "/installed/touch"))
            .collect(),
        &[],
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.create"
            && effect.resource
                == ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: "/decoy/nah".to_string(),
                    },
                }
    }));
    assert_eq!(launch(&plan, "nah"), (None, None));
    assert!(
        unresolved(&plan)
            .iter()
            .any(|detail| detail.contains("/decoy/nah: stale")),
        "{:?}",
        plan.boundaries
    );

    // Git runs a shell alias through `/bin/sh`, not an `sh` on PATH, and the
    // alias body's own `nah` is still certified by its search.
    let plan = analyze(
        shell("git -c alias.t='!nah trust .' t", "/decoy:/installed"),
        [("/decoy/nah", missing("/decoy/nah")), installed()]
            .into_iter()
            .chain(launcher("/decoy/git", "/installed/git"))
            .collect(),
        &[],
    );
    assert_eq!(launch(&plan, "sh").0.as_deref(), Some("/bin/sh"));
    assert_eq!(
        launch(&plan, "nah"),
        (
            Some("/opt/nah/bin/nah".to_string()),
            Some(vec!["/decoy/nah".to_string(), "/installed/nah".to_string()])
        )
    );

    // sudo and doas search their target on a secure path the host configures,
    // so the caller's PATH, and a decoy on it, certifies nothing: the target's
    // PATH is unknown and its search is an ambiguous boundary.
    for (wrapper, decoy, selected) in [
        ("sudo", "/decoy/sudo", "/installed/sudo"),
        ("doas", "/decoy/doas", "/installed/doas"),
    ] {
        let plan = analyze(
            shell(&format!("{wrapper} nah trust ."), "/decoy:/installed"),
            [
                ("/decoy/nah", file("/decoy/nah", "/decoy/nah", true)),
                installed(),
            ]
            .into_iter()
            .chain(launcher(decoy, selected))
            .collect(),
            &[],
        );
        assert_eq!(launch(&plan, wrapper).0.as_deref(), Some(selected));
        assert_eq!(launch(&plan, "nah"), (None, None), "{wrapper}");
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason == BoundaryReason::UNRECOVERABLE_SOURCE),
            "{wrapper}: {:?}",
            plan.boundaries
        );
    }

    // A search that finds nothing claims nothing.
    let plan = analyze(
        shell("nah trust .", "/decoy"),
        vec![("/decoy/nah", missing("/decoy/nah"))],
        &[],
    );
    assert_eq!(launch(&plan, "nah"), (None, None));
    assert!(unresolved(&plan).is_empty());

    // A certified binary is not program source, whether its bytes are
    // unreadable or not text: the basename model describes it, with the
    // certified path as its identity.
    let curl = "curl --fail --data-binary @- https://example.test/import";
    for sources in [&[][..], &[("/usr/bin/curl", "")][..]] {
        let mut resolver = RuntimeResolver::new(sources);
        if !sources.is_empty() {
            resolver = resolver
                .executable("/usr/bin/curl")
                .bytes("/usr/bin/curl", b"\x7fELF\xff");
        }
        let plan = Engine::new()
            .with_causality_detail(true)
            .with_resolver(Box::new(resolver))
            .analyze_with_observations(
                &shell(curl, "/usr/local/bin:/usr/bin"),
                None,
                None,
                Some(Arc::new(HostPaths(BTreeMap::from([
                    (
                        "/usr/local/bin/curl".to_string(),
                        missing("/usr/local/bin/curl"),
                    ),
                    (
                        "/usr/bin/curl".to_string(),
                        file("/usr/bin/curl", "/usr/bin/curl", true),
                    ),
                ])))),
            )
            .unwrap();
        assert_eq!(launch(&plan, "curl").0.as_deref(), Some("/usr/bin/curl"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.domain() == "network"),
            "{:?}",
            plan.effects
        );
        assert!(
            plan.boundaries
                .iter()
                .all(|boundary| boundary.reason != BoundaryReason::UNMODELED_COMMAND),
            "{:?}",
            plan.boundaries
        );
    }

    // A certified file whose bytes read as source is still analyzed as the
    // script it is.
    let plan = analyze(
        shell("tool", "/w"),
        vec![("/w/tool", file("/w/tool", "/w/tool", true))],
        &[("/w/tool", "#!/bin/sh\n/bin/rm -rf /selected\n")],
    );
    assert_eq!(launch(&plan, "tool").0.as_deref(), Some("/w/tool"));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effect.resource
                == ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: "/selected".to_string(),
                    },
                }
    }));

    // A lookup substitution prints the candidate the search selects, passing
    // over an earlier one that is absent or not executable, so the deletion
    // names the installed binary.
    for lookup in ["which nah", "command -v nah"] {
        let mut facts = vec![
            ("/decoy/nah", missing("/decoy/nah")),
            ("/data/nah", file("/data/nah", "/data/nah", false)),
            installed(),
            ("/bin/rm", file("/bin/rm", "/bin/rm", true)),
        ];
        for absent in ["/decoy/rm", "/data/rm", "/installed/rm"] {
            facts.push((absent, missing(absent)));
        }
        let plan = analyze(
            shell(
                &format!("rm \"$({lookup})\""),
                "/decoy:/data:/installed:/bin",
            ),
            facts,
            &[],
        );
        assert_eq!(deleted(&plan), ["fs:/installed/nah"], "{lookup}");
    }

    // Every candidate charges the observation bound; a PATH longer than it
    // ends in a limit boundary instead of a certificate.
    let limits = effinterp_engine::AnalysisLimits {
        max_observation_requests: 2,
        ..Default::default()
    };
    let plan = Engine::with_limits(limits.to_map())
        .unwrap()
        .analyze_with_observations(
            &shell("nah trust .", "/a:/b:/installed"),
            None,
            None,
            Some(Arc::new(HostPaths(BTreeMap::from(
                [
                    ("/a/nah", missing("/a/nah")),
                    ("/b/nah", missing("/b/nah")),
                    installed(),
                ]
                .map(|(path, outcome)| (path.to_string(), outcome)),
            )))),
        )
        .unwrap();
    assert_eq!(launch(&plan, "nah"), (None, None));
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason == BoundaryReason::OBSERVATION_UNAVAILABLE
            && boundary.limit.as_deref() == Some("max_observation_requests")
    }));
}
