use effinterp_engine::{Catalog, Engine, compile_registry_with_builtin};
use effinterp_proto::{
    AttrValue, BoundaryReason, CoverageLevel, Domain, ExecutionRealm, HostContext, McpCallArgs,
    McpServerIdentity, McpStdioSource, McpTransport, Plan, ProvenanceKind, ResourceExpr,
    ResourceIdentity, Subject, ToolCall, validate_plan,
};
use serde_json::{Value, json};

fn stdio(source: McpStdioSource, args: &[&str]) -> McpServerIdentity {
    McpServerIdentity::Known {
        transport: McpTransport::Stdio {
            source,
            args: args.iter().map(|arg| arg.to_string()).collect(),
        },
    }
}

fn npm(spec: &str, args: &[&str]) -> McpServerIdentity {
    stdio(
        McpStdioSource::Npm {
            spec: spec.to_string(),
        },
        args,
    )
}

fn pypi(spec: &str) -> McpServerIdentity {
    stdio(
        McpStdioSource::Pypi {
            spec: spec.to_string(),
        },
        &[],
    )
}

fn command(command: &str) -> McpServerIdentity {
    stdio(
        McpStdioSource::Command {
            command: command.to_string(),
        },
        &[],
    )
}

fn http(host: &str, path: &str, query: Option<&str>) -> McpServerIdentity {
    McpServerIdentity::Known {
        transport: McpTransport::Http {
            host: host.to_string(),
            path: path.to_string(),
            query: query.map(str::to_string),
        },
    }
}

fn supabase() -> McpServerIdentity {
    npm(
        "@supabase/mcp-server-supabase@latest",
        &["--project-ref=abc"],
    )
}

fn analyze_with(engine: &Engine, server: McpServerIdentity, tool: &str, arguments: Value) -> Plan {
    let plan = engine
        .analyze(&Subject::ToolCall {
            call: ToolCall::McpCall(McpCallArgs {
                server,
                tool: tool.to_string(),
                arguments,
            }),
            cwd: Some("/work".to_string()),
            context: HostContext::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn analyze(server: McpServerIdentity, tool: &str, arguments: Value) -> Plan {
    analyze_with(&Engine::new(), server, tool, arguments)
}

fn operations(plan: &Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|effect| effect.operation.0.as_str())
        .collect()
}

fn reasons(plan: &Plan) -> Vec<&str> {
    plan.boundaries
        .iter()
        .map(|boundary| boundary.reason.as_str())
        .collect()
}

fn assert_opaque(plan: &Plan) {
    assert!(plan.effects.is_empty(), "{:?}", operations(plan));
    assert_eq!(reasons(plan), [BoundaryReason::UNSUPPORTED_TOOL.as_str()]);
}

fn remote(endpoint: &str) -> ExecutionRealm {
    ExecutionRealm::Remote {
        endpoint: endpoint.to_string(),
    }
}

#[test]
fn supabase_sql_tools_nest_postgres_in_the_servers_remote_realm() {
    for (server, endpoint) in [
        (
            supabase(),
            "mcp:stdio:npm:@supabase/mcp-server-supabase@latest",
        ),
        (
            http("mcp.supabase.com", "/mcp", Some("project_ref=abc")),
            "mcp:http:mcp.supabase.com/mcp",
        ),
    ] {
        for tool in ["execute_sql", "apply_migration"] {
            let plan = analyze(
                server.clone(),
                tool,
                json!({"project_id": "abc", "name": "drop_users", "query": "DROP TABLE users; TRUNCATE orders"}),
            );
            assert_eq!(
                operations(&plan),
                ["database.schema_drop", "database.truncate"],
                "{tool}"
            );
            for effect in &plan.effects {
                assert_eq!(effect.realm, remote(endpoint));
            }
            assert!(plan.provenance.iter().any(|node| matches!(
                &node.kind,
                ProvenanceKind::ModelApplication { model }
                    if model.starts_with(&format!("mcp/supabase/{tool}@v1#blake3:"))
            )));
            assert!(plan.provenance.iter().any(|node| matches!(
                &node.kind,
                ProvenanceKind::ToolArgument { name } if name == "arguments.query"
            )));
        }
    }
}

#[test]
fn the_tool_name_alone_never_selects_a_model() {
    let drop = json!({"project_id": "abc", "query": "DROP TABLE users"});
    // Specs that keep Supabase's name but run other code, sources of another
    // kind, and lookalike hosts. Each stays opaque, read-only flag or not.
    for (spoof, read_only) in [
        "@supabase/mcp-server-supabase@npm:evil-server",
        "@supabase/mcp-server-supabase@github:evil/mcp",
        "@supabase/mcp-server-supabase@git+https://evil.test/mcp.git",
        "@supabase/mcp-server-supabase@https://evil.test/x.tgz",
        "@supabase/mcp-server-supabase@file:../evil",
        "@supabase/mcp-server-supabase@./evil",
        "@supabase/mcp-server-supabase@",
        // npm reads a tarball extension as a local file, and a bare
        // `user/repo` or `~/` as git or a path; only `latest` is a trusted tag.
        "@supabase/mcp-server-supabase@evil.tgz",
        "@supabase/mcp-server-supabase@EVIL.TAR.GZ",
        "@supabase/mcp-server-supabase@evil.tar",
        "@supabase/mcp-server-supabase@1.0.0-rc.tgz",
        // npm's tarball regex leaves the dot in `tar.gz` unescaped.
        "@supabase/mcp-server-supabase@1.0.0-a.tar-gz",
        "@supabase/mcp-server-supabase@1.0.0-a+b.TAR0GZ",
        "@supabase/mcp-server-supabase@0.13.0 || 1.0.0-rc.tarXgz",
        "@supabase/mcp-server-supabase@evil/mcp",
        "@supabase/mcp-server-supabase@~/evil",
        "@supabase/mcp-server-supabase@evil",
        "@supabase/mcp-server-supabase@0.13.0 || evil.tgz",
        "npm:@supabase/mcp-server-supabase",
        "@evil/mcp-server-supabase",
        "mcp-server-supabase",
    ]
    .into_iter()
    .flat_map(|spec| [(npm(spec, &[]), false), (npm(spec, &["--read-only"]), true)])
    .chain([
        (command("mcp-server-supabase"), false),
        (pypi("mcp-server-supabase"), false),
        (McpServerIdentity::Unknown, false),
        (http("mcp.supabase.com.evil.test", "/mcp", None), false),
        (
            http("mcp.supabase.com.evil.test", "/mcp", Some("read_only=true")),
            true,
        ),
        (http("mcp.supabase.com", "/mcpx", None), false),
        (http("mcp.neon.tech", "/mcp", None), false),
    ]) {
        let plan = analyze(spoof.clone(), "execute_sql", drop.clone());
        assert!(
            plan.effects.is_empty()
                && reasons(&plan) == [BoundaryReason::UNSUPPORTED_TOOL.as_str()],
            "{spoof:?} read_only={read_only}: {:?} {:?}",
            operations(&plan),
            reasons(&plan)
        );
    }
    // A known server's unmodeled tool is opaque too.
    assert_opaque(&analyze(supabase(), "deploy_edge_function", json!({})));
    // Registry versions, ranges and `latest` name the package; host names compare
    // case-insensitively; path segments must match.
    for server in [
        npm("@supabase/mcp-server-supabase", &[]),
        npm("@supabase/mcp-server-supabase@0.13.0", &[]),
        npm("@supabase/mcp-server-supabase@^0.13", &[]),
        npm("@supabase/mcp-server-supabase@latest", &[]),
        npm("@supabase/mcp-server-supabase@>=0.13 <1", &[]),
        npm("@supabase/mcp-server-supabase@0.12 - 0.13.x", &[]),
        npm("@supabase/mcp-server-supabase@^0.12 || ~0.13.0-beta.1", &[]),
        npm("@supabase/mcp-server-supabase@1.0.0-tar-gz", &[]),
        http("MCP.Supabase.com", "/mcp/", None),
    ] {
        let plan = analyze(server, "execute_sql", drop.clone());
        assert_eq!(operations(&plan), ["database.schema_drop"]);
    }
}

#[test]
fn an_observed_read_only_server_passes() {
    let drop = json!({"project_id": "abc", "query": "DROP TABLE users"});
    for (server, endpoint) in [
        (
            npm(
                "@supabase/mcp-server-supabase@0.13.0",
                &["--read-only", "--project-ref=abc"],
            ),
            "mcp:stdio:npm:@supabase/mcp-server-supabase@0.13.0",
        ),
        (
            http(
                "mcp.supabase.com",
                "/mcp",
                Some("project_ref=abc&read_only=true"),
            ),
            "mcp:http:mcp.supabase.com/mcp",
        ),
    ] {
        // Read-only mode runs SQL as a read-only Postgres user, where the
        // server runs any SQL.
        let plan = analyze(server.clone(), "execute_sql", drop.clone());
        assert_eq!(operations(&plan), ["database.read"]);
        assert_eq!(plan.effects[0].realm, remote(endpoint));
        assert!(plan.boundaries.is_empty());
        // Every mutating tool throws before it acts.
        for (tool, arguments) in [
            ("apply_migration", drop.clone()),
            ("delete_branch", json!({"branch_id": "br_1"})),
            ("reset_branch", json!({"branch_id": "br_1"})),
            ("merge_branch", json!({"branch_id": "br_1"})),
            ("rebase_branch", json!({"branch_id": "br_1"})),
            ("pause_project", json!({"project_id": "abc"})),
        ] {
            let plan = analyze(server.clone(), tool, arguments);
            assert!(plan.effects.is_empty(), "{tool}: {:?}", operations(&plan));
            assert!(plan.boundaries.is_empty(), "{tool}: {:?}", reasons(&plan));
        }
    }
    // A flag the server does not read as its option establishes nothing.
    for server in [
        npm("@supabase/mcp-server-supabase", &["--", "--read-only"]),
        http("mcp.supabase.com", "/mcp", Some("read_only=false")),
        http(
            "mcp.supabase.com",
            "/mcp",
            Some("read_only=true&read_only=false"),
        ),
    ] {
        let plan = analyze(server, "execute_sql", drop.clone());
        assert_eq!(operations(&plan), ["database.schema_drop"]);
    }
}

#[test]
fn a_missing_or_non_string_sql_argument_is_unrecoverable_without_an_effect() {
    for arguments in [
        json!({"project_id": "abc"}),
        json!({"project_id": "abc", "query": ["DROP TABLE users"]}),
    ] {
        let plan = analyze(supabase(), "execute_sql", arguments);
        assert!(plan.effects.is_empty(), "{:?}", operations(&plan));
        assert_eq!(
            reasons(&plan),
            [BoundaryReason::UNRECOVERABLE_SOURCE.as_str()]
        );
        assert_eq!(plan.boundaries[0].domains[0].0, "database");
    }
}

#[test]
fn supabase_branch_and_project_tools_emit_their_modeled_effects() {
    let delete = analyze(supabase(), "delete_branch", json!({"branch_id": "br_1"}));
    assert_eq!(operations(&delete), ["cloud.resource.delete"]);
    assert_eq!(delete.effects[0].realm, ExecutionRealm::Host);
    assert!(matches!(
        &delete.effects[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::CloudResource { provider: Some(provider), service, kind, id: Some(id), .. }
        } if provider == "supabase" && service == "branches" && kind == "branch" && id == "br_1"
    ));

    let reset = analyze(supabase(), "reset_branch", json!({"branch_id": "br_1"}));
    assert_eq!(operations(&reset), ["database.schema_drop"]);
    assert_eq!(
        reset.effects[0].attributes.get("object_kind"),
        Some(&AttrValue::String("database".to_string()))
    );

    for tool in ["merge_branch", "rebase_branch"] {
        let plan = analyze(supabase(), tool, json!({"branch_id": "br_1"}));
        assert!(plan.effects.is_empty(), "{tool}");
        assert_eq!(reasons(&plan), ["unresolved_sql"], "{tool}");
    }

    // A project-scoped server injects project_id, so the call may omit it.
    let pause = analyze(supabase(), "pause_project", json!({}));
    assert_eq!(operations(&pause), ["cloud.resource.stop"]);
    assert!(!pause.effects[0].operation.is_destructive());
}

fn compile_delete_many(no_effect_when: Value) -> Result<Engine, effinterp_engine::RegistryError> {
    let delete = |filtered: bool| {
        json!({
            "argument": "$.collection",
            "when": {"arguments": [
                {"argument": "$.options.filter", "shape": "empty", "matches": !filtered},
                {"argument": "$.options.dry_run", "shape": "true", "matches": false}
            ]},
            "emit": [{
                "operation": "database.write",
                "resource": {"kind": "database_table", "table": {"kind": "current"}},
                "attributes": {"filtered": {"kind": "constant_bool", "value": filtered}},
                "modality": "may"
            }]
        })
    };
    let servers = json!([
        {"kind": "command_basename", "name": "test-mcp"},
        {"kind": "pypi_package", "name": "test-mcp-py"}
    ]);
    let mut document = effinterp_model_schema::CandidateDocument {
        schema: effinterp_model_schema::CANDIDATE_SCHEMA_V1.to_string(),
        provenance: serde_json::from_value(json!({"author": "human", "sources": [{"uri": "test:mcp", "digest": format!("blake3:{}", "0".repeat(64))}]})).unwrap(),
        applicability: serde_json::from_value(json!({"platforms": [{"kind": "any"}], "versions": [{"target": "test-mcp", "requirement": "=1"}]})).unwrap(),
        assurance: effinterp_model_schema::AssuranceDeclaration::FixtureVerified,
        evidence: serde_json::from_value(json!({"fixtures": [{"kind": "registry", "name": "test", "expected_entries": ["test/mcp/delete_many@v1"]}], "negative_tests": [{"name": "negative", "subject": {"kind": "exec", "argv": ["true"]}, "absent_operations": ["database.write"]}], "mutation_tests": [{"name": "mutation", "mutation": "drop_first_effect"}], "expected_facts": ["database.write"], "expected_boundaries": []})).unwrap(),
        fragments: Default::default(),
        entries: vec![
            serde_json::from_value(json!({
                "kind": "mcp_tool",
                "id": "test/mcp/delete_many@v1",
                "servers": servers,
                "tool": "delete_many",
                "effects": [delete(false), delete(true)],
                "no_effect_when": no_effect_when
            }))
            .unwrap(),
            // Models only the unfiltered form, so a filtered call is outside it.
            serde_json::from_value(json!({
                "kind": "mcp_tool",
                "id": "test/mcp/delete_all@v1",
                "servers": servers,
                "tool": "delete_all",
                "effects": [delete(false)]
            }))
            .unwrap(),
        ],
    }
    .promoted(String::new());
    document.identity = effinterp_model_schema::document_content_identity(&document);
    let source = effinterp_model_schema::canonical_document_json(&document).unwrap();
    compile_registry_with_builtin(&[&source])
        .map(|registry| Engine::with_catalog(Catalog::from_registry(registry).unwrap()))
}

fn delete_many_engine() -> Engine {
    compile_delete_many(json!([{"arguments": [
        {"argument": "$.options.dry_run", "shape": "true", "matches": true}
    ]}]))
    .unwrap()
}

#[test]
fn argument_conditions_select_rules_and_an_uncovered_call_is_a_boundary() {
    let engine = delete_many_engine();
    let delete = |server: McpServerIdentity, tool: &str, options: Value| {
        analyze_with(
            &engine,
            server,
            tool,
            json!({"collection": "users", "options": options}),
        )
    };
    for (options, filtered) in [
        (json!({}), Some(false)),
        (json!({"filter": {}}), Some(false)),
        (json!({"filter": null, "dry_run": false}), Some(false)),
        (json!({"filter": {"id": 1}}), Some(true)),
        (json!({"filter": {}, "dry_run": true}), None),
    ] {
        let plan = delete(command("test-mcp"), "delete_many", options.clone());
        assert!(plan.boundaries.is_empty(), "{options}");
        match filtered {
            Some(filtered) => {
                assert_eq!(operations(&plan), ["database.write"], "{options}");
                assert_eq!(
                    plan.effects[0].attributes.get("filtered"),
                    Some(&AttrValue::Bool(filtered))
                );
            }
            None => assert!(plan.effects.is_empty(), "{options}"),
        }
    }

    // No rule covers a filtered delete_all: a boundary, not full coverage.
    let plan = delete(
        command("test-mcp"),
        "delete_all",
        json!({"filter": {"id": 1}}),
    );
    assert!(plan.effects.is_empty());
    assert_eq!(
        reasons(&plan),
        [BoundaryReason::UNRECOGNIZED_ARGUMENTS.as_str()]
    );
    assert_ne!(
        plan.coverage.0[&Domain::new("database")].level,
        CoverageLevel::Full
    );

    // Only a bare command resolved through PATH, and only an index release of
    // the PyPI project, is the server.
    for server in [
        pypi("Test_MCP.py==1.2"),
        pypi("test-mcp-py[cli, extra] >=1.0,<2"),
        pypi("test-mcp-py~=1.4.2.post1"),
        pypi("test-mcp-py==1.*"),
    ] {
        assert_eq!(
            operations(&delete(server, "delete_many", json!({}))),
            ["database.write"]
        );
    }
    for spoof in [
        command("/opt/bin/test-mcp"),
        command("./test-mcp"),
        command("node_modules/.bin/test-mcp"),
        npm("test-mcp", &[]),
        pypi("test-mcp-py @ https://evil.test/x.whl"),
        pypi("test-mcp-py@https://evil.test/x.whl"),
        pypi("./test-mcp-py"),
        pypi("test-mcp-py; python_version > '3'"),
        pypi("test-mcp-py.tar.gz"),
        pypi("test-mcp-py==1.0.tar.gz"),
        pypi("test-mcp-py===evil"),
        pypi("test-mcp-py --index-url=https://evil.test/simple"),
    ] {
        assert_opaque(&delete(spoof, "delete_many", json!({})));
    }

    // An empty no_effect_when condition would hold for every call.
    assert!(matches!(
        compile_delete_many(json!([{}])),
        Err(effinterp_engine::RegistryError::InvalidDeclaration { .. })
    ));
}
