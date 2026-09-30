use effinterp_engine::{Catalog, Engine};
use effinterp_proto::{
    ExecutionRealm, Plan, ResourceExpr, ResourceFamily, ResourceIdentity, Subject, validate_plan,
};

fn exec(argv: &[&str]) -> Plan {
    checked_plan(Subject::Exec {
        argv: argv.iter().map(|value| value.to_string()).collect(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    })
}

fn checked_plan(subject: Subject) -> Plan {
    let plan = Engine::new().analyze(&subject).unwrap();
    validate_plan(&plan).unwrap_or_else(|error| panic!("invalid plan for {subject:?}: {error:?}"));
    plan
}

fn boundary(plan: &Plan, reason: &str) -> bool {
    plan.boundaries
        .iter()
        .any(|boundary| boundary.reason.as_str() == reason)
}

fn remote_delete(plan: &Plan, endpoint: &str, path: &str) -> bool {
    plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.realm
                == (ExecutionRealm::Remote {
                    endpoint: endpoint.to_string(),
                })
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: actual }
            } if actual == path)
    })
}

fn unresolved_connect(plan: &Plan) -> bool {
    plan.effects.iter().any(|effect| {
        effect.operation.0 == "network.connect"
            && effect.resource
                == ResourceExpr::Unresolved {
                    family: ResourceFamily::new("network"),
                }
    })
}

#[test]
fn vagrant_ssh_connects_and_nests_named_and_default_commands() {
    for (argv, endpoint) in [
        (
            &["vagrant", "ssh", "-c", "rm -rf /x"][..],
            "vagrant:default",
        ),
        (
            &["vagrant", "ssh", "web", "-c", "rm -rf /x"][..],
            "vagrant:web",
        ),
        (
            &["vagrant", "ssh", "--", "-t", "rm -rf /x"][..],
            "vagrant:default",
        ),
    ] {
        let plan = exec(argv);
        assert!(remote_delete(&plan, endpoint, "/x"), "{argv:?}");
        assert!(unresolved_connect(&plan), "{argv:?}");
        assert!(!boundary(&plan, "unmodeled_command"), "{argv:?}");
    }

    let interactive = exec(&["vagrant", "ssh"]);
    assert!(unresolved_connect(&interactive));
    assert!(
        !interactive
            .execution_graph
            .nodes
            .iter()
            .any(|node| matches!(node.realm, ExecutionRealm::Remote { .. }))
    );

    let unmodeled = exec(&["vagrant", "up"]);
    assert!(boundary(&unmodeled, "unmodeled_subcommand"));
}

#[test]
fn lima_exec_words_run_in_the_selected_guest_and_workdir() {
    let plan = exec(&["limactl", "shell", "default", "rm", "-rf", "/x"]);
    assert!(remote_delete(&plan, "lima:default", "/x"));
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        node.realm
            == (ExecutionRealm::Remote {
                endpoint: "lima:default".to_string(),
            })
            && matches!(&node.subject, Subject::Exec { argv, .. }
                if argv == &["rm", "-rf", "/x"])
    }));

    let workdir = exec(&[
        "limactl",
        "shell",
        "--workdir",
        "/srv",
        "default",
        "rm",
        "-rf",
        "data",
    ]);
    assert!(remote_delete(&workdir, "lima:default", "/srv/data"));

    let relative = exec(&["limactl", "shell", "default", "rm", "-rf", "data"]);
    let delete = relative
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
        if matches!(parts.first(), Some(ResourceExpr::Parameter { name }) if name == "cwd")));

    let bare = exec(&["lima", "rm", "-rf", "/x"]);
    assert!(remote_delete(&bare, "lima:$LIMA_INSTANCE", "/x"));

    let interactive = exec(&["limactl", "shell", "default"]);
    assert!(
        !interactive
            .execution_graph
            .nodes
            .iter()
            .any(|node| matches!(node.realm, ExecutionRealm::Remote { .. }))
    );
}

#[test]
fn multipass_exec_runs_words_in_the_named_guest() {
    let plan = exec(&["multipass", "exec", "vm", "--", "rm", "-rf", "/x"]);
    assert!(remote_delete(&plan, "multipass:vm", "/x"));
}

#[test]
fn remote_model_catalog_ownership_and_output_are_deterministic() {
    let catalog = Catalog::builtin();
    for command in ["vagrant", "limactl", "lima", "multipass"] {
        let model = catalog.find(command).unwrap();
        let expected = match command {
            "vagrant" => "hashicorp/vagrant@v0",
            "limactl" | "lima" => "lima-vm/limactl@v0",
            "multipass" => "canonical/multipass@v0",
            _ => unreachable!(),
        };
        assert_eq!(model.id(), expected);
    }

    let argv = &["limactl", "shell", "default", "rm", "-rf", "/x"];
    assert_eq!(
        effinterp_proto::canonical_json(&exec(argv)),
        effinterp_proto::canonical_json(&exec(argv))
    );
}
