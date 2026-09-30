//! Metamorphic perturbation suite: each test pairs a base subject with a small
//! semantic mutation and asserts the SPECIFIC delta between the two plans'
//! effect sets — guarding against expectations being satisfied by unrelated
//! effects. Cross-file and flow-graph perturbations (import rename, variable
//! rebinding, repo-composed callbacks) live in the harness perturbation suite.

use std::collections::BTreeSet;

use effinterp_engine::Engine;
use effinterp_proto::{
    ExecutionRealm, Plan, ResourceExpr, ResourceIdentity, SourceDialect, Subject, validate_plan,
};

fn analyze(subject: Subject) -> Plan {
    let plan = Engine::new().analyze(&subject).unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    plan
}

fn shell(source: &str) -> Plan {
    analyze(Subject::Shell {
        source: source.to_string(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    })
}

fn exec(argv: &[&str]) -> Plan {
    analyze(Subject::Exec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    })
}

fn js(source: &str) -> Plan {
    analyze(Subject::Source {
        language: "js".into(),
        source: source.to_string(),
        dialect: Some(SourceDialect::Js),
        cwd: Some("/app".to_string()),
        context: Default::default(),
    })
}

fn render(expr: &ResourceExpr) -> String {
    match expr {
        ResourceExpr::Concrete { identity } => match identity {
            ResourceIdentity::FsPath { path } => path.clone(),
            ResourceIdentity::Process { executable, .. } => executable.clone(),
            ResourceIdentity::NetworkEndpoint { host, .. } => host.clone(),
            other => format!("{other:?}"),
        },
        ResourceExpr::Parameter { name } => format!("<{name}>"),
        ResourceExpr::Environment { name } => format!("${name}"),
        ResourceExpr::Unresolved { family } => format!("?{}", family.0),
        other => format!("{other:?}"),
    }
}

/// A plan's effect set as (operation, rendered resource) keys.
fn effects(plan: &Plan) -> BTreeSet<(String, String)> {
    plan.effects
        .iter()
        .map(|e| (e.operation.0.clone(), render(&e.resource)))
        .collect()
}

/// Effects gained by the mutant, then effects lost by it.
type EffectDelta = (BTreeSet<(String, String)>, BTreeSet<(String, String)>);

/// The exact delta between two plans' effect sets: (gained by mutant, lost by
/// mutant). Asserting on this keeps each perturbation honest — the mutation
/// must change exactly what it claims to change.
fn delta(base: &Plan, mutant: &Plan) -> EffectDelta {
    let b = effects(base);
    let m = effects(mutant);
    let gained = m.difference(&b).cloned().collect();
    let lost = b.difference(&m).cloned().collect();
    (gained, lost)
}

fn key(op: &str, resource: &str) -> (String, String) {
    (op.to_string(), resource.to_string())
}

fn set(entries: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    entries.iter().map(|(o, r)| key(o, r)).collect()
}

// 1a. Read flag -> write flag: `sed -i` edits its input in place, so the
// mutation adds exactly the in-place write and nothing else.
#[test]
fn sed_in_place_flag_adds_the_write() {
    let base = exec(&["sed", "s/a/b/", "notes.txt"]);
    let mutant = exec(&["sed", "-i", "s/a/b/", "notes.txt"]);

    assert!(effects(&base).contains(&key("filesystem.read", "/w/notes.txt")));
    assert!(!effects(&base).contains(&key("filesystem.write", "/w/notes.txt")));
    assert!(effects(&mutant).contains(&key("filesystem.write", "/w/notes.txt")));

    let (gained, lost) = delta(&base, &mutant);
    assert_eq!(gained, set(&[("filesystem.write", "/w/notes.txt")]));
    assert!(
        lost.is_empty(),
        "in-place flag must not drop effects: {lost:?}"
    );
}

// 1b. Read flag -> write flag, curl form: `-o` turns the plain request into a
// download that writes the output file.
#[test]
fn curl_output_flag_swaps_request_for_download_and_write() {
    let base = exec(&["curl", "https://example.com/f"]);
    let mutant = exec(&["curl", "-o", "out.txt", "https://example.com/f"]);

    let (gained, lost) = delta(&base, &mutant);
    assert_eq!(
        gained,
        set(&[
            ("network.download", "example.com"),
            ("filesystem.write", "/w/out.txt"),
        ])
    );
    assert_eq!(lost, set(&[("network.request", "example.com")]));
}

// 2. Output redirect -> stdout: `cmd > f` carries the file write; the bare
// command does not.
#[test]
fn dropping_the_redirect_drops_the_write() {
    let base = shell("echo hi > out.log");
    let mutant = shell("echo hi");

    assert!(effects(&base).contains(&key("filesystem.write", "/w/out.log")));

    let (gained, lost) = delta(&base, &mutant);
    assert!(
        gained.is_empty(),
        "removing a redirect must not add effects: {gained:?}"
    );
    assert_eq!(lost, set(&[("filesystem.write", "/w/out.log")]));
}

// 3. Remove an upload option: `-T` uploads the local file (and reads it);
// without it the same URL is a plain request.
#[test]
fn removing_upload_flag_removes_upload_and_payload_read() {
    let base = exec(&["curl", "-T", "data.tgz", "https://reg.example.com/up"]);
    let mutant = exec(&["curl", "https://reg.example.com/up"]);

    let (gained, lost) = delta(&base, &mutant);
    assert_eq!(gained, set(&[("network.request", "reg.example.com")]));
    assert_eq!(
        lost,
        set(&[
            ("network.upload", "reg.example.com"),
            ("filesystem.read", "/w/data.tgz"),
        ])
    );
}

// 5. Literal path -> dynamic input: the delete's resource must change CLASS
// (concrete path -> unresolved), not merely value.
#[test]
fn dynamic_operand_changes_resource_class() {
    let base = shell("rm /tmp/x");
    let mutant = shell("rm \"$1\"");

    let delete_of = |plan: &Plan| {
        plan.effects
            .iter()
            .find(|e| e.operation.0 == "filesystem.delete")
            .expect("rm produces a delete")
            .resource
            .clone()
    };
    assert!(matches!(
        delete_of(&base),
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/tmp/x"
    ));
    assert!(matches!(
        delete_of(&mutant),
        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
    ));
}

// 6. Move a call behind a never-executed definition: the defined-but-uncalled
// body contributes nothing; adding the call contributes exactly its effects.
#[test]
fn shell_function_effects_track_the_call_site() {
    let base = shell("cleanup() { rm -rf /var/cache/app; }\ncleanup");
    let mutant = shell("cleanup() { rm -rf /var/cache/app; }");

    assert!(effects(&base).contains(&key("filesystem.delete", "/var/cache/app")));
    assert!(
        mutant.effects.is_empty(),
        "uncalled function leaked effects: {:?}",
        effects(&mutant)
    );

    let (gained, lost) = delta(&base, &mutant);
    assert!(gained.is_empty());
    assert_eq!(
        lost,
        set(&[
            ("process.exec", "rm"),
            ("filesystem.delete", "/var/cache/app"),
        ])
    );
}

// 8. Change container realm: the same delete moves from the host realm into
// the container's realm when wrapped in `docker exec`.
#[test]
fn docker_exec_moves_the_delete_into_the_container_realm() {
    let realm_of = |plan: &Plan| {
        plan.effects
            .iter()
            .find(|e| {
                e.operation.0 == "filesystem.delete"
                    && matches!(
                        &e.resource,
                        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                            if path == "/x"
                    )
            })
            .expect("delete on /x")
            .realm
            .clone()
    };

    let base = shell("docker exec c1 rm /x");
    let mutant = shell("rm /x");
    assert_eq!(
        realm_of(&base),
        ExecutionRealm::Container {
            runtime: "docker".to_string(),
            name: "c1".to_string(),
        }
    );
    assert_eq!(realm_of(&mutant), ExecutionRealm::Host);
}

// 9. Replace a callback with a different function: effects follow the
// actually-passed callback, so swapping in an effect-free one removes exactly
// the callback's effects.
#[test]
fn js_callback_swap_removes_the_callback_effects() {
    let base = js(r#"
        const fs = require('fs');
        [1, 2].forEach(() => fs.unlinkSync('/cb'));
    "#);
    let mutant = js(r#"
        const fs = require('fs');
        [1, 2].forEach(() => {});
    "#);

    assert!(effects(&base).contains(&key("filesystem.delete", "/cb")));

    let (gained, lost) = delta(&base, &mutant);
    assert!(gained.is_empty());
    assert_eq!(lost, set(&[("filesystem.delete", "/cb")]));
}
