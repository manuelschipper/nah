use std::collections::HashMap;

use effinterp_engine::{
    Assurance, LIFECYCLE_CATALOG, Lang, LifecycleSig, ResolvedObject, ScopeKey, TypeRef,
    ValueOrigin,
};
use effinterp_model_schema::{SigEvidence, SigRole};

#[test]
fn assurance_orders_weakest_last() {
    assert!(Assurance::Exact < Assurance::Alternatives);
    assert!(Assurance::Alternatives < Assurance::Heuristic);
}

#[test]
fn shared_identity_and_type_shapes_are_constructible() {
    let module_scope = ScopeKey::Module {
        key: "pkg.cli".into(),
    };
    let go_scope = ScopeKey::GoPackage {
        key: "example.com/tool/cmd".into(),
    };
    let rust_scope = ScopeKey::RustModule {
        key: "tool::cmd".into(),
    };
    assert_ne!(module_scope, go_scope);
    assert_ne!(go_scope, rust_scope);

    let module_origin = ValueOrigin::Module {
        scope: module_scope,
        name: "parser".into(),
    };
    let local_origin = ValueOrigin::Local {
        file: "src/main.py".into(),
        function: "main".into(),
        name: "command".into(),
    };
    let site_origin = ValueOrigin::Site {
        file: "cmd/root.go".into(),
        function: "build".into(),
        ordinal: 3,
        result_index: 1,
    };
    assert_ne!(module_origin, local_origin);
    assert_ne!(local_origin, site_origin);

    let repo_type = TypeRef::Repo {
        file: "src/app.py".into(),
        name: "App".into(),
    };
    let external_type = TypeRef::External {
        path: "argparse.ArgumentParser".into(),
    };
    let child = ResolvedObject {
        file: "src/app.py".into(),
        class_name: "Child".into(),
        attrs: HashMap::new(),
        values: Default::default(),
        origin: Some(local_origin),
        ty: Some(repo_type),
    };
    let instance = ResolvedObject {
        file: String::new(),
        class_name: "ArgumentParser".into(),
        attrs: HashMap::from([("child".into(), child.clone())]),
        values: Default::default(),
        origin: Some(module_origin),
        ty: Some(external_type.clone()),
    };

    assert_eq!(instance.attrs.get("child"), Some(&child));
    assert_eq!(instance.ty, Some(external_type));
    assert_eq!(
        ResolvedObject {
            file: "src/legacy.py".into(),
            class_name: "Legacy".into(),
            attrs: HashMap::new(),
            values: Default::default(),
            origin: None,
            ty: None,
        }
        .origin,
        None
    );
}

#[allow(clippy::too_many_arguments)]
fn assert_sig(
    sig: &LifecycleSig,
    method: Option<&str>,
    role: SigRole,
    max_args: Option<usize>,
    evidence: SigEvidence,
    receiver_type: Option<&str>,
    fields: &[&str],
    params: &[&str],
    hooks: &[&str],
    derive_result: Option<usize>,
) {
    assert_eq!(sig.method, method);
    assert_eq!(sig.import_path, None);
    assert_eq!(sig.role, role);
    assert_eq!(sig.max_args, max_args);
    assert_eq!(sig.evidence, evidence);
    assert_eq!(sig.receiver_type, receiver_type);
    assert_eq!(sig.fields, fields);
    assert_eq!(sig.params, params);
    assert_eq!(sig.hooks, hooks);
    assert_eq!(sig.derive_result, derive_result);
    assert_eq!(sig.result_type, None);
    assert!(sig.field_tags.is_empty());
}

#[test]
fn lifecycle_catalog_is_the_exact_compiled_seed() {
    assert_eq!(LIFECYCLE_CATALOG.len(), 8);

    let cobra = LIFECYCLE_CATALOG
        .iter()
        .find(|framework| framework.id == "cobra")
        .unwrap();
    assert_eq!(cobra.id, "cobra");
    assert_eq!(cobra.lang, Some(Lang::Go));
    assert_eq!(cobra.sigs.len(), 6);
    assert_sig(
        &cobra.sigs[0],
        None,
        SigRole::Registers,
        None,
        SigEvidence::TypedReceiver,
        Some("github.com/spf13/cobra.Command"),
        &[
            "Run",
            "RunE",
            "PreRun",
            "PreRunE",
            "PostRun",
            "PostRunE",
            "PersistentPreRun",
            "PersistentPreRunE",
            "PersistentPostRun",
            "PersistentPostRunE",
        ],
        &[],
        &[],
        None,
    );
    assert_sig(
        &cobra.sigs[1],
        Some("AddCommand"),
        SigRole::Attaches,
        None,
        SigEvidence::TypedReceiver,
        Some("github.com/spf13/cobra.Command"),
        &[],
        &[],
        &[],
        None,
    );
    for (sig, method) in
        cobra.sigs[2..]
            .iter()
            .zip(["Execute", "ExecuteC", "ExecuteContext", "ExecuteContextC"])
    {
        assert_sig(
            sig,
            Some(method),
            SigRole::Dispatches,
            Some(1),
            SigEvidence::TypedReceiver,
            Some("github.com/spf13/cobra.Command"),
            &[],
            &[],
            &[],
            None,
        );
    }

    let kong = LIFECYCLE_CATALOG
        .iter()
        .find(|framework| framework.id == "kong")
        .unwrap();
    assert_eq!(kong.lang, Some(Lang::Go));
    assert_eq!(kong.sigs.len(), 2);
    let parse = &kong.sigs[0];
    assert_eq!(parse.method, Some("Parse"));
    assert_eq!(parse.import_path, Some("github.com/alecthomas/kong"));
    assert_eq!(parse.role, SigRole::Registers);
    assert_eq!(parse.evidence, SigEvidence::ExactImport);
    assert_eq!(parse.hooks, ["Run"]);
    assert_eq!(parse.derive_result, Some(0));
    assert_eq!(
        parse.result_type,
        Some("github.com/alecthomas/kong.Context")
    );
    assert_eq!(parse.field_tags, ["cmd"]);
    assert_sig(
        &kong.sigs[1],
        Some("Run"),
        SigRole::Dispatches,
        None,
        SigEvidence::TypedReceiver,
        Some("github.com/alecthomas/kong.Context"),
        &[],
        &[],
        &[],
        None,
    );

    let urfave = LIFECYCLE_CATALOG
        .iter()
        .find(|framework| framework.id == "urfave-cli-v3")
        .unwrap();
    assert_eq!(urfave.lang, Some(Lang::Go));
    assert_eq!(urfave.sigs.len(), 2);
    assert_sig(
        &urfave.sigs[0],
        None,
        SigRole::Registers,
        None,
        SigEvidence::TypedReceiver,
        Some("github.com/urfave/cli/v3.Command"),
        &["Action"],
        &[],
        &[],
        None,
    );
    assert_sig(
        &urfave.sigs[1],
        Some("Run"),
        SigRole::Dispatches,
        Some(2),
        SigEvidence::TypedReceiver,
        Some("github.com/urfave/cli/v3.Command"),
        &[],
        &[],
        &[],
        None,
    );

    let symfony = LIFECYCLE_CATALOG
        .iter()
        .find(|framework| framework.id == "symfony-console")
        .unwrap();
    assert_eq!(symfony.lang, Some(Lang::Php));
    assert_eq!(symfony.sigs.len(), 2);
    assert_sig(
        &symfony.sigs[0],
        Some("getDefaultCommands"),
        SigRole::Registers,
        None,
        SigEvidence::TypedReceiver,
        Some("Symfony\\Component\\Console\\Application"),
        &[],
        &[],
        &["execute"],
        None,
    );
    assert_sig(
        &symfony.sigs[1],
        Some("run"),
        SigRole::Dispatches,
        Some(2),
        SigEvidence::TypedReceiver,
        Some("Symfony\\Component\\Console\\Application"),
        &[],
        &[],
        &[],
        None,
    );

    let argparse = LIFECYCLE_CATALOG
        .iter()
        .find(|framework| framework.id == "argparse")
        .unwrap();
    assert_eq!(argparse.id, "argparse");
    assert_eq!(argparse.lang, Some(Lang::Python));
    assert_eq!(argparse.sigs.len(), 6);
    assert_sig(
        &argparse.sigs[0],
        Some("set_defaults"),
        SigRole::Registers,
        None,
        SigEvidence::NameAndImport,
        Some("argparse.ArgumentParser"),
        &[],
        &["func"],
        &[],
        None,
    );
    for (sig, method) in argparse.sigs[1..3]
        .iter()
        .zip(["add_subparsers", "add_parser"])
    {
        assert_sig(
            sig,
            Some(method),
            SigRole::DerivesDispatcher,
            None,
            SigEvidence::NameAndImport,
            Some("argparse.ArgumentParser"),
            &[],
            &[],
            &[],
            Some(0),
        );
    }
    for (sig, method) in
        argparse.sigs[3..]
            .iter()
            .zip(["parse_args", "parse_known_args", "parse_intermixed_args"])
    {
        assert_sig(
            sig,
            Some(method),
            SigRole::Dispatches,
            None,
            SigEvidence::NameAndImport,
            Some("argparse.ArgumentParser"),
            &[],
            &[],
            &[],
            None,
        );
    }

    let cleo = LIFECYCLE_CATALOG
        .iter()
        .find(|framework| framework.id == "cleo-application")
        .unwrap();
    assert_eq!(cleo.id, "cleo-application");
    assert_eq!(cleo.lang, Some(Lang::Python));
    assert_sig(
        &cleo.sigs[0],
        Some("run"),
        SigRole::Dispatches,
        None,
        SigEvidence::TypedReceiver,
        Some("cleo.application.Application"),
        &[],
        &[],
        &["_run"],
        None,
    );

    let thor = LIFECYCLE_CATALOG
        .iter()
        .find(|framework| framework.id == "thor-command")
        .unwrap();
    assert_eq!(thor.lang, Some(Lang::Ruby));
    assert_eq!(thor.sigs.len(), 2);
    assert_sig(
        &thor.sigs[0],
        Some("desc"),
        SigRole::Registers,
        None,
        SigEvidence::TypedReceiver,
        Some("thor.Thor"),
        &[],
        &["command"],
        &[],
        None,
    );
    assert_sig(
        &thor.sigs[1],
        Some("start"),
        SigRole::Dispatches,
        None,
        SigEvidence::TypedReceiver,
        Some("thor.Thor"),
        &[],
        &[],
        &[],
        None,
    );
}
