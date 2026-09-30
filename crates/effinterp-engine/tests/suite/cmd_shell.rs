//! The Windows command interpreter's command line: separators, links, and the
//! copy programs it launches.

use std::collections::BTreeMap;

use effinterp_engine::Engine;
use effinterp_proto::{
    CoverageLevel, Domain, HostContext, Plan, ResourceExpr, ResourceIdentity, Subject,
    validate_plan,
};

fn plan(source: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: source.to_string(),
            cwd: Some("/workspace/project".into()),
            context: HostContext {
                env: BTreeMap::from([("HOME".to_string(), "/home/test".to_string())]),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn paths(plan: &Plan, operation: &str) -> Vec<String> {
    plan.effects
        .iter()
        .filter(|effect| effect.operation.0 == operation)
        .map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => path.clone(),
            other => effinterp_proto::display_resource(other),
        })
        .collect()
}

fn filesystem_coverage(plan: &Plan) -> Option<CoverageLevel> {
    plan.coverage.level(&Domain::new("filesystem"))
}

#[test]
fn command_separators_interpret_every_command() {
    // `&` runs both commands; a quoted `&` and a caret-escaped one are text.
    for source in [
        "cmd /c 'echo hi & rd /s /q C:\\Users\\test'",
        "cmd /c 'echo \"a & b\" & rd /s /q C:\\Users\\test'",
        "cmd /c 'echo a ^& b & rd /s /q C:\\Users\\test'",
    ] {
        let plan = plan(source);
        assert_eq!(
            paths(&plan, "filesystem.delete"),
            ["C:/Users/test"],
            "{source}"
        );
        assert_eq!(
            filesystem_coverage(&plan),
            Some(CoverageLevel::Full),
            "{source}"
        );
    }
    // A conditional or piped command still runs, but which one runs, and in
    // which process, is decided at runtime.
    for source in [
        "cmd /c 'cd C:\\ && rd /s /q C:\\Users\\test'",
        "cmd /c 'type C:\\safe || rd /s /q C:\\Users\\test'",
        "cmd /c 'echo y | rd /s C:\\Users\\test'",
    ] {
        let plan = plan(source);
        assert_eq!(
            paths(&plan, "filesystem.delete"),
            ["C:/Users/test"],
            "{source}"
        );
        assert_eq!(
            filesystem_coverage(&plan),
            Some(CoverageLevel::Partial),
            "{source}"
        );
    }
    // A command the grammar refuses keeps its boundary without hiding the rest.
    let refused = plan("cmd /c 'dir C:\\ & del C:\\Users\\test\\x'");
    assert_eq!(paths(&refused, "filesystem.delete"), ["C:/Users/test/x"]);
    assert!(!refused.boundaries.is_empty());
    // An empty command around a separator is a syntax error, not a no-op.
    let empty = plan("cmd /c '&& del C:\\Users\\test\\x'");
    assert!(paths(&empty, "filesystem.delete").is_empty());
}

#[test]
fn mklink_hard_link_names_the_target_file_again() {
    let hard = plan("cmd /c 'mklink /h C:\\safe C:\\Users\\test\\.nah\\config.toml'");
    assert_eq!(paths(&hard, "filesystem.create"), ["C:/safe"]);
    let read = hard
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.read")
        .expect("hard link target read");
    assert_eq!(
        paths(&hard, "filesystem.read"),
        ["C:/Users/test/.nah/config.toml"]
    );
    assert_eq!(
        read.attributes["metadata"],
        effinterp_proto::AttrValue::Bool(true)
    );
    // Symbolic links and junctions stay outside the grammar.
    let symbolic = plan("cmd /c 'mklink /d C:\\safe C:\\Users\\test'");
    assert!(paths(&symbolic, "filesystem.create").is_empty());
    assert!(!symbolic.boundaries.is_empty());
}

#[test]
fn xcopy_and_robocopy_write_their_destination() {
    for source in [
        "cmd /c 'xcopy /y C:\\safe C:\\Users\\test\\.nah\\config.toml'",
        "cmd /c 'robocopy C:\\safe C:\\Users\\test\\.nah config.toml /e /r:1'",
    ] {
        let plan = plan(source);
        assert_eq!(paths(&plan, "filesystem.read"), ["C:/safe"], "{source}");
        assert!(
            paths(&plan, "filesystem.write")[0].starts_with("C:/Users/test/.nah"),
            "{source}"
        );
        assert_eq!(
            filesystem_coverage(&plan),
            Some(CoverageLevel::Partial),
            "{source}"
        );
    }
    // A switch outside the reviewed set, such as robocopy's /MIR purge, is
    // named as a gap rather than read as a plain copy.
    let mirror = plan("robocopy C:\\safe C:\\Users\\test /mir");
    assert!(mirror.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("/mir"))
    }));
}
