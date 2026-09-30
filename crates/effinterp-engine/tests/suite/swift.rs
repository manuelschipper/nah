//! The `swift -e` frontend: which FileManager calls a literal program proves,
//! and that every gate Swift itself enforces keeps the rest one boundary.

use std::collections::BTreeMap;

use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, BoundaryReason, HostContext, Plan, ResourceExpr, ResourceIdentity, Subject,
    validate_plan,
};

fn plan(program: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec!["swift".into(), "-e".into(), program.into()],
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

fn effects(plan: &Plan) -> Vec<(String, String)> {
    plan.effects
        .iter()
        .filter(|effect| effect.operation.0.starts_with("filesystem."))
        .map(|effect| {
            let path = match &effect.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => path.clone(),
                other => effinterp_proto::display_resource(other),
            };
            (effect.operation.0.clone(), path)
        })
        .collect()
}

fn pair(operation: &str, path: &str) -> (String, String) {
    (operation.to_string(), path.to_string())
}

#[test]
fn file_manager_calls_after_import_foundation_reach_their_effects() {
    for marker in ["try", "try?", "try!"] {
        let plan = plan(&format!(
            "import Foundation\n{marker} FileManager.default.removeItem(atPath: \"/tmp/doomed\")"
        ));
        assert_eq!(effects(&plan), [pair("filesystem.delete", "/tmp/doomed")]);
        // `removeItem` deletes a directory with its contents.
        assert_eq!(
            plan.effects
                .iter()
                .find(|effect| effect.operation.0 == "filesystem.delete")
                .and_then(|effect| effect.attributes.get("recursive")),
            Some(&AttrValue::Bool(true))
        );
        assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    }
    let plan = plan(concat!(
        "import Foundation\n",
        "try FileManager.default.moveItem(atPath: \"/tmp/a\", toPath: \"/tmp/b\")\n",
        "try FileManager.default.copyItem(atPath: \"/tmp/c\", toPath: \"/tmp/d\"); ",
        "FileManager.default.createFile(atPath: \"/tmp/e\", contents: nil)\n",
        "/* a comment */ try FileManager.default.createDirectory(atPath: \"/tmp/f\", ",
        "withIntermediateDirectories: true)\n",
        "try FileManager.default.removeItem(atPath: NSHomeDirectory() + \"/g\") // done",
    ));
    assert_eq!(
        effects(&plan),
        [
            pair("filesystem.move", "/tmp/a"),
            pair("filesystem.delete", "/tmp/a"),
            pair("filesystem.write", "/tmp/b"),
            pair("filesystem.read", "/tmp/c"),
            pair("filesystem.write", "/tmp/d"),
            pair("filesystem.write", "/tmp/e"),
            pair("filesystem.create", "/tmp/f"),
            pair("filesystem.delete", "/home/test/g"),
        ]
    );
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
}

#[test]
fn swift_gates_and_unmodeled_forms_withhold_every_effect() {
    let remove = "try! FileManager.default.removeItem(atPath: \"/tmp/doomed\")";
    for program in [
        // FileManager needs Foundation, and a throwing call needs `try`.
        remove.to_string(),
        "import Foundation\nFileManager.default.removeItem(atPath: \"/tmp/doomed\")".into(),
        // A type declaration anywhere in the file shadows FileManager.
        format!("import Foundation\n{remove}\nclass FileManager {{}}"),
        // A closure body runs only when called.
        format!("import Foundation\nlet f = {{ {remove} }}"),
        // Argument labels are case-sensitive.
        "import Foundation\ntry! FileManager.default.removeItem(atpath: \"/tmp/doomed\")".into(),
        "import Foundation\ntry! FileManager.default.removeItem(at: URL(fileURLWithPath: \"/tmp/doomed\"))".into(),
        "import Foundation\nlet p = Process(); p.executableURL = URL(fileURLWithPath: \"/bin/rm\"); try p.run()".into(),
        "import Foundation\ntry! FileManager.default.removeItem(atPath: \"/tmp/\\(name)\")".into(),
    ] {
        let plan = plan(&program);
        assert!(effects(&plan).is_empty(), "{program}");
        assert!(
            plan.boundaries.iter().any(|boundary| boundary.reason
                == BoundaryReason::UNRECOGNIZED_ARGUMENTS
                && !boundary.provenance.is_empty()),
            "{program}"
        );
    }
}
