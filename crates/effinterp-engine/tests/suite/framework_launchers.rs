//! Framework launchers reach the database command models: Django's
//! `manage.py`, Laravel's `artisan`, Symfony's `bin/console`, and
//! package-manager shorthands that run a project's local binary.

use std::collections::HashMap;

use effinterp_engine::{
    Engine, SourceRefusal, SourceRequest, SourceResolver, SourceResponse, UnavailableReason,
};
use effinterp_proto::{Plan, Subject, validate_plan};

struct Files(HashMap<&'static str, &'static str>);

impl SourceResolver for Files {
    fn source_mutation_disjoint(
        &self,
        _: &effinterp_proto::ResourceExpr,
        _: SourceRequest<'_>,
    ) -> bool {
        true
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.0
            .get(request.path.trim_start_matches('/'))
            .map_or_else(
                || SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
                |source| SourceResponse::Source(source.as_bytes().to_vec()),
            )
    }

    fn siblings(&self, _: &str) -> Option<Vec<String>> {
        None
    }
}

fn analyze(files: &[(&'static str, &'static str)], argv: &[&str]) -> Plan {
    let plan = Engine::new()
        .with_resolver(Box::new(Files(files.iter().copied().collect())))
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|word| word.to_string()).collect(),
            cwd: Some(String::new()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn database_effects(plan: &Plan) -> Vec<(String, Option<String>)> {
    plan.effects
        .iter()
        .filter(|effect| effect.operation.0.starts_with("database."))
        .map(|effect| {
            (
                effect.operation.0.clone(),
                effect
                    .attributes
                    .get("object_kind")
                    .map(|kind| format!("{kind:?}")),
            )
        })
        .collect()
}

fn has_boundary(plan: &Plan, reason: &str) -> bool {
    plan.boundaries
        .iter()
        .any(|boundary| boundary.reason.as_str() == reason)
}

const MANAGE_PY: &str = r#"#!/usr/bin/env python
import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "site.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError("Couldn't import Django.") from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
"#;

#[test]
fn django_management_commands_reach_the_django_admin_model() {
    let truncate = || vec![("database.truncate".to_string(), None)];
    // Django's generated script hands sys.argv to the dispatcher, from inside
    // the summarized main(), directly or through its shebang.
    for argv in [
        &["python3", "manage.py", "flush", "--noinput"][..],
        &["./manage.py", "flush"][..],
    ] {
        let plan = analyze(&[("manage.py", MANAGE_PY)], argv);
        assert_eq!(database_effects(&plan), truncate(), "{argv:?}");
        assert!(has_boundary(&plan, "unresolved_call"), "{argv:?}");
    }
    // Literal writes to sys.argv, under any alias, and a literal vector are
    // replayed; comments and strings that mention argv do not matter.
    let head = "import sys\nfrom django.core.management import execute_from_command_line\n";
    for (body, launch) in [
        (
            "sys.argv.append('--noinput')\nexecute_from_command_line(sys.argv)\n",
            "flush",
        ),
        (
            "sys.argv[1] = 'flush'\nexecute_from_command_line(sys.argv)\n",
            "check",
        ),
        (
            "from sys import argv as args\nargs.insert(1, 'flush')\nexecute_from_command_line(args)\n",
            "--noinput",
        ),
        (
            "execute_from_command_line(['manage.py', 'flush'])\n",
            "check",
        ),
        (
            "# argv is sys.argv\nprint('argv')\nexecute_from_command_line(sys.argv)\n",
            "flush",
        ),
        // Django reads `argv or sys.argv[:]`: an empty vector or None is
        // the process's argv, with its writes.
        ("execute_from_command_line([])\n", "flush"),
        ("execute_from_command_line(argv=None)\n", "flush"),
        (
            "sys.argv[1] = 'flush'\nexecute_from_command_line(())\n",
            "check",
        ),
    ] {
        let source = format!("{head}{body}");
        let plan = analyze(
            &[("manage.py", Box::leak(source.into_boxed_str()))],
            &["python3", "manage.py", launch],
        );
        assert_eq!(database_effects(&plan), truncate(), "{body}");
    }
    // A literal vector replaces the launch, and an empty one keeps a
    // harmless launch harmless; a write Nah cannot recover runs
    // no command it can name and says so; a script that never calls Django
    // runs none.
    for (body, launch, argv_boundary) in [
        (
            "execute_from_command_line(['manage.py', 'check'])\n",
            "flush",
            false,
        ),
        ("execute_from_command_line([])\n", "check", false),
        (
            "import os\nsys.argv[1] = os.environ['CMD']\nexecute_from_command_line(sys.argv)\n",
            "flush",
            true,
        ),
        (
            "args = sys.argv\nexecute_from_command_line(args)\n",
            "flush",
            true,
        ),
        ("print(sys.argv)\n", "flush", false),
    ] {
        let source = format!("{head}{body}");
        let plan = analyze(
            &[("manage.py", Box::leak(source.into_boxed_str()))],
            &["python3", "manage.py", launch],
        );
        assert!(database_effects(&plan).is_empty(), "{body}");
        assert_eq!(
            has_boundary(&plan, "input_determined_arguments"),
            argv_boundary,
            "{body}"
        );
    }
    // An unreadable manage.py is taken for the generated script, beside the
    // boundary that its bytes were not read; `-m django` is the dispatcher.
    for argv in [
        &["python3", "manage.py", "flush"][..],
        &["./manage.py", "flush"][..],
        &["python3", "-m", "django", "flush"][..],
    ] {
        let plan = analyze(&[], argv);
        assert_eq!(database_effects(&plan), truncate(), "{argv:?}");
    }
    assert!(has_boundary(
        &analyze(&[], &["python3", "manage.py", "flush"]),
        "unrecoverable_source"
    ));
    assert!(database_effects(&analyze(&[], &["python3", "manage.py", "migrate"])).is_empty());
    assert!(database_effects(&analyze(&[], &["python3", "tool.py", "flush"])).is_empty());
}

#[test]
fn php_entry_scripts_dispatch_by_their_framework_name() {
    for (argv, expected) in [
        (&["php", "artisan", "db:wipe"][..], Some("database_objects")),
        (
            &["php", "bin/console", "doctrine:database:drop", "--force"][..],
            Some("database"),
        ),
        (&["php", "bin/console", "doctrine:database:drop"][..], None),
        (&["php", "artisan", "migrate"][..], None),
        (&["php", "tool.php", "db:wipe"][..], None),
        // `-f`/`--file` names the same entry script.
        (
            &["php", "-f", "artisan", "db:wipe"][..],
            Some("database_objects"),
        ),
        (
            &[
                "php",
                "--file",
                "bin/console",
                "--",
                "doctrine:database:drop",
                "--force",
            ][..],
            Some("database"),
        ),
        // A colon-segment abbreviation resolves against the reviewed name.
        (
            &["php", "bin/console", "d:d:d", "--force"][..],
            Some("database"),
        ),
        (&["php", "bin/console", "d:d:c"][..], None),
    ] {
        let effects = database_effects(&analyze(&[], argv));
        match expected {
            Some(kind) => assert_eq!(
                effects,
                vec![(
                    "database.schema_drop".to_string(),
                    Some(format!(
                        "{:?}",
                        effinterp_proto::AttrValue::String(kind.into())
                    ))
                )],
                "{argv:?}"
            ),
            None => assert!(effects.is_empty(), "{argv:?}"),
        }
    }
}

#[test]
fn package_manager_shorthand_runs_the_local_binary_unless_a_script_owns_the_name() {
    let reset = |plan: &Plan| {
        database_effects(plan)
            .iter()
            .any(|(operation, _)| operation == "database.schema_drop")
    };
    let without_script = [("package.json", r#"{"scripts":{"build":"tsc"}}"#)];
    let with_script = [("package.json", r#"{"scripts":{"prisma":"echo hi"}}"#)];
    for argv in [
        &["pnpm", "prisma", "migrate", "reset"][..],
        &["yarn", "prisma", "migrate", "reset"][..],
        &["yarn", "run", "prisma", "migrate", "reset"][..],
    ] {
        // The manifest proves no script of that name: only the binary runs.
        let plan = analyze(&without_script, argv);
        assert!(reset(&plan), "{argv:?}");
        assert!(
            !has_boundary(&plan, "unresolved_package_script"),
            "{argv:?}"
        );
        // An unread manifest keeps both readings.
        let plan = analyze(&[], argv);
        assert!(reset(&plan), "{argv:?}");
        assert!(has_boundary(&plan, "unresolved_package_script"), "{argv:?}");
        // A script of that name runs instead of the binary.
        assert!(!reset(&analyze(&with_script, argv)), "{argv:?}");
    }
    // `pnpm run` never falls back to a binary.
    assert!(!reset(&analyze(
        &without_script,
        &["pnpm", "run", "prisma", "migrate", "reset"]
    )));
}
