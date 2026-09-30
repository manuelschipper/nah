//! Composer-bin PHP launch: an extensionless shebang wrapper includes a
//! bootstrap file, then constructs a namespaced class that lives at the
//! conventional PSR-4 path (`src/Runner.php` for `App\Runner`) with no
//! composer.json autoload map.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use effinterp_repo::{IndexLimits, Selector, build_index, effects_of, reach};

static NEXT_TEMP_REPO: AtomicU64 = AtomicU64::new(0);

fn temp_repo(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let nonce = NEXT_TEMP_REPO.fetch_add(1, Ordering::Relaxed);
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{tag}-{}-{nonce}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for (rel, content) in files {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    root
}

fn display(effect: &effinterp_proto::EffectFact) -> String {
    effinterp_proto::display_resource(&effect.resource)
}

fn origin(effect: &effinterp_proto::EffectFact) -> &str {
    effect
        .origin
        .as_ref()
        .map(|origin| origin.source_file.as_str())
        .unwrap_or("")
}

#[test]
fn extensionless_bin_reaches_psr4_layout_class() {
    let root = temp_repo(
        "php-bin-layout",
        &[
            ("composer.json", r#"{"bin":["bin/tool"]}"#),
            (
                "bin/tool",
                "#!/usr/bin/env php\n<?php\nrequire_once dirname(__DIR__) . '/autoload.php';\n$runner = new App\\Runner();\n$runner->run();\n",
            ),
            ("autoload.php", "<?php\n"),
            (
                "src/Runner.php",
                "<?php\nnamespace App;\nclass Runner {\n    public function run() { unlink('/tmp/from-run'); }\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    assert!(
        idx.entrypoints
            .iter()
            .any(|e| e.entrypoint.id == "bin/tool"),
        "extensionless php shebang is an entrypoint"
    );
    let report = reach(&idx, &Selector::parse("fs:/tmp/from-run").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "bin/tool" && h.fact.operation.0 == "filesystem.delete"),
        "bin -> Runner::run is queryable: {report:?}"
    );
    let surface = effects_of(&idx, "bin/tool")
        .expect("bin surface")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        surface
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete" && origin(e) == "src/Runner.php"),
        "delete attributes to the class file: {:?}",
        surface.effects
    );
}

#[test]
fn symfony_run_dispatches_only_registered_default_commands() {
    let root = temp_repo(
        "php-symfony-default-commands",
        &[
            (
                "composer.json",
                r#"{"bin":["bin/tool"],"autoload":{"psr-4":{"App\\":"src/"}}}"#,
            ),
            (
                "bin/tool",
                "#!/usr/bin/env php\n<?php\n$app = new App\\Application();\n$app->run();\n",
            ),
            (
                "src/Application.php",
                r#"<?php
namespace App;
use Symfony\Component\Console\Application as SymfonyApplication;
class Application extends SymfonyApplication {
    protected function getDefaultCommands(): array {
        $commands = parent::getDefaultCommands();
        $commands[] = new InstallCommand(new Downloader());
        $audit = makeAuditCommand();
        $commands[] = $audit;
        return $commands;
    }
}
function makeAuditCommand() { return new AuditCommand(); }
"#,
            ),
            (
                "src/InstallCommand.php",
                r#"<?php
namespace App;
class InstallCommand {
    private $downloader;
    public function __construct(Downloader $downloader) { $this->downloader = $downloader; }
    protected function execute() {
        $this->downloader->download();
        file_put_contents('/vendor/package.php', 'x');
    }
}
"#,
            ),
            (
                "src/Downloader.php",
                r#"<?php namespace App; class Downloader { public function download() { file_get_contents('https://repo.example.test/package.zip'); } }
"#,
            ),
            (
                "src/AuditCommand.php",
                r#"<?php namespace App; class AuditCommand extends AuditBaseCommand {}
"#,
            ),
            (
                "src/AuditBaseCommand.php",
                r#"<?php namespace App; class AuditBaseCommand { protected function execute() { system('git status'); } }
"#,
            ),
            (
                "src/DecoyCommand.php",
                r#"<?php namespace App; class DecoyCommand { protected function execute() { unlink('/must-not-run'); } }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effects_of(&index, "bin/tool")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    for (operation, source) in [
        ("filesystem.write", "src/InstallCommand.php"),
        ("network.request", "src/Downloader.php"),
        ("process.exec", "src/AuditBaseCommand.php"),
    ] {
        let effect = surface
            .effects
            .iter()
            .find(|effect| effect.operation.0 == operation && origin(effect) == source)
            .unwrap_or_else(|| panic!("missing {operation} from {source}: {surface:?}"));
        assert_eq!(
            effect
                .dispatch
                .as_ref()
                .map(|dispatch| dispatch.model.as_str()),
            Some("symfony-console")
        );
    }
    // Dispatch evidence is carried by terminal roots into the envelope graph,
    // not by a rendered path on the row: every root a fact names must resolve
    // there, and the dispatch node must record the same roots.
    let envelope = effects_of(&index, "bin/tool").unwrap();
    let nodes = &envelope.provenance.nodes;
    let dispatched: Vec<_> = envelope
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|effect| {
            matches!(
                effect.operation.0.as_str(),
                "filesystem.write" | "process.exec"
            )
        })
        .filter_map(|effect| effect.dispatch.as_ref())
        .collect();
    assert_eq!(dispatched.len(), 2);
    for dispatch in &dispatched {
        assert!(!dispatch.registration_roots.is_empty());
        assert!(!dispatch.dispatch_roots.is_empty());
        assert!(
            dispatch
                .registration_roots
                .iter()
                .chain(&dispatch.dispatch_roots)
                .all(|root| nodes.iter().any(|node| &node.id == root))
        );
        assert!(nodes.iter().any(|node| matches!(
            &node.evidence,
            effinterp_proto::ProtocolProvenanceKind::Dispatch {
                model,
                registration_roots,
                dispatch_roots,
            } if model == &dispatch.model
                && registration_roots == &dispatch.registration_roots
                && dispatch_roots == &dispatch.dispatch_roots
        )));
    }
    assert!(surface.effects.iter().all(|effect| {
        effect.operation.0 != "filesystem.delete" || display(effect) != "fs:/must-not-run"
    }));
    assert!(
        surface
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "dynamic_dispatch")
    );
}

#[test]
fn symfony_registration_arguments_remain_distinct_and_explainable() {
    let root = temp_repo(
        "php-symfony-registration-arguments",
        &[
            (
                "composer.json",
                r#"{"bin":["bin/tool"],"autoload":{"psr-4":{"App\\":"src/"}}}"#,
            ),
            (
                "bin/tool",
                "#!/usr/bin/env php\n<?php\n$app = new App\\Application();\n$app->run();\n",
            ),
            (
                "src/Application.php",
                r#"<?php
namespace App;
use Symfony\Component\Console\Application as SymfonyApplication;
class Application extends SymfonyApplication {
    protected function getDefaultCommands(): array {
        return [new PurgeCommand(), new PurgeCommand()];
    }
}
"#,
            ),
            (
                "src/PurgeCommand.php",
                r#"<?php
namespace App;
class PurgeCommand {
    protected function execute() { unlink('/tmp/shared-registration'); }
}
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let envelope = effects_of(&index, "bin/tool").unwrap();
    let facts: Vec<_> = envelope
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|fact| display(fact) == "fs:/tmp/shared-registration")
        .collect();
    assert_eq!(facts.len(), 2);
    assert_ne!(facts[0].fact_id, facts[1].fact_id);

    let registration_indices: std::collections::BTreeSet<_> = facts
        .iter()
        .flat_map(|fact| &fact.dispatch.as_ref().unwrap().registration_roots)
        .filter_map(|root| {
            envelope
                .provenance
                .nodes
                .iter()
                .find(|node| &node.id == root)
        })
        .filter_map(|node| match &node.evidence {
            effinterp_proto::ProtocolProvenanceKind::Source {
                evidence: effinterp_proto::SourceEvidence::Argument { index },
            } => Some(*index),
            _ => None,
        })
        .collect();
    assert_eq!(registration_indices, [0, 1].into_iter().collect());
}

#[test]
fn symfony_registry_requires_the_exact_base_and_stays_bounded() {
    let application = |base: &str, commands: String| {
        format!(
            "<?php namespace App; class Application extends {base} {{ protected function getDefaultCommands(): array {{ return [{commands}]; }} }}\n"
        )
    };
    let files = |base: &str, commands: String| {
        vec![
            (
                "composer.json",
                r#"{"bin":["bin/tool"],"autoload":{"psr-4":{"App\\":"src/"}}}"#.to_string(),
            ),
            (
                "bin/tool",
                "#!/usr/bin/env php\n<?php $app = new App\\Application(); $app->run();\n"
                    .to_string(),
            ),
            ("src/Application.php", application(base, commands)),
            (
                "src/Command.php",
                "<?php namespace App; class Command { protected function execute() { unlink('/registered'); } }\n"
                    .to_string(),
            ),
        ]
    };
    let wrong = files("WrongBase", "new Command()".to_string());
    let wrong_refs: Vec<_> = wrong
        .iter()
        .map(|(path, source)| (*path, source.as_str()))
        .collect();
    let wrong_root = temp_repo("php-symfony-wrong-base", &wrong_refs);
    let wrong_surface = effects_of(
        &build_index(&wrong_root, IndexLimits::default()),
        "bin/tool",
    )
    .unwrap()
    .payload
    .into_effects()
    .unwrap();
    assert!(wrong_surface.effects.is_empty());

    let computed = files(
        r"\Symfony\Component\Console\Application",
        "new $commandClass()".to_string(),
    );
    let computed_refs: Vec<_> = computed
        .iter()
        .map(|(path, source)| (*path, source.as_str()))
        .collect();
    let computed_root = temp_repo("php-symfony-computed-command", &computed_refs);
    let computed_surface = effects_of(
        &build_index(&computed_root, IndexLimits::default()),
        "bin/tool",
    )
    .unwrap()
    .payload
    .into_effects()
    .unwrap();
    assert!(computed_surface.effects.is_empty());
    assert!(
        computed_surface
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "dynamic_dispatch")
    );

    let commands = std::iter::repeat_n("new Command()", 65)
        .collect::<Vec<_>>()
        .join(", ");
    let bounded = files(r"\Symfony\Component\Console\Application", commands);
    let bounded_refs: Vec<_> = bounded
        .iter()
        .map(|(path, source)| (*path, source.as_str()))
        .collect();
    let bounded_root = temp_repo("php-symfony-command-bound", &bounded_refs);
    let bounded_index = build_index(&bounded_root, IndexLimits::default());
    let bounded_surface = effects_of(&bounded_index, "bin/tool")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(bounded_surface.effects.is_empty());
    assert!(
        bounded_surface
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "dynamic_dispatch"),
        "surface={bounded_surface:#?} composition={:#?}",
        (
            bounded_index.composition("bin/tool"),
            &bounded_index.registry.files["src/Application.php"].summary
        )
    );
}

#[test]
fn named_functions_do_not_inherit_caller_receiver_locals() {
    let root = temp_repo(
        "php-function-receiver-scope",
        &[
            (
                "composer.json",
                r#"{"bin":["bin/tool"],"autoload":{"psr-4":{"App\\":"src/"}}}"#,
            ),
            (
                "bin/tool",
                "#!/usr/bin/env php\n<?php\nfunction callee() { $runner->run(); }\n$runner = new App\\Runner();\ncallee();\n",
            ),
            (
                "src/Runner.php",
                "<?php namespace App; class Runner { public function run() { unlink('/wrong-scope'); } }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "bin/tool")
        .expect("bin surface")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        surface.effects.iter().all(|effect| {
            effect.operation.0 != "filesystem.delete" || display(effect) != "fs:/wrong-scope"
        }),
        "caller receiver leaked into callee: {surface:?}"
    );
}

#[test]
fn stored_closures_in_callback_tables_remain_visible() {
    let root = temp_repo(
        "php-stored-callback-table",
        &[(
            "bin/tool",
            "#!/usr/bin/env php\n<?php\n$purge = function () { unlink('/stored-callback'); };\n$table = ['purge' => $purge];\n",
        )],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "bin/tool")
        .expect("bin surface")
        .payload
        .into_effects()
        .unwrap();
    assert!(surface.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && display(effect) == "fs:/stored-callback"
    }));
}

#[test]
fn trait_adaptation_names_do_not_dispatch_same_named_classes() {
    let root = temp_repo(
        "php-trait-adaptation-receiver",
        &[
            (
                "composer.json",
                r#"{"bin":["bin/tool"],"autoload":{"psr-4":{"App\\":"src/"}}}"#,
            ),
            (
                "bin/tool",
                "#!/usr/bin/env php\n<?php\n$user = new App\\User();\n$user->run();\n",
            ),
            (
                "src/User.php",
                "<?php namespace App; class User { use Greets { go as run; } }\n",
            ),
            (
                "src/Greets.php",
                "<?php namespace App; trait Greets { public function go() {} }\n",
            ),
            (
                "src/go.php",
                "<?php namespace App; class go { public function run() { unlink('/wrong-trait-receiver'); } }\n",
            ),
        ],
    );
    let surface = effects_of(&build_index(&root, IndexLimits::default()), "bin/tool")
        .expect("bin surface")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        surface.effects.iter().all(|effect| {
            effect.operation.0 != "filesystem.delete"
                || display(effect) != "fs:/wrong-trait-receiver"
        }),
        "trait adaptation method dispatched as a class: {surface:?}"
    );
}

#[test]
fn missing_class_file_stays_a_boundary() {
    let root = temp_repo(
        "php-bin-missing",
        &[(
            "bin/tool",
            "#!/usr/bin/env php\n<?php\n$runner = new Vendor\\Thing();\n$runner->run();\n",
        )],
    );
    let idx = build_index(&root, IndexLimits::default());
    let surface = effects_of(&idx, "bin/tool")
        .expect("bin surface")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        surface.effects.is_empty(),
        "no invented effects: {:?}",
        surface.effects
    );
}

#[test]
fn composer_psr4_prefix_is_required_for_nonstandard_source_roots() {
    let files = |prefix: &'static str| {
        vec![
            (
                "composer.json",
                if prefix == "Acme\\" {
                    r#"{"bin":["bin/tool"],"autoload":{"psr-4":{"Acme\\":"app/"}}}"#
                } else {
                    r#"{"bin":["bin/tool"],"autoload":{"psr-4":{"Other\\":"app/"}}}"#
                },
            ),
            (
                "bin/tool",
                "#!/usr/bin/env php\n<?php $runner = new Acme\\Runner(); $runner->run();\n",
            ),
            (
                "app/Runner.php",
                "<?php namespace Acme; class Runner { public function run() { unlink('/composer-map'); } }\n",
            ),
        ]
    };

    let positive = temp_repo("php-composer-map-positive", &files("Acme\\"));
    let surface = effects_of(&build_index(&positive, IndexLimits::default()), "bin/tool")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(surface.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && display(effect).contains("/composer-map")
    }));

    let negative = temp_repo("php-composer-map-negative", &files("Other\\"));
    let surface = effects_of(&build_index(&negative, IndexLimits::default()), "bin/tool")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        surface.effects.is_empty(),
        "wrong PSR-4 prefix dispatched: {surface:?}"
    );
}
