#![allow(clippy::disallowed_macros)]

use effinterp_engine::{Engine, Lang, ObjectIdentity, ScopeKey, module_summaries};
use effinterp_proto::{
    BoundaryClass, CoverageLevel, Domain, Plan, ResourceExpr, ResourceIdentity, Subject,
    validate_plan,
};

fn php(code: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            dialect: None,
            language: "php".to_string(),
            source: code.to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    plan
}

fn code_source(plan: &Plan) -> Option<&str> {
    plan.effects
        .iter()
        .find(|effect| effect.operation.0 == "process.code_execution")
        .and_then(|effect| effect.attributes.get("source"))
        .and_then(|value| match value {
            effinterp_proto::AttrValue::String(value) => Some(value.as_str()),
            _ => None,
        })
}

#[test]
fn summaries_retain_control_and_call_slots() {
    let summary = module_summaries(
        "<?php require 'helper.php'; proof($flag); function proof($flag) { unlink('/before'); if ($flag) { unlink('/arm'); } else { unlink('/arm'); } helper(); unlink('/after'); } function never() { unlink('/never'); while (true) {} }",
        Lang::Php,
        "app.php",
        ScopeKey::Module {
            key: "app.php".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Php),
    );
    let summary: effinterp_engine::ModuleSummary =
        serde_json::from_slice(&serde_json::to_vec(&summary).unwrap()).unwrap();
    let proof = summary
        .functions
        .iter()
        .find(|function| function.name == "proof")
        .unwrap();
    assert_eq!(proof.summary.effects.len(), 4);
    assert_eq!(proof.calls.len(), 1);
    for (returns, expected) in [
        (None, [true, false, false, false]),
        (
            Some(effinterp_engine::CallContract::from_flags(
                true, false, false,
            )),
            [true, false, false, true],
        ),
        (
            Some(effinterp_engine::CallContract::from_flags(
                false, false, false,
            )),
            [false; 4],
        ),
    ] {
        let required = proof.summary.control_flow.requirements(
            &mut |_| false,
            &mut |_| returns.clone(),
            &mut |_, _| true,
        );
        for (slot, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                required
                    .on_success
                    .contains(&effinterp_engine::ControlFact::Effect(slot as u32)),
                expected,
                "slot {slot}, return {returns:?}"
            );
        }
    }
    let never = summary
        .functions
        .iter()
        .find(|function| function.name == "never")
        .unwrap();
    let required =
        never
            .summary
            .control_flow
            .requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
    assert!(!required.succeeds);
    assert!(required.on_success.is_empty());
    assert_eq!(never.summary.effects.len(), 1);
    for imported in [false, true] {
        let required = summary.module_control_flow.requirements(
            &mut |_| imported,
            &mut |_| None,
            &mut |_, _| true,
        );
        assert_eq!(
            required
                .on_success
                .contains(&effinterp_engine::ControlFact::Call(0)),
            imported
        );
    }
}

#[test]
fn environment_mutations_are_writes_and_removals_are_marked() {
    let body = r#"putenv("A=1");
putenv("OLD");
$_ENV["B"] = "2";
$_ENV[$key] = "dynamic";
unset($_ENV["C"]);
$_SERVER["NOT_ENV"] = "ignored";"#;
    let plan = php(&format!("<?php {body}"));
    let is_env_name = |effect: &effinterp_proto::Effect, expected: &str| {
        matches!(&effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            } | ResourceExpr::Environment { name } if name == expected)
    };
    for name in ["A", "OLD", "B", "C"] {
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "environment.write" && is_env_name(effect, name)
        }));
    }
    for name in ["OLD", "C"] {
        assert!(plan.effects.iter().any(|effect| {
            is_env_name(effect, name)
                && effect.attributes.get("unset") == Some(&effinterp_proto::AttrValue::Bool(true))
        }));
    }
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "environment.write"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "environment")
    }));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| is_env_name(effect, "NOT_ENV"))
    );
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && (is_env_name(effect, "B") || is_env_name(effect, "C"))
    }));

    let summary = module_summaries(
        &format!("<?php function configure() {{ {body} }}"),
        Lang::Php,
        "src/config.php",
        ScopeKey::Module {
            key: "src/config.php".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Php),
    );
    let configure = summary
        .functions
        .iter()
        .find(|function| function.name == "configure")
        .unwrap();
    for name in ["A", "OLD", "B", "C"] {
        assert!(configure.summary.effects.iter().any(|effect| {
            effect.operation.0 == "environment.write" && is_env_name(effect, name)
        }));
    }
}

#[test]
fn symfony_default_commands_are_exact_registration_objects() {
    let entry = module_summaries(
        "<?php $app = new App\\Application(); $app->run();",
        Lang::Php,
        "bin/tool",
        ScopeKey::Module {
            key: "bin/tool".to_string(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Php),
    );
    assert_eq!(entry.module_calls.len(), 2);
    assert!(entry.module_calls.iter().any(|call| {
        call.callee == "receiver.run"
            && matches!(
                call.receiver_identity(),
                Some(ObjectIdentity::Class { name, .. }) if name == "App\\Application"
            )
    }));

    let summary = module_summaries(
        r#"<?php
namespace Composer;
use Symfony\Component\Console\Application as SymfonyApplication;
use Vendor\PluginCommand;
class Application extends SymfonyApplication {
    protected function getDefaultCommands(): array {
        $commands = [new InstallCommand(new Downloader())];
        $audit = makeAuditCommand();
        $commands[] = $audit;
        $commands[] = new PluginCommand();
        return $commands;
    }
}
"#,
        Lang::Php,
        "src/Application.php",
        ScopeKey::Module {
            key: "src/Application.php".to_string(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Php),
    );
    let application = summary
        .classes
        .iter()
        .find(|class| class.name == "Composer\\Application")
        .unwrap();
    assert_eq!(
        application.bases,
        ["Symfony\\Component\\Console\\Application"]
    );
    let defaults = summary
        .functions
        .iter()
        .find(|function| function.name == "Composer\\Application.getDefaultCommands")
        .unwrap();
    let registration = defaults
        .calls
        .iter()
        .find(|call| call.lifecycle_registration)
        .unwrap();
    let identities: Vec<_> = registration
        .object_arguments()
        .map(|(_, identity)| identity)
        .collect();
    assert!(matches!(
        identities.as_slice(),
        [ObjectIdentity::Class { name, .. }, ObjectIdentity::Local { name: local, .. }, ObjectIdentity::Class { name: plugin, .. }]
            if name == "Composer\\InstallCommand" && local == "audit" && plugin == "Vendor\\PluginCommand"
    ));
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "Composer\\Application.run")
        .unwrap();
    assert!(run.calls.iter().any(|call| {
        call.callee == "this.getDefaultCommands"
            && matches!(call.receiver_identity(), Some(ObjectIdentity::Receiver))
    }));

    let overridden = module_summaries(
        r#"<?php
class Application extends \Symfony\Component\Console\Application {
    protected function getDefaultCommands(): array { return [new Command()]; }
    public function run() { return 0; }
}
"#,
        Lang::Php,
        "src/Application.php",
        ScopeKey::Module {
            key: "src/Application.php".to_string(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Php),
    );
    let run = overridden
        .functions
        .iter()
        .find(|function| function.name == "Application.run")
        .unwrap();
    assert!(
        run.calls
            .iter()
            .all(|call| call.callee != "this.getDefaultCommands")
    );
}

#[test]
fn deeply_nested_object_and_registry_expressions_are_bounded() {
    let nested = format!("{}new Foo(){}", "(".repeat(4_000), ")".repeat(4_000));
    let summary = module_summaries(
        &format!(
            "<?php $value = {nested}; consume({nested}); function make() {{ return {nested}; }}"
        ),
        Lang::Php,
        "src/deep.php",
        ScopeKey::Module {
            key: "src/deep.php".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Php),
    );
    assert!(summary.module_boundaries.is_empty());

    assert!(summary.module_calls.iter().any(|call| {
        call.callee == "consume"
            && call.object_arguments().any(|(_, identity)| {
                matches!(identity, ObjectIdentity::Class { name, .. } if name == "Foo")
            })
    }));
    assert!(summary.functions.iter().any(|function| {
        function.name == "make" && function.returns_instances == [Some("Foo".to_string())]
    }));

    let registry = format!(
        "{}[new Command()]{}",
        "array_merge(".repeat(4_000),
        ")".repeat(4_000)
    );
    let summary = module_summaries(
        &format!(
            "<?php class Application extends \\Symfony\\Component\\Console\\Application {{ protected function getDefaultCommands(): array {{ return {registry}; }} }}"
        ),
        Lang::Php,
        "src/Application.php",
        ScopeKey::Module {
            key: "src/Application.php".to_string(),
        },
        &effinterp_engine::SummaryBudget::new(200_000),
    );
    let defaults = summary
        .functions
        .iter()
        .find(|function| function.name == "Application.getDefaultCommands")
        .unwrap();
    let registration = defaults
        .calls
        .iter()
        .find(|call| call.lifecycle_registration)
        .unwrap();
    assert!(registration.object_arguments().any(|(_, identity)| {
        matches!(identity, ObjectIdentity::Class { name, .. } if name == "Command")
    }));
}

#[test]
fn module_summary_text_concat_refolds_after_binding() {
    let summary = module_summaries(
        "<?php function remove($id) { unlink('/tmp/job-' . $id . '.log'); }
        function purge($id) { unlink(sprintf('/tmp/job-%s.log', $id)); }",
        Lang::Php,
        "src/remove.php",
        ScopeKey::Module {
            key: "src/remove.php".to_string(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Php),
    );
    for name in ["remove", "purge"] {
        let effect = &summary
            .functions
            .iter()
            .find(|function| function.name == name)
            .expect("function summary")
            .summary
            .effects[0];
        let resource = effinterp_engine::substitute_resource_expr(
            &effect.resource,
            &std::collections::HashMap::from([(
                "id".to_string(),
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: "42".to_string(),
                    },
                },
            )]),
        );
        assert!(
            matches!(
                &resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/tmp/job-42.log"
            ),
            "{name}: {resource:?}"
        );
    }
}

fn ops(plan: &Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

fn deletes(plan: &Plan) -> Vec<String> {
    plan.effects
        .iter()
        .filter(|e| e.operation.0 == "filesystem.delete")
        .map(|e| match &e.resource {
            effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path },
            } => path.clone(),
            other => format!("{other:?}"),
        })
        .collect()
}

#[test]
fn no_entry_point_distinguishes_unreached_php_callables() {
    let declarations = "<?php class PurgeCommand { function handle() { unlink('/class'); } } function purge() { unlink('/function'); }";
    let plan = php(declarations);
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "no_entry_point")
        .expect("declaration-only PHP has no execution root");
    assert_eq!(boundary.class, BoundaryClass::Unresolved);
    assert_eq!(
        boundary.detail.as_deref(),
        Some(
            "no execution root reached; declared callables not executed: PurgeCommand.handle, purge"
        )
    );
    for domain in ["environment", "filesystem", "network", "process"] {
        assert_eq!(
            plan.coverage.0[&Domain::new(domain)].level,
            CoverageLevel::Partial
        );
    }

    let reached = php(&format!("{declarations} purge();"));
    assert!(deletes(&reached).contains(&"/function".to_string()));
    assert!(
        reached
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );

    let top_level = php("<?php function stale() { unlink('/stale'); } unlink('/top');");
    assert!(deletes(&top_level).contains(&"/top".to_string()));
    assert!(
        top_level
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );
    assert!(
        php("<?php")
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );
}

// Regression: console handlers and call-result receivers previously remained
// declarations even when framework or return evidence proved their dispatch.
#[test]
fn console_roots_and_constructed_receiver_chains_are_entered() {
    let artisan = php(
        "<?php use Illuminate\\Console\\Command; class CacheWarm extends Command { public function handle() { unlink('/artisan'); } }",
    );
    assert!(deletes(&artisan).contains(&"/artisan".to_string()));
    assert!(
        artisan
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );

    let symfony = php(
        "<?php use Symfony\\Component\\Console\\Command\\Command; class CacheWarm extends Command { protected function execute($input, $output) { unlink('/symfony'); } }",
    );
    assert!(deletes(&symfony).contains(&"/symfony".to_string()));

    let chains = php(
        "<?php class Warmer { static function make() { return new self(); } function direct() { unlink('/direct'); } function warm() { unlink('/warm'); } } (new Warmer())->direct(); Warmer::make()->warm();",
    );
    assert!(deletes(&chains).contains(&"/direct".to_string()));
    assert!(deletes(&chains).contains(&"/warm".to_string()));

    let invokable = php(
        "<?php use Illuminate\\Console\\Command; class CacheWarm extends Command { public function __invoke() { unlink('/invokable'); } }",
    );
    assert!(deletes(&invokable).contains(&"/invokable".to_string()));

    let shadowed = php(
        "<?php class Command {} class CacheWarm extends Command { function handle() { unlink('/dormant'); } }",
    );
    assert!(!deletes(&shadowed).contains(&"/dormant".to_string()));
    assert!(
        shadowed
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "no_entry_point")
    );
}

#[test]
fn system_nests_a_shell_command() {
    let plan = php("<?php system(\"rm -rf /tmp/x\");");
    assert!(
        ops(&plan).contains(&"process.exec"),
        "nested shell exec: {:?}",
        ops(&plan)
    );
    assert!(
        deletes(&plan).contains(&"/tmp/x".to_string()),
        "delete: {:?}",
        deletes(&plan)
    );
}

#[test]
fn php_interpolation_does_not_turn_locals_into_shell_environment_reads() {
    let plan = php(concat!(
        "<?php function reset_branch($branch) { ",
        "system(\"git reset --hard origin/$branch\"); } ",
        "reset_branch($unknown);",
    ));
    assert!(
        plan.effects.iter().all(|effect| !matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            } if name == "branch"
        )),
        "{:?}",
        plan.effects
    );
    assert!(
        plan.effects.iter().any(|effect| matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, argv, .. },
            } if executable == "git"
                && argv.iter().any(|argument| matches!(
                    argument,
                    ResourceExpr::Join { parts }
                        if matches!(parts.as_slice(), [
                            ResourceExpr::Literal { value },
                            ResourceExpr::Unresolved { family },
                        ] if value == "origin/" && family.0 == "process")
                ))
        )),
        "{:?}",
        plan.effects
    );
}

#[test]
fn unlink_is_a_delete() {
    let plan = php("<?php unlink(\"/data/f\");");
    assert_eq!(deletes(&plan), vec!["/data/f".to_string()]);
}

#[test]
fn file_put_contents_is_a_write() {
    let plan = php("<?php file_put_contents(\"/etc/passwd\", $x);");
    let w = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.write")
        .unwrap();
    assert!(matches!(
        &w.resource,
        effinterp_proto::ResourceExpr::Concrete { identity: effinterp_proto::ResourceIdentity::FsPath { path } } if path == "/etc/passwd"
    ));
}

#[test]
fn pdo_exec_nests_sql() {
    let plan = php("<?php $pdo->exec(\"DELETE FROM users\");");
    assert!(
        ops(&plan).iter().any(|o| o.starts_with("database.")),
        "nested SQL produced a database op: {:?}",
        ops(&plan)
    );
}

#[test]
fn uncalled_function_is_not_executed() {
    let plan = php("<?php function danger() { unlink(\"/important\"); } echo \"hi\";");
    assert!(
        deletes(&plan).is_empty(),
        "uncalled function's delete must not execute: {:?}",
        deletes(&plan)
    );
}

#[test]
fn call_substitutes_arguments() {
    // wipe("/var/cache") reaches system("rm -rf $p") with $p bound to the path.
    let plan = php("<?php function wipe($p) { system(\"rm -rf $p\"); } wipe(\"/var/cache\");");
    assert!(
        deletes(&plan).iter().any(|d| d.contains("/var/cache")),
        "arg substitution reaches a delete on /var/cache: {:?}",
        deletes(&plan)
    );
}

#[test]
fn unresolved_arguments_stay_parameterized_in_paths_and_interpolation() {
    let plan = php(
        "<?php function wipe($root, $name) { unlink(\"$root/$name/lock\"); } wipe($argv[1], 'tmp');",
    );
    let resource = &plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("delete")
        .resource;
    assert_eq!(
        resource,
        &ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Literal {
                    value: String::new()
                },
                ResourceExpr::Parameter {
                    name: "root".into(),
                },
                ResourceExpr::Literal { value: "/".into() },
                ResourceExpr::Literal {
                    value: "tmp".into(),
                },
                ResourceExpr::Literal {
                    value: "/lock".into(),
                },
            ],
        }
    );

    let concrete = php(
        "<?php function wipe($root, $name) { unlink(\"$root/$name/lock\"); } wipe('/srv', 'tmp');",
    );
    assert!(
        concrete.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/srv/tmp/lock"
            )
        }),
        "{:?}",
        concrete.effects
    );
}

#[test]
fn malformed_source_is_bounded_not_panicking() {
    let plan = php("<?php function {{{ broken");
    validate_plan(&plan).unwrap();
    // Either a parse boundary or simply no fabricated effects; never a panic.
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str().contains("php"))
            || plan.effects.is_empty()
    );
}

#[test]
fn deterministic() {
    let code = "<?php function w($p){ unlink($p); } w(\"/a\"); system(\"rm /b\");";
    let a = effinterp_proto::canonical_json(&php(code));
    let b = effinterp_proto::canonical_json(&php(code));
    assert_eq!(a, b);
}

#[test]
fn php_script_path_is_a_read_plus_opaque() {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec!["php".into(), "app.php".into()],
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(code_source(&plan), Some("file"));
    assert!(
        plan.effects.iter().any(|e| {
            e.operation.0 == "filesystem.read"
                && matches!(
                    &e.resource,
                    effinterp_proto::ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::FsPath { path },
                    } if path == "/w/app.php"
                )
        }),
        "php script operand should be a filesystem.read, got {:?}",
        ops(&plan)
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unrecoverable_source")
    );
}

#[test]
fn php_r_nests_inline_source() {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec!["php".into(), "-r".into(), "unlink('/tmp/x');".into()],
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(code_source(&plan), Some("argument"));
    assert!(
        ops(&plan).contains(&"filesystem.delete"),
        "php -r should nest into the inline source, got {:?}",
        ops(&plan)
    );
}

#[test]
fn closures_are_deferred_and_exact_invocations_execute_them() {
    let plan = php(
        "<?php $dormant = function () { unlink('/dormant'); }; $active = fn () => unlink('/active'); $active();",
    );
    assert!(deletes(&plan).contains(&"/active".to_string()));
    assert!(!deletes(&plan).contains(&"/dormant".to_string()));
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "dynamic_call")
    );
}

#[test]
fn callable_helpers_execute_only_exact_closures() {
    let plan = php(
        "<?php $write = function ($path) { file_put_contents($path, 'x'); }; call_user_func($write, '/callable'); call_user_func_array($write, ['/array-callable']); array_map(fn ($path) => unlink($path), ['/mapped']);",
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write"
            && format!("{:?}", effect.resource).contains("/callable")
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write"
            && format!("{:?}", effect.resource).contains("/array-callable")
    }));
    assert!(deletes(&plan).contains(&"/mapped".to_string()));
}

#[test]
fn inline_callbacks_remain_visible_outside_the_exact_helper_allowlist() {
    let plan = php(
        "<?php array_filter([1], function ($p) { unlink('/filter'); }); $app->get('/x', function () { unlink('/route'); }); register_shutdown_function(function () { unlink('/shutdown'); }); $stored = function () { unlink('/stored'); }; register_shutdown_function($stored); preg_replace_callback('/x/', function ($m) { unlink('/pcre'); }, 'x'); $handlers = ['a' => function () { unlink('/handler'); }]; (function () { unlink('/iife'); })();",
    );
    let deletes = deletes(&plan);
    for path in [
        "/filter",
        "/route",
        "/shutdown",
        "/stored",
        "/pcre",
        "/handler",
        "/iife",
    ] {
        assert!(
            deletes.contains(&path.to_string()),
            "missing {path}: {deletes:?}"
        );
    }
}

#[test]
fn stored_closures_that_escape_through_arrays_remain_visible() {
    let plan = php(
        "<?php $purge = function () { unlink('/stored-array'); }; $table = ['purge' => $purge]; function routes() { $cleanup = function () { unlink('/returned-array'); }; return ['cleanup' => $cleanup]; } routes();",
    );
    let deletes = deletes(&plan);
    for path in ["/stored-array", "/returned-array"] {
        assert!(
            deletes.contains(&path.to_string()),
            "missing {path}: {deletes:?}"
        );
    }
}

#[test]
fn destroyed_or_condition_only_closures_remain_dormant() {
    let plan = php(
        "<?php $unset = function () { unlink('/unset'); }; unset($unset); $checked = function () { unlink('/checked'); }; if ($checked !== null) { echo 'set'; } $direct = function () { unlink('/direct'); }; if ($direct) { echo 'set'; } $isset = function () { unlink('/isset'); }; if (isset($isset)) { echo 'set'; } $empty = function () { unlink('/empty'); }; empty($empty);",
    );
    let deletes = deletes(&plan);
    for path in ["/unset", "/checked", "/direct", "/isset", "/empty"] {
        assert!(
            !deletes.contains(&path.to_string()),
            "inert closure {path} executed: {deletes:?}"
        );
    }
}

#[test]
fn same_file_typed_receiver_dispatches_only_its_class() {
    let plan = php(
        "<?php class Wrong { public function run() { unlink('/wrong'); } } trait Cleanup { public function run() { unlink('/trait'); } } class Base { public function inherited() { unlink('/inherited'); } } class Runner extends Base { use Cleanup; } $runner = new Runner(); $runner->run(); $runner->inherited();",
    );
    let deletes = deletes(&plan);
    assert!(deletes.contains(&"/trait".to_string()), "{deletes:?}");
    assert!(deletes.contains(&"/inherited".to_string()), "{deletes:?}");
    assert!(!deletes.contains(&"/wrong".to_string()), "{deletes:?}");
}

#[test]
fn array_walk_and_usort_use_their_second_argument_as_the_callable() {
    let plan = php(
        "<?php array_walk(['/walk'], function ($path) { unlink($path); }); usort(['/left', '/right'], function ($left, $right) { unlink($left); unlink($right); return 0; });",
    );
    let deletes = deletes(&plan);
    for path in ["/walk", "/left", "/right"] {
        assert!(
            deletes.contains(&path.to_string()),
            "missing {path}: {deletes:?}"
        );
    }
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "dynamic_call")
    );
}

#[test]
fn callback_helpers_preserve_every_bounded_literal_value() {
    let plan = php(
        "<?php array_map(function ($path) { unlink($path); }, ['/map-a', '/map-b', '/map-c']); array_walk(['/walk-a', '/walk-b'], function ($path) { unlink($path); }); usort(['/sort-a', '/sort-b', '/sort-c'], function ($left, $right) { unlink($left); unlink($right); return 0; });",
    );
    let deletes = deletes(&plan);
    for path in [
        "/map-a", "/map-b", "/map-c", "/walk-a", "/walk-b", "/sort-a", "/sort-b", "/sort-c",
    ] {
        assert!(
            deletes.contains(&path.to_string()),
            "missing {path}: {deletes:?}"
        );
    }
}

#[test]
fn static_callback_forms_do_not_emit_dynamic_call_boundaries() {
    let plan = php(
        "<?php $items = []; array_map('trim', $items); usort($items, 'strcmp'); array_walk($items, 'do_thing'); array_map([$this, 'norm'], $items); array_map(null, $items, $items);",
    );
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "dynamic_call"),
        "static callback forms produced a dynamic boundary: {:?}",
        plan.boundaries
    );
}

#[test]
fn ordinary_array_arguments_are_not_treated_as_callables() {
    let plan = php(
        "<?php class Foo { public function bar() { unlink('/array-data'); } } class Handler { public function run() { unlink('/registered-array'); } } function render($row) {} class Renderer { public function render($row) {} } render(['Foo', 'bar']); $renderer = new Renderer(); $renderer->render(['Foo', 'bar']); register_shutdown_function(['Handler', 'run']);",
    );
    let deletes = deletes(&plan);
    assert!(
        !deletes.contains(&"/array-data".to_string()),
        "ordinary data array dispatched a method: {:?}",
        plan.effects
    );
    assert!(
        deletes.contains(&"/registered-array".to_string()),
        "known callback position did not dispatch: {:?}",
        plan.effects
    );
}

#[test]
fn guarded_rebindings_preserve_every_reachable_closure_and_receiver() {
    let plan = php(
        "<?php class First { public function run() { unlink('/receiver-first'); } } class Second { public function run() { unlink('/receiver-second'); } } $callback = function () { unlink('/first'); }; if ($argc > 1) { $callback = function () { unlink('/second'); }; } else { $callback = function () { unlink('/third'); }; } $callback(); $looped = function () { unlink('/loop-first'); }; foreach ($items as $item) { $looped = function () { unlink('/loop-second'); }; } $looped(); $receiver = new First(); if ($argc > 1) { $receiver = new Second(); } $receiver->run();",
    );
    let deletes = deletes(&plan);
    for path in [
        "/first",
        "/second",
        "/third",
        "/loop-first",
        "/loop-second",
        "/receiver-first",
        "/receiver-second",
    ] {
        assert!(
            deletes.contains(&path.to_string()),
            "missing {path}: {deletes:?}"
        );
    }
}

#[test]
fn exception_and_match_rebindings_preserve_guarded_candidates_only() {
    let plan = php(
        "<?php class First { public function run() { unlink('/receiver-first'); } } class Second { public function run() { unlink('/receiver-second'); } } class Third { public function run() { unlink('/receiver-third'); } } class Fourth { public function run() { unlink('/receiver-fourth'); } } class Stale { public function run() { unlink('/receiver-stale'); } } class Active { public function run() { unlink('/receiver-active'); } } $callback = function () { unlink('/callback-first'); }; try { $callback = function () { unlink('/callback-second'); }; } catch (Throwable $error) { $callback = function () { unlink('/callback-third'); }; } finally { $callback = function () { unlink('/callback-fourth'); }; } $callback(); $matched = function () { unlink('/match-first'); }; $choice = match (true) { default => $matched = function () { unlink('/match-second'); } }; $matched(); $receiver = new First(); try { $receiver = new Second(); } catch (Throwable $error) { $receiver = new Third(); } finally { $receiver = new Fourth(); } $receiver->run(); $straight = function () { unlink('/straight-stale'); }; $straight = function () { unlink('/straight-active'); }; $straight(); $exact = new Stale(); $exact = new Active(); $exact->run();",
    );
    let deletes = deletes(&plan);
    for path in [
        "/callback-first",
        "/callback-second",
        "/callback-third",
        "/callback-fourth",
        "/match-first",
        "/match-second",
        "/receiver-first",
        "/receiver-second",
        "/receiver-third",
        "/receiver-fourth",
        "/straight-active",
        "/receiver-active",
    ] {
        assert!(
            deletes.contains(&path.to_string()),
            "missing {path}: {deletes:?}"
        );
    }
    for path in ["/straight-stale", "/receiver-stale"] {
        assert!(
            !deletes.contains(&path.to_string()),
            "straight-line candidate remained active: {deletes:?}"
        );
    }
}

#[test]
fn callback_and_receiver_candidate_caps_emit_dynamic_dispatch_boundaries() {
    let closure_rebindings: String = (0..17)
        .map(|i| {
            format!(
                "if ($argc > {i}) {{ $callback = function () {{ unlink('/candidate-{i}'); }}; }}"
            )
        })
        .collect();
    let closure_plan = php(&format!(
        "<?php $callback = function () {{ unlink('/initial'); }}; {closure_rebindings} $callback();"
    ));
    assert!(closure_plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "dynamic_dispatch"
            && boundary.limit.as_deref() == Some("max_callback_values")
    }));

    let classes: String = (0..17)
        .map(|i| format!("class Candidate{i} {{ public function run() {{}} }}"))
        .collect();
    let receiver_rebindings: String = (1..17)
        .map(|i| format!("if ($argc > {i}) {{ $receiver = new Candidate{i}(); }}"))
        .collect();
    let receiver_plan = php(&format!(
        "<?php {classes} $receiver = new Candidate0(); {receiver_rebindings} $receiver->run();"
    ));
    assert!(receiver_plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "dynamic_dispatch"
            && boundary.limit.as_deref() == Some("max_callback_values")
    }));
}

#[test]
fn recursive_closures_terminate_and_preserve_reachable_effects() {
    let plan = php(
        "<?php $self = function () use (&$self) { unlink('/self'); $self(); }; $left = function () use (&$right) { unlink('/left'); $right(); }; $right = function () use (&$left) { unlink('/right'); $left(); }; $self(); $left();",
    );
    let deletes = deletes(&plan);
    for path in ["/self", "/left", "/right"] {
        assert!(
            deletes.contains(&path.to_string()),
            "missing {path}: {deletes:?}"
        );
    }
}

#[test]
fn closure_bindings_do_not_cross_named_function_scopes() {
    let plan = php(
        "<?php function apply_it($cb) { $cb('/caller-leak'); } function define_it() { $hidden = function () { unlink('/callee-leak'); }; } $cb = function ($path) { unlink($path); }; apply_it('strlen'); define_it(); $hidden();",
    );
    let deletes = deletes(&plan);
    assert!(!deletes.contains(&"/caller-leak".to_string()));
    assert!(!deletes.contains(&"/callee-leak".to_string()));
}

#[test]
fn catch_and_finally_paths_remain_visible() {
    let plan = php(
        "<?php try { unlink('/try'); } catch (Throwable $error) { unlink('/catch'); } finally { unlink('/finally'); }",
    );
    for path in ["/try", "/catch", "/finally"] {
        assert!(deletes(&plan).contains(&path.to_string()), "missing {path}");
    }
}

#[test]
fn filesystem_globs_preserve_escaped_absolute_roots() {
    for cwd in [None, Some("/work")] {
        for (operand, target) in [
            (r"\/tmp/*.rs", Some("/tmp/x.rs")),
            ("/tmp/*.rs", Some("/tmp/x.rs")),
            ("tmp/*.rs", cwd.map(|_| "/work/tmp/x.rs")),
            ("./src/*.php", cwd.map(|_| "/work/src/x.php")),
            ("src//./sub/*.php", cwd.map(|_| "/work/src/sub/x.php")),
        ] {
            let plan = Engine::new()
                .analyze(&Subject::Source {
                    dialect: None,
                    language: "php".to_string(),
                    source: format!("<?php glob('{}');", operand),
                    cwd: cwd.map(str::to_string),
                    context: Default::default(),
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            let read = plan
                .effects
                .iter()
                .find(|effect| effect.operation.0 == "filesystem.read")
                .unwrap();
            if let Some(target) = target {
                let ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern },
                } = &read.resource
                else {
                    panic!("expected rooted glob: {:?}", read.resource);
                };
                assert_eq!(
                    effinterp_proto::glob_match(pattern, target),
                    Ok(true),
                    "{operand:?}, cwd={cwd:?}: {pattern:?}"
                );
                if target == "/tmp/x.rs" {
                    assert_eq!(pattern, operand);
                    assert_eq!(
                        effinterp_proto::glob_match(pattern, "/work/tmp/x.rs"),
                        Ok(false)
                    );
                }
            } else {
                assert!(matches!(&read.resource, ResourceExpr::Join { .. }));
            }
        }
    }
}

#[test]
fn assignment_rhs_operators_never_overflow() {
    for (operator, expression) in [
        (".", "'/tmp/' . 'x'"),
        ("+", "$a + 1"),
        ("-", "$a - 1"),
        ("*", "$a * 1"),
        ("/", "$a / 1"),
        ("%", "$a % 1"),
        ("**", "$a ** 1"),
        ("??", "$a ?? '/tmp/x'"),
        ("?:", "$a ?: '/tmp/x'"),
        ("<=>", "$a <=> 1"),
        ("==", "$a == 1"),
        ("===", "$a === 1"),
        ("!=", "$a != 1"),
        ("<", "$a < 1"),
        ("&&", "$a && 1"),
        ("||", "$a || 1"),
        ("and", "($a and 1)"),
        ("or", "($a or 1)"),
        ("|", "$a | 1"),
        ("&", "$a & 1"),
        ("^", "$a ^ 1"),
        ("<<", "$a << 1"),
        (">>", "$a >> 1"),
        ("instanceof", "$a instanceof Foo"),
        ("??=", "$a ??= '/tmp/x'"),
        (".=", "$a .= '/tmp/x'"),
        ("+=", "$a += 1"),
        ("ternary", "$a ? $b : $c"),
        ("isset ternary", "isset($a) ? $a : '/tmp/x'"),
        ("nested concatenation", "'/tmp' . ('/' . 'x')"),
    ] {
        println!("assignment RHS operator: {operator}");
        let plan = php(&format!("<?php $f = {expression}; unlink($f);"));
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 1, "{operator}: {:?}", plan.effects);
        if operator == "." || operator == "nested concatenation" {
            assert!(
                matches!(&deletes[0].resource,
                ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                    if path == "/tmp/x"),
                "{operator}: {:?}",
                deletes[0]
            );
        } else {
            assert!(
                matches!(&deletes[0].resource,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem"),
                "{operator}: {:?}",
                deletes[0]
            );
        }
    }
    for expression in ["1 + 2", "$a ?? 1"] {
        println!("assignment RHS without effects: {expression}");
        let plan = php(&format!("<?php $x = {expression};"));
        assert!(plan.effects.is_empty());
        assert!(plan.boundaries.is_empty());
    }
}

#[test]
fn source_without_open_tag_is_unsupported_source() {
    for source in [r#"unlink("/tmp/x");"#, "<html>hi</html>", ""] {
        let plan = php(source);
        assert!(plan.effects.is_empty());
        let boundary = plan
            .boundaries
            .iter()
            .find(|boundary| boundary.reason.as_str() == "unsupported_source")
            .unwrap();
        assert_eq!(boundary.class, BoundaryClass::ParseFailure);
        assert_eq!(boundary.domains.len(), effinterp_proto::DOMAINS.len());
        for domain in &boundary.domains {
            assert_eq!(plan.coverage.0[domain].level, CoverageLevel::None);
        }
    }
    for (source, deletes_expected) in [
        (
            "<!DOCTYPE html><html><?php unlink('/var/www/app/state.json'); ?></html>",
            1,
        ),
        ("<?php", 0),
        ("<html><?= 'hi' ?><?php unlink('/tmp/x'); ?></html>", 1),
    ] {
        let plan = php(source);
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unsupported_source")
        );
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0 == "filesystem.delete")
                .count(),
            deletes_expected
        );
    }
}

#[test]
fn literal_builtin_callable_uses_its_arguments_without_dispatching_runtime_names() {
    let plan = php(
        r#"<?php call_user_func("unlink", "/tmp/callable"); call_user_func("file_put_contents", "/tmp/written", "data");"#,
    );
    assert_eq!(deletes(&plan), ["/tmp/callable"]);
    assert!(plan.effects.iter().any(|effect| effect.operation.0 == "filesystem.write" && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/tmp/written")));
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "dynamic_call")
    );
    assert!(plan.boundaries.is_empty());
    for domain in ["environment", "filesystem", "network", "process"] {
        assert!(plan.coverage.is_full(&Domain::new(domain)));
    }
    for source in [
        r#"<?php call_user_func($selector, "/tmp/false");"#,
        r#"<?php call_user_func("Custom\\unlink", "/tmp/false");"#,
        r#"<?php call_user_func(["Custom", "unlink"], "/tmp/false");"#,
        r#"<?php function unlink($path) {} call_user_func("unlink", "/tmp/false");"#,
    ] {
        let plan = php(source);
        assert!(deletes(&plan).is_empty(), "{source}");
        if !source.contains("function unlink") {
            assert_eq!(
                plan.boundaries
                    .iter()
                    .filter(|boundary| boundary.reason.as_str() == "dynamic_call")
                    .count(),
                1,
                "{source}"
            );
        }
    }
}

#[test]
fn literal_eval_decodes_source_and_preserves_dynamic_boundaries() {
    for source in [
        r#"<?php eval("unlink(\"/tmp/nested\");");"#,
        r#"<?php eval('unlink(\'/tmp/nested\');');"#,
        r#"<?php eval("\x75\156link(\"/tmp/nested\");");"#,
        r#"<?php eval("\u{75}nlink(\"/tmp/nested\");");"#,
    ] {
        let plan = php(source);
        assert_eq!(deletes(&plan), ["/tmp/nested"], "{source}");
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unmodeled_dynamic_code"),
            "{source}"
        );
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        for domain in ["environment", "filesystem", "network", "process"] {
            assert!(plan.coverage.is_full(&Domain::new(domain)), "{source}");
        }
    }
    for source in [
        r#"<?php eval($source);"#,
        r#"<?php eval("unlink($target);");"#,
        r#"<?php namespace Custom; function unlink($path) {} eval('unlink("/tmp/false");');"#,
    ] {
        let plan = php(source);
        assert!(deletes(&plan).is_empty(), "{source}");
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic_code")
                .count(),
            1,
            "{source}"
        );
    }
    let changed =
        php(r#"<?php $target = "/before"; eval('$target = "/after";'); unlink($target);"#);
    assert!(!deletes(&changed).contains(&"/before".to_string()));
    assert!(ops(&changed).contains(&"filesystem.delete"));
    let mut source = "unlink('/too-deep');".to_string();
    for _ in 0..10 {
        source = format!("eval({});", serde_json::to_string(&source).unwrap());
    }
    let plan = php(&format!("<?php {source}"));
    assert!(deletes(&plan).is_empty());
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.class == BoundaryClass::Limit)
    );
}

#[test]
fn builtin_names_are_case_insensitive() {
    let plan = php("<?php SYSTEM('rm -rf /tmp/x'); Call_User_Func('Unlink', '/tmp/y');");
    assert_eq!(deletes(&plan), ["/tmp/x", "/tmp/y"]);
}

#[test]
fn named_command_argument_is_the_command() {
    let plan = php(
        "<?php exec(output: $out, command: 'rm -rf /tmp/x'); shell_exec(command: 'rm /tmp/y');",
    );
    assert_eq!(deletes(&plan), ["/tmp/x", "/tmp/y"]);
}

#[test]
fn literal_variable_command_nests() {
    let plan = php("<?php $cmd = 'rm -rf /tmp/x'; system($cmd);");
    assert_eq!(deletes(&plan), ["/tmp/x"]);
}

#[test]
fn proc_open_literal_pipes_never_runs() {
    // PHP 8 rejects a literal for the by-reference `$pipes` before spawning.
    let plan = php("<?php proc_open('rm -rf /tmp/x', [], []);");
    assert!(deletes(&plan).is_empty(), "{:?}", plan.effects);
    let plan = php("<?php proc_open('rm -rf /tmp/x', [], $pipes);");
    assert_eq!(deletes(&plan), ["/tmp/x"]);
}

#[test]
fn http_contexts_preserve_unmodeled_routes_and_distinguish_missing_content() {
    let options = r#"["http"=>["method"=>"POST","content"=>file_get_contents("secret.key")]]"#;
    for consumer in [
        format!(r#"fopen("https://example.com/","r",false,stream_context_create({options}));"#),
        format!(r#"file("https://example.com/",0,stream_context_create({options}));"#),
        format!(r#"file_get_contents("https://$host/",false,stream_context_create({options}));"#),
        format!(
            r#"file_get_contents("ftp://example.com/",false,stream_context_create({options}));"#
        ),
    ] {
        let plan = php(&format!("<?php {consumer}"));
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_call"),
            "{consumer}"
        );
        for operation in ["filesystem.read", "network.request"] {
            assert!(
                plan.effects.iter().any(|e| e.operation.0 == operation),
                "{consumer}: {operation}"
            );
        }
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "network.upload"),
            "{consumer}"
        );
    }
    for (options, dynamic, upload) in [
        (r#"["http"=>["timeout"=>5]]"#, false, false),
        (r#"["ssl"=>["verify_peer"=>false]]"#, false, false),
        (r#"["http"=>["content"=>"ping"]]"#, false, true),
        (
            r#"["http"=>["content"=>file_get_contents("secret.key")]]"#,
            false,
            true,
        ),
        (
            r#"["http"=>["content"=>base64_encode(file_get_contents("secret.key"))]]"#,
            true,
            true,
        ),
        (r#"["http"=>[$key=>"ping"]]"#, true, false),
        (r#"["http"=>[...$options]]"#, true, false),
        (r#"$options"#, true, false),
    ] {
        let plan = php(&format!(
            r#"<?php file_get_contents("https://example.com/",false,stream_context_create({options}));"#
        ));
        assert_eq!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "dynamic_source"),
            dynamic,
            "{options}"
        );
        assert_eq!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "network.upload"),
            upload,
            "{options}"
        );
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "network.request"),
            "{options}"
        );
        if !dynamic {
            assert!(
                plan.boundaries.is_empty(),
                "{options}: {:?}",
                plan.boundaries
            );
        }
    }
}
