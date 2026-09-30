//! PHP class composition: PSR-4 resolution of the repo's own namespaces,
//! constructor and statically-named method entry, framework template
//! callbacks, and the negative space (vendored classes stay boundaries,
//! dynamic class names are typed boundaries, untyped receivers never
//! dispatch).

use std::collections::HashMap;

use effinterp_engine::{
    Engine, SourceRefusal, SourceRequest, SourceResolver, SourceResponse, UnavailableReason,
};
use effinterp_proto::{Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan};

struct MapResolver(HashMap<String, String>);

impl SourceResolver for MapResolver {
    fn source_mutation_disjoint(
        &self,
        _: &effinterp_proto::ResourceExpr,
        _: effinterp_engine::SourceRequest<'_>,
    ) -> bool {
        true
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.0.get(request.path).map_or_else(
            || SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
            |source| SourceResponse::Source(source.as_bytes().to_vec()),
        )
    }

    fn siblings(&self, path: &str) -> Option<Vec<String>> {
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        Some(
            self.0
                .keys()
                .filter(|candidate| {
                    candidate.as_str() != path
                        && candidate
                            .rsplit_once('/')
                            .map_or("", |(candidate_parent, _)| candidate_parent)
                            == parent
                })
                .cloned()
                .collect(),
        )
    }
}

fn engine(files: &[(&str, &str)]) -> Engine {
    Engine::new().with_resolver(Box::new(MapResolver(
        files
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )))
}

fn php(engine: &Engine, code: &str, cwd: &str) -> Plan {
    let plan = engine
        .analyze(&Subject::Source {
            dialect: None,
            language: "php".to_string(),
            source: code.to_string(),
            cwd: Some(cwd.to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    plan
}

fn ops(plan: &Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

fn reasons(plan: &Plan) -> Vec<&str> {
    plan.boundaries.iter().map(|b| b.reason.as_str()).collect()
}

const COMPOSER_JSON: &str = r#"{"autoload": {"psr-4": {"App\\": "src/"}}}"#;

const RUNNER: &str = "<?php\nnamespace App;\nclass Runner {\n    public function __construct() { unlink('/tmp/ctor'); }\n    public function go() { getenv('RUNNER_MODE'); }\n}\n";

#[test]
fn psr4_resolves_own_namespace_constructor_and_method() {
    let e = engine(&[
        ("/composer.json", COMPOSER_JSON),
        ("/src/Runner.php", RUNNER),
    ]);
    let plan = php(
        &e,
        "<?php use App\\Runner;\n$r = new Runner();\n$r->go();",
        "bin",
    );
    assert!(
        ops(&plan).contains(&"filesystem.delete"),
        "constructor runs: {:?}",
        ops(&plan)
    );
    assert!(
        ops(&plan).contains(&"environment.read"),
        "typed receiver dispatches the method: {:?}",
        ops(&plan)
    );
}

#[test]
fn constructor_properties_and_class_values_flow_to_paths() {
    let plan = php(
        &engine(&[]),
        r#"<?php
class Purger {
    const ROOT = '/srv/app';
    static $tmp = '/tmp/c';
    private string $assigned;
    private string $relative;
    public function __construct(private string $root) {
        $this->assigned = $root;
        $this->relative = 'data';
    }
    public function reset() {
        unlink($this->root . '/index.lock');
        unlink("{$this->root}/cache");
        unlink($this->assigned . '/assigned.lock');
        unlink('/srv/' . $this->relative);
        unlink(self::ROOT . '/x');
        unlink(static::$tmp . '/y');
    }
}
const BASE = '/srv/base';
$purger = new Purger('/srv/app');
$purger->reset();
unlink(BASE . '/lock');"#,
        "/w",
    );
    let paths: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .filter_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some(path.as_str()),
            _ => None,
        })
        .collect();
    for path in [
        "/srv/app/index.lock",
        "/srv/app/cache",
        "/srv/app/assigned.lock",
        "/srv/data",
        "/srv/app/x",
        "/tmp/c/y",
        "/srv/base/lock",
    ] {
        assert!(paths.contains(&path), "missing {path}: {:?}", plan.effects);
    }
}

#[test]
fn vendored_namespace_stays_an_external_boundary() {
    let e = engine(&[("/composer.json", COMPOSER_JSON)]);
    let plan = php(&e, "<?php use Vendor\\Thing;\nnew Thing();", "bin");
    assert!(
        reasons(&plan).contains(&"external_unmodeled"),
        "{:?}",
        reasons(&plan)
    );
    assert!(ops(&plan).is_empty(), "no effects: {:?}", ops(&plan));
}

#[test]
fn dynamic_class_name_is_a_typed_boundary() {
    let e = engine(&[
        ("/composer.json", COMPOSER_JSON),
        ("/src/Runner.php", RUNNER),
    ]);
    let plan = php(
        &e,
        "<?php $cls = 'App\\\\Runner';\n$r = new $cls();\n$r->go();",
        "bin",
    );
    assert!(
        reasons(&plan).contains(&"dynamic_class"),
        "{:?}",
        reasons(&plan)
    );
    assert!(
        ops(&plan).is_empty(),
        "a dynamic class never dispatches: {:?}",
        ops(&plan)
    );
}

#[test]
fn untyped_receiver_never_dispatches() {
    let e = engine(&[
        ("/composer.json", COMPOSER_JSON),
        ("/src/Runner.php", RUNNER),
    ]);
    let plan = php(&e, "<?php $x = make();\n$x->go();", "bin");
    assert!(ops(&plan).is_empty(), "{:?}", ops(&plan));
}

#[test]
fn static_call_dispatches_into_own_class() {
    let e = engine(&[
        ("/composer.json", COMPOSER_JSON),
        (
            "/src/Env.php",
            "<?php\nnamespace App;\nclass Env {\n    public static function read($name) { return getenv($name); }\n}\n",
        ),
    ]);
    let plan = php(&e, "<?php use App\\Env;\nEnv::read('HOME');", "bin");
    assert!(ops(&plan).contains(&"environment.read"), "{:?}", ops(&plan));
}

#[test]
fn symfony_run_template_reenters_do_run() {
    // Composer's shape: run() defers to the vendored Symfony Console parent,
    // which re-enters the subclass through doRun().
    let e = engine(&[
        ("/composer.json", COMPOSER_JSON),
        (
            "/src/Cli.php",
            "<?php\nnamespace App;\nuse Symfony\\Component\\Console\\Application as BaseApplication;\nclass Cli extends BaseApplication {\n    public function run($input = null, $output = null) { return parent::run($input, $output); }\n    public function doRun($input, $output) { unlink('/tmp/probe'); }\n}\n",
        ),
    ]);
    let plan = php(
        &e,
        "<?php use App\\Cli;\n$c = new Cli();\n$c->run();",
        "bin",
    );
    assert!(
        ops(&plan).contains(&"filesystem.delete"),
        "run -> parent::run -> doRun reaches the effect: {:?}",
        ops(&plan)
    );
}

#[test]
fn relative_cwd_dir_include_resolves() {
    // The composer shape: a bin/ entrypoint whose analysis cwd is the
    // repo-relative "bin", requiring `__DIR__ . '/../src/bootstrap.php'`.
    let e = engine(&[("/src/bootstrap.php", "<?php getenv('BOOT');")]);
    let plan = php(
        &e,
        "<?php require __DIR__ . '/../src/bootstrap.php';",
        "bin",
    );
    assert!(ops(&plan).contains(&"environment.read"), "{:?}", ops(&plan));
}

#[test]
fn include_if_exists_probes_and_bounds_the_missing_vendor_autoload() {
    // bootstrap.php's includeIfExists: the file_exists probe is a metadata
    // read, and the include of the absent vendor autoload stays a loud
    // boundary instead of silence.
    let e = engine(&[]);
    let plan = php(
        &e,
        "<?php\nfunction includeIfExists(string $file) {\n    return file_exists($file) ? include $file : null;\n}\nincludeIfExists(__DIR__.'/../vendor/autoload.php');",
        "src",
    );
    let read = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.read")
        .unwrap_or_else(|| panic!("file_exists reads: {:?}", ops(&plan)));
    assert!(
        format!("{:?}", read.resource).contains("vendor/autoload.php"),
        "{:?}",
        read.resource
    );
    assert!(
        reasons(&plan).contains(&"unresolved_include"),
        "{:?}",
        reasons(&plan)
    );
}

/// Extensionless Composer bin: shebang + PHP body. The shebang is not PHP,
/// but the body must still execute.
#[test]
fn shebang_wrapper_executes_the_php_body() {
    let plan = php(
        &engine(&[]),
        "#!/usr/bin/env php\n<?php\nunlink('/tmp/from-shebang');\n",
        "bin",
    );
    assert!(
        ops(&plan).contains(&"filesystem.delete"),
        "shebang body: {:?}",
        ops(&plan)
    );
}

/// `dirname(__DIR__) . '/file.php'` from a bin/ cwd, the Composer wrapper shape.
#[test]
fn dirname_dir_bootstrap_include_from_bin() {
    let e = engine(&[("/autoload.php", "<?php unlink('/tmp/from-boot');")]);
    let plan = php(
        &e,
        "#!/usr/bin/env php\n<?php\nrequire_once dirname(__DIR__) . '/autoload.php';\n",
        "bin",
    );
    assert!(
        ops(&plan).contains(&"filesystem.delete"),
        "dirname(__DIR__) include: {:?} reasons={:?}",
        ops(&plan),
        reasons(&plan)
    );
}

/// A written `Ns\\fn()` is a static name, not a variable-function dynamic
/// call. Following the include-defined body is a later edge.
#[test]
fn namespaced_function_is_not_dynamic() {
    let e = engine(&[(
        "/requirements.php",
        "<?php\nnamespace App;\nfunction check() { unlink('/tmp/checked'); }\n",
    )]);
    let plan = php(
        &e,
        "#!/usr/bin/env php\n<?php\nrequire_once dirname(__DIR__) . '/requirements.php';\nApp\\check();\n",
        "bin",
    );
    assert!(
        !reasons(&plan).contains(&"dynamic_call"),
        "Ns\\fn is static: {:?}",
        reasons(&plan)
    );
}

/// Qualified `new Vendor\\Runner()` + `$r->run()` with a declared PSR-4 map.
#[test]
fn qualified_new_dispatches_with_psr4() {
    let e = engine(&[
        ("/composer.json", COMPOSER_JSON),
        (
            "/src/Runner.php",
            "<?php\nnamespace App;\nclass Runner {\n    public function run() { unlink('/tmp/run'); }\n}\n",
        ),
    ]);
    let plan = php(
        &e,
        "#!/usr/bin/env php\n<?php\n$r = new App\\Runner();\n$r->run();\n",
        "bin",
    );
    assert!(
        ops(&plan).contains(&"filesystem.delete"),
        "qualified new + method: {:?} reasons={:?}",
        ops(&plan),
        reasons(&plan)
    );
}

/// Same launch without composer autoload metadata: PSR-4 layout under src/
/// still maps `App\\Runner` to `src/Runner.php`.
#[test]
fn qualified_new_follows_psr4_layout_without_composer_map() {
    let e = engine(&[(
        "/src/Runner.php",
        "<?php\nnamespace App;\nclass Runner {\n    public function run() { unlink('/tmp/run'); }\n}\n",
    )]);
    let plan = php(
        &e,
        "#!/usr/bin/env php\n<?php\n$r = new App\\Runner();\n$r->run();\n",
        "bin",
    );
    assert!(
        ops(&plan).contains(&"filesystem.delete"),
        "layout fallback: {:?} reasons={:?}",
        ops(&plan),
        reasons(&plan)
    );
}

/// A file at the conventional path whose namespace does not match the FQN
/// is not that class.
#[test]
fn layout_rejects_a_wrong_namespace() {
    let e = engine(&[(
        "/src/Runner.php",
        "<?php\nnamespace Other;\nclass Runner {\n    public function run() { unlink('/tmp/nope'); }\n}\n",
    )]);
    let plan = php(&e, "<?php $r = new App\\Runner(); $r->run();", "bin");
    assert!(
        reasons(&plan).contains(&"external_unmodeled"),
        "{:?}",
        reasons(&plan)
    );
    assert!(
        ops(&plan).is_empty(),
        "wrong namespace must not dispatch: {:?}",
        ops(&plan)
    );
}

/// Full Composer-bin shape: shebang, dirname bootstrap, qualified construct,
/// typed method. No composer.json autoload section.
#[test]
fn composer_bin_bootstrap_reaches_own_class() {
    let e = engine(&[
        ("/autoload.php", "<?php\n// custom autoloader, no effects\n"),
        (
            "/src/Runner.php",
            "<?php\nnamespace App;\nclass Runner {\n    public function run() { getenv('APP_MODE'); unlink('/tmp/from-run'); }\n}\n",
        ),
    ]);
    let plan = php(
        &e,
        "#!/usr/bin/env php\n<?php\nrequire_once dirname(__DIR__) . '/autoload.php';\n$runner = new App\\Runner();\n$exit = $runner->run();\nexit($exit);\n",
        "bin",
    );
    assert!(
        ops(&plan).contains(&"filesystem.delete"),
        "bin -> autoload -> Runner::run: {:?} reasons={:?}",
        ops(&plan),
        reasons(&plan)
    );
}

#[test]
fn trait_method_dispatch_requires_the_exact_use_declaration() {
    let run = |uses_trait: bool| {
        let runner = if uses_trait {
            "<?php\nnamespace App;\nclass Runner { use Deletes; }\n"
        } else {
            "<?php\nnamespace App;\nclass Runner {}\n"
        };
        let e = engine(&[
            ("/composer.json", COMPOSER_JSON),
            ("/src/Runner.php", runner),
            (
                "/src/Deletes.php",
                "<?php\nnamespace App;\ntrait Deletes { public function run() { unlink('/from-trait'); } }\n",
            ),
        ]);
        php(
            &e,
            "<?php use App\\Runner; $runner = new Runner(); $runner->run();",
            "bin",
        )
    };

    let positive = run(true);
    assert!(ops(&positive).contains(&"filesystem.delete"));
    let negative = run(false);
    assert!(
        ops(&negative).is_empty(),
        "a same-name trait method without `use` dispatched: {:?}",
        ops(&negative)
    );
}

#[test]
fn trait_adaptation_method_names_are_not_trait_receivers() {
    let e = engine(&[
        ("/composer.json", COMPOSER_JSON),
        (
            "/src/User.php",
            "<?php namespace App; class User { use Greets { go as run; } }",
        ),
        (
            "/src/Greets.php",
            "<?php namespace App; trait Greets { public function go() {} }",
        ),
        (
            "/src/go.php",
            "<?php namespace App; class go { public function run() { unlink('/wrong-trait-receiver'); } }",
        ),
    ]);
    let plan = php(
        &e,
        "<?php use App\\User; $user = new User(); $user->run();",
        "bin",
    );
    assert!(
        !plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && format!("{:?}", effect.resource).contains("/wrong-trait-receiver")
        }),
        "trait alias method dispatched as a class: {:?}",
        plan.effects
    );
}

#[test]
fn exact_callable_array_dispatches_a_typed_receiver() {
    let e = engine(&[
        ("/composer.json", COMPOSER_JSON),
        (
            "/src/Runner.php",
            "<?php\nnamespace App;\nclass Runner { public function run() { unlink('/callable-array'); } }\n",
        ),
    ]);
    let plan = php(
        &e,
        "<?php use App\\Runner; $runner = new Runner(); call_user_func([$runner, 'run']);",
        "bin",
    );
    assert!(
        ops(&plan).contains(&"filesystem.delete"),
        "{:?}",
        reasons(&plan)
    );

    let string_form = php(&e, r"<?php call_user_func(['App\Runner', 'run']);", "bin");
    assert!(
        ops(&string_form).contains(&"filesystem.delete"),
        "string class callable did not dispatch: {:?}",
        reasons(&string_form)
    );

    let keyed_form = php(
        &e,
        r"<?php call_user_func([0 => 'App\Runner', 1 => 'run']);",
        "bin",
    );
    assert!(
        ops(&keyed_form).contains(&"filesystem.delete"),
        "keyed callable array did not dispatch: {:?}",
        reasons(&keyed_form)
    );
}
