//! Exact cross-file resolution for statically identified JavaScript object
//! members, module singletons, constructor locals, and factory results.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_proto::{ResolutionAssurance, display_resource_with_scope};
use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use super::origin_effects;

fn assert_exact_member(tag: &str, cli: &str, tools: &str) {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        tag,
        &[("cli.js", cli), ("tools.js", tools)],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "cli.js")
        .expect("cli.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.iter().any(|effect| {
            effect.operation.as_str() == "process.exec"
                && display_resource_with_scope(&effect.resource).contains("proc:rm")
                && effect.assurance == Some(ResolutionAssurance::Exact)
                && effect
                    .origin
                    .as_ref()
                    .is_some_and(|origin| origin.source_file == "tools.js")
        }),
        "member call reaches the exact tools.js effect: {:?}",
        report.effects
    );
    assert!(
        report
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "unresolved_call"),
        "the resolved member boundary is retracted: {:?}",
        report.boundaries
    );
    assert!(
        origin_effects(&index, "tools.js", None)
            .iter()
            .any(|effect| effect.operation.as_str() == "process.exec"),
        "a forward surface carries the tools.js process effect"
    );
}

#[test]
fn exported_objects_singletons_and_factories_resolve_exactly() {
    let cases = [
        (
            "js-member-named-object",
            "import { bash } from './tools.js'\nbash.execute()\n",
            "import { spawn } from 'child_process'\nexport const bash = { execute() { spawn('rm') } }\n",
        ),
        (
            "js-member-default-object",
            "import bash from './tools.js'\nbash.execute()\n",
            "import { spawn } from 'child_process'\nexport default { execute() { spawn('rm') } }\n",
        ),
        (
            "js-member-nested-object",
            "import { tools } from './tools.js'\ntools.bash.execute()\n",
            "import { spawn } from 'child_process'\nexport const tools = { bash: { execute() { spawn('rm') } } }\n",
        ),
        (
            "js-member-singleton",
            "import { tool } from './tools.js'\ntool.execute()\n",
            "import { spawn } from 'child_process'\nclass Bash { execute() { spawn('rm') } }\nconst tool = new Bash()\nexport { tool }\n",
        ),
        (
            "js-member-factory",
            "import { createWriteTool } from './tools.js'\nconst tool = createWriteTool()\ntool.execute()\n",
            "import { spawn } from 'child_process'\nexport function createWriteTool() { return { execute() { spawn('rm') } } }\n",
        ),
        (
            "js-member-constructor-local",
            "import { Bash } from './tools.js'\nconst tool = new Bash()\ntool.execute()\n",
            "import { spawn } from 'child_process'\nexport class Bash { execute() { spawn('rm') } }\n",
        ),
    ];

    for (tag, cli, tools) in cases {
        assert_exact_member(tag, cli, tools);
    }
}

fn assert_unresolved(tag: &str, cli: &str, tools: &str) {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        tag,
        &[("cli.js", cli), ("tools.js", tools)],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "cli.js")
        .expect("cli.js analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .effects
            .iter()
            .all(|effect| effect.operation.as_str() != "process.exec"),
        "an untyped receiver must not reach a process effect: {:?}",
        report.effects
    );
    assert!(
        report
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_call"),
        "the unresolved member remains a boundary: {:?}",
        report.boundaries
    );
}

#[test]
fn dynamic_computed_rebound_and_unknown_receivers_stay_unresolved() {
    let tools = "import { spawn } from 'child_process'\nexport const bash = { execute() { spawn('rm') } }\nexport class Bash { execute() { spawn('rm') } }\n";
    let cases = [
        (
            "js-member-parameter",
            "function run(tool) { tool.execute() }\nrun({})\n",
        ),
        (
            "js-member-computed",
            "import { bash } from './tools.js'\nconst name = 'execute'\nbash[name]()\n",
        ),
        (
            "js-member-rebound",
            "import { Bash } from './tools.js'\nlet tool = new Bash()\ntool = unknown\ntool.execute()\n",
        ),
        (
            "js-member-missing-class",
            "const tool = new Missing()\ntool.execute()\n",
        ),
        (
            "js-member-importer-reassigned-method",
            "import { spawn } from 'child_process'\nimport { bash } from './tools.js'\nbash.execute = function () { spawn('ls') }\nbash.execute()\n",
        ),
    ];

    for (tag, cli) in cases {
        assert_unresolved(tag, cli, tools);
    }

    assert_unresolved(
        "js-member-definer-reassigned-method",
        "import { bash } from './tools.js'\nbash.execute()\n",
        "import { spawn } from 'child_process'\nexport const bash = { execute() { spawn('rm') } }\nbash.execute = function () { spawn('ls') }\n",
    );

    assert_unresolved(
        "js-member-divergent-object-factory",
        "import { make } from './tools.js'\nconst tool = make(true)\ntool.execute()\n",
        "import { spawn } from 'child_process'\nexport function make(flag) { if (flag) return { execute() { spawn('rm') } }; return { execute() { spawn('ls') } } }\n",
    );
}
