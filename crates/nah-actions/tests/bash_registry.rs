mod support;

use nah_actions::finalize;
use nah_proto::action::{ActionStream, Coverage, EffectKind, SemanticCode};
use support::{bash_plan, observe};

fn stream(source: &str) -> ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

fn has_system_state(source: &str, expected: &SemanticCode) -> bool {
    stream(source).effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::SystemState { operation } if operation == expected
        )
    })
}

fn unpublishes(source: &str) -> bool {
    has_system_state(source, &SemanticCode::REGISTRY_UNPUBLISH)
}

fn publishes(source: &str) -> bool {
    has_system_state(source, &SemanticCode::REGISTRY_PUBLISH)
}

#[test]
fn npm_unpublish_and_owner_control_changes_are_recognized() {
    for source in [
        "npm unpublish",
        "npm unpublish left-pad",
        "npm unpublish left-pad@1.3.0",
        "npm unpublish left-pad@1.3.0 --force --otp=123456",
        "npm unpublish left-pad@1.3.0 --no-dry-run",
        "npm unpublish left-pad@1.3.0 --no-force",
        "npm --registry https://registry.npmjs.org unpublish -- left-pad",
        "npm owner add alice left-pad",
        "npm owner add alice",
        "npm owner rm mallory left-pad --otp 123456",
        "npm owner rm mallory",
        "npm owner remove mallory left-pad --otp 123456",
        "npm owner remove mallory",
        "npm author add alice left-pad",
        "npm author add alice",
        "npm author rm mallory left-pad",
        "npm author rm mallory",
        "npm author remove mallory left-pad",
        "npm author remove mallory",
        "npm owner add alice left-pad --dry-run",
        "npm owner rm mallory left-pad --no-json",
    ] {
        assert!(unpublishes(source), "{source}");
    }
}

#[test]
fn cargo_and_gem_owner_changes_and_gem_yank_are_recognized() {
    for source in [
        "cargo owner --add alice crate-name",
        "cargo owner -aalice crate-name --registry crates-io",
        "cargo owner --remove mallory crate-name",
        "cargo owner -rmallory",
        "gem yank rack -v 3.0.0",
        "gem yank rack --version=3.0.0 --platform ruby --otp 123456 --host https://rubygems.org",
        "gem yank rack -v3.0.0 --dry-run",
        "gem yank rack -v 3.0.0 -v 3.0.0",
        "gem yank rack -v3.0.0 -v3.0.0",
        "gem yank rack -v 1.0.0 --version 2.0.0",
        "gem owner rack -a alice",
        "gem owner rack --add=alice --key release --otp=123456",
        "gem owner rack -rmallory --host https://rubygems.org",
    ] {
        assert!(unpublishes(source), "{source}");
    }
}

#[test]
fn repeated_cargo_and_gem_owner_changes_are_recognized() {
    for source in [
        "cargo owner --add alice --add bob crate-name",
        "cargo owner -a alice -a bob crate-name",
        "cargo owner --add=alice --add=bob crate-name",
        "cargo owner --add alice --remove bob crate-name",
        "gem owner rack -a alice -a bob",
        "gem owner rack --add alice --add bob",
        "gem owner rack -a alice -r bob",
    ] {
        assert!(unpublishes(source), "{source}");
    }
}

#[test]
fn every_reviewed_publish_cli_is_recognized() {
    for source in [
        "npm publish",
        "npm publish package.tgz --tag next --access public --registry http://localhost:4873 --otp 123456",
        "pnpm publish",
        "pnpm publish package.tgz --tag latest --registry http://localhost:4873",
        "yarn publish",
        "yarn npm publish --access public --tag next",
        "bun publish package.tgz --access public",
        "cargo publish --registry crates-io --allow-dirty",
        "gem push pkg.gem --host https://rubygems.org --otp 123456",
        "twine upload dist/* --repository-url https://upload.pypi.org/legacy/",
        "python -m twine upload dist/pkg.whl --repository pypi",
        "python3 -I -m twine upload dist/pkg.tar.gz",
        "uv publish",
        "uv publish dist/* --publish-url https://upload.pypi.org/legacy/",
        "poetry publish --build --repository pypi",
        "hatch publish dist/* --repo main",
        "flit publish --repository pypi",
        "dotnet nuget push package.nupkg --api-key secret --source https://api.nuget.org/v3/index.json",
        "nuget push package.nupkg secret -Source https://api.nuget.org/v3/index.json",
    ] {
        assert!(publishes(source), "{source}");
    }
}

#[test]
fn supported_publish_dry_runs_delegate_without_losing_recognition() {
    for source in [
        "npm publish --dry-run",
        "pnpm publish --dry-run",
        "npx npm publish --dry-run",
        "pnpm dlx npm publish --dry-run",
        "bunx npm publish --dry-run",
        "cargo publish --dry-run",
        "poetry publish --dry-run",
        "flit publish --dry-run",
    ] {
        let stream = stream(source);
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(
            !stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::SystemState { operation }
                        if operation == &SemanticCode::REGISTRY_PUBLISH
                )
            }),
            "{source}"
        );
    }
    assert!(publishes("npm publish --dry-run=false"));
    assert!(publishes("npm publish --no-dry-run"));
}

#[test]
fn transparent_and_package_runner_wrappers_preserve_registry_identity() {
    for source in [
        "sudo npm unpublish left-pad@1.3.0",
        "timeout 5 cargo publish",
        "command gem push pkg.gem",
        "env npm owner rm mallory left-pad",
        "npx npm publish",
        "npx npm publish --tag next",
        "npx --yes --package npm npm unpublish left-pad",
        "npx --yes npm unpublish left-pad --otp 123456",
        "pnpm dlx npm publish",
        "pnpm --package npm dlx npm owner add alice left-pad",
        "bunx npm publish",
        "bunx npm publish --tag next",
        "bunx --bun npm unpublish left-pad",
    ] {
        assert!(publishes(source) || unpublishes(source), "{source}");
    }
}

#[test]
fn standard_directory_executables_are_recognized_but_arbitrary_paths_are_not() {
    for source in [
        "/bin/npm unpublish left-pad",
        "/usr/bin/cargo publish",
        "/usr/sbin/gem push pkg.gem",
        "PATH=/tmp /usr/bin/npm owner rm mallory left-pad",
    ] {
        assert!(publishes(source) || unpublishes(source), "{source}");
    }
    for source in [
        "/tmp/npm unpublish left-pad",
        "./cargo publish",
        "/usr/local/bin/gem push pkg.gem",
        "PATH=/tmp npm unpublish left-pad",
        "export PATH=/tmp; cargo publish",
    ] {
        assert!(!publishes(source) && !unpublishes(source), "{source}");
    }
}

#[test]
fn reversible_listing_and_adjacent_package_operations_delegate() {
    for source in [
        "cargo yank --version 1.0.0 crate-name",
        "cargo yank --undo --version 1.0.0 crate-name",
        "npm deprecate left-pad@1.3.0 broken",
        "npm owner ls left-pad",
        "npm author ls left-pad",
        "cargo owner --list crate-name",
        "gem owner rack",
        "dotnet nuget delete package 1.0.0",
        "nuget delete package 1.0.0",
        "npm access public left-pad",
        "npm team add org:team user",
        "npm install left-pad",
        "npm uninstall left-pad",
        "pnpm add left-pad",
        "cargo package",
        "gem install rack",
        "npm pack",
    ] {
        assert!(!publishes(source) && !unpublishes(source), "{source}");
    }
}

#[test]
fn unrelated_registry_program_commands_preserve_full_coverage() {
    for source in [
        "cargo fmt --all --check",
        "cargo --color always fmt --all --check",
        "cargo clippy --fix",
        "cargo doc --open",
        "cargo tree -d",
        "cargo bench --bench x",
        "npm ci --prefer-offline",
        "npm run build --silent",
        "npm install --save-dev typescript",
        "npm --registry https://registry.npmjs.org install --save-dev typescript",
        "npm ls --depth 0",
        "pnpm install --frozen-lockfile",
        "pnpm add -D vite",
        "yarn install --frozen-lockfile",
        "yarn npm audit --recursive",
        "bun install --frozen-lockfile",
        "gem install rails --no-document",
        "gem --silent install rails --no-document",
        "twine check dist/pkg.whl --strict",
        "twine --disable-progress-bar check dist/pkg.whl --strict",
        "dotnet test --no-build",
        "dotnet restore --locked-mode",
        "nuget restore solution.sln -NonInteractive",
        "uv sync --frozen",
        "uv --directory . sync --frozen",
        "poetry install --no-root",
        "hatch build --clean",
        "flit build --format wheel",
        "npx eslint . --fix",
        "pnpm dlx eslint . --fix",
        "bunx eslint . --fix",
    ] {
        let stream = stream(source);
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(!publishes(source) && !unpublishes(source), "{source}");
    }
}

#[test]
fn dynamic_malformed_help_and_unknown_forms_do_not_claim_registry_effects() {
    for source in [
        "npm \"$COMMAND\" left-pad",
        "npm unpublish \"$PACKAGE\"",
        "cargo publish \"$OPTIONS\"",
        "gem yank rack -v \"$VERSION\"",
        "twine upload \"$FILES\"",
        "npm unpublish one two",
        "npm owner rm",
        "npm owner foo mallory left-pad",
        "npm author foo mallory left-pad",
        "cargo owner --add",
        "gem yank rack -v",
        "twine upload",
        "dotnet nuget push",
        "npm publish --unknown-selection value",
        "cargo publish --unknown-selection value",
        "cargo publish --allow-dirty=false",
        "poetry publish --dry-run=false",
        "poetry publish unexpected",
        "flit publish unexpected",
        "cargo publish --registry --help",
        "cargo publish --registry --dry-run",
        "cargo publish --add alice",
        "npm publish --tag --dry-run",
        "npm unpublish left-pad --otp --help",
        "gem yank rack --version --dry-run",
        "cargo owner --add --registry crates-io",
        "npm publish -v",
        "gem yank rack -v 3.0.0 --unknown-selection value",
        "npm publish --help",
        "cargo publish --help",
        "gem yank rack -v 3.0.0 --help",
        "twine upload dist/* --help",
    ] {
        assert!(!publishes(source) && !unpublishes(source), "{source}");
    }
}

#[test]
fn cargo_owner_rejects_publish_options() {
    for source in [
        "cargo owner --package victim --help",
        "cargo owner -p victim --add alice",
        "cargo owner --allow-dirty --remove mallory victim",
    ] {
        let stream = stream(source);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(!unpublishes(source), "{source}");
    }
}
