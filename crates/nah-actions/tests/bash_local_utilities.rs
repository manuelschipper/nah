mod support;

use nah_actions::finalize;
use nah_parse::normalize;
use nah_proto::action::{Coverage, EffectKind, FilesystemOperation, InvocationEffect, Sensitivity};
use support::{absolute, bash_plan, observe};

#[test]
fn local_utility_lowering_accounts_for_flags_and_separate_effects() {
    for (source, program) in [
        ("echo hello", "echo"),
        ("echo $((1 + 2))", "echo"),
        ("date", "date"),
        ("cat src/lib.rs", "cat"),
        ("sort -o sorted.txt", "sort"),
        ("tee sorted.txt", "tee"),
        ("true", "true"),
        ("false", "false"),
        ("cd ./src", "cd"),
        ("cut -d: -f1 src/lib.rs", "cut"),
        ("grep -r -n TODO src", "grep"),
        ("head -n 5 src/lib.rs", "head"),
        ("jq '.name' src/lib.rs", "jq"),
        ("pwd -P", "pwd"),
        ("rg -n TODO src", "rg"),
        ("stat -c %s src/lib.rs", "stat"),
        ("tail -n 5 src/lib.rs", "tail"),
        ("uniq src/lib.rs sorted.txt", "uniq"),
        ("wc -l src/lib.rs", "wc"),
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(effect.kind(), EffectKind::Invocation {
                invocation: InvocationEffect::Known { program: actual, operation, .. }
            } if actual == program && operation.as_str() == "local-utility")
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let plan = bash_plan("date -s tomorrow");
    let observation = observe(plan.observation_request(), "echo");
    let stream = finalize(plan, observation);
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::SystemState { operation } if operation.as_str() == "clock-set")
    }));

    for source in [
        "sort --definitely-unknown",
        "date --definitely-unknown",
        "grep --definitely-unknown TODO src",
        "head --definitely-unknown src/lib.rs",
        "jq --definitely-unknown . src/lib.rs",
        "rg --pre 'sh -c evil' TODO src",
        "rg --follow TODO src",
        "rg -L TODO src",
        "grep -R TODO src",
        "grep --dereference-recursive TODO src",
        "stat --definitely-unknown src/lib.rs",
        "tail --definitely-unknown src/lib.rs",
        "wc --definitely-unknown src/lib.rs",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(matches!(
            stream.effects()[0].kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::Opaque { .. }
            }
        ));
    }
}

#[test]
fn local_utility_lowering_fails_closed_at_option_and_word_boundaries() {
    for source in [
        "cat --definitely-unknown",
        "tee --definitely-unknown",
        "sort -o",
        "date -s",
        "cat \"$FILE\"",
        "cat prefix<(echo hello)",
        "cat ~root/.ssh/id_rsa",
        "cat src/lib.rs --help",
        "cat \"$FILE\" --help",
        "cat <(echo hello) --help",
        "cat --definitely-unknown --help",
        "date +%s --help",
        "sort src/lib.rs --help",
        "tee sorted.txt --help",
        "tee >(cat) -a",
        "sort src/lib.rs -o sorted.txt",
        "cd \"$TARGET\"",
        "cd -- src",
        "grep -f",
        "grep TODO \"$DIR\"",
        "head -n",
        "jq 'include \"module\"' src/lib.rs",
        "jq 'env.PATH' src/lib.rs",
        "rg TODO 'src/*'",
        "stat -c",
        "echo \"$TOKEN\"",
        "echo /etc/*",
        "true ~",
        "tail -f src/lib.rs",
        "tail --pid",
        "wc --files0-from .env",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        assert_eq!(
            finalize(plan, observation).coverage(),
            Coverage::Partial,
            "{source}: {:?}",
            normalize(source).unwrap()
        );
    }

    for (source, operation, target) in [
        ("cat -- -n", FilesystemOperation::Read, "/repo/-n"),
        (
            "date --file dates.txt",
            FilesystemOperation::Read,
            "/repo/dates.txt",
        ),
        (
            "sort --random-source random.bin",
            FilesystemOperation::Read,
            "/repo/random.bin",
        ),
        (
            "sort -rn -o sorted.txt src/lib.rs",
            FilesystemOperation::Write,
            "/repo/sorted.txt",
        ),
        (
            "sort -T scratch",
            FilesystemOperation::Write,
            "/repo/scratch",
        ),
        (
            "sort -o --help .env",
            FilesystemOperation::Write,
            "/repo/--help",
        ),
        ("sort -o -", FilesystemOperation::Write, "/repo/-"),
        ("tee -", FilesystemOperation::Write, "/repo/-"),
        (
            "grep --exclude-from .env TODO src",
            FilesystemOperation::Read,
            "/repo/.env",
        ),
        (
            "jq --slurpfile data src/lib.rs '. + $data'",
            FilesystemOperation::Read,
            "/repo/src/lib.rs",
        ),
        (
            "rg --ignore-file .env TODO src",
            FilesystemOperation::Read,
            "/repo/.env",
        ),
        (
            "uniq src/lib.rs sorted.txt",
            FilesystemOperation::Write,
            "/repo/sorted.txt",
        ),
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(effect.kind(), EffectKind::Filesystem { effect }
                if effect.operation == operation && effect.target == absolute(target))
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let plan = bash_plan("sort -o --help .env");
    let observation = observe(plan.observation_request(), "echo");
    let stream = finalize(plan, observation);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Read
                && effect.sensitivity == Sensitivity::EnvironmentSecret)
    }));

    let plan = bash_plan("sort --files0-from .env");
    let observation = observe(plan.observation_request(), "echo");
    let stream = finalize(plan, observation);
    assert_eq!(stream.coverage(), Coverage::Partial);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Read
                && effect.sensitivity == Sensitivity::EnvironmentSecret)
    }));
}
