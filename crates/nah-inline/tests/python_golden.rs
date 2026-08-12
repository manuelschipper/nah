use nah_inline::{
    Evidence, FindingKind, InlineInput, NestedExecution, ProtectionInput, analyze,
    interpret_language_effects,
};
use nah_proto::ctx::{AbsolutePath, Platform};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Case {
    id: String,
    program: String,
    code: String,
    #[serde(default = "default_home")]
    home: String,
    #[serde(default = "default_platform")]
    platform: String,
    #[serde(default)]
    critical_paths: Vec<String>,
    expected: Value,
}

fn default_home() -> String {
    "/home/dev".into()
}

fn default_platform() -> String {
    "linux".into()
}

#[test]
fn frozen_python_frontend_cases_match() {
    for line in include_str!("fixtures/python.jsonl").lines() {
        let case: Case = serde_json::from_str(line).unwrap();
        let platform = match case.platform.as_str() {
            "linux" => Platform::Linux,
            "macos" => Platform::Macos,
            "windows" => Platform::Windows,
            platform => panic!("{}: unknown platform {platform}", case.id),
        };
        let input = InlineInput {
            program: &case.program,
            code: &case.code,
            home: &case.home,
            platform,
        };
        let report = if case.critical_paths.is_empty() {
            analyze(input)
        } else {
            let critical_paths = case
                .critical_paths
                .iter()
                .map(|path| AbsolutePath::new(platform, path.clone()).unwrap())
                .collect::<Vec<_>>();
            interpret_language_effects(
                input,
                ProtectionInput {
                    critical_paths: &critical_paths,
                    ambient_variables: &[],
                },
            )
            .into_report()
        };

        let findings = report
            .findings()
            .iter()
            .map(|finding| {
                let kind = match finding.kind() {
                    FindingKind::RootDestruction => "root-destruction",
                    FindingKind::HomeDestruction => "home-destruction",
                    FindingKind::DecodedExecution => "decoded-execution",
                    FindingKind::NahTampering => "nah-tampering",
                };
                let evidence = match finding.evidence() {
                    Evidence::Exact => "exact",
                    Evidence::Conservative => "conservative",
                };
                format!("{kind}:{evidence}")
            })
            .collect::<Vec<_>>();
        let nested_executions = report
            .nested_executions()
            .iter()
            .map(|execution| match execution {
                NestedExecution::Shell {
                    program,
                    code,
                    stdout_inherited,
                    ..
                } => json!({
                    "kind":"shell",
                    "program":program,
                    "code":code,
                    "stdout_inherited":stdout_inherited
                }),
                NestedExecution::Command {
                    argv,
                    stdout_inherited,
                    ..
                } => json!({
                    "kind":"command",
                    "argv":argv,
                    "stdout_inherited":stdout_inherited
                }),
            })
            .collect::<Vec<_>>();
        let refusals = report
            .refusals()
            .iter()
            .map(|refusal| refusal.code())
            .collect::<Vec<_>>();
        let actual = json!({
            "findings":findings,
            "nested_executions":nested_executions,
            "refusals":refusals
        });

        assert_eq!(actual, case.expected, "{}", case.id);
    }
}
