//! Property/fuzz robustness tests for the invocation engine.
//!
//! A fixed-seed LCG drives thousands of adversarial inputs (random bytes,
//! unbalanced quotes, deep nesting, keywords, null bytes, Unicode, huge
//! sources) through every Subject variant. The invariants that must hold for
//! EVERY input: analysis never panics, a returned plan always passes
//! `validate`, analysis is deterministic, output stays bounded under random
//! limits, and plans round-trip through canonical JSON. Deterministic (fixed
//! seed) so any failure is reproducible; no external RNG dependency.

use std::panic::{AssertUnwindSafe, catch_unwind};

use effinterp_engine::{Engine, default_limits};
use effinterp_proto::{
    FileEditArgs, FilePatchArgs, FileReadArgs, FileWriteArgs, FsGlobArgs, FsGrepArgs, FsListArgs,
    Limits, PatchFormat, SourceDialect, SqlConnection, SqlDialect, Subject, ToolCall,
    UnknownToolArgs, canonical_json, from_plan_json, validate_plan,
};

/// A small deterministic PCG-style generator. Same seed => same sequence.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9e3779b97f4a7c15)
    }
    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545f4914f6cdd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len())]
    }
}

/// Tokens chosen to stress shell/SQL/source parsers and the nesting machinery.
const TOKENS: &[&str] = &[
    "rm",
    "-rf",
    "/",
    "sh",
    "-c",
    "\"",
    "'",
    "$(",
    ")",
    "`",
    "|",
    "&&",
    "||",
    ";",
    "\n",
    "\t",
    " ",
    "\0",
    "docker",
    "exec",
    "postgres",
    "psql",
    "UPDATE",
    "DROP",
    "TABLE",
    "public.users",
    "(",
    "{",
    "}",
    "[",
    "]",
    "\\",
    "é",
    "🔥",
    "\u{202e}",
    "0",
    "x",
    "=",
    "$",
    "#!",
    "python3",
    "node",
    "def",
    "function",
    "import",
    "os",
    "system",
    "require",
    "fs",
    "child_process",
    "SELECT",
    "FROM",
    "WHERE",
    "--",
    "/*",
    "*/",
    "\r\n",
    "<?php",
    "&",
    ">",
    "<",
    ">>",
    "<<",
    "<<-",
    "<<'",
    "<<EOF",
    "EOF",
    "2>&1",
    "~",
    "*",
    "?",
    "..",
    "env",
    "sudo",
    "git",
    "checkout",
    "aws",
    "s3",
    "s3://b/k",
    "kubectl",
    "..",
    "$TMPDIR",
    "requests.get(\"/api/x\")",
    "urlopen(\"\")",
    "URI(\"/x\")",
    "ENV[\"APP_ROOT\"]",
    "File.join(",
    "File.exist?(",
    "http.Get(\"/relative\")",
    "git2::Repository::open(",
    "socket.AF_UNIX",
    "\"\"",
];

/// Build a random source string: mostly token soup, with occasional raw
/// random Unicode and a few explicit pathological shapes.
fn gen_source(rng: &mut Rng) -> String {
    match rng.below(16) {
        0 => String::new(),
        1 => "   \t\n  ".to_string(),
        2 => ";;;|||&&&(((".to_string(),
        3 => "\"".repeat(1 + rng.below(200)),
        4 => "sh -c \"".repeat(1 + rng.below(80)), // deep unbalanced nesting
        5 => "x".repeat(1 + rng.below(40_000)),    // large, to exercise byte limit
        6 => {
            // deeply nested sh -c
            let depth = 1 + rng.below(60);
            let mut s = String::from("rm /x");
            for _ in 0..depth {
                s = format!("sh -c \"{s}\"");
            }
            s
        }
        7 => rng
            .pick(&[
                "f(){ rm /x; }; f",
                "g(){ cp $1 $2; }; g /a /b",
                "f(){ rm /x; }; a=(1 2); f \"${a[@]}\"",
            ])
            .to_string(),
        _ => {
            let n = rng.below(60);
            let mut s = String::with_capacity(n * 4);
            for _ in 0..n {
                if rng.below(6) == 0 {
                    // a raw random char (any Unicode scalar, incl. control)
                    let c = char::from_u32(rng.below(0x110000) as u32).unwrap_or('?');
                    s.push(c);
                } else {
                    s.push_str(rng.pick(TOKENS));
                }
            }
            s
        }
    }
}

fn gen_argv(rng: &mut Rng) -> Vec<String> {
    let n = rng.below(8);
    (0..n).map(|_| gen_source(rng)).collect()
}

fn gen_subject(rng: &mut Rng) -> Subject {
    let src = gen_source(rng);
    let cwd = if rng.below(2) == 0 {
        Some("/w".to_string())
    } else {
        None
    };
    match rng.below(14) {
        0 => Subject::Exec {
            argv: gen_argv(rng),
            cwd,
            context: Default::default(),
        },
        1 => Subject::Shell {
            source: src,
            cwd,
            context: Default::default(),
        },
        2 => Subject::Source {
            dialect: None,
            language: "python".into(),
            source: src,
            cwd,
            context: Default::default(),
        },
        3 => Subject::Source {
            language: "js".into(),
            source: src,
            dialect: Some(if rng.below(2) == 0 {
                SourceDialect::Js
            } else {
                SourceDialect::Ts
            }),
            cwd,
            context: Default::default(),
        },
        4 => Subject::Sql {
            source: src,
            dialect: rng.pick(&[
                SqlDialect::Postgres,
                SqlDialect::Mysql,
                SqlDialect::Sqlite,
                SqlDialect::Generic,
                SqlDialect::TSql,
                SqlDialect::Snowflake,
                SqlDialect::BigQuery,
                SqlDialect::ClickHouse,
                SqlDialect::Cql,
            ]),
            connection: SqlConnection::default(),
        },
        5 => Subject::ToolCall {
            call: ToolCall::FileRead(FileReadArgs {
                path: src,
                range: None,
            }),
            cwd,
            context: Default::default(),
        },
        6 => Subject::ToolCall {
            call: ToolCall::FileWrite(FileWriteArgs {
                path: gen_source(rng),
                content: src,
            }),
            cwd,
            context: Default::default(),
        },
        7 => Subject::ToolCall {
            call: ToolCall::FileEdit(FileEditArgs {
                path: gen_source(rng),
                old: gen_source(rng),
                new: src,
                count: Some(rng.below(4) as u32),
            }),
            cwd,
            context: Default::default(),
        },
        8 => Subject::ToolCall {
            call: ToolCall::FilePatch(FilePatchArgs {
                format: if rng.below(2) == 0 {
                    PatchFormat::Unified
                } else {
                    PatchFormat::ApplyPatch
                },
                text: src,
            }),
            cwd,
            context: Default::default(),
        },
        9 => Subject::ToolCall {
            call: ToolCall::FsGlob(FsGlobArgs {
                pattern: src,
                root: (rng.below(2) == 0).then(|| gen_source(rng)),
            }),
            cwd,
            context: Default::default(),
        },
        10 => Subject::ToolCall {
            call: ToolCall::FsGrep(FsGrepArgs {
                pattern: src,
                paths: (rng.below(2) == 0).then(|| gen_argv(rng)),
                root: (rng.below(2) == 0).then(|| gen_source(rng)),
            }),
            cwd,
            context: Default::default(),
        },
        11 => Subject::ToolCall {
            call: ToolCall::FsList(FsListArgs { path: src }),
            cwd,
            context: Default::default(),
        },
        12 => Subject::ToolCall {
            call: ToolCall::Unknown(UnknownToolArgs {
                name: src,
                args: serde_json::json!({"opaque": gen_source(rng)}),
            }),
            cwd,
            context: Default::default(),
        },
        _ => Subject::Source {
            dialect: None,
            language: rng
                .pick(&["go", "ruby", "rust", "java", "php", "unknownlang"])
                .to_string(),
            source: src,
            cwd,
            context: Default::default(),
        },
    }
}

/// Random limits, including zeros, to exercise saturation everywhere.
fn gen_limits(rng: &mut Rng) -> Limits {
    let mut limits = default_limits();
    for key in [
        "max_effects",
        "max_provenance_nodes",
        "max_boundaries",
        "max_execution_nodes",
        "max_execution_depth",
        "max_shell_function_depth",
        "max_shell_words",
        "max_heredoc_expansions",
        "max_source_bytes",
        "max_resolved_source_files",
        "max_patch_bytes",
        "max_patch_files",
        "max_analysis_steps",
        "max_analysis_bytes",
        "max_python_nodes",
        "max_js_nodes",
        "max_php_nodes",
        "max_java_nodes",
        "max_go_nodes",
        "max_ruby_nodes",
        "max_rust_nodes",
    ] {
        if rng.below(3) == 0 {
            limits.insert(key.to_string(), rng.below(12) as u64);
        }
    }
    limits
}

fn describe(subject: &Subject) -> String {
    format!("{subject:?}").chars().take(300).collect::<String>()
}

#[test]
fn engine_never_panics_and_plans_validate() {
    let engine = Engine::new();
    let mut rng = Rng::new(0xE1CE_F00D);
    for i in 0..8000u64 {
        let subject = gen_subject(&mut rng);
        let result = catch_unwind(AssertUnwindSafe(|| engine.analyze(&subject)));
        let plan = match result {
            Err(_) => panic!("PANIC on iteration {i}, subject: {}", describe(&subject)),
            Ok(Err(_)) => continue, // typed EngineError is allowed
            Ok(Ok(plan)) => plan,
        };
        if let Err(errors) = validate_plan(&plan) {
            panic!(
                "INVALID PLAN on iteration {i}\n  subject: {}\n  errors: {errors:?}",
                describe(&subject)
            );
        }
    }
}

#[test]
fn analysis_is_deterministic() {
    let engine = Engine::new();
    let mut rng = Rng::new(0xD37E_2222);
    for _ in 0..4000u64 {
        let subject = gen_subject(&mut rng);
        if let Ok(a) = engine.analyze(&subject) {
            let b = engine.analyze(&subject).unwrap();
            validate_plan(&a).unwrap_or_else(|e| panic!("invalid first plan: {e:?}"));
            validate_plan(&b).unwrap_or_else(|e| panic!("invalid second plan: {e:?}"));
            assert_eq!(
                canonical_json(&a),
                canonical_json(&b),
                "nondeterministic for {}",
                describe(&subject)
            );
        }
    }
}

#[test]
fn output_is_bounded_under_random_limits() {
    let mut rng = Rng::new(0xB0DD_5555);
    for i in 0..4000u64 {
        let limits = gen_limits(&mut rng);
        let engine = Engine::with_limits(limits.clone()).unwrap();
        let subject = gen_subject(&mut rng);
        let Ok((plan, stats)) = engine.analyze_with_stats(&subject) else {
            continue;
        };
        validate_plan(&plan).unwrap_or_else(|e| panic!("invalid at {i}: {e:?}"));
        assert_eq!(
            plan.effects
                .iter()
                .map(|effect| &effect.id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            plan.effects.len(),
            "duplicate effect ID at {i}"
        );
        let lim = |k: &str| limits.get(k).copied().unwrap_or(u64::MAX);
        // Each cap holds; a handful of one-shot saturation records may exceed
        // the boundary/provenance caps by a small constant (the escape hatch).
        assert!(
            plan.effects.len() as u64 <= lim("max_effects"),
            "effects at {i}"
        );
        assert!(
            // Two one-shot span nodes past the cap: one per budget meter.
            plan.provenance.len() as u64 <= lim("max_provenance_nodes").saturating_add(4),
            "provenance at {i}"
        );
        assert!(
            stats.steps <= lim("max_analysis_steps").saturating_add(64),
            "steps at {i}: {} over {}",
            stats.steps,
            lim("max_analysis_steps")
        );
        assert!(
            stats.retained_bytes <= lim("max_analysis_bytes").saturating_add(4096),
            "retained bytes at {i}: {} over {}",
            stats.retained_bytes,
            lim("max_analysis_bytes")
        );
        assert!(
            plan.boundaries.len() as u64 <= lim("max_boundaries").saturating_add(16),
            "boundaries at {i}"
        );
    }
}

#[test]
fn plans_round_trip_through_canonical_json() {
    let engine = Engine::new();
    let mut rng = Rng::new(0x2217_ABCD);
    for _ in 0..4000u64 {
        let subject = gen_subject(&mut rng);
        let Ok(plan) = engine.analyze(&subject) else {
            continue;
        };
        validate_plan(&plan).expect("original plan is valid");
        let json = canonical_json(&plan);
        let reparsed = from_plan_json(&json).expect("canonical JSON re-parses");
        validate_plan(&reparsed).expect("reparsed plan is valid");
        assert_eq!(json, canonical_json(&reparsed), "canonical form is stable");
    }
}
