use effinterp_engine::{Engine, default_limits};
use effinterp_proto::{ExecutionContent, Plan, Subject};

fn shell(source: &str) -> Plan {
    shell_with_limits(source, None)
}

fn shell_with_limits(source: &str, max_source_bytes: Option<u64>) -> Plan {
    let mut limits = default_limits();
    if let Some(max_source_bytes) = max_source_bytes {
        limits.insert("max_source_bytes".to_string(), max_source_bytes);
    }
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: source.to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    effinterp_proto::validate_plan(&plan).unwrap();
    plan
}

fn deleted(plan: &Plan) -> Vec<String> {
    let mut paths = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource(&effect.resource))
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

#[test]
fn mixed_printf_formats_repeat_through_pipes_and_written_scripts() {
    let piped = shell("printf '%s %b\\n' rm '-rf /mixed' rm '-rf /repeated' | sh");
    assert_eq!(deleted(&piped), ["fs:/mixed", "fs:/repeated"]);

    // External printf copies `%s` arguments verbatim, so a backslash there
    // needs no shared-escape check, including when the format repeats.
    let external = shell(r"/usr/bin/printf '%s\n' 'r\m -rf /one' 'r\m -rf /two' | sh");
    assert_eq!(deleted(&external), ["fs:/one", "fs:/two"]);
    let external = shell(r"/usr/bin/printf '%s' 'r\m -rf /etc' > build.sh; sh build.sh");
    assert_eq!(deleted(&external), ["fs:/etc"]);
    // `%c` writes only its argument's first character.
    let first_character = shell("printf '%c%s' rm 'm -rf /first-character' | sh");
    assert_eq!(deleted(&first_character), ["fs:/first-character"]);
    let external = shell("/usr/bin/printf '%c%s' rm 'm -rf /first-character' | sh");
    assert_eq!(deleted(&external), ["fs:/first-character"]);

    let source = "rm -rf /written-one\nrm -rf /written-two\n";
    let written = shell(
        "printf '%s %b\\n' rm '-rf /written-one' rm '-rf /written-two' > generated.sh; sh generated.sh",
    );
    assert_eq!(deleted(&written), ["fs:/written-one", "fs:/written-two"]);
    assert!(written.execution_graph.nodes.iter().any(|node| {
        node.selected_source_path() == Some("/w/generated.sh")
            && node.input.as_ref().is_some_and(|input| {
                input.content
                    == ExecutionContent::Predicted {
                        digest: effinterp_proto::content_digest(source.as_bytes()),
                    }
            })
    }));
}

#[test]
fn literal_output_decodes_only_bounded_ascii_escapes() {
    for (source, expected) in [
        (r"echo -ne 'rm\x20-rf\x20/echo' | sh", "fs:/echo"),
        (r"printf '\162\155\040-rf\040/octal' | sh", "fs:/octal"),
        (r"printf '\562\555\440-rf\440/wrapped' | sh", "fs:/wrapped"),
        (r"printf '\x72\x6d\x20-rf\x20/hex' | sh", "fs:/hex"),
        (
            r"printf '\u0072\u006d\u0020-rf\u0020/unicode' | sh",
            "fs:/unicode",
        ),
        (
            r"printf '\U00000072\U0000006d\U00000020-rf\U00000020/wide' | sh",
            "fs:/wide",
        ),
        (
            r"printf '%b' '\0162\0155\0040-rf\0040/percent-b' | sh",
            "fs:/percent-b",
        ),
        // Standard-directory twins of the builtins write the same bytes.
        (
            r"/usr/bin/printf '%b' '\162\155\040-rf\040/usr-printf' | sh",
            "fs:/usr-printf",
        ),
        (r"/bin/echo -n 'rm -rf /bin-echo' | sh", "fs:/bin-echo"),
        (r"/bin/cat <<< 'rm -rf /bin-cat' | sh", "fs:/bin-cat"),
    ] {
        assert_eq!(deleted(&shell(source)), [expected], "{source}");
    }
}

#[test]
fn uncertain_printf_semantics_do_not_invent_executed_source() {
    for source in [
        r"printf '%d' 'rm -rf /numeric' | sh",
        r"printf '%b' 'rm -rf /\u0000tmp' > payload.sh; sh payload.sh",
        r"printf '%2s' 'rm -rf /width' | sh",
        r"printf '%.1s' 'rm -rf /precision' | sh",
        r"printf '\xffrm -rf /hex-locale' | sh",
        r"printf '\377rm -rf /octal-locale' | sh",
        r"printf '\u0080rm -rf /unicode-locale' | sh",
        r#"printf '%b' 'rm -rf \"/escaped-quote\"' | sh"#,
        r"printf '%b' 'rm\c -rf /stop-output' | sh",
        r"echo -e 'rm\c -rf /stop-echo' | sh",
    ] {
        let plan = shell(source);
        assert!(deleted(&plan).is_empty(), "{source}");
        assert!(!plan.boundaries.is_empty(), "{source}");
    }
    // An empty or missing `%c` writes NUL in Bash 5 and nothing in Bash 3.2,
    // which splits or joins NUL-separated operands.
    for source in [
        r"printf '%s%c%s' /etc '' /../tmp/cache | xargs -0 rm -rf",
        r"printf '%s%c%s' /e '' tc | xargs -0 rm -rf",
        r"printf '%s%c' /etc | xargs -0 rm -rf",
    ] {
        let plan = shell(source);
        assert!(
            deleted(&plan)
                .iter()
                .all(|path| !path.contains("/etc") && !path.contains("/tmp")),
            "{source}"
        );
        assert!(!plan.boundaries.is_empty(), "{source}");
    }
}

#[test]
fn exact_output_requires_a_resolved_builtin_producer() {
    for source in [
        "printf(){ echo safe; }; printf '%s' 'rm -rf /shadowed' | sh",
        r#""$PRODUCER" '%s' 'rm -rf /unknown-producer' | sh"#,
        r#"printf "$FORMAT" 'rm -rf /unknown-format' | sh"#,
        r#"printf '%b' "$PAYLOAD" | sh"#,
        "/usr/local/bin/printf '%s' 'rm -rf /nonstandard-dir' | sh",
        // BSD echo prints `-e` and a second `-n` where GNU reads options.
        "/bin/echo -e 'rm -rf /bsd-echo' | sh",
        "/bin/echo -n -n 'rm -rf /bsd-echo' | sh",
        // BSD printf prints `\x`, `\u`, and `\U` escapes literally, and reads
        // `\0NNN` with one digit fewer than GNU under `%b`.
        r"/usr/bin/printf '\x72\x6d\x20-rf\x20/bsd-hex' | sh",
        r"/usr/bin/printf '%b' '\u0072\u006d\u0020-rf\u0020/bsd-unicode' | sh",
        r"/usr/bin/printf '%b' '\0162\0155\0040-rf\0040/bsd-octal' | sh",
    ] {
        let plan = shell(source);
        assert!(deleted(&plan).is_empty(), "{source}");
        assert!(!plan.boundaries.is_empty(), "{source}");
    }
}

#[test]
fn repeated_format_output_stops_at_the_source_byte_limit() {
    let format = format!("{}%s\\n", "true;".repeat(20));
    let source = format!("printf '{format}' '' '' '' 'rm -rf /past-limit' | sh");
    assert!(source.len() < 256);
    let plan = shell_with_limits(&source, Some(256));
    assert!(deleted(&plan).is_empty());
    assert!(!plan.boundaries.is_empty());
}

#[test]
fn literal_bytes_through_an_open_descriptor_are_the_file_content() {
    for source in [
        r#"exec 3>/tmp/c; printf '%s' 'TOOL=rm' >&3; exec 3>&-; source /tmp/c; "$TOOL" -rf /fd"#,
        r#"exec 3>/tmp/c; printf '%s' 'TOOL=' >&3; printf '%s' 'rm' 1>&3; exec 3>&-; source /tmp/c; "$TOOL" -rf /fd"#,
        r#"exec {out}>/tmp/c; echo TOOL=rm >&$out; exec {out}>&-; . /tmp/c; "$TOOL" -rf /fd"#,
    ] {
        assert_eq!(deleted(&shell(source)), ["fs:/fd"], "{source}");
    }
    // Another program may write to the open descriptor, and a conditional
    // write may not happen.
    for source in [
        r#"exec 3>/tmp/c; printf '%s' 'TOOL=rm' >&3; "$WRITER"; exec 3>&-; source /tmp/c; "$TOOL" -rf /fd"#,
        r#"exec 3>/tmp/c; true && printf '%s' 'TOOL=rm' >&3; exec 3>&-; source /tmp/c; "$TOOL" -rf /fd"#,
    ] {
        assert!(deleted(&shell(source)).is_empty(), "{source}");
    }
}

/// Observed host files are empty, so only a predicted write supplies source.
struct EmptyFiles;

impl effinterp_engine::SourceResolver for EmptyFiles {
    fn resolve(&self, _: effinterp_engine::SourceRequest<'_>) -> effinterp_engine::SourceResponse {
        effinterp_engine::SourceResponse::Source(Vec::new())
    }

    fn siblings(&self, _: &str) -> Option<Vec<String>> {
        None
    }
}

fn observed_shell(source: &str) -> Plan {
    let plan = Engine::new()
        .with_resolver(Box::new(EmptyFiles))
        .analyze(&Subject::Shell {
            source: source.to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    effinterp_proto::validate_plan(&plan).unwrap();
    plan
}

#[test]
fn literal_bytes_piped_into_tee_are_the_file_content() {
    for source in [
        "printf '%s' 'rm -rf /tee' | tee downloaded.sh >/dev/null; sh downloaded.sh",
        "echo 'rm -rf /tee' | tee downloaded.sh; sh downloaded.sh",
    ] {
        assert_eq!(deleted(&observed_shell(source)), ["fs:/tee"], "{source}");
    }
    // A read inside the pipeline races the write, background work may not
    // have written yet, and a second write of the file in the region leaves
    // its bytes unknown.
    for source in [
        "printf '%s' 'rm -rf /tee' | tee downloaded.sh | sh downloaded.sh",
        "printf '%s' 'rm -rf /tee' | tee downloaded.sh & sh downloaded.sh",
        "printf '%s' 'rm -rf /tee' | tee downloaded.sh | tee downloaded.sh >/dev/null; sh downloaded.sh",
        "\"$PRODUCER\" | tee downloaded.sh >/dev/null; sh downloaded.sh",
    ] {
        assert!(
            !deleted(&observed_shell(source)).contains(&"fs:/tee".to_string()),
            "{source}"
        );
    }
}
