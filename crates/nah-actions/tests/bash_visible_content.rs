mod support;

use nah_actions::finalize;
use nah_proto::action::{Coverage, EffectKind, FilesystemOperation};
use support::{absolute, bash_plan, observe};

fn stream(source: &str) -> nah_proto::action::ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

fn has_root_delete(source: &str) -> bool {
    stream(source).effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Delete
                    && effect.target == absolute("/")
                    && effect.recursive
        )
    })
}

#[test]
fn exact_visible_shell_programs_are_lowered_again() {
    for source in [
        "echo 'rm -rf /' | bash",
        "printf '%s' 'rm -rf /' | sh",
        "printf '%s' rm ' -rf /' | bash",
        "printf '%b' 'rm -rf /' | bash",
        "cat <<'EOF' | bash\nrm -rf /\nEOF\n",
        "cat <<EOF | bash\nrm -rf /\nEOF\n",
        "echo 'rm -rf /' | source /dev/stdin",
        "echo 'rm -rf /' | source /proc/self/fd/0",
        "eval \"$(printf '%s' 'rm -rf /')\"",
        "eval \"$(printf '%s' rm; printf '%s' ' -rf /')\"",
        "echo 'rm -rf /' > downloaded.sh; bash downloaded.sh",
        "printf '%s' 'rm -rf /' | tee downloaded.sh >/dev/null; sh downloaded.sh",
    ] {
        assert!(has_root_delete(source), "{source}: {:?}", stream(source));
    }
}

#[test]
fn bounded_printf_escapes_reach_existing_shell_guards() {
    for source in [
        r"printf '\x72\x6d\x20-rf\x20/' | bash",
        r"printf '\162\155\040-rf\040/' | bash",
        r"printf '\562\555\440-rf\440/' | bash",
        r"printf '\u0072\u006d\u0020-rf\u0020/' | bash",
        r"printf '\U00000072\U0000006d\U00000020-rf\U00000020/' | bash",
        r"printf '%b' '\x72\x6d\x20-rf\x20/' | bash",
        r"printf '%b' '\162\155\040-rf\040/' | bash",
        r"printf '%b' '\0162\0155\0040-rf\0040/' | bash",
        r"printf '%b' '\562\555\440-rf\440/' | bash",
        r"printf '%b' '\u0072\u006d\u0020-rf\u0020/' | bash",
        r"command printf '\x72\x6d\x20-rf\x20/' | bash",
        r"printf '\x72\x6d\x20-rf\x20/' > payload; bash payload",
        r#"eval "$(printf '\x72\x6d\x20-rf\x20/')""#,
        r"exec 3> >(bash); printf '\x72\x6d\x20-rf\x20/' >&3",
    ] {
        assert!(has_root_delete(source), "{source}: {:?}", stream(source));
    }
}

#[test]
fn uncertain_or_harmless_printf_output_does_not_invent_effects() {
    for source in [
        r"printf '\x72\x6d\x20-rf\x20/'",
        r"printf '\x72\x6d\x20-rf\x20/' | grep rm",
        r"printf '\x65\x63\x68\x6f ok' | bash",
        r#"printf "$FMT" 'rm -rf /' | bash"#,
        r#"printf '%b' "$PAYLOAD" | bash"#,
        r"printf '%d' 1 | bash",
        r"printf '%-s' 'rm -rf /' | bash",
        r"printf '%2s' 'rm -rf /' | bash",
        r"printf '%.1s' 'rm -rf /' | bash",
        r"printf '%b' 'rm\c -rf /' | bash",
        r#"printf '%b' 'rm -rf \"/\"' | bash"#,
        r"printf '\x' | bash",
        r"printf '\xff' | bash",
        r"printf '\377' | bash",
        r"printf '\0162\0155\0040-rf\0040/' | bash",
        r"printf '\u072' | bash",
        r"printf '\u0080' | bash",
        r"printf 'rm -rf /\0' | bash",
        r"printf(){ echo safe; }; printf '\x72\x6d\x20-rf\x20/' | bash",
    ] {
        assert!(!has_root_delete(source), "{source}: {:?}", stream(source));
    }
}

#[test]
fn ansi_c_words_are_static_but_unknown_content_stays_unresolved() {
    for source in ["$'rm' -rf /", "bash -c $'rm\\x20-rf\\x20/'"] {
        assert!(has_root_delete(source), "{source}: {:?}", stream(source));
    }

    for source in [
        "echo \"$PAYLOAD\" | bash",
        "bash preexisting.sh",
        "printf '%q' 'rm -rf /' | bash",
        "echo -ne 'rm\\x20-rf\\x20/' | bash",
        "cat <<EOF | bash\n$PAYLOAD\nEOF\n",
    ] {
        let observed = stream(source);
        assert_eq!(observed.coverage(), Coverage::Partial, "{source}");
        assert!(!has_root_delete(source), "{source}: {observed:?}");
    }
}

#[test]
fn exact_content_does_not_cross_an_unproven_stream_or_overwrite() {
    for source in [
        "echo 'rm -rf /' 2> downloaded.sh; bash downloaded.sh",
        "echo 'rm -rf /' > downloaded.sh; echo safe > downloaded.sh; bash downloaded.sh",
        "echo 'rm -rf /' >> downloaded.sh; bash downloaded.sh",
    ] {
        assert!(!has_root_delete(source), "{source}: {:?}", stream(source));
    }
}

#[test]
fn exact_content_reparsing_is_shell_specific_and_bounded() {
    let python = stream("echo 'rm -rf /' > payload.py; python3 payload.py");
    assert_eq!(python.coverage(), Coverage::Partial);
    assert!(!has_root_delete(
        "echo 'rm -rf /' > payload.py; python3 payload.py"
    ));

    let recursive = stream("echo 'bash downloaded.sh' > downloaded.sh; bash downloaded.sh");
    assert_eq!(recursive.coverage(), Coverage::Partial);
    assert!(!has_root_delete(
        "echo 'bash downloaded.sh' > downloaded.sh; bash downloaded.sh"
    ));

    assert_eq!(
        stream("echo 'echo safe' | bash; echo 'echo safe' | bash").coverage(),
        Coverage::Full
    );
}
