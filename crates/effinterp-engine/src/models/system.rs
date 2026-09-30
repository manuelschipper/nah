//! Host service, scheduling, power, and clock effects.
use std::collections::BTreeMap;

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan_with_value_indices};
use crate::models::common::{
    Attrs, arg_effect, code_execution, fs_full_no_spawn, opaque_source_with_provenance,
    operand_effect, program_input_attrs, system_full,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::nest::{Transition, word_resource};
use crate::paths::resolve_fs_word_with_cwd;
use crate::word::{Word, WordPart};
use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ProvenanceRef, ResourceExpr, ResourceFamily, ResourceIdentity, Subject,
};

pub(crate) const SERVICE_START: &str = "system.service_start";
pub(crate) const SERVICE_STOP: &str = "system.service_stop";
pub(crate) const SERVICE_RESTART: &str = "system.service_restart";
pub(crate) const SERVICE_ENABLE: &str = "system.service_enable";
pub(crate) const SERVICE_DISABLE: &str = "system.service_disable";
pub(crate) const SCHEDULED_JOB_WRITE: &str = "system.scheduled_job_write";
pub(crate) const SCHEDULED_JOB_DELETE: &str = "system.scheduled_job_delete";
pub(crate) const STORAGE_DESTROY: &str = "system.storage_destroy";
pub(crate) const POWER: &str = "system.power";
pub(crate) const CLOCK_SET: &str = "system.clock_set";
pub(crate) const KERNEL_TRIGGER: &str = "system.kernel_trigger";

const CRON_MONTHS: &[&str] = &[
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];
const CRON_DAYS: &[&str] = &["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
const CRON_SPECIALS: &[&str] = &[
    "@reboot",
    "@yearly",
    "@annually",
    "@monthly",
    "@weekly",
    "@daily",
    "@midnight",
    "@hourly",
];
type CronEnvironment = BTreeMap<String, String>;

fn cron_atom(value: &str, min: u8, max: u8, names: &[&str]) -> bool {
    value
        .parse::<u8>()
        .is_ok_and(|value| (min..=max).contains(&value))
        || names.iter().any(|name| value.eq_ignore_ascii_case(name))
}

fn cron_field(value: &str, min: u8, max: u8, names: &[&str]) -> bool {
    value.split(',').all(|part| {
        if part.is_empty() {
            return false;
        }
        let mut stepped = part.split('/');
        let base = stepped.next().unwrap();
        if let Some(step) = stepped.next()
            && (step.parse::<u16>().ok().is_none_or(|step| step == 0) || stepped.next().is_some())
        {
            return false;
        }
        if base == "*" {
            return true;
        }
        if let Some((start, end)) = base.split_once('-') {
            return cron_atom(start, min, max, names) && cron_atom(end, min, max, names);
        }
        cron_atom(base, min, max, names)
    })
}

fn cron_word(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_start_matches(char::is_whitespace);
    let end = value.find(char::is_whitespace).unwrap_or(value.len());
    (end != 0).then(|| (&value[..end], &value[end..]))
}

fn cron_command(line: &str) -> Option<&str> {
    let (first, mut rest) = cron_word(line)?;
    if first.starts_with('@') {
        return CRON_SPECIALS
            .contains(&first)
            .then(|| rest.trim_start_matches(char::is_whitespace))
            .filter(|command| !command.is_empty());
    }
    let mut fields = [first, "", "", "", ""];
    for field in &mut fields[1..] {
        (*field, rest) = cron_word(rest)?;
    }
    let valid = cron_field(fields[0], 0, 59, &[])
        && cron_field(fields[1], 0, 23, &[])
        && cron_field(fields[2], 1, 31, &[])
        && cron_field(fields[3], 1, 12, CRON_MONTHS)
        && cron_field(fields[4], 0, 7, CRON_DAYS);
    valid
        .then(|| rest.trim_start_matches(char::is_whitespace))
        .filter(|command| !command.is_empty())
}

fn cron_environment(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once('=')?;
    let name = name.trim();
    let mut chars = name.chars();
    let valid_name = chars
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_');
    valid_name.then(|| {
        let value = value.trim_start_matches(char::is_whitespace);
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .unwrap_or(value);
        (name, value)
    })
}

fn crontab_commands(source: &str) -> (Vec<(String, CronEnvironment)>, bool) {
    let mut environment = CronEnvironment::new();
    let mut commands = Vec::new();
    let mut complete = true;
    for line in source.lines() {
        let line = line.trim_start_matches(char::is_whitespace);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, value)) = cron_environment(line) {
            environment.insert(name.to_string(), value.to_string());
            continue;
        }
        let Some(command) = cron_command(line) else {
            complete = false;
            continue;
        };
        if command
            .char_indices()
            .any(|(index, character)| character == '%' && !command[..index].ends_with('\\'))
        {
            complete = false;
            continue;
        }
        commands.push((command.replace("\\%", "%"), environment.clone()));
    }
    (commands, complete)
}

pub(crate) fn system_models() -> Vec<Box<dyn CommandModel>> {
    vec![Box::new(System), Box::new(Visudo)]
}

/// sudo's visudo(8): it copies the sudoers file (`/etc/sudoers`, or the file
/// named by `-f` or the operand), runs the editor named by SUDO_EDITOR, VISUAL
/// or EDITOR on the copy, and installs a changed copy in place. `-c` only
/// parses the file; `-h` and `-V` print and exit. Both modes follow the
/// sudoers include directives to files named only in the file's contents.
struct Visudo;

impl CommandModel for Visudo {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process"]
    }

    fn id(&self) -> &'static str {
        "sudo/visudo@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["visudo"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        let mut check = false;
        let mut file = None;
        let mut operands = Vec::new();
        let mut unknown = Vec::new();
        let mut options = true;
        let mut i = 1;
        while i < ctx.argv.len() {
            let word = &ctx.argv[i];
            match word.as_literal() {
                Some("--") if options => options = false,
                Some("--help" | "--version") if options => return,
                Some("--check") if options => check = true,
                Some("--file") if options => {
                    i += 1;
                    file = ctx.argv.get(i).map(|value| (i, value.clone()));
                }
                Some("--no-includes" | "--owner" | "--perms" | "--quiet" | "--strict")
                    if options => {}
                Some(text) if options && text.starts_with("--file=") => {
                    file = Some((i, crate::models::args::strip_literal_prefix(word, 7)));
                }
                Some(text) if options && text.len() > 1 && text.starts_with('-') => {
                    for (at, flag) in text.char_indices().skip(1) {
                        match flag {
                            'h' | 'V' => return,
                            'c' => check = true,
                            'I' | 'O' | 'P' | 'q' | 's' => {}
                            'f' if at + 1 < text.len() => {
                                file = Some((
                                    i,
                                    crate::models::args::strip_literal_prefix(word, at + 1),
                                ));
                                break;
                            }
                            'f' => {
                                i += 1;
                                file = ctx.argv.get(i).map(|value| (i, value.clone()));
                            }
                            _ => {
                                unknown.push((i as u32, text.to_string()));
                                break;
                            }
                        }
                    }
                }
                None if options && word.literal_prefix().starts_with('-') => {
                    unknown.push((i as u32, word.render_raw()));
                }
                _ => operands.push(i),
            }
            i += 1;
        }
        if operands.len() > 1 {
            unknown.push((operands[1] as u32, "extra visudo operand".into()));
        }
        if !unknown.is_empty() {
            crate::models::common::unrecognized_arguments_boundary(
                builder,
                node,
                &["filesystem", "process"],
                &unknown,
            );
            return;
        }
        fs_full_no_spawn(builder);
        let (index, sudoers) = match (file, operands.first()) {
            (Some((index, file)), _) => (index, file),
            (None, Some(&index)) => (index, ctx.argv[index].clone()),
            (None, None) => (0, Word::literal("/etc/sudoers")),
        };
        let resource = ctx.resolve_fs_word(&sudoers);
        if check {
            arg_effect(
                builder,
                ctx,
                node,
                index as u32,
                "filesystem.read",
                resource,
                program_input_attrs(),
            );
        } else {
            // The editor is whatever SUDO_EDITOR, VISUAL or EDITOR names.
            ctx.nest_exec(
                builder,
                &[Word::new(vec![WordPart::Unknown])],
                ctx.cwd,
                None,
                &[node],
            );
            arg_effect(
                builder,
                ctx,
                node,
                index as u32,
                "filesystem.write",
                resource,
                Attrs::new(),
            );
        }
        builder.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::UNREAD_CONFIG,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("filesystem")],
                provenance: vec![node],
                limit: None,
                detail: Some(
                    "sudoers include directives name further files visudo reads or edits".into(),
                ),
            },
            CoverageLevel::Partial,
        );
    }
}
struct System;

// Switches and value parameters both power cmdlets bind in PowerShell 7,
// including the common parameters.
const POWER_SWITCHES: &[&str] = &["force", "confirm", "verbose", "debug"];
const POWER_VALUE_PARAMETERS: &[&str] = &[
    "computername",
    "credential",
    "wsmanauthentication",
    "erroraction",
    "warningaction",
    "informationaction",
    "progressaction",
    "errorvariable",
    "warningvariable",
    "informationvariable",
    "outvariable",
    "outbuffer",
    "pipelinevariable",
];

// Closed value sets the binder enforces: WsmanAuthentication's ValidateSet
// and the ActionPreference names the *Action common parameters take.
const WSMAN_AUTHENTICATION: &[&str] = &[
    "Default",
    "Basic",
    "Negotiate",
    "CredSSP",
    "Digest",
    "Kerberos",
];
const ACTION_PREFERENCES: &[&str] = &[
    "SilentlyContinue",
    "Stop",
    "Continue",
    "Inquire",
    "Ignore",
    "Break",
];

pub(crate) fn powershell_power(
    builder: &mut PlanBuilder,
    source: &str,
    node: ProvenanceRef,
) -> bool {
    let source = source.trim();
    let mut words = source.split_ascii_whitespace();
    let action = match words.next() {
        Some(command) if command.eq_ignore_ascii_case("Stop-Computer") => "poweroff",
        Some(command) if command.eq_ignore_ascii_case("Restart-Computer") => "reboot",
        _ => return false,
    };
    if source.contains(['\n', '\r']) {
        return false;
    }
    let restart = action == "reboot";
    let mut what_if = None;
    let mut wait = false;
    let mut waiting_parameter = false;
    // PowerShell rejects the whole command before any power action.
    let mut rejected = false;
    let mut local = true;
    let mut seen = Vec::new();
    while let Some(word) = words.next() {
        let Some(parameter) = word.strip_prefix('-') else {
            return false;
        };
        // A parameter binds its value as `-Name:value` or as the next word.
        let (name, inline) = match parameter.split_once(':') {
            Some((name, value)) => (name, Some(value)),
            None => (parameter, None),
        };
        let name = name.to_ascii_lowercase();
        if seen.contains(&name) {
            return false;
        }
        let switch = match inline {
            None => Some(true),
            Some(value) if value.eq_ignore_ascii_case("$true") => Some(true),
            Some(value) if value.eq_ignore_ascii_case("$false") => Some(false),
            Some(_) => None,
        };
        if name == "whatif" {
            let Some(value) = switch else { return false };
            what_if = Some(value);
        } else if restart && name == "wait" {
            let Some(value) = switch else { return false };
            wait = value;
        } else if POWER_SWITCHES.contains(&name.as_str()) {
            // `-Confirm:$false`, `-Force` and the like change prompting,
            // never whether the computer powers off.
            if switch.is_none() {
                return false;
            }
        } else {
            let waiting = restart && matches!(name.as_str(), "delay" | "timeout" | "for");
            if !waiting && !POWER_VALUE_PARAMETERS.contains(&name.as_str()) {
                return false;
            }
            let raw = match inline {
                Some(value) => value,
                None => words.next().unwrap_or(""),
            };
            if name == "computername" {
                // `-Wait` never waits for the local computer: PowerShell
                // skips it with an error and restarts only remote ones. Each
                // name of a list binds as its own literal.
                let Some(computers) = raw
                    .split(',')
                    .map(powershell_literal)
                    .collect::<Option<Vec<_>>>()
                else {
                    return false;
                };
                local = computers
                    .iter()
                    .all(|computer| *computer == "." || computer.eq_ignore_ascii_case("localhost"));
                seen.push(name);
                continue;
            }
            let Some(value) = powershell_literal(raw) else {
                return false;
            };
            let allowed = match name.as_str() {
                "wsmanauthentication" => Some(WSMAN_AUTHENTICATION),
                "erroraction" | "warningaction" | "informationaction" | "progressaction" => {
                    Some(ACTION_PREFERENCES)
                }
                _ => None,
            };
            let word = value.bytes().all(|byte| byte.is_ascii_alphabetic());
            if let Some(allowed) = allowed
                && !allowed
                    .iter()
                    .any(|known| value.eq_ignore_ascii_case(known))
            {
                // A name outside the set fails binding before the cmdlet
                // runs; a number or Suspend depends on conversions and
                // version rules this model does not carry.
                if !word || value.eq_ignore_ascii_case("Suspend") {
                    return false;
                }
                rejected = true;
            }
            if name == "outbuffer" {
                match value.parse::<i64>() {
                    Ok(size) => rejected |= !(0..=i64::from(i32::MAX)).contains(&size),
                    Err(_) if word => rejected = true,
                    Err(_) => return false,
                }
            }
            if waiting {
                waiting_parameter = true;
                // The binder converts the text to the parameter's type; a
                // value this model cannot convert is unmodeled, not rejected.
                let range = match name.as_str() {
                    "delay" => Some(1..=i64::from(i16::MAX)),
                    "timeout" => Some(-1..=i64::from(i32::MAX)),
                    _ => None,
                };
                rejected |= !match range {
                    Some(range) => {
                        let Ok(number) = value.parse::<i64>() else {
                            return false;
                        };
                        range.contains(&number)
                    }
                    None => ["Wmi", "WinRM", "PowerShell"]
                        .iter()
                        .any(|service| value.eq_ignore_ascii_case(service)),
                };
            }
        }
        seen.push(name);
    }
    // -Delay, -Timeout and -For are valid only with -Wait.
    rejected |= waiting_parameter && !wait;
    let powers = !(what_if.unwrap_or(false) || rejected || wait && local);
    for domain in ["system", "process"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
    }
    if powers {
        let model = builder.node(
            effinterp_proto::ProvenanceKind::ModelApplication {
                model: "system/powershell-power@v1".into(),
            },
            &[node],
        );
        let mut attributes = Attrs::new();
        text(&mut attributes, "action", action);
        system_change(&mut attributes, true, false, false, false, false);
        super::infrastructure::emit_with_attributes(
            builder,
            &[node, model],
            POWER,
            host(),
            attributes,
        );
    }
    true
}

/// A PowerShell argument as the parameter binder receives it: a quoted string
/// without expansion is its text, and an unquoted `-1` is a number, not a
/// parameter. None for a word this whitespace split cannot bind as a literal,
/// such as a variable, a subexpression or a quoted string the split broke.
fn powershell_literal(word: &str) -> Option<&str> {
    let text = if let Some(inner) = word.strip_prefix('\'').and_then(|w| w.strip_suffix('\'')) {
        (!inner.contains('\'')).then_some(inner)?
    } else if let Some(inner) = word.strip_prefix('"').and_then(|w| w.strip_suffix('"')) {
        (!inner.contains(['"', '$', '`'])).then_some(inner)?
    } else if word.contains(['\'', '"', '`']) || word.starts_with(['$', '(', '@', '{']) {
        return None;
    } else if let Some(number) = word.strip_prefix('-') {
        (!number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())).then_some(word)?
    } else {
        word
    };
    (!text.is_empty()).then_some(text)
}

fn flag(attributes: &mut Attrs, name: &str) {
    attributes.insert(name.into(), AttrValue::Bool(true));
}
fn text(attributes: &mut Attrs, name: &str, value: &str) {
    attributes.insert(name.into(), AttrValue::String(value.into()));
}
fn system_change(
    attributes: &mut Attrs,
    active: bool,
    cancel: bool,
    help: bool,
    runtime_only: bool,
    persistent: bool,
) {
    attributes.insert("active".into(), AttrValue::Bool(active));
    attributes.insert("cancel".into(), AttrValue::Bool(cancel));
    attributes.insert("help".into(), AttrValue::Bool(help));
    attributes.insert("runtime_only".into(), AttrValue::Bool(runtime_only));
    attributes.insert("persistent".into(), AttrValue::Bool(persistent));
}
fn valid_shutdown_time(value: &str) -> bool {
    if value == "now" {
        return true;
    }
    if let Some(minutes) = value.strip_prefix('+') {
        return !minutes.is_empty() && minutes.chars().all(|c| c.is_ascii_digit());
    }
    if value.len() != 5 || !value.is_ascii() || value.as_bytes()[2] != b':' {
        return false;
    }
    let bytes = value.as_bytes();
    bytes[..2].iter().all(|d| d.is_ascii_digit())
        && bytes[3..].iter().all(|d| d.is_ascii_digit())
        && bytes[..2].iter().fold(0u8, |n, d| n * 10 + *d - b'0') < 24
        && bytes[3..].iter().fold(0u8, |n, d| n * 10 + *d - b'0') < 60
}
fn valid_power_option(command: &str, value: &str) -> bool {
    if command == "shutdown" {
        return matches!(
            value,
            "-c" | "-f"
                | "-F"
                | "-H"
                | "-h"
                | "-k"
                | "-P"
                | "-p"
                | "-q"
                | "-r"
                | "-n"
                | "--no-wall"
                | "--no-sync"
                | "--force"
                | "--halt"
                | "--poweroff"
                | "--reboot"
                | "--show"
                | "--help"
                | "--version"
        ) || (value.starts_with('-')
            && !value.starts_with("--")
            && value[1..].chars().all(|c| {
                matches!(
                    c,
                    'c' | 'f' | 'F' | 'H' | 'h' | 'k' | 'P' | 'p' | 'q' | 'r' | 'n'
                )
            }));
    }
    matches!(
        value,
        "-f" | "-w" | "-n" | "--no-wall" | "--no-sync" | "--force"
    )
}
fn host() -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::HostSystem {},
    }
}
fn all_services() -> ResourceExpr {
    ResourceExpr::Pattern {
        pattern: effinterp_proto::ResourcePattern::ServiceUnit {
            manager: effinterp_proto::Field::Any,
            name_glob: "*".into(),
        },
    }
}
fn unit(manager: &str, word: &Word) -> ResourceExpr {
    word.as_literal()
        .map(|name| ResourceExpr::Concrete {
            identity: ResourceIdentity::ServiceUnit {
                manager: manager.into(),
                name: name.into(),
            },
        })
        .unwrap_or_else(|| ResourceExpr::Unresolved {
            family: ResourceFamily::new("system"),
        })
}
pub(crate) fn unmodeled_subcommand(builder: &mut PlanBuilder, node: ProvenanceRef) {
    fs_full_no_spawn(builder);
    builder.boundary(Boundary {
        reason: BoundaryReason::UNMODELED_SUBCOMMAND,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("system")],
        provenance: vec![node],
        limit: None,
        detail: None,
    });
    builder.declare_coverage(Domain::new("system"), CoverageLevel::Partial);
}

impl CommandModel for System {
    fn domains(&self) -> &'static [&'static str] {
        &["filesystem", "process", "system"]
    }

    fn id(&self) -> &'static str {
        "system/control@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &[
            "systemctl",
            "service",
            "shutdown",
            "reboot",
            "halt",
            "poweroff",
            "init",
            "telinit",
            "crontab",
            "at",
            "atrm",
            "date",
            "timedatectl",
            "hwclock",
        ]
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        fs_full_no_spawn(builder);
        system_full(builder);
        let command = ctx.argv[0]
            .as_literal()
            .unwrap_or("")
            .rsplit('/')
            .next()
            .unwrap();
        let has = |flag: &str| {
            ctx.argv
                .iter()
                .skip(1)
                .any(|w| w.as_literal() == Some(flag))
        };
        let mut attributes = Attrs::new();
        match command {
            "systemctl" => {
                if ctx
                    .argv
                    .iter()
                    .skip(1)
                    .any(|w| matches!(w.as_literal(), Some("--help" | "-h" | "--version")))
                {
                    return;
                }
                if has("--dry-run") {
                    return;
                }
                let mut systemctl_operands = Vec::new();
                // Options that take a value, joined (`--when=now`, `-Hhost`) or
                // as the next word, in command-line order.
                let mut values = Vec::new();
                let mut pending = None;
                // -H and -M words, which choose where the command runs.
                let mut realm_words = Vec::new();
                let mut after_options = false;
                for (index, word) in ctx.argv.iter().enumerate().skip(1) {
                    let Some(value) = word.as_literal() else {
                        // A tilde path is an operand; it cannot spell an option.
                        if pending.is_none()
                            && matches!(word.parts.first(), Some(WordPart::Env(name)) if name == "HOME")
                        {
                            systemctl_operands.push((index, word));
                            continue;
                        }
                        unmodeled_subcommand(builder, node);
                        return;
                    };
                    if let Some(option) = pending.take() {
                        if matches!(option, "--host" | "-H" | "--machine" | "-M") {
                            realm_words.push(index);
                        }
                        values.push((option, value));
                        continue;
                    }
                    if after_options {
                        systemctl_operands.push((index, word));
                        continue;
                    }
                    if value == "--" {
                        after_options = true;
                        continue;
                    }
                    if value.starts_with('-') && value != "-" {
                        let (name, inline) = match value.split_once('=') {
                            Some((name, inline)) if value.starts_with("--") => (name, Some(inline)),
                            _ if value.len() > 2
                                && (value.starts_with("-H") || value.starts_with("-M")) =>
                            {
                                (&value[..2], Some(&value[2..]))
                            }
                            _ => (value, None),
                        };
                        let takes_value = matches!(
                            name,
                            "--type"
                                | "--property"
                                | "--signal"
                                | "--kill-who"
                                | "--job-mode"
                                | "--preset-mode"
                                | "--lines"
                                | "--output"
                                | "--state"
                                | "--when"
                                | "--drop-in"
                                | "--host"
                                | "-H"
                                | "--machine"
                                | "-M"
                        );
                        if takes_value {
                            if matches!(name, "--host" | "-H" | "--machine" | "-M") {
                                realm_words.push(index);
                            }
                            match inline {
                                Some(inline) => values.push((name, inline)),
                                None => pending = Some(name),
                            }
                        } else if inline.is_some()
                            || !matches!(
                                value,
                                "--help"
                                    | "--version"
                                    | "--user"
                                    | "--runtime"
                                    | "--dry-run"
                                    | "--now"
                                    | "--no-block"
                                    | "--quiet"
                                    | "-q"
                                    | "--full"
                                    | "--force"
                                    | "--wait"
                                    | "--no-legend"
                                    | "--no-pager"
                                    | "--no-reload"
                                    | "--global"
                                    | "--check"
                                    | "--all"
                                    | "--failed"
                                    | "--recursive"
                                    | "--reverse"
                                    | "--no-ask-password"
                                    | "--stdin"
                            )
                        {
                            unmodeled_subcommand(builder, node);
                            return;
                        }
                    } else {
                        systemctl_operands.push((index, word));
                    }
                }
                if pending.is_some() {
                    unmodeled_subcommand(builder, node);
                    return;
                }
                let option = |names: &[&str]| {
                    values
                        .iter()
                        .rev()
                        .find(|(name, _)| names.contains(name))
                        .map(|(_, value)| *value)
                };
                // -H runs the operation on a remote host over SSH and -M in a
                // local container; the last one given decides. The rest of the
                // command runs there as it would here.
                let realm = values.iter().rev().find_map(|(name, value)| match *name {
                    "--host" | "-H" => Some(effinterp_proto::ExecutionRealm::Remote {
                        endpoint: value.rsplit('@').next().unwrap_or_default().to_string(),
                    }),
                    "--machine" | "-M" => Some(effinterp_proto::ExecutionRealm::Container {
                        runtime: "systemd-nspawn".to_string(),
                        name: value.to_string(),
                    }),
                    _ => None,
                });
                if let Some(realm) = realm {
                    let words = ctx
                        .argv
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| !realm_words.contains(index))
                        .map(|(_, word)| word.clone())
                        .collect::<Vec<_>>();
                    ctx.nest.nest(
                        builder,
                        Transition::exec(words.iter().map(word_resource).collect(), words.clone())
                            .stdin(ctx.stdin)
                            .kind(effinterp_proto::ExecutionEdgeKind::ContainerRealm)
                            .realm(realm),
                        &[node],
                        ctx.depth,
                    );
                    return;
                }
                let operands = systemctl_operands;
                if has("--user") {
                    flag(&mut attributes, "user_scope");
                }
                if has("--runtime") {
                    flag(&mut attributes, "runtime");
                }
                let verb = operands
                    .first()
                    .and_then(|(_, w)| w.as_literal())
                    .unwrap_or("");
                if verb == "--help" || verb == "--version" {
                    return;
                }
                const POWER_VERBS: &[&str] = &[
                    "poweroff",
                    "reboot",
                    "halt",
                    "kexec",
                    "suspend",
                    "hibernate",
                    "hybrid-sleep",
                    "suspend-then-hibernate",
                    "rescue",
                    "emergency",
                ];
                if has("--global") && (POWER_VERBS.contains(&verb) || verb == "isolate") {
                    unmodeled_subcommand(builder, node);
                    return;
                }
                // --when schedules a shutdown instead of starting it now; only
                // the shutdown verbs take it.
                let when = option(&["--when"]);
                if when.is_some() && !matches!(verb, "poweroff" | "reboot" | "halt" | "kexec") {
                    unmodeled_subcommand(builder, node);
                    return;
                }
                if POWER_VERBS.contains(&verb) {
                    match when {
                        Some("show") => return,
                        Some("" | "cancel") => {
                            flag(&mut attributes, "cancel");
                            system_change(&mut attributes, false, true, false, false, false);
                        }
                        _ => {
                            text(&mut attributes, "action", verb);
                            if let Some(when) = when {
                                text(&mut attributes, "when", when);
                            }
                            system_change(&mut attributes, true, false, false, false, false);
                        }
                    }
                    arg_effect(
                        builder,
                        ctx,
                        node,
                        operands[0].0 as u32,
                        POWER,
                        host(),
                        attributes,
                    );
                    return;
                }
                if (option(&["--drop-in"]).is_some() || has("--stdin")) && verb != "edit" {
                    unmodeled_subcommand(builder, node);
                    return;
                }
                // The unit-file commands change which units the boot and the
                // service manager can start: enabling covers every command
                // that links or unmasks a unit, disabling every one that
                // unlinks or masks it.
                let mut units = operands.iter().skip(1).copied().collect::<Vec<_>>();
                let ops: &[&str] = match verb {
                    "start" => &[SERVICE_START],
                    "stop" | "kill" => &[SERVICE_STOP],
                    "restart" | "reload-or-restart" | "try-restart" => &[SERVICE_RESTART],
                    "reload" => {
                        flag(&mut attributes, "reload");
                        &[SERVICE_RESTART]
                    }
                    "enable" => &[SERVICE_ENABLE],
                    "disable" => &[SERVICE_DISABLE],
                    "reenable" => &[SERVICE_DISABLE, SERVICE_ENABLE],
                    "preset" | "preset-all" => {
                        if verb == "preset-all" && !units.is_empty() {
                            unmodeled_subcommand(builder, node);
                            return;
                        }
                        match option(&["--preset-mode"]) {
                            Some("enable-only") => &[SERVICE_ENABLE],
                            Some("disable-only") => &[SERVICE_DISABLE],
                            _ if verb == "preset" => &[SERVICE_ENABLE],
                            _ => &[SERVICE_ENABLE, SERVICE_DISABLE],
                        }
                    }
                    "mask" => {
                        flag(&mut attributes, "mask");
                        &[SERVICE_DISABLE]
                    }
                    // Revert also removes a unit's mask with its overrides.
                    "unmask" | "revert" | "link" => {
                        flag(&mut attributes, verb);
                        &[SERVICE_ENABLE]
                    }
                    "set-default" => {
                        if units.len() != 1 {
                            unmodeled_subcommand(builder, node);
                            return;
                        }
                        flag(&mut attributes, "default");
                        &[SERVICE_ENABLE]
                    }
                    // TARGET UNIT...: TARGET pulls each UNIT in when it starts.
                    "add-wants" | "add-requires" => {
                        if units.len() < 2 {
                            unmodeled_subcommand(builder, node);
                            return;
                        }
                        let target = units.remove(0).1;
                        let Some(target) = target.as_literal() else {
                            unmodeled_subcommand(builder, node);
                            return;
                        };
                        text(&mut attributes, "dependency", &verb[4..]);
                        text(&mut attributes, "target", target);
                        &[SERVICE_ENABLE]
                    }
                    // `edit --stdin` writes the new contents without an editor.
                    "edit"
                        if has("--stdin")
                            && !(has("--user") && (has("--runtime") || has("--global"))) =>
                    {
                        // A user unit is edited under $XDG_CONFIG_HOME, else
                        // $HOME/.config.
                        let user_config = has("--user").then(|| {
                            let config = ResourceExpr::Join {
                                parts: vec![
                                    ctx.environment_value("HOME").unwrap_or(
                                        ResourceExpr::Environment {
                                            name: "HOME".into(),
                                        },
                                    ),
                                    ResourceExpr::Literal {
                                        value: "/.config".into(),
                                    },
                                ],
                            };
                            match ctx.environment_value("XDG_CONFIG_HOME") {
                                Some(ResourceExpr::Literal { value }) => {
                                    ctx.resolve_fs_word(&Word::literal(value))
                                }
                                Some(value) => value,
                                None if !ctx.tracks_host_context_environment()
                                    && !ctx.nest.environment_is_closed()
                                    && !ctx
                                        .nest
                                        .current_environment_unsets()
                                        .contains("XDG_CONFIG_HOME") =>
                                {
                                    ResourceExpr::Union {
                                        alternatives: vec![
                                            ResourceExpr::Environment {
                                                name: "XDG_CONFIG_HOME".into(),
                                            },
                                            config,
                                        ],
                                    }
                                }
                                None => config,
                            }
                        });
                        let base = if user_config.is_some() {
                            "systemd/user"
                        } else if has("--runtime") {
                            "/run/systemd/system"
                        } else if has("--global") {
                            "/etc/systemd/user"
                        } else {
                            "/etc/systemd/system"
                        };
                        let drop_in = match option(&["--drop-in"]) {
                            None | Some("") => "override.conf".to_string(),
                            Some(name) if name.ends_with(".conf") => name.to_string(),
                            Some(name) => format!("{name}.conf"),
                        };
                        if units.is_empty() || has("--full") && units.len() != 1 {
                            unmodeled_subcommand(builder, node);
                            return;
                        }
                        for (i, w) in &units {
                            let Some(name) = w.as_literal() else {
                                unmodeled_subcommand(builder, node);
                                continue;
                            };
                            // --full replaces a copy of the whole unit file.
                            let path = if has("--full") {
                                format!("{base}/{name}")
                            } else {
                                format!("{base}/{name}.d/{drop_in}")
                            };
                            let resource = match &user_config {
                                Some(config) => resolve_fs_word_with_cwd(
                                    &Word::literal(path),
                                    Some(config.clone()),
                                ),
                                None => ctx.resolve_fs_word(&Word::literal(path)),
                            };
                            arg_effect(
                                builder,
                                ctx,
                                node,
                                *i as u32,
                                "filesystem.write",
                                resource,
                                Attrs::new(),
                            );
                        }
                        return;
                    }
                    "isolate" => {
                        let mut isolate = attributes.clone();
                        flag(&mut isolate, "isolate");
                        system_change(&mut isolate, true, false, false, false, false);
                        arg_effect(
                            builder,
                            ctx,
                            node,
                            operands[0].0 as u32,
                            SERVICE_STOP,
                            all_services(),
                            isolate,
                        );
                        &[SERVICE_START]
                    }
                    "status" | "show" | "cat" | "daemon-reload" | "daemon-reexec" => return,
                    v if v.starts_with("list-") || v.starts_with("is-") => return,
                    _ => {
                        unmodeled_subcommand(builder, node);
                        return;
                    }
                };
                if has("--global")
                    && ops
                        .iter()
                        .any(|op| !matches!(*op, SERVICE_ENABLE | SERVICE_DISABLE))
                {
                    unmodeled_subcommand(builder, node);
                    return;
                }
                let now = has("--now")
                    && matches!(verb, "enable" | "disable" | "reenable" | "mask" | "preset");
                let targets = if verb == "preset-all" {
                    vec![(operands[0].0, all_services())]
                } else {
                    units
                        .iter()
                        .map(|(i, w)| {
                            (
                                *i,
                                if verb == "link" {
                                    // A unit is linked from its file; its name is the file's.
                                    match w.parts.last() {
                                        Some(WordPart::Literal(path))
                                            if path.contains('/') || w.as_literal().is_some() =>
                                        {
                                            unit(
                                                "systemd",
                                                &Word::literal(path.rsplit('/').next().unwrap()),
                                            )
                                        }
                                        _ => unit("systemd", &Word::new(vec![WordPart::Unknown])),
                                    }
                                } else {
                                    unit("systemd", w)
                                },
                            )
                        })
                        .collect()
                };
                for (i, resource) in targets {
                    for &op in ops {
                        let mut effect_attributes = attributes.clone();
                        if op == SERVICE_STOP {
                            system_change(
                                &mut effect_attributes,
                                true,
                                false,
                                false,
                                has("--runtime"),
                                false,
                            );
                        }
                        arg_effect(
                            builder,
                            ctx,
                            node,
                            i as u32,
                            op,
                            resource.clone(),
                            effect_attributes,
                        );
                        if now && matches!(op, SERVICE_ENABLE | SERVICE_DISABLE) {
                            arg_effect(
                                builder,
                                ctx,
                                node,
                                i as u32,
                                if op == SERVICE_ENABLE {
                                    SERVICE_START
                                } else {
                                    SERVICE_STOP
                                },
                                resource.clone(),
                                attributes.clone(),
                            );
                        }
                    }
                }
            }
            "service" => {
                if ctx
                    .argv
                    .iter()
                    .skip(1)
                    .any(|w| matches!(w.as_literal(), Some("--help" | "-h" | "--version")))
                {
                    return;
                }
                if ctx.argv.iter().skip(1).any(|w| {
                    w.as_literal()
                        .is_some_and(|value| value.starts_with('-') && value != "-")
                }) {
                    unmodeled_subcommand(builder, node);
                    return;
                }
                let op = match ctx.argv.get(2).and_then(Word::as_literal) {
                    Some("start") => SERVICE_START,
                    Some("stop") => SERVICE_STOP,
                    Some("restart") => SERVICE_RESTART,
                    Some("reload") => {
                        flag(&mut attributes, "reload");
                        SERVICE_RESTART
                    }
                    Some("status") => return,
                    _ => {
                        unmodeled_subcommand(builder, node);
                        return;
                    }
                };
                if let Some(w) = ctx.argv.get(1) {
                    if op == SERVICE_STOP {
                        system_change(&mut attributes, true, false, false, false, false);
                    }
                    arg_effect(builder, ctx, node, 1, op, unit("sysv", w), attributes);
                }
            }
            "init" | "telinit" => match ctx.argv.get(1).and_then(Word::as_literal) {
                Some(v @ ("0" | "6")) => {
                    text(
                        &mut attributes,
                        "action",
                        if v == "0" { "poweroff" } else { "reboot" },
                    );
                    system_change(&mut attributes, true, false, false, false, false);
                    arg_effect(builder, ctx, node, 1, POWER, host(), attributes);
                }
                _ => {
                    if ctx
                        .argv
                        .get(1)
                        .is_some_and(|word| word.as_literal().is_none())
                    {
                        unmodeled_subcommand(builder, node);
                    }

                    flag(&mut attributes, "isolate");
                    system_change(&mut attributes, true, false, false, false, false);
                    arg_effect(
                        builder,
                        ctx,
                        node,
                        0,
                        SERVICE_STOP,
                        all_services(),
                        attributes,
                    );
                }
            },
            "shutdown" | "reboot" | "halt" | "poweroff" => {
                let mut power_operands = Vec::new();
                let mut after_options = false;
                let mut cancel = false;
                let mut wall_only = false;
                let mut show = false;
                let mut reboot = false;
                let mut halt = false;
                for word in ctx.argv.iter().skip(1) {
                    let Some(value) = word.as_literal() else {
                        unmodeled_subcommand(builder, node);
                        return;
                    };
                    if after_options || !value.starts_with('-') || value == "-" {
                        after_options = true;
                        power_operands.push(value);
                        continue;
                    }
                    if value == "--" {
                        after_options = true;
                        continue;
                    }
                    if !valid_power_option(command, value) {
                        unmodeled_subcommand(builder, node);
                        return;
                    }
                    if value == "--help" || value == "--version" {
                        return;
                    }
                    if value == "--show" {
                        show = true;
                    } else if value == "-c" {
                        cancel = true;
                    } else if value == "-k" {
                        wall_only = true;
                    } else if value == "-r" || value == "--reboot" {
                        reboot = true;
                    } else if value == "-H" || value == "--halt" {
                        halt = true;
                    } else if !value.starts_with("--") {
                        for flag in value[1..].chars() {
                            match flag {
                                'c' => cancel = true,
                                'k' => wall_only = true,
                                'r' => reboot = true,
                                'H' => halt = true,
                                _ => {}
                            }
                        }
                    }
                }
                if show || wall_only {
                    return;
                }
                if command != "shutdown" && !power_operands.is_empty() {
                    unmodeled_subcommand(builder, node);
                    return;
                }
                if command == "shutdown" {
                    if cancel {
                        flag(&mut attributes, "cancel");
                        system_change(&mut attributes, false, true, false, false, false);
                    } else {
                        text(
                            &mut attributes,
                            "action",
                            if reboot {
                                "reboot"
                            } else if halt {
                                "halt"
                            } else {
                                "poweroff"
                            },
                        );
                        let time = power_operands.first().copied().unwrap_or("+1");
                        if !power_operands.is_empty() && !valid_shutdown_time(time) {
                            unmodeled_subcommand(builder, node);
                            return;
                        }
                        text(&mut attributes, "when", time);
                        system_change(&mut attributes, true, false, false, false, false);
                    }
                } else {
                    text(&mut attributes, "action", command);
                    system_change(&mut attributes, true, false, false, false, false);
                }
                arg_effect(builder, ctx, node, 0, POWER, host(), attributes);
            }
            "crontab" => {
                // cronie's crontab(1) takes one action: a file operand, or `-`
                // and by default stdin, replaces the crontab; -l lists, -r
                // removes and -e edits it; -T only checks a new crontab, and
                // -n/-c set and query the cluster host kept in the spool. -u
                // names whose crontab instead of the invoking user's, and -b
                // skips the backup a replacement or removal saves. getopt
                // rejects any other option, and -V prints the version, before
                // any action runs.
                let mut user = None;
                let mut backup = true;
                let mut actions = Vec::new();
                let mut operands = Vec::new();
                let mut options = true;
                let mut i = 1;
                while i < ctx.argv.len() {
                    match ctx.argv[i].as_literal() {
                        Some("--") if options => options = false,
                        Some(word) if options && word.len() > 1 && word.starts_with('-') => {
                            for (at, flag) in word.char_indices().skip(1) {
                                match flag {
                                    // Debugging builds take -x debug flags.
                                    'u' | 'x' => {
                                        let value = if word.len() > at + 1 {
                                            Some(&word[at + 1..])
                                        } else {
                                            i += 1;
                                            let Some(value) = ctx.argv.get(i) else {
                                                return;
                                            };
                                            value.as_literal()
                                        };
                                        if flag == 'u' {
                                            user = Some(value);
                                        }
                                        break;
                                    }
                                    'l' | 'r' | 'e' | 'T' | 'n' | 'c' => actions.push(flag),
                                    'b' => backup = false,
                                    'i' | 's' => {}
                                    _ => return,
                                }
                            }
                        }
                        _ => operands.push(i),
                    }
                    i += 1;
                }
                let action = match actions.as_slice() {
                    [] => None,
                    [action] => Some(*action),
                    _ => return,
                };
                let resource = ResourceExpr::Concrete {
                    identity: ResourceIdentity::ScheduledJob {
                        scheduler: "cron".into(),
                        owner: user.flatten().map(str::to_string),
                    },
                };
                // Each crontab is a file in the cron spool, named from its user
                // in a layout that differs between cron implementations. A
                // replacement, edit or removal is the scheduled-job effect on
                // the user's crontab and names no spool file; listing and the
                // cluster host have no scheduled-job operation, so they keep
                // the unresolved spool entry.
                let spool = resolve_fs_word_with_cwd(
                    &Word::new(vec![
                        WordPart::Literal("/var/spool/cron/".into()),
                        WordPart::Unknown,
                    ]),
                    None,
                );
                let (job, file_operation) = match action {
                    Some('l' | 'c') => (None, Some("filesystem.read")),
                    Some('n') => (None, Some("filesystem.write")),
                    Some('r') => (Some(SCHEDULED_JOB_DELETE), None),
                    Some('e') | None => (Some(SCHEDULED_JOB_WRITE), None),
                    _ => (None, None),
                };
                if action == Some('e') {
                    // The editor is whatever VISUAL or EDITOR names.
                    ctx.nest_exec(
                        builder,
                        &[Word::new(vec![WordPart::Unknown])],
                        ctx.cwd,
                        None,
                        &[node],
                    );
                }
                if let Some(job) = job {
                    arg_effect(builder, ctx, node, 0, job, resource, attributes);
                }
                if let Some(operation) = file_operation {
                    arg_effect(builder, ctx, node, 0, operation, spool, Attrs::new());
                }
                if backup && matches!(action, None | Some('r' | 'e')) {
                    // Replacing, editing or removing first saves the current
                    // crontab under $XDG_CACHE_HOME, else $HOME/.cache.
                    let mut cache = ResourceExpr::Join {
                        parts: vec![
                            ctx.environment_value("HOME")
                                .unwrap_or(ResourceExpr::Environment {
                                    name: "HOME".into(),
                                }),
                            ResourceExpr::Literal {
                                value: "/.cache".into(),
                            },
                        ],
                    };
                    cache = match ctx.environment_value("XDG_CACHE_HOME") {
                        Some(ResourceExpr::Literal { value }) => {
                            ctx.resolve_fs_word(&Word::literal(value))
                        }
                        Some(value) => value,
                        None if !ctx.tracks_host_context_environment()
                            && !ctx.nest.environment_is_closed()
                            && !ctx
                                .nest
                                .current_environment_unsets()
                                .contains("XDG_CACHE_HOME") =>
                        {
                            ResourceExpr::Union {
                                alternatives: vec![
                                    ResourceExpr::Environment {
                                        name: "XDG_CACHE_HOME".into(),
                                    },
                                    cache,
                                ],
                            }
                        }
                        None => cache,
                    };
                    let mut name = Word::literal("crontab/crontab.bak");
                    if let Some(user) = user {
                        // The name carries -u's user only when it is not the
                        // invoking user.
                        let named = match user {
                            Some(user) => Word::literal(format!("crontab/crontab.{user}.bak")),
                            None => Word::new(vec![
                                WordPart::Literal("crontab/crontab.".into()),
                                WordPart::Unknown,
                                WordPart::Literal(".bak".into()),
                            ]),
                        };
                        name = Word::new(vec![WordPart::Union(vec![name, named])]);
                    }
                    arg_effect(
                        builder,
                        ctx,
                        node,
                        0,
                        "filesystem.write",
                        resolve_fs_word_with_cwd(&name, Some(cache)),
                        Attrs::new(),
                    );
                }
                if action.is_some_and(|action| action != 'T') {
                    return;
                }
                // A replacement or -T check reads the new crontab from the
                // operand, or from stdin when there is none or it is `-`.
                let file = operands.first().copied();
                let stdin = file.is_none_or(|i| ctx.argv[i].as_literal() == Some("-"));
                if action.is_none() && stdin {
                    code_execution(
                        effinterp_proto::RequestAssurance::Conservative,
                        builder,
                        ctx,
                        node,
                        None,
                        "stdin",
                        Attrs::new(),
                    );
                    let mut provenance = vec![node];
                    provenance.extend(
                        ctx.stdin
                            .into_iter()
                            .flat_map(|stdin| stdin.provenance.iter().copied()),
                    );
                    if let Some(source) = ctx.stdin_literal() {
                        let (commands, complete) = crontab_commands(source);
                        for (command, environment) in commands {
                            let environment = environment
                                .into_iter()
                                .map(|(name, value)| (name, Some(ResourceExpr::Literal { value })))
                                .collect::<BTreeMap<_, _>>();
                            let environment_nodes = environment
                                .keys()
                                .cloned()
                                .map(|name| (name, node))
                                .collect();
                            ctx.nest.nest(
                                builder,
                                Transition::file(Subject::Shell {
                                    source: command,
                                    cwd: ctx.cwd.map(str::to_string),
                                    context: Default::default(),
                                })
                                .source_cwd(ctx.runtime_cwd)
                                .runtime_cwd(ctx.runtime_cwd)
                                .cwd(builder.current_execution_cwd(), ctx.cwd_node)
                                .environment(
                                    environment,
                                    environment_nodes,
                                    Default::default(),
                                ),
                                &provenance,
                                ctx.depth,
                            );
                        }
                        if !complete {
                            opaque_source_with_provenance(
                                builder,
                                &provenance,
                                &["environment", "filesystem", "network", "process", "system"],
                                "one or more literal crontab lines are outside the modeled grammar",
                            );
                        }
                    } else {
                        opaque_source_with_provenance(
                            builder,
                            &provenance,
                            &["environment", "filesystem", "network", "process", "system"],
                            if ctx.stdin.is_some() {
                                "crontab source is not statically recoverable"
                            } else {
                                "crontab reads scheduled shell source from stdin"
                            },
                        );
                    }
                }
                if let Some(i) = file.filter(|_| !stdin) {
                    operand_effect(
                        builder,
                        ctx,
                        node,
                        i as u32,
                        &ctx.argv[i],
                        "filesystem.read",
                        Attrs::new(),
                    );
                }
            }
            "at" | "atrm" => {
                if command == "at" && (has("-l") || has("-c")) {
                    return;
                }
                let removes_job = command == "atrm" || has("-r") || has("-d");
                let resource = ResourceExpr::Concrete {
                    identity: ResourceIdentity::ScheduledJob {
                        scheduler: "at".into(),
                        owner: None,
                    },
                };
                arg_effect(
                    builder,
                    ctx,
                    node,
                    0,
                    if removes_job {
                        SCHEDULED_JOB_DELETE
                    } else {
                        SCHEDULED_JOB_WRITE
                    },
                    resource,
                    attributes,
                );
                if !removes_job {
                    let file = ctx
                        .argv
                        .iter()
                        .position(|word| word.as_literal() == Some("-f"))
                        .and_then(|index| ctx.argv.get(index + 1).map(|word| (index + 1, word)));
                    if let Some((index, script)) = file {
                        code_execution(
                            effinterp_proto::RequestAssurance::Conservative,
                            builder,
                            ctx,
                            node,
                            Some(index as u32),
                            "file",
                            Attrs::new(),
                        );
                        super::sourceexec::nest(builder, ctx, node, index, script, |source| {
                            Subject::Shell {
                                source,
                                cwd: ctx.cwd.map(str::to_string),
                                context: Default::default(),
                            }
                        });
                        return;
                    }
                    code_execution(
                        effinterp_proto::RequestAssurance::Conservative,
                        builder,
                        ctx,
                        node,
                        None,
                        "stdin",
                        Attrs::new(),
                    );
                    if let Some(source) = ctx.stdin_literal() {
                        let mut provenance = vec![node];
                        provenance.extend(ctx.stdin.unwrap().provenance.iter().copied());
                        ctx.nest_subject(
                            builder,
                            Subject::Shell {
                                source: source.to_string(),
                                cwd: ctx.cwd.map(str::to_string),
                                context: Default::default(),
                            },
                            &provenance,
                        );
                    } else {
                        let mut provenance = vec![node];
                        provenance.extend(
                            ctx.stdin
                                .into_iter()
                                .flat_map(|stdin| stdin.provenance.iter().copied()),
                        );
                        opaque_source_with_provenance(
                            builder,
                            &provenance,
                            &["environment", "filesystem", "network", "process", "system"],
                            if ctx.stdin.is_some() {
                                "scheduled shell source is not statically recoverable"
                            } else {
                                "at reads scheduled shell source from stdin"
                            },
                        );
                    }
                }
            }
            "date" => {
                let mut set = false;
                let mut bad = false;
                let mut terminal = false;
                let mut has_date = false;
                let mut has_file = false;
                let mut option_format = false;
                let mut positional_format_count = 0;
                let mut i = 1;
                while i < ctx.argv.len() {
                    match ctx.argv[i].as_literal() {
                        Some("-s" | "--set") => {
                            set = true;
                            if i + 1 < ctx.argv.len() {
                                i += 1;
                            } else {
                                bad = true;
                            }
                        }
                        Some(s) if s.starts_with("--set=") => set = true,
                        Some("-d" | "--date") => {
                            has_date = true;
                            if i + 1 < ctx.argv.len() {
                                i += 1;
                            } else {
                                bad = true;
                            }
                        }
                        Some("-f" | "--file") => {
                            has_file = true;
                            if i + 1 < ctx.argv.len() {
                                i += 1;
                            } else {
                                bad = true;
                            }
                        }
                        Some("--rfc-3339") => {
                            option_format = true;
                            if i + 1 < ctx.argv.len() {
                                if !matches!(
                                    ctx.argv[i + 1].as_literal(),
                                    Some("date" | "seconds" | "ns")
                                ) {
                                    bad = true;
                                }
                                i += 1;
                            } else {
                                bad = true;
                            }
                        }
                        Some("-R" | "--rfc-email") => option_format = true,
                        Some("-u" | "--utc" | "--universal") => {}
                        Some(s) if s.starts_with("--file=") => {
                            has_file = true;
                            if s == "--file=" {
                                bad = true;
                            }
                        }
                        Some(s) if s.starts_with("--date=") => {
                            has_date = true;
                        }
                        Some(s) if s.starts_with('+') => {
                            positional_format_count += 1;
                            if positional_format_count > 1 {
                                bad = true;
                            }
                        }
                        Some(s) if s.starts_with("-I") => {
                            option_format = true;
                            let precision = &s[2..];
                            if !precision.is_empty()
                                && !matches!(
                                    precision,
                                    "date" | "hours" | "minutes" | "seconds" | "ns"
                                )
                            {
                                bad = true;
                            }
                        }
                        Some(s) if s.starts_with("--rfc-3339=") => {
                            option_format = true;
                            if !matches!(&s["--rfc-3339=".len()..], "date" | "seconds" | "ns") {
                                bad = true;
                            }
                        }
                        Some("--help" | "--version") => terminal = true,
                        Some("--debug") => {}
                        _ => bad = true,
                    }
                    i += 1;
                }
                // --help and --version print their text and exit before date
                // interprets an operand or touches the clock.
                if terminal {
                    return;
                }
                if has_date && has_file || set && (has_date || has_file) {
                    bad = true;
                }
                if option_format && positional_format_count != 0 {
                    bad = true;
                }

                const SPEC: FlagSpec<'static> = FlagSpec {
                    allow_abbreviation: false,
                    value_flags: &["-s", "--set", "-d", "--date", "-f", "--file", "--rfc-3339"],
                    known_flags: &[],
                };
                let scanned =
                    scan_with_value_indices(ctx.argv, &SPEC, ctx.tracks_host_context_environment());
                if !bad
                    && let Some((index, file)) =
                        scanned.values_of(&["-f", "--file"]).into_iter().last()
                    && file.as_literal() != Some("-")
                {
                    operand_effect(
                        builder,
                        ctx,
                        node,
                        index,
                        file,
                        "filesystem.read",
                        program_input_attrs(),
                    );
                }
                if set && !bad {
                    arg_effect(builder, ctx, node, 0, CLOCK_SET, host(), attributes);
                }
                if bad {
                    builder.boundary(Boundary {
                        reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        class: BoundaryClass::Unsupported,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: vec![
                            Domain::new("filesystem"),
                            Domain::new("process"),
                            Domain::new("system"),
                        ],
                        provenance: vec![node],
                        limit: None,
                        detail: None,
                    });
                    for domain in ["filesystem", "process", "system"] {
                        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
                    }
                }
            }
            "timedatectl" => {
                if matches!(
                    ctx.argv.get(1).and_then(Word::as_literal),
                    Some("set-time" | "set-timezone" | "set-ntp")
                ) {
                    arg_effect(builder, ctx, node, 1, CLOCK_SET, host(), attributes);
                }
            }
            "hwclock" => {
                if ["--systohc", "-w", "--hctosys", "-s", "--set"]
                    .iter()
                    .any(|f| has(f))
                {
                    arg_effect(builder, ctx, node, 0, CLOCK_SET, host(), attributes);
                }
            }
            _ => unreachable!(),
        }
    }
}
