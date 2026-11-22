use effinterp_proto::ProvenanceRef;

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::nest::SourceResolution;
use crate::word::Word;

/// How an AWS invocation's options shape its request, wherever they appear.
pub(super) fn aws_request_shape(argv: &[Word]) -> Option<&'static str> {
    argv.iter()
        .skip(1)
        .filter_map(Word::as_literal)
        .find_map(
            |word| match word.split_once('=').map_or(word, |(flag, _)| flag) {
                "--generate-cli-skeleton" => Some("skeleton"),
                "--cli-input-json" | "--cli-input-yaml" => Some("input"),
                _ => None,
            },
        )
}

/// What an AWS invocation's `--cli-input-json` or `--cli-input-yaml` makes of
/// its request.
pub(super) enum AwsRequestInput {
    /// No request input, or skeleton generation, which sends no request.
    Absent,
    /// argv with the input option replaced by the options its keys stand for.
    Read {
        argv: Vec<Word>,
        provenance: Vec<Vec<ProvenanceRef>>,
    },
    /// Input Nah cannot read, or that the CLI rejects.
    Unreadable,
}

/// Reads an AWS invocation's request input and spells it as options. The CLI
/// adds each top-level key, an API parameter name, to the request unless the
/// command line already set that parameter
/// (`awscli/customizations/cliinput.py`), so each key becomes the option the
/// CLI derives from its name, spelled as the command line usually spells it,
/// and the operation models read it as they read any other option.
/// The CLI reads the input inline or from a `file://`/`fileb://` path; Nah
/// reads such a path when source observation serves it, or when it is
/// `/dev/stdin` and stdin is literal text. A bare `-` is not a path to the
/// CLI, and it rejects both options together.
pub(super) fn aws_request_input(builder: &mut PlanBuilder, ctx: &InvocationCtx) -> AwsRequestInput {
    use serde_json::Value;
    let mut options = Vec::new();
    for (index, word) in ctx.argv.iter().enumerate().skip(1) {
        let Some(text) = word.as_literal() else {
            continue;
        };
        match text
            .split_once('=')
            .map_or((text, None), |(flag, value)| (flag, Some(value)))
        {
            ("--generate-cli-skeleton", _) => return AwsRequestInput::Absent,
            ("--cli-input-json" | "--cli-input-yaml", attached) => {
                options.push((index, attached, text.starts_with("--cli-input-yaml")));
            }
            _ => {}
        }
    }
    let (option, attached, yaml) = match options[..] {
        [] => return AwsRequestInput::Absent,
        [option] => option,
        _ => return AwsRequestInput::Unreadable,
    };
    let value_index = if attached.is_some() {
        option
    } else {
        option + 1
    };
    let Some(value) = attached.or_else(|| ctx.argv.get(value_index).and_then(Word::as_literal))
    else {
        return AwsRequestInput::Unreadable;
    };
    let mut from_stdin = false;
    let text = match value
        .strip_prefix("file://")
        .or_else(|| value.strip_prefix("fileb://"))
    {
        None => value.to_string(),
        Some("/dev/stdin") => {
            from_stdin = true;
            match ctx.stdin_literal() {
                Some(text) => text.to_string(),
                None => return AwsRequestInput::Unreadable,
            }
        }
        // The CLI expands `~` and environment variables in the path.
        Some(path) if path.is_empty() || path.contains(['~', '$']) => {
            return AwsRequestInput::Unreadable;
        }
        Some(path) => {
            match ctx.resolve_source_operand(builder, path, SourcePurpose::InvocationInput) {
                SourceResolution::Source { source, .. } => source,
                _ => return AwsRequestInput::Unreadable,
            }
        }
    };
    let parsed = if yaml {
        match crate::models::infrastructure::parse_data(builder, &text) {
            Ok(mut documents) if documents.len() == 1 => documents.pop(),
            _ => None,
        }
    } else {
        serde_json::from_str::<Value>(&text).ok()
    };
    let Some(Value::Object(input)) = parsed else {
        return AwsRequestInput::Unreadable;
    };
    let explicit = |name: &str| {
        ctx.argv.iter().filter_map(Word::as_literal).any(|word| {
            word.split_once('=')
                .map_or(word, |(flag, _)| flag)
                .strip_prefix("--")
                .is_some_and(|flag| flag == name || flag.strip_prefix("no-") == Some(name))
        })
    };
    let mut argv = Vec::new();
    let mut provenance = Vec::new();
    for index in (0..ctx.argv.len()).filter(|index| *index != option && *index != value_index) {
        argv.push(ctx.argv[index].clone());
        provenance.push(ctx.argv_provenance_at(builder, index));
    }
    let mut source = ctx.argv_provenance_at(builder, value_index);
    if value_index != option {
        source.extend(ctx.argv_provenance_at(builder, option));
    }
    if from_stdin && let Some(stdin) = ctx.stdin {
        source.extend(stdin.provenance.iter().copied());
    }
    for (key, value) in &input {
        let name = aws_option_name(key);
        if explicit(&name) {
            continue;
        }
        // A list of plain values is spelled as the words after its option;
        // anything else as the JSON the CLI also accepts for a parameter.
        let list = match value {
            Value::Array(items) if !items.is_empty() => items
                .iter()
                .map(|item| match item {
                    Value::String(text) => Some(text.clone()),
                    Value::Number(number) => Some(number.to_string()),
                    _ => None,
                })
                .map(|item| item.filter(|item| !item.is_empty() && !item.starts_with('-')))
                .collect::<Option<Vec<_>>>(),
            _ => None,
        };
        let words = match (value, list) {
            (_, Some(items)) => std::iter::once(format!("--{name}")).chain(items).collect(),
            (Value::Bool(true), _) => vec![format!("--{name}")],
            (Value::Bool(false), _) => vec![format!("--no-{name}")],
            (Value::Null, _) => return AwsRequestInput::Unreadable,
            // The option and its value are two words, as usually written;
            // the CLI needs `=` for a value that starts with `-`.
            (value, _) => {
                let text = match value {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                };
                if text.is_empty() || text.starts_with('-') {
                    vec![format!("--{name}={text}")]
                } else {
                    vec![format!("--{name}"), text]
                }
            }
        };
        for word in words {
            argv.push(Word::literal(word));
            provenance.push(source.clone());
        }
    }
    AwsRequestInput::Read { argv, provenance }
}

/// The option the AWS CLI derives from an API parameter name, as botocore's
/// `xform_name(name, "-")`: `SecretId` is `secret-id`,
/// `DBInstanceIdentifier` is `db-instance-identifier` and `TargetARNs` is
/// `target-arns`.
fn aws_option_name(name: &str) -> String {
    if name.contains('-') {
        return name.to_string();
    }
    let mut chars = name.chars().collect::<Vec<_>>();
    // A trailing plural acronym is split off whole.
    if chars.last() == Some(&'s') {
        let start = chars[..chars.len() - 1]
            .iter()
            .rposition(|c| !c.is_ascii_uppercase())
            .map_or(0, |index| index + 1);
        if chars.len() - 1 - start >= 2 {
            let tail = chars.split_off(start);
            chars.push('-');
            chars.extend(tail.iter().map(char::to_ascii_lowercase));
        }
    }
    // `(.)([A-Z][a-z]+)`, then `([a-z0-9])([A-Z])`, each replaced left to
    // right with a `-` between the groups.
    let mut first = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        first.push(chars[index]);
        if chars.get(index + 1).is_some_and(char::is_ascii_uppercase)
            && chars.get(index + 2).is_some_and(char::is_ascii_lowercase)
        {
            first.push('-');
            first.push(chars[index + 1]);
            index += 2;
            while chars.get(index).is_some_and(char::is_ascii_lowercase) {
                first.push(chars[index]);
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    let mut name = String::new();
    let mut index = 0;
    while index < first.len() {
        name.push(first[index]);
        if (first[index].is_ascii_lowercase() || first[index].is_ascii_digit())
            && first.get(index + 1).is_some_and(char::is_ascii_uppercase)
        {
            name.push('-');
            name.push(first[index + 1]);
            index += 2;
        } else {
            index += 1;
        }
    }
    name.to_ascii_lowercase()
}
