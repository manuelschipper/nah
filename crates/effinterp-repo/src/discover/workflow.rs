use super::*;

pub(super) fn github_workflow_steps(ctx: &mut Ctx, relpath: &str, content: &str) {
    let lines: Vec<&str> = content.lines().collect();
    let mut index = 0;
    let mut step = 0;
    let mut jobs_indent = None;
    let mut steps_indent = None;
    let mut step_indent = None;
    while index < lines.len() {
        let line = lines[index];
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            index += 1;
            continue;
        }
        if jobs_indent.is_none() {
            if trimmed == "jobs:" {
                jobs_indent = Some(indent);
            }
            index += 1;
            continue;
        }
        if indent <= jobs_indent.unwrap() {
            break;
        }
        if let Some(current_steps) = steps_indent
            && (indent < current_steps || (indent == current_steps && !trimmed.starts_with("- ")))
        {
            steps_indent = None;
            step_indent = None;
            continue;
        }
        if steps_indent.is_none() {
            if trimmed == "steps:" {
                steps_indent = Some(indent);
            }
            index += 1;
            continue;
        }

        let (value, key_indent) = if let Some(item) = trimmed.strip_prefix("- ") {
            if step_indent.is_some_and(|step_indent| step_indent != indent) {
                index += 1;
                continue;
            }
            step_indent = Some(indent);
            (item.strip_prefix("run:"), indent + 2)
        } else {
            (
                (step_indent.is_some_and(|step_indent| indent == step_indent + 2))
                    .then(|| trimmed.strip_prefix("run:"))
                    .flatten(),
                indent,
            )
        };
        let Some(value) = value else {
            index += 1;
            continue;
        };
        let run_index = index;
        let line_number = (run_index + 1) as u32;
        let (source, next) = github_run_source(&lines, run_index, key_indent, value.trim());
        index = next;
        step += 1;
        let mut argv = vec![
            GITHUB_ACTIONS_DRIVER.to_string(),
            "run".to_string(),
            relpath.to_string(),
        ];
        if let Some(source) = source {
            argv.push(source);
            if let Some((shell, working_directory, container, environment)) = github_step_context(
                &lines,
                run_index,
                jobs_indent.unwrap(),
                steps_indent.unwrap(),
                step_indent.unwrap(),
            ) {
                argv.push(shell);
                argv.push(working_directory);
                argv.push(container);
                argv.extend(environment);
            }
        }
        ctx.entrypoints.push(Entrypoint {
            id: format!("{relpath}:run.{step}"),
            subject: Subject::Exec {
                argv,
                cwd: Some(String::new()),
                context: Default::default(),
            },
            source_file: relpath.to_string(),
            source_cwd: Some(String::new()),
            evidence: EntrypointEvidence {
                kind: EntrypointKind::CiStep,
                file: relpath.to_string(),
                line: Some(line_number),
            },
            entry_function: None,
            registration: None,
            package_inits: Vec::new(),
            span_map: None,
        });
    }
}

fn github_step_context(
    lines: &[&str],
    run_index: usize,
    jobs_indent: usize,
    steps_indent: usize,
    step_indent: usize,
) -> Option<(String, String, String, Vec<String>)> {
    let start = (0..=run_index)
        .rev()
        .find(|index| {
            github_indent(lines[*index]) == step_indent && lines[*index].trim().starts_with("- ")
        })
        .unwrap_or(run_index);
    let end = (start + 1..lines.len())
        .find(|index| {
            !lines[*index].trim().is_empty() && github_indent(lines[*index]) <= step_indent
        })
        .unwrap_or(lines.len());
    let key_indent = step_indent + 2;
    let mut shell = None;
    let mut working_directory = None;
    let mut environment = Vec::new();
    let mut index = start;
    while index < end {
        let field = if index == start {
            lines[index].trim().strip_prefix("- ")
        } else if github_indent(lines[index]) == key_indent {
            Some(lines[index].trim())
        } else {
            None
        };
        if let Some(value) = field.and_then(|field| field.strip_prefix("shell:")) {
            shell = Some(github_yaml_scalar(value.trim())?);
        } else if let Some(value) = field.and_then(|field| field.strip_prefix("working-directory:"))
        {
            working_directory = Some(github_yaml_scalar(value.trim())?);
        } else if field.is_some_and(|field| field == "env:") {
            index += 1;
            while index < end && github_indent(lines[index]) > key_indent {
                let value = lines[index].trim();
                if let Some((name, value)) = value.split_once(':')
                    && !name.is_empty()
                    && name
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                {
                    environment.push(format!("{name}={}", github_yaml_scalar(value.trim())?));
                }
                index += 1;
            }
            continue;
        }
        index += 1;
    }
    let mut defaults = github_workflow_defaults(lines, jobs_indent);
    let job_defaults = github_job_defaults(lines, start, jobs_indent, steps_indent);
    if job_defaults.0.is_some() {
        defaults.0 = job_defaults.0;
    }
    if job_defaults.1.is_some() {
        defaults.1 = job_defaults.1;
    }
    let shell = shell.map(Ok).or(defaults.0).transpose().ok()?;
    let shell = match shell {
        Some(shell) => shell,
        None if github_job_uses_posix_default_shell(lines, start, jobs_indent, steps_indent) => {
            "bash".to_string()
        }
        None => return None,
    };
    let container = github_job_container(lines, start, jobs_indent, steps_indent).ok()?;
    Some((
        shell,
        working_directory
            .map(Ok)
            .or(defaults.1)
            .transpose()
            .ok()?
            .unwrap_or_default(),
        container.unwrap_or_default(),
        environment,
    ))
}

type GithubDefaults = (Option<Result<String, ()>>, Option<Result<String, ()>>);

fn github_workflow_defaults(lines: &[&str], jobs_indent: usize) -> GithubDefaults {
    let Some(defaults) = lines
        .iter()
        .position(|line| github_indent(line) == jobs_indent && line.trim() == "defaults:")
    else {
        return (None, None);
    };
    github_defaults(lines, defaults, lines.len())
}

fn github_job_defaults(
    lines: &[&str],
    step_index: usize,
    jobs_indent: usize,
    steps_indent: usize,
) -> GithubDefaults {
    let Some((job_start, job_end)) = github_job_range(lines, step_index, jobs_indent, steps_indent)
    else {
        return (None, None);
    };
    let Some(defaults) = (job_start + 1..job_end).find(|index| {
        github_indent(lines[*index]) == steps_indent && lines[*index].trim() == "defaults:"
    }) else {
        return (None, None);
    };
    github_defaults(lines, defaults, job_end)
}

fn github_job_uses_posix_default_shell(
    lines: &[&str],
    step_index: usize,
    jobs_indent: usize,
    steps_indent: usize,
) -> bool {
    let Some((job_start, job_end)) = github_job_range(lines, step_index, jobs_indent, steps_indent)
    else {
        return false;
    };
    let Some(runner) = (job_start + 1..job_end).find_map(|index| {
        (github_indent(lines[index]) == steps_indent)
            .then(|| lines[index].trim().strip_prefix("runs-on:"))
            .flatten()
    }) else {
        return false;
    };
    let Some(runner) = github_yaml_scalar(runner.trim()) else {
        return false;
    };
    !runner.contains("${{") && (runner.starts_with("ubuntu-") || runner.starts_with("macos-"))
}

fn github_job_container(
    lines: &[&str],
    step_index: usize,
    jobs_indent: usize,
    steps_indent: usize,
) -> Result<Option<String>, ()> {
    let Some((job_start, job_end)) = github_job_range(lines, step_index, jobs_indent, steps_indent)
    else {
        return Ok(None);
    };
    let Some(container) = (job_start + 1..job_end).find(|index| {
        github_indent(lines[*index]) == steps_indent
            && lines[*index].trim().starts_with("container:")
    }) else {
        return Ok(None);
    };
    let value = lines[container]
        .trim()
        .strip_prefix("container:")
        .unwrap()
        .trim();
    if !value.is_empty() {
        let image = github_yaml_scalar(value).ok_or(())?;
        return (!image.contains("${{")).then_some(Some(image)).ok_or(());
    }

    let mut image = None;
    for line in &lines[container + 1..job_end] {
        let indent = github_indent(line);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if indent <= steps_indent {
            break;
        }
        let value = trimmed.strip_prefix("image:").ok_or(())?;
        if image.is_some() {
            return Err(());
        }
        let value = github_yaml_scalar(value.trim()).ok_or(())?;
        if value.contains("${{") {
            return Err(());
        }
        image = Some(value);
    }
    image.map(Some).ok_or(())
}

fn github_job_range(
    lines: &[&str],
    step_index: usize,
    jobs_indent: usize,
    steps_indent: usize,
) -> Option<(usize, usize)> {
    let job_start = (0..step_index).rev().find(|index| {
        let line = lines[*index];
        let line_indent = github_indent(line);
        !line.trim().is_empty()
            && line_indent > jobs_indent
            && line_indent < steps_indent
            && line.trim_end().ends_with(':')
    })?;
    let job_indent = github_indent(lines[job_start]);
    let job_end = (job_start + 1..lines.len())
        .find(|index| {
            !lines[*index].trim().is_empty() && github_indent(lines[*index]) <= job_indent
        })
        .unwrap_or(lines.len());
    Some((job_start, job_end))
}

fn github_defaults(lines: &[&str], defaults: usize, end: usize) -> GithubDefaults {
    let defaults_indent = github_indent(lines[defaults]);
    let mut run_indent = None;
    let mut shell = None;
    let mut working_directory = None;
    for line in &lines[defaults + 1..end] {
        let line_indent = github_indent(line);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if line_indent <= defaults_indent {
            break;
        }
        if trimmed == "run:" && run_indent.is_none() {
            run_indent = Some(line_indent);
        } else if run_indent.is_some_and(|run| line_indent <= run) {
            break;
        } else if run_indent.is_some_and(|run| line_indent > run) {
            if let Some(value) = trimmed.strip_prefix("shell:") {
                shell = Some(github_yaml_scalar(value.trim()).ok_or(()));
            } else if let Some(value) = trimmed.strip_prefix("working-directory:") {
                working_directory = Some(github_yaml_scalar(value.trim()).ok_or(()));
            }
        }
    }
    (shell, working_directory)
}

fn github_yaml_scalar(value: &str) -> Option<String> {
    if let Some(value) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        return (!value.contains('\\')).then(|| value.to_string());
    }
    if let Some(value) = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    {
        return (!value.contains('\'')).then(|| value.to_string());
    }
    if value.starts_with(['"', '\'', '|', '>', '&', '*', '!', '[', '{']) {
        return None;
    }
    let value = value
        .char_indices()
        .find(|(index, ch)| {
            *ch == '#'
                && value[..*index]
                    .chars()
                    .next_back()
                    .is_none_or(char::is_whitespace)
        })
        .map_or(value, |(index, _)| &value[..index])
        .trim_end();
    (!value.is_empty() && !value.contains(": ")).then(|| value.to_string())
}

fn github_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn github_run_source(
    lines: &[&str],
    index: usize,
    key_indent: usize,
    value: &str,
) -> (Option<String>, usize) {
    let mut nested_end = index + 1;
    while nested_end < lines.len() {
        let nested = lines[nested_end];
        let nested_indent = nested.len() - nested.trim_start().len();
        if !nested.trim().is_empty() && nested_indent <= key_indent {
            break;
        }
        nested_end += 1;
    }
    if matches!(value, "|" | "|-" | "|+") {
        let mut source = Vec::new();
        for nested in &lines[index + 1..nested_end] {
            source.push(nested.trim_start());
        }
        let source = source.join("\n");
        return ((!source.is_empty()).then_some(source), nested_end);
    }
    if value.starts_with(['|', '>'])
        || lines[index + 1..nested_end]
            .iter()
            .any(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
    {
        return (None, nested_end);
    }
    (github_yaml_scalar(value), index + 1)
}
