//! PHP Composer PSR-4 autoload roots and the candidate files a class name maps to.

use std::path::Path;

pub(super) fn collect_php_psr4(
    root: &Path,
    admit: &mut dyn FnMut(&Path) -> bool,
) -> Vec<(String, String)> {
    if !admit(&root.join("composer.json")) {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(root.join("composer.json")) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let Some(map) = json
        .get("autoload")
        .and_then(|autoload| autoload.get("psr-4"))
        .and_then(serde_json::Value::as_object)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (prefix, value) in map {
        let roots: Vec<&str> = match value {
            serde_json::Value::String(root) => vec![root],
            serde_json::Value::Array(roots) => {
                roots.iter().filter_map(serde_json::Value::as_str).collect()
            }
            _ => Vec::new(),
        };
        for root in roots {
            out.push((
                prefix.trim_start_matches('\\').to_string(),
                root.trim_start_matches("./").trim_matches('/').to_string(),
            ));
        }
    }
    out.sort();
    out
}

pub(super) fn php_class_paths(class: &str, psr4: &[(String, String)]) -> Vec<String> {
    let class = class.trim_start_matches('\\');
    let mut out = vec![
        format!("{}.php", class.replace('\\', "/")),
        format!("src/{}.php", class.replace('\\', "/")),
        format!("lib/{}.php", class.replace('\\', "/")),
    ];
    for (prefix, root) in psr4 {
        let Some(relative) = class.strip_prefix(prefix) else {
            continue;
        };
        let relative = relative.trim_start_matches('\\').replace('\\', "/");
        out.push(if root.is_empty() {
            format!("{relative}.php")
        } else {
            format!("{root}/{relative}.php")
        });
    }
    out.sort();
    out.dedup();
    out
}
