#![allow(clippy::disallowed_macros, clippy::disallowed_methods)]

use effinterp_proto::{BoundaryReason, Modality};
use effinterp_repo::{
    IndexLimits, RepoChange, ResourceSelector, apply_changes, build_index, normalize_surface,
    reach, save_index,
};

use crate::support::temp_repo;

#[test]
fn self_recursion_converges_and_preserves_recursive_occurrences() {
    let root = temp_repo(
        "recursion-self",
        &[
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom purge import purge\npurge('/cache')\n",
            ),
            (
                "purge.py",
                "import os\ndef purge(path):\n    os.remove(path)\n    purge(child)\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("app.py").unwrap();
    let occurrences = composition
        .occurrence_effects
        .iter()
        .map(|occurrence| (occurrence.effect, &occurrence.path))
        .collect::<std::collections::HashSet<_>>();
    eprintln!("evidence: {:#?}", composition.occurrence_effects);
    assert_eq!(composition.occurrence_effects.len(), occurrences.len());
    let effects = composition
        .effects
        .iter()
        .map(|effect| {
            let mut effect = effect.effect.clone();
            effect.condition = None;
            effinterp_proto::canonical_json(&effect)
        })
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(composition.effects.len(), effects.len());
    let mut limits = IndexLimits::default();
    limits.repository.max_recursion_rounds = 8;
    limits.repository.max_composed_effects = composition.effects.len();
    let bounded = build_index(&root, limits);
    let bounded = bounded.composition("app.py").unwrap();
    assert!(
        bounded.budget.saturated.is_none(),
        "{:?}",
        bounded.boundaries
    );
    assert_eq!(
        bounded.occurrence_effects.len(),
        composition.occurrence_effects.len()
    );
    assert!(
        !composition
            .boundaries
            .iter()
            .any(|b| b.reason == BoundaryReason::RECURSIVE_CALL),
        "{:?}",
        composition.boundaries
    );
    assert!(
        composition
            .effects
            .iter()
            .any(|e| e.effect.operation.0 == "filesystem.delete")
    );
    assert!(composition.occurrence_effects.iter().any(|o| {
        let effect = &composition.effects[o.effect].effect;
        effect.operation.0 == "filesystem.delete"
            && effect.modality == Modality::May
            && effect.condition.as_ref().is_some_and(|c| c.is_widened())
            && o.path
                .iter()
                .filter(|step| step.as_str() == "purge.py:purge")
                .count()
                >= 2
    }));
    assert!(composition.effects.iter().any(|effect| matches!(
        effect.effect.resource,
        effinterp_proto::ResourceExpr::Union { .. }
    )));
    let report = reach(&index, &ResourceSelector::parse("fs:/cache").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| hit.fact.entrypoint == "app.py")
    );
    assert!(
        !report
            .payload
            .as_reach()
            .unwrap()
            .indeterminate
            .iter()
            .filter_map(|row| match row {
                effinterp_proto::Indeterminate::Boundary { evidence } => Some(evidence),
                _ => None,
            })
            .any(|hit| hit.entrypoint == "app.py"
                && hit.boundary_reason == BoundaryReason::RECURSIVE_CALL),
        "{:?}",
        report.payload.as_reach().unwrap().indeterminate
    );
    std::fs::write(
        root.join("app.py"),
        "#!/usr/bin/env python3\nfrom purge import purge\npurge('/cache')\npurge('/cache')\n",
    )
    .unwrap();
    let replayed = build_index(&root, IndexLimits::default());
    let replayed = replayed.composition("app.py").unwrap();
    assert_eq!(replayed.effects.len(), composition.effects.len());
    assert_eq!(
        replayed.occurrence_effects.len(),
        2 * composition.occurrence_effects.len()
    );
    assert!(replayed.budget.steps < 2 * composition.budget.steps);
}

#[test]
fn mutual_recursion_joins_arguments_and_matches_incremental_rebuild() {
    let root = temp_repo(
        "recursion-mutual",
        &[
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom first import purge\npurge('/cache')\n",
            ),
            (
                "first.py",
                "import os\nfrom second import again\ndef purge(path):\n    os.remove(path)\n    again('/child')\n",
            ),
            (
                "second.py",
                "from first import purge\ndef again(path):\n    purge(path)\n",
            ),
        ],
    );
    let limits = IndexLimits::default();
    let mut index = build_index(&root, limits.clone());
    let composition = index.composition("app.py").unwrap();
    assert!(
        !composition
            .boundaries
            .iter()
            .any(|b| b.reason == BoundaryReason::RECURSIVE_CALL),
        "{:?}",
        composition.boundaries
    );
    let resources = composition
        .effects
        .iter()
        .map(|effect| effinterp_proto::canonical_json(&effect.effect.resource))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        resources.contains("/cache") && resources.contains("/child"),
        "{resources}"
    );
    assert!(
        composition.effects.iter().any(|effect| matches!(
            effect.effect.resource,
            effinterp_proto::ResourceExpr::Union { .. }
        )),
        "{resources}"
    );
    std::fs::write(
        root.join("second.py"),
        "from first import purge\ndef again(path):\n    purge('/changed')\n",
    )
    .unwrap();
    apply_changes(
        &mut index,
        &root,
        &limits,
        &[RepoChange::Modified("second.py".into())],
    );
    let clean = build_index(&root, limits);
    assert_eq!(normalize_surface(&index), normalize_surface(&clean));
    assert_eq!(save_index(&index), save_index(&clean));
}

#[test]
fn growing_recursion_is_bounded_and_only_marks_the_growing_domain() {
    let root = temp_repo(
        "recursion-growing",
        &[
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom first import purge\npurge('/cache')\n",
            ),
            (
                "first.py",
                "import os\nfrom second import again\ndef purge(path):\n    os.remove(path)\n    again(path + '/child')\n",
            ),
            (
                "second.py",
                "from first import purge\ndef again(path):\n    purge(path)\n",
            ),
        ],
    );
    for rounds in [0, 1, 2, 3] {
        let mut limits = IndexLimits::default();
        limits.repository.max_recursion_rounds = rounds;
        let index = build_index(&root, limits);
        let composition = index.composition("app.py").unwrap();
        let recursive = composition
            .boundaries
            .iter()
            .filter(|b| b.reason == BoundaryReason::RECURSIVE_CALL)
            .collect::<Vec<_>>();
        assert_eq!(
            recursive.len(),
            1,
            "rounds {rounds}: {:?}",
            composition.boundaries
        );
        assert_eq!(recursive[0].domains, ["filesystem"]);
        assert!(!composition.effects.is_empty());
        assert!(composition.budget.steps < 100);
        assert!(composition.budget.saturated.is_none());
    }
    let baseline = build_index(&root, IndexLimits::default());
    let composition = baseline.composition("app.py").unwrap();
    for (limit, value) in [
        ("repository.max_compose_steps", composition.budget.steps - 1),
        (
            "repository.max_composed_effects",
            composition.effects.len() as u64 - 1,
        ),
        ("repository.max_composition_depth", 3),
    ] {
        let mut limits = IndexLimits::default();
        limits.set(limit, value).unwrap();
        let index = build_index(&root, limits);
        let composition = index.composition("app.py").unwrap();
        assert!(
            composition
                .boundaries
                .iter()
                .any(|b| b.reason == BoundaryReason::LIMIT_SATURATED
                    && b.limit.as_deref() == Some(limit)),
            "{limit}: {:?}",
            composition.boundaries
        );
        assert!(
            !composition
                .boundaries
                .iter()
                .any(|b| b.reason == BoundaryReason::RECURSIVE_CALL)
        );
    }
}

#[test]
fn nested_recursive_groups_do_not_spend_the_effect_budget_on_round_duplicates() {
    let root = temp_repo(
        "recursion-nested",
        &[
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom worker import first\nfirst()\n",
            ),
            (
                "worker.py",
                "import os\ndef first():\n    os.remove('/first')\n    second()\n    first()\ndef second():\n    os.remove('/second')\n    third()\n    second()\ndef third():\n    os.remove('/third')\n    fourth()\n    third()\ndef fourth():\n    os.remove('/fourth')\n    fourth()\n",
            ),
        ],
    );
    let mut limits = IndexLimits::default();
    limits.repository.max_composed_effects = 32;
    let index = build_index(&root, limits);
    let composition = index.composition("app.py").unwrap();
    assert!(
        composition.budget.saturated.is_none(),
        "{:?}",
        composition.boundaries
    );
    for resource in ["/first", "/second", "/third", "/fourth"] {
        assert!(composition.effects.iter().any(|effect| {
            effinterp_proto::canonical_json(&effect.effect.resource).contains(resource)
        }));
    }
    let mut wider_limits = IndexLimits::default();
    wider_limits.repository.max_recursion_rounds = 8;
    wider_limits.repository.max_composed_effects = composition.effects.len();
    let wider = build_index(&root, wider_limits);
    assert!(
        wider
            .composition("app.py")
            .unwrap()
            .budget
            .saturated
            .is_none()
    );
    let before: serde_json::Value = serde_json::from_str(&normalize_surface(&index)).unwrap();
    let after: serde_json::Value = serde_json::from_str(&normalize_surface(&wider)).unwrap();
    assert_eq!(before["entrypoints"], after["entrypoints"]);
}

#[test]
fn recursive_rounds_preserve_distinct_calls_at_the_same_path() {
    let root = temp_repo(
        "recursion-distinct-calls",
        &[
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom worker import walk\nwalk()\n",
            ),
            (
                "worker.py",
                "from helper import remove\ndef walk():\n    remove()\n    remove()\n    walk()\n",
            ),
            (
                "helper.py",
                "import os\ndef remove():\n    os.remove('/file')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("app.py").unwrap();
    assert!(composition.budget.saturated.is_none());
    for path in [
        vec!["app.py", "worker.py:walk", "helper.py:remove"],
        vec![
            "app.py",
            "worker.py:walk",
            "worker.py:walk",
            "helper.py:remove",
        ],
    ] {
        assert_eq!(
            composition
                .occurrence_effects
                .iter()
                .filter(|occurrence| {
                    occurrence.path == path
                        && composition.effects[occurrence.effect].effect.operation.0
                            == "filesystem.delete"
                })
                .count(),
            2,
            "{path:?}"
        );
    }
}
