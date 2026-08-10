use super::*;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn alias_snapshots_freeze_parse_time_state() {
    let mut state = LookupState::default();
    assert_eq!(
        state.apply_builtin("shopt", &strings(&["-s", "expand_aliases"])),
        Update::Exact
    );
    state.apply_builtin("alias", &strings(&["wipe=rm -rf /"]));
    let snapshot = state.alias_snapshot();
    state.apply_builtin("unalias", &strings(&["wipe"]));

    assert_eq!(
        snapshot.resolve("wipe", true),
        AliasResolution {
            replacements: vec!["rm -rf /".to_owned()],
            unexpanded: false,
            variants_complete: true,
        }
    );
    assert!(
        state
            .alias_snapshot()
            .resolve("wipe", true)
            .replacements
            .is_empty()
    );
}

#[test]
fn merged_alias_branches_retain_every_reachable_expansion() {
    let mut left = LookupState::default();
    left.apply_builtin("shopt", &strings(&["-s", "expand_aliases"]));
    left.apply_builtin("alias", &strings(&["run=rm -rf /"]));
    let mut right = left.clone();
    right.apply_builtin("alias", &strings(&["run=echo safe"]));
    let merged = LookupState::merge(&[left, right]).unwrap();
    let resolution = merged.alias_snapshot().resolve("run", true);
    assert_eq!(
        resolution.replacements,
        ["echo safe".to_owned(), "rm -rf /".to_owned()]
    );
    assert!(!resolution.unexpanded);
    assert!(resolution.variants_complete);
}

#[test]
fn merged_alias_option_branches_are_an_exhaustive_union() {
    let mut enabled = LookupState::default();
    enabled.apply_builtin("shopt", &strings(&["-s", "expand_aliases"]));
    enabled.apply_builtin("alias", &strings(&["run=rm -rf /"]));
    let mut disabled = enabled.clone();
    disabled.apply_builtin("shopt", &strings(&["-u", "expand_aliases"]));

    let merged = LookupState::merge(&[enabled, disabled]).unwrap();
    let resolution = merged.alias_snapshot().resolve("run", true);
    assert_eq!(resolution.replacements, ["rm -rf /".to_owned()]);
    assert!(resolution.unexpanded);
    assert!(resolution.variants_complete);
}

#[test]
fn aliases_require_the_option_and_an_eligible_lexical_word() {
    let mut state = LookupState::default();
    state.apply_builtin("alias", &strings(&["run=rm -rf /"]));
    assert!(
        state
            .alias_snapshot()
            .resolve("run", true)
            .replacements
            .is_empty()
    );
    state.apply_builtin("shopt", &strings(&["-s", "expand_aliases"]));
    assert!(
        state
            .alias_snapshot()
            .resolve("run", false)
            .replacements
            .is_empty()
    );
}

#[test]
fn alias_print_mode_does_not_replace_a_prior_definition() {
    let mut state = LookupState::default();
    state.apply_builtin("shopt", &strings(&["-s", "expand_aliases"]));
    state.apply_builtin("alias", &strings(&["run=rm -rf /"]));
    assert_eq!(
        state.apply_builtin("alias", &strings(&["-p", "run=echo safe"])),
        Update::Exact
    );
    assert_eq!(
        state.alias_snapshot().resolve("run", true).replacements,
        ["rm -rf /".to_owned()]
    );
}

#[test]
fn functions_and_enabled_builtins_mask_hashes() {
    let mut state = LookupState::default();
    state.apply_builtin("hash", &strings(&["-p", "/bin/rm", "echo", "wipe"]));
    assert_eq!(
        state
            .resolve("wipe", LookupMode::Normal, FunctionPresence::Present)
            .targets,
        [LookupTarget::Function]
    );
    assert_eq!(
        state
            .resolve("echo", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Builtin]
    );
    state.apply_builtin("enable", &strings(&["-n", "echo"]));
    assert_eq!(
        state
            .resolve("echo", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Hashed("/bin/rm".to_owned())]
    );
}

#[test]
fn exact_hash_remaps_are_classified_by_the_target_not_the_typed_name() {
    let mut state = LookupState::default();
    state.apply_builtin("hash", &strings(&["-p", "/bin/echo", "rm"]));
    state.apply_builtin("hash", &strings(&["-p", "/bin/rm", "say"]));

    assert_eq!(
        state
            .resolve("rm", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Hashed("/bin/echo".to_owned())]
    );
    assert_eq!(
        state
            .resolve("say", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Hashed("/bin/rm".to_owned())]
    );
}

#[test]
fn command_modes_match_bash_lookup_boundaries() {
    let mut state = LookupState::default();
    state.apply_builtin("hash", &strings(&["-p", "/bin/rm", "wipe"]));
    assert_eq!(
        state
            .resolve("wipe", LookupMode::Command, FunctionPresence::Present)
            .targets,
        [LookupTarget::Hashed("/bin/rm".to_owned())]
    );
    assert_eq!(
        state
            .resolve(
                "wipe",
                LookupMode::CommandDefaultPath,
                FunctionPresence::Present,
            )
            .targets,
        [LookupTarget::Path("wipe".to_owned())]
    );
    assert_eq!(
        state
            .resolve("wipe", LookupMode::BuiltinOnly, FunctionPresence::Present)
            .targets,
        [LookupTarget::MissingBuiltin]
    );
    assert_eq!(
        state
            .resolve("./wipe", LookupMode::BuiltinOnly, FunctionPresence::Absent,)
            .targets,
        [LookupTarget::MissingBuiltin]
    );
    let possible_function = state.resolve("wipe", LookupMode::Normal, FunctionPresence::Possible);
    assert_eq!(
        possible_function.targets,
        [
            LookupTarget::Function,
            LookupTarget::Hashed("/bin/rm".to_owned())
        ]
    );
    assert!(possible_function.variants_complete);

    assert_eq!(
        state
            .resolve("echo", LookupMode::External, FunctionPresence::Present)
            .targets,
        [LookupTarget::Path("echo".to_owned())]
    );
}

#[test]
fn hash_resets_and_path_changes_remove_exact_identity() {
    for reset in [
        strings(&["-d", "wipe"]),
        strings(&["-r"]),
        strings(&["wipe"]),
    ] {
        let mut state = LookupState::default();
        state.apply_builtin("hash", &strings(&["-p", "/bin/rm", "wipe"]));
        let update = state.apply_builtin("hash", &reset);
        let resolution = state.resolve("wipe", LookupMode::Normal, FunctionPresence::Absent);
        assert!(
            matches!(resolution.targets.as_slice(), [LookupTarget::Path(name)] if name == "wipe")
        );
        if reset == strings(&["wipe"]) {
            assert_eq!(update, Update::Partial);
            assert!(!resolution.variants_complete);
        }
    }

    let mut state = LookupState::default();
    state.apply_builtin("hash", &strings(&["-p", "/bin/rm", "wipe"]));
    assert_eq!(state.apply_path_change(Certainty::Yes), Update::Exact);
    assert!(matches!(
        state
            .resolve("wipe", LookupMode::Normal, FunctionPresence::Absent)
            .targets
            .as_slice(),
        [LookupTarget::Path(name)] if name == "wipe"
    ));
}

#[test]
fn path_searches_are_complete_at_the_lexical_name_boundary() {
    let state = LookupState::default();
    for mode in [
        LookupMode::Normal,
        LookupMode::Command,
        LookupMode::CommandDefaultPath,
    ] {
        let resolution = state.resolve("tool", mode, FunctionPresence::Absent);
        assert_eq!(resolution.targets, [LookupTarget::Path("tool".to_owned())]);
        assert!(resolution.variants_complete, "{mode:?}");
    }

    assert!(
        state
            .resolve("echo", LookupMode::Normal, FunctionPresence::Absent)
            .variants_complete
    );
    assert!(
        state
            .resolve("./tool", LookupMode::Normal, FunctionPresence::Absent)
            .variants_complete
    );
}

#[test]
fn unresolved_lookup_mutations_remain_visible_until_an_exact_reset() {
    let mut aliases = LookupState::default();
    aliases.apply_builtin("shopt", &strings(&["-s", "expand_aliases"]));
    aliases.apply_builtin("alias", &strings(&["run=echo safe"]));
    assert_eq!(aliases.invalidate_builtin("alias"), Update::Partial);
    let resolution = aliases.alias_snapshot().resolve("run", true);
    assert_eq!(resolution.replacements, ["echo safe".to_owned()]);
    assert!(resolution.unexpanded);
    assert!(!resolution.variants_complete);
    aliases.apply_builtin("unalias", &strings(&["-a"]));
    assert!(
        aliases
            .alias_snapshot()
            .resolve("run", true)
            .variants_complete
    );

    let mut hashes = LookupState::default();
    hashes.apply_builtin("hash", &strings(&["-p", "/bin/rm", "run"]));
    assert_eq!(hashes.invalidate_builtin("hash"), Update::Partial);
    let resolution = hashes.resolve("run", LookupMode::Normal, FunctionPresence::Absent);
    assert_eq!(
        resolution.targets,
        [
            LookupTarget::Hashed("/bin/rm".to_owned()),
            LookupTarget::Path("run".to_owned())
        ]
    );
    assert!(!resolution.variants_complete);
    hashes.apply_builtin("hash", &strings(&["-r"]));
    assert_eq!(
        hashes
            .resolve("run", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Path("run".to_owned())]
    );

    let mut unknown_hash = LookupState::default();
    unknown_hash.invalidate_builtin("hash");
    assert!(
        !unknown_hash
            .resolve("other", LookupMode::Normal, FunctionPresence::Absent)
            .variants_complete
    );

    let mut builtins = LookupState::default();
    assert_eq!(builtins.invalidate_builtin("enable"), Update::Partial);
    let resolution = builtins.resolve("echo", LookupMode::Normal, FunctionPresence::Absent);
    assert_eq!(
        resolution.targets,
        [LookupTarget::Builtin, LookupTarget::Path("echo".to_owned())]
    );
    assert!(!resolution.variants_complete);

    let mut sourced = LookupState::default();
    assert_eq!(sourced.invalidate_all(), Update::Partial);
    assert!(
        !sourced
            .alias_snapshot()
            .resolve("unknown", true)
            .variants_complete
    );
    assert!(
        !sourced
            .resolve("unknown", LookupMode::Normal, FunctionPresence::Absent)
            .variants_complete
    );
}

#[test]
fn dynamic_builtin_loading_refuses_and_s_still_mutates_named_builtins() {
    for arguments in [
        strings(&["-f", "/tmp/custom.so", "custom"]),
        strings(&["-d", "custom"]),
        strings(&["-nsf", "/tmp/custom.so", "custom"]),
    ] {
        let mut state = LookupState::default();
        assert_eq!(state.apply_builtin("enable", &arguments), Update::Refused);
        assert!(
            !state
                .resolve("custom", LookupMode::Normal, FunctionPresence::Absent)
                .variants_complete
        );
    }

    let mut state = LookupState::default();
    state.apply_builtin("hash", &strings(&["-p", "/bin/rm", "echo"]));
    state.apply_builtin("enable", &strings(&["-n", "echo"]));
    assert_eq!(
        state.apply_builtin("enable", &strings(&["-s", "echo"])),
        Update::Exact
    );
    assert_eq!(
        state
            .resolve("echo", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Builtin]
    );
}

#[test]
fn hashall_disables_lookup_without_discarding_the_table() {
    let mut state = LookupState::default();
    state.apply_builtin("hash", &strings(&["-p", "/bin/rm", "run"]));
    state.apply_builtin("set", &strings(&["+h"]));
    let disabled = state.resolve("run", LookupMode::Normal, FunctionPresence::Absent);
    assert_eq!(disabled.targets, [LookupTarget::Path("run".to_owned())]);
    assert!(disabled.variants_complete);

    assert_eq!(
        state.apply_builtin("hash", &strings(&["-r"])),
        Update::Exact
    );
    assert_eq!(state.invalidate_builtin("hash"), Update::Exact);
    state.apply_builtin("set", &strings(&["-h"]));
    assert_eq!(
        state
            .resolve("run", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Hashed("/bin/rm".to_owned())]
    );

    state.apply_builtin("set", &strings(&["+o", "hashall"]));
    assert!(matches!(
        state
            .resolve("run", LookupMode::Normal, FunctionPresence::Absent)
            .targets
            .as_slice(),
        [LookupTarget::Path(name)] if name == "run"
    ));
    state.apply_builtin("set", &strings(&["-ohashall"]));
    assert!(
        state
            .resolve("run", LookupMode::Normal, FunctionPresence::Absent)
            .variants_complete
    );
}

#[test]
fn shopt_and_set_forms_preserve_hashall_uncertainty() {
    let mut state = LookupState::default();
    state.apply_builtin("hash", &strings(&["-p", "/bin/rm", "run"]));

    let mut dynamic = state.clone();
    assert_eq!(dynamic.invalidate_builtin("shopt"), Update::Partial);
    assert_eq!(
        dynamic
            .resolve("run", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [
            LookupTarget::Hashed("/bin/rm".to_owned()),
            LookupTarget::Path("run".to_owned())
        ]
    );

    assert_eq!(
        state.apply_builtin("shopt", &strings(&["-uo", "hashall"])),
        Update::Exact
    );
    assert_eq!(
        state
            .resolve("run", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Path("run".to_owned())]
    );
    state.apply_builtin("shopt", &strings(&["-so", "hashall"]));
    assert_eq!(
        state
            .resolve("run", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Hashed("/bin/rm".to_owned())]
    );

    assert_eq!(
        state.apply_builtin("set", &strings(&["-euo", "pipefail"])),
        Update::Exact
    );
    assert_eq!(
        state.apply_builtin("set", &strings(&["+hZ"])),
        Update::Partial
    );
    let resolution = state.resolve("run", LookupMode::Normal, FunctionPresence::Absent);
    assert_eq!(
        resolution.targets,
        [
            LookupTarget::Hashed("/bin/rm".to_owned()),
            LookupTarget::Path("run".to_owned())
        ]
    );
    assert!(resolution.variants_complete);
}

#[test]
fn clustered_hash_options_follow_bash_action_precedence() {
    let mut state = LookupState::default();
    state.apply_builtin("hash", &strings(&["-p", "/bin/false", "old"]));
    assert_eq!(
        state.apply_builtin("hash", &strings(&["-rp", "/bin/echo", "say"])),
        Update::Exact
    );
    assert_eq!(
        state
            .resolve("old", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Path("old".to_owned())]
    );

    state.apply_builtin("hash", &strings(&["-dp", "/bin/rm", "say"]));
    assert_eq!(
        state
            .resolve("say", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Hashed("/bin/rm".to_owned())]
    );
    state.apply_builtin("hash", &strings(&["-p", "/bin/echo", "-t", "say"]));
    assert_eq!(
        state
            .resolve("say", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Hashed("/bin/rm".to_owned())]
    );
}

#[test]
fn path_changes_distinguish_accepted_rejected_and_uncertain_assignments() {
    let state_with_hash = || {
        let mut state = LookupState::default();
        state.apply_builtin("hash", &strings(&["-p", "/bin/rm", "run"]));
        state
    };

    let mut rejected = state_with_hash();
    assert_eq!(rejected.apply_path_change(Certainty::No), Update::Exact);
    assert_eq!(
        rejected
            .resolve("run", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Hashed("/bin/rm".to_owned())]
    );

    let mut accepted = state_with_hash();
    assert_eq!(accepted.apply_path_change(Certainty::Yes), Update::Exact);
    assert_eq!(
        accepted
            .resolve("run", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Path("run".to_owned())]
    );

    let mut uncertain = state_with_hash();
    assert_eq!(
        uncertain.apply_path_change(Certainty::Maybe),
        Update::Partial
    );
    let resolution = uncertain.resolve("run", LookupMode::Normal, FunctionPresence::Absent);
    assert_eq!(
        resolution.targets,
        [
            LookupTarget::Hashed("/bin/rm".to_owned()),
            LookupTarget::Path("run".to_owned())
        ]
    );
    assert!(resolution.variants_complete);
}

#[test]
fn handler_reachability_is_limited_to_bare_path_searches() {
    let mut state = LookupState::default();
    assert!(
        state
            .resolve("missing", LookupMode::Normal, FunctionPresence::Absent)
            .command_not_found_possible
    );
    assert!(
        !state
            .resolve("./missing", LookupMode::Normal, FunctionPresence::Absent,)
            .command_not_found_possible
    );
    assert!(
        !state
            .resolve("missing", LookupMode::BuiltinOnly, FunctionPresence::Absent,)
            .command_not_found_possible
    );
    assert!(
        state
            .resolve("missing", LookupMode::Command, FunctionPresence::Absent,)
            .command_not_found_possible
    );
    assert!(
        state
            .resolve(
                "missing",
                LookupMode::CommandDefaultPath,
                FunctionPresence::Absent,
            )
            .command_not_found_possible
    );
    assert!(
        state
            .resolve(
                r"missing\command",
                LookupMode::Normal,
                FunctionPresence::Absent,
            )
            .command_not_found_possible
    );

    state.apply_builtin("hash", &strings(&["-p", "/missing/exact", "missing"]));
    assert!(
        !state
            .resolve("missing", LookupMode::Normal, FunctionPresence::Absent)
            .command_not_found_possible
    );
}

#[test]
fn reenabled_builtin_masks_a_retained_hash_again() {
    let mut state = LookupState::default();
    state.apply_builtin("hash", &strings(&["-p", "/bin/rm", "eval"]));
    state.apply_builtin("enable", &strings(&["-n", "eval"]));
    assert_eq!(
        state
            .resolve("eval", LookupMode::Command, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Hashed("/bin/rm".to_owned())]
    );
    assert_eq!(
        state
            .resolve("eval", LookupMode::BuiltinOnly, FunctionPresence::Absent)
            .targets,
        [LookupTarget::MissingBuiltin]
    );

    state.apply_builtin("enable", &strings(&["-s", "eval"]));
    assert_eq!(
        state
            .resolve("eval", LookupMode::Normal, FunctionPresence::Absent)
            .targets,
        [LookupTarget::Builtin]
    );
}

#[test]
fn binding_limits_refuse_instead_of_dropping_state() {
    assert_eq!(LookupState::merge(&[]), Err(()));

    let mut state = LookupState::default();
    state.apply_builtin("shopt", &strings(&["-s", "expand_aliases"]));
    for index in 0..MAX_BINDINGS {
        assert_eq!(
            state.apply_builtin("alias", &[format!("name{index}=true")]),
            Update::Exact
        );
    }
    assert_eq!(
        state.apply_builtin("alias", &["overflow=true".to_owned()]),
        Update::Refused
    );
}
