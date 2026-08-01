use super::*;

fn facts(hosts: &[&str], producer_sources: &[usize], consumer_sinks: &[usize]) -> DescriptorFacts {
    DescriptorFacts::try_new(
        hosts.iter().map(|host| (*host).to_owned()).collect(),
        producer_sources.to_vec(),
        consumer_sinks.to_vec(),
    )
    .expect("bounded descriptor facts")
}

#[test]
fn descriptor_facts_are_independent_canonical_sets() {
    let facts = facts(
        &["two.example", "one.example", "two.example"],
        &[7, 3, 7],
        &[9, 4, 9],
    );
    assert_eq!(
        facts.hosts(),
        &["one.example".to_owned(), "two.example".to_owned()]
    );
    assert_eq!(facts.producer_sources(), &[3, 7]);
    assert_eq!(facts.consumer_sinks(), &[4, 9]);
}
#[test]
fn every_descriptor_fact_set_refuses_saturation() {
    let hosts = (0..=MAX_DESCRIPTOR_FACTS)
        .map(|index| format!("host-{index}"))
        .collect();
    assert_eq!(
        DescriptorFacts::try_new(hosts, vec![], vec![]),
        Err(DescriptorRefusal::Saturated)
    );
    assert_eq!(
        DescriptorFacts::try_new(vec![], (0..=MAX_DESCRIPTOR_FACTS).collect(), vec![]),
        Err(DescriptorRefusal::Saturated)
    );
    assert_eq!(
        DescriptorFacts::try_new(vec![], vec![], (0..=MAX_DESCRIPTOR_FACTS).collect()),
        Err(DescriptorRefusal::Saturated)
    );

    let duplicate_values = vec![1; MAX_DESCRIPTOR_FACTS + 1];
    assert!(DescriptorFacts::try_new(vec![], duplicate_values, vec![]).is_ok());
}
#[test]
fn descriptor_mutations_apply_left_to_right_without_aliasing() {
    let original = facts(&["first.example"], &[2], &[8]);
    let replacement = facts(&["second.example"], &[3], &[9]);
    let mut state = DescriptorState::default();

    assert_eq!(
        state.rebind("03", original.clone()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(
        state.duplicate("4", "/dev/fd/3"),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(
        state.rebind("3", replacement.clone()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(state.binding("3"), Some(&replacement));
    assert_eq!(state.binding("/proc/self/fd/04"), Some(&original));

    assert_eq!(state.move_binding("5", "4"), Ok(DescriptorUpdate::Exact));
    assert_eq!(state.binding("4"), None);
    assert_eq!(state.binding("/dev/fd/5"), Some(&original));
    assert_eq!(state.close("/proc/self/fd/5"), Ok(DescriptorUpdate::Exact));
    assert_eq!(state.binding("5"), None);
}
#[test]
fn close_rebind_and_same_descriptor_move_remove_old_provenance() {
    let retained = facts(&["socket.example"], &[1], &[6]);
    let mut state = DescriptorState::default();

    assert_eq!(
        state.rebind("7", retained.clone()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(
        state.rebind("7", DescriptorFacts::default()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(state.binding("7"), Some(&DescriptorFacts::default()));

    assert_eq!(
        state.rebind("7", retained.clone()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(state.duplicate("7", "1"), Ok(DescriptorUpdate::Exact));
    assert_eq!(state.binding("7"), Some(&DescriptorFacts::default()));

    assert_eq!(state.rebind("7", retained), Ok(DescriptorUpdate::Exact));
    assert_eq!(state.move_binding("7", "7"), Ok(DescriptorUpdate::Exact));
    assert_eq!(state.binding("7"), None);
}
#[test]
fn failed_duplication_is_reported_without_mutating_the_target() {
    let mut state = DescriptorState::default();
    let retained = facts(&["old.example"], &[1], &[2]);
    assert_eq!(
        state.rebind("8", retained.clone()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(state.duplicate("8", "99"), Ok(DescriptorUpdate::Uncertain));
    assert_eq!(state.binding("8"), Some(&retained));

    assert_eq!(state.close("0"), Ok(DescriptorUpdate::Exact));
    assert_eq!(
        state.duplicate("8", "/dev/stdin"),
        Ok(DescriptorUpdate::Uncertain)
    );
    assert_eq!(state.binding("8"), Some(&retained));
}
#[test]
fn descriptor_aliases_resolve_to_one_numeric_binding() {
    let stdin = facts(&[], &[11], &[]);
    let numbered = facts(&["socket.example"], &[12], &[13]);
    let mut state = DescriptorState::default();

    assert_eq!(
        state.rebind("/dev/stdin", stdin.clone()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(
        state.rebind("/proc/self/fd/003", numbered.clone()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(state.binding("0"), Some(&stdin));
    assert_eq!(state.binding("/dev/fd/0"), Some(&stdin));
    assert_eq!(state.binding("3"), Some(&numbered));
    assert_eq!(state.binding("/dev/fd/03"), Some(&numbered));
    assert_eq!(state.binding("/proc/self/fd/3"), Some(&numbered));

    assert_eq!(canonical_descriptor_fd("/dev/fd/"), None);
    assert_eq!(canonical_descriptor_fd("/proc/self/fd/name"), None);
    assert_eq!(canonical_descriptor_fd("{fd}"), None);
    assert_eq!(canonical_descriptor_fd("-"), None);
}
#[test]
fn branch_merge_unions_each_capability_or_refuses() {
    let mut left = DescriptorState::default();
    let mut right = DescriptorState::default();
    assert_eq!(
        left.rebind("3", facts(&["one.example"], &[1], &[7])),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(
        right.rebind("03", facts(&["two.example"], &[2], &[8])),
        Ok(DescriptorUpdate::Exact)
    );
    let merged = DescriptorState::merge(&[left, right]).expect("bounded merge");
    let binding = merged.binding("/dev/fd/3").expect("merged binding");
    assert_eq!(
        binding.hosts(),
        &["one.example".to_owned(), "two.example".to_owned()]
    );
    assert_eq!(binding.producer_sources(), &[1, 2]);
    assert_eq!(binding.consumer_sinks(), &[7, 8]);

    let saturated = (0..=MAX_DESCRIPTOR_FACTS)
        .map(|source| {
            let mut state = DescriptorState::default();
            assert_eq!(
                state.rebind("3", facts(&[], &[source], &[])),
                Ok(DescriptorUpdate::Exact)
            );
            state
        })
        .collect::<Vec<_>>();
    assert_eq!(
        DescriptorState::merge(&saturated),
        Err(DescriptorRefusal::Saturated)
    );
}
#[test]
fn uncertain_duplication_retains_the_old_target_alternative() {
    let source = facts(&["source.example"], &[3], &[4]);
    let old_target = facts(&["target.example"], &[8], &[9]);
    let mut source_present = DescriptorState::default();
    let mut source_absent = DescriptorState::default();
    assert_eq!(
        source_present.rebind("3", source),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(
        source_present.rebind("8", old_target.clone()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(
        source_absent.rebind("8", old_target),
        Ok(DescriptorUpdate::Exact)
    );

    let mut merged =
        DescriptorState::merge(&[source_present, source_absent]).expect("bounded merge");
    assert_eq!(merged.presence("3"), DescriptorPresence::Maybe);
    assert_eq!(merged.presence("8"), DescriptorPresence::Present);
    assert_eq!(merged.duplicate("8", "3"), Ok(DescriptorUpdate::Uncertain));

    let target = merged.binding("8").expect("target remains present");
    assert_eq!(
        target.hosts(),
        &["source.example".to_owned(), "target.example".to_owned()]
    );
    assert_eq!(target.producer_sources(), &[3, 8]);
    assert_eq!(target.consumer_sinks(), &[4, 9]);
    assert_eq!(merged.presence("8"), DescriptorPresence::Present);
}
#[test]
fn state_fact_caps_are_global_and_failed_rebind_is_transactional() {
    fn reaches_cap(mut make_facts: impl FnMut(usize) -> DescriptorFacts) {
        let mut state = DescriptorState::default();
        for index in 0..MAX_DESCRIPTOR_FACTS {
            assert_eq!(
                state.rebind(&(index + 3).to_string(), make_facts(index)),
                Ok(DescriptorUpdate::Exact)
            );
        }
        let before = state.clone();
        assert_eq!(
            state.rebind("99", make_facts(MAX_DESCRIPTOR_FACTS)),
            Err(DescriptorRefusal::Saturated)
        );
        assert_eq!(state, before);
        assert_eq!(state.binding("99"), None);
    }

    reaches_cap(|index| facts(&[&format!("host-{index}")], &[], &[]));
    reaches_cap(|index| facts(&[], &[index], &[]));
    reaches_cap(|index| facts(&[], &[], &[index]));
}
#[test]
fn saturated_duplication_refuses_but_move_can_reuse_source_capacity() {
    let mut state = DescriptorState::default();
    for source in 0..MAX_DESCRIPTOR_FACTS {
        assert_eq!(
            state.rebind(&(source + 3).to_string(), facts(&[], &[source], &[])),
            Ok(DescriptorUpdate::Exact)
        );
    }
    let before = state.clone();
    assert_eq!(
        state.duplicate("99", "3"),
        Err(DescriptorRefusal::Saturated)
    );
    assert_eq!(state, before);

    assert_eq!(state.move_binding("99", "3"), Ok(DescriptorUpdate::Exact));
    assert_eq!(state.binding("3"), None);
    assert_eq!(
        state
            .binding("99")
            .expect("moved binding")
            .producer_sources(),
        &[0]
    );
}
#[test]
fn allocated_alias_copies_survive_variable_reallocation_and_unset() {
    let first_id = SymbolicDescriptorId::new(100);
    let second_id = SymbolicDescriptorId::new(101);
    let first = facts(&["first.example"], &[1], &[2]);
    let second = facts(&["second.example"], &[3], &[4]);
    let mut state = DescriptorState::default();

    assert_eq!(
        state.bind_allocated("fd", first_id, first.clone()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(state.duplicate("0", "{fd}"), Ok(DescriptorUpdate::Exact));
    assert_eq!(state.binding("0"), Some(&first));
    assert_eq!(state.copy_alias("old", "fd"), Ok(DescriptorUpdate::Exact));
    assert_eq!(
        state.bind_allocated("fd", second_id, second.clone()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(
        state.alias_binding("old"),
        Ok(Some((DescriptorPresence::Present, first.clone())))
    );
    assert_eq!(
        state.alias_binding("fd"),
        Ok(Some((DescriptorPresence::Present, second.clone())))
    );

    assert!(state.unset_alias("fd"));
    assert_eq!(state.alias_binding("fd"), Ok(None));
    assert_eq!(
        state.alias_binding("old"),
        Ok(Some((DescriptorPresence::Present, first)))
    );

    assert_eq!(state.move_alias("1", "old"), Ok(DescriptorUpdate::Exact));
    assert_eq!(
        state.binding("1"),
        Some(&facts(&["first.example"], &[1], &[2]))
    );
    assert_eq!(
        state.alias_binding("old"),
        Ok(Some((
            DescriptorPresence::Absent,
            DescriptorFacts::default()
        )))
    );
}
#[test]
fn allocated_alias_branch_merge_preserves_all_identities_and_old_target() {
    let old_target = facts(&["target.example"], &[8], &[9]);
    let mut left = DescriptorState::default();
    let mut right = DescriptorState::default();
    assert_eq!(
        left.rebind("0", old_target.clone()),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(right.rebind("0", old_target), Ok(DescriptorUpdate::Exact));
    assert_eq!(
        left.bind_allocated(
            "fd",
            SymbolicDescriptorId::new(200),
            facts(&["left.example"], &[1], &[2]),
        ),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(
        right.bind_allocated(
            "fd",
            SymbolicDescriptorId::new(201),
            facts(&["right.example"], &[3], &[4]),
        ),
        Ok(DescriptorUpdate::Exact)
    );

    let mut merged = DescriptorState::merge(&[left, right]).expect("bounded alias merge");
    let (presence, alias) = merged
        .alias_binding("fd")
        .expect("bounded alias resolution")
        .expect("merged alias");
    assert_eq!(presence, DescriptorPresence::Maybe);
    assert_eq!(
        alias.hosts(),
        &["left.example".to_owned(), "right.example".to_owned()]
    );
    assert_eq!(
        merged.duplicate_alias("0", "fd"),
        Ok(DescriptorUpdate::Uncertain)
    );
    let stdin = merged.binding("0").expect("stdin remains present");
    assert_eq!(
        stdin.hosts(),
        &[
            "left.example".to_owned(),
            "right.example".to_owned(),
            "target.example".to_owned(),
        ]
    );
    assert_eq!(stdin.producer_sources(), &[1, 3, 8]);
    assert_eq!(stdin.consumer_sinks(), &[2, 4, 9]);
}
#[test]
fn coprocess_scalar_and_array_aliases_use_distinct_symbolic_ids() {
    let producer = SymbolicDescriptorId::new(300);
    let consumer = SymbolicDescriptorId::new(301);
    let default_producer = SymbolicDescriptorId::new(302);
    let default_consumer = SymbolicDescriptorId::new(303);
    let producer_facts = facts(&[], &[12], &[]);
    let consumer_facts = facts(&[], &[], &[13]);
    let mut state = DescriptorState::default();

    state
        .rebind_symbolic(producer, producer_facts.clone())
        .expect("producer binding");
    state
        .rebind_symbolic(consumer, consumer_facts.clone())
        .expect("consumer binding");
    state
        .rebind_symbolic(default_producer, facts(&[], &[14], &[]))
        .expect("default producer binding");
    state
        .rebind_symbolic(default_consumer, facts(&[], &[], &[15]))
        .expect("default consumer binding");
    assert_eq!(
        state.set_coprocess_aliases("JOB", producer, consumer),
        Ok(DescriptorUpdate::Exact)
    );
    assert_eq!(
        state.set_coprocess_aliases("COPROC", default_producer, default_consumer),
        Ok(DescriptorUpdate::Exact)
    );

    assert_eq!(
        state.alias_binding("JOB"),
        Ok(Some((DescriptorPresence::Present, producer_facts.clone())))
    );
    assert_eq!(
        state.alias_binding("JOB[0]"),
        Ok(Some((DescriptorPresence::Present, producer_facts)))
    );
    assert_eq!(
        state.alias_binding("JOB[1]"),
        Ok(Some((DescriptorPresence::Present, consumer_facts)))
    );
    assert_eq!(
        state
            .alias_binding("COPROC")
            .expect("bounded default alias")
            .expect("default scalar")
            .1
            .producer_sources(),
        &[14]
    );
    assert_eq!(
        state
            .alias_binding("COPROC[1]")
            .expect("bounded default alias")
            .expect("default consumer")
            .1
            .consumer_sinks(),
        &[15]
    );
}
#[test]
fn closing_a_branch_correlated_alias_retains_other_open_alias_facts() {
    let mut base = DescriptorState::default();
    base.bind_allocated(
        "left",
        SymbolicDescriptorId::new(400),
        facts(&[], &[1], &[]),
    )
    .unwrap();
    base.bind_allocated(
        "right",
        SymbolicDescriptorId::new(401),
        facts(&[], &[2], &[]),
    )
    .unwrap();
    let mut first = base.clone();
    first.copy_alias("closed", "left").unwrap();
    first.copy_alias("open", "right").unwrap();
    let mut second = base;
    second.copy_alias("closed", "right").unwrap();
    second.copy_alias("open", "left").unwrap();

    let mut merged = DescriptorState::merge(&[first, second]).unwrap();
    assert_eq!(
        merged.close_alias("closed"),
        Ok(DescriptorUpdate::Uncertain)
    );
    let (presence, remaining) = merged.alias_binding("open").unwrap().unwrap();
    assert_eq!(presence, DescriptorPresence::Maybe);
    assert_eq!(remaining.producer_sources(), &[1, 2]);
}
#[test]
fn retained_exact_content_has_one_aggregate_bound() {
    let half = crate::INVOCATION_EVIDENCE_CAP / 2 + 1;
    let content = "x".repeat(half);
    let first = DescriptorFacts::try_new(vec![], vec![1], vec![])
        .unwrap()
        .try_with_exact_content(content.clone())
        .unwrap();
    let second = DescriptorFacts::try_new(vec![], vec![2], vec![])
        .unwrap()
        .try_with_exact_content(content)
        .unwrap();
    let mut state = DescriptorState::default();
    assert_eq!(state.rebind("3", first), Ok(DescriptorUpdate::Exact));
    let before = state.clone();
    assert_eq!(state.rebind("4", second), Err(DescriptorRefusal::Saturated));
    assert_eq!(state, before);
}
