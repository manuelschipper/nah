//! Owns persistent Bash descriptor identities and the facts they carry.

use nah_proto::action::NetworkDirection;

use crate::bash_descriptor_paths::canonical_descriptor_fd;

pub(crate) type NetworkEndpoint = (NetworkDirection, String);
pub(crate) type DescriptorFlow = (usize, usize);
pub(crate) type RoutedNetworkEndpoint = (usize, NetworkEndpoint);

const MAX_DESCRIPTOR_FACTS: usize = 32;
const SYMBOLIC_DESCRIPTOR_PREFIX: &str = "\0nah-symbolic:";

/// Independent capabilities carried by one descriptor.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DescriptorFacts {
    hosts: Vec<String>,
    producer_sources: Vec<usize>,
    consumer_sinks: Vec<usize>,
    write_targets: Vec<String>,
    content: DescriptorContent,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
enum DescriptorContent {
    #[default]
    Unavailable,
    Exact(String),
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DescriptorRefusal {
    Saturated,
}

impl DescriptorFacts {
    pub(crate) fn try_new(
        hosts: Vec<String>,
        producer_sources: Vec<usize>,
        consumer_sinks: Vec<usize>,
    ) -> Result<Self, DescriptorRefusal> {
        Ok(Self {
            hosts: bounded_set(hosts)?,
            producer_sources: bounded_set(producer_sources)?,
            consumer_sinks: bounded_set(consumer_sinks)?,
            write_targets: Vec::new(),
            content: DescriptorContent::Unavailable,
        })
    }

    pub(crate) fn try_with_write_target(
        mut self,
        target: String,
    ) -> Result<Self, DescriptorRefusal> {
        self.write_targets = bounded_set(vec![target])?;
        Ok(self)
    }

    pub(crate) fn try_with_exact_content(
        mut self,
        content: String,
    ) -> Result<Self, DescriptorRefusal> {
        if content.len() > crate::INVOCATION_EVIDENCE_CAP {
            return Err(DescriptorRefusal::Saturated);
        }
        self.content = DescriptorContent::Exact(content);
        Ok(self)
    }

    pub(crate) fn with_unknown_content(mut self) -> Self {
        self.content = DescriptorContent::Unknown;
        self
    }

    pub(crate) fn hosts(&self) -> &[String] {
        &self.hosts
    }

    pub(crate) fn producer_sources(&self) -> &[usize] {
        &self.producer_sources
    }

    pub(crate) fn consumer_sinks(&self) -> &[usize] {
        &self.consumer_sinks
    }

    pub(crate) fn write_targets(&self) -> &[String] {
        &self.write_targets
    }

    pub(crate) fn exact_content(&self) -> Option<&str> {
        match &self.content {
            DescriptorContent::Exact(content) => Some(content),
            DescriptorContent::Unavailable | DescriptorContent::Unknown => None,
        }
    }

    pub(crate) fn tracks_content(&self) -> bool {
        self.content != DescriptorContent::Unavailable
    }

    pub(crate) fn appended_exact_output(
        &self,
        output: &str,
    ) -> Result<Option<String>, DescriptorRefusal> {
        let DescriptorContent::Exact(prefix) = &self.content else {
            return Ok(None);
        };
        let Some(length) = prefix.len().checked_add(output.len()) else {
            return Err(DescriptorRefusal::Saturated);
        };
        if length > crate::INVOCATION_EVIDENCE_CAP {
            return Err(DescriptorRefusal::Saturated);
        }
        let mut combined = prefix.clone();
        combined.push_str(output);
        Ok(Some(combined))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.hosts.is_empty()
            && self.producer_sources.is_empty()
            && self.consumer_sinks.is_empty()
            && self.write_targets.is_empty()
            && self.content == DescriptorContent::Unavailable
    }

    fn merge(&mut self, other: &Self) -> Result<(), DescriptorRefusal> {
        let hosts = merged_set(&self.hosts, &other.hosts)?;
        let producer_sources = merged_set(&self.producer_sources, &other.producer_sources)?;
        let consumer_sinks = merged_set(&self.consumer_sinks, &other.consumer_sinks)?;
        let write_targets = merged_set(&self.write_targets, &other.write_targets)?;
        self.hosts = hosts;
        self.producer_sources = producer_sources;
        self.consumer_sinks = consumer_sinks;
        self.write_targets = write_targets;
        self.content = match (&self.content, &other.content) {
            (DescriptorContent::Unavailable, DescriptorContent::Unavailable) => {
                DescriptorContent::Unavailable
            }
            (DescriptorContent::Exact(left), DescriptorContent::Exact(right)) if left == right => {
                DescriptorContent::Exact(left.clone())
            }
            _ => DescriptorContent::Unknown,
        };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DescriptorPresence {
    Absent,
    Present,
    Maybe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DescriptorUpdate {
    Exact,
    Uncertain,
}

/// Stable identity supplied by the lowering coordinator for one allocation
/// site. The state never generates ids, so cloned branches cannot collide.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SymbolicDescriptorId(usize);

impl SymbolicDescriptorId {
    pub(crate) const fn new(allocation: usize) -> Self {
        Self(allocation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DescriptorSlot {
    pub(crate) presence: DescriptorPresence,
    pub(crate) facts: DescriptorFacts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DescriptorAlias {
    pub(crate) presence: DescriptorPresence,
    pub(crate) ids: Vec<SymbolicDescriptorId>,
}

/// Canonical descriptor capabilities after applying redirects in shell order.
///
/// Empty facts still retain that a descriptor is open, while a missing entry
/// means it is closed or was never modeled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DescriptorState {
    bindings: Vec<(String, DescriptorSlot)>,
    aliases: Vec<(String, DescriptorAlias)>,
}

impl Default for DescriptorState {
    fn default() -> Self {
        Self {
            bindings: ["0", "1", "2"]
                .into_iter()
                .map(|descriptor| {
                    (
                        descriptor.to_owned(),
                        DescriptorSlot {
                            presence: DescriptorPresence::Present,
                            facts: DescriptorFacts::default(),
                        },
                    )
                })
                .collect(),
            aliases: Vec::new(),
        }
    }
}

impl DescriptorState {
    pub(crate) fn binding(&self, descriptor: &str) -> Option<&DescriptorFacts> {
        self.slot(descriptor).map(|slot| &slot.facts)
    }

    #[cfg(test)]
    pub(crate) fn presence(&self, descriptor: &str) -> DescriptorPresence {
        self.slot(descriptor)
            .map_or(DescriptorPresence::Absent, |slot| slot.presence)
    }

    pub(crate) fn alias_binding(
        &self,
        name: &str,
    ) -> Result<Option<(DescriptorPresence, DescriptorFacts)>, DescriptorRefusal> {
        Ok(self
            .resolved_alias_slot(name)?
            .map(|slot| (slot.presence, slot.facts)))
    }

    pub(crate) fn reference_binding(
        &self,
        descriptor: &str,
    ) -> Result<Option<(DescriptorPresence, DescriptorFacts)>, DescriptorRefusal> {
        if let Some(alias) = allocated_descriptor_name(descriptor) {
            return self.alias_binding(alias);
        }
        Ok(self
            .slot(descriptor)
            .cloned()
            .map(|slot| (slot.presence, slot.facts)))
    }

    pub(crate) fn possible_facts(&self) -> Result<DescriptorFacts, DescriptorRefusal> {
        let mut slots = self.bindings.iter().map(|(_, slot)| slot);
        let Some(first) = slots.next() else {
            return Ok(DescriptorFacts::default());
        };
        let mut facts = first.facts.clone();
        for slot in slots {
            facts.merge(&slot.facts)?;
        }
        Ok(facts)
    }

    pub(crate) fn record_output(
        &mut self,
        output: &DescriptorFacts,
        exact_content: Option<String>,
    ) -> Result<(), DescriptorRefusal> {
        if !output.tracks_content() {
            return Ok(());
        }
        let mut candidate = self.clone();
        let same_output = |facts: &DescriptorFacts| {
            if output.write_targets.is_empty() {
                !output.consumer_sinks.is_empty()
                    && facts.consumer_sinks == output.consumer_sinks
                    && facts.write_targets.is_empty()
            } else {
                facts
                    .write_targets
                    .iter()
                    .any(|target| output.write_targets.contains(target))
            }
        };
        let matching = candidate
            .bindings
            .iter()
            .filter(|(_, slot)| same_output(&slot.facts))
            .map(|(_, slot)| {
                slot.facts.write_targets == output.write_targets
                    && slot.facts.consumer_sinks == output.consumer_sinks
            })
            .collect::<Vec<_>>();
        let exact_identity = !matching.is_empty() && matching.iter().all(|exact| *exact);
        for (_, slot) in &mut candidate.bindings {
            if !same_output(&slot.facts) {
                continue;
            }
            slot.facts.content = if exact_identity {
                exact_content
                    .as_ref()
                    .map_or(DescriptorContent::Unknown, |content| {
                        DescriptorContent::Exact(content.clone())
                    })
            } else {
                DescriptorContent::Unknown
            };
        }
        candidate.ensure_bounded()?;
        *self = candidate;
        Ok(())
    }

    pub(crate) fn rebind_symbolic(
        &mut self,
        id: SymbolicDescriptorId,
        facts: DescriptorFacts,
    ) -> Result<(), DescriptorRefusal> {
        let mut candidate = self.clone();
        candidate.rebind_symbolic_unchecked(id, facts);
        candidate.ensure_bounded()?;
        *self = candidate;
        Ok(())
    }

    /// Binds a new allocated descriptor and points its shell variable at that
    /// identity. Reusing the variable does not overwrite older identities.
    #[cfg(test)]
    pub(crate) fn bind_allocated(
        &mut self,
        variable: &str,
        id: SymbolicDescriptorId,
        facts: DescriptorFacts,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        if variable.is_empty() {
            return Ok(DescriptorUpdate::Uncertain);
        }
        let mut candidate = self.clone();
        candidate.rebind_symbolic_unchecked(id, facts);
        candidate.set_alias_unchecked(
            variable,
            DescriptorAlias {
                presence: DescriptorPresence::Present,
                ids: vec![id],
            },
        );
        candidate.ensure_bounded()?;
        *self = candidate;
        Ok(DescriptorUpdate::Exact)
    }

    /// Copies descriptor identity, not just the current variable name.
    pub(crate) fn copy_alias(
        &mut self,
        target: &str,
        source: &str,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        if target.is_empty() {
            return Ok(DescriptorUpdate::Uncertain);
        }
        let Some(source_alias) = self.alias(source).cloned() else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let (alias, update) = match source_alias.presence {
            DescriptorPresence::Absent => return Ok(DescriptorUpdate::Uncertain),
            DescriptorPresence::Present => (source_alias, DescriptorUpdate::Exact),
            DescriptorPresence::Maybe => {
                let prior = self.alias(target).cloned();
                let ids = merged_set(
                    &source_alias.ids,
                    prior
                        .as_ref()
                        .map_or([].as_slice(), |alias| alias.ids.as_slice()),
                )?;
                (
                    DescriptorAlias {
                        presence: if prior
                            .is_some_and(|alias| alias.presence == DescriptorPresence::Present)
                        {
                            DescriptorPresence::Present
                        } else {
                            DescriptorPresence::Maybe
                        },
                        ids,
                    },
                    DescriptorUpdate::Uncertain,
                )
            }
        };
        let mut candidate = self.clone();
        candidate.set_alias_unchecked(target, alias);
        candidate.ensure_bounded()?;
        *self = candidate;
        Ok(update)
    }

    /// Forgets only the variable-to-id mapping; descriptor facts remain until
    /// the descriptor itself is closed or rebound.
    pub(crate) fn unset_alias(&mut self, name: &str) -> bool {
        let Ok(index) = self
            .aliases
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(name))
        else {
            return false;
        };
        self.aliases.remove(index);
        true
    }

    /// Installs the Bash coprocess scalar/array identity convention. The caller
    /// supplies globally unique ids and binds their facts separately.
    pub(crate) fn set_coprocess_aliases(
        &mut self,
        name: &str,
        producer: SymbolicDescriptorId,
        consumer: SymbolicDescriptorId,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        if name.is_empty() {
            return Ok(DescriptorUpdate::Uncertain);
        }
        let mut candidate = self.clone();
        for (alias, id) in [
            (name.to_owned(), producer),
            (format!("{name}[0]"), producer),
            (format!("{name}[1]"), consumer),
        ] {
            candidate.set_alias_unchecked(
                &alias,
                DescriptorAlias {
                    presence: DescriptorPresence::Present,
                    ids: vec![id],
                },
            );
        }
        candidate.ensure_bounded()?;
        *self = candidate;
        Ok(DescriptorUpdate::Exact)
    }

    /// Replaces all retained capabilities for one descriptor.
    #[cfg(test)]
    pub(crate) fn rebind(
        &mut self,
        descriptor: &str,
        facts: DescriptorFacts,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        let Some(descriptor) = canonical_descriptor_fd(descriptor) else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let mut candidate = self.clone();
        candidate.remove(&descriptor);
        candidate.insert(
            descriptor,
            DescriptorSlot {
                presence: DescriptorPresence::Present,
                facts,
            },
        );
        candidate.ensure_bounded()?;
        *self = candidate;
        Ok(DescriptorUpdate::Exact)
    }

    /// Copies the source snapshot to the target without aliasing future changes.
    ///
    /// An uncertain source unions its facts with the old target because the
    /// redirect succeeds on one branch and leaves the target alone on another.
    #[cfg(test)]
    pub(crate) fn duplicate(
        &mut self,
        target: &str,
        source: &str,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        if let Some(alias) = allocated_descriptor_name(source) {
            return self.duplicate_alias(target, alias);
        }
        let Some(target) = canonical_descriptor_fd(target) else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let Some(source) = canonical_descriptor_fd(source) else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let mut candidate = self.clone();
        let update = candidate.duplicate_canonical(&target, &source)?;
        candidate.ensure_bounded()?;
        *self = candidate;
        Ok(update)
    }

    #[cfg(test)]
    pub(crate) fn duplicate_alias(
        &mut self,
        target: &str,
        source: &str,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        let Some(target) = canonical_descriptor_fd(target) else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let Some(source_slot) = self.resolved_alias_slot(source)? else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let mut candidate = self.clone();
        let update = candidate.duplicate_slot(&target, source_slot)?;
        candidate.ensure_bounded()?;
        *self = candidate;
        Ok(update)
    }

    #[cfg(test)]
    fn duplicate_canonical(
        &mut self,
        target: &str,
        source: &str,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        let Some(source_slot) = self.slot(source).cloned() else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        self.duplicate_slot(target, source_slot)
    }

    pub(crate) fn duplicate_slot(
        &mut self,
        target: &str,
        source_slot: DescriptorSlot,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        let (slot, update) = match source_slot.presence {
            DescriptorPresence::Absent => return Ok(DescriptorUpdate::Uncertain),
            DescriptorPresence::Present => (source_slot, DescriptorUpdate::Exact),
            DescriptorPresence::Maybe => {
                let prior = self.slot(target).cloned();
                let mut facts = source_slot.facts;
                if let Some(prior) = &prior {
                    facts.merge(&prior.facts)?;
                }
                (
                    DescriptorSlot {
                        presence: if prior
                            .is_some_and(|prior| prior.presence == DescriptorPresence::Present)
                        {
                            DescriptorPresence::Present
                        } else {
                            DescriptorPresence::Maybe
                        },
                        facts,
                    },
                    DescriptorUpdate::Uncertain,
                )
            }
        };
        self.remove(target);
        self.insert(target.to_owned(), slot);
        Ok(update)
    }

    /// Duplicates first, then closes the source, matching Bash move redirects.
    #[cfg(test)]
    pub(crate) fn move_binding(
        &mut self,
        target: &str,
        source: &str,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        if let Some(alias) = allocated_descriptor_name(source) {
            return self.move_alias(target, alias);
        }
        let Some(target) = canonical_descriptor_fd(target) else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let Some(source) = canonical_descriptor_fd(source) else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let mut candidate = self.clone();
        let update = candidate.duplicate_canonical(&target, &source)?;
        candidate.remove(&source);
        candidate.ensure_bounded()?;
        *self = candidate;
        Ok(update)
    }

    #[cfg(test)]
    pub(crate) fn move_alias(
        &mut self,
        target: &str,
        source: &str,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        let Some(target) = canonical_descriptor_fd(target) else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let Some(alias) = self.alias(source).cloned() else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let Some(source_slot) = self.resolved_alias_slot(source)? else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let mut candidate = self.clone();
        let mut update = candidate.duplicate_slot(&target, source_slot)?;
        if alias.presence == DescriptorPresence::Present && alias.ids.len() == 1 {
            candidate.remove(&symbolic_descriptor_key(alias.ids[0]));
        } else {
            update = DescriptorUpdate::Uncertain;
            candidate.mark_symbolic_maybe(&alias.ids);
        }
        candidate.ensure_bounded()?;
        *self = candidate;
        Ok(update)
    }

    #[cfg(test)]
    pub(crate) fn close(
        &mut self,
        descriptor: &str,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        if let Some(alias) = allocated_descriptor_name(descriptor) {
            return self.close_alias(alias);
        }
        let Some(descriptor) = canonical_descriptor_fd(descriptor) else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        self.remove(&descriptor);
        Ok(DescriptorUpdate::Exact)
    }

    pub(crate) fn close_alias(
        &mut self,
        name: &str,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        let Some(alias) = self.alias(name).cloned() else {
            return Ok(DescriptorUpdate::Uncertain);
        };
        let mut candidate = self.clone();
        let update = if alias.presence == DescriptorPresence::Present && alias.ids.len() == 1 {
            candidate.remove(&symbolic_descriptor_key(alias.ids[0]));
            DescriptorUpdate::Exact
        } else {
            candidate.mark_symbolic_maybe(&alias.ids);
            DescriptorUpdate::Uncertain
        };
        candidate.ensure_bounded()?;
        *self = candidate;
        Ok(update)
    }

    pub(crate) fn bind_allocated_slot_unchecked(
        &mut self,
        variable: &str,
        id: SymbolicDescriptorId,
        source: DescriptorSlot,
    ) -> Result<DescriptorUpdate, DescriptorRefusal> {
        let mut alias = DescriptorAlias {
            presence: source.presence,
            ids: vec![id],
        };
        if source.presence == DescriptorPresence::Maybe
            && let Some(prior) = self.alias(variable).cloned()
        {
            alias.ids = merged_set(&alias.ids, &prior.ids)?;
            if prior.presence == DescriptorPresence::Present {
                alias.presence = DescriptorPresence::Present;
            }
        }
        self.rebind_symbolic_unchecked(id, source.facts);
        if source.presence == DescriptorPresence::Maybe
            && let Some(slot) = self
                .bindings
                .iter_mut()
                .find_map(|(key, slot)| (key == &symbolic_descriptor_key(id)).then_some(slot))
        {
            slot.presence = DescriptorPresence::Maybe;
        }
        self.set_alias_unchecked(variable, alias);
        Ok(if source.presence == DescriptorPresence::Present {
            DescriptorUpdate::Exact
        } else {
            DescriptorUpdate::Uncertain
        })
    }

    /// Joins possible branch states without discarding provenance.
    pub(crate) fn merge(states: &[Self]) -> Result<Self, DescriptorRefusal> {
        let mut merged = Self {
            bindings: Vec::new(),
            aliases: Vec::new(),
        };
        for state in states {
            for (descriptor, slot) in &state.bindings {
                match merged
                    .bindings
                    .binary_search_by(|(candidate, _)| candidate.cmp(descriptor))
                {
                    Ok(index) => merged.bindings[index].1.facts.merge(&slot.facts)?,
                    Err(index) => merged
                        .bindings
                        .insert(index, (descriptor.clone(), slot.clone())),
                }
            }
        }
        for (descriptor, slot) in &mut merged.bindings {
            if states.iter().any(|state| {
                state
                    .slot(descriptor)
                    .is_none_or(|candidate| candidate.presence != DescriptorPresence::Present)
            }) {
                slot.presence = DescriptorPresence::Maybe;
            }
        }
        for state in states {
            for (name, alias) in &state.aliases {
                match merged
                    .aliases
                    .binary_search_by(|(candidate, _)| candidate.cmp(name))
                {
                    Ok(index) => {
                        merged.aliases[index].1.ids =
                            merged_set(&merged.aliases[index].1.ids, &alias.ids)?;
                    }
                    Err(index) => {
                        merged.aliases.insert(index, (name.clone(), alias.clone()));
                    }
                }
            }
        }
        for (name, alias) in &mut merged.aliases {
            if states.iter().any(|state| {
                state
                    .alias(name)
                    .is_none_or(|candidate| candidate.presence != DescriptorPresence::Present)
            }) {
                alias.presence = DescriptorPresence::Maybe;
            }
        }
        merged.ensure_bounded()?;
        Ok(merged)
    }

    pub(crate) fn alias(&self, name: &str) -> Option<&DescriptorAlias> {
        self.aliases
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(name))
            .ok()
            .map(|index| &self.aliases[index].1)
    }

    pub(crate) fn resolved_alias_slot(
        &self,
        name: &str,
    ) -> Result<Option<DescriptorSlot>, DescriptorRefusal> {
        let Some(alias) = self.alias(name) else {
            return Ok(None);
        };
        let mut facts: Option<DescriptorFacts> = None;
        let mut presence = alias.presence;
        let mut found = false;
        for id in &alias.ids {
            let Some(slot) = self.slot(&symbolic_descriptor_key(*id)) else {
                presence = DescriptorPresence::Maybe;
                continue;
            };
            found = true;
            if let Some(facts) = &mut facts {
                facts.merge(&slot.facts)?;
            } else {
                facts = Some(slot.facts.clone());
            }
            if slot.presence != DescriptorPresence::Present {
                presence = DescriptorPresence::Maybe;
            }
        }
        if !found {
            presence = DescriptorPresence::Absent;
        }
        Ok(Some(DescriptorSlot {
            presence,
            facts: facts.unwrap_or_default(),
        }))
    }

    pub(crate) fn slot(&self, descriptor: &str) -> Option<&DescriptorSlot> {
        let descriptor = if descriptor.starts_with(SYMBOLIC_DESCRIPTOR_PREFIX) {
            descriptor.to_owned()
        } else {
            canonical_descriptor_fd(descriptor)?
        };
        self.bindings
            .binary_search_by(|(candidate, _)| candidate.cmp(&descriptor))
            .ok()
            .map(|index| &self.bindings[index].1)
    }

    fn rebind_symbolic_unchecked(&mut self, id: SymbolicDescriptorId, facts: DescriptorFacts) {
        let descriptor = symbolic_descriptor_key(id);
        self.remove(&descriptor);
        self.insert(
            descriptor,
            DescriptorSlot {
                presence: DescriptorPresence::Present,
                facts,
            },
        );
    }

    fn set_alias_unchecked(&mut self, name: &str, alias: DescriptorAlias) {
        match self
            .aliases
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(name))
        {
            Ok(index) => self.aliases[index].1 = alias,
            Err(index) => self.aliases.insert(index, (name.to_owned(), alias)),
        }
    }

    pub(crate) fn mark_symbolic_maybe(&mut self, ids: &[SymbolicDescriptorId]) {
        for id in ids {
            if let Some(slot) = self
                .bindings
                .iter_mut()
                .find_map(|(key, slot)| (key == &symbolic_descriptor_key(*id)).then_some(slot))
            {
                slot.presence = DescriptorPresence::Maybe;
            }
        }
    }

    pub(crate) fn mark_all_maybe(&mut self) {
        for (_, slot) in &mut self.bindings {
            slot.presence = DescriptorPresence::Maybe;
        }
    }

    pub(crate) fn insert(&mut self, descriptor: String, slot: DescriptorSlot) {
        match self
            .bindings
            .binary_search_by(|(candidate, _)| candidate.cmp(&descriptor))
        {
            Ok(index) => self.bindings[index].1 = slot,
            Err(index) => self.bindings.insert(index, (descriptor, slot)),
        }
    }

    pub(crate) fn remove(&mut self, descriptor: &str) -> bool {
        let Ok(index) = self
            .bindings
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(descriptor))
        else {
            return false;
        };
        self.bindings.remove(index);
        true
    }

    pub(crate) fn ensure_bounded(&self) -> Result<(), DescriptorRefusal> {
        let hosts = self
            .bindings
            .iter()
            .map(|(_, slot)| slot.facts.hosts.len())
            .sum::<usize>();
        let producer_sources = self
            .bindings
            .iter()
            .map(|(_, slot)| slot.facts.producer_sources.len())
            .sum::<usize>();
        let consumer_sinks = self
            .bindings
            .iter()
            .map(|(_, slot)| slot.facts.consumer_sinks.len())
            .sum::<usize>();
        let aliases = self
            .aliases
            .iter()
            .map(|(_, alias)| alias.ids.len())
            .sum::<usize>();
        let write_targets = self
            .bindings
            .iter()
            .map(|(_, slot)| slot.facts.write_targets.len())
            .sum::<usize>();
        let write_target_bytes = self
            .bindings
            .iter()
            .flat_map(|(_, slot)| &slot.facts.write_targets)
            .map(String::len)
            .sum::<usize>();
        let content_bytes = self
            .bindings
            .iter()
            .map(|(_, slot)| slot.facts.exact_content().map_or(0, str::len))
            .sum::<usize>();
        if [hosts, producer_sources, consumer_sinks]
            .into_iter()
            .any(|facts| facts > MAX_DESCRIPTOR_FACTS)
            || aliases > MAX_DESCRIPTOR_FACTS
            || write_targets > MAX_DESCRIPTOR_FACTS
            || write_target_bytes > crate::INVOCATION_EVIDENCE_CAP
            || content_bytes > crate::INVOCATION_EVIDENCE_CAP
        {
            return Err(DescriptorRefusal::Saturated);
        }
        Ok(())
    }
}

pub(crate) fn allocated_descriptor_name(descriptor: &str) -> Option<&str> {
    let name = descriptor.strip_prefix('{')?.strip_suffix('}')?;
    (!name.is_empty() && !name.contains(['{', '}'])).then_some(name)
}

pub(crate) fn symbolic_descriptor_key(id: SymbolicDescriptorId) -> String {
    format!("{SYMBOLIC_DESCRIPTOR_PREFIX}{}", id.0)
}

fn bounded_set<T: Ord>(mut values: Vec<T>) -> Result<Vec<T>, DescriptorRefusal> {
    values.sort();
    values.dedup();
    if values.len() > MAX_DESCRIPTOR_FACTS {
        return Err(DescriptorRefusal::Saturated);
    }
    Ok(values)
}

fn merged_set<T: Clone + Ord>(left: &[T], right: &[T]) -> Result<Vec<T>, DescriptorRefusal> {
    bounded_set(left.iter().chain(right).cloned().collect())
}

#[cfg(test)]
mod tests;
