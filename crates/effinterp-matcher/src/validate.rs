//! Query validation: the schema versions, nesting and work limits a query must
//! satisfy before any plan is read.

use effinterp_proto::AttrValue;

use crate::query::{
    Absence, Assertion, AttributeTest, BINDING_SCHEMA_VERSION, BoundaryDomainsPredicate,
    COMPATIBLE_SCHEMA_VERSIONS, COVERAGE_SCHEMA_VERSION, Closure, ConditionPredicate,
    EffectRelationship, ElementTest, Endpoint, PLAN_ORDER_SCHEMA_VERSION, PortScope, Query,
    Refusal, ResourcePredicate, ResourceVariant, SCHEMA_VERSION, SELECTION_SCHEMA_VERSION,
    Selector, Traversal,
};

impl Query {
    pub fn new(assertion: Assertion) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            assertion,
        }
    }

    /// Reject a query whose meaning is undefined before any plan is read,
    /// for evaluation under each effect assertion's own closure.
    pub fn validate(&self) -> Result<(), Refusal> {
        self.validate_for(Absence::Closure)
    }

    /// Reject a query whose meaning is undefined under `absence` before any
    /// plan is read.
    pub fn validate_for(&self, absence: Absence) -> Result<(), Refusal> {
        self.validate_with(QueryLimits::default(), absence)
    }

    pub fn validate_with_limits(&self, limits: QueryLimits) -> Result<(), Refusal> {
        self.validate_with(limits, Absence::Closure)
    }

    pub(crate) fn validate_with(
        &self,
        limits: QueryLimits,
        absence: Absence,
    ) -> Result<(), Refusal> {
        if self.schema_version != SCHEMA_VERSION
            && !COMPATIBLE_SCHEMA_VERSIONS.contains(&self.schema_version)
        {
            return Err(Refusal::UnsupportedVersion(self.schema_version));
        }
        Self::validate_assertion(
            &self.assertion,
            self.schema_version,
            &[],
            0,
            limits,
            &mut Budget(limits.max_steps),
        )?;
        Self::validate_closures(&self.assertion, absence)
    }

    fn validate_closure_domain(closure: Option<&Closure>) -> Result<(), Refusal> {
        match closure {
            Some(Closure::DomainFullOrBoundaryFree { domain }) if domain.is_empty() => {
                Err(Refusal::InvalidInput("closure domain"))
            }
            _ => Ok(()),
        }
    }

    /// Every effect assertion declares a closure exactly when `absence` reads
    /// it. Runs after the nesting depth is validated.
    fn validate_closures(assertion: &Assertion, absence: Absence) -> Result<(), Refusal> {
        let closure = match assertion {
            Assertion::All { assertions } | Assertion::Any { assertions } => {
                return assertions
                    .iter()
                    .try_for_each(|assertion| Self::validate_closures(assertion, absence));
            }
            Assertion::Not { assertion } => return Self::validate_closures(assertion, absence),
            Assertion::BindEffect {
                closure, assertion, ..
            } => {
                Self::validate_closures(assertion, absence)?;
                closure
            }
            Assertion::Effect { closure, .. } | Assertion::RelatedEffect { closure, .. } => closure,
            Assertion::Flow { .. }
            | Assertion::SubjectKind { .. }
            | Assertion::Coverage { .. }
            | Assertion::TransferDestinations { .. }
            | Assertion::Boundary { .. } => return Ok(()),
        };
        match (absence, closure) {
            (Absence::Closure, Some(_)) | (Absence::Conclusive, None) => Ok(()),
            (Absence::Closure, None) => Err(Refusal::InvalidInput("effect closure required")),
            (Absence::Conclusive, Some(_)) => Err(Refusal::InvalidInput(
                "effect closure under conclusive absence",
            )),
        }
    }

    fn validate_assertion(
        assertion: &Assertion,
        schema_version: u32,
        bindings: &[String],
        depth: usize,
        limits: QueryLimits,
        budget: &mut Budget,
    ) -> Result<(), Refusal> {
        budget.charge()?;
        if depth > limits.max_assertion_depth {
            return Err(Refusal::InvalidInput("assertion nesting depth"));
        }
        match assertion {
            Assertion::All { assertions } | Assertion::Any { assertions } => {
                if assertions.is_empty() {
                    return Err(Refusal::InvalidInput("empty boolean assertion"));
                }
                for assertion in assertions {
                    Self::validate_assertion(
                        assertion,
                        schema_version,
                        bindings,
                        depth + 1,
                        limits,
                        budget,
                    )?;
                }
                Ok(())
            }
            Assertion::Not { assertion } => Self::validate_assertion(
                assertion,
                schema_version,
                bindings,
                depth + 1,
                limits,
                budget,
            ),
            Assertion::Effect {
                selector: inner,
                closure,
            } => {
                Self::validate_selector(inner, schema_version, limits, budget)?;
                Self::validate_closure_domain(closure.as_ref())?;
                Ok(())
            }
            Assertion::BindEffect {
                name,
                selector,
                closure,
                assertion,
                related,
            } => {
                if schema_version < BINDING_SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "effect binding requires schema version 3",
                    ));
                }
                if name.is_empty() || bindings.contains(name) {
                    return Err(Refusal::InvalidInput("effect binding name"));
                }
                if let Some(related) = related {
                    if schema_version < PLAN_ORDER_SCHEMA_VERSION {
                        return Err(Refusal::InvalidInput(
                            "related effect binding requires schema version 5",
                        ));
                    }
                    Self::validate_relationship(
                        &related.binding,
                        related.relationship,
                        schema_version,
                        bindings,
                    )?;
                }
                Self::validate_selector(selector, schema_version, limits, budget)?;
                Self::validate_closure_domain(closure.as_ref())?;
                let mut nested = bindings.to_vec();
                nested.push(name.clone());
                Self::validate_assertion(
                    assertion,
                    schema_version,
                    &nested,
                    depth + 1,
                    limits,
                    budget,
                )
            }
            Assertion::RelatedEffect {
                binding,
                relationship,
                selector,
                closure,
            } => {
                if schema_version < BINDING_SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "related effect requires schema version 3",
                    ));
                }
                Self::validate_relationship(binding, *relationship, schema_version, bindings)?;
                Self::validate_selector(selector, schema_version, limits, budget)?;
                Self::validate_closure_domain(closure.as_ref())?;
                Ok(())
            }
            Assertion::Flow {
                source,
                destination,
                traversal,
                ..
            } => {
                if let Traversal::ByteFlow { edges, .. } = traversal {
                    if schema_version < BINDING_SCHEMA_VERSION {
                        return Err(Refusal::InvalidInput(
                            "byte-flow traversal requires schema version 3",
                        ));
                    }
                    if edges.is_empty()
                        || edges
                            .iter()
                            .enumerate()
                            .any(|(index, edge)| edges[..index].contains(edge))
                    {
                        return Err(Refusal::InvalidInput("byte-flow edge allowlist"));
                    }
                }
                Self::validate_endpoint(source, schema_version, bindings, limits, budget)?;
                Self::validate_endpoint(destination, schema_version, bindings, limits, budget)?;
                if !matches!(traversal, Traversal::ByteFlow { .. })
                    && [source, destination]
                        .iter()
                        .any(|endpoint| matches!(endpoint, Endpoint::Port { .. }))
                {
                    return Err(Refusal::InvalidInput(
                        "port endpoint outside a byte-flow traversal",
                    ));
                }
                if *traversal == Traversal::ResourcePairs
                    && [source, destination]
                        .iter()
                        .any(|endpoint| matches!(endpoint, Endpoint::Value(_)))
                {
                    return Err(Refusal::InvalidInput(
                        "resource-pair traversal between value occurrences",
                    ));
                }
                Ok(())
            }
            Assertion::SubjectKind { kinds } => {
                if schema_version < SELECTION_SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "subject-kind assertion requires schema version 4",
                    ));
                }
                if kinds.is_empty()
                    || kinds
                        .iter()
                        .enumerate()
                        .any(|(index, kind)| kinds[..index].contains(kind))
                {
                    return Err(Refusal::InvalidInput("subject-kind set"));
                }
                Ok(())
            }
            Assertion::Coverage { domain } => {
                if schema_version < COVERAGE_SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "coverage assertion requires schema version 6",
                    ));
                }
                if domain.is_empty() {
                    return Err(Refusal::InvalidInput("coverage domain"));
                }
                Ok(())
            }
            Assertion::TransferDestinations {
                binding,
                destination,
                ..
            } => {
                if schema_version < COVERAGE_SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "transfer-destination assertion requires schema version 6",
                    ));
                }
                if !bindings.contains(binding) {
                    return Err(Refusal::InvalidInput("unbound transfer source"));
                }
                Self::validate_resource(destination, schema_version, 0, limits, budget)
            }
            Assertion::Boundary {
                reason, domains, ..
            } => {
                if reason.is_empty() {
                    return Err(Refusal::InvalidInput("boundary reason"));
                }
                if let Some(domains) = domains {
                    let values = match domains {
                        BoundaryDomainsPredicate::AllOf(values)
                        | BoundaryDomainsPredicate::AnyOf(values) => values,
                    };
                    if values.is_empty()
                        || values.iter().any(|domain| domain.0.is_empty())
                        || values
                            .iter()
                            .enumerate()
                            .any(|(index, domain)| values[..index].contains(domain))
                    {
                        return Err(Refusal::InvalidInput("boundary domain set"));
                    }
                    for _ in values {
                        budget.charge()?;
                    }
                }
                Ok(())
            }
        }
    }

    fn validate_endpoint(
        endpoint: &Endpoint,
        schema_version: u32,
        bindings: &[String],
        limits: QueryLimits,
        budget: &mut Budget,
    ) -> Result<(), Refusal> {
        match endpoint {
            Endpoint::Interaction(selector) => {
                Self::validate_selector(selector, schema_version, limits, budget)
            }
            Endpoint::Value(_) => Ok(()),
            Endpoint::EffectBinding { name } => {
                if schema_version < BINDING_SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "bound flow endpoint requires schema version 3",
                    ));
                }
                if !bindings.contains(name) {
                    return Err(Refusal::InvalidInput("unbound flow endpoint"));
                }
                Ok(())
            }
            Endpoint::Port { scope, .. } => {
                if schema_version < SELECTION_SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "port flow endpoint requires schema version 4",
                    ));
                }
                match scope {
                    PortScope::SameExecution { binding } if !bindings.contains(binding) => {
                        Err(Refusal::InvalidInput("unbound port scope"))
                    }
                    _ => Ok(()),
                }
            }
        }
    }

    fn validate_relationship(
        binding: &str,
        relationship: EffectRelationship,
        schema_version: u32,
        bindings: &[String],
    ) -> Result<(), Refusal> {
        if !bindings.iter().any(|bound| bound == binding) {
            return Err(Refusal::InvalidInput("unbound effect reference"));
        }
        if relationship.same_resource && schema_version < SELECTION_SCHEMA_VERSION {
            return Err(Refusal::InvalidInput(
                "same-resource relationship requires schema version 4",
            ));
        }
        if relationship.after && schema_version < PLAN_ORDER_SCHEMA_VERSION {
            return Err(Refusal::InvalidInput(
                "plan-order relationship requires schema version 5",
            ));
        }
        if !relationship.same_execution
            && !relationship.same_realm
            && !relationship.same_resource
            && !relationship.after
        {
            return Err(Refusal::InvalidInput("empty effect relationship"));
        }
        Ok(())
    }

    fn validate_selector(
        selector: &Selector,
        schema_version: u32,
        limits: QueryLimits,
        budget: &mut Budget,
    ) -> Result<(), Refusal> {
        let name = selector.operation.name();
        if name.is_empty() || name.split('.').any(str::is_empty) {
            return Err(Refusal::InvalidInput("operation name"));
        }
        for attribute in &selector.attributes {
            if attribute.name.is_empty() {
                return Err(Refusal::InvalidInput("attribute name"));
            }
            if let AttributeTest::OneOf(values)
            | AttributeTest::AnyElement(ElementTest::OneOf(values))
            | AttributeTest::AllElements(ElementTest::OneOf(values)) = &attribute.test
                && (values.is_empty()
                    || values
                        .iter()
                        .enumerate()
                        .any(|(index, value)| values[..index].contains(value)))
            {
                return Err(Refusal::InvalidInput("attribute set"));
            }
            if let AttributeTest::AnyElement(test) | AttributeTest::AllElements(test) =
                &attribute.test
            {
                if schema_version < SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "list element predicate requires schema version 7",
                    ));
                }
                // A list element is a scalar, so a list-valued element test
                // could never pass.
                if match test {
                    ElementTest::Equals(value) => matches!(value, AttrValue::List(_)),
                    ElementTest::OneOf(values) => values
                        .iter()
                        .any(|value| matches!(value, AttrValue::List(_))),
                    ElementTest::Text(_) => false,
                } {
                    return Err(Refusal::InvalidInput("list element value"));
                }
            }
            if matches!(attribute.test, AttributeTest::Text(_))
                && schema_version < BINDING_SCHEMA_VERSION
            {
                return Err(Refusal::InvalidInput(
                    "text attribute predicate requires schema version 3",
                ));
            }
        }
        if selector.condition == Some(ConditionPredicate::Complete)
            && schema_version < SCHEMA_VERSION
        {
            return Err(Refusal::InvalidInput(
                "complete condition predicate requires schema version 7",
            ));
        }
        Self::validate_resource(&selector.resource, schema_version, 0, limits, budget)
    }

    fn validate_resource(
        predicate: &ResourcePredicate,
        schema_version: u32,
        depth: usize,
        limits: QueryLimits,
        budget: &mut Budget,
    ) -> Result<(), Refusal> {
        budget.charge()?;
        if depth > limits.max_resource_depth {
            return Err(Refusal::InvalidInput("resource predicate nesting depth"));
        }
        match predicate {
            ResourcePredicate::All { predicates } | ResourcePredicate::AnyOf { predicates } => {
                if predicates.is_empty() {
                    return Err(Refusal::InvalidInput("empty resource predicate"));
                }
                for predicate in predicates {
                    Self::validate_resource(predicate, schema_version, depth + 1, limits, budget)?;
                }
                Ok(())
            }
            ResourcePredicate::Not { predicate } => {
                Self::validate_resource(predicate, schema_version, depth + 1, limits, budget)
            }
            ResourcePredicate::GitTreePathLabel { .. }
                if schema_version < SELECTION_SCHEMA_VERSION =>
            {
                Err(Refusal::InvalidInput(
                    "Git tree-path label requires schema version 4",
                ))
            }
            ResourcePredicate::ObservedPath { observation, .. } => {
                if schema_version < COVERAGE_SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "observed path kind requires schema version 6",
                    ));
                }
                if observation.0.is_empty() {
                    return Err(Refusal::InvalidInput("label observation binding"));
                }
                Ok(())
            }
            ResourcePredicate::Label { observation, .. }
            | ResourcePredicate::InheritedLabel { observation, .. }
            | ResourcePredicate::GitTreePathLabel { observation, .. } => {
                if schema_version < BINDING_SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "label predicate requires schema version 3",
                    ));
                }
                if observation.0.is_empty() {
                    return Err(Refusal::InvalidInput("label observation binding"));
                }
                Ok(())
            }
            ResourcePredicate::Variant {
                variant: ResourceVariant::CredentialStore { provider },
            } => {
                if schema_version < BINDING_SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "credential-store identity requires schema version 3",
                    ));
                }
                if provider.is_empty() {
                    return Err(Refusal::InvalidInput("credential-store provider"));
                }
                Ok(())
            }
            ResourcePredicate::Variant {
                variant: ResourceVariant::EnvironmentVariable { name },
            } => {
                if schema_version < BINDING_SCHEMA_VERSION {
                    return Err(Refusal::InvalidInput(
                        "environment-variable identity requires schema version 3",
                    ));
                }
                if name.is_empty() {
                    return Err(Refusal::InvalidInput("environment-variable name"));
                }
                Ok(())
            }
            ResourcePredicate::Family { family } if family.is_empty() => {
                Err(Refusal::InvalidInput("resource family"))
            }
            ResourcePredicate::StorageVolume { manager, name }
                if manager.is_none() && name.is_none() =>
            {
                Err(Refusal::InvalidInput("storage-volume fields"))
            }
            ResourcePredicate::KubernetesResource {
                namespace,
                selection,
            } if namespace.is_none() && selection.is_none() => {
                Err(Refusal::InvalidInput("Kubernetes resource fields"))
            }
            ResourcePredicate::CloudResource {
                provider,
                service,
                kind,
            } if provider.is_none() && service.is_none() && kind.is_none() => {
                Err(Refusal::InvalidInput("cloud-resource fields"))
            }
            _ => Ok(()),
        }
    }
}

/// Work and nesting limits for validating and evaluating one matcher query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryLimits {
    /// Each effect, boundary, occurrence or reachable pair examined and each
    /// route searched costs one step.
    pub max_steps: usize,
    /// Maximum nesting below the root assertion.
    pub max_assertion_depth: usize,
    /// Maximum nesting below the root resource predicate.
    pub max_resource_depth: usize,
    /// Maximum nesting below the root effect condition.
    pub max_condition_depth: usize,
}

impl Default for QueryLimits {
    fn default() -> Self {
        Self {
            max_steps: 1 << 20,
            max_assertion_depth: 32,
            max_resource_depth: 32,
            max_condition_depth: 16,
        }
    }
}

/// The work steps one validation or evaluation may still spend.
pub(crate) struct Budget(pub(crate) usize);

impl Budget {
    pub(crate) fn charge(&mut self) -> Result<(), Refusal> {
        self.0 = self.0.checked_sub(1).ok_or(Refusal::WorkLimit)?;
        Ok(())
    }
}
