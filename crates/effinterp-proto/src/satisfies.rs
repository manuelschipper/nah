use crate::{
    ExecutionRealm, PathPlatform, ResourceExpr, ResourceIdentity, ResourcePattern, Subject,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const RELATION_WORK_LIMIT: usize = 1_048_576;
pub const RELATION_BYTE_LIMIT: usize = 1_048_576;
pub const RELATION_DEPTH_LIMIT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BindingSource {
    Declared,
    Observed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub value: String,
    pub source: BindingSource,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
    pub platform: PathPlatform,
    pub cwd: Option<Binding>,
    pub env: BTreeMap<String, Binding>,
}
impl Bindings {
    pub fn none(platform: PathPlatform) -> Self {
        Self {
            platform,
            cwd: None,
            env: BTreeMap::new(),
        }
    }
    /// Copy only supplied invocation context; never consult the current host.
    pub fn from_subject(subject: &Subject) -> Self {
        let (cwd, context) = match subject {
            Subject::Exec { cwd, context, .. }
            | Subject::Shell { cwd, context, .. }
            | Subject::Source { cwd, context, .. }
            | Subject::ToolCall { cwd, context, .. } => (cwd, context),
            Subject::Sql { .. } => return Self::none(PathPlatform::Posix),
        };
        let declared = |value: &String| Binding {
            value: value.clone(),
            source: BindingSource::Declared,
        };
        Self {
            platform: PathPlatform::Posix,
            cwd: cwd.as_ref().map(declared),
            env: context
                .env
                .iter()
                .map(|(name, value)| (name.clone(), declared(value)))
                .collect(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedIdentity {
    #[serde(default)]
    pub realm: ExecutionRealm,
    pub identity: ResourceIdentity,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedExpr {
    #[serde(default)]
    pub realm: ExecutionRealm,
    pub expr: ResourceExpr,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(deserialize_with = "required_scope_realm")]
    pub realm: Option<ExecutionRealm>,
    pub set: ScopeSet,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeSet {
    Exact { identity: ResourceIdentity },
    Pattern { pattern: ResourcePattern },
    FsSubtree { root: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProofStep {
    Binding { name: String, source: BindingSource },
    Pattern,
    RecursiveExtent,
    Alternative { index: usize },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub steps: Vec<ProofStep>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MatchReason {
    Unbound { names: Vec<String> },
    UnresolvedFamily,
    UnsupportedShape,
    UnderqualifiedFields,
    UnderqualifiedRealm,
    TruncatedArgv,
    InvalidInput,
    Limit,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Match {
    Satisfied { proof: Proof },
    NotSatisfied,
    Indeterminate { reason: MatchReason },
}
/// A resource relation: compares one resource expression with a concrete
/// identity or scope, exactly as supplied. It knows no operation, so it has no
/// recursive extent, and a filesystem subtree root must be absolute. To ask
/// whether an effect reaches a resource, use [`EffectQuery`] instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelationRequest {
    Satisfies {
        concrete: QualifiedIdentity,
        expr: QualifiedExpr,
        bindings: Bindings,
    },
    Contains {
        scope: Scope,
        expr: QualifiedExpr,
        bindings: Bindings,
    },
    Intersects {
        scope: Scope,
        expr: QualifiedExpr,
        bindings: Bindings,
    },
}
impl RelationRequest {
    pub fn validate(&self) -> Result<(), MatchReason> {
        let mut budget = Budget::default();
        match self {
            Self::Satisfies {
                concrete,
                expr,
                bindings,
            } => {
                budget.identity(&concrete.identity, 0)?;
                budget.expr(&expr.expr, 0)?;
                budget.serialized(bindings)?;
                budget.serialized(&concrete.realm)?;
                budget.serialized(&expr.realm)?;
            }
            Self::Contains {
                scope,
                expr,
                bindings,
            }
            | Self::Intersects {
                scope,
                expr,
                bindings,
            } => {
                budget.expr(&expr.expr, 0)?;
                budget.serialized(bindings)?;
                budget.serialized(&scope.realm)?;
                budget.serialized(&expr.realm)?;
                match &scope.set {
                    ScopeSet::Exact { identity } => budget.identity(identity, 0)?,
                    ScopeSet::Pattern { pattern } => budget.pattern(pattern, 0)?,
                    ScopeSet::FsSubtree { root } => {
                        budget.charge(root.len(), root.len())?;
                        if !crate::is_absolute_path(root, bindings.platform) {
                            return Err(MatchReason::InvalidInput);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    pub fn evaluate(&self) -> Match {
        match self {
            Self::Satisfies {
                concrete,
                expr,
                bindings,
            } => satisfies(concrete, expr, bindings),
            Self::Contains {
                scope,
                expr,
                bindings,
            } => relation(scope, expr, bindings, true),
            Self::Intersects {
                scope,
                expr,
                bindings,
            } => scope_intersects(scope, expr, bindings),
        }
    }
}
/// Borrowed effect target. Optional proof dimensions are absent only when the
/// source representation does not carry them, such as a causal occurrence.
#[derive(Debug, Clone, Copy)]
pub struct EffectTarget<'a> {
    pub operation: &'a crate::Operation,
    pub resource: &'a ResourceExpr,
    pub attributes: &'a BTreeMap<String, crate::AttrValue>,
    pub realm: &'a ExecutionRealm,
    pub modality: Option<crate::Modality>,
    pub request_assurance: Option<crate::RequestAssurance>,
    pub condition: Option<&'a Option<crate::Condition>>,
    pub execution_assurance: Option<crate::ExecutionAssurance>,
}
impl<'a> From<&'a crate::Effect> for EffectTarget<'a> {
    fn from(effect: &'a crate::Effect) -> Self {
        Self {
            operation: &effect.operation,
            resource: &effect.resource,
            attributes: &effect.attributes,
            realm: &effect.realm,
            modality: Some(effect.modality),
            request_assurance: Some(effect.request_assurance),
            condition: Some(&effect.condition),
            execution_assurance: None,
        }
    }
}
impl<'a> From<&'a crate::EffectFact> for EffectTarget<'a> {
    fn from(effect: &'a crate::EffectFact) -> Self {
        Self {
            operation: &effect.operation,
            resource: &effect.resource,
            attributes: &effect.attributes,
            realm: &effect.realm,
            modality: Some(effect.modality),
            request_assurance: Some(effect.request_assurance),
            condition: Some(&effect.condition),
            execution_assurance: None,
        }
    }
}
/// Effect queries retain request-local operands; no host context is inferred.
///
/// Unlike a [`RelationRequest`], an effect query evaluates an effect's reach, not
/// just its resource expression: see [`EffectQuery::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectQuery {
    Satisfies { concrete: QualifiedIdentity },
    Contains { scope: Scope },
    Intersects { scope: Scope },
}
impl EffectQuery {
    pub fn validate(
        &self,
        target: EffectTarget<'_>,
        bindings: &Bindings,
    ) -> Result<(), MatchReason> {
        let mut budget = Budget::default();
        self.inspect(&mut budget)?;
        budget.expr(target.resource, 0)?;
        budget.serialized(bindings)?;
        budget.serialized(target.realm)
    }
    /// Evaluates whether the effect's reach relates to the query operand.
    ///
    /// The query's realm and the domain implied by its operand must match the
    /// target's realm and operation domain. A filesystem effect whose `recursive`
    /// attribute is `true` reaches its whole subtree, root included, so descendants
    /// can satisfy `Contains` or `Intersects`. A relative subtree root is resolved
    /// against the explicit cwd in `bindings`, as target paths are.
    ///
    /// Only the target's operation, resource, `recursive` attribute, and realm are
    /// evaluated. Its modality, request assurance, condition, and execution
    /// assurance are not, so a match does not prove the effect is certain,
    /// unconditional, or executed.
    pub fn evaluate(&self, target: EffectTarget<'_>, bindings: &Bindings) -> Match {
        let mut budget = Budget::default();
        let (realm, domain) = match self {
            Self::Satisfies { concrete } => (
                Some(&concrete.realm),
                crate::ResourceFamily::new(crate::identity_family(&concrete.identity)).domain(),
            ),
            Self::Contains { scope } | Self::Intersects { scope } => (
                scope.realm.as_ref(),
                match &scope.set {
                    ScopeSet::Exact { identity } => {
                        crate::ResourceFamily::new(crate::identity_family(identity)).domain()
                    }
                    ScopeSet::Pattern { pattern } => pattern.family().domain(),
                    ScopeSet::FsSubtree { .. } => Some("filesystem"),
                },
            ),
        };
        if let Err(reason) = budget
            .serialized(target.realm)
            .and_then(|_| budget.serialized(&realm))
        {
            return unknown(reason);
        }
        let realm = realm.map_or_else(yes, |realm| realm_match(realm, target.realm));
        if realm == Match::NotSatisfied
            || domain.is_some_and(|domain| domain != target.operation.domain())
        {
            return Match::NotSatisfied;
        }
        let check = budget
            .expr(target.resource, 0)
            .and_then(|_| budget.serialized(bindings))
            .and_then(|_| self.inspect(&mut budget));
        if let Err(reason) = check {
            return unknown(reason);
        }
        let recursive = if target.operation.domain() == "filesystem" {
            match target.attributes.get("recursive") {
                None | Some(crate::AttrValue::Bool(false)) => false,
                Some(crate::AttrValue::Bool(true)) => true,
                Some(_) => return and(realm, unknown(MatchReason::UnsupportedShape)),
            }
        } else {
            false
        };
        let mut evaluator = Evaluator {
            bindings,
            host: target.realm.is_host(),
            local_cwd: None,
            budget,
        };
        // Relative effect scopes need the same explicit cwd evidence as target paths.
        let mut scope_steps = Vec::new();
        let normalized = match self {
            Self::Contains { scope } | Self::Intersects { scope } => match &scope.set {
                ScopeSet::FsSubtree { root } => {
                    let (root, steps) = match evaluator.path(root.clone(), Vec::new()) {
                        Ok(path) => path,
                        Err(reason) => return and(realm, unknown(reason)),
                    };
                    scope_steps = steps;
                    let scope = Scope {
                        realm: None,
                        set: ScopeSet::FsSubtree { root },
                    };
                    Some(match self {
                        Self::Contains { .. } => Self::Contains { scope },
                        _ => Self::Intersects { scope },
                    })
                }
                _ => None,
            },
            _ => None,
        };
        and(
            and(
                realm,
                Match::Satisfied {
                    proof: Proof { steps: scope_steps },
                },
            ),
            evaluator.effect_target(
                normalized.as_ref().unwrap_or(self),
                target.resource,
                recursive,
            ),
        )
    }
    fn inspect(&self, budget: &mut Budget) -> Result<(), MatchReason> {
        match self {
            Self::Satisfies { concrete } => budget.identity(&concrete.identity, 0),
            Self::Contains { scope } | Self::Intersects { scope } => match &scope.set {
                ScopeSet::Exact { identity } => budget.identity(identity, 0),
                ScopeSet::Pattern { pattern } => budget.pattern(pattern, 0),
                ScopeSet::FsSubtree { root } => {
                    budget.charge(root.len(), root.len())?;
                    if !root.is_empty() {
                        Ok(())
                    } else {
                        Err(MatchReason::InvalidInput)
                    }
                }
            },
        }
    }
}
impl Evaluator<'_> {
    fn effect_target(
        &mut self,
        query: &EffectQuery,
        expr: &ResourceExpr,
        recursive: bool,
    ) -> Match {
        if let Err(reason) = self.budget.charge(1, 0) {
            return unknown(reason);
        }
        if !recursive {
            return match query {
                EffectQuery::Satisfies { concrete } => self.member(&concrete.identity, expr),
                EffectQuery::Contains { scope } => self.scope(scope, expr, true),
                EffectQuery::Intersects { scope } => self.scope(scope, expr, false),
            };
        }
        if let Some((path, alternatives)) = join_union(expr) {
            return self.union(
                alternatives,
                matches!(query, EffectQuery::Contains { .. }),
                |this, alternative| {
                    if path.is_empty() {
                        return this.effect_target(query, alternative, true);
                    }
                    if let Err(reason) = this.budget.serialized(expr) {
                        return unknown(reason);
                    }
                    let branch = replace_join_alternative(expr, &path, alternative);
                    this.effect_target(query, &branch, true)
                },
            );
        }
        let (root, steps) = match self
            .text(expr, true)
            .and_then(|(value, steps)| self.path(value, steps))
        {
            Ok(root) => root,
            Err(reason) => return unknown(reason),
        };
        let result = match query {
            EffectQuery::Satisfies { concrete } => match &concrete.identity {
                ResourceIdentity::FsPath { path } => match self.path(path.clone(), vec![]) {
                    Ok((path, proof)) => and(
                        truth(subtree(&root, &path)),
                        Match::Satisfied {
                            proof: Proof { steps: proof },
                        },
                    ),
                    Err(reason) => unknown(reason),
                },
                _ => Match::NotSatisfied,
            },
            EffectQuery::Contains { scope } | EffectQuery::Intersects { scope } => {
                let contains = matches!(query, EffectQuery::Contains { .. });
                match &scope.set {
                    ScopeSet::Exact { identity } => {
                        if contains {
                            Match::NotSatisfied
                        } else {
                            self.effect_target(
                                &EffectQuery::Satisfies {
                                    concrete: QualifiedIdentity {
                                        realm: ExecutionRealm::Host,
                                        identity: identity.clone(),
                                    },
                                },
                                expr,
                                true,
                            )
                        }
                    }
                    ScopeSet::FsSubtree { root: expected } => {
                        let expected = crate::normalize_path(expected, self.bindings.platform);
                        truth(subtree(&expected, &root) || !contains && subtree(&root, &expected))
                    }
                    ScopeSet::Pattern {
                        pattern: ResourcePattern::FsPath { .. },
                    } => {
                        if let Err(reason) = self
                            .budget
                            .charge(root.len(), root.len().saturating_mul(128))
                        {
                            return unknown(reason);
                        }
                        let mut glob = String::new();
                        for c in root.trim_end_matches('/').chars() {
                            if matches!(c, '*' | '?' | '[' | ']' | '\\') {
                                glob.push('\\');
                            }
                            glob.push(c);
                        }
                        glob.push_str("/**");
                        let root_match = self.scope(
                            scope,
                            &ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path: root },
                            },
                            contains,
                        );
                        if !contains && matches!(root_match, Match::Satisfied { .. }) {
                            root_match
                        } else {
                            let descendants = self.scope(
                                scope,
                                &ResourceExpr::Pattern {
                                    pattern: ResourcePattern::FsPath { glob },
                                },
                                contains,
                            );
                            if contains {
                                and(root_match, descendants)
                            } else {
                                match (root_match, descendants) {
                                    (_, yes @ Match::Satisfied { .. }) => yes,
                                    (unknown @ Match::Indeterminate { .. }, _)
                                    | (_, unknown @ Match::Indeterminate { .. }) => unknown,
                                    _ => Match::NotSatisfied,
                                }
                            }
                        }
                    }
                    _ => Match::NotSatisfied,
                }
            }
        };
        step(
            and(
                result,
                Match::Satisfied {
                    proof: Proof { steps },
                },
            ),
            ProofStep::RecursiveExtent,
        )
    }
}

fn yes() -> Match {
    Match::Satisfied {
        proof: Proof { steps: Vec::new() },
    }
}
fn unknown(reason: MatchReason) -> Match {
    Match::Indeterminate { reason }
}
fn truth(value: bool) -> Match {
    if value { yes() } else { Match::NotSatisfied }
}
fn and(a: Match, b: Match) -> Match {
    match (a, b) {
        (Match::NotSatisfied, _) | (_, Match::NotSatisfied) => Match::NotSatisfied,
        (
            Match::Indeterminate {
                reason: MatchReason::Unbound { mut names },
            },
            Match::Indeterminate {
                reason: MatchReason::Unbound { names: other },
            },
        ) => {
            names.extend(other);
            names.sort();
            names.dedup();
            unknown(MatchReason::Unbound { names })
        }
        (a @ Match::Indeterminate { .. }, _) | (_, a @ Match::Indeterminate { .. }) => a,
        (Match::Satisfied { mut proof }, Match::Satisfied { proof: other }) => {
            proof.steps.extend(other.steps);
            Match::Satisfied { proof }
        }
    }
}
fn step(result: Match, step: ProofStep) -> Match {
    if let Match::Satisfied { mut proof } = result {
        proof.steps.push(step);
        Match::Satisfied { proof }
    } else {
        result
    }
}

// Every visit and inspected byte consumes the same work allowance. Strings and
// pattern scratch reserve an upper bound before parsing or cloning; recursion
// stops before traversing a child at depth 64.
#[derive(Default)]
struct Budget {
    work: usize,
    bytes: usize,
}
impl Budget {
    fn charge(&mut self, work: usize, bytes: usize) -> Result<(), MatchReason> {
        self.work = self.work.saturating_add(work);
        self.bytes = self.bytes.saturating_add(bytes);
        if self.work > RELATION_WORK_LIMIT || self.bytes > RELATION_BYTE_LIMIT {
            Err(MatchReason::Limit)
        } else {
            Ok(())
        }
    }
    fn expr(&mut self, expr: &ResourceExpr, depth: usize) -> Result<(), MatchReason> {
        if depth >= RELATION_DEPTH_LIMIT {
            return Err(MatchReason::Limit);
        }
        self.charge(1, 256)?;
        match expr {
            ResourceExpr::Concrete { identity } => self.identity(identity, depth + 1),
            ResourceExpr::Literal { value }
            | ResourceExpr::Parameter { name: value }
            | ResourceExpr::Environment { name: value } => self.charge(value.len(), value.len()),
            ResourceExpr::Unresolved { family } => self.charge(family.0.len(), family.0.len()),
            ResourceExpr::Property { base, name } => {
                self.charge(name.len(), name.len())?;
                self.expr(base, depth + 1)
            }
            ResourceExpr::Join { parts }
            | ResourceExpr::Union {
                alternatives: parts,
            } => {
                if parts.is_empty() {
                    return Err(MatchReason::InvalidInput);
                }
                for part in parts {
                    self.expr(part, depth + 1)?;
                }
                Ok(())
            }
            ResourceExpr::Pattern { pattern } => self.pattern(pattern, depth + 1),
        }
    }
    fn identity(&mut self, identity: &ResourceIdentity, depth: usize) -> Result<(), MatchReason> {
        if depth >= RELATION_DEPTH_LIMIT {
            return Err(MatchReason::Limit);
        }
        if let Some(scope) = identity.scope() {
            for value in scope.values() {
                self.expr(value, depth + 1)?;
            }
        }
        for value in identity.infrastructure_values() {
            self.expr(value, depth + 1)?;
        }
        match identity {
            ResourceIdentity::Artifact {
                endpoint,
                name,
                reference,
                ..
            } => {
                for value in [endpoint.as_ref(), name.as_ref()]
                    .into_iter()
                    .chain(reference.value())
                {
                    self.expr(value, depth + 1)?;
                }
            }
            ResourceIdentity::Process { argv, cwd, .. } => {
                if argv.len() > crate::resource::MAX_PROCESS_ARGV {
                    return Err(MatchReason::InvalidInput);
                }
                for arg in argv {
                    self.expr(arg, depth + 1)?;
                }
                if let Some(cwd) = cwd {
                    self.expr(cwd, depth + 1)?;
                }
            }
            ResourceIdentity::GitRepository {
                worktree,
                git_dir,
                pathspec,
            } => {
                for expr in worktree.iter().chain(git_dir).chain(pathspec) {
                    self.expr(expr, depth + 1)?;
                }
            }
            ResourceIdentity::Container { storage, .. } => {
                for item in storage {
                    match item {
                        crate::ContainerStorage::BindMount {
                            host_path,
                            container_path,
                            ..
                        } => {
                            self.expr(host_path, depth + 1)?;
                            self.expr(container_path, depth + 1)?;
                        }
                        crate::ContainerStorage::Volume { container_path, .. } => {
                            self.expr(container_path, depth + 1)?
                        }
                    }
                }
            }
            _ => (),
        }
        self.serialized(identity)?;
        if crate::validate::selector_identity_is_valid(identity) {
            Ok(())
        } else {
            Err(MatchReason::InvalidInput)
        }
    }
    fn serialized(&mut self, value: &impl Serialize) -> Result<(), MatchReason> {
        value
            .serialize(&mut InputInspector {
                budget: self,
                depth: 0,
            })
            .map_err(|_| MatchReason::Limit)
    }
    fn pattern(&mut self, pattern: &ResourcePattern, depth: usize) -> Result<(), MatchReason> {
        if let ResourcePattern::Process { argv_prefix, .. } = pattern {
            if argv_prefix.len() > crate::resource::MAX_PROCESS_ARGV {
                return Err(MatchReason::InvalidInput);
            }
            for arg in argv_prefix {
                self.expr(arg, depth + 1)?;
            }
        }
        self.serialized(pattern)?;
        for text in pattern.texts() {
            self.charge(text.len(), text.len().saturating_mul(64))?;
        }
        if let ResourcePattern::Process {
            executable: crate::TextField::Glob { glob },
            ..
        } = pattern
        {
            self.charge(glob.len(), glob.len().saturating_mul(64))?;
        }
        pattern.validate_syntax().map_err(|e| match e {
            crate::glob::GlobError::Limit => MatchReason::Limit,
            _ => MatchReason::InvalidInput,
        })
    }
}

/// Membership is a resource fact, independent of policy and whole-plan coverage.
pub fn satisfies(concrete: &QualifiedIdentity, expr: &QualifiedExpr, bindings: &Bindings) -> Match {
    let mut budget = Budget::default();
    if let Err(reason) = budget
        .serialized(&concrete.realm)
        .and_then(|_| budget.serialized(&expr.realm))
    {
        return unknown(reason);
    }
    let realm = realm_match(&concrete.realm, &expr.realm);
    if realm == Match::NotSatisfied {
        return realm;
    }
    let known_family = match &expr.expr {
        ResourceExpr::Concrete { identity } => {
            crate::ResourceFamily::new(crate::identity_family(identity)).domain()
        }
        ResourceExpr::Pattern { pattern } => pattern.family().domain(),
        ResourceExpr::Unresolved { family } => family.domain(),
        _ => None,
    };
    if known_family.is_some_and(|family| {
        Some(family)
            != crate::ResourceFamily::new(crate::identity_family(&concrete.identity)).domain()
    }) {
        return Match::NotSatisfied;
    }
    let check = budget
        .identity(&concrete.identity, 0)
        .and_then(|_| budget.expr(&expr.expr, 0))
        .and_then(|_| budget.serialized(bindings));
    if let Err(reason) = check {
        return unknown(reason);
    }
    let mut evaluator = Evaluator {
        bindings,
        host: expr.realm.is_host(),
        local_cwd: None,
        budget,
    };
    and(realm, evaluator.member(&concrete.identity, &expr.expr))
}
/// Overlap succeeds only through membership of a shared point.
pub fn scope_intersects(scope: &Scope, expr: &QualifiedExpr, bindings: &Bindings) -> Match {
    relation(scope, expr, bindings, false)
}
fn realm_match(a: &ExecutionRealm, b: &ExecutionRealm) -> Match {
    let a = serde_json::to_value(a).expect("realm");
    let b = serde_json::to_value(b).expect("realm");
    let mut result = compare_json(&a, &b);
    if a.get("realm") == b.get("realm")
        && a.get("realm").and_then(serde_json::Value::as_str) == Some("kubernetes")
        && ["namespace", "container"]
            .iter()
            .any(|key| a.get(key).is_none() || b.get(key).is_none())
    {
        result = and(result, unknown(MatchReason::UnderqualifiedRealm));
    }
    if a.get("realm") == b.get("realm")
        && a.get("realm").and_then(serde_json::Value::as_str) == Some("chroot")
        && (a.get("host_root").is_none() || b.get("host_root").is_none())
    {
        result = and(result, unknown(MatchReason::UnderqualifiedRealm));
    }
    match result {
        Match::Indeterminate { .. } => unknown(MatchReason::UnderqualifiedRealm),
        other => other,
    }
}
fn compare_json(a: &serde_json::Value, b: &serde_json::Value) -> Match {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            let keys: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
            keys.into_iter().fold(yes(), |result, key| {
                and(
                    result,
                    compare_json(
                        a.get(key).unwrap_or(&Value::Null),
                        b.get(key).unwrap_or(&Value::Null),
                    ),
                )
            })
        }
        (Value::Null, Value::Null) => yes(),
        (Value::Null, _) | (_, Value::Null) => unknown(MatchReason::UnderqualifiedFields),
        _ => truth(a == b),
    }
}
struct Evaluator<'a> {
    bindings: &'a Bindings,
    host: bool,
    local_cwd: Option<(String, Vec<ProofStep>)>,
    budget: Budget,
}
impl Evaluator<'_> {
    fn binding(&self, name: &str, cwd: bool) -> Result<&Binding, MatchReason> {
        if self.host
            && let Some(binding) = if cwd {
                self.bindings.cwd.as_ref()
            } else {
                self.bindings.env.get(name)
            }
        {
            return Ok(binding);
        }
        Err(MatchReason::Unbound {
            names: vec![name.to_string()],
        })
    }
    fn cwd(&self) -> Result<(&str, Vec<ProofStep>), MatchReason> {
        let (value, steps) = if let Some((value, steps)) = &self.local_cwd {
            (value.as_str(), steps.clone())
        } else {
            let binding = self.binding("cwd", true)?;
            (
                binding.value.as_str(),
                vec![ProofStep::Binding {
                    name: "cwd".into(),
                    source: binding.source.clone(),
                }],
            )
        };
        if !crate::is_absolute_path(value, self.bindings.platform) {
            return Err(MatchReason::Unbound {
                names: vec!["cwd".into()],
            });
        }
        Ok((value, steps))
    }
    fn text(
        &mut self,
        expr: &ResourceExpr,
        filesystem: bool,
    ) -> Result<(String, Vec<ProofStep>), MatchReason> {
        self.budget.charge(1, 0)?;
        match expr {
            ResourceExpr::Literal { value } => Ok((value.clone(), vec![])),
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Ok((path.clone(), vec![])),
            ResourceExpr::Environment { name } | ResourceExpr::Parameter { name }
                if matches!(expr, ResourceExpr::Environment { .. }) || name == "cwd" =>
            {
                let cwd = matches!(expr, ResourceExpr::Parameter { .. });
                let length = self.binding(name, cwd)?.value.len();
                self.budget.charge(length, length.saturating_mul(2))?;
                let binding = self.binding(name, cwd)?;
                Ok((
                    binding.value.clone(),
                    vec![ProofStep::Binding {
                        name: name.clone(),
                        source: binding.source.clone(),
                    }],
                ))
            }
            ResourceExpr::Parameter { name } => Err(MatchReason::Unbound {
                names: vec![name.clone()],
            }),
            ResourceExpr::Join { parts } => {
                let mut value = String::new();
                let mut proof = vec![];
                let mut error = None;
                for part in parts {
                    match self.text(part, filesystem) {
                        Ok((text, steps)) => {
                            if filesystem
                                && matches!(
                                    part,
                                    ResourceExpr::Concrete {
                                        identity: ResourceIdentity::FsPath { .. }
                                    }
                                )
                                && !value.is_empty()
                                && !value.ends_with('/')
                                && !text.starts_with('/')
                            {
                                value.push('/');
                            }
                            self.budget.charge(text.len(), text.len())?;
                            value.push_str(&text);
                            proof.extend(steps);
                        }
                        Err(reason) => {
                            error = Some(match (error.take(), reason) {
                                (
                                    Some(MatchReason::Unbound { mut names }),
                                    MatchReason::Unbound { names: other },
                                ) => {
                                    names.extend(other);
                                    names.sort();
                                    names.dedup();
                                    MatchReason::Unbound { names }
                                }
                                (Some(prior), _) => prior,
                                (None, reason) => reason,
                            });
                        }
                    }
                }
                if let Some(error) = error {
                    Err(error)
                } else {
                    Ok((value, proof))
                }
            }
            ResourceExpr::Unresolved { .. } => Err(MatchReason::UnresolvedFamily),
            _ => Err(MatchReason::UnsupportedShape),
        }
    }
    fn path(
        &mut self,
        value: String,
        mut proof: Vec<ProofStep>,
    ) -> Result<(String, Vec<ProofStep>), MatchReason> {
        if value.is_empty() {
            return Err(MatchReason::InvalidInput);
        }
        let value = if crate::is_absolute_path(&value, self.bindings.platform) {
            value
        } else {
            let (cwd, steps) = self.cwd()?;
            proof.extend(steps);
            format!("{cwd}/{value}")
        };
        self.budget
            .charge(value.len(), value.len().saturating_mul(2))?;
        Ok((crate::normalize_path(&value, self.bindings.platform), proof))
    }
    fn union(
        &mut self,
        alternatives: &[ResourceExpr],
        all: bool,
        mut eval: impl FnMut(&mut Self, &ResourceExpr) -> Match,
    ) -> Match {
        let mut result = if all { yes() } else { Match::NotSatisfied };
        for (index, expr) in alternatives.iter().enumerate() {
            let candidate = step(eval(self, expr), ProofStep::Alternative { index });
            if all {
                result = and(result, candidate);
                if result == Match::NotSatisfied {
                    return result;
                }
            } else {
                match candidate {
                    Match::Satisfied { .. } => return candidate,
                    Match::Indeterminate { .. } => {
                        result = if matches!(result, Match::Indeterminate { .. }) {
                            and(result, candidate)
                        } else {
                            candidate
                        }
                    }
                    _ => (),
                }
            }
        }
        result
    }
    fn member(&mut self, identity: &ResourceIdentity, expr: &ResourceExpr) -> Match {
        if let Err(reason) = self.budget.charge(1, 0) {
            return unknown(reason);
        }
        if matches!(expr, ResourceExpr::Join { .. })
            && let Some((path, alternatives)) = join_union(expr)
        {
            return self.union(alternatives, false, |this, alternative| {
                if let Err(reason) = this.budget.serialized(expr) {
                    return unknown(reason);
                }
                let branch = replace_join_alternative(expr, &path, alternative);
                this.member(identity, &branch)
            });
        }
        if !matches!(expr, ResourceExpr::Union { .. })
            && let Some(domain) = crate::resource_domain(expr)
            && crate::ResourceFamily::new(crate::identity_family(identity)).domain() != Some(domain)
        {
            return Match::NotSatisfied;
        }
        if matches!(expr, ResourceExpr::Join { .. }) {
            match self.joined_glob(expr) {
                Ok(Some((glob, steps))) => {
                    return and(
                        self.pattern_member(identity, &ResourcePattern::FsPath { glob }),
                        Match::Satisfied {
                            proof: Proof { steps },
                        },
                    );
                }
                Err(reason) => return unknown(reason),
                _ => (),
            }
        }
        match expr {
            ResourceExpr::Union { alternatives } => {
                self.union(alternatives, false, |this, expr| {
                    this.member(identity, expr)
                })
            }
            ResourceExpr::Pattern { pattern } => self.pattern_member(identity, pattern),
            ResourceExpr::Concrete { identity: expected } => self.exact(identity, expected),
            ResourceExpr::Unresolved { .. } => unknown(MatchReason::UnresolvedFamily),
            _ => {
                let fs = matches!(identity, ResourceIdentity::FsPath { .. });
                let value = self.text(expr, fs).and_then(|(value, proof)| {
                    if fs {
                        self.path(value, proof)
                    } else {
                        Ok((value, proof))
                    }
                });
                match value {
                    Err(reason) => unknown(reason),
                    Ok((value, steps)) => {
                        let result = match identity {
                            ResourceIdentity::FsPath { path } => {
                                truth(crate::normalize_path(path, self.bindings.platform) == value)
                            }
                            ResourceIdentity::EnvironmentVariable { name } => truth(*name == value),
                            ResourceIdentity::NetworkEndpoint { .. } => {
                                match parse_endpoint(&value) {
                                    Ok(expected) => self.exact(identity, &expected),
                                    Err(reason) => unknown(reason),
                                }
                            }
                            _ => unknown(MatchReason::UnsupportedShape),
                        };
                        and(
                            result,
                            Match::Satisfied {
                                proof: Proof { steps },
                            },
                        )
                    }
                }
            }
        }
    }
    fn exact(&mut self, identity: &ResourceIdentity, expected: &ResourceIdentity) -> Match {
        if let Err(reason) = self
            .budget
            .serialized(identity)
            .and_then(|_| self.budget.serialized(expected))
        {
            return unknown(reason);
        }
        if crate::identity_family(identity) != crate::identity_family(expected) {
            return Match::NotSatisfied;
        }
        // An unstated cloud ID may name the other resource or another one.
        if [identity, expected]
            .iter()
            .any(|identity| matches!(identity, ResourceIdentity::CloudResource { id: None, .. }))
        {
            return unknown(MatchReason::UnderqualifiedFields);
        }
        if let (ResourceIdentity::FsPath { path: a }, ResourceIdentity::FsPath { path: b }) =
            (identity, expected)
        {
            return match (self.path(a.clone(), vec![]), self.path(b.clone(), vec![])) {
                (Ok((a, mut proof)), Ok((b, other))) => {
                    proof.extend(other);
                    and(
                        truth(a == b),
                        Match::Satisfied {
                            proof: Proof { steps: proof },
                        },
                    )
                }
                (Err(reason), _) | (_, Err(reason)) => unknown(reason),
            };
        }
        if let (
            ResourceIdentity::Process {
                executable: a,
                argv,
                path: ap,
                cwd: ac,
            },
            ResourceIdentity::Process {
                executable: b,
                argv: expected,
                path: bp,
                cwd: bc,
            },
        ) = (identity, expected)
        {
            let mut result = truth(a == b);
            result = and(
                result,
                compare_json(&serde_json::json!(ap), &serde_json::json!(bp)),
            );
            result = and(
                result,
                if argv.iter().chain(expected).any(truncated_arg) {
                    unknown(MatchReason::TruncatedArgv)
                } else {
                    truth(argv.len() == expected.len())
                },
            );
            let previous_cwd = self.local_cwd.take();
            self.local_cwd = ac
                .as_ref()
                .and_then(|cwd| self.text(cwd, true).ok())
                .and_then(|(value, steps)| self.path(value, steps).ok());
            for (arg, expected) in argv.iter().zip(expected) {
                result = and(result, self.argument(arg, expected));
            }
            self.local_cwd = previous_cwd;
            result = and(
                result,
                self.compare_value(&serde_json::json!(ac), &serde_json::json!(bc)),
            );
            return result;
        }
        if let (
            ResourceIdentity::GitRepository {
                worktree: a,
                git_dir: ad,
                pathspec: ap,
            },
            ResourceIdentity::GitRepository {
                worktree: b,
                git_dir: bd,
                pathspec: bp,
            },
        ) = (identity, expected)
        {
            let mut result = and(
                self.compare_value(&serde_json::json!(a), &serde_json::json!(b)),
                self.compare_value(&serde_json::json!(ad), &serde_json::json!(bd)),
            );
            let previous_cwd = self.local_cwd.take();
            self.local_cwd = a
                .as_ref()
                .and_then(|worktree| self.text(worktree, true).ok())
                .and_then(|(value, steps)| self.path(value, steps).ok());
            result = and(
                result,
                self.compare_value(&serde_json::json!(ap), &serde_json::json!(bp)),
            );
            self.local_cwd = previous_cwd;
            return result;
        }
        let a = normalize_relation_identity(identity, self.bindings.platform);
        let b = normalize_relation_identity(expected, self.bindings.platform);
        self.compare_value(
            &serde_json::to_value(a).expect("identity"),
            &serde_json::to_value(b).expect("identity"),
        )
    }
    fn compare_value(&mut self, a: &serde_json::Value, b: &serde_json::Value) -> Match {
        use serde_json::Value;
        if let Err(reason) = self.budget.charge(1, 0) {
            return unknown(reason);
        }
        if a.get("expr").is_some() && b.get("expr").is_some() {
            let a: ResourceExpr = serde_json::from_value(a.clone()).expect("nested expression");
            let b: ResourceExpr = serde_json::from_value(b.clone()).expect("nested expression");
            return match &a {
                ResourceExpr::Concrete { identity } => self.member(identity, &b),
                _ => match &b {
                    ResourceExpr::Concrete { identity } => self.member(identity, &a),
                    _ => self.argument(&a, &b),
                },
            };
        }
        if a.get("state").and_then(Value::as_str) == Some("unknown")
            || b.get("state").and_then(Value::as_str) == Some("unknown")
        {
            return unknown(MatchReason::UnderqualifiedFields);
        }
        match (a, b) {
            (Value::Object(a), Value::Object(b)) => {
                let keys: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
                let mut result = yes();
                for key in keys {
                    if key == "access" && a.contains_key("identity") && b.contains_key("identity") {
                        continue;
                    }
                    if key == "kind"
                        && a.contains_key("identity")
                        && b.contains_key("identity")
                        && (a.get(key).and_then(Value::as_str) == Some("unsupported")
                            || b.get(key).and_then(Value::as_str) == Some("unsupported"))
                    {
                        result = and(result, unknown(MatchReason::UnderqualifiedFields));
                        continue;
                    }
                    result = and(
                        result,
                        self.compare_value(
                            a.get(key).unwrap_or(&Value::Null),
                            b.get(key).unwrap_or(&Value::Null),
                        ),
                    );
                }
                result
            }
            (Value::Array(a), Value::Array(b)) => {
                if a.is_empty() != b.is_empty() {
                    return unknown(MatchReason::UnderqualifiedFields);
                }
                let mut result = truth(a.len() == b.len());
                for (a, b) in a.iter().zip(b) {
                    result = and(result, self.compare_value(a, b));
                }
                result
            }
            _ => compare_json(a, b),
        }
    }
    fn argument(&mut self, arg: &ResourceExpr, expected: &ResourceExpr) -> Match {
        if matches!(arg,ResourceExpr::Unresolved { family } if family.0 == "process")
            || matches!(expected,ResourceExpr::Unresolved { family } if family.0 == "process")
        {
            return unknown(MatchReason::TruncatedArgv);
        }
        if let ResourceExpr::Union { alternatives } = arg {
            return self.union(alternatives, true, |this, arg| this.argument(arg, expected));
        }
        if matches!(arg, ResourceExpr::Pattern { .. }) && arg == expected {
            return yes();
        }
        let value = self.text(arg, false);
        let Ok((value, steps)) = value else {
            return unknown(value.unwrap_err());
        };
        let result = match expected {
            ResourceExpr::Pattern {
                pattern: ResourcePattern::ArtifactField { glob },
            } => self.glob(glob, &value, None),
            ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { .. },
            } => self.member(
                &ResourceIdentity::FsPath {
                    path: value.clone(),
                },
                expected,
            ),
            ResourceExpr::Union { alternatives } => {
                self.union(alternatives, false, |this, expr| this.argument(arg, expr))
            }
            _ => match self.text(expected, false) {
                Ok((expected, proof)) => and(
                    truth(value == expected),
                    Match::Satisfied {
                        proof: Proof { steps: proof },
                    },
                ),
                Err(reason) => unknown(reason),
            },
        };
        and(
            result,
            Match::Satisfied {
                proof: Proof { steps },
            },
        )
    }
    fn joined_glob(
        &mut self,
        expr: &ResourceExpr,
    ) -> Result<Option<(String, Vec<ProofStep>)>, MatchReason> {
        fn leaves<'a>(expr: &'a ResourceExpr, parts: &mut Vec<&'a ResourceExpr>) {
            if let ResourceExpr::Join { parts: children } = expr {
                for child in children {
                    leaves(child, parts);
                }
            } else {
                parts.push(expr);
            }
        }
        let mut parts = Vec::new();
        leaves(expr, &mut parts);
        if !parts
            .iter()
            .any(|part| matches!(part, ResourceExpr::Pattern { .. }))
        {
            return Ok(None);
        }
        let mut output = String::new();
        let mut steps = Vec::new();
        let mut previous_segment = false;
        for part in parts {
            self.budget.charge(1, 0)?;
            let is_segment = matches!(
                part,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { .. }
                }
            ) || matches!(part,ResourceExpr::Parameter { name } if name == "cwd");
            let (value, proof, pattern) = match part {
                ResourceExpr::Pattern {
                    pattern: ResourcePattern::FsPath { glob },
                } => (glob.clone(), vec![], true),
                ResourceExpr::Pattern { .. } => return Err(MatchReason::UnsupportedShape),
                _ => {
                    let (value, proof) = self.text(part, true)?;
                    (value, proof, false)
                }
            };
            if !output.is_empty()
                && !output.ends_with('/')
                && !value.starts_with('/')
                && (is_segment || pattern && previous_segment)
            {
                output.push('/');
            }
            self.budget
                .charge(value.len(), value.len().saturating_mul(2))?;
            if pattern {
                output.push_str(&value);
            } else {
                for c in value.chars() {
                    if matches!(c, '*' | '?' | '[' | ']' | '\\') {
                        output.push('\\');
                    }
                    output.push(c);
                }
            }
            steps.extend(proof);
            previous_segment = is_segment;
        }
        Ok(Some((output, steps)))
    }
    fn filesystem_glob(&mut self, glob: &str) -> Result<(String, Vec<ProofStep>), MatchReason> {
        let mut steps = Vec::new();
        let mut glob = if crate::is_absolute_path(glob, self.bindings.platform) {
            glob.to_string()
        } else {
            let (cwd, proof) = self.cwd()?;
            let cwd = crate::normalize_path(cwd, self.bindings.platform);
            steps.extend(proof);
            let mut prefix = String::new();
            for c in cwd.trim_end_matches('/').chars() {
                if matches!(c, '*' | '?' | '[' | ']' | '\\') {
                    prefix.push('\\');
                }
                prefix.push(c);
            }
            format!("{prefix}/{glob}")
        };
        if self.bindings.platform == PathPlatform::Windows && glob.as_bytes().get(1) == Some(&b':')
        {
            glob.replace_range(..1, &glob[..1].to_ascii_uppercase());
        }
        self.budget
            .charge(glob.len(), glob.len().saturating_mul(64))?;
        Ok((crate::glob::normalize_glob(&glob), steps))
    }
    fn glob(&mut self, glob: &str, value: &str, separator: Option<char>) -> Match {
        if let Err(reason) = self.budget.charge(
            glob.len() + value.len(),
            (glob.len() + value.len()).saturating_mul(64),
        ) {
            return unknown(reason);
        }
        match crate::glob::match_namespace(
            glob,
            value,
            separator,
            separator == Some('/'),
            separator == Some('/'),
            &mut self.budget.work,
        ) {
            Ok(true) => step(yes(), ProofStep::Pattern),
            Ok(false) => Match::NotSatisfied,
            Err(crate::glob::GlobError::Limit) => unknown(MatchReason::Limit),
            Err(_) => unknown(MatchReason::InvalidInput),
        }
    }
    fn pattern_member(&mut self, identity: &ResourceIdentity, pattern: &ResourcePattern) -> Match {
        if matches!(pattern, ResourcePattern::ArtifactField { .. }) {
            return unknown(MatchReason::UnsupportedShape);
        }
        if let Err(reason) = self
            .budget
            .serialized(identity)
            .and_then(|_| self.budget.serialized(pattern))
        {
            return unknown(reason);
        }
        let field = |constraint: &crate::Field, value: Option<&String>| match constraint {
            crate::Field::Any => yes(),
            crate::Field::Exact { value: expected } => value.map_or_else(
                || unknown(MatchReason::UnderqualifiedFields),
                |value| truth(value == expected),
            ),
        };
        match (pattern, identity) {
            (ResourcePattern::FsPath { glob }, ResourceIdentity::FsPath { path }) => {
                let (glob, binding_steps) = match self.filesystem_glob(glob) {
                    Ok(value) => value,
                    Err(reason) => return unknown(reason),
                };
                match self.path(path.clone(), binding_steps) {
                    Ok((path, steps)) => and(
                        self.glob(&glob, &path, Some('/')),
                        Match::Satisfied {
                            proof: Proof { steps },
                        },
                    ),
                    Err(reason) => unknown(reason),
                }
            }
            (
                ResourcePattern::EnvironmentVariable { name_glob },
                ResourceIdentity::EnvironmentVariable { name },
            ) => self.glob(name_glob, name, None),
            (
                ResourcePattern::NetworkEndpoint {
                    host_glob,
                    scheme,
                    port,
                    path_prefix,
                },
                ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme: actual_scheme,
                    port: actual_port,
                    path,
                },
            ) => {
                let mut result = if host_glob.contains(':') {
                    truth(normalize_host(host_glob) == normalize_host(host))
                } else {
                    self.glob(&normalize_host(host_glob), &normalize_host(host), Some('.'))
                };
                result = and(
                    result,
                    match scheme {
                        crate::Field::Any => yes(),
                        crate::Field::Exact { value } => actual_scheme.as_ref().map_or_else(
                            || unknown(MatchReason::UnderqualifiedFields),
                            |actual| truth(value.eq_ignore_ascii_case(actual)),
                        ),
                    },
                );
                result = and(
                    result,
                    match port {
                        crate::PortField::Any => yes(),
                        crate::PortField::Exact { value } => actual_port.map_or_else(
                            || unknown(MatchReason::UnderqualifiedFields),
                            |port| truth(*value == port),
                        ),
                    },
                );
                and(result, optional_prefix(path_prefix, path, true))
            }
            (
                ResourcePattern::DatabaseTable {
                    server,
                    database,
                    schema,
                    table,
                },
                ResourceIdentity::DatabaseTable {
                    server: a,
                    database: b,
                    schema: c,
                    table: d,
                },
            ) => and(
                and(field(server, a.as_ref()), field(database, b.as_ref())),
                and(field(schema, c.as_ref()), field(table, Some(d))),
            ),
            (
                ResourcePattern::DatabaseSchema {
                    server,
                    database,
                    schema,
                },
                ResourceIdentity::DatabaseSchema {
                    server: a,
                    database: b,
                    schema: c,
                },
            ) => and(
                and(field(server, a.as_ref()), field(database, b.as_ref())),
                field(schema, c.as_ref()),
            ),
            (
                ResourcePattern::ObjectStore {
                    provider,
                    bucket,
                    key_prefix,
                },
                ResourceIdentity::ObjectStore {
                    provider: actual,
                    bucket: actual_bucket,
                    key,
                    ..
                },
            ) => and(
                and(
                    field(provider, actual.as_ref()),
                    truth(bucket == actual_bucket),
                ),
                optional_prefix(key_prefix, key, false),
            ),
            (
                ResourcePattern::CloudResource {
                    provider,
                    service,
                    kind,
                    id_glob,
                },
                ResourceIdentity::CloudResource {
                    provider: a,
                    service: b,
                    kind: c,
                    id,
                    ..
                },
            ) => and(
                and(field(provider, a.as_ref()), field(service, Some(b))),
                and(
                    field(kind, Some(c)),
                    match id {
                        Some(id) => self.glob(id_glob, id, None),
                        None => unknown(MatchReason::UnderqualifiedFields),
                    },
                ),
            ),
            (
                ResourcePattern::MessageTopic { system, name_glob },
                ResourceIdentity::MessageTopic {
                    system: actual,
                    name,
                    ..
                },
            ) => and(
                field(system, actual.as_ref()),
                self.glob(name_glob, name, None),
            ),
            (
                ResourcePattern::ServiceUnit { manager, name_glob },
                ResourceIdentity::ServiceUnit {
                    manager: actual,
                    name,
                },
            ) => and(
                field(manager, Some(actual)),
                self.glob(name_glob, name, None),
            ),
            (
                ResourcePattern::Container {
                    runtime,
                    name_glob,
                    image_glob,
                },
                ResourceIdentity::Container {
                    runtime: actual,
                    name,
                    image,
                    ..
                },
            ) => {
                let mut result = field(runtime, Some(actual));
                for (constraint, value) in [(name_glob, name), (image_glob, image)] {
                    if let Some(glob) = constraint {
                        result = and(
                            result,
                            value.as_ref().map_or_else(
                                || unknown(MatchReason::UnderqualifiedFields),
                                |value| self.glob(glob, value, None),
                            ),
                        );
                    }
                }
                result
            }
            (
                ResourcePattern::Process {
                    executable,
                    argv_prefix,
                },
                ResourceIdentity::Process {
                    executable: actual,
                    argv,
                    cwd,
                    ..
                },
            ) => {
                let previous_cwd = self.local_cwd.take();
                self.local_cwd = cwd
                    .as_ref()
                    .and_then(|cwd| self.text(cwd, true).ok())
                    .and_then(|(value, steps)| self.path(value, steps).ok());
                let mut result = match executable {
                    crate::TextField::Any => yes(),
                    crate::TextField::Exact { value } => truth(value == actual),
                    crate::TextField::Glob { glob } => self.glob(glob, actual, None),
                };
                result = and(
                    result,
                    if argv.len() < argv_prefix.len() && argv.iter().any(truncated_arg) {
                        unknown(MatchReason::TruncatedArgv)
                    } else {
                        truth(argv.len() >= argv_prefix.len())
                    },
                );
                for (a, b) in argv.iter().zip(argv_prefix) {
                    result = and(result, self.argument(a, b));
                }
                self.local_cwd = previous_cwd;
                result
            }
            (
                ResourcePattern::GitRepository {
                    worktree,
                    git_dir,
                    pathspec_glob,
                },
                ResourceIdentity::GitRepository {
                    worktree: a,
                    git_dir: b,
                    pathspec: c,
                },
            ) => {
                let mut result = yes();
                for (expected, value, glob) in [
                    (worktree, a, false),
                    (git_dir, b, false),
                    (pathspec_glob, c, true),
                ] {
                    if let Some(expected) = expected {
                        let matched = match value {
                            None => unknown(MatchReason::UnderqualifiedFields),
                            Some(value) => match self.text(value, true) {
                                Ok((value, _)) => {
                                    if glob {
                                        self.glob(expected, &value, Some('/'))
                                    } else {
                                        truth(expected == &value)
                                    }
                                }
                                Err(reason) => unknown(reason),
                            },
                        };
                        result = and(result, matched);
                    }
                }
                result
            }
            _ => Match::NotSatisfied,
        }
    }
}
fn optional_prefix(expected: &Option<String>, actual: &Option<String>, segmented: bool) -> Match {
    expected.as_ref().map_or_else(yes, |prefix| {
        actual.as_ref().map_or_else(
            || unknown(MatchReason::UnderqualifiedFields),
            |value| {
                truth(if segmented {
                    subtree(prefix, value)
                } else {
                    value.starts_with(prefix)
                })
            },
        )
    })
}
fn subtree(root: &str, path: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|tail| root.ends_with('/') || tail.starts_with('/'))
}
fn relation(scope: &Scope, expr: &QualifiedExpr, bindings: &Bindings, contains: bool) -> Match {
    let mut budget = Budget::default();
    let check = budget
        .expr(&expr.expr, 0)
        .and_then(|_| budget.serialized(bindings))
        .and_then(|_| budget.serialized(&scope.realm))
        .and_then(|_| budget.serialized(&expr.realm))
        .and_then(|_| match &scope.set {
            ScopeSet::Exact { identity } => budget.identity(identity, 0),
            ScopeSet::Pattern { pattern } => budget.pattern(pattern, 0),
            ScopeSet::FsSubtree { root } => {
                budget.charge(root.len(), root.len())?;
                if crate::is_absolute_path(root, bindings.platform) {
                    Ok(())
                } else {
                    Err(MatchReason::InvalidInput)
                }
            }
        });
    if let Err(reason) = check {
        return unknown(reason);
    }
    let realm = scope
        .realm
        .as_ref()
        .map_or_else(yes, |realm| realm_match(realm, &expr.realm));
    if realm == Match::NotSatisfied {
        return realm;
    }
    let mut evaluator = Evaluator {
        bindings,
        host: expr.realm.is_host(),
        local_cwd: None,
        budget,
    };
    let normalized = match &scope.set {
        ScopeSet::FsSubtree { root } => Some(Scope {
            realm: None,
            set: ScopeSet::FsSubtree {
                root: crate::normalize_path(root, bindings.platform),
            },
        }),
        _ => None,
    };
    and(
        realm,
        evaluator.scope(normalized.as_ref().unwrap_or(scope), &expr.expr, contains),
    )
}
impl Evaluator<'_> {
    fn scope(&mut self, scope: &Scope, expr: &ResourceExpr, contains: bool) -> Match {
        if let Err(reason) = self.budget.charge(1, 0) {
            return unknown(reason);
        }
        if let ResourceExpr::Union { alternatives } = expr {
            return self.union(alternatives, contains, |this, expr| {
                this.scope(scope, expr, contains)
            });
        }
        if matches!(expr, ResourceExpr::Join { .. })
            && let Some((path, alternatives)) = join_union(expr)
        {
            return self.union(alternatives, contains, |this, alternative| {
                if let Err(reason) = this.budget.serialized(expr) {
                    return unknown(reason);
                }
                let branch = replace_join_alternative(expr, &path, alternative);
                this.scope(scope, &branch, contains)
            });
        }
        let domain = match &scope.set {
            ScopeSet::Exact { identity } => {
                crate::ResourceFamily::new(crate::identity_family(identity)).domain()
            }
            ScopeSet::Pattern { pattern } => pattern.family().domain(),
            ScopeSet::FsSubtree { .. } => Some("filesystem"),
        };
        if let (Some(a), Some(b)) = (domain, crate::resource_domain(expr))
            && a != b
        {
            return Match::NotSatisfied;
        }
        if matches!(
            &scope.set,
            ScopeSet::Pattern {
                pattern: ResourcePattern::ArtifactField { .. }
            }
        ) || matches!(
            expr,
            ResourceExpr::Pattern {
                pattern: ResourcePattern::ArtifactField { .. }
            }
        ) {
            return unknown(MatchReason::UnsupportedShape);
        }
        if let ScopeSet::Pattern {
            pattern: ResourcePattern::FsPath { glob },
        } = &scope.set
        {
            let (resolved, steps) = match self.filesystem_glob(glob) {
                Ok(value) => value,
                Err(reason) => return unknown(reason),
            };
            if &resolved != glob {
                let scope = Scope {
                    realm: None,
                    set: ScopeSet::Pattern {
                        pattern: ResourcePattern::FsPath { glob: resolved },
                    },
                };
                return and(
                    self.scope(&scope, expr, contains),
                    Match::Satisfied {
                        proof: Proof { steps },
                    },
                );
            }
        }
        if matches!(expr, ResourceExpr::Join { .. }) {
            match self.joined_glob(expr) {
                Ok(Some((glob, steps))) => {
                    return and(
                        self.scope(
                            scope,
                            &ResourceExpr::Pattern {
                                pattern: ResourcePattern::FsPath { glob },
                            },
                            contains,
                        ),
                        Match::Satisfied {
                            proof: Proof { steps },
                        },
                    );
                }
                Err(reason) => return unknown(reason),
                _ => (),
            }
        }
        if let ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath { glob },
        } = expr
        {
            let (resolved, steps) = match self.filesystem_glob(glob) {
                Ok(value) => value,
                Err(reason) => return unknown(reason),
            };
            if &resolved != glob {
                let expr = ResourceExpr::Pattern {
                    pattern: ResourcePattern::FsPath { glob: resolved },
                };
                return and(
                    self.scope(scope, &expr, contains),
                    Match::Satisfied {
                        proof: Proof { steps },
                    },
                );
            }
        }
        if let ScopeSet::Exact { identity } = &scope.set {
            if !contains {
                return self.member(identity, expr);
            }
            if let ResourceExpr::Concrete { identity: actual } = expr {
                return self.exact(actual, identity);
            }
        }
        if let ResourceExpr::Concrete { identity } = expr {
            return match &scope.set {
                ScopeSet::Exact { identity: expected } => self.exact(identity, expected),
                ScopeSet::Pattern { pattern } => self.pattern_member(identity, pattern),
                ScopeSet::FsSubtree { root } => match identity {
                    ResourceIdentity::FsPath { path } => match self.path(path.clone(), vec![]) {
                        Ok((path, steps)) => and(
                            truth(subtree(
                                &crate::normalize_path(root, self.bindings.platform),
                                &path,
                            )),
                            Match::Satisfied {
                                proof: Proof { steps },
                            },
                        ),
                        Err(reason) => unknown(reason),
                    },
                    _ => Match::NotSatisfied,
                },
            };
        }
        if !contains
            && let ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { glob },
            } = expr
        {
            let mut candidates = Vec::new();
            let mut globs = vec![glob.as_str()];
            match &scope.set {
                ScopeSet::FsSubtree { root } => candidates.push(root.clone()),
                ScopeSet::Pattern {
                    pattern: ResourcePattern::FsPath { glob },
                } => globs.push(glob),
                _ => (),
            }
            for glob in globs {
                if let Err(reason) = self
                    .budget
                    .charge(glob.len(), glob.len().saturating_mul(64))
                {
                    return unknown(reason);
                }
                match crate::glob::glob_witness(glob, &mut self.budget.work) {
                    Ok(Some(candidate)) => candidates.push(candidate),
                    Err(crate::glob::GlobError::Limit) => return unknown(MatchReason::Limit),
                    _ => (),
                }
            }
            for path in candidates {
                let identity = ResourceIdentity::FsPath { path };
                let in_expr = self.member(&identity, expr);
                let in_scope = self.scope(scope, &ResourceExpr::Concrete { identity }, false);
                let matched = and(in_expr, in_scope);
                if matches!(matched, Match::Satisfied { .. }) {
                    return matched;
                }
            }
        }
        if let (ScopeSet::Pattern { pattern: expected }, ResourceExpr::Pattern { pattern }) =
            (&scope.set, expr)
        {
            if expected.domain() != pattern.domain() {
                return Match::NotSatisfied;
            }
            if contains && expected == pattern {
                return yes();
            }
        }
        if let (
            ScopeSet::FsSubtree { root },
            ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { glob },
            },
        ) = (&scope.set, expr)
        {
            let mut prefix = glob
                .split('/')
                .take_while(|segment| !segment.contains(['*', '?', '[', '\\']))
                .collect::<Vec<_>>()
                .join("/");
            if prefix.is_empty() && glob.starts_with('/') {
                prefix.push('/');
            }
            if !crate::is_absolute_path(glob, self.bindings.platform) {
                return unknown(MatchReason::Unbound {
                    names: vec!["cwd".into()],
                });
            }
            if contains && subtree(root, &prefix) {
                return yes();
            }
            // An empty prefix supplies no literal branch to prove disjointness.
            if !prefix.is_empty() && !subtree(root, &prefix) && !subtree(&prefix, root) {
                return Match::NotSatisfied;
            }
        }
        if matches!(expr, ResourceExpr::Unresolved { .. }) {
            return unknown(MatchReason::UnresolvedFamily);
        }
        if matches!(
            expr,
            ResourceExpr::Literal { .. }
                | ResourceExpr::Environment { .. }
                | ResourceExpr::Parameter { .. }
                | ResourceExpr::Join { .. }
        ) && domain == Some("filesystem")
        {
            return match self
                .text(expr, true)
                .and_then(|(value, steps)| self.path(value, steps))
            {
                Ok((path, steps)) => and(
                    self.scope(
                        scope,
                        &ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        },
                        contains,
                    ),
                    Match::Satisfied {
                        proof: Proof { steps },
                    },
                ),
                Err(reason) => unknown(reason),
            };
        }
        unknown(MatchReason::UnsupportedShape)
    }
}

pub const SATISFIES_CASE_SCHEMA_V1: &str = "effinterp/satisfies-case/v1";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SatisfiesCase {
    pub schema: String,
    pub id: String,
    pub request: RelationRequest,
    pub expected: Match,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
}
impl SatisfiesCase {
    pub fn replay(&self) -> Result<(), String> {
        if self.schema != SATISFIES_CASE_SCHEMA_V1 || self.id.is_empty() {
            return Err("invalid satisfies case identity".into());
        }
        if self.request.validate() == Err(MatchReason::InvalidInput) {
            return Err("invalid relation input".into());
        }
        let actual = self.request.evaluate();
        if matches!(
            actual,
            Match::Indeterminate {
                reason: MatchReason::InvalidInput
            }
        ) {
            return Err("invalid relation input".into());
        }
        if actual != self.expected {
            return Err(format!("expected {:?}, got {actual:?}", self.expected));
        }
        Ok(())
    }
    pub fn from_canonical_json(input: &str) -> Result<Self, String> {
        if input.len() > RELATION_BYTE_LIMIT {
            return Err("relation input limit".into());
        }
        crate::canonical::reject_duplicate_keys(input).map_err(|e| e.to_string())?;
        let case: Self = serde_json::from_str(input).map_err(|e| e.to_string())?;
        case.replay()?;
        if crate::canonical_json(&case) != input {
            return Err("noncanonical satisfies case".into());
        }
        Ok(case)
    }
}

fn normalize_host(host: &str) -> String {
    let identity = crate::resource::normalize_identity(
        ResourceIdentity::NetworkEndpoint {
            host: host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            scheme: None,
            port: None,
            path: None,
        },
        PathPlatform::Posix,
    );
    let ResourceIdentity::NetworkEndpoint { host, .. } = identity else {
        unreachable!()
    };
    host
}
fn parse_endpoint(text: &str) -> Result<ResourceIdentity, MatchReason> {
    let (scheme, rest) = text
        .split_once("://")
        .map_or((None, text), |(scheme, rest)| {
            (Some(scheme.to_string()), rest)
        });
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    let (host, port) = if let Some(address) = authority.strip_prefix('[') {
        let (host, tail) = address.split_once(']').ok_or(MatchReason::InvalidInput)?;
        (
            host,
            if tail.is_empty() {
                None
            } else {
                Some(tail.strip_prefix(':').ok_or(MatchReason::InvalidInput)?)
            },
        )
    } else if authority.matches(':').count() == 1 {
        let (host, port) = authority.rsplit_once(':').unwrap();
        (host, Some(port))
    } else {
        (authority, None)
    };
    if host.is_empty() {
        return Err(MatchReason::InvalidInput);
    }
    let port = port
        .map(|port| port.parse::<u16>().map_err(|_| MatchReason::InvalidInput))
        .transpose()?;
    Ok(ResourceIdentity::NetworkEndpoint {
        host: host.to_string(),
        scheme,
        port,
        path: (!path.is_empty()).then(|| path.to_string()),
    })
}

fn truncated_arg(expr: &ResourceExpr) -> bool {
    matches!(expr,ResourceExpr::Unresolved { family } if family.0 == "process")
}

fn join_union(expr: &ResourceExpr) -> Option<(Vec<usize>, &[ResourceExpr])> {
    match expr {
        ResourceExpr::Union { alternatives } => Some((vec![], alternatives)),
        ResourceExpr::Join { parts } => parts.iter().enumerate().find_map(|(index, part)| {
            let (mut path, alternatives) = join_union(part)?;
            path.insert(0, index);
            Some((path, alternatives))
        }),
        _ => None,
    }
}
fn replace_join_alternative(
    expr: &ResourceExpr,
    path: &[usize],
    alternative: &ResourceExpr,
) -> ResourceExpr {
    if path.is_empty() {
        return alternative.clone();
    }
    let ResourceExpr::Join { parts } = expr else {
        unreachable!()
    };
    ResourceExpr::Join {
        parts: parts
            .iter()
            .enumerate()
            .map(|(index, part)| {
                if index == path[0] {
                    replace_join_alternative(part, &path[1..], alternative)
                } else {
                    part.clone()
                }
            })
            .collect(),
    }
}

fn required_scope_realm<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ExecutionRealm>, D::Error> {
    Option::<ExecutionRealm>::deserialize(deserializer)
}

pub(crate) fn validate_pattern_input(pattern: &ResourcePattern) -> Result<(), MatchReason> {
    Budget::default().pattern(pattern, 0)
}

// Keep nested union order intact: proof indexes refer to the supplied alternatives.
fn normalize_relation_identity(
    identity: &ResourceIdentity,
    platform: PathPlatform,
) -> ResourceIdentity {
    let mut normalized = crate::resource::normalize_identity(identity.clone(), platform);
    for (original, value) in identity
        .infrastructure_values()
        .into_iter()
        .zip(normalized.infrastructure_values_mut())
    {
        *value = original.clone();
    }
    if let (Some(original), Some(scope)) = (identity.scope(), normalized.scope_mut()) {
        *scope = original.clone();
    }
    if let (
        ResourceIdentity::Container {
            storage: original, ..
        },
        ResourceIdentity::Container { storage, .. },
    ) = (identity, &mut normalized)
    {
        *storage = original.clone();
        storage.sort_by_cached_key(|item| {
            crate::canonical_json(&crate::resource::normalize_identity(
                ResourceIdentity::Container {
                    runtime: String::new(),
                    name: None,
                    image: None,
                    storage: vec![item.clone()],
                },
                platform,
            ))
        });
        storage.dedup();
    }
    normalized
}

// Inspect borrowed values before JSON encoding can scan or allocate an oversized
// string. Container and string reservations bound later canonicalization scratch.
struct InputInspector<'a> {
    budget: &'a mut Budget,
    depth: usize,
}
struct InspectedFields<'a, 'b>(&'a mut InputInspector<'b>);
#[derive(Debug)]
struct InputLimit;
impl std::fmt::Display for InputLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("relation input limit")
    }
}
impl std::error::Error for InputLimit {}
impl serde::ser::Error for InputLimit {
    fn custom<T: std::fmt::Display>(_: T) -> Self {
        Self
    }
}
impl<'b> InputInspector<'b> {
    fn charge(&mut self, work: usize, bytes: usize) -> Result<(), InputLimit> {
        self.budget.charge(work, bytes).map_err(|_| InputLimit)
    }
    fn fields<'a>(&'a mut self, count: usize) -> Result<InspectedFields<'a, 'b>, InputLimit> {
        if self.depth >= RELATION_DEPTH_LIMIT {
            return Err(InputLimit);
        }
        self.charge(count.saturating_add(1), 256)?;
        self.depth += 1;
        Ok(InspectedFields(self))
    }
}
impl<'a, 'b> serde::Serializer for &'a mut InputInspector<'b> {
    type Ok = ();
    type Error = InputLimit;
    type SerializeSeq = InspectedFields<'a, 'b>;
    type SerializeTuple = InspectedFields<'a, 'b>;
    type SerializeTupleStruct = InspectedFields<'a, 'b>;
    type SerializeTupleVariant = InspectedFields<'a, 'b>;
    type SerializeMap = InspectedFields<'a, 'b>;
    type SerializeStruct = InspectedFields<'a, 'b>;
    type SerializeStructVariant = InspectedFields<'a, 'b>;
    fn serialize_bool(self, _: bool) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_i8(self, _: i8) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_i16(self, _: i16) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_i32(self, _: i32) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_i64(self, _: i64) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_u8(self, _: u8) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_u16(self, _: u16) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_u32(self, _: u32) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_u64(self, _: u64) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_f32(self, _: f32) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_f64(self, _: f64) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_char(self, _: char) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_i128(self, _: i128) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_u128(self, _: u128) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }

    fn serialize_str(self, value: &str) -> Result<(), InputLimit> {
        self.charge(
            value.len().saturating_add(1),
            value.len().saturating_mul(64),
        )
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<(), InputLimit> {
        self.charge(
            value.len().saturating_add(1),
            value.len().saturating_mul(64),
        )
    }
    fn serialize_none(self) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), InputLimit> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), InputLimit> {
        self.charge(1, 0)
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<(), InputLimit> {
        self.serialize_str(variant)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), InputLimit> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), InputLimit> {
        self.charge(variant.len(), variant.len().saturating_mul(64))?;
        value.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, InputLimit> {
        self.fields(len.unwrap_or(0))
    }
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, InputLimit> {
        self.fields(len)
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, InputLimit> {
        self.fields(len)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, InputLimit> {
        self.fields(len)
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, InputLimit> {
        self.fields(len.unwrap_or(0))
    }
    fn serialize_struct(
        self,
        _: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, InputLimit> {
        self.fields(len)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, InputLimit> {
        self.fields(len)
    }
}
impl serde::ser::SerializeSeq for InspectedFields<'_, '_> {
    type Ok = ();
    type Error = InputLimit;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), InputLimit> {
        value.serialize(&mut *self.0)
    }
    fn end(self) -> Result<(), InputLimit> {
        self.0.depth -= 1;
        Ok(())
    }
}
impl serde::ser::SerializeTuple for InspectedFields<'_, '_> {
    type Ok = ();
    type Error = InputLimit;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), InputLimit> {
        value.serialize(&mut *self.0)
    }
    fn end(self) -> Result<(), InputLimit> {
        self.0.depth -= 1;
        Ok(())
    }
}
impl serde::ser::SerializeTupleStruct for InspectedFields<'_, '_> {
    type Ok = ();
    type Error = InputLimit;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), InputLimit> {
        value.serialize(&mut *self.0)
    }
    fn end(self) -> Result<(), InputLimit> {
        self.0.depth -= 1;
        Ok(())
    }
}
impl serde::ser::SerializeTupleVariant for InspectedFields<'_, '_> {
    type Ok = ();
    type Error = InputLimit;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), InputLimit> {
        value.serialize(&mut *self.0)
    }
    fn end(self) -> Result<(), InputLimit> {
        self.0.depth -= 1;
        Ok(())
    }
}
impl serde::ser::SerializeMap for InspectedFields<'_, '_> {
    type Ok = ();
    type Error = InputLimit;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), InputLimit> {
        value.serialize(&mut *self.0)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), InputLimit> {
        value.serialize(&mut *self.0)
    }
    fn end(self) -> Result<(), InputLimit> {
        self.0.depth -= 1;
        Ok(())
    }
}
impl serde::ser::SerializeStruct for InspectedFields<'_, '_> {
    type Ok = ();
    type Error = InputLimit;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), InputLimit> {
        self.0.charge(key.len(), key.len().saturating_mul(64))?;
        value.serialize(&mut *self.0)
    }
    fn end(self) -> Result<(), InputLimit> {
        self.0.depth -= 1;
        Ok(())
    }
}
impl serde::ser::SerializeStructVariant for InspectedFields<'_, '_> {
    type Ok = ();
    type Error = InputLimit;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), InputLimit> {
        self.0.charge(key.len(), key.len().saturating_mul(64))?;
        value.serialize(&mut *self.0)
    }
    fn end(self) -> Result<(), InputLimit> {
        self.0.depth -= 1;
        Ok(())
    }
}
