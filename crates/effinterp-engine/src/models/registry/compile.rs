//! Compilation of validated documents into the runtime registry.

use super::*;

pub struct CompiledRegistry {
    pub(super) command_models: Vec<DeclarativeCommandModel>,
    pub(super) library_apis: Vec<CompiledLibraryApi>,
    pub(super) mcp_tools: Vec<CompiledMcpTool>,
    pub(super) lifecycles: Vec<FrameworkLifecycle>,
    pub(super) declaration_digests: BTreeMap<String, String>,
    pub(super) document_identities: Vec<String>,
    pub(super) model_set_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledLibraryApi {
    pub(crate) lang: LifecycleLanguage,
    pub(crate) targets: Vec<String>,
    pub(crate) operation: String,
    pub(crate) model: String,
}

impl CompiledRegistry {
    pub fn lifecycles(&self) -> &[FrameworkLifecycle] {
        &self.lifecycles
    }

    pub fn declaration_digests(&self) -> &BTreeMap<String, String> {
        &self.declaration_digests
    }

    pub fn document_identities(&self) -> &[String] {
        &self.document_identities
    }

    pub fn model_set_digest(&self) -> &str {
        &self.model_set_digest
    }

    pub fn command_ids(&self) -> Vec<&str> {
        self.command_models.iter().map(|model| model.id()).collect()
    }

    pub(crate) fn library_apis(&self) -> &[CompiledLibraryApi] {
        &self.library_apis
    }

    pub(crate) fn mcp_tools(&self) -> &[CompiledMcpTool] {
        &self.mcp_tools
    }

    pub(crate) fn into_command_models(self) -> Vec<Box<dyn CommandModel>> {
        self.command_models
            .into_iter()
            .map(|model| Box::new(model) as Box<dyn CommandModel>)
            .collect()
    }
}

/// Compile promoted pack documents after the bundled documents; ownership is exclusive.
pub fn compile_registry_with_builtin(sources: &[&str]) -> Result<CompiledRegistry, RegistryError> {
    let sources = PROMOTED_MODEL_SOURCES
        .iter()
        .copied()
        .chain(sources.iter().copied())
        .collect::<Vec<_>>();
    compile_registry(&sources)
}

/// Compile model documents into one registry, validating each document's schema,
/// identity, canonical form and declarations. Command ownership is exclusive.
pub fn compile_registry(sources: &[&str]) -> Result<CompiledRegistry, RegistryError> {
    let mut documents = Vec::new();
    for source in sources {
        let document: DeclarationDocument =
            serde_json::from_str(source).map_err(|error| RegistryError::Json(error.to_string()))?;
        effinterp_model_schema::validate_bundled_document(source, &document)
            .map_err(|detail| invalid("document", detail))?;
        validate_document(&document)?;
        documents.push(document);
    }
    compile_documents(documents)
}

struct BundledDeclaration {
    declaration: Declaration,
    document_identity: String,
    fragments: BTreeMap<String, BehaviorDeclaration>,
}

fn compile_documents(
    documents: Vec<DeclarationDocument>,
) -> Result<CompiledRegistry, RegistryError> {
    let mut declarations = Vec::new();
    let mut document_identities = Vec::new();
    for document in documents {
        document_identities.push(document.identity.clone());
        for declaration in document.entries {
            declarations.push(BundledDeclaration {
                declaration,
                document_identity: document.identity.clone(),
                fragments: document.fragments.clone(),
            });
        }
    }
    declarations.sort_by(|left, right| left.declaration.id().cmp(right.declaration.id()));
    document_identities.sort();

    let mut ids = BTreeSet::new();
    let mut ownership = BTreeMap::<String, String>::new();
    let mut lifecycle_keys = BTreeMap::new();
    let mut command_models = Vec::new();
    let mut library_apis = Vec::new();
    let mut mcp_tools = Vec::<CompiledMcpTool>::new();
    let mut lifecycles = Vec::new();
    let mut declaration_digests = BTreeMap::new();

    for bundled in declarations {
        let id = bundled.declaration.id().to_string();
        if !ids.insert(id.clone()) {
            return Err(RegistryError::DuplicateId(id));
        }
        validate_id(&id)?;
        let digest = declaration_digest(&bundled.document_identity, &bundled.declaration);
        declaration_digests.insert(id.clone(), digest.clone());
        match bundled.declaration {
            Declaration::Command(mut command) => {
                let mut expanded = BehaviorDeclaration::default();
                for fragment in &command.fragments {
                    let behavior = bundled
                        .fragments
                        .get(fragment)
                        .ok_or_else(|| invalid(&id, format!("unknown fragment {fragment:?}")))?;
                    expanded.extend(behavior);
                }
                expanded.extend(&command.behavior);
                command.behavior = expanded;
                validate_command(&command)?;
                for name in &command.commands {
                    if let Some(first) = ownership.insert(name.clone(), id.clone()) {
                        return Err(RegistryError::CommandOwnership {
                            command: name.clone(),
                            first,
                            second: id,
                        });
                    }
                }
                command_models.push(DeclarativeCommandModel::new(command, digest));
            }
            Declaration::Lifecycle(lifecycle) => {
                validate_lifecycle(&lifecycle, &mut lifecycle_keys)?;
                lifecycles.push(compile_lifecycle(lifecycle));
            }
            Declaration::LibraryApi(api) => {
                validate_library_api(&api)?;
                library_apis.extend(api.symbols.into_iter().map(|symbol| {
                    CompiledLibraryApi {
                        lang: api.lang,
                        targets: std::iter::once(callable_target(&symbol.target))
                            .chain(symbol.aliases)
                            .collect(),
                        operation: symbol.operation,
                        model: format!("{}#blake3:{digest}", api.id),
                    }
                }));
            }
            Declaration::McpTool(tool) => {
                validate_mcp_tool(&tool)?;
                // Two declarations for one tool of one server would make the
                // call's behavior depend on declaration order.
                if let Some(first) = mcp_tools.iter().find(|compiled| {
                    compiled.declaration.tool == tool.tool
                        && compiled
                            .declaration
                            .servers
                            .iter()
                            .any(|server| tool.servers.contains(server))
                }) {
                    return Err(invalid(
                        &id,
                        format!(
                            "MCP tool {:?} is also declared by {:?}",
                            tool.tool, first.declaration.id
                        ),
                    ));
                }
                mcp_tools.push(CompiledMcpTool {
                    model: format!("{id}#blake3:{digest}"),
                    declaration: tool,
                });
            }
        }
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(COMPILER_SCHEMA_V2.as_bytes());
    hasher.update(b"\0");
    for (id, digest) in &declaration_digests {
        hasher.update(id.as_bytes());
        hasher.update(b"\0");
        hasher.update(digest.as_bytes());
        hasher.update(b"\0");
    }

    Ok(CompiledRegistry {
        command_models,
        library_apis,
        mcp_tools,
        lifecycles,
        declaration_digests,
        document_identities,
        model_set_digest: format!("blake3:{}", hasher.finalize().to_hex()),
    })
}

// Build-generated, predecoded values borrow their strings and containers directly
// from the binary. Serde only materializes a command when it is first selected.
pub(super) enum ModelValue {
    Null,
    Bool(bool),
    Number(u64, bool),
    String(&'static str),
    Seq(&'static [Self]),
    Map(&'static [(&'static str, Self)]),
}

impl<'de> serde::de::IntoDeserializer<'de, serde::de::value::Error> for &'de ModelValue {
    type Deserializer = Self;

    fn into_deserializer(self) -> Self {
        self
    }
}

impl<'de> serde::Deserializer<'de> for &'de ModelValue {
    type Error = serde::de::value::Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        use serde::de::value::{MapDeserializer, SeqDeserializer};
        match self {
            ModelValue::Null => visitor.visit_unit(),
            ModelValue::Bool(value) => visitor.visit_bool(*value),
            ModelValue::Number(value, false) => visitor.visit_u64(*value),
            ModelValue::Number(value, true) => visitor.visit_i64((*value as i64).wrapping_neg()),
            ModelValue::String(value) => visitor.visit_borrowed_str(value),
            ModelValue::Seq(values) => visitor.visit_seq(SeqDeserializer::new(values.iter())),
            ModelValue::Map(values) => visitor.visit_map(MapDeserializer::new(
                values.iter().map(|(key, value)| (*key, value)),
            )),
        }
    }

    fn deserialize_option<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self {
            ModelValue::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        use serde::de::IntoDeserializer;
        match self {
            ModelValue::String(value) => visitor.visit_enum((*value).into_deserializer()),
            _ => unreachable!("generated unit enum is a string"),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf
        unit unit_struct newtype_struct seq tuple tuple_struct map struct identifier ignored_any
    }
}

#[cfg(test)]
pub(crate) fn builtin_registry() -> CompiledRegistry {
    generated_registry()
}

pub(in crate::models) fn builtin_command_models() -> Vec<Box<dyn CommandModel>> {
    generated_command_models()
        .into_iter()
        .map(|model| Box::new(model) as Box<dyn CommandModel>)
        .collect()
}

pub(in crate::models) fn builtin_library_apis() -> &'static [CompiledLibraryApi] {
    static LIBRARY_APIS: LazyLock<Vec<CompiledLibraryApi>> = LazyLock::new(generated_library_apis);
    &LIBRARY_APIS
}

pub(in crate::models) fn builtin_mcp_tools() -> &'static [CompiledMcpTool] {
    static MCP_TOOLS: LazyLock<Vec<CompiledMcpTool>> = LazyLock::new(generated_mcp_tools);
    &MCP_TOOLS
}

pub(in crate::models) fn builtin_document_identities() -> &'static [String] {
    static DOCUMENT_IDENTITIES: LazyLock<Vec<String>> =
        LazyLock::new(generated_document_identities);
    &DOCUMENT_IDENTITIES
}

pub(crate) fn builtin_lifecycles() -> Vec<FrameworkLifecycle> {
    generated_lifecycles()
}

pub(super) fn leak_string(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

pub(super) fn leak_strings(values: Vec<String>) -> &'static [&'static str] {
    Box::leak(
        values
            .into_iter()
            .map(leak_string)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}

fn compile_lifecycle(declaration: LifecycleDeclaration) -> FrameworkLifecycle {
    let sigs = declaration
        .signatures
        .into_iter()
        .map(|signature| {
            let (method, receiver_type, import_path) = lifecycle_target(&signature.target);
            LifecycleSig {
                method: method.map(leak_string),
                import_path: import_path.map(leak_string),
                role: signature.role,
                max_args: signature.max_args,
                component: signature.component,
                evidence: signature.evidence,
                receiver_type: receiver_type.map(leak_string),
                fields: leak_strings(signature.fields),
                params: leak_strings(signature.params),
                hooks: leak_strings(signature.hooks),
                derive_result: signature.derive_result,
                result_type: signature.result_type.map(leak_string),
                field_tags: leak_strings(signature.field_tags),
            }
        })
        .collect::<Vec<_>>();
    FrameworkLifecycle {
        id: leak_string(declaration.id),
        lang: declaration.lang.map(|lang| match lang {
            LifecycleLanguage::Python => Lang::Python,
            LifecycleLanguage::Js => Lang::Js(effinterp_proto::SourceDialect::Js),
            LifecycleLanguage::Ts => Lang::Js(effinterp_proto::SourceDialect::Ts),
            LifecycleLanguage::Go => Lang::Go,
            LifecycleLanguage::Ruby => Lang::Ruby,
            LifecycleLanguage::Rust => Lang::Rust,
            LifecycleLanguage::Java => Lang::Java,
            LifecycleLanguage::Php => Lang::Php,
        }),
        sigs: Box::leak(sigs.into_boxed_slice()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_exposes_the_complete_promoted_model_set() {
        let actual = builtin_registry();
        let expected = compile_registry(PROMOTED_MODEL_SOURCES).unwrap();
        assert_eq!(actual.command_ids(), expected.command_ids());
        for (actual, expected) in actual.command_models.iter().zip(&expected.command_models) {
            assert_eq!(*actual.declaration, *expected.declaration, "{}", actual.id);
            assert_eq!(actual.command_names, expected.command_names);
            assert_eq!(actual.domains, expected.domains);
            assert_eq!(actual.digest, expected.digest);
            assert_eq!(actual.value_flags, expected.value_flags);
            assert_eq!(actual.known_flags, expected.known_flags);
            assert_eq!(
                actual.case_insensitive_flags,
                expected.case_insensitive_flags
            );
            assert_eq!(actual.strict_flags, expected.strict_flags);
            assert_eq!(actual.named_value_flags, expected.named_value_flags);
        }
        assert_eq!(actual.library_apis, expected.library_apis);
        assert_eq!(actual.mcp_tools, expected.mcp_tools);
        assert_eq!(actual.document_identities(), expected.document_identities());
        assert_eq!(actual.lifecycles(), expected.lifecycles());
        assert_eq!(actual.declaration_digests(), expected.declaration_digests());
        assert_eq!(actual.model_set_digest(), expected.model_set_digest());
        assert_eq!(
            super::super::super::Catalog::from_registry(actual)
                .unwrap()
                .model_set_id(),
            super::super::super::Catalog::from_registry(expected)
                .unwrap()
                .model_set_id(),
        );
    }
}
