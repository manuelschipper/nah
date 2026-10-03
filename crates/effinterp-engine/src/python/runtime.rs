//! Bounded execution evidence for runtime-owned import demand.

use std::collections::BTreeMap;

use effinterp_proto::ExecutionInputReason;
use rustpython_parser::Parse;
use rustpython_parser::ast::{self, Constant, Expr, Stmt};

/// Module requests with proven execution; false means reachability is uncertain.
/// Straight-line module/class execution, literal branches, and direct calls to
/// locally bound zero-argument functions prove demand. Other callable/control-flow
/// bodies retain requests as uncertainty evidence.
pub(crate) fn runtime_imports(
    source: &str,
    max_nodes: u64,
) -> Result<BTreeMap<String, bool>, ExecutionInputReason> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum StatementFlow {
        Next,
        Return,
        Raise,
        Uncertain,
    }

    fn collect(
        statements: &[Stmt],
        mut definite: bool,
        imports: &mut BTreeMap<String, bool>,
        remaining: &mut u64,
    ) -> StatementFlow {
        let mut flow = StatementFlow::Next;
        let mut functions = BTreeMap::new();
        for statement in statements {
            if *remaining == 0 {
                return StatementFlow::Uncertain;
            }
            *remaining -= 1;
            if !matches!(
                statement,
                Stmt::FunctionDef(_)
                    | Stmt::Import(_)
                    | Stmt::ImportFrom(_)
                    | Stmt::Expr(_)
                    | Stmt::Pass(_)
            ) {
                functions.clear();
            }
            match statement {
                Stmt::Import(import) => {
                    for alias in &import.names {
                        functions.remove(
                            alias
                                .asname
                                .as_deref()
                                .unwrap_or_else(|| alias.name.as_str().split('.').next().unwrap()),
                        );
                        imports
                            .entry(alias.name.to_string())
                            .and_modify(|reached| *reached |= definite)
                            .or_insert(definite);
                        // Demand for this import does not prove that it finishes.
                        // Ordinary dependencies are not opened to establish continuation.
                        definite = false;
                        flow = StatementFlow::Uncertain;
                    }
                }
                Stmt::ImportFrom(import) => {
                    functions.clear();
                    imports
                        .entry(super::import_bindings::import_from_module(import))
                        .and_modify(|reached| *reached |= definite)
                        .or_insert(definite);
                    // Attribute resolution can fail even for a builtin module.
                    definite = false;
                    flow = StatementFlow::Uncertain;
                }
                Stmt::ClassDef(class) => {
                    if !class.bases.is_empty()
                        || !class.keywords.is_empty()
                        || !class.decorator_list.is_empty()
                        || !class.type_params.is_empty()
                    {
                        definite = false;
                        flow = StatementFlow::Uncertain;
                    }
                    let step = collect(&class.body, definite, imports, remaining);
                    match step {
                        StatementFlow::Return | StatementFlow::Raise => {
                            return if flow == StatementFlow::Uncertain {
                                flow
                            } else {
                                step
                            };
                        }
                        StatementFlow::Uncertain => {
                            definite = false;
                            flow = step;
                        }
                        StatementFlow::Next => {}
                    }
                }
                Stmt::If(statement) => {
                    let step = match literal_truth(&statement.test) {
                        Some(true) => collect(&statement.body, definite, imports, remaining),
                        Some(false) => collect(&statement.orelse, definite, imports, remaining),
                        None => {
                            collect(&statement.body, false, imports, remaining);
                            collect(&statement.orelse, false, imports, remaining);
                            // Evaluating the condition itself may prevent either branch.
                            StatementFlow::Uncertain
                        }
                    };
                    match step {
                        StatementFlow::Return | StatementFlow::Raise => {
                            return if flow == StatementFlow::Uncertain {
                                flow
                            } else {
                                step
                            };
                        }
                        StatementFlow::Uncertain => {
                            definite = false;
                            flow = step;
                        }
                        StatementFlow::Next => {}
                    }
                }
                Stmt::FunctionDef(function) => {
                    collect(&function.body, false, imports, remaining);
                    // Definition-time expressions can fail before later code runs.
                    // Their evaluation is unsupported, including future annotations.
                    if function.returns.is_some()
                        || !function.decorator_list.is_empty()
                        || !function.type_params.is_empty()
                        || argument_definition_expressions(&function.args)
                    {
                        definite = false;
                        flow = StatementFlow::Uncertain;
                    }
                    if function.decorator_list.is_empty()
                        && function.returns.is_none()
                        && function.type_params.is_empty()
                        && function.args.posonlyargs.is_empty()
                        && function.args.args.is_empty()
                        && function.args.kwonlyargs.is_empty()
                        && function.args.vararg.is_none()
                        && function.args.kwarg.is_none()
                        && !super::definitions::body_has_yield(&function.body)
                    {
                        functions.insert(function.name.as_str(), function.body.as_slice());
                    } else {
                        functions.remove(function.name.as_str());
                    }
                }
                Stmt::Expr(expression) => {
                    if let Expr::Call(call) = expression.value.as_ref()
                        && let Expr::Name(name) = call.func.as_ref()
                        && call.args.is_empty()
                        && call.keywords.is_empty()
                        && let Some(body) = functions.get(name.id.as_str())
                    {
                        match collect(body, definite, imports, remaining) {
                            StatementFlow::Raise => {
                                return if flow == StatementFlow::Uncertain {
                                    flow
                                } else {
                                    StatementFlow::Raise
                                };
                            }
                            StatementFlow::Uncertain => {
                                definite = false;
                                flow = StatementFlow::Uncertain;
                            }
                            StatementFlow::Next | StatementFlow::Return => {}
                        }
                    } else if !matches!(expression.value.as_ref(), Expr::Constant(_)) {
                        definite = false;
                        flow = StatementFlow::Uncertain;
                    }
                    functions.clear();
                }
                Stmt::AsyncFunctionDef(function) => {
                    collect(&function.body, false, imports, remaining);
                    if function.returns.is_some()
                        || !function.decorator_list.is_empty()
                        || !function.type_params.is_empty()
                        || argument_definition_expressions(&function.args)
                    {
                        definite = false;
                        flow = StatementFlow::Uncertain;
                    }
                }
                Stmt::For(statement) => {
                    collect(&statement.body, false, imports, remaining);
                    collect(&statement.orelse, false, imports, remaining);
                }
                Stmt::AsyncFor(statement) => {
                    collect(&statement.body, false, imports, remaining);
                    collect(&statement.orelse, false, imports, remaining);
                }
                Stmt::While(statement) => {
                    collect(&statement.body, false, imports, remaining);
                    collect(&statement.orelse, false, imports, remaining);
                }
                Stmt::Try(statement) => {
                    collect(&statement.body, false, imports, remaining);
                    for handler in &statement.handlers {
                        let ast::ExceptHandler::ExceptHandler(handler) = handler;
                        collect(&handler.body, false, imports, remaining);
                    }
                    collect(&statement.orelse, false, imports, remaining);
                    collect(&statement.finalbody, false, imports, remaining);
                }
                Stmt::TryStar(statement) => {
                    collect(&statement.body, false, imports, remaining);
                    for handler in &statement.handlers {
                        let ast::ExceptHandler::ExceptHandler(handler) = handler;
                        collect(&handler.body, false, imports, remaining);
                    }
                    collect(&statement.orelse, false, imports, remaining);
                    collect(&statement.finalbody, false, imports, remaining);
                }
                Stmt::With(statement) => {
                    collect(&statement.body, false, imports, remaining);
                    definite = false;
                    flow = StatementFlow::Uncertain;
                }
                Stmt::AsyncWith(statement) => {
                    collect(&statement.body, false, imports, remaining);
                    definite = false;
                    flow = StatementFlow::Uncertain;
                }
                Stmt::Match(statement) => {
                    for case in &statement.cases {
                        collect(&case.body, false, imports, remaining);
                    }
                }
                Stmt::Return(statement) => {
                    return if flow == StatementFlow::Uncertain
                        || statement
                            .value
                            .as_ref()
                            .is_some_and(|value| !matches!(value.as_ref(), Expr::Constant(_)))
                    {
                        StatementFlow::Uncertain
                    } else {
                        StatementFlow::Return
                    };
                }
                Stmt::Raise(_) => {
                    return if flow == StatementFlow::Uncertain {
                        flow
                    } else {
                        StatementFlow::Raise
                    };
                }
                Stmt::Break(_) | Stmt::Continue(_) => return StatementFlow::Uncertain,
                Stmt::Pass(_) | Stmt::Global(_) | Stmt::Nonlocal(_) => {}
                Stmt::Assign(statement)
                    if matches!(statement.value.as_ref(), Expr::Constant(_))
                        && statement
                            .targets
                            .iter()
                            .all(|target| matches!(target, Expr::Name(_))) => {}
                _ => {
                    // Unsupported expressions and assignment targets may raise before
                    // subsequent imports, including inside a directly called function.
                    definite = false;
                    flow = StatementFlow::Uncertain;
                }
            }
            if matches!(
                statement,
                Stmt::For(_)
                    | Stmt::AsyncFor(_)
                    | Stmt::While(_)
                    | Stmt::Try(_)
                    | Stmt::TryStar(_)
                    | Stmt::Match(_)
            ) {
                definite = false;
                flow = StatementFlow::Uncertain;
            }
        }
        flow
    }
    let suite = ast::Suite::parse(source, "<python-runtime-selection>")
        .map_err(|_| ExecutionInputReason::Ambiguous)?;
    let mut imports = BTreeMap::new();
    let mut remaining = max_nodes;
    collect(&suite, true, &mut imports, &mut remaining);
    if remaining == 0 {
        return Err(ExecutionInputReason::BudgetRefused {
            limit: "max_python_nodes".to_string(),
        });
    }
    Ok(imports)
}

fn literal_truth(expression: &Expr) -> Option<bool> {
    let Expr::Constant(value) = expression else {
        return None;
    };
    match &value.value {
        Constant::Bool(value) => Some(*value),
        Constant::None => Some(false),
        Constant::Int(value) => Some(value != &0.into()),
        Constant::Float(value) => Some(*value != 0.0),
        Constant::Str(value) => Some(!value.is_empty()),
        Constant::Bytes(value) => Some(!value.is_empty()),
        _ => None,
    }
}

fn argument_definition_expressions(args: &ast::Arguments) -> bool {
    args.posonlyargs
        .iter()
        .chain(&args.args)
        .chain(&args.kwonlyargs)
        .any(|arg| arg.default.is_some() || arg.def.annotation.is_some())
        || args
            .vararg
            .as_ref()
            .is_some_and(|arg| arg.annotation.is_some())
        || args
            .kwarg
            .as_ref()
            .is_some_and(|arg| arg.annotation.is_some())
}
