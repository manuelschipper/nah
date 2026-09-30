//! The argument vector a program hands Django's
//! `execute_from_command_line`: a literal list it spells, or `sys.argv` as
//! launched and then changed by literal writes Nah can replay. Any other use
//! of `sys.argv` leaves the vector unknown.

use rustpython_parser::ast::{self, Constant, Expr, Ranged, Stmt, UnaryOp};
use rustpython_parser::text_size::TextRange;
use rustpython_parser::{Mode, Parse, Tok, lexer::lex};

use super::resolve::{Imports, str_literal};

pub(super) enum ArgumentVector {
    /// The command-line words after the program name.
    Known(Vec<String>),
    /// `sys.argv` is launched with words Nah cannot read.
    Symbolic,
    /// The vector is built, changed or shared in a way Nah cannot replay.
    Unknown,
}

/// The vector the call passes. `launch` is the launch's `sys.argv`, with
/// the script at `launch[0]`, when every word is literal.
pub(super) fn argument_vector(
    imports: &Imports,
    source: &str,
    call: &ast::ExprCall,
    launch: Option<Vec<String>>,
) -> ArgumentVector {
    let argument = match (call.args.as_slice(), call.keywords.as_slice()) {
        ([], []) => None,
        ([argument], []) => Some(argument),
        ([], [keyword]) if keyword.arg.as_deref() == Some("argv") => Some(&keyword.value),
        _ => return ArgumentVector::Unknown,
    };
    // Django's ManagementUtility reads `argv or sys.argv[:]`, so an empty
    // sequence or None selects the process's argv.
    let argument = argument.filter(|argument| {
        !matches!(argument,
            Expr::List(ast::ExprList { elts, .. }) | Expr::Tuple(ast::ExprTuple { elts, .. })
                if elts.is_empty())
            && !matches!(
                argument,
                Expr::Constant(ast::ExprConstant {
                    value: Constant::None,
                    ..
                })
            )
    });
    if let Some(Expr::List(ast::ExprList { elts, .. }) | Expr::Tuple(ast::ExprTuple { elts, .. })) =
        argument
    {
        return match elts.iter().map(str_literal).collect::<Option<Vec<_>>>() {
            Some(words) => ArgumentVector::Known(words.into_iter().skip(1).collect()),
            None => ArgumentVector::Unknown,
        };
    }
    if argument.is_some_and(|argument| !is_argv(imports, argument)) {
        return ArgumentVector::Unknown;
    }
    let Ok(suite) = ast::Suite::parse(source, "<python>") else {
        return ArgumentVector::Unknown;
    };
    let mut scan = Scan {
        imports,
        call: call.range,
        argument: argument.map(Ranged::range),
        call_block: None,
        writes: Vec::new(),
        references: 0,
        unknown: false,
        aliases: vec!["argv".to_string()],
        imports_at: Vec::new(),
    };
    scan.block(&suite);
    // Every mention of an alias outside import statements (comments and
    // strings are not name tokens) must be a reference the scan classified.
    let mentions = lex(source, Mode::Module)
        .filter_map(Result::ok)
        .filter(|(token, range)| {
            matches!(token, Tok::Name { name } if scan.aliases.contains(name))
                && !scan
                    .imports_at
                    .iter()
                    .any(|import| import.contains_range(*range))
        })
        .count();
    let Some((block, index)) = scan.call_block else {
        return ArgumentVector::Unknown;
    };
    if scan.unknown || mentions != scan.references {
        return ArgumentVector::Unknown;
    }
    let Some(mut argv) = launch else {
        return ArgumentVector::Symbolic;
    };
    for (statement, write) in scan.writes {
        // A write replays only as a statement of the call's own block that
        // runs before it.
        if !block[..index]
            .iter()
            .any(|earlier| earlier.range() == statement)
            || !write.apply(&mut argv)
        {
            return ArgumentVector::Unknown;
        }
    }
    ArgumentVector::Known(argv.into_iter().skip(1).collect())
}

fn is_argv(imports: &Imports, expr: &Expr) -> bool {
    imports.resolve_callee(expr).as_deref() == Some("sys.argv")
}

enum Write {
    Set(i64, String),
    Append(String),
    Insert(i64, String),
    Extend(Vec<String>),
}

impl Write {
    /// Applies the write as CPython's list does; false where it raises.
    fn apply(self, argv: &mut Vec<String>) -> bool {
        let len = argv.len() as i64;
        match self {
            Self::Set(index, word) => {
                let index = if index < 0 { index + len } else { index };
                if !(0..len).contains(&index) {
                    return false;
                }
                argv[index as usize] = word;
            }
            Self::Append(word) => argv.push(word),
            Self::Insert(index, word) => {
                let index = if index < 0 {
                    (index + len).max(0)
                } else {
                    index.min(len)
                };
                argv.insert(index as usize, word);
            }
            Self::Extend(words) => argv.extend(words),
        }
        true
    }
}

struct Scan<'a, 'b> {
    imports: &'a Imports,
    call: TextRange,
    /// The dispatch call's argument when it spells `sys.argv`.
    argument: Option<TextRange>,
    /// The innermost statement list holding the call, and the index of the
    /// statement in it that contains the call.
    call_block: Option<(&'b [Stmt], usize)>,
    /// Literal writes, each with the statement that is exactly the write.
    writes: Vec<(TextRange, Write)>,
    references: usize,
    unknown: bool,
    /// Names that may spell `sys.argv`: `argv`, and its alias from
    /// `from sys import argv as ...`.
    aliases: Vec<String>,
    imports_at: Vec<TextRange>,
}

impl<'b> Scan<'_, 'b> {
    fn block(&mut self, body: &'b [Stmt]) {
        for (index, statement) in body.iter().enumerate() {
            if statement.range().contains_range(self.call) {
                self.call_block = Some((body, index));
            }
            self.statement(statement);
        }
    }

    fn statement(&mut self, statement: &'b Stmt) {
        match statement {
            Stmt::Import(import) => self.imports_at.push(import.range),
            Stmt::ImportFrom(import) => {
                self.imports_at.push(import.range);
                if import.module.as_deref() == Some("sys") {
                    self.aliases.extend(
                        import
                            .names
                            .iter()
                            .filter(|name| name.name.as_str() == "argv")
                            .filter_map(|name| name.asname.as_ref().map(|alias| alias.to_string())),
                    );
                }
            }
            Stmt::Expr(expression) => match self.method_write(&expression.value) {
                Some(write) => self.writes.push((statement.range(), write)),
                None => self.expr(&expression.value),
            },
            Stmt::Assign(assign) => {
                match assign.targets.as_slice() {
                    [Expr::Subscript(target)] if is_argv(self.imports, &target.value) => {
                        self.references += 1;
                        match (index_literal(&target.slice), str_literal(&assign.value)) {
                            (Some(index), Some(word)) => {
                                self.writes
                                    .push((statement.range(), Write::Set(index, word)));
                            }
                            _ => {
                                self.unknown = true;
                                self.expr(&target.slice);
                            }
                        }
                    }
                    targets => targets.iter().for_each(|target| self.target(target)),
                }
                self.expr(&assign.value);
            }
            Stmt::AugAssign(assign) => {
                if is_argv(self.imports, &assign.target) {
                    self.references += 1;
                    match (&assign.op, literal_words(&assign.value)) {
                        (ast::Operator::Add, Some(words)) => {
                            self.writes.push((statement.range(), Write::Extend(words)));
                        }
                        _ => self.unknown = true,
                    }
                } else {
                    self.target(&assign.target);
                }
                self.expr(&assign.value);
            }
            Stmt::AnnAssign(assign) => {
                self.target(&assign.target);
                if let Some(value) = &assign.value {
                    self.expr(value);
                }
            }
            Stmt::Delete(delete) => delete.targets.iter().for_each(|target| self.target(target)),
            Stmt::Return(ret) => {
                if let Some(value) = &ret.value {
                    self.expr(value);
                }
            }
            Stmt::FunctionDef(def) => self.block(&def.body),
            Stmt::AsyncFunctionDef(def) => self.block(&def.body),
            Stmt::ClassDef(class) => self.block(&class.body),
            Stmt::If(branch) => {
                self.expr(&branch.test);
                self.block(&branch.body);
                self.block(&branch.orelse);
            }
            Stmt::While(repeat) => {
                self.expr(&repeat.test);
                self.block(&repeat.body);
                self.block(&repeat.orelse);
            }
            Stmt::For(repeat) => {
                self.target(&repeat.target);
                self.read(&repeat.iter);
                self.block(&repeat.body);
                self.block(&repeat.orelse);
            }
            Stmt::With(with) => {
                for item in &with.items {
                    self.expr(&item.context_expr);
                }
                self.block(&with.body);
            }
            Stmt::Try(attempt) => {
                self.block(&attempt.body);
                for handler in &attempt.handlers {
                    let ast::ExceptHandler::ExceptHandler(handler) = handler;
                    if let Some(kind) = &handler.type_ {
                        self.expr(kind);
                    }
                    self.block(&handler.body);
                }
                self.block(&attempt.orelse);
                self.block(&attempt.finalbody);
            }
            Stmt::Raise(raise) => {
                if let Some(exception) = &raise.exc {
                    self.expr(exception);
                }
                if let Some(cause) = &raise.cause {
                    self.expr(cause);
                }
            }
            // An alias mentioned in a statement the scan does not walk stays
            // unclassified, and the token count then refuses the vector.
            _ => {}
        }
    }

    /// `argv.append(s)`, `argv.insert(i, s)` or `argv.extend([...])` with
    /// literal operands, as a whole statement.
    fn method_write(&mut self, expr: &Expr) -> Option<Write> {
        let Expr::Call(call) = expr else {
            return None;
        };
        let Expr::Attribute(method) = call.func.as_ref() else {
            return None;
        };
        if !call.keywords.is_empty() || !is_argv(self.imports, &method.value) {
            return None;
        }
        let write = match (method.attr.as_str(), call.args.as_slice()) {
            ("append", [word]) => Write::Append(str_literal(word)?),
            ("insert", [index, word]) => Write::Insert(index_literal(index)?, str_literal(word)?),
            ("extend", [words]) => Write::Extend(literal_words(words)?),
            _ => return None,
        };
        self.references += 1;
        Some(write)
    }

    /// An assignment or deletion target: `sys.argv` there is changed in a
    /// way the scan does not replay.
    fn target(&mut self, target: &Expr) {
        if is_argv(self.imports, target) {
            self.references += 1;
            self.unknown = true;
            return;
        }
        match target {
            Expr::Subscript(subscript) => {
                self.target(&subscript.value);
                self.expr(&subscript.slice);
            }
            Expr::Attribute(attribute) => self.expr(&attribute.value),
            Expr::Tuple(tuple) => tuple.elts.iter().for_each(|target| self.target(target)),
            Expr::List(list) => list.elts.iter().for_each(|target| self.target(target)),
            Expr::Starred(starred) => self.target(&starred.value),
            _ => {}
        }
    }

    /// A position that only reads the list: iteration, comparison,
    /// indexing, `len`.
    fn read(&mut self, expr: &Expr) {
        if is_argv(self.imports, expr) {
            self.references += 1;
        } else {
            self.expr(expr);
        }
    }

    fn expr(&mut self, expr: &Expr) {
        if is_argv(self.imports, expr) {
            // Anywhere else, the list may reach code that changes it.
            self.references += 1;
            self.unknown |= self.argument != Some(expr.range());
            return;
        }
        match expr {
            Expr::Call(call) => {
                if let Expr::Attribute(method) = call.func.as_ref()
                    && is_argv(self.imports, &method.value)
                {
                    self.references += 1;
                    self.unknown |= !matches!(method.attr.as_str(), "index" | "count" | "copy");
                } else {
                    self.expr(&call.func);
                }
                let len = self.imports.resolve_callee(&call.func).as_deref() == Some("len");
                for argument in &call.args {
                    if len {
                        self.read(argument);
                    } else {
                        self.expr(argument);
                    }
                }
                for keyword in &call.keywords {
                    // `execute_from_command_line(argv=...)` spells the name.
                    if keyword
                        .arg
                        .as_ref()
                        .is_some_and(|name| self.aliases.iter().any(|alias| alias == name.as_str()))
                    {
                        self.references += 1;
                    }
                    self.expr(&keyword.value);
                }
            }
            Expr::Subscript(subscript) => {
                self.read(&subscript.value);
                self.expr(&subscript.slice);
            }
            Expr::Compare(compare) => {
                self.read(&compare.left);
                compare
                    .comparators
                    .iter()
                    .for_each(|operand| self.read(operand));
            }
            Expr::Attribute(attribute) => self.expr(&attribute.value),
            Expr::BoolOp(operation) => operation.values.iter().for_each(|value| self.expr(value)),
            Expr::BinOp(operation) => {
                self.expr(&operation.left);
                self.expr(&operation.right);
            }
            Expr::UnaryOp(operation) => self.expr(&operation.operand),
            Expr::IfExp(choice) => {
                self.expr(&choice.test);
                self.expr(&choice.body);
                self.expr(&choice.orelse);
            }
            Expr::List(list) => list.elts.iter().for_each(|element| self.expr(element)),
            Expr::Tuple(tuple) => tuple.elts.iter().for_each(|element| self.expr(element)),
            Expr::Set(set) => set.elts.iter().for_each(|element| self.expr(element)),
            Expr::Dict(dict) => {
                dict.keys.iter().flatten().for_each(|key| self.expr(key));
                dict.values.iter().for_each(|value| self.expr(value));
            }
            Expr::JoinedStr(joined) => joined.values.iter().for_each(|value| self.expr(value)),
            Expr::FormattedValue(formatted) => self.expr(&formatted.value),
            Expr::Starred(starred) => self.expr(&starred.value),
            Expr::Await(awaited) => self.expr(&awaited.value),
            // An alias mentioned in an expression the scan does not walk stays
            // unclassified, and the token count then refuses the vector.
            _ => {}
        }
    }
}

fn index_literal(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Constant(ast::ExprConstant {
            value: Constant::Int(value),
            ..
        }) => value.to_string().parse().ok(),
        Expr::UnaryOp(ast::ExprUnaryOp {
            op: UnaryOp::USub,
            operand,
            ..
        }) => index_literal(operand).map(|value| -value),
        _ => None,
    }
}

fn literal_words(expr: &Expr) -> Option<Vec<String>> {
    match expr {
        Expr::List(ast::ExprList { elts, .. }) | Expr::Tuple(ast::ExprTuple { elts, .. }) => {
            elts.iter().map(str_literal).collect()
        }
        _ => None,
    }
}
