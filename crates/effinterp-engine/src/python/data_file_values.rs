//! Paths a Python program reads out of a data file it names: one string a
//! key lookup on `json.load(open(FILE))` or `yaml.safe_load(open(FILE))`
//! selects (`crate::data_file`). Such a value is the path a delete takes
//! (`shutil.rmtree(json.load(open('cfg.json'))['out'])`), and a program
//! that only prints one is the exact text a shell substitution or pipe
//! reads from it (`PlanBuilder::record_printed_text`).

use rustpython_parser::ast::{self, Expr, Stmt};

use super::PythonWalker;
use super::resolve::str_literal;
use crate::SourcePurpose;
use crate::data_file::{DataFormat, key_value};
use crate::nest::SourceResolution;
use crate::paths::resolve_fs_path;
use effinterp_proto::{ResourceExpr, ResourceIdentity};

impl PythonWalker<'_, '_> {
    /// The path a key lookup on a data file this program opens by a literal
    /// name selects, read as the host and the plan's earlier writes leave
    /// the file. A summary runs where it is called, when the file may hold
    /// other bytes, so a summarized body recovers nothing; nor does a load
    /// through a `json` or `yaml` module the program's own search path
    /// shadows.
    pub(super) fn data_file_key(&mut self, expr: &Expr) -> Option<String> {
        if self.capture.is_some() {
            return None;
        }
        let mut keys = Vec::new();
        let mut current = expr;
        while let Expr::Subscript(subscript) = current {
            keys.push(str_literal(&subscript.slice)?);
            current = &subscript.value;
        }
        keys.reverse();
        let Expr::Call(load) = current else {
            return None;
        };
        let (format, module) = match self.imports.resolve_callee(&load.func)?.as_str() {
            "json.load" => (DataFormat::Json, "json"),
            "yaml.safe_load" => (DataFormat::Yaml, "yaml"),
            _ => return None,
        };
        let ([Expr::Call(open)], []) = (load.args.as_slice(), load.keywords.as_slice()) else {
            return None;
        };
        if keys.is_empty()
            || self.imports.resolve_callee(&open.func).as_deref() != Some("open")
            || !open.keywords.is_empty()
        {
            return None;
        }
        let path = match open.args.as_slice() {
            [path] => str_literal(path)?,
            [path, mode] if matches!(str_literal(mode).as_deref(), Some("r" | "rt")) => {
                str_literal(path)?
            }
            _ => return None,
        };
        if !self.standard_module_unshadowed(module) {
            return None;
        }
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = resolve_fs_path(&path, self.cwd.as_deref())
        else {
            return None;
        };
        // A file that cannot be read leaves no evidence: the call keeps its
        // own unresolved value.
        if !self
            .nest
            .host_source_readable(self.builder, &path, SourcePurpose::InvocationInput)
        {
            return None;
        }
        let SourceResolution::Source { source, .. } = self.nest.resolve_source_file(
            self.builder,
            &path,
            SourcePurpose::InvocationInput,
            "python",
        ) else {
            return None;
        };
        key_value(&source, format, &keys)
    }

    /// Record the exact text a program prints when all it does is import
    /// modules and print one data-file key: that path and a newline.
    pub(super) fn record_printed_data_key(&mut self, suite: &[Stmt]) {
        let Some((last, imports)) = suite.split_last() else {
            return;
        };
        if !imports
            .iter()
            .all(|statement| matches!(statement, Stmt::Import(_)))
        {
            return;
        }
        let Stmt::Expr(ast::StmtExpr { value, .. }) = last else {
            return;
        };
        let Expr::Call(print) = value.as_ref() else {
            return;
        };
        let ([printed], []) = (print.args.as_slice(), print.keywords.as_slice()) else {
            return;
        };
        if self.imports.resolve_callee(&print.func).as_deref() != Some("print")
            || !self.prints_to_stdout(print)
        {
            return;
        }
        if let Some(path) = self.data_file_key(printed) {
            self.builder.record_printed_text(format!("{path}\n"));
        }
    }
}
