// Vendored from gosyn 0.2.14 at upstream commit 2e36ea96b12c3689913cb0796c5bca07301d8a07.
// Local diff: keep the token after a string-only import spec for the group parser.

use crate::ast;
use crate::ast::{ChanMode, ChannelType};
use crate::scanner::Scanner;
use crate::token::{Keyword, LitKind, Operator, Token, TokenKind};
use crate::Error;

use std::path::Path;
use std::rc::Rc;

use anyhow::Result;

#[derive(Default)]
pub struct Parser {
    scan: Scanner,

    expr_level: i32,
    comments: Vec<Rc<ast::Comment>>, // all comments
    lead_comments: Vec<Rc<ast::Comment>>,
    lead_comment_end_line: Option<usize>,
    current: Option<(usize, Token)>,
    prev_pos: (usize, bool), // save previous token position for rollback
    is_started: bool,
}

impl Parser {
    /// parse input source to `ast::File`, path will be \<input\>
    pub fn from<S: AsRef<str>>(s: S) -> Self {
        Parser {
            scan: Scanner::from(s),
            ..Default::default()
        }
    }

    /// read file content and parse to `ast::File`
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Parser {
            scan: Scanner::from_file(path)?,
            ..Default::default()
        })
    }
}

impl Parser {
    const MAX_DEPTH: i32 = 64;

    fn inc_expr_level(&mut self) -> Result<()> {
        self.expr_level += 1;
        if self.expr_level >= Self::MAX_DEPTH {
            Err(self.else_error("too many depth"))
        } else {
            Ok(())
        }
    }

    fn dec_expr_level(&mut self) {
        self.expr_level -= 1;
    }

    fn unexpected<K>(&self, expect: &[K], actual: Option<(usize, Token)>) -> anyhow::Error
    where
        K: Into<TokenKind> + Copy,
    {
        let (pos, actual) = actual
            .map(|(pos, tok)| (pos, Some(tok)))
            .unwrap_or((self.scan.position(), None));

        let expect = expect.iter().map(|&x| x.into()).collect();
        Error::UnexpectedToken {
            expect,
            actual,
            path: self.scan.path(),
            location: self.scan.line_info(pos),
        }
        .into()
    }

    fn else_error_at<S: AsRef<str>>(&self, pos: usize, reason: S) -> anyhow::Error {
        Error::Else {
            path: self.scan.path(),
            location: self.scan.line_info(pos),
            reason: reason.as_ref().to_string(),
        }
        .into()
    }

    fn else_error<S: AsRef<str>>(&self, reason: S) -> anyhow::Error {
        self.else_error_at(self.scan.position(), reason)
    }

    fn expect<K>(&mut self, expect: K) -> Result<usize>
    where
        K: Into<TokenKind> + Copy,
    {
        let current = self.current.take();
        if let Some((pos, tok)) = &current {
            if tok.is(expect) {
                self.next()?;
                return Ok(*pos);
            }
        }

        Err(self.unexpected(&[expect.into()], current))
    }

    /// skip while current equal to expect
    fn skipped<K>(&mut self, expect: K) -> Result<bool>
    where
        K: Into<TokenKind>,
    {
        Ok(match &self.current {
            Some((_, tok)) if tok.is(expect) => {
                self.next()?;
                true
            }
            _ => false,
        })
    }

    fn current_is<K>(&self, expect: K) -> bool
    where
        K: Into<TokenKind>,
    {
        match &self.current {
            Some((_, tok)) => tok.is(expect),
            None => false,
        }
    }

    fn current_not<K>(&self, expect: K) -> bool
    where
        K: Into<TokenKind>,
    {
        !self.current_is(expect)
    }

    fn current_kind(&self) -> Result<TokenKind> {
        match self.current.as_ref().map(|(_, tok)| tok.kind()) {
            Some(kind) => Ok(kind),
            None => Err(self.else_error("unexpected EOF")),
        }
    }

    fn current_pos(&self) -> usize {
        match &self.current {
            Some((pos, _)) => *pos,
            _ => self.scan.position(),
        }
    }

    fn preback(&self) -> (usize, bool) {
        self.prev_pos
    }

    fn goback(&mut self, prev: (usize, bool)) {
        self.scan.goback(prev);
        self.current = self.scan_next().unwrap();
    }

    fn scan_next(&mut self) -> Result<Option<(usize, Token)>> {
        self.prev_pos = self.scan.preback();
        self.scan.next_token()
    }

    fn next(&mut self) -> Result<Option<&(usize, Token)>> {
        if !self.is_started {
            self.is_started = true;
        }
        let mut line = 0;
        let mut pos_tok = self.scan_next()?;
        while let Some((pos, Token::Comment(text))) = pos_tok {
            if self.scan.line_info(pos).0 > line + 1 {
                self.clear_lead_comments();
            }

            let ended = self.scan.position();
            line = self.scan.line_info(ended).0;
            let comment = Rc::new(ast::Comment { pos, text });
            self.comments.push(comment.clone());
            self.lead_comments.push(comment.clone());
            self.lead_comment_end_line = Some(line);
            pos_tok = self.scan_next()?;
        }

        if let (Some(comment_end_line), Some((pos, _))) = (self.lead_comment_end_line, &pos_tok) {
            let token_start_line = self.scan.line_info(*pos).0;
            if token_start_line > comment_end_line + 1 {
                self.clear_lead_comments();
            }
        }

        self.current = pos_tok;
        Ok(self.current.as_ref())
    }

    fn clear_lead_comments(&mut self) {
        self.lead_comments.clear();
        self.lead_comment_end_line = None;
    }

    fn drain_comments(&mut self) -> Vec<Rc<ast::Comment>> {
        self.lead_comment_end_line = None;
        self.lead_comments.drain(0..).collect()
    }

    fn line_end_comment(&mut self) -> Result<Option<Rc<ast::Comment>>> {
        let pos = self.current_pos();
        let (line0, _) = self.scan.line_info(pos);

        let start = self.preback();
        if !self.current_is(Operator::SemiColon) {
            return Ok(None);
        }

        Ok(match self.scan_next()? {
            None => None,
            Some((pos, Token::Comment(text))) => {
                self.clear_lead_comments();
                let (line1, _) = self.scan.line_info(pos);
                if line0 == line1 {
                    self.next()?;
                    Some(Rc::new(ast::Comment { pos, text }))
                } else {
                    self.goback(start);
                    self.next()?;
                    None
                }
            }
            _ => {
                self.clear_lead_comments();
                self.goback(start);
                self.next()?;
                None
            }
        })
    }
}

impl Parser {
    fn identifier(&mut self) -> Result<ast::Ident> {
        let current = self.current.take();
        if let Some((pos, Token::Literal(LitKind::Ident, name))) = current {
            self.next()?;
            return Ok(ast::Ident { pos, name });
        }

        Err(self.unexpected(&[LitKind::Ident], current))
    }

    fn identifier_list(&mut self, first: Option<ast::Ident>) -> Result<Vec<ast::Ident>> {
        let mut list = match first {
            Some(id) => vec![id],
            None => vec![self.identifier()?],
        };

        while self.skipped(Operator::Comma)? {
            list.push(self.identifier()?);
        }

        Ok(list)
    }

    fn string_literal_or_none(&mut self) -> Result<Option<ast::StringLit>> {
        Ok(match self.current.take() {
            Some((pos, Token::Literal(LitKind::String, value))) => {
                self.next()?;
                Some(ast::StringLit { pos, value })
            }
            current => {
                self.current = current;
                None
            }
        })
    }

    fn string_literal(&mut self) -> Result<ast::StringLit> {
        let current = self.current.take();
        if let Some((pos, Token::Literal(LitKind::String, value))) = current {
            self.next()?;
            return Ok(ast::StringLit { pos, value });
        }

        Err(self.unexpected(&[LitKind::String], current))
    }
}

impl Parser {
    /// parse source into golang file
    /// including imports and `type`, `var`, `const` declarations
    pub fn parse_file(&mut self) -> Result<ast::File> {
        if !self.is_started {
            self.next()?;
        }
        let mut file = ast::File {
            path: self.scan.path(),
            ..Default::default()
        };

        file.docs = self.drain_comments();
        file.pkg_name = self.parse_package()?;
        self.skipped(Operator::SemiColon)?;

        // match Import declaration
        // ignore import relative pragma
        while self.current_is(Keyword::Import) {
            file.imports.extend(self.parse_import_decl()?);
            self.skipped(Operator::SemiColon)?;
        }

        let decl_key = &[Keyword::Func, Keyword::Var, Keyword::Type, Keyword::Const];
        // match declaration keyword
        while let Some((_, tok)) = &self.current {
            file.decl.push(match tok {
                Token::Keyword(Keyword::Func) => {
                    ast::Declaration::Function(self.parse_func_decl()?)
                }
                Token::Keyword(Keyword::Var) => {
                    ast::Declaration::Variable(self.parse_decl(Parser::parse_var_spec)?)
                }
                Token::Keyword(Keyword::Type) => {
                    ast::Declaration::Type(self.parse_decl(Parser::parse_type_spec)?)
                }
                Token::Keyword(Keyword::Const) => {
                    ast::Declaration::Const(self.parse_decl(Parser::parse_const_spec)?)
                }
                _ => {
                    let current = self.current.take();
                    return Err(self.unexpected(decl_key, current));
                }
            });
        }

        file.comments.extend(self.comments.drain(0..));
        Ok(file)
    }

    /// parse current token as package name
    /// which is an ident but can not be '_'
    fn parse_package(&mut self) -> Result<ast::Ident> {
        self.expect(Keyword::Package)?;
        let ast::Ident { pos, name } = self.identifier()?;
        (name != "_")
            .then_some(ast::Ident { pos, name })
            .ok_or_else(|| self.else_error_at(pos, "package name can't be blank"))
    }

    fn parse_import_decl(&mut self) -> Result<Vec<ast::Import>> {
        self.expect(Keyword::Import)?;
        match self.skipped(Operator::ParenLeft)? {
            false => Ok(vec![self.parse_import_spec()?]),
            true => {
                let mut imports = vec![];
                while !self.current_is(Operator::ParenRight) {
                    imports.push(self.parse_import_spec()?);
                    self.skipped(Operator::SemiColon)?;
                }

                self.expect(Operator::ParenRight)?;
                Ok(imports)
            }
        }
    }

    fn parse_import_spec(&mut self) -> Result<ast::Import> {
        let exp_list: &[TokenKind] = &[
            Operator::Dot.into(),
            LitKind::Ident.into(),
            LitKind::String.into(),
        ];

        let (pos, tok) = match self.current.take() {
            Some((pos, tok)) => (pos, tok),
            _ => return Err(self.else_error("unexpected EOF")),
        };
        self.next()?;

        let (name, path) = match tok {
            Token::Literal(LitKind::Ident, name) => {
                (Some(ast::Ident { pos, name }), self.string_literal()?)
            }
            Token::Operator(Operator::Dot) => {
                let name = String::from(".");
                (Some(ast::Ident { pos, name }), self.string_literal()?)
            }
            Token::Literal(LitKind::String, value) => (None, ast::StringLit { pos, value }),
            other => return Err(self.unexpected(exp_list, Some((pos, other)))),
        };

        Ok(ast::Import { name, path })
    }

    fn parse_func_decl(&mut self) -> Result<ast::FuncDecl> {
        let docs = self.drain_comments();
        let pos = self.expect(Keyword::Func)?;
        let recv = self
            .current_is(Operator::ParenLeft)
            .then(|| self.parameters())
            .map_or(Ok(None), |x| x.map(Some))?;

        let name = self.identifier()?;
        let typ_params = if recv.is_none() && self.current_is(Operator::BarackLeft) {
            self.parse_type_parameters()?.0
        } else {
            Default::default()
        };

        let params = self.parameters()?;
        let params = self.check_field_list(params, true)?;
        let result = self.parse_result()?;
        let result = self.check_field_list(result, false)?;

        let typ = ast::FuncType { pos, typ_params, params, result };

        let body = self
            .current_is(Operator::BraceLeft)
            .then(|| self.parse_block_stmt())
            .map_or(Ok(None), |x| x.map(Some))?;

        self.skipped(Operator::SemiColon)?;
        Ok(ast::FuncDecl { docs, name, typ, recv, body })
    }

    fn parse_decl<S: ast::Spec, F: FnMut(&mut Parser, usize) -> Result<S>>(
        &mut self,
        mut parse_spec: F,
    ) -> Result<ast::Decl<S>> {
        let mut specs = vec![];
        let pos0 = self.current_pos();
        let docs = self.drain_comments();

        self.next()?;
        if self.current_is(Operator::ParenLeft) {
            let mut index = 0;
            let left = self.expect(Operator::ParenLeft)?;
            while !self.current_is(Operator::ParenRight) {
                // index for check first iota in const spec
                specs.push(parse_spec(self, index)?);
                self.skipped(Operator::SemiColon)?;
                index += 1;
            }
            let right = self.expect(Operator::ParenRight)?;
            let pos1 = Some((left, right));
            self.skipped(Operator::SemiColon)?;
            return Ok(ast::Decl { docs, pos0, specs, pos1 });
        }

        let pos1 = None;
        specs.push(parse_spec(self, 0)?.with_docs(docs));
        self.skipped(Operator::SemiColon)?;
        Ok(ast::Decl { docs: vec![], pos0, specs, pos1 })
    }

    fn parse_type_spec(&mut self, _: usize) -> Result<ast::TypeSpec> {
        let docs = self.drain_comments();
        let name = self.identifier()?;
        let pos0 = self.current_pos();
        let start = self.preback();

        if !self.skipped(Operator::BarackLeft)? {
            let alias = self.skipped(Operator::Assign)?;
            let typ = self.type_()?;
            let params = ast::FieldList::default();
            return Ok(ast::TypeSpec { docs, alias, name, typ, params });
        }

        match self.current_kind()? {
            TokenKind::Literal(LitKind::Ident) => {
                let start2 = self.preback();

                let mut x = ast::Expression::Ident(self.identifier()?);
                if !self.current_is(Operator::BarackRight) {
                    self.inc_expr_level()?;
                    let p = self.primary_expression(Some(x))?;
                    x = self.binary_expression(Some(p), 0)?;
                    self.dec_expr_level();
                }

                let (pname, ptype) = extract(x, self.current_is(Operator::Comma));
                if pname.is_some() && (ptype.is_some() || !self.current_is(Operator::BarackRight)) {
                    self.goback(start);
                    let params = self.type_parameters()?;
                    let alias = self.skipped(Operator::Assign)?;
                    let typ = self.type_()?;
                    return Ok(ast::TypeSpec { docs, alias, name, typ, params });
                }

                self.goback(start2); // TODO: how to avoid this
                let len = Box::new(self.parse_next_level_expr()?);
                let pos1 = self.expect(Operator::BarackRight)?;
                let typ = Box::new(self.type_()?);
                let arr = ast::ArrayType { pos: (pos0, pos1), len, typ };
                let typ = ast::Expression::TypeArray(arr);
                let alias = false;
                let params = ast::FieldList::default();
                Ok(ast::TypeSpec { docs, alias, name, typ, params })
            }
            TokenKind::Operator(Operator::BarackRight) => {
                let pos1 = self.expect(Operator::BarackRight)?;
                let slice = ast::SliceType {
                    pos: (pos0, pos1),
                    typ: Box::new(self.type_()?),
                };
                let alias = false;
                let params = ast::FieldList::default();
                let typ = ast::Expression::TypeSlice(slice);
                Ok(ast::TypeSpec { docs, alias, name, typ, params })
            }
            _ => {
                // array type
                let len = Box::new(self.array_len()?);
                let pos1 = self.expect(Operator::BarackRight)?;
                let typ = Box::new(self.type_()?);
                let arr = ast::ArrayType { pos: (pos0, pos1), len, typ };
                let typ = ast::Expression::TypeArray(arr);
                let alias = false;
                let params = ast::FieldList::default();
                Ok(ast::TypeSpec { docs, alias, name, typ, params })
            }
        }
    }

    fn parse_var_spec(&mut self, _: usize) -> Result<ast::VarSpec> {
        let mut spec = ast::VarSpec {
            docs: self.drain_comments(),
            name: self.identifier_list(None)?,
            ..Default::default()
        };

        match self.skipped(Operator::Assign)? {
            true => spec.values = self.expression_list()?,
            false => {
                spec.typ = Some(self.type_()?);
                if self.skipped(Operator::Assign)? {
                    spec.values = self.expression_list()?;
                }
            }
        }

        if spec.typ.is_none() && spec.values.is_empty() {
            let pos = self.current_pos();
            Err(self.else_error_at(pos, "mission variable type or initialization"))
        } else {
            Ok(spec)
        }
    }

    fn parse_const_spec(&mut self, index: usize) -> Result<ast::ConstSpec> {
        let mut spec = ast::ConstSpec {
            docs: self.drain_comments(),
            name: self.identifier_list(None)?,
            ..Default::default()
        };

        match self.skipped(Operator::Assign)? {
            true => spec.values = self.expression_list()?,
            false => {
                if self.current_is(LitKind::Ident) {
                    spec.typ = Some(self.type_()?);
                    self.expect(Operator::Assign)?;
                    spec.values = self.expression_list()?;
                }
            }
        }

        if spec.values.is_empty() && (spec.typ.is_some() || index == 0) {
            let pos = self.current_pos();
            Err(self.else_error_at(pos, "mission constant value"))
        } else {
            Ok(spec)
        }
    }

    fn parse_type_list(&mut self) -> Result<Vec<ast::Expression>> {
        let mut result = vec![self.type_()?];
        while self.skipped(Operator::Comma)? {
            result.push(self.type_()?);
        }

        Ok(result)
    }

    #[inline]
    fn type_(&mut self) -> Result<ast::Expression> {
        self.inc_expr_level()?;
        match self.type_or_none()? {
            Some(typ) => {
                self.dec_expr_level();
                Ok(typ)
            }
            None => Err(self.else_error("expect a type representation")),
        }
    }

    /// parse a comma-separated type list
    /// in some case we found an '[' and it may be a list of type instance
    /// or just an index expression
    /// so we have a parameter `strict`
    /// if not strict, the first element may be a expression
    /// if strict we must have a list of type
    fn type_list(&mut self, strict: bool) -> Result<(ast::Expression, bool)> {
        self.inc_expr_level()?;
        let expr = match strict {
            true => self.type_()?,
            false => self.expression()?,
        };

        let comma = self.skipped(Operator::Comma)?;
        if comma {
            if let Some(typ) = self.type_or_none()? {
                let mut list = vec![expr, typ];
                while self.skipped(Operator::Comma)? {
                    match self.type_or_none()? {
                        Some(typ) => list.push(typ),
                        None => break,
                    }
                }

                self.dec_expr_level();
                return Ok((ast::Expression::List(list), true));
            }
        }

        self.dec_expr_level();
        Ok((expr, comma))
    }

    /// Type      = TypeName [ TypeArgs ] | TypeLit | "(" Type ")" .
    /// TypeName  = identifier | QualifiedIdent .
    /// TypeArgs  = "[" TypeList [ "," ] "]" .
    /// TypeList  = Type { "," Type } .
    /// TypeLit   = ArrayType | StructType | PointerType | FunctionType | InterfaceType |
    ///             SliceType | MapType | ChannelType .
    fn type_or_none(&mut self) -> Result<Option<ast::Expression>> {
        match &self.current {
            Some((_, Token::Operator(Operator::Star))) => {
                let pos = self.expect(Operator::Star)?;
                let typ = Box::new(self.type_()?);
                let ptr = ast::PointerType { pos, typ };
                Ok(Some(ast::Expression::TypePointer(ptr)))
            }

            Some((_, Token::Operator(Operator::Arrow))) => {
                let pos = self.expect(Operator::Arrow)?;
                let pos1 = self.expect(Keyword::Chan)?;
                let typ = Box::new(self.type_()?);
                let pos = (pos, pos1);
                let dir = Some(ChanMode::Recv);
                let chan = ast::ChannelType { pos, dir, typ };
                Ok(Some(ast::Expression::TypeChannel(chan)))
            }

            Some((_, Token::Keyword(Keyword::Func))) => {
                let typ = self.func_type()?;
                Ok(Some(ast::Expression::TypeFunction(typ)))
            }

            Some((_, Token::Operator(Operator::BarackLeft))) => {
                let pos = self.expect(Operator::BarackLeft)?;
                if self.current_is(Operator::BarackRight) {
                    let pos = (pos, self.expect(Operator::BarackRight)?);
                    let typ = Box::new(self.type_()?);
                    let slice = ast::SliceType { pos, typ };
                    return Ok(Some(ast::Expression::TypeSlice(slice)));
                }

                let len = Box::new(self.array_len()?);
                let pos1 = self.expect(Operator::BarackRight)?;
                let typ = Box::new(self.type_()?);
                let pos = (pos, pos1);
                let arr = ast::ArrayType { len, typ, pos };
                Ok(Some(ast::Expression::TypeArray(arr)))
            }

            Some((_, Token::Keyword(Keyword::Chan))) => {
                let pos = self.expect(Keyword::Chan)?;
                let pos1 = self.current_pos();
                let dir = self.skipped(Operator::Arrow)?.then_some(ChanMode::Send);
                let typ = Box::new(self.type_()?);
                let pos = (pos, pos1);
                let chan = ast::ChannelType { pos, dir, typ };
                Ok(Some(ast::Expression::TypeChannel(chan)))
            }

            Some((_, Token::Keyword(Keyword::Map))) => {
                self.next()?;
                let pos0 = self.expect(Operator::BarackLeft)?;
                let key = Box::new(self.type_()?);
                let pos1 = self.expect(Operator::BarackRight)?;
                let val = Box::new(self.type_()?);
                let pos = (pos0, pos1);
                let map = ast::MapType { pos, key, val };
                Ok(Some(ast::Expression::TypeMap(map)))
            }

            Some((_, Token::Keyword(Keyword::Struct))) => {
                let typ = self.struct_type()?;
                Ok(Some(ast::Expression::TypeStruct(typ)))
            }

            Some((_, Token::Keyword(Keyword::Interface))) => {
                let typ = self.parse_interface_type()?;
                Ok(Some(ast::Expression::TypeInterface(typ)))
            }

            Some((_, Token::Literal(LitKind::Ident, _))) => {
                // `_` is a regular identifier syntactically; rejection of `_`
                // in non-binding type positions is the type checker's job.
                // Matches go/parser.
                Ok(Some(self.qualified_ident(None)?))
            }

            Some((pos0, Token::Operator(Operator::ParenLeft))) => {
                let pos0 = *pos0;
                self.next()?;
                let typ = self.type_()?;
                let pos1 = self.expect(Operator::ParenRight)?;
                Ok(Some(ast::Expression::Paren(ast::ParenExpression {
                    pos: (pos0, pos1),
                    expr: Box::new(typ),
                })))
            }

            _ => Ok(None),
        }
    }

    fn parse_type_parameters(&mut self) -> Result<(ast::FieldList, bool)> {
        let mut fs = ast::FieldList::default();
        let pos0 = self.expect(Operator::BarackLeft)?;
        if self.current_is(Operator::BarackRight) {
            return Err(self.else_error("type parameter list cannot be empty"));
        }

        let mut extra_comma = false;
        while !self.current_is(Operator::BarackRight) {
            fs.list.push(ast::Field {
                name: self.identifier_list(None)?,
                typ: self.parse_type_elem()?,
                tag: None,
                comments: Default::default(),
            });

            extra_comma = self.skipped(Operator::Comma)?;
        }

        let pos1 = self.expect(Operator::BarackRight)?;
        fs.pos = Some((pos0, pos1));
        Ok((fs, extra_comma))
    }

    fn func_type(&mut self) -> Result<ast::FuncType> {
        // keep this position
        // caller should not consume the keyword
        let pos = self.expect(Keyword::Func)?;

        if self.current_is(Operator::BarackLeft) {
            return Err(self.else_error("func type should have no type parameters"));
        }

        let params = self.parameters()?;
        let params = self.check_field_list(params, true)?;
        let result = self.parse_result()?;
        let result = self.check_field_list(result, false)?;
        let typ_params = ast::FieldList::default();

        Ok(ast::FuncType { pos, typ_params, params, result })
    }

    fn struct_type(&mut self) -> Result<ast::StructType> {
        self.expect(Keyword::Struct)?;
        let pos0 = self.expect(Operator::BraceLeft)?;

        let mut fields = vec![];
        while !self.current_is(Operator::BraceRight) {
            let mut field = self.field_decl()?;
            if let Some(comment) = self.line_end_comment()? {
                field.comments.push(comment);
            }

            fields.push(field);
            self.skipped(Operator::SemiColon)?;
        }

        let pos1 = self.expect(Operator::BraceRight)?;
        Ok(ast::StructType { pos: (pos0, pos1), fields })
    }

    fn field_decl(&mut self) -> Result<ast::Field> {
        match &self.current {
            Some((_, Token::Literal(LitKind::Ident, _))) => {
                let name = self.identifier()?;
                match &self.current {
                    Some((
                        _,
                        Token::Operator(Operator::Dot | Operator::SemiColon | Operator::BraceRight)
                        | Token::Literal(LitKind::String, ..),
                    )) => {
                        let typ = self.qualified_ident(Some(name))?;
                        let tag = self.string_literal_or_none()?;
                        let comments = self.drain_comments();
                        Ok(ast::Field { name: vec![], typ, tag, comments })
                    }
                    _ => {
                        let mut name = self.identifier_list(Some(name))?;

                        let typ = if name.len() == 1 && self.current_is(Operator::BarackLeft) {
                            let typ = self.array_or_typeargs()?;
                            if let ast::Expression::Index(mut typ) = typ {
                                let name = name.pop().unwrap(); // FIXME: avoid this
                                typ.left = Box::new(ast::Expression::Ident(name));
                                let tag = self.string_literal_or_none()?;
                                let typ = ast::Expression::Index(typ);
                                let comments = self.drain_comments();
                                return Ok(ast::Field { name: vec![], typ, tag, comments });
                            }
                            typ
                        } else {
                            self.type_()?
                        };

                        let tag = self.string_literal_or_none()?;
                        let comments = self.drain_comments();
                        Ok(ast::Field { name, typ, tag, comments })
                    }
                }
            }

            Some((_, Token::Operator(Operator::Star))) => {
                let pos = self.expect(Operator::Star)?;
                let embedded_type = self.qualified_ident(None)?;
                let embedded_type = Box::new(embedded_type);
                let pointer_type = ast::PointerType { pos, typ: embedded_type };
                let typ = ast::Expression::TypePointer(pointer_type);
                let tag = self.string_literal_or_none()?;
                let comments = self.drain_comments();
                Ok(ast::Field { name: vec![], typ, tag, comments })
            }

            _ => Err(self.else_error("expect field name or embeded field")),
        }
    }

    // InterfaceType  = "interface" "{" { InterfaceElem ";" } "}" .
    // InterfaceElem  = MethodElem | TypeElem .
    fn parse_interface_type(&mut self) -> Result<ast::InterfaceType> {
        let pos = self.expect(Keyword::Interface)?;
        let pos1 = self.expect(Operator::BraceLeft)?;

        let mut methods = ast::FieldList::default();
        while !self.current_is(Operator::BraceRight) {
            let start = self.preback();
            if self.current_is(LitKind::Ident) {
                // try parse method name first
                if let Ok(field) = self.parse_method_elem() {
                    methods.list.push(field);
                    continue;
                }
            }

            self.goback(start);
            methods.list.push(ast::Field {
                tag: None,
                name: vec![],
                typ: self.parse_type_elem()?,
                comments: Default::default(),
            });
            if !self.current_is(Operator::BraceRight) {
                self.expect(Operator::SemiColon)?;
            }
        }

        methods.pos = Some((pos1, self.expect(Operator::BraceRight)?));
        Ok(ast::InterfaceType { pos, methods })
    }

    // MethodElem  = MethodName Signature .
    // MethodName  = identifier .
    fn parse_method_elem(&mut self) -> Result<ast::Field> {
        let id = self.identifier()?;

        let params = self.parameters()?;
        let params = self.check_field_list(params, true)?;
        let result = self.parse_result()?;
        let result = self.check_field_list(result, false)?;
        let func = ast::FuncType {
            params,
            result,
            ..Default::default()
        };

        if !self.current_is(Operator::BraceRight) {
            self.expect(Operator::SemiColon)?;
        }

        Ok(ast::Field {
            tag: None,
            name: vec![id],
            typ: ast::Expression::TypeFunction(func),
            comments: Default::default(),
        })
    }

    // TypeElem       = TypeTerm { "|" TypeTerm } .
    // TypeTerm       = Type | UnderlyingType .
    // UnderlyingType = "~" Type .
    fn parse_type_elem(&mut self) -> Result<ast::Expression> {
        let mut typ = self.parse_type_term()?;
        while self.current_is(Operator::Or) {
            let op = Operator::Or;
            let pos = self.current_pos();
            self.next()?;

            let x = Box::new(typ);
            let y = Some(Box::new(self.parse_type_term()?));
            let opt = ast::Operation { op, pos, x, y };

            typ = ast::Expression::Operation(opt)
        }

        Ok(typ)
    }

    fn parse_type_term(&mut self) -> Result<ast::Expression> {
        let pos = self.current_pos();
        let under_type = self.skipped(Operator::Tiled)?;
        let typ = self.type_()?;
        Ok(match under_type {
            false => typ,
            true => {
                let op = Operator::Tiled;
                let x = Box::new(typ);
                let opt = ast::Operation { pos, op, x, y: None };
                ast::Expression::Operation(opt)
            }
        })
    }

    fn array_len(&mut self) -> Result<ast::Expression> {
        let pos = self.current_pos();
        let ellipsis = ast::Ellipsis { pos, elt: None };
        match self.skipped(Operator::DotDotDot)? {
            true => Ok(ast::Expression::Ellipsis(ellipsis)),
            false => self.parse_next_level_expr(),
        }
    }

    #[inline]
    fn expression_list(&mut self) -> Result<Vec<ast::Expression>> {
        let mut result = vec![self.expression()?];
        while self.skipped(Operator::Comma)? {
            result.push(self.expression()?);
        }

        Ok(result)
    }

    #[inline]
    fn parse_next_level_expr(&mut self) -> Result<ast::Expression> {
        self.inc_expr_level()?;
        let expr = self.expression();
        self.dec_expr_level();
        expr
    }

    /// parse source into golang Expression
    /// Expression = UnaryExpr | Expression binary_op Expression .
    /// UnaryExpr  = PrimaryExpr | unary_op UnaryExpr .
    #[inline]
    pub fn expression(&mut self) -> Result<ast::Expression> {
        if !self.is_started {
            self.next()?;
        }
        self.binary_expression(None, 0)
    }

    /// // Expression = UnaryExpr | Expression binary_op Expression .
    fn binary_expression(
        &mut self,
        p: Option<ast::Expression>,
        prec: usize,
    ) -> Result<ast::Expression> {
        let mut x = match p {
            Some(expr) => expr,
            None => self.unray_expression()?,
        };

        loop {
            if let Some((pos, Token::Operator(op))) = self.current {
                let prec2 = op.precedence();
                if prec2 > prec {
                    self.next()?;
                    let x_ = Box::new(x);
                    let y = Some(Box::new(self.binary_expression(None, prec2)?));
                    let opt = ast::Operation { pos, op, x: x_, y };
                    x = ast::Expression::Operation(opt);
                    continue;
                }
            }
            break;
        }

        Ok(x)
    }

    fn unray_expression(&mut self) -> Result<ast::Expression> {
        match self.current {
            Some((
                pos,
                Token::Operator(
                    op @ (Operator::Star
                    | Operator::Add
                    | Operator::Sub
                    | Operator::Not
                    | Operator::Xor
                    | Operator::Tiled),
                ),
            )) => {
                self.next()?;
                let x = Box::new(self.unray_expression()?);
                let opt = ast::Operation { pos, op, x, y: None };
                Ok(ast::Expression::Operation(opt))
            }

            Some((pos, Token::Operator(op @ Operator::And))) => {
                self.next()?;
                let x = Box::new(unparen(self.unray_expression()?));
                let opt = ast::Operation { pos, op, x, y: None };
                Ok(ast::Expression::Operation(opt))
            }

            Some((pos, Token::Operator(op @ Operator::Arrow))) => {
                self.next()?;
                match self.unray_expression()? {
                    // convert `<- ChanType` to `<-chan Type`
                    ast::Expression::TypeChannel(typ) => {
                        let chan_type = self.reset_chan_arrow(pos, typ)?;
                        Ok(ast::Expression::TypeChannel(chan_type))
                    }
                    // receive message
                    x => {
                        let x = Box::new(x);
                        let opt = ast::Operation { pos, op, x, y: None };
                        Ok(ast::Expression::Operation(opt))
                    }
                }
            }

            _ => self.primary_expression(None),
        }
    }

    /// Primary expressions are the operands for unary and binary expressions.
    /// ```text
    /// PrimaryExpr =
    ///     Operand |
    ///     Conversion |
    ///     MethodExpr |
    ///     PrimaryExpr Selector |
    ///     PrimaryExpr Index |
    ///     PrimaryExpr Slice |
    ///     PrimaryExpr TypeAssertion |
    ///     PrimaryExpr Arguments .
    ///
    ///     Selector       = "." identifier .
    ///     Index          = "[" Expression "]" .
    ///     Slice          = "[" [ Expression ] ":" [ Expression ] "]" |
    ///                      "[" [ Expression ] ":" Expression ":" Expression "]" .
    ///     TypeAssertion  = "." "(" Type ")" .
    ///     Arguments      = "(" [ ( ExpressionList | Type [ "," ExpressionList ] ) [ "..." ] [ "," ] ] ")" .
    /// ```
    fn primary_expression(&mut self, p: Option<ast::Expression>) -> Result<ast::Expression> {
        let mut x = match p {
            Some(expr) => expr,
            None => self.operand()?,
        };

        loop {
            let pos = self.current_pos();

            match &self.current {
                Some((_, Token::Operator(Operator::Dot))) => match self.next()? {
                    Some((_, Token::Literal(LitKind::Ident, _))) => {
                        x = ast::Expression::Selector(ast::Selector {
                            pos,
                            x: Box::new(x),
                            sel: self.identifier()?,
                        })
                    }
                    Some((_, Token::Operator(Operator::ParenLeft))) => {
                        self.next()?;
                        let right = match self.skipped(Keyword::Type)? {
                            false => Some(Box::new(self.type_()?)),
                            true => None,
                        };

                        let left = Box::new(x);
                        let pos = (pos, self.expect(Operator::ParenRight)?);
                        let ast = ast::TypeAssertion { pos, right, left };
                        x = ast::Expression::TypeAssert(ast);
                    }
                    _ => return Err(self.else_error("expect name or '('")),
                },

                Some((_, Token::Operator(Operator::BarackLeft))) => {
                    let (op, mut index) = self.parse_slice_index_or_type_inst()?;
                    let pos = (pos, self.expect(Operator::BarackRight)?);
                    let left = Box::new(x);

                    x = match op {
                        None => {
                            let index = Box::new(index.pop().unwrap().unwrap()); // FIXME: avoid unwrap
                            ast::Expression::Index(ast::Index { pos, left, index })
                        }
                        Some(Operator::Comma) => {
                            let indices = index.into_iter().flatten().collect();
                            ast::Expression::IndexList(ast::IndexList { pos, left, indices })
                        }
                        Some(Operator::Colon) => {
                            let len = index.len();
                            let i3 = index.pop().unwrap_or(None).map(Box::new);
                            let i2 = index.pop().unwrap_or(None).map(Box::new);
                            let i1 = index.pop().unwrap_or(None).map(Box::new);

                            let index = match len {
                                3 => [i1, i2, i3],
                                2 => [i2, i3, None],
                                1 => [i3, None, None],
                                _ => unreachable!("len should less then 3"),
                            };

                            ast::Expression::Slice(ast::Slice { pos, left, index })
                        }
                        _ => unreachable!("bad operator"),
                    };
                }

                Some((_, Token::Operator(Operator::ParenLeft))) => {
                    self.next()?;
                    let mut args = vec![];

                    let mut end_with_comma = false;
                    while self.current_not(Operator::ParenRight)
                        && self.current_not(Operator::DotDotDot)
                    {
                        if !args.is_empty() {
                            self.expect(Operator::Comma)?;
                            end_with_comma = true;
                        }

                        // NOTE: last parameter can have an extra comma like `f(a, b,)`
                        if self.current_not(Operator::ParenRight)
                            && self.current_not(Operator::DotDotDot)
                        {
                            args.push(self.parse_next_level_expr()?);
                            end_with_comma = false;
                        }
                    }

                    let func = Box::new(x);
                    let current_pos = self.current_pos();
                    let dots = self.skipped(Operator::DotDotDot)?.then_some(current_pos);
                    if dots.is_some() && (end_with_comma || args.is_empty()) {
                        return Err(self.else_error_at(current_pos, "dotdotdot has no name"));
                    }

                    self.skipped(Operator::Comma)?; // (a, b...,)

                    let pos = (pos, self.expect(Operator::ParenRight)?);
                    let call = ast::Call { pos, args, func, dots };
                    x = ast::Expression::Call(call);
                }

                Some((_, Token::Operator(Operator::BraceLeft))) => {
                    if !self.check_brace(&x) {
                        break;
                    }

                    let typ = Box::new(x);
                    let val = self.parse_lit_value()?;
                    let lit = ast::CompositeLit { typ, val };
                    x = ast::Expression::CompositeLit(lit);
                }

                _ => break,
            }
        }

        Ok(x)
    }

    /// Operand     = Literal | OperandName [ TypeArgs ] | "(" Expression ")" .
    /// Literal     = BasicLit | CompositeLit | FunctionLit .
    /// BasicLit    = int_lit | float_lit | imaginary_lit | rune_lit | string_lit .
    /// OperandName = identifier | QualifiedIdent .
    fn operand(&mut self) -> Result<ast::Expression> {
        match &self.current {
            Some((_, Token::Literal(LitKind::Ident, _))) => {
                let name = self.identifier()?;
                Ok(ast::Expression::Ident(name))
            }

            Some((_, Token::Literal(..))) => {
                let lit = self.literal()?;
                Ok(ast::Expression::BasicLit(lit))
            }

            Some((_, Token::Operator(Operator::ParenLeft))) => {
                let pos = self.current_pos();
                self.next()?;

                let expr = Box::new(self.parse_next_level_expr()?);
                let pos1 = self.expect(Operator::ParenRight)?;
                let pos = (pos, pos1);
                let expr = ast::ParenExpression { pos, expr };
                Ok(ast::Expression::Paren(expr))
            }

            Some((_, Token::Keyword(Keyword::Func))) => {
                let typ = self.func_type()?;
                if self.current_is(Operator::BraceLeft) {
                    let body = self.func_body()?;
                    let lit = ast::FuncLit { typ, body };
                    return Ok(ast::Expression::FuncLit(lit));
                }

                Ok(ast::Expression::TypeFunction(typ))
            }

            Some((
                _,
                Token::Operator(Operator::BarackLeft)
                | Token::Keyword(Keyword::Chan | Keyword::Map | Keyword::Struct | Keyword::Interface),
            )) => self.type_(),

            _ => Err(self.else_error("expect expression")),
        }
    }

    /// reset the channel direction of expression `<- chan_typ`
    fn reset_chan_arrow(&mut self, pos: usize, mut typ: ChannelType) -> Result<ast::ChannelType> {
        match typ.dir {
            Some(ast::ChanMode::Recv) => {
                // <- <-chan T
                Err(self.unexpected(
                    &[Keyword::Chan],
                    Some((typ.pos.1, Token::Operator(Operator::Arrow))),
                ))
            }
            None => {
                // <- chan T
                typ.pos = (typ.pos.0, pos);
                typ.dir = Some(ast::ChanMode::Recv);
                Ok(typ)
            }
            Some(ast::ChanMode::Send) => {
                // <- chan<- T
                match *typ.typ {
                    // <-chan <-chan T
                    ast::Expression::TypeChannel(chan_type) => {
                        let chan_type = self.reset_chan_arrow(typ.pos.1, chan_type)?;
                        typ.typ = Box::new(ast::Expression::TypeChannel(chan_type));
                        typ.dir = Some(ast::ChanMode::Recv);
                        typ.pos = (typ.pos.0, pos);
                        Ok(typ)
                    }
                    // <-chan <-expr
                    _ => Err(self.else_error_at(typ.pos.1, "expect channel type")),
                }
            }
        }
    }

    /// check if brace is belong to current expression
    fn check_brace(&self, expr: &ast::Expression) -> bool {
        match expr {
            ast::Expression::TypeStruct(..)
            | ast::Expression::TypeMap(..)
            | ast::Expression::TypeArray(..)
            | ast::Expression::TypeSlice(..) => true,
            ast::Expression::Ident(..)
            | ast::Expression::IndexList(..) // map[k, v]{}
            | ast::Expression::Selector(..)
            | ast::Expression::Index(..) => self.expr_level >= 0,
            _ => false,
        }
    }

    fn parse_slice_index_or_type_inst(
        &mut self,
    ) -> Result<(Option<Operator>, Vec<Option<ast::Expression>>)> {
        self.next()?;

        let mut colon = 0;
        let mut index = vec![];

        if self.skipped(Operator::Colon)? {
            colon += 1;
            index.push(None);
            if self.current_is(Operator::BarackRight) {
                return Ok((Some(Operator::Colon), index));
            }
        }

        // [:... [...
        index.push(Some(self.parse_next_level_expr()?));
        if self.current_is(Operator::BarackRight) {
            let op = (colon > 0).then_some(Operator::Colon);
            return Ok((op, index));
        }

        match &self.current {
            Some((_, Token::Operator(Operator::Comma))) => {
                // [a, ...
                // TypeArgs = "[" TypeList [ "," ] "]" -- allow trailing comma.
                while self.skipped(Operator::Comma)? {
                    if self.current_is(Operator::BarackRight) {
                        break;
                    }
                    index.push(Some(self.parse_next_level_expr()?));
                }
                // go/ast uses IndexListExpr only for >= 2 type args.
                let op = (index.len() > 1).then_some(Operator::Comma);
                Ok((op, index))
            }
            // [:a:... [a:...
            Some((_, Token::Operator(Operator::Colon))) => {
                self.next()?;
                if self.current_is(Operator::BarackRight) {
                    return Ok((Some(Operator::Colon), index)); // [:a] [a:]
                }

                index.push(Some(self.parse_next_level_expr()?));
                if self.current_is(Operator::BarackRight) {
                    return Ok((Some(Operator::Colon), index)); // [:a:b] [a:b]
                }

                if index.len() == 3 {
                    let pos = self.current_pos();
                    return Err(self.else_error_at(pos, "expect ] in slice [:a:b..."));
                }

                self.expect(Operator::Colon)?;
                index.push(Some(self.parse_next_level_expr()?));
                Ok((Some(Operator::Colon), index))
            }
            _ => {
                let current = self.current.take();
                Err(self.unexpected(&[Operator::Colon, Operator::Comma], current))
            }
        }
    }

    fn literal(&mut self) -> Result<ast::BasicLit> {
        match self.current.take() {
            Some((pos, Token::Literal(kind, value))) => {
                self.next()?;
                Ok(ast::BasicLit { pos, kind, value })
            }
            _ => Err(self.else_error("expect basic literal")),
        }
    }

    fn parse_lit_value(&mut self) -> Result<ast::LiteralValue> {
        let mut values = vec![];
        self.inc_expr_level()?;
        let pos0 = self.expect(Operator::BraceLeft)?;
        while !self.current_is(Operator::BraceRight) {
            values.push(self.parse_element()?);
            self.skipped(Operator::Comma)?;
        }

        self.dec_expr_level();
        let pos1 = self.expect(Operator::BraceRight)?;
        let pos = (pos0, pos1);
        Ok(ast::LiteralValue { pos, values })
    }

    fn parse_element(&mut self) -> Result<ast::KeyedElement> {
        let key = self.parse_element_value()?;
        match self.skipped(Operator::Colon)? {
            true => {
                let key = Some(key);
                let val = self.parse_element_value()?;
                Ok(ast::KeyedElement { key, val })
            }
            false => Ok(ast::KeyedElement { key: None, val: key }),
        }
    }

    fn parse_element_value(&mut self) -> Result<ast::Element> {
        Ok(match self.current_is(Operator::BraceLeft) {
            true => ast::Element::LitValue(self.parse_lit_value()?),
            false => ast::Element::Expr(self.expression()?),
        })
    }

    fn func_body(&mut self) -> Result<ast::BlockStmt> {
        self.parse_block_stmt()
    }

    fn parse_result(&mut self) -> Result<ast::FieldList> {
        Ok(match self.current {
            Some((_, Token::Operator(Operator::ParenLeft))) => self.parameters()?,
            _ => {
                let list = self
                    .type_or_none()?
                    .map(|typ| vec![typ.into()])
                    .unwrap_or_default();

                ast::FieldList { pos: None, list }
            }
        })
    }

    /// Parameters     = "(" [ ParameterList [ "," ] ] ")" .
    /// ParameterList  = ParameterDecl { "," ParameterDecl } .
    fn parameters(&mut self) -> Result<ast::FieldList> {
        self.params_list(Operator::ParenLeft, Operator::ParenRight)
    }

    fn type_parameters(&mut self) -> Result<ast::FieldList> {
        self.params_list(Operator::BarackLeft, Operator::BarackRight)
    }

    fn params_list(&mut self, open: Operator, close: Operator) -> Result<ast::FieldList> {
        let pos0 = self.expect(open)?;

        let mut list = vec![];
        while !self.current_is(close) {
            list.extend(self.parse_parameter_decl()?);
            self.skipped(Operator::Comma)?; // extra comma
        }

        let pos = Some((pos0, self.expect(close)?));
        Ok(ast::FieldList { pos, list })
    }

    /// ParameterDecl = [ IdentifierList ] [ "..." ] Type .
    fn parse_parameter_decl(&mut self) -> Result<Vec<ast::Field>> {
        // "..." Type
        if self.current_is(Operator::DotDotDot) {
            let pos = self.expect(Operator::DotDotDot)?;
            let elt = Some(Box::new(self.type_()?));
            let typ = ast::Expression::Ellipsis(ast::Ellipsis { pos, elt });
            return Ok(vec![typ.into()]);
        }

        // Type
        if self.current_not(LitKind::Ident) {
            let typ = self.type_()?;
            return Ok(vec![typ.into()]);
        }

        let mut end_with_comma = false;
        let mut id_list = vec![self.identifier()?];

        loop {
            match self.current_kind()? {
                TokenKind::Operator(Operator::ParenRight) => {
                    // Type1, Type2) | Type1, Type2,)
                    return Ok(id_list.into_iter().map(|id| id.into()).collect());
                }
                TokenKind::Operator(Operator::BarackLeft) => {
                    if end_with_comma {
                        // a, b, []
                        let mut list = id_list.into_iter().map(|id| id.into()).collect::<Vec<_>>();
                        list.push(self.type_()?.into());
                        return Ok(list);
                    }

                    match self.array_or_typeargs()? {
                        ast::Expression::Index(mut typ) => {
                            // Type1, Type2[Args]
                            let id = id_list.pop().unwrap(); // FIXME: avoid unwrap
                            typ.left = Box::new(ast::Expression::Ident(id));
                            let typ = ast::Expression::Index(typ);

                            let mut list =
                                id_list.into_iter().map(|id| id.into()).collect::<Vec<_>>();
                            list.push(typ.into());
                            return Ok(list);
                        }
                        typ => {
                            // a, b [N]T
                            let name = id_list;
                            return Ok(vec![ast::Field {
                                name,
                                typ,
                                tag: None,
                                comments: Default::default(),
                            }]);
                        }
                    }
                }
                TokenKind::Operator(Operator::DotDotDot) => {
                    if end_with_comma {
                        // a, b, ...Type
                        let pos = self.expect(Operator::DotDotDot)?;
                        let elt = Some(Box::new(self.type_()?));
                        let typ = ast::Expression::Ellipsis(ast::Ellipsis { pos, elt });

                        let mut list = id_list.into_iter().map(|id| id.into()).collect::<Vec<_>>();
                        list.push(typ.into());
                        return Ok(list);
                    }

                    if id_list.len() > 1 {
                        return Err(self.else_error("ellipsis type should have only one parameter"));
                    }

                    // a ...Type
                    let name = id_list;
                    let pos = self.expect(Operator::DotDotDot)?;
                    let elt = Some(Box::new(self.type_()?));
                    let typ = ast::Ellipsis { pos, elt };
                    let typ = ast::Expression::Ellipsis(typ);
                    return Ok(vec![ast::Field {
                        name,
                        typ,
                        tag: None,
                        comments: Default::default(),
                    }]);
                }
                TokenKind::Operator(Operator::Dot) => {
                    if end_with_comma {
                        return Err(self.else_error("unexpected '.' after ','"));
                    }

                    let pkg = id_list.pop();
                    let typ = self.qualified_ident(pkg)?;
                    let mut list = id_list.into_iter().map(Into::into).collect::<Vec<_>>();
                    list.push(typ.into());
                    return Ok(list);
                }
                TokenKind::Operator(Operator::Comma) => {
                    self.next()?;
                    end_with_comma = true;
                    if self.current_is(LitKind::Ident) {
                        id_list.push(self.identifier()?);
                        end_with_comma = false;
                    }
                }
                _ => {
                    if end_with_comma {
                        // a, b, Type
                        return Ok(id_list.into_iter().map(|id| id.into()).collect::<Vec<_>>());
                    }

                    // a, b Type
                    let typ = self.parse_type_elem()?;
                    let name = id_list;
                    return Ok(vec![ast::Field {
                        name,
                        typ,
                        tag: None,
                        comments: Default::default(),
                    }]);
                }
            }
        }
    }

    /// x [n]E or x[n,], x[n1, n2], ...
    /// when we found an '[' it maybe an slice or array type or type args
    /// we will parse type list
    /// if it have not extra comman and have an type after ']' then it must be an array type
    /// if list length greater than 1 then it must be type args
    /// if list have extra comma then it must be type args
    /// else it will be an index expression
    fn array_or_typeargs(&mut self) -> Result<ast::Expression> {
        let pos0 = self.expect(Operator::BarackLeft)?;
        if self.current_is(Operator::BarackRight) {
            let pos = (pos0, self.expect(Operator::BarackRight)?);
            let typ = Box::new(self.type_()?);
            let slice = ast::SliceType { pos, typ };
            return Ok(ast::Expression::TypeSlice(slice));
        }

        let (expr, comma) = self.type_list(false)?;
        let pos1 = self.expect(Operator::BarackRight)?;

        if !comma {
            if let Some(typ) = self.type_or_none()? {
                let array = ast::ArrayType {
                    pos: (pos0, pos1),
                    len: Box::new(expr),
                    typ: Box::new(typ),
                };

                return Ok(ast::Expression::TypeArray(array));
            }
        }

        Ok(ast::Expression::Index(ast::Index {
            pos: (pos0, pos1),
            left: Box::new(ast::Expression::List(vec![])), // FIXME: this should be None
            index: Box::new(expr),
        }))
    }

    fn qualified_ident(&mut self, name: Option<ast::Ident>) -> Result<ast::Expression> {
        let name = match name {
            Some(name) => name,
            None => self.identifier()?,
        };

        let mut x = ast::Expression::Ident(name);

        let pos = self.current_pos();
        if self.skipped(Operator::Dot)? {
            let x_ = Box::new(x);
            let sel = self.identifier()?;
            let sec = ast::Selector { pos, x: x_, sel };
            x = ast::Expression::Selector(sec);
        }

        match self.current_is(Operator::BarackLeft) {
            false => Ok(x),
            // pkg.T[a, b, c]
            true => self.type_instance(x),
        }
    }

    fn type_instance(&mut self, left: ast::Expression) -> Result<ast::Expression> {
        let pos0 = self.expect(Operator::BarackLeft)?;
        if self.current_is(Operator::BarackRight) {
            return Err(self.else_error("expect type argument list"));
        }

        let (index, _) = self.type_list(true)?;
        let pos = (pos0, self.expect(Operator::BarackRight)?);

        Ok(ast::Expression::Index(ast::Index {
            pos,
            left: Box::new(left),
            index: Box::new(index),
        }))
    }

    fn check_field_list(&self, fields: ast::FieldList, trailing: bool) -> Result<ast::FieldList> {
        match &fields.list[..] {
            [] => Ok(fields),
            [first, ..] => {
                let named = !first.name.is_empty();
                let (pos, list) = (fields.pos(), &fields.list);

                for (index, field) in list.iter().enumerate() {
                    if field.name.is_empty() == named {
                        return Err(self.else_error_at(pos, "mixed named and unnamed parameters"));
                    }

                    let is_ellipsis = matches!(field.typ, ast::Expression::Ellipsis(..));
                    if is_ellipsis && (index != list.len() - 1 || !trailing) {
                        return Err(self
                            .else_error_at(pos, "can only use ... with final parameter in list"));
                    }
                }

                Ok(fields)
            }
        }
    }

    fn parse_stmt_list(&mut self) -> Result<Vec<ast::Statement>> {
        let mut result = vec![];
        while !matches!(
            &self.current,
            None | Some((
                _,
                Token::Keyword(Keyword::Case | Keyword::Default)
                    | Token::Operator(Operator::BraceRight),
            ))
        ) {
            result.push(self.parse_stmt()?)
        }

        Ok(result)
    }

    /// parse source into golang Statement
    pub fn parse_stmt(&mut self) -> Result<ast::Statement> {
        if !self.is_started {
            self.next()?;
        }
        let (pos, tok) = match &self.current {
            Some((pos, tok)) => (*pos, tok),
            _ => return Err(self.else_error("expect statement")),
        };

        match tok {
            Token::Literal(..)
            | Token::Keyword(
                Keyword::Func | Keyword::Struct | Keyword::Map | Keyword::Chan | Keyword::Interface,
            )
            | Token::Operator(
                Operator::Add
                | Operator::Sub
                | Operator::Star
                | Operator::Xor
                | Operator::Arrow
                | Operator::Not
                | Operator::ParenLeft
                | Operator::BarackLeft,
            ) => self
                .parse_simple_stmt()
                .and_then(|stmt| self.skipped(Operator::SemiColon).and(Ok(stmt))),
            Token::Keyword(Keyword::Var | Keyword::Type | Keyword::Const) => {
                self.parse_decl_stmt().map(ast::Statement::Declaration)
            }
            Token::Operator(Operator::BraceLeft) => {
                self.parse_block_stmt().map(ast::Statement::Block)
            }
            Token::Keyword(Keyword::Go) => self.parse_go_stmt().map(ast::Statement::Go),
            Token::Keyword(Keyword::Defer) => self.parse_defer_stmt().map(ast::Statement::Defer),
            Token::Keyword(Keyword::Return) => self.parse_return_stmt().map(ast::Statement::Return),
            Token::Keyword(Keyword::If) => self.parse_if_stmt().map(ast::Statement::If),
            Token::Keyword(Keyword::Switch) => self.parse_switch_stmt(),
            Token::Keyword(Keyword::Select) => self.parse_select_stmt().map(ast::Statement::Select),
            Token::Keyword(Keyword::For) => self.parse_for_stmt(),
            Token::Operator(Operator::SemiColon) => {
                self.next()?;
                Ok(ast::Statement::Empty(ast::EmptyStmt { pos }))
            }
            Token::Operator(Operator::BraceRight) => {
                Ok(ast::Statement::Empty(ast::EmptyStmt { pos }))
            }
            Token::Keyword(
                key @ (Keyword::Break | Keyword::FallThrough | Keyword::Continue | Keyword::Goto),
            ) => self.parse_branch_stmt(*key).map(ast::Statement::Branch),
            _ => Err(self.else_error_at(pos, "expect statement")),
        }
    }

    fn parse_range_expr(&mut self) -> Result<ast::RangeExpr> {
        let pos = self.expect(Keyword::Range)?;
        let right = Box::new(self.expression()?);
        Ok(ast::RangeExpr { pos, right })
    }

    fn parse_simple_stmt(&mut self) -> Result<ast::Statement> {
        let left = self.expression_list()?;
        let (pos, tok) = match &self.current {
            Some((pos, tok)) => (*pos, tok),
            _ => return Err(self.else_error("unexpected EOF")),
        };

        Ok(match tok {
            &Token::Operator(
                op @ (Operator::Define
                | Operator::Assign
                | Operator::AddAssign
                | Operator::SubAssign
                | Operator::MulAssign
                | Operator::QuoAssign
                | Operator::RemAssign
                | Operator::AndAssign
                | Operator::OrAssign
                | Operator::XorAssign
                | Operator::ShlAssign
                | Operator::ShrAssign
                | Operator::AndNotAssign),
            ) => {
                self.next()?;
                let is_range = self.current_is(Keyword::Range);
                let is_assign = op == Operator::Assign || op == Operator::Define;
                let right = match is_range && is_assign {
                    true => vec![ast::Expression::Range(self.parse_range_expr()?)],
                    false => self.expression_list()?,
                };

                if op == Operator::Define {
                    self.check_assign_stmt(&left)?;
                }

                if left.len() < right.len() {
                    return Err(self
                        .else_error_at(pos, "left side can not less than right side for assign"));
                }

                let assign = ast::AssignStmt { op, pos, left, right };
                return Ok(ast::Statement::Assign(assign));
            }
            _ => {
                let expr = self.check_single_expr(left)?;
                match self.current {
                    Some((_, Token::Operator(Operator::Colon))) => match expr {
                        ast::Expression::Ident(name) => {
                            self.next()?;
                            let stmt = Box::new(self.parse_stmt()?);
                            ast::Statement::Label(ast::LabeledStmt { pos, name, stmt })
                        }
                        _ => return Err(self.else_error_at(pos, "illegal label declaration")),
                    },
                    Some((_, Token::Operator(Operator::Arrow))) => {
                        self.next()?;
                        let value = self.expression()?;
                        ast::Statement::Send(ast::SendStmt { pos, chan: expr, value })
                    }
                    Some((_, Token::Operator(op @ (Operator::Inc | Operator::Dec)))) => {
                        self.next()?;
                        ast::Statement::IncDec(ast::IncDecStmt { pos, expr, op })
                    }
                    _ => ast::Statement::Expr(ast::ExprStmt { expr }),
                }
            }
        })
    }

    fn check_single_expr(&mut self, mut list: Vec<ast::Expression>) -> Result<ast::Expression> {
        if let Some(expr) = list.pop() {
            if list.is_empty() {
                return Ok(expr);
            }
        }

        Err(self.else_error_at(
            list.first()
                .map(|expr| expr.pos())
                .unwrap_or_else(|| self.current_pos()),
            "expect single expression",
        ))
    }

    fn check_assign_stmt(&mut self, list: &Vec<ast::Expression>) -> Result<()> {
        for expr in list {
            if !matches!(expr, ast::Expression::Ident(..)) {
                return Err(self.else_error_at(expr.pos(), "expect identifier on left side of :="));
            }
        }

        Ok(())
    }

    fn parse_decl_stmt(&mut self) -> Result<ast::DeclStmt> {
        Ok(match &self.current {
            Some((_, Token::Keyword(Keyword::Var))) => {
                ast::DeclStmt::Variable(self.parse_decl(Parser::parse_var_spec)?)
            }
            Some((_, Token::Keyword(Keyword::Type))) => {
                ast::DeclStmt::Type(self.parse_decl(Parser::parse_type_spec)?)
            }
            Some((_, Token::Keyword(Keyword::Const))) => {
                ast::DeclStmt::Const(self.parse_decl(Parser::parse_const_spec)?)
            }
            _ => unreachable!("must call at var | const | type"),
        })
    }

    fn parse_block_stmt(&mut self) -> Result<ast::BlockStmt> {
        let mut list = vec![];
        self.inc_expr_level()?;
        let pos0 = self.expect(Operator::BraceLeft)?;
        while !self.current_is(Operator::BraceRight) {
            list.push(self.parse_stmt()?);
        }

        self.dec_expr_level();
        let pos = (pos0, self.expect(Operator::BraceRight)?);
        Ok(ast::BlockStmt { pos, list })
    }

    fn parse_go_stmt(&mut self) -> Result<ast::GoStmt> {
        let pos = self.expect(Keyword::Go)?;
        match self.expression()? {
            ast::Expression::Call(call) => {
                // { go f() } with no semicolon
                self.skipped(Operator::SemiColon)?;
                Ok(ast::GoStmt { pos, call })
            }
            _ => Err(self.else_error_at(pos + 2, "must be invoked function after go")),
        }
    }

    fn parse_defer_stmt(&mut self) -> Result<ast::DeferStmt> {
        let pos = self.expect(Keyword::Defer)?;
        match self.expression()? {
            ast::Expression::Call(call) => {
                self.expect(Operator::SemiColon)?;
                Ok(ast::DeferStmt { pos, call })
            }
            _ => Err(self.else_error_at(pos + 2, "must be invoked function after go")),
        }
    }

    fn parse_return_stmt(&mut self) -> Result<ast::ReturnStmt> {
        let pos = self.expect(Keyword::Return)?;
        let ret = if self.current_not(Operator::SemiColon) && self.current_not(Operator::BraceRight)
        {
            self.expression_list()?
        } else {
            vec![]
        };

        self.skipped(Operator::SemiColon)?;
        Ok(ast::ReturnStmt { pos, ret })
    }

    fn parse_branch_stmt(&mut self, key: Keyword) -> Result<ast::BranchStmt> {
        let pos = self.expect(key)?;
        let ident = match key {
            Keyword::Goto => Some(self.identifier()?),
            Keyword::FallThrough => None,
            _ if self.current_is(LitKind::Ident) => Some(self.identifier()?),
            _ => None,
        };

        self.skipped(Operator::SemiColon)?;
        Ok(ast::BranchStmt { pos, key, ident })
    }

    /// parse if statement like
    /// `if _, ok := m[k]; ok { ... }`
    /// `if a > 1 {}`
    fn parse_if_stmt(&mut self) -> Result<ast::IfStmt> {
        let pos = self.expect(Keyword::If)?;
        let (init, cond) = self.parse_if_header()?;
        let body = self.parse_block_stmt()?;

        let else_: Option<Box<ast::Statement>> = self
            .skipped(Keyword::Else)?
            .then(|| match &self.current {
                Some((_, Token::Keyword(Keyword::If))) => {
                    let stmt = self.parse_if_stmt()?;
                    Ok(ast::Statement::If(stmt))
                }
                Some((_, Token::Operator(Operator::BraceLeft))) => {
                    let block = self.parse_block_stmt()?;
                    self.expect(Operator::SemiColon)?;
                    Ok(ast::Statement::Block(block))
                }
                _ => Err(self.else_error("expect else or if statement")),
            })
            .map_or(Ok(None), |r| r.map(|r| Some(Box::new(r))))?;

        if else_.is_none() {
            self.skipped(Operator::SemiColon)?;
        }

        Ok(ast::IfStmt { pos, init, cond, body, else_ })
    }

    fn parse_if_header(&mut self) -> Result<(Option<Box<ast::Statement>>, ast::Expression)> {
        if self.current_is(Operator::BraceLeft) {
            return Err(self.else_error("mission condition in if statement"));
        }

        let prev_level = self.expr_level;
        self.expr_level = -1;

        let init = self
            .current_not(Operator::SemiColon)
            .then(|| match self.current_is(Keyword::Var) {
                false => self.parse_simple_stmt(),
                true => Err(self.else_error("var declaration not allowed in if statement")),
            })
            .map_or(Ok(None), |r| r.map(Some))?;

        let cond = self
            .current_not(Operator::BraceLeft)
            .then(|| {
                self.expect(Operator::SemiColon)?;
                self.parse_simple_stmt()
            })
            .map_or(Ok(None), |r| r.map(Some))?;

        let (init, cond) = match (init, cond) {
            (Some(init), Some(cond)) => (Some(init), cond),
            (Some(init), None) => (None, init),
            (None, Some(cond)) => (None, cond),
            (None, None) => return Err(self.else_error("mission cond in if statement")),
        };

        let cond = match cond {
            ast::Statement::Expr(s) => s.expr,
            _ => return Err(self.else_error("cond must be boolean expression")),
        };

        self.expr_level = prev_level;
        Ok((init.map(Box::new), cond))
    }

    fn parse_switch_stmt(&mut self) -> Result<ast::Statement> {
        let pos = self.expect(Keyword::Switch)?;
        let (mut init, mut tag) = (None, None);

        let prev_level = self.expr_level;
        self.expr_level = -1;

        if self.current_not(Operator::BraceLeft) {
            if self.current_not(Operator::SemiColon) {
                tag = Some(self.parse_simple_stmt()?);
            }

            if self.skipped(Operator::SemiColon)? {
                init = tag.take();
            }

            if self.current_not(Operator::BraceLeft) {
                tag = Some(self.parse_simple_stmt()?);
            }
        };

        self.expr_level = prev_level;
        let init = init.map(Box::new);
        let type_switch = self.is_type_switch(&tag)?;
        let block = self.parse_case_block(type_switch)?;

        Ok(if type_switch {
            let tag = tag.map(Box::new);
            ast::Statement::TypeSwitch(ast::TypeSwitchStmt { pos, init, tag, block })
        } else {
            let tag = match tag {
                None => None,
                Some(ast::Statement::Expr(s)) => Some(s.expr),
                _ => return Err(self.else_error("switch tag must be an expression")),
            };

            ast::Statement::Switch(ast::SwitchStmt { pos, init, tag, block })
        })
    }

    fn parse_case_block(&mut self, type_assert: bool) -> Result<ast::CaseBlock> {
        let mut body = vec![];
        let pos = self.expect(Operator::BraceLeft)?;
        while self.current_not(Operator::BraceRight) {
            let ((pos, tok), list) = match &self.current {
                Some((_, Token::Keyword(Keyword::Case))) => (
                    (self.expect(Keyword::Case)?, Keyword::Case),
                    match type_assert {
                        true => self.parse_type_list()?,
                        false => self.expression_list()?,
                    },
                ),
                _ => ((self.expect(Keyword::Default)?, Keyword::Default), vec![]),
            };

            let pos = (pos, self.expect(Operator::Colon)?);
            let body_ = Box::new(self.parse_stmt_list()?);
            body.push(ast::CaseClause { tok, pos, list, body: body_ });
        }

        let pos = (pos, self.expect(Operator::BraceRight)?);
        Ok(ast::CaseBlock { pos, body })
    }

    fn is_type_switch(&mut self, tag: &Option<ast::Statement>) -> Result<bool> {
        Ok(match tag {
            Some(ast::Statement::Expr(ast::ExprStmt {
                expr: ast::Expression::TypeAssert(ast::TypeAssertion { right, .. }),
            })) => right.is_none(),
            Some(ast::Statement::Assign(assign)) => {
                assign.left.len() == 1
                    && assign.right.len() == 1
                    && matches!(
                        assign.right.first(),
                        Some(ast::Expression::TypeAssert(ast::TypeAssertion {
                            right: None,
                            ..
                        }))
                    )
                    && match assign.op {
                        Operator::Define => true,
                        Operator::Assign => {
                            return Err(self.else_error_at(assign.pos, "expect := found ="))
                        }
                        _ => false,
                    }
            }
            _ => false,
        })
    }

    fn parse_select_stmt(&mut self) -> Result<ast::SelectStmt> {
        let pos = self.expect(Keyword::Select)?;
        let body = self.parse_comm_block()?;
        Ok(ast::SelectStmt { pos, body })
    }

    fn parse_comm_stmt(&mut self) -> Result<ast::Statement> {
        let list = self.expression_list()?;
        Ok(match self.current.as_ref() {
            Some((pos, Token::Operator(Operator::Arrow))) => {
                let pos = *pos;
                self.next()?;
                let value = self.expression()?;
                let chan = self.check_single_expr(list)?;
                ast::Statement::Send(ast::SendStmt { pos, chan, value })
            }
            Some((pos, Token::Operator(op @ (Operator::Define | Operator::Assign)))) => {
                if list.len() > 2 {
                    return Err(self.else_error("expect 1 or 2 expression"));
                };

                let op = *op;
                let pos = *pos;
                self.next()?;
                let left = list;

                if op == Operator::Define {
                    self.check_assign_stmt(&left)?;
                }

                let right = vec![self.expression()?];
                ast::Statement::Assign(ast::AssignStmt { pos, op, left, right })
            }
            _ => {
                let expr = self.check_single_expr(list)?;
                ast::Statement::Expr(ast::ExprStmt { expr })
            }
        })
    }

    fn parse_comm_block(&mut self) -> Result<ast::CommBlock> {
        let mut body = vec![];
        let pos = self.expect(Operator::BraceLeft)?;
        while self.current_not(Operator::BraceRight) {
            let pos = self.current_pos();
            let (comm, tok) = match self.current.as_ref() {
                Some((_, Token::Keyword(Keyword::Case))) => {
                    self.expect(Keyword::Case)?;
                    let stmt = self.parse_comm_stmt()?;
                    (Some(Box::new(stmt)), Keyword::Case)
                }
                _ => {
                    self.expect(Keyword::Default)?;
                    (None, Keyword::Default)
                }
            };

            let pos = (pos, self.expect(Operator::Colon)?);
            let body_ = Box::new(self.parse_stmt_list()?);
            body.push(ast::CommClause { pos, tok, comm, body: body_ });
        }

        let pos = (pos, self.expect(Operator::BraceRight)?);
        Ok(ast::CommBlock { pos, body })
    }

    fn parse_for_stmt(&mut self) -> Result<ast::Statement> {
        let pos = self.expect(Keyword::For)?;

        let prev_level = self.expr_level;
        self.expr_level = -1;

        if self.current_is(Keyword::Range) {
            let pos = (pos, self.expect(Keyword::Range)?);
            let expr = self.expression()?;
            self.expr_level = prev_level;
            let body = self.parse_block_stmt()?;

            // for range
            return Ok(ast::Statement::Range(ast::RangeStmt {
                op: None,
                key: None,
                value: None,
                pos,
                expr,
                body,
            }));
        }

        if self.current_is(Operator::BraceLeft) {
            // for {
            self.expr_level = prev_level;
            let body = self.parse_block_stmt()?;
            return Ok(ast::Statement::For(ast::ForStmt {
                pos,
                body,
                init: None,
                cond: None,
                post: None,
            }));
        }

        let mut cond = None;
        if self.current_not(Operator::SemiColon) {
            cond = match self.parse_simple_stmt()? {
                ast::Statement::Assign(mut assign) if assign.is_range() => {
                    if assign.left.len() > 2 {
                        return Err(self.else_error_at(assign.pos, "expect at most 2 expression"));
                    }

                    let mut left = assign.left.into_iter();
                    let key = left.next();
                    let value = left.next();
                    let op = Some((assign.pos, assign.op));

                    let (pos1, expr) = match assign.right.pop() {
                        Some(ast::Expression::Range(ast::RangeExpr { pos, right })) => (pos, right),
                        _ => unreachable!(),
                    };

                    let expr = *expr;
                    let pos = (pos, pos1);
                    self.expr_level = prev_level;
                    let body = self.parse_block_stmt()?;
                    return Ok(ast::Statement::Range(ast::RangeStmt {
                        pos,
                        key,
                        value,
                        op,
                        expr,
                        body,
                    }));
                }
                stmt => Some(Box::new(stmt)),
            };
        };

        let mut init = None;
        let mut post = None;
        if self.current_is(Operator::SemiColon) {
            self.next()?;
            init = cond;
            cond = None;

            if self.current_not(Operator::SemiColon) {
                cond = Some(Box::new(self.parse_simple_stmt()?));
            }

            self.expect(Operator::SemiColon)?;
            if self.current_not(Operator::BraceLeft) {
                post = Some(Box::new(self.parse_simple_stmt()?));
            }
        }

        self.expr_level = prev_level;
        let body = self.parse_block_stmt()?;
        Ok(ast::Statement::For(ast::ForStmt {
            pos,
            init,
            cond,
            post,
            body,
        }))
    }
}

/// https://github.com/golang/go/blob/master/src/cmd/compile/internal/syntax/parser.go#L665
/// extra split x to name and expression
/// x           force    name    expr
//    ------------------------------------
//    P*[]int     T/F      P       *[]int
//    P*E         T        P       *E
//    P*E         F        nil     P*E
//    P([]int)    T/F      P       []int
//    P(E)        T        P       E
//    P(E)        F        nil     P(E)
//    P*E|F|~G    T/F      P       *E|F|~G
//    P*E|F|G     T        P       *E|F|G
//    P*E|F|G     F        nil     P*E|F|G
fn extract(expr: ast::Expression, force: bool) -> (Option<ast::Ident>, Option<ast::Expression>) {
    match expr {
        ast::Expression::Ident(id) => (Some(id), None),
        ast::Expression::Operation(mut opt) => match opt {
            ast::Operation { y: None, .. } => (None, Some(ast::Expression::Operation(opt))),
            ast::Operation {
                x: optx,
                y: Some(opty),
                op: Operator::Star,
                ..
            } => match *optx {
                ast::Expression::Ident(id) if (force || is_type_elem(&opty)) => {
                    (opt.x, opt.y) = (opty, None);
                    (Some(id), Some(ast::Expression::Operation(opt)))
                }
                _ => {
                    (opt.x, opt.y) = (optx, Some(opty));
                    (None, Some(ast::Expression::Operation(opt)))
                }
            },
            ast::Operation {
                x: optx,
                y: Some(opty),
                op: Operator::Or,
                ..
            } => match extract(*optx, force || is_type_elem(&opty)) {
                (Some(name), Some(lhs)) => {
                    (opt.x, opt.y) = (Box::new(lhs), Some(opty));
                    (Some(name), Some(ast::Expression::Operation(opt)))
                }
                (Some(name), None) => {
                    let optx = Box::new(ast::Expression::Ident(name));
                    let opty = Some(opty);
                    (opt.x, opt.y) = (optx, opty);
                    (None, Some(ast::Expression::Operation(opt)))
                }
                (None, Some(expr)) => {
                    let optx = Box::new(expr);
                    let opty = Some(opty);
                    (opt.x, opt.y) = (optx, opty);
                    (None, Some(ast::Expression::Operation(opt)))
                }
                _ => panic!("extract lost"),
            },
            _ => (None, Some(ast::Expression::Operation(opt))),
        },
        ast::Expression::Call(mut call) => {
            if let ast::Expression::Ident(id) = *call.func {
                let mut args = call.args;
                match (args.pop(), args.pop()) {
                    (Some(arg0), None) => {
                        if call.dots.is_none() && (force || is_type_elem(&arg0)) {
                            return (Some(id), Some(arg0));
                        }
                        args.push(arg0);
                    }
                    (arg0, arg1) => {
                        if let Some(arg) = arg1 {
                            args.push(arg)
                        }
                        if let Some(arg) = arg0 {
                            args.push(arg)
                        }
                    }
                };

                call.args = args;
                call.func = Box::new(ast::Expression::Ident(id));
            }
            (None, Some(ast::Expression::Call(call)))
        }
        _ => (None, Some(expr)),
    }
}

fn unparen(expr: ast::Expression) -> ast::Expression {
    match expr {
        ast::Expression::Paren(x) => *x.expr,
        _ => expr,
    }
}

fn is_type_elem(expr: &ast::Expression) -> bool {
    match expr {
        ast::Expression::TypeArray(..)
        | ast::Expression::TypeStruct(..)
        | ast::Expression::TypeFunction(..)
        | ast::Expression::TypeInterface(..)
        | ast::Expression::TypeSlice(..)
        | ast::Expression::TypeMap(..)
        | ast::Expression::TypeChannel(..) => true,
        ast::Expression::Paren(p) => is_type_elem(&p.expr),
        ast::Expression::Operation(opt) => match opt {
            ast::Operation { op: Operator::Tiled, .. } => true,
            ast::Operation { y: Some(opty), .. } => is_type_elem(opty),
            ast::Operation { x: optx, .. } => is_type_elem(optx),
        },
        _ => false,
    }
}

#[cfg(test)]
mod test {
    use crate::ast::{self, Declaration, Expression};
    use crate::parser::Parser;
    use crate::token::{Keyword, Operator};

    use anyhow::{Ok, Result};

    fn new_started_parser(s: &str) -> Parser {
        let mut parser = Parser::from(s);
        parser.next().expect("no error parsing test input");
        parser
    }

    fn finish(parser: &mut Parser) -> Result<()> {
        parser.skipped(Operator::SemiColon)?;
        match &parser.current {
            None => Ok(()),
            Some((pos, token)) => Err(anyhow::anyhow!("unconsumed token at {pos}: {token:?}")),
        }
    }

    fn parse_expression_complete(source: &str) -> Result<Expression> {
        let mut parser = Parser::from(source);
        let expression = parser.expression()?;
        finish(&mut parser)?;
        Ok(expression)
    }

    fn parse_statement_complete(source: &str) -> Result<ast::Statement> {
        let mut parser = Parser::from(source);
        let statement = parser.parse_stmt()?;
        finish(&mut parser)?;
        Ok(statement)
    }

    fn assert_ident(expression: &Expression, expected: &str) {
        match expression {
            Expression::Ident(ident) => assert_eq!(ident.name, expected),
            other => panic!("expected identifier {expected:?}, got {other:?}"),
        }
    }

    fn assert_pointer_type(expression: &Expression, expected_pos: usize) -> &Expression {
        match expression {
            Expression::TypePointer(pointer) => {
                assert_eq!(pointer.pos, expected_pos);
                &pointer.typ
            }
            other => panic!("expected pointer type at {expected_pos}, got {other:?}"),
        }
    }

    fn assert_binary(expression: &Expression, expected: Operator) -> (&Expression, &Expression) {
        match expression {
            Expression::Operation(operation) => {
                assert_eq!(operation.op, expected);
                let right = operation.y.as_deref().expect("expected binary operation");
                (&operation.x, right)
            }
            other => panic!("expected {expected:?} operation, got {other:?}"),
        }
    }

    #[test]
    fn parse_package() -> Result<()> {
        let pkg = |s| {
            let mut parser = new_started_parser(s);
            let pkg = parser.parse_package()?;
            finish(&mut parser)?;
            Ok(pkg)
        };

        pkg("package main")?;

        assert!(pkg("\n\n").is_err());
        assert!(pkg("package _").is_err());
        assert!(pkg("package\n_").is_err());
        assert!(pkg("package package").is_err());
        pkg("package\n\nmain")?;

        Ok(())
    }

    #[test]
    fn parse_imports() -> Result<()> {
        let import = |s| {
            let mut parser = new_started_parser(s);
            let imp = parser.parse_import_decl()?;
            finish(&mut parser)?;
            Ok(imp)
        };

        import("import ()")?;
        import("import `aa`")?;
        import("import (\n\n)")?;
        import(r#"import "liba""#)?;
        import(r#"import . "libb""#)?;
        import(r#"import _ "libc""#)?;
        import(r#"import d "libd""#)?;

        assert!(import("import _").is_err());
        assert!(import("import _ _").is_err());
        assert!(import("import . ()").is_err());

        Ok(())
    }

    #[test]
    fn parse_decl() -> Result<()> {
        let vars = |s| {
            let mut parser = new_started_parser(s);
            let vars = parser.parse_decl(Parser::parse_var_spec)?;
            finish(&mut parser)?;
            Ok(vars)
        };

        vars("var a int")?;
        vars("var a = 1")?;
        vars("var a, b int")?;
        vars("var b = x.AB.A")?;
        vars("var a, b = 1, 2")?;
        vars("var a, b = result()")?;
        vars("var a, b int = 1, 2")?;
        vars("var (a = 1; b int = 2)")?;
        vars("var (a int; b, c int = 2, 3; e, f = 5, 6)")?;

        assert!(vars("var a, b;").is_err());

        let consts = |s| {
            let mut parser = new_started_parser(s);
            let consts = parser.parse_decl(Parser::parse_const_spec)?;
            finish(&mut parser)?;
            Ok(consts)
        };

        consts("const a = 1")?;
        consts("const a int64 = 1")?;
        consts("const a, b int64 = 1, 2")?;
        consts("const (a = iota; b; c;)")?;
        consts("const (a = 1; b, c = 2, 3)")?;

        assert!(consts("const a int64;").is_err());

        Ok(())
    }

    #[test]
    fn parse_iota_in_constant_expressions() -> Result<()> {
        let mut parser = new_started_parser(
            "const (
                Flag = 1 << iota
                Mask = 1<<(iota+1) - 1
                KiB = 1 << (10 * iota)
                MiB
                GiB
            )",
        );
        let declaration = parser.parse_decl(Parser::parse_const_spec)?;
        finish(&mut parser)?;

        assert_eq!(declaration.specs.len(), 5);

        let [flag] = declaration.specs[0].values.as_slice() else {
            return Err(anyhow::anyhow!("expected one Flag expression"));
        };
        let (_, iota) = assert_binary(flag, Operator::Shl);
        assert_ident(iota, "iota");

        let [mask] = declaration.specs[1].values.as_slice() else {
            return Err(anyhow::anyhow!("expected one Mask expression"));
        };
        let (shift, _) = assert_binary(mask, Operator::Sub);
        let (_, amount) = assert_binary(shift, Operator::Shl);
        match amount {
            Expression::Paren(paren) => {
                let (iota, _) = assert_binary(&paren.expr, Operator::Add);
                assert_ident(iota, "iota");
            }
            other => {
                return Err(anyhow::anyhow!(
                    "expected parenthesized shift, got {other:?}"
                ))
            }
        }

        assert_eq!(declaration.specs[2].values.len(), 1);
        assert!(declaration.specs[3].values.is_empty());
        assert!(declaration.specs[4].values.is_empty());

        Ok(())
    }

    #[test]
    fn parse_func_decl() -> Result<()> {
        let func = |s, (none_recv, type_params_len, params_len, result_len)| {
            let mut parser = new_started_parser(s);
            let func = parser.parse_func_decl()?;
            finish(&mut parser)?;

            assert_eq!(func.recv.as_ref().map(|_| ()), none_recv);
            assert_eq!(func.typ.typ_params.list.len(), type_params_len);

            assert_eq!(func.typ.params.list.len(), params_len);
            assert_eq!(func.typ.result.list.len(), result_len);

            Ok(func)
        };

        func("func a()", (None, 0, 0, 0))?;
        func("func a(x int) int", (None, 0, 1, 1))?;
        func("func (S[T]) Bar()", (Some(()), 0, 0, 0))?;
        func("func min[P any]()", (None, 1, 0, 0))?;
        func("func min[_ any]()", (None, 1, 0, 0))?;
        func("func f() { go f1() }", (None, 0, 0, 0))?;
        func("func f(n int) func(p *T)", (None, 0, 1, 1))?;
        func("func h[T Ordered](a []T)", (None, 1, 1, 0))?;
        func("func min[S ~[]E, E any]()", (None, 2, 0, 0))?;
        func("func min[P Constraint[int]]()", (None, 1, 0, 0))?;
        func("func f(a, _ int, z float32) bool", (None, 0, 2, 1))?;
        func("func f(a, b int, z float32) (bool)", (None, 0, 2, 1))?;
        func("func f(prefix string, values ...int)", (None, 0, 2, 0))?;
        func("func min[S interface{ ~[]byte|string }]()", (None, 1, 0, 0))?;

        func(
            "func f(int, int, float64) (float64, *[]int)",
            (None, 0, 3, 2),
        )?;
        func(
            "func (m *M) Print() { fmt.Print(m.message)}",
            (Some(()), 0, 0, 0),
        )?;
        func(
            "func f(int, int, float64) (*a, []b, map[c]d)",
            (None, 0, 3, 3),
        )?;
        func(
            "func min[T any](x, y T) T { return Min(x, y) }",
            (None, 1, 1, 1),
        )?;
        func(
            "func fn2() (int, *int, int) { return 0, nil, 0 }",
            (None, 0, 0, 3),
        )?;
        func(
            "func a(w t1, r *t2, e chan<- t3) {x <- t4{c: c, t: t};}",
            (None, 0, 3, 0),
        )?;
        func(
            "func min[T ~int|~float64](x, y T) T { return Min(x, y) }",
            (None, 1, 1, 1),
        )?;
        func(
            "func (t *T) f(a *u) *s {return &t[(ptr(u.P(a))>>3)%size].root}",
            (Some(()), 0, 1, 1),
        )?;
        func(
            "func (s *SL[K, V]) It() M[K, V] { return &S[K, V]{a.b.c[0], nil} }",
            (Some(()), 0, 0, 1),
        )?;

        assert!(func("func(...int", (None, 0, 0, 0)).is_err());
        assert!(func("func() (...int)", (None, 0, 0, 0)).is_err());
        assert!(func("func(a int, bool)", (None, 0, 0, 0)).is_err());
        assert!(func("func(int) (...bool, int)", (None, 0, 0, 0)).is_err());

        Ok(())
    }

    #[test]
    fn reject_empty_type_parameter_list() {
        let source = "package p\nfunc min[](x, y T) T { return x }\n";
        assert!(Parser::from(source).parse_file().is_err());
    }

    #[test]
    fn parse_type_decl() -> Result<()> {
        let typ = |s| {
            let mut parser = new_started_parser(s);
            let mut typ = parser.parse_decl(Parser::parse_type_spec)?;
            finish(&mut parser)?;
            Ok(typ.specs.pop().unwrap())
        };

        match typ("type n [2]int")?.typ {
            ast::Expression::TypeArray(_) => {}
            _ => return Err(anyhow::anyhow!("not type ARRAY")),
        };

        match typ("type a [sz(k{})]T")?.typ {
            ast::Expression::TypeArray(_) => {}
            _ => return Err(anyhow::anyhow!("not type ARRAY")),
        };

        let type_struct = |s| match typ(s)?.typ {
            ast::Expression::TypeStruct(s) => Ok(s),
            _ => Err(anyhow::anyhow!("not type STRUCT")),
        };

        type_struct("type s struct{a struct{}}")?;
        type_struct("type p[T any] struct {a[T]}")?;
        type_struct("type S[T any] struct { P[T]; l L[T]}")?;
        type_struct("type S[T int | string] struct { F T }")?;
        type_struct("type S[K Order, V any] struct {SL[K, V]}")?;
        type_struct("type S[T int | complex128, PT *T] struct {F PT}")?;
        type_struct("type S[E ~int | ~complex128, T ~*E] struct {F T}")?;
        type_struct("type S[T ~int | ~string, PT ~int | ~string | ~*T] struct {F T}")?;
        type_struct("type S[T int | *bool, PT *T | float64, PPT *PT | string] struct {F PPT}")?;

        assert!(type_struct("type s struct{a, b}").is_err());
        assert!(type_struct("type s struct{a int,int}").is_err());
        assert!(type_struct("type s struct{a int, b int}").is_err());

        Ok(())
    }

    #[test]
    fn parse_type_aliases() -> Result<()> {
        let source = "package p
            type Alias = Original
            type Set[P comparable] = map[P]bool
        ";
        let file = Parser::from(source).parse_file()?;
        let [Declaration::Type(alias_decl), Declaration::Type(set_decl)] = file.decl.as_slice()
        else {
            return Err(anyhow::anyhow!("expected two type declarations"));
        };

        let [alias] = alias_decl.specs.as_slice() else {
            return Err(anyhow::anyhow!("expected one Alias spec"));
        };
        assert_eq!(alias.name.name, "Alias");
        assert!(alias.alias);
        assert!(alias.params.list.is_empty());
        match &alias.typ {
            Expression::Ident(ident) => assert_eq!(ident.name, "Original"),
            other => return Err(anyhow::anyhow!("expected alias identifier, got {other:?}")),
        }

        let [set] = set_decl.specs.as_slice() else {
            return Err(anyhow::anyhow!("expected one Set spec"));
        };
        assert_eq!(set.name.name, "Set");
        assert!(set.alias);
        assert_eq!(set.params.list.len(), 1);
        assert_eq!(set.params.list[0].name.len(), 1);
        assert_eq!(set.params.list[0].name[0].name, "P");
        match &set.params.list[0].typ {
            Expression::Ident(ident) => assert_eq!(ident.name, "comparable"),
            other => {
                return Err(anyhow::anyhow!(
                    "expected comparable constraint, got {other:?}"
                ))
            }
        }
        match &set.typ {
            Expression::TypeMap(map) => {
                assert_ident(&map.key, "P");
                assert_ident(&map.val, "bool");
            }
            other => return Err(anyhow::anyhow!("expected map alias, got {other:?}")),
        }

        Ok(())
    }

    #[test]
    fn parse_any_and_comparable_as_predeclared_identifiers() -> Result<()> {
        let source = "package p
            type Alias = any
            type Set[T comparable] map[T]any
            func identity(any any) any { return any }
        ";

        Parser::from(source).parse_file()?;
        Ok(())
    }

    #[test]
    fn reject_empty_type_argument_lists() {
        for source in [
            "package p\nfunc F[T any]() {}\nfunc _() { F[]() }\n",
            "package p\ntype Box[T any] struct{}\nvar _ Box[]\n",
        ] {
            assert!(Parser::from(source).parse_file().is_err(), "{source:?}");
        }
    }

    #[test]
    fn parse_parameters() -> Result<()> {
        let params = |s| {
            let mut parser = new_started_parser(s);
            let params = parser.parameters()?;
            finish(&mut parser)?;
            Ok(params)
        };

        params("()")?;
        params("(S[T])")?;
        params("(bool)")?;
        params("(a bool)")?;
        params("(func())")?;
        params("(a,\n b,\n)")?;
        params("(a ...bool)")?;
        params("(a, b, c bool)")?;
        params("(a.b, c.d)")?;
        params("(int, int, bool)")?;
        params("(a, b int, c bool)")?;
        params("(int, bool, ...int)")?;
        params("(a, _ int, z float32)")?;
        params("(a, b int, z float32)")?;
        params("(prefix string, values ...int)")?;
        params("(a, b int, z float64, opt ...T)")?;

        let check = |s| {
            let mut ps = new_started_parser(s);
            let params = ps.parameters()?;
            ps.check_field_list(params, true)
        };

        assert!(check("(,)").is_err());
        assert!(check("(...)").is_err());
        assert!(check("(a, ...)").is_err());
        assert!(check("(...int, bool)").is_err());
        assert!(check("(...int, ...bool)").is_err());
        assert!(check("(a, b, c, d ...int)").is_err());

        let ret_params = |s| {
            let mut parser = new_started_parser(s);
            let params = parser.parse_result()?;
            finish(&mut parser)?;
            Ok(params)
        };

        ret_params("(int)")?;
        ret_params("(a int)")?;
        ret_params("(int, bool)")?;
        ret_params("(a int, b bool)")?;

        let check = |s| {
            let mut ps = new_started_parser(s);
            let params = ps.parameters()?;
            ps.check_field_list(params, false)
        };

        assert!(check("(...bool)").is_err());
        assert!(check("(a int, bool)").is_err());
        assert!(check("(...bool, int)").is_err());

        Ok(())
    }

    #[test]
    fn parse_expr() -> Result<()> {
        let expr = parse_expression_complete;

        expr("a + b")?;
        expr("a % b")?;
        expr("a + b * c + d")?;
        expr("a * b + c * d")?;
        expr("(4.9790119248836735e+00 + 7.7388724745781045e+00i)")?;

        expr("call()")?;
        expr("call(1)")?;
        expr("call(1, 2)")?;
        expr("call(1, a...)")?;
        expr("call(a, b...)")?;
        expr("call(a, x.M()%99)")?;
        expr("call(a, b,)")?;
        expr("call(1/* comment */)")?;

        expr("x.(int)")?;
        expr("x.(type)")?;
        expr("struct{}")?;

        expr("<-chan chan int")?;
        expr("<-chan chan<- int")?;
        expr("<-chan <-chan <-chan int")?;

        assert!(expr("<-chan <-chan <- int").is_err());

        Ok(())
    }

    #[test]
    fn parse_all_expression_operators() -> Result<()> {
        let binary = [
            ("+", Operator::Add),
            ("-", Operator::Sub),
            ("*", Operator::Star),
            ("/", Operator::Quo),
            ("%", Operator::Rem),
            ("&", Operator::And),
            ("|", Operator::Or),
            ("^", Operator::Xor),
            ("<<", Operator::Shl),
            (">>", Operator::Shr),
            ("&^", Operator::AndNot),
            ("&&", Operator::AndAnd),
            ("||", Operator::OrOr),
            ("==", Operator::Equal),
            ("!=", Operator::NotEqual),
            ("<", Operator::Less),
            ("<=", Operator::LessEqual),
            (">", Operator::Greater),
            (">=", Operator::GreaterEqual),
        ];

        for (source, expected) in binary {
            let expression = parse_expression_complete(&format!("left {source} right"))?;
            let (left, right) = assert_binary(&expression, expected);
            assert_ident(left, "left");
            assert_ident(right, "right");
        }

        for (source, expected) in [
            ("+value", Operator::Add),
            ("-value", Operator::Sub),
            ("*value", Operator::Star),
            ("!value", Operator::Not),
            ("^value", Operator::Xor),
            ("&value", Operator::And),
            ("<-value", Operator::Arrow),
        ] {
            match parse_expression_complete(source)? {
                Expression::Operation(operation) => {
                    assert_eq!(operation.op, expected, "{source}");
                    assert!(operation.y.is_none(), "{source}");
                    assert_ident(&operation.x, "value");
                }
                other => return Err(anyhow::anyhow!("unexpected AST for {source}: {other:?}")),
            }
        }

        Ok(())
    }

    #[test]
    fn parse_expression_precedence_and_associativity() -> Result<()> {
        let expression = parse_expression_complete("a || b && c == d + e * f")?;
        let (a, and) = assert_binary(&expression, Operator::OrOr);
        assert_ident(a, "a");
        let (b, equal) = assert_binary(and, Operator::AndAnd);
        assert_ident(b, "b");
        let (c, add) = assert_binary(equal, Operator::Equal);
        assert_ident(c, "c");
        let (d, multiply) = assert_binary(add, Operator::Add);
        assert_ident(d, "d");
        let (e, f) = assert_binary(multiply, Operator::Star);
        assert_ident(e, "e");
        assert_ident(f, "f");

        let expression = parse_expression_complete("a - b - c")?;
        let (subtract, c) = assert_binary(&expression, Operator::Sub);
        let (a, b) = assert_binary(subtract, Operator::Sub);
        assert_ident(a, "a");
        assert_ident(b, "b");
        assert_ident(c, "c");

        let expression = parse_expression_complete("!-value")?;
        match expression {
            Expression::Operation(not) => {
                assert_eq!(not.op, Operator::Not);
                assert!(not.y.is_none());
                match *not.x {
                    Expression::Operation(negate) => {
                        assert_eq!(negate.op, Operator::Sub);
                        assert!(negate.y.is_none());
                        assert_ident(&negate.x, "value");
                    }
                    other => return Err(anyhow::anyhow!("expected unary minus, got {other:?}")),
                }
            }
            other => return Err(anyhow::anyhow!("expected unary not, got {other:?}")),
        }

        Ok(())
    }

    #[test]
    fn parse_primary_expression_ast_shapes() -> Result<()> {
        match parse_expression_complete("pkg.Value")? {
            Expression::Selector(selector) => {
                assert_ident(&selector.x, "pkg");
                assert_eq!(selector.sel.name, "Value");
            }
            other => return Err(anyhow::anyhow!("expected selector, got {other:?}")),
        }

        match parse_expression_complete("values[1]")? {
            Expression::Index(index) => {
                assert_ident(&index.left, "values");
                assert!(matches!(*index.index, Expression::BasicLit(_)));
            }
            other => return Err(anyhow::anyhow!("expected index, got {other:?}")),
        }

        match parse_expression_complete("values[1:2:3]")? {
            Expression::Slice(slice) => {
                assert_ident(&slice.left, "values");
                assert!(slice.index.iter().all(Option::is_some));
            }
            other => return Err(anyhow::anyhow!("expected slice, got {other:?}")),
        }

        match parse_expression_complete("Factory[int, string]")? {
            Expression::IndexList(index) => {
                assert_ident(&index.left, "Factory");
                assert_eq!(index.indices.len(), 2);
            }
            other => return Err(anyhow::anyhow!("expected index list, got {other:?}")),
        }

        match parse_expression_complete("func(x int) int { return x }")? {
            Expression::FuncLit(function) => {
                assert_eq!(function.typ.params.list.len(), 1);
                assert_eq!(function.typ.result.list.len(), 1);
                assert_eq!(function.body.list.len(), 1);
            }
            other => return Err(anyhow::anyhow!("expected function literal, got {other:?}")),
        }

        match parse_expression_complete("map[string]int{\"one\": 1}")? {
            Expression::CompositeLit(literal) => {
                assert!(matches!(*literal.typ, Expression::TypeMap(_)));
                assert_eq!(literal.val.values.len(), 1);
            }
            other => return Err(anyhow::anyhow!("expected composite literal, got {other:?}")),
        }

        Ok(())
    }

    #[test]
    fn parse_numeric_literal_files() {
        for literal in ["1e5", "2E10", "0x1p-2", "0X1P+2", "0B1010"] {
            let source = format!("package p\nvar x = {literal}\n");
            assert!(Parser::from(source).parse_file().is_ok(), "{literal}");
        }

        for literal in ["0x1p1a", "0x1.0p1a", "0X.8Pdead"] {
            let source = format!("package p\nvar x = {literal}\n");
            assert!(Parser::from(source).parse_file().is_err(), "{literal}");
        }
    }

    #[test]
    fn parse_operand() -> Result<()> {
        let operand = parse_expression_complete;

        operand("a")?;
        operand("`Hola`")?;
        operand("[10]string{}")?;
        operand("[6]int{1, 2, 3, 5}")?;
        operand("[...]string{`Sat`, `Sun`}")?;
        operand("[][]Point{{{0, 1}, {1, 2}}}")?;
        operand("[...]Point{{1.5, -3.5}, {0, 0}}")?;
        operand("map[string]Point{`orig`: {0, 0}}")?;
        operand("map[Point]string{{0, 0}: `orig`}")?;

        Ok(())
    }

    #[test]
    fn parse_slice_index() -> Result<()> {
        let slice = |s| {
            let mut parser = new_started_parser(s);
            let slice = parser.parse_slice_index_or_type_inst()?;
            parser.expect(Operator::BarackRight)?;
            finish(&mut parser)?;
            Ok(slice)
        };

        slice("[a]")?;
        slice("[:]")?;
        slice("[a:]")?;
        slice("[:a]")?;
        slice("[a:b]")?;
        slice("[:a:b]")?;
        slice("[a:b:c]")?;

        assert!(slice("[]").is_err());
        assert!(slice("[::]").is_err());
        assert!(slice("[a::b]").is_err());
        assert!(slice("[a:b:]").is_err());

        Ok(())
    }

    #[test]
    fn parse_func_type() -> Result<()> {
        let func = |s| {
            let mut parser = new_started_parser(s);
            let func = parser.func_type()?;
            finish(&mut parser)?;
            Ok(func)
        };

        func("func()")?;
        func("func(x int) int")?;
        func("func(n int) func(p *T)")?;
        func("func(a, _ int, z float32) bool")?;
        func("func(a, b int, z float32) (bool)")?;
        func("func(prefix string, values ...int)")?;
        func("func(a.b, c.d) e.f")?;
        func("func(int, int, float64) (float64, *[]int)")?;
        func("func(int, int, float64) (*a, []b, map[c]d)")?;

        assert!(func("func(...int").is_err());
        assert!(func("func() (...int)").is_err());
        assert!(func("func(a int, bool)").is_err());
        assert!(func("func(int) (...bool, int)").is_err());

        Ok(())
    }

    #[test]
    fn parse_interface_type() -> Result<()> {
        let interface = |s| {
            let mut parser = new_started_parser(s);
            let interface = parser.parse_interface_type()?;
            finish(&mut parser)?;
            Ok(interface)
        };

        interface("
        interface {
            P                // illegal: P is a type parameter
            int | ~P         // illegal: P is a type parameter
            ~int | MyInt     // illegal: the type sets for ~int and MyInt are not disjoint (~int includes MyInt)
            float32 | Float  // overlapping type sets but Float is an interface
        }
    ")?;

        interface("interface{}")?;
        interface("interface{Close() error}")?;
        interface("interface{Show(int) string}")?;
        interface("interface{Show(...int) string}")?;
        interface("interface {os.FileInfo; String() string}")?;
        interface("interface {Publish(string, []byte) error}")?;

        interface("interface {~int}")?;
        interface("interface{ chan int | chan<- string }")?;
        interface("interface{ <-chan int | chan<- int }")?;
        interface("interface {~int; String() string}")?;
        interface("interface {~int | ~string | Bad3}")?;

        interface(
            "
            interface {
                ~[]byte  // the underlying type of []byte is itself
                ~MyInt   // illegal: the underlying type of MyInt is not MyInt
                ~error   // illegal: error is an interface
            }
        ",
        )?;

        assert!(interface("interface {a b}").is_err());
        assert!(interface("interface {a, b;}").is_err());
        assert!(interface("interface {a | b c}").is_err());
        assert!(interface("interface {a b | c}").is_err());

        Ok(())
    }

    #[test]
    fn parse_interface_with_type_union_and_method() -> Result<()> {
        let mut parser = new_started_parser("interface { ~T | ~U; Method() }");
        let interface = parser.parse_interface_type()?;
        finish(&mut parser)?;

        let [type_element, method] = interface.methods.list.as_slice() else {
            return Err(anyhow::anyhow!("expected one type element and one method"));
        };

        assert!(type_element.name.is_empty());
        let (left, right) = assert_binary(&type_element.typ, Operator::Or);
        for (term, expected) in [(left, "T"), (right, "U")] {
            match term {
                Expression::Operation(operation) => {
                    assert_eq!(operation.op, Operator::Tiled);
                    assert!(operation.y.is_none());
                    assert_ident(&operation.x, expected);
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "expected underlying type {expected}, got {other:?}"
                    ))
                }
            }
        }

        assert_eq!(method.name.len(), 1);
        assert_eq!(method.name[0].name, "Method");
        assert!(matches!(method.typ, Expression::TypeFunction(_)));

        Ok(())
    }

    #[test]
    fn parse_struct_type() -> Result<()> {
        let struct_ = |s| {
            let mut parser = new_started_parser(s);
            let struct_ = parser.struct_type()?;
            finish(&mut parser)?;
            Ok(struct_)
        };

        struct_("struct {}")?;
        struct_("struct {T1}")?;
        struct_("struct {*T2}")?;
        struct_("struct {a[T]}")?;
        struct_("struct {P.T3}")?;
        struct_("struct {*P.T4}")?;
        struct_("struct {SL[K, V]}")?;
        struct_("struct {A *[]int}")?;
        struct_("struct {x, y int}")?;
        struct_("struct {u float32}")?;
        struct_("struct {_ float32}")?;
        struct_("struct {a T; b [1]T }")?;
        struct_("struct {a int; b bool}")?;
        struct_("struct {a int\nb bool}")?;
        struct_("struct {a int ``; b bool}")?;
        struct_("struct {micro uint64 `protobuf:\"1\"`}")?;

        assert!(struct_("struct {*[]a}").is_err());
        assert!(struct_("struct {**T2}").is_err());
        assert!(struct_("struct {a, b}").is_err());
        assert!(struct_("struct {a ...int}").is_err());
        assert!(struct_("struct {a, b int, bool}").is_err());

        Ok(())
    }

    #[test]
    fn parse_embedded_pointer_field_ast_shapes() -> Result<()> {
        let mut parser = new_started_parser("struct { T; *U; *pkg.V; *Box[int] }");
        let struct_type = parser.struct_type()?;
        finish(&mut parser)?;

        let [plain, pointer, qualified_pointer, generic_pointer] = struct_type.fields.as_slice()
        else {
            return Err(anyhow::anyhow!("expected four struct fields"));
        };

        assert!(struct_type.fields.iter().all(|field| field.name.is_empty()));
        assert_ident(&plain.typ, "T");

        let pointer_type = assert_pointer_type(&pointer.typ, 12);
        assert_ident(pointer_type, "U");

        let qualified_type = assert_pointer_type(&qualified_pointer.typ, 16);
        match qualified_type {
            Expression::Selector(selector) => {
                assert_ident(&selector.x, "pkg");
                assert_eq!(selector.sel.name, "V");
            }
            other => return Err(anyhow::anyhow!("expected qualified type, got {other:?}")),
        }

        let generic_type = assert_pointer_type(&generic_pointer.typ, 24);
        match generic_type {
            Expression::Index(index) => {
                assert_ident(&index.left, "Box");
                assert_ident(&index.index, "int");
            }
            other => return Err(anyhow::anyhow!("expected generic type, got {other:?}")),
        }

        Ok(())
    }

    #[test]
    fn parse_receive_only_channel_struct_field() -> Result<()> {
        let mut parser = new_started_parser("struct { events <-chan Event }");
        let struct_type = parser.struct_type()?;
        finish(&mut parser)?;

        let [field] = struct_type.fields.as_slice() else {
            return Err(anyhow::anyhow!("expected one struct field"));
        };
        assert_eq!(field.name.len(), 1);
        assert_eq!(field.name[0].name, "events");
        match &field.typ {
            Expression::TypeChannel(channel) => {
                assert_eq!(channel.dir, Some(ast::ChanMode::Recv));
                assert_ident(&channel.typ, "Event");
            }
            other => return Err(anyhow::anyhow!("expected channel field, got {other:?}")),
        }

        Ok(())
    }

    #[test]
    fn parse_call_expr() -> Result<()> {
        let call = |s| {
            let mut parser = Parser::from(s);
            match parser.expression()? {
                ast::Expression::Call(call) => {
                    finish(&mut parser)?;
                    Ok(call)
                }
                _ => Err(anyhow::anyhow!("not a CALL expression")),
            }
        };

        call("f(1)")?;
        call("f(1,2)")?;
        call("f(1,2,)")?;
        call("f(1,2,a...)")?;
        call("f(1,2,a...,)")?;
        call("f(f(),f()...)")?;
        call("f(f(f(f(f(f(1),),),),),)")?;
        call("f(fi()[f()],fi()[a].b...)")?;
        call("f(fi()[f()],fi()[a].b...,)")?;
        call("f(struct{a, b int}{a: 1, b: 2},)")?;

        assert!(call("f(...)").is_err());
        assert!(call("f(a b)").is_err());
        assert!(call("f(a...b)").is_err());
        assert!(call("f(a..., b)").is_err());
        assert!(call("f(a, b, ...)").is_err());
        assert!(call("f(fi()[f()] fi()[a].b...)").is_err());

        Ok(())
    }

    #[test]
    fn parse_stmt() -> Result<()> {
        let stmt = parse_statement_complete;

        match stmt("a <- b{c: c, d: d}")? {
            ast::Statement::Send(_) => {}
            _ => return Err(anyhow::anyhow!("not a SEND statement")),
        };

        match stmt("if err != nil { return }")? {
            ast::Statement::If(ifs) => {
                assert!(ifs.init.is_none());
                assert_eq!(ifs.body.list.len(), 1)
            }
            _ => return Err(anyhow::anyhow!("not a IF statement")),
        };

        match stmt("{ _ = &AnyList{1, '1'} }")? {
            ast::Statement::Block(block) => match block.list.first() {
                Some(ast::Statement::Assign(_)) => {}
                _ => return Err(anyhow::anyhow!("block is empty")),
            },
            _ => return Err(anyhow::anyhow!("not a BLOCK statement")),
        };

        match stmt("defer close()")? {
            ast::Statement::Defer(_) => {}
            _ => return Err(anyhow::anyhow!("not a DEFER statement")),
        };

        match stmt("fmt.Sprintf(`123`, rand.Int()%99);")? {
            ast::Statement::Expr(ast::ExprStmt {
                expr: ast::Expression::Call(call),
            }) => {
                assert_eq!(call.args.len(), 2);
            }
            _ => return Err(anyhow::anyhow!("not a CALL statement")),
        };

        match stmt("Update(a, x...)")? {
            ast::Statement::Expr(ast::ExprStmt {
                expr: ast::Expression::Call(call),
            }) => {
                assert_eq!(call.args.len(), 2);
            }
            _ => return Err(anyhow::anyhow!("not a CALL statement")),
        };

        match stmt("return &S[K, V]{a.b.c[0], nil}")? {
            ast::Statement::Return(_) => {}
            _ => return Err(anyhow::anyhow!("not a RETURN statement")),
        };

        Ok(())
    }

    #[test]
    fn parse_all_statement_kinds() -> Result<()> {
        assert!(matches!(
            parse_statement_complete(";")?,
            ast::Statement::Empty(_)
        ));

        match parse_statement_complete("Loop: for {}")? {
            ast::Statement::Label(label) => {
                assert_eq!(label.name.name, "Loop");
                assert!(matches!(*label.stmt, ast::Statement::For(_)));
            }
            other => return Err(anyhow::anyhow!("expected label, got {other:?}")),
        }

        match parse_statement_complete("counter++")? {
            ast::Statement::IncDec(statement) => {
                assert_eq!(statement.op, Operator::Inc);
                assert_ident(&statement.expr, "counter");
            }
            other => return Err(anyhow::anyhow!("expected increment, got {other:?}")),
        }

        match parse_statement_complete("counter--")? {
            ast::Statement::IncDec(statement) => {
                assert_eq!(statement.op, Operator::Dec);
                assert_ident(&statement.expr, "counter");
            }
            other => return Err(anyhow::anyhow!("expected decrement, got {other:?}")),
        }

        match parse_statement_complete("go worker(1)")? {
            ast::Statement::Go(statement) => assert_eq!(statement.call.args.len(), 1),
            other => return Err(anyhow::anyhow!("expected go statement, got {other:?}")),
        }

        match parse_statement_complete("<-ready")? {
            ast::Statement::Expr(statement) => match statement.expr {
                Expression::Operation(operation) => {
                    assert_eq!(operation.op, Operator::Arrow);
                    assert!(operation.y.is_none());
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "expected receive expression, got {other:?}"
                    ))
                }
            },
            other => {
                return Err(anyhow::anyhow!(
                    "expected expression statement, got {other:?}"
                ))
            }
        }

        for (source, expected, label) in [
            ("break Outer", Keyword::Break, Some("Outer")),
            ("continue", Keyword::Continue, None),
            ("goto Done", Keyword::Goto, Some("Done")),
            ("fallthrough", Keyword::FallThrough, None),
        ] {
            match parse_statement_complete(source)? {
                ast::Statement::Branch(statement) => {
                    assert_eq!(statement.key, expected, "{source}");
                    assert_eq!(
                        statement.ident.as_ref().map(|ident| ident.name.as_str()),
                        label
                    );
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "expected branch statement for {source}, got {other:?}"
                    ))
                }
            }
        }

        match parse_statement_complete("return first, second")? {
            ast::Statement::Return(statement) => assert_eq!(statement.ret.len(), 2),
            other => return Err(anyhow::anyhow!("expected return, got {other:?}")),
        }

        assert!(matches!(
            parse_statement_complete("var value int")?,
            ast::Statement::Declaration(ast::DeclStmt::Variable(_))
        ));
        assert!(matches!(
            parse_statement_complete("const value = 1")?,
            ast::Statement::Declaration(ast::DeclStmt::Const(_))
        ));
        assert!(matches!(
            parse_statement_complete("type Value int")?,
            ast::Statement::Declaration(ast::DeclStmt::Type(_))
        ));

        for source in [
            "go worker",
            "go (worker())",
            "defer worker",
            "defer (worker())",
            "fallthrough Label",
            "counter++++",
        ] {
            assert!(
                parse_statement_complete(source).is_err(),
                "expected rejection of {source:?}"
            );
        }

        Ok(())
    }

    #[test]
    fn reject_goto_without_label() {
        assert!(parse_statement_complete("goto").is_err());
    }

    #[test]
    fn parse_assign_stmt() -> Result<()> {
        let assign = |s, (l_len, r_len)| {
            let mut parser = new_started_parser(s);
            match parser.parse_simple_stmt()? {
                ast::Statement::Assign(assign) => {
                    finish(&mut parser)?;
                    if assign.left.len() != l_len {
                        return Err(anyhow::anyhow!("left side length error"));
                    }
                    if assign.right.len() != r_len {
                        return Err(anyhow::anyhow!("right side length error"));
                    }

                    Ok(assign)
                }
                _ => Err(anyhow::anyhow!("not a ASSIGN statement")),
            }
        };

        assign("x = 1", (1, 1))?;
        assign("*p = f()", (1, 1))?;
        assign("a[i] = 23", (1, 1))?;
        assign("(k) = <-ch", (1, 1))?;
        assign("a[i] <<= 2", (1, 1))?;
        assign("i &^= 1<<n", (1, 1))?;
        assign("_ = m[K, V]{}", (1, 1))?;
        assign("t := x.(type)", (1, 1))?;
        assign("_ = AAA{A: 1,}", (1, 1))?;
        assign("t, ok := x.(int)", (2, 1))?;
        assign("f2 := func() { go f1() }", (1, 1))?;
        assign("_ = &S[K, V]{a.b.c[0], nil}", (1, 1))?;
        assign("_ = &PeerInfo{time.Now(), '1'}", (1, 1))?;
        assign("one, two, three = '一', '二', '三'", (3, 3))?;

        for (source, expected) in [
            ("value = other", Operator::Assign),
            ("value += other", Operator::AddAssign),
            ("value -= other", Operator::SubAssign),
            ("value *= other", Operator::MulAssign),
            ("value /= other", Operator::QuoAssign),
            ("value %= other", Operator::RemAssign),
            ("value &= other", Operator::AndAssign),
            ("value |= other", Operator::OrAssign),
            ("value ^= other", Operator::XorAssign),
            ("value <<= other", Operator::ShlAssign),
            ("value >>= other", Operator::ShrAssign),
            ("value &^= other", Operator::AndNotAssign),
            ("value := other", Operator::Define),
        ] {
            assert_eq!(assign(source, (1, 1))?.op, expected, "{source}");
        }

        assert!(assign("a b = f()", (2, 1)).is_err());
        assert!(assign("a = b() c()", (1, 2)).is_err());
        assert!(assign("a = b(), c()", (1, 2)).is_err());

        Ok(())
    }

    #[test]
    fn parse_for_stmt() -> Result<()> {
        let range_stmt = |s| {
            let mut parser = new_started_parser(s);
            let statement = parser.parse_for_stmt()?;
            finish(&mut parser)?;
            match statement {
                ast::Statement::Range(rg) => Ok(rg),
                _ => Err(anyhow::anyhow!("not a RANGE statement")),
            }
        };

        range_stmt("for range ch {};")?;

        let rg = range_stmt("for x := range ch {};")?;
        assert!(rg.key.is_some());
        assert!(rg.value.is_none());
        assert!(rg.op.is_some());
        assert!(rg.body.list.is_empty());

        let rg = range_stmt("for _, v := range x {};")?;
        assert!(rg.key.is_some());
        assert!(rg.value.is_some());
        assert!(rg.op.is_some());
        assert!(rg.body.list.is_empty());

        let for_stmt = |s| {
            let mut parser = new_started_parser(s);
            let statement = parser.parse_for_stmt()?;
            finish(&mut parser)?;
            match statement {
                ast::Statement::For(fs) => Ok(fs),
                _ => Err(anyhow::anyhow!("not a FOR statement")),
            }
        };

        let fs = for_stmt("for {};")?;
        assert!(fs.init.is_none());
        assert!(fs.cond.is_none());
        assert!(fs.post.is_none());

        let fs = for_stmt("for loop {};")?;
        assert!(fs.init.is_none());
        assert!(fs.cond.is_some());
        assert!(fs.post.is_none());

        let fs = for_stmt("for i := 0; i < 1; {};")?;
        assert!(fs.init.is_some());
        assert!(fs.cond.is_some());
        assert!(fs.post.is_none());

        let fs = for_stmt("for i := 0; i < 1; i++ {};")?;
        assert!(fs.init.is_some());
        assert!(fs.cond.is_some());
        assert!(fs.post.is_some());

        let fs = for_stmt("for i := 0; i < 10; i = i + n {}")?;
        assert!(fs.init.is_some());
        assert!(fs.cond.is_some());
        assert!(fs.post.is_some());

        Ok(())
    }

    #[test]
    fn parse_select_stmt() -> Result<()> {
        let select = |s| {
            let mut parser = new_started_parser(s);
            let select = parser.parse_select_stmt()?;
            finish(&mut parser)?;
            Ok(select)
        };

        let slt = select(
            "select {
            case i1 = <-c1:
            case c2 <- i2:
            case i3, ok := (<-c3):
            case a[f()] = <-c4:
            default:
            }",
        )?;

        assert_eq!(slt.body.body.len(), 5);

        select("select {}")?;
        select("select {};")?;
        select("select  { default: ;}")?;
        select("select { default: }")?;

        assert!(select("select{;}").is_err());
        assert!(select("select; {}").is_err());
        assert!(select("select a {}").is_err());

        Ok(())
    }

    #[test]
    fn parse_switch_stmt() -> Result<()> {
        let switch = |s| {
            let mut parser = new_started_parser(s);
            let statement = parser.parse_switch_stmt()?;
            finish(&mut parser)?;
            match statement {
                ast::Statement::Switch(swt) => Ok(swt),
                _ => Err(anyhow::anyhow!("not a SWITCH statement")),
            }
        };

        let swt = switch("switch x {}")?;
        assert!(swt.init.is_none());
        assert!(swt.tag.is_some());

        let swt = switch("switch ;x {}")?;
        assert!(swt.init.is_none());
        assert!(swt.tag.is_some());

        let swt = switch(
            "switch ; {
            case true:
            print(mustbe)
            default:
        }",
        )?;
        assert!(swt.init.is_none());
        assert!(swt.tag.is_none());
        assert_eq!(swt.block.body.len(), 2);

        let swt = switch(
            "switch x {
            case 5:
            print(5)
        }",
        )?;
        assert!(swt.init.is_none());
        assert!(swt.tag.is_some());

        let swt = switch(
            "switch tag {
            default: s3()
            case 0, 1, 2, 3: s1()
            case 4, 5, 6, 7: s2()
            }",
        )?;
        assert!(swt.init.is_none());
        assert!(swt.tag.is_some());

        let swt = switch(
            "switch x := f(); {
            case x < 0: return -x
            default: return x
            }",
        )?;
        assert!(swt.init.is_some());
        assert!(swt.tag.is_none());

        let swt = switch(
            "
        switch a.b.c.(string) {
            case \"ok\":
            default:
            }",
        )?;
        assert!(swt.init.is_none());
        assert!(swt.tag.is_some());

        let swt = switch(
            "
        switch v, ok := a.b.c.(string); v {
            case \"ok\":
            default:
            }",
        )?;
        assert!(swt.init.is_some());
        assert!(swt.tag.is_some());

        let swt = switch(
            "
            switch s = a.(string); s {
            case \"\":
            }",
        )?;
        assert!(swt.init.is_some());
        assert!(swt.tag.is_some());

        assert!(switch(
            "switch s = a.(string) {
            case \"\":
            }",
        )
        .is_err());

        // FIXME: error reason is not correct
        assert!(switch(
            "switch s, ok = a.(string) {
            case \"\":
            }",
        )
        .is_err());

        let type_switch = |s| {
            let mut parser = new_started_parser(s);
            let statement = parser.parse_switch_stmt()?;
            finish(&mut parser)?;
            match statement {
                ast::Statement::TypeSwitch(swt) => Ok(swt),
                _ => Err(anyhow::anyhow!("not a TYPE_SWITCH statement")),
            }
        };

        let swt = type_switch("switch x;x.(type) {}")?;
        assert!(swt.init.is_some());
        assert!(swt.tag.is_some());

        let swt = type_switch("switch prev := r.descsByName[name]; prev.(type) {}")?;
        assert!(swt.init.is_some());
        assert!(swt.tag.is_some());

        let swt = type_switch(
            "
        switch a := x; c.(type) {
            case nil, *d:
            default:
            }",
        )?;
        assert!(swt.init.is_some());
        assert!(swt.tag.is_some());

        let swt = type_switch(
            "
        switch v.(type) {
        case nil:
            printString(\"x is nil\")                // type of i is type of x (interface{})
        case int:
            printInt(i)                            // type of i is int
        case float64:
            printFloat64(i)                        // type of i is float64
        case func(int) float64:
            printFunction(i)                       // type of i is func(int) float64
        case bool, string:
            printString(\"type is bool or string\")  // type of i is type of x (interface{})
        default:
            printString(\"don't know the type\")     // type of i is type of x (interface{})
            }",
        )?;
        assert!(swt.init.is_none());
        assert!(swt.tag.is_some());

        let swt = type_switch(
            "
            switch t := v.(type) {
                case int:
                    print(t+1)
                case bool:
                    print(!!t)
                case string:
                    print(t+\"!!\")
                default:
            }
            ",
        )?;
        assert!(swt.init.is_none());
        assert!(swt.tag.is_some());

        for source in [
            "switch x := v.(int) {}",
            "switch x := v.(*T) {}",
            "switch x := v.(interface{}) {}",
            "switch x = v.(type) {}",
        ] {
            assert!(
                new_started_parser(source).parse_switch_stmt().is_err(),
                "{source}"
            );
        }

        for op in [
            "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "&^=",
        ] {
            for assertion in ["int", "type"] {
                let source = format!("switch x {op} v.({assertion}) {{}}");
                assert!(
                    new_started_parser(&source).parse_switch_stmt().is_err(),
                    "{source}"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn parse_if_stmt() -> Result<()> {
        let stmt = |s| {
            let mut parser = new_started_parser(s);
            let ifst = parser.parse_if_stmt()?;
            finish(&mut parser)?;
            Ok(ifst)
        };

        stmt("if true {{}};")?;
        stmt("if m[struct{ int }{1}] {};")?;
        stmt("if struct{ bool }{true}.bool {};")?;

        let ifst = stmt("if a > 0 {};")?;
        assert!(ifst.init.is_none());

        let ifst = stmt("if a > 0 && yes {};")?;
        assert!(ifst.init.is_none());

        let ifst = stmt("if x := f(); x > 0 {};")?;
        assert!(ifst.init.is_some());

        let ifst = stmt("if true {} else if false {} else {};")?;
        assert!(ifst.else_.is_some());

        assert!(stmt("if true {} else false {};").is_err());

        Ok(())
    }

    #[test]
    fn parse_docs() -> Result<()> {
        let code = include_str!("../tests/testdata/docs.go");
        let mut ast = Parser::from(code).parse_file()?;

        assert_eq!(ast.docs.len(), 2);
        while let Some(decl) = ast.decl.pop() {
            match decl {
                Declaration::Const(..) => continue,
                Declaration::Function(x) => assert_eq!(x.docs.len(), 2),
                Declaration::Type(x) => {
                    assert_eq!(x.docs.len(), 0);
                    assert_eq!(x.specs[0].docs.len(), 1);

                    match &x.specs[0].typ {
                        Expression::TypeStruct(x) => {
                            assert_eq!(x.fields[0].comments.len(), 1);
                            assert_eq!(x.fields[1].comments.len(), 2);
                            assert_eq!(x.fields[2].comments.len(), 1);
                            assert_eq!(x.fields[3].comments.len(), 3);
                            assert_eq!(x.fields[4].comments.len(), 2);
                            assert_eq!(x.fields[5].comments.len(), 0);
                        }
                        _ => continue,
                    }
                }
                Declaration::Variable(x) => {
                    assert_eq!(x.docs.len(), 3);
                    assert_eq!(x.specs[0].docs.len(), 1);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn parse_func_docs() -> Result<()> {
        // TODO: need more test case
        let code = include_str!("../tests/testdata/func_docs.go");
        let ast = Parser::from(code).parse_file()?;

        match ast.decl.first() {
            Some(Declaration::Function(x)) => {
                assert_eq!(
                    x.docs[0].to_owned().text,
                    "/*
----------------abc-------------------------
test-abc[bcd]
*/"
                );

                Ok(())
            }
            _ => Err(anyhow::anyhow!("no declaration found")),
        }
    }

    /// TypeArgs = "[" TypeList [ "," ] "]" -- gofmt emits the trailing comma
    /// for multi-line lists.
    #[test]
    fn parse_trailing_comma_in_brackets() -> Result<()> {
        let cases = [
            // generic call, single line, trailing comma
            "package p\nfunc F[T any, U any]() {}\nfunc _() { F[int, string,]() }\n",
            // generic call, multi-line, trailing comma
            "package p\nfunc F[T any, U any]() {}\nfunc _() {\n\tF[\n\t\tint, string,\n\t]()\n}\n",
            // generic call, one type per line, trailing comma
            "package p\nfunc F[T any, U any]() {}\nfunc _() {\n\tF[\n\t\tint,\n\t\tstring,\n\t]()\n}\n",
            // composite literal with generic type instantiation
            "package p\ntype S[A, B any] struct{}\nfunc _() {\n\t_ = &S[\n\t\tint, string,\n\t]{}\n}\n",
            // three type arguments with trailing comma
            "package p\nfunc R[A, B, C any]() {}\nfunc _() {\n\tR[\n\t\tint,\n\t\tstring,\n\t\tbool,\n\t]()\n}\n",
            // single type argument with trailing comma
            "package p\nfunc F[T any]() {}\nfunc _() { F[int,]() }\n",
        ];
        for src in cases {
            Parser::from(src)
                .parse_file()
                .map_err(|e| anyhow::anyhow!("failed to parse {src:?}: {e}"))?;
        }
        Ok(())
    }

    /// No trailing comma -> ASI inserts `;` after the last identifier ->
    /// invalid Go. Pin that gosyn keeps rejecting it.
    #[test]
    fn parse_multiline_brackets_without_trailing_comma_rejected() {
        let src =
            "package p\nfunc F[T any, U any]() {}\nfunc _() {\n\tF[\n\t\tint, string\n\t]()\n}\n";
        assert!(Parser::from(src).parse_file().is_err());
    }

    /// `Foo[a,]` must parse as Index, not IndexList[1] -- matches go/ast.
    #[test]
    fn parse_single_arg_trailing_comma_yields_index_not_indexlist() -> Result<()> {
        let src = "package p\nfunc F[T any]() {}\nfunc _() { F[int,]() }\n";
        let file = Parser::from(src).parse_file()?;
        let func = match file.decl.last() {
            Some(Declaration::Function(f)) => f,
            _ => return Err(anyhow::anyhow!("expected function declaration")),
        };
        let body = func
            .body
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("expected function body"))?;
        let call_expr = match body.list.first() {
            Some(ast::Statement::Expr(e)) => &e.expr,
            other => {
                return Err(anyhow::anyhow!(
                    "expected expression statement, got {other:?}"
                ))
            }
        };
        let call = match call_expr {
            Expression::Call(c) => c,
            other => return Err(anyhow::anyhow!("expected call expression, got {other:?}")),
        };
        match &*call.func {
            Expression::Index(_) => Ok(()),
            Expression::IndexList(_) => Err(anyhow::anyhow!(
                "F[int,] must parse as Index, not IndexList (matches go/ast)"
            )),
            other => Err(anyhow::anyhow!("unexpected node: {other:?}")),
        }
    }

    /// `_` in type-arg position is valid Go (e.g. `func (b *Box[_]) M()`);
    /// go/parser accepts it and defers rejection to the type checker.
    #[test]
    fn parse_blank_identifier_in_type_args() -> Result<()> {
        let cases = [
            // single blank in receiver
            "package p\ntype Box[T any] struct{}\nfunc (b *Box[_]) Hello() {}\n",
            // mixed list with blank as the second name
            "package p\ntype Cache[K, V any] struct{}\nfunc (c *Cache[K, _]) Keys() []K { return nil }\n",
            // blank in expression-context generic instantiation
            "package p\ntype Box[T any] struct{}\nvar _ Box[_]\n",
            // pre-existing accepted form: blank in type-parameter declaration
            "package p\ntype Box[_ any] struct{}\n",
        ];
        for src in cases {
            Parser::from(src)
                .parse_file()
                .map_err(|e| anyhow::anyhow!("failed to parse {src:?}: {e}"))?;
        }
        Ok(())
    }
}
