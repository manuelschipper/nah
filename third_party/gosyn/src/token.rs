//! Define all golang syntax token

use std::fmt::{Debug, Formatter};
use strum::EnumString;
use strum::IntoStaticStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Eq, PartialEq, Debug, EnumString, IntoStaticStr)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Operator {
    #[strum(serialize = "+")]
    Add,
    #[strum(serialize = "-")]
    Sub,
    #[strum(serialize = "*")]
    Star,
    #[strum(serialize = "/")]
    Quo,
    #[strum(serialize = "%")]
    Rem,

    #[strum(serialize = "&")]
    And,
    #[strum(serialize = "|")]
    Or,
    #[strum(serialize = "^")]
    Xor,
    #[strum(serialize = "<<")]
    Shl,
    #[strum(serialize = ">>")]
    Shr,
    #[strum(serialize = "&^")]
    AndNot,

    #[strum(serialize = "+=")]
    AddAssign,
    #[strum(serialize = "-=")]
    SubAssign,
    #[strum(serialize = "*=")]
    MulAssign,
    #[strum(serialize = "/=")]
    QuoAssign,
    #[strum(serialize = "%=")]
    RemAssign,

    #[strum(serialize = "&=")]
    AndAssign,
    #[strum(serialize = "|=")]
    OrAssign,
    #[strum(serialize = "^=")]
    XorAssign,
    #[strum(serialize = "<<=")]
    ShlAssign,
    #[strum(serialize = ">>=")]
    ShrAssign,
    #[strum(serialize = "&^=")]
    AndNotAssign,

    #[strum(serialize = "&&")]
    AndAnd,
    #[strum(serialize = "||")]
    OrOr,
    #[strum(serialize = "<-")]
    Arrow,
    #[strum(serialize = "++")]
    Inc,
    #[strum(serialize = "--")]
    Dec,

    #[strum(serialize = "==")]
    Equal,
    #[strum(serialize = "<")]
    Less,
    #[strum(serialize = ">")]
    Greater,
    #[strum(serialize = "=")]
    Assign,
    #[strum(serialize = "!")]
    Not,
    #[strum(serialize = "~")]
    Tiled,

    #[strum(serialize = "!=")]
    NotEqual,
    #[strum(serialize = "<=")]
    LessEqual,
    #[strum(serialize = ">=")]
    GreaterEqual,
    #[strum(serialize = ":=")]
    Define,
    #[strum(serialize = "...")]
    DotDotDot,

    #[strum(serialize = "(")]
    ParenLeft,
    #[strum(serialize = ")")]
    ParenRight,
    #[strum(serialize = "[")]
    BarackLeft,
    #[strum(serialize = "]")]
    BarackRight,
    #[strum(serialize = "{")]
    BraceLeft,
    #[strum(serialize = "}")]
    BraceRight,

    #[strum(serialize = ",")]
    Comma,
    #[strum(serialize = ":")]
    Colon,
    #[strum(serialize = ".")]
    Dot,
    #[strum(serialize = ";")]
    SemiColon,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, EnumString, IntoStaticStr)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Keyword {
    #[strum(serialize = "break")]
    Break,
    #[strum(serialize = "case")]
    Case,
    #[strum(serialize = "chan")]
    Chan,
    #[strum(serialize = "const")]
    Const,
    #[strum(serialize = "continue")]
    Continue,

    #[strum(serialize = "default")]
    Default,
    #[strum(serialize = "defer")]
    Defer,
    #[strum(serialize = "else")]
    Else,
    #[strum(serialize = "fallthrough")]
    FallThrough,
    #[strum(serialize = "for")]
    For,

    #[strum(serialize = "func")]
    Func,
    #[strum(serialize = "go")]
    Go,
    #[strum(serialize = "goto")]
    Goto,
    #[strum(serialize = "if")]
    If,
    #[strum(serialize = "import")]
    Import,

    #[strum(serialize = "interface")]
    Interface,
    #[strum(serialize = "map")]
    Map,
    #[strum(serialize = "package")]
    Package,
    #[strum(serialize = "range")]
    Range,
    #[strum(serialize = "return")]
    Return,

    #[strum(serialize = "select")]
    Select,
    #[strum(serialize = "struct")]
    Struct,
    #[strum(serialize = "switch")]
    Switch,
    #[strum(serialize = "type")]
    Type,
    #[strum(serialize = "var")]
    Var,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LitKind {
    Ident,
    String,
    Integer,
    Float,
    Imag,
    Char,
}

#[derive(Eq, PartialEq, Clone)]
pub enum Token {
    Comment(String),
    Keyword(Keyword),
    Operator(Operator),
    Literal(LitKind, String),
}

impl From<Keyword> for Token {
    fn from(word: Keyword) -> Self {
        Token::Keyword(word)
    }
}

impl From<Operator> for Token {
    fn from(op: Operator) -> Self {
        Token::Operator(op)
    }
}

#[rustfmt::skip]
impl Operator {
    pub fn precedence(&self) -> usize {
        match self {
            | Operator::OrOr => 1,
            | Operator::AndAnd => 2,
            | Operator::Equal
            | Operator::NotEqual
            | Operator::Less
            | Operator::Greater
            | Operator::LessEqual
            | Operator::GreaterEqual => 3,
            | Operator::Add
            | Operator::Sub
            | Operator::Or
            | Operator::Xor => 4,
            | Operator::Star
            | Operator::Quo
            | Operator::Rem
            | Operator::Shl
            | Operator::Shr
            | Operator::And
            | Operator::AndNot => 5,
            _ => 0,
        }
    }

    pub(crate) fn to_str(self) -> &'static str {
        self.into()
    }
}

impl Keyword {
    fn to_str(self) -> &'static str {
        self.into()
    }
}

impl Debug for Token {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Comment(_) => write!(f, "/* comment */"),
            Token::Literal(_, lit) => write!(f, "'{lit}'"),
            Token::Operator(op) => write!(f, "'{}'", op.to_str()),
            Token::Keyword(word) => write!(f, "'{}'", word.to_str()),
        }
    }
}

impl Token {
    pub fn str_len(&self) -> usize {
        match self {
            Token::Operator(op) => op.to_str().len(),
            Token::Keyword(word) => word.to_str().len(),
            Token::Comment(text) => text.len(),
            Token::Literal(_, value) => value.len(),
        }
    }

    pub fn kind(&self) -> TokenKind {
        match self {
            Token::Comment(_) => TokenKind::Comment,
            Token::Operator(op) => TokenKind::Operator(*op),
            Token::Keyword(word) => TokenKind::Keyword(*word),
            Token::Literal(kind, _) => TokenKind::Literal(*kind),
        }
    }

    pub fn is<K: Into<TokenKind>>(&self, exp: K) -> bool {
        self.kind() == exp.into()
    }

    pub fn precedence(&self) -> Option<(Operator, usize)> {
        match self {
            Token::Operator(op) => Some((*op, op.precedence())),
            _ => None,
        }
    }
}

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum TokenKind {
    Comment,
    Keyword(Keyword),
    Literal(LitKind),
    Operator(Operator),
}

impl From<Keyword> for TokenKind {
    fn from(word: Keyword) -> Self {
        TokenKind::Keyword(word)
    }
}

impl From<LitKind> for TokenKind {
    fn from(lit: LitKind) -> Self {
        TokenKind::Literal(lit)
    }
}

impl From<Operator> for TokenKind {
    fn from(op: Operator) -> Self {
        TokenKind::Operator(op)
    }
}

impl Debug for TokenKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Comment => unreachable!(),
            Self::Keyword(word) => write!(f, "'{}'", word.to_str()),
            Self::Operator(op) => write!(f, "'{}'", op.to_str()),
            Self::Literal(kind) => match kind {
                LitKind::Ident => write!(f, "Identifier"),
                LitKind::String => write!(f, "String Literals"),
                LitKind::Integer => write!(f, "Integer Literals"),
                LitKind::Imag => write!(f, "Imaginary Literals"),
                LitKind::Char => write!(f, "Character Literals"),
                LitKind::Float => write!(f, "Float Literals"),
            },
        }
    }
}
