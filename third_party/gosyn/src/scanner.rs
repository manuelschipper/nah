use crate::token::Keyword;
use crate::token::LitKind;
use crate::token::Operator;
use crate::token::Token;
use crate::Error;
use crate::LexicalToken;

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use unic_ucd_category::GeneralCategory;

#[derive(Default)]
pub struct Scanner {
    pos: usize, // index as chars
    semicolon: bool,
    lines: Vec<usize>,

    source: String,
    path: PathBuf,
    chars: Vec<char>,
    indices: Vec<usize>,
}

impl Scanner {
    pub(crate) fn from<S: AsRef<str>>(s: S) -> Self {
        let path = "<input>".into();
        let source = s.as_ref().to_string();
        let (indices, chars): (Vec<_>, Vec<_>) = source.char_indices().unzip();

        Self {
            path,
            source,
            indices,
            chars,
            ..Default::default()
        }
    }

    pub(crate) fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut source = fs::read_to_string(&path)?;
        const BOM: &str = "\u{feff}";
        if source.starts_with(BOM) {
            source = source.split_off(BOM.len());
        }

        let path = path.as_ref().into();
        let (indices, chars): (Vec<_>, Vec<_>) = source.char_indices().unzip();

        Ok(Self {
            path,
            source,
            indices,
            chars,
            ..Default::default()
        })
    }

    pub(crate) fn path(&self) -> PathBuf {
        self.path.clone()
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn preback(&self) -> (usize, bool) {
        (self.pos, self.semicolon)
    }

    pub(crate) fn goback(&mut self, pre: (usize, bool)) {
        self.pos = pre.0;
        self.semicolon = pre.1
    }

    pub(crate) fn line_info(&self, pos: usize) -> (usize, usize) {
        match self.lines.binary_search(&pos) {
            Ok(index) => (index + 1, 0),
            Err(0) => (1, pos),
            Err(index) => {
                let start_at = self.lines[index - 1];
                (index, pos - start_at)
            }
        }
    }

    fn add_line(&mut self, line_start: usize) {
        self.lines.push(line_start);
    }

    fn error<S: AsRef<str>>(&self, reason: S) -> anyhow::Error {
        self.error_at(self.pos, reason)
    }

    fn error_at<S: AsRef<str>>(&self, pos: usize, reason: S) -> anyhow::Error {
        Error::Else {
            path: self.path(),
            location: self.line_info(pos),
            reason: reason.as_ref().into(),
        }
        .into()
    }

    fn next_char(&mut self, skp: usize) -> Option<char> {
        self.chars.get(self.pos + skp).copied()
    }

    fn next_nstr(&self, n: usize) -> &str {
        let start = self.indices[self.pos];
        let end = self
            .indices
            .get(self.pos + n)
            .copied()
            .unwrap_or(self.source.len());
        &self.source[start..end]
    }

    #[rustfmt::skip]
    fn try_insert_semicolon(&mut self, tok: &Token) -> bool {
        matches!(
            tok,
            | &Token::Literal(..)
            | &Token::Operator(Operator::Inc)
            | &Token::Operator(Operator::Dec)
            | &Token::Operator(Operator::ParenRight)
            | &Token::Operator(Operator::BraceRight)
            | &Token::Operator(Operator::BarackRight)
            | &Token::Keyword(Keyword::Break)
            | &Token::Keyword(Keyword::Return)
            | &Token::Keyword(Keyword::Continue)
            | &Token::Keyword(Keyword::FallThrough)
        )
    }

    fn line_ended(&mut self) -> bool {
        let mut chars = self.chars[self.pos..].iter().peekable();

        loop {
            match chars.next() {
                None | Some('\n') => return true,
                Some(c) if c.is_whitespace() => continue,
                Some('/') => match chars.next() {
                    Some('/') => return true,
                    Some('*') => loop {
                        match chars.next() {
                            None | Some('\n') => return true,
                            Some('*') if chars.next_if_eq(&&'/').is_some() => break,
                            _ => continue,
                        }
                    },
                    _ => return false,
                },
                _ => return false,
            }
        }
    }

    pub(crate) fn skip_whitespace(&mut self) -> usize {
        let mut skipped = 0;
        while let Some(ch) = self.next_char(0) {
            if ch.is_whitespace() {
                if ch == '\n' {
                    self.add_line(self.pos + 1);
                }

                skipped += 1;
                self.pos += 1;
                continue;
            }

            break;
        }
        skipped
    }

    pub(crate) fn next_token(&mut self) -> Result<Option<(usize, Token)>> {
        if self.semicolon && self.line_ended() {
            let pos = self.pos;
            let tok = Token::Operator(Operator::SemiColon);
            self.semicolon = false;
            return Ok(Some((pos, tok)));
        }

        self.semicolon = false;
        self.skip_whitespace();
        if self.pos >= self.chars.len() {
            return Ok(None);
        }

        let current = self.pos;
        let (tok, char_count) = self.scan_token()?;
        self.add_token_cross_line(&tok);
        self.pos += char_count;
        self.semicolon = self.try_insert_semicolon(&tok);
        Ok(Some((current, tok)))
    }

    pub(crate) fn tokenize(mut self) -> Result<Vec<LexicalToken>> {
        let mut tokens = Vec::new();
        while let Some((start, token)) = self.next_token()? {
            let end = self.position();
            if start < end {
                tokens.push(LexicalToken { start, end, token });
            }
        }
        Ok(tokens)
    }

    fn add_token_cross_line(&mut self, tok: &Token) {
        match tok {
            Token::Comment(text) | Token::Literal(.., text) => {
                for (index, ch) in text.chars().enumerate() {
                    if ch == '\n' {
                        self.add_line(self.pos + index + 1)
                    }
                }
            }
            _ => {}
        }
    }

    /// return next Token
    pub(crate) fn scan_token(&mut self) -> Result<(Token, usize)> {
        if let Ok(op) = Operator::from_str(self.next_nstr(3)) {
            let char_count = op.to_str().len();
            return Ok((op.into(), char_count));
        }

        if let Some(tok_cnt) = match self.next_nstr(2) {
            "//" => {
                let comment = self.scan_line_comment();
                let char_count = comment.len();
                Some((Token::Comment(comment.iter().collect()), char_count))
            }
            "/*" => {
                let comment = self.scan_general_comment()?;
                let char_count = comment.len();
                Some((Token::Comment(comment.iter().collect()), char_count))
            }
            two => Operator::from_str(two).ok().map(|op| {
                let char_count = op.to_str().len();
                (op.into(), char_count)
            }),
        } {
            return Ok(tok_cnt);
        }

        // caller make sure here is at least one character
        let next0_char = self.next_char(0).unwrap();
        let next1_is_digits = matches!(self.next_char(1), Some('0'..='9'));
        let next0_char_op = Operator::from_str(&next0_char.to_string()).ok();

        Ok(match next0_char {
            c if is_decimal_digit(c) => self.scan_lit_number()?,
            '.' if next1_is_digits => self.scan_lit_number()?,
            '\'' => {
                let runes = self.scan_lit_rune()?;
                let char_count = runes.len();
                let runes = runes.iter().collect();

                (Token::Literal(LitKind::Char, runes), char_count)
            }
            '"' | '`' => {
                let litstr = self.scan_lit_string()?;
                let char_count = litstr.len();
                let litstr = litstr.iter().collect();
                (Token::Literal(LitKind::String, litstr), char_count)
            }
            ch if is_letter(ch) => {
                let identifier = self.scan_identifier();
                let char_count = identifier.len();
                let identifier = identifier.iter().collect::<String>();
                let tok = match Keyword::from_str(identifier.as_str()) {
                    Ok(word) => Token::Keyword(word),
                    _ => Token::Literal(LitKind::Ident, identifier),
                };

                (tok, char_count)
            }
            other => match next0_char_op {
                Some(op) => (op.into(), op.to_str().len()),
                _ => return Err(self.error(format!("unresolved character {other:?}"))),
            },
        })
    }

    /// Scan line comment from `//` to `\n`
    fn scan_line_comment(&mut self) -> &[char] {
        let start = self.pos;
        let mut end = start;
        while let Some(ch) = self.chars.get(end) {
            if ch == &'\n' {
                break;
            }
            end += 1;
        }

        &self.chars[start..end]
    }

    /// Scan general comment from `/*` to `*/`
    fn scan_general_comment(&mut self) -> Result<&[char]> {
        let chars = &self.chars;
        assert_eq!(chars[self.pos], '/');
        assert_eq!(chars[self.pos + 1], '*');

        let start = self.pos;
        let mut end = start + 2;
        let mut happy_endding = false;
        while end < chars.len() - 1 && !happy_endding {
            happy_endding = chars[end] == '*' && chars[end + 1] == '/';
            end += 1;
        }

        if happy_endding {
            let end = (end + 1).min(chars.len());
            return Ok(&self.chars[start..end]);
        }

        Err(self.error("comment no termination '*/'"))
    }

    /// scan an identifier
    /// caller must ensure that the first character is a unicode letter
    /// caller should check if identify is a keyword
    fn scan_identifier(&mut self) -> &[char] {
        let start = self.pos;
        let mut end = start;
        while let Some(&ch) = self.chars.get(end) {
            if !is_letter(ch) && !is_unicode_digit(ch) {
                break;
            }
            end += 1;
        }

        &self.chars[start..end]
    }

    fn scan_rune(&mut self, start_at: usize, quote: char) -> Result<Vec<char>> {
        let mut chars = self.chars[start_at..].iter().copied();
        let (next1, next2) = (chars.next(), chars.next());

        // must match a valid character
        let must_be = |ch: Option<char>, valid: fn(char) -> bool| match ch {
            Some(ch) if valid(ch) => Ok(ch),
            Some(_) => Err(self.error("illegal rune literal")),
            None => Err(self.error("literal not terminated")),
        };

        // take exactly N valid character
        let mut match_n = |n, valid| {
            (0..)
                .take(n)
                .map(|_| must_be(chars.next(), valid))
                .collect::<Result<Vec<char>>>()
        };

        // return normal character and error directly
        let es_sequence = match next1 {
            Some('\\') => match next2 {
                Some('x') => match_n(2, is_hex_digit)?,
                Some('u') => match_n(4, is_hex_digit)?,
                Some('U') => match_n(8, is_hex_digit)?,
                Some(ch) if is_octal_digit(ch) => match_n(2, is_octal_digit)?,
                Some(ch) if is_escaped_char(ch, quote) => return Ok(vec!['\\', ch]),
                Some(_) => return Err(self.error("unknown escape sequence")),
                None => return Err(self.error("literal not terminated")),
            },
            Some(ch) if is_unicode_char(ch) => return Ok(vec![ch]),
            None => return Err(self.error_at(self.pos, "literal not terminated")),
            Some(_) => return Err(self.error_at(self.pos, "unexpected character")),
        };

        let es_sequence = [vec![next1.unwrap(), next2.unwrap()], es_sequence].concat();
        let (radix, sequence) = match es_sequence.get(1).unwrap() {
            'x' | 'u' | 'U' => (16, &es_sequence[2..]),
            _ => (8, &es_sequence[1..]), // here must be octal_digit
        };
        let value = u32::from_str_radix(&String::from_iter(sequence), radix)
            .expect("here must be a valid u32");
        if radix == 8 && value > u8::MAX.into() {
            return Err(self.error("octal escape value exceeds 255"));
        }
        char::from_u32(value).ok_or_else(|| self.error("invalid Unicode code point"))?;

        Ok(es_sequence)
    }

    fn scan_lit_rune(&mut self) -> Result<Vec<char>> {
        let chars = &self.chars;
        assert_eq!(&chars[self.pos], &'\'');

        let mut rune = self.scan_rune(self.pos + 1, '\'')?;
        match self.chars.get(self.pos + 1 + rune.len()) {
            Some('\'') => {
                let mut res = vec!['\''];
                res.append(&mut rune);
                res.push('\'');
                Ok(res)
            }
            Some(_) => Err(self.error_at(self.pos, "rune literal expect termination")),
            None => Err(self.error_at(self.pos, "rune literal not termination")),
        }
    }

    fn scan_lit_string(&mut self) -> Result<Vec<char>> {
        let mut result = vec![];
        let quote = self.chars[self.pos];
        result.push(quote);

        if quote == '`' {
            let chars = self.chars[self.pos + 1..].iter();
            for &ch in chars {
                result.push(ch);
                if ch == quote {
                    break;
                }
            }
        } else {
            let end = self.chars.len();
            let mut pos = self.pos + 1;
            while pos < end {
                let mut rune = self.scan_rune(pos, quote)?;
                pos += rune.len();
                let quit = rune.len() == 1 && rune[0] == quote;
                result.append(&mut rune);
                if quit {
                    break;
                }
            }
        }

        if result.len() >= 2 && result.last() == Some(&quote) {
            return Ok(result);
        }

        let offset = self.pos + result.len();
        Err(self.error_at(offset, "string literal not terminated"))
    }

    fn scan_digits(&mut self, skp: usize, mut result: String, valid: fn(char) -> bool) -> String {
        let mut underline = true;
        for &ch in &self.chars[self.pos + skp..] {
            if (ch == '_' && !underline) || (ch != '_' && !valid(ch)) {
                break;
            }
            result.push(ch);
            underline = ch != '_';
        }

        result
    }

    fn scan_digits2(&mut self, skp: usize, result: &mut String, valid: fn(char) -> bool) {
        let mut underline = true;
        for &ch in &self.chars[self.pos + skp..] {
            if (ch == '_' && !underline) || (ch != '_' && !valid(ch)) {
                break;
            }
            result.push(ch);
            underline = ch != '_';
        }
    }

    fn scan_lit_number(&mut self) -> Result<(Token, usize)> {
        // integer part
        let (radix, prefix_len, mut numlit) = match self.next_char(0) {
            Some('.') | None => (10, 0, String::new()),
            Some(_) => {
                let next2 = String::from(self.next_nstr(2));
                match next2.as_str() {
                    "0b" | "0B" => (2, 2, self.scan_digits(2, next2, is_binary_digit)),
                    "0o" | "0O" => (8, 2, self.scan_digits(2, next2, is_octal_digit)),
                    "0x" | "0X" => (16, 2, self.scan_digits(2, next2, is_hex_digit)),
                    _ => (10, 0, self.scan_digits(0, String::new(), is_decimal_digit)),
                }
            }
        };

        if numlit.ends_with('_') {
            return Err(self.error_at(
                self.pos + numlit.len(),
                "'_' must separate successive digits",
            ));
        }

        let fac_start = numlit.len();
        if let Some('.') = self.next_char(fac_start) {
            numlit.push('.');
            match radix {
                2 | 8 => return Err(self.error_at(self.pos + fac_start, "invalid radix point")),
                16 => self.scan_digits2(fac_start + 1, &mut numlit, is_hex_digit),
                _ => self.scan_digits2(fac_start + 1, &mut numlit, is_decimal_digit),
            };
        }

        let fac_part = &numlit[fac_start..];
        if fac_part.starts_with("._") || (fac_part.ends_with('_')) {
            return Err(self.error_at(self.pos + fac_start, "'_' must separate successive digits"));
        }

        let valid_digit = match radix {
            2 => is_binary_digit,
            8 => is_octal_digit,
            16 => is_hex_digit,
            _ => is_decimal_digit,
        };
        if prefix_len != 0 && !numlit[prefix_len..].chars().any(valid_digit) {
            return Err(self.error_at(self.pos + numlit.len(), "mantissa has no digits"));
        }
        if matches!(radix, 2 | 8)
            && matches!(self.next_char(numlit.len()), Some(ch) if is_decimal_digit(ch))
        {
            return Err(self.error_at(self.pos + numlit.len(), "invalid digit for numeric base"));
        }

        let skipped = numlit.len();
        let int_part = &numlit[..fac_start];
        let invalid_legacy_octal = prefix_len == 0
            && int_part.len() > 1
            && int_part.starts_with('0')
            && int_part.chars().any(|ch| matches!(ch, '8' | '9'));
        let next1 = self.next_char(fac_start);
        if numlit.is_empty() {
            return Err(self.error_at(self.pos + skipped, "invalid radix point"));
        } else if radix != 10 && matches!(next1, Some('e' | 'E')) {
            return Err(self.error_at(self.pos + skipped, "E exponent requires decimal mantissa"));
        } else if radix != 16 && matches!(next1, Some('p' | 'P')) {
            return Err(self.error_at(
                self.pos + skipped,
                "P exponent requires hexadecimal mantissa",
            ));
        };

        let exp_start = numlit.len();
        if let Some(exp @ ('e' | 'E' | 'p' | 'P')) = self.next_char(skipped) {
            numlit.push(exp);
            if let Some(signed @ ('+' | '-')) = self.next_char(skipped + 1) {
                numlit.push(signed);
            }

            self.scan_digits2(numlit.len(), &mut numlit, is_decimal_digit)
        }

        let exp_part = &numlit[exp_start..];
        let fac_part = &numlit[fac_start..];
        if !exp_part.is_empty() && !exp_part.chars().skip(1).any(is_decimal_digit) {
            return Err(self.error_at(self.pos + numlit.len(), "exponent has no digits"));
        }
        if radix == 16 && !fac_part.is_empty() && exp_part.is_empty() {
            return Err(self.error_at(
                self.pos + skipped + exp_part.len(),
                "mantissa has no digits",
            ));
        }

        if exp_part
            .as_bytes()
            .iter()
            .skip(1) // skip e|E|p|P
            .find(|&&ch| ch != b'+' && ch != b'-')
            == Some(&b'_')
            || exp_part.ends_with('_')
        {
            return Err(self.error_at(
                self.pos + skipped + exp_part.len(),
                "'_' must separate successive digits",
            ));
        }

        let char_count = numlit.len();
        let is_imaginary = self.next_char(char_count) == Some('i');
        let is_float = numlit.contains('.') || !exp_part.is_empty();
        if invalid_legacy_octal && !is_imaginary && !is_float {
            return Err(self.error_at(self.pos + char_count, "invalid digit in octal literal"));
        }

        if is_imaginary {
            Ok((Token::Literal(LitKind::Imag, numlit + "i"), char_count + 1))
        } else if is_float {
            Ok((Token::Literal(LitKind::Float, numlit), char_count))
        } else {
            Ok((Token::Literal(LitKind::Integer, numlit), char_count))
        }
    }
}

/// here are some difference from the golang specification of [Characters](https://golang.org/ref/spec#Characters)
/// go's `unicode_char` is an arbitrary Unicode code point except newline
/// but rust's char is a [unicode scalar value](https://www.unicode.org/glossary/#unicode_scalar_value)
fn is_unicode_char(c: char) -> bool {
    !is_newline(c)
}

fn is_newline(c: char) -> bool {
    c == '\u{000A}'
}

fn is_unicode_letter(c: char) -> bool {
    GeneralCategory::of(c).is_letter()
}

fn is_unicode_digit(c: char) -> bool {
    matches!(GeneralCategory::of(c), GeneralCategory::DecimalNumber)
}

fn is_letter(c: char) -> bool {
    is_unicode_letter(c) || c == '_'
}

fn is_binary_digit(c: char) -> bool {
    matches!(c, '0'..='1')
}

fn is_octal_digit(c: char) -> bool {
    matches!(c, '0'..='7')
}

fn is_decimal_digit(c: char) -> bool {
    c.is_ascii_digit()
}

fn is_hex_digit(c: char) -> bool {
    c.is_ascii_hexdigit()
}

fn is_escaped_char(c: char, quote: char) -> bool {
    ['a', 'b', 'f', 'n', 'r', 't', 'v', '\\'].contains(&c) || c == quote
}

#[cfg(test)]
mod tests {
    use super::Scanner;
    use crate::token::Keyword;
    use crate::token::LitKind;
    use crate::token::Operator;
    use crate::token::Token;

    fn scan_tokens(source: &str) -> Vec<(usize, Token)> {
        let mut scanner = Scanner::from(source);
        let mut tokens = vec![];
        while let Some(token) = scanner.next_token().expect("source should scan") {
            tokens.push(token);
        }
        tokens
    }

    #[test]
    fn line_ended() {
        let ended = |s| Scanner::from(s).line_ended();

        assert!(!ended("1"));
        assert!(!ended("/**/123"));
        assert!(ended("//"));
        assert!(ended("/**/"));
        assert!(ended("/*\n*/"));
        assert!(ended("/**/ //"));
    }

    #[test]
    fn insert_semicolon() {
        const SEMI: Token = Token::Operator(Operator::SemiColon);

        let mut scan = Scanner::from("return//\nreturn");
        let mut next = move || scan.next_token();

        assert!(!matches!(next(), Ok(Some((_, SEMI)))));
        assert!(matches!(next(), Ok(Some((_, SEMI)))));
        assert!(!matches!(next(), Ok(Some((_, SEMI)))));

        let mut scan = Scanner::from("a\nb\nc");
        let mut next = move || scan.next_token();

        assert!(!matches!(next(), Ok(Some((_, SEMI)))));
        assert!(matches!(next(), Ok(Some((_, SEMI)))));
        assert!(!matches!(next(), Ok(Some((_, SEMI)))));
        assert!(matches!(next(), Ok(Some((_, SEMI)))));
        assert!(!matches!(next(), Ok(Some((_, SEMI)))));
    }

    #[test]
    fn insert_semicolon_after_all_trigger_tokens() {
        for source in [
            "name",
            "1",
            "1.5",
            "1i",
            "'x'",
            r#""x""#,
            "break",
            "continue",
            "fallthrough",
            "return",
            "x++",
            "x--",
            "(x)",
            "x[0]",
            "struct{}",
        ] {
            let tokens = scan_tokens(&format!("{source}\n+"));
            let semicolons = tokens
                .iter()
                .filter(|(_, token)| *token == Token::Operator(Operator::SemiColon))
                .count();
            assert_eq!(semicolons, 1, "{source:?}");
        }
    }

    #[test]
    fn do_not_insert_semicolon_after_non_trigger_tokens() {
        for source in [
            "case",
            "chan",
            "const",
            "default",
            "defer",
            "else",
            "for",
            "func",
            "go",
            "goto",
            "if",
            "import",
            "interface",
            "map",
            "range",
            "select",
            "struct",
            "switch",
            "type",
            "var",
            "+",
            "(",
            "[",
            "{",
            ",",
            ".",
            ":",
        ] {
            let tokens = scan_tokens(&format!("{source}\n+"));
            assert!(
                tokens
                    .iter()
                    .all(|(_, token)| *token != Token::Operator(Operator::SemiColon)),
                "{source:?}"
            );
        }
    }

    #[test]
    fn do_not_insert_semicolon_after_package_keyword() {
        let tokens = scan_tokens("package\n+");
        assert!(tokens
            .iter()
            .all(|(_, token)| *token != Token::Operator(Operator::SemiColon)));
    }

    #[test]
    fn scan_text() {
        assert_eq!(
            scan_tokens("'一', '二', '三'"),
            vec![
                (0, Token::Literal(LitKind::Char, "'一'".into())),
                (3, Token::Operator(Operator::Comma)),
                (5, Token::Literal(LitKind::Char, "'二'".into())),
                (8, Token::Operator(Operator::Comma)),
                (10, Token::Literal(LitKind::Char, "'三'".into())),
                (13, Token::Operator(Operator::SemiColon)),
            ]
        );

        assert_eq!(
            scan_tokens("n%9"),
            vec![
                (0, Token::Literal(LitKind::Ident, "n".into())),
                (1, Token::Operator(Operator::Rem)),
                (2, Token::Literal(LitKind::Integer, "9".into())),
                (3, Token::Operator(Operator::SemiColon)),
            ]
        );
    }

    #[test]
    fn scan_identifiers_and_keywords() {
        assert_eq!(
            scan_tokens("alpha β2 _x9"),
            vec![
                (0, Token::Literal(LitKind::Ident, "alpha".into())),
                (6, Token::Literal(LitKind::Ident, "β2".into())),
                (9, Token::Literal(LitKind::Ident, "_x9".into())),
                (12, Token::Operator(Operator::SemiColon)),
            ]
        );

        let keywords = [
            ("break", Keyword::Break),
            ("case", Keyword::Case),
            ("chan", Keyword::Chan),
            ("const", Keyword::Const),
            ("continue", Keyword::Continue),
            ("default", Keyword::Default),
            ("defer", Keyword::Defer),
            ("else", Keyword::Else),
            ("fallthrough", Keyword::FallThrough),
            ("for", Keyword::For),
            ("func", Keyword::Func),
            ("go", Keyword::Go),
            ("goto", Keyword::Goto),
            ("if", Keyword::If),
            ("import", Keyword::Import),
            ("interface", Keyword::Interface),
            ("map", Keyword::Map),
            ("package", Keyword::Package),
            ("range", Keyword::Range),
            ("return", Keyword::Return),
            ("select", Keyword::Select),
            ("struct", Keyword::Struct),
            ("switch", Keyword::Switch),
            ("type", Keyword::Type),
            ("var", Keyword::Var),
        ];

        for (source, keyword) in keywords {
            let tokens = scan_tokens(source);
            assert_eq!(
                tokens.first(),
                Some(&(0, Token::Keyword(keyword))),
                "{source}"
            );
        }
    }

    #[test]
    fn scan_all_operators_and_punctuation() {
        let operators = [
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
            ("+=", Operator::AddAssign),
            ("-=", Operator::SubAssign),
            ("*=", Operator::MulAssign),
            ("/=", Operator::QuoAssign),
            ("%=", Operator::RemAssign),
            ("&=", Operator::AndAssign),
            ("|=", Operator::OrAssign),
            ("^=", Operator::XorAssign),
            ("<<=", Operator::ShlAssign),
            (">>=", Operator::ShrAssign),
            ("&^=", Operator::AndNotAssign),
            ("&&", Operator::AndAnd),
            ("||", Operator::OrOr),
            ("<-", Operator::Arrow),
            ("++", Operator::Inc),
            ("--", Operator::Dec),
            ("==", Operator::Equal),
            ("<", Operator::Less),
            (">", Operator::Greater),
            ("=", Operator::Assign),
            ("!", Operator::Not),
            ("~", Operator::Tiled),
            ("!=", Operator::NotEqual),
            ("<=", Operator::LessEqual),
            (">=", Operator::GreaterEqual),
            (":=", Operator::Define),
            ("...", Operator::DotDotDot),
            ("(", Operator::ParenLeft),
            (")", Operator::ParenRight),
            ("[", Operator::BarackLeft),
            ("]", Operator::BarackRight),
            ("{", Operator::BraceLeft),
            ("}", Operator::BraceRight),
            (",", Operator::Comma),
            (":", Operator::Colon),
            (".", Operator::Dot),
            (";", Operator::SemiColon),
        ];

        for (source, operator) in operators {
            let tokens = scan_tokens(source);
            assert_eq!(
                tokens.first(),
                Some(&(0, Token::Operator(operator))),
                "{source}"
            );
        }
    }

    #[test]
    fn scan_whitespace_positions_and_invalid_characters() {
        assert_eq!(
            scan_tokens("a \t\r\n b"),
            vec![
                (0, Token::Literal(LitKind::Ident, "a".into())),
                (1, Token::Operator(Operator::SemiColon)),
                (6, Token::Literal(LitKind::Ident, "b".into())),
                (7, Token::Operator(Operator::SemiColon)),
            ]
        );

        assert!(Scanner::from("@").next_token().is_err());
    }

    #[test]
    fn scan_lookahead_preserves_utf8_boundaries() {
        assert_eq!(Scanner::from("a本").next_nstr(3), "a本");
        assert_eq!(Scanner::from("本a").next_nstr(2), "本a");
        assert_eq!(Scanner::from("本ab").next_nstr(2), "本a");
        assert_eq!(Scanner::from(">>=本").next_nstr(3), ">>=");

        for source in ["a本", "本+", "本==字", "a本+"] {
            let mut scanner = Scanner::from(source);
            while scanner.next_token().unwrap().is_some() {}
        }
    }

    #[test]
    fn scan_lit_number() {
        let numeric = |s: &str| {
            let mut sc = Scanner::from(s);
            let (n, size) = sc.scan_lit_number()?;
            if size != s.len() {
                return Err(sc.error("scan not finished"));
            }
            Ok(n)
        };

        assert!(numeric("1").is_ok());
        assert!(numeric("42").is_ok());
        assert!(numeric("4_2").is_ok());
        assert!(numeric("0600").is_ok());
        assert!(numeric("0_600").is_ok());
        assert!(numeric("0o600").is_ok());
        assert!(numeric("0O600").is_ok());
        assert!(numeric("0b1010").is_ok());
        assert!(numeric("0B1010").is_ok());
        assert!(numeric("0xBadFace").is_ok());
        assert!(numeric("0xBad_Face").is_ok());
        assert!(numeric("0x_67_7a_2f_cc_40_c6").is_ok());
        assert!(numeric("170141183460469231731687303715884105727").is_ok());
        assert!(numeric("170_141183_460469_231731_687303_715884_105727").is_ok());

        assert!(numeric("42_").is_err());
        assert!(numeric("4__2").is_err());
        assert!(numeric("0_xBadFace").is_err());

        assert!(numeric("0.").is_ok());
        assert!(numeric("1E6").is_ok());
        assert!(numeric(".25").is_ok());
        assert!(numeric("1_5.").is_ok());
        assert!(numeric("72.40").is_ok());
        assert!(numeric("1.e+0").is_ok());
        assert!(numeric("072.40").is_ok());
        assert!(numeric("2.71828").is_ok());
        assert!(numeric(".12345E+5").is_ok());
        assert!(numeric("0.15e+0_2").is_ok());
        assert!(numeric("6.67428e-11").is_ok());

        assert!(numeric("0x15e").is_ok());
        assert!(numeric("0x1p-2").is_ok());
        assert!(numeric("0x2.p10").is_ok());
        assert!(numeric("0X.8p-0").is_ok());
        assert!(numeric("0x1.Fp+0").is_ok());
        assert!(numeric("0X_1FFFP-16").is_ok());
        assert!(numeric("0x1p1_0").is_ok());

        assert!(numeric("1p-2").is_err());
        assert!(numeric("1_.5").is_err());
        assert!(numeric("1._5").is_err());
        assert!(numeric("0x.p1").is_err());
        assert!(numeric("1.5_e1").is_err());
        assert!(numeric("1.5e_1").is_err());
        assert!(numeric("1.5e1_").is_err());
        assert!(numeric("1.5e+_1").is_err());
        assert!(numeric("0x1.5e-2").is_err());
        assert!(numeric("0x1p1a").is_err());
        assert!(numeric("0x1.0p1a").is_err());
        assert!(numeric("0X.8Pdead").is_err());

        let numeric_kind = |s: &str| match numeric(s).unwrap() {
            Token::Literal(kind, value) => {
                assert_eq!(value, s);
                kind
            }
            token => panic!("expected numeric literal, got {token:?}"),
        };

        for literal in ["1e5", "2E10", "1e+5", "1e1_0", "0x1p-2", "0X1P+2"] {
            assert_eq!(numeric_kind(literal), LitKind::Float, "{literal}");
        }
        for literal in ["1", "42", "0B1010", "0x15e", "0xdead"] {
            assert_eq!(numeric_kind(literal), LitKind::Integer, "{literal}");
        }
        for literal in ["1e5i", "0x1p-2i"] {
            assert_eq!(numeric_kind(literal), LitKind::Imag, "{literal}");
        }

        assert!(numeric("0i").is_ok());
        assert!(numeric("0.i").is_ok());
        assert!(numeric("1E6i").is_ok());
        assert!(numeric(".25i").is_ok());
        assert!(numeric("0123i").is_ok());
        assert!(numeric("0o123i").is_ok());
        assert!(numeric("0xabci").is_ok());
        assert!(numeric("1.e+0i").is_ok());
        assert!(numeric("2.71828i").is_ok());
        assert!(numeric("0x1p-2i").is_ok());
        assert!(numeric(".12345E+5i").is_ok());
        assert!(numeric("6.67428e-11i").is_ok());
        assert!(numeric("7.7388724745781045e+00i").is_ok());
    }

    #[test]
    fn reject_numeric_base_prefix_without_digits() {
        let invalid = ["0b", "0B", "0o", "0O", "0x", "0X"];
        let accepted: Vec<_> = invalid
            .into_iter()
            .filter(|source| Scanner::from(source).scan_lit_number().is_ok())
            .collect();
        assert!(
            accepted.is_empty(),
            "accepted invalid literals: {accepted:?}"
        );
    }

    #[test]
    fn reject_invalid_digits_for_numeric_base() {
        let invalid = [
            "0b2", "0B9", "0b102", "0o8", "0O9", "08", "09", "0_8", "0128", "0xG",
        ];
        let accepted: Vec<_> = invalid
            .into_iter()
            .filter(|source| Scanner::from(source).scan_lit_number().is_ok())
            .collect();
        assert!(
            accepted.is_empty(),
            "accepted invalid literals: {accepted:?}"
        );
    }

    #[test]
    fn scan_hex_literal_followed_by_identifier() {
        assert_eq!(
            scan_tokens("0x1G"),
            vec![
                (0, Token::Literal(LitKind::Integer, "0x1".into())),
                (3, Token::Literal(LitKind::Ident, "G".into())),
                (4, Token::Operator(Operator::SemiColon)),
            ]
        );
    }

    #[test]
    fn reject_exponents_without_digits() {
        let invalid = ["1e", "1E+", "1e-", "0x1p", "0X1P+", "0x1p-"];
        let accepted: Vec<_> = invalid
            .into_iter()
            .filter(|source| Scanner::from(source).scan_lit_number().is_ok())
            .collect();
        assert!(
            accepted.is_empty(),
            "accepted invalid literals: {accepted:?}"
        );
    }

    #[test]
    fn scan_lit_rune() {
        let rune = |s| Scanner::from(s).scan_lit_rune();
        assert!(rune(r#"''"#).is_err());
        assert!(rune(r#"'a'"#).is_ok());
        assert!(rune(r#"'ä'"#).is_ok());
        assert!(rune(r#"'本'"#).is_ok());
        assert!(rune(r#"'\t'"#).is_ok());
        assert!(rune(r#"'\000'"#).is_ok());
        assert!(rune(r#"'\007'"#).is_ok());
        assert!(rune(r#"'\377'"#).is_ok());
        assert!(rune(r#"'\x07'"#).is_ok());
        assert!(rune(r#"'\xff'"#).is_ok());
        assert!(rune(r#"'\u12e4'"#).is_ok());
        assert!(rune(r#"'\U00101234'"#).is_ok());
        assert!(rune(r#"'\''"#).is_ok());

        assert!(rune(r#"'aa'"#).is_err());
        assert!(rune(r#"'\xa'"#).is_err());
        assert!(rune(r#"'\0'"#).is_err());
        assert!(rune(r#"'\k'"#).is_err());
        assert!(rune(r#"'\uDFFF'"#).is_err());
        assert!(rune(r#"'\U00110000'"#).is_err());
        assert!(rune("'\n'").is_err());
        assert!(rune("'a").is_err());
    }

    #[test]
    fn reject_out_of_range_octal_escape_in_rune() {
        assert!(Scanner::from(r#"'\400'"#).scan_lit_rune().is_err());
    }

    #[test]
    fn reject_double_quote_escape_in_rune() {
        assert!(Scanner::from(r#"'\"'"#).scan_lit_rune().is_err());
    }

    #[test]
    fn scan_lit_string() {
        let lit_str = |s| Scanner::from(s).scan_lit_string();

        assert!(lit_str("``").is_ok());
        assert!(lit_str(r#""""#).is_ok());
        assert!(lit_str("`abc`").is_ok());
        assert!(lit_str(r#""\n""#).is_ok());
        assert!(lit_str(r#""\"""#).is_ok());
        assert!(lit_str(r#""日本語""#).is_ok());
        assert!(lit_str("`\\n\n\\n`").is_ok());
        assert!(lit_str(r#""\xff\u00FF""#).is_ok());
        assert!(lit_str(r#""Hello, world!\n""#).is_ok());
        assert!(lit_str(r#""\u65e5本\U00008a9e""#).is_ok());

        assert!(lit_str(r#""\uD800""#).is_err());
        assert!(lit_str(r#""\U00110000""#).is_err());
        assert!(lit_str(r#""\k""#).is_err());
        assert!(lit_str("\"line\nbreak\"").is_err());
        assert!(lit_str("\"abc").is_err());
        assert!(lit_str("`abc").is_err());
    }

    #[test]
    fn reject_out_of_range_octal_escape_in_string() {
        assert!(Scanner::from(r#""\400""#).scan_lit_string().is_err());
    }

    #[test]
    fn reject_single_quote_escape_in_interpreted_string() {
        assert!(Scanner::from(r#""\'""#).scan_lit_string().is_err());
    }

    #[test]
    fn scan_comment() {
        let mut comments = Scanner::from("// 注释\r\n//123\n/*注释*/");

        let next = comments.next_token();
        assert!(match next {
            Ok(Some((_, Token::Comment(comment)))) => comment == "// 注释\r",
            _ => false,
        });

        let next = comments.next_token();
        assert!(match next {
            Ok(Some((_, Token::Comment(comment)))) => comment == "//123",
            _ => false,
        });

        let next = comments.next_token();
        assert!(match next {
            Ok(Some((_, Token::Comment(comment)))) => comment == "/*注释*/",
            _ => false,
        });

        assert!(Scanner::from("/* */").scan_general_comment().is_ok());
        assert!(Scanner::from("/*").scan_general_comment().is_err());
        assert!(Scanner::from("/*/").scan_general_comment().is_err());
    }

    #[test]
    fn scan_line_info() {
        let code = "package main 代码 \n/*😃\n注释*/\n\n//🎃\n\n";
        let mut scanner = Scanner::from(code);
        while let Ok(Some(..)) = scanner.next_token() {}

        let mut lines = scanner.lines.iter();
        assert_eq!(lines.next(), Some(&17));
        assert_eq!(lines.next(), Some(&21));
        assert_eq!(lines.next(), Some(&26));
        assert_eq!(lines.next(), Some(&27));
        assert_eq!(lines.next(), Some(&31));
        assert_eq!(lines.next(), Some(&32));
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn get_line_info() {
        let scanner = Scanner {
            lines: vec![10, 20, 30],
            ..Default::default()
        };

        assert_eq!(scanner.line_info(5), (1, 5));
        assert_eq!(scanner.line_info(20), (2, 0));
        assert_eq!(scanner.line_info(50), (3, 20));
    }
}
