//! Lexer and parser for the YARA subset Sigil evaluates.
//!
//! One pass produces rules whose conditions are already resolved (string and
//! rule names become indices) and type-checked, so everything the evaluator
//! sees is known to be well-formed. Every problem is recorded with its line;
//! a construct outside the subset is an error naming the construct, never a
//! silently skipped rule.
//!
//! Recovery: a problem inside a condition skips the rest of that condition;
//! a syntax error anywhere else skips to the next line that starts a rule, so
//! one bad rule does not hide the problems in the rules after it.

use super::{ArithOp, CmpOp, Expr, Quant};

/// `(line, message)`.
pub(super) type Problem = (usize, String);
type PResult<T> = Result<T, Problem>;

/// Largest bounded hex jump, `[0-N]`: the per-string limit on counted
/// repetition ([`super::strings::MAX_COUNTED_REPETITION`]), checked here too
/// so the error names the jump and its line.
pub(super) const MAX_HEX_JUMP: u32 = super::strings::MAX_COUNTED_REPETITION as u32;

/// Longest rule or tag identifier YARA accepts.
const MAX_IDENTIFIER: usize = 128;

/// Terms in one condition. Parsing and evaluation recurse over the
/// condition, so an absurdly long one (a generated rule, a hostile file) is
/// refused rather than allowed to exhaust a scan thread's stack. Real rules
/// use a few dozen at most; `any of ($a*)` is one term.
const MAX_CONDITION_TERMS: usize = 1000;

/// Nesting of parentheses, `not` and unary minus in one condition.
const MAX_CONDITION_NESTING: usize = 64;

/// Nesting of hex alternatives.
const MAX_HEX_NESTING: usize = 16;

/// Words YARA reserves: none may name a rule, a tag or a meta-less identifier.
const KEYWORDS: &[&str] = &[
    "all",
    "and",
    "any",
    "ascii",
    "at",
    "base64",
    "base64wide",
    "condition",
    "contains",
    "defined",
    "endswith",
    "entrypoint",
    "false",
    "filesize",
    "for",
    "fullword",
    "global",
    "icontains",
    "iendswith",
    "iequals",
    "import",
    "in",
    "include",
    "int16",
    "int16be",
    "int32",
    "int32be",
    "int8",
    "int8be",
    "istartswith",
    "matches",
    "meta",
    "nocase",
    "none",
    "not",
    "of",
    "or",
    "private",
    "rule",
    "startswith",
    "strings",
    "them",
    "true",
    "uint16",
    "uint16be",
    "uint32",
    "uint32be",
    "uint8",
    "uint8be",
    "wide",
    "with",
    "xor",
];

/// Functions that read an integer out of the scanned data.
const INT_READERS: &[&str] = &[
    "int8", "int16", "int32", "int8be", "int16be", "int32be", "uint8", "uint16", "uint32",
    "uint8be", "uint16be", "uint32be",
];

/// Operators over text values.
const STRING_OPERATORS: &[&str] = &[
    "contains",
    "icontains",
    "startswith",
    "istartswith",
    "endswith",
    "iendswith",
    "iequals",
    "matches",
];

/// Modifiers Sigil evaluates.
const SUPPORTED_MODIFIERS: &[&str] = &["nocase", "wide", "ascii", "fullword", "private"];

/// Modifiers YARA has that Sigil refuses.
const REFUSED_MODIFIERS: &[&str] = &["xor", "base64", "base64wide"];

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

/// A rule as written, with its condition resolved.
#[derive(Debug)]
pub(super) struct RuleAst {
    pub name: String,
    pub line: usize,
    pub private: bool,
    pub global: bool,
    pub tags: Vec<String>,
    pub meta: Vec<MetaEntry>,
    pub strings: Vec<StringAst>,
    pub condition: Expr,
    /// The rule's source text, from its first modifier to its closing brace.
    pub source: String,
}

#[derive(Debug)]
pub(super) struct MetaEntry {
    pub key: String,
    pub value: MetaValue,
    pub line: usize,
}

#[derive(Debug)]
pub(super) enum MetaValue {
    Str(String),
    /// A number or a boolean: valid YARA, but no key Sigil reads takes one.
    Other,
}

#[derive(Debug)]
pub(super) struct StringAst {
    /// Name without the `$`; empty for an anonymous string.
    pub name: String,
    pub line: usize,
    pub value: StringValue,
    pub mods: Modifiers,
}

#[derive(Debug)]
pub(super) enum StringValue {
    Text(Vec<u8>),
    Hex(Vec<HexToken>),
    Regex {
        pattern: String,
        nocase: bool,
        dotall: bool,
    },
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Modifiers {
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
    pub fullword: bool,
    pub private: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HexToken {
    /// A byte; `mask` has the bits that must equal `value` (`0xFF` exact,
    /// `0xF0` for `4?`, `0x0F` for `?4`, `0x00` for `??`).
    Byte { value: u8, mask: u8 },
    /// `[n]`, `[n-m]`, `[n-]`, `[-]`.
    Jump { min: u32, max: Option<u32> },
    /// `( ... | ... )`.
    Alt(Vec<Vec<HexToken>>),
}

/// What [`parse`] produced.
#[derive(Debug, Default)]
pub(super) struct Parsed {
    pub rules: Vec<RuleAst>,
    pub errors: Vec<Problem>,
}

/// Parse a whole YARA source file.
pub(super) fn parse(src: &str) -> Parsed {
    // Editors on Windows write a byte-order mark; it is not YARA.
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    let mut p = Parser {
        lx: Lexer {
            src: src.as_bytes(),
            pos: 0,
            line: 1,
        },
        out: Parsed::default(),
        declared: Vec::new(),
    };
    p.run();
    p.out
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    /// `$name`; empty for the anonymous `$`.
    StrId(String),
    /// `$prefix*`.
    StrWild(String),
    /// `#name`.
    StrCount(String),
    /// `@name`.
    StrOffset(String),
    /// `!name`.
    StrLength(String),
    Int(i64),
    Float,
    Text(Vec<u8>),
    Punct(&'static str),
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    line: usize,
}

const TWO_CHAR_PUNCT: &[&str] = &["..", "==", "!=", "<=", ">=", "<<", ">>"];
const ONE_CHAR_PUNCT: &[&str] = &[
    "{", "}", "(", ")", "[", "]", ":", "=", ",", "<", ">", "+", "-", "*", "\\", "%", "&", "|", "^",
    "~", ".", "/",
];

#[derive(Clone)]
struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: usize,
}

impl Lexer<'_> {
    fn at(&self, offset: usize) -> Option<u8> {
        self.src.get(self.pos + offset).copied()
    }

    /// Whitespace and both comment forms.
    fn skip_trivia(&mut self) -> PResult<()> {
        loop {
            match self.at(0) {
                Some(b'\n') => {
                    self.line += 1;
                    self.pos += 1;
                }
                Some(c) if c.is_ascii_whitespace() => self.pos += 1,
                Some(b'/') if self.at(1) == Some(b'/') => {
                    while self.at(0).is_some_and(|c| c != b'\n') {
                        self.pos += 1;
                    }
                }
                Some(b'/') if self.at(1) == Some(b'*') => {
                    let line = self.line;
                    self.pos += 2;
                    loop {
                        match self.at(0) {
                            None => {
                                return Err((
                                    line,
                                    "comment is not closed (`/*` without `*/`)".into(),
                                ))
                            }
                            Some(b'*') if self.at(1) == Some(b'/') => {
                                self.pos += 2;
                                break;
                            }
                            Some(b'\n') => {
                                self.line += 1;
                                self.pos += 1;
                            }
                            Some(_) => self.pos += 1,
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn ident_chars(&mut self) -> String {
        let start = self.pos;
        while self
            .at(0)
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            self.pos += 1;
        }
        String::from_utf8_lossy(&self.src[start..self.pos]).into_owned()
    }

    fn next(&mut self) -> PResult<Token> {
        self.skip_trivia()?;
        let line = self.line;
        let Some(c) = self.at(0) else {
            return Ok(Token {
                tok: Tok::Eof,
                line,
            });
        };
        let tok = match c {
            b'"' => Tok::Text(self.text()?),
            b'$' => {
                self.pos += 1;
                let name = self.ident_chars();
                if self.at(0) == Some(b'*') {
                    self.pos += 1;
                    Tok::StrWild(name)
                } else {
                    Tok::StrId(name)
                }
            }
            b'#' => {
                self.pos += 1;
                Tok::StrCount(self.ident_chars())
            }
            b'@' => {
                self.pos += 1;
                Tok::StrOffset(self.ident_chars())
            }
            b'!' if self.at(1) != Some(b'=') => {
                self.pos += 1;
                Tok::StrLength(self.ident_chars())
            }
            b'0'..=b'9' => self.number()?,
            c if c.is_ascii_alphabetic() || c == b'_' => Tok::Ident(self.ident_chars()),
            _ => {
                let rest = &self.src[self.pos..];
                if let Some(p) = TWO_CHAR_PUNCT
                    .iter()
                    .chain(ONE_CHAR_PUNCT)
                    .find(|p| rest.starts_with(p.as_bytes()))
                {
                    self.pos += p.len();
                    Tok::Punct(p)
                } else {
                    return Err((line, format!("unexpected character {}", show_byte(c))));
                }
            }
        };
        Ok(Token { tok, line })
    }

    fn peek(&self) -> PResult<Token> {
        self.clone().next()
    }

    fn peek2(&self) -> PResult<(Token, Token)> {
        let mut l = self.clone();
        let a = l.next()?;
        let b = l.next()?;
        Ok((a, b))
    }

    fn number(&mut self) -> PResult<Tok> {
        let line = self.line;
        let (radix, start) = match (self.at(0), self.at(1)) {
            (Some(b'0'), Some(b'x' | b'X')) => (16, self.pos + 2),
            (Some(b'0'), Some(b'o')) => (8, self.pos + 2),
            _ => (10, self.pos),
        };
        let mut end = start;
        while self
            .src
            .get(end)
            .is_some_and(|c| (*c as char).is_digit(radix))
        {
            end += 1;
        }
        if end == start {
            return Err((line, "number has no digits".into()));
        }
        if radix == 10
            && self.src.get(end) == Some(&b'.')
            && self.src.get(end + 1).is_some_and(|c| c.is_ascii_digit())
        {
            self.pos = end + 1;
            while self.at(0).is_some_and(|c| c.is_ascii_digit()) {
                self.pos += 1;
            }
            return Ok(Tok::Float);
        }
        let digits = std::str::from_utf8(&self.src[start..end]).unwrap_or("0");
        let mut value = i64::from_str_radix(digits, radix)
            .map_err(|_| (line, format!("number {digits} is too large")))?;
        self.pos = end;
        for (suffix, factor) in [(&b"KB"[..], 1024i64), (&b"MB"[..], 1024 * 1024)] {
            if self.src[self.pos..].starts_with(suffix) {
                value = value
                    .checked_mul(factor)
                    .ok_or_else(|| (line, format!("number {digits} is too large")))?;
                self.pos += 2;
                break;
            }
        }
        if self
            .at(0)
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return Err((
                line,
                "unexpected characters after a number (size suffixes are `KB` and `MB`)".into(),
            ));
        }
        Ok(Tok::Int(value))
    }

    /// A `"..."` literal; the cursor is on the opening quote.
    fn text(&mut self) -> PResult<Vec<u8>> {
        let line = self.line;
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            let Some(c) = self.at(0) else {
                return Err((line, "text string is not closed".into()));
            };
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\n' => {
                    return Err((
                        line,
                        "text string is not closed before the end of the line".into(),
                    ))
                }
                b'\\' => {
                    let escape = self.at(1);
                    self.pos += 2;
                    match escape {
                        Some(b'"') => out.push(b'"'),
                        Some(b'\\') => out.push(b'\\'),
                        Some(b't') => out.push(b'\t'),
                        Some(b'n') => out.push(b'\n'),
                        Some(b'r') => out.push(b'\r'),
                        Some(b'x') => {
                            let digits = self
                                .src
                                .get(self.pos..self.pos + 2)
                                .and_then(|h| std::str::from_utf8(h).ok())
                                .and_then(|h| u8::from_str_radix(h, 16).ok());
                            match digits {
                                Some(b) => {
                                    out.push(b);
                                    self.pos += 2;
                                }
                                None => {
                                    return Err((line, "`\\x` needs two hex digits".into()))
                                }
                            }
                        }
                        Some(other) => {
                            return Err((
                                line,
                                format!(
                                    "unknown escape `\\{}` in text string (supported: \\\" \\\\ \\t \\n \\r \\xHH)",
                                    show_char(other)
                                ),
                            ))
                        }
                        None => return Err((line, "text string is not closed".into())),
                    }
                }
                _ => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    /// A `/.../is` literal; the cursor is on the opening slash.
    fn regex(&mut self) -> PResult<(String, bool, bool)> {
        let line = self.line;
        self.pos += 1;
        let mut pattern = Vec::new();
        loop {
            match self.at(0) {
                None | Some(b'\n') => {
                    return Err((
                        line,
                        "regular expression is not closed (missing `/`)".into(),
                    ))
                }
                Some(b'\\') if self.at(1) == Some(b'/') => {
                    pattern.push(b'/');
                    self.pos += 2;
                }
                Some(b'\\') => match self.at(1) {
                    None | Some(b'\n') => {
                        return Err((
                            line,
                            "regular expression is not closed (missing `/`)".into(),
                        ))
                    }
                    Some(n) => {
                        pattern.extend_from_slice(&[b'\\', n]);
                        self.pos += 2;
                    }
                },
                Some(b'/') => {
                    self.pos += 1;
                    break;
                }
                Some(c) => {
                    pattern.push(c);
                    self.pos += 1;
                }
            }
        }
        let (mut nocase, mut dotall) = (false, false);
        while let Some(c) = self.at(0) {
            match c {
                b'i' => nocase = true,
                b's' => dotall = true,
                c if c.is_ascii_alphanumeric() || c == b'_' => {
                    return Err((
                        line,
                        format!(
                            "regular expression flag `{}` is not supported (only `i` and `s`)",
                            show_char(c)
                        ),
                    ))
                }
                _ => break,
            }
            self.pos += 1;
        }
        if pattern.is_empty() {
            return Err((line, "empty regular expression".into()));
        }
        let pattern = String::from_utf8(pattern)
            .map_err(|_| (line, "regular expression is not valid UTF-8".to_string()))?;
        Ok((pattern, nocase, dotall))
    }

    /// A `{ ... }` hex string; the cursor is on the opening brace.
    fn hex(&mut self) -> PResult<Vec<HexToken>> {
        let line = self.line;
        self.pos += 1;
        let (tokens, _) = self.hex_seq(0, line)?;
        if tokens.is_empty() {
            return Err((line, "empty hex string".into()));
        }
        if matches!(tokens.first(), Some(HexToken::Jump { .. }))
            || matches!(tokens.last(), Some(HexToken::Jump { .. }))
        {
            return Err((line, "a hex string cannot start or end with a jump".into()));
        }
        Ok(tokens)
    }

    fn hex_seq(&mut self, depth: usize, open: usize) -> PResult<(Vec<HexToken>, u8)> {
        let mut out = Vec::new();
        // On a later line than the `{`, a stray character most likely means
        // the closing brace is missing.
        let hint = |line: usize| {
            if line > open {
                format!(" (is the hex string opened on line {open} missing its `}}`?)")
            } else {
                String::new()
            }
        };
        loop {
            self.skip_trivia()?;
            let line = self.line;
            match self.at(0) {
                None => return Err((line, "hex string is not closed (missing `}`)".into())),
                Some(b'}') => {
                    if depth > 0 {
                        return Err((line, "hex alternative `(` is not closed".into()));
                    }
                    self.pos += 1;
                    return Ok((out, b'}'));
                }
                Some(end @ (b'|' | b')')) => {
                    if depth == 0 {
                        return Err((
                            line,
                            format!("`{}` outside a hex alternative `( ... )`", end as char),
                        ));
                    }
                    self.pos += 1;
                    return Ok((out, end));
                }
                Some(b'(') => {
                    if depth >= MAX_HEX_NESTING {
                        return Err((
                            line,
                            format!("hex alternatives are nested deeper than {MAX_HEX_NESTING}"),
                        ));
                    }
                    self.pos += 1;
                    let mut branches = Vec::new();
                    loop {
                        let (branch, end) = self.hex_seq(depth + 1, open)?;
                        if branch.is_empty() {
                            return Err((line, "empty branch in hex alternative".into()));
                        }
                        if branch
                            .iter()
                            .any(|t| matches!(t, HexToken::Jump { max: None, .. }))
                        {
                            return Err((
                                line,
                                "unbounded jumps are not allowed inside a hex alternative".into(),
                            ));
                        }
                        branches.push(branch);
                        if end == b')' {
                            break;
                        }
                    }
                    out.push(HexToken::Alt(branches));
                }
                Some(b'[') => {
                    self.pos += 1;
                    let start = self.pos;
                    while self.at(0).is_some_and(|c| c != b']' && c != b'\n') {
                        self.pos += 1;
                    }
                    if self.at(0) != Some(b']') {
                        return Err((line, "hex jump `[` is not closed".into()));
                    }
                    let body = String::from_utf8_lossy(&self.src[start..self.pos])
                        .split_whitespace()
                        .collect::<String>();
                    self.pos += 1;
                    out.push(parse_jump(&body).map_err(|m| (line, m))?);
                }
                Some(b'~') => {
                    return Err((
                        line,
                        "the `~` (not) operator in hex strings is not supported".into(),
                    ))
                }
                Some(c) if is_hex_nibble(c) => {
                    let Some(c2) = self.at(1).filter(|c| is_hex_nibble(*c)) else {
                        return Err((
                            line,
                            format!(
                                "hex bytes are written as two digits (`4D`, `4?`, `?D`, `??`){}",
                                hint(line)
                            ),
                        ));
                    };
                    self.pos += 2;
                    out.push(hex_byte(c, c2));
                }
                Some(c) => {
                    return Err((
                        line,
                        format!("unexpected {} in hex string{}", show_byte(c), hint(line)),
                    ))
                }
            }
        }
    }

    /// Skip what is left of a condition, up to (not including) the `}` that
    /// closes the rule. Used after a problem, so the next rule still parses.
    fn skip_condition_rest(&mut self) {
        while let Some(c) = self.at(0) {
            match c {
                b'}' => return,
                b'\n' => {
                    self.line += 1;
                    self.pos += 1;
                }
                b'"' => {
                    if self.text().is_err() {
                        self.skip_line();
                    }
                }
                b'/' if matches!(self.at(1), Some(b'/' | b'*')) => {
                    if self.skip_trivia().is_err() {
                        self.pos = self.src.len();
                    }
                }
                b'/' => {
                    if self.regex().is_err() {
                        self.skip_line();
                    }
                }
                _ => self.pos += 1,
            }
        }
    }

    fn skip_line(&mut self) {
        while self.at(0).is_some_and(|c| c != b'\n') {
            self.pos += 1;
        }
    }

    /// Move to the next line that starts a top-level declaration. Returns
    /// false at the end of the file.
    fn resync(&mut self) -> bool {
        loop {
            self.skip_line();
            if self.at(0).is_none() {
                return false;
            }
            self.pos += 1;
            self.line += 1;
            let rest = &self.src[self.pos..];
            let indent = rest
                .iter()
                .take_while(|c| **c == b' ' || **c == b'\t')
                .count();
            let word: String = rest[indent..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
                .map(|c| *c as char)
                .collect();
            if matches!(
                word.as_str(),
                "rule" | "private" | "global" | "import" | "include"
            ) {
                return true;
            }
        }
    }
}

fn is_hex_nibble(c: u8) -> bool {
    c.is_ascii_hexdigit() || c == b'?'
}

fn hex_byte(hi: u8, lo: u8) -> HexToken {
    let nibble = |c: u8| -> (u8, u8) {
        match (c as char).to_digit(16) {
            Some(d) => (d as u8, 0xF),
            None => (0, 0),
        }
    };
    let (hv, hm) = nibble(hi);
    let (lv, lm) = nibble(lo);
    HexToken::Byte {
        value: (hv << 4) | lv,
        mask: (hm << 4) | lm,
    }
}

fn parse_jump(body: &str) -> Result<HexToken, String> {
    let num = |s: &str| -> Result<u32, String> {
        s.parse::<u32>()
            .map_err(|_| format!("hex jump `[{body}]` is not `[n]`, `[n-m]`, `[n-]` or `[-]`"))
    };
    let (min, max) = match body.split_once('-') {
        None => {
            let n = num(body)?;
            (n, Some(n))
        }
        Some(("", "")) => (0, None),
        Some((lo, "")) => (num(lo)?, None),
        Some(("", _)) => return Err(format!("hex jump `[{body}]` needs a lower bound (`[0-n]`)")),
        Some((lo, hi)) => (num(lo)?, Some(num(hi)?)),
    };
    if let Some(max) = max {
        if min > max {
            return Err(format!("hex jump `[{body}]` has its bounds reversed"));
        }
        if max > MAX_HEX_JUMP {
            return Err(format!(
                "hex jump `[{body}]` is wider than Sigil's limit of {MAX_HEX_JUMP} bytes; \
                 split the string, or use an unbounded jump `[{min}-]`"
            ));
        }
        if max == 0 {
            return Err("hex jump `[0]` skips nothing".into());
        }
    } else if min > MAX_HEX_JUMP {
        return Err(format!(
            "hex jump `[{body}]` starts past Sigil's limit of {MAX_HEX_JUMP} bytes"
        ));
    }
    Ok(HexToken::Jump { min, max })
}

fn show_byte(c: u8) -> String {
    if c.is_ascii_graphic() {
        format!("`{}`", c as char)
    } else {
        format!("byte 0x{c:02X}")
    }
}

fn show_char(c: u8) -> String {
    if c.is_ascii_graphic() {
        (c as char).to_string()
    } else {
        format!("\\x{c:02X}")
    }
}

fn describe(t: &Tok) -> String {
    match t {
        Tok::Ident(w) => format!("`{w}`"),
        Tok::StrId(n) => format!("`${n}`"),
        Tok::StrWild(n) => format!("`${n}*`"),
        Tok::StrCount(n) => format!("`#{n}`"),
        Tok::StrOffset(n) => format!("`@{n}`"),
        Tok::StrLength(n) => format!("`!{n}`"),
        Tok::Int(n) => format!("the number {n}"),
        Tok::Float => "a floating-point number".into(),
        Tok::Text(_) => "a text string".into(),
        Tok::Punct(p) => format!("`{p}`"),
        Tok::Eof => "the end of the file".into(),
    }
}

fn is_ident(t: &Token, word: &str) -> bool {
    matches!(&t.tok, Tok::Ident(w) if w == word)
}

// ---------------------------------------------------------------------------
// Parser: declarations
// ---------------------------------------------------------------------------

struct Parser<'a> {
    lx: Lexer<'a>,
    out: Parsed,
    /// Every rule name seen so far, in order, including rules with errors,
    /// so a reference to a broken rule is not reported a second time as an
    /// unknown identifier.
    declared: Vec<String>,
}

impl Parser<'_> {
    fn err(&mut self, line: usize, msg: impl Into<String>) {
        self.out.errors.push((line, msg.into()));
    }

    fn run(&mut self) {
        loop {
            let tok = match self.lx.peek() {
                Ok(t) => t,
                Err(e) => {
                    self.out.errors.push(e);
                    if self.lx.resync() {
                        continue;
                    }
                    break;
                }
            };
            let result = match &tok.tok {
                Tok::Eof => break,
                Tok::Ident(k) if k == "import" || k == "include" => self.refused_directive(k),
                Tok::Ident(k) if k == "rule" || k == "private" || k == "global" => self.rule(),
                other => Err((
                    tok.line,
                    format!("expected `rule`, found {}", describe(other)),
                )),
            };
            if let Err(e) = result {
                self.out.errors.push(e);
                if !self.lx.resync() {
                    break;
                }
            }
        }
    }

    fn refused_directive(&mut self, keyword: &str) -> PResult<()> {
        let t = self.lx.next()?;
        let arg = self.lx.next()?;
        let what = match &arg.tok {
            Tok::Text(b) => format!("{keyword} \"{}\"", String::from_utf8_lossy(b)),
            _ => keyword.to_string(),
        };
        let why = if keyword == "import" {
            "modules (pe, elf, math, hash, dotnet, magic, cuckoo, console, ...) are not \
             supported; Sigil evaluates the string-matching core of YARA"
        } else {
            "`include` is not supported; pass each rule file with --rules, or a directory \
             of them"
        };
        self.err(t.line, format!("`{what}`: {why}"));
        Ok(())
    }

    fn at_section(&self, name: &str) -> PResult<bool> {
        let (a, b) = self.lx.peek2()?;
        Ok(is_ident(&a, name) && b.tok == Tok::Punct(":"))
    }

    fn expect_punct(&mut self, p: &'static str, context: &str) -> PResult<usize> {
        let t = self.lx.next()?;
        if t.tok == Tok::Punct(p) {
            Ok(t.line)
        } else {
            Err((
                t.line,
                format!("expected `{p}` {context}, found {}", describe(&t.tok)),
            ))
        }
    }

    fn rule(&mut self) -> PResult<()> {
        self.lx.skip_trivia()?;
        let start = self.lx.pos;
        let mut private = false;
        let mut global = false;
        let rule_line = self.lx.line;
        loop {
            let t = self.lx.next()?;
            match &t.tok {
                Tok::Ident(k) if k == "private" => {
                    if private {
                        self.err(t.line, "`private` is repeated");
                    }
                    private = true;
                }
                Tok::Ident(k) if k == "global" => {
                    if global {
                        self.err(t.line, "`global` is repeated");
                    }
                    global = true;
                }
                Tok::Ident(k) if k == "rule" => break,
                other => {
                    return Err((
                        t.line,
                        format!("expected `rule`, found {}", describe(other)),
                    ))
                }
            }
        }
        let name_tok = self.lx.next()?;
        let line = name_tok.line;
        let name = match name_tok.tok {
            Tok::Ident(n) if KEYWORDS.contains(&n.as_str()) => {
                return Err((
                    line,
                    format!("`{n}` is a reserved word and cannot name a rule"),
                ))
            }
            Tok::Ident(n) => n,
            other => {
                return Err((
                    line,
                    format!(
                        "expected a rule name after `rule`, found {}",
                        describe(&other)
                    ),
                ))
            }
        };
        if name.len() > MAX_IDENTIFIER {
            self.err(
                line,
                format!("rule name is longer than {MAX_IDENTIFIER} characters"),
            );
        }
        if self.declared.contains(&name) {
            self.err(line, format!("rule `{name}` is defined more than once"));
        }
        let this = self.declared.len();
        self.declared.push(name.clone());

        let mut tags: Vec<String> = Vec::new();
        if self.lx.peek()?.tok == Tok::Punct(":") {
            self.lx.next()?;
            while let Tok::Ident(tag) = self.lx.peek()?.tok {
                let t = self.lx.next()?;
                if KEYWORDS.contains(&tag.as_str()) {
                    return Err((
                        t.line,
                        format!("`{tag}` is a reserved word and cannot be a tag"),
                    ));
                }
                if tags.contains(&tag) {
                    self.err(t.line, format!("tag `{tag}` is repeated"));
                }
                tags.push(tag);
            }
            if tags.is_empty() {
                let t = self.lx.peek()?;
                return Err((
                    t.line,
                    format!("expected a tag after `:`, found {}", describe(&t.tok)),
                ));
            }
        }
        self.expect_punct("{", &format!("to open rule `{name}`"))?;

        let mut meta = Vec::new();
        let mut strings = Vec::new();
        if self.at_section("meta")? {
            self.lx.next()?;
            self.lx.next()?;
            meta = self.meta()?;
        }
        if self.at_section("strings")? {
            self.lx.next()?;
            self.lx.next()?;
            strings = self.strings()?;
        }
        if !self.at_section("condition")? {
            let t = self.lx.peek()?;
            let msg = if is_ident(&t, "meta") {
                "`meta:` must come before `strings:`".to_string()
            } else if t.tok == Tok::Punct("}") {
                format!("rule `{name}` has no `condition:` section")
            } else {
                format!("expected `condition:`, found {}", describe(&t.tok))
            };
            return Err((t.line, msg));
        }
        self.lx.next()?;
        self.lx.next()?;

        let mut cond = CondParser {
            lx: &mut self.lx,
            strings: &strings,
            used: vec![false; strings.len()],
            rules: &self.declared,
            this,
            terms: 0,
            nesting: 0,
        };
        let parsed = cond.condition();
        let used = std::mem::take(&mut cond.used);
        let condition = match parsed {
            Ok(e) => Some(e),
            Err(e) => {
                self.out.errors.push(e);
                self.lx.skip_condition_rest();
                None
            }
        };
        self.expect_punct("}", &format!("to close rule `{name}`"))?;
        let source = String::from_utf8_lossy(&self.lx.src[start..self.lx.pos]).into_owned();

        let Some(condition) = condition else {
            return Ok(());
        };
        for (s, used) in strings.iter().zip(&used) {
            if !used {
                self.err(
                    s.line,
                    format!(
                        "string ${} is not used in the condition of rule `{name}` \
                         (YARA refuses unreferenced strings)",
                        s.name
                    ),
                );
            }
        }
        self.out.rules.push(RuleAst {
            name,
            line: rule_line,
            private,
            global,
            tags,
            meta,
            strings,
            condition,
            source,
        });
        Ok(())
    }

    fn meta(&mut self) -> PResult<Vec<MetaEntry>> {
        let mut out = Vec::new();
        loop {
            if self.at_section("strings")?
                || self.at_section("condition")?
                || self.lx.peek()?.tok == Tok::Punct("}")
            {
                return Ok(out);
            }
            let key_tok = self.lx.next()?;
            let key = match key_tok.tok {
                Tok::Ident(k) => k,
                other => {
                    return Err((
                        key_tok.line,
                        format!(
                            "expected a meta key or `condition:`, found {}",
                            describe(&other)
                        ),
                    ))
                }
            };
            self.expect_punct("=", &format!("after meta key `{key}`"))?;
            let v = self.lx.next()?;
            let value = match v.tok {
                Tok::Text(b) => MetaValue::Str(String::from_utf8_lossy(&b).into_owned()),
                Tok::Int(_) | Tok::Float => MetaValue::Other,
                Tok::Punct("-") => match self.lx.next()?.tok {
                    Tok::Int(_) | Tok::Float => MetaValue::Other,
                    other => {
                        return Err((
                            v.line,
                            format!("expected a number after `-`, found {}", describe(&other)),
                        ))
                    }
                },
                Tok::Ident(t) if t == "true" || t == "false" => MetaValue::Other,
                other => {
                    return Err((
                        v.line,
                        format!(
                            "meta `{key}` must be a text string, a number, true or false; found {}",
                            describe(&other)
                        ),
                    ))
                }
            };
            out.push(MetaEntry {
                key,
                value,
                line: key_tok.line,
            });
        }
    }

    fn strings(&mut self) -> PResult<Vec<StringAst>> {
        let mut out: Vec<StringAst> = Vec::new();
        loop {
            if self.at_section("condition")? || self.lx.peek()?.tok == Tok::Punct("}") {
                return Ok(out);
            }
            let t = self.lx.next()?;
            let name = match t.tok {
                Tok::StrId(n) => n,
                Tok::Ident(k) if k == "meta" => {
                    return Err((t.line, "`meta:` must come before `strings:`".into()))
                }
                other => {
                    return Err((
                        t.line,
                        format!(
                            "expected a string definition such as `$a = \"...\"`, found {}",
                            describe(&other)
                        ),
                    ))
                }
            };
            if !name.is_empty() && out.iter().any(|s| s.name == name) {
                self.err(t.line, format!("string ${name} is defined more than once"));
            }
            self.expect_punct("=", &format!("after ${name}"))?;
            self.lx.skip_trivia()?;
            let value = match self.lx.at(0) {
                Some(b'"') => StringValue::Text(self.lx.text()?),
                Some(b'{') => StringValue::Hex(self.lx.hex()?),
                Some(b'/') => {
                    let (pattern, nocase, dotall) = self.lx.regex()?;
                    StringValue::Regex {
                        pattern,
                        nocase,
                        dotall,
                    }
                }
                _ => {
                    return Err((
                        self.lx.line,
                        format!(
                            "string ${name}: expected a text string \"...\", a hex string \
                             {{ ... }} or a regular expression /.../"
                        ),
                    ))
                }
            };
            let mods = self.modifiers(&name)?;
            let problem = match &value {
                StringValue::Text(b) if b.is_empty() => Some("is an empty text string"),
                StringValue::Hex(_) if mods.nocase || mods.wide || mods.ascii || mods.fullword => {
                    Some("is a hex string, which only takes the `private` modifier")
                }
                StringValue::Regex { .. } if mods.wide => Some(
                    "is a regular expression with `wide`, which is not supported \
                     (write the UTF-16 bytes into the expression, or use a text string)",
                ),
                _ => None,
            };
            if let Some(p) = problem {
                self.err(t.line, format!("string ${name} {p}"));
            }
            out.push(StringAst {
                name,
                line: t.line,
                value,
                mods,
            });
        }
    }

    fn modifiers(&mut self, name: &str) -> PResult<Modifiers> {
        let mut mods = Modifiers::default();
        loop {
            let (a, b) = self.lx.peek2()?;
            let Tok::Ident(m) = &a.tok else {
                return Ok(mods);
            };
            if b.tok == Tok::Punct(":") || matches!(m.as_str(), "condition" | "meta" | "strings") {
                return Ok(mods);
            }
            let m = m.clone();
            self.lx.next()?;
            let flag = match m.as_str() {
                "nocase" => Some(&mut mods.nocase),
                "wide" => Some(&mut mods.wide),
                "ascii" => Some(&mut mods.ascii),
                "fullword" => Some(&mut mods.fullword),
                "private" => Some(&mut mods.private),
                _ => None,
            };
            match flag {
                Some(f) => {
                    if *f {
                        self.err(
                            a.line,
                            format!("string ${name}: modifier `{m}` is repeated"),
                        );
                    }
                    *f = true;
                }
                None if REFUSED_MODIFIERS.contains(&m.as_str()) => {
                    if self.lx.peek()?.tok == Tok::Punct("(") {
                        self.skip_parens()?;
                    }
                    self.err(
                        a.line,
                        format!(
                            "string ${name}: the `{m}` modifier is not supported (supported: {})",
                            SUPPORTED_MODIFIERS.join(", ")
                        ),
                    );
                }
                None => {
                    let hint = super::super::custom::closest(&m, SUPPORTED_MODIFIERS)
                        .map(|s| format!(" (did you mean `{s}`?)"))
                        .unwrap_or_default();
                    self.err(
                        a.line,
                        format!("string ${name}: unknown modifier `{m}`{hint}"),
                    );
                }
            }
        }
    }

    fn skip_parens(&mut self) -> PResult<()> {
        let mut depth = 0usize;
        loop {
            let t = self.lx.next()?;
            match t.tok {
                Tok::Punct("(") => depth += 1,
                Tok::Punct(")") => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                Tok::Eof => return Err((t.line, "`(` is not closed".into())),
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Parser: conditions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Bool,
    Int,
}

type Typed = (Expr, Ty);

struct CondParser<'p, 'a> {
    lx: &'p mut Lexer<'a>,
    strings: &'p [StringAst],
    used: Vec<bool>,
    rules: &'p [String],
    this: usize,
    /// Terms built so far (see [`MAX_CONDITION_TERMS`]).
    terms: usize,
    /// Current nesting (see [`MAX_CONDITION_NESTING`]).
    nesting: usize,
}

fn as_bool((e, ty): Typed) -> Expr {
    match ty {
        Ty::Bool => e,
        // YARA reads a number in a boolean position as "is non-zero".
        Ty::Int => Expr::Cmp(CmpOp::Ne, Box::new(e), Box::new(Expr::Int(0))),
    }
}

impl CondParser<'_, '_> {
    fn next(&mut self) -> PResult<Token> {
        self.lx.next()
    }

    /// Count one more term, refusing a condition past the limit.
    fn term(&mut self, line: usize) -> PResult<()> {
        self.terms += 1;
        if self.terms > MAX_CONDITION_TERMS {
            return Err((
                line,
                format!(
                    "the condition has more than {MAX_CONDITION_TERMS} terms; use `any of`/`N of` \
                     over a set of strings"
                ),
            ));
        }
        Ok(())
    }

    /// Enter one level of nesting, refusing a condition past the limit.
    fn nest(&mut self, line: usize) -> PResult<()> {
        self.nesting += 1;
        if self.nesting > MAX_CONDITION_NESTING {
            return Err((
                line,
                format!("the condition is nested deeper than {MAX_CONDITION_NESTING} levels"),
            ));
        }
        Ok(())
    }

    fn peek_ident(&self, word: &str) -> PResult<bool> {
        Ok(is_ident(&self.lx.peek()?, word))
    }

    fn int(&self, (e, ty): Typed, line: usize, what: &str) -> PResult<Expr> {
        match ty {
            Ty::Int => Ok(e),
            Ty::Bool => Err((
                line,
                format!("{what} needs a number, but this is a true/false expression"),
            )),
        }
    }

    fn condition(&mut self) -> PResult<Expr> {
        let e = self.or()?;
        let t = self.lx.peek()?;
        if t.tok != Tok::Punct("}") {
            return Err(self.unexpected(&t));
        }
        Ok(as_bool(e))
    }

    fn unexpected(&self, t: &Token) -> Problem {
        match &t.tok {
            Tok::Ident(w) if STRING_OPERATORS.contains(&w.as_str()) => (
                t.line,
                format!("the string operator `{w}` is not supported"),
            ),
            Tok::Punct(p @ ("&" | "|" | "^" | "<<" | ">>" | "~")) => (
                t.line,
                format!("the bitwise operator `{p}` is not supported"),
            ),
            Tok::Punct("[") => (
                t.line,
                "indexing (`@a[i]`, `!a[i]`, arrays) is not supported".into(),
            ),
            other => (
                t.line,
                format!("unexpected {} in condition", describe(other)),
            ),
        }
    }

    fn or(&mut self) -> PResult<Typed> {
        let mut lhs = self.and()?;
        while self.peek_ident("or")? {
            let t = self.next()?;
            self.term(t.line)?;
            let rhs = self.and()?;
            lhs = (
                Expr::Or(Box::new(as_bool(lhs)), Box::new(as_bool(rhs))),
                Ty::Bool,
            );
        }
        Ok(lhs)
    }

    fn and(&mut self) -> PResult<Typed> {
        let mut lhs = self.not()?;
        while self.peek_ident("and")? {
            let t = self.next()?;
            self.term(t.line)?;
            let rhs = self.not()?;
            lhs = (
                Expr::And(Box::new(as_bool(lhs)), Box::new(as_bool(rhs))),
                Ty::Bool,
            );
        }
        Ok(lhs)
    }

    fn not(&mut self) -> PResult<Typed> {
        if self.peek_ident("not")? {
            let t = self.next()?;
            self.term(t.line)?;
            self.nest(t.line)?;
            let e = self.not()?;
            self.nesting -= 1;
            return Ok((Expr::Not(Box::new(as_bool(e))), Ty::Bool));
        }
        self.comparison()
    }

    fn cmp_op(t: &Token) -> Option<CmpOp> {
        Some(match t.tok {
            Tok::Punct("==") => CmpOp::Eq,
            Tok::Punct("!=") => CmpOp::Ne,
            Tok::Punct("<") => CmpOp::Lt,
            Tok::Punct("<=") => CmpOp::Le,
            Tok::Punct(">") => CmpOp::Gt,
            Tok::Punct(">=") => CmpOp::Ge,
            _ => return None,
        })
    }

    fn comparison(&mut self) -> PResult<Typed> {
        let lhs = self.additive()?;
        let t = self.lx.peek()?;
        let Some(op) = Self::cmp_op(&t) else {
            return match &t.tok {
                Tok::Ident(w) if STRING_OPERATORS.contains(&w.as_str()) => Err(self.unexpected(&t)),
                Tok::Punct("&" | "|" | "^" | "<<" | ">>") => Err(self.unexpected(&t)),
                _ => Ok(lhs),
            };
        };
        self.next()?;
        self.term(t.line)?;
        let rhs = self.additive()?;
        let symbol = describe(&t.tok);
        let lhs = self.int(lhs, t.line, &format!("the left side of {symbol}"))?;
        let rhs = self.int(rhs, t.line, &format!("the right side of {symbol}"))?;
        let after = self.lx.peek()?;
        if Self::cmp_op(&after).is_some() {
            return Err((
                after.line,
                "comparisons cannot be chained (`a < b < c`); join them with `and`".into(),
            ));
        }
        Ok((Expr::Cmp(op, Box::new(lhs), Box::new(rhs)), Ty::Bool))
    }

    fn additive(&mut self) -> PResult<Typed> {
        let mut lhs = self.multiplicative()?;
        loop {
            let t = self.lx.peek()?;
            let op = match t.tok {
                Tok::Punct("+") => ArithOp::Add,
                Tok::Punct("-") => ArithOp::Sub,
                _ => return Ok(lhs),
            };
            self.next()?;
            self.term(t.line)?;
            let rhs = self.multiplicative()?;
            let symbol = describe(&t.tok);
            let l = self.int(lhs, t.line, &symbol)?;
            let r = self.int(rhs, t.line, &symbol)?;
            lhs = (Expr::Arith(op, Box::new(l), Box::new(r)), Ty::Int);
        }
    }

    fn multiplicative(&mut self) -> PResult<Typed> {
        let mut lhs = self.unary()?;
        loop {
            let t = self.lx.peek()?;
            let op = match t.tok {
                Tok::Punct("*") => ArithOp::Mul,
                Tok::Punct("\\") => ArithOp::Div,
                Tok::Punct("%") => ArithOp::Mod,
                _ => return Ok(lhs),
            };
            self.next()?;
            self.term(t.line)?;
            let rhs = self.unary()?;
            let symbol = describe(&t.tok);
            let l = self.int(lhs, t.line, &symbol)?;
            let r = self.int(rhs, t.line, &symbol)?;
            lhs = (Expr::Arith(op, Box::new(l), Box::new(r)), Ty::Int);
        }
    }

    fn unary(&mut self) -> PResult<Typed> {
        let t = self.lx.peek()?;
        match t.tok {
            Tok::Punct("-") => {
                self.next()?;
                self.term(t.line)?;
                self.nest(t.line)?;
                let e = self.unary()?;
                self.nesting -= 1;
                let e = self.int(e, t.line, "`-`")?;
                Ok((Expr::Neg(Box::new(e)), Ty::Int))
            }
            Tok::Punct("~") => Err(self.unexpected(&t)),
            _ => self.primary(),
        }
    }

    fn primary(&mut self) -> PResult<Typed> {
        let t = self.next()?;
        let line = t.line;
        self.term(line)?;
        match t.tok {
            Tok::Ident(w) => self.word(w, line),
            Tok::Int(n) => self.after_number((Expr::Int(n), Ty::Int), line),
            Tok::Float => Err((line, "floating-point numbers are not supported".into())),
            Tok::Text(_) => Err((
                line,
                "text values are not supported in conditions (string comparisons and \
                 external string variables are refused)"
                    .into(),
            )),
            Tok::Punct("(") => {
                self.nest(line)?;
                let e = self.or()?;
                self.nesting -= 1;
                let close = self.next()?;
                if close.tok != Tok::Punct(")") {
                    return Err(match close.tok {
                        Tok::Punct(",") | Tok::Punct("..") => (
                            close.line,
                            "unexpected `,`/`..`: ranges are only valid after `in` \
                             (`$a in (0..100)`)"
                                .into(),
                        ),
                        _ => {
                            let mut e = self.unexpected(&close);
                            e.1 = format!("expected `)`: {}", e.1);
                            e
                        }
                    });
                }
                self.after_number(e, line)
            }
            Tok::StrId(n) => self.string_ref(n, line),
            Tok::StrWild(n) => Err((
                line,
                format!("`${n}*` selects a set of strings and is only valid inside `of (...)`"),
            )),
            Tok::StrCount(n) => {
                let i = self.resolve(&n, line)?;
                if self.peek_ident("in")? {
                    return Err((line, format!("`#{n} in (range)` is not supported")));
                }
                Ok((Expr::Count(i), Ty::Int))
            }
            Tok::StrOffset(n) => Err((
                line,
                format!(
                    "`@{n}` (match offsets) is not supported; use `${n} at N` or `${n} in (N..M)`"
                ),
            )),
            Tok::StrLength(n) => Err((line, format!("`!{n}` (match lengths) is not supported"))),
            Tok::Eof => Err((line, "the condition ends unexpectedly".into())),
            other => Err(self.unexpected(&Token { tok: other, line })),
        }
    }

    fn word(&mut self, w: String, line: usize) -> PResult<Typed> {
        match w.as_str() {
            "true" => Ok((Expr::Bool(true), Ty::Bool)),
            "false" => Ok((Expr::Bool(false), Ty::Bool)),
            "filesize" => Ok((Expr::Filesize, Ty::Int)),
            "any" | "all" | "none" => {
                let of = self.next()?;
                if !is_ident(&of, "of") {
                    return Err((of.line, format!("expected `of` after `{w}`")));
                }
                let set = self.set(line)?;
                let quant = match w.as_str() {
                    "any" => Quant::Any,
                    "all" => Quant::All,
                    _ => Quant::None,
                };
                Ok((Expr::Of(quant, set), Ty::Bool))
            }
            "them" => Err((
                line,
                "`them` can only follow `of`, as in `any of them`".into(),
            )),
            "for" => Err((
                line,
                "`for` loops (`for any of ...`, `for all i in ...`) are not supported".into(),
            )),
            "entrypoint" => Err((line, "`entrypoint` is not supported".into())),
            "defined" => Err((line, "`defined` is not supported".into())),
            "with" => Err((line, "`with` declarations are not supported".into())),
            _ if INT_READERS.contains(&w.as_str()) => Err((
                line,
                format!("`{w}()` (reading integers from the file) is not supported"),
            )),
            _ if STRING_OPERATORS.contains(&w.as_str()) => {
                Err((line, format!("the string operator `{w}` is not supported")))
            }
            _ if KEYWORDS.contains(&w.as_str()) => {
                Err((line, format!("unexpected `{w}` in condition")))
            }
            _ => {
                let next = self.lx.peek()?;
                match next.tok {
                    Tok::Punct(".") => {
                        return Err((
                            line,
                            format!("`{w}.`: modules are not supported (there is no `import`)"),
                        ))
                    }
                    Tok::Punct("(") => {
                        return Err((line, format!("function call `{w}(...)` is not supported")))
                    }
                    Tok::Punct("[") => {
                        return Err((line, format!("`{w}[...]`: indexing is not supported")))
                    }
                    _ => {}
                }
                match self.rules.iter().position(|r| *r == w) {
                    Some(i) if i == self.this => {
                        Err((line, format!("rule `{w}` cannot refer to itself")))
                    }
                    Some(i) if i < self.this => Ok((Expr::RuleRef(i), Ty::Bool)),
                    _ => Err((
                        line,
                        format!(
                            "unknown identifier `{w}`: external variables and modules are not \
                             supported, and a rule reference must name a rule defined earlier \
                             in the same file"
                        ),
                    )),
                }
            }
        }
    }

    /// A number may be the count of an `of`: `2 of them`, `50% of ($a*)`.
    fn after_number(&mut self, e: Typed, line: usize) -> PResult<Typed> {
        if e.1 != Ty::Int {
            return Ok(e);
        }
        let (a, b) = self.lx.peek2()?;
        let percent = if is_ident(&a, "of") {
            false
        } else if a.tok == Tok::Punct("%") && is_ident(&b, "of") {
            self.next()?;
            true
        } else {
            return Ok(e);
        };
        self.next()?;
        let set = self.set(line)?;
        let n = e.0;
        if let Expr::Int(k) = n {
            let limit = if percent { 100 } else { set.len() as i64 };
            if k <= 0 {
                return Err((
                    line,
                    format!(
                        "`{k}{} of` is ambiguous; write `none of`",
                        if percent { "%" } else { "" }
                    ),
                ));
            }
            if k > limit {
                return Err((
                    line,
                    if percent {
                        format!("`{k}% of` is more than 100%")
                    } else {
                        format!("`{k} of` asks for more strings than the set has ({limit})")
                    },
                ));
            }
        }
        let quant = if percent {
            Quant::Percent(Box::new(n))
        } else {
            Quant::AtLeast(Box::new(n))
        };
        Ok((Expr::Of(quant, set), Ty::Bool))
    }

    fn string_ref(&mut self, n: String, line: usize) -> PResult<Typed> {
        if n.is_empty() {
            return Err((
                line,
                "an anonymous `$` can only be used inside a `for..of` loop, which is not \
                 supported; use `any of them`"
                    .into(),
            ));
        }
        let i = self.resolve(&n, line)?;
        if self.peek_ident("at")? {
            self.next()?;
            let at = self.additive()?;
            let at = self.int(at, line, &format!("`${n} at`"))?;
            return Ok((Expr::StrAt(i, Box::new(at)), Ty::Bool));
        }
        if self.peek_ident("in")? {
            self.next()?;
            let open = self.next()?;
            if open.tok != Tok::Punct("(") {
                return Err((open.line, format!("expected `(` after `${n} in`")));
            }
            let lo = self.additive()?;
            let lo = self.int(lo, line, "a range bound")?;
            let dots = self.next()?;
            if dots.tok != Tok::Punct("..") {
                return Err((dots.line, "expected `..` in a range `(lo..hi)`".into()));
            }
            let hi = self.additive()?;
            let hi = self.int(hi, line, "a range bound")?;
            let close = self.next()?;
            if close.tok != Tok::Punct(")") {
                return Err((close.line, "expected `)` to close the range".into()));
            }
            return Ok((Expr::StrIn(i, Box::new(lo), Box::new(hi)), Ty::Bool));
        }
        Ok((Expr::Str(i), Ty::Bool))
    }

    fn resolve(&mut self, n: &str, line: usize) -> PResult<usize> {
        if n.is_empty() {
            return Err((
                line,
                "an anonymous string cannot be referred to by name; use `them` or `($*)`".into(),
            ));
        }
        match self.strings.iter().position(|s| s.name == n) {
            Some(i) => {
                self.used[i] = true;
                Ok(i)
            }
            None => Err((line, format!("string ${n} is not defined in this rule"))),
        }
    }

    fn set(&mut self, line: usize) -> PResult<Vec<usize>> {
        let t = self.next()?;
        let mut out: Vec<usize> = Vec::new();
        match t.tok {
            Tok::Ident(w) if w == "them" => {
                if self.strings.is_empty() {
                    return Err((t.line, "`them` in a rule that has no strings".into()));
                }
                out.extend(0..self.strings.len());
                self.used.iter_mut().for_each(|u| *u = true);
            }
            Tok::Punct("(") => loop {
                let item = self.next()?;
                match item.tok {
                    Tok::StrId(n) => {
                        let i = self.resolve(&n, item.line)?;
                        out.push(i);
                    }
                    Tok::StrWild(prefix) => {
                        let before = out.len();
                        for (i, s) in self.strings.iter().enumerate() {
                            if s.name.starts_with(&prefix) {
                                out.push(i);
                                self.used[i] = true;
                            }
                        }
                        if out.len() == before {
                            return Err((
                                item.line,
                                format!("`${prefix}*` matches no string in this rule"),
                            ));
                        }
                    }
                    Tok::Ident(r) => {
                        return Err((
                            item.line,
                            format!("sets of rules (`of ({r}, ...)`) are not supported"),
                        ))
                    }
                    other => {
                        return Err((
                            item.line,
                            format!(
                                "expected `$name` or `$prefix*` in a set, found {}",
                                describe(&other)
                            ),
                        ))
                    }
                }
                let sep = self.next()?;
                match sep.tok {
                    Tok::Punct(",") => continue,
                    Tok::Punct(")") => break,
                    other => {
                        return Err((
                            sep.line,
                            format!("expected `,` or `)` in a set, found {}", describe(&other)),
                        ))
                    }
                }
            },
            other => {
                return Err((
                    t.line,
                    format!(
                        "expected `them` or a set such as `($a, $b*)` after `of`, found {}",
                        describe(&other)
                    ),
                ))
            }
        }
        let mut seen = std::collections::HashSet::new();
        out.retain(|i| seen.insert(*i));
        if self.peek_ident("at")? || self.peek_ident("in")? {
            return Err((
                line,
                "`of ... at N` and `of ... in (range)` are not supported".into(),
            ));
        }
        Ok(out)
    }
}
