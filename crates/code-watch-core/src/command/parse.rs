//! The command text as a tree: pipelines of stages, each a simple command or a group, with the
//! substitutions, redirections and here-texts that belong to it. Built from `brush-parser`'s
//! AST; text it cannot parse is an error, never an empty tree.

use super::readers;
use brush_parser::ast::{
    self, AndOr, Command, CompoundCommand, CompoundList, ExtendedTestExpr, IoRedirect,
};
use brush_parser::word::{self, Parameter, ParameterExpr, WordPiece, WordPieceWithSource};
use brush_parser::{Parser, ParserOptions};
use std::io::Cursor;

/// The input could not be parsed as shell text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFailure;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub stages: Vec<Stage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    Simple(Simple),
    /// A subshell, brace group or compound command: its bodies, flattened.
    Group(Group),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Simple {
    /// The command name and its arguments, without assignments and redirections.
    pub words: Vec<Word>,
    pub attached: Attached,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub pipelines: Vec<Pipeline>,
    pub attached: Attached,
    /// The name this group is defined under when it is a function body.
    pub function: Option<String>,
}

/// What hangs off a command besides its words.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attached {
    /// Targets of the redirections that write to a file.
    pub written_files: Vec<String>,
    /// Here-strings and here-documents: text a reader runs as a script.
    pub here_texts: Vec<HereText>,
    /// Command substitutions in words that are not command words (assignments, redirect targets, `for` lists).
    pub subs: Vec<Sub>,
    /// `<(...)` and `>(...)`, as arguments or redirect targets.
    pub procs: Vec<Proc>,
    /// Variable assignments in the order written, including `for NAME in`.
    pub assigns: Vec<Assign>,
    /// Descriptors this command reads from (`<&3`).
    pub dup_inputs: Vec<i32>,
}

/// An assignment to a scalar variable. `value` is `None` when the name is set to something the
/// text does not show (`+=`, arrays, an array element, a `for` variable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assign {
    pub name: String,
    pub value: Option<Word>,
}

/// A here-string or here-document body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HereText {
    pub body: Word,
    /// Substitutions in the body are expanded into the text the reader gets: a here-document
    /// with an unquoted delimiter. A here-string is judged by `body.whole_substitution`.
    pub expands: bool,
}

/// A shell word with its quoting removed. Expansions stay as their source text, so a program
/// name written `$c` or `$(echo curl)` still shows its `$`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    pub text: String,
    pub subs: Vec<Sub>,
    /// The word is nothing but command substitutions: `"$(...)"`, `` `...` ``.
    pub whole_substitution: bool,
}

/// The text inside `$(...)` or backticks, parsed again one level deeper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sub {
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcKind {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub kind: ProcKind,
    pub body: Vec<Pipeline>,
    /// The descriptor it is attached to: `exec 3< <(...)`.
    pub fd: Option<i32>,
}

/// Longest text parsed in one piece. The parser slows down with size when text nests deeply, so a
/// bigger text is parsed line by line and only the part that cannot be is read as plain tokens.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

/// Deepest nesting handed to the parser. Its time grows exponentially with nested `case` and
/// quickly with nested parentheses and `${`, so text nested deeper is refused before parsing;
/// real commands nest a few levels.
const MAX_PAREN_DEPTH: usize = 64;
const MAX_CASE_DEPTH: usize = 8;
const MAX_EXPANSION_DEPTH: usize = 32;

/// Whether the text nests parentheses, `case` or `${` deeper than the parser can take in bounded
/// time. One linear pass; quotes are not honoured, so it errs towards refusing.
pub fn too_complex(text: &str) -> bool {
    let bytes = text.as_bytes();
    let (mut parens, mut cases, mut expansions) = (0usize, 0usize, 0usize);
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => {
                parens += 1;
                if parens > MAX_PAREN_DEPTH {
                    return true;
                }
            }
            b')' => parens = parens.saturating_sub(1),
            b'$' if bytes.get(i + 1) == Some(&b'{') => {
                expansions += 1;
                if expansions > MAX_EXPANSION_DEPTH {
                    return true;
                }
            }
            b'}' => expansions = expansions.saturating_sub(1),
            b'c' | b'e' if i == 0 || !is_word(bytes[i - 1]) => {
                let rest = &bytes[i..];
                let word_ends = |len: usize| rest.get(len).is_none_or(|b| !is_word(*b));
                if rest.starts_with(b"case") && word_ends(4) {
                    cases += 1;
                    if cases > MAX_CASE_DEPTH {
                        return true;
                    }
                } else if rest.starts_with(b"esac") && word_ends(4) {
                    cases = cases.saturating_sub(1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Parses `text` into its pipelines, every list, group and compound command included.
pub fn parse(text: &str) -> Result<Vec<Pipeline>, ParseFailure> {
    if text.len() > MAX_TEXT_BYTES || too_complex(text) {
        return Err(ParseFailure);
    }
    let options = ParserOptions {
        enable_extended_globbing: true,
        ..ParserOptions::default()
    };
    let program = Parser::new(Cursor::new(text), &options)
        .parse_program()
        .map_err(|_| ParseFailure)?;
    let mut out = Vec::new();
    for list in &program.complete_commands {
        lists(list, &mut out)?;
    }
    Ok(out)
}

type Parsed<T = ()> = Result<T, ParseFailure>;

fn lists(list: &CompoundList, out: &mut Vec<Pipeline>) -> Parsed {
    for item in &list.0 {
        pipeline(&item.0.first, out)?;
        for next in &item.0.additional {
            match next {
                AndOr::And(p) | AndOr::Or(p) => pipeline(p, out)?,
            }
        }
    }
    Ok(())
}

fn pipeline(p: &ast::Pipeline, out: &mut Vec<Pipeline>) -> Parsed {
    let stages = p.seq.iter().map(stage).collect::<Parsed<_>>()?;
    out.push(Pipeline { stages });
    Ok(())
}

fn stage(command: &Command) -> Parsed<Stage> {
    match command {
        Command::Simple(simple) => simple_command(simple).map(Stage::Simple),
        Command::Compound(compound, redirects) => {
            let mut group = compound_command(compound)?;
            if let Some(list) = redirects {
                for r in &list.0 {
                    redirect(r, &mut group.attached)?;
                }
            }
            Ok(Stage::Group(group))
        }
        Command::Function(def) => {
            let mut group = compound_command(&def.body.0)?;
            group.function = Some(convert_word(&def.fname)?.text);
            Ok(Stage::Group(group))
        }
        Command::ExtendedTest(test, redirects) => {
            let mut attached = Attached::default();
            test_words(&test.expr, &mut attached)?;
            for r in redirects.iter().flat_map(|l| &l.0) {
                redirect(r, &mut attached)?;
            }
            Ok(Stage::Group(Group {
                pipelines: Vec::new(),
                attached,
                function: None,
            }))
        }
    }
}

fn compound_command(compound: &CompoundCommand) -> Parsed<Group> {
    let mut pipelines = Vec::new();
    let mut attached = Attached::default();
    match compound {
        CompoundCommand::BraceGroup(b) => lists(&b.list, &mut pipelines)?,
        CompoundCommand::Subshell(s) => lists(&s.list, &mut pipelines)?,
        CompoundCommand::IfClause(i) => {
            lists(&i.condition, &mut pipelines)?;
            lists(&i.then, &mut pipelines)?;
            for e in i.elses.iter().flatten() {
                if let Some(condition) = &e.condition {
                    lists(condition, &mut pipelines)?;
                }
                lists(&e.body, &mut pipelines)?;
            }
        }
        CompoundCommand::WhileClause(w) | CompoundCommand::UntilClause(w) => {
            lists(&w.0, &mut pipelines)?;
            lists(&w.1.list, &mut pipelines)?;
        }
        CompoundCommand::ForClause(f) => {
            attached.assigns.push(Assign {
                name: f.variable_name.clone(),
                value: None,
            });
            for w in f.values.iter().flatten() {
                attached.subs.extend(convert_word(w)?.subs);
            }
            lists(&f.body.list, &mut pipelines)?;
        }
        CompoundCommand::ArithmeticForClause(f) => {
            for expr in [&f.initializer, &f.condition, &f.updater]
                .into_iter()
                .flatten()
            {
                attached.subs.extend(convert_text(&expr.value)?.subs);
            }
            lists(&f.body.list, &mut pipelines)?;
        }
        CompoundCommand::CaseClause(c) => {
            attached.subs.extend(convert_word(&c.value)?.subs);
            for item in &c.cases {
                for pattern in &item.patterns {
                    attached.subs.extend(convert_word(pattern)?.subs);
                }
                if let Some(list) = &item.cmd {
                    lists(list, &mut pipelines)?;
                }
            }
        }
        CompoundCommand::Coprocess(c) => pipelines.push(Pipeline {
            stages: vec![stage(&c.body)?],
        }),
        CompoundCommand::Arithmetic(a) => {
            pipelines.extend(parse(&a.expr.value)?);
        }
    }
    Ok(Group {
        pipelines,
        attached,
        function: None,
    })
}

fn test_words(expr: &ExtendedTestExpr, attached: &mut Attached) -> Parsed {
    match expr {
        ExtendedTestExpr::And(a, b) | ExtendedTestExpr::Or(a, b) => {
            test_words(a, attached)?;
            test_words(b, attached)?;
        }
        ExtendedTestExpr::Not(e) | ExtendedTestExpr::Parenthesized(e) => test_words(e, attached)?,
        ExtendedTestExpr::UnaryTest(_, w) => attached.subs.extend(convert_word(w)?.subs),
        ExtendedTestExpr::BinaryTest(_, a, b) => {
            attached.subs.extend(convert_word(a)?.subs);
            attached.subs.extend(convert_word(b)?.subs);
        }
    }
    Ok(())
}

fn simple_command(simple: &ast::SimpleCommand) -> Parsed<Simple> {
    let mut words = Vec::new();
    let mut attached = Attached::default();
    for item in simple.prefix.iter().flat_map(|p| &p.0) {
        item_into(item, &mut words, &mut attached)?;
    }
    if let Some(name) = &simple.word_or_name {
        words.push(convert_word(name)?);
    }
    for item in simple.suffix.iter().flat_map(|s| &s.0) {
        item_into(item, &mut words, &mut attached)?;
    }
    split_env_string(&mut words);
    Ok(Simple { words, attached })
}

/// `env -S 'sh -x'` runs the words of its operand: they become words of the command.
fn split_env_string(words: &mut Vec<Word>) {
    let Some(env) = words.iter().position(|w| basename(&w.text) == "env") else {
        return;
    };
    let Some(flag) = words[env + 1..]
        .iter()
        .position(|w| matches!(w.text.as_str(), "-S" | "--split-string"))
        .map(|i| env + 1 + i)
    else {
        return;
    };
    if flag + 1 >= words.len() {
        return;
    }
    let operand = words[flag + 1].text.clone();
    let split = operand.split_whitespace().map(|t| Word {
        text: t.to_string(),
        subs: Vec::new(),
        whole_substitution: false,
    });
    words.splice(flag..=flag + 1, split);
}

fn item_into(
    item: &ast::CommandPrefixOrSuffixItem,
    words: &mut Vec<Word>,
    attached: &mut Attached,
) -> Parsed {
    match item {
        ast::CommandPrefixOrSuffixItem::Word(w) => words.push(convert_word(w)?),
        ast::CommandPrefixOrSuffixItem::AssignmentWord(assignment, _) => {
            assignment_into(assignment, attached)?;
        }
        ast::CommandPrefixOrSuffixItem::IoRedirect(r) => redirect(r, attached)?,
        ast::CommandPrefixOrSuffixItem::ProcessSubstitution(kind, sub) => {
            attached.procs.push(proc_substitution(kind, sub)?);
        }
    }
    Ok(())
}

fn assignment_into(assignment: &ast::Assignment, attached: &mut Attached) -> Parsed {
    let (name, element) = match &assignment.name {
        ast::AssignmentName::VariableName(name) => (name, None),
        ast::AssignmentName::ArrayElementName(name, index) => (name, Some(index)),
    };
    if let Some(index) = element {
        attached.subs.extend(convert_text(index)?.subs);
    }
    let known = element.is_none() && !assignment.append;
    let value = match &assignment.value {
        ast::AssignmentValue::Scalar(w) => {
            let w = convert_word(w)?;
            if known {
                Some(w)
            } else {
                attached.subs.extend(w.subs);
                None
            }
        }
        ast::AssignmentValue::Array(items) => {
            for (index, w) in items {
                if let Some(index) = index {
                    attached.subs.extend(convert_word(index)?.subs);
                }
                attached.subs.extend(convert_word(w)?.subs);
            }
            None
        }
    };
    attached.assigns.push(Assign {
        name: name.clone(),
        value,
    });
    Ok(())
}

fn redirect(r: &IoRedirect, attached: &mut Attached) -> Parsed {
    match r {
        IoRedirect::File(fd, kind, target) => match target {
            ast::IoFileRedirectTarget::Filename(w) => {
                let w = convert_word(w)?;
                attached.subs.extend(w.subs);
                if matches!(
                    kind,
                    ast::IoFileRedirectKind::Write
                        | ast::IoFileRedirectKind::Append
                        | ast::IoFileRedirectKind::ReadAndWrite
                        | ast::IoFileRedirectKind::Clobber
                ) {
                    attached.written_files.push(w.text);
                }
            }
            ast::IoFileRedirectTarget::ProcessSubstitution(kind, sub) => {
                let mut proc = proc_substitution(kind, sub)?;
                proc.fd = *fd;
                attached.procs.push(proc);
            }
            ast::IoFileRedirectTarget::Fd(n) => {
                if matches!(kind, ast::IoFileRedirectKind::DuplicateInput) {
                    attached.dup_inputs.push(*n);
                }
            }
            ast::IoFileRedirectTarget::Duplicate(w) => {
                if let (ast::IoFileRedirectKind::DuplicateInput, Ok(n)) =
                    (kind, w.value.parse::<i32>())
                {
                    attached.dup_inputs.push(n);
                }
            }
        },
        IoRedirect::OutputAndError(w, _) => {
            let w = convert_word(w)?;
            attached.subs.extend(w.subs);
            attached.written_files.push(w.text);
        }
        IoRedirect::HereString(_, w) => attached.here_texts.push(HereText {
            body: convert_word(w)?,
            expands: false,
        }),
        IoRedirect::HereDocument(_, doc) => {
            let body = if doc.requires_expansion {
                convert_heredoc(&doc.doc.value)?
            } else {
                Word {
                    text: doc.doc.value.clone(),
                    subs: Vec::new(),
                    whole_substitution: false,
                }
            };
            attached.here_texts.push(HereText {
                body,
                expands: doc.requires_expansion,
            });
        }
    }
    Ok(())
}

fn proc_substitution(
    kind: &ast::ProcessSubstitutionKind,
    sub: &ast::SubshellCommand,
) -> Parsed<Proc> {
    let mut body = Vec::new();
    lists(&sub.list, &mut body)?;
    let kind = match kind {
        ast::ProcessSubstitutionKind::Read => ProcKind::Read,
        ast::ProcessSubstitutionKind::Write => ProcKind::Write,
    };
    Ok(Proc {
        kind,
        body,
        fd: None,
    })
}

fn convert_word(w: &ast::Word) -> Parsed<Word> {
    convert_text(&w.value)
}

fn convert_text(source: &str) -> Parsed<Word> {
    let pieces = word::parse(source, &ParserOptions::default()).map_err(|_| ParseFailure)?;
    word_from_pieces(source, &pieces)
}

/// Quotes in a here-document body are literal; only the expansions count.
fn convert_heredoc(source: &str) -> Parsed<Word> {
    let pieces =
        word::parse_heredoc(source, &ParserOptions::default()).map_err(|_| ParseFailure)?;
    let mut word = word_from_pieces(source, &pieces)?;
    word.text = source.to_string();
    Ok(word)
}

fn word_from_pieces(source: &str, pieces: &[WordPieceWithSource]) -> Parsed<Word> {
    let mut text = String::new();
    let mut subs = Vec::new();
    let mut only_subs = true;
    unquote(source, pieces, &mut text, &mut subs, &mut only_subs)?;
    let whole_substitution = only_subs && !subs.is_empty();
    Ok(Word {
        text,
        subs,
        whole_substitution,
    })
}

fn source_slice(source: &str, piece: &WordPieceWithSource) -> String {
    source
        .chars()
        .skip(piece.start_index)
        .take(piece.end_index.saturating_sub(piece.start_index))
        .collect()
}

fn unquote(
    source: &str,
    pieces: &[WordPieceWithSource],
    text: &mut String,
    subs: &mut Vec<Sub>,
    only_subs: &mut bool,
) -> Parsed {
    for p in pieces {
        match &p.piece {
            WordPiece::Text(t) | WordPiece::SingleQuotedText(t) | WordPiece::EscapeSequence(t) => {
                text.push_str(t.strip_prefix('\\').unwrap_or(t));
                *only_subs &= t.trim().is_empty();
            }
            WordPiece::DoubleQuotedSequence(inner)
            | WordPiece::GettextDoubleQuotedSequence(inner) => {
                unquote(source, inner, text, subs, only_subs)?;
            }
            WordPiece::CommandSubstitution(body)
            | WordPiece::BackquotedCommandSubstitution(body) => {
                text.push_str(&source_slice(source, p));
                subs.push(Sub { body: body.clone() });
            }
            WordPiece::ParameterExpansion(expr) => {
                for inner in parameter_texts(expr) {
                    subs.extend(convert_text(inner)?.subs);
                }
                text.push_str(&source_slice(source, p));
                *only_subs = false;
            }
            WordPiece::ArithmeticExpression(expr) => {
                subs.extend(convert_text(&expr.value)?.subs);
                text.push_str(&source_slice(source, p));
                *only_subs = false;
            }
            WordPiece::AnsiCQuotedText(t) => {
                text.push_str(&ansi_c_value(t));
                *only_subs = false;
            }
            WordPiece::TildeExpansion(_) => {
                text.push_str(&source_slice(source, p));
                *only_subs = false;
            }
        }
    }
    Ok(())
}

/// The value of the text inside `$'...'`: `\x73h` and `\163h` are `sh`.
fn ansi_c_value(raw: &str) -> String {
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(kind) = chars.next() else {
            out.push('\\');
            break;
        };
        let (radix, max) = match kind {
            'x' => (16, 2),
            'u' => (16, 4),
            'U' => (16, 8),
            '0'..='7' => (8, 3),
            _ => (0, 0),
        };
        if radix == 0 {
            out.push(match kind {
                'a' => '\x07',
                'b' => '\x08',
                'e' | 'E' => '\x1b',
                'f' => '\x0c',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'v' => '\x0b',
                other => other,
            });
            continue;
        }
        let mut digits = String::new();
        if radix == 8 {
            digits.push(kind);
        }
        while digits.len() < max {
            match chars.peek() {
                Some(d) if d.is_digit(radix) => digits.extend(chars.next()),
                _ => break,
            }
        }
        match u32::from_str_radix(&digits, radix)
            .ok()
            .and_then(char::from_u32)
        {
            Some(decoded) => out.push(decoded),
            None => out.push(kind),
        }
    }
    out
}

/// The texts inside a `${...}` that the shell expands too: defaults, patterns, replacements,
/// offsets and the array index.
fn parameter_texts(expr: &ParameterExpr) -> Vec<&str> {
    use ParameterExpr as P;
    fn index(parameter: &Parameter) -> Option<&str> {
        match parameter {
            Parameter::NamedWithIndex { index, .. } => Some(index.as_str()),
            _ => None,
        }
    }
    let mut texts = Vec::new();
    match expr {
        P::Parameter { parameter, .. }
        | P::ParameterLength { parameter, .. }
        | P::Transform { parameter, .. } => texts.extend(index(parameter)),
        P::UseDefaultValues {
            parameter,
            default_value: value,
            ..
        }
        | P::AssignDefaultValues {
            parameter,
            default_value: value,
            ..
        }
        | P::IndicateErrorIfNullOrUnset {
            parameter,
            error_message: value,
            ..
        }
        | P::UseAlternativeValue {
            parameter,
            alternative_value: value,
            ..
        }
        | P::RemoveSmallestSuffixPattern {
            parameter,
            pattern: value,
            ..
        }
        | P::RemoveLargestSuffixPattern {
            parameter,
            pattern: value,
            ..
        }
        | P::RemoveSmallestPrefixPattern {
            parameter,
            pattern: value,
            ..
        }
        | P::RemoveLargestPrefixPattern {
            parameter,
            pattern: value,
            ..
        }
        | P::UppercaseFirstChar {
            parameter,
            pattern: value,
            ..
        }
        | P::UppercasePattern {
            parameter,
            pattern: value,
            ..
        }
        | P::LowercaseFirstChar {
            parameter,
            pattern: value,
            ..
        }
        | P::LowercasePattern {
            parameter,
            pattern: value,
            ..
        } => {
            texts.extend(index(parameter));
            texts.extend(value.as_deref());
        }
        P::ReplaceSubstring {
            parameter,
            pattern,
            replacement,
            ..
        } => {
            texts.extend(index(parameter));
            texts.push(pattern);
            texts.extend(replacement.as_deref());
        }
        P::Substring {
            parameter,
            offset,
            length,
            ..
        } => {
            texts.extend(index(parameter));
            texts.push(&offset.value);
            texts.extend(length.as_ref().map(|l| l.value.as_str()));
        }
        P::VariableNames { .. } | P::MemberKeys { .. } => {}
    }
    texts
}

pub fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// A program that runs another program given as its arguments.
struct Wrapper {
    name: &'static str,
    /// Flags that consume the following word.
    value_flags: &'static [&'static str],
    /// Operands before the program (a duration, a lock file).
    operands: usize,
    /// Flags that stand in for those operands (`taskset -c LIST cmd` has no mask operand).
    replaces_operands: &'static [&'static str],
}

const fn wrapper(
    name: &'static str,
    value_flags: &'static [&'static str],
    operands: usize,
) -> Wrapper {
    Wrapper {
        name,
        value_flags,
        operands,
        replaces_operands: &[],
    }
}

/// Matching the real program through these is what keeps `sudo -u root bash` from hiding the
/// shell behind the user name.
const WRAPPERS: &[Wrapper] = &[
    wrapper(
        "sudo",
        &[
            "-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
        ],
        0,
    ),
    wrapper("doas", &["-u", "-C"], 0),
    wrapper("env", &["-u", "-C"], 0),
    wrapper(
        "xargs",
        &["-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a"],
        0,
    ),
    wrapper("nice", &["-n"], 0),
    wrapper("nohup", &[], 0),
    wrapper("exec", &["-a"], 0),
    wrapper("command", &[], 0),
    wrapper("builtin", &[], 0),
    wrapper("time", &[], 0),
    wrapper("busybox", &[], 0),
    wrapper("timeout", &["-s", "-k"], 1),
    wrapper("stdbuf", &["-i", "-o", "-e"], 0),
    wrapper("setsid", &[], 0),
    wrapper("ionice", &["-c", "-n", "-p", "-P", "-u"], 0),
    wrapper("flock", &["-w", "-E"], 1),
    wrapper("arch", &[], 0),
    wrapper("caffeinate", &["-t", "-w"], 0),
    wrapper("pkexec", &["--user"], 0),
    Wrapper {
        replaces_operands: &["-c", "--cpu-list"],
        ..wrapper("taskset", &["-c", "--cpu-list"], 1)
    },
    wrapper(
        "strace",
        &["-o", "-e", "-p", "-s", "-u", "-E", "-P", "-a", "-I", "-O"],
        0,
    ),
    wrapper("ltrace", &["-o", "-e", "-p", "-s", "-u", "-a"], 0),
    wrapper(
        "parallel",
        &["-j", "-n", "-N", "-S", "-a", "-P", "--jobs"],
        0,
    ),
    wrapper("chroot", &["--userspec", "--groups"], 1),
];

impl Simple {
    /// Index of the program that really runs: after wrappers such as `sudo -u root`,
    /// `/usr/bin/env`, `nohup`, their flags and `VAR=value` prefixes, and through a launcher
    /// (`docker run img sh`, `ssh host sh`) to the reader it starts.
    pub fn program_index(&self) -> Option<usize> {
        let i = self.wrapped_index(0)?;
        let name = basename(&self.words[i].text);
        if name == "ssh" {
            let start = readers::ssh_command_start(&self.words, i)?;
            return Some(
                self.wrapped_index(start)
                    .filter(|&k| readers::is_inner_program(basename(&self.words[k].text)))
                    .unwrap_or(i),
            );
        }
        let Some(launcher) = readers::LAUNCHERS.iter().find(|l| l.name == name) else {
            return Some(i);
        };
        let rest = &self.words[i + 1..];
        let after_subcommand = rest
            .iter()
            .position(|w| launcher.subcommands.contains(&w.text.as_str()))
            .map_or(rest.len(), |at| at + 1);
        let inner = rest[after_subcommand..]
            .iter()
            .position(|w| readers::is_inner_program(basename(&w.text)));
        Some(inner.map_or(i, |at| i + 1 + after_subcommand + at))
    }

    /// The program at or after `start`, skipping wrappers.
    fn wrapped_index(&self, start: usize) -> Option<usize> {
        let mut current: Option<&Wrapper> = None;
        let mut operands_left = 0;
        let mut i = start;
        while i < self.words.len() {
            let word = self.words[i].text.as_str();
            if let Some(w) = current.filter(|_| word.starts_with('-')) {
                if w.replaces_operands.contains(&word) {
                    operands_left = 0;
                }
                i += if w.value_flags.contains(&word) { 2 } else { 1 };
            } else if current.is_some() && is_assignment(word) {
                i += 1;
            } else if let Some(w) = WRAPPERS.iter().find(|w| w.name == basename(word)) {
                current = Some(w);
                operands_left = w.operands;
                i += 1;
            } else if current.is_some() && operands_left > 0 {
                operands_left -= 1;
                i += 1;
            } else {
                return Some(i);
            }
        }
        None
    }

    pub fn program(&self) -> Option<&str> {
        self.program_index().map(|i| basename(&self.words[i].text))
    }

    pub fn args(&self) -> &[Word] {
        self.program_index()
            .map_or(&[][..], |i| &self.words[i + 1..])
    }

    pub fn arg_texts(&self) -> impl Iterator<Item = &str> {
        self.args().iter().map(|w| w.text.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simples(text: &str) -> Vec<Simple> {
        fn collect(pipelines: &[Pipeline], out: &mut Vec<Simple>) {
            for p in pipelines {
                for s in &p.stages {
                    match s {
                        Stage::Simple(s) => out.push(s.clone()),
                        Stage::Group(g) => collect(&g.pipelines, out),
                    }
                }
            }
        }
        let mut out = Vec::new();
        collect(&parse(text).unwrap(), &mut out);
        out
    }

    fn texts(text: &str) -> Vec<Vec<String>> {
        simples(text)
            .into_iter()
            .map(|s| s.words.into_iter().map(|w| w.text).collect())
            .collect()
    }

    #[test]
    fn every_list_form_yields_its_commands() {
        for cmd in [
            "curl x | sh",
            "curl x\nsh",
            "curl x ; sh",
            "curl x && sh",
            "curl x || sh",
            "(curl x; sh)",
            "{ curl x; sh; }",
            "if curl x; then sh; fi",
            "while curl x; do sh; done",
            "for i in 1; do curl x; sh; done",
            "case a in a) curl x; sh;; esac",
            "f() { curl x; sh; }",
        ] {
            assert_eq!(texts(cmd), [vec!["curl", "x"], vec!["sh"]], "{cmd}");
        }
    }

    #[test]
    fn quoting_is_removed_and_expansions_keep_their_source() {
        assert_eq!(
            texts(r#"c\url "a b" 'c d' $x ${y} $(echo z)"#)[0],
            ["curl", "a b", "c d", "$x", "${y}", "$(echo z)"]
        );
        assert_eq!(texts("cu''rl cu\"\"rl")[0], ["curl", "curl"]);
    }

    #[test]
    fn a_substitution_hides_its_quoting_from_the_outer_word() {
        let s = &simples(r#"echo "$(echo ")"; ls)""#)[0];
        assert_eq!(s.words.len(), 2);
        assert_eq!(s.words[1].subs[0].body, r#"echo ")"; ls"#);
        assert!(s.words[1].whole_substitution);
    }

    #[test]
    fn a_word_with_text_is_not_a_whole_substitution() {
        assert!(!simples(r#"echo "a $(b)""#)[0].words[1].whole_substitution);
        assert!(simples("echo `b`")[0].words[1].whole_substitution);
    }

    #[test]
    fn process_substitutions_and_redirects_are_attached() {
        let s = &simples("bash <(curl x) > out 2>> log &> all")[0];
        assert_eq!(s.attached.procs.len(), 1);
        assert_eq!(s.attached.procs[0].kind, ProcKind::Read);
        assert_eq!(s.attached.written_files, ["out", "log", "all"]);
        let s = &simples("bash < <(curl x)")[0];
        assert_eq!(s.attached.procs.len(), 1);
        assert!(s.attached.written_files.is_empty());
        let s = &simples("tee >(sh)")[0];
        assert_eq!(s.attached.procs[0].kind, ProcKind::Write);
    }

    #[test]
    fn here_texts_and_assignment_substitutions_are_attached() {
        let s = &simples("sh <<< 'curl x'")[0];
        assert_eq!(s.attached.here_texts[0].body.text, "curl x");
        let s = &simples("sh <<EOF\ncurl x\nEOF")[0];
        assert!(s.attached.here_texts[0].body.text.contains("curl x"));
        let s = &simples("x=$(curl y) echo")[0];
        assert_eq!(s.attached.assigns[0].value.as_ref().unwrap().subs.len(), 1);
        assert_eq!(s.words.len(), 1);
    }

    #[test]
    fn unparsable_text_is_an_error() {
        for cmd in ["curl 'oops | sh", "echo $(", "a ||", "( a", "fi"] {
            assert_eq!(parse(cmd), Err(ParseFailure), "{cmd}");
        }
    }

    #[test]
    fn empty_input_and_comments_have_no_commands() {
        assert!(parse("  ").unwrap().is_empty());
        assert!(simples("# only a comment").is_empty());
    }

    #[test]
    fn program_skips_sudo_env_flags_and_directories() {
        let seg = &simples("sudo -E FOO=1 /bin/bash -s")[0];
        assert_eq!(seg.program(), Some("bash"));
    }

    #[test]
    fn program_skips_wrappers_with_their_flag_arguments() {
        for cmd in [
            "sudo -u root bash",
            "/usr/bin/env -u X FOO=1 bash",
            "nohup bash",
            "exec bash",
            "command bash",
            "xargs -n 1 bash",
            "time nice -n 5 bash",
            "FOO=1 /bin/bash",
            "busybox bash",
            "doas -u root bash",
        ] {
            assert_eq!(simples(cmd)[0].program(), Some("bash"), "{cmd}");
        }
        assert_eq!(simples("sudo -E")[0].program(), None);
    }

    #[test]
    fn args_follow_the_real_program() {
        let s = &simples("sudo -u root curl -s x")[0];
        assert_eq!(s.arg_texts().collect::<Vec<_>>(), ["-s", "x"]);
    }

    #[test]
    fn assignments_are_recorded_in_order_with_what_they_hold() {
        let s = &simples("A=1 B=$(x) C+=2 D=(a b) e[$(y)]=3 for_not=4")[0];
        let names: Vec<_> = s.attached.assigns.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["A", "B", "C", "D", "e", "for_not"]);
        let known: Vec<_> = s
            .attached
            .assigns
            .iter()
            .map(|a| a.value.is_some())
            .collect();
        assert_eq!(known, [true, true, false, false, false, true]);
        assert_eq!(s.attached.subs.len(), 1);
        assert!(s.words.is_empty());
    }

    #[test]
    fn declaration_builtins_keep_their_assignments_out_of_the_words() {
        let s = &simples("export A=b C=$(x)")[0];
        assert_eq!(s.words.len(), 1);
        assert_eq!(s.attached.assigns.len(), 2);
    }

    #[test]
    fn a_for_variable_is_an_assignment_to_something_unknown() {
        let Stage::Group(g) = &parse("for U in a b; do :; done").unwrap()[0].stages[0] else {
            panic!("group")
        };
        assert_eq!(g.attached.assigns[0].name, "U");
        assert!(g.attached.assigns[0].value.is_none());
    }
}
