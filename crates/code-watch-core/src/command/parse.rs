//! The command text as a tree: pipelines of stages, each a simple command or a group, with the
//! substitutions, redirections and here-texts that belong to it. Built from `brush-parser`'s
//! AST; text it cannot parse is an error, never an empty tree.

use brush_parser::ast::{self, AndOr, Command, CompoundCommand, CompoundList, IoRedirect};
use brush_parser::word::{self, WordPiece, WordPieceWithSource};
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
}

/// What hangs off a command besides its words.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attached {
    /// Targets of the redirections that write to a file.
    pub written_files: Vec<String>,
    /// Here-strings and here-documents: text a reader runs as a script.
    pub here_texts: Vec<Word>,
    /// Command substitutions in words that are not command words (assignments, redirect targets, `for` lists).
    pub subs: Vec<Sub>,
    /// `<(...)` and `>(...)`, as arguments or redirect targets.
    pub procs: Vec<Proc>,
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
}

/// Longest text parsed. The parser is quadratic on deeply nested substitutions, so a bigger
/// text is reported as not checked instead of being left to run for minutes.
const MAX_TEXT_BYTES: usize = 64 * 1024;

/// Parses `text` into its pipelines, every list, group and compound command included.
pub fn parse(text: &str) -> Result<Vec<Pipeline>, ParseFailure> {
    if text.len() > MAX_TEXT_BYTES {
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
        Command::Function(def) => compound_command(&def.body.0).map(Stage::Group),
        Command::ExtendedTest(..) => Ok(Stage::Group(Group {
            pipelines: Vec::new(),
            attached: Attached::default(),
        })),
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
            for w in f.values.iter().flatten() {
                attached.subs.extend(convert_word(w)?.subs);
            }
            lists(&f.body.list, &mut pipelines)?;
        }
        CompoundCommand::ArithmeticForClause(f) => lists(&f.body.list, &mut pipelines)?,
        CompoundCommand::CaseClause(c) => {
            attached.subs.extend(convert_word(&c.value)?.subs);
            for item in &c.cases {
                if let Some(list) = &item.cmd {
                    lists(list, &mut pipelines)?;
                }
            }
        }
        CompoundCommand::Coprocess(c) => pipelines.push(Pipeline {
            stages: vec![stage(&c.body)?],
        }),
        CompoundCommand::Arithmetic(_) => {}
    }
    Ok(Group {
        pipelines,
        attached,
    })
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
    Ok(Simple { words, attached })
}

fn item_into(
    item: &ast::CommandPrefixOrSuffixItem,
    words: &mut Vec<Word>,
    attached: &mut Attached,
) -> Parsed {
    match item {
        ast::CommandPrefixOrSuffixItem::Word(w) => words.push(convert_word(w)?),
        ast::CommandPrefixOrSuffixItem::AssignmentWord(assignment, _) => {
            assignment_subs(&assignment.value, attached)?;
        }
        ast::CommandPrefixOrSuffixItem::IoRedirect(r) => redirect(r, attached)?,
        ast::CommandPrefixOrSuffixItem::ProcessSubstitution(kind, sub) => {
            attached.procs.push(proc_substitution(kind, sub)?);
        }
    }
    Ok(())
}

fn assignment_subs(value: &ast::AssignmentValue, attached: &mut Attached) -> Parsed {
    match value {
        ast::AssignmentValue::Scalar(w) => attached.subs.extend(convert_word(w)?.subs),
        ast::AssignmentValue::Array(items) => {
            for (_, w) in items {
                attached.subs.extend(convert_word(w)?.subs);
            }
        }
    }
    Ok(())
}

fn redirect(r: &IoRedirect, attached: &mut Attached) -> Parsed {
    match r {
        IoRedirect::File(_, kind, target) => match target {
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
                attached.procs.push(proc_substitution(kind, sub)?);
            }
            ast::IoFileRedirectTarget::Fd(_) | ast::IoFileRedirectTarget::Duplicate(_) => {}
        },
        IoRedirect::OutputAndError(w, _) => {
            let w = convert_word(w)?;
            attached.subs.extend(w.subs);
            attached.written_files.push(w.text);
        }
        IoRedirect::HereString(_, w) => attached.here_texts.push(convert_word(w)?),
        IoRedirect::HereDocument(_, doc) => {
            let mut w = convert_word(&doc.doc)?;
            w.text = doc.doc.value.clone();
            attached.here_texts.push(w);
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
    Ok(Proc { kind, body })
}

fn convert_word(w: &ast::Word) -> Parsed<Word> {
    let pieces = word::parse(&w.value, &ParserOptions::default()).map_err(|_| ParseFailure)?;
    let mut text = String::new();
    let mut subs = Vec::new();
    let mut only_subs = true;
    unquote(&w.value, &pieces, &mut text, &mut subs, &mut only_subs);
    Ok(Word {
        text,
        subs,
        whole_substitution: only_subs,
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
) {
    for p in pieces {
        match &p.piece {
            WordPiece::Text(t) | WordPiece::SingleQuotedText(t) | WordPiece::EscapeSequence(t) => {
                text.push_str(t.strip_prefix('\\').unwrap_or(t));
                *only_subs = false;
            }
            WordPiece::DoubleQuotedSequence(inner)
            | WordPiece::GettextDoubleQuotedSequence(inner) => {
                unquote(source, inner, text, subs, only_subs);
            }
            WordPiece::CommandSubstitution(body)
            | WordPiece::BackquotedCommandSubstitution(body) => {
                text.push_str(&source_slice(source, p));
                subs.push(Sub { body: body.clone() });
            }
            WordPiece::AnsiCQuotedText(_)
            | WordPiece::TildeExpansion(_)
            | WordPiece::ParameterExpansion(_)
            | WordPiece::ArithmeticExpression(_) => {
                text.push_str(&source_slice(source, p));
                *only_subs = false;
            }
        }
    }
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Programs that run another program given as their arguments, with the flags that consume the
/// following word. Matching the real program through them is what keeps `sudo -u root bash`
/// from hiding the shell behind the user name.
const WRAPPERS: &[(&str, &[&str])] = &[
    (
        "sudo",
        &[
            "-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
        ],
    ),
    ("doas", &["-u", "-C"]),
    ("env", &["-u", "-C", "-S"]),
    ("xargs", &["-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a"]),
    ("nice", &["-n"]),
    ("nohup", &[]),
    ("exec", &[]),
    ("command", &[]),
    ("time", &[]),
    ("busybox", &[]),
];

impl Simple {
    /// Index of the program that really runs: after wrappers such as `sudo -u root`,
    /// `/usr/bin/env`, `nohup`, their flags and `VAR=value` prefixes.
    pub fn program_index(&self) -> Option<usize> {
        let mut arg_flags: Option<&[&str]> = None;
        let mut i = 0;
        while i < self.words.len() {
            let word = self.words[i].text.as_str();
            if let Some(flags) = arg_flags.filter(|_| word.starts_with('-')) {
                i += if flags.contains(&word) { 2 } else { 1 };
            } else if arg_flags.is_some() && is_assignment(word) {
                i += 1;
            } else if let Some((_, flags)) = WRAPPERS.iter().find(|(n, _)| *n == basename(word)) {
                arg_flags = Some(flags);
                i += 1;
            } else {
                return Some(i);
            }
        }
        None
    }

    /// The program name without its directory.
    pub fn program(&self) -> Option<&str> {
        self.program_index().map(|i| basename(&self.words[i].text))
    }

    /// The words after the program.
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
        assert_eq!(s.attached.here_texts[0].text, "curl x");
        let s = &simples("sh <<EOF\ncurl x\nEOF")[0];
        assert!(s.attached.here_texts[0].text.contains("curl x"));
        let s = &simples("x=$(curl y) echo")[0];
        assert_eq!(s.attached.subs.len(), 1);
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
}
