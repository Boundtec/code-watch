//! Flattens a command into every simple command it can run, at any depth, with whether the
//! command's output is run as a script. Variables and `cd` set earlier in the text are
//! followed (`resolve.rs`) and texts run by a child (`sh -c`, `$(...)`, `ssh`) inherit them.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::mpsc;
use std::time::Duration;

use super::MAX_DEPTH;
use super::floor;
use super::parse::{
    self, Assign, Attached, MAX_TEXT_BYTES, Pipeline, ProcKind, Simple, Stage, Word,
};
use super::readers::{self, EMITTERS, FETCHERS, reads_script_files, runs_text};
use super::resolve::Env;

/// One simple command found somewhere in the text, its words resolved.
pub struct Occurrence {
    pub simple: Simple,
    /// Its output ends up run as a script: a later stage of its pipeline (or of the pipeline
    /// of a group around it) reads a script, or it sits inside the `$(...)` that is the whole
    /// script of `sh -c`/`eval`, or inside a `<(...)` that a shell or `source` reads, or it
    /// wrote a file that a later command runs.
    pub feeds_script: bool,
    /// A later stage of the same pipeline reads a script.
    pub piped_into_reader: bool,
    /// The working directory when it runs, if the text set one.
    pub cwd: Option<String>,
}

/// Why the analysis could not look at some text.
pub enum Limit {
    /// Part of the text could not be parsed; `floor` says a token-level pass found a download
    /// reaching a reader in it.
    Unparsable { floor: bool },
    /// The text nests deeper than the parser can take, or the analysis did not finish in time:
    /// input made to stall the check.
    Hostile,
    /// `MAX_DEPTH` reached; `reaches_shell` says the text left unread holds a script reader or `eval`,
    /// or is itself run as a script.
    TooDeep { reaches_shell: bool },
}

#[derive(Default)]
pub struct Flat {
    pub occurrences: Vec<Occurrence>,
    pub limits: Vec<Limit>,
    /// Bodies of `x=$(...)` not yet analysed: one that a use of `$x` reached was analysed there,
    /// with the script it feeds.
    pending: Vec<Pending>,
    files: Files,
}

struct Pending {
    body: String,
    depth: usize,
    env: Env,
    used: bool,
}

/// Files the text writes and later may run: a fetch's output (the occurrence that wrote it)
/// and the text of `echo`/here-documents redirected to a file.
#[derive(Default)]
struct Files {
    fetched: Vec<(String, usize)>,
    emitted: Vec<(String, String)>,
    /// Occurrences of a `<(...)` held on a descriptor (`exec 3< <(...)`), for a reader that
    /// later reads it (`sh <&3`).
    fd_sources: HashMap<i32, Range<usize>>,
}

/// Stack for the analysis thread. The parser and the tree are recursive, so a hostile command
/// with thousands of nested groups must not be able to overflow the caller's stack; the memory
/// is only touched when such input arrives.
const ANALYSIS_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Programs whose arguments set variables of the shell itself.
const DECLARERS: &[&str] = &["export", "local", "readonly", "declare", "typeset"];
/// Programs that give their operands a value the text does not show.
const UNBINDERS: &[&str] = &["read", "unset", "getopts", "mapfile", "readarray"];

/// How long the analysis may run before the text is treated as hostile. Legitimate commands
/// are read in milliseconds.
pub const DEADLINE: Duration = Duration::from_secs(2);

pub fn flatten(command: &str) -> Flat {
    guarded(command, DEADLINE, analyse)
}

fn analyse(command: String) -> Flat {
    let mut flat = Flat::default();
    text(&command, 0, false, &Env::default(), &mut flat);
    while let Some(at) = flat.pending.iter().position(|p| !p.used) {
        flat.pending[at].used = true;
        let (body, depth, env) = {
            let p = &flat.pending[at];
            (p.body.clone(), p.depth, p.env.clone())
        };
        text(&body, depth, false, &env, &mut flat);
    }
    flat
}

/// Runs `work` on a thread with a big stack and waits for it at most `deadline`. A thread that
/// does not answer is left behind (the process is short-lived) and the text is reported as
/// hostile.
fn guarded(
    command: &str,
    deadline: Duration,
    work: impl FnOnce(String) -> Flat + Send + 'static,
) -> Flat {
    let (send, receive) = mpsc::channel();
    let owned = command.to_string();
    let spawned = std::thread::Builder::new()
        .stack_size(ANALYSIS_STACK_BYTES)
        .spawn(move || {
            let _ = send.send(work(owned));
        });
    let limit = match spawned.map(|_| receive.recv_timeout(deadline)) {
        Ok(Ok(flat)) => return flat,
        Ok(Err(mpsc::RecvTimeoutError::Timeout)) => Limit::Hostile,
        _ => Limit::Unparsable {
            floor: floor::reaches_reader(command),
        },
    };
    Flat {
        limits: vec![limit],
        ..Flat::default()
    }
}

#[cfg(test)]
pub(super) fn flatten_within(
    command: &str,
    deadline: Duration,
    work: impl FnOnce(String) -> Flat + Send + 'static,
) -> Flat {
    guarded(command, deadline, work)
}

/// Lines tried as separate pieces when the whole text does not parse; more than this and the
/// rest is left to the token-level floor.
const MAX_SALVAGE_PARSES: usize = 400;

fn text(source: &str, depth: usize, feeds: bool, env: &Env, flat: &mut Flat) {
    if parse::too_complex(source) {
        flat.limits.push(Limit::Hostile);
        return;
    }
    match parse::parse(source) {
        Ok(pipelines) => run_parsed(&pipelines, depth, feeds, env, flat),
        Err(_) => salvage(source, depth, feeds, env, flat),
    }
}

fn run_parsed(pipelines: &[Pipeline], depth: usize, feeds: bool, env: &Env, flat: &mut Flat) {
    if depth >= MAX_DEPTH {
        flat.limits.push(Limit::TooDeep {
            reaches_shell: feeds || holds_runner(pipelines),
        });
        return;
    }
    let mut env = env.clone();
    collect_functions(pipelines, &mut env.functions);
    walk(pipelines, depth, feeds, &mut env, flat);
}

fn collect_functions(pipelines: &[Pipeline], names: &mut std::collections::HashSet<String>) {
    for stage in pipelines.iter().flat_map(|p| &p.stages) {
        if let Stage::Group(group) = stage {
            names.extend(group.function.clone());
            collect_functions(&group.pipelines, names);
        }
    }
}

/// Text that does not parse as a whole: every run of lines that does is analysed, the rest is
/// read by the token-level floor, so a bad line never hides a download that runs before it.
fn salvage(source: &str, depth: usize, feeds: bool, env: &Env, flat: &mut Flat) {
    let lines: Vec<&str> = source.split_inclusive('\n').collect();
    let mut unread = String::new();
    let mut attempts = 0;
    let mut start = 0;
    while start < lines.len() {
        let mut parsed = None;
        for end in start + 1..=lines.len() {
            attempts += 1;
            let piece = lines[start..end].concat();
            if attempts > MAX_SALVAGE_PARSES || piece.len() > MAX_TEXT_BYTES {
                break;
            }
            if let Ok(pipelines) = parse::parse(&piece) {
                parsed = Some((end, pipelines));
                break;
            }
        }
        match parsed {
            Some((end, pipelines)) => {
                run_parsed(&pipelines, depth, feeds, env, flat);
                start = end;
            }
            None => {
                unread.push_str(lines[start]);
                start += 1;
            }
        }
    }
    if !unread.is_empty() || lines.is_empty() {
        let reaches = floor::reaches_reader(&unread) || feeds && floor::mentions_fetch(&unread);
        flat.limits.push(Limit::Unparsable { floor: reaches });
    }
}

/// A string literal of code in another language: shell text when it parses, nothing otherwise.
fn code_text(source: &str, depth: usize, feeds: bool, env: &Env, flat: &mut Flat) {
    if parse::parse(source).is_ok() {
        text(source, depth, feeds, env, flat);
    }
}

fn code_literals(code: &str, depth: usize, feeds: bool, env: &Env, flat: &mut Flat) {
    for literal in readers::string_literals(code) {
        if literal.contains(char::is_whitespace) {
            code_text(&literal, depth + 1, feeds, env, flat);
        }
    }
}

/// Whether the pipelines, or any substitution inside them, hold a script reader or `eval`.
fn holds_runner(pipelines: &[Pipeline]) -> bool {
    let in_subs = |attached: &Attached| {
        attached
            .subs
            .iter()
            .chain(
                attached
                    .assigns
                    .iter()
                    .flat_map(|a| a.value.iter().flat_map(|v| &v.subs)),
            )
            .any(|s| parse::parse(&s.body).is_ok_and(|p| holds_runner(&p)))
            || attached.procs.iter().any(|p| holds_runner(&p.body))
    };
    pipelines.iter().flat_map(|p| &p.stages).any(|s| match s {
        Stage::Simple(simple) => {
            readers::simple_reads_script(simple)
                || simple.program().is_some_and(runs_text)
                || simple
                    .words
                    .iter()
                    .flat_map(|w| &w.subs)
                    .any(|s| parse::parse(&s.body).is_ok_and(|p| holds_runner(&p)))
                || in_subs(&simple.attached)
        }
        Stage::Group(group) => holds_runner(&group.pipelines) || in_subs(&group.attached),
    })
}

fn walk(pipelines: &[Pipeline], depth: usize, feeds: bool, env: &mut Env, flat: &mut Flat) {
    for pipeline in pipelines {
        let mut reader_after = vec![false; pipeline.stages.len()];
        for i in (0..pipeline.stages.len().saturating_sub(1)).rev() {
            reader_after[i] =
                reader_after[i + 1] || reads_script(&pipeline.stages[i + 1], &env.functions);
        }
        for (i, stage) in pipeline.stages.iter().enumerate() {
            let piped_into_reader = reader_after[i];
            let stage_feeds = feeds || piped_into_reader;
            match stage {
                Stage::Simple(simple) => {
                    simple_stage(simple, depth, stage_feeds, piped_into_reader, env, flat);
                }
                Stage::Group(group) => {
                    for assign in &group.attached.assigns {
                        env.unbind(&assign.name);
                    }
                    walk(&group.pipelines, depth, stage_feeds, env, flat);
                    attached_children(&group.attached, depth, env, flat);
                }
            }
        }
    }
}

/// A reader, or a call of a function the text defines (its body may run anything).
fn reads_script(stage: &Stage, functions: &std::collections::HashSet<String>) -> bool {
    readers::stage_reads_script(stage)
        || matches!(stage, Stage::Simple(simple)
            if simple.program().is_some_and(|p| functions.contains(p)))
}

fn attached_children(attached: &Attached, depth: usize, env: &Env, flat: &mut Flat) {
    for sub in &attached.subs {
        text(&sub.body, depth + 1, false, env, flat);
    }
    for proc in &attached.procs {
        run_parsed(&proc.body, depth + 1, false, env, flat);
    }
}

/// One simple command: its words resolved, its assignments bound for the texts it runs (and
/// for the commands after it when it is not a prefix of another command), then what it runs.
fn simple_stage(
    simple: &Simple,
    depth: usize,
    feeds: bool,
    piped: bool,
    env: &mut Env,
    flat: &mut Flat,
) {
    let resolved = resolve_simple(simple, env, flat);
    let feeds = feeds || readers::writes_into_reader(&resolved);
    let mut bound = env.clone();
    for assign in &simple.attached.assigns {
        bind(assign, &mut bound, depth, flat);
    }
    let at = flat.occurrences.len();
    flat.occurrences.push(Occurrence {
        simple: resolved.clone(),
        feeds_script: feeds,
        piped_into_reader: piped,
        cwd: env.cwd.clone(),
    });
    track_files(&resolved, at, depth, env, flat);
    feed_descriptors(&resolved, flat);
    simple_children(&resolved, depth, piped, feeds, &bound, flat);
    let program = resolved.program();
    if resolved.words.is_empty() || program.is_some_and(|p| DECLARERS.contains(&p)) {
        let cwd = env.cwd.clone();
        *env = bound;
        env.cwd = cwd;
    }
    apply_effects(&resolved, env);
}

fn resolve_simple(simple: &Simple, env: &Env, flat: &mut Flat) -> Simple {
    let mut used = Vec::new();
    let mut word = |w: &Word| {
        let r = env.resolve(w);
        used.extend(r.used);
        r.word
    };
    let words = simple.words.iter().map(&mut word).collect();
    let mut attached = simple.attached.clone();
    attached.written_files = simple
        .attached
        .written_files
        .iter()
        .map(|f| env.resolve_text(f))
        .collect();
    for here in &mut attached.here_texts {
        here.body = word(&here.body);
    }
    for id in used {
        flat.pending[id].used = true;
    }
    Simple { words, attached }
}

/// Binds the name to a literal or a command, or unbinds it: a value the text does not show is
/// never guessed.
fn bind(assign: &Assign, env: &mut Env, depth: usize, flat: &mut Flat) {
    let Some(value) = &assign.value else {
        env.unbind(&assign.name);
        return;
    };
    let r = env.resolve(value);
    for id in r.used {
        flat.pending[id].used = true;
    }
    let value = r.word;
    if value.whole_substitution && value.subs.len() == 1 {
        let body = value.subs[0].body.clone();
        flat.pending.push(Pending {
            body: body.clone(),
            depth: depth + 1,
            env: env.clone(),
            used: false,
        });
        env.set_command(&assign.name, value.text, body, flat.pending.len() - 1);
        return;
    }
    for sub in &value.subs {
        text(&sub.body, depth + 1, false, env, flat);
    }
    if value.subs.is_empty() {
        env.set_literal(&assign.name, value.text);
    } else {
        env.unbind(&assign.name);
    }
}

/// `cd` sets the directory when its operand is known; `read`, `unset` and the like unbind
/// their operands.
fn apply_effects(simple: &Simple, env: &mut Env) {
    match simple.program() {
        Some("cd" | "pushd") => {
            let operand = simple
                .arg_texts()
                .find(|a| *a != "--" && !(a.starts_with('-') && a.len() > 1));
            env.cwd = operand
                .filter(|a| *a != "-" && !a.contains("$(") && !a.contains('`'))
                .map(|a| env.absolute(a));
        }
        Some(p) if UNBINDERS.contains(&p) => {
            for arg in simple.arg_texts().filter(|a| !a.starts_with('-')) {
                env.unbind(arg);
            }
        }
        _ => {}
    }
}

/// A reader that takes its script from a descriptor held on a `<(...)` makes what that held
/// feed a script.
fn feed_descriptors(simple: &Simple, flat: &mut Flat) {
    if simple.attached.dup_inputs.is_empty() || !readers::simple_reads_script(simple) {
        return;
    }
    for fd in &simple.attached.dup_inputs {
        if let Some(range) = flat.files.fd_sources.get(fd).cloned() {
            for occurrence in &mut flat.occurrences[range] {
                occurrence.feeds_script = true;
            }
        }
    }
}

/// Follows a file written by one command and run by a later one: a fetch's output makes that
/// fetch feed a script, written text is analysed when it is run.
fn track_files(simple: &Simple, at: usize, depth: usize, env: &Env, flat: &mut Flat) {
    let Some(program) = simple.program() else {
        return;
    };
    if FETCHERS.contains(&program) {
        for path in fetch_outputs(simple, program) {
            flat.files.fetched.push((env.absolute(&path), at));
        }
    }
    if let Some(emitted) = emitted_text(simple, program) {
        for path in &simple.attached.written_files {
            flat.files
                .emitted
                .push((env.absolute(path), emitted.clone()));
        }
    }
    let Some(target) = run_target(simple, program) else {
        return;
    };
    let target = env.absolute(&target);
    for (path, fetch) in &flat.files.fetched {
        if *path == target {
            flat.occurrences[*fetch].feeds_script = true;
        }
    }
    let (run, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut flat.files.emitted)
        .into_iter()
        .partition(|(path, _)| *path == target);
    flat.files.emitted = kept;
    for (_, body) in run {
        text(&body, depth + 1, false, env, flat);
    }
}

fn fetch_outputs(simple: &Simple, program: &str) -> Vec<String> {
    let flags: &[&str] = if program == "wget" {
        &["-O", "--output-document"]
    } else {
        &["-o", "--output"]
    };
    let flagged = simple
        .args()
        .windows(2)
        .filter(|pair| flags.contains(&pair[0].text.as_str()) && pair[1].text != "-")
        .map(|pair| pair[1].text.clone());
    let attached = simple.arg_texts().filter_map(|a| {
        flags
            .iter()
            .filter(|f| f.starts_with("--"))
            .find_map(|f| a.strip_prefix(&format!("{f}=")))
            .map(str::to_string)
    });
    flagged
        .chain(attached)
        .chain(simple.attached.written_files.iter().cloned())
        .collect()
}

/// What a command prints into its redirect: the arguments of `echo`/`printf`, or its here-texts.
fn emitted_text(simple: &Simple, program: &str) -> Option<String> {
    if EMITTERS.contains(&program) {
        let words = readers::emitted_args(simple);
        return Some(
            words
                .iter()
                .map(|w| w.text.as_str())
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    let bodies: Vec<&str> = simple
        .attached
        .here_texts
        .iter()
        .map(|h| h.body.text.as_str())
        .collect();
    (!bodies.is_empty()).then(|| bodies.join("\n"))
}

/// The file a command runs: the script operand of a shell, `source` or interpreter, or the
/// program itself when it is a path.
fn run_target(simple: &Simple, program: &str) -> Option<String> {
    if readers::reads_script_operand(program) {
        if simple.arg_texts().any(readers::is_dash_c) {
            return None;
        }
        return simple
            .arg_texts()
            .find(|a| !a.starts_with('-'))
            .map(str::to_string);
    }
    let word = &simple.words[simple.program_index()?].text;
    word.contains('/').then(|| word.clone())
}

/// Follows what a simple command runs from its words: the `-c` text, the `eval` text, command
/// substitutions, process substitutions, here-texts and the code of other interpreters. When the
/// stage's output is run as a script (`stage_feeds`), so is the output of everything it runs.
fn simple_children(
    simple: &Simple,
    depth: usize,
    piped: bool,
    stage_feeds: bool,
    env: &Env,
    flat: &mut Flat,
) {
    let program = simple.program();
    let emits = piped && program.is_some_and(|p| EMITTERS.contains(&p));
    let runs = program.is_some_and(runs_text);
    let script_words: Vec<&Word> = if emits {
        readers::emitted_args(simple).iter().collect()
    } else {
        readers::script_words(simple, program)
    };
    for word in simple.words.iter() {
        let is_script = script_words.iter().any(|w| std::ptr::eq(*w, word));
        for sub in &word.subs {
            text(
                &sub.body,
                depth + 1,
                stage_feeds || is_script && word.whole_substitution,
                env,
                flat,
            );
        }
    }
    if runs || emits {
        run_text(&script_words, depth, stage_feeds, env, flat);
    }
    if program == Some("git") {
        for script in simple.arg_texts().filter_map(readers::git_alias_script) {
            text(script, depth + 1, stage_feeds, env, flat);
        }
    }
    for code in readers::inline_code(simple) {
        code_literals(code, depth, stage_feeds, env, flat);
    }
    let reads_files = program.is_some_and(reads_script_files);
    for proc in &simple.attached.procs {
        let feeds = stage_feeds || reads_files && proc.kind == ProcKind::Read;
        let first = flat.occurrences.len();
        run_parsed(&proc.body, depth + 1, feeds, env, flat);
        if let (Some(fd), ProcKind::Read) = (proc.fd, proc.kind) {
            flat.files
                .fd_sources
                .insert(fd, first..flat.occurrences.len());
        }
    }
    let is_code = program.is_some_and(readers::runs_code);
    let reads_here_text = piped || readers::simple_reads_script(simple);
    for here in &simple.attached.here_texts {
        let body = &here.body;
        let spliced = stage_feeds || reads_here_text && (here.expands || body.whole_substitution);
        for sub in &body.subs {
            text(&sub.body, depth + 1, spliced, env, flat);
        }
        if is_code {
            code_literals(&body.text, depth, stage_feeds, env, flat);
        } else if (reads_here_text || stage_feeds) && !body.whole_substitution {
            text(&body.text, depth + 1, stage_feeds, env, flat);
        }
    }
    for sub in &simple.attached.subs {
        text(&sub.body, depth + 1, stage_feeds, env, flat);
    }
}

/// Parses the literal part of the script words again. A word that is only a substitution is
/// followed through its substitution instead (its output is the script).
fn run_text(words: &[&Word], depth: usize, feeds: bool, env: &Env, flat: &mut Flat) {
    let literal: Vec<&str> = words
        .iter()
        .filter(|w| !w.whole_substitution)
        .map(|w| w.text.as_str())
        .collect();
    if !literal.is_empty() {
        text(&literal.join(" "), depth + 1, feeds, env, flat);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetch_flags(text: &str) -> Vec<(bool, bool)> {
        flatten(text)
            .occurrences
            .iter()
            .filter(|o| o.simple.program() == Some("curl"))
            .map(|o| (o.feeds_script, o.piped_into_reader))
            .collect()
    }

    #[test]
    fn a_fetch_feeds_a_script_through_a_pipe_a_group_or_a_script_word() {
        assert_eq!(fetch_flags("curl x | sh"), [(true, true)]);
        assert_eq!(fetch_flags("(curl x) | sh"), [(true, false)]);
        assert_eq!(fetch_flags("sh -c \"$(curl x)\""), [(true, false)]);
        assert_eq!(fetch_flags("eval $(curl x)"), [(true, false)]);
        assert_eq!(fetch_flags("bash <(curl x)"), [(true, false)]);
        assert_eq!(fetch_flags("sh <<< \"$(curl x)\""), [(true, false)]);
    }

    #[test]
    fn a_fetch_that_is_only_data_does_not_feed_a_script() {
        for cmd in [
            "curl x ; sh",
            "echo $(curl x)",
            "sh -c 'echo $(curl x)'",
            "sh -c \"echo $(curl x)\"",
            "cat <(curl x)",
            "sh $(curl x)",
        ] {
            let flags = fetch_flags(cmd);
            assert!(!flags.is_empty(), "{cmd}");
            assert!(flags.iter().all(|f| *f == (false, false)), "{cmd}");
        }
    }

    #[test]
    fn hostile_nesting_and_size_are_reported_not_crashed_on() {
        let braces = format!("{}a;{}", "{ ".repeat(5000), " }".repeat(5000));
        assert!(flatten(&braces).limits.is_empty());
        let huge = format!("echo {}", "a".repeat(70_000));
        assert!(matches!(
            flatten(&huge).limits[..],
            [Limit::Unparsable { floor: false }]
        ));
    }

    #[test]
    fn long_pipelines_are_linear() {
        let pipes = vec!["a"; 8000].join(" | ");
        assert_eq!(flatten(&pipes).occurrences.len(), 8000);
    }

    #[test]
    fn depth_counts_substitutions_process_substitutions_and_text() {
        for cmd in [
            "echo $(echo $(echo $(echo hi)))",
            "cat <(cat <(cat <(cat f)))",
            "sh -c 'sh -c \"sh -c \\\"echo hi\\\"\"'",
        ] {
            assert!(
                matches!(flatten(cmd).limits[..], [Limit::TooDeep { .. }]),
                "{cmd}"
            );
        }
    }
}
