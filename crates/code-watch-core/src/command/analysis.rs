//! Flattens a command into every simple command it can run, at any depth, with whether the
//! command's output is run as a script.

use super::MAX_DEPTH;
use super::parse::{self, Attached, Pipeline, ProcKind, Simple, Stage, Word};
use super::readers::{self, is_dash_c, reads_script_files, runs_text};

/// One simple command found somewhere in the text.
pub struct Occurrence {
    pub simple: Simple,
    /// Its output ends up run as a script: a later stage of its pipeline (or of the pipeline
    /// of a group around it) reads a script, or it sits inside the `$(...)` that is the whole
    /// script of `sh -c`/`eval`, or inside a `<(...)` that a shell or `source` reads.
    pub feeds_script: bool,
    /// A later stage of the same pipeline reads a script.
    pub piped_into_reader: bool,
}

/// Why the analysis could not look at some text.
pub enum Limit {
    Unparsable,
    /// `MAX_DEPTH` reached; `reaches_shell` says the text left unread holds a script reader or `eval`.
    TooDeep {
        reaches_shell: bool,
    },
}

#[derive(Default)]
pub struct Flat {
    pub occurrences: Vec<Occurrence>,
    pub limits: Vec<Limit>,
}

/// Stack for the analysis thread. The parser and the tree are recursive, so a hostile command
/// with thousands of nested groups must not be able to overflow the caller's stack; the memory
/// is only touched when such input arrives.
const ANALYSIS_STACK_BYTES: usize = 256 * 1024 * 1024;

pub fn flatten(command: &str) -> Flat {
    let run = || {
        let mut flat = Flat::default();
        text(command, 0, false, &mut flat);
        flat
    };
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(ANALYSIS_STACK_BYTES)
            .spawn_scoped(scope, run)
            .ok()
            .and_then(|handle| handle.join().ok())
    })
    .unwrap_or_else(|| Flat {
        occurrences: Vec::new(),
        limits: vec![Limit::Unparsable],
    })
}

fn text(source: &str, depth: usize, feeds: bool, flat: &mut Flat) {
    let parsed = parse::parse(source);
    if depth >= MAX_DEPTH {
        let reaches_shell = parsed.as_ref().is_ok_and(|p| holds_runner(p));
        flat.limits.push(Limit::TooDeep { reaches_shell });
        return;
    }
    match parsed {
        Ok(pipelines) => walk(&pipelines, depth, feeds, flat),
        Err(_) => flat.limits.push(Limit::Unparsable),
    }
}

fn nested_pipelines(pipelines: &[Pipeline], depth: usize, feeds: bool, flat: &mut Flat) {
    if depth >= MAX_DEPTH {
        flat.limits.push(Limit::TooDeep {
            reaches_shell: holds_runner(pipelines),
        });
    } else {
        walk(pipelines, depth, feeds, flat);
    }
}

/// Whether the pipelines, or any substitution inside them, hold a script reader or `eval`.
fn holds_runner(pipelines: &[Pipeline]) -> bool {
    let in_subs = |attached: &Attached| {
        attached
            .subs
            .iter()
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

fn walk(pipelines: &[Pipeline], depth: usize, feeds: bool, flat: &mut Flat) {
    for pipeline in pipelines {
        let mut reader_after = vec![false; pipeline.stages.len()];
        for i in (0..pipeline.stages.len().saturating_sub(1)).rev() {
            reader_after[i] =
                reader_after[i + 1] || readers::stage_reads_script(&pipeline.stages[i + 1]);
        }
        for (i, stage) in pipeline.stages.iter().enumerate() {
            let piped_into_reader = reader_after[i];
            let stage_feeds = feeds || piped_into_reader;
            match stage {
                Stage::Simple(simple) => {
                    flat.occurrences.push(Occurrence {
                        simple: simple.clone(),
                        feeds_script: stage_feeds,
                        piped_into_reader,
                    });
                    simple_children(simple, depth, flat);
                }
                Stage::Group(group) => {
                    walk(&group.pipelines, depth, stage_feeds, flat);
                    attached_children(&group.attached, depth, flat);
                }
            }
        }
    }
}

fn attached_children(attached: &Attached, depth: usize, flat: &mut Flat) {
    for sub in &attached.subs {
        text(&sub.body, depth + 1, false, flat);
    }
    for proc in &attached.procs {
        nested_pipelines(&proc.body, depth + 1, false, flat);
    }
}

/// Follows what a simple command runs from its words: the `-c` text, the `eval` text, command
/// substitutions, process substitutions and here-texts.
fn simple_children(simple: &Simple, depth: usize, flat: &mut Flat) {
    let program = simple.program();
    let runs = program.is_some_and(runs_text);
    let script_words = script_words(simple, program);
    for word in simple.words.iter() {
        let is_script = script_words.iter().any(|w| std::ptr::eq(*w, word));
        for sub in &word.subs {
            text(
                &sub.body,
                depth + 1,
                is_script && word.whole_substitution,
                flat,
            );
        }
    }
    if runs {
        run_text(&script_words, depth, flat);
    }
    let reads_files = program.is_some_and(reads_script_files);
    for proc in &simple.attached.procs {
        let feeds = reads_files && proc.kind == ProcKind::Read;
        nested_pipelines(&proc.body, depth + 1, feeds, flat);
    }
    let reads_here_text = program.is_some_and(readers::is_shell);
    for here in &simple.attached.here_texts {
        for sub in &here.subs {
            text(
                &sub.body,
                depth + 1,
                reads_here_text && here.whole_substitution,
                flat,
            );
        }
        if reads_here_text && !here.whole_substitution {
            text(&here.text, depth + 1, false, flat);
        }
    }
    for sub in &simple.attached.subs {
        text(&sub.body, depth + 1, false, flat);
    }
}

/// The words a shell or `eval` runs as text: the argument of `-c`, or all arguments of `eval`.
fn script_words<'a>(simple: &'a Simple, program: Option<&str>) -> Vec<&'a Word> {
    let args = simple.args();
    match program {
        Some("eval") => args.iter().collect(),
        Some(p) if readers::is_shell(p) => args
            .windows(2)
            .filter(|pair| is_dash_c(&pair[0].text))
            .map(|pair| &pair[1])
            .collect(),
        _ => Vec::new(),
    }
}

/// Parses the literal part of the script words again. A word that is only a substitution is
/// followed through its substitution instead (its output is the script).
fn run_text(words: &[&Word], depth: usize, flat: &mut Flat) {
    let literal: Vec<&str> = words
        .iter()
        .filter(|w| !w.whole_substitution)
        .map(|w| w.text.as_str())
        .collect();
    if !literal.is_empty() {
        text(&literal.join(" "), depth + 1, false, flat);
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
        assert!(matches!(flatten(&huge).limits[..], [Limit::Unparsable]));
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
