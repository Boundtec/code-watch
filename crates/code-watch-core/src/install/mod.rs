//! The before-an-install layer: shows what an `npm`, `pnpm`, `yarn`, `pip` or `brew` install
//! would run, reading only what is on disk. It never runs a package manager, never touches the
//! network and never writes; anything it cannot read is reported as `install/unchecked`.

mod brew;
mod node;
mod pip;
mod read;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::finding::{Evidence, Finding, Layer, Severity};

/// Dependency names listed in one finding before "and N more".
const LISTED_NAMES: usize = 20;

pub const RULE_UNCHECKED: &str = "install/unchecked";

struct Spec {
    id: &'static str,
    title: &'static str,
    remediation: &'static str,
}

const SPECS: &[Spec] = &[
    Spec {
        id: "install/lifecycle-script-fetch-run",
        title: "An install script downloads and runs code",
        remediation: "Do not install here; read the script first.",
    },
    Spec {
        id: "install/lifecycle-script",
        title: "The install runs a script automatically",
        remediation: "Read the script before installing, or install with --ignore-scripts.",
    },
    Spec {
        id: "install/dependency-scripts",
        title: "Dependencies run install scripts",
        remediation: "Read what these packages run before installing, or install with --ignore-scripts.",
    },
    Spec {
        id: "install/dependency-scripts-blocked",
        title: "Dependency install scripts are blocked by pnpm unless allowed",
        remediation: "Allow a package's build only after reading what it runs.",
    },
    Spec {
        id: "install/dependency-scripts-unknown",
        title: "The lockfile does not say which dependencies run install scripts",
        remediation: "Install with --ignore-scripts, or use a lockfile that records them.",
    },
    Spec {
        id: "install/no-scripts",
        title: "Lifecycle scripts are turned off for this install",
        remediation: "",
    },
    Spec {
        id: "install/repo-code-at-install",
        title: "The repository ships code that runs on every install",
        remediation: "Read the file before installing; --ignore-scripts does not stop it.",
    },
    Spec {
        id: "install/no-script-found",
        title: "No install script found",
        remediation: "",
    },
    Spec {
        id: "install/global-package",
        title: "A global install runs a package's own install scripts",
        remediation: "Install global tools only from authors you trust; allow a package you trust in the user allowlist.",
    },
    Spec {
        id: "install/pip-build-code",
        title: "pip builds and runs project code to install this",
        remediation: "Read setup.py or the build backend first. --only-binary :all: stops source builds from an index, not a local directory, an editable or a VCS install.",
    },
    Spec {
        id: "install/pip-wheels-only",
        title: "pip installs wheels only, no project code is built",
        remediation: "",
    },
    Spec {
        id: "install/brew-unknown-tap",
        title: "brew runs formula code from a tap outside homebrew",
        remediation: "Read the formula before installing it.",
    },
    Spec {
        id: RULE_UNCHECKED,
        title: "The install could not be checked",
        remediation: "Look at what the install runs yourself, or ask the user.",
    },
];

pub const RULE_IDS: &[&str] = &[
    "install/lifecycle-script-fetch-run",
    "install/lifecycle-script",
    "install/dependency-scripts",
    "install/dependency-scripts-blocked",
    "install/dependency-scripts-unknown",
    "install/no-scripts",
    "install/repo-code-at-install",
    "install/no-script-found",
    "install/global-package",
    "install/pip-build-code",
    "install/pip-wheels-only",
    "install/brew-unknown-tap",
    RULE_UNCHECKED,
];

/// What the install layer borrows from the rest of the engine, so it keeps no rules of its own.
pub struct Judge<'a> {
    /// Whether a script's text is blocked by the command layer (fetches or decodes and runs).
    pub script_blocks: &'a dyn Fn(&str) -> bool,
    /// Whether the repo rule for `setup.py` flags this file's text.
    pub setup_py_flagged: &'a dyn Fn(&str) -> bool,
}

pub(crate) fn finding(
    id: &str,
    severity: Severity,
    file: Option<String>,
    line: Option<usize>,
    excerpt: &str,
    package: Option<String>,
) -> Finding {
    let spec = SPECS
        .iter()
        .find(|s| s.id == id)
        .expect("known install rule id");
    Finding {
        rule_id: spec.id.into(),
        severity,
        layer: Layer::Rules,
        title: spec.title.into(),
        evidence: Evidence::new(file, line, excerpt),
        remediation: spec.remediation.into(),
        domain: None,
        package,
        advisories: Vec::new(),
    }
}

pub(crate) fn unchecked(file: &str, why: &str) -> Finding {
    finding(
        RULE_UNCHECKED,
        Severity::Warn,
        Some(file.into()),
        None,
        why,
        None,
    )
}

/// Names for one finding: the first few, then "and N more".
pub(crate) fn list(names: &BTreeSet<String>) -> String {
    let shown: Vec<&str> = names
        .iter()
        .take(LISTED_NAMES)
        .map(String::as_str)
        .collect();
    let mut joined = shown.join(", ");
    if names.len() > LISTED_NAMES {
        joined.push_str(&format!(" and {} more", names.len() - LISTED_NAMES));
    }
    joined
}

/// `path` as the user would write it: relative to `cwd` when it lies under it.
pub(crate) fn shown(path: &Path, cwd: &Path) -> String {
    path.strip_prefix(cwd)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// An address as it may be shown: no user, password, query or fragment, which is where tokens go.
pub(crate) fn redact(address: &str) -> String {
    let bare = address.split(['?', '#']).next().unwrap_or("");
    match bare.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, tail) = rest
                .split_once('/')
                .map_or((rest, None), |(a, t)| (a, Some(t)));
            let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            match tail {
                Some(tail) => format!("{scheme}://{host}/{tail}"),
                None => format!("{scheme}://{host}"),
            }
        }
        None => bare.to_string(),
    }
}

/// Whether `word` is `name` or a versioned form of an interpreter or pip (`python3.12`, `pip3.9`).
fn versioned(word: &str, name: &str) -> bool {
    word.strip_prefix(name)
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// Programs and subcommands that run code at install time and are not analysed; an empty list
/// means every use. A match is reported as "not checked", never as clean.
const NOT_CHECKED: &[(&str, &[&[&str]])] = &[
    ("npx", &[]),
    ("pnpx", &[]),
    ("bunx", &[]),
    ("uvx", &[]),
    (
        "bun",
        &[
            &["install"],
            &["i"],
            &["add"],
            &["a"],
            &["update"],
            &["upgrade"],
            &["x"],
            &["create"],
        ],
    ),
    (
        "pipx",
        &[
            &["install"],
            &["run"],
            &["upgrade"],
            &["upgrade-all"],
            &["reinstall"],
            &["inject"],
        ],
    ),
    ("poetry", &[&["install"], &["add"], &["update"], &["sync"]]),
    (
        "uv",
        &[
            &["sync"],
            &["add"],
            &["pip", "install"],
            &["pip", "sync"],
            &["tool", "install"],
            &["tool", "run"],
        ],
    ),
];

/// The not-checked finding for a program the layer does not analyse, if this use runs code.
fn not_checked(program: &str, args: &[String]) -> Option<Finding> {
    let (_, subs) = NOT_CHECKED.iter().find(|(p, _)| *p == program)?;
    let words: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let hit = if subs.is_empty() {
        Some(program.to_string())
    } else {
        subs.iter()
            .find(|sub| words.windows(sub.len()).any(|w| w == **sub))
            .map(|sub| format!("{program} {}", sub.join(" ")))
    }?;
    Some(unchecked_command(&hit))
}

pub(crate) fn unchecked_command(what: &str) -> Finding {
    finding(
        RULE_UNCHECKED,
        Severity::Warn,
        None,
        None,
        &format!("not checked: {what} may run install-time code"),
        None,
    )
}

/// Where `-m pip` is among a Python interpreter's args: interpreter flags (`-I`, `-u`,
/// `-W ignore`, `-Im`) may come first; the first word that is not a flag is a script.
fn python_dash_m_pip(args: &[String]) -> Option<&[String]> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let dash_m =
            arg == "-m" || (arg.starts_with('-') && !arg.starts_with("--") && arg.ends_with('m'));
        if dash_m {
            return match args.get(i + 1).map(String::as_str) {
                Some("pip") => Some(&args[i + 2..]),
                _ => None,
            };
        }
        match arg {
            "-c" => return None,
            "-W" | "-X" => i += 1,
            _ if arg.starts_with('-') => {}
            _ => return None,
        }
        i += 1;
    }
    None
}

/// Checks each simple command of a command line, in order, for an install. Each entry holds the
/// words of one command starting at the program. A `cd <dir>` before an install moves where it
/// is judged. Programs that install but are not analysed (`npx`, `bun`, `uv`, `pipx`, `poetry`,
/// `brew bundle`) give `install/unchecked` where they run code.
pub fn analyze(commands: &[Vec<String>], cwd: &Path, judge: &Judge) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut here: PathBuf = cwd.to_path_buf();
    for words in commands {
        let words = unparenthesised(words);
        let Some(program) = words.first().map(|w| basename(w)) else {
            continue;
        };
        let args = &words[1..];
        match program {
            "cd" => {
                if let Some(dir) = args.iter().find(|a| !a.starts_with('-') && *a != "-") {
                    here = here.join(dir);
                }
            }
            "npm" | "pnpm" | "yarn" => {
                findings.extend(node::analyze(program, args, &here, cwd, judge, None))
            }
            "corepack" => {
                let mut rest = args.iter().skip_while(|a| a.starts_with('-'));
                // `corepack pnpm@9 install` names the version it pins after the manager.
                if let Some((manager, version)) = rest.next().map(|m| {
                    m.split_once('@')
                        .map_or((m.as_str(), None), |(n, v)| (n, Some(v)))
                }) && matches!(manager, "npm" | "pnpm" | "yarn")
                {
                    let after: Vec<String> = rest.cloned().collect();
                    findings.extend(node::analyze(manager, &after, &here, cwd, judge, version));
                }
            }
            "brew" => findings.extend(brew::analyze(args)),
            p if versioned(p, "pip") => findings.extend(pip::analyze(args, &here, cwd, judge)),
            p if versioned(p, "python") => {
                if let Some(rest) = python_dash_m_pip(args) {
                    findings.extend(pip::analyze(rest, &here, cwd, judge));
                }
            }
            p => findings.extend(not_checked(p, args)),
        }
    }
    findings
}

/// `(cd x && npm i)` reaches us as `(cd` and `i)`; the parentheses are not part of the words.
fn unparenthesised(words: &[String]) -> Vec<String> {
    let mut out = words.to_vec();
    if let Some(first) = out.first_mut() {
        *first = first.trim_start_matches('(').to_string();
    }
    if let Some(last) = out.last_mut() {
        *last = last.trim_end_matches(')').to_string();
    }
    out.retain(|w| !w.is_empty());
    out
}
