use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use globset::Glob;

use super::read::{MAX_LOCK_BYTES, MAX_TEXT_BYTES, ReadError, read_optional};
use super::{Judge, finding, list, redact, shown, unchecked};
use crate::finding::{Finding, Severity};

/// The scripts a project install may run, in npm's order. pnpm and yarn run a subset; listing
/// the superset errs toward showing more.
const SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
];

/// Workspace members and flagged dependencies whose own manifest is read.
const MAX_MEMBERS: usize = 50;
/// Installed manifests read to find dependency scripts.
const MAX_INSPECTED: usize = 5000;
const MAX_WALK_UP: usize = 16;

const INSTALL_WORDS: &[&str] = &[
    "install",
    "i",
    "in",
    "ins",
    "inst",
    "insta",
    "instal",
    "isnt",
    "isnta",
    "isntal",
    "isntall",
    "add",
    "ci",
    "ic",
    "clean-install",
    "install-clean",
    "isntall-clean",
    "it",
    "cit",
    "install-test",
    "install-ci-test",
];

/// Subcommands that run lifecycle scripts or fetch and run code but are not analysed.
fn runs_code_unchecked(manager: &str, sub: &str) -> bool {
    match manager {
        "npm" => matches!(
            sub,
            "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "rebuild"
                | "rb"
                | "link"
                | "ln"
                | "dedupe"
                | "ddp"
                | "find-dupes"
                | "exec"
                | "x"
        ),
        "pnpm" => matches!(
            sub,
            "update"
                | "up"
                | "upgrade"
                | "rebuild"
                | "rb"
                | "dlx"
                | "approve-builds"
                | "link"
                | "ln"
                | "create"
        ),
        _ => matches!(
            sub,
            "up" | "upgrade" | "upgrade-interactive" | "dlx" | "rebuild" | "create" | "link"
        ),
    }
}

/// Subcommands that take another subcommand (`yarn workspace <w> add`, `pnpm recursive install`).
fn wraps_subcommand(manager: &str, sub: &str) -> bool {
    match manager {
        "pnpm" => matches!(sub, "recursive" | "multi" | "m"),
        "yarn" => matches!(sub, "workspace" | "workspaces"),
        _ => false,
    }
}

/// Subcommands after which later words are arguments, not a subcommand.
fn takes_free_words(sub: &str) -> bool {
    matches!(
        sub,
        "run"
            | "run-script"
            | "rum"
            | "urn"
            | "test"
            | "tst"
            | "t"
            | "start"
            | "stop"
            | "restart"
            | "view"
            | "info"
            | "ls"
            | "list"
            | "ll"
            | "la"
            | "config"
            | "set"
            | "get"
            | "pack"
            | "publish"
            | "cache"
            | "audit"
            | "outdated"
            | "why"
            | "explain"
            | "whoami"
            | "version"
            | "help"
    )
}

/// Flags that take the next word as a value, so it is not mistaken for a package.
const VALUE_FLAGS: &[&str] = &[
    "--registry",
    "--workspace",
    "-w",
    "--filter",
    "-F",
    "--tag",
    "--loglevel",
    "--cache",
    "--userconfig",
    "--omit",
    "--include",
    "--save-prefix",
    "--fetch-retries",
    "--network-concurrency",
    "--store-dir",
    "--reporter",
    "--cwd",
    "--prefix",
    "-C",
    "--dir",
    "--install-strategy",
    "--script-shell",
    "--before",
    "--otp",
    "--lockfile-dir",
    "--globalconfig",
    "--min-release-age",
    "--audit-level",
    "--fund-level",
];

struct Invocation {
    global: bool,
    packages: Vec<String>,
    dir: PathBuf,
    /// The command line's own word on scripts; absent leaves the project's settings to say.
    ignore_scripts: Option<bool>,
    skip_build: bool,
    /// The command line allows dependency builds (pnpm 10 blocks them by default).
    allows_builds: bool,
}

enum Parsed {
    Install(Invocation),
    NotChecked(String),
    Other,
}

fn parse(manager: &str, args: &[String], here: &Path) -> Parsed {
    let mut global = false;
    let mut ignore_scripts = None;
    let mut skip_build = false;
    let mut allows_builds = false;
    let mut dir = here.to_path_buf();
    let mut positionals: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            positionals.extend(args[i + 1..].iter().map(String::as_str));
            break;
        }
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if arg.starts_with('-') => (f, Some(v)),
            _ => (arg, None),
        };
        match flag {
            "-g" | "--global" => global = true,
            "--location" if inline == Some("global") => global = true,
            "--ignore-scripts" => {
                // npm's option parser takes a following `true` or `false` as the value.
                let value = inline.or_else(|| {
                    let next = args.get(i + 1).map(String::as_str);
                    next.filter(|n| matches!(*n, "true" | "false"))
                        .inspect(|_| i += 1)
                });
                ignore_scripts = Some(value != Some("false"));
            }
            "--no-ignore-scripts" => ignore_scripts = Some(false),
            "--mode" => {
                let value = inline.or_else(|| {
                    i += 1;
                    args.get(i).map(String::as_str)
                });
                skip_build = value == Some("skip-build");
            }
            "--dangerously-allow-all-builds" => allows_builds |= inline != Some("false"),
            "--allow-build" => {
                allows_builds = true;
                if inline.is_none() {
                    i += 1;
                }
            }
            f if f
                .strip_prefix("--config.")
                .is_some_and(|key| config_key_allows_builds(key, inline)) =>
            {
                allows_builds = true;
            }
            "--prefix" | "-C" | "--dir" | "--cwd" => {
                let value = inline.or_else(|| {
                    i += 1;
                    args.get(i).map(String::as_str)
                });
                if let Some(v) = value {
                    dir = here.join(v);
                }
            }
            f if VALUE_FLAGS.contains(&f) => {
                if inline.is_none() {
                    i += 1;
                }
            }
            f if f.starts_with('-') => {}
            _ => positionals.push(arg),
        }
        i += 1;
    }
    let Some((at, sub)) = positionals
        .iter()
        .copied()
        .enumerate()
        .take_while(|(_, p)| !takes_free_words(p))
        .find(|(_, p)| {
            is_install(manager, p)
                || runs_code_unchecked(manager, p)
                || wraps_subcommand(manager, p)
                || (manager == "yarn" && *p == "global")
        })
    else {
        return match (manager, positionals.first()) {
            ("yarn", None) => Parsed::Install(Invocation {
                global,
                packages: Vec::new(),
                dir,
                ignore_scripts,
                skip_build,
                allows_builds,
            }),
            _ => Parsed::Other,
        };
    };
    let mut packages: Vec<String> = positionals[at + 1..]
        .iter()
        .map(|p| p.to_string())
        .collect();
    if wraps_subcommand(manager, sub) {
        let inner = positionals[at + 1..]
            .iter()
            .find(|p| is_install(manager, p) || runs_code_unchecked(manager, p));
        return match inner {
            Some(inner) => Parsed::NotChecked(format!("{manager} {sub} {inner}")),
            None => Parsed::Other,
        };
    }
    if manager == "yarn" && sub == "global" {
        return match packages.first().map(String::as_str) {
            Some("add") => {
                packages.remove(0);
                Parsed::Install(Invocation {
                    global: true,
                    packages,
                    dir,
                    ignore_scripts,
                    skip_build,
                    allows_builds,
                })
            }
            Some(other) if runs_code_unchecked(manager, other) => {
                Parsed::NotChecked(format!("yarn global {other}"))
            }
            _ => Parsed::Other,
        };
    }
    if !is_install(manager, sub) {
        return Parsed::NotChecked(format!("{manager} {sub}"));
    }
    if matches!(
        sub,
        "ci" | "ic"
            | "clean-install"
            | "install-clean"
            | "isntall-clean"
            | "cit"
            | "install-ci-test"
    ) {
        packages.clear();
    }
    Parsed::Install(Invocation {
        global,
        packages,
        dir,
        ignore_scripts,
        skip_build,
        allows_builds,
    })
}

/// pnpm's `--config.<key>[=value]` spells a setting in either case style; a key that allows
/// builds counts unless it is set to false. Any `onlyBuiltDependencies` or `allowBuild` form
/// counts, since which packages it names is not worth parsing: the result can only show more.
fn config_key_allows_builds(key: &str, inline: Option<&str>) -> bool {
    let key: String = key
        .chars()
        .filter(|c| *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    if key.starts_with("dangerouslyallowallbuilds") {
        return inline != Some("false");
    }
    key.starts_with("onlybuiltdependencies") || key.starts_with("allowbuild")
}

fn is_install(manager: &str, sub: &str) -> bool {
    match manager {
        "npm" => INSTALL_WORDS.contains(&sub),
        "pnpm" => matches!(sub, "install" | "i" | "add" | "it" | "install-test"),
        _ => matches!(sub, "install" | "add"),
    }
}

fn package_name(spec: &str) -> &str {
    let tail = spec.strip_prefix('@').unwrap_or(spec);
    match tail.find('@') {
        Some(at) => &spec[..spec.len() - tail.len() + at],
        None => spec,
    }
}

pub(super) fn analyze(
    manager: &str,
    args: &[String],
    here: &Path,
    cwd: &Path,
    judge: &Judge,
) -> Vec<Finding> {
    let inv = match parse(manager, args, here) {
        Parsed::Install(inv) => inv,
        Parsed::NotChecked(what) => return vec![super::unchecked_command(&what)],
        Parsed::Other => return Vec::new(),
    };
    if inv.global {
        return inv
            .packages
            .iter()
            .map(|spec| redact(spec))
            .map(|spec| {
                finding(
                    "install/global-package",
                    Severity::Warn,
                    None,
                    None,
                    &format!("{manager} global install of {spec}"),
                    Some(package_name(&spec).to_string()),
                )
            })
            .collect();
    }
    let mut out = Vec::new();
    let project = Project {
        manager,
        dir: &inv.dir,
        root: find_root(manager, &inv.dir),
        cwd,
        judge,
        skip_build: inv.skip_build,
        allows_builds: inv.allows_builds,
    };
    project.repo_code(&mut out);
    // Yarn berry has no --ignore-scripts and does not read .npmrc; elsewhere the command line beats the project's settings.
    let off = match inv.ignore_scripts {
        Some(flag) => flag && !project.berry(),
        None => project.scripts_off(&mut out),
    };
    if off {
        out.push(finding(
            "install/no-scripts",
            Severity::Info,
            None,
            None,
            &format!(
                "{manager} install with lifecycle scripts turned off; an environment setting such as npm_config_ignore_scripts can override this"
            ),
            None,
        ));
        return out;
    }
    let mut remote = BTreeMap::new();
    let declared = project.own_scripts(!inv.packages.is_empty(), &mut remote, &mut out);
    let covered = project.dependency_scripts(&declared, &mut remote, &mut out);
    project.report_remote(&remote, &mut out);
    for spec in inv.packages.iter().map(|spec| redact(spec)) {
        out.push(finding(
            "install/dependency-scripts",
            Severity::Warn,
            None,
            None,
            &format!(
                "{spec} and its dependencies may run install scripts; they cannot be read offline"
            ),
            Some(package_name(&spec).to_string()),
        ));
    }
    if covered && inv.packages.is_empty() && out.is_empty() {
        out.push(finding(
            "install/no-script-found",
            Severity::Info,
            Some(shown(&inv.dir.join("package.json"), cwd)),
            None,
            "no install script in package.json, and the lockfile covers every dependency",
            None,
        ));
    }
    out
}

/// The directory holding the lockfile or workspace file this install reads: the nearest
/// ancestor with one that is a workspace root listing this directory as a member, not looking
/// above a repository root. A lockfile of an unrelated parent project is not this project's.
fn find_root(manager: &str, dir: &Path) -> PathBuf {
    let markers: &[&str] = match manager {
        "npm" => &["package-lock.json", "npm-shrinkwrap.json"],
        "pnpm" => &["pnpm-lock.yaml", "pnpm-workspace.yaml"],
        _ => &["yarn.lock"],
    };
    for ancestor in dir.ancestors().take(MAX_WALK_UP) {
        let marked = markers.iter().any(|m| ancestor.join(m).is_file());
        if marked && (ancestor == dir || lists_member(ancestor, dir)) {
            return ancestor.to_path_buf();
        }
        if ancestor.join(".git").exists() {
            break;
        }
    }
    dir.to_path_buf()
}

/// Whether `root`'s `workspaces` (package.json) or `pnpm-workspace.yaml` `packages` globs match `member`;
/// a `!` pattern excludes.
fn lists_member(root: &Path, member: &Path) -> bool {
    let Ok(relative) = member.strip_prefix(root) else {
        return false;
    };
    let relative = relative.to_string_lossy().replace('\\', "/");
    let mut patterns: Vec<String> = Vec::new();
    if let Ok(Some((json, _))) = manifest_if_present(&root.join("package.json")) {
        let ws = json.get("workspaces");
        let list = ws.and_then(|w| {
            w.as_array()
                .or_else(|| w.get("packages").and_then(|p| p.as_array()))
        });
        patterns.extend(
            list.into_iter()
                .flatten()
                .filter_map(|v| v.as_str())
                .map(String::from),
        );
    }
    if let Ok(Some(text)) = read_optional(&root.join("pnpm-workspace.yaml"), MAX_TEXT_BYTES)
        && let Ok(y) = serde_norway::from_str::<serde_norway::Value>(&text)
    {
        patterns.extend(
            y.get("packages")
                .and_then(|p| p.as_sequence())
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str())
                .map(String::from),
        );
    }
    let matches = |pattern: &str| {
        let pattern = pattern.trim_start_matches("./").trim_end_matches('/');
        globset::GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .is_ok_and(|g| g.compile_matcher().is_match(&relative))
    };
    let mut listed = false;
    for pattern in &patterns {
        match pattern.strip_prefix('!') {
            Some(negated) => listed &= !matches(negated),
            None => listed |= matches(pattern),
        }
    }
    listed
}

type Declared = Vec<(String, String)>;
type Remote = BTreeMap<String, String>;

struct Project<'a> {
    manager: &'a str,
    dir: &'a Path,
    root: PathBuf,
    cwd: &'a Path,
    judge: &'a Judge<'a>,
    skip_build: bool,
    allows_builds: bool,
}

impl Project<'_> {
    fn file(&self, name: &str) -> (PathBuf, String) {
        let path = self.dir.join(name);
        let shown = shown(&path, self.cwd);
        (path, shown)
    }

    /// A lockfile or settings file, from the workspace root.
    fn root_file(&self, name: &str) -> (PathBuf, String) {
        let path = self.root.join(name);
        let shown = shown(&path, self.cwd);
        (path, shown)
    }

    /// Whether this is yarn berry (2 and later), which has its own config file and scripts rules.
    fn berry(&self) -> bool {
        if self.manager != "yarn" {
            return false;
        }
        match read_optional(&self.root.join("yarn.lock"), MAX_LOCK_BYTES) {
            Ok(Some(lock)) => lock.contains("__metadata:"),
            _ => self.root.join(".yarnrc.yml").is_file() || self.dir.join(".yarnrc.yml").is_file(),
        }
    }

    /// Repository files whose code runs on every install, whatever `ignore-scripts` says.
    fn repo_code(&self, out: &mut Vec<Finding>) {
        let mut found: Vec<(String, String)> = Vec::new();
        match self.manager {
            "pnpm" => {
                for name in [".pnpmfile.cjs", ".pnpmfile.mjs"] {
                    for (path, shown) in [self.root_file(name), self.file(name)] {
                        if path.is_file() && !found.iter().any(|(f, _)| *f == shown) {
                            found.push((shown, "pnpm hooks".into()));
                        }
                    }
                }
                if let Some(y) = self.yaml("pnpm-workspace.yaml", out) {
                    for key in ["pnpmfile", "globalPnpmfile"] {
                        if y.get(key).is_some() {
                            found.push((
                                self.root_file("pnpm-workspace.yaml").1,
                                format!("{key} setting"),
                            ));
                        }
                    }
                }
                let (path, shown) = self.root_file("package.json");
                if let Ok(Some((json, _))) = manifest_if_present(&path)
                    && json.pointer("/pnpm/pnpmfile").is_some()
                {
                    found.push((shown, "pnpm.pnpmfile setting".into()));
                }
            }
            "yarn" => {
                if let Some(y) = self.yaml(".yarnrc.yml", out) {
                    let plugins = y
                        .get("plugins")
                        .and_then(|p| p.as_sequence())
                        .is_some_and(|p| !p.is_empty());
                    for (hit, what) in [
                        (
                            y.get("yarnPath").is_some(),
                            "yarnPath replaces yarn with a checked-in file",
                        ),
                        (plugins, "plugins are loaded from the repository"),
                    ] {
                        if hit {
                            found.push((self.root_file(".yarnrc.yml").1, what.into()));
                        }
                    }
                }
                let (path, shown) = self.root_file(".yarnrc");
                if let Ok(Some(text)) = read_optional(&path, MAX_TEXT_BYTES)
                    && text
                        .lines()
                        .any(|l| l.trim_start().starts_with("yarn-path"))
                {
                    found.push((
                        shown,
                        "yarn-path replaces yarn with a checked-in file".into(),
                    ));
                }
            }
            _ => {}
        }
        for (file, what) in found {
            out.push(finding(
                "install/repo-code-at-install",
                Severity::Warn,
                Some(file),
                None,
                &format!(
                    "{what}: repository code runs on every install, whatever ignore-scripts says"
                ),
                None,
            ));
        }
    }

    /// Whether the project's own settings turn install scripts off. An unreadable settings
    /// file is reported and then counts as not off.
    fn scripts_off(&self, out: &mut Vec<Finding>) -> bool {
        match self.manager {
            "pnpm" => self
                .yaml("pnpm-workspace.yaml", out)
                .is_some_and(|y| y.get("ignoreScripts").and_then(|v| v.as_bool()) == Some(true)),
            _ if self.berry() => false,
            _ => {
                for (path, name) in [self.file(".npmrc"), self.root_file(".npmrc")] {
                    match read_optional(&path, MAX_TEXT_BYTES) {
                        Ok(Some(text)) => {
                            if let Some(off) = npmrc_ignores_scripts(&text) {
                                return off;
                            }
                        }
                        Ok(None) => {}
                        Err(e) => out.push(unchecked(&name, e.describe())),
                    }
                    if self.root == self.dir {
                        break;
                    }
                }
                false
            }
        }
    }

    /// A settings file from the workspace root; one that is invalid is reported once.
    fn yaml(&self, name: &str, out: &mut Vec<Finding>) -> Option<serde_norway::Value> {
        let (path, shown) = self.root_file(name);
        let problem = match read_optional(&path, MAX_TEXT_BYTES) {
            Ok(None) => return None,
            Ok(Some(text)) => match serde_norway::from_str(&text) {
                Ok(v) => return Some(v),
                Err(_) => unchecked(&shown, "is not valid YAML"),
            },
            Err(e) => unchecked(&shown, e.describe()),
        };
        if !out.contains(&problem) {
            out.push(problem);
        }
        None
    }

    fn package_json(
        &self,
        dir: &Path,
        out: &mut Vec<Finding>,
    ) -> Option<(serde_json::Value, String)> {
        let path = dir.join("package.json");
        let name = shown(&path, self.cwd);
        match super::read::read_text(&path, MAX_TEXT_BYTES) {
            Err(ReadError::Missing) => {
                out.push(unchecked(&name, "does not exist"));
                None
            }
            Err(e) => {
                out.push(unchecked(&name, e.describe()));
                None
            }
            Ok(text) => match serde_json::from_str(text.trim_start_matches('\u{feff}')) {
                Ok(v) => Some((v, text)),
                Err(_) => {
                    out.push(unchecked(&name, "is not valid JSON"));
                    None
                }
            },
        }
    }

    /// Lists the project's own install scripts and its workspace members', and returns the
    /// dependencies they declare; those that come from git or a URL go into `remote`.
    fn own_scripts(
        &self,
        named_packages: bool,
        remote: &mut Remote,
        out: &mut Vec<Finding>,
    ) -> Declared {
        let mut declared = Declared::new();
        let Some((root, text)) = self.package_json(self.dir, out) else {
            return declared;
        };
        self.list_scripts(self.dir, &root, &text, named_packages, None, out);
        collect_dependencies(&root, &mut declared, remote);
        for member in self.workspace_dirs(&root, out) {
            if let Some((json, text)) = self.package_json(&member, out) {
                self.list_scripts(&member, &json, &text, false, None, out);
                collect_dependencies(&json, &mut declared, remote);
            }
        }
        declared
    }

    /// One warning per dependency that is fetched from git or a URL: npm and pnpm run its
    /// `prepare` as well as its install scripts, and lockfiles do not flag that.
    fn report_remote(&self, remote: &Remote, out: &mut Vec<Finding>) {
        for (name, from) in remote.iter().take(MAX_MEMBERS) {
            out.push(finding(
                "install/dependency-scripts",
                Severity::Warn,
                None,
                None,
                &format!("{name} comes from {from}, not a registry tarball: its prepare and install scripts may run"),
                Some(name.clone()),
            ));
        }
        if remote.len() > MAX_MEMBERS {
            out.push(finding(
                "install/dependency-scripts",
                Severity::Warn,
                None,
                None,
                &format!(
                    "and {} more dependencies come from git or a URL",
                    remote.len() - MAX_MEMBERS
                ),
                None,
            ));
        }
    }

    fn list_scripts(
        &self,
        dir: &Path,
        json: &serde_json::Value,
        text: &str,
        named_packages: bool,
        package: Option<&str>,
        out: &mut Vec<Finding>,
    ) {
        let file = shown(&dir.join("package.json"), self.cwd);
        for name in SCRIPTS {
            // npm does not run `prepare` when installing named packages.
            if named_packages && *name == "prepare" {
                continue;
            }
            let Some(script) = json
                .pointer(&format!("/scripts/{name}"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let blocks = (self.judge.script_blocks)(script);
            let line = text
                .lines()
                .position(|l| l.contains(&format!("\"{name}\"")))
                .map(|i| i + 1);
            out.push(finding(
                if blocks {
                    "install/lifecycle-script-fetch-run"
                } else {
                    "install/lifecycle-script"
                },
                if blocks {
                    Severity::Block
                } else {
                    Severity::Warn
                },
                Some(file.clone()),
                line,
                &format!("{name}: {script}"),
                package.map(String::from),
            ));
        }
    }

    /// Member directories of `workspaces` (npm, yarn) or `pnpm-workspace.yaml`, for patterns
    /// that are a directory or `dir/*`. Other patterns are reported as not listed.
    fn workspace_dirs(&self, root: &serde_json::Value, out: &mut Vec<Finding>) -> Vec<PathBuf> {
        let mut patterns: Vec<String> = Vec::new();
        let ws = root.get("workspaces");
        let from_json = ws.and_then(|w| {
            w.as_array()
                .or_else(|| w.get("packages").and_then(|p| p.as_array()))
        });
        patterns.extend(
            from_json
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str())
                .map(String::from),
        );
        if self.manager == "pnpm"
            && let Some(y) = self.yaml("pnpm-workspace.yaml", out)
        {
            patterns.extend(
                y.get("packages")
                    .and_then(|p| p.as_sequence())
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str())
                    .map(String::from),
            );
        }
        let mut dirs = Vec::new();
        for pattern in patterns {
            let pattern = pattern.trim_start_matches("./").trim_end_matches('/');
            let (base, wildcard) = match pattern.strip_suffix("/*") {
                Some(base) => (base, true),
                None => (pattern, false),
            };
            if base.contains(['*', '?', '[', '{', '!']) || base.starts_with("..") {
                out.push(unchecked(
                    "package.json",
                    &format!("workspace pattern {pattern} is not listed"),
                ));
                continue;
            }
            let base_dir = self.dir.join(base);
            if !wildcard {
                dirs.push(base_dir);
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&base_dir) else {
                continue;
            };
            let mut subs: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.join("package.json").is_file())
                .collect();
            subs.sort();
            dirs.extend(subs);
        }
        if dirs.len() > MAX_MEMBERS {
            dirs.truncate(MAX_MEMBERS);
            out.push(unchecked(
                "package.json",
                "more workspace members than the limit, the rest are not listed",
            ));
        }
        dirs
    }

    /// Reports dependencies that run scripts and returns whether the lockfile was read and
    /// covers every declared dependency, which is the only case that can be called clean.
    fn dependency_scripts(
        &self,
        declared: &Declared,
        remote: &mut Remote,
        out: &mut Vec<Finding>,
    ) -> bool {
        match self.manager {
            "npm" => self.npm_dependencies(declared, remote, out),
            "pnpm" => self.pnpm_dependencies(declared, remote, out),
            _ => self.yarn_dependencies(remote, out),
        }
    }

    /// The declared dependencies a lockfile has no entry for, as one unknown finding.
    fn covers(
        &self,
        declared: &Declared,
        locked: &HashSet<String>,
        file: &str,
        out: &mut Vec<Finding>,
    ) -> bool {
        let missing: BTreeSet<String> = declared
            .iter()
            .map(|(name, _)| name)
            .filter(|name| !locked.contains(*name))
            .cloned()
            .collect();
        if missing.is_empty() {
            return true;
        }
        self.unknown(
            file,
            &format!(
                "the lockfile does not list {}; they may run install scripts",
                list(&missing)
            ),
            Severity::Warn,
            out,
        );
        false
    }

    fn npm_dependencies(
        &self,
        declared: &Declared,
        remote: &mut Remote,
        out: &mut Vec<Finding>,
    ) -> bool {
        for name in [
            "package-lock.json",
            "npm-shrinkwrap.json",
            "node_modules/.package-lock.json",
        ] {
            let (path, shown) = self.root_file(name);
            let text = match read_optional(&path, MAX_LOCK_BYTES) {
                Ok(Some(t)) => t,
                Ok(None) => continue,
                Err(e) => {
                    out.push(unchecked(&shown, e.describe()));
                    return false;
                }
            };
            let Ok(lock) =
                serde_json::from_str::<serde_json::Value>(text.trim_start_matches('\u{feff}'))
            else {
                out.push(unchecked(&shown, "is not valid JSON"));
                return false;
            };
            let Some(packages) = lock.get("packages").and_then(|p| p.as_object()) else {
                self.unknown(
                    &shown,
                    "this lockfile version does not record install scripts; dependencies may run them",
                    Severity::Warn,
                    out,
                );
                return false;
            };
            let tail_of = |key: &str| {
                key.rsplit_once("node_modules/")
                    .map_or(key.to_string(), |(_, t)| t.to_string())
            };
            let mut locked = HashSet::new();
            let mut names = BTreeSet::new();
            for (key, entry) in packages.iter().filter(|(k, _)| !k.is_empty()) {
                let tail = tail_of(key);
                if entry.get("hasInstallScript").and_then(|v| v.as_bool()) == Some(true) {
                    names.insert(
                        entry
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or(&tail)
                            .to_string(),
                    );
                }
                if let Some(resolved) = entry.get("resolved").and_then(|r| r.as_str())
                    && entry.get("link").and_then(|l| l.as_bool()) != Some(true)
                    && !is_registry_tarball(resolved)
                {
                    remote.insert(tail.clone(), redact(resolved));
                }
                locked.insert(tail);
            }
            self.report_dependencies(
                &names,
                "will run",
                &shown,
                &|n| Some(self.root.join("node_modules").join(n)),
                out,
            );
            return self.covers(declared, &locked, &shown, out);
        }
        self.unknown(
            "package-lock.json",
            "no lockfile or node_modules found; every dependency may run install scripts",
            Severity::Warn,
            out,
        );
        false
    }

    /// pnpm 10's lockfile does not record which packages build (`requiresBuild` is only written
    /// by older versions), so a package counts when the lock flags it or its installed
    /// manifest under `node_modules/.pnpm` has an install-time script. A package in the lock
    /// that is not installed cannot be read, so it makes the result unknown.
    fn pnpm_dependencies(
        &self,
        declared: &Declared,
        remote: &mut Remote,
        out: &mut Vec<Finding>,
    ) -> bool {
        let (path, shown) = self.root_file("pnpm-lock.yaml");
        let text = match read_optional(&path, MAX_LOCK_BYTES) {
            Ok(Some(t)) => t,
            Ok(None) => {
                self.unknown(
                    "pnpm-lock.yaml",
                    "no lockfile found; dependencies may run install scripts",
                    Severity::Warn,
                    out,
                );
                return false;
            }
            Err(e) => {
                out.push(unchecked(&shown, e.describe()));
                return false;
            }
        };
        let Ok(lock) = serde_norway::from_str::<serde_norway::Value>(&text) else {
            out.push(unchecked(&shown, "is not valid YAML"));
            return false;
        };
        let mut names = BTreeSet::new();
        let mut dirs: BTreeMap<String, PathBuf> = BTreeMap::new();
        let mut inspected = 0usize;
        let mut total = 0usize;
        let mut not_installed = 0usize;
        let store = self.root.join("node_modules/.pnpm");
        for section in ["packages", "snapshots"] {
            let Some(map) = lock.get(section).and_then(|s| s.as_mapping()) else {
                continue;
            };
            for (key, entry) in map {
                let Some(key) = key.as_str() else { continue };
                let Some(name) = pnpm_key_name(key) else {
                    continue;
                };
                if entry.get("requiresBuild").and_then(|v| v.as_bool()) == Some(true) {
                    names.insert(name.to_string());
                }
                if section == "packages"
                    && let Some(res) = entry.get("resolution").and_then(|r| r.as_mapping())
                    && ["repo", "directory", "tarball"]
                        .iter()
                        .any(|k| res.contains_key(*k))
                {
                    remote.insert(name.to_string(), "git or a URL".into());
                }
                let bare = key.strip_prefix('/').unwrap_or(key).replace('/', "+");
                let dir = store.join(&bare).join("node_modules").join(name);
                let installed = dir.is_dir();
                if section == "packages" {
                    total += 1;
                    not_installed += usize::from(!installed);
                    if installed && inspected < MAX_INSPECTED {
                        inspected += 1;
                        if installs_something(&dir) {
                            names.insert(name.to_string());
                        }
                    }
                }
                if installed {
                    dirs.insert(name.to_string(), dir);
                }
            }
        }
        let covered = self.covers(declared, &pnpm_locked(&lock), &shown, out);
        let builds = PnpmBuilds::read(self, out);
        if builds.blocks_all() {
            out.push(finding(
                "install/dependency-scripts-blocked",
                Severity::Info,
                Some(shown),
                None,
                "pnpm 10 and later run no dependency build scripts unless allowed, and nothing is allowed here",
                None,
            ));
            return covered;
        }
        if total > 0 && inspected == 0 && names.is_empty() {
            self.unknown(
                &shown,
                "pnpm-lock.yaml does not say which packages run build scripts and node_modules is not installed; they may run",
                Severity::Warn,
                out,
            );
            return false;
        }
        if not_installed > 0 {
            self.unknown(
                &shown,
                &format!("{not_installed} packages in the lockfile are not in node_modules, so whether they run build scripts cannot be read; they may run"),
                Severity::Warn,
                out,
            );
        }
        if !names.is_empty() {
            self.report_pnpm_builds(&builds, &names, &dirs, &shown, out);
        }
        covered && not_installed == 0
    }

    fn report_pnpm_builds(
        &self,
        settings: &PnpmBuilds,
        names: &BTreeSet<String>,
        dirs: &BTreeMap<String, PathBuf>,
        shown: &str,
        out: &mut Vec<Finding>,
    ) {
        let dir_of = |n: &str| dirs.get(n).cloned();
        match settings.mode() {
            PnpmMode::RunsAll => self.report_dependencies(names, "will run", shown, &dir_of, out),
            PnpmMode::Unknown(problem) => {
                let why = problem.map_or_else(String::new, |p| format!(": {p}"));
                self.report_dependencies(
                    names,
                    &format!("may run (what pnpm allows is not known{why})"),
                    shown,
                    &dir_of,
                    out,
                );
            }
            PnpmMode::Gated => {
                let (allowed, blocked): (BTreeSet<_>, BTreeSet<_>) =
                    names.iter().cloned().partition(|n| settings.allows(n));
                self.report_dependencies(&allowed, "will run", shown, &dir_of, out);
                if !blocked.is_empty() {
                    out.push(finding(
                        "install/dependency-scripts-blocked",
                        Severity::Info,
                        Some(shown.into()),
                        None,
                        &format!(
                            "{} blocked by pnpm unless allowed: {}",
                            blocked.len(),
                            list(&blocked)
                        ),
                        None,
                    ));
                }
            }
        }
    }

    fn yarn_dependencies(&self, remote: &mut Remote, out: &mut Vec<Finding>) -> bool {
        let (path, shown) = self.root_file("yarn.lock");
        let lock = match read_optional(&path, MAX_LOCK_BYTES) {
            Ok(Some(t)) => t,
            Ok(None) => {
                self.unknown(
                    "yarn.lock",
                    "no lockfile found; dependencies may run install scripts",
                    Severity::Warn,
                    out,
                );
                return false;
            }
            Err(e) => {
                out.push(unchecked(&shown, e.describe()));
                return false;
            }
        };
        if !lock.contains("__metadata:") {
            self.unknown(
                &shown,
                "yarn 1 runs dependency scripts and its lockfile does not list them",
                Severity::Warn,
                out,
            );
            return false;
        }
        if let Ok(parsed) = serde_norway::from_str::<serde_norway::Value>(&lock) {
            for (key, entry) in parsed.as_mapping().into_iter().flatten() {
                let (Some(key), Some(res)) = (
                    key.as_str(),
                    entry.get("resolution").and_then(|r| r.as_str()),
                ) else {
                    continue;
                };
                let registry = ["@npm:", "@workspace:", "@patch:", "@builtin<"]
                    .iter()
                    .any(|m| res.contains(m));
                if !registry
                    && let Some(name) = key
                        .split(", ")
                        .next()
                        .and_then(pnpm_key_name)
                        .map(String::from)
                {
                    remote.insert(name, redact(res));
                }
            }
        }
        let rc = self.yaml(".yarnrc.yml", out);
        let setting = rc
            .as_ref()
            .and_then(|y| y.get("enableScripts"))
            .and_then(|v| v.as_bool());
        match setting {
            Some(false) => self.unknown(
                &shown,
                "yarn does not run dependency scripts while enableScripts is false (a package marked built in dependenciesMeta still runs, and an environment setting can override this)",
                Severity::Info,
                out,
            ),
            _ if self.skip_build => self.unknown(
                &shown,
                "yarn install --mode=skip-build runs no build scripts",
                Severity::Info,
                out,
            ),
            Some(true) => out.push(finding(
                "install/dependency-scripts",
                Severity::Warn,
                Some(self.root_file(".yarnrc.yml").1),
                None,
                "enableScripts is on: dependencies may run install scripts and yarn.lock does not list them",
                None,
            )),
            None => self.unknown(
                &shown,
                "yarn runs dependency build scripts unless enableScripts is false, and yarn.lock does not list them; they may run",
                Severity::Warn,
                out,
            ),
        }
        false
    }

    fn unknown(&self, file: &str, why: &str, severity: Severity, out: &mut Vec<Finding>) {
        out.push(finding(
            "install/dependency-scripts-unknown",
            severity,
            Some(file.into()),
            None,
            why,
            None,
        ));
    }

    /// One grouped finding for the dependencies that run scripts; a package already installed in
    /// `node_modules` has its script text judged too, and a fetch-and-run one is a block.
    fn report_dependencies(
        &self,
        names: &BTreeSet<String>,
        verb: &str,
        file: &str,
        dir_of: &dyn Fn(&str) -> Option<PathBuf>,
        out: &mut Vec<Finding>,
    ) {
        if names.is_empty() {
            return;
        }
        out.push(finding(
            "install/dependency-scripts",
            Severity::Warn,
            Some(file.into()),
            None,
            &format!(
                "{} packages {verb} install scripts: {}",
                names.len(),
                list(names)
            ),
            None,
        ));
        for name in names.iter().take(MAX_MEMBERS) {
            let Some(dir) = dir_of(name) else { continue };
            let path = dir.join("package.json");
            let (json, text) = match manifest_if_present(&path) {
                Ok(Some(m)) => m,
                Ok(None) => continue,
                Err(why) => {
                    out.push(unchecked(&shown(&path, self.cwd), why));
                    continue;
                }
            };
            let mut found = Vec::new();
            self.list_scripts(&dir, &json, &text, false, Some(name), &mut found);
            out.extend(found.into_iter().filter(|f| f.severity == Severity::Block));
        }
    }
}

/// What the last `ignore-scripts` assignment says, if there is one; `;` and `#` start a
/// comment line.
fn npmrc_ignores_scripts(text: &str) -> Option<bool> {
    let mut off = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with(['#', ';']) {
            continue;
        }
        if let Some((key, value)) = line.split_once('=')
            && key.trim() == "ignore-scripts"
        {
            off = Some(value.trim().trim_matches(['"', '\'']) == "true");
        }
    }
    off
}

/// Whether an `.npmrc` sets a key that allows dependency builds to run (pnpm 10 still reads
/// them there): `dangerously-allow-all-builds` unless false, or any `only-built-dependencies`
/// or `allow-build` form. Which packages a list names is not read, so it counts as all.
fn npmrc_allows_builds(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with(['#', ';']))
        .filter_map(|line| line.split_once('='))
        .any(|(key, value)| {
            config_key_allows_builds(key.trim(), Some(value.trim().trim_matches(['"', '\''])))
        })
}

/// The `dependencies`, `devDependencies` and `optionalDependencies` of a manifest. Specs that
/// fetch from git or a URL go into `remote` too.
fn collect_dependencies(json: &serde_json::Value, declared: &mut Declared, remote: &mut Remote) {
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(map) = json.get(section).and_then(|d| d.as_object()) else {
            continue;
        };
        for (name, spec) in map {
            let spec = spec.as_str().unwrap_or("");
            if is_remote_spec(spec) {
                remote.insert(name.clone(), redact(spec));
            }
            declared.push((name.clone(), spec.to_string()));
        }
    }
}

/// A dependency spec that npm and pnpm fetch from git, a URL or disk instead of the registry,
/// and so may build (`prepare`) as well as run install scripts.
fn is_remote_spec(spec: &str) -> bool {
    const SCHEMES: &[&str] = &[
        "git+",
        "git:",
        "ssh:",
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
        "http:",
        "https:",
        "file:",
        "link:",
        "portal:",
    ];
    if SCHEMES.iter().any(|s| spec.starts_with(s)) {
        return true;
    }
    // `owner/repo` shorthand for a GitHub repository.
    let (path, _) = spec.split_once('#').unwrap_or((spec, ""));
    let word = |w: &str| {
        !w.is_empty()
            && !w.starts_with('.')
            && w.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    };
    path.split_once('/')
        .is_some_and(|(owner, repo)| word(owner) && word(repo))
}

/// A lockfile `resolved` that is an https tarball from a registry, not a git or file source.
fn is_registry_tarball(resolved: &str) -> bool {
    resolved.starts_with("https://")
        && resolved
            .split(['?', '#'])
            .next()
            .is_some_and(|p| p.ends_with(".tgz"))
}

/// Names of the dependencies the lockfile's importers (or older top-level maps) list.
fn pnpm_locked(lock: &serde_norway::Value) -> HashSet<String> {
    let mut sources: Vec<&serde_norway::Value> = vec![lock];
    sources.extend(
        lock.get("importers")
            .and_then(|i| i.as_mapping())
            .into_iter()
            .flat_map(|m| m.values()),
    );
    let mut names = HashSet::new();
    for source in sources {
        for section in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "specifiers",
        ] {
            for key in source
                .get(section)
                .and_then(|d| d.as_mapping())
                .into_iter()
                .flat_map(|m| m.keys())
            {
                if let Some(name) = key.as_str() {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

/// `name@1.0.0(peer@2)` (v6, v9), `/name@1.0.0` or `/name/1.0.0` (v5) to `name`.
fn pnpm_key_name(key: &str) -> Option<&str> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let key = key.split_once('(').map_or(key, |(head, _)| head);
    let body = key.strip_prefix('@').unwrap_or(key);
    match body.find('@') {
        Some(at) => Some(&key[..key.len() - body.len() + at]),
        None => key.rsplit_once('/').map(|(name, _)| name),
    }
}

enum PnpmMode {
    RunsAll,
    Gated,
    Unknown(Option<String>),
}

/// What pnpm allows to build, from `pnpm-workspace.yaml` and the `pnpm` key of package.json:
/// `onlyBuiltDependencies` (pnpm 10), `allowBuilds` (pnpm 11) and `dangerouslyAllowAllBuilds`.
/// The root package.json is read once: it holds the `pnpm` key and the `packageManager` version.
struct PnpmBuilds {
    allow_all: bool,
    allowed: Vec<globset::GlobMatcher>,
    major: Option<u32>,
    manifest_problem: Option<String>,
    /// An `onlyBuiltDependenciesFile` that could not be read: what it allows is then unknown.
    file_problem: Option<String>,
}

impl PnpmBuilds {
    fn read(p: &Project, out: &mut Vec<Finding>) -> Self {
        let mut me = PnpmBuilds {
            allow_all: false,
            allowed: Vec::new(),
            major: None,
            manifest_problem: None,
            file_problem: None,
        };
        let mut sources = Vec::new();
        sources.extend(p.yaml("pnpm-workspace.yaml", out));
        let (path, shown) = p.root_file("package.json");
        match manifest_if_present(&path) {
            Ok(Some((json, _))) => {
                me.major = json
                    .get("packageManager")
                    .and_then(|v| v.as_str())
                    .and_then(|pm| pm.strip_prefix("pnpm@"))
                    .and_then(|v| v.split('.').next().and_then(|m| m.parse::<u32>().ok()));
                if let Some(pnpm) = json.get("pnpm")
                    && let Ok(v) = serde_norway::to_value(pnpm)
                {
                    sources.push(v);
                }
            }
            Ok(None) => {}
            Err(why) => {
                me.manifest_problem = Some(format!("{shown} {why}"));
            }
        }
        me.allow_all = p.allows_builds;
        for (path, name) in [p.file(".npmrc"), p.root_file(".npmrc")] {
            match read_optional(&path, MAX_TEXT_BYTES) {
                Ok(Some(text)) => me.allow_all |= npmrc_allows_builds(&text),
                Ok(None) => {}
                Err(e) => {
                    out.push(unchecked(&name, e.describe()));
                    me.file_problem = Some(format!("{name} could not be read"));
                }
            }
            if p.root == p.dir {
                break;
            }
        }
        for source in sources {
            if let Some(file) = source
                .get("onlyBuiltDependenciesFile")
                .and_then(|v| v.as_str())
            {
                me.read_allow_file(p, file);
            }
            if source
                .get("dangerouslyAllowAllBuilds")
                .and_then(|v| v.as_bool())
                == Some(true)
            {
                me.allow_all = true;
            }
            for entry in source
                .get("onlyBuiltDependencies")
                .and_then(|v| v.as_sequence())
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str())
            {
                me.add(entry);
            }
            for (key, value) in source
                .get("allowBuilds")
                .and_then(|v| v.as_mapping())
                .into_iter()
                .flatten()
            {
                if value.as_bool() == Some(true)
                    && let Some(key) = key.as_str()
                {
                    me.add(key);
                }
            }
        }
        me
    }

    /// The JSON array of package names in `onlyBuiltDependenciesFile`, a path that stays inside the project once symlinks are resolved.
    fn read_allow_file(&mut self, p: &Project, file: &str) {
        let inside = std::fs::canonicalize(&p.root)
            .ok()
            .zip(std::fs::canonicalize(p.root.join(file)).ok())
            .filter(|(root, target)| target.starts_with(root));
        let names = inside
            .and_then(|(_, target)| read_optional(&target, MAX_TEXT_BYTES).ok().flatten())
            .and_then(|text| serde_json::from_str::<Vec<String>>(&text).ok());
        match names {
            Some(names) => names.iter().for_each(|n| self.add(n)),
            None => self.file_problem = Some(format!("{file} could not be read")),
        }
    }

    /// A `name@version || version` entry allows the package name; the version part is ignored,
    /// which can only show more than pnpm would run.
    fn add(&mut self, entry: &str) {
        let body = entry.strip_prefix('@').unwrap_or(entry);
        let name = match body.find('@') {
            Some(at) => &entry[..entry.len() - body.len() + at],
            None => entry,
        };
        if let Ok(glob) = Glob::new(name) {
            self.allowed.push(glob.compile_matcher());
        }
    }

    /// pnpm 10 or later with no setting that allows any build: every dependency build is blocked.
    fn blocks_all(&self) -> bool {
        self.major.is_some_and(|m| m >= 10)
            && !self.allow_all
            && self.allowed.is_empty()
            && self.file_problem.is_none()
    }

    fn allows(&self, name: &str) -> bool {
        self.allow_all || self.allowed.iter().any(|g| g.is_match(name))
    }

    /// An unreadable package.json (already reported once by the project scan) leaves the version unknown, which shows more, and says why.
    fn mode(&self) -> PnpmMode {
        match self.major {
            Some(major) if major < 10 => PnpmMode::RunsAll,
            _ if self.file_problem.is_some() => PnpmMode::Unknown(self.file_problem.clone()),
            Some(_) => PnpmMode::Gated,
            None => PnpmMode::Unknown(self.manifest_problem.clone()),
        }
    }
}

/// A package.json that may legitimately be absent; a file that is there but cannot be read,
/// is too big or is not JSON is an error naming why, never a silent skip.
fn manifest_if_present(path: &Path) -> Result<Option<(serde_json::Value, String)>, &'static str> {
    let Some(text) = read_optional(path, MAX_TEXT_BYTES).map_err(ReadError::describe)? else {
        return Ok(None);
    };
    match serde_json::from_str(text.trim_start_matches('\u{feff}')) {
        Ok(v) => Ok(Some((v, text))),
        Err(_) => Err("is not valid JSON"),
    }
}

/// Whether an installed package's manifest has a script npm and pnpm run when installing it.
fn installs_something(dir: &Path) -> bool {
    // npm and node-gyp build a package with a binding.gyp and no install script on their own.
    if dir.join("binding.gyp").is_file() {
        return true;
    }
    let Ok(Some(text)) = read_optional(&dir.join("package.json"), MAX_TEXT_BYTES) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    ["preinstall", "install", "postinstall"]
        .iter()
        .any(|s| json.pointer(&format!("/scripts/{s}")).is_some())
}
