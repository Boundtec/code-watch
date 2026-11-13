use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use globset::Glob;

use super::read::{MAX_LOCK_BYTES, MAX_TEXT_BYTES, ReadError, read_optional};
use super::{Judge, finding, shown, unchecked};
use crate::finding::{Finding, Severity};

/// The scripts a project install may run, in npm's order (npm docs, using-npm/scripts, read
/// 2026-11-13). pnpm and yarn run a subset; listing the superset errs toward showing more.
const SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
];

/// Dependency names listed in one finding before "and N more".
const LISTED_NAMES: usize = 20;
/// Workspace members and flagged dependencies whose own manifest is read.
const MAX_MEMBERS: usize = 50;
/// Installed manifests read to find dependency scripts.
const MAX_INSPECTED: usize = 5000;

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
    "clean-install",
    "it",
    "cit",
    "install-test",
    "install-ci-test",
];

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
];

struct Invocation {
    global: bool,
    packages: Vec<String>,
    dir: PathBuf,
    ignore_scripts: bool,
}

fn parse(manager: &str, args: &[String], here: &Path) -> Option<Invocation> {
    let mut global = false;
    let mut ignore_scripts = false;
    let mut dir = here.to_path_buf();
    let mut positionals: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if arg.starts_with('-') => (f, Some(v)),
            _ => (arg, None),
        };
        match flag {
            "-g" | "--global" => global = true,
            "--location" if inline == Some("global") => global = true,
            "--ignore-scripts" => ignore_scripts = inline != Some("false"),
            "--no-ignore-scripts" => ignore_scripts = false,
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
    let mut rest = positionals.into_iter();
    let sub = rest.next();
    let mut packages: Vec<String> = rest.map(String::from).collect();
    match (manager, sub) {
        ("yarn", None) => {}
        ("yarn", Some("global")) => {
            if packages.first().map(String::as_str) != Some("add") {
                return None;
            }
            packages.remove(0);
            global = true;
        }
        (_, Some(s)) if is_install(manager, s) => {}
        _ => return None,
    }
    if matches!(sub, Some("ci" | "clean-install" | "cit")) {
        packages.clear();
    }
    Some(Invocation {
        global,
        packages,
        dir,
        ignore_scripts,
    })
}

fn is_install(manager: &str, sub: &str) -> bool {
    match manager {
        "npm" => INSTALL_WORDS.contains(&sub),
        "pnpm" => matches!(sub, "install" | "i" | "add"),
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
    let Some(inv) = parse(manager, args, here) else {
        return Vec::new();
    };
    if inv.global {
        return inv
            .packages
            .iter()
            .map(|spec| {
                finding(
                    "install/global-package",
                    Severity::Warn,
                    None,
                    None,
                    &format!("{manager} global install of {spec}"),
                    Some(package_name(spec).to_string()),
                )
            })
            .collect();
    }
    let mut out = Vec::new();
    let project = Project {
        manager,
        dir: &inv.dir,
        cwd,
        judge,
    };
    if inv.ignore_scripts || project.scripts_off(&mut out) {
        out.push(finding(
            "install/no-scripts",
            Severity::Info,
            None,
            None,
            &format!("{manager} install with scripts turned off"),
            None,
        ));
        return out;
    }
    project.own_scripts(!inv.packages.is_empty(), &mut out);
    project.dependency_scripts(&mut out);
    if !out.iter().any(|f| {
        matches!(
            f.rule_id.as_str(),
            "install/lifecycle-script"
                | "install/lifecycle-script-fetch-run"
                | "install/dependency-scripts"
                | super::RULE_UNCHECKED
        )
    }) {
        out.push(finding(
            "install/no-script-found",
            Severity::Info,
            Some(shown(&inv.dir.join("package.json"), cwd)),
            None,
            "no install script in package.json or the lockfile",
            None,
        ));
    }
    out
}

struct Project<'a> {
    manager: &'a str,
    dir: &'a Path,
    cwd: &'a Path,
    judge: &'a Judge<'a>,
}

impl Project<'_> {
    fn file(&self, name: &str) -> (PathBuf, String) {
        let path = self.dir.join(name);
        let shown = shown(&path, self.cwd);
        (path, shown)
    }

    /// Whether the project's own settings turn install scripts off. An unreadable settings
    /// file is reported and then counts as not off.
    fn scripts_off(&self, out: &mut Vec<Finding>) -> bool {
        match self.manager {
            "pnpm" => self
                .yaml("pnpm-workspace.yaml", out)
                .is_some_and(|y| y.get("ignoreScripts").and_then(|v| v.as_bool()) == Some(true)),
            _ => {
                let (path, name) = self.file(".npmrc");
                match read_optional(&path, MAX_TEXT_BYTES) {
                    Ok(Some(text)) => npmrc_ignores_scripts(&text),
                    Ok(None) => false,
                    Err(e) => {
                        out.push(unchecked(&name, e.describe()));
                        false
                    }
                }
            }
        }
    }

    fn yaml(&self, name: &str, out: &mut Vec<Finding>) -> Option<serde_norway::Value> {
        let (path, shown) = self.file(name);
        match read_optional(&path, MAX_TEXT_BYTES) {
            Ok(None) => None,
            Ok(Some(text)) => match serde_norway::from_str(&text) {
                Ok(v) => Some(v),
                Err(_) => {
                    out.push(unchecked(&shown, "is not valid YAML"));
                    None
                }
            },
            Err(e) => {
                out.push(unchecked(&shown, e.describe()));
                None
            }
        }
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

    fn own_scripts(&self, named_packages: bool, out: &mut Vec<Finding>) {
        let Some((root, text)) = self.package_json(self.dir, out) else {
            return;
        };
        self.list_scripts(self.dir, &root, &text, named_packages, None, out);
        for member in self.workspace_dirs(&root, out) {
            if let Some((json, text)) = self.package_json(&member, out) {
                self.list_scripts(&member, &json, &text, false, None, out);
            }
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

    fn dependency_scripts(&self, out: &mut Vec<Finding>) {
        match self.manager {
            "npm" => self.npm_dependencies(out),
            "pnpm" => self.pnpm_dependencies(out),
            _ => self.yarn_dependencies(out),
        }
    }

    fn npm_dependencies(&self, out: &mut Vec<Finding>) {
        for name in [
            "package-lock.json",
            "npm-shrinkwrap.json",
            "node_modules/.package-lock.json",
        ] {
            let (path, shown) = self.file(name);
            let text = match read_optional(&path, MAX_LOCK_BYTES) {
                Ok(Some(t)) => t,
                Ok(None) => continue,
                Err(e) => {
                    out.push(unchecked(&shown, e.describe()));
                    return;
                }
            };
            let Ok(lock) =
                serde_json::from_str::<serde_json::Value>(text.trim_start_matches('\u{feff}'))
            else {
                out.push(unchecked(&shown, "is not valid JSON"));
                return;
            };
            let Some(packages) = lock.get("packages").and_then(|p| p.as_object()) else {
                self.unknown(
                    &shown,
                    "this lockfile version does not record install scripts",
                    out,
                );
                return;
            };
            let names: BTreeSet<String> = packages
                .iter()
                .filter(|(_, e)| e.get("hasInstallScript").and_then(|v| v.as_bool()) == Some(true))
                .map(|(key, e)| {
                    let tail = key
                        .rsplit_once("node_modules/")
                        .map_or(key.as_str(), |(_, t)| t);
                    e.get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or(tail)
                        .to_string()
                })
                .collect();
            self.report_dependencies(
                &names,
                "will run",
                &shown,
                &|n| Some(self.dir.join("node_modules").join(n)),
                out,
            );
            return;
        }
        self.unknown(
            "package-lock.json",
            "no lockfile or node_modules found",
            out,
        );
    }

    /// pnpm 10's lockfile does not record which packages build (`requiresBuild` is only written
    /// by older versions), so a package counts when the lock flags it or its installed
    /// manifest under `node_modules/.pnpm` has an install-time script.
    fn pnpm_dependencies(&self, out: &mut Vec<Finding>) {
        let (path, shown) = self.file("pnpm-lock.yaml");
        let text = match read_optional(&path, MAX_LOCK_BYTES) {
            Ok(Some(t)) => t,
            Ok(None) => return self.unknown("pnpm-lock.yaml", "no lockfile found", out),
            Err(e) => return out.push(unchecked(&shown, e.describe())),
        };
        let Ok(lock) = serde_norway::from_str::<serde_norway::Value>(&text) else {
            return out.push(unchecked(&shown, "is not valid YAML"));
        };
        let mut names = BTreeSet::new();
        let mut dirs: BTreeMap<String, PathBuf> = BTreeMap::new();
        let mut inspected = 0usize;
        let store = self.dir.join("node_modules/.pnpm");
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
                let bare = key.strip_prefix('/').unwrap_or(key).replace('/', "+");
                let dir = store.join(&bare).join("node_modules").join(name);
                if section == "packages" && dir.is_dir() && inspected < MAX_INSPECTED {
                    inspected += 1;
                    if installs_something(&dir) {
                        names.insert(name.to_string());
                    }
                }
                if dir.is_dir() {
                    dirs.insert(name.to_string(), dir);
                }
            }
        }
        if inspected == 0 && names.is_empty() {
            return self.unknown(
                &shown,
                "pnpm-lock.yaml does not say which packages run build scripts and node_modules is not installed",
                out,
            );
        }
        if names.is_empty() {
            return;
        }
        let settings = PnpmBuilds::read(self, out);
        let dir_of = |n: &str| dirs.get(n).cloned();
        match settings.mode(self) {
            PnpmMode::RunsAll => self.report_dependencies(&names, "will run", &shown, &dir_of, out),
            PnpmMode::Unknown => self.report_dependencies(
                &names,
                "may run (the pnpm version is not known)",
                &shown,
                &dir_of,
                out,
            ),
            PnpmMode::Gated => {
                let (allowed, blocked): (BTreeSet<_>, BTreeSet<_>) =
                    names.into_iter().partition(|n| settings.allows(n));
                self.report_dependencies(&allowed, "will run", &shown, &dir_of, out);
                if !blocked.is_empty() {
                    out.push(finding(
                        "install/dependency-scripts-blocked",
                        Severity::Info,
                        Some(shown),
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

    fn yarn_dependencies(&self, out: &mut Vec<Finding>) {
        let (path, shown) = self.file("yarn.lock");
        let lock = match read_optional(&path, MAX_LOCK_BYTES) {
            Ok(Some(t)) => t,
            Ok(None) => return self.unknown("yarn.lock", "no lockfile found", out),
            Err(e) => return out.push(unchecked(&shown, e.describe())),
        };
        if !lock.contains("__metadata:") {
            return self.unknown(
                &shown,
                "yarn 1 runs dependency scripts and its lockfile does not list them",
                out,
            );
        }
        let rc = self.yaml(".yarnrc.yml", out);
        let enabled = rc
            .as_ref()
            .and_then(|y| y.get("enableScripts"))
            .and_then(|v| v.as_bool())
            == Some(true);
        if enabled {
            out.push(finding(
                "install/dependency-scripts",
                Severity::Warn,
                Some(self.file(".yarnrc.yml").1),
                None,
                "enableScripts is on: dependencies may run install scripts and yarn.lock does not list them",
                None,
            ));
        } else {
            self.unknown(
                &shown,
                "yarn does not run dependency scripts unless enableScripts is on",
                out,
            );
        }
    }

    fn unknown(&self, file: &str, why: &str, out: &mut Vec<Finding>) {
        out.push(finding(
            "install/dependency-scripts-unknown",
            Severity::Info,
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
            let Ok(Some(text)) = read_optional(&dir.join("package.json"), MAX_TEXT_BYTES) else {
                continue;
            };
            let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            let mut found = Vec::new();
            self.list_scripts(&dir, &json, &text, false, Some(name), &mut found);
            out.extend(found.into_iter().filter(|f| f.severity == Severity::Block));
        }
    }
}

fn list(names: &BTreeSet<String>) -> String {
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

/// Last assignment wins; `;` and `#` start a comment line.
fn npmrc_ignores_scripts(text: &str) -> bool {
    let mut off = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with(['#', ';']) {
            continue;
        }
        if let Some((key, value)) = line.split_once('=')
            && key.trim() == "ignore-scripts"
        {
            off = value.trim().trim_matches(['"', '\'']) == "true";
        }
    }
    off
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
    Unknown,
}

/// What pnpm allows to build, from `pnpm-workspace.yaml` and the `pnpm` key of package.json:
/// `onlyBuiltDependencies` (pnpm 10), `allowBuilds` (pnpm 11) and `dangerouslyAllowAllBuilds`
/// (pnpm docs, settings/build, read 2026-11-13).
struct PnpmBuilds {
    allow_all: bool,
    allowed: Vec<globset::GlobMatcher>,
}

impl PnpmBuilds {
    fn read(p: &Project, out: &mut Vec<Finding>) -> Self {
        let mut me = PnpmBuilds {
            allow_all: false,
            allowed: Vec::new(),
        };
        let mut sources = Vec::new();
        sources.extend(p.yaml("pnpm-workspace.yaml", out));
        let (path, _) = p.file("package.json");
        if let Ok(Some(text)) = read_optional(&path, MAX_TEXT_BYTES)
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
            && let Some(pnpm) = json.get("pnpm")
            && let Ok(v) = serde_norway::to_value(pnpm)
        {
            sources.push(v);
        }
        for source in sources {
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

    fn allows(&self, name: &str) -> bool {
        self.allow_all || self.allowed.iter().any(|g| g.is_match(name))
    }

    fn mode(&self, p: &Project) -> PnpmMode {
        let (path, _) = p.file("package.json");
        let version = read_optional(&path, MAX_TEXT_BYTES)
            .ok()
            .flatten()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|j| {
                j.get("packageManager")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .and_then(|pm| pm.strip_prefix("pnpm@").map(String::from))
            .and_then(|v| v.split('.').next().and_then(|m| m.parse::<u32>().ok()));
        match version {
            Some(major) if major >= 10 => PnpmMode::Gated,
            Some(_) => PnpmMode::RunsAll,
            None => PnpmMode::Unknown,
        }
    }
}

/// Whether an installed package's manifest has a script npm and pnpm run when installing it.
fn installs_something(dir: &Path) -> bool {
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
