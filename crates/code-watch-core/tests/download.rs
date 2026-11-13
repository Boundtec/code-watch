use std::fs;
use std::path::Path;

use code_watch_core::download::{Gatekeeper, Kind, MacTools, Signature, ToolError};
use code_watch_core::{Allowlists, Engine, Layer, LayerStatus, Severity, Verdict, render};

struct Fake {
    quarantine: bool,
    signature: Signature,
}

impl MacTools for Fake {
    fn quarantine(&self, _: &Path) -> Result<bool, ToolError> {
        Ok(self.quarantine)
    }
    fn signature(&self, _: &Path, _: Kind) -> Result<Signature, ToolError> {
        Ok(self.signature.clone())
    }
    fn gatekeeper(&self, _: &Path, _: Kind) -> Result<Gatekeeper, ToolError> {
        Ok(Gatekeeper::Accepted)
    }
}

fn unsigned() -> Fake {
    Fake {
        quarantine: true,
        signature: Signature::Unsigned,
    }
}

fn engine() -> Engine {
    Engine::embedded().unwrap()
}

fn allow(body: &str) -> (tempfile::TempDir, Allowlists) {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("code-watch")).unwrap();
    fs::write(
        dir.path().join("code-watch/allow.toml"),
        format!("schema = 1\n{body}"),
    )
    .unwrap();
    let lists = Allowlists::load(Some(dir.path()), None).unwrap();
    (dir, lists)
}

#[test]
fn an_unsigned_app_blocks_and_the_layer_ran() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("T.app")).unwrap();
    let r = engine()
        .check_download(
            &d.path().join("T.app"),
            Some(&unsigned()),
            &Allowlists::empty(),
        )
        .unwrap();
    assert_eq!(r.verdict(), Verdict::Block);
    assert_eq!(r.layers()[&Layer::Download], LayerStatus::Ran);
    assert_eq!(r.findings()[0].rule_id, "download/unsigned");
    assert!(render::to_human(&r).contains("layers: llm off, download ran"));
}

#[test]
fn without_tools_the_layer_is_skipped_with_its_reason_in_text_and_json() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("a.dmg"), b"x").unwrap();
    let r = engine()
        .check_download(&d.path().join("a.dmg"), None, &Allowlists::empty())
        .unwrap();
    assert_eq!(r.layers()[&Layer::Download], LayerStatus::Skipped);
    assert_eq!(r.findings().len(), 1);
    assert_eq!(r.findings()[0].rule_id, "download/unchecked");
    assert_eq!(r.verdict(), Verdict::Warn);
    assert!(render::to_human(&r).contains("download skipped (macOS only)"));
    let json: serde_json::Value = serde_json::from_str(&render::to_json(&r).unwrap()).unwrap();
    assert_eq!(json["layers"]["download"], "skipped");
    assert_eq!(json["skipped_layers"]["download"], "macOS only");
}

#[test]
fn a_missing_path_is_an_error_even_where_the_layer_is_skipped() {
    let d = tempfile::tempdir().unwrap();
    assert!(
        engine()
            .check_download(&d.path().join("nope"), None, &Allowlists::empty())
            .is_err()
    );
}

#[test]
fn an_allowlist_entry_hides_a_finding_by_rule_and_path_and_it_stays_listed() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("T.app")).unwrap();
    let app = d.path().join("T.app");
    let canonical = fs::canonicalize(&app).unwrap();
    let (_dir, lists) = allow(&format!(
        "[[allow]]\nrule = \"download/unsigned\"\npath = \"{}\"\n",
        canonical.display()
    ));
    let r = engine()
        .check_download(&app, Some(&unsigned()), &lists)
        .unwrap();
    assert_eq!(r.verdict(), Verdict::Allow);
    assert_eq!(r.suppressed().len(), 1);
    assert!(r.allowlist_warnings().is_empty());
    let (_dir, other) = allow("[[allow]]\nrule = \"download/unsigned\"\npath = \"/elsewhere/*\"\n");
    let r = engine()
        .check_download(&app, Some(&unsigned()), &other)
        .unwrap();
    assert_eq!(r.verdict(), Verdict::Block);
}

#[test]
fn download_rule_ids_are_known_to_the_allowlist() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("a.txt"), b"x").unwrap();
    let (_dir, lists) = allow("[[allow]]\nrule = \"download/unchecked\"\n");
    let r = engine()
        .check_download(&d.path().join("a.txt"), Some(&unsigned()), &lists)
        .unwrap();
    assert!(r.allowlist_warnings().is_empty());
}

#[test]
fn another_kind_is_allowed_with_the_layer_listed_as_ran() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("a.txt"), b"hello world").unwrap();
    let r = engine()
        .check_download(
            &d.path().join("a.txt"),
            Some(&unsigned()),
            &Allowlists::empty(),
        )
        .unwrap();
    assert_eq!(r.verdict(), Verdict::Allow);
    assert_eq!(r.findings()[0].severity, Severity::Info);
    assert_eq!(r.layers()[&Layer::Download], LayerStatus::Ran);
}

#[cfg(unix)]
#[test]
fn a_pipe_blocks_through_the_engine_and_no_tool_is_asked() {
    let d = tempfile::tempdir().unwrap();
    for name in ["pipe", "x.dmg"] {
        let path = d.path().join(name);
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success());
        let accepting = Fake {
            quarantine: true,
            signature: Signature::Valid,
        };
        let r = engine()
            .check_download(&path, Some(&accepting), &Allowlists::empty())
            .unwrap();
        assert_eq!(r.verdict(), Verdict::Block, "{name}");
        assert_eq!(r.findings()[0].rule_id, "download/unchecked", "{name}");
    }
}

#[cfg(target_os = "macos")]
mod real {
    use std::process::Command;

    use code_watch_core::download::MacOsTools;

    use super::*;

    fn run(path: &Path) -> code_watch_core::Report {
        engine()
            .check_download(path, Some(&MacOsTools::default()), &Allowlists::empty())
            .unwrap()
    }

    fn ids(r: &code_watch_core::Report) -> Vec<&str> {
        r.findings().iter().map(|f| f.rule_id.as_str()).collect()
    }

    fn ls_copy(dir: &Path, name: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        fs::copy("/bin/ls", &p).unwrap();
        let s = Command::new("/usr/bin/codesign")
            .args(["--remove-signature"])
            .arg(&p)
            .status()
            .unwrap();
        assert!(s.success());
        p
    }

    #[test]
    fn apple_signed_calculator_has_only_the_no_quarantine_note() {
        let r = run(Path::new("/System/Applications/Calculator.app"));
        assert_eq!(ids(&r), ["download/no-quarantine"]);
        assert_eq!(r.verdict(), Verdict::Allow);
    }

    #[test]
    fn an_unsigned_executable_blocks() {
        let d = tempfile::tempdir().unwrap();
        let r = run(&ls_copy(d.path(), "plain"));
        assert_eq!(ids(&r), ["download/unsigned", "download/no-quarantine"]);
        assert_eq!(r.verdict(), Verdict::Block);
    }

    #[test]
    fn an_ad_hoc_signed_executable_is_not_accepted_by_gatekeeper() {
        let d = tempfile::tempdir().unwrap();
        let p = ls_copy(d.path(), "adhoc");
        let s = Command::new("/usr/bin/codesign")
            .args(["-f", "-s", "-"])
            .arg(&p)
            .output()
            .unwrap();
        assert!(s.status.success());
        let r = run(&p);
        assert_eq!(ids(&r), ["download/not-accepted", "download/no-quarantine"]);
    }

    #[test]
    fn a_quarantine_mark_written_in_the_tempdir_is_seen() {
        let d = tempfile::tempdir().unwrap();
        let p = ls_copy(d.path(), "marked");
        let s = Command::new("/usr/bin/xattr")
            .args(["-w", "com.apple.quarantine", "0081;00000000;test;"])
            .arg(&p)
            .status()
            .unwrap();
        assert!(s.success());
        assert_eq!(ids(&run(&p)), ["download/unsigned"]);
    }

    #[test]
    fn an_unsigned_disk_image_only_warns_and_the_file_is_untouched() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.dmg");
        fs::write(&p, b"not really an image").unwrap();
        let before = (
            fs::read(&p).unwrap(),
            fs::metadata(&p).unwrap().modified().unwrap(),
        );
        let r = run(&p);
        assert_eq!(
            ids(&r),
            ["download/unsigned-image", "download/no-quarantine"]
        );
        assert_eq!(r.verdict(), Verdict::Warn);
        assert_eq!(
            before,
            (
                fs::read(&p).unwrap(),
                fs::metadata(&p).unwrap().modified().unwrap()
            )
        );
    }

    #[test]
    fn an_unsigned_pkg_blocks_through_pkgutil() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.pkg");
        let s = Command::new("/usr/bin/pkgbuild")
            .args(["--nopayload", "--identifier", "x.y"])
            .arg(&p)
            .output()
            .unwrap();
        assert!(s.status.success());
        assert_eq!(
            ids(&run(&p)),
            ["download/unsigned", "download/no-quarantine"]
        );
    }
}
