//! The downloads layer: checks a downloaded `.dmg`, `.pkg`, `.app` or executable before it is
//! opened. It only reads: it never changes the file, clears the quarantine mark or mounts an image.

mod exec;
mod mac;

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::finding::{Evidence, Finding, Layer, Severity};

pub use exec::{Exec, ExecError, Output, ProcessExec};
pub use mac::MacOsTools;

pub const RULE_UNSIGNED: &str = "download/unsigned";
pub const RULE_UNSIGNED_IMAGE: &str = "download/unsigned-image";
pub const RULE_BAD_SIGNATURE: &str = "download/bad-signature";
pub const RULE_NOT_ACCEPTED: &str = "download/not-accepted";
pub const RULE_NO_QUARANTINE: &str = "download/no-quarantine";
pub const RULE_UNCHECKED: &str = "download/unchecked";
pub const RULE_OTHER_KIND: &str = "download/not-checked-kind";
pub const RULE_IDS: [&str; 7] = [
    RULE_UNSIGNED,
    RULE_UNSIGNED_IMAGE,
    RULE_BAD_SIGNATURE,
    RULE_NOT_ACCEPTED,
    RULE_NO_QUARANTINE,
    RULE_UNCHECKED,
    RULE_OTHER_KIND,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dmg,
    Pkg,
    App,
    MachO,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    Valid,
    Unsigned,
    /// The signature is there and does not verify; the text is the tool's complaint.
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gatekeeper {
    Accepted,
    Rejected(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ToolError {
    #[error("{0} is not installed")]
    Missing(&'static str),
    #[error("{0} did not answer in time")]
    TimedOut(&'static str),
    #[error("{0} gave no usable answer ({1})")]
    Failed(&'static str, String),
}

/// What the layer asks the operating system. Every call is read-only.
pub trait MacTools {
    /// Whether the file carries the `com.apple.quarantine` mark.
    fn quarantine(&self, path: &Path) -> Result<bool, ToolError>;
    fn signature(&self, path: &Path, kind: Kind) -> Result<Signature, ToolError>;
    /// Whether Gatekeeper would open the file (notarized, or otherwise allowed).
    fn gatekeeper(&self, path: &Path, kind: Kind) -> Result<Gatekeeper, ToolError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadStatus {
    Ran,
    /// The layer is not available here; the text says why.
    Skipped(String),
}

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("{0} does not exist or cannot be read")]
    Unreadable(String),
}

/// A path the layer will look at: where it really is, and what kind it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub path: PathBuf,
    pub kind: Option<Kind>,
    /// A pipe, socket or device: never opened, because opening one can block with no end.
    pub special: bool,
}

/// Resolves the path (so the tools never see `..`, a link or a leading `-`) and names its kind.
/// Only regular files are opened and only directories are listed as bundles.
pub fn subject(path: &Path) -> Result<Subject, DownloadError> {
    let unreadable = || DownloadError::Unreadable(path.display().to_string());
    let meta = fs::metadata(path).map_err(|_| unreadable())?;
    let path = fs::canonicalize(path).map_err(|_| unreadable())?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let special = !meta.is_dir() && !meta.is_file();
    let kind = if special {
        None
    } else if meta.is_dir() {
        name.ends_with(".app").then_some(Kind::App)
    } else if name.ends_with(".dmg") {
        Some(Kind::Dmg)
    } else if name.ends_with(".pkg") {
        Some(Kind::Pkg)
    } else {
        is_macho(&path).then_some(Kind::MachO)
    };
    Ok(Subject {
        path,
        kind,
        special,
    })
}

/// Thin and fat Mach-O magics. `0xCAFEBABE` is also a Java class file, so it counts only when
/// the next word is a small architecture count.
fn is_macho(path: &Path) -> bool {
    let mut head = [0u8; 8];
    let read = File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    if read < 8 {
        return false;
    }
    let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let count = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    match magic {
        0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE => true,
        0xCAFE_BABE | 0xCAFE_BABF => (1..=30).contains(&count),
        _ => false,
    }
}

/// Runs the checks for one file and returns the findings. A signature or Gatekeeper check that
/// could not finish blocks, so a file cannot choose to be slow or odd enough to pass; only the
/// informational quarantine check may fail as a warning.
pub fn analyze(subject: &Subject, tools: &dyn MacTools) -> Vec<Finding> {
    let file = subject.path.display().to_string();
    if subject.special {
        return vec![finding(
            RULE_UNCHECKED,
            Severity::Block,
            "The file is not a regular file, so it was not checked",
            &file,
            "a pipe, socket or device",
            "Do not open it; get the file from the publisher's own site.",
        )];
    }
    let Some(kind) = subject.kind else {
        return vec![finding(
            RULE_OTHER_KIND,
            Severity::Info,
            "Not a kind this layer checks",
            &file,
            "Only .dmg, .pkg, .app bundles and executables are checked.",
            "",
        )];
    };
    let mut findings = Vec::new();
    match tools.quarantine(&subject.path) {
        Ok(true) => {}
        Ok(false) => findings.push(finding(
            RULE_NO_QUARANTINE,
            Severity::Info,
            "The file has no quarantine mark",
            &file,
            "macOS does not check a file without the mark when it is opened.",
            "Expected for a file that did not come through a browser; the other checks still apply.",
        )),
        Err(e) => findings.push(unchecked(&file, &e, Severity::Warn)),
    }
    let signature = tools.signature(&subject.path, kind);
    let signed_ok = match &signature {
        Ok(Signature::Valid) => true,
        Ok(Signature::Unsigned) => {
            findings.push(unsigned(kind, &file));
            false
        }
        Ok(Signature::Invalid(why)) => {
            findings.push(finding(
                RULE_BAD_SIGNATURE,
                Severity::Block,
                "The code signature does not verify",
                &file,
                why,
                "The file was changed or damaged. Do not open it; download it again from the publisher.",
            ));
            false
        }
        Err(e) => {
            findings.push(unchecked(&file, e, Severity::Block));
            false
        }
    };
    if signed_ok {
        match tools.gatekeeper(&subject.path, kind) {
            Ok(Gatekeeper::Accepted) => {}
            Ok(Gatekeeper::Rejected(why)) => findings.push(finding(
                RULE_NOT_ACCEPTED,
                Severity::Block,
                "Gatekeeper would not open this file",
                &file,
                &why,
                "It is not notarized or its certificate was revoked. Do not open it.",
            )),
            Err(e) => findings.push(unchecked(&file, &e, Severity::Block)),
        }
    }
    findings
}

fn unsigned(kind: Kind, file: &str) -> Finding {
    if kind == Kind::Dmg {
        return finding(
            RULE_UNSIGNED_IMAGE,
            Severity::Warn,
            "The disk image is not signed; the app inside is not checked",
            file,
            "code-watch never mounts an image.",
            "Get the app from its publisher, then run `code-watch download` on the app before opening it.",
        );
    }
    finding(
        RULE_UNSIGNED,
        Severity::Block,
        "The file is not code signed",
        file,
        "no signature found",
        "Do not open it; get it from the publisher's own site.",
    )
}

fn unchecked(file: &str, why: &ToolError, severity: Severity) -> Finding {
    let remediation = if severity == Severity::Block {
        "The signature check did not finish. Do not open the file until it has been checked."
    } else {
        "Check the file by hand; the verdict says nothing about this check."
    };
    finding(
        RULE_UNCHECKED,
        severity,
        "A check could not run",
        file,
        &why.to_string(),
        remediation,
    )
}

/// The finding for a platform with no tools: nothing was checked, and the exit code must not
/// look like a pass.
pub fn unavailable(subject: &Subject) -> Finding {
    finding(
        RULE_UNCHECKED,
        Severity::Warn,
        "The download check is not available on this platform",
        &subject.path.display().to_string(),
        "macOS only",
        "Nothing was checked. Verify the file by hand before opening it.",
    )
}

fn finding(
    rule: &str,
    severity: Severity,
    title: &str,
    file: &str,
    excerpt: &str,
    remediation: &str,
) -> Finding {
    Finding {
        rule_id: rule.into(),
        severity,
        layer: Layer::Download,
        title: title.into(),
        evidence: Evidence::new(Some(file.into()), None, excerpt),
        remediation: remediation.into(),
        domain: None,
        package: None,
        advisories: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    struct Fake {
        quarantine: Result<bool, ToolError>,
        signature: Result<Signature, ToolError>,
        gatekeeper: Result<Gatekeeper, ToolError>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl Fake {
        fn good() -> Self {
            Self {
                quarantine: Ok(true),
                signature: Ok(Signature::Valid),
                gatekeeper: Ok(Gatekeeper::Accepted),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl MacTools for Fake {
        fn quarantine(&self, _: &Path) -> Result<bool, ToolError> {
            self.calls.borrow_mut().push("quarantine");
            self.quarantine.clone()
        }
        fn signature(&self, _: &Path, _: Kind) -> Result<Signature, ToolError> {
            self.calls.borrow_mut().push("signature");
            self.signature.clone()
        }
        fn gatekeeper(&self, _: &Path, _: Kind) -> Result<Gatekeeper, ToolError> {
            self.calls.borrow_mut().push("gatekeeper");
            self.gatekeeper.clone()
        }
    }

    fn subj(kind: Option<Kind>) -> Subject {
        Subject {
            path: PathBuf::from("/d/f"),
            kind,
            special: false,
        }
    }

    fn run(fake: &Fake, kind: Kind) -> Vec<(String, Severity)> {
        analyze(&subj(Some(kind)), fake)
            .into_iter()
            .map(|f| (f.rule_id, f.severity))
            .collect()
    }

    fn timed_out() -> ToolError {
        ToolError::TimedOut("x")
    }

    #[test]
    fn a_signed_notarized_quarantined_file_has_no_findings() {
        let fake = Fake::good();
        assert!(run(&fake, Kind::App).is_empty());
        assert_eq!(
            *fake.calls.borrow(),
            ["quarantine", "signature", "gatekeeper"]
        );
    }

    #[test]
    fn unsigned_blocks_and_gatekeeper_is_not_asked() {
        let fake = Fake {
            signature: Ok(Signature::Unsigned),
            ..Fake::good()
        };
        for kind in [Kind::App, Kind::Pkg, Kind::MachO] {
            assert_eq!(run(&fake, kind), [(RULE_UNSIGNED.into(), Severity::Block)]);
        }
        assert!(!fake.calls.borrow().contains(&"gatekeeper"));
    }

    #[test]
    fn the_unsigned_image_advice_points_at_the_publisher_not_at_opening_the_image() {
        let advice = unsigned(Kind::Dmg, "x.dmg").remediation;
        assert!(advice.contains("publisher") && !advice.to_lowercase().contains("open the image"));
    }

    #[test]
    fn an_unsigned_disk_image_only_warns_and_says_the_app_inside_is_not_checked() {
        let fake = Fake {
            signature: Ok(Signature::Unsigned),
            ..Fake::good()
        };
        assert_eq!(
            run(&fake, Kind::Dmg),
            [(RULE_UNSIGNED_IMAGE.into(), Severity::Warn)]
        );
        let f = analyze(&subj(Some(Kind::Dmg)), &fake);
        assert!(f[0].title.contains("app inside is not checked"));
        assert!(f[0].remediation.contains("code-watch download"));
    }

    #[test]
    fn an_invalid_signature_blocks_for_every_kind_even_a_dmg() {
        let fake = Fake {
            signature: Ok(Signature::Invalid("sealed resource missing".into())),
            ..Fake::good()
        };
        for kind in [Kind::App, Kind::Dmg, Kind::Pkg, Kind::MachO] {
            assert_eq!(
                run(&fake, kind),
                [(RULE_BAD_SIGNATURE.into(), Severity::Block)]
            );
        }
        assert!(!fake.calls.borrow().contains(&"gatekeeper"));
    }

    #[test]
    fn a_signed_file_gatekeeper_rejects_blocks_for_every_kind_even_a_dmg() {
        let fake = Fake {
            gatekeeper: Ok(Gatekeeper::Rejected(
                "source=Unnotarized Developer ID".into(),
            )),
            ..Fake::good()
        };
        for kind in [Kind::App, Kind::Dmg, Kind::Pkg, Kind::MachO] {
            assert_eq!(
                run(&fake, kind),
                [(RULE_NOT_ACCEPTED.into(), Severity::Block)]
            );
        }
    }

    #[test]
    fn no_quarantine_mark_is_info_only() {
        let fake = Fake {
            quarantine: Ok(false),
            ..Fake::good()
        };
        assert_eq!(
            run(&fake, Kind::App),
            [(RULE_NO_QUARANTINE.into(), Severity::Info)]
        );
    }

    #[test]
    fn a_failed_quarantine_check_warns() {
        let fake = Fake {
            quarantine: Err(timed_out()),
            ..Fake::good()
        };
        assert_eq!(
            run(&fake, Kind::App),
            [(RULE_UNCHECKED.into(), Severity::Warn)]
        );
    }

    #[test]
    fn a_signature_check_that_could_not_finish_blocks_and_gatekeeper_is_not_asked() {
        let errors = [
            timed_out(),
            ToolError::Missing("codesign"),
            ToolError::Failed("codesign", "exit code 9".into()),
        ];
        for error in errors {
            let fake = Fake {
                signature: Err(error),
                ..Fake::good()
            };
            assert_eq!(
                run(&fake, Kind::App),
                [(RULE_UNCHECKED.into(), Severity::Block)]
            );
            assert!(!fake.calls.borrow().contains(&"gatekeeper"));
        }
    }

    #[test]
    fn a_gatekeeper_check_that_could_not_finish_blocks_for_every_error_and_kind() {
        let errors = [
            timed_out(),
            ToolError::Missing("spctl"),
            ToolError::Failed("spctl", "exit code 1".into()),
        ];
        for error in errors {
            for kind in [Kind::App, Kind::Dmg, Kind::Pkg, Kind::MachO] {
                let fake = Fake {
                    gatekeeper: Err(error.clone()),
                    ..Fake::good()
                };
                assert_eq!(run(&fake, kind), [(RULE_UNCHECKED.into(), Severity::Block)]);
            }
        }
    }

    #[test]
    fn both_checks_timing_out_blocks_with_a_plain_reason() {
        let fake = Fake {
            signature: Err(timed_out()),
            gatekeeper: Err(timed_out()),
            ..Fake::good()
        };
        let found = analyze(&subj(Some(Kind::App)), &fake);
        assert!(found.iter().any(|f| f.severity == Severity::Block));
        assert!(found.iter().all(|f| f.rule_id == RULE_UNCHECKED));
        assert!(
            found
                .iter()
                .any(|f| f.remediation.contains("signature check did not finish"))
        );
    }

    #[test]
    fn a_file_that_is_not_regular_blocks_without_asking_any_tool() {
        let fake = Fake::good();
        let special = Subject {
            special: true,
            ..subj(None)
        };
        let found: Vec<_> = analyze(&special, &fake)
            .into_iter()
            .map(|f| (f.rule_id, f.severity))
            .collect();
        assert_eq!(found, [(RULE_UNCHECKED.into(), Severity::Block)]);
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn no_tools_is_a_warning_finding_not_silence() {
        let f = unavailable(&subj(None));
        assert_eq!(
            (f.rule_id.as_str(), f.severity),
            (RULE_UNCHECKED, Severity::Warn)
        );
        assert!(f.title.contains("not available on this platform"));
    }

    #[test]
    fn many_findings_come_out_in_check_order() {
        let fake = Fake {
            quarantine: Ok(false),
            signature: Ok(Signature::Unsigned),
            ..Fake::good()
        };
        assert_eq!(
            run(&fake, Kind::App),
            [
                (RULE_NO_QUARANTINE.into(), Severity::Info),
                (RULE_UNSIGNED.into(), Severity::Block)
            ]
        );
    }

    #[test]
    fn another_kind_is_one_info_finding_and_no_tool_runs() {
        let fake = Fake::good();
        let f = analyze(&subj(None), &fake);
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].rule_id.as_str(), f[0].severity),
            (RULE_OTHER_KIND, Severity::Info)
        );
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn evidence_carries_the_resolved_path_and_the_findings_are_download_layer() {
        let fake = Fake {
            signature: Ok(Signature::Unsigned),
            ..Fake::good()
        };
        let f = analyze(&subj(Some(Kind::App)), &fake);
        assert_eq!(f[0].evidence.file.as_deref(), Some("/d/f"));
        assert_eq!(f[0].layer, Layer::Download);
    }

    #[test]
    fn a_tool_complaint_with_escape_sequences_reaches_the_finding_cleaned() {
        let fake = Fake {
            signature: Ok(Signature::Invalid("\u{1b}[31mred".into())),
            ..Fake::good()
        };
        let f = analyze(&subj(Some(Kind::App)), &fake);
        assert!(!f[0].evidence.excerpt.contains('\u{1b}'));
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, bytes).unwrap();
        p
    }

    fn kind_of(path: &Path) -> Option<Kind> {
        subject(path).unwrap().kind
    }

    #[test]
    fn extensions_pick_dmg_and_pkg_case_insensitively() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(kind_of(&write(d.path(), "a.dmg", b"x")), Some(Kind::Dmg));
        assert_eq!(kind_of(&write(d.path(), "A.PKG", b"x")), Some(Kind::Pkg));
        assert_eq!(kind_of(&write(d.path(), "a.txt", b"hello world")), None);
    }

    #[test]
    fn an_app_is_a_directory_and_a_dir_named_dmg_is_not_a_kind() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("T.app")).unwrap();
        fs::create_dir(d.path().join("x.dmg")).unwrap();
        fs::create_dir(d.path().join("plain")).unwrap();
        assert_eq!(kind_of(&d.path().join("T.app")), Some(Kind::App));
        assert_eq!(kind_of(&d.path().join("x.dmg")), None);
        assert_eq!(kind_of(&d.path().join("plain")), None);
        assert_eq!(kind_of(&write(d.path(), "f.app", b"not a bundle")), None);
    }

    #[test]
    fn mach_o_magics_are_recognised_and_a_java_class_is_not() {
        let d = tempfile::tempdir().unwrap();
        let magic = |m: u32, n: u32| [m.to_be_bytes(), n.to_be_bytes()].concat();
        assert_eq!(
            kind_of(&write(d.path(), "a", &magic(0xCFFA_EDFE, 7))),
            Some(Kind::MachO)
        );
        assert_eq!(
            kind_of(&write(d.path(), "b", &magic(0xFEED_FACE, 7))),
            Some(Kind::MachO)
        );
        assert_eq!(
            kind_of(&write(d.path(), "c", &magic(0xCAFE_BABE, 2))),
            Some(Kind::MachO)
        );
        assert_eq!(
            kind_of(&write(
                d.path(),
                "j.class",
                &magic(0xCAFE_BABE, 0x0000_0041)
            )),
            None
        );
        assert_eq!(kind_of(&write(d.path(), "short", &[0xCF, 0xFA])), None);
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        let status = std::process::Command::new("/usr/bin/mkfifo")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_is_never_opened_and_is_marked_special_whatever_its_name() {
        let d = tempfile::tempdir().unwrap();
        for name in ["pipe", "x.dmg", "x.pkg"] {
            let path = d.path().join(name);
            mkfifo(&path);
            let s = subject(&path).unwrap();
            assert!(s.special && s.kind.is_none(), "{name}");
        }
    }

    #[test]
    fn a_missing_path_is_an_error_before_any_tool_runs() {
        let d = tempfile::tempdir().unwrap();
        assert!(subject(&d.path().join("nope")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_resolved_for_kind_and_path_and_a_dangling_one_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let target = write(d.path(), "real.dmg", b"x");
        std::os::unix::fs::symlink(&target, d.path().join("-link")).unwrap();
        std::os::unix::fs::symlink(d.path().join("gone"), d.path().join("dangling")).unwrap();
        let s = subject(&d.path().join("-link")).unwrap();
        assert_eq!(s.kind, Some(Kind::Dmg));
        assert_eq!(s.path, fs::canonicalize(&target).unwrap());
        assert!(subject(&d.path().join("dangling")).is_err());
    }

    #[test]
    fn a_relative_path_starting_with_a_dash_reaches_the_tools_absolute() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "-x.pkg", b"x");
        let s = subject(&d.path().join("-x.pkg")).unwrap();
        assert!(s.path.is_absolute());
    }
}
