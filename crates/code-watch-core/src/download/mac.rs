//! The macOS tools behind `MacTools`: what each is called with and how its answer is read.

use std::ffi::OsString;
use std::path::Path;

use super::exec::{Exec, ExecError, Output, ProcessExec};
use super::{Gatekeeper, Kind, MacTools, Signature, ToolError};

pub const XATTR: &str = "/usr/bin/xattr";
pub const CODESIGN: &str = "/usr/bin/codesign";
pub const SPCTL: &str = "/usr/sbin/spctl";
pub const PKGUTIL: &str = "/usr/sbin/pkgutil";

pub struct MacOsTools {
    exec: Box<dyn Exec>,
}

impl Default for MacOsTools {
    fn default() -> Self {
        Self::new(Box::new(ProcessExec::default()))
    }
}

impl MacOsTools {
    pub fn new(exec: Box<dyn Exec>) -> Self {
        Self { exec }
    }

    fn run(&self, tool: &'static str, args: Vec<OsString>) -> Result<Output, ToolError> {
        self.exec.run(tool, &args).map_err(|e| match e {
            ExecError::NotFound => ToolError::Missing(tool),
            ExecError::TimedOut => ToolError::TimedOut(tool),
            ExecError::Io(why) => ToolError::Failed(tool, why),
        })
    }
}

fn args(parts: &[&str], path: &Path) -> Vec<OsString> {
    parts
        .iter()
        .map(OsString::from)
        .chain([path.as_os_str().to_owned()])
        .collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Only a clean UTF-8 answer naming the missing attribute counts as "not quarantined".
fn says_no_such_xattr(stderr: &[u8]) -> bool {
    std::str::from_utf8(stderr).is_ok_and(|s| s.contains("No such xattr"))
}

fn failed(tool: &'static str, out: &Output) -> ToolError {
    let why = match out.code {
        Some(code) => format!("exit code {code}"),
        None => "ended by a signal".into(),
    };
    ToolError::Failed(tool, why)
}

/// The `spctl` type (and context) Gatekeeper is asked about for each kind. A bare executable is
/// asked as a primary-signature open: `--type execute` refuses every non-bundle binary, Apple's own
/// included.
fn spctl_type(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Pkg => &["--type", "install"],
        Kind::App => &["--type", "execute"],
        Kind::Dmg | Kind::MachO => &["--type", "open", "--context", "context:primary-signature"],
    }
}

impl MacTools for MacOsTools {
    fn quarantine(&self, path: &Path) -> Result<bool, ToolError> {
        let out = self.run(XATTR, args(&["-p", "com.apple.quarantine"], path))?;
        match out.code {
            Some(0) => Ok(true),
            Some(1) if !out.truncated && says_no_such_xattr(&out.stderr) => Ok(false),
            _ => Err(failed(XATTR, &out)),
        }
    }

    fn signature(&self, path: &Path, kind: Kind) -> Result<Signature, ToolError> {
        if kind == Kind::Pkg {
            return self.pkg_signature(path);
        }
        let out = self.run(CODESIGN, args(&["--verify", "--deep", "--strict"], path))?;
        match out.code {
            Some(0) => Ok(Signature::Valid),
            Some(1) => {
                let why = text(&out.stderr);
                if why.contains("code object is not signed at all") {
                    Ok(Signature::Unsigned)
                } else {
                    Ok(Signature::Invalid(why))
                }
            }
            _ => Err(failed(CODESIGN, &out)),
        }
    }

    fn gatekeeper(&self, path: &Path, kind: Kind) -> Result<Gatekeeper, ToolError> {
        let mut parts = vec!["--assess"];
        parts.extend(spctl_type(kind));
        parts.push("-vv");
        let out = self.run(SPCTL, args(&parts, path))?;
        match out.code {
            Some(0) => Ok(Gatekeeper::Accepted),
            Some(3) => Ok(Gatekeeper::Rejected(text(&out.stderr))),
            _ => Err(failed(SPCTL, &out)),
        }
    }
}

impl MacOsTools {
    /// `codesign` does not read installer signatures, so a `.pkg` goes through `pkgutil`.
    fn pkg_signature(&self, path: &Path) -> Result<Signature, ToolError> {
        let out = self.run(PKGUTIL, args(&["--check-signature"], path))?;
        let shown = text(&out.stdout);
        let status = shown
            .lines()
            .find(|l| l.trim_start().starts_with("Status:"));
        match (out.code, status) {
            (Some(0), _) => Ok(Signature::Valid),
            (Some(1), Some(line)) if line.contains("no signature") => Ok(Signature::Unsigned),
            (Some(1), Some(line)) => Ok(Signature::Invalid(line.trim().to_owned())),
            _ => Err(failed(PKGUTIL, &out)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;

    use super::*;

    /// Answers each call from a script and records what was run.
    struct Script {
        answers: RefCell<Vec<Result<Output, ExecError>>>,
        calls: RefCell<Vec<(String, Vec<OsString>)>>,
    }

    fn out(code: i32, stdout: &str, stderr: &str) -> Result<Output, ExecError> {
        Ok(Output {
            code: Some(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
            truncated: false,
        })
    }

    fn tools(answer: Result<Output, ExecError>) -> (MacOsTools, std::rc::Rc<Script>) {
        let script = std::rc::Rc::new(Script {
            answers: RefCell::new(vec![answer]),
            calls: RefCell::new(Vec::new()),
        });
        struct Shared(std::rc::Rc<Script>);
        impl Exec for Shared {
            fn run(&self, program: &str, args: &[OsString]) -> Result<Output, ExecError> {
                self.0
                    .calls
                    .borrow_mut()
                    .push((program.to_owned(), args.to_vec()));
                self.0.answers.borrow_mut().remove(0)
            }
        }
        (MacOsTools::new(Box::new(Shared(script.clone()))), script)
    }

    fn p() -> PathBuf {
        PathBuf::from("/d/my \"file\" -x.dmg")
    }

    fn argv(script: &Script) -> Vec<String> {
        let calls = script.calls.borrow();
        let (tool, args) = &calls[0];
        std::iter::once(tool.clone())
            .chain(args.iter().map(|a| a.to_string_lossy().into_owned()))
            .collect()
    }

    // quarantine

    #[test]
    fn xattr_present_absent_and_the_exact_call() {
        let (t, s) = tools(out(0, "0081;x\n", ""));
        assert_eq!(t.quarantine(&p()), Ok(true));
        assert_eq!(
            argv(&s),
            [XATTR, "-p", "com.apple.quarantine", "/d/my \"file\" -x.dmg"]
        );
        let (t, _) = tools(out(
            1,
            "",
            "xattr: f: No such xattr: com.apple.quarantine\n",
        ));
        assert_eq!(t.quarantine(&p()), Ok(false));
    }

    #[test]
    fn xattr_failures_are_unchecked_not_absent() {
        for answer in [
            out(1, "", "xattr: f: No such file\n"),
            out(2, "", "No such xattr"),
            Ok(Output {
                code: Some(1),
                stdout: vec![],
                stderr: b"\xff No such xattr".to_vec(),
                truncated: false,
            }),
            out(1, "", ""),
            Ok(Output {
                code: Some(1),
                stdout: vec![],
                stderr: b"No such xattr".to_vec(),
                truncated: true,
            }),
            Err(ExecError::TimedOut),
            Err(ExecError::NotFound),
            Err(ExecError::Io("x".into())),
        ] {
            let (t, _) = tools(answer.clone());
            assert!(t.quarantine(&p()).is_err(), "{answer:?}");
        }
        let (t, _) = tools(Err(ExecError::TimedOut));
        assert_eq!(t.quarantine(&p()), Err(ToolError::TimedOut(XATTR)));
        let (t, _) = tools(Err(ExecError::NotFound));
        assert_eq!(t.quarantine(&p()), Err(ToolError::Missing(XATTR)));
    }

    // codesign

    #[test]
    fn codesign_reads_valid_unsigned_and_invalid_and_uses_strict_deep() {
        let (t, s) = tools(out(0, "", ""));
        assert_eq!(t.signature(&p(), Kind::App), Ok(Signature::Valid));
        assert_eq!(
            argv(&s),
            [
                CODESIGN,
                "--verify",
                "--deep",
                "--strict",
                "/d/my \"file\" -x.dmg"
            ]
        );
        let (t, _) = tools(out(1, "", "f: code object is not signed at all\n"));
        assert_eq!(t.signature(&p(), Kind::Dmg), Ok(Signature::Unsigned));
        let (t, _) = tools(out(1, "", "f: a sealed resource is missing or invalid\n"));
        assert_eq!(
            t.signature(&p(), Kind::MachO),
            Ok(Signature::Invalid(
                "f: a sealed resource is missing or invalid\n".into()
            ))
        );
    }

    #[test]
    fn codesign_other_exit_codes_and_tool_trouble_are_unchecked() {
        for answer in [
            out(2, "", ""),
            out(127, "", ""),
            Err(ExecError::TimedOut),
            Err(ExecError::NotFound),
        ] {
            let (t, _) = tools(answer.clone());
            assert!(t.signature(&p(), Kind::App).is_err(), "{answer:?}");
        }
    }

    #[test]
    fn a_huge_codesign_complaint_is_still_an_invalid_signature() {
        let (t, _) = tools(Ok(Output {
            code: Some(1),
            stdout: vec![],
            stderr: vec![b'x'; 70_000],
            truncated: true,
        }));
        assert!(matches!(
            t.signature(&p(), Kind::App),
            Ok(Signature::Invalid(_))
        ));
    }

    // pkgutil

    #[test]
    fn a_pkg_is_read_with_pkgutil_not_codesign() {
        let (t, s) = tools(out(
            0,
            "Package \"x.pkg\":\n   Status: signed by a developer certificate issued by Apple (Notarized Developer ID)\n",
            "",
        ));
        assert_eq!(t.signature(&p(), Kind::Pkg), Ok(Signature::Valid));
        assert_eq!(
            argv(&s),
            [PKGUTIL, "--check-signature", "/d/my \"file\" -x.dmg"]
        );
    }

    #[test]
    fn pkgutil_no_signature_and_a_bad_one() {
        let (t, _) = tools(out(1, "Package \"x\":\n   Status: no signature\n", ""));
        assert_eq!(t.signature(&p(), Kind::Pkg), Ok(Signature::Unsigned));
        let (t, _) = tools(out(1, "Package \"x\":\n   Status: invalid signature\n", ""));
        assert_eq!(
            t.signature(&p(), Kind::Pkg),
            Ok(Signature::Invalid("Status: invalid signature".into()))
        );
    }

    #[test]
    fn pkgutil_that_could_not_read_the_package_is_unchecked() {
        for answer in [
            out(1, "Could not open package: x\n", ""),
            out(2, "", ""),
            Err(ExecError::TimedOut),
            Err(ExecError::NotFound),
        ] {
            let (t, _) = tools(answer.clone());
            assert!(t.signature(&p(), Kind::Pkg).is_err(), "{answer:?}");
        }
    }

    // spctl

    #[test]
    fn spctl_types_and_results() {
        let cases = [
            (
                Kind::Dmg,
                ["--type", "open", "--context", "context:primary-signature"].as_slice(),
            ),
            (
                Kind::MachO,
                ["--type", "open", "--context", "context:primary-signature"].as_slice(),
            ),
            (Kind::Pkg, ["--type", "install"].as_slice()),
            (Kind::App, ["--type", "execute"].as_slice()),
        ];
        for (kind, want) in cases {
            let (t, s) = tools(out(0, "", "x: accepted\nsource=Notarized Developer ID\n"));
            assert_eq!(t.gatekeeper(&p(), kind), Ok(Gatekeeper::Accepted));
            let mut expected = vec![SPCTL.to_owned(), "--assess".into()];
            expected.extend(want.iter().map(|s| s.to_string()));
            expected.extend(["-vv".into(), "/d/my \"file\" -x.dmg".into()]);
            assert_eq!(argv(&s), expected, "{kind:?}");
        }
        let (t, _) = tools(out(3, "", "x: rejected\nsource=Unnotarized Developer ID\n"));
        assert!(matches!(
            t.gatekeeper(&p(), Kind::App),
            Ok(Gatekeeper::Rejected(why)) if why.contains("Unnotarized")
        ));
    }

    #[test]
    fn spctl_decides_by_exit_code_not_by_text() {
        let (t, _) = tools(out(0, "rejected", "rejected"));
        assert_eq!(t.gatekeeper(&p(), Kind::App), Ok(Gatekeeper::Accepted));
        for answer in [
            out(1, "", "invalid API object reference"),
            out(5, "", ""),
            Err(ExecError::TimedOut),
            Err(ExecError::NotFound),
        ] {
            let (t, _) = tools(answer.clone());
            assert!(t.gatekeeper(&p(), Kind::App).is_err(), "{answer:?}");
        }
        let (t, _) = tools(Ok(Output {
            code: Some(3),
            stdout: vec![b'x'; 70_000],
            stderr: vec![],
            truncated: true,
        }));
        assert!(matches!(
            t.gatekeeper(&p(), Kind::App),
            Ok(Gatekeeper::Rejected(_))
        ));
    }
}
