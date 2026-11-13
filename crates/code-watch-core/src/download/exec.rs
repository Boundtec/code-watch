//! Runs one external program with a time limit and a cap on what is read from it.

use std::ffi::OsString;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// `None` when the process was ended by a signal.
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// A stream held more than the cap; the rest was dropped and the process stopped.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    NotFound,
    TimedOut,
    Io(String),
}

pub trait Exec {
    fn run(&self, program: &str, args: &[OsString]) -> Result<Output, ExecError>;
}

/// Spawns the program directly (never through a shell) with no stdin.
pub struct ProcessExec {
    pub timeout: Duration,
    pub max_output: usize,
}

impl Default for ProcessExec {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_output: DEFAULT_MAX_OUTPUT,
        }
    }
}

enum Stream {
    Out,
    Err,
}

/// Reads at most `cap` bytes; the flag says there was more.
fn read_capped(mut from: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut limited = (&mut from).take(cap as u64);
    if limited.read_to_end(&mut buf).is_err() {
        return (buf, false);
    }
    let mut probe = [0u8; 1];
    let more = matches!(from.read(&mut probe), Ok(n) if n > 0);
    (buf, more)
}

impl Exec for ProcessExec {
    fn run(&self, program: &str, args: &[OsString]) -> Result<Output, ExecError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ExecError::NotFound,
                _ => ExecError::Io(e.to_string()),
            })?;
        let (tx, rx) = mpsc::channel();
        let cap = self.max_output;
        for (which, pipe) in [
            (Stream::Out, child.stdout.take().map(boxed)),
            (Stream::Err, child.stderr.take().map(boxed)),
        ] {
            let tx = tx.clone();
            thread::spawn(move || {
                let (bytes, more) = pipe.map_or((Vec::new(), false), |p| read_capped(p, cap));
                let _ = tx.send((which, bytes, more));
            });
        }
        drop(tx);
        let deadline = Instant::now() + self.timeout;
        let (mut stdout, mut stderr, mut truncated) = (Vec::new(), Vec::new(), false);
        for _ in 0..2 {
            let left = deadline.saturating_duration_since(Instant::now());
            let Ok((which, bytes, more)) = rx.recv_timeout(left) else {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ExecError::TimedOut);
            };
            truncated |= more;
            match which {
                Stream::Out => stdout = bytes,
                Stream::Err => stderr = bytes,
            }
            if more {
                let _ = child.kill();
            }
        }
        let status = child.wait().map_err(|e| ExecError::Io(e.to_string()))?;
        Ok(Output {
            code: status.code(),
            stdout,
            stderr,
            truncated,
        })
    }
}

fn boxed(pipe: impl Read + Send + 'static) -> Box<dyn Read + Send> {
    Box::new(pipe)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn exec(timeout_ms: u64, max_output: usize) -> ProcessExec {
        ProcessExec {
            timeout: Duration::from_millis(timeout_ms),
            max_output,
        }
    }

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_process_that_outlives_the_timeout_is_killed_and_reported() {
        let r = exec(100, 1024).run("/bin/sleep", &os(&["30"]));
        assert_eq!(r, Err(ExecError::TimedOut));
    }

    #[test]
    fn output_over_the_cap_is_cut_and_the_process_stopped() {
        let r = exec(5000, 100).run("/usr/bin/yes", &[]).unwrap();
        assert!(r.truncated);
        assert_eq!(r.stdout.len(), 100);
    }

    #[test]
    fn output_exactly_at_the_cap_is_not_truncated() {
        let r = exec(5000, 4).run("/bin/echo", &os(&["abc"])).unwrap();
        assert!(!r.truncated);
        assert_eq!(r.stdout, b"abc\n");
    }

    #[test]
    fn the_exit_code_and_stderr_are_returned() {
        let r = exec(5000, 1024)
            .run("/bin/sh", &os(&["-c", "echo bad >&2; exit 3"]))
            .unwrap();
        assert_eq!(r.code, Some(3));
        assert_eq!(r.stderr, b"bad\n");
    }

    #[test]
    fn a_missing_program_is_not_found() {
        let r = exec(5000, 1024).run("/nonexistent/tool", &[]);
        assert_eq!(r, Err(ExecError::NotFound));
    }

    #[test]
    fn arguments_are_passed_without_a_shell() {
        let r = exec(5000, 1024)
            .run("/bin/echo", &os(&["-n", "a b; $(x) 'q'"]))
            .unwrap();
        assert_eq!(r.stdout, b"a b; $(x) 'q'");
    }
}
