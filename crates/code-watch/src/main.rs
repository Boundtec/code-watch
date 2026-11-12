use std::io::{self, Write};
use std::panic::{self, UnwindSafe};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use code_watch_core::{Engine, Report, render};

mod hook;

/// Exit code for errors and bad usage. Verdicts use 0, 1 and 2, so 2 always means "block".
const EXIT_ERROR: u8 = 3;

#[derive(Parser)]
#[command(
    name = "code-watch",
    version,
    about = "Checks a developer's machine before risky code runs"
)]
struct Cli {
    /// Print the report as JSON instead of text. Put it before the command arguments.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan a directory (for example a freshly cloned repository) without running anything in it
    Scan { dir: PathBuf },
    /// Check a shell command before it runs
    Check {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Scan every repository on clone, through a git template hook (changes your global git config)
    InstallHook,
    /// Remove what install-hook added, leaving your git config as it was
    UninstallHook,
}

fn main() -> ExitCode {
    panic::set_hook(Box::new(|info| {
        let _ = writeln!(io::stderr(), "code-watch: internal error: {info}");
    }));
    guarded(real_main)
}

/// Runs `f` and turns a panic into the error exit code: the default 101 would be read as a
/// verdict-less crash by hooks that only know 0, 1, 2 and 3.
fn guarded(f: impl FnOnce() -> ExitCode + UnwindSafe) -> ExitCode {
    panic::catch_unwind(f).unwrap_or(ExitCode::from(EXIT_ERROR))
}

fn real_main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let ok = matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion);
            let _ = e.print();
            return ExitCode::from(if ok { 0 } else { EXIT_ERROR });
        }
    };
    let report = match run(&cli) {
        Ok(Outcome::Report(report)) => report,
        Ok(Outcome::Message(message)) => {
            println!("code-watch: {message}");
            return ExitCode::SUCCESS;
        }
        Err(e) => return fail(&format!("{e:#}")),
    };
    let text = if cli.json {
        match render::to_json(&report) {
            Ok(text) => text,
            Err(e) => return fail(&e.to_string()),
        }
    } else {
        render::to_human(&report)
    };
    let mut stdout = io::stdout().lock();
    match writeln!(stdout, "{}", text.trim_end()).and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::from(report.verdict().exit_code()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::from(EXIT_ERROR),
        Err(e) => fail(&e.to_string()),
    }
}

fn fail(message: &str) -> ExitCode {
    let _ = writeln!(io::stderr(), "code-watch: {message}");
    ExitCode::from(EXIT_ERROR)
}

/// What a subcommand produces: a scan report, or a plain message for the hook commands.
enum Outcome {
    Report(Report),
    Message(String),
}

fn run(cli: &Cli) -> anyhow::Result<Outcome> {
    Ok(match &cli.command {
        Cmd::Scan { dir } => Outcome::Report(Engine::embedded()?.scan_dir(dir)?),
        Cmd::Check { command } => {
            Outcome::Report(Engine::embedded()?.check_command(&command.join(" ")))
        }
        Cmd::InstallHook => Outcome::Message(hook::install(&std::env::current_exe()?)?),
        Cmd::UninstallHook => Outcome::Message(hook::uninstall()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_exits_with_the_error_code() {
        panic::set_hook(Box::new(|_| {}));
        let code = guarded(|| panic!("boom"));
        let _ = panic::take_hook();
        assert_eq!(code, ExitCode::from(EXIT_ERROR));
    }
}
