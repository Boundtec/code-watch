use std::ffi::OsString;
use std::io::{self, Write};
use std::panic::{self, UnwindSafe};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use code_watch_core::allow::find_repo_root;
use code_watch_core::osv::{Cache, DEFAULT_TTL, OsvMode, SystemClock, UreqOsv};
use code_watch_core::{Allowlists, Engine, OsvSetup, Report, render};

mod adapter;
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
    Scan {
        dir: PathBuf,
        /// Do not look up known vulnerabilities (the OSV layer reports "off")
        #[arg(long, conflicts_with = "offline")]
        no_osv: bool,
        /// Check known vulnerabilities from the fresh local cache only, with no network
        #[arg(long)]
        offline: bool,
    },
    /// Check a shell command before it runs
    Check {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Scan every repository on clone, through a git template hook (changes your global git config)
    InstallHook,
    /// Answer an agent's pre-command hook: reads its hook JSON on stdin, replies in its format
    Adapter {
        agent: adapter::Agent,
        /// Allow commands the adapter cannot check (default: deny them)
        #[arg(long)]
        fail_open: bool,
        /// Deny commands the adapter cannot check (the default)
        #[arg(long, conflicts_with = "fail_open")]
        fail_closed: bool,
        /// Codex cannot ask: answer a warning with a deny (default) or let it run and say so on stderr
        #[arg(long, value_enum, default_value_t = adapter::CodexWarn::Deny)]
        codex_warn: adapter::CodexWarn,
        /// Cursor cannot stay silent: answer a clean command with an ask (default, Cursor's prompt decides) or an allow
        #[arg(long, value_enum, default_value_t = adapter::CursorClean::Ask)]
        cursor_clean: adapter::CursorClean,
    },
    /// Print the settings snippet that connects an agent to `adapter` (edits nothing)
    InstallAdapter { agent: adapter::Agent },
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
    match &cli.command {
        Cmd::Adapter {
            agent,
            fail_open,
            codex_warn,
            cursor_clean,
            ..
        } => {
            let policy = adapter::Policy {
                fail: if *fail_open {
                    adapter::FailMode::Open
                } else {
                    adapter::FailMode::Closed
                },
                codex_warn: *codex_warn,
                cursor_clean: *cursor_clean,
            };
            return adapter::run(*agent, policy, user_dir().as_deref());
        }
        Cmd::InstallAdapter { agent } => return install_adapter(*agent),
        _ => {}
    }
    let report = match run(&cli) {
        Ok(Outcome::Report(report)) => report,
        Ok(Outcome::Message(message)) => {
            println!("code-watch: {}", render::terminal_safe(&message));
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
    let _ = writeln!(
        io::stderr(),
        "code-watch: {}",
        render::terminal_safe(message)
    );
    ExitCode::from(EXIT_ERROR)
}

/// What a subcommand produces: a scan report, or a plain message for the hook commands.
enum Outcome {
    Report(Report),
    Message(String),
}

fn run(cli: &Cli) -> anyhow::Result<Outcome> {
    let user_dir = user_dir();
    Ok(match &cli.command {
        Cmd::Scan {
            dir,
            no_osv,
            offline,
        } => {
            let allow = Allowlists::load(user_dir.as_deref(), Some(dir))?;
            let engine = Engine::embedded()?;
            if *no_osv {
                return Ok(Outcome::Report(engine.scan_dir_with(dir, &allow)?));
            }
            let cache_dir = osv_cache_dir(std::env::var_os("XDG_CACHE_HOME"), dirs::home_dir())
                .ok_or_else(|| {
                    anyhow::anyhow!("no home directory for the OSV cache; pass --no-osv")
                })?;
            let cache = Cache::new(cache_dir, DEFAULT_TTL, Box::new(SystemClock));
            let client = UreqOsv::default();
            let setup = OsvSetup {
                mode: if *offline {
                    OsvMode::Offline
                } else {
                    OsvMode::Live
                },
                client: &client,
                cache: &cache,
            };
            Outcome::Report(engine.scan_dir_osv(dir, &allow, Some(&setup))?)
        }
        Cmd::Check { command } => {
            let cwd = std::env::current_dir().ok();
            let command = command.join(" ");
            Outcome::Report(check_command(
                cwd.as_deref(),
                &command,
                user_dir.as_deref(),
            )?)
        }
        Cmd::Adapter { .. } | Cmd::InstallAdapter { .. } => unreachable!("handled before run"),
        Cmd::InstallHook => Outcome::Message(hook::install(&std::env::current_exe()?)?),
        Cmd::UninstallHook => Outcome::Message(hook::uninstall()?),
    })
}

fn user_dir() -> Option<PathBuf> {
    user_config_dir(std::env::var_os("XDG_CONFIG_HOME"), dirs::home_dir())
}

/// The check shared by `check` and the adapters. A repo allowlist applies only when `cwd` is a
/// directory inside a git work tree; any other `cwd` is treated as outside a repo.
fn check_command(
    cwd: Option<&Path>,
    command: &str,
    user_dir: Option<&Path>,
) -> anyhow::Result<Report> {
    let repo = cwd.filter(|d| d.is_dir()).and_then(find_repo_root);
    let allow = Allowlists::load(user_dir, repo.as_deref())?;
    Ok(Engine::embedded()?.check_command_with(command, &allow))
}

fn install_adapter(agent: adapter::Agent) -> ExitCode {
    let printed = std::env::current_exe()
        .map_err(anyhow::Error::from)
        .and_then(|exe| adapter::install::snippet(agent, &exe))
        .and_then(|(value, file)| {
            let _ = writeln!(io::stderr(), "code-watch: merge this into {file}:");
            if agent == adapter::Agent::Cursor {
                let _ = writeln!(
                    io::stderr(),
                    "code-watch: clean commands still go through Cursor's approval prompt (--cursor-clean ask); add --cursor-clean allow to the command if you run Cursor in auto-run mode"
                );
            }
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        });
    match printed {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&format!("{e:#}")),
    }
}

/// `$XDG_CONFIG_HOME` when it is an absolute path, else `~/.config`; the same on macOS and Linux.
fn user_config_dir(xdg: Option<OsString>, home: Option<PathBuf>) -> Option<PathBuf> {
    xdg.map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home.map(|h| h.join(".config")))
}

/// `$XDG_CACHE_HOME/code-watch/osv` when the variable is an absolute path, else
/// `~/.cache/code-watch/osv`; the same on macOS and Linux.
fn osv_cache_dir(xdg: Option<OsString>, home: Option<PathBuf>) -> Option<PathBuf> {
    xdg.map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home.map(|h| h.join(".cache")))
        .map(|base| base.join("code-watch").join("osv"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_osv_cache_follows_xdg_cache_home_else_dot_cache() {
        let home = Some(PathBuf::from("/h"));
        let dir = |xdg: Option<&str>| osv_cache_dir(xdg.map(OsString::from), home.clone());
        assert_eq!(dir(Some("/x")), Some(PathBuf::from("/x/code-watch/osv")));
        assert_eq!(
            dir(Some("rel")),
            Some(PathBuf::from("/h/.cache/code-watch/osv"))
        );
        assert_eq!(dir(None), Some(PathBuf::from("/h/.cache/code-watch/osv")));
        assert_eq!(osv_cache_dir(None, None), None);
    }

    #[test]
    fn xdg_config_home_wins_when_absolute_else_home_dot_config() {
        let home = Some(PathBuf::from("/h"));
        let dir = |xdg: Option<&str>| user_config_dir(xdg.map(OsString::from), home.clone());
        assert_eq!(dir(Some("/x")), Some(PathBuf::from("/x")));
        assert_eq!(dir(Some("rel")), Some(PathBuf::from("/h/.config")));
        assert_eq!(dir(Some("")), Some(PathBuf::from("/h/.config")));
        assert_eq!(dir(None), Some(PathBuf::from("/h/.config")));
        assert_eq!(user_config_dir(None, None), None);
    }

    #[test]
    fn a_panic_exits_with_the_error_code() {
        panic::set_hook(Box::new(|_| {}));
        let code = guarded(|| panic!("boom"));
        let _ = panic::take_hook();
        assert_eq!(code, ExitCode::from(EXIT_ERROR));
    }
}
