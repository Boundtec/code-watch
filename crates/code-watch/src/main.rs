use std::ffi::OsString;
use std::io::{self, Write};
use std::panic::{self, UnwindSafe};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use code_watch_core::allow::find_repo_root;
use code_watch_core::download::{MacOsTools, MacTools};
use code_watch_core::osv::{Cache, DEFAULT_TTL, OsvMode, SystemClock, UreqOsv};
use code_watch_core::{Allowlists, Engine, OsvSetup, Report, render};

mod adapter;
mod hook;
mod shim;

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
    /// Check a downloaded .dmg, .pkg, .app or executable before opening it (macOS only; read-only)
    Download { path: PathBuf },
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
        #[arg(long, value_enum, default_value_t = adapter::WarnAnswer::Deny)]
        codex_warn: adapter::WarnAnswer,
        /// Cursor cannot stay silent: answer a clean command with an ask (default, Cursor's prompt decides) or an allow
        #[arg(long, value_enum, default_value_t = adapter::CursorClean::Ask)]
        cursor_clean: adapter::CursorClean,
        /// Gemini CLI cannot ask: answer a warning with a deny (default) or let it run and say so on stderr
        #[arg(long, value_enum, default_value_t = adapter::WarnAnswer::Deny)]
        gemini_warn: adapter::WarnAnswer,
        /// OpenCode cannot ask: answer a warning with a deny (default) or let it run and say so on stderr
        #[arg(long, value_enum, default_value_t = adapter::WarnAnswer::Deny)]
        opencode_warn: adapter::WarnAnswer,
    },
    /// Print the settings snippet that connects an agent to `adapter` (edits nothing); for opencode,
    /// write the plugin to <PATH> or print it with --print
    InstallAdapter {
        agent: adapter::Agent,
        /// opencode only: where to write the plugin (replaced only if code-watch wrote it)
        path: Option<PathBuf>,
        /// opencode only: print the plugin instead of writing it
        #[arg(long, conflicts_with = "path")]
        print: bool,
        /// opencode only: let commands through when the plugin cannot run the check
        #[arg(long)]
        fail_open: bool,
        /// opencode only: let a warning run and say so on stderr (default: deny it)
        #[arg(long, value_enum)]
        opencode_warn: Option<adapter::WarnAnswer>,
    },
    /// Guard git, npm, pnpm, yarn, pip, brew and curl through PATH shims
    Shims {
        #[command(subcommand)]
        action: ShimsCmd,
    },
    /// Remove what install-hook added, leaving your git config as it was
    UninstallHook,
}

#[derive(Subcommand)]
enum ShimsCmd {
    /// Write the shims into <DIR>; put it first on PATH
    Install { dir: PathBuf },
    /// Remove the shims code-watch wrote in <DIR> and nothing else
    Uninstall { dir: PathBuf },
    /// Show whether each shim in <DIR> points at this binary (exit 1 if any does not)
    Status { dir: PathBuf },
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
    let mut argv = std::env::args_os();
    if let Some(name) = argv.next().as_deref().and_then(shim::invoked_as) {
        return shim::run(name, argv.collect());
    }
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
            gemini_warn,
            opencode_warn,
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
                gemini_warn: *gemini_warn,
                opencode_warn: *opencode_warn,
            };
            return adapter::run(*agent, policy, user_dir().as_deref());
        }
        Cmd::InstallAdapter {
            agent,
            path,
            print,
            fail_open,
            opencode_warn,
        } => {
            return install_adapter(*agent, path.as_deref(), *print, *fail_open, *opencode_warn);
        }
        Cmd::Shims { action } => return shims(action),
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
        Cmd::Download { path } => {
            let repo = path
                .parent()
                .filter(|d| d.is_dir())
                .and_then(find_repo_root);
            let allow = Allowlists::load(user_dir.as_deref(), repo.as_deref())?;
            let tools = cfg!(target_os = "macos").then(MacOsTools::default);
            let tools = tools.as_ref().map(|t| t as &dyn MacTools);
            Outcome::Report(Engine::embedded()?.check_download(path, tools, &allow)?)
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
        Cmd::Adapter { .. } | Cmd::InstallAdapter { .. } | Cmd::Shims { .. } => {
            unreachable!("handled before run")
        }
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

fn shims(action: &ShimsCmd) -> ExitCode {
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(anyhow::Error::from);
    let done = match action {
        ShimsCmd::Install { dir } => exe.and_then(|exe| shim::install(dir, &exe)),
        ShimsCmd::Uninstall { dir } => shim::uninstall(dir),
        ShimsCmd::Status { dir } => {
            return match exe {
                Ok(exe) => {
                    let (text, all_ok) = shim::status(dir, &exe);
                    println!("{text}");
                    ExitCode::from(if all_ok { 0 } else { 1 })
                }
                Err(e) => fail(&format!("{e:#}")),
            };
        }
    };
    match done {
        Ok(message) => {
            println!("code-watch: {message}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("{e:#}")),
    }
}

/// OpenCode has no settings file for hooks: the plugin itself is written or printed.
fn install_opencode(
    path: Option<&Path>,
    print: bool,
    fail_open: bool,
    warn: adapter::WarnAnswer,
) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let text = adapter::opencode::render(&exe, fail_open, warn)?;
    match (path, print) {
        (Some(path), _) => {
            let done = adapter::opencode::install(path, &text)?;
            println!("code-watch: {done} {}", path.display());
        }
        (None, true) => print!("{text}"),
        (None, false) => anyhow::bail!("name the file to write the plugin to, or use --print"),
    }
    Ok(())
}

fn install_adapter(
    agent: adapter::Agent,
    path: Option<&Path>,
    print: bool,
    fail_open: bool,
    opencode_warn: Option<adapter::WarnAnswer>,
) -> ExitCode {
    if agent == adapter::Agent::Opencode {
        let warn = opencode_warn.unwrap_or(adapter::WarnAnswer::Deny);
        return match install_opencode(path, print, fail_open, warn) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&format!("{e:#}")),
        };
    }
    if path.is_some() || print || fail_open || opencode_warn.is_some() {
        return fail("only opencode takes a path, --print, --fail-open or --opencode-warn");
    }
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
