//! Drives `install.sh` against a fake release directory that uses the real archive names and the
//! `sha256sum` line format, served by `file://` or by a local HTTP server that redirects
//! `latest/download` the way GitHub does. No real network.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;

use tempfile::TempDir;

const TARGET: &str = "x86_64-unknown-linux-musl";

struct Env {
    root: TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Env {
            root: TempDir::new().unwrap(),
        };
        for dir in ["release", "shim", "home"] {
            fs::create_dir(env.path(dir)).unwrap();
        }
        env.set_uname("Linux", "x86_64");
        env
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn set_uname(&self, os: &str, machine: &str) {
        let shim = self.path("shim/uname");
        let script =
            format!("#!/bin/sh\nif [ \"$1\" = -s ]; then echo {os}; else echo {machine}; fi\n");
        fs::write(&shim, script).unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Builds `release/<dir>/code-watch-<version>-<target>.tar.gz` and returns the sha256 of it.
    fn add_archive(&self, dir: &str, version: &str, target: &str, body: &str) -> (String, String) {
        let name = format!("code-watch-{version}-{target}");
        let stage = self.path("stage").join(&name);
        fs::create_dir_all(&stage).unwrap();
        let bin = stage.join("code-watch");
        fs::write(&bin, format!("#!/bin/sh\necho {body}\n")).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let out_dir = self.path("release").join(dir);
        fs::create_dir_all(&out_dir).unwrap();
        let archive = out_dir.join(format!("{name}.tar.gz"));
        let status = Command::new("tar")
            .arg("-C")
            .arg(self.path("stage"))
            .arg("-czf")
            .arg(&archive)
            .arg(&name)
            .status()
            .unwrap();
        assert!(status.success());
        (format!("{name}.tar.gz"), sha256(&archive))
    }

    fn write_sums(&self, dir: &str, lines: &[(String, String)]) {
        let text: String = lines
            .iter()
            .map(|(file, sum)| format!("{sum}  {file}\n"))
            .collect();
        fs::write(self.path("release").join(dir).join("SHA256SUMS"), text).unwrap();
    }

    /// One good release in `dir` for the shimmed target and a sibling target.
    fn good_release(&self, dir: &str, version: &str, body: &str) {
        let ours = self.add_archive(dir, version, TARGET, body);
        let other = self.add_archive(dir, version, "aarch64-apple-darwin", "other");
        self.write_sums(dir, &[other, ours]);
    }

    fn install_dir(&self) -> PathBuf {
        self.path("home/bin")
    }

    fn run(&self, base_url: &str, version: Option<&str>) -> Output {
        let path = format!(
            "{}:{}",
            self.path("shim").display(),
            std::env::var("PATH").unwrap()
        );
        let mut cmd = Command::new("sh");
        cmd.arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.sh"))
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.path("home"))
            .env("TMPDIR", self.path("home"))
            .env("CODE_WATCH_BASE_URL", base_url)
            .env("CODE_WATCH_INSTALL_DIR", self.install_dir());
        if let Some(v) = version {
            cmd.env("CODE_WATCH_VERSION", v);
        }
        cmd.output().unwrap()
    }

    fn file_url(&self) -> String {
        format!("file://{}", self.path("release").display())
    }

    fn installed(&self) -> bool {
        self.install_dir().join("code-watch").exists()
    }

    fn assert_refused(&self, out: &Output, needle: &str) {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
        assert!(stderr.contains(needle), "stderr: {stderr}");
        assert!(!self.installed());
        let leftovers = self
            .install_dir()
            .exists()
            .then(|| fs::read_dir(self.install_dir()).unwrap().count());
        assert_eq!(leftovers.unwrap_or(0), 0, "install dir must stay empty");
    }
}

fn sha256(file: &Path) -> String {
    let out = Command::new("sh")
        .arg("-c")
        .arg("if command -v sha256sum >/dev/null; then sha256sum \"$1\"; else shasum -a 256 \"$1\"; fi")
        .arg("sh")
        .arg(file)
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

/// Serves `root` on 127.0.0.1; `/latest/download/<f>` answers 302 to `/download/v<latest>/<f>`.
fn serve(root: PathBuf, latest: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut request_line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request_line)
                .unwrap();
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .to_string();
            let response = if let Some(file) = path.strip_prefix("/latest/download/") {
                format!("HTTP/1.1 302 Found\r\nLocation: /download/v{latest}/{file}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
            } else {
                let file = root.join(path.trim_start_matches('/'));
                match fs::read(&file) {
                    Ok(body) => {
                        let mut r = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        r.extend(body);
                        r
                    }
                    Err(_) => {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    }
                }
            };
            let _ = stream.write_all(&response);
        }
    });
    base
}

fn run_binary(env: &Env) -> String {
    let out = Command::new(env.install_dir().join("code-watch"))
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn good_checksum_installs_an_executable_binary() {
    let env = Env::new();
    env.good_release("download/v1.2.3", "1.2.3", "good");
    let out = env.run(&env.file_url(), Some("v1.2.3"));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(run_binary(&env), "good");
}

#[test]
fn version_with_and_without_v_picks_the_same_archive() {
    let env = Env::new();
    env.good_release("download/v1.2.3", "1.2.3", "one");
    env.good_release("download/v2.0.0", "2.0.0", "two");
    assert!(env.run(&env.file_url(), Some("1.2.3")).status.success());
    assert_eq!(run_binary(&env), "one");
    assert!(env.run(&env.file_url(), Some("v2.0.0")).status.success());
    assert_eq!(run_binary(&env), "two");
}

#[test]
fn latest_follows_the_redirect_without_a_version() {
    let env = Env::new();
    env.good_release("download/v1.2.3", "1.2.3", "latest");
    let base = serve(env.path("release"), "1.2.3");
    let out = env.run(&base, None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(run_binary(&env), "latest");
}

#[test]
fn latest_from_a_plain_directory() {
    let env = Env::new();
    env.good_release("latest/download", "3.1.0", "plain");
    assert!(env.run(&env.file_url(), None).status.success());
    assert_eq!(run_binary(&env), "plain");
}

#[test]
fn bad_checksum_refuses_and_installs_nothing() {
    let env = Env::new();
    let (file, _) = env.add_archive("download/v1.2.3", "1.2.3", TARGET, "good");
    env.write_sums("download/v1.2.3", &[(file, "0".repeat(64))]);
    let out = env.run(&env.file_url(), Some("1.2.3"));
    env.assert_refused(&out, "checksum mismatch");
}

#[test]
fn tampered_archive_after_signing_refuses() {
    let env = Env::new();
    env.good_release("download/v1.2.3", "1.2.3", "good");
    let archive = env.path(&format!(
        "release/download/v1.2.3/code-watch-1.2.3-{TARGET}.tar.gz"
    ));
    let mut bytes = fs::read(&archive).unwrap();
    bytes.push(0);
    fs::write(&archive, bytes).unwrap();
    let out = env.run(&env.file_url(), Some("1.2.3"));
    env.assert_refused(&out, "checksum mismatch");
}

#[test]
fn sums_without_the_archive_line_refuse() {
    let env = Env::new();
    env.add_archive("download/v1.2.3", "1.2.3", TARGET, "good");
    let other = env.add_archive("download/v1.2.3", "1.2.3", "aarch64-apple-darwin", "other");
    env.write_sums("download/v1.2.3", &[other]);
    let out = env.run(&env.file_url(), Some("1.2.3"));
    env.assert_refused(&out, "no entry");
}

#[test]
fn unknown_architecture_and_os_refuse() {
    let env = Env::new();
    env.good_release("download/v1.2.3", "1.2.3", "good");
    env.set_uname("Linux", "riscv64");
    env.assert_refused(
        &env.run(&env.file_url(), Some("1.2.3")),
        "unsupported architecture",
    );
    env.set_uname("FreeBSD", "x86_64");
    env.assert_refused(
        &env.run(&env.file_url(), Some("1.2.3")),
        "unsupported operating system",
    );
}

#[test]
fn missing_archive_download_refuses() {
    let env = Env::new();
    let (file, sum) = env.add_archive("download/v1.2.3", "1.2.3", TARGET, "good");
    env.write_sums("download/v1.2.3", &[(file.clone(), sum)]);
    fs::remove_file(env.path(&format!("release/download/v1.2.3/{file}"))).unwrap();
    env.assert_refused(&env.run(&env.file_url(), Some("1.2.3")), "download failed");
}

#[test]
fn missing_sums_file_refuses() {
    let env = Env::new();
    env.add_archive("download/v1.2.3", "1.2.3", TARGET, "good");
    env.assert_refused(&env.run(&env.file_url(), Some("1.2.3")), "download failed");
}

#[test]
fn unwritable_install_dir_refuses_and_keeps_the_old_binary() {
    let env = Env::new();
    env.good_release("download/v1.2.3", "1.2.3", "new");
    fs::create_dir(env.install_dir()).unwrap();
    fs::write(
        env.install_dir().join("code-watch"),
        "#!/bin/sh\necho old\n",
    )
    .unwrap();
    fs::set_permissions(env.install_dir(), fs::Permissions::from_mode(0o555)).unwrap();
    let writable_anyway = fs::write(env.install_dir().join("probe"), "").is_ok();
    let out = env.run(&env.file_url(), Some("1.2.3"));
    fs::set_permissions(env.install_dir(), fs::Permissions::from_mode(0o755)).unwrap();
    if writable_anyway {
        return;
    }
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        fs::read_to_string(env.install_dir().join("code-watch")).unwrap(),
        "#!/bin/sh\necho old\n"
    );
}

#[test]
fn missing_install_dir_is_created_and_a_second_run_replaces_the_binary() {
    let env = Env::new();
    env.good_release("download/v1.0.0", "1.0.0", "first");
    env.good_release("download/v1.1.0", "1.1.0", "second");
    assert!(!env.install_dir().exists());
    assert!(env.run(&env.file_url(), Some("1.0.0")).status.success());
    assert_eq!(run_binary(&env), "first");
    assert!(env.run(&env.file_url(), Some("1.1.0")).status.success());
    assert_eq!(run_binary(&env), "second");
    assert_eq!(
        fs::read_dir(env.install_dir()).unwrap().count(),
        1,
        "no staged file left behind"
    );
}

#[test]
fn files_outside_the_install_dir_are_untouched() {
    let env = Env::new();
    env.good_release("download/v1.2.3", "1.2.3", "good");
    let sentinels = [env.path("home/sentinel"), env.path("release/sentinel")];
    for s in &sentinels {
        fs::write(s, "keep").unwrap();
    }
    assert!(env.run(&env.file_url(), Some("1.2.3")).status.success());
    for s in &sentinels {
        assert_eq!(fs::read_to_string(s).unwrap(), "keep");
    }
    let mut home: Vec<_> = fs::read_dir(env.path("home"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    home.sort();
    assert_eq!(
        home,
        ["bin", "sentinel"],
        "no temp directory left in TMPDIR"
    );
}

#[test]
fn path_hint_appears_only_when_the_dir_is_not_on_path() {
    let env = Env::new();
    env.good_release("download/v1.2.3", "1.2.3", "good");
    let out = env.run(&env.file_url(), Some("1.2.3"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("add it to your PATH"));
}
