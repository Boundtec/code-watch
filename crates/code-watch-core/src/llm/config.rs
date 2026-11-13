use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::anthropic::Anthropic;
use super::http::KeyFn;
use super::openai::OpenAiCompat;
use super::provider::LlmProvider;

/// Total time for the one call when `timeout_secs` is not set.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);
pub const MAX_TIMEOUT_SECS: u64 = 120;
const OPENAI_BASE: &str = "https://api.openai.com/v1";
const ANTHROPIC_BASE: &str = "https://api.anthropic.com";

#[derive(Deserialize)]
struct File {
    llm: Option<Section>,
}

/// `deny_unknown_fields`: a typo in the config must not silently leave the layer half set up.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    provider: Kind,
    base_url: Option<String>,
    model: String,
    api_key_env: Option<String>,
    #[serde(default)]
    clone_hook: bool,
    timeout_secs: Option<u64>,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    OpenaiCompat,
    Anthropic,
    Local,
}

/// What the config says about the layer.
pub enum Resolution {
    /// Not configured, or not wanted in this mode: every report says `llm off`.
    Off,
    /// Configured but unusable; the reason is safe to print (never a key or a config excerpt).
    Skipped(String),
    On(Box<dyn LlmProvider>),
}

/// Reads `<dir>/code-watch/config.toml`. `hook` is the clone-time scan, where the layer runs
/// only when `clone_hook = true`: a checkout must not wait on the network or send a private repo
/// to a remote provider the user did not choose for that.
pub fn resolve(dir: Option<&Path>, hook: bool, key: KeyFn) -> Resolution {
    let Some(dir) = dir else {
        return Resolution::Off;
    };
    let text = match fs::read_to_string(dir.join("code-watch/config.toml")) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Resolution::Off,
        Err(_) => return Resolution::Skipped("the config file could not be read".into()),
    };
    let Ok(file) = toml::from_str::<File>(&text) else {
        return Resolution::Skipped("the [llm] config is not valid".into());
    };
    let Some(section) = file.llm else {
        return Resolution::Off;
    };
    if hook && !section.clone_hook {
        return Resolution::Off;
    }
    match build(section, key) {
        Ok(provider) => Resolution::On(provider),
        Err(why) => Resolution::Skipped(why.into()),
    }
}

fn build(s: Section, key: KeyFn) -> Result<Box<dyn LlmProvider>, &'static str> {
    if s.model.trim().is_empty() {
        return Err("the [llm] config has no model");
    }
    let timeout = match s.timeout_secs {
        None => DEFAULT_TIMEOUT,
        Some(secs @ 1..=MAX_TIMEOUT_SECS) => Duration::from_secs(secs),
        Some(_) => return Err("the [llm] timeout_secs is out of range"),
    };
    let base = match (s.base_url, s.provider) {
        (Some(url), _) => url,
        (None, Kind::OpenaiCompat) => OPENAI_BASE.to_owned(),
        (None, Kind::Anthropic) => ANTHROPIC_BASE.to_owned(),
        (None, Kind::Local) => return Err("the local provider needs a base_url"),
    };
    check_base(&base, s.provider == Kind::Local)?;
    let key_env = s.api_key_env.filter(|n| !n.is_empty());
    if let Some(name) = &key_env {
        if key(name).is_none_or(|v| v.is_empty()) && s.provider != Kind::Local {
            return Err("the API key variable is not set");
        }
    } else if s.provider != Kind::Local {
        return Err("the [llm] config has no api_key_env");
    }
    let nonempty: KeyFn = Box::new(move |name| key(name).filter(|v| !v.is_empty()));
    Ok(match s.provider {
        Kind::Anthropic => Box::new(Anthropic::new(
            &base,
            &s.model,
            key_env.as_deref().unwrap_or_default(),
            nonempty,
            timeout,
        )),
        Kind::OpenaiCompat | Kind::Local => Box::new(OpenAiCompat::new(
            &base, &s.model, key_env, nonempty, timeout,
        )),
    })
}

/// A remote provider must use https, so the key and the repo text are not sent in the clear. The
/// local provider is loopback only: it is the one that may skip the key and use http, and that is
/// safe only when the traffic never leaves the machine.
fn check_base(base: &str, local: bool) -> Result<(), &'static str> {
    let uri: ureq::http::Uri = base
        .parse()
        .map_err(|_| "the [llm] base_url is not a URL")?;
    let host = uri.host().ok_or("the [llm] base_url is not a URL")?;
    if local {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !loopback || !matches!(uri.scheme_str(), Some("http" | "https")) {
            return Err("the local provider must use a loopback address");
        }
    } else if uri.scheme_str() != Some("https") {
        return Err("a remote provider must use https");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(name: &str) -> Option<String> {
        (name == "FAKE_KEY").then(|| "fake-key-123".to_owned())
    }

    fn resolve_text(config: &str, hook: bool) -> Resolution {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("code-watch")).unwrap();
        fs::write(dir.path().join("code-watch/config.toml"), config).unwrap();
        resolve(Some(dir.path()), hook, Box::new(env))
    }

    fn why(r: Resolution) -> String {
        match r {
            Resolution::Skipped(w) => w,
            Resolution::Off => "off".into(),
            Resolution::On(_) => "on".into(),
        }
    }

    const OPENAI: &str =
        "[llm]\nprovider = \"openai_compat\"\nmodel = \"m\"\napi_key_env = \"FAKE_KEY\"\n";

    #[test]
    fn no_config_file_no_table_or_no_directory_means_off() {
        assert_eq!(why(resolve(None, false, Box::new(env))), "off");
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            why(resolve(Some(empty.path()), false, Box::new(env))),
            "off"
        );
        assert_eq!(why(resolve_text("[other]\nx = 1\n", false)), "off");
    }

    #[test]
    fn a_complete_config_turns_the_layer_on() {
        assert_eq!(why(resolve_text(OPENAI, false)), "on");
        let anthropic =
            "[llm]\nprovider = \"anthropic\"\nmodel = \"m\"\napi_key_env = \"FAKE_KEY\"\n";
        assert_eq!(why(resolve_text(anthropic, false)), "on");
    }

    #[test]
    fn a_broken_config_is_skipped_with_a_reason_and_never_off() {
        let cases = [
            (
                "[llm]\nprovider = \"nope\"\nmodel = \"m\"\n",
                "is not valid",
            ),
            (
                "[llm]\nprovider = \"anthropic\"\nmodel = \"m\"\nextra = 1\n",
                "is not valid",
            ),
            ("not toml [", "is not valid"),
            (
                "[llm]\nprovider = \"anthropic\"\nmodel = \" \"\napi_key_env = \"FAKE_KEY\"\n",
                "no model",
            ),
            (
                "[llm]\nprovider = \"anthropic\"\nmodel = \"m\"\n",
                "no api_key_env",
            ),
            (
                "[llm]\nprovider = \"anthropic\"\nmodel = \"m\"\napi_key_env = \"UNSET\"\n",
                "variable is not set",
            ),
            (
                "[llm]\nprovider = \"openai_compat\"\nmodel = \"m\"\napi_key_env = \"FAKE_KEY\"\nbase_url = \"http://api.example.com/v1\"\n",
                "must use https",
            ),
            (
                "[llm]\nprovider = \"local\"\nmodel = \"m\"\n",
                "needs a base_url",
            ),
            (
                "[llm]\nprovider = \"local\"\nmodel = \"m\"\nbase_url = \"http://10.0.0.5:11434/v1\"\n",
                "loopback",
            ),
            (
                "[llm]\nprovider = \"local\"\nmodel = \"m\"\nbase_url = \"http://localhost.evil.com/v1\"\n",
                "loopback",
            ),
        ];
        for (config, expect) in cases {
            let w = why(resolve_text(config, false));
            assert!(w.contains(expect), "{config}: {w}");
            assert!(!w.contains("fake-key-123"));
        }
    }

    #[test]
    fn an_unreadable_config_file_is_skipped_not_off() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("code-watch/config.toml")).unwrap();
        let w = why(resolve(Some(dir.path()), false, Box::new(env)));
        assert!(w.contains("could not be read"), "{w}");
    }

    #[test]
    fn local_runs_without_a_key_on_loopback_only() {
        for base in [
            "http://localhost:11434/v1",
            "http://127.0.0.1:1234/v1",
            "http://[::1]:8000/v1",
        ] {
            let config =
                format!("[llm]\nprovider = \"local\"\nmodel = \"m\"\nbase_url = \"{base}\"\n");
            assert_eq!(why(resolve_text(&config, false)), "on", "{base}");
        }
    }

    #[test]
    fn the_timeout_has_a_default_a_cap_and_a_floor() {
        let with = |t: &str| format!("{OPENAI}timeout_secs = {t}\n");
        assert_eq!(why(resolve_text(&with("30"), false)), "on");
        assert_eq!(why(resolve_text(&with("120"), false)), "on");
        for bad in ["0", "121"] {
            assert!(why(resolve_text(&with(bad), false)).contains("out of range"));
        }
    }

    #[test]
    fn the_clone_hook_runs_the_layer_only_when_asked() {
        assert_eq!(why(resolve_text(OPENAI, true)), "off");
        let opted_in = format!("{OPENAI}clone_hook = true\n");
        assert_eq!(why(resolve_text(&opted_in, true)), "on");
        assert_eq!(why(resolve_text(&opted_in, false)), "on");
    }
}
