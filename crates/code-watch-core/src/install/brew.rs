use crate::finding::{Finding, Severity};

use super::{finding, redact};

/// `brew install|reinstall|upgrade <user>/<repo>/<formula>`, `brew tap <user>/<repo>` and a
/// formula given as a `.rb` path or URL run Ruby from outside homebrew's own taps. Nothing is
/// read from disk: taps are not inspected.
pub(super) fn analyze(args: &[String]) -> Vec<Finding> {
    let mut positionals = args.iter().filter(|a| !a.starts_with('-'));
    let Some(sub) = positionals.next() else {
        return Vec::new();
    };
    if sub == "bundle" {
        return vec![super::unchecked_command("brew bundle")];
    }
    let named: Vec<&String> = positionals.collect();
    let hits: Vec<&String> = match sub.as_str() {
        "install" | "reinstall" | "upgrade" => named
            .into_iter()
            .filter(|n| is_foreign_formula(n))
            .collect(),
        "tap" => named
            .into_iter()
            .take(1)
            .filter(|n| is_foreign_tap(n))
            .collect(),
        _ => Vec::new(),
    };
    hits.into_iter()
        .map(|name| redact(name))
        .map(|name| {
            finding(
                "install/brew-unknown-tap",
                Severity::Warn,
                None,
                None,
                &format!("brew {sub} {name}"),
                Some(name),
            )
        })
        .collect()
}

fn is_homebrew(user: &str) -> bool {
    user.eq_ignore_ascii_case("homebrew")
}

fn is_foreign_tap(name: &str) -> bool {
    let mut parts = name.split('/');
    matches!((parts.next(), parts.next(), parts.next()), (Some(u), Some(r), None) if !u.is_empty() && !r.is_empty() && !is_homebrew(u))
}

fn is_foreign_formula(name: &str) -> bool {
    if name.contains("://") || name.ends_with(".rb") {
        return true;
    }
    let parts: Vec<&str> = name.split('/').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty()) && !is_homebrew(parts[0])
}
