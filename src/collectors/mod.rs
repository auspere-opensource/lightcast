//! Collectors: each turns local files into findings, with its own status and caps.

pub mod agents;
pub mod browser;
pub mod cli;
pub mod customizations;
pub mod ide;
pub mod keys;
pub mod mcp;
pub mod skills;

use std::time::Instant;

use crate::context::Ctx;
use crate::model::{CollectorRun, CollectorState, Finding};

pub struct Output {
    pub findings: Vec<Finding>,
    pub run: CollectorRun,
}

/// Small accumulator every collector uses for status bookkeeping.
pub struct Tracker {
    name: &'static str,
    started: Instant,
    pub sources_read: u32,
    pub problems: Vec<String>,
    pub unreadable: u32,
    pub capped: bool,
}

impl Tracker {
    pub fn new(name: &'static str) -> Tracker {
        Tracker { name, started: Instant::now(), sources_read: 0, problems: Vec::new(), unreadable: 0, capped: false }
    }

    pub fn unreadable(&mut self, why: String) {
        self.unreadable += 1;
        self.problems.push(why);
    }

    pub fn capped(&mut self, why: String) {
        self.capped = true;
        self.problems.push(why);
    }

    pub fn finish(self, findings: Vec<Finding>) -> Output {
        let status = if self.capped {
            CollectorState::Partial
        } else if self.unreadable > 0 && self.sources_read == 0 {
            CollectorState::Unreadable
        } else if self.unreadable > 0 {
            CollectorState::Partial
        } else {
            CollectorState::Ok
        };
        Output {
            findings,
            run: CollectorRun {
                name: self.name.to_string(),
                status,
                duration_ms: self.started.elapsed().as_millis() as u64,
                sources_read: self.sources_read,
                problems: self.problems,
            },
        }
    }
}

pub const ALL: &[&str] = &["browser", "mcp", "agents", "customizations", "skills", "ide", "cli", "keys"];

pub fn run(name: &str, ctx: &Ctx) -> Output {
    match name {
        "browser" => browser::collect(ctx),
        "mcp" => mcp::collect(ctx),
        "agents" => agents::collect(ctx),
        "customizations" => customizations::collect(ctx),
        "skills" => skills::collect(ctx),
        "ide" => ide::collect(ctx),
        "cli" => cli::collect(ctx),
        "keys" => keys::collect(ctx),
        _ => unreachable!("unknown collector {name}"),
    }
}

/// Basename of a command without directories or a Windows executable suffix, lowercased.
pub fn command_basename(cmd: &str) -> String {
    let base = cmd.rsplit(['/', '\\']).next().unwrap_or(cmd).to_lowercase();
    for ext in [".exe", ".cmd", ".bat", ".ps1"] {
        if let Some(stripped) = base.strip_suffix(ext) {
            return stripped.to_string();
        }
    }
    base
}

/// Host part of a URL, lowercase, without userinfo or port. Nothing else of the URL is kept.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let hostport = authority.rsplit('@').next()?;
    let host = if hostport.starts_with('[') {
        hostport.split(']').next()?.trim_start_matches('[')
    } else {
        hostport.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// Path part of a URL without query or fragment.
pub fn url_path(url: &str) -> String {
    let rest = match url.split_once("://") {
        Some((_, r)) => r,
        None => return String::new(),
    };
    let after_host = match rest.find('/') {
        Some(i) => &rest[i..],
        None => return "/".to_string(),
    };
    after_host.split(['?', '#']).next().unwrap_or("/").to_string()
}

/// Days since 1970-01-01 to YYYY-MM-DD (proleptic Gregorian).
pub fn civil_date(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn unix_secs_to_date(secs: i64) -> String {
    civil_date(secs.div_euclid(86_400))
}

pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let date = unix_secs_to_date(secs);
    let t = secs.rem_euclid(86_400);
    format!("{date}T{:02}:{:02}:{:02}Z", t / 3600, (t % 3600) / 60, t % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parts() {
        assert_eq!(url_host("https://user:pw@Chat.OpenAI.com:443/c/abc?x=1#f").as_deref(), Some("chat.openai.com"));
        assert_eq!(url_path("https://chatgpt.com/c/abc?x=1#f"), "/c/abc");
        assert_eq!(url_path("https://chatgpt.com"), "/");
        assert_eq!(url_host("not a url"), None);
    }

    #[test]
    fn dates() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(unix_secs_to_date(1_762_560_000), "2025-11-08");
    }

    #[test]
    fn basenames() {
        assert_eq!(command_basename("C:\\Program Files\\nodejs\\npx.cmd"), "npx");
        assert_eq!(command_basename("/usr/bin/bash"), "bash");
    }
}
