//! Per-scan context: where home is, which OS rules apply, caps, and small shared helpers.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::catalog::Catalog;
use crate::geo::Geo;

/// Hard limits that keep a scan bounded on any machine.
#[derive(Debug, Clone)]
pub struct Caps {
    /// Largest config/manifest/rc file parsed.
    pub max_config_bytes: u64,
    /// Largest browser database copied.
    pub max_db_bytes: u64,
    /// Rows read per browser table.
    pub max_rows: u32,
    /// Directory entries visited per collector.
    pub max_entries: u32,
    /// Whole-scan wall clock.
    pub deadline: Duration,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            max_config_bytes: 4 * 1024 * 1024,
            max_db_bytes: 512 * 1024 * 1024,
            max_rows: 2_000_000,
            max_entries: 50_000,
            deadline: Duration::from_secs(60),
        }
    }
}

pub struct Ctx<'a> {
    pub home: PathBuf,
    pub os: &'static str,
    pub projects: Vec<PathBuf>,
    pub catalog: &'a Catalog,
    /// Offline DB-IP lookups for IP-literal hosts; None when the databases did not load.
    pub geo: Option<&'a Geo>,
    pub caps: Caps,
    pub started: Instant,
    /// When set, PATH is read from here instead of the process environment (tests).
    pub path_env: Option<String>,
    /// When set, env vars are read from here instead of the process environment (tests).
    pub env_override: Option<Vec<(String, String)>>,
}

pub fn current_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

impl<'a> Ctx<'a> {
    pub fn out_of_time(&self) -> bool {
        self.started.elapsed() > self.caps.deadline
    }

    pub fn os_matches(&self, os: &str) -> bool {
        os == "all" || os == self.os
    }

    fn config_dir(&self) -> PathBuf {
        match self.os {
            "macos" => self.home.join("Library").join("Application Support"),
            "windows" => self.home.join("AppData").join("Roaming"),
            _ => self.home.join(".config"),
        }
    }

    fn local_dir(&self) -> PathBuf {
        match self.os {
            "macos" => self.home.join("Library").join("Application Support"),
            "windows" => self.home.join("AppData").join("Local"),
            _ => self.home.join(".config"),
        }
    }

    /// Expand a catalog path template. `{project}` templates expand once per `--project` dir;
    /// wildcard path segments are expanded within the global entry and deadline caps.
    pub fn expand(&self, template: &str) -> Vec<PathBuf> {
        let bases: Vec<Option<&PathBuf>> = if template.contains("{project}") {
            self.projects.iter().map(Some).collect()
        } else {
            vec![None]
        };
        let mut out = Vec::new();
        for p in bases {
            let mut s = template
                .replace("{home}", &self.home.to_string_lossy())
                .replace("{config}", &self.config_dir().to_string_lossy())
                .replace("{local}", &self.local_dir().to_string_lossy());
            if let Some(p) = p {
                s = s.replace("{project}", &p.to_string_lossy());
            }
            expand_glob(Path::new(&s), &mut out, self.caps.max_entries as usize, self.started, self.caps.deadline);
            if out.len() >= self.caps.max_entries as usize || self.out_of_time() {
                break;
            }
        }
        out
    }

    /// Show a path with the home directory as `~`, using `/` separators.
    pub fn display(&self, p: &Path) -> String {
        let s = match p.strip_prefix(&self.home) {
            Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
            Ok(rest) => format!("~/{}", rest.to_string_lossy()),
            Err(_) => p.to_string_lossy().to_string(),
        };
        s.replace('\\', "/")
    }

    /// Read a small text file. Returns None when it is missing; Err text when unreadable or too big.
    pub fn read_small(&self, p: &Path) -> Option<Result<String, String>> {
        let meta = match fs::metadata(p) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => return Some(Err(format!("{}: {}", self.display(p), io_reason(&e)))),
        };
        if !meta.is_file() {
            return None;
        }
        if meta.len() > self.caps.max_config_bytes {
            return Some(Err(format!("{}: larger than {} bytes, skipped", self.display(p), self.caps.max_config_bytes)));
        }
        let mut buf = Vec::with_capacity(meta.len() as usize);
        match fs::File::open(p).and_then(|mut f| f.read_to_end(&mut buf)) {
            Ok(_) => Some(Ok(String::from_utf8_lossy(&buf).into_owned())),
            Err(e) => Some(Err(format!("{}: {}", self.display(p), io_reason(&e)))),
        }
    }

    pub fn env_vars(&self) -> Vec<(String, String)> {
        match &self.env_override {
            Some(v) => v.clone(),
            None => std::env::vars_os()
                .map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()))
                .collect(),
        }
    }
}

fn expand_glob(p: &Path, out: &mut Vec<PathBuf>, max: usize, started: Instant, deadline: Duration) {
    if out.len() >= max || started.elapsed() > deadline {
        return;
    }
    // Catalog globs support one `*` in a path segment (for example `python*` or `*.md`).
    let comps: Vec<_> = p.components().collect();
    if let Some(i) = comps.iter().position(|c| c.as_os_str().to_string_lossy().contains('*')) {
        let parent: PathBuf = comps[..i].iter().collect();
        let rest: PathBuf = comps[i + 1..].iter().collect();
        let pattern = comps[i].as_os_str().to_string_lossy();
        if let Ok(rd) = fs::read_dir(&parent) {
            let mut names: Vec<_> = rd
                .flatten()
                .filter(|e| wildcard_match(&e.file_name().to_string_lossy(), &pattern))
                .take(max.saturating_sub(out.len()))
                .map(|e| e.path())
                .collect();
            names.sort();
            for n in names {
                expand_glob(&n.join(&rest), out, max, started, deadline);
                if out.len() >= max || started.elapsed() > deadline {
                    break;
                }
            }
        }
    } else {
        out.push(p.to_path_buf());
    }
}

fn wildcard_match(name: &str, pattern: &str) -> bool {
    let Some((prefix, suffix)) = pattern.split_once('*') else { return name == pattern };
    name.starts_with(prefix) && name.ends_with(suffix) && name.len() >= prefix.len() + suffix.len()
}

pub fn io_reason(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => "permission denied",
        std::io::ErrorKind::NotFound => "not found",
        _ => "unreadable",
    }
}

/// Git blob SHA-1 of a file's bytes: sha1("blob <len>\0" + bytes).
pub fn git_blob_oid(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(format!("blob {}\0", bytes.len()).as_bytes());
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_segment_globs() {
        assert!(wildcard_match("python3.12", "python*"));
        assert!(wildcard_match("security.instructions.md", "*.instructions.md"));
        assert!(!wildcard_match("security.md", "*.instructions.md"));
    }
}
