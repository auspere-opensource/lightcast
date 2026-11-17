//! Upstream tracing: which AI providers (and other destinations) a finding can send data to, and
//! in which country each is based.
//!
//! Everything is offline. Hostnames are never resolved; only IP literals are geolocated (DB-IP).
//! Package inspection reads dependency NAMES and searches the launched package's own code for
//! catalogued provider API hostnames. No user file content is read.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::catalog::Provider;
use crate::collectors::url_host;
use crate::context::Ctx;
use crate::geo::{ip_literal, Place};
use crate::model::{Confidence, Upstream};

pub const HQ_BASIS: &str = "provider headquarters (catalog, unverified); processing region may differ";
pub const UNRESOLVED_BASIS: &str = "unknown: the hostname was not resolved (scans make no network calls)";

fn url_site(url: &str) -> String {
    url_host(url).map(|h| h.trim_start_matches("www.").to_string()).unwrap_or_else(|| url.to_string())
}

/// Country basis for a provider, naming the source that supports it.
pub fn provider_country_basis(p: &Provider) -> String {
    if p.hq_country == "LOCAL" {
        return "runs on this machine or network".into();
    }
    let Some(s) = &p.source else { return HQ_BASIS.into() };
    let mut out = match (p.status.as_str(), s.source_kind.as_str()) {
        ("verified", "primary") => format!("provider headquarters per its own legal page ({})", url_site(&s.source_url)),
        ("verified", _) => format!("provider headquarters per {} (secondary source)", url_site(&s.source_url)),
        _ => format!("provider headquarters, unconfirmed ({})", url_site(&s.source_url)),
    };
    if !s.regional_entities.is_empty() {
        let ents: Vec<String> = s.regional_entities.iter().take(3).map(|e| format!("{} for {}", e.country, e.region)).collect();
        let more = s.regional_entities.len().saturating_sub(3);
        out.push_str(&format!("; regional contracting entities: {}{}", ents.join(", "), if more > 0 { format!(" and {more} more") } else { String::new() }));
    }
    out.push_str("; processing region may differ");
    out
}

/// "CN: \"we … store your Personal Data in People's Republic of China\"" when the provider says where.
pub fn provider_processing(p: &Provider) -> Option<String> {
    let s = p.source.as_ref()?;
    if s.processing_countries.is_empty() {
        return None;
    }
    Some(format!("{} (provider's own statement: \"{}\")", s.processing_countries.join("+"), s.processing_note))
}

/// Upstream for a catalogued provider.
pub fn for_provider(p: &Provider, basis: String, confidence: Confidence) -> Upstream {
    Upstream {
        provider: p.name.clone(),
        provider_id: Some(p.id.clone()),
        host: None,
        country: Some(p.hq_country.clone()),
        country_basis: provider_country_basis(p),
        processing: provider_processing(p),
        via: vec![],
        basis: vec![basis],
        confidence,
    }
}

fn cloud_label(cloud: &str) -> &'static str {
    match cloud {
        "aws" => "AWS",
        "gcp" => "Google Cloud",
        _ => "cloud",
    }
}

/// Pin an upstream to the cloud region that serves it. The country becomes the region's country
/// (where the request is processed); headquarters moves into the basis. `how` says where the code
/// came from ("the endpoint host", "AWS_REGION in the settings env").
pub fn apply_region(ctx: &Ctx, u: &mut Upstream, p: &Provider, code: &str, how: &str) {
    let Some(cloud) = p.cloud.as_deref() else { return };
    let hq = format!("provider headquarters {}", p.hq_country);
    match ctx.catalog.cloud_region(cloud, code) {
        Some(r) => {
            u.country = r.country.clone();
            u.country_basis = match &r.country {
                Some(_) => format!("{} region {} ({}) from {how}, per {}; {hq}", cloud_label(cloud), r.code, r.location, url_site(&r.source_url)),
                None => format!(
                    "{} {} endpoint ({}) from {how}: no single country, and the provider says it does not guarantee data residency; {hq}",
                    cloud_label(cloud),
                    r.code,
                    r.location
                ),
            };
            u.processing = Some(format!("{} region {}{}", cloud_label(cloud), r.code, r.country.as_deref().map(|c| format!(" ({c})")).unwrap_or_default()));
        }
        None => {
            u.country_basis = format!("{} region code {code} from {how} is not in the region catalog; {}", cloud_label(cloud), u.country_basis);
        }
    }
    u.basis.push(format!("{} region {code} from {how}", cloud_label(cloud)));
}

/// Apply region env vars (e.g. AWS_REGION) to every matching provider upstream. Only values that are
/// known region codes are used; any other value is ignored and never stored.
pub fn apply_region_env(ctx: &Ctx, ups: &mut [Upstream], env: &[(String, String)], src: &str) {
    for u in ups.iter_mut() {
        let Some(p) = u.provider_id.as_deref().and_then(|id| ctx.catalog.provider(id)) else { continue };
        let Some(cloud) = p.cloud.as_deref() else { continue };
        if u.basis.iter().any(|b| b.contains(" region ") && b.contains("the endpoint host")) {
            continue; // an explicit regional endpoint wins over an env default
        }
        for name in &p.region_env {
            if let Some((_, v)) = env.iter().find(|(k, _)| k == name) {
                let code = v.trim().to_ascii_lowercase();
                if ctx.catalog.cloud_region(cloud, &code).is_some() {
                    apply_region(ctx, u, p, &code, &format!("{name} in the {src}"));
                    break;
                }
            }
        }
    }
}

/// Upstream for a host: a catalogued provider when one matches, else the host itself.
pub fn for_host(ctx: &Ctx, host: &str, basis: String) -> Upstream {
    if let Some((p, code)) = ctx.catalog.provider_for_regional_host(host) {
        let mut u = for_provider(p, basis, Confidence::High);
        u.host = Some(host.to_string());
        apply_region(ctx, &mut u, p, &code, "the endpoint host");
        return u;
    }
    if let Some(p) = ctx.catalog.provider_for_host(host) {
        let mut u = for_provider(p, basis, Confidence::High);
        u.host = Some(host.to_string());
        return u;
    }
    if let Some(r) = ctx.catalog.file.tools.mcp_remote_hosts.iter().find(|r| r.host == host) {
        return Upstream {
            provider: r.provider.clone(),
            provider_id: None,
            host: Some(host.to_string()),
            country: r.hq_country.clone(),
            country_basis: if r.hq_country.is_some() { HQ_BASIS.into() } else { "unknown".into() },
            processing: None,
            via: vec![],
            basis: vec![basis],
            confidence: Confidence::High,
        };
    }
    let (country, country_basis) = match ip_literal(host).and_then(|ip| ctx.geo.map(|g| g.lookup(ip))) {
        Some(Place::NonPublic(kind)) => (Some("LOCAL".to_string()), format!("{kind} address, not on the public internet")),
        Some(p @ Place::Public { .. }) => match &p {
            Place::Public { country_code, .. } => (country_code.clone(), format!("{} (IP Geolocation by DB-IP)", p.describe())),
            _ => unreachable!(),
        },
        None if host == "localhost" || host.ends_with(".localhost") => (Some("LOCAL".into()), "this machine".into()),
        None => (None, UNRESOLVED_BASIS.into()),
    };
    Upstream {
        provider: host.to_string(),
        provider_id: None,
        host: Some(host.to_string()),
        country,
        country_basis,
        processing: None,
        via: vec![],
        basis: vec![basis],
        confidence: Confidence::Medium,
    }
}

/// Host from an endpoint value such as "https://gw.example/v1?k=x" or "127.0.0.1:11434".
/// Only the host survives; the rest of the value is dropped here.
pub fn endpoint_host(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    if v.contains("://") {
        url_host(v)
    } else {
        url_host(&format!("http://{v}"))
    }
}

/// Merge links to the same destination through the same chain, keeping all evidence.
pub fn merge(list: Vec<Upstream>) -> Vec<Upstream> {
    let mut out: Vec<Upstream> = Vec::new();
    for u in list {
        let key = |x: &Upstream| (x.provider_id.clone().unwrap_or_else(|| x.provider.clone()), x.via.clone());
        if let Some(e) = out.iter_mut().find(|e| key(e) == key(&u)) {
            for b in u.basis {
                if !e.basis.contains(&b) {
                    e.basis.push(b);
                }
            }
            e.confidence = e.confidence.max(u.confidence);
            if e.host.is_none() {
                e.host = u.host;
            }
        } else {
            out.push(u);
        }
    }
    out.sort_by(|a, b| a.via.len().cmp(&b.via.len()).then(a.provider.cmp(&b.provider)));
    out
}

/// What inspecting an installed package found.
#[derive(Default, Clone)]
pub struct PackageEvidence {
    /// provider id -> evidence lines
    pub providers: BTreeMap<String, Vec<String>>,
    pub installed_at: Option<String>,
    pub files_scanned: u32,
    pub capped: bool,
}

const CODE_EXT: &[&str] = &["js", "mjs", "cjs", "ts", "py"];
const MAX_FILES: u32 = 600;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;

pub struct PackageInspector<'c, 'a> {
    ctx: &'c Ctx<'a>,
    cache: HashMap<(String, String), PackageEvidence>,
}

impl<'c, 'a> PackageInspector<'c, 'a> {
    pub fn new(ctx: &'c Ctx<'a>) -> Self {
        PackageInspector { ctx, cache: HashMap::new() }
    }

    pub fn inspect(&mut self, eco: &str, name: &str) -> PackageEvidence {
        let key = (eco.to_string(), name.to_lowercase());
        if let Some(e) = self.cache.get(&key) {
            return e.clone();
        }
        let ev = match eco {
            "npm" => self.npm(name),
            "pypi" => self.pypi(name),
            _ => PackageEvidence::default(),
        };
        self.cache.insert(key, ev.clone());
        ev
    }

    fn roots(&self, kind: &str) -> Vec<(String, PathBuf)> {
        let mut v = Vec::new();
        for r in self.ctx.catalog.file.locations.package_roots.iter().filter(|r| r.kind == kind && self.ctx.os_matches(&r.os)) {
            for p in self.ctx.expand(&r.path) {
                if p.is_dir() {
                    v.push((r.layout.clone(), p));
                }
            }
        }
        v
    }

    fn npm(&self, name: &str) -> PackageEvidence {
        let mut ev = PackageEvidence::default();
        // Find the node_modules tree that holds the launched package.
        let mut tree: Option<PathBuf> = None;
        for (layout, root) in self.roots("npm") {
            let nm = match layout.as_str() {
                "npx" => {
                    let Some(Ok(text)) = self.ctx.read_small(&root.join("package.json")) else { continue };
                    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
                    let launched = v.get("dependencies").and_then(|d| d.as_object()).is_some_and(|d| d.contains_key(name));
                    if !launched {
                        continue;
                    }
                    root.join("node_modules")
                }
                _ => root.clone(),
            };
            if nm.join(name).join("package.json").is_file() {
                tree = Some(nm);
                break;
            }
        }
        let Some(nm) = tree else { return ev };
        ev.installed_at = Some(self.ctx.display(&nm.join(name)));
        for p in &self.ctx.catalog.file.upstream.providers {
            for sdk in &p.npm {
                if nm.join(sdk).join("package.json").is_file() {
                    ev.providers.entry(p.id.clone()).or_default().push(format!("installed dependency tree includes the {sdk} SDK"));
                }
            }
        }
        self.scan_code(&nm.join(name), &mut ev);
        ev
    }

    fn pypi(&self, name: &str) -> PackageEvidence {
        let mut ev = PackageEvidence::default();
        let norm = |s: &str| s.to_lowercase().replace('-', "_");
        let want = norm(name);
        for (_, root) in self.roots("pypi") {
            for sp in site_packages(&root) {
                let Ok(rd) = fs::read_dir(&sp) else { continue };
                let dists: Vec<String> = rd
                    .flatten()
                    .filter_map(|e| e.file_name().to_str().map(str::to_string))
                    .filter_map(|n| n.strip_suffix(".dist-info").map(|d| d.split('-').next().unwrap_or(d).to_string()))
                    .collect();
                if !dists.iter().any(|d| norm(d) == want) {
                    continue;
                }
                ev.installed_at = Some(self.ctx.display(&sp));
                for d in &dists {
                    if let Some(p) = self.ctx.catalog.provider_for_sdk("pypi", d) {
                        ev.providers.entry(p.id.clone()).or_default().push(format!("installed environment includes the {d} SDK"));
                    }
                }
                self.scan_code(&sp.join(&want), &mut ev);
                return ev;
            }
        }
        ev
    }

    /// Search the package's own code (not its nested dependencies) for catalogued provider hosts.
    fn scan_code(&self, dir: &Path, ev: &mut PackageEvidence) {
        if !dir.is_dir() {
            return;
        }
        let hosts: Vec<(&str, &str)> = self
            .ctx
            .catalog
            .file
            .upstream
            .providers
            .iter()
            .flat_map(|p| p.api_hosts.iter().filter(|h| h.contains('.') && h.matches('.').count() >= 1).map(move |h| (p.id.as_str(), h.as_str())))
            .collect();
        let mut total = 0u64;
        let mut stack = vec![(dir.to_path_buf(), 0u32)];
        while let Some((d, depth)) = stack.pop() {
            let Ok(rd) = fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                let fname = e.file_name();
                if p.is_dir() {
                    if depth < 8 && fname != "node_modules" && fname != "__pycache__" && fname != ".git" {
                        stack.push((p, depth + 1));
                    }
                    continue;
                }
                let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
                if !CODE_EXT.contains(&ext) {
                    continue;
                }
                let Ok(meta) = e.metadata() else { continue };
                if meta.len() > MAX_FILE_BYTES {
                    continue;
                }
                if ev.files_scanned >= MAX_FILES || total + meta.len() > MAX_TOTAL_BYTES {
                    ev.capped = true;
                    return;
                }
                let Ok(bytes) = fs::read(&p) else { continue };
                ev.files_scanned += 1;
                total += meta.len();
                let text = String::from_utf8_lossy(&bytes);
                for (pid, host) in &hosts {
                    if contains_host(&text, host) {
                        let line = format!("package code references {host}");
                        let v = ev.providers.entry(pid.to_string()).or_default();
                        if !v.contains(&line) {
                            v.push(line);
                        }
                    }
                }
            }
        }
    }
}

/// True when `host` appears as a whole hostname (not inside a longer name).
fn contains_host(text: &str, host: &str) -> bool {
    let b = text.as_bytes();
    let mut from = 0;
    while let Some(i) = text[from..].find(host) {
        let s = from + i;
        let e = s + host.len();
        let before_ok = s == 0 || !(b[s - 1].is_ascii_alphanumeric() || b[s - 1] == b'-' || b[s - 1] == b'_');
        let after_ok = e >= b.len() || !(b[e].is_ascii_alphanumeric() || b[e] == b'-' || b[e] == b'_');
        // A preceding '.' means a subdomain of host, which still belongs to the provider.
        if before_ok && after_ok {
            return true;
        }
        from = e;
    }
    false
}

fn site_packages(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let win = root.join("Lib").join("site-packages");
    if win.is_dir() {
        out.push(win);
    }
    if let Ok(rd) = fs::read_dir(root.join("lib")) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("python") {
                let sp = e.path().join("site-packages");
                if sp.is_dir() {
                    out.push(sp);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_in_code() {
        assert!(contains_host("fetch('https://api.elevenlabs.io/v1/tts')", "api.elevenlabs.io"));
        assert!(contains_host("const u = \"studio-api.prod.suno.com\"", "suno.com"));
        assert!(!contains_host("notsuno.com", "suno.com"));
    }

    #[test]
    fn resolve_localhost_without_external_dns() {
        // localhost is answered from the hosts file, so this test sends nothing off the machine.
        let r = resolve_hosts(&["localhost".to_string()]);
        let got = &r["localhost"];
        assert!(!got.failed, "{got:?}");
        let geo = crate::geo::Geo::embedded();
        let mut u = Upstream {
            provider: "localhost".into(),
            provider_id: None,
            host: Some("localhost".into()),
            country: None,
            country_basis: String::new(),
            processing: None,
            via: vec![],
            basis: vec![],
            confidence: Confidence::Medium,
        };
        apply_resolution(&mut u, got, geo.as_ref());
        assert_eq!(u.country.as_deref(), Some("LOCAL"));
        assert!(u.country_basis.contains("--resolve"));
    }

    #[test]
    fn failed_resolution_is_reported_not_guessed() {
        let mut u = Upstream {
            provider: "x".into(),
            provider_id: None,
            host: Some("x".into()),
            country: None,
            country_basis: String::new(),
            processing: None,
            via: vec![],
            basis: vec![],
            confidence: Confidence::Medium,
        };
        apply_resolution(&mut u, &Resolved { ips: vec![], failed: true }, None);
        assert!(u.country.is_none());
        assert!(u.country_basis.contains("no address"));
    }

    #[test]
    fn endpoint_hosts() {
        assert_eq!(endpoint_host("https://gw.example.com/v1?key=secret").as_deref(), Some("gw.example.com"));
        assert_eq!(endpoint_host("127.0.0.1:11434").as_deref(), Some("127.0.0.1"));
        assert_eq!(endpoint_host(""), None);
    }
}

/// Opt-in (`--resolve`): resolve destination hosts whose country is unknown through the system
/// resolver and geolocate the answers with DB-IP. This is the ONLY network activity the tool can
/// perform, and only when asked. At most `MAX_RESOLVE` hosts, each bounded by `RESOLVE_TIMEOUT`.
pub const MAX_RESOLVE: usize = 32;
pub const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug, Clone)]
pub struct Resolved {
    pub ips: Vec<std::net::IpAddr>,
    pub failed: bool,
}

/// Resolve hostnames in parallel; each lookup gets its own thread so a slow resolver cannot block
/// past the timeout (an abandoned lookup thread ends when the OS resolver returns).
pub fn resolve_hosts(hosts: &[String]) -> BTreeMap<String, Resolved> {
    use std::net::ToSocketAddrs;
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();
    for h in hosts.iter().take(MAX_RESOLVE) {
        let tx = tx.clone();
        let h = h.clone();
        std::thread::spawn(move || {
            let ips: Vec<std::net::IpAddr> = (h.as_str(), 443u16).to_socket_addrs().map(|it| it.map(|a| a.ip()).collect()).unwrap_or_default();
            let _ = tx.send((h, ips));
        });
    }
    drop(tx);
    let deadline = std::time::Instant::now() + RESOLVE_TIMEOUT;
    let mut out: BTreeMap<String, Resolved> = hosts.iter().take(MAX_RESOLVE).map(|h| (h.clone(), Resolved { ips: vec![], failed: true })).collect();
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        match rx.recv_timeout(left) {
            Ok((h, mut ips)) => {
                ips.sort();
                ips.dedup();
                let failed = ips.is_empty();
                out.insert(h, Resolved { ips, failed });
            }
            Err(_) => break,
        }
    }
    out
}

/// Apply resolution results to an upstream whose country is unknown.
pub fn apply_resolution(u: &mut Upstream, r: &Resolved, geo: Option<&crate::geo::Geo>) {
    if r.failed {
        u.country_basis = "unknown: --resolve found no address (or timed out)".into();
        return;
    }
    let places: Vec<(std::net::IpAddr, Place)> = r.ips.iter().filter_map(|ip| geo.map(|g| (*ip, g.lookup(*ip)))).collect();
    let mut countries: Vec<String> = places
        .iter()
        .filter_map(|(_, p)| match p {
            Place::NonPublic(_) => Some("LOCAL".to_string()),
            Place::Public { country_code, .. } => country_code.clone(),
        })
        .collect();
    countries.sort();
    countries.dedup();
    if let Some((ip, p)) = places.first() {
        u.country = Some(countries.join("+")).filter(|c| !c.is_empty());
        u.country_basis = format!(
            "resolved with --resolve to {ip}{} ({}); CDN or anycast addresses show an edge location, not the operator",
            if r.ips.len() > 1 { format!(" and {} more", r.ips.len() - 1) } else { String::new() },
            p.describe()
        );
    }
}
