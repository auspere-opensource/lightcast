//! Runs collectors and assembles the [`Report`]: ids, summary, headline, paranoid filtering.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use crate::catalog::Catalog;
use crate::collectors::{self, now_rfc3339};
use crate::context::{current_os, sha256_hex, Caps, Ctx};
use crate::geo::Geo;
use crate::model::*;

pub struct ScanOptions {
    pub home: PathBuf,
    pub os: &'static str,
    pub projects: Vec<PathBuf>,
    pub only: Vec<String>,
    pub paranoid: bool,
    pub show_hostname: bool,
    pub caps: Caps,
    pub path_env: Option<String>,
    pub env_override: Option<Vec<(String, String)>>,
    /// Opt-in: resolve unknown destination hosts via the system resolver (network use).
    pub resolve: bool,
}

impl ScanOptions {
    pub fn for_home(home: PathBuf) -> ScanOptions {
        ScanOptions {
            home,
            os: current_os(),
            projects: vec![],
            only: vec![],
            paranoid: false,
            show_hostname: false,
            caps: Caps::default(),
            path_env: None,
            env_override: None,
            resolve: false,
        }
    }
}

pub fn scan(catalog: &Catalog, opts: &ScanOptions) -> Report {
    let geo = Geo::embedded();
    let ctx = Ctx {
        home: opts.home.clone(),
        os: opts.os,
        projects: opts.projects.clone(),
        catalog,
        geo: geo.as_ref(),
        caps: opts.caps.clone(),
        started: Instant::now(),
        path_env: opts.path_env.clone(),
        env_override: opts.env_override.clone(),
    };
    let names: Vec<&str> = collectors::ALL
        .iter()
        .copied()
        .filter(|n| opts.only.is_empty() || opts.only.iter().any(|o| o == n))
        .collect();

    let outputs: Vec<collectors::Output> = std::thread::scope(|s| {
        let handles: Vec<_> = names.iter().map(|n| s.spawn(|| collectors::run(n, &ctx))).collect();
        handles.into_iter().map(|h| h.join().expect("collector panicked")).collect()
    });

    let mut runs = Vec::new();
    let mut findings = Vec::new();
    for o in outputs {
        runs.push(o.run);
        findings.extend(o.findings);
    }
    for n in collectors::ALL.iter().filter(|n| !names.contains(n)) {
        runs.push(CollectorRun { name: n.to_string(), status: CollectorState::Skipped, duration_ms: 0, sources_read: 0, problems: vec![] });
    }

    resolve_chains(catalog, &mut findings);
    let dns_lookups = if opts.resolve { resolve_unknown(&mut findings, geo.as_ref()) } else { 0 };

    findings.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then(b.worst().cmp(&a.worst()))
            .then(b.grade.cmp(&a.grade))
            .then(b.confidence.cmp(&a.confidence))
            .then(a.subject.name.to_lowercase().cmp(&b.subject.name.to_lowercase()))
    });
    for (i, f) in findings.iter_mut().enumerate() {
        f.id = format!("f-{:04}", i + 1);
    }

    let hostname = gethostname::gethostname().to_string_lossy().into_owned();
    let mut report = Report {
        schema: REPORT_SCHEMA.into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        catalog_version: catalog.file.version.clone(),
        catalog_sha256: catalog.file.sha256.clone(),
        scanned_at: now_rfc3339(),
        paranoid: opts.paranoid,
        host: Host {
            os: opts.os.into(),
            hostname_hash: format!("sha256:{}", sha256_hex(hostname.as_bytes())),
            hostname: if opts.show_hostname && !opts.paranoid { Some(hostname) } else { None },
        },
        collectors: runs,
        data_sources: data_sources(catalog, geo.as_ref()),
        network: Network { dns_lookups, resolver: if opts.resolve { Some("system resolver (--resolve)".into()) } else { None } },
        summary: Summary::default(),
        findings,
    };
    if opts.paranoid {
        apply_paranoid(&mut report);
    }
    report.summary = summarise(&report.findings);
    report
}

pub fn agent_name(id: &str) -> &str {
    match id {
        "claude_code" => "Claude Code",
        "codex_cli" => "Codex CLI",
        "gemini_cli" => "Gemini CLI",
        "copilot_cli" => "Copilot CLI",
        "cursor_agent" => "Cursor Agent",
        other => other,
    }
}

/// Longest agent chain followed (agent → its MCP server → the agent that server launches → …).
pub const MAX_CHAIN_DEPTH: usize = 4;

/// The coding agent whose own config an MCP server entry lives in, if any.
fn host_agent(client: &str) -> Option<&'static str> {
    match client.split(' ').next().unwrap_or("") {
        "claude_code" => Some("claude_code"),
        "codex_cli" => Some("codex_cli"),
        "gemini_cli" => Some("gemini_cli"),
        _ => None,
    }
}

struct ServerNode {
    label: String,
    direct: Vec<Upstream>,
    launches: Option<String>,
}

struct Graph {
    /// agent id -> where the agent itself sends prompts
    own: BTreeMap<String, Vec<Upstream>>,
    /// agent id -> MCP servers configured inside that agent
    servers: BTreeMap<String, Vec<ServerNode>>,
}

impl Graph {
    /// Everything data handed to `agent` can reach, with routes in `via` (nearest hop first).
    /// Cycles are cut and depth is capped; a cut adds an explicit "chain not followed" link.
    fn reach(&self, agent: &str, depth: usize, visiting: &mut Vec<String>) -> Vec<Upstream> {
        if visiting.iter().any(|a| a == agent) {
            return vec![cut(format!("cycle back to {}", agent_name(agent)))];
        }
        if depth > MAX_CHAIN_DEPTH {
            return vec![cut(format!("chain deeper than {MAX_CHAIN_DEPTH} hops"))];
        }
        visiting.push(agent.to_string());
        let mut out: Vec<Upstream> = self.own.get(agent).cloned().unwrap_or_default();
        for s in self.servers.get(agent).into_iter().flatten() {
            for u in &s.direct {
                let mut u = u.clone();
                u.via.insert(0, s.label.clone());
                out.push(u);
            }
            if let Some(next) = &s.launches {
                for mut u in self.reach(next, depth + 1, visiting) {
                    u.via.insert(0, agent_name(next).to_string());
                    u.via.insert(0, s.label.clone());
                    out.push(u);
                }
            }
        }
        visiting.pop();
        out
    }
}

fn cut(why: String) -> Upstream {
    Upstream {
        provider: "chain not followed".into(),
        provider_id: None,
        host: None,
        country: None,
        country_basis: "unknown".into(),
        processing: None,
        via: vec![],
        basis: vec![why],
        confidence: Confidence::Low,
    }
}

/// A finding that launches a coding agent inherits everything that agent can reach: the agent's
/// own provider (from its user-scope settings, else its default) and, transitively, the
/// destinations of the MCP servers configured inside it. Agent findings gain the same reach.
pub fn resolve_chains(catalog: &Catalog, findings: &mut [Finding]) {
    let mut g = Graph { own: BTreeMap::new(), servers: BTreeMap::new() };
    let mut user_scope_agent_rows: Vec<usize> = Vec::new();
    for (i, f) in findings.iter().enumerate() {
        match f.kind {
            Kind::Agent => {
                let Some(e) = f.evidence.first() else { continue };
                let Some(agent) = e.rule_id.strip_prefix("settings:").and_then(|r| r.split(':').next()) else { continue };
                // First seen wins: user-scope settings are listed before project scope in the catalog.
                if !g.own.contains_key(agent) {
                    g.own.insert(agent.to_string(), f.upstreams.clone());
                    user_scope_agent_rows.push(i);
                }
            }
            Kind::McpServer => {
                if let Some(agent) = f.subject.client.as_deref().and_then(host_agent) {
                    g.servers.entry(agent.to_string()).or_default().push(ServerNode {
                        label: format!("MCP server \"{}\"", f.subject.name),
                        direct: f.upstreams.clone(),
                        launches: f.via_agent.clone(),
                    });
                }
            }
            _ => {}
        }
    }
    for a in &catalog.file.upstream.agent_defaults {
        if g.own.contains_key(&a.agent) {
            continue;
        }
        let ups = match catalog.provider(&a.provider) {
            Some(p) => vec![crate::upstream::for_provider(p, format!("{}'s default provider (no settings file found)", agent_name(&a.agent)), Confidence::Medium)],
            None => vec![Upstream {
                provider: "unknown model provider".into(),
                provider_id: None,
                host: None,
                country: None,
                country_basis: "unknown: this agent's provider is not in the catalog".into(),
                processing: None,
                via: vec![],
                basis: vec![format!("{} is launched here", agent_name(&a.agent))],
                confidence: Confidence::Low,
            }],
        };
        g.own.insert(a.agent.clone(), ups);
    }

    // Agents: their own provider plus everything their MCP servers reach.
    for &i in &user_scope_agent_rows {
        let Some(agent) = findings[i].evidence.first().and_then(|e| e.rule_id.strip_prefix("settings:")).and_then(|r| r.split(':').next()).map(str::to_string) else { continue };
        findings[i].upstreams = crate::upstream::merge(g.reach(&agent, 1, &mut Vec::new()));
    }
    // Anything that launches an agent inherits that agent's reach.
    for f in findings.iter_mut() {
        let Some(agent) = f.via_agent.clone() else { continue };
        let name = agent_name(&agent).to_string();
        let mut ups = std::mem::take(&mut f.upstreams);
        // An MCP server that lives inside agent X and launches X would loop; start from X as visited.
        let mut visiting: Vec<String> = f.subject.client.as_deref().and_then(host_agent).map(|a| vec![a.to_string()]).unwrap_or_default();
        if visiting.first() == Some(&agent) {
            visiting.clear();
        }
        for mut u in g.reach(&agent, 1, &mut visiting) {
            if f.kind == Kind::CliTool {
                // The CLI *is* the agent: same destinations, no extra hop.
                ups.push(u);
                continue;
            }
            u.via.insert(0, name.clone());
            u.basis = u.basis.iter().map(|b| format!("{name}: {b}")).collect();
            u.basis.insert(0, format!("this {} launches {name}", if f.kind == Kind::McpServer { "MCP server" } else { "tool" }));
            ups.push(u);
        }
        f.upstreams = crate::upstream::merge(ups);
    }
}

/// Resolve each distinct unknown-country destination host once and update every upstream using it.
fn resolve_unknown(findings: &mut [Finding], geo: Option<&Geo>) -> usize {
    let mut hosts: Vec<String> = findings
        .iter()
        .flat_map(|f| f.upstreams.iter())
        .filter(|u| u.country.is_none() && u.provider_id.is_none())
        .filter_map(|u| u.host.clone())
        .filter(|h| crate::geo::ip_literal(h).is_none())
        .collect();
    hosts.sort();
    hosts.dedup();
    if hosts.is_empty() {
        return 0;
    }
    let results = crate::upstream::resolve_hosts(&hosts);
    for f in findings.iter_mut() {
        for u in f.upstreams.iter_mut().filter(|u| u.country.is_none() && u.provider_id.is_none()) {
            if let Some(r) = u.host.as_ref().and_then(|h| results.get(h)) {
                crate::upstream::apply_resolution(u, r, geo);
            }
        }
    }
    results.len()
}

fn data_sources(catalog: &Catalog, geo: Option<&Geo>) -> Vec<String> {
    let mut v = vec![format!("lightcast catalog {} (sha256 {})", catalog.file.version, catalog.file.sha256)];
    if let Some(g) = geo {
        v.push(g.credit());
    }
    v
}

/// True when any finding shows a DB-IP result, so outputs must carry the attribution.
pub fn uses_geo(r: &Report) -> bool {
    r.findings.iter().any(|f| {
        f.capability_basis.iter().any(|b| b.contains("DB-IP country"))
            || f.evidence.iter().any(|e| e.detail.iter().any(|d| d.contains("DB-IP country")))
    })
}

/// Drop dates and per-profile / per-project detail for reports that will leave the team.
pub fn apply_paranoid(r: &mut Report) {
    r.scanned_at = r.scanned_at.get(..10).unwrap_or("").to_string();
    for f in &mut r.findings {
        // Uncatalogued remote hosts can name internal infrastructure.
        for b in &mut f.capability_basis {
            if b.starts_with("remote host ") {
                *b = "remote host is not in the catalog".into();
            }
        }
        for e in &mut f.evidence {
            e.detail.retain(|d| !d.starts_with("last "));
            for d in &mut e.detail {
                if d.starts_with("remote host ") && d != "remote host: local machine" {
                    *d = "remote host withheld (paranoid)".into();
                }
            }
            if matches!(e.source_kind.as_str(), "history" | "cookie" | "download") {
                e.location = "browser profile".into();
            }
        }
        for n in &mut f.notes {
            if n.starts_with("project scope:") {
                *n = "project scope".into();
            }
        }
        if let Some(c) = &f.subject.client {
            if c.contains('/') {
                f.subject.client = Some("settings file".into());
            }
        }
        // Uncatalogued destination hosts can name internal infrastructure; providers stay.
        for u in &mut f.upstreams {
            if u.provider_id.is_none() && u.host.is_some() && u.host.as_deref() == Some(u.provider.as_str()) {
                u.provider = "uncatalogued host (withheld)".into();
                u.host = None;
                u.country_basis = match &u.country {
                    Some(_) => "IP geolocation (detail withheld)".into(),
                    None => "unknown".into(),
                };
            }
        }
    }
}

pub fn summarise(findings: &[Finding]) -> Summary {
    let count = |k: Kind| findings.iter().filter(|f| f.kind == k).count();
    let actors: Vec<&Finding> = findings.iter().filter(|f| matches!(f.kind, Kind::McpServer | Kind::Agent | Kind::IdeExtension)).collect();
    let mut by_worst: BTreeMap<(std::cmp::Reverse<Severity>, &'static str), usize> = BTreeMap::new();
    let mut unknown = 0usize;
    for f in &actors {
        match f.capabilities.first() {
            Some(c) => *by_worst.entry((std::cmp::Reverse(c.severity()), c.label())).or_default() += 1,
            None if f.kind == Kind::McpServer => unknown += 1,
            None => {}
        }
    }
    let mut by_worst: Vec<(String, usize)> = by_worst.into_iter().map(|((_, l), n)| (l.to_string(), n)).collect();
    if unknown > 0 {
        by_worst.push(("unknown".into(), unknown));
    }
    let worst = findings.iter().flat_map(|f| f.capabilities.iter().copied()).max_by_key(|c| c.severity());
    let destinations = destinations(findings);
    Summary {
        web_services: count(Kind::WebService),
        mcp_servers: count(Kind::McpServer),
        agents: count(Kind::Agent),
        customizations: count(Kind::Customization),
        skills: count(Kind::Skill),
        plugins: count(Kind::Plugin),
        ide_extensions: count(Kind::IdeExtension),
        cli_tools: count(Kind::CliTool),
        packages: count(Kind::Package),
        api_keys: count(Kind::ApiKey),
        worst,
        by_worst,
        unverified_findings: findings.iter().filter(|f| f.unverified).count(),
        low_confidence_findings: findings.iter().filter(|f| f.confidence == Confidence::Low).count(),
        destinations,
        redactions: findings.iter().map(|f| f.redactions).sum(),
        headline: headline(findings),
    }
}

pub fn kind_label(k: Kind) -> &'static str {
    match k {
        Kind::WebService => "web service",
        Kind::McpServer => "MCP server",
        Kind::Agent => "agent",
        Kind::Customization => "customization",
        Kind::Skill => "skill",
        Kind::Plugin => "plugin",
        Kind::IdeExtension => "IDE extension",
        Kind::CliTool => "CLI",
        Kind::Package => "package",
        Kind::ApiKey => "API key",
    }
}

/// One row per (destination, country), listing every finding that can send data there.
pub fn destinations(findings: &[Finding]) -> Vec<Destination> {
    let mut map: BTreeMap<(Option<String>, String), Destination> = BTreeMap::new();
    for f in findings {
        for u in &f.upstreams {
            let key = (u.country.clone(), u.provider.clone());
            let d = map.entry(key).or_insert_with(|| Destination {
                provider: u.provider.clone(),
                country: u.country.clone(),
                country_basis: u.country_basis.clone(),
                processing: u.processing.clone(),
                from: vec![],
            });
            let via = if u.via.is_empty() { String::new() } else { format!(" via {}", u.via.join(" → ")) };
            let line = format!("{} {} \"{}\"{via}", f.id, kind_label(f.kind), f.subject.name);
            if !d.from.contains(&line) {
                d.from.push(line);
            }
        }
    }
    let mut v: Vec<Destination> = map.into_values().collect();
    // Unknown country last; otherwise by country then provider.
    v.sort_by(|a, b| (a.country.is_none(), &a.country, &a.provider).cmp(&(b.country.is_none(), &b.country, &b.provider)));
    v
}

fn noun(k: Kind, n: usize) -> &'static str {
    match (k, n == 1) {
        (Kind::McpServer, true) => "MCP server",
        (Kind::McpServer, false) => "MCP servers",
        (Kind::Agent, true) => "agent",
        (Kind::Agent, false) => "agents",
        (Kind::ApiKey, true) => "API key",
        (Kind::ApiKey, false) => "API keys",
        (_, true) => "item",
        (_, false) => "items",
    }
}

pub fn headline(findings: &[Finding]) -> String {
    if let Some(f) = findings
        .iter()
        .find(|f| f.capabilities.contains(&Capability::ShellExec) && f.capabilities.contains(&Capability::CredentialReach))
    {
        return format!("{} \"{}\" can act as you: it can run shell commands and is handed credentials.", noun(f.kind, 1), f.subject.name);
    }
    let Some(worst) = findings.iter().flat_map(|f| f.capabilities.iter().copied()).max_by_key(|c| c.severity()) else {
        return "No agent, MCP server or key was shown to hold a risky capability.".into();
    };
    // Count by kind for the worst capability.
    let mut by_kind: BTreeMap<Kind, usize> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.capabilities.first() == Some(&worst)) {
        *by_kind.entry(f.kind).or_default() += 1;
    }
    let parts: Vec<String> = by_kind.iter().map(|(k, n)| format!("{n} {}", noun(*k, *n))).collect();
    let verb_phrase = match worst {
        Capability::CredentialReach if by_kind.keys().all(|k| *k == Kind::ApiKey) => "sit in plain-text files any local agent can read".to_string(),
        c => c.phrase().to_string(),
    };
    let total: usize = by_kind.values().sum();
    let phrase = if total == 1 { verb_phrase.replace("sit in", "sits in") } else { verb_phrase.replace("is handed", "are handed").replace("talks to", "talk to").replace("runs unpinned", "run unpinned") };
    format!("{} {}.", parts.join(" and "), phrase)
}

/// Exit status: 1 when any finding's worst capability is at or above `fail_on`.
pub fn exceeds(report: &Report, fail_on: Severity) -> bool {
    report.findings.iter().filter_map(|f| f.worst()).any(|s| s >= fail_on)
}
