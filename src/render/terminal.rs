//! Plain terminal report. ANSI colour only when writing to a terminal and NO_COLOR is unset.

use std::fmt::Write;

use crate::model::*;

pub const FOOTER: &str = "This is one machine. AISDR shows every machine, which of these were\napproved, and what each agent did. auspere.ai/lightcast";
pub const UNVERIFIED_EXPLANATION: &str = "* Unverified rule: this finding matched a catalog rule that has not yet been confirmed against the actual app or tool on a real machine. Treat it as a lead to review, not a confirmed conclusion.";

const LIST_LIMIT: usize = 12;

struct Style {
    on: bool,
}

impl Style {
    fn b(&self, s: &str) -> String {
        if self.on { format!("\x1b[1m{s}\x1b[0m") } else { s.to_string() }
    }
    fn dim(&self, s: &str) -> String {
        if self.on { format!("\x1b[2m{s}\x1b[0m") } else { s.to_string() }
    }
    fn sev(&self, sev: Severity, s: &str) -> String {
        if !self.on {
            return s.to_string();
        }
        let code = match sev {
            Severity::Critical => "31;1",
            Severity::High => "33;1",
            Severity::Medium => "33",
            Severity::Low => "2",
        };
        format!("\x1b[{code}m{s}\x1b[0m")
    }
}

fn pad(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n >= w {
        let mut t: String = s.chars().take(w.saturating_sub(1)).collect();
        t.push('…');
        t
    } else {
        format!("{s}{}", " ".repeat(w - n))
    }
}

fn upstream_line(st: &Style, u: &Upstream, verbose: bool) -> String {
    let cc = u.country.clone().unwrap_or_else(|| "country unknown".into());
    let via = if u.via.is_empty() { String::new() } else { format!(" via {}", u.via.join(" → ")) };
    let head = format!("→ {} ({cc}){via}", u.provider);
    let why = if verbose { u.basis.join("; ") } else { u.basis.first().cloned().unwrap_or_default() };
    format!("{} {}", st.b(&head), st.dim(&format!("[{}] {why}", u.confidence.label())))
}

pub fn render(r: &Report, color: bool, footer: bool, verbose: bool) -> String {
    let st = Style { on: color };
    let mut o = String::new();
    let rule = "─".repeat(72);
    let _ = writeln!(o, "{}", st.b("LightCast"));
    let host = r.host.hostname.clone().unwrap_or_else(|| "this machine".into());
    let _ = writeln!(o, "{}", st.dim(&format!("{host} · {} · {} · catalog {}", r.host.os, r.scanned_at, r.catalog_version)));
    let _ = writeln!(o, "{rule}");
    let worst = r.summary.worst.map(|c| c.severity()).unwrap_or(Severity::Low);
    let _ = writeln!(o, "{}", st.sev(worst, &r.summary.headline));
    if verbose && r.summary.unverified_findings > 0 {
        let _ = writeln!(o, "{}", st.dim(UNVERIFIED_EXPLANATION));
    }
    if !r.summary.by_worst.is_empty() {
        let parts: Vec<String> = r.summary.by_worst.iter().map(|(c, n)| format!("{n} {c}")).collect();
        let _ = writeln!(o, "{}", st.dim(&format!("Agents, MCP servers and extensions by worst capability: {}", parts.join(", "))));
    }
    let _ = writeln!(o);

    let kinds = [
        Kind::WebService,
        Kind::Agent,
        Kind::Customization,
        Kind::McpServer,
        Kind::ApiKey,
        Kind::IdeExtension,
        Kind::CliTool,
        Kind::Plugin,
        Kind::Skill,
        Kind::Package,
    ];
    for k in kinds {
        let fs: Vec<&Finding> = r.findings.iter().filter(|f| f.kind == k).collect();
        if fs.is_empty() {
            continue;
        }
        let _ = writeln!(o, "{}", st.b(&format!("{} ({})", k.title(), fs.len())));
        if matches!(k, Kind::Skill | Kind::Plugin | Kind::Package) && !verbose {
            let exact = fs.iter().filter(|f| f.confidence == Confidence::High).count();
            let named = fs.iter().filter(|f| f.confidence != Confidence::High && f.evidence.iter().any(|e| e.rule_id != "unmatched")).count();
            let unknown = fs.len() - exact - named;
            let _ = writeln!(
                o,
                "  {}",
                st.dim(&format!("{exact} identical to a catalogued upstream copy · {named} match by name only · {unknown} origin unknown"))
            );
        }
        let limit = if verbose || matches!(k, Kind::WebService | Kind::Agent | Kind::McpServer | Kind::ApiKey) {
            usize::MAX
        } else if matches!(k, Kind::Skill | Kind::Package) {
            5
        } else {
            LIST_LIMIT
        };
        for f in fs.iter().take(limit) {
            let mark = if f.unverified { "*" } else { " " };
            let name = match (&f.subject.client, k) {
                (Some(c), Kind::McpServer) => format!("{} [{}]", f.subject.name, c),
                _ => f.subject.name.clone(),
            };
            let reach = match f.capabilities.first() {
                Some(c) => st.sev(c.severity(), c.phrase()),
                None if k == Kind::McpServer => st.dim("reach unknown"),
                None => String::new(),
            };
            let _ = writeln!(o, "  {mark}{} {} {} {}", pad(&name, 34), pad(f.grade.label(), 11), pad(f.confidence.label(), 7), reach);
            if verbose || matches!(k, Kind::Agent | Kind::McpServer) {
                for b in &f.capability_basis {
                    let _ = writeln!(o, "      {}", st.dim(&format!("· {b}")));
                }
            }
            if verbose || matches!(k, Kind::Agent | Kind::McpServer) {
                for u in &f.upstreams {
                    let _ = writeln!(o, "      {}", upstream_line(&st, u, verbose));
                }
            }
            if !verbose && matches!(k, Kind::Agent | Kind::McpServer) {
                for n in &f.notes {
                    let _ = writeln!(o, "      {}", st.dim(&format!("· {n}")));
                }
            }
            if verbose {
                for e in &f.evidence {
                    let _ = writeln!(o, "      {}", st.dim(&format!("evidence: {} [{}] {} {}", e.source_kind, e.rule_status, e.location, e.detail.join("; "))));
                }
                for n in &f.notes {
                    let _ = writeln!(o, "      {}", st.dim(&format!("note: {n}")));
                }
            } else if k == Kind::WebService {
                if let Some(n) = f.notes.iter().find(|n| n.contains("not visible")) {
                    let _ = writeln!(o, "      {}", st.dim(&format!("· {n}")));
                }
            }
        }
        if fs.len() > limit {
            let _ = writeln!(o, "  {}", st.dim(&format!("… and {} more (use --verbose or --html)", fs.len() - limit)));
        }
        let _ = writeln!(o);
    }
    if !r.summary.destinations.is_empty() {
        let countries: std::collections::BTreeSet<&str> = r.summary.destinations.iter().filter_map(|d| d.country.as_deref()).filter(|c| *c != "LOCAL").collect();
        let plural = |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        let _ = writeln!(
            o,
            "{}",
            st.b(&format!(
                "Where data can go ({}, {})",
                plural(r.summary.destinations.len(), "destination", "destinations"),
                plural(countries.len(), "country", "countries")
            ))
        );
        let _ = writeln!(o, "  {}", st.dim("country = the cloud region when the endpoint or a region setting names one, else provider headquarters"));
        for d in &r.summary.destinations {
            let cc = d.country.clone().unwrap_or_else(|| "??".into());
            let senders: Vec<String> = d.from.iter().map(|s| s.split_once(' ').map(|x| x.1).unwrap_or(s).to_string()).collect();
            let shown = if verbose || senders.len() <= 3 { senders.join("; ") } else { format!("{}; +{} more", senders[..3].join("; "), senders.len() - 3) };
            let _ = writeln!(o, "  {} {} ← {}", pad(&cc, 6), pad(&d.provider, 26), shown);
            if !d.country_basis.is_empty() && (d.country.is_none() || !d.country_basis.starts_with("provider headquarters per its own legal page") || verbose) {
                let _ = writeln!(o, "  {}", st.dim(&format!("       {}", d.country_basis)));
            }
            if let Some(p) = &d.processing {
                let _ = writeln!(o, "  {}", st.dim(&format!("       processing: {p}")));
            }
        }
        let _ = writeln!(o);
    }
    if r.findings.is_empty() {
        let _ = writeln!(o, "No AI services, agents, MCP servers, skills, extensions or keys were found.\n");
    }

    let _ = writeln!(o, "{rule}");
    let runs: Vec<String> = r
        .collectors
        .iter()
        .map(|c| {
            let s = match c.status {
                CollectorState::Ok => "ok",
                CollectorState::Partial => "partial",
                CollectorState::Unreadable => "unreadable",
                CollectorState::Skipped => "skipped",
            };
            format!("{} {s} ({})", c.name, c.sources_read)
        })
        .collect();
    let _ = writeln!(o, "{}", st.dim(&format!("Collectors (sources read): {}", runs.join(" · "))));
    for c in &r.collectors {
        for p in c.problems.iter().take(if verbose { usize::MAX } else { 3 }) {
            let _ = writeln!(o, "{}", st.dim(&format!("  {}: {p}", c.name)));
        }
        if !verbose && c.problems.len() > 3 {
            let _ = writeln!(o, "{}", st.dim(&format!("  {}: … {} more", c.name, c.problems.len() - 3)));
        }
    }
    if r.network.dns_lookups > 0 {
        let _ = writeln!(o, "{}", st.dim(&format!("{} DNS lookups made because --resolve was passed; nothing else was sent", r.network.dns_lookups)));
    }
    if crate::report::uses_geo(r) {
        let _ = writeln!(o, "{}", st.dim(&format!("IP data: {} ({}), {}", crate::geo::ATTRIBUTION, crate::geo::ATTRIBUTION_URL, crate::geo::LICENSE)));
    }
    if footer {
        let _ = writeln!(o, "\n{}", FOOTER);
    }
    o
}
