//! Self-contained HTML report: no external requests, every count expands to its rows.

use std::fmt::Write;

use crate::model::*;
use crate::render::terminal::{FOOTER, UNVERIFIED_EXPLANATION};

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

const CSS: &str = r#"
:root{--bg:#fafaf8;--fg:#1d1d1b;--muted:#6b6b66;--line:#e2e1dc;--card:#fff;--crit:#b42318;--high:#b54708;--med:#8a6d00;--low:#6b6b66;--accent:#1f4fd1}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecebe6;--muted:#a3a29b;--line:#2e2d2a;--card:#1c1c1a;--crit:#f97066;--high:#fdb022;--med:#e9c46a;--low:#a3a29b;--accent:#84a9ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 16px 64px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px}
.meta{color:var(--muted);font-size:13px}.headline{font-size:18px;font-weight:600;margin:20px 0 8px;padding:14px 16px;border-left:4px solid var(--crit);background:var(--card)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin:16px 0}
.card{display:block;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;color:inherit;text-decoration:none}
.card b{display:block;font-size:24px}.card span{color:var(--muted);font-size:13px}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}th{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
details summary{cursor:pointer;color:var(--accent)}details ul{margin:6px 0 0;padding-left:18px;color:var(--muted);font-size:13px}
.sev-critical{color:var(--crit);font-weight:600}.sev-high{color:var(--high);font-weight:600}.sev-medium{color:var(--med)}.sev-low{color:var(--low)}
.pill{display:inline-block;font-size:12px;padding:1px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.unv{color:var(--high);font-size:12px}.unv-note{margin:12px 0;padding:10px 12px;border-left:3px solid var(--high);background:var(--card);color:var(--muted);font-size:13px}footer{margin-top:40px;color:var(--muted);font-size:13px;white-space:pre-line}
code{font-size:13px}
"#;

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "sev-critical",
        Severity::High => "sev-high",
        Severity::Medium => "sev-medium",
        Severity::Low => "sev-low",
    }
}

fn anchor(k: Kind) -> &'static str {
    match k {
        Kind::WebService => "web",
        Kind::McpServer => "mcp",
        Kind::Agent => "agents",
        Kind::Customization => "customizations",
        Kind::Skill => "skills",
        Kind::Plugin => "plugins",
        Kind::IdeExtension => "ide",
        Kind::CliTool => "cli",
        Kind::Package => "packages",
        Kind::ApiKey => "keys",
    }
}

pub fn render(r: &Report, footer: bool) -> String {
    let mut o = String::new();
    let _ = write!(
        o,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
         <title>LightCast report</title><style>{CSS}</style></head><body><main>"
    );
    let _ = write!(o, "<h1>LightCast</h1><div class=\"meta\">{} · {} · catalog {} · tool {}</div>", esc(&r.host.hostname.clone().unwrap_or_else(|| "this machine".into())), esc(&r.scanned_at), esc(&r.catalog_version), esc(&r.tool_version));
    let _ = write!(o, "<div class=\"headline\">{}</div>", esc(&r.summary.headline));
    if r.summary.unverified_findings > 0 {
        let _ = write!(o, "<div class=\"unv-note\">{}</div>", esc(UNVERIFIED_EXPLANATION));
    }
    if !r.summary.by_worst.is_empty() {
        let parts: Vec<String> = r.summary.by_worst.iter().map(|(c, n)| format!("{n} {}", esc(c))).collect();
        let _ = write!(o, "<div class=\"meta\">Agents, MCP servers and extensions by worst capability: {}</div>", parts.join(", "));
    }

    let kinds = [Kind::WebService, Kind::Agent, Kind::Customization, Kind::McpServer, Kind::ApiKey, Kind::IdeExtension, Kind::CliTool, Kind::Plugin, Kind::Skill, Kind::Package];
    if !r.summary.destinations.is_empty() {
        o.push_str("<h2 id=\"destinations\">Where data can go</h2><p class=\"meta\">Country is the cloud region when the endpoint or a region setting names one, otherwise the provider's headquarters; the basis column says which.</p>");
        o.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Country</th><th>Destination</th><th>Sent from</th><th>Country basis</th><th>Stated processing</th></tr></thead><tbody>");
        for d in &r.summary.destinations {
            let from: Vec<String> = d
                .from
                .iter()
                .map(|s| {
                    let (id, rest) = s.split_once(' ').unwrap_or((s, ""));
                    format!("<a href=\"#{}\">{}</a>", esc(id), esc(rest))
                })
                .collect();
            let _ = write!(
                o,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"meta\">{}</td><td class=\"meta\">{}</td></tr>",
                esc(d.country.as_deref().unwrap_or("unknown")),
                esc(&d.provider),
                from.join("<br>"),
                esc(&d.country_basis),
                esc(d.processing.as_deref().unwrap_or(""))
            );
        }
        o.push_str("</tbody></table></div>");
    }
    o.push_str("<div class=\"cards\">");
    for k in kinds {
        let n = r.findings.iter().filter(|f| f.kind == k).count();
        let _ = write!(o, "<a class=\"card\" href=\"#{}\"><b>{n}</b><span>{}</span></a>", anchor(k), esc(k.title()));
    }
    o.push_str("</div>");

    for k in kinds {
        let fs: Vec<&Finding> = r.findings.iter().filter(|f| f.kind == k).collect();
        let _ = write!(o, "<h2 id=\"{}\">{} ({})</h2>", anchor(k), esc(k.title()), fs.len());
        if fs.is_empty() {
            o.push_str("<p class=\"meta\">None found.</p>");
            continue;
        }
        o.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Name</th><th>Grade</th><th>Confidence</th><th>Reach</th><th>Evidence</th></tr></thead><tbody>");
        for f in fs {
            let mut name = esc(&f.subject.name);
            for extra in [&f.subject.provider, &f.subject.client, &f.subject.package, &f.subject.version].into_iter().flatten() {
                let _ = write!(name, "<br><span class=\"meta\">{}</span>", esc(extra));
            }
            if f.unverified {
                name.push_str("<br><span class=\"unv\">rule not yet verified</span>");
            }
            let reach = if f.capabilities.is_empty() {
                if k == Kind::McpServer { "<span class=\"meta\">unknown</span>".to_string() } else { String::new() }
            } else {
                f.capabilities
                    .iter()
                    .zip(f.capability_basis.iter().map(Some).chain(std::iter::repeat(None)))
                    .map(|(c, b)| {
                        format!(
                            "<div class=\"{}\">{}</div>{}",
                            sev_class(c.severity()),
                            esc(c.phrase()),
                            b.map(|b| format!("<div class=\"meta\">{}</div>", esc(b))).unwrap_or_default()
                        )
                    })
                    .collect()
            };
            let mut ev = String::new();
            let _ = write!(ev, "<details><summary>{} source{}</summary><ul>", f.evidence.len(), if f.evidence.len() == 1 { "" } else { "s" });
            for e in &f.evidence {
                let _ = write!(
                    ev,
                    "<li><span class=\"pill\">{}</span> {} <code>{}</code> · rule <code>{}</code> [{}]{}</li>",
                    esc(e.grade.label()),
                    esc(&e.source_kind),
                    esc(&e.location),
                    esc(&e.rule_id),
                    esc(&e.rule_status),
                    if e.detail.is_empty() { String::new() } else { format!(" · {}", esc(&e.detail.join("; "))) }
                );
            }
            for u in &f.upstreams {
                let via = if u.via.is_empty() { String::new() } else { format!(" via {}", esc(&u.via.join(" → "))) };
                let country_basis = if u.country_basis.is_empty() { String::new() } else { format!(" · {}", esc(&u.country_basis)) };
                let _ = write!(
                    ev,
                    "<li>→ <b>{}</b> ({}){via} · {} · {}{country_basis}</li>",
                    esc(&u.provider),
                    esc(u.country.as_deref().unwrap_or("country unknown")),
                    esc(u.confidence.label()),
                    esc(&u.basis.join("; "))
                );
            }
            for n in &f.notes {
                let _ = write!(ev, "<li>{}</li>", esc(n));
            }
            if f.redactions > 0 {
                let _ = write!(ev, "<li>{} value(s) withheld</li>", f.redactions);
            }
            ev.push_str("</ul></details>");
            let _ = write!(
                o,
                "<tr id=\"{}\"><td>{name}</td><td><span class=\"pill\">{}</span></td><td>{}</td><td>{reach}</td><td>{ev}</td></tr>",
                esc(&f.id),
                esc(f.grade.label()),
                esc(f.confidence.label())
            );
        }
        o.push_str("</tbody></table></div>");
    }

    o.push_str("<h2 id=\"collectors\">Collectors</h2><div class=\"table-wrap\"><table><thead><tr><th>Collector</th><th>Status</th><th>Sources read</th><th>Time</th><th>Problems</th></tr></thead><tbody>");
    for c in &r.collectors {
        let status = format!("{:?}", c.status).to_lowercase();
        let probs: Vec<String> = c.problems.iter().map(|p| esc(p)).collect();
        let _ = write!(o, "<tr><td>{}</td><td>{status}</td><td>{}</td><td>{} ms</td><td class=\"meta\">{}</td></tr>", esc(&c.name), c.sources_read, c.duration_ms, probs.join("<br>"));
    }
    o.push_str("</tbody></table></div>");
    if r.network.dns_lookups > 0 {
        let _ = write!(o, "<p class=\"meta\">{} DNS lookups were made because --resolve was passed; nothing else was sent.</p>", r.network.dns_lookups);
    }
    // DB-IP Lite (CC BY 4.0) requires this link on any page that displays or uses its results.
    o.push_str("<h2 id=\"sources\">Data sources</h2><ul class=\"meta\">");
    for s in &r.data_sources {
        if s.starts_with(crate::geo::ATTRIBUTION) {
            let _ = write!(
                o,
                "<li><a href='{}'>{}</a> · {} · {}</li>",
                crate::geo::ATTRIBUTION_URL,
                crate::geo::ATTRIBUTION,
                crate::geo::LICENSE,
                esc(s.rsplit(", ").next().unwrap_or(""))
            );
        } else {
            let _ = write!(o, "<li>{}</li>", esc(s));
        }
    }
    o.push_str("</ul>");
    if footer {
        let _ = write!(o, "<footer>{}</footer>", esc(FOOTER));
    }
    o.push_str("</main></body></html>\n");
    o
}
