//! AI command-line tools on PATH, and AI packages in global npm / pipx / uv tool directories.
//! Only file and directory NAMES are read.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use super::{command_basename, Output, Tracker};
use crate::catalog::is_unverified;
use crate::context::Ctx;
use crate::model::{Confidence, Evidence, Finding, Grade, Kind, Subject};

/// True when an executable name itself names AI tooling.
pub fn looks_ai(name: &str) -> bool {
    const TOKENS: &[&str] = &["mcp", "llm", "gpt", "claude", "agent", "copilot", "gemini", "openai", "anthropic", "ollama", "langchain", "rag"];
    let n = name.to_lowercase();
    if n.len() < 4 {
        return false;
    }
    let parts: Vec<&str> = n.split(['-', '_', '.']).collect();
    TOKENS.iter().any(|t| n.contains(t)) || parts.contains(&"ai")
}

fn package_name(eco: &str, entry: &str) -> Option<String> {
    if eco != "pypi" {
        return Some(entry.to_string());
    }
    if entry.starts_with('.') || entry == "__pycache__" {
        return None;
    }
    let stem = entry.strip_suffix(".dist-info").or_else(|| entry.strip_suffix(".egg-info"));
    let name = match stem {
        Some(s) => s.rsplit_once('-').map(|(name, _)| name).unwrap_or(s),
        None => entry,
    };
    Some(name.replace('_', "-").to_lowercase())
}

pub fn collect(ctx: &Ctx) -> Output {
    let mut t = Tracker::new("cli");
    let mut findings = Vec::new();
    let path_var = ctx.path_env.clone().or_else(|| std::env::var("PATH").ok()).unwrap_or_default();

    // command -> first directory it was found in
    let mut on_path: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut entries = 0u32;
    // PATH syntax belongs to the host running the scan, not the OS being scanned (they differ
    // only in tests); split_paths also handles quoted Windows entries.
    for dir in std::env::split_paths(&path_var).filter(|d| !d.as_os_str().is_empty()) {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        t.sources_read += 1;
        for e in rd.flatten() {
            entries += 1;
            if entries > ctx.caps.max_entries * 4 {
                t.capped("PATH holds too many entries; the rest were not read".into());
                break;
            }
            let name = command_basename(&e.file_name().to_string_lossy());
            on_path.entry(name).or_insert_with(|| dir.clone());
        }
    }

    let mut matched: BTreeSet<String> = BTreeSet::new();
    for c in &ctx.catalog.file.tools.ai_cli {
        if let Some(dir) = on_path.get(&c.command) {
            matched.insert(c.command.clone());
            findings.push(Finding {
                id: String::new(),
                kind: Kind::CliTool,
                subject: Subject { name: c.tool.clone(), provider: Some(c.provider.clone()), package: Some(c.command.clone()), ..Default::default() },
                grade: Grade::Installed,
                confidence: Confidence::Medium,
                capabilities: vec![],
                capability_basis: vec![],
                evidence: vec![Evidence {
                    rule_id: format!("ai_cli:{}", c.command),
                    rule_status: c.status.clone(),
                    source_kind: "path".into(),
                    location: ctx.display(dir),
                    grade: Grade::Installed,
                    detail: vec![format!("executable {}", c.command)],
                }],
                unverified: is_unverified(&c.status),
                notes: if c.agent { vec!["coding agent: see Agent settings for whether it runs without asking".into()] } else { vec![] },
                redactions: 0,
                upstreams: vec![],
                via_agent: ctx.catalog.file.upstream.agent_defaults.iter().find(|a| a.command == c.command).map(|a| a.agent.clone()),
            });
        }
    }
    for (name, dir) in &on_path {
        if matched.contains(name) {
            continue;
        }
        // Harvested command names include generic words ("test", "code"); a bare PATH name is only
        // reported when the name itself says it is AI tooling.
        if !looks_ai(name) {
            continue;
        }
        let fps = ctx.catalog.lookup("cli_command", name);
        let Some(fp) = fps.iter().find(|f| !f.collision) else { continue };
        findings.push(Finding {
            id: String::new(),
            kind: Kind::CliTool,
            subject: Subject { name: name.clone(), provider: Some(fp.repo.clone()), package: Some(name.clone()), ..Default::default() },
            grade: Grade::Installed,
            // A bare executable name is a name-only match.
            confidence: Confidence::Low,
            capabilities: vec![],
            capability_basis: vec![],
            evidence: vec![Evidence {
                rule_id: format!("fp:cli_command:{}", fp.id),
                rule_status: "unverified".into(),
                source_kind: "path".into(),
                location: ctx.display(dir),
                grade: Grade::Installed,
                detail: vec![format!("executable name matches a command from {}", fp.repo)],
            }],
            unverified: true,
            notes: vec!["name-only match: another program may share this name".into()],
            redactions: 0,
            upstreams: vec![],
            via_agent: None,
        });
    }

    // Global packages.
    let mut seen_packages: BTreeSet<(String, String)> = BTreeSet::new();
    let mut package_entries = 0u32;
    for loc in ctx.catalog.file.locations.package_dirs.iter().filter(|loc| loc.os.as_deref().is_none_or(|os| ctx.os_matches(os))) {
        let eco = loc.kind.clone().unwrap_or_default();
        for dir in ctx.expand(&loc.path) {
            if ctx.out_of_time() {
                t.capped("scan deadline reached; remaining package locations were skipped".into());
                return t.finish(findings);
            }
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            t.sources_read += 1;
            let mut names: Vec<String> = Vec::new();
            for e in rd.flatten() {
                package_entries += 1;
                if package_entries > ctx.caps.max_entries {
                    t.capped(format!("more than {} package entries; the rest were not read", ctx.caps.max_entries));
                    return t.finish(findings);
                }
                let n = e.file_name().to_string_lossy().into_owned();
                if eco == "npm" && n.starts_with('@') {
                    if let Ok(sub) = fs::read_dir(e.path()) {
                        for s in sub.flatten() {
                            package_entries += 1;
                            if package_entries > ctx.caps.max_entries {
                                t.capped(format!("more than {} package entries; the rest were not read", ctx.caps.max_entries));
                                return t.finish(findings);
                            }
                            names.push(format!("{n}/{}", s.file_name().to_string_lossy()));
                        }
                    }
                } else if let Some(n) = package_name(&eco, &n) {
                    names.push(n);
                }
            }
            names.sort();
            for n in names {
                if !seen_packages.insert((eco.clone(), n.clone())) {
                    continue;
                }
                let fp_type = if eco == "npm" { "npm_package" } else { "pypi_package" };
                let fps = ctx.catalog.lookup(fp_type, &n);
                let mp = ctx.catalog.file.tools.mcp_packages.iter().find(|m| m.package.eq_ignore_ascii_case(&n));
                let Some((rule_id, confidence, repo)) = fps
                    .iter()
                    .find(|f| !f.collision)
                    .map(|f| (format!("fp:{fp_type}:{}", f.id), Confidence::parse(&f.confidence), Some(f.repo.clone())))
                    .or_else(|| {
                        ctx.catalog
                            .provider_for_sdk(&eco, &n)
                            .map(|p| (format!("provider_sdk:{}:{n}", p.id), Confidence::High, Some(p.name.clone())))
                    })
                    .or_else(|| mp.map(|m| (format!("mcp_package:{}", m.package), Confidence::Medium, None)))
                else {
                    continue;
                };
                findings.push(Finding {
                    id: String::new(),
                    kind: Kind::Package,
                    subject: Subject { name: n.clone(), provider: repo, package: Some(format!("{eco}:{n}")), ..Default::default() },
                    grade: Grade::Installed,
                    confidence,
                    capabilities: vec![],
                    capability_basis: vec![],
                    evidence: vec![Evidence {
                        rule_id,
                        rule_status: "unverified".into(),
                        source_kind: "package_dir".into(),
                        location: ctx.display(&dir),
                        grade: Grade::Installed,
                        detail: vec![],
                    }],
                    unverified: true,
                    notes: vec![],
                    redactions: 0,
                    upstreams: vec![],
                    via_agent: None,
                });
            }
        }
    }
    t.finish(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_distribution_entries_become_package_names() {
        assert_eq!(package_name("pypi", "openai-2.7.1.dist-info").as_deref(), Some("openai"));
        assert_eq!(package_name("pypi", "google_genai-1.2.3.dist-info").as_deref(), Some("google-genai"));
        assert_eq!(package_name("pypi", "anthropic").as_deref(), Some("anthropic"));
        assert_eq!(package_name("pypi", "__pycache__"), None);
    }
}
