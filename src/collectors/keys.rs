//! AI API-key presence. Reports that a known key NAME is set and where. The value, any part of
//! it, and its length are never kept; an assignment with an empty value is not reported.

use std::collections::BTreeMap;

use super::{Output, Tracker};
use crate::context::Ctx;
use crate::model::{Capability, Confidence, Evidence, Finding, Grade, Kind, Subject};
use crate::upstream;

/// Parse `NAME=value`, `export NAME=value`, `set -gx NAME value`; return the name when the value is non-empty.
pub fn assigned_name(line: &str) -> Option<&str> {
    let l = line.trim();
    if l.starts_with('#') {
        return None;
    }
    let l = l.strip_prefix("export ").unwrap_or(l).trim_start();
    if let Some(rest) = l.strip_prefix("set ") {
        // fish: set [-gx] NAME value
        let mut parts = rest.split_whitespace().filter(|p| !p.starts_with('-'));
        let name = parts.next()?;
        return parts.next().map(|_| name);
    }
    let (name, value) = l.split_once('=')?;
    let name = name.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let v = value.trim().trim_matches(['"', '\'']);
    if v.is_empty() {
        None
    } else {
        Some(name)
    }
}

pub fn collect(ctx: &Ctx) -> Output {
    let mut t = Tracker::new("keys");
    let known = &ctx.catalog.file.tools.key_names;
    // name -> list of places
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (k, v) in ctx.env_vars() {
        if !v.is_empty() && known.iter().any(|kn| kn.name == k) {
            found.entry(k).or_default().push("process environment".into());
        }
    }
    t.sources_read += 1;

    for tmpl in &ctx.catalog.file.locations.key_files {
        for path in ctx.expand(tmpl) {
            let text = match ctx.read_small(&path) {
                None => continue,
                Some(Err(why)) => {
                    t.unreadable(why);
                    continue;
                }
                Some(Ok(s)) => s,
            };
            t.sources_read += 1;
            for line in text.lines() {
                if let Some(name) = assigned_name(line) {
                    if known.iter().any(|kn| kn.name == name) {
                        let shown = ctx.display(&path);
                        let places = found.entry(name.to_string()).or_default();
                        if !places.contains(&shown) {
                            places.push(shown);
                        }
                    }
                }
            }
        }
    }

    let findings = found
        .into_iter()
        .map(|(name, places)| {
            let provider = known.iter().find(|k| k.name == name).map(|k| k.provider.clone());
            let in_file = places.iter().any(|p| p != "process environment");
            let mut caps = vec![];
            let mut basis = vec![];
            if in_file {
                caps.push(Capability::CredentialReach);
                basis.push("stored in plain text in a file any local agent can read".to_string());
            }
            Finding {
                id: String::new(),
                kind: Kind::ApiKey,
                subject: Subject { name: name.clone(), provider, ..Default::default() },
                grade: Grade::Configured,
                confidence: Confidence::High,
                capabilities: caps,
                capability_basis: basis,
                evidence: places
                    .iter()
                    .map(|p| Evidence {
                        rule_id: format!("key:{name}"),
                        rule_status: "verified".into(),
                        source_kind: if p == "process environment" { "env".into() } else { "file".into() },
                        location: p.clone(),
                        grade: Grade::Configured,
                        detail: vec!["name present with a non-empty value (value not read into the report)".into()],
                    })
                    .collect(),
                unverified: false,
                notes: vec![],
                redactions: places.len() as u32,
                upstreams: ctx
                    .catalog
                    .provider_for_env(&name)
                    .map(|p| vec![upstream::for_provider(p, "an API key for this provider is set here".into(), Confidence::Low)])
                    .unwrap_or_default(),
                via_agent: None,
            }
        })
        .collect();
    t.finish(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments() {
        assert_eq!(assigned_name("export OPENAI_API_KEY=sk-123"), Some("OPENAI_API_KEY"));
        assert_eq!(assigned_name("ANTHROPIC_API_KEY=\"x\""), Some("ANTHROPIC_API_KEY"));
        assert_eq!(assigned_name("OPENAI_API_KEY="), None);
        assert_eq!(assigned_name("# OPENAI_API_KEY=x"), None);
        assert_eq!(assigned_name("set -gx GROQ_API_KEY abc"), Some("GROQ_API_KEY"));
        assert_eq!(assigned_name("if [ -x foo ]; then"), None);
    }
}
