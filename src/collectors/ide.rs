//! IDE extensions: VS Code-family extension directories, named `<publisher>.<name>-<version>[-<platform>]`.
//! Only directory names are read.

use std::collections::BTreeMap;
use std::fs;

use super::{Output, Tracker};
use crate::catalog::is_unverified;
use crate::context::Ctx;
use crate::model::{Confidence, Evidence, Finding, Grade, Kind, Subject};
use crate::upstream;

/// Split `anthropic.claude-code-2.1.318-linux-x64` into ("anthropic.claude-code", "2.1.318").
pub fn split_dir_name(name: &str) -> Option<(String, String)> {
    let lower = name.to_lowercase();
    let bytes: Vec<char> = lower.chars().collect();
    for i in 0..bytes.len() {
        if bytes[i] == '-' && bytes.get(i + 1).is_some_and(|c| c.is_ascii_digit()) {
            let id: String = bytes[..i].iter().collect();
            let rest: String = bytes[i + 1..].iter().collect();
            let version = rest.split('-').next().unwrap_or("").to_string();
            if id.contains('.') {
                return Some((id, version));
            }
        }
    }
    None
}

pub fn collect(ctx: &Ctx) -> Output {
    let mut t = Tracker::new("ide");
    // (ide, extension id) -> (newest version, location)
    let mut seen: BTreeMap<(String, String), (String, String)> = BTreeMap::new();
    for loc in ctx.catalog.file.locations.ide_extension_dirs.iter().filter(|loc| loc.os.as_deref().is_none_or(|os| ctx.os_matches(os))) {
        for dir in ctx.expand(&loc.path) {
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            t.sources_read += 1;
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let Some((id, version)) = split_dir_name(&name) else { continue };
                let key = (loc.ide.clone().unwrap_or_default(), id);
                let entry = seen.entry(key).or_insert_with(|| (version.clone(), ctx.display(&dir)));
                if version_gt(&version, &entry.0) {
                    entry.0 = version;
                }
            }
        }
    }
    let mut findings = Vec::new();
    for ((ide, id), (version, location)) in seen {
        let curated = ctx.catalog.file.tools.ide_extensions.iter().find(|x| {
            x.id == id || x.id.strip_suffix(".*").is_some_and(|publisher| id.split('.').next() == Some(publisher))
        });
        let fp = ctx.catalog.lookup("vscode_extension", &id);
        let (provider, tool, confidence, rule_id, status) = if let Some(c) = curated {
            (Some(c.provider.clone()), Some(c.tool.clone()), Confidence::Medium, format!("ide:{}", c.id), c.status.clone())
        } else if let Some(f) = fp.first() {
            (None, None, Confidence::parse(&f.confidence), format!("fp:vscode_extension:{}", f.id), "verified".to_string())
        } else {
            continue; // not an AI extension as far as the catalog knows
        };
        let upstreams = curated
            .and_then(|c| c.upstream.as_deref())
            .and_then(|u| ctx.catalog.provider(u))
            .map(|p| vec![upstream::for_provider(p, "extension from this provider; its default backend".into(), Confidence::Medium)])
            .unwrap_or_default();
        findings.push(Finding {
            id: String::new(),
            kind: Kind::IdeExtension,
            subject: Subject { name: id.clone(), provider, client: Some(ide), version: Some(version), package: tool },
            grade: Grade::Installed,
            confidence,
            capabilities: vec![],
            capability_basis: vec![],
            evidence: vec![Evidence {
                rule_id,
                rule_status: status.clone(),
                source_kind: "manifest".into(),
                location,
                grade: Grade::Installed,
                detail: vec![],
            }],
            unverified: is_unverified(&status) && status != "measured_present",
            notes: vec![],
            redactions: 0,
            upstreams,
            via_agent: None,
        });
    }
    t.finish(findings)
}

fn version_gt(a: &str, b: &str) -> bool {
    let p = |s: &str| s.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    p(a) > p(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_names() {
        assert_eq!(split_dir_name("anthropic.claude-code-2.1.318-linux-x64"), Some(("anthropic.claude-code".into(), "2.1.318".into())));
        assert_eq!(split_dir_name("openai.chatgpt-26.51021.22027-linux-x64"), Some(("openai.chatgpt".into(), "26.51021.22027".into())));
        assert_eq!(split_dir_name("GitHub.copilot-chat-0.30.1"), Some(("github.copilot-chat".into(), "0.30.1".into())));
        assert_eq!(split_dir_name(".obsolete"), None);
    }
}
