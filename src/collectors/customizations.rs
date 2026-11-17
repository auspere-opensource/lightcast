//! AI configuration, instruction and memory files.
//!
//! Only file names, locations and metadata are read. File contents are never opened.

use std::fs;

use super::{Output, Tracker};
use crate::catalog::is_unverified;
use crate::context::Ctx;
use crate::model::{Confidence, Evidence, Finding, Grade, Kind, Subject};

pub fn collect(ctx: &Ctx) -> Output {
    let mut t = Tracker::new("customizations");
    let mut findings = Vec::new();
    let mut entries = 0u32;

    for loc in ctx.catalog.file.locations.agent_files.iter().filter(|loc| ctx.os_matches(&loc.os)) {
        for path in ctx.expand(&loc.path) {
            if ctx.out_of_time() {
                t.capped("scan deadline reached; remaining configuration locations were skipped".into());
                return t.finish(findings);
            }
            let Ok(meta) = fs::metadata(&path) else { continue };
            if !meta.is_file() {
                continue;
            }
            entries += 1;
            if entries > ctx.caps.max_entries {
                t.capped(format!("more than {} configuration files; the rest were not read", ctx.caps.max_entries));
                return t.finish(findings);
            }
            t.sources_read += 1;
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| loc.kind.clone());
            findings.push(Finding {
                id: String::new(),
                kind: Kind::Customization,
                subject: Subject { name, client: Some(loc.tool.clone()), package: Some(loc.kind.clone()), ..Default::default() },
                grade: Grade::Configured,
                confidence: Confidence::Medium,
                capabilities: vec![],
                capability_basis: vec![],
                evidence: vec![Evidence {
                    rule_id: format!("agent_file:{}:{}", loc.tool, loc.kind),
                    rule_status: loc.status.clone(),
                    source_kind: loc.kind.clone(),
                    location: ctx.display(&path),
                    grade: Grade::Configured,
                    detail: vec![format!("{} scope", loc.scope)],
                }],
                unverified: is_unverified(&loc.status),
                notes: vec!["contents were not read".into()],
                redactions: 0,
                upstreams: vec![],
                via_agent: None,
            });
        }
    }
    t.finish(findings)
}
