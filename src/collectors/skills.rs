//! Agent skills and plugins.
//!
//! Skills: each `<dir>/<name>/SKILL.md` is hashed as a git blob and matched against the catalog.
//! Only the hash, the directory name and file counts are kept; no file content.
//! Plugins: installed plugin ids and known/synced marketplace names. The plugin *directory cache*
//! (a listing of plugins available to install) is deliberately not read: it is not an installation.

use std::fs;
use std::path::Path;

use serde_json::Value;

use super::{Output, Tracker};
use crate::catalog::is_unverified;
use crate::context::{git_blob_oid, Ctx};
use crate::model::{Confidence, Evidence, Finding, Grade, Kind, Subject};

pub fn collect(ctx: &Ctx) -> Output {
    let mut t = Tracker::new("skills");
    let mut findings = Vec::new();
    let mut entries = 0u32;

    for loc in ctx.catalog.file.locations.skill_dirs.iter().filter(|loc| loc.os.as_deref().is_none_or(|os| ctx.os_matches(os))) {
        for dir in ctx.expand(&loc.path) {
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            t.sources_read += 1;
            let mut names: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
            names.sort();
            for skill_dir in names {
                entries += 1;
                if entries > ctx.caps.max_entries {
                    t.capped(format!("more than {} skill directories; the rest were not read", ctx.caps.max_entries));
                    break;
                }
                let md = skill_dir.join("SKILL.md");
                let bytes = match fs::metadata(&md) {
                    Ok(m) if m.is_file() && m.len() <= ctx.caps.max_config_bytes => match fs::read(&md) {
                        Ok(b) => b,
                        Err(_) => {
                            t.unreadable(format!("{}: unreadable", ctx.display(&md)));
                            continue;
                        }
                    },
                    Ok(m) if m.is_file() => {
                        t.unreadable(format!("{}: too large, skipped", ctx.display(&md)));
                        continue;
                    }
                    _ => continue,
                };
                findings.push(skill_finding(ctx, loc.client.as_deref().unwrap_or("agents"), &loc.status, &skill_dir, &bytes));
            }
        }
    }

    for loc in ctx.catalog.file.locations.plugin_dirs.iter().filter(|loc| loc.os.as_deref().is_none_or(|os| ctx.os_matches(os))) {
        for dir in ctx.expand(&loc.path) {
            if !dir.is_dir() {
                continue;
            }
            t.sources_read += 1;
            plugins(ctx, &mut t, &dir, &mut findings);
        }
    }
    let mut out = t.finish(findings);
    out.run.name = "skills".into();
    out
}

fn count_scripts(dir: &Path) -> usize {
    let mut n = 0;
    let mut stack = vec![(dir.to_path_buf(), 0)];
    while let Some((d, depth)) = stack.pop() {
        if depth > 4 || n > 500 {
            break;
        }
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push((p, depth + 1));
            } else if let Some(ext) = p.extension().and_then(|x| x.to_str()) {
                if matches!(ext, "sh" | "py" | "js" | "mjs" | "ts" | "ps1" | "rb" | "bash") {
                    n += 1;
                }
            }
        }
    }
    n
}

fn skill_finding(ctx: &Ctx, client: &str, loc_status: &str, skill_dir: &Path, bytes: &[u8]) -> Finding {
    let name = skill_dir.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let oid = git_blob_oid(bytes);
    let by_blob = ctx.catalog.lookup_blob(&oid);
    let mut notes = Vec::new();
    let (confidence, rule_id, rule_status, unverified, provider) = if let Some(fp) = by_blob.first() {
        notes.push(format!("SKILL.md is byte-identical to the catalogued copy in {}", fp.repo));
        (Confidence::High, format!("fp:agent_skill:{}", fp.id), "verified".to_string(), false, Some(fp.repo.clone()))
    } else if let Some(fp) = ctx.catalog.lookup("agent_skill", &name).first() {
        notes.push(format!(
            "name matches a skill in {} but SKILL.md differs from the catalogued copy (a local edit, another release, or another skill with the same name)",
            fp.repo
        ));
        (Confidence::Low, format!("fp:agent_skill:{}", fp.id), "unverified".to_string(), true, None)
    } else {
        notes.push("not in the catalog: origin unknown".into());
        (Confidence::Low, "unmatched".into(), "unverified".into(), true, None)
    };
    let scripts = count_scripts(skill_dir);
    if scripts > 0 {
        notes.push(format!("ships {scripts} script file(s) an agent may run"));
    }
    Finding {
        id: String::new(),
        kind: Kind::Skill,
        subject: Subject { name, provider, client: Some(client.to_string()), ..Default::default() },
        grade: Grade::Installed,
        confidence,
        capabilities: vec![],
        capability_basis: vec![],
        evidence: vec![Evidence {
            rule_id,
            rule_status,
            source_kind: "manifest".into(),
            location: ctx.display(&skill_dir.join("SKILL.md")),
            grade: Grade::Installed,
            detail: vec![format!("SKILL.md blob {}", &oid[..12])],
        }],
        unverified: unverified && is_unverified(loc_status),
        notes,
        redactions: 0,
        upstreams: vec![],
        via_agent: None,
    }
}

fn plugins(ctx: &Ctx, t: &mut Tracker, dir: &Path, out: &mut Vec<Finding>) {
    // installed_plugins.json: shape not yet verified on a machine with plugins installed; parsed loosely.
    let installed = dir.join("installed_plugins.json");
    if let Some(r) = ctx.read_small(&installed) {
        match r.ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
            Some(v) => {
                let ids: Vec<String> = match v.get("plugins").unwrap_or(&v) {
                    Value::Object(m) => m.keys().cloned().collect(),
                    Value::Array(a) => a.iter().filter_map(|x| x.get("name").or_else(|| x.get("id")).and_then(Value::as_str).map(str::to_string)).collect(),
                    _ => vec![],
                };
                for id in ids {
                    let name = id.split('@').next().unwrap_or(&id).to_string();
                    out.push(plugin_finding(ctx, Kind::Plugin, &name, &installed, "claude_plugin", "installed plugin"));
                }
            }
            None => t.unreadable(format!("{}: not valid JSON", ctx.display(&installed))),
        }
    }
    let known = dir.join("known_marketplaces.json");
    if let Some(Ok(s)) = ctx.read_small(&known) {
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&s) {
            for name in m.keys() {
                out.push(plugin_finding(ctx, Kind::Plugin, name, &known, "claude_plugin_marketplace", "plugin marketplace (a source of plugins, not an installed plugin)"));
            }
        }
    }
    let synced = dir.join("synced");
    if let Ok(rd) = fs::read_dir(&synced) {
        for e in rd.flatten() {
            let f = e.path().join(".marketplaces.json");
            if let Some(Ok(s)) = ctx.read_small(&f) {
                if let Ok(v) = serde_json::from_str::<Value>(&s) {
                    for row in v.get("rows").and_then(Value::as_array).into_iter().flatten() {
                        if let Some(name) = row.get("name").and_then(Value::as_str) {
                            out.push(plugin_finding(ctx, Kind::Plugin, name, &f, "claude_plugin_marketplace", "organisation-synced plugin marketplace (a source of plugins, not an installed plugin)"));
                        }
                    }
                }
            }
        }
    }
}

fn plugin_finding(ctx: &Ctx, kind: Kind, name: &str, src: &Path, fp_type: &str, what: &str) -> Finding {
    let fp = ctx.catalog.lookup(fp_type, name);
    let (confidence, rule_id, unverified) = match fp.first() {
        Some(f) => (Confidence::parse(&f.confidence), format!("fp:{fp_type}:{}", f.id), false),
        None => (Confidence::Low, "unmatched".to_string(), true),
    };
    let grade = if fp_type == "claude_plugin_marketplace" { Grade::Configured } else { Grade::Installed };
    Finding {
        id: String::new(),
        kind,
        subject: Subject { name: name.to_string(), client: Some("claude_code".into()), ..Default::default() },
        grade,
        confidence,
        capabilities: vec![],
        capability_basis: vec![],
        evidence: vec![Evidence {
            rule_id,
            rule_status: if unverified { "unverified".into() } else { "verified".into() },
            source_kind: "manifest".into(),
            location: ctx.display(src),
            grade,
            detail: vec![what.to_string()],
        }],
        unverified,
        notes: vec![],
        redactions: 0,
        upstreams: vec![],
        via_agent: None,
    }
}
