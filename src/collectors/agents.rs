//! Agent settings collector: does an installed coding agent act without asking?
//!
//! Only specific settings keys are inspected. Permission-rule text is never kept: the report says
//! "allows every shell command" or "N pre-approved command patterns", not the patterns.

use std::path::Path;

use serde_json::Value;

use super::{Output, Tracker};
use crate::catalog::AgentSettingsLoc;
use crate::context::Ctx;
use crate::model::{Capability, Confidence, Evidence, Finding, Grade, Kind, Subject, Upstream};
use crate::upstream;

pub fn collect(ctx: &Ctx) -> Output {
    let mut t = Tracker::new("agents");
    let mut findings = Vec::new();
    for loc in &ctx.catalog.file.locations.agent_settings {
        for path in ctx.expand(&loc.path) {
            let text = match ctx.read_small(&path) {
                None => continue,
                Some(Err(why)) => {
                    t.unreadable(why);
                    continue;
                }
                Some(Ok(s)) => s,
            };
            t.sources_read += 1;
            let user_scope = !loc.path.contains("{project}");
            let parsed = match loc.format.as_str() {
                "claude_settings" => claude(ctx, &text).map(|p| p.map(|(c, n)| (c, n, claude_upstreams(ctx, &text, user_scope)))),
                "codex_toml" => codex(&text).map(|p| p.map(|(c, n)| (c, n, codex_upstreams(ctx, &text)))),
                _ => Err("unknown format".into()),
            };
            match parsed {
                Ok(Some((caps, notes, ups))) => {
                    let mut f = finding(ctx, loc, &path, caps, notes);
                    f.upstreams = ups;
                    findings.push(f);
                }
                Ok(None) => {}
                Err(why) => t.unreadable(format!("{}: {why}", ctx.display(&path))),
            }
        }
    }
    t.finish(findings)
}

type Parsed = Result<Option<(Vec<(Capability, String)>, Vec<String>)>, String>;

fn truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Where Claude Code sends prompts: Anthropic, unless the settings (or, for the user scope, the
/// process environment) route it through Bedrock, Vertex or a gateway. Only flag truthiness and
/// the gateway HOST are read from values.
pub fn claude_upstreams(ctx: &Ctx, text: &str, user_scope: bool) -> Vec<Upstream> {
    let cat = ctx.catalog;
    let mut env: Vec<(String, String, &'static str)> = Vec::new();
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        if let Some(Value::Object(m)) = v.get("env") {
            for (k, val) in m {
                if let Some(s) = val.as_str() {
                    env.push((k.clone(), s.to_string(), "settings env"));
                }
            }
        }
    }
    if user_scope {
        for (k, v) in ctx.env_vars() {
            if k.starts_with("CLAUDE_CODE_USE_") || k == "ANTHROPIC_BASE_URL" || matches!(k.as_str(), "AWS_REGION" | "AWS_DEFAULT_REGION" | "CLOUD_ML_REGION") {
                env.push((k, v, "process environment"));
            }
        }
    }
    let mut ups = Vec::new();
    for (k, v, src) in &env {
        if let Some(r) = cat.file.upstream.claude_code_routes.iter().find(|r| r.env == *k) {
            if truthy(v) {
                if let Some(p) = cat.provider(&r.provider) {
                    ups.push(upstream::for_provider(p, format!("{k} is set in the {src}"), Confidence::High));
                }
            }
        } else if k.ends_with("_BASE_URL") && cat.endpoint_env.is_match(k) {
            if let Some(h) = upstream::endpoint_host(v) {
                let mut u = upstream::for_host(ctx, &h, format!("{k} in the {src} sends requests to this host"));
                if u.provider_id.is_none() {
                    u.basis.push("a gateway; where it forwards requests is not visible locally".into());
                }
                ups.push(u);
            }
        }
    }
    // Region codes: settings env first, then the process environment.
    for src in ["settings env", "process environment"] {
        let pairs: Vec<(String, String)> = env.iter().filter(|(_, _, s)| *s == src).map(|(k, v, _)| (k.clone(), v.clone())).collect();
        upstream::apply_region_env(ctx, &mut ups, &pairs, src);
    }
    if ups.is_empty() {
        if let Some(p) = cat.provider("anthropic") {
            ups.push(upstream::for_provider(p, "Claude Code's default provider; no routing override found".into(), Confidence::Medium));
        }
    }
    upstream::merge(ups)
}

/// Where Codex CLI sends prompts: `model_provider` (default openai) and that provider's base_url host.
pub fn codex_upstreams(ctx: &Ctx, text: &str) -> Vec<Upstream> {
    let cat = ctx.catalog;
    let Ok(v) = toml::from_str::<toml::Value>(text) else { return vec![] };
    let id = v.get("model_provider").and_then(|x| x.as_str()).unwrap_or("openai").to_string();
    let mut ups = Vec::new();
    let custom = v.get("model_providers").and_then(|m| m.get(&id));
    if let Some(c) = custom {
        if let Some(h) = c.get("base_url").and_then(|x| x.as_str()).and_then(upstream::endpoint_host) {
            ups.push(upstream::for_host(ctx, &h, format!("model_providers.{id}.base_url sends requests to this host")));
        }
        if let Some(p) = c.get("env_key").and_then(|x| x.as_str()).and_then(|k| cat.provider_for_env(k)) {
            ups.push(upstream::for_provider(p, format!("model_providers.{id} uses a {} key", p.name), Confidence::High));
        }
    }
    if ups.is_empty() {
        let mapped = match id.as_str() {
            "azure" => "azure_openai",
            "ollama" | "oss" => "ollama_local",
            other => other,
        };
        if let Some(p) = cat.provider(mapped) {
            let why = if v.get("model_provider").is_some() { format!("model_provider is {id}") } else { "Codex CLI's default provider; no model_provider set".into() };
            ups.push(upstream::for_provider(p, why, Confidence::High));
        } else {
            ups.push(Upstream {
                provider: format!("model provider \"{id}\""),
                provider_id: None,
                host: None,
                country: None,
                country_basis: "unknown: provider not in the catalog".into(),
                processing: None,
                via: vec![],
                basis: vec![format!("model_provider is {id}")],
                confidence: Confidence::Low,
            });
        }
    }
    upstream::merge(ups)
}

pub fn claude(ctx: &Ctx, text: &str) -> Parsed {
    let v: Value = serde_json::from_str(text).map_err(|_| "not valid JSON".to_string())?;
    let mut caps = Vec::new();
    let mut notes = Vec::new();
    let perms = v.get("permissions");
    if perms.and_then(|p| p.get("defaultMode")).and_then(Value::as_str) == Some("bypassPermissions") {
        caps.push((Capability::ShellExec, "permissions.defaultMode is bypassPermissions: tools run without asking".into()));
        caps.push((Capability::FsWrite, "permissions.defaultMode is bypassPermissions: edits happen without asking".into()));
    }
    if let Some(allow) = perms.and_then(|p| p.get("allow")).and_then(Value::as_array) {
        let rules: Vec<&str> = allow.iter().filter_map(Value::as_str).collect();
        if rules.iter().any(|r| matches!(*r, "Bash" | "Bash(*)" | "Bash(*:*)" | "Bash(:*)")) {
            caps.push((Capability::ShellExec, "an allow rule pre-approves every shell command".into()));
        }
        if rules.iter().any(|r| matches!(*r, "Write" | "Edit" | "Write(*)" | "Edit(*)" | "MultiEdit")) {
            caps.push((Capability::FsWrite, "an allow rule pre-approves file edits anywhere".into()));
        }
        if rules.iter().any(|r| matches!(*r, "WebFetch" | "WebFetch(*)")) {
            caps.push((Capability::NetworkEgress, "an allow rule pre-approves every web fetch".into()));
        }
        let bash_patterns = rules.iter().filter(|r| r.starts_with("Bash(")).count();
        if bash_patterns > 0 {
            notes.push(format!("{bash_patterns} pre-approved shell command pattern(s) (text not shown)"));
        }
        let mcp = rules.iter().filter(|r| r.starts_with("mcp__")).count();
        if mcp > 0 {
            notes.push(format!("{mcp} pre-approved MCP tool rule(s)"));
        }
    }
    if let Some(Value::Object(env)) = v.get("env") {
        let cred: Vec<&String> = env.keys().filter(|k| ctx.catalog.is_credential_name(k)).collect();
        if !cred.is_empty() {
            caps.push((Capability::CredentialReach, format!("settings env sets: {}", cred.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))));
        }
    }
    Ok(Some((caps, notes)))
}

pub fn codex(text: &str) -> Parsed {
    let v: toml::Value = toml::from_str(text).map_err(|_| "not valid TOML".to_string())?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let approval = s("approval_policy");
    let sandbox = s("sandbox_mode");
    let mut caps = Vec::new();
    let mut notes = Vec::new();
    if sandbox == "danger-full-access" {
        caps.push((Capability::FsWrite, "sandbox_mode is danger-full-access: no filesystem sandbox".into()));
        if approval == "never" {
            caps.push((Capability::ShellExec, "approval_policy is never with no sandbox: commands run unrestricted without asking".into()));
        } else {
            caps.push((Capability::ShellExec, "sandbox_mode is danger-full-access: approved commands run unrestricted".into()));
        }
    } else if !sandbox.is_empty() {
        notes.push(format!("sandbox_mode {sandbox}"));
    }
    if !approval.is_empty() {
        notes.push(format!("approval_policy {approval}"));
    }
    if let Some(toml::Value::Table(p)) = v.get("projects") {
        let trusted = p.values().filter(|x| x.get("trust_level").and_then(|t| t.as_str()) == Some("trusted")).count();
        if trusted > 0 {
            notes.push(format!("{trusted} trusted project director{}", if trusted == 1 { "y" } else { "ies" }));
        }
    }
    Ok(Some((caps, notes)))
}

fn finding(ctx: &Ctx, loc: &AgentSettingsLoc, path: &Path, mut caps: Vec<(Capability, String)>, notes: Vec<String>) -> Finding {
    caps.sort_by_key(|(c, _)| std::cmp::Reverse(c.severity()));
    let name = match loc.agent.as_str() {
        "claude_code" => "Claude Code",
        "codex_cli" => "Codex CLI",
        other => other,
    };
    let provider = match loc.agent.as_str() {
        "claude_code" => Some("Anthropic".to_string()),
        "codex_cli" => Some("OpenAI".to_string()),
        _ => None,
    };
    Finding {
        id: String::new(),
        kind: Kind::Agent,
        subject: Subject { name: name.into(), provider, client: Some(ctx.display(path)), ..Default::default() },
        grade: Grade::Configured,
        confidence: Confidence::High,
        capability_basis: caps.iter().map(|(_, b)| b.clone()).collect(),
        capabilities: caps.into_iter().map(|(c, _)| c).collect(),
        evidence: vec![Evidence {
            rule_id: format!("settings:{}:{}", loc.agent, loc.format),
            rule_status: loc.status.clone(),
            source_kind: "config".into(),
            location: ctx.display(path),
            grade: Grade::Configured,
            detail: vec![],
        }],
        unverified: false,
        notes,
        redactions: 0,
        upstreams: vec![],
        via_agent: None,
    }
}
