//! MCP server collector: reads client config files and classifies each server's reach.
//!
//! Privacy: argument values, env-var values and header values are parsed only to be dropped.
//! Kept: server name, command basename, launcher package name, transport, remote HOST, env-var and
//! header NAMES, and derived facts (pinned or not, shell or not, root of a filesystem server).

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use super::{command_basename, url_host, Output, Tracker};
use crate::catalog::{is_unverified, McpConfigLoc};
use crate::context::Ctx;
use crate::model::{Capability, Confidence, Evidence, Finding, Grade, Kind, Subject, Upstream};
use crate::upstream::{self, PackageInspector};

#[derive(Debug, Default)]
pub struct ServerSpec {
    pub name: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env_names: Vec<String>,
    pub header_names: Vec<String>,
    pub url: Option<String>,
    pub transport: Option<String>,
    /// For project-scoped entries inside ~/.claude.json: the project directory.
    pub project: Option<String>,
    /// Env values, held only long enough to take the HOST of endpoint-URL variables. Never output.
    pub env_values: Vec<(String, String)>,
}

pub fn collect(ctx: &Ctx) -> Output {
    let mut t = Tracker::new("mcp");
    let mut findings = Vec::new();
    let mut inspector = PackageInspector::new(ctx);
    for loc in ctx.catalog.file.locations.mcp_configs.iter().filter(|l| ctx.os_matches(&l.os)) {
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
            let specs = match parse(&loc.format, &text) {
                Ok(s) => s,
                Err(why) => {
                    t.unreadable(format!("{}: {why}", ctx.display(&path)));
                    continue;
                }
            };
            for spec in specs {
                findings.push(analyse(ctx, &mut inspector, loc, &path, spec));
            }
        }
    }
    t.finish(findings)
}

pub fn parse(format: &str, text: &str) -> Result<Vec<ServerSpec>, String> {
    match format {
        "codex_toml" => parse_codex(text),
        _ => {
            let v: Value = serde_json::from_str(strip_jsonc(text).as_str()).map_err(|_| "not valid JSON".to_string())?;
            let mut out = Vec::new();
            match format {
                "mcp_servers" => out.extend(from_map(v.get("mcpServers"), None)),
                "vscode" => {
                    out.extend(from_map(v.get("servers"), None));
                    out.extend(from_map(v.get("mcp").and_then(|m| m.get("servers")), None));
                }
                "claude_json" => {
                    out.extend(from_map(v.get("mcpServers"), None));
                    if let Some(Value::Object(projects)) = v.get("projects") {
                        for (dir, p) in projects {
                            out.extend(from_map(p.get("mcpServers"), Some(dir.clone())));
                        }
                    }
                }
                other => return Err(format!("unknown config format {other}")),
            }
            Ok(out)
        }
    }
}

/// VS Code configs allow // comments and trailing commas. Strip comments outside strings.
fn strip_jsonc(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let (mut i, mut in_str) = (0, false);
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c as char);
            if c == b'\\' && i + 1 < b.len() {
                out.push(b[i + 1] as char);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
        } else if c == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else {
            out.push(c as char);
            i += 1;
        }
    }
    // Byte-wise push breaks multi-byte chars only inside strings we never keep; re-decode safely.
    let cleaned = String::from_utf8_lossy(out.as_bytes()).into_owned();
    remove_trailing_commas(&cleaned)
}

fn remove_trailing_commas(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut in_str = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
            out.push(c);
        } else if c == ',' {
            let next = chars[i + 1..].iter().find(|c| !c.is_whitespace());
            if !matches!(next, Some('}') | Some(']')) {
                out.push(c);
            }
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

fn from_map(v: Option<&Value>, project: Option<String>) -> Vec<ServerSpec> {
    let Some(Value::Object(map)) = v else { return vec![] };
    map.iter()
        .map(|(name, cfg)| {
            let s = |k: &str| cfg.get(k).and_then(Value::as_str).map(str::to_string);
            ServerSpec {
                name: name.clone(),
                command: s("command"),
                args: cfg
                    .get("args")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                    .unwrap_or_default(),
                env_names: keys(cfg.get("env")),
                header_names: keys(cfg.get("headers")),
                url: s("url").or_else(|| s("serverUrl")).or_else(|| s("httpUrl")),
                transport: s("type").or_else(|| s("transport")),
                project: project.clone(),
                env_values: match cfg.get("env") {
                    Some(Value::Object(m)) => m.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string()))).collect(),
                    _ => vec![],
                },
            }
        })
        .collect()
}

fn keys(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Object(m)) => m.keys().cloned().collect(),
        _ => vec![],
    }
}

fn parse_codex(text: &str) -> Result<Vec<ServerSpec>, String> {
    let v: toml::Value = toml::from_str(text).map_err(|_| "not valid TOML".to_string())?;
    let Some(toml::Value::Table(servers)) = v.get("mcp_servers") else { return Ok(vec![]) };
    Ok(servers
        .iter()
        .map(|(name, cfg)| {
            let s = |k: &str| cfg.get(k).and_then(|x| x.as_str()).map(str::to_string);
            let tkeys = |k: &str| match cfg.get(k) {
                Some(toml::Value::Table(t)) => t.keys().cloned().collect(),
                _ => vec![],
            };
            let mut header_names: Vec<String> = tkeys("http_headers");
            if let Some(v) = s("bearer_token_env_var") {
                header_names.push(format!("Authorization (from {v})"));
            }
            ServerSpec {
                name: name.clone(),
                command: s("command"),
                args: cfg
                    .get("args")
                    .and_then(|a| a.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                    .unwrap_or_default(),
                env_names: tkeys("env"),
                header_names,
                url: s("url"),
                transport: None,
                project: None,
                env_values: match cfg.get("env") {
                    Some(toml::Value::Table(t)) => t.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string()))).collect(),
                    _ => vec![],
                },
            }
        })
        .collect())
}

/// The package a launcher (npx, bunx, uvx, pipx run, docker run) starts, and whether it is pinned.
pub fn launcher_package(cmd: &str, args: &[String]) -> Option<(String, String, bool)> {
    let positional = |skip_first: Option<&str>, value_flags: &[&str]| -> Option<String> {
        let mut it = args.iter().peekable();
        if let Some(first) = skip_first {
            // e.g. "pipx run", "docker run", "pnpm dlx"
            loop {
                let a = it.next()?;
                if a == first {
                    break;
                }
            }
        }
        while let Some(a) = it.next() {
            if a.starts_with('-') {
                if value_flags.contains(&a.as_str()) {
                    it.next();
                }
                continue;
            }
            return Some(a.clone());
        }
        None
    };
    match cmd {
        "npx" | "bunx" => {
            let spec = positional(None, &["-p", "--package", "-c", "--call"])?;
            let (name, pinned) = npm_split(&spec);
            Some(("npm".into(), name, pinned))
        }
        "pnpm" | "yarn" => {
            let spec = positional(Some("dlx"), &["-p", "--package"])?;
            let (name, pinned) = npm_split(&spec);
            Some(("npm".into(), name, pinned))
        }
        "uvx" | "pipx" => {
            let spec = if cmd == "pipx" { positional(Some("run"), &["--spec", "--python"])? } else { positional(None, &["--from", "--python", "--with"])? };
            let (name, pinned) = match spec.find("==").or_else(|| spec.find('@')) {
                Some(i) => (spec[..i].to_string(), !spec[i..].ends_with("latest")),
                None => (spec.clone(), false),
            };
            Some(("pypi".into(), name, pinned))
        }
        "docker" | "podman" => {
            let image = positional(
                Some("run"),
                &["-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "--mount", "-w", "--workdir", "--entrypoint", "-u", "--user", "--env-file", "--platform"],
            )?;
            let pinned = image.contains("@sha256:") || image.rsplit('/').next().is_some_and(|last| last.contains(':') && !last.ends_with(":latest"));
            let name = image.split('@').next().unwrap_or(&image);
            let name = match name.rsplit_once(':') {
                Some((n, tag)) if !tag.contains('/') => n,
                _ => name,
            };
            Some(("oci".into(), name.to_string(), pinned))
        }
        _ => None,
    }
}

fn npm_split(spec: &str) -> (String, bool) {
    let (scope_part, rest) = if let Some(r) = spec.strip_prefix('@') { ("@", r) } else { ("", spec) };
    match rest.find('@') {
        Some(i) => {
            let version = &rest[i + 1..];
            (format!("{scope_part}{}", &rest[..i]), !(version.is_empty() || version == "latest" || version == "next"))
        }
        None => (spec.to_string(), false),
    }
}

/// Coding-agent packages that, launched as an MCP server, forward work to that agent's provider.
const AGENT_PACKAGES: &[(&str, &str)] = &[("@openai/codex", "codex_cli"), ("@anthropic-ai/claude-code", "claude_code"), ("@google/gemini-cli", "gemini_cli")];

fn trace_upstreams(
    ctx: &Ctx,
    inspector: &mut PackageInspector,
    spec: &ServerSpec,
    base: Option<&str>,
    pkg: Option<&(String, String, bool)>,
) -> (Vec<Upstream>, Option<String>, Vec<String>) {
    let cat = ctx.catalog;
    let mut ups = Vec::new();
    let mut notes = Vec::new();
    let mut via_agent = None;
    for n in &spec.env_names {
        if let Some(p) = cat.provider_for_env(n) {
            ups.push(upstream::for_provider(p, format!("the config passes {n} to the server"), Confidence::High));
        }
    }
    for (k, v) in &spec.env_values {
        if cat.endpoint_env.is_match(k) {
            if let Some(h) = upstream::endpoint_host(v) {
                ups.push(upstream::for_host(ctx, &h, format!("{k} points the server at this host")));
            }
        }
    }
    if let Some((eco, name, _)) = pkg {
        if let Some(mp) = cat.file.tools.mcp_packages.iter().find(|m| m.package.eq_ignore_ascii_case(name)) {
            for id in &mp.upstreams {
                if let Some(p) = cat.provider(id) {
                    ups.push(upstream::for_provider(p, format!("catalog: {} calls {} (status {})", mp.package, p.name, mp.status), Confidence::Medium));
                }
            }
        }
        if let Some(p) = cat.provider_for_sdk(eco, name) {
            ups.push(upstream::for_provider(p, format!("the server package {name} is the {} SDK", p.name), Confidence::High));
        }
        if eco == "npm" || eco == "pypi" {
            let ev = inspector.inspect(eco, name);
            for (pid, lines) in &ev.providers {
                if let Some(p) = cat.provider(pid) {
                    ups.push(upstream::for_provider(p, lines.join("; "), Confidence::Medium));
                }
            }
            match &ev.installed_at {
                Some(at) => {
                    notes.push(format!("installed copy inspected at {at} ({} code files)", ev.files_scanned));
                    if ev.capped {
                        notes.push("package inspection hit its size cap; upstreams may be incomplete".into());
                    }
                }
                None => notes.push("installed copy not found; upstreams come from the config only".into()),
            }
        }
        if let Some((_, agent)) = AGENT_PACKAGES.iter().find(|(p, _)| p.eq_ignore_ascii_case(name)) {
            via_agent = Some(agent.to_string());
        }
    }
    if let Some(b) = base {
        if let Some(a) = cat.file.upstream.agent_defaults.iter().find(|a| a.command == b) {
            via_agent = Some(a.agent.clone());
        }
    }
    if let Some(url) = &spec.url {
        if let Some(h) = url_host(url) {
            if !is_local(&h) {
                ups.push(upstream::for_host(ctx, &h, "remote MCP endpoint in the config".into()));
            }
        }
    }
    upstream::apply_region_env(ctx, &mut ups, &spec.env_values, "server env");
    (upstream::merge(ups), via_agent, notes)
}

fn analyse(ctx: &Ctx, inspector: &mut PackageInspector, loc: &McpConfigLoc, path: &Path, spec: ServerSpec) -> Finding {
    let cat = ctx.catalog;
    let tools = &cat.file.tools;
    let mut caps: Vec<(Capability, String)> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut detail: Vec<String> = Vec::new();
    let mut confidence = Confidence::Low;
    let mut unverified = true;
    let mut matched_rule: Option<(String, String)> = None;

    let base = spec.command.as_deref().map(command_basename);
    let pkg = base.as_deref().and_then(|b| launcher_package(b, &spec.args));
    let transport = spec
        .transport
        .clone()
        .unwrap_or_else(|| if spec.url.is_some() { "http".into() } else { "stdio".into() });
    detail.push(format!("transport {transport}"));
    if let Some(b) = &base {
        detail.push(format!("command {b}"));
    }

    if let Some(b) = &base {
        if tools.shell_commands.iter().any(|s| s == b) {
            caps.push((Capability::ShellExec, format!("command is a shell ({b})")));
        }
    }

    if let Some((eco, name, pinned)) = &pkg {
        detail.push(format!("package {name} ({eco}, {})", if *pinned { "pinned" } else { "unpinned" }));
        if !pinned {
            caps.push((Capability::UnpinnedCode, format!("{} runs {name} without a pinned version", base.clone().unwrap_or_default())));
        }
        let fp_type = match eco.as_str() {
            "npm" => "npm_package",
            "pypi" => "pypi_package",
            _ => "oci_image",
        };
        if let Some(fp) = best(cat.lookup(fp_type, name)) {
            confidence = confidence.max(Confidence::parse(&fp.confidence));
            unverified = false;
            matched_rule = Some((format!("fp:{fp_type}:{}", fp.id), format!("catalog ({})", fp.repo)));
        }
        if let Some(mp) = tools.mcp_packages.iter().find(|m| m.package.eq_ignore_ascii_case(name)) {
            confidence = confidence.max(Confidence::Medium);
            unverified = unverified && is_unverified(&mp.status);
            if matched_rule.is_none() {
                matched_rule = Some((format!("mcp_package:{}", mp.package), mp.status.clone()));
            }
            for c in &mp.capabilities {
                if let Some(cap) = parse_cap(c) {
                    caps.push((cap, format!("catalog: {} → {c} (status {})", mp.package, mp.status)));
                }
            }
            if name.ends_with("server-filesystem") {
                let roots = filesystem_roots(ctx, &spec.args);
                if !roots.is_empty() {
                    notes.push(format!("filesystem roots: {}", roots.join(", ")));
                }
            }
        }
    } else if let Some(b) = &base {
        if let Some(fp) = best(cat.lookup("cli_command", b)) {
            confidence = confidence.max(Confidence::parse(&fp.confidence));
            unverified = false;
            matched_rule = Some((format!("fp:cli_command:{}", fp.id), format!("catalog ({})", fp.repo)));
        }
    }
    if matched_rule.is_none() {
        if let Some(fp) = best(cat.lookup("mcp_registry_name", &spec.name)) {
            confidence = confidence.max(Confidence::parse(&fp.confidence).min(Confidence::Medium));
            unverified = false;
            matched_rule = Some((format!("fp:mcp_registry_name:{}", fp.id), format!("catalog ({})", fp.repo)));
        }
    }

    let cred_env: Vec<&String> = spec.env_names.iter().filter(|n| cat.is_credential_name(n)).collect();
    if !cred_env.is_empty() {
        caps.push((Capability::CredentialReach, format!("env names passed in: {}", join(&cred_env))));
    }
    let cred_hdr: Vec<&String> = spec.header_names.iter().filter(|n| cat.is_credential_name(n.split(' ').next().unwrap_or(n))).collect();
    if !cred_hdr.is_empty() {
        caps.push((Capability::CredentialReach, format!("credential headers: {}", join(&cred_hdr))));
    }
    if !spec.env_names.is_empty() {
        detail.push(format!("env names: {}", spec.env_names.join(", ")));
    }

    let mut provider = None;
    if let Some(url) = &spec.url {
        match url_host(url) {
            Some(h) if is_local(&h) => detail.push("remote host: local machine".into()),
            Some(h) => {
                let place = crate::geo::ip_literal(&h).and_then(|ip| ctx.geo.map(|g| g.lookup(ip)));
                match &place {
                    Some(p) => detail.push(format!("remote host {h} ({})", p.describe())),
                    None => detail.push(format!("remote host {h}")),
                }
                if let Some(rh) = tools.mcp_remote_hosts.iter().find(|r| r.host == h) {
                    provider = Some(rh.provider.clone());
                    confidence = confidence.max(Confidence::Medium);
                    unverified = unverified && is_unverified(&rh.status);
                    matched_rule.get_or_insert((format!("mcp_remote:{h}"), rh.status.clone()));
                } else if let Some(ph) = cat.provider_host(&h) {
                    provider = Some(ph.provider.clone());
                } else {
                    let why = match &place {
                        Some(p) => format!("remote host {h} is not in the catalog ({})", p.describe()),
                        None => format!("remote host {h} is not in the catalog"),
                    };
                    caps.push((Capability::RemoteUnknown, why));
                }
            }
            None => notes.push("remote URL could not be parsed".into()),
        }
    }

    let (upstreams, via_agent, up_notes) = trace_upstreams(ctx, inspector, &spec, base.as_deref(), pkg.as_ref());
    notes.extend(up_notes);

    // Values that were parsed and dropped: every argument, env value and header value.
    let redactions = (spec.args.len() + spec.env_names.len() + spec.header_names.len()) as u32;

    caps.sort_by_key(|(c, _)| std::cmp::Reverse(c.severity()));
    let mut seen = BTreeSet::new();
    caps.retain(|(c, _)| seen.insert(*c));

    let scope_note = match &spec.project {
        Some(dir) => {
            let shown = ctx.display(Path::new(dir));
            notes.push(format!("project scope: {shown}"));
            "project"
        }
        None => loc.scope.as_str(),
    };

    let (rule_id, rule_status) = matched_rule.clone().unwrap_or_else(|| ("unmatched".into(), "unverified".into()));
    if matched_rule.is_none() {
        notes.push("not in the catalog: identity and reach are unknown beyond what the config states".into());
    }

    Finding {
        id: String::new(),
        kind: Kind::McpServer,
        subject: Subject {
            name: spec.name.clone(),
            provider,
            client: Some(format!("{} ({scope_note})", loc.client)),
            package: pkg.map(|(_, n, _)| n),
            version: None,
        },
        grade: Grade::Configured,
        confidence,
        capability_basis: caps.iter().map(|(_, b)| b.clone()).collect(),
        capabilities: caps.into_iter().map(|(c, _)| c).collect(),
        evidence: vec![
            Evidence {
                rule_id: format!("config:{}:{}", loc.client, loc.format),
                rule_status: loc.status.clone(),
                source_kind: "config".into(),
                location: ctx.display(path),
                grade: Grade::Configured,
                detail,
            },
            Evidence {
                rule_id,
                rule_status,
                source_kind: "catalog".into(),
                location: "catalog".into(),
                grade: Grade::Configured,
                detail: vec![],
            },
        ],
        unverified,
        notes,
        redactions,
        upstreams,
        via_agent,
    }
}

fn best(v: Vec<&crate::catalog::Fingerprint>) -> Option<&crate::catalog::Fingerprint> {
    v.into_iter().max_by_key(|f| (!f.collision, Confidence::parse(&f.confidence)))
}

fn parse_cap(s: &str) -> Option<Capability> {
    Some(match s {
        "shell_exec" => Capability::ShellExec,
        "credential_reach" => Capability::CredentialReach,
        "fs_write" => Capability::FsWrite,
        "remote_unknown" => Capability::RemoteUnknown,
        "unpinned_code" => Capability::UnpinnedCode,
        "network_egress" => Capability::NetworkEgress,
        "fs_read" => Capability::FsRead,
        _ => return None,
    })
}

fn is_local(h: &str) -> bool {
    h == "localhost" || h == "127.0.0.1" || h == "::1" || h.ends_with(".localhost")
}

/// Classify filesystem-server root arguments without keeping arbitrary paths.
fn filesystem_roots(ctx: &Ctx, args: &[String]) -> Vec<String> {
    let home = ctx.home.to_string_lossy().to_string();
    let mut out = BTreeSet::new();
    for a in args.iter().filter(|a| !a.starts_with('-') && !a.starts_with('@') && a.contains(['/', '\\', '~'])) {
        let a = a.trim_end_matches(['/', '\\']);
        let class = if a.is_empty() || a == "/" || a.ends_with(":") {
            "filesystem root"
        } else if a == "~" || a == home {
            "entire home directory"
        } else if a.starts_with('~') || a.starts_with(&home) {
            "a directory under home"
        } else {
            "a directory outside home"
        };
        out.insert(class.to_string());
    }
    out.into_iter().collect()
}

fn join(v: &[&String]) -> String {
    v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn launchers() {
        assert_eq!(launcher_package("npx", &s(&["-y", "@modelcontextprotocol/server-filesystem", "/"])), Some(("npm".into(), "@modelcontextprotocol/server-filesystem".into(), false)));
        assert_eq!(launcher_package("npx", &s(&["-y", "@playwright/mcp@0.0.41"])), Some(("npm".into(), "@playwright/mcp".into(), true)));
        assert_eq!(launcher_package("npx", &s(&["chrome-devtools-mcp@latest"])), Some(("npm".into(), "chrome-devtools-mcp".into(), false)));
        assert_eq!(launcher_package("uvx", &s(&["mcp-server-fetch"])), Some(("pypi".into(), "mcp-server-fetch".into(), false)));
        assert_eq!(launcher_package("uvx", &s(&["mcp-server-git==0.6.2"])), Some(("pypi".into(), "mcp-server-git".into(), true)));
        assert_eq!(
            launcher_package("docker", &s(&["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"])),
            Some(("oci".into(), "ghcr.io/github/github-mcp-server".into(), false))
        );
        assert_eq!(launcher_package("node", &s(&["server.js"])), None);
    }

    #[test]
    fn jsonc() {
        let v = parse("vscode", "{ // c\n \"servers\": { \"a\": { \"command\": \"npx\", \"args\": [\"x\",], }, }, /* b */ }").unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].args, vec!["x"]);
    }

    #[test]
    fn codex() {
        let v = parse("codex_toml", "model='x'\n[mcp_servers.fs]\ncommand='npx'\nargs=['-y','@modelcontextprotocol/server-filesystem']\n[mcp_servers.fs.env]\nAPI_KEY='secret'\n").unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].env_names, vec!["API_KEY"]);
    }
}
