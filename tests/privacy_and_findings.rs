//! Builds a synthetic home directory seeded with canary strings in every place the privacy
//! contract says is never read, stored or printed, scans it, and checks every output format.

use std::fs;
use std::path::{Path, PathBuf};

use lightcast::catalog::Catalog;
use lightcast::model::{Capability, Grade, Kind, Report};
use lightcast::render;
use lightcast::report::{scan, ScanOptions};
use rusqlite::Connection;

const CANARY: &str = "CANARY";

fn write(p: &Path, s: &str) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, s).unwrap();
}

fn chrome_profile(dir: &Path) {
    fs::create_dir_all(dir.join("Network")).unwrap();
    let h = Connection::open(dir.join("History")).unwrap();
    h.execute_batch(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
         CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);",
    )
    .unwrap();
    // 13_400_000_000_000_000 µs after 1601 ≈ 2025-08.
    let rows = [
        "https://chatgpt.com/c/CANARY-conversation-id?q=CANARY-query#CANARY-frag",
        "https://chatgpt.com/c/second-CANARY-id",
        "https://chatgpt.com/CANARY-unmatched-path/with-user-text",
        "https://claude.ai/new",
        "https://www.perplexity.ai/search/CANARY-question-slug-about-payroll",
        "https://api.groq.com/openai/v1/CANARY",
        "https://example.com/not-ai/CANARY",
    ];
    for (i, u) in rows.iter().enumerate() {
        h.execute(
            "INSERT INTO urls(url, title, visit_count, last_visit_time) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![u, "CANARY page title", (i + 2) as i64, 13_400_000_000_000_000i64],
        )
        .unwrap();
    }
    h.execute("INSERT INTO downloads_url_chains VALUES (1, 0, 'https://files07.oaiusercontent.com/file-CANARYFILE/CANARY-report.pdf?sig=CANARY')", [])
        .unwrap();
    let c = Connection::open(dir.join("Network").join("Cookies")).unwrap();
    c.execute_batch(
        "CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB);
         INSERT INTO cookies VALUES ('.chatgpt.com', '__Secure-next-auth.session-token', 'CANARY-cookie-value', x'43414e415259');
         INSERT INTO cookies VALUES ('claude.ai', 'sessionKey', 'CANARY-session', x'43414e415259');
         INSERT INTO cookies VALUES ('example.com', 'CANARY-name-on-other-host', 'CANARY', x'00');",
    )
    .unwrap();
}

fn firefox_profile(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    let p = Connection::open(dir.join("places.sqlite")).unwrap();
    p.execute_batch(
        "CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
         CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT);
         CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT);
         INSERT INTO moz_places VALUES (1, 'https://gemini.google.com/app/CANARYGEMINI', 'CANARY title', 4, 1762560000000000);
         INSERT INTO moz_places VALUES (2, 'https://claude.ai/download/CANARY.zip', 'CANARY', 1, 1762560000000000);
         INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI');
         INSERT INTO moz_annos VALUES (1, 2, 1, 'file:///home/someone/Downloads/CANARY.zip');",
    )
    .unwrap();
    let c = Connection::open(dir.join("cookies.sqlite")).unwrap();
    c.execute_batch(
        "CREATE TABLE moz_cookies(host TEXT, name TEXT, value TEXT);
         INSERT INTO moz_cookies VALUES ('claude.ai', 'sessionKey', 'CANARY-ff-session');",
    )
    .unwrap();
}

struct Fixture {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    path_dir: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home").join("CANARYUSER");
    chrome_profile(&home.join(".config/google-chrome/Default"));
    firefox_profile(&home.join(".mozilla/firefox/abcd.default-release"));

    write(
        &home.join(".cursor/mcp.json"),
        r#"{ "mcpServers": {
            "shellbox": { "command": "/bin/bash", "args": ["-c", "curl CANARY-arg"], "env": { "GITHUB_TOKEN": "CANARY-env-value", "LOG_LEVEL": "CANARY" } },
            "files":    { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "~"] },
            "pinned":   { "command": "npx", "args": ["-y", "@playwright/mcp@0.0.41"] },
            "remote":   { "url": "https://mcp.siteonly-unknown.example/sse?token=CANARY-url-token", "headers": { "Authorization": "Bearer CANARY-header" } },
            "notion":   { "type": "http", "url": "https://mcp.notion.com/mcp" },
            "byip":     { "url": "http://8.8.8.8:8080/mcp?key=CANARY-ip-token" },
            "lan":      { "url": "http://10.20.30.40/mcp" },
            "loop":     { "url": "http://127.0.0.1:3000/mcp" },
            "voice":    { "command": "npx", "args": ["-y", "voice-mcp"], "env": { "ELEVENLABS_API_KEY": "CANARY-11labs" } },
            "codexsrv": { "command": "codex", "args": ["mcp-server"] },
            "gw":       { "command": "node", "args": ["CANARY.js"], "env": { "OPENAI_BASE_URL": "https://siteonly-gw.example/v1?key=CANARY-gw" } },
            "ds":       { "command": "node", "args": ["x.js"], "env": { "DEEPSEEK_API_KEY": "CANARY-ds" } },
            "vx":       { "url": "https://europe-west4-aiplatform.googleapis.com/v1/projects/CANARY/locations/europe-west4" },
            "vxglobal": { "url": "https://aiplatform.global.rep.googleapis.com/v1/CANARY" },
            "badregion":{ "command": "node", "args": ["y.js"], "env": { "GEMINI_API_KEY": "CANARY-g", "CLOUD_ML_REGION": "CANARY-not-a-region" } }
        } }"#,
    );
    write(
        &home.join(".claude.json"),
        r#"{ "mcpServers": {
                "tts":      { "command": "npx", "args": ["-y", "voice-mcp"], "env": { "ELEVENLABS_API_KEY": "CANARY-tts" } },
                "loopback": { "command": "codex", "args": ["mcp-server", "CANARY"] }
             },
             "projects": { "/work/SITEONLY-client-project": { "mcpServers": { "db": { "command": "uvx", "args": ["mcp-server-git", "--repository", "/work/CANARY"] } } } } }"#,
    );
    write(
        &home.join(".claude/settings.json"),
        r#"{ "permissions": { "defaultMode": "bypassPermissions", "allow": ["Bash(rm -rf CANARY-rule:*)", "mcp__CANARY__tool"] }, "env": { "ANTHROPIC_API_KEY": "CANARY-settings-env", "CLAUDE_CODE_USE_BEDROCK": "1", "AWS_REGION": "eu-central-1" } }"#,
    );
    write(
        &home.join(".codex/config.toml"),
        "approval_policy = \"on-request\"\nsandbox_mode = \"workspace-write\"\n[projects.\"/work/CANARY\"]\ntrust_level = \"trusted\"\n[mcp_servers.claudesrv]\ncommand = \"claude\"\nargs = [\"mcp\", \"serve\", \"CANARY\"]\n",
    );
    write(&home.join(".claude/skills/my-skill/SKILL.md"), "---\nname: my-skill\n---\nCANARY skill body\n");
    write(&home.join(".claude/skills/my-skill/scripts/run.sh"), "echo CANARY\n");
    write(&home.join(".claude/CLAUDE.md"), "CANARY private standing instructions\n");
    fs::create_dir_all(home.join(".vscode/extensions/github.copilot-1.250.0")).unwrap();
    fs::create_dir_all(home.join(".vscode/extensions/ms-python.python-2025.1.0")).unwrap();
    fs::create_dir_all(home.join(".local/lib/python3.12/site-packages/openai-2.7.1.dist-info")).unwrap();
    write(&home.join(".bashrc"), "export PATH=$PATH:/x\nexport OPENAI_API_KEY=sk-CANARY-file-key\nexport EMPTY_ONE=\n# GROQ_API_KEY=CANARY-commented\n");

    // An npx-installed MCP server: ElevenLabs SDK in its tree, a Suno host in its own code.
    let npx = home.join(".npm/_npx/0a1b2c3d");
    write(&npx.join("package.json"), r#"{ "dependencies": { "voice-mcp": "^1.0.0" } }"#);
    write(&npx.join("node_modules/voice-mcp/package.json"), r#"{ "name": "voice-mcp", "version": "1.0.0" }"#);
    write(&npx.join("node_modules/voice-mcp/dist/index.js"), "const SONG = 'https://studio-api.prod.suno.com/api/generate/CANARY';\nexport default SONG;\n");
    write(&npx.join("node_modules/@elevenlabs/elevenlabs-js/package.json"), r#"{ "name": "@elevenlabs/elevenlabs-js" }"#);

    let path_dir = tmp.path().join("bin");
    for name in ["claude", "test", "code", "ollama", "atlassian-mcp-CANARY"] {
        write(&path_dir.join(name), "#!/bin/sh\n");
    }
    Fixture { _tmp: tmp, home, path_dir }
}

fn run(f: &Fixture, paranoid: bool) -> Report {
    let catalog = Catalog::embedded().unwrap();
    let mut opts = ScanOptions::for_home(f.home.clone());
    opts.os = "linux";
    opts.paranoid = paranoid;
    opts.path_env = Some(f.path_dir.to_string_lossy().into_owned());
    opts.env_override = Some(vec![
        ("ANTHROPIC_API_KEY".into(), "CANARY-process-env".into()),
        ("HOME".into(), "CANARY".into()),
    ]);
    scan(&catalog, &opts)
}

fn all_outputs(r: &Report) -> Vec<(&'static str, String)> {
    vec![
        ("json", serde_json::to_string_pretty(r).unwrap()),
        ("terminal", render::terminal::render(r, false, true, false)),
        ("terminal-verbose", render::terminal::render(r, true, true, true)),
        ("html", render::html::render(r, true)),
        ("card", render::card::render(r)),
    ]
}

#[test]
fn no_canary_reaches_any_output() {
    let f = fixture();
    for paranoid in [false, true] {
        let r = run(&f, paranoid);
        for (name, out) in all_outputs(&r) {
            assert!(!out.to_uppercase().contains(CANARY), "{name} output (paranoid={paranoid}) leaked a canary:\n{}", leak_context(&out));
            assert!(!out.contains(&*f.home.to_string_lossy()), "{name} output printed the absolute home path");
            // Remote MCP hosts and project paths are allowed in a normal report, never in a paranoid one.
            if paranoid {
                assert!(!out.to_uppercase().contains("SITEONLY"), "{name} paranoid output kept a host or project path");
            }
        }
    }
}

#[test]
fn presentation_explains_unverified_rules_without_disallowed_sources() {
    let f = fixture();
    let r = run(&f, false);
    let terminal = render::terminal::render(&r, false, false, false);
    let verbose = render::terminal::render(&r, false, false, true);
    let html = render::html::render(&r, false);

    assert!(!terminal.contains("rule not yet verified on a real machine"), "{terminal}");
    assert!(!terminal.contains("nothing was sent anywhere"), "{terminal}");
    assert!(verbose.contains("Treat it as a lead to review, not a confirmed conclusion."), "{verbose}");
    assert!(html.contains("Treat it as a lead to review, not a confirmed conclusion."), "{html}");
    assert!(!html.contains("nothing was sent anywhere"), "{html}");
    let forbidden_source = concat!("wiki", "pedia");
    for (name, out) in all_outputs(&r) {
        assert!(!out.to_ascii_lowercase().contains(forbidden_source), "{name} output mentioned a disallowed source");
    }
}

fn leak_context(out: &str) -> String {
    out.lines().filter(|l| l.to_uppercase().contains(CANARY)).take(5).collect::<Vec<_>>().join("\n")
}

fn find<'a>(r: &'a Report, kind: Kind, name: &str) -> &'a lightcast::model::Finding {
    r.findings
        .iter()
        .find(|x| x.kind == kind && x.subject.name == name)
        .unwrap_or_else(|| panic!("no {kind:?} finding named {name}; have: {:?}", r.findings.iter().map(|f| (&f.kind, &f.subject.name)).collect::<Vec<_>>()))
}

#[test]
fn expected_findings() {
    let f = fixture();
    let r = run(&f, false);

    let chatgpt = find(&r, Kind::WebService, "ChatGPT");
    assert_eq!(chatgpt.grade, Grade::DataOut);
    assert!(chatgpt.evidence.iter().any(|e| e.grade == Grade::Used));
    assert!(chatgpt.evidence.iter().any(|e| e.grade == Grade::SignedIn));
    let claude = find(&r, Kind::WebService, "Claude");
    assert_eq!(claude.grade, Grade::DataOut, "firefox download from claude.ai");
    assert!(claude.notes.iter().all(|n| !n.contains("not visible")), "note only applies when grade < used… but data_out > used");
    assert_eq!(find(&r, Kind::WebService, "Gemini").grade, Grade::Used);
    let pplx = find(&r, Kind::WebService, "Perplexity");
    assert_eq!(pplx.grade, Grade::Used);
    assert!(pplx.unverified, "perplexity usage template is unverified");
    assert_eq!(find(&r, Kind::WebService, "Groq API").grade, Grade::Reached);

    let shell = find(&r, Kind::McpServer, "shellbox");
    assert_eq!(shell.capabilities.first(), Some(&Capability::ShellExec));
    assert!(shell.capabilities.contains(&Capability::CredentialReach));
    assert!(r.summary.headline.contains("can act as you"), "{}", r.summary.headline);

    let files = find(&r, Kind::McpServer, "files");
    assert!(files.capabilities.contains(&Capability::FsWrite));
    assert!(files.capabilities.contains(&Capability::UnpinnedCode));
    assert!(files.notes.iter().any(|n| n.contains("entire home directory")));
    assert!(!find(&r, Kind::McpServer, "pinned").capabilities.contains(&Capability::UnpinnedCode));
    let remote = find(&r, Kind::McpServer, "remote");
    assert!(remote.capabilities.contains(&Capability::RemoteUnknown));
    assert!(remote.capabilities.contains(&Capability::CredentialReach));
    assert!(!find(&r, Kind::McpServer, "notion").capabilities.contains(&Capability::RemoteUnknown));
    // DB-IP Lite: 8.8.8.8 is AS15169 Google LLC, US (measured against release 2026-11).
    let byip = find(&r, Kind::McpServer, "byip");
    let basis = byip.capability_basis.join(" | ");
    assert!(basis.contains("AS15169") && basis.contains("DB-IP country US"), "{basis}");
    let lan = find(&r, Kind::McpServer, "lan");
    assert!(lan.capability_basis.join(" ").contains("private-network address"), "{:?}", lan.capability_basis);
    assert!(!find(&r, Kind::McpServer, "loop").capabilities.contains(&Capability::RemoteUnknown));
    assert!(r.data_sources.iter().any(|s| s.starts_with("IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0")));
    assert!(render::html::render(&r, false).contains("<a href='https://db-ip.com'>IP Geolocation by DB-IP</a>"));
    assert!(render::terminal::render(&r, false, false, false).contains("IP data: IP Geolocation by DB-IP"));

    // Upstream tracing.
    let up = |name: &str| -> Vec<(String, Option<String>, Vec<String>)> {
        find(&r, Kind::McpServer, name).upstreams.iter().map(|u| (u.provider.clone(), u.country.clone(), u.via.clone())).collect()
    };
    let voice = up("voice");
    assert!(voice.iter().any(|(p, c, _)| p == "ElevenLabs" && c.as_deref() == Some("US")), "{voice:?}");
    assert!(voice.iter().any(|(p, _, _)| p == "Suno"), "{voice:?}");
    let v = find(&r, Kind::McpServer, "voice");
    let eleven = v.upstreams.iter().find(|u| u.provider == "ElevenLabs").unwrap();
    assert!(eleven.basis.iter().any(|b| b.contains("ELEVENLABS_API_KEY")) && eleven.basis.iter().any(|b| b.contains("@elevenlabs/elevenlabs-js")), "{:?}", eleven.basis);
    let codexsrv = up("codexsrv");
    assert!(codexsrv.iter().any(|(p, c, via)| p == "OpenAI" && c.as_deref() == Some("US") && via == &vec!["Codex CLI".to_string()]), "{codexsrv:?}");
    let openai = find(&r, Kind::McpServer, "codexsrv").upstreams.iter().find(|u| u.provider == "OpenAI").unwrap();
    assert_eq!(
        openai.country_basis,
        "provider headquarters (catalog, unverified); processing region may differ"
    );
    let gw = up("gw");
    assert!(gw.iter().any(|(p, c, _)| p == "siteonly-gw.example" && c.is_none()), "{gw:?}");
    assert!(up("ds").iter().any(|(p, c, _)| p == "DeepSeek" && c.as_deref() == Some("CN")));
    let ds = find(&r, Kind::McpServer, "ds").upstreams.iter().find(|u| u.provider == "DeepSeek").unwrap();
    assert!(ds.country_basis.starts_with("provider headquarters per its own legal page (cdn.deepseek.com)"), "{}", ds.country_basis);
    assert!(ds.processing.as_deref().is_some_and(|p| p.starts_with("CN")), "{:?}", ds.processing);
    let cc_up = &find(&r, Kind::Agent, "Claude Code").upstreams;
    assert!(cc_up.iter().any(|u| u.provider_id.as_deref() == Some("aws_bedrock")), "{cc_up:?}");
    assert!(!cc_up.iter().any(|u| u.provider_id.as_deref() == Some("anthropic")), "Bedrock routing replaces the default");
    // Cloud regions: the endpoint host or a region env var gives the processing country.
    let br = cc_up.iter().find(|u| u.provider_id.as_deref() == Some("aws_bedrock")).unwrap();
    assert_eq!(br.country.as_deref(), Some("DE"), "{br:#?}");
    assert!(br.country_basis.starts_with("AWS region eu-central-1 (Europe (Frankfurt)) from AWS_REGION in the settings env"), "{}", br.country_basis);
    let vx = find(&r, Kind::McpServer, "vx").upstreams.iter().find(|u| u.provider_id.as_deref() == Some("google")).unwrap();
    assert_eq!(vx.country.as_deref(), Some("NL"), "{vx:#?}");
    let vg = find(&r, Kind::McpServer, "vxglobal").upstreams.iter().find(|u| u.provider_id.as_deref() == Some("google")).unwrap();
    assert!(vg.country.is_none() && vg.country_basis.contains("no single country"), "{vg:#?}");
    let bad = find(&r, Kind::McpServer, "badregion").upstreams.iter().find(|u| u.provider_id.as_deref() == Some("google")).unwrap();
    assert_eq!(bad.country.as_deref(), Some("US"), "an unknown region value is ignored: {bad:#?}");

    let cn = r.summary.destinations.iter().find(|d| d.country.as_deref() == Some("CN")).expect("a CN destination");
    assert!(cn.from.iter().any(|s| s.contains("\"ds\"")), "{:?}", cn.from);
    assert!(render::terminal::render(&r, false, false, false).contains("Where data can go"));

    // Transitive chains: codexsrv -> Codex CLI -> MCP "claudesrv" -> Claude Code -> MCP "tts" -> ElevenLabs.
    let cs = &find(&r, Kind::McpServer, "codexsrv").upstreams;
    let deep = cs.iter().find(|u| u.provider == "ElevenLabs").unwrap_or_else(|| panic!("{cs:#?}"));
    assert_eq!(deep.via, vec!["Codex CLI", "MCP server \"claudesrv\"", "Claude Code", "MCP server \"tts\""]);
    assert!(cs.iter().any(|u| u.provider_id.as_deref() == Some("aws_bedrock") && u.via == vec!["Codex CLI", "MCP server \"claudesrv\"", "Claude Code"]));
    // Claude Code's "loopback" server launches Codex again: the walk must stop and say so.
    assert!(cs.iter().any(|u| u.provider == "chain not followed" && u.basis.iter().any(|b| b.contains("cycle back to Codex CLI"))), "{cs:#?}");
    let cc_reach = &find(&r, Kind::Agent, "Claude Code").upstreams;
    assert!(cc_reach.iter().any(|u| u.provider == "ElevenLabs" && u.via == vec!["MCP server \"tts\""]), "{cc_reach:#?}");

    let db = find(&r, Kind::McpServer, "db");
    assert!(db.notes.iter().any(|n| n.starts_with("project scope:")));

    let cc = find(&r, Kind::Agent, "Claude Code");
    assert!(cc.capabilities.contains(&Capability::ShellExec));
    assert!(cc.notes.iter().any(|n| n.contains("1 pre-approved shell command pattern")));
    let codex = find(&r, Kind::Agent, "Codex CLI");
    assert!(codex.capabilities.is_empty(), "workspace-write + on-request is not unattended");

    let key = find(&r, Kind::ApiKey, "OPENAI_API_KEY");
    assert!(key.capabilities.contains(&Capability::CredentialReach));
    let env_key = find(&r, Kind::ApiKey, "ANTHROPIC_API_KEY");
    assert!(env_key.capabilities.is_empty(), "process env only");
    assert!(r.findings.iter().all(|f| f.subject.name != "GROQ_API_KEY"), "commented-out key must not count");

    assert!(r.findings.iter().any(|f| f.kind == Kind::IdeExtension && f.subject.name == "github.copilot"));
    assert!(r.findings.iter().all(|f| f.subject.name != "ms-python.python"));
    assert!(r.findings.iter().any(|f| f.kind == Kind::CliTool && f.subject.name == "Claude Code"));
    assert!(r.findings.iter().any(|f| f.kind == Kind::CliTool && f.subject.name == "Ollama"));
    assert!(r.findings.iter().all(|f| !(f.kind == Kind::CliTool && (f.subject.name == "test" || f.subject.name == "code"))));
    let memory = find(&r, Kind::Customization, "CLAUDE.md");
    assert_eq!(memory.subject.client.as_deref(), Some("Claude Code"));
    assert!(memory.notes.iter().any(|n| n == "contents were not read"));
    assert!(r.findings.iter().any(|f| f.kind == Kind::Package && f.subject.name == "openai"));

    let skill = find(&r, Kind::Skill, "my-skill");
    assert!(skill.notes.iter().any(|n| n.contains("1 script")));
}

#[test]
fn paranoid_drops_dates_and_profiles() {
    let f = fixture();
    let r = run(&f, true);
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("google-chrome") && !json.contains("chrome:Default"));
    assert!(!json.contains("\"last 20"), "dates must be dropped");
    assert!(!json.contains("8.8.8.8") && !json.contains("AS15169"), "remote IPs and their geolocation must be withheld");
    assert_eq!(r.scanned_at.len(), 10, "only the date is kept");
    assert_eq!(r.network.dns_lookups, 0, "no DNS unless --resolve");
}

#[test]
fn missing_home_is_quiet_and_ok() {
    let tmp = tempfile::tempdir().unwrap();
    let catalog = Catalog::embedded().unwrap();
    let mut opts = ScanOptions::for_home(tmp.path().to_path_buf());
    opts.os = "linux";
    opts.path_env = Some(String::new());
    opts.env_override = Some(vec![]);
    let r = scan(&catalog, &opts);
    assert!(r.findings.is_empty());
    assert!(r.summary.headline.starts_with("No agent"));
}

#[test]
fn corrupt_files_degrade_to_unreadable() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().to_path_buf();
    write(&home.join(".cursor/mcp.json"), "{ not json CANARY");
    write(&home.join(".config/google-chrome/Default/History"), "not a database CANARY");
    let catalog = Catalog::embedded().unwrap();
    let mut opts = ScanOptions::for_home(home);
    opts.os = "linux";
    opts.path_env = Some(String::new());
    opts.env_override = Some(vec![]);
    let r = scan(&catalog, &opts);
    let mcp = r.collectors.iter().find(|c| c.name == "mcp").unwrap();
    assert_ne!(format!("{:?}", mcp.status), "Ok");
    for (name, out) in all_outputs(&r) {
        assert!(!out.contains(CANARY), "{name} leaked file content from a corrupt file");
    }
}
