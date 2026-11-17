//! The fingerprint catalog, compiled by `tools/build_catalog.py` and embedded at build time.

use std::collections::HashMap;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;

const EMBEDDED: &str = include_str!("../catalog/catalog.json");

#[derive(Debug, Deserialize)]
pub struct Template {
    pub template: String,
    #[serde(default)]
    pub meaning: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct NamedStatus {
    #[serde(alias = "suffix")]
    pub name: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct WebService {
    pub service: String,
    pub provider: String,
    pub hosts: Vec<String>,
    pub history_reliable_for_usage: bool,
    pub used: Vec<Template>,
    pub viewed_not_used: Vec<Template>,
    pub observed_unclassified: Vec<Template>,
    pub not_usage: Vec<Template>,
    pub signed_in_cookies: Vec<NamedStatus>,
    pub data_out_hosts: Vec<NamedStatus>,
}

#[derive(Debug, Deserialize)]
pub struct ProviderHost {
    pub id: String,
    pub host: String,
    pub provider: String,
    pub service: String,
    pub category: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct Fingerprint {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub confidence: String,
    pub repo: String,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub blob: Option<String>,
    #[serde(default)]
    pub collision: bool,
}

#[derive(Debug, Deserialize)]
pub struct AiCli {
    pub command: String,
    pub provider: String,
    pub tool: String,
    pub agent: bool,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct IdeExt {
    pub id: String,
    pub provider: String,
    pub tool: String,
    pub status: String,
    #[serde(default)]
    pub upstream: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KeyName {
    pub name: String,
    pub provider: String,
}

#[derive(Debug, Deserialize)]
pub struct McpPackage {
    pub package: String,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub upstreams: Vec<String>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct RemoteHost {
    pub host: String,
    pub provider: String,
    #[serde(default)]
    pub hq_country: Option<String>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct Tools {
    pub ai_cli: Vec<AiCli>,
    pub ide_extensions: Vec<IdeExt>,
    pub key_names: Vec<KeyName>,
    pub mcp_packages: Vec<McpPackage>,
    pub mcp_remote_hosts: Vec<RemoteHost>,
    pub shell_commands: Vec<String>,
    pub credential_name_patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BrowserRoot {
    #[serde(default)]
    pub browser: Option<String>,
    pub os: String,
    pub root: String,
}

#[derive(Debug, Deserialize)]
pub struct Browsers {
    pub chromium: Vec<BrowserRoot>,
    pub firefox: Vec<BrowserRoot>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct McpConfigLoc {
    pub client: String,
    pub scope: String,
    pub os: String,
    pub path: String,
    pub format: String,
    pub status: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DirLoc {
    #[serde(default)]
    pub client: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub ide: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    pub path: String,
    pub status: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentSettingsLoc {
    pub agent: String,
    pub path: String,
    pub format: String,
    pub status: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentFileLoc {
    pub tool: String,
    pub kind: String,
    pub scope: String,
    pub os: String,
    pub path: String,
    pub status: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PackageRoot {
    pub kind: String,
    pub layout: String,
    pub os: String,
    pub path: String,
    pub status: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegionalEntity {
    pub region: String,
    pub entity: String,
    pub country: String,
}

/// Cited evidence for a provider row (catalog/src/provider_sources.json).
#[derive(Debug, Deserialize, Clone)]
pub struct ProviderSource {
    pub source_kind: String,
    pub source_url: String,
    pub source_quote: String,
    pub regional_entities: Vec<RegionalEntity>,
    pub processing_countries: Vec<String>,
    pub processing_note: String,
}

#[derive(Debug, Deserialize)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub hq_country: String,
    pub status: String,
    pub api_hosts: Vec<String>,
    pub npm: Vec<String>,
    pub pypi: Vec<String>,
    pub env_keys: Vec<String>,
    pub base_url_env: Vec<String>,
    #[serde(default)]
    pub source: Option<ProviderSource>,
    #[serde(default)]
    pub cloud: Option<String>,
    #[serde(default)]
    pub regional_hosts: Vec<String>,
    #[serde(default)]
    pub region_env: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CloudRegion {
    pub code: String,
    pub location: String,
    pub country: Option<String>,
    pub source_url: String,
}

#[derive(Debug, Deserialize)]
pub struct CloudRegions {
    pub regions: Vec<CloudRegion>,
}

#[derive(Debug, Deserialize)]
pub struct CloudRegionCatalog {
    pub aws: CloudRegions,
    pub gcp: CloudRegions,
}

#[derive(Debug, Deserialize)]
pub struct AgentDefault {
    pub agent: String,
    pub command: String,
    pub provider: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaudeRoute {
    pub env: String,
    pub provider: String,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamCatalog {
    pub providers: Vec<Provider>,
    pub agent_defaults: Vec<AgentDefault>,
    pub claude_code_routes: Vec<ClaudeRoute>,
    pub endpoint_env_pattern: String,
}

#[derive(Debug, Deserialize)]
pub struct Locations {
    pub browsers: Browsers,
    pub mcp_configs: Vec<McpConfigLoc>,
    pub skill_dirs: Vec<DirLoc>,
    pub plugin_dirs: Vec<DirLoc>,
    pub ide_extension_dirs: Vec<DirLoc>,
    pub package_dirs: Vec<DirLoc>,
    pub key_files: Vec<String>,
    pub agent_settings: Vec<AgentSettingsLoc>,
    pub agent_files: Vec<AgentFileLoc>,
    pub package_roots: Vec<PackageRoot>,
}

#[derive(Debug, Deserialize)]
pub struct CatalogFile {
    pub version: String,
    pub sha256: String,
    pub web_services: Vec<WebService>,
    pub provider_hosts: Vec<ProviderHost>,
    pub fingerprints: Vec<Fingerprint>,
    pub tools: Tools,
    pub locations: Locations,
    pub upstream: UpstreamCatalog,
    pub cloud_regions: CloudRegionCatalog,
}

/// The catalog plus lookup indexes built once per scan.
pub struct Catalog {
    pub file: CatalogFile,
    /// (type, lowercase identifier) -> fingerprint indexes
    by_type_id: HashMap<(String, String), Vec<usize>>,
    /// skill blob oid -> fingerprint indexes
    by_blob: HashMap<String, Vec<usize>>,
    pub credential_patterns: Vec<Regex>,
    pub endpoint_env: Regex,
}

impl Catalog {
    pub fn embedded() -> Result<Catalog> {
        Catalog::parse_json(EMBEDDED)
    }

    pub fn parse_json(s: &str) -> Result<Catalog> {
        let file: CatalogFile = serde_json::from_str(s).context("catalog.json does not parse")?;
        let mut by_type_id: HashMap<(String, String), Vec<usize>> = HashMap::new();
        let mut by_blob: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, f) in file.fingerprints.iter().enumerate() {
            by_type_id.entry((f.kind.clone(), f.id.to_lowercase())).or_default().push(i);
            if let Some(b) = &f.blob {
                by_blob.entry(b.clone()).or_default().push(i);
            }
        }
        let credential_patterns = file
            .tools
            .credential_name_patterns
            .iter()
            .map(|p| Regex::new(&format!("(?i){p}")))
            .collect::<Result<Vec<_>, _>>()
            .context("credential_name_patterns")?;
        let endpoint_env = Regex::new(&format!("(?i){}", file.upstream.endpoint_env_pattern)).context("endpoint_env_pattern")?;
        Ok(Catalog { file, by_type_id, by_blob, credential_patterns, endpoint_env })
    }

    pub fn lookup(&self, kind: &str, id: &str) -> Vec<&Fingerprint> {
        self.by_type_id
            .get(&(kind.to_string(), id.to_lowercase()))
            .map(|v| v.iter().map(|&i| &self.file.fingerprints[i]).collect())
            .unwrap_or_default()
    }

    pub fn lookup_blob(&self, oid: &str) -> Vec<&Fingerprint> {
        self.by_blob
            .get(oid)
            .map(|v| v.iter().map(|&i| &self.file.fingerprints[i]).collect())
            .unwrap_or_default()
    }

    pub fn is_credential_name(&self, name: &str) -> bool {
        self.credential_patterns.iter().any(|r| r.is_match(name))
    }

    pub fn provider(&self, id: &str) -> Option<&Provider> {
        self.file.upstream.providers.iter().find(|p| p.id == id)
    }

    /// AI provider whose API host matches exactly or as a parent domain.
    pub fn provider_for_host(&self, host: &str) -> Option<&Provider> {
        let h = host.trim_start_matches('.').to_lowercase();
        self.file
            .upstream
            .providers
            .iter()
            .find(|p| p.api_hosts.iter().any(|a| h == *a || h.ends_with(&format!(".{a}"))))
    }

    /// Provider and region code when the host matches a `{region}` template, e.g.
    /// bedrock-runtime.eu-central-1.amazonaws.com -> (aws_bedrock, "eu-central-1").
    pub fn provider_for_regional_host(&self, host: &str) -> Option<(&Provider, String)> {
        let h = host.to_lowercase();
        for p in &self.file.upstream.providers {
            for t in &p.regional_hosts {
                let Some((pre, post)) = t.split_once("{region}") else { continue };
                if h.len() > pre.len() + post.len() && h.starts_with(pre) && h.ends_with(post) {
                    let code = &h[pre.len()..h.len() - post.len()];
                    if !code.is_empty() && !code.contains('.') {
                        return Some((p, code.to_string()));
                    }
                }
            }
        }
        None
    }

    pub fn cloud_region(&self, cloud: &str, code: &str) -> Option<&CloudRegion> {
        let list = match cloud {
            "aws" => &self.file.cloud_regions.aws.regions,
            "gcp" => &self.file.cloud_regions.gcp.regions,
            _ => return None,
        };
        list.iter().find(|r| r.code == code)
    }

    pub fn provider_for_env(&self, name: &str) -> Option<&Provider> {
        self.file.upstream.providers.iter().find(|p| p.env_keys.iter().any(|k| k == name))
    }

    pub fn provider_for_sdk(&self, eco: &str, package: &str) -> Option<&Provider> {
        let norm = |s: &str| s.to_lowercase().replace('_', "-");
        let pkg = norm(package);
        self.file.upstream.providers.iter().find(|p| {
            let list = if eco == "npm" { &p.npm } else { &p.pypi };
            list.iter().any(|x| norm(x) == pkg)
        })
    }

    pub fn provider_host(&self, host: &str) -> Option<&ProviderHost> {
        let h = host.to_lowercase();
        self.file.provider_hosts.iter().find(|p| p.host == h)
    }

    pub fn web_service_for_host(&self, host: &str) -> Option<(&WebService, &str)> {
        let h = host.trim_start_matches('.').to_lowercase();
        for s in &self.file.web_services {
            for base in &s.hosts {
                if h == *base || h.ends_with(&format!(".{base}")) {
                    return Some((s, base.as_str()));
                }
            }
        }
        None
    }
}

/// Status strings that mean "not confirmed on a real machine".
pub fn is_unverified(status: &str) -> bool {
    !matches!(status, "verified")
}
