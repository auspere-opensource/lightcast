//! The report model. Every output is a rendering of [`Report`].

use serde::{Deserialize, Serialize};

pub const REPORT_SCHEMA: &str = "lightcast.report/v1";

/// What the local evidence shows, weakest first. Ordering is used to pick a finding's strongest grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    Installed,
    Configured,
    Reached,
    SignedIn,
    Used,
    DataOut,
}

impl Grade {
    pub fn label(self) -> &'static str {
        match self {
            Grade::Installed => "installed",
            Grade::Configured => "configured",
            Grade::Reached => "reached",
            Grade::SignedIn => "signed_in",
            Grade::Used => "used",
            Grade::DataOut => "data_out",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn parse(s: &str) -> Confidence {
        match s {
            "high" => Confidence::High,
            "medium" => Confidence::Medium,
            _ => Confidence::Low,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// Blast-radius classes, most severe first in declaration order of severity via [`Capability::severity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ShellExec,
    CredentialReach,
    FsWrite,
    RemoteUnknown,
    UnpinnedCode,
    NetworkEgress,
    FsRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
    pub fn parse(s: &str) -> Option<Severity> {
        match s {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl Capability {
    pub fn severity(self) -> Severity {
        match self {
            Capability::ShellExec | Capability::CredentialReach => Severity::Critical,
            Capability::FsWrite | Capability::RemoteUnknown => Severity::High,
            Capability::UnpinnedCode | Capability::NetworkEgress => Severity::Medium,
            Capability::FsRead => Severity::Low,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Capability::ShellExec => "shell_exec",
            Capability::CredentialReach => "credential_reach",
            Capability::FsWrite => "fs_write",
            Capability::RemoteUnknown => "remote_unknown",
            Capability::UnpinnedCode => "unpinned_code",
            Capability::NetworkEgress => "network_egress",
            Capability::FsRead => "fs_read",
        }
    }
    pub fn phrase(self) -> &'static str {
        match self {
            Capability::ShellExec => "can run shell commands",
            Capability::CredentialReach => "is handed credentials",
            Capability::FsWrite => "can write files",
            Capability::RemoteUnknown => "talks to an uncatalogued remote host",
            Capability::UnpinnedCode => "runs unpinned code that can change under you",
            Capability::NetworkEgress => "can make network requests",
            Capability::FsRead => "can read files",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    WebService,
    McpServer,
    Agent,
    Customization,
    Skill,
    Plugin,
    IdeExtension,
    CliTool,
    Package,
    ApiKey,
}

impl Kind {
    pub fn title(self) -> &'static str {
        match self {
            Kind::WebService => "AI web services",
            Kind::McpServer => "MCP servers",
            Kind::Agent => "Agent settings",
            Kind::Customization => "AI configuration & memory",
            Kind::Skill => "Agent skills",
            Kind::Plugin => "Agent plugins",
            Kind::IdeExtension => "IDE extensions",
            Kind::CliTool => "AI command-line tools",
            Kind::Package => "AI packages",
            Kind::ApiKey => "AI API keys (names only)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub rule_id: String,
    pub rule_status: String,
    pub source_kind: String,
    /// Path with the home directory shown as `~`. Never a URL, value or file content.
    pub location: String,
    pub grade: Grade,
    /// Small, privacy-safe facts: counts, path shapes, cookie names, env-var names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detail: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Subject {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Where a finding can send data: an AI provider or another remote destination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Upstream {
    /// Provider display name, or the destination host when no provider matches.
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// ISO 3166-1 alpha-2, "LOCAL" for this machine or a private network, or None when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// What the country is based on, e.g. "provider headquarters per its own legal page (…)".
    pub country_basis: String,
    /// Where the provider itself says it stores or processes data, when its own page says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processing: Option<String>,
    /// Intermediate agents, nearest first, e.g. ["Codex CLI"].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via: Vec<String>,
    /// Why this link was drawn: one line per piece of evidence.
    pub basis: Vec<String>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub kind: Kind,
    pub subject: Subject,
    pub grade: Grade,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    /// Why each capability was assigned; one line per capability, same order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_basis: Vec<String>,
    pub evidence: Vec<Evidence>,
    /// True when any rule behind this finding has not been verified on a real machine.
    pub unverified: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    pub redactions: u32,
    /// Providers and destinations this finding can send data to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<Upstream>,
    /// Set when this finding launches a coding agent whose own upstreams are inherited (resolved after collection).
    #[serde(skip)]
    pub via_agent: Option<String>,
}

impl Finding {
    pub fn worst(&self) -> Option<Severity> {
        self.capabilities.iter().map(|c| c.severity()).max()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorState {
    Ok,
    Partial,
    Unreadable,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorRun {
    pub name: String,
    pub status: CollectorState,
    pub duration_ms: u64,
    pub sources_read: u32,
    /// Human-readable reasons for partial/unreadable, without values or content.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub os: String,
    pub hostname_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Destination {
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    pub country_basis: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processing: Option<String>,
    /// "<finding id> <kind> <name>[ via <agent>]" for each sender.
    pub from: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Summary {
    pub web_services: usize,
    pub mcp_servers: usize,
    pub agents: usize,
    pub customizations: usize,
    pub skills: usize,
    pub plugins: usize,
    pub ide_extensions: usize,
    pub cli_tools: usize,
    pub packages: usize,
    pub api_keys: usize,
    pub worst: Option<Capability>,
    /// MCP servers, agents and extensions by their worst capability class.
    pub by_worst: Vec<(String, usize)>,
    pub unverified_findings: usize,
    pub low_confidence_findings: usize,
    /// One row per destination: where data can go and which findings send it there.
    pub destinations: Vec<Destination>,
    pub redactions: u32,
    pub headline: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Network {
    pub dns_lookups: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema: String,
    pub tool_version: String,
    pub catalog_version: String,
    pub catalog_sha256: String,
    pub scanned_at: String,
    pub paranoid: bool,
    pub host: Host,
    pub collectors: Vec<CollectorRun>,
    /// Data the scan relied on, with required attributions.
    pub data_sources: Vec<String>,
    /// Network use. Zero lookups unless the user passed --resolve.
    pub network: Network,
    pub findings: Vec<Finding>,
    pub summary: Summary,
}
