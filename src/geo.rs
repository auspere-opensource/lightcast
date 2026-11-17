//! Offline IP geolocation from DB-IP Lite (Country + ASN), embedded at build time.
//!
//! IP Geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0. Every output that shows a
//! result carries that attribution.
//!
//! Only IP *literals* are looked up. The scanner never resolves hostnames: that would be a network
//! call, which the privacy contract forbids.

use std::net::IpAddr;

use serde::Deserialize;

const COUNTRY_DB: &[u8] = include_bytes!("../catalog/geo/dbip-country-lite.mmdb");
const ASN_DB: &[u8] = include_bytes!("../catalog/geo/dbip-asn-lite.mmdb");
const MANIFEST: &str = include_str!("../catalog/geo/MANIFEST.json");

pub const ATTRIBUTION: &str = "IP Geolocation by DB-IP";
pub const ATTRIBUTION_URL: &str = "https://db-ip.com";
pub const LICENSE: &str = "CC BY 4.0";

#[derive(Deserialize)]
struct Names {
    en: Option<String>,
}

#[derive(Deserialize)]
struct Country {
    iso_code: Option<String>,
    names: Option<Names>,
}

#[derive(Deserialize)]
struct CountryRecord {
    country: Option<Country>,
}

#[derive(Deserialize)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// Loopback, private, link-local, CGNAT, unique-local and similar: never routed on the internet.
    NonPublic(&'static str),
    Public { country_code: Option<String>, country: Option<String>, asn: Option<u32>, as_org: Option<String> },
}

impl Place {
    /// One line for reports, e.g. "AS13335 Cloudflare, Inc. · DB-IP country AU (Australia)".
    pub fn describe(&self) -> String {
        match self {
            Place::NonPublic(kind) => format!("{kind} address, not on the public internet"),
            Place::Public { country_code, country, asn, as_org } => {
                let mut parts = Vec::new();
                match (asn, as_org) {
                    (Some(n), Some(o)) => parts.push(format!("AS{n} {o}")),
                    (Some(n), None) => parts.push(format!("AS{n}")),
                    _ => parts.push("network owner unknown".into()),
                }
                match (country_code, country) {
                    (Some(c), Some(n)) => parts.push(format!("DB-IP country {c} ({n})")),
                    (Some(c), None) => parts.push(format!("DB-IP country {c}")),
                    _ => parts.push("country unknown".into()),
                }
                parts.join(" · ")
            }
        }
    }
}

pub struct Geo {
    country: maxminddb::Reader<&'static [u8]>,
    asn: maxminddb::Reader<&'static [u8]>,
    pub release: String,
}

#[derive(Deserialize)]
struct Manifest {
    release: String,
}

impl Geo {
    pub fn embedded() -> Option<Geo> {
        let country = maxminddb::Reader::from_source(COUNTRY_DB).ok()?;
        let asn = maxminddb::Reader::from_source(ASN_DB).ok()?;
        let release = serde_json::from_str::<Manifest>(MANIFEST).map(|m| m.release).unwrap_or_default();
        Some(Geo { country, asn, release })
    }

    /// "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0, release 2026-11".
    pub fn credit(&self) -> String {
        format!("{ATTRIBUTION} ({ATTRIBUTION_URL}), {LICENSE}, release {}", self.release)
    }

    pub fn lookup(&self, ip: IpAddr) -> Place {
        if let Some(kind) = non_public(ip) {
            return Place::NonPublic(kind);
        }
        let c: Option<CountryRecord> = self.country.lookup(ip).ok().and_then(|r| r.decode().ok()).flatten();
        let a: Option<AsnRecord> = self.asn.lookup(ip).ok().and_then(|r| r.decode().ok()).flatten();
        let country = c.and_then(|c| c.country);
        Place::Public {
            country_code: country.as_ref().and_then(|c| c.iso_code.clone()),
            country: country.and_then(|c| c.names).and_then(|n| n.en),
            asn: a.as_ref().and_then(|a| a.autonomous_system_number),
            as_org: a.and_then(|a| a.autonomous_system_organization),
        }
    }
}

/// Parse a URL host as an IP literal (`[v6]` brackets already stripped by `url_host`).
pub fn ip_literal(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

fn non_public(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_private() {
                Some("private-network")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if o[0] == 100 && (64..=127).contains(&o[1]) {
                Some("carrier-grade NAT")
            } else if v4.is_unspecified() || v4.is_broadcast() || v4.is_documentation() || o[0] >= 240 {
                Some("reserved")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if let Some(v4) = v6.to_ipv4_mapped() {
                return non_public(IpAddr::V4(v4));
            }
            if v6.is_loopback() {
                Some("loopback")
            } else if v6.is_unspecified() || (s[0] == 0x2001 && s[1] == 0x0db8) {
                Some("reserved")
            } else if (s[0] & 0xfe00) == 0xfc00 {
                Some("unique-local")
            } else if (s[0] & 0xffc0) == 0xfe80 {
                Some("link-local")
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_lookups_use_the_embedded_databases() {
        let g = Geo::embedded().expect("embedded DB-IP databases load");
        // Values measured against DB-IP Lite 2026-11 on 2026-11-08.
        match g.lookup("1.1.1.1".parse().unwrap()) {
            Place::Public { asn, .. } => assert_eq!(asn, Some(13335)),
            p => panic!("{p:?}"),
        }
        match g.lookup("8.8.8.8".parse().unwrap()) {
            Place::Public { asn, country_code, .. } => {
                assert_eq!(asn, Some(15169));
                assert_eq!(country_code.as_deref(), Some("US"));
            }
            p => panic!("{p:?}"),
        }
        assert!(g.credit().starts_with("IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"));
    }

    #[test]
    fn non_public_ranges_are_not_looked_up() {
        let g = Geo::embedded().unwrap();
        for (ip, kind) in [
            ("10.1.2.3", "private-network"),
            ("192.168.1.1", "private-network"),
            ("127.0.0.1", "loopback"),
            ("100.64.0.1", "carrier-grade NAT"),
            ("169.254.1.1", "link-local"),
            ("::1", "loopback"),
            ("fd00::1", "unique-local"),
            ("::ffff:10.0.0.1", "private-network"),
        ] {
            assert_eq!(g.lookup(ip.parse().unwrap()), Place::NonPublic(kind), "{ip}");
        }
    }

    #[test]
    fn literals() {
        assert!(ip_literal("203.0.113.9").is_some());
        assert!(ip_literal("[2606:4700::1]").is_some());
        assert!(ip_literal("mcp.notion.com").is_none());
    }
}

