//! Browser collector: history path shapes, cookie NAMES and download HOSTS on catalogued AI hosts.
//!
//! Privacy: the original databases are never opened. Each is copied into a private temp dir and the
//! copy is queried. Cookie values, page titles, query strings, fragments, IDs and slugs are never
//! selected or kept; a URL is reduced to its host plus the catalog template it matched.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use super::{url_host, url_path, Output, Tracker};
use crate::catalog::{is_unverified, Template, WebService};
use crate::context::{io_reason, Ctx};
use crate::model::{Confidence, Evidence, Finding, Grade, Kind, Subject};

#[derive(Default)]
struct PathStat {
    urls: u32,
    visits: u64,
    last_day: Option<i64>,
}

#[derive(Default)]
struct ServiceAcc {
    /// (profile, bucket, template, status) -> stats. bucket: used | viewed_not_used | observed_unclassified | not_usage | other
    paths: BTreeMap<(String, &'static str, String, String), PathStat>,
    cookies: BTreeMap<(String, String, String), ()>,
    downloads: BTreeMap<(String, String, String), u32>,
}

#[derive(Default)]
struct HostAcc {
    profiles: BTreeSet<String>,
    visits: u64,
}

pub fn collect(ctx: &Ctx) -> Output {
    let mut t = Tracker::new("browser");
    let mut services: BTreeMap<String, ServiceAcc> = BTreeMap::new();
    let mut provider_hosts: BTreeMap<String, HostAcc> = BTreeMap::new();

    let tmp = match tempfile::Builder::new().prefix("lightcast-").tempdir() {
        Ok(d) => d,
        Err(_) => {
            t.unreadable("could not create a private temp directory".into());
            return t.finish(Vec::new());
        }
    };

    let mut db_n = 0u32;
    let locs = &ctx.catalog.file.locations.browsers;
    for r in locs.chromium.iter().filter(|r| ctx.os_matches(&r.os)) {
        let browser = r.browser.clone().unwrap_or_else(|| "chromium".into());
        for root in ctx.expand(&r.root) {
            if !root.is_dir() {
                continue;
            }
            for prof in chromium_profiles(&root) {
                if ctx.out_of_time() {
                    t.capped("60-second scan limit reached; remaining browser profiles skipped".into());
                    break;
                }
                let label = format!("{browser}:{}", prof.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
                scan_chromium(ctx, &mut t, tmp.path(), &mut db_n, &prof, &label, &mut services, &mut provider_hosts);
            }
        }
    }
    for r in locs.firefox.iter().filter(|r| ctx.os_matches(&r.os)) {
        for root in ctx.expand(&r.root) {
            let Ok(rd) = fs::read_dir(&root) else { continue };
            let mut profs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.join("places.sqlite").is_file()).collect();
            profs.sort();
            for prof in profs {
                if ctx.out_of_time() {
                    t.capped("60-second scan limit reached; remaining browser profiles skipped".into());
                    break;
                }
                let label = format!("firefox:{}", prof.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
                scan_firefox(ctx, &mut t, tmp.path(), &mut db_n, &prof, &label, &mut services, &mut provider_hosts);
            }
        }
    }

    let findings = build_findings(ctx, services, provider_hosts);
    drop(tmp);
    t.finish(findings)
}

fn chromium_profiles(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.join("History").is_file() {
        out.push(root.to_path_buf());
    }
    if let Ok(rd) = fs::read_dir(root) {
        let mut v: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.join("History").is_file()).collect();
        v.sort();
        out.extend(v);
    }
    out
}

/// Copy a database (and its -wal/-journal) into the temp dir and open the copy.
fn open_copy(ctx: &Ctx, t: &mut Tracker, tmp: &Path, n: &mut u32, src: &Path, label: &str) -> Option<Connection> {
    let meta = match fs::metadata(src) {
        Ok(m) if m.is_file() => m,
        Ok(_) => return None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            t.unreadable(format!("{label} {}: {}", file_name(src), io_reason(&e)));
            return None;
        }
    };
    if meta.len() > ctx.caps.max_db_bytes {
        t.capped(format!("{label} {}: larger than {} MB, skipped", file_name(src), ctx.caps.max_db_bytes / 1_048_576));
        return None;
    }
    *n += 1;
    let dst = tmp.join(format!("db{n}.sqlite"));
    if let Err(e) = fs::copy(src, &dst) {
        let why = copy_failure_reason(&file_name(src), label, e.raw_os_error(), e.kind() == std::io::ErrorKind::PermissionDenied, ctx.os)
            .unwrap_or_else(|| io_reason(&e).to_string());
        t.unreadable(format!("{label} {}: {why}", file_name(src)));
        return None;
    }
    for ext in ["-wal", "-journal"] {
        let side = PathBuf::from(format!("{}{ext}", src.display()));
        if side.is_file() {
            let _ = fs::copy(&side, PathBuf::from(format!("{}{ext}", dst.display())));
        }
    }
    match Connection::open(&dst) {
        Ok(c) => {
            t.sources_read += 1;
            Some(c)
        }
        Err(_) => {
            t.unreadable(format!("{label} {}: not a readable database", file_name(src)));
            None
        }
    }
}

/// Explain a failed database copy. On Windows, error 32/33 is a sharing/lock violation: since 2024
/// Chromium browsers hold their cookie database exclusively while running (an infostealer defence),
/// and Edge keeps running in the background after its windows close. lightcast does not bypass
/// that lock; it says what was skipped and what still counted.
fn copy_failure_reason(file: &str, label: &str, os_error: Option<i32>, denied: bool, os: &str) -> Option<String> {
    let locked = os == "windows" && matches!(os_error, Some(32) | Some(33));
    if !(locked || denied) {
        return None;
    }
    let browser = label.split(':').next().unwrap_or("the browser");
    let is_cookies = file.eq_ignore_ascii_case("cookies");
    Some(match (locked, is_cookies) {
        (true, true) => {
            let edge_hint = if browser == "edge" {
                " Edge also runs in the background after its windows close (Startup boost and background apps); end msedge.exe in Task Manager, or turn both off in Settings > System and performance, to include it."
            } else {
                " Fully quit the browser to include it."
            };
            format!("in use by the running {browser}, which locks its cookie database while running. Sign-in evidence was skipped for this profile; history and downloads were still read.{edge_hint}")
        }
        (true, false) => format!("in use by the running {browser}; this file was skipped. Fully quit the browser to include it."),
        (false, _) => "permission denied; the current user cannot read this file".to_string(),
    })
}

fn file_name(p: &Path) -> String {
    p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Run a query that returns rows of text/integer columns, capped at max_rows.
fn rows<F: FnMut(&rusqlite::Row) -> rusqlite::Result<()>>(
    conn: &Connection,
    sql: &str,
    max_rows: u32,
    t: &mut Tracker,
    label: &str,
    mut f: F,
) {
    let sql = format!("{sql} LIMIT {}", max_rows as u64 + 1);
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return, // table absent in this browser version
    };
    let mut q = match stmt.query([]) {
        Ok(q) => q,
        Err(_) => return,
    };
    let mut n = 0u32;
    while let Ok(Some(row)) = q.next() {
        n += 1;
        if n > max_rows {
            t.capped(format!("{label}: more than {max_rows} rows; the rest were not read"));
            break;
        }
        let _ = f(row);
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_chromium(
    ctx: &Ctx,
    t: &mut Tracker,
    tmp: &Path,
    n: &mut u32,
    prof: &Path,
    label: &str,
    services: &mut BTreeMap<String, ServiceAcc>,
    hosts: &mut BTreeMap<String, HostAcc>,
) {
    if let Some(conn) = open_copy(ctx, t, tmp, n, &prof.join("History"), label) {
        rows(&conn, "SELECT url, visit_count, last_visit_time FROM urls", ctx.caps.max_rows, t, label, |r| {
            let url: String = r.get(0)?;
            let visits: i64 = r.get(1).unwrap_or(0);
            let last: i64 = r.get(2).unwrap_or(0);
            // Chrome time: microseconds since 1601-01-01.
            let day = if last > 0 { Some((last / 1_000_000 - 11_644_473_600) / 86_400) } else { None };
            record_visit(ctx, label, &url, visits, day, services, hosts);
            Ok(())
        });
        rows(&conn, "SELECT url FROM downloads_url_chains", ctx.caps.max_rows, t, label, |r| {
            let url: String = r.get(0)?;
            record_download(ctx, label, &url, services);
            Ok(())
        });
    }
    for cpath in [prof.join("Network").join("Cookies"), prof.join("Cookies")] {
        if !cpath.is_file() {
            continue;
        }
        if let Some(conn) = open_copy(ctx, t, tmp, n, &cpath, label) {
            // The value columns are never selected.
            rows(&conn, "SELECT host_key, name FROM cookies", ctx.caps.max_rows, t, label, |r| {
                let host: String = r.get(0)?;
                let name: String = r.get(1)?;
                record_cookie(ctx, label, &host, &name, services);
                Ok(())
            });
        }
        break;
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_firefox(
    ctx: &Ctx,
    t: &mut Tracker,
    tmp: &Path,
    n: &mut u32,
    prof: &Path,
    label: &str,
    services: &mut BTreeMap<String, ServiceAcc>,
    hosts: &mut BTreeMap<String, HostAcc>,
) {
    if let Some(conn) = open_copy(ctx, t, tmp, n, &prof.join("places.sqlite"), label) {
        rows(&conn, "SELECT url, visit_count, last_visit_date FROM moz_places", ctx.caps.max_rows, t, label, |r| {
            let url: String = r.get(0)?;
            let visits: i64 = r.get(1).unwrap_or(0);
            let last: i64 = r.get(2).unwrap_or(0);
            let day = if last > 0 { Some(last / 1_000_000 / 86_400) } else { None };
            record_visit(ctx, label, &url, visits, day, services, hosts);
            Ok(())
        });
        rows(
            &conn,
            "SELECT p.url FROM moz_annos a JOIN moz_places p ON p.id = a.place_id \
             JOIN moz_anno_attributes t ON t.id = a.anno_attribute_id WHERE t.name = 'downloads/destinationFileURI'",
            ctx.caps.max_rows,
            t,
            label,
            |r| {
                let url: String = r.get(0)?;
                record_download(ctx, label, &url, services);
                Ok(())
            },
        );
    }
    if let Some(conn) = open_copy(ctx, t, tmp, n, &prof.join("cookies.sqlite"), label) {
        rows(&conn, "SELECT host, name FROM moz_cookies", ctx.caps.max_rows, t, label, |r| {
            let host: String = r.get(0)?;
            let name: String = r.get(1)?;
            record_cookie(ctx, label, &host, &name, services);
            Ok(())
        });
    }
}

fn segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

fn template_matches(template: &str, segs: &[&str]) -> bool {
    let tsegs = segments(template);
    if tsegs.len() != segs.len() {
        return false;
    }
    tsegs.iter().zip(segs).all(|(t, s)| (t.starts_with('{') && t.ends_with('}')) || t == s)
}

fn classify<'a>(svc: &'a WebService, segs: &[&str]) -> Option<(&'static str, &'a Template)> {
    let groups: [(&'static str, &Vec<Template>); 4] = [
        ("used", &svc.used),
        ("viewed_not_used", &svc.viewed_not_used),
        ("not_usage", &svc.not_usage),
        ("observed_unclassified", &svc.observed_unclassified),
    ];
    for (bucket, list) in groups {
        for tpl in list {
            if template_matches(&tpl.template, segs) {
                return Some((bucket, tpl));
            }
        }
    }
    None
}

fn record_visit(
    ctx: &Ctx,
    label: &str,
    url: &str,
    visits: i64,
    day: Option<i64>,
    services: &mut BTreeMap<String, ServiceAcc>,
    hosts: &mut BTreeMap<String, HostAcc>,
) {
    let Some(host) = url_host(url) else { return };
    if let Some((svc, _)) = ctx.catalog.web_service_for_host(&host) {
        let path = url_path(url);
        let segs = segments(&path);
        let (bucket, template, status) = match classify(svc, &segs) {
            Some((b, tpl)) => (b, tpl.template.clone(), tpl.status.clone()),
            // Unmatched paths are kept only as a count; their shape could carry user text.
            None => ("other", String::new(), "verified".to_string()),
        };
        let acc = services.entry(svc.service.clone()).or_default();
        let st = acc.paths.entry((label.to_string(), bucket, template, status)).or_default();
        st.urls += 1;
        st.visits += visits.max(0) as u64;
        if let Some(d) = day {
            st.last_day = Some(st.last_day.map_or(d, |x: i64| x.max(d)));
        }
    } else if let Some(ph) = ctx.catalog.provider_host(&host) {
        let acc = hosts.entry(ph.host.clone()).or_default();
        acc.profiles.insert(label.to_string());
        acc.visits += visits.max(0) as u64;
    }
}

fn record_download(ctx: &Ctx, label: &str, url: &str, services: &mut BTreeMap<String, ServiceAcc>) {
    let Some(host) = url_host(url) else { return };
    for svc in &ctx.catalog.file.web_services {
        for d in &svc.data_out_hosts {
            if host == d.name || host.ends_with(&format!(".{}", d.name)) {
                let acc = services.entry(svc.service.clone()).or_default();
                *acc.downloads.entry((label.to_string(), d.name.clone(), d.status.clone())).or_default() += 1;
                return;
            }
        }
    }
}

fn record_cookie(ctx: &Ctx, label: &str, host: &str, name: &str, services: &mut BTreeMap<String, ServiceAcc>) {
    let Some((svc, _)) = ctx.catalog.web_service_for_host(host) else { return };
    if let Some(c) = svc.signed_in_cookies.iter().find(|c| c.name == name) {
        let acc = services.entry(svc.service.clone()).or_default();
        acc.cookies.insert((label.to_string(), c.name.clone(), c.status.clone()), ());
    }
}

fn build_findings(ctx: &Ctx, services: BTreeMap<String, ServiceAcc>, hosts: BTreeMap<String, HostAcc>) -> Vec<Finding> {
    let mut out = Vec::new();
    for svc in &ctx.catalog.file.web_services {
        let Some(acc) = services.get(&svc.service) else { continue };
        let mut ev: Vec<Evidence> = Vec::new();
        let mut profiles: BTreeSet<&str> = BTreeSet::new();
        let mut total_visits = 0u64;
        for ((profile, bucket, template, status), st) in &acc.paths {
            profiles.insert(profile);
            total_visits += st.visits;
            let date = st.last_day.map(super::civil_date);
            let mut detail = vec![format!("{} URLs, {} visits", st.urls, st.visits)];
            if let Some(d) = date {
                detail.push(format!("last {d}"));
            }
            let (grade, rule_id, rule_status) = match *bucket {
                "used" => (Grade::Used, format!("url:{}:{}", svc.service, template), status.clone()),
                "other" => (Grade::Reached, format!("host:{}", svc.hosts.join(",")), "verified".to_string()),
                b => {
                    detail.insert(0, format!("{b}: {template}"));
                    (Grade::Reached, format!("url:{}:{}", svc.service, template), status.clone())
                }
            };
            if *bucket == "used" {
                detail.insert(0, format!("path {template}"));
            }
            ev.push(Evidence {
                rule_id,
                rule_status,
                source_kind: "history".into(),
                location: profile.clone(),
                grade,
                detail,
            });
        }
        for (profile, name, status) in acc.cookies.keys() {
            profiles.insert(profile);
            ev.push(Evidence {
                rule_id: format!("cookie:{}:{}", svc.service, name),
                rule_status: status.clone(),
                source_kind: "cookie".into(),
                location: profile.clone(),
                grade: Grade::SignedIn,
                detail: vec![format!("cookie name {name}")],
            });
        }
        for ((profile, suffix, status), count) in &acc.downloads {
            profiles.insert(profile);
            ev.push(Evidence {
                rule_id: format!("download:{}:{}", svc.service, suffix),
                rule_status: status.clone(),
                source_kind: "download".into(),
                location: profile.clone(),
                grade: Grade::DataOut,
                detail: vec![format!("{count} downloads from *.{suffix}")],
            });
        }
        if ev.is_empty() {
            continue;
        }
        let grade = ev.iter().map(|e| e.grade).max().unwrap_or(Grade::Reached);
        let unverified = ev.iter().filter(|e| e.grade == grade).all(|e| is_unverified(&e.rule_status));
        let mut notes = vec![format!("{} browser profile(s), {} visits", profiles.len(), total_visits)];
        if !svc.history_reliable_for_usage && grade < Grade::Used {
            notes.push("usage is not visible from browser history for this service; absence of 'used' is not evidence of non-use".into());
        }
        out.push(Finding {
            id: String::new(),
            kind: Kind::WebService,
            subject: Subject { name: svc.service.clone(), provider: Some(svc.provider.clone()), ..Default::default() },
            grade,
            confidence: Confidence::High,
            capabilities: vec![],
            capability_basis: vec![],
            evidence: ev,
            unverified,
            notes,
            redactions: 0,
            upstreams: svc
                .hosts
                .iter()
                .find_map(|h| ctx.catalog.provider_for_host(h))
                .map(|p| vec![crate::upstream::for_provider(p, format!("visited in the browser (strongest evidence: {})", grade.label()), Confidence::High)])
                .unwrap_or_default(),
            via_agent: None,
        });
    }
    for (host, acc) in hosts {
        let Some(ph) = ctx.catalog.provider_host(&host) else { continue };
        out.push(Finding {
            id: String::new(),
            kind: Kind::WebService,
            subject: Subject { name: ph.service.clone(), provider: Some(ph.provider.clone()), ..Default::default() },
            grade: Grade::Reached,
            confidence: Confidence::Medium,
            capabilities: vec![],
            capability_basis: vec![],
            evidence: acc
                .profiles
                .iter()
                .map(|p| Evidence {
                    rule_id: ph.id.clone(),
                    rule_status: ph.status.clone(),
                    source_kind: "history".into(),
                    location: p.clone(),
                    grade: Grade::Reached,
                    detail: vec![format!("host {host} ({})", ph.category)],
                })
                .collect(),
            unverified: is_unverified(&ph.status),
            notes: vec![format!("{} visits", acc.visits)],
            redactions: 0,
            upstreams: ctx
                .catalog
                .provider_for_host(&host)
                .map(|p| vec![crate::upstream::for_provider(p, format!("{host} visited in the browser"), Confidence::Medium)])
                .unwrap_or_default(),
            via_agent: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_windows_cookies_are_explained_not_bypassed() {
        let m = copy_failure_reason("Cookies", "edge:Default", Some(32), false, "windows").unwrap();
        assert!(m.contains("history and downloads were still read") && m.contains("msedge.exe"), "{m}");
        let c = copy_failure_reason("Cookies", "chrome:Default", Some(33), false, "windows").unwrap();
        assert!(c.contains("running chrome") && !c.contains("msedge"), "{c}");
        assert!(copy_failure_reason("History", "chrome:Default", Some(32), false, "windows").unwrap().contains("this file was skipped"));
        // On Linux error 32 is EPIPE, not a lock: fall back to the generic reason.
        assert!(copy_failure_reason("Cookies", "chrome:Default", Some(32), false, "linux").is_none());
        assert!(copy_failure_reason("Cookies", "chrome:Default", None, true, "linux").unwrap().contains("permission denied"));
    }

    #[test]
    fn templates() {
        assert!(template_matches("/c/{id}", &["c", "abc123"]));
        assert!(!template_matches("/c/{id}", &["c"]));
        assert!(!template_matches("/c/{id}", &["g", "abc"]));
        assert!(template_matches("/new", &["new"]));
    }
}
