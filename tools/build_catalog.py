#!/usr/bin/env python3
"""Compile catalog/vendor/* and catalog/src/*.yaml into catalog/catalog.json.

The binary embeds catalog.json at build time; it never fetches a catalog during a scan.

Run bounded from the repo root:
  python3 -I tools/build_catalog.py
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
VENDOR = ROOT / "catalog" / "vendor"
SRC = ROOT / "catalog" / "src"
OUT = ROOT / "catalog" / "catalog.json"
VERSION = "2026.11.1"

STATUSES = {"verified", "observed_unclassified", "not_observed", "unverified", "fixture_only", "measured_present"}
CAPS = {"shell_exec", "credential_reach", "fs_write", "remote_unknown", "unpinned_code", "network_egress", "fs_read"}
FP_TYPES = {
    "agent_skill", "claude_plugin", "claude_plugin_marketplace", "cli_command", "npm_package",
    "pypi_package", "mcp_registry_name", "vscode_extension", "browser_extension_name",
    "browser_extension_id", "oci_image", "package",
}


def load_yaml(p: pathlib.Path):
    with p.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def fail(msg: str) -> None:
    print(f"build_catalog: {msg}", file=sys.stderr)
    sys.exit(1)


def services(url_rules) -> list[dict]:
    out = []
    for s in url_rules["services"]:
        def templates(key):
            rows = []
            for r in s.get(key) or []:
                st = r.get("status", "observed_unclassified" if key == "observed_unclassified" else "unverified")
                if st not in STATUSES:
                    fail(f"{s['service']}: bad status {st}")
                for t in str(r["template"]).split(","):
                    t = t.strip()
                    if t:
                        rows.append({"template": t, "meaning": r.get("meaning") or r.get("note", ""), "status": st})
            return rows

        out.append({
            "service": s["service"],
            "provider": s["provider"],
            "hosts": s["hosts"],
            "history_reliable_for_usage": s.get("history_reliable_for_usage", True),
            "used": templates("used"),
            "viewed_not_used": templates("viewed_not_used"),
            "observed_unclassified": templates("observed_unclassified"),
            "not_usage": templates("not_usage"),
            "signed_in_cookies": [
                {"name": c["name"], "status": c.get("status", "unverified")}
                for c in (s.get("signed_in_cookies") or [])
            ],
            "data_out_hosts": [
                {"suffix": d["suffix"], "status": d.get("status", "unverified")}
                for d in (s.get("data_out_hosts") or [])
            ],
        })
    return out


def hosts() -> list[dict]:
    rows, seen = [], set()
    for f in ("providers.yaml", "providers.expanded.addon.yaml"):
        for r in load_yaml(VENDOR / f)["rules"]:
            m = r["match"]
            if m["type"] != "exact_hostname":
                continue  # port hints are network-only evidence; not used by a local scan
            h = m["value"].lower()
            if h in seen:
                continue
            seen.add(h)
            rows.append({"id": r["id"], "host": h, "provider": r["provider"], "service": r["service"],
                         "category": r["category"], "status": "unverified"})
    return rows


def fingerprints() -> tuple[list[dict], dict]:
    data = json.loads((VENDOR / "fingerprints.generated.json").read_text(encoding="utf-8"))
    rows = []
    for f in data["fingerprints"]:
        t = f["type"]
        if t not in FP_TYPES:
            fail(f"unknown fingerprint type {t}")
        row = {
            "type": t,
            "id": f["identifier"],
            "confidence": f["confidence"],
            "repo": f["source_repo"],
            "license": f.get("repo_license"),
        }
        if f.get("skill_md_blob_oid"):
            row["blob"] = f["skill_md_blob_oid"]
        if f.get("collision"):
            row["collision"] = True
        rows.append(row)
    return rows, {"generated_at": data.get("generated_at"), "source": data.get("source"), "stats": data.get("stats", {})}


def check_tools(tools) -> None:
    for p in tools["credential_name_patterns"]:
        re.compile(p)
    for r in tools["mcp_packages"]:
        bad = set(r["capabilities"]) - CAPS
        if bad:
            fail(f"mcp_packages {r['package']}: unknown capabilities {bad}")
    for key in ("ai_cli", "ide_extensions", "mcp_packages", "mcp_remote_hosts"):
        for r in tools[key]:
            if r["status"] not in STATUSES:
                fail(f"{key}: bad status {r['status']}")


def check_upstream(up, tools) -> None:
    ids = [p["id"] for p in up["providers"]]
    if len(ids) != len(set(ids)):
        fail("duplicate provider ids")
    for p in up["providers"]:
        if p["status"] not in STATUSES:
            fail(f"provider {p['id']}: bad status")
        if not (re.fullmatch(r"[A-Z]{2}", p["hq_country"]) or p["hq_country"] == "LOCAL"):
            fail(f"provider {p['id']}: hq_country must be ISO alpha-2 or LOCAL")
        for k in ("api_hosts", "npm", "pypi", "env_keys", "base_url_env"):
            if not isinstance(p.get(k), list):
                fail(f"provider {p['id']}: {k} must be a list")
    known = set(ids) | {"unknown"}
    for a in up["agent_defaults"]:
        if a["provider"] not in known:
            fail(f"agent {a['agent']}: unknown provider {a['provider']}")
    for r in up["claude_code_routes"]:
        if r["provider"] not in known:
            fail(f"route {r['env']}: unknown provider")
    re.compile(up["endpoint_env_pattern"])
    for r in tools["ide_extensions"]:
        if r.get("upstream") and r["upstream"] not in known:
            fail(f"ide {r['id']}: unknown upstream {r['upstream']}")
    for r in tools["mcp_packages"]:
        for u in r.get("upstreams", []):
            if u not in known:
                fail(f"mcp_package {r['package']}: unknown upstream {u}")


def merge_sources(up) -> None:
    """Attach cited evidence (catalog/src/provider_sources.json) to each provider row.

    A row's status becomes the source's status; a country that disagrees with its source fails the build.
    """
    path = SRC / "provider_sources.json"
    if not path.exists():
        return  # rows keep their authored status (unverified)
    src = json.loads(path.read_text(encoding="utf-8"))
    by_id = {r["id"]: r for r in src["providers"]}
    for p in up["providers"]:
        r = by_id.get(p["id"])
        if not r:
            continue  # stays as authored (e.g. status unverified)
        if r["hq_country"] != p["hq_country"]:
            fail(f"provider {p['id']}: providers.yaml says {p['hq_country']}, cited source says {r['hq_country']}")
        if r["status"] not in STATUSES or r["source_kind"] not in ("primary", "secondary"):
            fail(f"provider_sources {p['id']}: bad status or source_kind")
        for c in r["processing_countries"] + [e["country"] for e in r["regional_entities"]]:
            if not re.fullmatch(r"[A-Z]{2}", c):
                fail(f"provider_sources {p['id']}: bad country {c}")
        p["status"] = r["status"]
        p["source"] = {k: r[k] for k in ("source_kind", "source_url", "source_quote", "regional_entities", "processing_countries", "processing_note")}


def main() -> None:
    url_rules = load_yaml(VENDOR / "url_usage_rules.seed.yaml")
    tools = load_yaml(SRC / "tools.yaml")
    locations = load_yaml(SRC / "locations.yaml")
    check_tools(tools)
    upstream = load_yaml(SRC / "providers.yaml")
    check_upstream(upstream, tools)
    merge_sources(upstream)
    regions = json.loads((SRC / "cloud_regions.json").read_text(encoding="utf-8"))
    for cloud in ("aws", "gcp"):
        codes = [r["code"] for r in regions[cloud]["regions"]]
        if len(codes) != len(set(codes)):
            fail(f"cloud_regions: duplicate {cloud} code")
        for r in regions[cloud]["regions"]:
            if r["country"] is not None and not re.fullmatch(r"[A-Z]{2}", r["country"]):
                fail(f"cloud_regions: bad country for {r['code']}")
    for p in upstream["providers"]:
        if p.get("regional_hosts"):
            if p.get("cloud") not in ("aws", "gcp"):
                fail(f"provider {p['id']}: regional_hosts need cloud aws|gcp")
            for t in p["regional_hosts"]:
                if t.count("{region}") != 1:
                    fail(f"provider {p['id']}: template {t} needs exactly one {{region}}")
    fps, fp_meta = fingerprints()
    catalog = {
        "schema": "lightcast.catalog/v1",
        "version": VERSION,
        "web_services": services(url_rules),
        "provider_hosts": hosts(),
        "fingerprints": fps,
        "fingerprints_meta": fp_meta,
        "tools": tools,
        "locations": locations,
        "upstream": upstream,
        "cloud_regions": regions,
    }
    body = json.dumps(catalog, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    catalog["sha256"] = hashlib.sha256(body.encode()).hexdigest()
    OUT.write_text(json.dumps(catalog, sort_keys=True, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(catalog['web_services'])} web services, "
          f"{len(catalog['provider_hosts'])} provider hosts, {len(fps)} fingerprints, {OUT.stat().st_size} bytes")


if __name__ == "__main__":
    main()
