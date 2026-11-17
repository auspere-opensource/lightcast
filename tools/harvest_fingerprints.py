#!/usr/bin/env python3
"""Harvest local-install fingerprints for AI tooling listed in aitools.json.

aitools.json only nominates candidate repositories, using each entry's own tags
and topics.  The fingerprints come from the repositories themselves: package
manifests, MCP registry metadata, Claude plugin manifests, browser-extension
manifests and agent skills.  Only those files are read, through batched GitHub
GraphQL queries made with the authenticated `gh` CLI.

Output: catalog/vendor/fingerprints.generated.json.  The source files are never modified.

Run bounded, from the repo root:
  python3 -I tools/harvest_fingerprints.py
"""

from __future__ import annotations

import base64
import collections
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import time
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "aitools.json"
OUT = ROOT / "catalog" / "vendor" / "fingerprints.generated.json"
BATCH = 20

# Keep the embedded catalog deliberately small: one useful, high-confidence
# fingerprint from each of ten distinct MIT-licensed repositories.
INCLUDED_FINGERPRINTS = {
    ("apify/apify-mcp-server", "npm_package", "@apify/actors-mcp-server"),
    ("bytebase/dbhub", "mcp_registry_name", "io.github.bytebase/dbhub"),
    ("CursorTouch/Windows-MCP", "mcp_registry_name", "io.github.CursorTouch/Windows-MCP"),
    ("lackeyjb/playwright-skill", "agent_skill", "playwright-skill"),
    ("microsoft/poml", "vscode_extension", "poml-team.poml"),
    ("nidhinjs/prompt-master", "agent_skill", "prompt-master"),
    ("nyldn/claude-octopus", "npm_package", "@anthropic-plugins/claude-octopus"),
    ("open-webui/mcpo", "pypi_package", "mcpo"),
    ("openclaw/mcporter", "npm_package", "mcporter"),
    ("sooperset/mcp-atlassian", "pypi_package", "mcp-atlassian"),
}
INCLUDED_REPOS = {repo.lower() for repo, _, _ in INCLUDED_FINGERPRINTS}

# Candidate selection: an exact match on one of the entry's own tags or topics.
GROUPS = {
    "mcp": re.compile(r"^(mcp|mcp-server|mcp-servers|mcp-client|model-context-protocol|modelcontextprotocol)$"),
    "skill_plugin": re.compile(r"^(claude-skills?|agent-skills?|anthropic-skills|claude-code-plugins?|claude-plugins?)$"),
    "vscode": re.compile(r"^(vscode-extension|vscode-extensions)$"),
    "browser": re.compile(r"^(chrome-extension|browser-extension|firefox-extension|edge-extension)$"),
}
# Groups whose tag alone does not imply AI; they also need AI evidence.
NEEDS_AI_EVIDENCE = {"vscode", "browser"}
AI_RX = re.compile(
    r"\b(ai|llms?|gpt(-?\d)?|chatgpt|openai|claude|anthropic|gemini|copilot|mcp|agents?|ollama|langchain|"
    r"model[- ]context[- ]protocol|large[- ]language[- ]models?|genai|generative[- ]ai|deepseek|mistral)\b",
    re.I,
)
GENERIC = {
    "server", "cli", "app", "main", "mcp", "index", "test", "agent", "start", "dev", "run", "tool", "tools",
    "client", "api", "core", "bot", "chat", "extension", "plugin", "plugins", "skills", "skill", "demo", "example",
}

QUERY_REPO = """
  r%(i)d: repository(owner: %(owner)s, name: %(name)s) {
    nameWithOwner isArchived stargazerCount description
    licenseInfo { spdxId }
    repositoryTopics(first: 20) { nodes { topic { name } } }
    pkg: object(expression: "HEAD:package.json") { ...B }
    py: object(expression: "HEAD:pyproject.toml") { ...B }
    man: object(expression: "HEAD:manifest.json") { ...B }
    srcman: object(expression: "HEAD:src/manifest.json") { ...B }
    pubman: object(expression: "HEAD:public/manifest.json") { ...B }
    srv: object(expression: "HEAD:server.json") { ...B }
    cplug: object(expression: "HEAD:.claude-plugin/plugin.json") { ...B }
    cmkt: object(expression: "HEAD:.claude-plugin/marketplace.json") { ...B }
    rootskill: object(expression: "HEAD:SKILL.md") { ...B }
    skills: object(expression: "HEAD:skills") { ... on Tree { entries { name type object { ... on Tree { entries { name oid } } } } } }
    plugins: object(expression: "HEAD:plugins") { ... on Tree { entries { name type } } }
  }"""
FRAGMENT = "fragment B on Blob { oid text isTruncated }"


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def terms(entry):
    meta = entry.get("metadata") or {}
    return {t.lower() for t in (entry.get("tags") or [])} | {t.lower() for t in (meta.get("topics") or [])}


def repo_of(url):
    m = re.match(r"https?://github\.com/([^/\s]+)/([^/\s#?]+)", url or "")
    if not m:
        return None
    return m.group(1), re.sub(r"\.git$", "", m.group(2))


def select_candidates():
    data = json.loads(SRC.read_text())
    cands = {}
    for e in data:
        t = terms(e)
        groups = [g for g, rx in GROUPS.items() if any(rx.match(x) for x in t)]
        if not groups:
            continue
        rp = repo_of(e.get("endpoint_url"))
        if not rp:
            continue
        key = f"{rp[0]}/{rp[1]}".lower()
        c = cands.setdefault(key, {"owner": rp[0], "name": rp[1], "groups": set(), "entry_text": ""})
        c["groups"].update(groups)
        c["entry_text"] += " ".join([e.get("name") or "", e.get("description") or "", " ".join(t)]) + " "
    return [candidate for key, candidate in cands.items() if key in INCLUDED_REPOS]


def gql(query):
    p = subprocess.run(["gh", "api", "graphql", "-f", f"query={query}"], capture_output=True, text=True, timeout=180)
    try:
        body = json.loads(p.stdout) if p.stdout.strip() else {}
    except json.JSONDecodeError:
        body = {}
    if "data" not in body:
        raise RuntimeError((p.stderr or p.stdout)[:300])
    errs = [e for e in body.get("errors", []) if e.get("type") not in ("NOT_FOUND",)]
    return body["data"] or {}, errs, sum(1 for e in body.get("errors", []) if e.get("type") == "NOT_FOUND")


def fetch(batch, stats):
    q = "query {" + "".join(
        QUERY_REPO % {"i": i, "owner": json.dumps(c["owner"]), "name": json.dumps(c["name"])} for i, c in enumerate(batch)
    ) + "}\n" + FRAGMENT
    for attempt in range(3):
        try:
            data, errs, nf = gql(q)
            stats["not_found"] += nf
            if errs:
                stats["other_errors"] += len(errs)
                log("  graphql errors:", [e.get("message", "")[:120] for e in errs[:3]])
            return [(c, data.get(f"r{i}")) for i, c in enumerate(batch)]
        except Exception as ex:  # transient or response too large
            log(f"  batch of {len(batch)} failed (attempt {attempt + 1}): {str(ex)[:160]}")
            if len(batch) > 1:
                mid = len(batch) // 2
                return fetch(batch[:mid], stats) + fetch(batch[mid:], stats)
            time.sleep(5 * (attempt + 1))
    stats["failed_repos"] += len(batch)
    return [(c, None) for c in batch]


def blob(r, k):
    o = r.get(k)
    return o if o and o.get("text") is not None else None


def jload(b):
    try:
        return json.loads(b["text"])
    except Exception:
        return None


def frontmatter_name(text):
    m = re.match(r"^---\s*\n(.*?)\n---", text or "", re.S)
    if m:
        n = re.search(r"^name:\s*['\"]?([^'\"\n]+?)['\"]?\s*$", m.group(1), re.M)
        if n:
            return n.group(1).strip()
    return None


def chrome_id_from_key(key):
    try:
        der = base64.b64decode(key)
    except Exception:
        return None
    h = hashlib.sha256(der).hexdigest()[:32]
    return "".join(chr(ord("a") + int(ch, 16)) for ch in h)


def conf_for_name(name, base):
    n = (name or "").lower().split("/")[-1]
    if n in GENERIC or len(n) < 4:
        return "low"
    return base


def extract(c, r):
    rows = []
    repo = r["nameWithOwner"]
    topics = [n["topic"]["name"] for n in (r.get("repositoryTopics") or {}).get("nodes", [])]
    ai_text = " ".join([c["entry_text"], r.get("description") or "", " ".join(topics)])

    def add(kind, ident, where, conf, **extra):
        if not ident or not isinstance(ident, str):
            return
        rows.append({"type": kind, "identifier": ident.strip(), "where_found_locally": where, "confidence": conf, **extra})

    pkg = jload(blob(r, "pkg")) if blob(r, "pkg") else None
    if isinstance(pkg, dict):
        name = pkg.get("name")
        kw = " ".join(pkg.get("keywords") or []) if isinstance(pkg.get("keywords"), list) else ""
        ai_text += " " + (pkg.get("description") or "") + " " + kw
        engines = pkg.get("engines") if isinstance(pkg.get("engines"), dict) else {}
        if engines.get("vscode") and pkg.get("publisher") and name:
            add("vscode_extension", f"{pkg['publisher']}.{name}".lower(),
                "~/.vscode/extensions/<publisher>.<name>-<version> (also Cursor/Windsurf extension dirs)", "high")
        elif name and not pkg.get("private"):
            add("npm_package", name, "MCP config args (npx/bunx), global node_modules, lockfiles",
                conf_for_name(name, "high" if (name.startswith("@") or "mcp" in name.lower()) else "medium"))
        b = pkg.get("bin")
        cmds = [b and name and name.split("/")[-1]] if isinstance(b, str) else list(b) if isinstance(b, dict) else []
        for cmd in filter(None, cmds):
            add("cli_command", cmd, "MCP config 'command', PATH executables, shell history", conf_for_name(cmd, "medium"))

    pyb = blob(r, "py")
    if pyb:
        try:
            py = tomllib.loads(pyb["text"])
        except Exception:
            py = {}
        proj = py.get("project") or {}
        poetry = (py.get("tool") or {}).get("poetry") or {}
        pname = proj.get("name") or poetry.get("name")
        ai_text += " " + (proj.get("description") or poetry.get("description") or "")
        if pname:
            add("pypi_package", pname, "MCP config args (uvx/pipx), site-packages dist-info",
                conf_for_name(pname, "high" if "mcp" in pname.lower() else "medium"))
        for cmd in list((proj.get("scripts") or {})) + list((poetry.get("scripts") or {})):
            add("cli_command", cmd, "MCP config 'command', PATH executables, shell history", conf_for_name(cmd, "medium"))

    for k in ("man", "srcman", "pubman"):
        mb = blob(r, k)
        m = jload(mb) if mb else None
        if isinstance(m, dict) and "manifest_version" in m:
            nm = m.get("name")
            if isinstance(nm, str) and not nm.startswith("__MSG_"):
                add("browser_extension_name", nm, "browser profile Extensions/<id>/<ver>/manifest.json 'name'", "low")
            if isinstance(m.get("key"), str):
                eid = chrome_id_from_key(m["key"])
                add("browser_extension_id", eid, "browser profile Extensions/<id> directory", "high")
            break

    srv = jload(blob(r, "srv")) if blob(r, "srv") else None
    if isinstance(srv, dict):
        add("mcp_registry_name", srv.get("name"), "MCP registry / client config server name", "high")
        for p in srv.get("packages") or []:
            if not isinstance(p, dict):
                continue
            reg = (p.get("registryType") or p.get("registry_name") or p.get("registry_type") or "").lower()
            ident = p.get("identifier") or p.get("name")
            kind = {"npm": "npm_package", "pypi": "pypi_package", "oci": "oci_image", "docker": "oci_image"}.get(reg, "package")
            add(kind, ident, "MCP config args / container image", "high")

    for k, kind in (("cplug", "claude_plugin"), ("cmkt", "claude_plugin_marketplace")):
        d = jload(blob(r, k)) if blob(r, k) else None
        if isinstance(d, dict):
            add(kind, d.get("name"), "~/.claude/plugins (installed plugins / known marketplaces)", conf_for_name(d.get("name"), "medium"))
            if kind == "claude_plugin_marketplace":
                for p in d.get("plugins") or []:
                    if isinstance(p, dict):
                        add("claude_plugin", p.get("name"), "~/.claude/plugins (installed plugins)", conf_for_name(p.get("name"), "medium"))

    rs = blob(r, "rootskill")
    if rs:
        nm = frontmatter_name(rs["text"]) or c["name"]
        add("agent_skill", nm, "~/.claude/skills/<name>/SKILL.md, .claude/skills, .agents/skills", "high",
            skill_md_blob_oid=rs["oid"], match_rule="high when local SKILL.md git-blob SHA-1 equals skill_md_blob_oid; low on name only")

    sk = r.get("skills")
    for e in (sk or {}).get("entries", []) if isinstance(sk, dict) else []:
        if e.get("type") != "tree":
            continue
        sub = {x["name"]: x["oid"] for x in ((e.get("object") or {}).get("entries") or [])}
        if "SKILL.md" in sub:
            add("agent_skill", e["name"], "~/.claude/skills/<name>/SKILL.md, .claude/skills, .agents/skills", "high",
                skill_md_blob_oid=sub["SKILL.md"], match_rule="high when local SKILL.md git-blob SHA-1 equals skill_md_blob_oid; low on name only")

    pl = r.get("plugins")
    for e in (pl or {}).get("entries", []) if isinstance(pl, dict) else []:
        if e.get("type") == "tree":
            add("claude_plugin", e["name"], "~/.claude/plugins (installed plugins)", "low")

    ai = bool(AI_RX.search(ai_text))
    meta = {
        "source_repo": repo,
        "repo_license": ((r.get("licenseInfo") or {}).get("spdxId")),
        "repo_stars": r.get("stargazerCount"),
        "repo_archived": r.get("isArchived"),
        "candidate_groups": sorted(c["groups"]),
        "ai_evidence": ai,
    }
    return [{**row, **meta} for row in rows], ai


def main():
    t0 = time.time()
    cands = select_candidates()
    log(f"candidates: {len(cands)} repos  by group: "
        f"{dict(collections.Counter(g for c in cands for g in c['groups']))}")
    stats = collections.Counter()
    rows, repos_with_rows, skipped_non_ai = [], 0, 0
    for i in range(0, len(cands), BATCH):
        for c, r in fetch(cands[i:i + BATCH], stats):
            if not r:
                continue
            stats["repos_fetched"] += 1
            got, ai = extract(c, r)
            if c["groups"] <= NEEDS_AI_EVIDENCE and not ai:
                skipped_non_ai += 1
                continue
            if got:
                repos_with_rows += 1
            rows.extend(got)
        log(f"  {min(i + BATCH, len(cands))}/{len(cands)} repos, rows so far {len(rows)}")

    # A fingerprint shared by several repos is ambiguous: keep it once, list every repo, and downgrade it.
    by_key = collections.OrderedDict()
    for row in rows:
        key = (row["type"], row["identifier"].lower(), row.get("skill_md_blob_oid"))
        if key in by_key:
            by_key[key]["also_in_repos"].append(row["source_repo"])
        else:
            by_key[key] = {**row, "also_in_repos": []}
    final = []
    for row in by_key.values():
        if (row["source_repo"], row["type"], row["identifier"]) not in INCLUDED_FINGERPRINTS:
            continue
        if row["also_in_repos"] and not row.get("skill_md_blob_oid"):
            row["confidence"] = "low" if row["confidence"] != "high" else "medium"
            row["collision"] = True
        final.append(row)

    selected = {(row["source_repo"], row["type"], row["identifier"]) for row in final}
    missing = INCLUDED_FINGERPRINTS - selected
    if missing:
        raise RuntimeError(f"curated fingerprints missing upstream: {sorted(missing)}")

    out = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "generator": "tools/harvest_fingerprints.py",
        "source": "Candidate repos from aitools.json (entry tags/topics); identifiers read from each repo's own manifests via GitHub GraphQL at HEAD.",
        "notes": [
            "A fingerprint identifies installed or configured tooling; it does not prove use.",
            "vscode/browser candidates are kept only with AI evidence in name, description, tags, topics or manifest keywords.",
            "agent_skill rows are high confidence only when the local SKILL.md git-blob SHA-1 matches skill_md_blob_oid.",
            "Identifiers shared by several repos are marked collision=true and downgraded.",
        ],
        "stats": {
            "candidate_repos": len(cands),
            "repos_fetched": stats["repos_fetched"],
            "repos_not_found": stats["not_found"],
            "repos_failed": stats["failed_repos"],
            "graphql_other_errors": stats["other_errors"],
            "skipped_no_ai_evidence": skipped_non_ai,
            "repos_with_fingerprints": repos_with_rows,
            "fingerprints": len(final),
            "by_type": dict(collections.Counter(r["type"] for r in final)),
            "by_confidence": dict(collections.Counter(r["confidence"] for r in final)),
            "seconds": round(time.time() - t0, 1),
        },
        "fingerprints": final,
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    log(json.dumps(out["stats"], indent=1))


if __name__ == "__main__":
    main()
