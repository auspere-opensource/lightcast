# Privacy contract

`lightcast` reads names, shapes and counts. It never reads content or secret values into its
report, and it makes no network calls. This file is the contract; `tests/privacy_and_findings.rs`
enforces it on every change.

## What is read, and what never leaves the scan

| Source | Kept in the report | Never read, stored or printed |
| --- | --- | --- |
| Browser history | Host; which catalogued path template matched (e.g. `/c/{id}`); URL and visit counts; last-visit date | Full URLs, IDs, slugs, query strings, fragments, page titles, unmatched path text |
| Browser cookies | Cookie **names** on catalogued AI hosts | Cookie values (the value columns are never selected) |
| Browser downloads | Count per catalogued AI file host | File names, paths, referrers |
| MCP client configs | Server name, command basename, launcher package name and whether it is pinned, transport, remote **host**, env-var and header **names**; for env vars whose name marks an endpoint (`*_BASE_URL`, `*_API_BASE`, `*_API_URL`, `*_ENDPOINT`, `*_HOST`), the **host** of the value | Argument values, other env-var values, header values, URL paths and query strings |
| Agent settings | Whether specific settings allow unattended commands or edits; counts of pre-approved rules; whether routing flags (`CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_VERTEX`) are true; the **host** of a base-URL override; Codex `model_provider` id; a cloud **region code** from `AWS_REGION`, `AWS_DEFAULT_REGION` or `CLOUD_ML_REGION` (kept only when it is a known region code) | The text of permission rules; other env values |
| AI configuration and memory | Known config, instruction, rule and memory file names and paths | File contents |
| Installed MCP packages (npx cache, global npm, uv/pipx environments) | Names of installed dependencies; which catalogued AI provider hostnames appear in the launched package's own code | Everything else in those files; nothing outside the launched package |
| Skills and plugins | Directory name, git-blob SHA-1 of `SKILL.md`, count of script files | Any file content |
| IDE extensions | Extension id and version from the directory name | Anything inside the extension |
| PATH and package dirs | Executable and package **names** | Anything else |
| Env and dotfiles | Whether a known AI key **name** is assigned a non-empty value, and in which file | The value, any part of it, or its length |

Region-code variables in MCP server env (`AWS_REGION`, `AWS_DEFAULT_REGION`, `CLOUD_ML_REGION`,
`GOOGLE_CLOUD_LOCATION`, `GOOGLE_CLOUD_REGION`, `VERTEX_LOCATION`) are read only to match them
against the catalogued AWS and Google Cloud region codes; a value that is not a known code is
discarded and never stored.

Upstream providers and countries are worked out offline. Hostnames are **never resolved**: that
would be a network call. A provider's country is its headquarters from the catalog (marked
unverified; processing regions may differ). Only an endpoint written as an IP address is
geolocated, using the embedded DB-IP Lite database.

Paths are shown relative to `~`, so your username does not appear. The hostname is stored only as a
SHA-256 hash unless you pass `--show-hostname`.

## Operating rules

1. **Read-only.** Browser databases are copied into a private temporary directory and the copy is
   queried. The temporary directory is deleted when the scan ends. Originals are never opened.
2. **No network by default.** CI runs a real scan under `strace` and fails on any `socket`,
   `connect` or `sendto` call. The one exception is opt-in: `--resolve` (below).
3. **No elevation, no bypassing locks.** Files the current user cannot read are reported as
   `unreadable` and skipped. On Windows, Chrome and Edge lock their cookie database while running
   (Edge also keeps running in the background); lightcast reports that sign-in evidence was skipped
   and never works around the lock with shadow copies, backup privileges or similar.
4. **Bounded.** Config files over 4 MB and databases over 512 MB are skipped; at most 2,000,000 rows
   per table and 50,000 directory entries or expanded location matches per collector are read; the scan stops at 60 seconds.
   A capped collector reports `partial` and says what it skipped.
5. **Outputs go only where you point them.** The default is the terminal.
6. **`--paranoid`** also drops dates, browser profile names, project paths, uncatalogued remote
   MCP hosts and uncatalogued upstream hosts (with their IP geolocation detail), for reports you
   will share outside your team. Catalogued provider names and countries stay.
7. **Withheld values are counted.** Structured and HTML reports record how many argument, env and
   header values were parsed and dropped. The terminal summary omits this count.

## `--resolve` (opt-in network use)

Without `--resolve`, a destination host that is not a catalogued provider has country "unknown".
With it, the tool asks the operating system's DNS resolver for the addresses of those hosts, and
only those, then geolocates the answers with the embedded DB-IP database.

- **Scope:** destination hosts from MCP configs, endpoint overrides and agent base URLs whose
  country is unknown. Browser history hosts and catalogued provider hosts are never looked up.
- **What leaves the machine:** the hostnames, sent to whichever DNS resolver the system is
  configured to use (and onward through normal DNS). Nothing else.
- **Limits:** at most 32 hosts, 3 seconds per lookup; unanswered hosts stay "unknown".
- **Disclosure:** the report records `network.dns_lookups`, and the terminal and HTML outputs say
  how many lookups were made.
- **Accuracy:** a CDN or anycast address geolocates to an edge, not to the operator. The report
  says so beside every resolved country.

## How the tests check this

The integration test builds a fake home directory and plants the string `CANARY` in every value the
table above says is never kept: cookie values, encrypted cookie blobs, URL IDs, slugs, query strings,
fragments, page titles, download file names, MCP argument, env and header values, permission-rule
text, settings env values, endpoint-URL paths and query strings, installed package code, skill
file content, dotfile key values and process env values. Hosts and project paths that the contract
allows in a normal report are planted as `SITEONLY` and must not appear in a paranoid one. It then
renders the JSON, terminal (plain and verbose), HTML and share-card outputs, in normal and paranoid
mode, and fails if `CANARY` or the absolute home path appears anywhere.

Report a suspected violation as a security issue, not a public bug.
