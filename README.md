# LightCast

See every AI service, agent, MCP server, skill, extension and API key on your machine in seconds,
with the evidence for each, and find out which of them can act as you.

```
$ lightcast
LightCast
this machine · macos · 2026-11-08T14:02:11Z · catalog 2026.11.1
────────────────────────────────────────────────────────────────────────
MCP server "shellbox" can act as you: it can run shell commands and is handed credentials.

AI web services (4)
   ChatGPT                            data_out    high
   Claude                             signed_in   high
      · usage is not visible from browser history for this service; …
MCP servers (5)
   shellbox [cursor (user)]           configured  low     can run shell commands
      · command is a shell (bash)
      · env names passed in: GITHUB_TOKEN
   files [cursor (user)]              configured  medium  can write files
      · filesystem roots: entire home directory
...
```

- **Local and read-only.** No account, no telemetry, no network calls. See [PRIVACY.md](PRIVACY.md).
- **Evidence over claims.** Every finding has a grade (`installed`, `configured`, `reached`,
  `signed_in`, `used`, `data_out`), a confidence, and the rule and file it came from. Rules that
  have not been confirmed on a real machine are marked with `*`.
- **Where data goes.** Each MCP server, agent and extension is traced to the AI providers it can
  send data to: from the credentials it is handed, endpoint overrides, the SDKs in its installed
  dependency tree, provider hostnames in its code, and the agent it launches (an MCP server that
  runs Codex inherits Codex's provider). Each destination carries a country.
- **Blast radius first.** Agents and MCP servers are classed by what their config shows they can do:
  `shell_exec`, `credential_reach`, `fs_write`, `remote_unknown`, `unpinned_code`, `network_egress`.

## Install and run

Release builds are not yet code-signed for macOS or Windows, which both need a manual step before the
first run. Each archive carries a plain-text `INSTALL.txt` for its platform, and the release folder
has `INSTALL-windows.txt`, `INSTALL-macos.txt` and `INSTALL-linux.txt` to read before unpacking
(sources in [`packaging/`](packaging/)).

```sh
cargo install --path .        # from a checkout; release binaries are coming
lightcast                   # terminal report
lightcast --html report.html --json report.json --card card.svg
lightcast --project ~/src/my-repo    # also scan a repo's .mcp.json, .cursor/, .vscode/, .claude/
lightcast --paranoid --html share.html   # for reports leaving your team
```

| Option | Does |
| --- | --- |
| `--json FILE` / `--json -` | Full report as JSON (`-` prints it instead of the terminal report) |
| `--html FILE` | Self-contained HTML report; every count expands to its rows |
| `--card FILE` | Counts-only share card (SVG): no names, hosts or dates |
| `--only mcp,agents` | Run a subset of collectors: `browser`, `mcp`, `agents`, `customizations`, `skills`, `ide`, `cli`, `keys` |
| `--project DIR` | Also scan a project directory (repeatable) |
| `--paranoid` | Drop dates, profile names, project paths and uncatalogued hosts |
| `--resolve` | Opt-in network use: resolve unknown destination hosts via system DNS and geolocate them (see PRIVACY.md) |
| `--verbose` | Every finding with its evidence |
| `--fail-on SEVERITY` | Exit 1 at or above `critical` (default), `high`, `medium` or `low` |
| `--no-footer` | Omit the product footer |
| `--color auto\|always\|never` | Terminal colour; `auto` also honours `NO_COLOR` and turns colour off on Windows consoles that cannot show it |
| `catalog show` | Bundled catalog version and row counts |

Exit codes: `0` nothing at or above `--fail-on`, `1` something is, `2` the scan could not run.
`--fail-on high` makes it usable in CI or a pre-commit hook.

## What it looks at

| Collector | Reads |
| --- | --- |
| `browser` | Chrome, Edge, Brave, Chromium, Arc, Vivaldi, Opera and Firefox history, cookie names and downloads |
| `mcp` | Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Gemini CLI and Codex CLI MCP configs |
| `agents` | Claude Code and Codex CLI settings that let them act without asking |
| `customizations` | Known AI config, instruction, rule and memory file locations; names and paths only |
| `skills` | Agent skills (`~/.claude/skills`, `.agents/skills`) and Claude plugins/marketplaces |
| `ide` | VS Code, VS Code Server, Cursor and Windsurf extensions from AI publishers |
| `cli` | AI CLIs on `PATH`; AI packages in npm, pipx, uv, user Python, Conda, Poetry, pyenv and bounded home/project virtualenv locations |
| `keys` | Known AI API-key names in the environment and shell rc / `.env` files |

Most config locations come from documentation and have not yet been confirmed on every OS; each
one's status is in [`catalog/src/locations.yaml`](catalog/src/locations.yaml).

## Where data can go

```
Where data can go (4 destinations, 2 countries)
  country = the cloud region when the endpoint or a region setting names one, else provider headquarters
  CN     DeepSeek                   ← MCP server "ds"
  US     ElevenLabs                 ← MCP server "voice"
  US     OpenAI                     ← agent "Codex CLI"; MCP server "codexsrv" via Codex CLI
  ??     gw.internal.example        ← MCP server "gw"
         unknown: the hostname was not resolved (scans make no network calls)
```

Country is, in order of strength: the AWS or Google Cloud **region** named by the endpoint host
(`bedrock-runtime.eu-central-1.amazonaws.com`, `europe-west4-aiplatform.googleapis.com`) or by a
region setting (`AWS_REGION`, `CLOUD_ML_REGION`), from the clouds' own region lists in
[`catalog/src/cloud_regions.json`](catalog/src/cloud_regions.json); the embedded DB-IP Lite
database for endpoints written as IP addresses; or the provider's headquarters, cited in
[`catalog/src/provider_sources.json`](catalog/src/provider_sources.json). Hostnames are never resolved unless you pass `--resolve`.

## The catalog

Detection rules are data, not code. [`catalog/src/`](catalog/src/) holds hand-written rules;
[`catalog/vendor/`](catalog/vendor/) holds generated fingerprints and the browser URL rule pack.
`python3 -I tools/build_catalog.py` compiles them into `catalog/catalog.json`, which is embedded in
the binary at build time.

To add a tool: add a row with `status: unverified`. To promote a browser rule to `verified`, attach
the output of `python3 -I tools/verify_url_rules.py` from a real machine to your pull request.
It reports path shapes, counts, cookie names and download hosts only.

## One machine is not a fleet

`lightcast` shows what is on one laptop today. [Auspere AISDR](https://auspere.ai/lightcast)
shows every machine, which of these were approved, and what each agent did.

## License

MIT. See [NOTICE](NOTICE) for third-party data.

IP geolocation: [IP Geolocation by DB-IP](https://db-ip.com), DB-IP Lite (Country and ASN),
licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Refresh it with
`tools/fetch_dbip.sh`; the release in use is recorded in `catalog/geo/MANIFEST.json`. Catalog fingerprints are identifiers and hashes taken from public repositories; each row
records its source repository and that repository's license.
