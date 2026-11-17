# Releasing LightCast

Releases are built from an exact commit, on three platforms, packaged reproducibly, and signed.

## What a release contains

| File | Built where |
| --- | --- |
| `lightcast-<v>-x86_64-unknown-linux-musl.tar.gz` | Static binary, in a digest-pinned `rust:<toolchain>-alpine` container |
| `lightcast-<v>-universal-apple-darwin.tar.gz` | Universal (Apple Silicon + Intel) binary on the macOS build host |
| `lightcast-<v>-x86_64-pc-windows-msvc.zip` | On the Windows build host |
| `lightcast-<v>-src.tar.gz` | `git archive` of the released commit |
| `lightcast-<v>.cdx.json` | CycloneDX SBOM of the locked dependency graph |
| `release.json` | Commit, toolchain, container digest, per-platform signing status, artifact hashes |
| `INSTALL-windows.txt`, `INSTALL-macos.txt`, `INSTALL-linux.txt` | Plain-text install guides from `packaging/`, also inside each archive as `INSTALL.txt` |
| `SHA256SUMS` | Every file above |
| `*.sigstore.json` | A cosign signature bundle for every file above |

Archives also carry `LICENSE`, `NOTICE` (DB-IP attribution), `README.md` and `PRIVACY.md`.

## Two release paths

**From the project's build hosts:** `tools/release.sh`. It refuses a dirty tree, builds the
committed `git archive`, and runs every build under a hard resource ceiling (container limits on
Linux, `tools/run-bounded-macos.sh` on macOS, a Job Object via `tools/run-bounded-windows.ps1` on
Windows). Host addresses and keys come from the environment; see the header of the script.

```sh
MAC_HOST=… MAC_SSH_KEY=… WIN_HOST=… WIN_SSH_KEY=… WIN_BUILD_DIR=E:/WINDOWS_BUILD/lightcast \
COSIGN_KEY=/secure/lightcast.key COSIGN_PUBLIC_KEY=/secure/lightcast.pub \
COSIGN_PASSWORD_FILE=/secure/lightcast.pass \
  /path/to/run-bounded.sh 8G 600% 1024 -- tools/release.sh
```

**From GitHub:** push a `v*` tag; `.github/workflows/release.yml` builds each platform, signs every
file keylessly with Sigstore (GitHub OIDC identity, recorded in the Rekor transparency log),
attaches SLSA build provenance, and opens a draft release.

## Signing

| Layer | Status | To enable |
| --- | --- | --- |
| Sigstore cosign, every file | Ready | Local path: a dedicated `lightcast` cosign key pair kept outside the repository, password in an owner-only file. GitHub path: nothing, it is keyless. |
| Apple Developer ID + notarization | Not configured: no Developer ID identity on the macOS host | Enrol in the Apple Developer Program, install a "Developer ID Application" certificate, then set `APPLE_SIGNING_IDENTITY` and `APPLE_NOTARY_PROFILE` (a `notarytool store-credentials` profile) |
| Windows Authenticode | Not configured: no code-signing certificate on the Windows host | Obtain an OV/EV code-signing certificate (or Azure Trusted Signing), install it for the build user, set `WINDOWS_CERT_SHA1` |

Until Apple and Windows signing are configured, macOS Gatekeeper and Windows SmartScreen will warn on
first run; `release.json` records this for each platform. Never sign a public release with
`COSIGN_TLOG=false`: that mode exists for test keys and leaves no transparency-log entry.

## Verifying a release

```sh
tools/verify-release.sh ./lightcast-0.1.2 lightcast-cosign.pub
```

It checks `SHA256SUMS`, then every signature bundle. Get the public key from the project's own site
or repository, not only from the download itself.

## Before tagging

1. `cargo clippy --all-targets -- -D warnings` and `cargo test` pass on Linux, macOS and Windows.
2. `tools/fetch_dbip.sh` was run within the last month, and `catalog/geo/MANIFEST.json` committed.
3. `python3 -I tools/build_catalog.py` leaves `catalog/catalog.json` unchanged.
4. The version in `Cargo.toml` is bumped and the commit is on `main`.
