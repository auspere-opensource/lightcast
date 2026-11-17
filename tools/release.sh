#!/usr/bin/env bash
# Build, package, checksum and sign an lightcast release from the exact committed tree.
#
# Run from a clean checkout on the Linux release host, itself under a memory ceiling:
#   scripts/run-bounded.sh 8G 600% 1024 -- tools/release.sh            (or any equivalent ceiling)
#
# Platforms:
#   linux   x86_64-unknown-linux-musl, static, built in a pinned rust:<toolchain>-alpine container
#           with --memory/--memory-swap/--cpus/--pids-limit set
#   macos   universal (aarch64 + x86_64) built on MAC_HOST under tools/run-bounded-macos.sh
#   windows x86_64-pc-windows-msvc built on WIN_HOST under tools/run-bounded-windows.ps1 (Job Object)
#
# Required env (never read from files in this repo):
#   MAC_HOST, MAC_SSH_KEY        e.g. user@10.0.0.5 and a key path
#   WIN_HOST, WIN_SSH_KEY, WIN_BUILD_DIR   e.g. E:/WINDOWS_BUILD/lightcast
# Signing (optional; each step is skipped with a notice when unset):
#   COSIGN_KEY, COSIGN_PUBLIC_KEY [COSIGN_PASSWORD_FILE] [COSIGN_TLOG=true|false]
#   APPLE_SIGNING_IDENTITY [APPLE_NOTARY_PROFILE]       (Developer ID identity / notarytool keychain profile on MAC_HOST)
#   WINDOWS_CERT_SHA1 [WINDOWS_TIMESTAMP_URL]           (code-signing certificate thumbprint on WIN_HOST)
# Skip a platform with SKIP_LINUX=1, SKIP_MACOS=1 or SKIP_WINDOWS=1.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

die() { echo "release: $*" >&2; exit 1; }
note() { echo "release: $*" >&2; }

# 1. Exact commit only.
[[ -z "$(git status --porcelain)" ]] || die "the working tree is not clean; commit or stash first"
commit="$(git rev-parse HEAD)"
short="${commit:0:12}"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
toolchain="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)"
[[ -n "$version" && -n "$toolchain" ]] || die "could not read version or toolchain"
name="lightcast-${version}"
out="$root/dist/${name}-${short}"
[[ ! -e "$out" ]] || die "$out already exists; releases are immutable"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

src="$out/${name}-src.tar.gz"
git archive --format=tar --prefix="${name}/" HEAD | gzip -n -9 > "$src"
note "source archive $(basename "$src") from $commit"

# Deterministic packaging: fixed mtime, sorted entries, no owner names.
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export SOURCE_DATE_EPOCH
docs=(LICENSE NOTICE README.md PRIVACY.md)

# Plain-text install guide for an unsigned build: packaging/INSTALL-<platform>.txt with the
# version filled in; CRLF line endings for Windows.
install_doc() { # platform destination
  local text
  text="$(sed "s/@VERSION@/${version}/g" "$root/packaging/INSTALL-$1.txt")"
  if [[ "$1" == windows ]]; then printf '%s\n' "$text" | sed 's/$/\r/' > "$2"; else printf '%s\n' "$text" > "$2"; fi
}

pack_tar() { # dir_with_binary archive platform
  local stage="$1" archive="$2"
  for d in "${docs[@]}"; do cp "$root/$d" "$stage/"; done
  install_doc "$3" "$stage/INSTALL.txt"
  tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner -C "$(dirname "$stage")" -cf - "$(basename "$stage")" | gzip -n -9 > "$archive"
}

pack_zip() { # dir_with_binary archive platform
  local stage="$1" archive="$2"
  for d in "${docs[@]}"; do cp "$root/$d" "$stage/"; done
  install_doc "$3" "$stage/INSTALL.txt"
  python3 -I - "$stage" "$archive" "$SOURCE_DATE_EPOCH" <<'PY'
import os, sys, time, zipfile
stage, archive, epoch = sys.argv[1], sys.argv[2], int(sys.argv[3])
ts = time.gmtime(max(epoch, 315532800))[:6]
base = os.path.basename(stage)
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
    for f in sorted(os.listdir(stage)):
        info = zipfile.ZipInfo(f"{base}/{f}", ts)
        info.external_attr = (0o755 if f.endswith(".exe") else 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        with open(os.path.join(stage, f), "rb") as fh:
            z.writestr(info, fh.read())
PY
}

# 2. Build the three platforms in parallel: they run on different hosts and share nothing until
#    packaging. Each job logs to its own file; the first failure stops the others.
logs="$root/dist/${name}-${short}.logs"
mkdir -p "$logs" "$work/status"
status() { printf '%s' "$3" > "$work/status/$1.$2"; }   # platform key value
read_status() { cat "$work/status/$1.$2" 2>/dev/null || echo "$3"; }

# 2a. Linux: static musl in a pinned container with hard resource limits.
build_linux() {
  image="rust:${toolchain}-alpine"
  docker pull -q "$image" >/dev/null
  image_digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$image")"
  status linux image "$image_digest"
  note "linux: building in $image_digest"
  mkdir -p "$work/linux"
  docker run --rm --name "lightcast-release-${short}" --network=bridge \
    --memory=6g --memory-swap=6g --cpus=6 --pids-limit=512 \
    -v "$src:/in/src.tar.gz:ro" -v "$work/linux:/out" \
    "$image_digest" sh -euc '
      apk add --no-cache musl-dev >/dev/null
      mkdir -p /build && tar -xzf /in/src.tar.gz -C /build --strip-components=1
      cd /build
      cargo build --release --locked --target x86_64-unknown-linux-musl
      cp target/x86_64-unknown-linux-musl/release/lightcast /out/
    '
  stage="$work/${name}-x86_64-unknown-linux-musl"
  mkdir -p "$stage" && cp "$work/linux/lightcast" "$stage/"
  # Rust's musl target emits a static PIE; `file` calls that "static-pie linked".
  file "$stage/lightcast" | grep -Eq "static(ally|-pie) linked" || die "linux binary is not statically linked: $(file -b "$stage/lightcast")"
  pack_tar "$stage" "$out/${name}-x86_64-unknown-linux-musl.tar.gz" linux
  status linux signing "cosign only (no platform signing on Linux)"
}

# 2b. macOS universal binary.
build_macos() {
  : "${MAC_HOST:?set MAC_HOST}" "${MAC_SSH_KEY:?set MAC_SSH_KEY}"
  mssh() { ssh -o BatchMode=yes -o ServerAliveInterval=30 -i "$MAC_SSH_KEY" "$MAC_HOST" "$@"; }
  rdir="build/lightcast-release-${short}"
  mssh "rm -rf ~/$rdir && mkdir -p ~/$rdir"
  mssh "cat > ~/$rdir/src.tar.gz" < "$src"
  mssh "bash -lc 'set -euo pipefail; export PATH=\$HOME/.cargo/bin:\$PATH; cd ~/$rdir && tar -xzf src.tar.gz --strip-components=1 \
    && rustup toolchain install $toolchain --profile minimal --target aarch64-apple-darwin --target x86_64-apple-darwin >/dev/null \
    && tools/run-bounded-macos.sh 8192 512 2400 -- cargo build --release --locked -j 4 --target aarch64-apple-darwin \
    && tools/run-bounded-macos.sh 8192 512 2400 -- cargo build --release --locked -j 4 --target x86_64-apple-darwin \
    && lipo -create -output lightcast target/aarch64-apple-darwin/release/lightcast target/x86_64-apple-darwin/release/lightcast \
    && lipo -info lightcast'"
  if [[ -n "${APPLE_SIGNING_IDENTITY:-}" ]]; then
    mssh "cd ~/$rdir && codesign --force --options runtime --timestamp --sign \"$APPLE_SIGNING_IDENTITY\" lightcast && codesign --verify --strict --verbose=2 lightcast"
    if [[ -n "${APPLE_NOTARY_PROFILE:-}" ]]; then
      mssh "cd ~/$rdir && ditto -c -k --keepParent lightcast notarize.zip && xcrun notarytool submit notarize.zip --keychain-profile \"$APPLE_NOTARY_PROFILE\" --wait"
      status macos signing "Developer ID signed and notarized"
    else
      status macos signing "Developer ID signed, not notarized (APPLE_NOTARY_PROFILE unset)"
    fi
  else
    status macos signing "not Apple-signed (APPLE_SIGNING_IDENTITY unset); Gatekeeper will warn"
  fi
  stage="$work/${name}-universal-apple-darwin"
  mkdir -p "$stage"
  mssh "cat ~/$rdir/lightcast" > "$stage/lightcast"
  chmod 0755 "$stage/lightcast"
  pack_tar "$stage" "$out/${name}-universal-apple-darwin.tar.gz" macos
}

# 2c. Windows x64.
build_windows() {
  : "${WIN_HOST:?set WIN_HOST}" "${WIN_SSH_KEY:?set WIN_SSH_KEY}" "${WIN_BUILD_DIR:?set WIN_BUILD_DIR}"
  wps() { # run a PowerShell script from stdin on WIN_HOST
    local enc; enc="$(iconv -f UTF-8 -t UTF-16LE | base64 -w0)"
    # PowerShell's progress stream arrives as CLIXML on stderr; drop it. An empty result is fine
    # (grep exits 1 on no output), but the remote exit status must still fail the release.
    local rc=0
    ssh -o BatchMode=yes -o ServerAliveInterval=30 -i "$WIN_SSH_KEY" "$WIN_HOST" "powershell -NoProfile -NonInteractive -EncodedCommand $enc" > "$work/wps.out" 2>&1 || rc=$?
    grep -v -e '^#< CLIXML' -e '^<Objs' "$work/wps.out" || true
    return "$rc"
  }
  wdir="${WIN_BUILD_DIR}/release-${short}"
  wps <<EOF
\$ErrorActionPreference = 'Stop'
if (Test-Path '$wdir') { Remove-Item -Recurse -Force '$wdir' }
New-Item -ItemType Directory -Path '$wdir' | Out-Null
EOF
  scp -q -o BatchMode=yes -i "$WIN_SSH_KEY" "$src" "$WIN_HOST:$wdir/src.tar.gz"
  sign_ps=""
  if [[ -n "${WINDOWS_CERT_SHA1:-}" ]]; then
    sign_ps="\$st = Get-ChildItem \"\${env:ProgramFiles(x86)}\\Windows Kits\\10\\bin\\*\\x64\\signtool.exe\" | Select-Object -Last 1; & \$st.FullName sign /sha1 $WINDOWS_CERT_SHA1 /fd SHA256 /tr ${WINDOWS_TIMESTAMP_URL:-http://timestamp.digicert.com} /td SHA256 target\\release\\lightcast.exe; if (\$LASTEXITCODE) { exit \$LASTEXITCODE }; & \$st.FullName verify /pa target\\release\\lightcast.exe; if (\$LASTEXITCODE) { exit \$LASTEXITCODE }"
    status windows signing "Authenticode signed (certificate $WINDOWS_CERT_SHA1)"
  else
    status windows signing "not Authenticode-signed (WINDOWS_CERT_SHA1 unset); SmartScreen will warn"
  fi
  wps <<EOF
\$ErrorActionPreference = 'Stop'
Set-Location '$wdir'
tar -xzf src.tar.gz --strip-components=1
& rustup toolchain install $toolchain --profile minimal | Out-Null
powershell -NoProfile -ExecutionPolicy Bypass -File tools\\run-bounded-windows.ps1 -MemoryMB 12288 -MaxProcs 256 -TimeoutSec 2400 -Command "cargo build --release --locked -j 8"
if (\$LASTEXITCODE) { exit \$LASTEXITCODE }
$sign_ps
EOF
  stage="$work/${name}-x86_64-pc-windows-msvc"
  mkdir -p "$stage"
  scp -q -o BatchMode=yes -i "$WIN_SSH_KEY" "$WIN_HOST:$wdir/target/release/lightcast.exe" "$stage/lightcast.exe"
  pack_zip "$stage" "$out/${name}-x86_64-pc-windows-msvc.zip" windows
}

declare -A job_pid=()
for plat in linux macos windows; do
  skip="SKIP_${plat^^}"
  [[ "${!skip:-}" == 1 ]] && { note "$plat: skipped"; continue; }
  ( "build_$plat" ) > "$logs/$plat.log" 2>&1 &
  job_pid[$plat]=$!
  note "$plat: started (log $logs/$plat.log)"
done
stop_jobs() {
  for p in "${job_pid[@]}"; do kill "$p" 2>/dev/null || true; done
  # Killing the docker client does not stop its container.
  docker rm -f "lightcast-release-${short}" >/dev/null 2>&1 || true
}
trap 'stop_jobs; rm -rf "$work"' EXIT
trap 'echo "release: interrupted" >&2; exit 130' INT TERM

started=$(date +%s)
while ((${#job_pid[@]})); do
  set +e; wait -n -p done_pid "${job_pid[@]}"; rc=$?; set -e
  for plat in "${!job_pid[@]}"; do
    [[ "${job_pid[$plat]}" == "$done_pid" ]] || continue
    unset 'job_pid[$plat]'
    if ((rc != 0)); then
      echo "release: $plat FAILED (exit $rc) after $(( $(date +%s) - started ))s; last lines of its log:" >&2
      tail -25 "$logs/$plat.log" >&2
      stop_jobs
      die "stopping: $plat build failed; other builds were stopped"
    fi
    note "$plat: done after $(( $(date +%s) - started ))s"
  done
done
trap 'rm -rf "$work"' EXIT
image_digest="$(read_status linux image "")"
declare -A platform_signing=(
  [linux]="$(read_status linux signing skipped)"
  [macos]="$(read_status macos signing skipped)"
  [windows]="$(read_status windows signing skipped)"
)

# 3. SBOM from the locked dependency graph.
mkdir -p "$work/sbom" && tar -xzf "$src" -C "$work/sbom" --strip-components=1
( cd "$work/sbom" && cargo cyclonedx --format json --override-filename sbom >/dev/null )
cp "$work/sbom/sbom.json" "$out/${name}.cdx.json"

# Install guides beside the archives: needed BEFORE unpacking (Windows "Unblock", checksums).
for plat in linux macos windows; do install_doc "$plat" "$out/INSTALL-$plat.txt"; done

# 4. Manifest (artifacts only).
python3 -I - "$out" "$version" "$commit" "$toolchain" "$image_digest" "$SOURCE_DATE_EPOCH" \
  "${platform_signing[linux]:-skipped}" "${platform_signing[macos]:-skipped}" "${platform_signing[windows]:-skipped}" <<'PY'
import hashlib, json, os, sys
out, version, commit, toolchain, image, epoch, sl, sm, sw = sys.argv[1:10]
files = {}
for f in sorted(os.listdir(out)):
    p = os.path.join(out, f)
    if os.path.isfile(p) and f not in ("release.json", "SHA256SUMS"):
        files[f] = {"sha256": hashlib.sha256(open(p, "rb").read()).hexdigest(), "bytes": os.path.getsize(p)}
json.dump({
    "name": "lightcast", "version": version, "git_commit": commit, "rust_toolchain": toolchain,
    "linux_build_image": image or None, "source_date_epoch": int(epoch),
    "platform_signing": {"linux": sl, "macos": sm, "windows": sw},
    "artifacts": files,
}, open(os.path.join(out, "release.json"), "w"), indent=1)
PY

# 5. Checksums over every artifact and the manifest.
( cd "$out" && sha256sum -- * | LC_ALL=C sort -k2 > SHA256SUMS )

# 6. Sigstore cosign signatures over every artifact, the checksums and the manifest.
if [[ -n "${COSIGN_KEY:-}" ]]; then
  : "${COSIGN_PUBLIC_KEY:?set COSIGN_PUBLIC_KEY to verify what was signed}"
  tlog="${COSIGN_TLOG:-true}"
  sign_flags=()
  if [[ "$tlog" == "false" ]]; then
    # A signing config with no transparency log: signs fully offline (cosign v3). For test keys only;
    # public releases should keep the default and land in the Rekor transparency log.
    cat > "$work/signing-config.json" <<'JSON'
{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json","caUrls":[],"oidcUrls":[],"rekorTlogUrls":[],"tsaUrls":[],"rekorTlogConfig":{"selector":"ANY"},"tsaConfig":{"selector":"ANY"}}
JSON
    sign_flags=(--signing-config "$work/signing-config.json")
  fi
  (
    if [[ -n "${COSIGN_PASSWORD_FILE:-}" ]]; then COSIGN_PASSWORD="$(cat "$COSIGN_PASSWORD_FILE")"; export COSIGN_PASSWORD; fi
    cd "$out"
    for f in *; do
      [[ "$f" == *.sigstore.json ]] && continue
      cosign sign-blob --yes --key "$COSIGN_KEY" "${sign_flags[@]}" --bundle "$f.sigstore.json" "$f" >/dev/null 2>&1 \
        || { echo "release: cosign failed for $f" >&2; exit 1; }
    done
  )
  cp "$COSIGN_PUBLIC_KEY" "$out/lightcast-cosign.pub"
  verify_flags=(); [[ "$tlog" == "false" ]] && verify_flags=(--insecure-ignore-tlog=true)
  for b in "$out"/*.sigstore.json; do
    cosign verify-blob --key "$COSIGN_PUBLIC_KEY" --bundle "$b" "${verify_flags[@]}" "${b%.sigstore.json}" >/dev/null 2>&1 \
      || die "signature did not verify: $(basename "$b")"
  done
  note "cosign: signed and verified $(ls "$out"/*.sigstore.json | wc -l) files (transparency log upload: $tlog)"
else
  note "cosign: COSIGN_KEY unset, artifacts are NOT signed"
fi

note "done: $out"
ls -l "$out" >&2
