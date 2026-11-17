#!/usr/bin/env bash
# Verify a downloaded lightcast release directory: checksums, then cosign signatures.
#
# Usage: tools/verify-release.sh DIR [PUBLIC_KEY]
#   DIR         a directory holding the release files, SHA256SUMS and *.sigstore.json bundles
#   PUBLIC_KEY  defaults to DIR/lightcast-cosign.pub. Obtain the key from a channel you trust
#               (the project website or repository), not only from the same download.
# Set OFFLINE_SIGNATURES=1 only for test releases signed without the transparency log.
set -euo pipefail
dir="$(cd "${1:?usage: verify-release.sh DIR [PUBLIC_KEY]}" && pwd)"
key="${2:-$dir/lightcast-cosign.pub}"
key="$(cd "$(dirname "$key")" && pwd)/$(basename "$key")"   # absolute, before changing directory
cd "$dir"
sha256sum --check --strict SHA256SUMS
command -v cosign >/dev/null || { echo "cosign not installed: checksums verified, signatures NOT verified" >&2; exit 1; }
flags=()
[[ "${OFFLINE_SIGNATURES:-}" == 1 ]] && flags=(--insecure-ignore-tlog=true)
n=0
for b in *.sigstore.json; do
  cosign verify-blob --key "$key" --bundle "$b" "${flags[@]}" "${b%.sigstore.json}" >/dev/null
  n=$((n + 1))
done
[[ $n -gt 0 ]] || { echo "no signatures found" >&2; exit 1; }
echo "verified: SHA256SUMS and $n signatures"
