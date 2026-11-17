#!/usr/bin/env bash
# Download DB-IP Lite (Country + ASN, MMDB) straight from db-ip.com into catalog/geo/.
#
# Licence: Creative Commons Attribution 4.0 International. Attribution required:
#   <a href='https://db-ip.com'>IP Geolocation by DB-IP</a>
# The databases are embedded in the binary at build time; the scanner never downloads anything.
#
# Usage: tools/fetch_dbip.sh [YYYY-MM]   (default: current UTC month, falling back to the previous one)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/catalog/geo"
mkdir -p "$out"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

month="${1:-$(date -u +%Y-%m)}"
candidates=("$month")
if [[ $# -eq 0 ]]; then
  candidates+=("$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m 2>/dev/null || date -u -v-1m +%Y-%m)")
fi

fetch() { # kind month
  local url="https://download.db-ip.com/free/dbip-$1-lite-$2.mmdb.gz"
  curl --fail --silent --show-error --location --max-time 300 --proto '=https' -o "$tmp/$1.mmdb.gz" "$url"
}

chosen=""
for m in "${candidates[@]}"; do
  if fetch country "$m" && fetch asn "$m"; then chosen="$m"; break; fi
done
[[ -n "$chosen" ]] || { echo "fetch_dbip: no DB-IP Lite release found for ${candidates[*]}" >&2; exit 1; }

for kind in country asn; do
  gunzip -c "$tmp/$kind.mmdb.gz" > "$tmp/dbip-$kind-lite.mmdb"
  # An MMDB file ends with its metadata section, which starts with this marker.
  if ! LC_ALL=C grep -q $'\xab\xcd\xefMaxMind.com' "$tmp/dbip-$kind-lite.mmdb"; then
    echo "fetch_dbip: $kind download is not an MMDB file" >&2; exit 1
  fi
  mv "$tmp/dbip-$kind-lite.mmdb" "$out/dbip-$kind-lite.mmdb"
done

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
bytes() { wc -c < "$1" | tr -d ' '; }

cat > "$out/MANIFEST.json" <<EOF
{
  "source": "https://db-ip.com/db/lite.php",
  "release": "$chosen",
  "license": "CC-BY-4.0",
  "attribution": "IP Geolocation by DB-IP",
  "attribution_url": "https://db-ip.com",
  "fetched_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "files": {
    "dbip-country-lite.mmdb": {"sha256": "$(sha "$out/dbip-country-lite.mmdb")", "bytes": $(bytes "$out/dbip-country-lite.mmdb")},
    "dbip-asn-lite.mmdb": {"sha256": "$(sha "$out/dbip-asn-lite.mmdb")", "bytes": $(bytes "$out/dbip-asn-lite.mmdb")}
  }
}
EOF
echo "fetch_dbip: DB-IP Lite $chosen -> catalog/geo/ ($(bytes "$out/dbip-country-lite.mmdb") + $(bytes "$out/dbip-asn-lite.mmdb") bytes)"
