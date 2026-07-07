#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_DIR="${TEMPO_CDP_CHROME_CACHE:-$ROOT/.local/chrome-for-testing}"
MANIFEST="$CACHE_DIR/last-known-good-versions-with-downloads.json"

case "$(uname -s):$(uname -m)" in
  Darwin:arm64) PLATFORM="mac-arm64" ;;
  Darwin:x86_64) PLATFORM="mac-x64" ;;
  Linux:x86_64) PLATFORM="linux64" ;;
  *)
    echo "unsupported platform for Chrome for Testing: $(uname -s) $(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p "$CACHE_DIR"
curl -fsSL \
  "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json" \
  -o "$MANIFEST"

read -r VERSION URL RELATIVE_BIN < <(
  python3 - "$MANIFEST" "$PLATFORM" <<'PY'
import json
import sys

manifest_path, platform = sys.argv[1], sys.argv[2]
with open(manifest_path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

stable = manifest["channels"]["Stable"]
downloads = stable["downloads"]["chrome"]
match = next((item for item in downloads if item["platform"] == platform), None)
if match is None:
    raise SystemExit(f"no Stable Chrome for Testing download for {platform}")

if platform.startswith("mac-"):
    relative = "chrome-mac-{arch}/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing".format(
        arch="arm64" if platform == "mac-arm64" else "x64"
    )
elif platform == "linux64":
    relative = "chrome-linux64/chrome"
else:
    raise SystemExit(f"unsupported platform: {platform}")

print(stable["version"], match["url"], relative)
PY
)

INSTALL_DIR="$CACHE_DIR/$VERSION/$PLATFORM"
ZIP="$CACHE_DIR/$VERSION-$PLATFORM.zip"
CHROME="$INSTALL_DIR/$RELATIVE_BIN"

if [[ ! -x "$CHROME" ]]; then
  rm -rf "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  echo "downloading Chrome for Testing $VERSION ($PLATFORM)..." >&2
  curl -fL "$URL" -o "$ZIP"
  unzip -q "$ZIP" -d "$INSTALL_DIR"
  chmod +x "$CHROME"
fi

printf '%s\n' "$CHROME"
