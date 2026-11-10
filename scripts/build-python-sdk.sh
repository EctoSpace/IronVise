#!/usr/bin/env bash
# Build and inspect fresh artifacts before replacing the generated dist folder.
# This never publishes packages or starts GitHub Actions.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SDK_BUILD=$(mktemp -d)
trap 'rm -rf "$SDK_BUILD"' EXIT
python3 -m build "$ROOT/sdk/python" --outdir "$SDK_BUILD"
python3 "$ROOT/scripts/check-product-layout.py" --python-dist "$SDK_BUILD"
rm -rf "$ROOT/sdk/python/dist"
mkdir -p "$ROOT/sdk/python/dist"
mv "$SDK_BUILD"/*.whl "$SDK_BUILD"/*.tar.gz "$ROOT/sdk/python/dist/"
