#!/usr/bin/env bash
# Record the current UI locally. Uses labelled demonstration fixtures, not a
# live audit or private user data. This script never starts GitHub Actions.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
command -v ffmpeg >/dev/null || { echo "ffmpeg is required" >&2; exit 1; }
MEDIA_WORK=$(mktemp -d)
trap 'rm -rf "$MEDIA_WORK"' EXIT
cd "$ROOT/gui"
IRONVISE_MEDIA_OUTPUT="$MEDIA_WORK" npx playwright test --config playwright.media.config.ts
OUT="$ROOT/site/marketing_assets/videos"
mkdir -p "$OUT"
for pair in 'interface-overview:ironvise_gui_demo' 'audit-evidence-walkthrough:ironvise_audit_demo'; do
    recording=${pair%%:*}
    name=${pair#*:}
    dir="$MEDIA_WORK/record-site-media-IronVise-$recording-chromium"
    input="$dir/video.webm"
    start=$(cat "$dir/opening.txt" 2>/dev/null || echo 0.8)
    ffmpeg -y -v error -ss "$start" -i "$input" -an -vf fps=30 \
        -c:v libx264 -preset slow -crf 23 -pix_fmt yuv420p -movflags +faststart \
        -metadata title="IronVise 0.8 - demonstration data" "$OUT/$name.mp4"
    ffmpeg -y -v error -i "$OUT/$name.mp4" -vf \
        'fps=6,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96[p];[b][p]paletteuse=dither=bayer' \
        "$OUT/$name.gif"
done
echo "Updated IronVise videos, GIFs and screenshots in site/marketing_assets."
