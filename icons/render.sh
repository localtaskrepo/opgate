#!/bin/bash
# Renders the app icons in web/ from these SVGs (Homebrew librsvg and imagemagick).
# icon.svg: home screen and notifications (brass fingerprint gate, polished metal on green);
# apple.svg: iOS (square, iOS rounds it); badge.svg: Android status bar (white, only the alpha counts);
# favicon.svg: browser tab and page headers (three bold ridges, crisp at 16 px; also served as is).
set -euo pipefail
cd "$(dirname "$0")"
W=../web
rsvg-convert -w 512 icon.svg -o $W/icon-512.png
rsvg-convert -w 192 icon.svg -o $W/icon-192.png
rsvg-convert -w 512 maskable.svg -o $W/icon-maskable.png
rsvg-convert -w 180 apple.svg -o $W/apple-touch-icon.png
rsvg-convert -w 96 badge.svg -o $W/badge.png
rsvg-convert -w 32 favicon.svg -o $W/favicon-32.png
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
rsvg-convert -w 16 favicon.svg -o "$t/16.png"
magick "$t/16.png" $W/favicon-32.png $W/favicon.ico
cp favicon.svg $W/favicon.svg
