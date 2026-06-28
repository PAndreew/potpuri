#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' "$root_dir/extension/manifest.json")
archive="$root_dir/dist/potpuri-extension-$version.zip"

if [ -z "$version" ]; then
  echo "Could not read extension version" >&2
  exit 1
fi

mkdir -p "$root_dir/dist"
rm -f "$archive"
cd "$root_dir/extension"
zip -q -r "$archive" . -x '*.DS_Store'
echo "$archive"
