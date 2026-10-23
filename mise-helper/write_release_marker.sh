#!/bin/sh
# The release packager supplies APPLICATION_SHA from its selected artifact source.
set -eu
if [ "$#" -ne 1 ]; then
  echo 'release-marker-output-required' >&2
  exit 1
fi
source_sha="${APPLICATION_SHA:-}"
if [ "${#source_sha}" -ne 40 ]; then
  echo 'release-marker-source-invalid' >&2
  exit 1
fi
case "$source_sha" in
  *[!0-9a-f]*) echo 'release-marker-source-invalid' >&2; exit 1 ;;
esac
mkdir -p "$1/.well-known"
printf '{"source_sha":"%s"}\n' "$source_sha" > "$1/.well-known/adw-release.json"
