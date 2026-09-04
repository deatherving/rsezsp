#!/usr/bin/env bash
# Copy the crate to a host with a dongle attached, for hardware validation.
#
# Not piped through head/grep: closing the pipe early SIGPIPEs tar and
# truncates the transfer, leaving stale source on the remote. The transfer is
# verified afterwards rather than assumed.
set -euo pipefail

HOST="${1:?usage: deploy-remote.sh user@host [remote-dir]}"
DIR="${2:-/tmp/rsezsp-build}"
SSH=(ssh -o ConnectTimeout=10 "$HOST")

tmp=$(mktemp -t rsezsp-src.XXXXXX).tgz
trap 'rm -f "$tmp"' EXIT
# --no-mac-metadata and COPYFILE_DISABLE stop macOS tar emitting AppleDouble
# companion files, which a Linux host extracts as literal `._file` junk.
COPYFILE_DISABLE=1 tar czf "$tmp" \
  --no-mac-metadata --no-xattrs \
  --exclude target --exclude .git --exclude fuzz/target \
  --exclude fuzz/corpus --exclude fuzz/artifacts .
printf 'archive: %s bytes\n' "$(wc -c <"$tmp" | tr -d ' ')"

"${SSH[@]}" "rm -rf '$DIR/src' && mkdir -p '$DIR'"
"${SSH[@]}" "tar xzf - -C '$DIR'" <"$tmp"

local_sum=$(find . -name '*.rs' -not -path './target/*' -not -path './fuzz/target/*' \
  | sort | xargs shasum | shasum | cut -d' ' -f1)
remote_sum=$("${SSH[@]}" "cd '$DIR' && find . -name '*.rs' -not -path './target/*' \
  -not -path './fuzz/target/*' | sort | xargs shasum | shasum | cut -d' ' -f1")
if [ "$local_sum" != "$remote_sum" ]; then
  echo "transfer verification FAILED: local $local_sum, remote $remote_sum" >&2
  exit 1
fi
echo "verified: remote source matches local ($local_sum)"
