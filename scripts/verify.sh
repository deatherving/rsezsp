#!/usr/bin/env bash
# Runs every check CI runs, in CI's order, before you push.
#
# Check the EXIT CODE, do not grep the output. Filtering a gate's output is how
# a failure gets read as success.
#
#   ./scripts/verify.sh          everything
#   ./scripts/verify.sh --fast   skip the fuzz build
set -euo pipefail

cd "$(cd "$(dirname "$0")/.." && pwd)"
FAST="${1:-}"
failed=()

step() {
  local name="$1"; shift
  printf '\n\033[1m==> %s\033[0m\n' "$name"
  if "$@"; then
    printf '\033[32mok\033[0m   %s\n' "$name"
  else
    printf '\033[31mFAIL\033[0m %s\n' "$name"
    failed+=("$name")
  fi
}

step "cargo fmt --check" cargo fmt --all -- --check
step "clippy" cargo clippy --all-targets --all-features -- -D warnings
step "tests" cargo test --all-features
step "cargo doc" env RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
# The crate must build without the runtime: the codecs are sans-I/O, and a
# dependency creeping into them would only show up here.
step "no-default-features" cargo clippy --all-targets --no-default-features -- -D warnings
step "tests without the runtime" cargo test --no-default-features
# Builds the crate from only the files that would be published, and compiles it
# there. Catches an `exclude` entry that removes something the build needs --
# invisible locally, because the file is still sitting on disk.
step "packages for crates.io" cargo package --all-features --allow-dirty

if [[ "$FAST" != "--fast" ]]; then
  # Compile-only. A long campaign is a separate, deliberate activity; a target
  # that stops building is a regression that should fail fast.
  # `--sanitizer none` keeps this on stable: ASan is the only part of
  # cargo-fuzz that needs nightly, and it has almost nothing to find in a
  # crate that forbids `unsafe`.
  if command -v cargo-fuzz >/dev/null; then
    step "fuzz targets build" cargo fuzz build --sanitizer none
  else
    printf '\n\033[33mskip\033[0m fuzz build (cargo-fuzz not installed)\n'
  fi
fi

printf '\n'
if ((${#failed[@]})); then
  printf '\033[31m%d check(s) failed:\033[0m\n' "${#failed[@]}"
  printf '  - %s\n' "${failed[@]}"
  exit 1
fi
printf '\033[32mall checks passed\033[0m\n'
