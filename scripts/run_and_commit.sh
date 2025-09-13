#!/bin/bash
set -euo pipefail

# Determine repository root (this script resides in scripts/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

INPUT_REL="scripts/rule.yml"
OUTPUT_REL="merged.sgmodule"

# Run aggregator with requested name/desc using relative paths
python3 scripts/aggregate.py \
  -i "$INPUT_REL" \
  -o "$OUTPUT_REL" \
  --name "ProxyScript" \
  --desc "ProxyScript"

# Add and commit only if there are changes
if ! git diff --quiet -- "$OUTPUT_REL"; then
  git add "$OUTPUT_REL"
  git commit -m "chore(build): regenerate merged.sgmodule via helper script"
  echo "Committed updated $OUTPUT_REL."
else
  echo "No changes in $OUTPUT_REL. Skipping commit."
fi
