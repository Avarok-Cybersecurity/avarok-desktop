#!/usr/bin/env bash
# Every tracked source file stays at or under 250 lines; split a longer one, never raise this.
# Exempt: licence texts (copied verbatim) and Cargo.lock (generated).
set -euo pipefail
limit=250
status=0
while IFS= read -r file; do
  case "$file" in LICENSE-*|Cargo.lock) continue ;; esac
  lines=$(wc -l < "$file" | tr -d ' ')
  if [ "$lines" -gt "$limit" ]; then
    echo "::error file=$file::$file has $lines lines; the limit is $limit"
    status=1
  fi
done < <(git ls-files)
exit "$status"
