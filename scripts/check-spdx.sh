#!/usr/bin/env bash
# No file in this MIT OR Apache-2.0 repository may declare an AGPL or GPL licence, and every
# Rust source must declare ours. CertifiedCopy's AGPL code is read for behaviour, never copied.
set -euo pipefail
status=0
if git grep -nIiE 'SPDX-License-Identifier:.*GPL' -- ':!scripts/check-spdx.sh'; then
  echo "::error::a file names a GPL-family licence in its SPDX header"
  status=1
fi
while IFS= read -r file; do
  if ! head -n 1 "$file" | grep -qF 'SPDX-License-Identifier: MIT OR Apache-2.0'; then
    echo "::error file=$file::$file does not start with the MIT OR Apache-2.0 SPDX header"
    status=1
  fi
done < <(git ls-files '*.rs')
exit "$status"
