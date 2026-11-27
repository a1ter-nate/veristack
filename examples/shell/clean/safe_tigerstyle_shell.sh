#!/usr/bin/env bash
set -euo pipefail
TARGET_URL="${1:?target url required}"
curl --fail --max-time 10 "$TARGET_URL"
