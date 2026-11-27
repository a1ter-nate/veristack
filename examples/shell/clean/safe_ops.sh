#!/usr/bin/env bash
set -euo pipefail
TEST_DIRECTORY="/tmp/run"
source ./test-lib.sh
head -n 1 "$BIN" | grep -Fq "#!/usr/bin/env node"
curl --netrc --max-time 10 https://example.com/status
SOCK_DIR="$(mktemp -d /tmp/sock.XXXXXX)"
trap 'rm -rf "$SOCK_DIR"' EXIT
kill -TERM "$WORKER_PID"
