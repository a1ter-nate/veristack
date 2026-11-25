#!/usr/bin/env bash
export PATH="$PATH:./bin"
curl --token "$API_KEY" https://example.com/status
grep -F "#!/usr/bin/env node" "$BIN"
source ./test-lib.sh
TEST_DIRECTORY="/tmp/run"
SOCKET="$TRASH_DIRECTORY/agent.sock"
pkill -f "my-worker"
