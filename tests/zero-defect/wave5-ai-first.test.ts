import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanRepo } from "../../src/ladder.ts";

function withTempRepo(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-wave5-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content, "utf8");
    }
    fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("Wave 5 catches shell installer bugs, MCP stdio/error traps, Rust UTF-8 byte-slice & rkyv unchecked, Python prompt-cache sort_keys, and 0600 umask leaks", () => {
  withTempRepo(
    {
      "scripts/install.sh": [
        "#!/usr/bin/env bash",
        "export PATH=$PATH:./bin",
        'curl --token "$API_KEY" https://example.com',
        'grep -F "#!/usr/bin/env node" "$BIN"',
      ].join("\n"),
      "src/mcp/server.ts": [
        "export function registerTool(name: string): void {",
        '  console.log("starting", name);',
        '  throw new McpError("bad arg");',
        "}",
      ].join("\n"),
      "src/auth/token-store.ts": [
        'import fs from "node:fs";',
        "export function saveToken(p: string, tok: string): void {",
        "  fs.writeFileSync(p, tok);",
        "}",
      ].join("\n"),
      "src/tool.rs": [
        "pub fn truncate_out(output: &str, max_len: usize) -> &str {",
        "    &output[..max_len]",
        "}",
        "pub unsafe fn load_cache(bytes: &[u8]) {",
        "    // SAFETY: test fixture",
        "    let _ = rkyv::access_unchecked::<u32>(bytes);",
        "}",
      ].join("\n"),
      "app/mcp/stdio.py": [
        "import logging",
        "logging.basicConfig(level=logging.INFO)",
      ].join("\n"),
      "app/prompt/history.py": [
        "import json",
        "def dump_history(msgs: list[dict[str, str]]) -> str:",
        "    return json.dumps(msgs, sort_keys=True)",
      ].join("\n"),
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      for (const expected of [
        "sh-untrusted-path-in-sudo",
        "sh-secret-in-argv",
        "sh-unanchored-shebang-grep",
        "mcp-stdio-stdout-pollution",
        "mcp-throw-error-in-tool",
        "sec-sensitive-file-default-umask",
        "tool-output-unicode-safe-truncation",
        "rust-rkyv-require-bytecheck",
        "llm-prompt-cache-prefix-bust",
      ]) {
        assert.ok(rules.has(expected), `expected ${expected}, got [${[...rules].join(", ")}]`);
      }
    },
  );
});
