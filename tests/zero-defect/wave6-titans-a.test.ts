import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanRepo } from "../../src/ladder.ts";

function withTempRepo(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-wave6-"));
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

test("Wave 6 catches Go concurrency/path/UTF-8 bugs, SQL LIMIT/NULL traps, and Trojan Source BiDi chars", () => {
  withTempRepo(
    {
      "pkg/server/worker.go": [
        "package server",
        "import (",
        '  "path"',
        '  "path/filepath"',
        '  "sync"',
        '  "sync/atomic"',
        '  "unicode/utf8"',
        ")",
        "func step(s string) int {",
        "  pos := 0",
        "  for _, r := range s { pos += utf8.RuneLen(r) }",
        "  return pos",
        "}",
        "func joinUnsafe(root, reqPath string) string {",
        "  return filepath.Join(root, path.Clean(reqPath))",
        "}",
        "func daemon(conn interface{ Close() error }) {",
        "  defer conn.Close()",
        "  select {}",
        "}",
        "func doubleClose(ch chan int, err error) {",
        "  defer close(ch)",
        "  if err != nil { close(ch) }",
        "}",
        "func spin(jobs chan int) {",
        "  for {",
        "    select {",
        "    case v := <-jobs:",
        "      _ = v",
        "    }",
        "  }",
        "}",
        "func waitCond(c *sync.Cond, ready bool) {",
        "  if !ready { c.Wait() }",
        "}",
        "func quota(cur *atomic.Int64, limit int64) {",
        "  if cur.Load() < limit { cur.Add(1) }",
        "}",
      ].join("\n"),
      "db/schema/queries.sql": [
        "SELECT id FROM orders LIMIT 10;",
        "SELECT id FROM orders WHERE deleted_at != NULL;",
        "SELECT id FROM orders WHERE customer_id NOT IN (SELECT id FROM blocked);",
      ].join("\n"),
      "src/bidi.ts": `export const label = "admin\u202Euser";\n`,
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      for (const expected of [
        "go-range-string-runelen-offset",
        "go-url-path-posix-clean-before-filepath",
        "go-defer-before-blocking-select",
        "go-channel-double-close",
        "go-select-unchecked-channel-spin",
        "condvar-wait-without-loop",
        "atomic-check-then-mutate-toctou",
        "sql-limit-offset-without-order-by",
        "sql-null-trap-predicate",
        "bidi-trojan-source-control-chars",
      ]) {
        assert.ok(rules.has(expected), `expected ${expected}, got [${[...rules].join(", ")}]`);
      }
    },
  );
});

test("Wave 6 allows clean Go concurrency/path code and deterministic SQL", () => {
  withTempRepo(
    {
      "pkg/server/clean.go": [
        "package server",
        "import (",
        '  "path"',
        '  "path/filepath"',
        '  "strings"',
        '  "sync"',
        '  "sync/atomic"',
        ")",
        "func joinSafe(root, reqPath string) string {",
        '  if strings.Contains(reqPath, "\\\\") { return "" }',
        "  return filepath.Join(root, path.Clean(reqPath))",
        "}",
        "func waitSafe(c *sync.Cond, ready *bool) {",
        "  for !*ready { c.Wait() }",
        "}",
        "func quotaSafe(cur *atomic.Int64, limit int64) bool {",
        "  v := cur.Load()",
        "  if v < limit { return cur.CompareAndSwap(v, v+1) }",
        "  return false",
        "}",
        "func loopSafe(jobs chan int) {",
        "  for {",
        "    select {",
        "    case v, ok := <-jobs:",
        "      if !ok { jobs = nil; continue }",
        "      _ = v",
        "    }",
        "  }",
        "}",
      ].join("\n"),
      "db/schema/clean.sql": [
        "SELECT id FROM orders ORDER BY created_at, id LIMIT 10;",
        "SELECT id FROM orders WHERE deleted_at IS NOT NULL;",
        "SELECT id FROM orders WHERE customer_id NOT IN (SELECT id FROM blocked WHERE id IS NOT NULL);",
      ].join("\n"),
    },
    (dir) => {
      const w6 = scanRepo(dir).findings.filter((f) => f.id.startsWith("W6:"));
      assert.equal(w6.length, 0, `unexpected W6 findings: ${w6.map((f) => f.rule).join(", ")}`);
    },
  );
});
