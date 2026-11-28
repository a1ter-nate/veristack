import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanRepo } from "@veristack/core";

test("TS/Rust/SQL/Python calibration eliminates Bun.serve fetch, URL.port, SQLite migration, lock-clone, and *.test.py FPs", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-zd-cal-"));
  try {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "migrations"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "src", "server.ts"),
      [
        "export const srv = Bun.serve({",
        "  port: 0,",
        "  fetch(req: Request): Response { return new Response(new URL(req.url).port ? 'p' : 'd'); },",
        "});",
        "export async function bounded(url: string, init: RequestInit): Promise<Response> {",
        "  return fetch(url, init);",
        "}",
        "export function drainBatches(items: string[], batchSize: number): number {",
        "  let count = 0;",
        "  while (items.length > 0) { count += items.splice(0, batchSize).length; }",
        "  return count;",
        "}",
        "export function freshAbort(): AbortController { return new AbortController(); }",
      ].join("\n"),
    );
    fs.writeFileSync(
      path.join(dir, "src", "lock.rs"),
      "pub async fn read_val(m: &Mutex<String>) -> String { let v = m.lock().await.clone(); v }\n",
    );
    fs.writeFileSync(
      path.join(dir, "migrations", "001_init.sql"),
      "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT);\n",
    );
    fs.writeFileSync(
      path.join(dir, "src", "helper.test.py"),
      "def test_ok():\n    assert 1 + 1 == 2\n",
    );
    const report = scanRepo(dir);
    const rules = new Set(report.findings.map((f) => f.rule));
    assert.equal(rules.has("require-bounded-external-await"), false);
    assert.equal(rules.has("tiger-explicit-over-implicit"), false);
    assert.equal(rules.has("no-falsy-check-on-number"), false);
    assert.equal(rules.has("perf-quadratic-loop-scan"), false);
    assert.equal(rules.has("affine-unreleased-resource"), false);
    assert.equal(rules.has("rust-drop-under-lock-guard"), false);
    assert.equal(rules.has("db-migration-missing-lock-timeout"), false);
    assert.equal(rules.has("no-release-stripped-assert"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
