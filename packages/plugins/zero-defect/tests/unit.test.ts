import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanRepo } from "@veristack/core";
import { analyzeGunawiCloudGuards, compareTemporalProtocols, extractLdfiMinimalCutSets, mineTemporalProtocols } from "@veristack/plugin-zero-defect";

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

test("Ammons temporal protocol mining, Alvaro LDFI cut-sets, and Gunawi cloud guards detect violations cleanly", () => {
  const baseline = mineTemporalProtocols([
    { traceId: "t1", events: ["open", "auth", "commit", "close"] },
    { traceId: "t2", events: ["open", "auth", "commit", "close"] },
    { traceId: "t3", events: ["open", "auth", "commit", "close"] },
  ]);
  assert.ok(baseline.rules.some((r) => r.kind === "always-precedes" && r.first === "auth" && r.second === "commit"));
  assert.ok(baseline.rules.some((r) => r.kind === "always-pairs" && r.first === "open" && r.second === "close"));
  const brokenDiff = compareTemporalProtocols(baseline, [{ traceId: "bad", events: ["open", "commit"] }]);
  assert.equal(brokenDiff.passed, false);
  assert.equal(brokenDiff.violations[0]?.rule, "temporal-protocol-violated");

  const cuts = extractLdfiMinimalCutSets({
    flows: [
      { id: "checkout", ioDependencies: ["pg", "stripe"] },
      { id: "refund", ioDependencies: ["pg", "stripe"] },
      { id: "notify", ioDependencies: ["resend"] },
    ],
  }, 2);
  assert.equal(cuts[0]?.blastRadius, 3);

  const cloudBad = analyzeGunawiCloudGuards({
    rel: "src/cloud.ts", abs: "/tmp/src/cloud.ts", language: "typescript", isTest: false, isWorkflow: false, lines: 8,
    content: [
      "export async function retryCharge(amt: number): Promise<void> { await billing.charge(amt); }",
      "export async function loadUsers(): Promise<unknown[]> { const res = await api.list({ limit: 100 }); return res.items; }",
      "export async function callPeer(): Promise<unknown> { return rpcClient.getUser({ id: '1' }); }",
    ].join("\n"),
  });
  const rules = new Set(cloudBad.map((f) => f.rule));
  assert.equal(rules.has("cloud-non-idempotent-recovery"), true);
  assert.equal(rules.has("cloud-silent-limit-truncation"), true);
  assert.equal(rules.has("cloud-rpc-missing-timeout"), true);
});

test("audit round 4 calibration: IPv6 error msg, table-driven loops, dedup clock smells, injected spawn, batched Promise.all, and double-escaped regex literal", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-round4-cal-"));
  try {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "src", "clean.ts"),
      [
        'import type { ChildProcess } from "node:child_process";',
        "export function formatDiag(url: URL): Error {",
        "  return new Error(`Bad host ${url.hostname}: unsupported`);",
        "}",
        "export function launch(spawn: (c: string) => ChildProcess, cmd: string): ChildProcess {",
        "  return spawn(cmd);",
        "}",
        "export async function fetchBatched(urls: string[]): Promise<Response[]> {",
        "  const out: Response[] = [];",
        "  for (let i = 0; i < urls.length; i += 4) {",
        "    const batch = urls.slice(i, i + 4);",
        "    const res = await Promise.all(batch.map((u) => fetch(u, { signal: AbortSignal.timeout(5000) })));",
        "    out.push(...res);",
        "  }",
        "  return out;",
        "}",
      ].join("\n"),
    );
    fs.writeFileSync(
      path.join(dir, "src", "bad-regex.ts"),
      "export function stripBrackets(host: string): string { return host.replace(/^\\\\[|\\\\]$/gu, ''); }\n",
    );
    fs.writeFileSync(
      path.join(dir, "tests", "table.test.ts"),
      [
        'import { test, expect } from "vitest";',
        "const CASES = [{ name: 'a', v: 1 }];",
        "for (const row of CASES) {",
        "  test(`case ${row.name}`, () => {",
        "    const claims = { exp: Math.floor(Date.now() / 1000) + 60 };",
        "    expect(claims.exp).toBeGreaterThan(0);",
        "  });",
        "}",
        "test('elapsed dedup', () => {",
        "  const t0 = Date.now();",
        "  expect(Date.now() - t0).toBeLessThan(1000);",
        "});",
      ].join("\n"),
    );
    const report = scanRepo(dir);
    const cleanRules = new Set(report.findings.filter((f) => f.file === "src/clean.ts").map((f) => f.rule));
    assert.equal(cleanRules.has("http-ipv6-unbracketed-host-header"), false);
    assert.equal(cleanRules.has("agent-subprocess-missing-error-handler"), false);
    assert.equal(cleanRules.has("perf-nplus1-io-in-loop"), false);
    assert.equal(report.findings.some((f) => f.file === "src/bad-regex.ts" && f.rule === "regex-double-escaped-literal"), true);
    const testFindings = report.findings.filter((f) => f.file === "tests/table.test.ts");
    assert.equal(testFindings.some((f) => f.rule === "test-no-test-in-loop"), false);
    assert.equal(testFindings.some((f) => f.line === 5 && f.rule === "no-test-nondeterminism"), false);
    assert.equal(testFindings.filter((f) => f.line === 11 && (f.rule === "no-elapsed-time-bound" || f.rule === "no-test-nondeterminism")).length <= 1, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
