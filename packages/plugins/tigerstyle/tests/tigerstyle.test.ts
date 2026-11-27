import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import { discoverRepo } from "@veristack/core";
import { formatMarkdownReport as formatMarkdown, formatTerminalReport as formatTerminal } from "@veristack/core";
import { scanRepo } from "@veristack/core";
import { evaluateRatchet, type RatchetBaseline } from "@veristack/core";
import { countDirectRuntimeDependencies } from "@veristack/plugin-tigerstyle";

function makeTempRepo(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-tiger-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  }
  return dir;
}

describe("TigerStyle strict rules & Effect v4 integration", () => {
  test("catches core TS/JS TigerStyle violations (assertions, recursion, bounds, length, nesting, naming, interfaces, explicit)", () => {
    const longBody = Array.from({ length: 74 }, (_, i) => `  const v${i} = x + ${i};`).join("\n");
    const repo = makeTempRepo({
      "package.json": JSON.stringify({ name: "demo-lib", version: "1.0.0", dependencies: {} }),
      "src/violations.ts": [
        `export function badAssertions(x: number) {`,
        `  console.assert(x > 0, "positive");`,
        `  return x;`,
        `}`,
        `export function recurse(n: number): number {`,
        `  if (n <= 0) return 0;`,
        `  return recurse(n - 1) + 1;`,
        `}`,
        `export function unboundedLoop(items: number[]) {`,
        `  while (true) {`,
        `    if (items.length === 0) break;`,
        `    items.pop();`,
        `  }`,
        `}`,
        `export function deepNest(a: boolean, b: boolean, c: boolean, d: boolean) {`,
        `  if (a) { if (b) { if (c) { if (d) { if (a && b) return 1; } } } }`,
        `  return 0;`,
        `}`,
        `export function wideSig(a: number, b: number, c: number, d: number, e: number) {`,
        `  return a + b + c + d + e;`,
        `}`,
        `export function badNaming(timeout: number, start: number, finish: number) {`,
        `  const maxLatencyMs = timeout;`,
        `  const usrAcct = start + finish;`,
        `  return maxLatencyMs + usrAcct;`,
        `}`,
        `export async function implicitFetch(url: string) {`,
        `  return fetch(url);`,
        `}`,
        `export function tooLong(x: number) {`,
        longBody,
        `  return v0 + v73;`,
        `}`,
      ].join("\n"),
    });
    try {
      const report = scanRepo(repo);
      const rules = new Set(report.findings.map((f) => f.rule));
      assert.equal(rules.has("tiger-non-halting-assert"), true);
      assert.equal(rules.has("tiger-no-recursion"), true);
      assert.equal(rules.has("tiger-unbounded-loop"), true);
      assert.equal(rules.has("tiger-push-ifs-up-fors-down"), true);
      assert.equal(rules.has("tiger-interface-surface"), true);
      assert.equal(rules.has("tiger-big-endian-naming"), true);
      assert.equal(rules.has("tiger-explicit-over-implicit"), true);
      assert.equal(rules.has("tiger-function-length"), true);
      assert.equal(rules.has("tiger-low-assertion-density"), true);
      assert.ok(report.tigerStyle);
      assert.equal((report.tigerStyle?.overallScore ?? 100) < 100, true);
      const term = formatTerminal(report);
      const md = formatMarkdown(report);
      assert.equal(term.includes("TIGERSTYLE COVERAGE"), true);
      assert.equal(md.includes("## TigerStyle Coverage"), true);
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });

  test("enforces all Effect v4 TigerStyle rules and passes clean Effect v4 code", () => {
    const badRepo = makeTempRepo({
      "package.json": JSON.stringify({ name: "eff-svc", version: "1.0.0", dependencies: { effect: "^4.0.0" } }),
      "src/worker.ts": [
        `import { Effect, Layer, ManagedRuntime, Queue, Schedule, ServiceMap } from "effect";`,
        `class InvariantError extends Error {}`,
        `export const badQueue = Queue.unbounded<string>();`,
        `export const badConc = (items: string[]) => Effect.forEach(items, (x) => Effect.succeed(x), { concurrency: "unbounded" });`,
        `export const badRetry = (eff: Effect.Effect<void, Error>) => Effect.retry(eff, Schedule.exponential("100 millis"));`,
        `export const badAssert = (ok: boolean) => ok ? Effect.void : Effect.fail(new InvariantError("broken"));`,
        `export const badHandler = (items: string[]) => Effect.forEach(items, () => Effect.sync(() => ManagedRuntime.make(Layer.empty)), { concurrency: 4 });`,
        `export class HugeService extends ServiceMap.Service<HugeService, {`,
        `  a(): void; b(): void; c(): void; d(): void; e(): void; f(): void; g(): void; h(): void; i(): void;`,
        `}>()("HugeService", {`,
        `  a: () => {}, b: () => {}, c: () => {}, d: () => {}, e: () => {}, f: () => {}, g: () => {}, h: () => {}, i: () => {},`,
        `}) {}`,
      ].join("\n"),
    });
    const cleanRepo = makeTempRepo({
      "package.json": JSON.stringify({ name: "eff-clean", version: "1.0.0", dependencies: { effect: "^4.0.0" } }),
      "src/worker.ts": [
        `import { Duration, Effect, Queue, Schedule, ServiceMap } from "effect";`,
        `const CONCURRENCY_MAX = 8;`,
        `const QUEUE_CAPACITY_MAX = 64;`,
        `const RETRY_COUNT_MAX = 3;`,
        `export const boundedQueue = Queue.bounded<string>(QUEUE_CAPACITY_MAX);`,
        `export const boundedBatch = (items: readonly string[]) => Effect.forEach(items, (x) => Effect.succeed(x), { concurrency: CONCURRENCY_MAX });`,
        `export const boundedRetry = (eff: Effect.Effect<void, Error>) => Effect.retry(eff, Schedule.intersect(Schedule.exponential(Duration.millis(50)), Schedule.recurs(RETRY_COUNT_MAX)));`,
        `export const fatalAssert = (ok: boolean) => (ok ? Effect.void : Effect.dieMessage("invariant violated"));`,
        `export class SmallService extends ServiceMap.Service<SmallService, { ping(): Effect.Effect<void> }>()("SmallService", {`,
        `  ping: () => Effect.void,`,
        `}) {}`,
      ].join("\n"),
      "tests/worker.test.ts": [
        `import { TestClock, TestRandom } from "effect";`,
        `export const dstProof = [TestClock, TestRandom];`,
      ].join("\n"),
    });
    try {
      const badReport = scanRepo(badRepo);
      const badRules = new Set(badReport.findings.map((f) => f.rule));
      assert.equal(badRules.has("tiger-unbounded-queue"), true);
      assert.equal(badRules.has("effect-unbounded-concurrency"), true);
      assert.equal(badRules.has("effect-uncapped-retry-schedule"), true);
      assert.equal(badRules.has("effect-assertion-as-typed-error"), true);
      assert.equal(badRules.has("effect-runtime-alloc-in-handler"), true);
      assert.equal(badRules.has("effect-large-service-interface"), true);

      const cleanReport = scanRepo(cleanRepo);
      const tigerFindings = cleanReport.findings.filter((f) => f.rule.startsWith("tiger-") || f.rule.startsWith("effect-"));
      assert.deepEqual(tigerFindings, []);
      const ts14 = cleanReport.tigerStyle?.principles.find((p) => p.id === "TS-14");
      assert.equal(ts14?.grade === "strong" || ts14?.grade === "not-applicable", true);
    } finally {
      fs.rmSync(badRepo, { recursive: true, force: true });
      fs.rmSync(cleanRepo, { recursive: true, force: true });
    }
  });

  test("catches SQL, Shell, Rust, Go, C#, Python TigerStyle rules and respects SAFETY directive", () => {
    const repo = makeTempRepo({
      "package.json": JSON.stringify({ name: "poly-lib", version: "1.0.0", dependencies: {} }),
      "db/schema.sql": [
        `CREATE TABLE invoices (id INT, amount_usd FLOAT, approved_at TIMESTAMP, rejected_at TIMESTAMP, cancelled_at TIMESTAMP);`,
        `WITH RECURSIVE tree AS (SELECT id FROM nodes UNION ALL SELECT n.id FROM nodes n JOIN tree t ON n.parent = t.id) SELECT * FROM tree;`,
        `DECLARE cur CURSOR FOR SELECT id FROM invoices;`,
      ].join("\n"),
      "scripts/fetch.sh": [
        `#!/usr/bin/env bash`,
        `curl https://example.com/api`,
        `while true; do`,
        `  echo "spin"`,
        `done`,
      ].join("\n"),
      "src/core.rs": [
        `#[derive(Serialize)]`,
        `pub struct WireFrame { pub len: usize }`,
        `pub fn run_work(items: &[u32]) {`,
        `  let (tx, _rx) = mpsc::channel();`,
        `  for x in items { let v = Vec::new(); let _ = (tx.send(x), v); }`,
        `}`,
      ].join("\n"),
      "src/safe_loop.ts": [
        `export function guardedLoop(queue: number[]): number {`,
        `  let total = 0;`,
        `  // SAFETY: drains bounded input array strictly decreasing length each step`,
        `  while (true) {`,
        `    const next = queue.pop();`,
        `    if (next === undefined) break;`,
        `    total += next;`,
        `  }`,
        `  return total;`,
        `}`,
      ].join("\n"),
    });
    try {
      const report = scanRepo(repo);
      const rules = new Set(report.findings.map((f) => f.rule));
      assert.equal(rules.has("tiger-fixed-width-types"), true);
      assert.equal(rules.has("tiger-no-recursion"), true);
      assert.equal(rules.has("tiger-explicit-over-implicit"), true);
      assert.equal(rules.has("tiger-push-ifs-up-fors-down"), true);
      assert.equal(rules.has("tiger-interface-surface"), true);
      assert.equal(rules.has("tiger-unbounded-queue"), true);
      assert.equal(rules.has("tiger-hot-path-allocation"), true);
      assert.equal(rules.has("tiger-unbounded-loop"), true);
      const safeLoopHits = report.findings.filter((f) => f.file === "src/safe_loop.ts" && f.rule === "tiger-unbounded-loop");
      assert.deepEqual(safeLoopHits, []);
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });

  test("ratchets direct runtime dependency count monotonically and caps bloated manifests", () => {
    const bloatedDeps = Object.fromEntries(Array.from({ length: 25 }, (_, i) => [`dep-${i}`, "1.0.0"]));
    const repo = makeTempRepo({
      "package.json": JSON.stringify({ name: "bloated-lib", version: "1.0.0", dependencies: bloatedDeps }),
      "src/index.ts": `export const ok = 1;\n`,
    });
    try {
      const report = scanRepo(repo);
      assert.equal(report.findings.some((f) => f.rule === "tiger-minimal-dependencies"), true);
      const baseline: RatchetBaseline = {
        version: 1,
        rules: {},
        dependenciesCount: 3,
      };
      const evalRes = evaluateRatchet(report.findings, baseline, report.rungs, 5);
      assert.equal(evalRes.passed, false);
      assert.equal(evalRes.regressions.some((r) => r.rule === "tiger-minimal-dependencies"), true);
      assert.equal(countDirectRuntimeDependencies(discoverRepo(repo)).count, 25);
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });
});
