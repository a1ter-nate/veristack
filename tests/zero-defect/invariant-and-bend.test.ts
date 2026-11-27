import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { auditDiffInvariantLoss, auditTsAstPredicateDrop, buildSyntheticRevertEvents } from "@veristack/plugin-lang-typescript";
import { scanGitDiffCheats } from "@veristack/plugin-ci-auditor";
import { discoverRepo } from "@veristack/core";
import { scanRepo } from "@veristack/core";
import { runPrecisionBench } from "@veristack/plugin-zero-defect";
import { compareInvariantSnapshots, inferDynamicInvariants } from "@veristack/plugin-zero-defect";
import { auditLaws } from "@veristack/plugin-laws-formal";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

test("7-language precision bench passes with 100% recall and zero clean or adversarial FPs", () => {
  const report = runPrecisionBench(repoRoot);
  assert.equal(report.passed, true, JSON.stringify(report.languages.filter((l) => l.missedRules.length > 0 || l.cleanFalsePositives.length > 0 || l.commentWrappedFps.length > 0 || l.stringWrappedFps.length > 0)));
  const langs = new Set(report.languages.map((l) => l.language));
  for (const expected of ["typescript", "csharp", "rust", "python", "go", "sql", "shell"]) {
    assert.ok(langs.has(expected), `missing bench language ${expected}`);
  }
  assert.equal(report.totalCleanFps, 0);
  assert.equal(report.totalAdversarialFps, 0);
});

test("Bend 2 paired LAWS.bend + PROOF.bend and .verification/laws manifest verify cleanly", () => {
  const repo = discoverRepo(repoRoot);
  const result = auditLaws(repo, { verify: false });
  assert.equal(result.findings.length, 0, JSON.stringify(result.findings));
  assert.ok(result.declaredLaws >= 12);
});

test("auditDiffInvariantLoss catches dropped null, bounds, cleanup, and error guards in diffs", () => {
  const afterSafe = [
    "export function load(input: string | null, items: string[]): string {",
    "  if (input === null) return '';",
    "  if (items.length === 0) return '';",
    "  return input.trim();",
    "}",
  ].join("\n");
  const beforeBuggy = [
    "export function load(input: string | null, items: string[]): string {",
    "  return input.trim();",
    "}",
  ].join("\n");

  const revertEvents = buildSyntheticRevertEvents("src/loader.ts", afterSafe, beforeBuggy);
  const hits = auditDiffInvariantLoss(revertEvents);
  assert.ok(hits.some((h) => h.rule === "diff-invariant-guard-dropped" && h.message.includes("null-nil-guard")));
  assert.ok(hits.some((h) => h.rule === "diff-invariant-guard-dropped" && h.message.includes("bounds-length-guard")));
});

test("scanGitDiffCheats detects when a commit silently removes a guard invariant", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-inv-diff-"));
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "CI"], { cwd: tmp });
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, "src/handler.go"),
      "package handler\nfunc sliceSuffix(s, p string) string {\n\tif len(s) > len(p) {\n\t\treturn s[len(p)+1:]\n\t}\n\treturn \"\"\n}\n",
    );
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    fs.writeFileSync(
      path.join(tmp, "src/handler.go"),
      "package handler\nfunc sliceSuffix(s, p string) string {\n\treturn s[len(p)+1:]\n}\n",
    );
    const hits = scanGitDiffCheats(tmp, "HEAD");
    assert.ok(hits.some((h) => h.rule === "diff-invariant-guard-dropped"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("AST control-flow and predicate-weakening diff catches dropped if-branch, stripped && clause, and relaxed bounds", () => {
  const safeTs = [
    "export function allow(a: number, b: number, limit: number): boolean {",
    "  if (a >= 0 && b <= limit) {",
    "    return true;",
    "  }",
    "  return false;",
    "}",
  ].join("\n");
  const weakenedTs = [
    "export function allow(a: number, b: number, limit: number): boolean {",
    "  if (a >= 0) {",
    "    return true;",
    "  }",
    "  return false;",
    "}",
  ].join("\n");

  const astHits = auditTsAstPredicateDrop("src/policy.ts", safeTs, weakenedTs);
  assert.ok(astHits.some((h) => h.message.includes("ast-logical-clause-stripped")));
  assert.ok(astHits.some((h) => h.message.includes("ast-comparison-bound-dropped")));

  const evs = buildSyntheticRevertEvents("src/policy.ts", safeTs, weakenedTs);
  const diffHits = auditDiffInvariantLoss(evs);
  assert.ok(diffHits.some((h) => h.rule === "diff-predicate-weakened"));

  const withTest = [
    ...evs,
    { file: "tests/policy.test.ts", line: 5, kind: "add" as const, raw: "expect(allow(1, 99, 10)).toBe(true);", code: "expect(allow(1, 99, 10)).toBe(true);" },
  ];
  assert.deepEqual(
    auditDiffInvariantLoss(withTest, { allowTestedPredicateRefactor: true }).filter((h) => h.rule === "diff-predicate-weakened"),
    [],
  );
});

test("repo-wide Engler deviant-behavior miner catches outlier null-check, cleanup, and route-auth omissions", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-deviant-"));
  try {
    const mk = (rel: string, content: string): void => {
      const full = path.join(tmp, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content, "utf8");
    };

    mk(
      "src/users.ts",
      [
        "export function a(id: string) { const u = findUser(id); if (!u) return ''; return u.name; }",
        "export function b(id: string) { const u = findUser(id); if (u === null) return ''; return u.name; }",
        "export function c(id: string) { const u = findUser(id); return u?.name ?? ''; }",
        "export function d(id: string) { const u = findUser(id); return u.name; }",
      ].join("\n"),
    );

    mk(
      "src/locks.ts",
      [
        "export function l1() { const g = acquireLease(); try { work(g); } finally { g.release(); } }",
        "export function l2() { const g = acquireLease(); try { work(g); } finally { g.release(); } }",
        "export function l3() { const g = acquireLease(); try { work(g); } finally { g.release(); } }",
        "export function l4() { const g = acquireLease(); work(g); g.release(); }",
      ].join("\n"),
    );

    mk("src/routes/orders.ts", "export function orders(req: unknown) { requireAuth(req); return 1; }\n");
    mk("src/routes/invoices.ts", "export function invoices(req: unknown) { requireAuth(req); return 2; }\n");
    mk("src/routes/billing.ts", "export function billing(req: unknown) { requireAuth(req); return 3; }\n");
    mk("src/routes/export.ts", "export function exportData() { return 4; }\n");

    const report = scanRepo(tmp);
    const rules = new Set(report.findings.map((f) => f.rule));
    assert.ok(rules.has("invariant-deviant-null-check"));
    assert.ok(rules.has("invariant-deviant-paired-cleanup"));
    assert.ok(rules.has("invariant-deviant-route-auth"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("Daikon-style dynamic invariant capture infers bounds/domain/sorted/relational invariants and catches violations", () => {
  const baseline = inferDynamicInvariants([
    { fn: "applyDiscount", args: { amount: 1000, pct: 10 }, result: 900, throws: false },
    { fn: "applyDiscount", args: { amount: 500, pct: 20 }, result: 400, throws: false },
    { fn: "applyDiscount", args: { amount: 200, pct: 0 }, result: 200, throws: false },
    { fn: "nextStatus", args: { ev: "pay" }, result: "paid", throws: false },
    { fn: "nextStatus", args: { ev: "ship" }, result: "shipped", throws: false },
    { fn: "nextStatus", args: { ev: "cancel" }, result: "cancelled", throws: false },
    { fn: "nextStatus", args: { ev: "pay" }, result: "paid", throws: false },
    { fn: "sortIds", args: { input: [3, 1, 2] }, result: [1, 2, 3], throws: false },
    { fn: "sortIds", args: { input: [9, 4] }, result: [4, 9], throws: false },
    { fn: "sortIds", args: { input: [5, 2, 8] }, result: [2, 5, 8], throws: false },
  ]);

  assert.ok(baseline.invariants.some((i) => i.fn === "applyDiscount" && i.kind === "relational-le-arg" && i.detail === "amount"));
  assert.ok(baseline.invariants.some((i) => i.fn === "applyDiscount" && i.kind === "non-negative-result"));
  assert.ok(baseline.invariants.some((i) => i.fn === "nextStatus" && i.kind === "enum-domain"));
  assert.ok(baseline.invariants.some((i) => i.fn === "sortIds" && i.kind === "sorted-numeric-array"));
  assert.ok(baseline.invariants.some((i) => i.fn === "sortIds" && i.kind === "length-le-arg-length" && i.detail === "input"));

  const regressed = inferDynamicInvariants([
    { fn: "applyDiscount", args: { amount: 1000, pct: 10 }, result: 1200, throws: false },
    { fn: "applyDiscount", args: { amount: 500, pct: 20 }, result: -5, throws: false },
    { fn: "applyDiscount", args: { amount: 200, pct: 0 }, result: 200, throws: true },
    { fn: "nextStatus", args: { ev: "pay" }, result: "paid", throws: false },
    { fn: "nextStatus", args: { ev: "ship" }, result: "corrupted", throws: false },
    { fn: "nextStatus", args: { ev: "cancel" }, result: "cancelled", throws: false },
    { fn: "nextStatus", args: { ev: "pay" }, result: "paid", throws: false },
    { fn: "sortIds", args: { input: [3, 1, 2] }, result: [3, 1, 2], throws: false },
    { fn: "sortIds", args: { input: [9, 4] }, result: [4, 9], throws: false },
    { fn: "sortIds", args: { input: [5, 2, 8] }, result: [2, 5, 8], throws: false },
  ]);

  const diff = compareInvariantSnapshots(baseline, regressed);
  assert.equal(diff.passed, false);
  assert.ok(diff.violations.some((v) => v.message.includes("relational-le-arg")));
  assert.ok(diff.violations.some((v) => v.message.includes("non-negative-result")));
  assert.ok(diff.violations.some((v) => v.message.includes("never-throws")));
  assert.ok(diff.violations.some((v) => v.message.includes("enum-domain")));
  assert.ok(diff.violations.some((v) => v.message.includes("sorted-numeric-array")));
});
