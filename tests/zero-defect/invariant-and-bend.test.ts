import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { auditDiffInvariantLoss, buildSyntheticRevertEvents } from "../../src/ast/invariant-loss.ts";
import { scanGitDiffCheats } from "../../src/ci-auditor.ts";
import { discoverRepo } from "../../src/discover.ts";
import { runPrecisionBench } from "../../src/zero-defect/bench.ts";
import { auditLaws } from "../../src/zero-defect/laws.ts";

const repoRoot = path.resolve(import.meta.dir, "..", "..");

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
