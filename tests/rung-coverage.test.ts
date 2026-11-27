import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanRepo } from "@veristack/core";
import { buildRatchetBaseline, evaluateRatchet } from "@veristack/core";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");

function makeTempRepo(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-rungs-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  }
  return dir;
}

test("default vstack scan exits 1 when rungs are missing or not running in CI, and --strict rejects --allow-missing-rungs", () => {
  const tmp = makeTempRepo({
    "package.json": JSON.stringify({ name: "bare-lib", version: "1.0.0" }),
    "tsconfig.json": JSON.stringify({ compilerOptions: { strict: true } }),
    "src/math.ts": "export function add(a: number, b: number): number { return a + b; }\n",
  });
  try {
    const defaultScan = spawnSync(process.execPath, [binPath, "scan", tmp], { encoding: "utf8" });
    assert.equal(defaultScan.status, 1);
    assert.match(defaultScan.stdout, /NOT-COVERED/);
    assert.match(defaultScan.stderr, /FAIL:/);

    const allowedScan = spawnSync(process.execPath, [binPath, "scan", tmp, "--allow-missing-rungs"], {
      encoding: "utf8",
    });
    assert.equal(allowedScan.status, 0, allowedScan.stdout + allowedScan.stderr);

    const strictAllowed = spawnSync(
      process.execPath,
      [binPath, "scan", tmp, "--strict", "--allow-missing-rungs"],
      { encoding: "utf8" },
    );
    assert.equal(strictAllowed.status, 1);
    assert.match(strictAllowed.stderr, /forbids --allow-missing-rungs/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("tools installed locally WITHOUT CI workflow execution fail scan and cap coverage at poorly-covered (<= 50%)", () => {
  const tmp = makeTempRepo({
    "package.json": JSON.stringify({
      name: "no-ci-lib",
      devDependencies: {
        oxlint: "^1.0.0",
        veristack: "^0.1.4",
        "fast-check": "^3.0.0",
        "@stryker-mutator/core": "^8.0.0",
        k6: "^0.1.0",
      },
    }),
    ".editorconfig": "root = true\n",
    ".oxlintrc.json": JSON.stringify({ rules: {} }),
    "lefthook.yml": "pre-commit:\n  commands:\n    lint:\n      run: oxlint\n",
    ".github/CODEOWNERS": "* @owner\n",
    "tsconfig.json": JSON.stringify({ compilerOptions: { strict: true, noUnusedLocals: true } }),
    "src/calc.ts": "export function doubleVal(x: number): number { return x * 2; }\n",
    "tests/calc.test.ts": [
      "import assert from 'node:assert/strict';",
      "import test from 'node:test';",
      "import fc from 'fast-check';",
      "import { doubleVal } from '../src/calc.ts';",
      "test('doubles', () => { fc.assert(fc.property(fc.integer(), (n) => doubleVal(n) === n * 2)); assert.equal(doubleVal(2), 4); });",
    ].join("\n"),
    "spec/model.qnt": "module model { var x: int }\n",
    "stryker-config.json": "{}\n",
  });
  try {
    const report = scanRepo(tmp);
    const r0 = report.rungs.find((r) => r.rung === "R0");
    const r2 = report.rungs.find((r) => r.rung === "R2");
    const r5 = report.rungs.find((r) => r.rung === "R5");
    assert.ok(r0 && r2 && r5);
    assert.equal(r0.executedInCi, false);
    assert.equal(r0.coverageGrade, "poorly-covered");
    assert.ok(r0.coverageScore <= 50);
    assert.equal(r2.executedInCi, false);
    assert.equal(r2.coverageGrade, "poorly-covered");
    assert.equal(r5.executedInCi, false);
    assert.equal(r5.coverageGrade, "poorly-covered");
    assert.ok(report.summary.unexecutedRungCount >= 4);

    const cli = spawnSync(process.execPath, [binPath, "scan", tmp], { encoding: "utf8" });
    assert.equal(cli.status, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("mentioning tools in markdown docs or prod string literals does NOT credit any rung", () => {
  const tmp = makeTempRepo({
    "package.json": JSON.stringify({ dependencies: { express: "^5.0.0" } }),
    "README.md":
      "We plan to use fast-check, stryker, Quint, TLA+, k6, Testcontainers, Playwright, and OpenTelemetry.\n",
    "AGENTS.md": "Always run oxlint, prettier, knip, deslop-please, and bombadil.\n",
    "src/strings.ts": [
      "export const tools = [",
      "  'stryker', 'k6', 'fast-check', 'Testcontainers', 'opentelemetry', 'toHaveScreenshot', 'quint',",
      "];",
    ].join("\n"),
  });
  try {
    const report = scanRepo(tmp);
    assert.equal(report.archetype, "service");
    for (const rungId of ["R0", "R2", "R3", "R4", "R5", "R6", "R7", "R8"] as const) {
      const rung = report.rungs.find((r) => r.rung === rungId);
      assert.ok(rung);
      assert.equal(rung.coverageGrade, "not-covered", `${rungId} should be not-covered`);
      assert.equal(rung.coverageScore, 0, `${rungId} should have 0 score`);
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("frontend archetype marks R4 not-applicable and R6/R7/R8 not-covered when absent (no silent covered bug)", () => {
  const tmp = makeTempRepo({
    "package.json": JSON.stringify({ dependencies: { react: "^19.0.0" } }),
    "src/App.tsx": "export function App() { return <div>Hello</div>; }\n",
  });
  try {
    const report = scanRepo(tmp);
    assert.equal(report.archetype, "frontend");
    const r4 = report.rungs.find((r) => r.rung === "R4");
    const r6 = report.rungs.find((r) => r.rung === "R6");
    const r7 = report.rungs.find((r) => r.rung === "R7");
    const r8 = report.rungs.find((r) => r.rung === "R8");
    assert.ok(r4 && r6 && r7 && r8);
    assert.equal(r4.coverageGrade, "not-applicable");
    assert.equal(r6.coverageGrade, "not-covered");
    assert.equal(r7.coverageGrade, "not-covered");
    assert.equal(r8.coverageGrade, "not-covered");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("ratchet detects rung coverage regressions and dropped CI execution", () => {
  const full = scanRepo(repoRoot);
  const baseline = buildRatchetBaseline(full.findings, full.rungs);
  const degradedRungs = full.rungs.map((r) =>
    r.rung === "R6" ? { ...r, coverageGrade: "not-covered" as const, coverageScore: 0, executedInCi: false } : r,
  );
  const evalResult = evaluateRatchet(full.findings, baseline, degradedRungs);
  assert.equal(evalResult.passed, false);
  assert.equal(evalResult.rungRegressions.length, 1);
  assert.equal(evalResult.rungRegressions[0]?.rung, "R6");
});
