import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanGitDiffCheats } from "../../src/ci-auditor.ts";
import { scanRepo } from "../../src/ladder.ts";
import { runPlantedFaultCanary } from "../../src/rungs/mutation-probe.ts";
import { runTwoSidedOracleCheck } from "../../src/rungs/oracle-check.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");

function makeTempRepo(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-redteam-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  }
  return dir;
}

test("blocks Opus/Fable YAML comment + workflow_dispatch + if:false + echo + empty stub theater under scan and --strict", () => {
  const tmp = makeTempRepo({
    "package.json": JSON.stringify({
      name: "theater",
      devDependencies: { oxlint: "^1.0.0", "fast-check": "^3.0.0", veristack: "^0.1.5" },
    }),
    "tsconfig.json": JSON.stringify({ compilerOptions: { strict: true, noUnusedLocals: true } }),
    ".editorconfig": "root = true\n",
    ".oxlintrc.json": JSON.stringify({ rules: {} }),
    "lefthook.yml": "# empty hook\n",
    ".github/CODEOWNERS": "# empty\n",
    "stryker-config.json": "{}\n",
    "spec/model.tla": "-- empty\n",
    ".github/workflows/ci.yml": [
      "name: Theater",
      "on: workflow_dispatch",
      "concurrency:",
      "  group: theater",
      "  cancel-in-progress: true",
      "jobs:",
      "  fake:",
      "    if: false",
      "    timeout-minutes: 5",
      "    runs-on: ubuntu-latest",
      "    steps:",
      '      - run: echo "oxlint tsc knip vitest stryker quint k6 veristack"',
      "      # oxlint tsc knip vitest stryker quint k6 veristack",
    ].join("\n"),
    "src/math.ts": "export function add(a: number, b: number): number { return a - b; }\n",
    "tests/math.test.ts": [
      "import assert from 'node:assert/strict';",
      "import test from 'node:test';",
      "import fc from 'fast-check';",
      "import { add } from '../src/math.ts';",
      "test('empty commands', () => { const c = fc.commands([]); assert.equal(Array.isArray(c), true); assert.equal(add(2, 1), 1); });",
    ].join("\n"),
  });
  try {
    const report = scanRepo(tmp, { strict: true });
    assert.ok(report.summary.unexecutedRungCount >= 5);
    assert.equal(report.summary.wellCoveredCount, 0);

    const defaultCli = spawnSync(process.execPath, [binPath, "scan", tmp], { encoding: "utf8" });
    assert.equal(defaultCli.status, 1);

    const strictCli = spawnSync(process.execPath, [binPath, "scan", tmp, "--strict"], { encoding: "utf8" });
    assert.equal(strictCli.status, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("blocks scope hiding under --strict: .vstackignore, .vstack.json ignore, 2501-char JS minification, and src/vendor", () => {
  const ignoreRepo = makeTempRepo({
    ".vstackignore": "src/bad.ts\n",
    "src/bad.ts": "// hidden\nexport const x = (1 as any);\n",
  });
  const jsonIgnoreRepo = makeTempRepo({
    ".vstack.json": JSON.stringify({ ignore: ["src/bad.ts"] }),
    "src/bad.ts": "// hidden\nexport const x = (1 as any);\n",
  });
  const minifiedRepo = makeTempRepo({
    "src/padded.js": `export const pad = "${"a".repeat(2600)}";\n// prose\nexport function run(x) { return eval(x); }\n`,
  });
  const vendorRepo = makeTempRepo({
    "src/vendor/bad.ts": "// hidden in nested vendor\nexport function f(x: unknown) { return x as any; }\n",
  });

  try {
    const r1 = scanRepo(ignoreRepo, { strict: true });
    assert.ok(r1.scopeExclusions.some((e) => e.reason === "vstackignore" && e.path === "src/bad.ts"));
    assert.equal(spawnSync(process.execPath, [binPath, "scan", ignoreRepo, "--strict"], { encoding: "utf8" }).status, 1);

    const r2 = scanRepo(jsonIgnoreRepo, { strict: true });
    assert.ok(r2.scopeExclusions.some((e) => e.reason === "config-ignore"));
    assert.equal(spawnSync(process.execPath, [binPath, "scan", jsonIgnoreRepo, "--strict"], { encoding: "utf8" }).status, 1);

    const r3 = scanRepo(minifiedRepo, { strict: true });
    assert.ok(r3.scopeExclusions.some((e) => e.reason === "minified" && e.path === "src/padded.js"));
    assert.equal(spawnSync(process.execPath, [binPath, "scan", minifiedRepo, "--strict"], { encoding: "utf8" }).status, 1);

    const r4 = scanRepo(vendorRepo, { strict: true });
    assert.ok(r4.findings.some((f) => f.file === "src/vendor/bad.ts"));
  } finally {
    fs.rmSync(ignoreRepo, { recursive: true, force: true });
    fs.rmSync(jsonIgnoreRepo, { recursive: true, force: true });
    fs.rmSync(minifiedRepo, { recursive: true, force: true });
    fs.rmSync(vendorRepo, { recursive: true, force: true });
  }
});

test("blocks missing --ratchet auto-creation, declared library disguise on Express service, and reports package recommendations", () => {
  const tmp = makeTempRepo({
    "package.json": JSON.stringify({ dependencies: { express: "^5.0.0" } }),
    ".verification/rungs.json": JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: {} }),
    "src/server.ts": "import express from 'express';\nexport const app = express();\n",
  });
  try {
    const report = scanRepo(tmp);
    assert.ok(report.findings.some((f) => f.rule === "rung-archetype-mismatch"));

    const ratchetRes = spawnSync(
      process.execPath,
      [binPath, "scan", tmp, "--ratchet", path.join(tmp, "nonexistent.json")],
      { encoding: "utf8" },
    );
    assert.equal(ratchetRes.status, 1);
    assert.match(ratchetRes.stderr, /Refusing to auto-create/);

    const terminalRes = spawnSync(process.execPath, [binPath, "scan", tmp], { encoding: "utf8" });
    assert.equal(terminalRes.status, 1);
    assert.match(terminalRes.stdout, /Packages:.*typescript:/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("diff-cheats fails closed on bad git ref, catches deleted test file, and catches strict-to-weak assertion dilution", () => {
  const tmp = makeTempRepo({
    "src/calc.ts": "export function sum(a: number, b: number): number { return a + b; }\n",
    "tests/calc.test.ts": [
      "import assert from 'node:assert/strict';",
      "import test from 'node:test';",
      "import { sum } from '../src/calc.ts';",
      "test('sum', () => {",
      "  assert.equal(sum(1, 2), 3);",
      "  assert.equal(sum(2, 3), 5);",
      "  assert.equal(sum(0, 0), 0);",
      "});",
    ].join("\n"),
    "tests/extra.test.ts": "import assert from 'node:assert/strict';\nimport test from 'node:test';\ntest('ok', () => { assert.equal(1, 1); });\n",
  });
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "CI"], { cwd: tmp });
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    const badRefHits = scanGitDiffCheats(tmp, "nonexistent-ref-xyz");
    assert.ok(badRefHits.some((f) => f.rule === "diff-command-failed"));

    fs.rmSync(path.join(tmp, "tests/extra.test.ts"));
    fs.writeFileSync(
      path.join(tmp, "tests/calc.test.ts"),
      "import test from 'node:test';\nimport { sum } from '../src/calc.ts';\ntest('sum', () => { expect(sum(1, 2)).toBeDefined(); });\n",
    );
    const hits = scanGitDiffCheats(tmp, "HEAD");
    assert.ok(hits.some((f) => f.rule === "diff-test-file-deleted"));
    assert.ok(hits.some((f) => f.rule === "diff-assertion-deleted"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("planted-fault canary fails on theater tests and passes on real tests; two-sided oracle catches silent expectation rewrite", () => {
  const tmp = makeTempRepo({
    "src/guard.ts": "export function isAdult(age: number): boolean { return age >= 18; }\n",
    "tests/guard.test.ts": [
      "import assert from 'node:assert/strict';",
      "import test from 'node:test';",
      "import { isAdult } from '../src/guard.ts';",
      "test('boundary', () => {",
      "  assert.equal(isAdult(18), true);",
      "  assert.equal(isAdult(17), false);",
      "});",
    ].join("\n"),
  });
  try {
    const strong = runPlantedFaultCanary({
      repoRoot: tmp,
      testCmd: "bun test ./tests/guard.test.ts",
      targets: ["src/guard.ts"],
      maxMutants: 2,
      minKillRate: 1.0,
    });
    assert.equal(strong.passed, true);
    assert.equal(strong.killedMutants, 1);

    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "CI"], { cwd: tmp });
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "base"], { cwd: tmp });

    fs.writeFileSync(path.join(tmp, "src/guard.ts"), "export function isAdult(age: number): boolean { return age >= 21; }\n");
    fs.writeFileSync(
      path.join(tmp, "tests/guard.test.ts"),
      [
        "import assert from 'node:assert/strict';",
        "import test from 'node:test';",
        "import { isAdult } from '../src/guard.ts';",
        "test('boundary', () => {",
        "  assert.equal(isAdult(21), true);",
        "  assert.equal(isAdult(18), false);",
        "});",
      ].join("\n"),
    );
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "silent-rewrite"], { cwd: tmp });

    const oracle = runTwoSidedOracleCheck(tmp, "HEAD~1", "bun test ./tests/guard.test.ts");
    assert.equal(oracle.passed, false);
    assert.match(oracle.reason, /ORACLE REWRITE DETECTED/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
