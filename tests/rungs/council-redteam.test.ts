import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanGitDiffCheats } from "../../src/ci-auditor.ts";
import { discoverRepo } from "../../src/discover.ts";
import { scanRepo } from "../../src/ladder.ts";
import { loadRungManifest } from "../../src/rungs/manifest.ts";
import { runPlantedFaultCanary } from "../../src/rungs/mutation-probe.ts";
import { runTwoSidedOracleCheck } from "../../src/rungs/oracle-check.ts";
import { computeRepoTreeHash } from "../../src/rungs/receipts.ts";
import { parseStructuredReports, reportParsers } from "../../src/rungs/reports.ts";
import { auditCodeownersPerimeter, parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";

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

test("blocks YAML comment, workflow_dispatch, if:false, if:'false', paths filter, dead needs, exit 0, and || echo theater", () => {
  const cases = [
    'name: A\non: workflow_dispatch\njobs:\n  j:\n    steps:\n      - run: bun test\n',
    'name: B\non: [pull_request]\njobs:\n  j:\n    if: "false"\n    steps:\n      - run: bun test\n',
    'name: C\non:\n  pull_request:\n    paths: ["docs/**"]\njobs:\n  j:\n    steps:\n      - run: bun test\n',
    'name: D\non: [pull_request]\njobs:\n  gate:\n    if: false\n    steps:\n      - run: bun test\n  downstream:\n    needs: gate\n    steps:\n      - run: bun test\n',
    'name: E\non: [pull_request]\njobs:\n  j:\n    steps:\n      - run: |\n          exit 0\n          bun test\n',
    'name: F\non: [pull_request]\njobs:\n  j:\n    steps:\n      - run: bun test || echo ok\n',
    'name: G\non: [pull_request]\njobs:\n  j:\n    steps:\n      - run: ": bun test"\n',
  ];
  for (const wf of cases) {
    const info = parseGitHubWorkflow({
      rel: ".github/workflows/t.yml",
      abs: "/virtual/.github/workflows/t.yml",
      isTest: false,
      isWorkflow: true,
      content: wf,
      lines: 10,
    });
    assert.equal(info.isPrBlocking && info.activeCommands.length > 0, false, `Should reject theater workflow:\n${wf}`);
  }
});

test("rejects no-op rung commands, dangerous allowExcluded globs, and git diff --quiet canary cheat", () => {
  const tmp = makeTempRepo({
    ".verification/rungs.json": JSON.stringify({
      schemaVersion: 1,
      archetype: "library",
      rungs: { R0: { command: "true" } },
    }),
  });
  const badAllow = makeTempRepo({
    ".verification/rungs.json": JSON.stringify({
      schemaVersion: 1,
      archetype: "library",
      allowExcluded: ["**"],
      rungs: {},
    }),
  });
  const canaryRepo = makeTempRepo({
    "src/guard.ts": "export function isAdult(age: number): boolean { return age >= 18; }\n",
  });
  try {
    assert.match(loadRungManifest(tmp).error ?? "", /no-op|swallows/);
    assert.match(loadRungManifest(badAllow).error ?? "", /too broad/);

    const diffCheat = runPlantedFaultCanary({
      repoRoot: canaryRepo,
      testCmd: "git diff --quiet",
      targets: ["src/guard.ts"],
      maxMutants: 2,
      minKillRate: 0.8,
    });
    assert.equal(diffCheat.passed, false);

    const hashCheat = runPlantedFaultCanary({
      repoRoot: canaryRepo,
      testCmd: "node -e \"const fs=require('fs'); process.exit(fs.readFileSync('src/guard.ts','utf8').endsWith('\\n\\n')?1:0)\"",
      targets: ["src/guard.ts"],
      maxMutants: 2,
      minKillRate: 0.8,
    });
    assert.equal(hashCheat.passed, false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
    fs.rmSync(badAllow, { recursive: true, force: true });
    fs.rmSync(canaryRepo, { recursive: true, force: true });
  }
});

test("blocks scope hiding under --strict: .vstackignore, .vstack.json ignore, 2501-char JS minification, symlinks, and git-tracked bin/coverage", () => {
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
  const trackedDirsRepo = makeTempRepo({
    "bin/cli.mjs": "// hidden in bin\nexport function f(x) { return eval(x); }\n",
    "src/coverage/bad.ts": "// hidden in coverage\nexport function g(x: unknown) { return x as any; }\n",
  });
  spawnSync("git", ["init", "-q"], { cwd: trackedDirsRepo });
  spawnSync("git", ["add", "."], { cwd: trackedDirsRepo });
  fs.symlinkSync(path.join(trackedDirsRepo, "bin/cli.mjs"), path.join(trackedDirsRepo, "src/sym.mjs"));

  try {
    assert.ok(scanRepo(ignoreRepo, { strict: true }).scopeExclusions.some((e) => e.reason === "vstackignore"));
    assert.equal(spawnSync(process.execPath, [binPath, "scan", ignoreRepo, "--strict"], { encoding: "utf8" }).status, 1);

    assert.ok(scanRepo(jsonIgnoreRepo, { strict: true }).scopeExclusions.some((e) => e.reason === "config-ignore"));
    assert.equal(spawnSync(process.execPath, [binPath, "scan", jsonIgnoreRepo, "--strict"], { encoding: "utf8" }).status, 1);

    assert.ok(scanRepo(minifiedRepo, { strict: true }).scopeExclusions.some((e) => e.reason === "minified"));
    assert.equal(spawnSync(process.execPath, [binPath, "scan", minifiedRepo, "--strict"], { encoding: "utf8" }).status, 1);

    const trackedScan = scanRepo(trackedDirsRepo, { strict: true });
    assert.ok(trackedScan.findings.some((f) => f.file === "bin/cli.mjs"));
    assert.ok(trackedScan.findings.some((f) => f.file === "src/coverage/bad.ts"));
    assert.ok(trackedScan.scopeExclusions.some((e) => e.reason === "symlink" && e.path === "src/sym.mjs"));
  } finally {
    fs.rmSync(ignoreRepo, { recursive: true, force: true });
    fs.rmSync(jsonIgnoreRepo, { recursive: true, force: true });
    fs.rmSync(minifiedRepo, { recursive: true, force: true });
    fs.rmSync(trackedDirsRepo, { recursive: true, force: true });
  }
});

test("enforces GitHub CODEOWNERS locations, last-match-wins un-owning, and Bun.serve archetype detection", () => {
  const badLoc = makeTempRepo({
    "src/CODEOWNERS": "* @owner\n",
  });
  const unowned = makeTempRepo({
    ".github/CODEOWNERS": "* @owner\n/.verification/\n",
  });
  const bunServer = makeTempRepo({
    ".verification/rungs.json": JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: {} }),
    "src/server.ts": "export const s = Bun.serve({ port: 3000, fetch() { return new Response('ok'); } });\n",
  });
  try {
    const rBadLoc = discoverRepo(badLoc);
    assert.equal(auditCodeownersPerimeter(rBadLoc.files, rBadLoc.allRelPaths).passed, false);

    const rUnowned = discoverRepo(unowned);
    assert.equal(auditCodeownersPerimeter(rUnowned.files, rUnowned.allRelPaths).passed, false);

    const rSrv = scanRepo(bunServer);
    assert.equal(rSrv.archetype, "library");
    assert.ok(rSrv.findings.some((f) => f.rule === "rung-archetype-mismatch"));
  } finally {
    fs.rmSync(badLoc, { recursive: true, force: true });
    fs.rmSync(unowned, { recursive: true, force: true });
    fs.rmSync(bunServer, { recursive: true, force: true });
  }
});

test("refuses git-tracked receipts and hashes lockfiles into computeRepoTreeHash", () => {
  const tmp = makeTempRepo({
    "src/a.ts": "export const a = 1;\n",
    "bun.lock": "v1\n",
    ".verification/receipts/R0.json": '{"schemaVersion":1,"rung":"R0"}\n',
  });
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["add", "."], { cwd: tmp });
    const scan = scanRepo(tmp);
    assert.ok(scan.findings.some((f) => f.rule === "receipt-committed-to-git"));

    const h1 = computeRepoTreeHash(discoverRepo(tmp));
    fs.writeFileSync(path.join(tmp, "bun.lock"), "v2\n");
    const h2 = computeRepoTreeHash(discoverRepo(tmp));
    assert.notEqual(h1, h2);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("diff-cheats fails closed on bad git ref, catches deleted test file and strict-to-weak dilution; oracle-check catches working-tree rewrite & blanket waiver", () => {
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
    "tests/extra.test.ts": "import assert from 'node:assert/strict';\nimport test from 'node:test';\ntest('ok', () => { assert.equal(1, 1); });\n",
  });
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "CI"], { cwd: tmp });
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "base"], { cwd: tmp });

    assert.ok(scanGitDiffCheats(tmp, "nonexistent-ref-xyz").some((f) => f.rule === "diff-command-failed"));
    assert.equal(runTwoSidedOracleCheck(tmp, "nonexistent-ref-xyz", "true").passed, false);

    fs.writeFileSync(path.join(tmp, "src/guard.ts"), "export function isAdult(age: number): boolean { return age >= 21; }\n");
    fs.writeFileSync(
      path.join(tmp, "tests/guard.test.ts"),
      "import assert from 'node:assert/strict';\nimport test from 'node:test';\nimport { isAdult } from '../src/guard.ts';\ntest('boundary', () => { assert.equal(isAdult(21), true); assert.equal(isAdult(18), false); });\n",
    );
    fs.mkdirSync(path.join(tmp, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".verification/behavior-changes.json"), JSON.stringify({ changes: [{ why: "self-waiver" }] }));

    const wtOracle = runTwoSidedOracleCheck(tmp, "HEAD", "bun test ./tests/guard.test.ts");
    assert.equal(wtOracle.passed, false);
    assert.match(wtOracle.reason, /ORACLE REWRITE DETECTED/);

    fs.rmSync(path.join(tmp, "tests/extra.test.ts"));
    fs.writeFileSync(
      path.join(tmp, "tests/guard.test.ts"),
      "import test from 'node:test';\nimport { isAdult } from '../src/guard.ts';\ntest('boundary', () => { expect(isAdult(21)).toBeDefined(); });\n",
    );
    const hits = scanGitDiffCheats(tmp, "HEAD");
    assert.ok(hits.some((f) => f.rule === "diff-test-file-deleted"));
    assert.ok(hits.some((f) => f.rule === "diff-assertion-deleted"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("parseStructuredReports loads LCOV, Stryker, and JUnit and ignores non-finite Cobertura rates; array needs propagates dead jobs", () => {
  const tmp = makeTempRepo({
    "coverage/lcov.info": "SF:src/a.ts\nDA:1,1\nDA:2,0\nend_of_record\n",
    "reports/mutation/mutation.json": JSON.stringify({ files: { "src/a.ts": { mutants: [{ status: "Killed" }, { status: "Killed" }, { status: "Survived" }] } } }),
    "junit.xml": '<testsuites tests="4" failures="0" skipped="1"></testsuites>',
  });
  try {
    const parsed = parseStructuredReports(tmp);
    assert.equal(parsed.lineCoveragePct, 50);
    assert.equal(parsed.mutationScore, 66.67);
    assert.equal(parsed.testsPassed, 3);
    assert.equal(parsed.testsFailed, 0);

    const badCob = reportParsers.parseCoberturaXml('<class filename="src/bad.ts" line-rate="1.2.3"/>');
    assert.equal(badCob.size, 0);

    const wf = parseGitHubWorkflow({
      rel: ".github/workflows/ci.yml",
      abs: "/tmp/ci.yml",
      content: [
        "on: pull_request",
        "jobs:",
        "  dead:",
        "    if: false",
        "    steps:",
        "      - run: echo dead",
        "  downstream:",
        "    needs: [dead]",
        "    steps:",
        "      - run: bun test",
      ].join("\n"),
      lines: 10,
      isTest: false,
      isWorkflow: true,
    });
    assert.equal(wf.activeCommands.length, 0);
    assert.ok(wf.deadJobs.includes("downstream"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
