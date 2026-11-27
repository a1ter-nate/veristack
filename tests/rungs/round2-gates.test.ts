import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanGitDiffCheats } from "@veristack/plugin-ci-auditor";
import { discoverRepo } from "@veristack/core";
import { scanRepo } from "@veristack/core";
import { lintNoComments } from "@veristack/plugin-anti-slop";
import { buildRatchetBaseline, evaluateRatchet } from "@veristack/core";
import { scrubChildEnv, validateExecutableCommand } from "@veristack/plugin-control-plane";
import { auditManifestDowngrade } from "@veristack/plugin-control-plane";
import { loadRungManifest } from "@veristack/core";
import { runPlantedFaultCanary } from "@veristack/plugin-canary";
import { runTwoSidedOracleCheck } from "@veristack/plugin-canary";
import { loadValidReceipts, runAllDeclaredRungs, runRungAndWriteReceipt } from "@veristack/plugin-canary";
import { evaluateCrapForCoverageFile } from "@veristack/plugin-canary";
import { parseGitHubWorkflow } from "@veristack/plugin-ci-auditor";
import { runPrecisionBench } from "@veristack/plugin-zero-defect";
import { auditFormalSync } from "@veristack/plugin-laws-formal";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");

function makeTempRepo(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-r2-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  }
  return dir;
}

function initGit(dir: string): void {
  spawnSync("git", ["init", "-q"], { cwd: dir });
  spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: dir });
  spawnSync("git", ["config", "user.name", "CI"], { cwd: dir });
  spawnSync("git", ["add", "."], { cwd: dir });
  spawnSync("git", ["commit", "-q", "-m", "base"], { cwd: dir });
}

test("receipt validation rejects unkeyed strict, bad digest, stale treeHash, wrong commitSha, wrong ciRunId, zero tests, and scrubs child env", () => {
  const scrubbed = scrubChildEnv({ PATH: "/usr/bin", VSTACK_RECEIPT_KEY: "secret", GITHUB_TOKEN: "ghs_x" });
  assert.equal(scrubbed.VSTACK_RECEIPT_KEY, undefined);
  assert.equal(scrubbed.GITHUB_TOKEN, undefined);
  assert.equal(scrubbed.PATH, "/usr/bin");

  const tmp = makeTempRepo({
    ".gitignore": ".verification/receipts/\n",
    ".verification/rungs.json": JSON.stringify({
      schemaVersion: 1,
      archetype: "library",
      rungs: { R2: { command: "bun test ./tests/calc.test.ts", required: true } },
    }),
    "src/calc.ts": "export function add(a: number, b: number): number { return a + b; }\n",
    "tests/calc.test.ts":
      "import assert from 'node:assert/strict';\nimport test from 'node:test';\nimport { add } from '../src/calc.ts';\ntest('add', () => { assert.equal(add(1, 2), 3); });\n",
  });
  try {
    initGit(tmp);
    const repo = discoverRepo(tmp);
    const loaded = loadRungManifest(tmp);
    assert.ok(loaded.manifest);

    const key = "ephemeral-secret-key-1234567890";
    const allRes = runAllDeclaredRungs(repo, "all", key);
    assert.equal(allRes.passed, true);
    const rec = runRungAndWriteReceipt(repo, "R2", loaded.manifest, key);
    assert.equal(rec.exitCode, 0);
    assert.ok(rec.digest.startsWith("hmac:"));

    const okRes = loadValidReceipts(repo, loaded.manifest, { strict: true, hmacKeyOverride: key });
    assert.equal(okRes.receipts.has("R2"), true);

    const noKeyStrict = loadValidReceipts(repo, loaded.manifest, { strict: true, hmacKeyOverride: "" });
    assert.ok(noKeyStrict.findings.some((f) => f.rule === "receipt-unsigned-strict"));

    const wrongKey = loadValidReceipts(repo, loaded.manifest, { strict: true, hmacKeyOverride: "wrong-key-999999" });
    assert.equal(wrongKey.receipts.has("R2"), false);

    const recPath = path.join(tmp, ".verification/receipts/R2.json");
    const parsed = JSON.parse(fs.readFileSync(recPath, "utf8")) as Record<string, unknown>;
    fs.writeFileSync(recPath, JSON.stringify({ ...parsed, commitSha: "0000000000000000000000000000000000000000" }));
    assert.equal(loadValidReceipts(repo, loaded.manifest, { strict: true, hmacKeyOverride: key }).receipts.has("R2"), false);

    fs.writeFileSync(recPath, JSON.stringify({ ...parsed, treeHash: "deadbeef" }));
    assert.equal(loadValidReceipts(repo, loaded.manifest, { strict: true, hmacKeyOverride: key }).receipts.has("R2"), false);

    fs.writeFileSync(recPath, JSON.stringify(parsed));
    fs.writeFileSync(path.join(tmp, "src/calc.ts"), "export function add(a: number, b: number): number { return a - b; }\n");
    assert.equal(loadValidReceipts(discoverRepo(tmp), loaded.manifest, { strict: true, hmacKeyOverride: key }).receipts.has("R2"), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("canary distinguishes real kills from real survivors and rejects .trimEnd() source-hash cheats and --version commands", () => {
  assert.notEqual(validateExecutableCommand("R0", "bunx oxlint --version"), null);
  assert.notEqual(validateExecutableCommand("R0", "oxlint || :"), null);
  assert.notEqual(validateExecutableCommand("R1", "node scripts/run.mjs tsc"), null);
  assert.notEqual(validateExecutableCommand("R2", "bun test | tee out.log"), null);
  assert.notEqual(validateExecutableCommand("R2", "! bun test"), null);
  assert.notEqual(validateExecutableCommand("canary", "node -e 'console.log(1)'"), null);

  const tmp = makeTempRepo({
    "src/math.ts": [
      "export function isAdult(age: number): boolean {",
      "  if (age >= 18) return true;",
      "  return false;",
      "}",
      "export function isSenior(age: number): boolean {",
      "  if (age >= 65) return true;",
      "  return false;",
      "}",
    ].join("\n"),
    "tests/math.test.ts": [
      "import assert from 'node:assert/strict';",
      "import test from 'node:test';",
      "import { isAdult, isSenior } from '../src/math.ts';",
      "test('boundaries', () => {",
      "  assert.equal(isAdult(18), true);",
      "  assert.equal(isAdult(17), false);",
      "  assert.equal(isSenior(65), true);",
      "  assert.equal(isSenior(64), false);",
      "});",
    ].join("\n"),
  });
  try {
    const partial = runPlantedFaultCanary({
      repoRoot: tmp,
      testCmd: "bun test ./tests/math.test.ts",
      targets: ["src/math.ts"],
      maxMutants: 2,
      minKillRate: 0.75,
    });
    assert.equal(partial.totalMutants, 2);
    assert.equal(partial.invalidKills, 0);
    assert.equal(partial.killedMutants, 2);
    assert.equal(partial.passed, true);

    fs.writeFileSync(
      path.join(tmp, "tests/math.test.ts"),
      "import assert from 'node:assert/strict';\nimport test from 'node:test';\nimport { isAdult } from '../src/math.ts';\ntest('weak', () => { assert.equal(typeof isAdult(18), 'boolean'); });\n",
    );
    const weak = runPlantedFaultCanary({
      repoRoot: tmp,
      testCmd: "bun test ./tests/math.test.ts",
      targets: ["src/math.ts"],
      maxMutants: 2,
      minKillRate: 0.2,
    });
    assert.equal(weak.minKillRate, 0.75);
    assert.equal(weak.passed, false);
    assert.ok(weak.survivedMutants >= 1);

    fs.writeFileSync(
      path.join(tmp, "tests/math.test.ts"),
      [
        "import assert from 'node:assert/strict';",
        "import crypto from 'node:crypto';",
        "import fs from 'node:fs';",
        "import test from 'node:test';",
        "const orig = crypto.createHash('sha256').update(fs.readFileSync('src/math.ts', 'utf8').trimEnd()).digest('hex');",
        "test('hash-cheat', () => {",
        "  const cur = crypto.createHash('sha256').update(fs.readFileSync('src/math.ts', 'utf8').trimEnd()).digest('hex');",
        "  assert.equal(cur, orig);",
        "});",
      ].join("\n"),
    );
    const baselineSrc = fs.readFileSync(path.join(tmp, "src/math.ts"), "utf8");
    const fixedHash = spawnSync(
      "bun",
      ["-e", `import crypto from 'node:crypto'; console.log(crypto.createHash('sha256').update(${JSON.stringify(baselineSrc.trimEnd())}).digest('hex'))`],
      { encoding: "utf8" },
    ).stdout.trim();
    fs.writeFileSync(
      path.join(tmp, "tests/math.test.ts"),
      `import assert from 'node:assert/strict';\nimport crypto from 'node:crypto';\nimport fs from 'node:fs';\nimport test from 'node:test';\ntest('hash-cheat', () => {\n  const cur = crypto.createHash('sha256').update(fs.readFileSync('src/math.ts', 'utf8').trimEnd()).digest('hex');\n  assert.equal(cur, '${fixedHash}');\n});\n`,
    );
    const cheatRes = runPlantedFaultCanary({
      repoRoot: tmp,
      testCmd: "bun test ./tests/math.test.ts",
      targets: ["src/math.ts"],
      maxMutants: 2,
      minKillRate: 0.75,
    });
    assert.equal(cheatRes.passed, false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("rejects wildcard allowExcluded, detects manifest downgrades, fixture oracle rewrites, and workflow evasion variants", () => {
  for (const pat of ["**/*", "*/*", "**/*.ts", "services/**", "s*/**", "src/evil.ts"]) {
    const tmp = makeTempRepo({
      ".verification/rungs.json": JSON.stringify({ schemaVersion: 1, archetype: "library", allowExcluded: [pat], rungs: {} }),
    });
    try {
      const loaded = loadRungManifest(tmp);
      assert.ok(loaded.error, `expected allowExcluded '${pat}' to be rejected`);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }

  const wf = parseGitHubWorkflow({
    rel: ".github/workflows/evade.yml",
    abs: "/tmp/evade.yml",
    isTest: false,
    isWorkflow: true,
    lines: 20,
    content: [
      "on:",
      "  pull_request:",
      "    types: [opened]",
      "jobs:",
      "  j1:",
      "    continue-on-error: ${{ 1 == 1 }}",
      "    steps:",
      "      - shell: true {0}",
      "        run: bun test",
      "  j2:",
      "    steps:",
      "      - run: |",
      "          bun test || /bin/true",
      "          bun test && echo ok",
      "          bun test | tee log.txt",
      "          ! bun test",
      "          bun test &",
    ].join("\n"),
  });
  assert.equal(wf.isPrBlocking, false);
  assert.equal(wf.activeCommands.length, 0);

  const repoDir = makeTempRepo({
    ".verification/rungs.json": JSON.stringify({
      schemaVersion: 1,
      archetype: "service",
      rungs: { R2: { command: "bun test", required: true, canary: { enabled: true, minKillRate: 0.8, maxMutants: 6 } } },
    }),
    "src/fn.ts": "export function ok(n: number): boolean { return n >= 10; }\n",
    "tests/fixtures/cases.json": JSON.stringify({ min: 10, expect: true }),
    "tests/fn.test.ts": [
      "import assert from 'node:assert/strict';",
      "import fs from 'node:fs';",
      "import test from 'node:test';",
      "import { ok } from '../src/fn.ts';",
      "test('fixture', () => {",
      "  const c = JSON.parse(fs.readFileSync('tests/fixtures/cases.json', 'utf8'));",
      "  assert.equal(ok(c.min), c.expect);",
      "});",
    ].join("\n"),
  });
  try {
    initGit(repoDir);
    fs.appendFileSync(path.join(repoDir, "tests/fn.test.ts"), "\ntest('extra', () => { assert.equal(ok(15) && ok(10), true); });\n");
    const oraclePass = runTwoSidedOracleCheck(repoDir, "HEAD", "bun test ./tests/fn.test.ts");
    assert.equal(oraclePass.passed, true);

    fs.writeFileSync(path.join(repoDir, "src/fn.ts"), "export function ok(n: number): boolean { return n >= 20; }\n");
    const diffCanary = runPlantedFaultCanary({
      repoRoot: repoDir,
      testCmd: "bun test ./tests/fn.test.ts",
      baseRef: "HEAD",
      maxMutants: 2,
    });
    assert.equal(diffCanary.totalMutants, 1);
    assert.equal(diffCanary.invalidKills, 1);

    fs.writeFileSync(path.join(repoDir, "tests/fixtures/cases.json"), JSON.stringify({ min: 10, expect: false }));
    const oracleRes = runTwoSidedOracleCheck(repoDir, "HEAD", "bun test ./tests/fn.test.ts");
    assert.equal(oracleRes.passed, false);

    fs.writeFileSync(
      path.join(repoDir, ".verification/rungs.json"),
      JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test" } } }),
    );
    const downgrades = auditManifestDowngrade(repoDir, "HEAD");
    assert.ok(downgrades.some((f) => f.rule === "diff-manifest-downgrade"));
    assert.ok(scanGitDiffCheats(repoDir, "HEAD").some((f) => f.rule === "diff-manifest-downgrade"));
  } finally {
    fs.rmSync(repoDir, { recursive: true, force: true });
  }
});

test("enforces monorepo strict workspace floor, source-tree untracked dirs, Vue SFCs, Go slop, per-function CRAP, ratchet, formal-sync, and bench", () => {
  const tmp = makeTempRepo({
    "packages/core/package.json": JSON.stringify({ name: "core" }),
    "packages/core/src/a.ts": "export const a = 1;\n",
    "packages/core/tests/a.test.ts": "import assert from 'node:assert/strict';\nimport test from 'node:test';\nimport { a } from '../src/a.ts';\ntest('a', () => { assert.equal(a, 1); });\n",
    "libs/orders/package.json": JSON.stringify({ name: "orders" }),
    "libs/orders/src/order.ts": "export const total = (x: number) => x;\n",
    "src/vendor/bad.ts": "export const x = (1 as any);\n",
    "src/App.vue": '<template><div/></template>\n<script setup lang="ts">\nconst x = 1 as any;\n</script>\n',
    "src/bad.go": "package bad\nimport \"unsafe\"\nfunc f(err error, p unsafe.Pointer) { if err != nil {} }\n",
  });
  try {
    const scan = scanRepo(tmp);
    assert.ok((scan.workspaces ?? []).some((w) => w.path === "libs/orders" && w.score === 0));
    assert.equal(scan.summary.overallCoverageScore, 0);
    assert.ok(scan.findings.some((f) => f.file === "src/vendor/bad.ts"));
    assert.ok(scan.findings.some((f) => f.file === "src/App.vue"));
    assert.ok(scan.findings.some((f) => f.file === "src/bad.go" && f.rule === "no-unsafe-pointer"));
    assert.ok(scan.findings.some((f) => f.file === "src/bad.go" && f.rule === "no-swallowing-catch"));

    const strictCli = spawnSync(process.execPath, [binPath, "scan", tmp, "--strict"], { encoding: "utf8" });
    assert.notEqual(strictCli.status, 0);

    const covFile = path.join(tmp, "lcov.info");
    fs.writeFileSync(covFile, "SF:packages/core/src/a.ts\nDA:1,1\nend_of_record\n");
    const crap = evaluateCrapForCoverageFile(tmp, covFile, 30);
    assert.equal(crap.passed, false);
    assert.ok(crap.uncoveredRepoFiles.includes("libs/orders/src/order.ts"));
    assert.throws(() => evaluateCrapForCoverageFile(tmp, covFile, Number.NaN));

    const cleanCrapDir = makeTempRepo({
      "package.json": JSON.stringify({ name: "clean-crap" }),
      "src/ok.ts": "export function ok(n: number): number { return n > 0 ? n : 0; }\n",
      "tests/ok.test.ts": "export const t = 1;\n",
      "lcov.info": "SF:src/ok.ts\nDA:1,1\nend_of_record\n",
    });
    try {
      const cleanCrap = evaluateCrapForCoverageFile(cleanCrapDir, path.join(cleanCrapDir, "lcov.info"), 30);
      assert.equal(cleanCrap.passed, true);
      assert.deepEqual(cleanCrap.uncoveredRepoFiles, []);
    } finally {
      fs.rmSync(cleanCrapDir, { recursive: true, force: true });
    }

    const vueOnlyDir = makeTempRepo({ "src/App.vue": "<template><div/></template>\n<script>export const a = 1;</script>\n" });
    try {
      assert.equal(scanRepo(vueOnlyDir).archetype, "frontend");
    } finally {
      fs.rmSync(vueOnlyDir, { recursive: true, force: true });
    }

    const base = buildRatchetBaseline([{ id: "1", rule: "r1", category: "cheat", rung: "R0", severity: "error", file: "src/a.ts", line: 1, message: "m", fix: "f" }]);
    const same = evaluateRatchet([{ id: "1", rule: "r1", category: "cheat", rung: "R0", severity: "error", file: "src/a.ts", line: 1, message: "m", fix: "f" }], base);
    assert.equal(same.passed, true);
    const moved = evaluateRatchet([{ id: "2", rule: "r1", category: "cheat", rung: "R0", severity: "error", file: "src/b.ts", line: 1, message: "m", fix: "f" }], base);
    assert.equal(moved.passed, false);
    const rungSnap = [{ rung: "R0" as const, name: "R0", speedBudget: "1s", targetBudget: "100%", status: "covered" as const, coverageGrade: "well-covered" as const, coverageScore: 100, executedInCi: true, receiptVerified: true, idealCoverage: "", observedCoverage: "", checks: [], observedCount: 1, evidence: ["e"], gaps: [] }];
    const rungBase = buildRatchetBaseline([], rungSnap);
    assert.equal(evaluateRatchet([], rungBase, rungSnap).passed, true);

    const emptyBench = runPrecisionBench(tmp);
    assert.equal(emptyBench.passed, false);

    fs.mkdirSync(path.join(tmp, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "spec.qnt"), "module M { val ok = true }\n");
    fs.writeFileSync(
      path.join(tmp, ".verification/control-plan.json"),
      JSON.stringify({ schemaVersion: 1, formalChecks: [{ id: "m", kind: "formal", specFile: "spec.qnt", coveredPaths: [], syncCommit: "abcdef1" }] }),
    );
    assert.ok(auditFormalSync(discoverRepo(tmp)).some((f) => f.rule === "formal-sync-empty-covered-paths"));

    assert.equal(runTwoSidedOracleCheck(tmp, "", "bun test").passed, false);
    assert.match(runTwoSidedOracleCheck(tmp, "--evil", "bun test").reason, /Invalid or missing/);
    assert.deepEqual(lintNoComments("src/esc.py", 'x = "escaped \\" # still string"\n', "python"), []);
    const rustCfg = makeTempRepo({ "src/t.rs": "#[cfg(test)]\nmod t { fn f() -> bool { 1 == 1 } }\n" });
    try {
      const cfgCanary = runPlantedFaultCanary({ repoRoot: rustCfg, testCmd: "cargo test", targets: ["src/t.rs"], maxMutants: 2 });
      assert.equal(cfgCanary.totalMutants, 0);
    } finally {
      fs.rmSync(rustCfg, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
