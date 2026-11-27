import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { discoverRepo } from "../../src/discover.ts";
import { executeHookEvent, loadHookConfig } from "../../src/hooks/runtime.ts";
import { classifyCanaryOutcome, isRetryableCanarySignal } from "../../src/rungs/canary-runner.ts";
import { parseAndValidateCommandArgv } from "../../src/rungs/command-audit.ts";
import { auditRunnerConfigs, runGitClean } from "../../src/rungs/config-audit.ts";
import { discoverWorkspaces } from "../../src/rungs/manifest.ts";
import { insertSemanticNoOp, runPlantedFaultCanary, runPlantedFaultCanaryAsync } from "../../src/rungs/mutation-probe.ts";
import { runTwoSidedOracleCheck } from "../../src/rungs/oracle-check.ts";
import { computeRepoTreeHash, runRungAndWriteReceipt } from "../../src/rungs/receipts.ts";
import { evaluateCrapForCoverageFile, parseStructuredReports, reportParsers } from "../../src/rungs/reports.ts";
import { checkGitHubBranchProtection, evaluateBranchProtectionJson, globMatchesPath, parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-mpin-"));
  try { fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

async function withTempDirAsync(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-mpin-a-"));
  try { await fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function initGit(dir: string): void {
  runGitClean(dir, ["init", "-q", "-b", "main"]);
  runGitClean(dir, ["config", "user.name", "Test"]);
  runGitClean(dir, ["config", "user.email", "t@test.local"]);
}

test("hooks runtime pins: empty/non-object/malformed payloads across pre-edit/post-edit/stop, bash abs/rel paths, edits/patches, and config", () => {
  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.mkdirSync(path.join(dir, "sub"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: {} }));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p" }));
    fs.writeFileSync(path.join(dir, "src.ts"), "export const v = 1;\n");
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "base"]);

    assert.equal(executeHookEvent("pre-edit", "", { repoRoot: dir, harness: "claude" }).exitCode, 2);
    assert.equal(executeHookEvent("post-edit", "", { repoRoot: dir, harness: "claude" }).exitCode, 0);
    assert.equal(executeHookEvent("pre-edit", "[]", { repoRoot: dir, harness: "claude" }).exitCode, 2);
    const stopArr = executeHookEvent("stop", "[]", { repoRoot: dir, harness: "claude" });
    assert.equal(JSON.parse(stopArr.stdout).decision, "block");
    assert.equal(executeHookEvent("pre-edit", "{bad", { repoRoot: dir, harness: "claude" }).exitCode, 2);
    const stopBad = executeHookEvent("stop", "{bad", { repoRoot: dir, harness: "claude" });
    assert.equal(JSON.parse(stopBad.stdout).decision, "block");
    assert.equal(executeHookEvent("post-edit", "{bad", { repoRoot: dir, harness: "claude" }).exitCode, 0);

    const absTarget = path.join(dir, ".verification", "rungs.json");
    assert.equal(
      executeHookEvent("pre-edit", JSON.stringify({ cwd: path.join(dir, "sub"), tool_name: "Bash", tool_input: { command: `rm -f ${absTarget}` } }), { repoRoot: dir, harness: "claude" }).exitCode,
      2,
    );
    assert.equal(
      executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_name: "Bash", tool_input: { command: "cd sub && rm -f ../package.json" } }), { repoRoot: dir, harness: "claude" }).exitCode,
      2,
    );
    assert.equal(
      executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_name: "Bash", tool_input: { command: "node -e \"require('fs').writeFileSync('.verification/rungs.json', '{}')\"" } }), { repoRoot: dir, harness: "claude" }).exitCode,
      2,
    );

    const editDirty = executeHookEvent(
      "pre-edit",
      JSON.stringify({ cwd: dir, tool_name: "MultiEdit", tool_input: { file_path: path.join(dir, "src.ts"), edits: [{ old_string: "1", new_string: "(1 as any)", replace_all: true }] } }),
      { repoRoot: dir, harness: "claude" },
    );
    assert.equal(editDirty.exitCode, 2);

    const patchDirty = executeHookEvent(
      "pre-edit",
      JSON.stringify({ cwd: dir, tool_name: "ApplyPatch", tool_input: { patch: "*** Begin Patch\n*** Update File: src.ts\n@@\n-export const v = 1;\n+export const v = (1 as any);\n*** End Patch\n" } }),
      { repoRoot: dir, harness: "claude" },
    );
    assert.equal(patchDirty.exitCode, 2);

    fs.writeFileSync(path.join(dir, ".verification", "hooks.json"), "not-json");
    assert.equal(loadHookConfig(dir).enabled, true);
    fs.writeFileSync(path.join(dir, ".verification", "hooks.json"), "[]");
    assert.equal(loadHookConfig(dir).tier, "immediate");
    fs.writeFileSync(path.join(dir, ".verification", "hooks.json"), JSON.stringify({ enabled: true, tier: "all", auditLog: "audit.jsonl", harnesses: ["claude", "invalid"] }));
    const cfg = loadHookConfig(dir);
    assert.equal(cfg.tier, "all");
    assert.equal(cfg.auditLog, "audit.jsonl");
    assert.deepEqual(cfg.harnesses, ["claude"]);
    executeHookEvent("post-edit", JSON.stringify({ cwd: dir, tool_input: { file_path: path.join(dir, "src.ts") } }), { repoRoot: dir, harness: "claude" });
    assert.equal(fs.existsSync(path.join(dir, "audit.jsonl")), true);
  });
});

test("config-audit pins: local package bin/tarball shadowing, node_modules/.bin escape, pytest addopts edge cases, and Python shadowing", () => {
  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "local-evil"), { recursive: true });
    fs.writeFileSync(path.join(dir, "local-evil", "package.json"), JSON.stringify({ name: "helper", bin: { oxlint: "./fake.js" } }));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", devDependencies: { helper: "file:./local-evil" } }));
    assert.ok(auditRunnerConfigs(dir)?.includes("shadows verification binary"));

    fs.writeFileSync(path.join(dir, "local-evil", "package.json"), JSON.stringify({ name: "helper", bin: { helper: "./ok.js" } }));
    assert.equal(auditRunnerConfigs(dir), null);

    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", devDependencies: { helper: "./oxlint-1.0.tgz" } }));
    assert.ok(auditRunnerConfigs(dir)?.includes("tarball"));

    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", devDependencies: { helper: "./my-lib-1.0.tgz" } }));
    assert.equal(auditRunnerConfigs(dir), null);

    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app" }));
    fs.mkdirSync(path.join(dir, "node_modules", ".bin"), { recursive: true });
    fs.mkdirSync(path.join(dir, "node_modules", "oxlint"), { recursive: true });
    fs.writeFileSync(path.join(dir, "node_modules", "oxlint", "cli.js"), "#!/usr/bin/env node\n");
    fs.symlinkSync(path.join(dir, "node_modules", "oxlint", "cli.js"), path.join(dir, "node_modules", ".bin", "oxlint"));
    assert.equal(auditRunnerConfigs(dir), null);

    fs.unlinkSync(path.join(dir, "node_modules", ".bin", "oxlint"));
    fs.writeFileSync(path.join(dir, "fake-oxlint.js"), "#!/usr/bin/env node\n");
    fs.symlinkSync(path.join(dir, "fake-oxlint.js"), path.join(dir, "node_modules", ".bin", "oxlint"));
    assert.ok(auditRunnerConfigs(dir)?.includes("resolves outside node_modules"));
    fs.rmSync(path.join(dir, "node_modules"), { recursive: true, force: true });

    fs.writeFileSync(path.join(dir, "pytest.ini"), "[pytest]\naddopts = tests/only_one.py\n");
    assert.ok(auditRunnerConfigs(dir)?.includes("positional selector"));
    fs.writeFileSync(path.join(dir, "pytest.ini"), "[pytest]\naddopts = --cov-fail-under -q\n");
    assert.ok(auditRunnerConfigs(dir)?.includes("missing a non-flag value"));
    fs.unlinkSync(path.join(dir, "pytest.ini"));

    fs.mkdirSync(path.join(dir, "pytest"), { recursive: true });
    fs.writeFileSync(path.join(dir, "pytest", "__init__.py"), "");
    assert.ok(auditRunnerConfigs(dir)?.includes("shadows verification tool"));
    fs.rmSync(path.join(dir, "pytest"), { recursive: true, force: true });

    fs.writeFileSync(path.join(dir, "hook.pth"), "import os\n");
    assert.ok(auditRunnerConfigs(dir)?.includes(".pth"));
    fs.unlinkSync(path.join(dir, "hook.pth"));
    fs.writeFileSync(path.join(dir, "jest.config.json"), JSON.stringify({ testNamePattern: "smoke" }));
    assert.ok(auditRunnerConfigs(dir)?.includes("testNamePattern"));
    fs.writeFileSync(path.join(dir, "jest.config.json"), JSON.stringify({ verbose: true }));
    assert.equal(auditRunnerConfigs(dir), null);
    fs.unlinkSync(path.join(dir, "jest.config.json"));
    assert.equal(parseAndValidateCommandArgv("R2", "uv run pytest", dir).error, undefined);
    assert.ok(parseAndValidateCommandArgv("R2", "uv run ./evil", dir).error?.includes("disallowed uv run target"));
  });
});

test("oracle-check pins: workspace node_modules symlink remapping, deleted Rust inline tests, and behavior-changes approval validation", () => {
  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "packages", "core"), { recursive: true });
    fs.mkdirSync(path.join(dir, "node_modules", "@ws"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, "packages", "core", "index.ts"), "export const val = () => 7;\n");
    fs.symlinkSync(path.join(dir, "packages", "core"), path.join(dir, "node_modules", "@ws", "core"));
    fs.writeFileSync(path.join(dir, "tests", "ws.test.ts"), 'import { test, expect } from "bun:test";\nimport { val } from "../node_modules/@ws/core/index.ts";\ntest("v", () => expect(val()).toBe(7));\n');
    fs.writeFileSync(path.join(dir, "lib.rs"), "pub fn f() -> i32 { 1 }\n#[cfg(test)]\nmod tests {\n  #[test]\n  fn ok() { assert_eq!(1, 1); }\n}\n");
    fs.writeFileSync(path.join(dir, ".verification", "behavior-changes.json"), JSON.stringify({ changes: [{ file: "tests/ws.test.ts", reason: "intentional return value update", approvedBy: "@owner" }] }));
    runGitClean(dir, ["add", "packages", "tests", "lib.rs", ".verification"]);
    runGitClean(dir, ["commit", "-q", "-m", "base"]);

    fs.writeFileSync(path.join(dir, "packages", "core", "index.ts"), "export const val = () => 9;\n");
    fs.writeFileSync(path.join(dir, "tests", "ws.test.ts"), 'import { test, expect } from "bun:test";\nimport { val } from "../node_modules/@ws/core/index.ts";\ntest("v", () => expect(val()).toBe(9));\n');
    const approved = runTwoSidedOracleCheck(dir, "HEAD", "bun test ./tests/ws.test.ts");
    assert.equal(approved.passed, true);
    assert.equal(approved.declaredBehaviorChange, true);

    fs.writeFileSync(path.join(dir, "packages", "core", "index.ts"), "export const val = () => 7;\n");
    fs.writeFileSync(path.join(dir, "tests", "ws.test.ts"), 'import { test, expect } from "bun:test";\nimport { val } from "../node_modules/@ws/core/index.ts";\ntest("v", () => expect(val()).toBe(7));\n');
    fs.unlinkSync(path.join(dir, "lib.rs"));
    const delRust = runTwoSidedOracleCheck(dir, "HEAD", "bun test ./tests/ws.test.ts");
    assert.equal(delRust.passed, false);
    assert.ok(delRust.reason.includes("Rust file(s) containing inline tests were deleted"));
  });
});

test("reports pins: self-closing JUnit suites, TRX counters, invalid attrs, maxMtimeMs freshness, Stryker statuses, and nested CRAP span ownership", () => {
  const scJunit = reportParsers.parseJunitOrTrx('<testsuites><testsuite name="a" tests="3" failures="0"/><testsuite name="b" tests="2" failures="1"/></testsuites>');
  assert.deepEqual(scJunit, { passed: 4, failed: 1, skipped: 0 });
  const rootOnly = reportParsers.parseJunitOrTrx('<testsuites tests="4" failures="1" errors="0" skipped="1"></testsuites>');
  assert.deepEqual(rootOnly, { passed: 2, failed: 1, skipped: 1 });
  const trx = reportParsers.parseJunitOrTrx('<TestRun><ResultSummary><Counters total="6" passed="3" failed="1" error="1" timeout="0" aborted="0" inconclusive="0" notRunnable="0"/></ResultSummary></TestRun>');
  assert.deepEqual(trx, { passed: 3, failed: 2, skipped: 1 });
  assert.equal(reportParsers.parseJunitOrTrx('<testsuite tests="abc" failures="0"/>'), undefined);

  assert.equal(reportParsers.parseStrykerJson(JSON.stringify({ files: { a: { mutants: [{ status: "Killed" }, { status: "Timeout" }, { status: "Survived" }, { status: "NoCoverage" }] } } })), 50);
  assert.equal(reportParsers.parseStrykerJson(JSON.stringify({ files: { a: { mutants: [{ status: "CompileError" }] } } })), undefined);

  withTempDir((dir) => {
    const junitAbs = path.join(dir, "junit.xml");
    fs.writeFileSync(junitAbs, '<testsuite tests="3" failures="0"/>\n');
    const st = fs.statSync(junitAbs);
    assert.equal(parseStructuredReports(dir, { rung: "R2", maxMtimeMs: st.mtimeMs - 5_000 }).testsPassed, undefined);
    assert.equal(parseStructuredReports(dir, { rung: "R2", maxMtimeMs: st.mtimeMs + 5_000 }).testsPassed, 3);
    assert.equal(parseStructuredReports(path.join(dir, "missing"), { rung: "R2", minMtimeMs: 1 }).testsPassed, undefined);

    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "src", "nested.ts"),
      [
        "export function outer(items: number[]) {",
        "  const fn = (x: number) => (x > 0 ? x : 0);",
        "  if (items.length === 0) return 0;",
        "  return items.map(fn).reduce((a, b) => a + b, 0);",
        "}",
      ].join("\n"),
    );
    fs.writeFileSync(path.join(dir, "lcov.info"), `SF:${path.join(dir, "src", "nested.ts")}\nDA:1,1\nDA:2,1\nDA:3,1\nDA:4,1\nDA:5,1\nDA:99,0\nend_of_record\n`);
    const rep = evaluateCrapForCoverageFile(dir, "lcov.info", 30);
    assert.equal(rep.passed, true);
    assert.equal(rep.evaluatedFiles, 1);

    fs.writeFileSync(
      path.join(dir, "src", "nested.ts"),
      [
        "export function outer(a: number, b: number, c: number, d: number, e: number, f: number): number {",
        "  function inner(x: number): number {",
        "    if (x > 0 && a > 0 && b > 0 && c > 0 && d > 0 && e > 0 && f > 0) return x;",
        "    return 0;",
        "  }",
        "  return inner(a);",
        "}",
      ].join("\n"),
    );
    fs.writeFileSync(path.join(dir, "lcov.info"), "SF:src/nested.ts\nDA:1,1\nDA:2,0\nDA:3,0\nDA:4,0\nDA:5,0\nDA:6,1\nDA:7,1\nend_of_record\n");
    const nestedFail = evaluateCrapForCoverageFile(dir, "lcov.info", 30);
    assert.equal(nestedFail.passed, false);
    assert.ok(nestedFail.worstCrap > 30);
    assert.throws(() => evaluateCrapForCoverageFile(dir, "lcov.info", 0));
  });
});

test("receipts & manifest pins: git-tracked binary asset hash, JUnit failure fallback without stdout summary, and explicit workspace archetype", () => {
  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "packages", "pkg", "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.mkdirSync(path.join(dir, "assets"), { recursive: true });
    fs.writeFileSync(path.join(dir, "packages", "pkg", "package.json"), JSON.stringify({ name: "pkg" }));
    fs.writeFileSync(path.join(dir, "packages", "pkg", "src", "a.ts"), "export const a = 1;\n");
    fs.writeFileSync(path.join(dir, "assets", "blob.bin"), Buffer.from([1, 2, 3, 4]));
    fs.writeFileSync(
      path.join(dir, "tests", "dot.test.mjs"),
      'import fs from "node:fs"; import test from "node:test"; test("dot", () => { console.log("Mutation score: 88%"); fs.writeFileSync("junit.xml", \'<testsuite tests="3" failures="1"/>\\n\'); });\n',
    );
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "init"]);

    const repo1 = discoverRepo(dir);
    const h1 = computeRepoTreeHash(repo1);
    fs.writeFileSync(path.join(dir, "assets", "blob.bin"), Buffer.from([9, 8, 7, 6]));
    const h2 = computeRepoTreeHash(discoverRepo(dir));
    assert.notEqual(h1, h2);

    const ws = discoverWorkspaces(repo1, {
      schemaVersion: 1,
      archetype: "fullstack",
      allowExcluded: [],
      rungs: {},
      workspaces: [{ name: "pkg", path: "packages/pkg", archetype: "fullstack" }],
    });
    assert.equal(ws.find((w) => w.path === "packages/pkg")?.archetype, "fullstack");

    const rec = runRungAndWriteReceipt(
      discoverRepo(dir),
      "R2",
      { schemaVersion: 1, archetype: "library", allowExcluded: [], rungs: { R2: { command: "node --test --test-reporter=dot ./tests/dot.test.mjs", required: true } } },
      "test-key-1234",
    );
    assert.equal(rec.exitCode, 1);
    assert.equal(rec.metrics?.testsFailed, 1);
    assert.equal(rec.metrics?.mutationScore, undefined);
  });
});

test("workflow-audit pins: unanchored globs, multi-hop workflow_call with cycle guard, label/fork PR gating, and branch protection checks", () => {
  assert.equal(globMatchesPath("foo.txt", "foo.txt"), true);
  assert.equal(globMatchesPath("foo.txt", "a/foo.txt"), true);
  assert.equal(globMatchesPath("foo.txt", "foo.txt/bar"), true);
  assert.equal(globMatchesPath("foo.txt", "a/foo.txt/bar"), true);
  assert.equal(globMatchesPath("foo.txt", "barfoo.txt"), false);
  assert.equal(globMatchesPath("logs/", "a/logs/out.txt"), true);
  assert.equal(globMatchesPath("!foo.txt", "foo.txt"), false);
  assert.equal(globMatchesPath("*", "anything/file.ts"), true);

  const mkWf = (rel: string, content: string) => ({ rel, abs: `/tmp/${rel}`, isTest: false, isWorkflow: true, lines: content.split("\n").length, content });
  const w1 = mkWf(".github/workflows/ci.yml", "on: [pull_request]\njobs:\n  call1:\n    uses: ./.github/workflows/l2.yml\n");
  const w2 = mkWf(".github/workflows/l2.yml", "on: workflow_call\njobs:\n  call2:\n    uses: ./.github/workflows/l3.yml\n");
  const w3 = mkWf(".github/workflows/l3.yml", "on: workflow_call\njobs:\n  call3:\n    uses: ./.github/workflows/l4.yml\n");
  const w4 = mkWf(".github/workflows/l4.yml", "on: workflow_call\njobs:\n  run:\n    runs-on: ubuntu-latest\n    steps:\n      - run: vitest run\n  cycle:\n    uses: ./.github/workflows/ci.yml\n");
  const parsedChain = parseGitHubWorkflow(w1, [w1, w2, w3, w4]);
  assert.equal(parsedChain.isPrBlocking, true);
  assert.equal(parsedChain.activeCommands.includes("vitest run"), true);

  const labelGated = parseGitHubWorkflow(
    mkWf(".github/workflows/lbl.yml", "on: [pull_request]\njobs:\n  t:\n    if: contains(github.event.pull_request.labels.*.name, 'run-ci')\n    runs-on: ubuntu-latest\n    steps:\n      - run: vitest run\n"),
  );
  assert.equal(labelGated.activeCommands.length, 0);

  const forkGated = parseGitHubWorkflow(
    mkWf(".github/workflows/fork.yml", "on: [pull_request]\njobs:\n  t:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on: ubuntu-latest\n    steps:\n      - run: vitest run\n"),
  );
  assert.equal(forkGated.activeCommands.length, 0);

  withTempDir((dir) => {
    initGit(dir);
    const noRemote = checkGitHubBranchProtection(dir);
    assert.equal(noRemote.checked, false);
    assert.ok(noRemote.detail.includes("No GitHub origin remote"));
  });

  const okBp = evaluateBranchProtectionJson("main", JSON.stringify({
    required_status_checks: { contexts: ["self-verify-vstack-strict"] },
    required_pull_request_reviews: { require_code_owner_reviews: true, required_approving_review_count: 1, dismiss_stale_reviews: true },
    enforce_admins: { enabled: true },
    allow_force_pushes: { enabled: false },
  }));
  assert.equal(okBp.passed, true);
  assert.equal(evaluateBranchProtectionJson("main", "bad-json").checked, false);
});

test("mutation-probe & canary-runner pins: AST loop/return/arithmetic operators, crash vs assertion classification, retryable signal, and async parity", async () => {
  const crashRes = classifyCanaryOutcome(
    { status: 1, stdout: "SyntaxError: Unexpected token\n", stderr: "", signal: null },
    100,
    25_000,
    [["bun", "test"]],
  );
  assert.equal(crashRes.outcome, "invalid");
  assert.ok(crashRes.diagnostic?.includes("crash="));

  const killedRes = classifyCanaryOutcome(
    { status: 1, stdout: "AssertionError: expected 1 to equal 2\n0 pass\n1 fail\n", stderr: "", signal: null },
    100,
    25_000,
    [["bun", "test"]],
  );
  assert.equal(killedRes.outcome, "killed");

  assert.equal(isRetryableCanarySignal({ status: 1, stdout: "", stderr: "", signal: "SIGKILL" }, 500, 25_000), true);
  assert.equal(isRetryableCanarySignal({ status: 1, stdout: "", stderr: "", signal: "SIGTERM" }, 24_000, 25_000), false);

  await withTempDirAsync(async (dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "src", "ops.ts"),
      [
        "export function sumPos(nums: number[]): number {",
        "  let acc = 0;",
        "  let i = 0;",
        "  while (i < nums.length) {",
        "    const n = nums[i] ?? 0;",
        "    if (n > 0) acc += n;",
        "    i += 1;",
        "  }",
        "  return acc + 1;",
        "}",
        "export function isFlag(x: boolean): boolean {",
        "  if (!x) {",
        "    return false;",
        "  }",
        "  return true;",
        "}",
      ].join("\n"),
    );
    fs.writeFileSync(
      path.join(dir, "tests", "ops.test.ts"),
      [
        'import { test, expect } from "bun:test";',
        'import { sumPos, isFlag } from "../src/ops.ts";',
        'test("ops", () => {',
        "  expect(sumPos([2, -3, 4])).toBe(7);",
        "  expect(sumPos([])).toBe(1);",
        "  expect(isFlag(true)).toBe(true);",
        "  expect(isFlag(false)).toBe(false);",
        "});",
      ].join("\n"),
    );
    const syncRep = runPlantedFaultCanary({ repoRoot: dir, testCmd: "bun test ./tests/ops.test.ts", targets: ["src/ops.ts"], maxMutants: 5, minKillRate: 0.75 });
    assert.equal(syncRep.passed, true);
    assert.equal(syncRep.killedMutants, 5);
    assert.equal(syncRep.invalidKills, 0);

    const asyncRep = await runPlantedFaultCanaryAsync({ repoRoot: dir, testCmd: "bun test ./tests/ops.test.ts", targets: ["src/ops.ts"], maxMutants: 5, minKillRate: 0.75, concurrency: 2 });
    assert.equal(asyncRep.passed, true);
    assert.equal(asyncRep.killedMutants, 5);
    assert.equal(asyncRep.invalidKills, 0);

    const pyNoOp = insertSemanticNoOp("a.py", "# header\n\nfrom __future__ import annotations\nx = 1\n", 1);
    assert.ok(pyNoOp.indexOf("from __future__ import annotations") < pyNoOp.indexOf("_"));

    fs.writeFileSync(path.join(dir, "src", "lib.rs"), "pub fn f(x: &&str) -> bool { let c = || true; c() }\n");
    const rsSkip = runPlantedFaultCanary({ repoRoot: dir, testCmd: "bun test ./tests/ops.test.ts", targets: ["src/lib.rs"], maxMutants: 4, minKillRate: 0.75 });
    assert.equal(rsSkip.totalMutants, 0);
  });
});
