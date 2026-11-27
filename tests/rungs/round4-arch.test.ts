import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanGitDiffCheats } from "@veristack/plugin-ci-auditor";
import { discoverRepo } from "@veristack/core";
import { scanSingleFile } from "@veristack/plugin-harnesses";
import { runDoctor } from "@veristack/plugin-harnesses";
import { manageHooks } from "@veristack/plugin-harnesses";
import { executeHookEvent } from "@veristack/plugin-control-plane";
import { scanRepo } from "@veristack/core";
import { parseAndValidateCommandArgv, validateExecutableCommand } from "@veristack/plugin-control-plane";
import { loadRungManifest } from "@veristack/core";
import { runPlantedFaultCanary } from "@veristack/plugin-canary";
import { runTwoSidedOracleCheck } from "@veristack/plugin-canary";
import { computeRepoTreeHash, loadValidReceipts, runRungAndWriteReceipt } from "@veristack/plugin-canary";
import { evaluateCrapForCoverageFile, parseStructuredReports, reportParsers } from "@veristack/plugin-canary";
import { parseGitHubWorkflow } from "@veristack/plugin-ci-auditor";
import { fitEmpiricalBigO } from "@veristack/plugin-zero-defect";
import { auditFormalSync } from "@veristack/plugin-laws-formal";
import { auditLaws } from "@veristack/plugin-laws-formal";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function initGit(dir: string): void {
  spawnSync("git", ["init", "-q"], { cwd: dir });
  spawnSync("git", ["config", "user.email", "t@t.local"], { cwd: dir });
  spawnSync("git", ["config", "user.name", "T"], { cwd: dir });
}

test("positive per-runner argv grammar and DAG script expander kill P0 flag & cycle bypasses", () => {
  const blocked = [
    ["R2", "bun test -t '^(?!.*bad)'"],
    ["R2", "bun test -r ./evil.ts"],
    ["R2", "bun test --config=./evil.toml"],
    ["R2", "node --test --import ./evil.mjs"],
    ["R2", "node --test --test-reporter=./evil.mjs"],
    ["R2", "vitest run --pass-with-no-tests"],
    ["R2", "vitest run -c ./evil.config.ts"],
    ["R2", "jest --testPathIgnorePatterns=.*"],
    ["R2", "pytest -k 'not .'"],
    ["R2", "pytest -p evil_plugin"],
    ["R6", "pytest --benchmark-disable tests/bench.py"],
    ["R2", "go test -run '^$' ./..."],
    ["R2", "go test -skip '.*' ./..."],
    ["R2", "go test -exec=/usr/bin/true ./..."],
    ["R2", "cargo test -- --skip ''"],
    ["R2", "dotnet test --filter FullyQualifiedName=None"],
    ["R0", "npx --no-install -p oxlint -c 'printf hi'"],
    ["R2", "uv run -w pytest python3 -c 'print(1)'"],
    ["R0", "oxlint --allow all src"],
    ["R1", "tsc --init"],
    ["R1", "mypy --ignore-errors src"],
    ["R5", "vstack canary . --test-cmd 'bun test' --min-kill-rate 0"],
  ] as const;
  for (const [rung, cmd] of blocked) {
    assert.notEqual(validateExecutableCommand(rung, cmd), null, `expected ${rung} '${cmd}' to be blocked`);
  }

  const dir = mkTmp("vstack-dag-");
  try {
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({
      name: "victim-app",
      scripts: {
        noop: "bun run noop",
        pretest: "bun run shared",
        test: "bun run shared",
        shared: "bun test",
      },
    }), "utf8");
    assert.ok(parseAndValidateCommandArgv("R0", "bun run noop", dir).error?.includes("cyclic"));
    assert.ok(parseAndValidateCommandArgv("R2", "bun run test", dir).steps.length >= 2);
    assert.ok(parseAndValidateCommandArgv("R5", "node bin/vstack.mjs canary . --fail", dir).error?.includes("only allowed inside"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("oracle-check re-expands testCmd on restored baseRef package.json and preserves binary fixtures", () => {
  const dir = mkTmp("vstack-oracle-r4-");
  try {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ scripts: { test: "bun test ./tests/real.test.ts" } }), "utf8");
    fs.writeFileSync(path.join(dir, "src", "m.ts"), "export const add = (a: number, b: number) => a + b;\n", "utf8");
    fs.writeFileSync(path.join(dir, "tests", "real.test.ts"), 'import { expect, test } from "bun:test";\nimport { add } from "../src/m.ts";\ntest("add", () => expect(add(2, 3)).toBe(5));\n', "utf8");
    spawnSync("git", ["add", "."], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "base"], { cwd: dir });

    fs.writeFileSync(path.join(dir, "src", "m.ts"), "export const add = (a: number, b: number) => a - b;\n", "utf8");
    fs.writeFileSync(path.join(dir, "tests", "trivial.test.ts"), 'import { expect, test } from "bun:test";\ntest("ok", () => expect(1).toBe(1));\n', "utf8");
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ scripts: { test: "bun test ./tests/trivial.test.ts" } }), "utf8");
    const res = runTwoSidedOracleCheck(dir, "HEAD", "bun run test");
    assert.equal(res.passed, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("treeHash hashes .verification/reports/backdoor.mjs, canary defeats void 0 strip & /tmp counter, and CRAP owns innermost spans", () => {
  const dir = mkTmp("vstack-r4-core-");
  try {
    fs.mkdirSync(path.join(dir, ".verification", "reports"), { recursive: true });
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "a.ts"), "export const f = (x: number) => (x > 0 ? 1 : 0);\n", "utf8");
    const h1 = computeRepoTreeHash(discoverRepo(dir));
    fs.writeFileSync(path.join(dir, ".verification", "reports", "backdoor.mjs"), "export const pwn = 1;\n", "utf8");
    const h2 = computeRepoTreeHash(discoverRepo(dir));
    assert.notEqual(h1, h2);

    const origNoVoid = fs.readFileSync(path.join(dir, "src", "a.ts"), "utf8").replace(/\bvoid\s+0\s*;/g, "").replace(/\s+/g, "");
    fs.writeFileSync(path.join(dir, "tests", "a.test.ts"), [
      'import { expect, test } from "bun:test";',
      'import fs from "node:fs";',
      'test("strip void 0", () => {',
      '  const s = fs.readFileSync("src/a.ts", "utf8").replace(/\\bvoid\\s+0\\s*;/g, "").replace(/\\s+/g, "");',
      `  expect(s).toBe(${JSON.stringify(origNoVoid)});`,
      "});",
    ].join("\n"), "utf8");
    const noopRes = runPlantedFaultCanary({ repoRoot: dir, testCmd: "bun test ./tests/a.test.ts", targets: ["src/a.ts"], maxMutants: 1, minKillRate: 0.75 });
    assert.equal(noopRes.passed, false);

    fs.writeFileSync(path.join(dir, "src", "nested.ts"), [
      "export function outer(x: number): number {",
      "  const helper = () => { const a = 1; const b = 2; const c = 3; return a + b + c; };",
      "  if (x === 1) return helper();",
      "  if (x === 2) return 2;",
      "  if (x === 3) return 3;",
      "  if (x === 4) return 4;",
      "  if (x === 5) return 5;",
      "  if (x === 6) return 6;",
      "  return 0;",
      "}",
    ].join("\n"), "utf8");
    fs.writeFileSync(path.join(dir, "lcov.info"), "SF:src/nested.ts\nDA:2,1\nDA:3,0\nDA:4,0\nDA:5,0\nDA:6,0\nDA:7,0\nDA:8,0\nDA:9,0\nend_of_record\n", "utf8");
    const crap = evaluateCrapForCoverageFile(dir, "lcov.info", 30);
    assert.equal(crap.passed, false);

    const hijackedJunit = `<testsuite tests="2" failures="2"><testcase name="x"><system-out><Counters total="5" passed="5" failed="0"/></system-out></testcase></testsuite>`;
    assert.deepEqual(reportParsers.parseJunitOrTrx(hijackedJunit), { passed: 0, failed: 2, skipped: 0 });
    const wrappedJunit = `<testsuites><testsuite name="wrapper"><testsuite tests="3" failures="3"/></testsuite></testsuites>`;
    assert.deepEqual(reportParsers.parseJunitOrTrx(wrappedJunit), { passed: 0, failed: 3, skipped: 0 });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Rust comment #[cfg(test)] cannot blind analyzers, monorepo working-directory CI works, and check-file/hooks/CLI fail closed", () => {
  const dir = mkTmp("vstack-r4-lang-");
  try {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "evil.rs"), "// #[cfg(test)] mention\npub fn bad(x: Option<i32>) -> i32 { x.unwrap() }\n", "utf8");
    fs.writeFileSync(path.join(dir, ".github", "workflows", "ci.yml"), [
      "on: [pull_request]",
      "permissions: { contents: read }",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    defaults: { run: { working-directory: crates/core } }",
      "    steps:",
      "      - uses: 'evil/act@abc1234'",
      "      - run: cargo test",
    ].join("\n"), "utf8");
    fs.writeFileSync(path.join(dir, ".verification", "chokepoints.json"), "{ invalid json", "utf8");
    const scan = scanRepo(dir);
    assert.equal(scan.findings.some((f) => f.rule === "rust-prod-unwrap-or-expect"), true);
    assert.equal(scan.findings.some((f) => f.rule === "ci-unpinned-third-party-action"), true);
    assert.equal(scan.findings.some((f) => f.rule === "chokepoints-invalid-json"), true);
    const wfFile = discoverRepo(dir).files.find((f) => f.rel === ".github/workflows/ci.yml");
    assert.ok(wfFile);
    assert.ok(parseGitHubWorkflow(wfFile).activeCommands.includes("cargo test"));

    const wfCheck = scanSingleFile(path.join(dir, ".github", "workflows", "ci.yml"), { repoRoot: dir, tier: "all", strict: true });
    assert.equal(wfCheck.findings.some((f) => f.rule === "ci-unpinned-third-party-action"), true);

    fs.writeFileSync(path.join(dir, "src", "ok.ts"), "export const a = 1;\n", "utf8");
    const preEdit = executeHookEvent("pre-edit", JSON.stringify({
      tool_input: { file_path: path.join(dir, "src", "ok.ts"), old_string: "const a = 1;", new_string: "const a = (1 as any);" },
    }), { repoRoot: dir, harness: "claude" });
    assert.equal(preEdit.exitCode, 2);

    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "price.test.ts"), 'import { expect, test } from "bun:test";\ntest("p", () => expect(1).toBe(1));\n', "utf8");
    spawnSync("git", ["add", "."], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: dir });
    spawnSync("git", ["mv", "tests/price.test.ts", "tests/price.disabled.ts"], { cwd: dir });
    fs.writeFileSync(path.join(dir, ".vstackignore"), "src/\n", "utf8");
    const cheats = scanGitDiffCheats(dir, "HEAD");
    assert.equal(cheats.some((f) => f.rule === "diff-test-file-deleted"), true);
    assert.equal(cheats.some((f) => f.rule === "diff-config-strictness-downgrade"), true);

    assert.equal(runDoctor(dir).healthy, false);
    assert.equal(manageHooks(dir, "status").enabled, false);
    assert.equal(auditLaws(discoverRepo(dir), { verify: true }).findings.some((f) => f.rule === "laws-empty"), true);
    fs.writeFileSync(path.join(dir, ".verification", "control-plan.json"), JSON.stringify({ formalChecks: [] }), "utf8");
    assert.equal(auditFormalSync(discoverRepo(dir)).length > 0, true);
    assert.equal(fitEmpiricalBigO([{ n: 10, timeMs: 1 }, { n: 11, timeMs: 1 }, { n: 12, timeMs: 1 }]).passed, false);

    const cliLaws = spawnSync("node", [binPath, "laws", dir, "--verify", "--fail"], { encoding: "utf8" });
    assert.equal(cliLaws.status, 1);
    const cliDoctor = spawnSync("node", [binPath, "doctor", dir, "--fail"], { encoding: "utf8" });
    assert.equal(cliDoctor.status, 1);
    const cliFormal = spawnSync("node", [binPath, "formal-sync", dir, "--fail"], { encoding: "utf8" });
    assert.equal(cliFormal.status, 1);
    const cliDiff = spawnSync("node", [binPath, "diff-cheats", dir, "--base", "HEAD", "--fail"], { encoding: "utf8" });
    assert.equal(cliDiff.status, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("receipts, reports, and manifest edge branches stay pinned against mutation survivors", () => {
  const dir = mkTmp("vstack-r4-pins-");
  try {
    fs.mkdirSync(path.join(dir, ".verification", "receipts"), { recursive: true });
    fs.mkdirSync(path.join(dir, "coverage"), { recursive: true });
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "x.ts"), "export const x = 1;\n", "utf8");
    fs.writeFileSync(path.join(dir, "coverage", "cobertura-coverage.xml"), '<coverage><packages><package><classes><class filename="src/x.ts"><lines><line number="1" hits="1"/></lines></class></classes></package></packages></coverage>', "utf8");
    const parsedRep = parseStructuredReports(dir);
    assert.equal(parsedRep.fileCoverage.get("src/x.ts"), 1);

    const manifest = {
      schemaVersion: 1 as const,
      archetype: "library" as const,
      allowExcluded: [],
      rungs: { R2: { command: "bun test", required: true, canary: { enabled: true, maxMutants: 4, minKillRate: 0.75 } } },
    };
    const key = "test-secret-hmac-key-1234";
    const repo = discoverRepo(dir);
    const fakeBadCanary = {
      schemaVersion: 1,
      rung: "R2",
      command: "bun test",
      commitSha: "no-git",
      treeHash: computeRepoTreeHash(repo),
      exitCode: 0,
      durationMs: 10,
      metrics: { testsPassed: 2, testsFailed: 0 },
      canary: { totalMutants: 4, killedMutants: 4, survivedMutants: 0, invalidKills: 1, killRate: 1, minKillRate: 0.75, passed: true, survivors: [] },
      timestamp: "2026-01-01T00:00:00.000Z",
      digest: "hmac:invalid",
    };
    fs.writeFileSync(path.join(dir, ".verification", "receipts", "R2.json"), JSON.stringify(fakeBadCanary), "utf8");
    assert.equal(loadValidReceipts(repo, manifest, { strict: true, hmacKeyOverride: key }).receipts.size, 0);
    assert.equal(loadRungManifest(dir).manifest, undefined);
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({
      schemaVersion: 1,
      archetype: "library",
      rungs: { R0: { command: "oxlint src", required: false } },
    }), "utf8");
    const loadedOpt = loadRungManifest(dir);
    assert.equal(loadedOpt.manifest?.rungs.R0?.required, false);
    assert.throws(() => runRungAndWriteReceipt(repo, "R6", manifest, key), /not declared/);

    fs.mkdirSync(path.join(dir, "scripts"), { recursive: true });
    fs.writeFileSync(path.join(dir, "scripts", "check-perf-budget.mjs"), "console.log('fake');\n", "utf8");
    assert.ok(parseAndValidateCommandArgv("R6", "bun scripts/check-perf-budget.mjs", dir).error?.includes("veristack repository"));

    const wfCoe = {
      rel: ".github/workflows/coe.yml",
      abs: path.join(dir, ".github/workflows/coe.yml"),
      isTest: false,
      isWorkflow: true,
      lines: 10,
      content: "on: [pull_request]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - continue-on-error: \"${{ false }}\"\n        run: bun test\n      - continue-on-error: \"${{ inputs.skip }}\"\n        run: vitest run\n",
    };
    const parsedWf = parseGitHubWorkflow(wfCoe);
    assert.equal(parsedWf.activeCommands.includes("bun test"), true);
    assert.equal(parsedWf.activeCommands.includes("vitest run"), false);

    const r0Manifest = {
      schemaVersion: 1 as const,
      archetype: "library" as const,
      allowExcluded: [],
      rungs: { R0: { command: "bunx oxlint src/x.ts", required: true } },
    };
    const r0Rec = runRungAndWriteReceipt(repo, "R0", r0Manifest, key);
    assert.equal(r0Rec.metrics, undefined);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
