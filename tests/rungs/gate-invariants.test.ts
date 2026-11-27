import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { discoverRepo } from "../../src/discover.ts";
import { executeHookEvent } from "../../src/hooks/runtime.ts";
import { lintNoComments } from "../../src/no-comments.ts";
import { buildRatchetBaseline, evaluateRatchet } from "../../src/ratchet.ts";
import { parseAndValidateCommandArgv, runArgvChain } from "../../src/rungs/command-audit.ts";
import { auditDeclaredArchetype, inferArchetypeFromFiles, loadRungManifest } from "../../src/rungs/manifest.ts";
import { runTwoSidedOracleCheck } from "../../src/rungs/oracle-check.ts";
import { loadValidReceipts, runRungAndWriteReceipt } from "../../src/rungs/receipts.ts";
import { evaluateCrapForCoverageFile, parseStructuredReports } from "../../src/rungs/reports.ts";
import { globMatchesPath, parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";
import type { RungManifest, RungReceipt, RungStatus } from "../../src/types.ts";
import { auditFormalSync } from "../../src/zero-defect/formal-sync.ts";
import { auditLaws } from "../../src/zero-defect/laws.ts";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-gate-inv-"));
  try {
    fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function initGit(dir: string): void {
  spawnSync("git", ["init", "-q"], { cwd: dir });
  spawnSync("git", ["config", "user.email", "t@e.com"], { cwd: dir });
  spawnSync("git", ["config", "user.name", "t"], { cwd: dir });
}

function mkRungStatus(rung: "R0" | "R2", grade: RungStatus["coverageGrade"]): RungStatus {
  return {
    rung,
    name: rung,
    speedBudget: "1s",
    targetBudget: "1s",
    status: grade === "not-applicable" ? "not-applicable" : "covered",
    coverageGrade: grade,
    coverageScore: grade === "well-covered" ? 100 : 50,
    executedInCi: true,
    receiptVerified: grade === "well-covered",
    idealCoverage: "",
    observedCoverage: "",
    checks: [],
    observedCount: 1,
    evidence: [],
    gaps: [],
  };
}

test("manifest validates canary testCommand types, archetype inference, and bidirectional downgrade checks", () => {
  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".verification", "rungs.json"),
      JSON.stringify({
        schemaVersion: 1,
        archetype: "library",
        rungs: { R2: { command: "bun test", required: true, canary: { enabled: true, testCommand: "echo fake" } } },
      }),
    );
    assert.ok(loadRungManifest(dir).error);

    fs.writeFileSync(
      path.join(dir, ".verification", "rungs.json"),
      JSON.stringify({
        schemaVersion: 1,
        archetype: "library",
        rungs: { R2: { command: "bun test", required: true, canary: { enabled: true, testCommand: 123 } } },
      }),
    );
    const nonStrCanary = loadRungManifest(dir);
    assert.equal(nonStrCanary.error, undefined);
    assert.equal(nonStrCanary.manifest?.rungs.R2?.canary?.testCommand, undefined);

    fs.writeFileSync(
      path.join(dir, ".verification", "rungs.json"),
      JSON.stringify({
        schemaVersion: 1,
        archetype: "library",
        rungs: { R2: { command: "bun test", required: true, canary: { enabled: true, testCommand: "bun test ./tests/" } } },
      }),
    );
    const okCanary = loadRungManifest(dir);
    assert.equal(okCanary.error, undefined);
    assert.equal(okCanary.manifest?.rungs.R2?.canary?.testCommand, "bun test ./tests/");

    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "server.test.ts"), "app.listen(3000);\n");
    fs.writeFileSync(path.join(dir, "index.ts"), "export const v = 1;\n");
    const repo = discoverRepo(dir);
    assert.equal(inferArchetypeFromFiles(repo.files, repo.files.map((f) => f.rel)), "library");

    const svcManifest: RungManifest = { schemaVersion: 1, archetype: "service", allowExcluded: [], rungs: {} };
    const feManifest: RungManifest = { schemaVersion: 1, archetype: "frontend", allowExcluded: [], rungs: {} };
    const libManifest: RungManifest = { schemaVersion: 1, archetype: "library", allowExcluded: [], rungs: {} };
    assert.equal(auditDeclaredArchetype(svcManifest, "frontend").length, 1);
    assert.equal(auditDeclaredArchetype(svcManifest, "fullstack").length, 1);
    assert.equal(auditDeclaredArchetype(svcManifest, "service").length, 0);
    assert.equal(auditDeclaredArchetype(feManifest, "service").length, 1);
    assert.equal(auditDeclaredArchetype(feManifest, "fullstack").length, 1);
    assert.equal(auditDeclaredArchetype(feManifest, "frontend").length, 0);
    assert.equal(auditDeclaredArchetype(libManifest, "service").length, 1);
    assert.equal(auditDeclaredArchetype(libManifest, "library").length, 0);
  });
});

test("receipts enforce schema, filename match, HMAC digest, treeHash, test counts, and mutationScore", () => {
  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "ok.test.ts"), 'import { expect, test } from "bun:test";\ntest("ok", () => { expect(1).toBe(1); });\n');
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: dir });

    const manifest: RungManifest = {
      schemaVersion: 1,
      archetype: "library",
      allowExcluded: [],
      rungs: { R2: { command: "bun test ./tests/ok.test.ts", required: true } },
    };
    const key = "secret-hmac-key-1234";
    const repo = discoverRepo(dir);
    const written = runRungAndWriteReceipt(repo, "R2", manifest, key);
    assert.equal(written.exitCode, 0);
    assert.equal(written.metrics?.testsPassed, 1);
    assert.equal(Object.hasOwn(written, "canary"), false);
    assert.equal(written.ciRunId, process.env.GITHUB_RUN_ID || undefined);

    const ciCheck = spawnSync(
      "bun",
      [
        "-e",
        `import { discoverRepo } from "./src/discover.ts";
         import { loadValidReceipts, runRungAndWriteReceipt } from "./src/rungs/receipts.ts";
         const repo = discoverRepo(${JSON.stringify(dir)});
         const manifest = ${JSON.stringify(manifest)};
         const key = ${JSON.stringify(key)};
         const rec = runRungAndWriteReceipt(repo, "R2", manifest, key);
         const ok = loadValidReceipts(repo, manifest, { strict: true, hmacKeyOverride: key }).receipts.size;
         console.log(JSON.stringify({ ciRunId: rec.ciRunId ?? null, ok }));`,
      ],
      { cwd: process.cwd(), env: { ...process.env, GITHUB_RUN_ID: "ci-run-42" }, encoding: "utf8" },
    );
    assert.equal(ciCheck.status, 0);
    const ciParsed = JSON.parse(ciCheck.stdout.trim()) as { ciRunId: string | null; ok: number };
    assert.equal(ciParsed.ciRunId, "ci-run-42");
    assert.equal(ciParsed.ok, 1);

    const rcptPath = path.join(dir, ".verification", "receipts", "R2.json");
    fs.writeFileSync(rcptPath, JSON.stringify(written));
    const okLoad = loadValidReceipts(repo, manifest, { strict: true, hmacKeyOverride: key });
    assert.equal(okLoad.receipts.size, 1);

    const saved = JSON.parse(fs.readFileSync(rcptPath, "utf8")) as RungReceipt;
    const signReceipt = (base: Omit<RungReceipt, "digest">): RungReceipt => {
      const canonical = JSON.stringify({
        schemaVersion: base.schemaVersion,
        rung: base.rung,
        command: base.command,
        commitSha: base.commitSha,
        treeHash: base.treeHash,
        exitCode: base.exitCode,
        ciRunId: base.ciRunId ?? null,
        metrics: base.metrics ?? null,
        canary: base.canary ?? null,
      });
      return { ...base, digest: `hmac:${crypto.createHmac("sha256", key).update(canonical).digest("hex")}` };
    };
    const { digest: _origDigest, ...savedBase } = saved;
    void _origDigest;
    const canaryManifest: RungManifest = {
      ...manifest,
      rungs: { R2: { command: "bun test ./tests/ok.test.ts", required: true, canary: { enabled: true, maxMutants: 4, minKillRate: 0.75 } } },
    };
    const goodCanary = { totalMutants: 4, killedMutants: 4, survivedMutants: 0, invalidKills: 0, killRate: 1, minKillRate: 0.75, passed: true, survivors: [] };
    fs.writeFileSync(rcptPath, JSON.stringify(signReceipt({ ...savedBase, canary: goodCanary })));
    assert.equal(loadValidReceipts(repo, canaryManifest, { strict: true, hmacKeyOverride: key }).receipts.size, 1);
    for (const badCanary of [
      undefined,
      { ...goodCanary, passed: false },
      { ...goodCanary, killRate: 0.5 },
      { ...goodCanary, totalMutants: 2 },
      { ...goodCanary, invalidKills: 1 },
    ]) {
      const nextBase: Omit<RungReceipt, "digest"> = badCanary ? { ...savedBase, canary: badCanary } : { ...savedBase };
      fs.writeFileSync(rcptPath, JSON.stringify(signReceipt(nextBase)));
      assert.equal(loadValidReceipts(repo, canaryManifest, { strict: true, hmacKeyOverride: key }).receipts.size, 0);
    }

    const badVariants: Array<Record<string, unknown>> = [
      { ...saved, schemaVersion: 2 },
      { ...saved, rung: "" },
      { ...saved, digest: 42 },
      { ...saved, rung: "R3" },
      { ...saved, command: "bun test" },
      { ...saved, exitCode: 1 },
      { ...saved, treeHash: "deadbeef" },
      { ...saved, metrics: { testsPassed: 0, testsFailed: 0 } },
      { ...saved, metrics: { testsPassed: 2, testsFailed: 1 } },
    ];
    for (const variant of badVariants) {
      fs.writeFileSync(rcptPath, JSON.stringify(variant));
      assert.equal(loadValidReceipts(repo, manifest, { strict: true, hmacKeyOverride: key }).receipts.size, 0);
    }

    fs.writeFileSync(rcptPath, JSON.stringify(saved));
    assert.equal(loadValidReceipts(repo, manifest, { strict: true, hmacKeyOverride: "other-hmac-key-9999" }).receipts.size, 0);
  });
});

test("workflow audit enforces tag-only push, paths, paths-ignore, branches-ignore, PR types, merge_group, and shells", () => {
  const parseWf = (content: string) =>
    parseGitHubWorkflow({
      abs: "/tmp/.github/workflows/ci.yml",
      rel: ".github/workflows/ci.yml",
      content,
      lines: content.split("\n").length,
      isTest: false,
      isWorkflow: true,
    });

  assert.equal(parseWf("on:\n  push:\n    tags:\n      - 'v*'\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bun test\n").isPrBlocking, false);
  assert.equal(parseWf("on:\n  push:\n    tags:\n      - 'v*'\n    branches:\n      - main\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bun test\n").isPrBlocking, true);
  assert.equal(parseWf("on:\n  pull_request:\n    types: [labeled]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bun test\n").isPrBlocking, false);
  assert.equal(parseWf("on:\n  pull_request:\n    types: [opened, synchronize]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bun test\n").isPrBlocking, true);
  assert.equal(parseWf("on: merge_group\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bun test\n").isPrBlocking, true);
  assert.equal(parseWf("on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: python\n        run: bun test\n").activeCommands.length, 0);
  assert.equal(parseWf("on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - if: false\n        run: bun test\n").activeCommands.length, 0);
});

test("ratchet detects rung downgrades, missing rung snapshots, and preserves healthy baselines", () => {
  const rungsBase: RungStatus[] = [mkRungStatus("R0", "well-covered"), mkRungStatus("R2", "well-covered")];
  const base = buildRatchetBaseline([], rungsBase);
  assert.equal(evaluateRatchet([], base, rungsBase).passed, true);
  assert.equal(evaluateRatchet([], base, [mkRungStatus("R0", "well-covered"), mkRungStatus("R2", "not-applicable")]).passed, false);
  assert.equal(evaluateRatchet([], base, [mkRungStatus("R0", "well-covered"), mkRungStatus("R2", "poorly-covered")]).passed, false);
  assert.equal(evaluateRatchet([], { ...base, rungs: undefined }, rungsBase).passed, false);
});

test("no-comments handles Python shebangs, whitespace, and Rust doc comments strictly", () => {
  assert.equal(lintNoComments("script.py", "#!/usr/bin/env python3\nx = 1\n", "python").length, 0);
  assert.equal(lintNoComments("script.py", "#!/usr/bin/env python3", "python").length, 0);
  assert.equal(lintNoComments("script.py", 'x = "not # a comment"\n', "python").length, 0);
  assert.equal(lintNoComments("script.py", "#!/usr/bin/env python3\n# prose\nx = 1\n", "python").length, 1);

  const rsDoc = "/// Public doc\npub fn ok() -> i32 { 1 }\n";
  assert.equal(lintNoComments("lib.rs", rsDoc, "rust", { allowExportedTsDoc: true }).length, 0);
  assert.equal(lintNoComments("lib.rs", rsDoc, "rust", { allowExportedTsDoc: false }).length, 1);
  assert.equal(lintNoComments("lib.rs", "// prose\npub fn ok() -> i32 { 1 }\n", "rust", { allowExportedTsDoc: true }).length, 1);
});

test("reports preSnapshot freshness ignores stale files and accepts newly modified reports; CRAP fails uncovered branches", () => {
  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    const junitAbs = path.join(dir, "junit.xml");
    fs.writeFileSync(junitAbs, '<testsuite tests="5" failures="0" errors="0" skipped="0"></testsuite>\n');
    const st = fs.statSync(junitAbs);
    const snap = new Map<string, { mtimeMs: number; size: number }>([["junit.xml", { mtimeMs: st.mtimeMs, size: st.size }]]);
    assert.equal(parseStructuredReports(dir, { rung: "R2", preSnapshot: snap }).testsPassed, undefined);

    fs.writeFileSync(junitAbs, '<testsuite tests="7" failures="1" errors="0" skipped="0"></testsuite>\n');
    const fresh = parseStructuredReports(dir, { rung: "R2", preSnapshot: snap });
    assert.equal(fresh.testsPassed, 6);
    assert.equal(fresh.testsFailed, 1);
    const st2 = fs.statSync(junitAbs);
    assert.equal(parseStructuredReports(dir, { rung: "R2", minMtimeMs: st2.mtimeMs + 10_000 }).testsPassed, undefined);
    assert.equal(parseStructuredReports(dir, { rung: "R2", minMtimeMs: st2.mtimeMs - 10_000 }).testsPassed, 6);

    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".verification", "mutation.json"),
      JSON.stringify({ files: { "a.ts": { mutants: [{ status: "Killed" }, { status: "Killed" }, { status: "Survived" }] } } }),
    );
    const mutRep = parseStructuredReports(dir, { rung: "R5", preSnapshot: snap });
    assert.ok(typeof mutRep.mutationScore === "number" && mutRep.mutationScore > 60);

    fs.writeFileSync(
      path.join(dir, "src", "complex.ts"),
      "export function c(a: number, b: number, d: number, e: number, f: number, g: number): number {\n  if (a > 0 && b > 0 && d > 0 && e > 0 && f > 0 && g > 0) return 1;\n  return 0;\n}\n",
    );
    fs.writeFileSync(path.join(dir, "src", "types.d.ts"), "export type X = number;\n");
    fs.writeFileSync(path.join(dir, "src", "complex.test.ts"), "export const t = 1;\n");
    fs.writeFileSync(path.join(dir, "lcov.info"), "SF:src/complex.ts\nDA:1,0\nDA:2,0\nDA:3,0\nend_of_record\n");
    const crapRep = evaluateCrapForCoverageFile(dir, "lcov.info", 30);
    assert.equal(crapRep.passed, false);
    assert.deepEqual(crapRep.uncoveredRepoFiles, []);

    const chainFail = runArgvChain([["node", "-e", "process.exit(1)"], ["node", "-e", "console.log('RAN_SECOND')"]], { cwd: dir, env: process.env, timeoutMs: 5000 });
    assert.equal(chainFail.status, 1);
    assert.equal(chainFail.stdout.includes("RAN_SECOND"), false);
  });
});

test("command-audit rejects forbidden verbs and path binaries; laws enforces PROOF.bend and CODEOWNERS; hooks checks all harnesses", () => {
  withTempDir((dir) => {
    assert.ok(parseAndValidateCommandArgv("R2", "sh -c true", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "./bun test", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "node -e 1", dir).error);
    assert.equal(parseAndValidateCommandArgv("R2", "bun test ./tests/", dir).error, undefined);

    fs.mkdirSync(path.join(dir, ".verification", "laws"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.mkdirSync(path.join(dir, ".github"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "laws", "PROOF.bend"), "law L1 : Nat -> Nat\n");
    fs.writeFileSync(path.join(dir, "tests", "l1.test.ts"), "export const x = 'L1';\n");
    fs.writeFileSync(path.join(dir, ".github", "CODEOWNERS"), "/.verification/laws/ @owner\n");
    const lawOk = auditLaws(discoverRepo(dir), { verify: true });
    assert.equal(lawOk.findings.some((f) => f.rule === "laws-unowned-by-codeowners"), false);
    assert.equal(lawOk.lawFiles.length, 1);

    fs.writeFileSync(path.join(dir, ".github", "CODEOWNERS"), "/README.md @owner\n");
    const lawMissingOwner = auditLaws(discoverRepo(dir), { verify: true });
    assert.ok(lawMissingOwner.findings.some((f) => f.rule === "laws-unowned-by-codeowners"));

    fs.writeFileSync(path.join(dir, ".verification", "hooks.json"), JSON.stringify({ enabled: true, tier: "immediate", harnesses: ["claude", "codex", "cursor", "copilot", "grok"] }));
    fs.writeFileSync(path.join(dir, "clean.ts"), "export const ok = 1;\n");
    fs.writeFileSync(path.join(dir, "dirty.ts"), "export const x = (1 as any);\n");
    const claudeOk = executeHookEvent("pre-edit", JSON.stringify({ tool_name: "Write", tool_input: { file_path: "clean.ts", content: "export const ok = 1;\n" } }), { repoRoot: dir, harness: "claude" });
    assert.equal(claudeOk.exitCode, 0);
    const claudeDirty = executeHookEvent("pre-edit", JSON.stringify({ tool_name: "Write", tool_input: { file_path: "dirty.ts", content: "export const x = (1 as any);\n" } }), { repoRoot: dir, harness: "claude" });
    assert.equal(claudeDirty.exitCode, 2);
    const postClaudeDirty = executeHookEvent("post-edit", JSON.stringify({ tool_name: "Write", tool_input: { file_path: "dirty.ts" } }), { repoRoot: dir, harness: "claude" });
    assert.ok(postClaudeDirty.stdout.includes("additionalContext"));
    const postGrokDirty = executeHookEvent("post-edit", JSON.stringify({ tool_name: "Write", tool_input: { file_path: "dirty.ts" } }), { repoRoot: dir, harness: "grok" });
    assert.equal(postGrokDirty.stdout, "");
    const postCopilotClean = executeHookEvent("post-edit", JSON.stringify({ tool_name: "Write", tool_input: { file_path: "clean.ts" } }), { repoRoot: dir, harness: "copilot" });
    assert.equal(postCopilotClean.stdout, "");

    const badOracle = runTwoSidedOracleCheck(dir, "--bad-ref", "bun test");
    assert.equal(badOracle.passed, false);
  });
});

test("globMatchesPath, formal-sync subdir rejection, workspace parsing, LCOV branch coverage, and hooks tamper/tier", () => {
  assert.equal(globMatchesPath("*.bend", "nested/dir/LAWS.bend"), true);
  assert.equal(globMatchesPath("/LAWS.bend", "nested/LAWS.bend"), false);
  assert.equal(globMatchesPath("/LAWS.bend", "LAWS.bend"), true);
  assert.equal(globMatchesPath("dir/*.bend", "dir/a.bend"), true);
  assert.equal(globMatchesPath("dir/*.bend", "dir/sub/a.bend"), false);
  assert.equal(globMatchesPath("dir/**", "dir/sub/a.bend"), true);

  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "sub", ".verification"), { recursive: true });
    fs.mkdirSync(path.join(dir, "sub", "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "sub", "LAWS.bend"), "law L1 : Nat -> Nat\n");
    fs.writeFileSync(path.join(dir, "sub", "src", "a.ts"), "export const a = 1;\n");
    fs.writeFileSync(path.join(dir, "README.md"), "hi\n");
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: dir });
    const sha = (spawnSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).stdout ?? "").trim();
    fs.writeFileSync(
      path.join(dir, "sub", ".verification", "control-plan.json"),
      JSON.stringify({ schemaVersion: 1, formalChecks: [{ id: "F1", specFile: "LAWS.bend", coveredPaths: ["src/a.ts"], syncCommit: sha }] }),
    );
    const subFs = auditFormalSync(discoverRepo(path.join(dir, "sub")));
    assert.ok(subFs.some((f) => f.rule === "formal-sync-unknown-commit"));

    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".verification", "rungs.json"),
      JSON.stringify({
        schemaVersion: 1,
        archetype: "fullstack",
        rungs: {},
        workspaces: [
          { name: "app", path: "apps", archetype: "service" },
          { name: "web", path: "apps/web", archetype: "frontend" },
          { name: 123, path: "bad", archetype: "library" },
          "invalid",
        ],
      }),
    );
    const loaded = loadRungManifest(dir);
    assert.equal(loaded.manifest?.workspaces?.length, 2);
    fs.mkdirSync(path.join(dir, "apps", "web"), { recursive: true });
    fs.writeFileSync(path.join(dir, "apps", "web", "App.tsx"), "export const A = () => null;\n");
    assert.equal(auditDeclaredArchetype(loaded.manifest, "fullstack", discoverRepo(dir)).length, 0);

    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "br.ts"), "export function f(x: number): number {\n  if (x === 1) return 1;\n  if (x === 2) return 2;\n  return x > 0 ? 3 : 0;\n}\n");
    fs.writeFileSync(
      path.join(dir, "lcov.info"),
      "SF:src/br.ts\nDA:1,1\nDA:2,1\nDA:3,1\nDA:4,0\nBRDA:2,0,0,1\nBRDA:2,0,1,1\nBRDA:3,1,0,1\nBRDA:3,1,1,0\nend_of_record\n",
    );
    const covRep = parseStructuredReports(dir);
    assert.equal(covRep.fileCoverage.get("src/br.ts"), 0.75);
    const covCrap = evaluateCrapForCoverageFile(dir, "lcov.info", 30);
    assert.ok(covCrap.worstCrap > 4 && covCrap.worstCrap < 6);

    fs.writeFileSync(path.join(dir, ".verification", "hooks.json"), JSON.stringify({ enabled: true, tier: "all", harnesses: ["claude"] }));
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "hooks on"], { cwd: dir });
    fs.writeFileSync(path.join(dir, ".verification", "hooks.json"), JSON.stringify({ enabled: false, tier: "all", harnesses: ["claude"] }));
    const stopRes = executeHookEvent("stop", JSON.stringify({ cwd: dir }), { repoRoot: dir, harness: "claude" });
    assert.ok(stopRes.findings.some((f) => f.rule === "hook-protected-control-plane"));
  });
});
