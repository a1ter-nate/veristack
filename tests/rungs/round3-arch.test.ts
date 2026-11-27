import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scanGitDiffCheats } from "@veristack/plugin-ci-auditor";
import { discoverRepo } from "@veristack/core";
import { formatTerminalReport } from "@veristack/core";
import { scanSingleFile } from "@veristack/plugin-harnesses";
import { runDoctor } from "@veristack/plugin-harnesses";
import { manageHooks } from "@veristack/plugin-harnesses";
import { executeHookEvent } from "@veristack/plugin-control-plane";
import { scanRepo } from "@veristack/core";
import { parseAndValidateCommandArgv, sanitizeShellBlock, validateExecutableCommand } from "@veristack/plugin-control-plane";
import { auditDeclaredArchetype, discoverWorkspaces, loadRungManifest } from "@veristack/core";
import { runPlantedFaultCanary } from "@veristack/plugin-canary";
import { evaluateCrapForCoverageFile, reportParsers } from "@veristack/plugin-canary";
import { auditCodeownersPerimeter, parseGitHubWorkflow } from "@veristack/plugin-ci-auditor";
import { fitEmpiricalBigO } from "@veristack/plugin-zero-defect";
import { compareInvariantSnapshots, inferDynamicInvariants } from "@veristack/plugin-zero-defect";
import { auditFormalSync } from "@veristack/plugin-laws-formal";
import { evaluateSpcSeries } from "@veristack/plugin-zero-defect";
import { auditLaws } from "@veristack/plugin-laws-formal";
import { generateMcdcVectors } from "@veristack/plugin-zero-defect";

function makeTempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function initGitRepo(dir: string): void {
  spawnSync("git", ["init", "-q"], { cwd: dir });
  spawnSync("git", ["config", "user.email", "test@example.com"], { cwd: dir });
  spawnSync("git", ["config", "user.name", "Test User"], { cwd: dir });
}

test("zero-shell command audit blocks shell redirects, env prefixes, quoting splits, and bunfig preload while allowing go test -v", () => {
  assert.notEqual(validateExecutableCommand("R2", "bun test > /dev/null && echo '1 pass'"), null);
  assert.notEqual(validateExecutableCommand("R2", "PATH=/tmp/fake:$PATH vitest run"), null);
  assert.notEqual(validateExecutableCommand("R2", "bun test --ver''sion"), null);
  assert.notEqual(validateExecutableCommand("R2", "vitest --help"), null);
  assert.notEqual(validateExecutableCommand("R2", "go test -run=^$ ./..."), null);
  assert.notEqual(validateExecutableCommand("R2", "./scripts/bun test"), null);
  assert.equal(validateExecutableCommand("R2", "go test -v -race ./..."), null);
  assert.equal(validateExecutableCommand("R1", "staticcheck ./... && go vet ./..."), null);
  assert.equal(validateExecutableCommand("R6", "pytest --benchmark-only tests/bench.py"), null);
  assert.notEqual(validateExecutableCommand("R6", "pytest tests/bench.py"), null);

  const dir = makeTempDir("vstack-bunfig-");
  try {
    fs.writeFileSync(path.join(dir, "bunfig.toml"), '[test]\npreload = ["./evil.ts"]\n', "utf8");
    const res = parseAndValidateCommandArgv("R2", "bun test", dir);
    assert.ok(res.error?.includes("preload"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("sanitizeShellBlock skips if/for/case conditional blocks", () => {
  const active = sanitizeShellBlock("if false; then\n  bun test\nfi\nfor x in; do\n  vitest run\ndone\n");
  assert.deepEqual(active, []);
});

test("positive allowExcluded rejects source/domain paths and accepts examples/", () => {
  const dir = makeTempDir("vstack-allow-");
  try {
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".verification", "rungs.json"),
      JSON.stringify({ schemaVersion: 1, archetype: "library", allowExcluded: ["domain/"], rungs: {} }),
      "utf8",
    );
    assert.ok(loadRungManifest(dir).error?.includes("strictly allowlisted"));

    fs.writeFileSync(
      path.join(dir, ".verification", "rungs.json"),
      JSON.stringify({ schemaVersion: 1, archetype: "library", allowExcluded: ["examples/*/caught/"], rungs: {} }),
      "utf8",
    );
    assert.equal(loadRungManifest(dir).error, undefined);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("semantic AST no-op canary defeats whitespace-stripping source hash cheats", () => {
  const dir = makeTempDir("vstack-noop-");
  try {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "src", "calc.ts"),
      "export function double(x: number): number {\n  if (x > 0) return x * 2;\n  return 0;\n}\n",
      "utf8",
    );
    const origStripped = fs.readFileSync(path.join(dir, "src", "calc.ts"), "utf8").replace(/\s+/g, "");
    fs.writeFileSync(
      path.join(dir, "tests", "calc.test.ts"),
      [
        'import { expect, test } from "bun:test";',
        'import fs from "node:fs";',
        'import path from "node:path";',
        'test("ws-stripped hash cheat", () => {',
        '  const s = fs.readFileSync(path.resolve("src/calc.ts"), "utf8").replace(/\\s+/g, "");',
        `  expect(s).toBe(${JSON.stringify(origStripped)});`,
        "});",
      ].join("\n"),
      "utf8",
    );
    const res = runPlantedFaultCanary({
      repoRoot: dir,
      testCmd: "bun test ./tests/calc.test.ts",
      targets: ["src/calc.ts"],
      maxMutants: 2,
      minKillRate: 0.75,
    });
    assert.equal(res.passed, false);
    assert.ok(res.invalidKills > 0 || res.survivors.some((s) => s.operator.includes("noop")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("true per-function CRAP catches 0%-covered complex function inside high-coverage file", () => {
  const dir = makeTempDir("vstack-crap-");
  try {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    const lines = [
      "export function trivial(): number {",
      "  const a = 1;",
      "  const b = 2;",
      "  const c = 3;",
      "  const d = 4;",
      "  const e = 5;",
      "  const f = 6;",
      "  const g = 7;",
      "  const h = 8;",
      "  return a + b + c + d + e + f + g + h;",
      "}",
      "export function complexUncovered(x: number): number {",
      "  if (x === 1) return 1;",
      "  if (x === 2) return 2;",
      "  if (x === 3) return 3;",
      "  if (x === 4) return 4;",
      "  if (x === 5) return 5;",
      "  if (x === 6) return 6;",
      "  return 0;",
      "}",
    ];
    fs.writeFileSync(path.join(dir, "src", "mod.ts"), `${lines.join("\n")}\n`, "utf8");
    const daLines = [
      ...Array.from({ length: 11 }, (_, i) => `DA:${i + 1},1`),
      ...Array.from({ length: 9 }, (_, i) => `DA:${i + 12},0`),
    ].join("\n");
    fs.writeFileSync(path.join(dir, "lcov.info"), `SF:src/mod.ts\n${daLines}\nend_of_record\n`, "utf8");
    const crap = evaluateCrapForCoverageFile(dir, "lcov.info", 30);
    assert.equal(crap.passed, false);
    assert.equal(crap.offenders[0]?.coveragePct, 0);
    assert.ok((crap.offenders[0]?.cyclomaticComplexity ?? 0) >= 7);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("JUnit nested testsuite and TRX inconclusive/notRunnable parse accurately", () => {
  const nested = `<testsuites><testsuite tests="3" failures="0" disabled="1"><testsuite tests="3" failures="0"/></testsuite></testsuites>`;
  assert.deepEqual(reportParsers.parseJunitOrTrx(nested), { passed: 2, failed: 0, skipped: 1 });
  const trx = `<Counters total="5" executed="5" passed="3" failed="0" error="0" timeout="0" aborted="0" inconclusive="1" notRunnable="1" />`;
  assert.deepEqual(reportParsers.parseJunitOrTrx(trx), { passed: 3, failed: 2, skipped: 0 });
  assert.equal(reportParsers.parseJunitOrTrx(`<testsuite tests="NaN" failures="0" />`), undefined);
});

test("diff-cheats pairs .js -> .ts migrations cleanly and scopes fit() strictly to test files", () => {
  const dir = makeTempDir("vstack-diff-field-");
  try {
    initGitRepo(dir);
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "src", "geom.js"),
      "export function fit(box) {\n  if (box === null) return 0;\n  return box.size;\n}\n",
      "utf8",
    );
    spawnSync("git", ["add", "."], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "base"], { cwd: dir });

    fs.unlinkSync(path.join(dir, "src", "geom.js"));
    fs.writeFileSync(
      path.join(dir, "src", "geom.ts"),
      "export interface Box { size: number; }\nexport function fit(box: Box): number {\n  return box.size;\n}\nexport const v = fit({ size: 4 });\n",
      "utf8",
    );
    spawnSync("git", ["add", "-A"], { cwd: dir });
    const findings = scanGitDiffCheats(dir, "HEAD");
    assert.equal(findings.some((f) => f.rule === "diff-ts-skipped-test"), false);
    assert.equal(findings.some((f) => f.rule === "diff-invariant-guard-dropped"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("behavioral anti-sham guards catch silent catch return and catchall accepted:true stubs", () => {
  const dir = makeTempDir("vstack-sham-");
  try {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "src", "handler.ts"),
      [
        "export function handle(kind: string): { accepted: boolean } {",
        "  try {",
        "    if (kind === 'x') return { accepted: true };",
        "  } catch {",
        "    return { accepted: true };",
        "  }",
        "  switch (kind) {",
        "    default: return { accepted: true };",
        "  }",
        "}",
      ].join("\n"),
      "utf8",
    );
    const report = scanRepo(dir);
    assert.equal(report.findings.some((f) => f.rule === "no-silent-catch-return"), true);
    assert.equal(report.findings.some((f) => f.rule === "no-catchall-success-stub"), true);
    const term = formatTerminalReport(report);
    assert.ok(term.includes("HYGIENE-ONLY SCAN"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("laws --verify, formal-sync, big-o, spc, invariants, and mcdc fail closed on degenerate inputs", () => {
  const dir = makeTempDir("vstack-zd-");
  try {
    fs.mkdirSync(path.join(dir, ".verification", "laws"), { recursive: true });
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "a.ts"), "export const a = 1;\n", "utf8");
    fs.writeFileSync(
      path.join(dir, ".verification", "laws", "app.laws.json"),
      JSON.stringify({ laws: [{ id: "L1", witnessRef: "src/a.ts" }] }),
      "utf8",
    );
    const lawRes = auditLaws(discoverRepo(dir), { verify: true });
    assert.equal(lawRes.findings.some((f) => f.rule === "laws-unverifiable-witness"), true);

    fs.writeFileSync(
      path.join(dir, ".verification", "control-plan.json"),
      JSON.stringify({ formalChecks: [{ id: "F1", specFile: "src/a.ts", coveredPaths: [], syncCommit: "abcdef1", contentHash: "123" }] }),
      "utf8",
    );
    const fsRes = auditFormalSync(discoverRepo(dir));
    assert.equal(fsRes.some((f) => f.rule === "formal-sync-empty-covered-paths"), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  assert.equal(fitEmpiricalBigO([{ n: 10, timeMs: 1 }, { n: 10, timeMs: 2 }, { n: 10, timeMs: 3 }]).passed, false);
  assert.equal(fitEmpiricalBigO([{ n: 10, timeMs: 1 }, { n: 20, timeMs: 2 }, { n: 40, timeMs: 4 }], { maxTimeExponent: Number.NaN }).passed, false);
  assert.equal(evaluateSpcSeries("lat", [], 100).status, "spec_breach");
  assert.equal(evaluateSpcSeries("lat", [10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 50], 100).status, "drift_warning");

  const baseSnap = inferDynamicInvariants([
    { fn: "calc", result: 1 },
    { fn: "calc", result: 2 },
    { fn: "calc", result: 3 },
  ]);
  const emptySnap = inferDynamicInvariants([]);
  assert.equal(compareInvariantSnapshots(baseSnap, emptySnap).passed, false);
  assert.deepEqual(generateMcdcVectors("a && true").variables, ["a"]);
});

test("hooks block control-plane edits, re-report unfixed stop errors, and doctor detects disableAllHooks and info downgrades", () => {
  const dir = makeTempDir("vstack-hooks-r3-");
  try {
    initGitRepo(dir);
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "bad.ts"), "export const x = (1 as any) + 1;\n", "utf8");
    spawnSync("git", ["add", "."], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: dir });

    const pre = executeHookEvent("pre-edit", JSON.stringify({ tool_input: { file_path: ".vstack.json", content: "{}" } }), { repoRoot: dir });
    assert.equal((JSON.parse(pre.stdout) as { permission: string }).permission, "deny");

    executeHookEvent("post-edit", JSON.stringify({ session_id: "s1", tool_input: { file_path: "src/bad.ts" } }), { repoRoot: dir });
    const stop = executeHookEvent("stop", JSON.stringify({ session_id: "s1" }), { repoRoot: dir });
    assert.equal((JSON.parse(stop.stdout) as { decision: string }).decision, "block");

    assert.throws(() => scanSingleFile("src/nonexistent.ts", { repoRoot: dir }), /File not found/);

    fs.mkdirSync(path.join(dir, ".claude"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".claude", "settings.local.json"), JSON.stringify({ disableAllHooks: true, hooks: { PostToolUse: [{ command: "npx vstack hook post-edit" }] } }), "utf8");
    fs.writeFileSync(path.join(dir, ".vstack.json"), JSON.stringify({ rules: { "no-chained-or-any-cast": "info" } }), "utf8");
    assert.equal(manageHooks(dir, "status").enabled, false);
    assert.equal(runDoctor(dir).healthy, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("workflow-audit and manifest workspace discovery enforce CODEOWNERS precedence, tag-only push, and C# test project exclusion", () => {
  const dir = makeTempDir("vstack-wf-r3-");
  try {
    fs.mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
    fs.mkdirSync(path.join(dir, "App"), { recursive: true });
    fs.mkdirSync(path.join(dir, "App.Tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "App", "App.csproj"), '<Project Sdk="Microsoft.NET.Sdk"></Project>\n', "utf8");
    fs.writeFileSync(path.join(dir, "App", "Program.cs"), "public class Program {}\n", "utf8");
    fs.writeFileSync(path.join(dir, "App.Tests", "App.Tests.csproj"), '<Project Sdk="Microsoft.NET.Sdk"></Project>\n', "utf8");
    fs.writeFileSync(path.join(dir, "CODEOWNERS"), "* @root-owner\n", "utf8");
    fs.writeFileSync(path.join(dir, ".github", "CODEOWNERS"), ".verification/rungs.json\n", "utf8");
    fs.writeFileSync(
      path.join(dir, ".github", "workflows", "release.yml"),
      "on:\n  push:\n    tags:\n      - 'v*'\njobs:\n  rel:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bun test\n",
      "utf8",
    );
    const repo = discoverRepo(dir);
    const ws = discoverWorkspaces(repo);
    assert.deepEqual(ws.map((w) => w.path), ["App"]);
    const relWf = repo.files.find((f) => f.rel === ".github/workflows/release.yml");
    assert.ok(relWf);
    assert.equal(parseGitHubWorkflow(relWf).isPrBlocking, false);
    const perim = auditCodeownersPerimeter(repo.files, repo.allRelPaths);
    assert.equal(perim.passed, false);

    const mismatch = auditDeclaredArchetype({ schemaVersion: 1, archetype: "library", allowExcluded: [], rungs: {} }, "service");
    assert.equal(mismatch.some((f) => f.rule === "rung-archetype-mismatch"), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
