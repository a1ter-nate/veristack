import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { maskCode, scanLexical } from "../../src/anti-slop/lexical-mask.ts";
import { analyzeTsAstGuards, parseTsAst } from "../../src/ast/ts-ast.ts";
import { scanGitDiffCheats } from "../../src/ci-auditor.ts";
import { extractSfcScript } from "../../src/discover.ts";
import { scanSingleFile } from "../../src/hooks/check-file.ts";
import { executeHookEvent } from "../../src/hooks/runtime.ts";
import { scanRepo } from "../../src/ladder.ts";
import { lintNoComments } from "../../src/no-comments.ts";
import { buildRatchetBaseline, evaluateRatchet } from "../../src/ratchet.ts";
import { parseAndValidateCommandArgv } from "../../src/rungs/command-audit.ts";
import { auditRunnerConfigs, runGitClean, scrubChildEnv } from "../../src/rungs/config-audit.ts";
import { insertSemanticNoOp } from "../../src/rungs/mutation-probe.ts";
import { reportParsers } from "../../src/rungs/reports.ts";
import { parseRunnerTestCounts } from "../../src/rungs/runner-metrics.ts";
import { parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";
import type { RungStatus } from "../../src/types.ts";
import { auditManifestDowngrade } from "../../src/zero-defect/anti-evasion.ts";
import { fitEmpiricalBigO } from "../../src/zero-defect/big-o.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-r8-"));
  try { fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function initGit(dir: string): void {
  runGitClean(dir, ["init", "-q", "-b", "main"]);
  runGitClean(dir, ["config", "user.name", "Test"]);
  runGitClean(dir, ["config", "user.email", "t@test.local"]);
}

test("round8 arch: zero raw spawnSync('git') outside config-audit.ts and diff.noprefix=true neutralized", () => {
  const srcDir = path.join(repoRoot, "src");
  const offenders: string[] = [];
  const rawGitRe = /spawnSync\s*\(\s*["']git["']/;
  const walk = (dir: string): void => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".ts")) {
        const rel = path.relative(repoRoot, p).split(path.sep).join("/");
        if (rel === "src/rungs/config-audit.ts") continue;
        if (rawGitRe.exec(fs.readFileSync(p, "utf8"))) offenders.push(rel);
      }
    }
  };
  walk(srcDir);
  assert.deepEqual(offenders, []);

  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "a.test.ts"), "test('a', () => expect(1).toBe(1));\n");
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "init"]);
    runGitClean(dir, ["config", "diff.noprefix", "true"]);
    fs.writeFileSync(path.join(dir, "tests", "a.test.ts"), "test.skip('a', () => expect(1).toBe(1));\n");
    const cheats = scanGitDiffCheats(dir, "HEAD");
    assert.ok(cheats.some((c) => c.file === "tests/a.test.ts"));
  });
});

test("round8 arch: positive Cargo/Nextest/Pytest/JS configs, pnpm -F, LC_EVIL scrub, and workflow GITHUB_ENV", () => {
  const cleanEnv = scrubChildEnv({ PATH: "/usr/bin", LC_ALL: "C.UTF-8", LC_EVIL: "payload" });
  assert.equal(cleanEnv.LC_ALL, "C.UTF-8");
  assert.equal(cleanEnv.LC_EVIL, undefined);

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, ".cargo"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".cargo", "config.toml"), "[alias]\nnextest = 'version'\n");
    assert.ok(auditRunnerConfigs(dir));
    fs.rmSync(path.join(dir, ".cargo"), { recursive: true, force: true });

    fs.writeFileSync(path.join(dir, "pytest.ini"), "[pytest]\naddopts = -kfake\n");
    assert.ok(auditRunnerConfigs(dir));
    fs.writeFileSync(path.join(dir, "pytest.ini"), "[pytest]\nnorecursedirs = *\n");
    assert.ok(auditRunnerConfigs(dir));
    fs.unlinkSync(path.join(dir, "pytest.ini"));

    fs.writeFileSync(path.join(dir, "vitest.config.ts"), "export default { test: { passWithNoTests: true } };\n");
    assert.ok(auditRunnerConfigs(dir));
    fs.unlinkSync(path.join(dir, "vitest.config.ts"));

    const outside = parseAndValidateCommandArgv("R2", "pnpm -F ../outside exec bun test", dir);
    assert.ok(outside.error);

    const extPerf = parseAndValidateCommandArgv("R6", "bun scripts/check-perf-budget.mjs", dir);
    assert.ok(extPerf.error);
  });

  const wf = parseGitHubWorkflow({
    rel: ".github/workflows/ci.yml", abs: "/tmp/ci.yml", isTest: false, isWorkflow: true, lines: 12,
    content: [
      "on: [push]",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: echo 'NODE_OPTIONS=--require=./x' | tee -a \"$GITHUB_ENV\"",
      "      - run: bun test",
    ].join("\n"),
  });
  assert.equal(wf.activeCommands.includes("bun test"), false);
});

test("round8 arch: hooks case-insensitive closure, Bash + PostToolUse/Stop authoritative worktree check, and dist takeover immunity", () => {
  const caseRes = executeHookEvent(
    "pre-edit",
    JSON.stringify({ cwd: repoRoot, tool_name: "Write", tool_input: { file_path: path.join(repoRoot, "src/Cli.ts"), content: "export const x = 1;\n" } }),
    { repoRoot, harness: "claude" },
  );
  assert.equal(caseRes.exitCode, 2);

  const noSpaceBash = executeHookEvent(
    "pre-edit",
    JSON.stringify({ cwd: repoRoot, tool_name: "Bash", tool_input: { command: "echo x >src/cli.ts" } }),
    { repoRoot, harness: "claude" },
  );
  assert.equal(noSpaceBash.exitCode, 2);

  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), "{}\n");
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "init"]);
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), '{"rungs":{}}\n');

    const postBash = executeHookEvent(
      "post-edit",
      JSON.stringify({ cwd: dir, tool_name: "Bash", tool_input: { command: "F=.verification/rungs.json" } }),
      { repoRoot: dir, harness: "claude" },
    );
    assert.ok(postBash.findings.some((f) => f.rule === "hook-protected-control-plane"));

    const stopRes = executeHookEvent("stop", JSON.stringify({ cwd: dir }), { repoRoot: dir, harness: "claude" });
    assert.equal(JSON.parse(stopRes.stdout).decision, "block");
  });
});

test("round8 arch: unified lexical scanner (TSX, Rust fields, Python triple quotes, SQL), Cobertura/JUnit, runner-metrics, Big-O, and ratchet", () => {
  const tsxBad = "export function Row({ x }: { x: unknown }) { return <div><span>ok</span>{(x as any)}<span>end</span></div>; }\n";
  assert.ok(maskCode(tsxBad, "typescript").includes("as any"));
  assert.equal(scanLexical("export const r = <div><span>ok</span>a || b<span>end</span></div>;\n", true, "typescript").regexSpans.length, 0);

  const rustField = "pub struct Svc { pub id: u64, #[cfg(test)] pub fake_flag: bool, }\npub fn prod_bug(v: Option<i32>) -> i32 { v.unwrap() }\n";
  assert.ok(maskCode(rustField, "rust", true).includes("v.unwrap()"));

  const pyEmptyDoc = 'def f():\n    """"""\n    return x\n';
  assert.ok(maskCode(pyEmptyDoc, "python", true).includes("return x"));

  const pySingleDoc = '"Single-line doc."\nfrom __future__ import annotations\nx = 1\n';
  const pyNoOp = insertSemanticNoOp("a.py", pySingleDoc, 0);
  assert.ok(pyNoOp.indexOf("from __future__") < pyNoOp.indexOf("if False:"));

  assert.equal(lintNoComments("src/A.tsx", "export const A = () => <p>Don't panic</p>;\n// prose comment\n", "typescript").length, 1);
  assert.equal(lintNoComments("src/a.rs", 'pub fn f() -> &\'static str { cr#"a " // not a comment"# }\n', "rust").length, 0);
  assert.equal(lintNoComments("src/a.ts", "/** Exported */\n@Controller('items')\nexport class Items {}\n", "typescript").length, 0);

  const sfc = extractSfcScript("App.vue", '<script setup lang="ts">\nconst quoteRe = /["\']/;\nexport const x = (1 as any);\n</script>\n');
  assert.ok(sfc && sfc.content.includes("as any"));

  const jsxInJs = parseTsAst({ rel: "App.js", abs: "/tmp/App.js", language: "javascript", isTest: false, isWorkflow: false, content: "export function App() { return <div>hi</div>; }\n", lines: 1 });
  assert.ok(jsxInJs !== null);

  assert.equal(scanSingleFile(path.join(repoRoot, "tests/anti-slop/gate-pin-matrix.test.ts").replace("gate-pin-matrix.test.ts", "fake.d.ts"), { repoRoot, tier: "all", content: "// ambient comment\nexport declare const x: number;\n" }).findings.length, 0);

  const cob = reportParsers.parseCoberturaXml('<coverage><packages><package><classes><class name="Dict&lt;string, int>" filename="src/a.cs" line-rate="0.9"><lines><line number="1" hits="1"/></lines></class></classes></package></packages></coverage>');
  assert.equal(cob.get("src/a.cs"), 1);

  const nestedJunit = reportParsers.parseJunitOrTrx('<testsuites><testsuite name="wrap" tests="0" failures="0"><testsuite name="inner" tests="5" failures="3"/></testsuite></testsuites>');
  assert.deepEqual(nestedJunit, { passed: 2, failed: 3, skipped: 0 });

  assert.equal(parseRunnerTestCounts("=== 5 passed in 0.01s ===\nno tests ran in 0.01s\n", [["pytest", "-q"]]).passed, 0);
  assert.equal(parseRunnerTestCounts("--- PASS: TestFake (0.00s)\n? pkg [no test files]\n", [["go", "test", "./..."]]).passed, 0);

  const linearWithConst = fitEmpiricalBigO([
    { n: 50, timeMs: 1.0 },
    { n: 100, timeMs: 1.2 },
    { n: 200, timeMs: 1.6 },
    { n: 400, timeMs: 2.4 },
    { n: 800, timeMs: 4.0 },
  ], { maxTimeExponent: 1.45 });
  assert.equal(linearWithConst.passed, true);

  const quadWithConst = fitEmpiricalBigO([
    { n: 10, timeMs: 1000.1 },
    { n: 20, timeMs: 1000.4 },
    { n: 40, timeMs: 1001.6 },
    { n: 80, timeMs: 1006.4 },
    { n: 160, timeMs: 1025.6 },
  ], { maxTimeExponent: 1.45 });
  assert.equal(quadWithConst.passed, false);

  const baseRungs: RungStatus[] = [
    { rung: "R0", name: "Static", speedBudget: "<2s", targetBudget: "100%", status: "covered", coverageGrade: "well-covered", coverageScore: 100, executedInCi: true, receiptVerified: true, idealCoverage: "", observedCoverage: "", checks: [], observedCount: 1, evidence: [], gaps: [] },
    { rung: "R1", name: "Types", speedBudget: "<10s", targetBudget: "100%", status: "covered", coverageGrade: "well-covered", coverageScore: 100, executedInCi: true, receiptVerified: true, idealCoverage: "", observedCoverage: "", checks: [], observedCount: 1, evidence: [], gaps: [] },
  ];
  const curRungs: RungStatus[] = [
    { rung: "R0", name: "Static", speedBudget: "<2s", targetBudget: "100%", status: "covered", coverageGrade: "well-covered", coverageScore: 100, executedInCi: false, receiptVerified: false, idealCoverage: "", observedCoverage: "", checks: [], observedCount: 1, evidence: [], gaps: [] },
    { rung: "R1", name: "Types", speedBudget: "<10s", targetBudget: "100%", status: "covered", coverageGrade: "well-covered", coverageScore: 90, executedInCi: true, receiptVerified: true, idealCoverage: "", observedCoverage: "", checks: [], observedCount: 1, evidence: [], gaps: [] },
  ];
  const rat = evaluateRatchet([], buildRatchetBaseline([], baseRungs), curRungs);
  assert.equal(rat.passed, false);
  assert.equal(rat.rungRegressions.length, 2);

  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test", required: true } } }));
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "init"]);
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test ./tests/trivial.test.ts", required: true } } }));
    const downgrades = auditManifestDowngrade(dir, "HEAD", { downgradeOnly: true });
    assert.ok(downgrades.length > 0);
  });

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "clean.go"), 'package p\nimport "sync"\ntype S struct { initOnce sync.Once }\nfunc (s *S) Run() { s.initOnce.Do(func() {}) }\n');
    fs.writeFileSync(path.join(dir, "src", "clean.py"), 'from datetime import UTC, datetime\ndef f(p, status: int):\n    with open(str(p), "r", encoding="utf-8") as fh:\n        _ = fh.read()\n    _ = datetime.now().replace(tzinfo=UTC)\n    match status:\n        case 200 | 201:\n            return "ok"\n        case _:\n            return "err"\n');
    fs.writeFileSync(path.join(dir, "src", "clean.ts"), 'const ALLOWED = new Set(["/home"]);\nexport function go(req: { query: { next: string } }, res: { status: (n: number) => { end: () => void }; redirect: (u: string) => void }) {\n  const target = req.query.next;\n  if (!ALLOWED.has(target)) return res.status(400).end();\n  res.redirect(target);\n}\nexport function clamp(base: number, maxWidth: number): number { return Math.max(base, maxWidth); }\n');
    const report = scanRepo(dir);
    const badRules = report.findings.filter((f) => ["go-unclosed-http-body", "py-open-missing-encoding", "py-datetime-dst-replace-tzinfo", "implicit-sm-non-exhaustive-switch", "ast-taint-to-sink", "math-floor-ceiling-inversion"].includes(f.rule));
    assert.deepEqual(badRules, []);
  });

  const astRedirectCheck = analyzeTsAstGuards({ rel: "src/r.ts", abs: "/tmp/r.ts", language: "typescript", isTest: false, isWorkflow: false, content: "export function h(req: any, res: any) { const u = req.query.u; res.redirect(u); }\n", lines: 1 });
  assert.ok(astRedirectCheck.some((f) => f.rule === "ast-taint-to-sink"));
});
