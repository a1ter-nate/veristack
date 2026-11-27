import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { maskCode } from "../../src/anti-slop/lexical-mask.ts";
import { analyzeT3TestGuards } from "../../src/ast/t3-immune-rules.ts";
import { parseTsAst } from "../../src/ast/ts-ast.ts";
import { extractSfcScript } from "../../src/discover.ts";
import { executeHookEvent } from "../../src/hooks/runtime.ts";
import { scanRepo } from "../../src/ladder.ts";
import { lintNoComments } from "../../src/no-comments.ts";
import { parseAndValidateCommandArgv, runArgvChain, scrubChildEnv } from "../../src/rungs/command-audit.ts";
import { auditRunnerConfigs, runGitClean } from "../../src/rungs/config-audit.ts";
import { auditDeclaredArchetype, inferArchetypeFromFiles, isHostRepoFile, loadRungManifest } from "../../src/rungs/manifest.ts";
import { insertSemanticNoOp, runPlantedFaultCanary } from "../../src/rungs/mutation-probe.ts";
import { runTwoSidedOracleCheck } from "../../src/rungs/oracle-check.ts";
import { computeRepoTreeHash, hasGitTrackedReceipts } from "../../src/rungs/receipts.ts";
import { evaluateCrapForCoverageFile, reportParsers } from "../../src/rungs/reports.ts";
import { parseRunnerTestCounts } from "../../src/rungs/runner-metrics.ts";
import { parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";
import { auditManifestDowngrade } from "../../src/zero-defect/anti-evasion.ts";
import { runRedBeforeFix } from "../../src/zero-defect/index.ts";
import { discoverRepo } from "../../src/discover.ts";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-r9-"));
  try { fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function initGit(dir: string): void {
  runGitClean(dir, ["init", "-q", "-b", "main"]);
  runGitClean(dir, ["config", "user.name", "Test"]);
  runGitClean(dir, ["config", "user.email", "t@test.local"]);
}

test("round9 arch: tool-integrity dependency lock, Python/Cargo/Jest config audits, and strict command schemas", () => {
  withTempDir((dir) => {
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", optionalDependencies: { typescript: "file:./evil-tsc" } }));
    assert.ok(auditRunnerConfigs(dir));

    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", overrides: { oxlint: "link:../fake" } }));
    assert.ok(auditRunnerConfigs(dir));

    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", bin: { tsc: "./evil.js" } }));
    assert.ok(auditRunnerConfigs(dir));

    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", jest: { testPathIgnorePatterns: ["tests/"] } }));
    assert.ok(auditRunnerConfigs(dir));

    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p" }));
    assert.equal(auditRunnerConfigs(dir), null);

    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "pytest.py"), "def main(): return 0\n");
    assert.ok(auditRunnerConfigs(dir));
    fs.unlinkSync(path.join(dir, "src", "pytest.py"));

    fs.mkdirSync(path.join(dir, "sub"), { recursive: true });
    fs.writeFileSync(path.join(dir, "sub", "conftest.py"), "def pytest_ignore_collect(collection_path, config):\n    return True\n");
    assert.ok(auditRunnerConfigs(dir));
    fs.unlinkSync(path.join(dir, "sub", "conftest.py"));

    fs.writeFileSync(path.join(dir, "Cargo.toml"), '[workspace]\nmembers = ["a"]\nexclude = ["b"]\n');
    assert.ok(auditRunnerConfigs(dir));
    fs.writeFileSync(path.join(dir, "Cargo.toml"), '[workspace.lints.clippy]\nall = { level = "allow" }\n');
    assert.ok(auditRunnerConfigs(dir));
    fs.unlinkSync(path.join(dir, "Cargo.toml"));

    assert.ok(parseAndValidateCommandArgv("R2", "python -m unittest discover -p nope.py", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "pytest --benchmark-only", dir).error);
    assert.equal(parseAndValidateCommandArgv("R6", "pytest --benchmark-only", dir).error, undefined);
    assert.ok(parseAndValidateCommandArgv("canary", "dotnet test --no-build", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "vitest run & vitest run", dir).error);
  });
});

test("round9 arch: monotonic downgradeOnly audit allows upgrades while blocking narrowing, dilution, and tool swaps", () => {
  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    const baseManifest = {
      schemaVersion: 1,
      archetype: "library",
      rungs: {
        R2: {
          command: "bun test --timeout 15000 ./tests/",
          required: true,
          canary: { enabled: true, testCommand: "bun test --timeout 15000 ./tests/a.test.ts", targets: ["src/a.ts", "src/b.ts"], maxMutants: 6, minKillRate: 0.75 },
        },
      },
    };
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify(baseManifest));
    fs.writeFileSync(path.join(dir, ".verification", "control-plan.json"), '{"syncCommit":"abc"}\n');
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", devDependencies: { typescript: "^5.9.0" } }));
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "base"]);

    const upgraded = {
      ...baseManifest,
      rungs: {
        R2: {
          command: "bun test --timeout 30000 ./tests/ ./examples/clean/",
          required: true,
          canary: { enabled: true, testCommand: "bun test --timeout 30000 ./tests/a.test.ts ./tests/b.test.ts", targets: ["src/a.ts", "src/b.ts", "src/c.ts"], maxMutants: 12, minKillRate: 0.75 },
        },
      },
    };
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify(upgraded));
    assert.deepEqual(auditManifestDowngrade(dir, "HEAD", { downgradeOnly: true }), []);

    const diluted = {
      ...baseManifest,
      rungs: {
        R2: {
          command: "bun test --timeout 15000 ./tests/",
          required: true,
          canary: { enabled: true, testCommand: "bun test --timeout 15000 ./tests/a.test.ts", targets: ["src/a.ts", "src/b.ts", "src/c.ts"], maxMutants: 6, minKillRate: 0.75 },
        },
      },
    };
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify(diluted));
    assert.ok(auditManifestDowngrade(dir, "HEAD", { downgradeOnly: true }).some((f) => f.id.includes("canary-dilute")));

    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ ...baseManifest, archetype: "cli" }));
    assert.ok(auditManifestDowngrade(dir, "HEAD", { downgradeOnly: true }).some((f) => f.id.includes("archetype")));

    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify(baseManifest));
    fs.writeFileSync(path.join(dir, ".verification", "control-plan.json"), '{"syncCommit":"forged"}\n');
    assert.ok(auditManifestDowngrade(dir, "HEAD").some((f) => f.id.includes("control-plan")));

    fs.writeFileSync(path.join(dir, ".verification", "control-plan.json"), '{"syncCommit":"abc"}\n');
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", optionalDependencies: { typescript: "file:./fake" }, devDependencies: { typescript: "^5.9.0" } }));
    assert.ok(auditManifestDowngrade(dir, "HEAD", { downgradeOnly: true }).some((f) => f.id.includes("pkg-tool-shadow")));
  });
});

test("round9 arch: hooks bare control-plane names, git fetch forgery block, anchorBaseSha pinning, and no-origin stop audit", () => {
  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test", required: true } } }));
    fs.writeFileSync(path.join(dir, "src", "a.ts"), "export const x = 1;\n");
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "base"]);

    const bareBlock = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_name: "Write", tool_input: { file_path: path.join(dir, "rungs.json"), content: "{}" } }), { repoRoot: dir, harness: "claude" });
    assert.equal(bareBlock.exitCode, 2);

    const fetchBlock = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_name: "Bash", tool_input: { command: "git fetch . +HEAD:refs/remotes/origin/main" } }), { repoRoot: dir, harness: "claude" });
    assert.equal(fetchBlock.exitCode, 2);

    const replaceBlock = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_name: "Bash", tool_input: { command: "git replace HEAD~1 HEAD" } }), { repoRoot: dir, harness: "claude" });
    assert.equal(replaceBlock.exitCode, 2);

    executeHookEvent("post-edit", JSON.stringify({ cwd: dir, session_id: "sess-r9", tool_name: "Write", tool_input: { file_path: path.join(dir, "src", "a.ts") } }), { repoRoot: dir, harness: "claude" });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test ./tests/empty.test.ts", required: true } } }));
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "downgrade"]);

    const stopRes = executeHookEvent("stop", JSON.stringify({ cwd: dir, session_id: "sess-r9" }), { repoRoot: dir, harness: "claude" });
    assert.equal(JSON.parse(stopRes.stdout).decision, "block");
  });
});

test("round9 arch: workflow-audit taint order & local action inspection, JUnit/Cobertura/pytest parsing, NoOp variants, and introspection theater", () => {
  const poisonedOrder = parseGitHubWorkflow({
    rel: ".github/workflows/ci.yml", abs: "/tmp/ci.yml", isTest: false, isWorkflow: true, lines: 14,
    content: [
      "on: [push]",
      "jobs:",
      "  t:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - env:",
      "          NODE_OPTIONS: --require=./x",
      "        run: echo 'PATH=/tmp/evil' >> \"$GITHUB_PATH\"",
      "      - run: bun test",
    ].join("\n"),
  });
  assert.equal(poisonedOrder.activeCommands.includes("bun test"), false);

  const safeActionFiles = [
    { rel: ".github/actions/setup/action.yml", abs: "/tmp/action.yml", isTest: false, isWorkflow: true, lines: 6, content: "runs:\n  using: composite\n  steps:\n    - run: echo setup\n      shell: bash\n" },
  ];
  const safeComposite = parseGitHubWorkflow({
    rel: ".github/workflows/ci.yml", abs: "/tmp/ci.yml", isTest: false, isWorkflow: true, lines: 10,
    content: "on: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/setup\n      - run: bun test\n",
  }, safeActionFiles);
  assert.equal(safeComposite.activeCommands.includes("bun test"), true);

  const nestedJunit = reportParsers.parseJunitOrTrx('<testsuites><testsuite name="outer" tests="5" failures="0"><testsuite name="inner" tests="5" failures="2"/></testsuite></testsuites>');
  assert.ok(nestedJunit && nestedJunit.failed >= 2);

  const pySkip = parseRunnerTestCounts("1 passed, 2 skipped in 0.05s\n", [["pytest", "-q"]]);
  assert.equal(pySkip.matched, true);
  assert.equal(pySkip.passed, 1);

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "fn.ts"), "export function a() { return 1; }\n\nexport function f(a: boolean, b: boolean) {\n  if (a && b) return 1;\n  return 0;\n}\n");
    fs.writeFileSync(path.join(dir, "cov.xml"), '<coverage><packages><package><classes><class name="fn" filename="src/fn.ts" line-rate="1.0"><lines><line number="1" hits="1"/><line number="3" hits="1"/><line number="4" hits="1" branch="true" condition-coverage="50% (1/2)"/><line number="5" hits="1"/></lines></class></classes></package></packages></coverage>');
    const crap = evaluateCrapForCoverageFile(dir, "cov.xml", 30);
    assert.equal(crap.evaluatedFiles, 1);
    assert.equal(crap.worstCrap, 4.13);
  });

  const pyMultiFuture = 'from __future__ import (\n    annotations,\n    division,\n)\nx = 1\n';
  const pyMut = insertSemanticNoOp("a.py", pyMultiFuture, 0);
  assert.ok(pyMut.indexOf(")") < pyMut.indexOf("if False:"));

  const tsBoolNoOp = insertSemanticNoOp("a.ts", "export function f(x: number) { if (x > 0) return 1; return 0; }\n", 2);
  assert.ok(tsBoolNoOp.includes("Boolean("));

  const jsIntrospect = analyzeT3TestGuards({
    rel: "tests/t.test.ts", abs: "/tmp/t.test.ts", language: "typescript", isTest: true, isWorkflow: false, lines: 2,
    content: 'import { foo } from "../src/foo.ts";\ntest("t", () => expect(foo.toString()).toContain("==="));\n',
  });
  assert.ok(jsIntrospect.some((f) => f.rule === "test-source-introspection-theater"));

  const pyIntrospect = analyzeT3TestGuards({
    rel: "tests/test_a.py", abs: "/tmp/test_a.py", language: "python", isTest: true, isWorkflow: false, lines: 2,
    content: "import inspect\ndef test_a(): assert '==' in inspect.getsource(foo)\n",
  });
  assert.ok(pyIntrospect.some((f) => f.rule === "test-source-introspection-theater"));
});

test("round9 arch: unified lexical scanner cross-language FP calibration (TSX, SFC, SQL, Go, TS, C#, Astro)", () => {
  const tsxApos = "export const C = ({ x }: { x: unknown }) => <div><span>it's fine</span>{(x as any)}</div>;\n";
  assert.ok(maskCode(tsxApos, "typescript").includes("as any"));

  const sfcRe = extractSfcScript("App.vue", '<script setup lang="ts">\nexport default /[</script>]/;\nconst s = `${`</script>`}`;\nexport const y = (1 as any);\n</script>\n');
  assert.ok(sfcRe && sfcRe.content.includes("as any"));

  const astroAst = parseTsAst({ rel: "Page.astro.ts", abs: "/tmp/Page.astro.ts", language: "typescript", isTest: false, isWorkflow: false, lines: 1, content: "export const el = <div>hello</div>;\n" });
  assert.ok(astroAst !== null);

  const sqlMasked = maskCode("SELECT E'it\\'s' FROM t;", "sql", true);
  assert.ok(sqlMasked.includes("FROM t"));

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "up.sql"), "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$\nBEGIN\n  CREATE POLICY p ON items USING (auth.uid() = user_id);\nEND;\n$$;\nINSERT INTO items(id, val) VALUES (1, 'a') ON CONFLICT (id) DO UPDATE SET val = NULL;\n");
    fs.writeFileSync(path.join(dir, "src", "redis.go"), 'package p\nimport "context"\ntype R struct{}\nfunc (r *R) Do(ctx context.Context, cmd string) error { return nil }\nfunc Run(ctx context.Context, r *R) error { return r.Do(ctx, "PING") }\n');
    fs.writeFileSync(path.join(dir, "src", "retry.ts"), "export function limit(retries: number, maxRetries: number): number { return Math.max(retries, maxRetries); }\n");
    fs.writeFileSync(path.join(dir, "src", "OrderResult.cs"), "public record OrderResult(string Status);\n");
    const report = scanRepo(dir);
    const fpRules = report.findings.filter((f) => ["sql-rls-policy-missing-tenant-predicate", "sql-eq-null", "go-unclosed-http-body", "math-floor-ceiling-inversion", "string-wire-dto"].includes(f.rule));
    assert.deepEqual(fpRules, []);
  });
});

test("round9 arch: manifest archetype inference & allowExcluded, oracle-check head isolation, receipts hash, hooks variants, and multi-lang NoOp", () => {
  assert.equal(isHostRepoFile("src/a.ts"), true);
  assert.equal(isHostRepoFile("templates/ts/a.ts"), false);
  assert.equal(isHostRepoFile("examples/ts/a.ts"), false);

  const mkFile = (rel: string, content: string, language?: "typescript"): Parameters<typeof inferArchetypeFromFiles>[0][number] => ({
    rel, abs: `/tmp/${rel}`, language, isTest: false, isWorkflow: false, lines: 1, content,
  });
  assert.equal(inferArchetypeFromFiles([mkFile("src/a.ts", "export const x = 1;", "typescript")], ["src/a.ts"]), "library");
  assert.equal(inferArchetypeFromFiles([mkFile("src/App.tsx", "export const A = () => <div/>;", "typescript")], ["src/App.tsx"]), "frontend");
  assert.equal(inferArchetypeFromFiles([mkFile("src/App.svelte", "<script></script>", "typescript")], ["src/App.svelte"]), "frontend");
  assert.equal(inferArchetypeFromFiles([mkFile("src/Page.astro", "---\n---\n<div/>", "typescript")], ["src/Page.astro"]), "frontend");
  assert.equal(inferArchetypeFromFiles([mkFile("src/srv.ts", "app.listen(3000);", "typescript")], ["src/srv.ts"]), "service");
  assert.equal(inferArchetypeFromFiles([mkFile("src/App.tsx", "export const A = () => <div/>;", "typescript"), mkFile("src/srv.ts", "app.listen(3000);", "typescript")], ["src/App.tsx", "src/srv.ts"]), "fullstack");
  assert.equal(lintNoComments("src/A.cs", "/// <summary>Public API</summary>\npublic class A {}\n", "csharp").length, 0);

  const baseM = { schemaVersion: 1 as const, archetype: "library" as const, allowExcluded: [], rungs: {} };
  assert.equal(auditDeclaredArchetype(baseM, "library").length, 0);
  assert.equal(auditDeclaredArchetype(baseM, "service").length, 1);
  assert.equal(auditDeclaredArchetype({ ...baseM, archetype: "frontend" }, "fullstack").length, 1);
  assert.equal(auditDeclaredArchetype({ ...baseM, archetype: "service" }, "frontend").length, 1);
  assert.equal(auditDeclaredArchetype({ ...baseM, archetype: "fullstack" }, "library").length, 0);

  withTempDir((dir) => {
    assert.equal(loadRungManifest(dir).manifest, undefined);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), "not json");
    assert.ok(loadRungManifest(dir).error);
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ archetype: "bogus", rungs: {} }));
    assert.ok(loadRungManifest(dir).error);
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ archetype: "library", allowExcluded: ["src/"], rungs: {} }));
    assert.ok(loadRungManifest(dir).error);
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ archetype: "library", allowExcluded: ["examples/../src/"], rungs: {} }));
    assert.ok(loadRungManifest(dir).error);
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ archetype: "library", allowExcluded: ["examples/**"], rungs: {} }));
    assert.ok(loadRungManifest(dir).error);
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({
      archetype: "library",
      allowExcluded: ["examples/bad/"],
      workspaces: [{ name: "web", path: "/apps/web/", archetype: "frontend" }],
      rungs: { R2: { command: "bun test", required: true, canary: { enabled: true, minKillRate: 0.2, maxMutants: 1 } } },
    }));
    const loaded = loadRungManifest(dir);
    assert.equal(loaded.error, undefined);
    assert.equal(loaded.manifest?.rungs.R2?.canary?.minKillRate, 0.75);
    assert.equal(loaded.manifest?.rungs.R2?.canary?.maxMutants, 4);
    assert.equal(loaded.manifest?.workspaces?.[0]?.path, "apps/web");
  });

  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "math.ts"), "export function add(a: number, b: number) { return a + b; }\n");
    fs.writeFileSync(path.join(dir, "tests", "math.test.ts"), 'import { test, expect } from "bun:test";\nimport { add } from "../src/math.ts";\ntest("add", () => expect(add(2, 3)).toBe(5));\n');
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "init"]);

    assert.equal(runTwoSidedOracleCheck(dir, "", "bun test ./tests/").passed, false);
    assert.equal(runTwoSidedOracleCheck(dir, "--bad", "bun test ./tests/").passed, false);
    assert.equal(runTwoSidedOracleCheck(dir, "nonexistent-ref", "bun test ./tests/").passed, false);

    fs.writeFileSync(path.join(dir, "tests", "math.test.ts"), 'import fs from "node:fs";\nimport { test, expect } from "bun:test";\nimport { add } from "../src/math.ts";\ntest("add", () => { fs.writeFileSync("head-side-effect.txt", "x"); expect(add(2, 3)).toBe(5); });\n');
    const cleanOracle = runTwoSidedOracleCheck(dir, "HEAD", "bun test ./tests/");
    assert.equal(cleanOracle.passed, true);
    assert.equal(fs.existsSync(path.join(dir, "head-side-effect.txt")), false);

    fs.writeFileSync(path.join(dir, "src", "math.ts"), "export function add(a: number, b: number) { return a - b; }\n");
    fs.writeFileSync(path.join(dir, "tests", "math.test.ts"), 'import { test, expect } from "bun:test";\nimport { add } from "../src/math.ts";\ntest("add", () => expect(add(2, 3)).toBe(-1));\n');
    const regOracle = runTwoSidedOracleCheck(dir, "HEAD", "bun test ./tests/");
    assert.equal(regOracle.passed, false);
    assert.ok(regOracle.reason.includes("base tests/configs"));
    assert.equal(regOracle.reason.includes("0 passing tests"), false);

    const h1 = computeRepoTreeHash(discoverRepo(dir));
    fs.writeFileSync(path.join(dir, "src", "math.ts"), "export function add(a: number, b: number) { return a + b + 1; }\n");
    const h2 = computeRepoTreeHash(discoverRepo(dir));
    assert.notEqual(h1, h2);
    assert.equal(hasGitTrackedReceipts(dir), false);
    fs.mkdirSync(path.join(dir, ".verification", "receipts"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "receipts", "R2.json"), "{}\n");
    assert.equal(computeRepoTreeHash(discoverRepo(dir)), h2);
    runGitClean(dir, ["add", "-f", ".verification/receipts/R2.json"]);
    assert.equal(hasGitTrackedReceipts(dir), true);

    assert.equal(executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_name: "Bash", tool_input: { command: "bun test" } }), { repoRoot: dir, harness: "claude" }).exitCode, 0);
    assert.equal(executeHookEvent("stop", JSON.stringify({ cwd: dir, reason: "shutdown" }), { repoRoot: dir, harness: "claude" }).exitCode, 0);

    fs.mkdirSync(path.join(dir, "tests", "newdir"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "math.ts"), "export function add(a: number, b: number) { return a * b; }\n");
    fs.writeFileSync(path.join(dir, "tests", "newdir", "mul.test.ts"), 'import { test, expect } from "bun:test";\nimport { add } from "../../src/math.ts";\ntest("mul", () => expect(add(2, 3)).toBe(6));\n');
    const rbf = runRedBeforeFix(dir, "HEAD", "bun test ./tests/newdir/mul.test.ts");
    assert.equal(rbf.passed, true);
  });

  withTempDir((cleanDir) => {
    initGit(cleanDir);
    fs.mkdirSync(path.join(cleanDir, "src"), { recursive: true });
    fs.mkdirSync(path.join(cleanDir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(cleanDir, ".verification", "ratchet.json"), JSON.stringify({ version: 1, rules: {} }));
    fs.writeFileSync(path.join(cleanDir, "src", "ok.ts"), "export const ok = 1;\n");
    runGitClean(cleanDir, ["add", "."]);
    runGitClean(cleanDir, ["commit", "-q", "-m", "clean"]);
    const realDir = fs.realpathSync(cleanDir);
    executeHookEvent("post-edit", JSON.stringify({ cwd: realDir, session_id: "clean-stop-r9", tool_name: "Write", tool_input: { file_path: path.join(realDir, "src", "ok.ts") } }), { repoRoot: realDir, harness: "claude" });
    const stateFile = path.join(os.tmpdir(), "vstack-hook-sessions", `${crypto.createHash("sha256").update(`${realDir}:clean-stop-r9`).digest("hex").slice(0, 16)}.json`);
    assert.equal(fs.existsSync(stateFile), true);
    const cleanStop = executeHookEvent("stop", JSON.stringify({ cwd: realDir, session_id: "clean-stop-r9" }), { repoRoot: realDir, harness: "claude" });
    assert.equal(cleanStop.exitCode, 0);
    assert.equal(fs.existsSync(stateFile), false);
  });

  withTempDir((pyDir) => {
    fs.mkdirSync(path.join(pyDir, "sub"), { recursive: true });
    const cwdRes = runArgvChain([["bun", "-e", "console.log(process.cwd())"]], { cwd: pyDir, env: scrubChildEnv(), timeoutMs: 5000, stepCwds: ["sub"] });
    assert.equal(cwdRes.status, 0);
    assert.equal(path.basename(cwdRes.stdout.trim()), "sub");

    fs.writeFileSync(path.join(pyDir, "calc.py"), "def is_pos(x):\n    if x <= 0:\n        return False\n    return x > 1 and x != 99\n");
    fs.writeFileSync(path.join(pyDir, "test_calc.py"), "import unittest\nfrom calc import is_pos\nclass T(unittest.TestCase):\n    def test_pos(self):\n        self.assertTrue(is_pos(2))\n        self.assertFalse(is_pos(0))\n        self.assertFalse(is_pos(99))\n");
    const pyCanary = runPlantedFaultCanary({ repoRoot: pyDir, testCmd: "python3 -m unittest discover", targets: ["calc.py"], maxMutants: 2, minKillRate: 0.75 });
    assert.equal(pyCanary.passed, true);
    assert.equal(pyCanary.killedMutants, 2);

    fs.writeFileSync(path.join(pyDir, "weak.py"), "def ok(x):\n    return x and 1\n");
    fs.writeFileSync(path.join(pyDir, "test_weak.py"), "import unittest\nfrom weak import ok\nclass W(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(ok(1), 1)\n");
    const weakCanary = runPlantedFaultCanary({ repoRoot: pyDir, testCmd: "python3 -m unittest test_weak.py", targets: ["weak.py"], maxMutants: 1, minKillRate: 0.75 });
    assert.equal(weakCanary.passed, false);
    assert.equal(weakCanary.survivors[0]?.line, 2);
    assert.equal(weakCanary.survivors[0]?.mutated, "or");
  });

  assert.ok(insertSemanticNoOp("a.go", "package p\nfunc Add(a int) int { return a }\n", 0).includes("if false {}"));
  assert.ok(insertSemanticNoOp("a.rs", "pub fn add(a: i32) -> i32 { a }\n", 0).includes("if false {}"));
  assert.ok(insertSemanticNoOp("a.cs", "public class C { public int Add(int a) { return a; } }\n", 0).includes("if (false) {}"));
  assert.ok(insertSemanticNoOp("a.ts", "export function f(x: number) { return x + 1; }\n", 1).includes("(x + 1)"));
});
