import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { maskCode } from "@veristack/plugin";
import { analyzeT3TestGuards } from "@veristack/plugin-lang-typescript";
import { scanGitDiffCheats } from "@veristack/plugin-ci-auditor";
import { extractSfcScript } from "@veristack/plugin-lang-typescript";
import { executeHookEvent } from "@veristack/plugin-control-plane";
import { scanRepo } from "@veristack/core";
import { parseAndValidateCommandArgv, sanitizeShellBlock } from "@veristack/plugin-control-plane";
import { auditRunnerConfigs, runGitClean } from "@veristack/plugin-control-plane";
import { loadRungManifest } from "@veristack/core";
import { evaluateCrapForCoverageFile } from "@veristack/plugin-canary";
import { auditCodeownersPerimeter } from "@veristack/plugin-ci-auditor";
import { auditManifestDowngrade } from "@veristack/plugin-control-plane";
import { runRedBeforeFix } from "@veristack/plugin-zero-defect";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-r10-"));
  try { fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function initGit(dir: string): void {
  runGitClean(dir, ["init", "-q", "-b", "main"]);
  runGitClean(dir, ["config", "user.name", "Test"]);
  runGitClean(dir, ["config", "user.email", "t@test.local"]);
}

test("round10 final: hooks global git-option skipper, pre-edit anchorBaseSha pin, session-dir protection, and all bare names", () => {
  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test", required: true } } }));
    fs.writeFileSync(path.join(dir, "src", "a.ts"), "export const a = 1;\n");
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "base"]);

    const globalGitCmds = [
      "git -C . update-ref refs/remotes/origin/main HEAD",
      "git -c core.hooksPath=/tmp/evil status",
      "git --no-pager reset --hard HEAD~1",
      "git commit --no-verify -am tidy",
      "git apply evil.patch",
      "git switch --orphan clean",
      "rm -rf /tmp/vstack-hook-sessions/abc.json",
    ];
    for (const cmd of globalGitCmds) {
      const res = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, session_id: "r10-s1", tool_name: "Bash", tool_input: { command: cmd } }), { repoRoot: dir, harness: "claude" });
      assert.equal(res.exitCode, 2, `Expected pre-edit block for: ${cmd}`);
    }

    for (const bare of ["rungs.json", "behavior-changes.json", "control-plan.json", "escapes.json", "invariants.json", "chokepoints.json"]) {
      const res = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_name: "Write", tool_input: { file_path: path.join(dir, bare), content: "{}" } }), { repoRoot: dir, harness: "claude" });
      assert.equal(res.exitCode, 2, `Expected pre-edit block for bare ${bare}`);
    }

    const baseSha = runGitClean(dir, ["rev-parse", "HEAD"]).stdout.trim();
    runGitClean(dir, ["update-ref", "refs/remotes/origin/main", baseSha]);
    executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, session_id: "r10-pin", tool_name: "Bash", tool_input: { command: "bun test" } }), { repoRoot: dir, harness: "claude" });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test ./tests/empty.test.ts", required: true } } }));
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "weaken"]);
    runGitClean(dir, ["update-ref", "refs/remotes/origin/main", "HEAD"]);
    const stopPinned = executeHookEvent("stop", JSON.stringify({ cwd: dir, session_id: "r10-pin" }), { repoRoot: dir, harness: "claude" });
    assert.equal(JSON.parse(stopPinned.stdout).decision, "block");
  });

  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test", required: true } } }));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0" }));
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "base"]);
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test ./tests/empty.test.ts", required: true } } }));
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "weaken"]);
    for (let i = 1; i <= 6; i++) {
      fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", version: `1.0.${i}` }));
      runGitClean(dir, ["add", "."]);
      runGitClean(dir, ["commit", "-q", "-m", `pad ${i}`]);
    }
    const stopNoOrigin = executeHookEvent("stop", JSON.stringify({ cwd: dir, session_id: "fresh-no-origin" }), { repoRoot: dir, harness: "claude" });
    assert.equal(JSON.parse(stopNoOrigin.stdout).decision, "block");
  });
});

test("round10 final: lifecycle-script lock, npm:/github:/nested/pnpm overrides & patchedDependencies, value-flag narrowing, and conftest/addopts/JS config hardening", () => {
  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test --concurrency 4", required: true } } }));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", devDependencies: { oxlint: "^1.0.0" } }));
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "base"]);

    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test --concurrency 4 ./tests/dummy.test.ts", required: true } } }));
    assert.ok(auditManifestDowngrade(dir, "HEAD", { downgradeOnly: true }).some((f) => f.id === "DIFF:manifest:cmd-R2"));

    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test --concurrency 4", required: true } } }));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", scripts: { postinstall: "node evil.js" }, devDependencies: { oxlint: "^1.0.0" } }));
    assert.ok(auditManifestDowngrade(dir, "HEAD", { downgradeOnly: true }).some((f) => f.id === "DIFF:manifest:pkg-lifecycle-postinstall"));
    assert.ok(scanGitDiffCheats(dir, "HEAD").some((f) => f.rule === "diff-config-strictness-downgrade"));

    const badPkgs = [
      { name: "p", overrides: { oxlint: "npm:left-pad@1.3.0" } },
      { name: "p", overrides: { pkg: { oxlint: "github:evil/oxlint" } } },
      { name: "p", resolutions: { typescript: "evil/tsc" } },
      { name: "p", peerDependencies: { vitest: "file:./fake" } },
      { name: "p", pnpm: { overrides: { oxlint: "npm:fake@1" } } },
      { name: "p", pnpm: { patchedDependencies: { "oxlint@1.0.0": "patches/oxlint.patch" } } },
    ];
    for (const bp of badPkgs) {
      fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify(bp));
      assert.ok(auditRunnerConfigs(dir), `Expected config-audit failure for ${JSON.stringify(bp)}`);
      assert.ok(auditManifestDowngrade(dir, "HEAD", { downgradeOnly: true }).length > 0);
    }
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", devDependencies: { oxlint: "^1.0.0" } }));

    fs.mkdirSync(path.join(dir, "tests", "a", "b", "c", "d"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "a", "b", "c", "d", "conftest.py"), "def pytest_pyfunc_call(pyfuncitem):\n    return True\n");
    assert.ok(auditRunnerConfigs(dir));
    fs.writeFileSync(path.join(dir, "tests", "a", "b", "c", "d", "conftest.py"), "pytest_plugins = ['evil_plug']\n");
    assert.ok(auditRunnerConfigs(dir));
    fs.unlinkSync(path.join(dir, "tests", "a", "b", "c", "d", "conftest.py"));

    fs.writeFileSync(path.join(dir, "pytest.ini"), "[pytest]\naddopts = --cov --ignore=tests/real.py\n");
    assert.ok(auditRunnerConfigs(dir));
    fs.writeFileSync(path.join(dir, "pytest.ini"), "[pytest]\naddopts = --cov-fail-under=80\n");
    assert.equal(auditRunnerConfigs(dir), null);
    fs.writeFileSync(path.join(dir, "pytest.ini"), "[pytest]\naddopts = --cov-fail-under=0\n");
    assert.ok(auditRunnerConfigs(dir)?.includes("below 1"));
    fs.unlinkSync(path.join(dir, "pytest.ini"));

    fs.writeFileSync(path.join(dir, "vitest.workspace.ts"), "const s = ['./evil.ts'];\nexport default { test: { setupFiles: s } };\n");
    assert.ok(auditRunnerConfigs(dir));
    fs.unlinkSync(path.join(dir, "vitest.workspace.ts"));

    fs.mkdirSync(path.join(dir, "packages", "app"), { recursive: true });
    fs.writeFileSync(path.join(dir, "packages", "app", "vitest.config.ts"), "export default { test: { exclude: ['tests/real.test.ts'] } };\n");
    assert.ok(auditRunnerConfigs(dir));
    fs.unlinkSync(path.join(dir, "packages", "app", "vitest.config.ts"));
  });
});

test("round10 final: sanitizeShellBlock conditionals/pipes, pnpm -F {...}..., NameError red-before-fix, String(fn) theater, and lexical polish", () => {
  assert.deepEqual(sanitizeShellBlock("[ 1 = 2 ] && bun test\n"), []);
  assert.deepEqual(sanitizeShellBlock("bun test | wc -l\n"), []);

  withTempDir((dir) => {
    assert.ok(parseAndValidateCommandArgv("R2", 'pnpm -F "{../outside}..." exec bun test', dir).error);
  });

  const strIntrospect = analyzeT3TestGuards({
    rel: "tests/s.test.ts", abs: "/tmp/s.test.ts", language: "typescript", isTest: true, isWorkflow: false, lines: 2,
    content: 'import { foo } from "../src/foo.ts";\ntest("t", () => expect(String(foo)).toContain("==="));\n',
  });
  assert.ok(strIntrospect.some((f) => f.rule === "test-source-introspection-theater"));

  const hashIntrospect = analyzeT3TestGuards({
    rel: "tests/h.test.ts", abs: "/tmp/h.test.ts", language: "typescript", isTest: true, isWorkflow: false, lines: 3,
    content: 'import crypto from "node:crypto";\nimport fs from "node:fs";\ntest("h", () => expect(crypto.createHash("sha256").update(fs.readFileSync("src/a.ts")).digest("hex")).toBe("x"));\n',
  });
  assert.ok(hashIntrospect.some((f) => f.rule === "test-source-introspection-theater"));

  const sfcTsx = extractSfcScript("App.vue", "<script lang=\"tsx\">\nexport const C = ({ x }: any) => <div><span>it's ok</span>{(x as any)}</div>;\n</script>\n");
  assert.ok(sfcTsx && sfcTsx.content.includes("as any"));

  assert.ok(maskCode("const v = obj.default / 2 + (x as any) / 3;\n", "typescript").includes("as any"));

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "hdr.py"), 'def check(headers):\n    cc = headers.get("Cache-Control", "").lower()\n    return "no-store" in cc\n');
    const report = scanRepo(dir);
    assert.equal(report.findings.some((f) => f.rule === "http-case-sensitive-header-directive"), false);
  });

  withTempDir((dir) => {
    initGit(dir);
    fs.writeFileSync(path.join(dir, "app.py"), "def ok(): return 1\n");
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "base"]);
    fs.writeFileSync(path.join(dir, "app.py"), "def ok(): return 1\ndef added(): return 2\n");
    fs.writeFileSync(path.join(dir, "test_app.py"), "import unittest\nfrom app import *\nclass T(unittest.TestCase):\n    def test_a(self):\n        self.assertEqual(added(), 2)\n");
    const rbf = runRedBeforeFix(dir, "HEAD", "python3 -m unittest discover");
    assert.equal(rbf.passed, false);
    assert.ok(rbf.reason.includes("INVALID RED"));
  });

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ archetype: "library", allowExcluded: ["   ", "examples/bad/"], rungs: {} }));
    const loaded = loadRungManifest(dir);
    assert.equal(loaded.error, undefined);
    assert.deepEqual(loaded.manifest?.allowExcluded, ["examples/bad/"]);

    fs.writeFileSync(path.join(dir, "Cargo.toml"), '[workspace]\nmembers = ["a", "b"]\ndefault-members = ["a"]\n');
    assert.ok(auditRunnerConfigs(dir));
    fs.unlinkSync(path.join(dir, "Cargo.toml"));

    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "calc.py"), "def f(x):\n    if x > 0:\n        return 1\n    return 0\n");
    fs.writeFileSync(path.join(dir, "cov.info"), "SF:src/calc.py\nDA:1,1\nDA:2,1\nDA:3,1\nDA:4,1\nend_of_record\n");
    const pyCrap = evaluateCrapForCoverageFile(dir, "cov.info", 30);
    assert.equal(pyCrap.passed, true);
    assert.equal(pyCrap.worstCrap, 2);

    const perim = auditCodeownersPerimeter(
      [{ rel: ".github/CODEOWNERS", abs: "/tmp/CODEOWNERS", isTest: false, isWorkflow: false, lines: 5, content: "\n# lock control plane\n/.verification/ @owner\n/.github/ @owner\n/package.json @owner\n" }],
      [".github/CODEOWNERS", ".github/workflows/ci.yml", ".verification/rungs.json", ".verification/behavior-changes.json", "package.json"],
    );
    assert.equal(perim.passed, true);
  });
});

test("round10 calibration: monorepo workspace build-dir skip, helper script language exclusion, scheduled R8 canaries, benign GITHUB_ENV, and retention cutoffs", () => {
  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "apps", "api", "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "apps", "api", "dist"), { recursive: true });
    fs.mkdirSync(path.join(dir, ".github", "scripts"), { recursive: true });
    fs.mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
    fs.mkdirSync(path.join(dir, "apps", "api", "scripts", "canary"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tsconfig.json"), '{"compilerOptions":{"strict":true}}\n');
    fs.writeFileSync(path.join(dir, "apps", "api", "package.json"), '{"name":"api","dependencies":{"express":"^5.0.0"}}\n');
    fs.writeFileSync(path.join(dir, "apps", "api", "src", "cutoff.ts"), "const RETENTION_MS = 86400000;\nexport function cutoff(): number { return Date.now() - RETENTION_MS; }\n");
    fs.writeFileSync(path.join(dir, "apps", "api", "src", "cutoff.test.ts"), 'import { test, expect } from "vitest";\ntest("c", () => expect(1).toBe(1));\n');
    fs.writeFileSync(path.join(dir, "apps", "api", "dist", "cutoff.js"), "// generated comment\nexport function cutoff() { return 1; }\n");
    fs.writeFileSync(path.join(dir, ".github", "scripts", "helper.py"), "print('ci helper')\n");
    fs.writeFileSync(path.join(dir, "apps", "api", "scripts", "canary", "run.mjs"), "export const ok = true;\n");
    fs.writeFileSync(path.join(dir, ".github", "workflows", "pr.yml"), [
      "on: [pull_request]",
      "jobs:",
      "  changes:",
      "    if: github.event_name != 'pull_request' || github.actor != 'bot'",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: echo ok",
      "  test:",
      "    needs: changes",
      "    if: needs.changes.outputs.api == 'true'",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: echo 'CONCURRENCY=4' >> \"$GITHUB_ENV\"",
      "      - run: vitest run",
    ].join("\n"));
    fs.writeFileSync(path.join(dir, ".github", "workflows", "production-canaries.yml"), [
      "on:",
      "  schedule:",
      "    - cron: '17 * * * *'",
      "jobs:",
      "  canary:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: node apps/api/scripts/canary/run.mjs",
    ].join("\n"));
    runGitClean(dir, ["add", "tsconfig.json", "apps/api/package.json", "apps/api/src/cutoff.ts", "apps/api/src/cutoff.test.ts", ".github", "apps/api/scripts/canary/run.mjs"]);
    runGitClean(dir, ["commit", "-q", "-m", "init"]);

    const report = scanRepo(dir);
    assert.equal(report.languages.includes("python"), false);
    assert.equal(report.findings.some((f) => f.file.includes("apps/api/dist/")), false);
    assert.equal(report.findings.some((f) => f.rule === "cdc-wall-clock-duration"), false);
    const r2 = report.rungs.find((r) => r.rung === "R2");
    const r8 = report.rungs.find((r) => r.rung === "R8");
    assert.equal(r2?.executedInCi, true);
    assert.equal(r8?.executedInCi, true);
    assert.equal(r8?.coverageGrade, "well-covered");
  });
});
