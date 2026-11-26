import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { discoverRepo, extractSfcScript } from "../../src/discover.ts";
import { scanRepo } from "../../src/ladder.ts";
import { parseAndValidateCommandArgv, scrubChildEnv } from "../../src/rungs/command-audit.ts";
import { runPlantedFaultCanary } from "../../src/rungs/mutation-probe.ts";
import { runTwoSidedOracleCheck } from "../../src/rungs/oracle-check.ts";
import { evaluateCrapForCoverageFile } from "../../src/rungs/reports.ts";
import { parseRunnerTestCounts, stripAnsi } from "../../src/rungs/runner-metrics.ts";
import { maskCode } from "../../src/test-lexical.ts";
import { auditManifestDowngrade } from "../../src/zero-defect/anti-evasion.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-r5-"));
  try {
    fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function initGit(dir: string): void {
  spawnSync("git", ["init", "-q", "-b", "main"], { cwd: dir });
  spawnSync("git", ["config", "user.name", "Test"], { cwd: dir });
  spawnSync("git", ["config", "user.email", "t@test.local"], { cwd: dir });
}

test("Arch-1: control-plane lock catches dirty working-tree edits when HEAD == origin/main, missing origin/main, and gate script edits", () => {
  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.mkdirSync(path.join(dir, "scripts"), { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "demo", scripts: { perf: "node scripts/check-perf-budget.mjs" } }));
    fs.writeFileSync(path.join(dir, "scripts", "check-perf-budget.mjs"), "const t = performance.now(); console.log(t);\n");
    const manifest = {
      schemaVersion: 1,
      archetype: "library",
      rungs: { R6: { command: "bun run perf", required: true } },
    };
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify(manifest));
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: dir });
    const headSha = (spawnSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).stdout ?? "").trim();
    spawnSync("git", ["update-ref", "refs/remotes/origin/main", headSha], { cwd: dir });
    spawnSync("git", ["remote", "add", "origin", "https://example.invalid/demo.git"], { cwd: dir });

    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({ ...manifest, allowExcluded: ["examples/*/evil/"] }));
    const verifyDirty = spawnSync(process.execPath, [binPath, "verify", dir, "--strict"], { encoding: "utf8" });
    assert.equal(verifyDirty.status, 1);
    assert.match(verifyDirty.stderr, /allowExcluded/);

    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify(manifest));
    fs.writeFileSync(path.join(dir, "scripts", "check-perf-budget.mjs"), "process.exit(0);\n");
    const scriptTamper = auditManifestDowngrade(dir, "origin/main", { failClosedOnMissingBase: true });
    assert.ok(scriptTamper.some((f) => f.message.includes("scripts/check-perf-budget.mjs")));

    fs.writeFileSync(path.join(dir, "scripts", "check-perf-budget.mjs"), "const t = performance.now(); console.log(t);\n");
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "demo", scripts: { perf: "true" } }));
    const pkgTamper = auditManifestDowngrade(dir, "origin/main", { failClosedOnMissingBase: true });
    assert.ok(pkgTamper.some((f) => f.message.includes("package.json script 'perf'")));

    spawnSync("git", ["update-ref", "-d", "refs/remotes/origin/main"], { cwd: dir });
    const missingBase = spawnSync(process.execPath, [binPath, "verify", dir, "--strict"], { encoding: "utf8" });
    assert.equal(missingBase.status, 1);
    assert.match(missingBase.stderr, /missing-base-ref/);
  });
});

test("Arch-2: typed positive argv grammar blocks spoofed veristack, external paths, clippy -A, hyperfine shell, custom reporters & allows valid multi-lang flags", () => {
  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "bin"), { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "veristack" }));
    fs.writeFileSync(path.join(dir, "bin", "vstack.mjs"), "process.exit(0);\n");
    assert.ok(parseAndValidateCommandArgv("R0", "node bin/vstack.mjs no-comments . --fail", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "bun test /tmp/external.test.ts", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "uv run --directory /tmp pytest", dir).error);
    assert.ok(parseAndValidateCommandArgv("R1", "cargo clippy -- -A warnings", dir).error);
    assert.equal(parseAndValidateCommandArgv("R1", "cargo clippy -- -D warnings", dir).error, undefined);
    assert.ok(parseAndValidateCommandArgv("R6", "hyperfine 'true'", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "vitest run --reporter ./evil.mjs", dir).error);
    assert.ok(parseAndValidateCommandArgv("R0", "eslint --max-warnings=-1 src", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "go test -count=0 ./...", dir).error);
    assert.ok(parseAndValidateCommandArgv("R5", "vstack crap --coverage lcov.info --max-crap 999 --fail", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "pytest -m trivial", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "go test -short ./...", dir).error);

    assert.equal(parseAndValidateCommandArgv("R6", "go test -bench=. -benchmem ./...", dir).error, undefined);
    assert.equal(parseAndValidateCommandArgv("R2", 'dotnet test --collect:"XPlat Code Coverage"', dir).error, undefined);
    assert.equal(parseAndValidateCommandArgv("R2", "bun test --rerun-each=3 ./tests/", dir).error, undefined);
    assert.equal(parseAndValidateCommandArgv("R1", "tsc -b --skipLibCheck", dir).error, undefined);
    assert.equal(parseAndValidateCommandArgv("R2", "cargo test --features extra -- --nocapture", dir).error, undefined);
    assert.equal(parseAndValidateCommandArgv("R2", "bun --cwd packages/a test", dir).error, undefined);
    assert.equal(parseAndValidateCommandArgv("R2", "pytest -n auto --cov-fail-under=80 -ra", dir).error, undefined);
    assert.equal(parseAndValidateCommandArgv("R0", "oxlint --type-aware -D correctness src", dir).error, undefined);

    fs.writeFileSync(path.join(dir, "bunfig.toml"), '"preload" = ["./evil.ts"]\n');
    assert.ok(parseAndValidateCommandArgv("R2", "bun test", dir).error);
    fs.writeFileSync(path.join(dir, "bunfig.toml"), '[test]\nroot = "tests/trivial"\n');
    assert.ok(parseAndValidateCommandArgv("R2", "bun test", dir).error);
  });

  const cleanEnv = scrubChildEnv({ FORCE_COLOR: "1", CLICOLOR_FORCE: "1", PATH: "/usr/bin" });
  assert.equal(cleanEnv.FORCE_COLOR, undefined);
  assert.equal(cleanEnv.NO_COLOR, "1");

  const esc = String.fromCharCode(27);
  assert.equal(stripAnsi(`${esc}[32m 3 pass${esc}[0m`), " 3 pass");
  assert.equal(parseRunnerTestCounts(`${esc}[32m 3 pass${esc}[0m\n`, [["bun", "test"]]).passed, 3);
  assert.equal(parseRunnerTestCounts("Ran 4 tests in 0.01s\n\nOK\n", [["python3", "-m", "unittest", "discover"]]).passed, 4);
  assert.equal(parseRunnerTestCounts("Summary [ 0.2s] 5 tests run: 5 passed, 0 failed\n", [["cargo", "nextest", "run"]]).passed, 5);
  assert.equal(parseRunnerTestCounts("WARNING: 1 failed earlier\n=== 2 passed in 0.1s ===\n", [["pytest"]]).failed, 0);
  assert.equal(parseRunnerTestCounts("ok pkg/a 0.01s\nok pkg/b 0.00s [no tests to run]\n", [["go", "test", "./..."]]).passed, 1);
});

test("Arch-3 & Arch-4: opaque TMPDIR canary, compile-crash rejection, newly added bunfig oracle bypass, and Rust inline cfg(test) oracle", () => {
  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "calc.ts"), "export function ok(a: number): boolean {\n  if (a === 5) return true;\n  return false;\n}\n");
    fs.writeFileSync(
      path.join(dir, "tests", "theater.test.ts"),
      'import { expect, test } from "bun:test";\ntest("peek tmpdir", () => { expect(process.env.TMPDIR ?? "").not.toMatch(/\\.tmp-m\\d+$/); });\n',
    );
    const tmpdirCheat = runPlantedFaultCanary({
      repoRoot: dir,
      testCmd: "bun test ./tests/theater.test.ts",
      targets: ["src/calc.ts"],
      maxMutants: 2,
      minKillRate: 0.75,
    });
    assert.equal(tmpdirCheat.passed, false);
    assert.equal(tmpdirCheat.killedMutants, 0);

    fs.writeFileSync(
      path.join(dir, "tests", "crash.test.ts"),
      'import { test } from "bun:test";\nimport { ok } from "../src/calc.ts";\ntest("c", () => { if (!ok(5)) { console.error("SyntaxError: Unexpected token — compilation failed"); process.exit(1); } });\n',
    );
    const crashRes = runPlantedFaultCanary({
      repoRoot: dir,
      testCmd: "bun test ./tests/crash.test.ts",
      targets: ["src/calc.ts"],
      maxMutants: 2,
      minKillRate: 0.75,
    });
    assert.equal(crashRes.passed, false);
    assert.ok(crashRes.invalidKills > 0);
  });

  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "math.ts"), "export function mul(a: number, b: number): number { return a * b; }\n");
    fs.writeFileSync(path.join(dir, "tests", "math.test.ts"), 'import { expect, test } from "bun:test";\nimport { mul } from "../src/math.ts";\ntest("mul", () => { expect(mul(3, 4)).toBe(12); });\n');
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "base"], { cwd: dir });

    fs.writeFileSync(path.join(dir, "src", "math.ts"), "export function mul(): number { return 0; }\n");
    fs.mkdirSync(path.join(dir, "tests", "bypass"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "bypass", "ok.test.ts"), 'import { expect, test } from "bun:test";\ntest("ok", () => { expect(1).toBe(1); });\n');
    fs.writeFileSync(path.join(dir, "bunfig.toml"), '[test]\nroot = "tests/bypass"\n');
    const oracleRes = runTwoSidedOracleCheck(dir, "HEAD", "bun test");
    assert.equal(oracleRes.passed, false);
  });
});

test("Arch-5 & Arch-8: CRAP sibling lambdas, Cobertura relative source, Python raw docstring, Rust cfg(test) variants, SFC <!--, TS SQLi & sham catches", () => {
  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "arr.ts"), "export function go(xs: number[]): number[] {\n  return xs.map(x => x > 0 ? x : 0).filter(y => y > 0 && y < 10 && y !== 5 && y !== 3 && y !== 2);\n}\n");
    fs.writeFileSync(path.join(dir, "lcov.info"), "SF:src/arr.ts\nDA:1,1\nDA:2,1\nDA:3,1\nend_of_record\n");
    const crap = evaluateCrapForCoverageFile(dir, "lcov.info", 30);
    assert.equal(crap.passed, true);

    fs.writeFileSync(path.join(dir, "src", "mod.py"), 'def f(x):\n    r"""\n    if a and b or c:\n        pass\n    """\n    return x\n');
    const pyMasked = maskCode(fs.readFileSync(path.join(dir, "src", "mod.py"), "utf8"), "python", true);
    assert.equal(pyMasked.includes("if a"), false);

    fs.writeFileSync(path.join(dir, "cov.xml"), '<coverage><sources><source>src</source></sources><packages><package><classes><class filename="mod.py" line-rate="1.0"><lines><line number="1" hits="1"/><line number="6" hits="1"/></lines></class></classes></package></packages></coverage>\n');
    const cob = evaluateCrapForCoverageFile(dir, "cov.xml", 30);
    assert.equal(cob.evaluatedFiles, 1);
  });

  const sfc = extractSfcScript("src/A.svelte", '<script lang="ts">\nconst open = "<!--";\nconst bad = (1 as any);\n</script>\n<!-- tpl -->');
  assert.ok(sfc && sfc.content.includes("as any"));

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src", "app", "api", "auth", "session"), { recursive: true });
    fs.mkdirSync(path.join(dir, "src", "mcp"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "src", "lib.rs"),
      "pub fn ok() -> i32 { 1 }\n#[cfg(all(test, unix))]\n#[allow(clippy::unwrap_used)]\nmod tests {\n  struct H { is_running: bool, is_stopped: bool }\n  fn t() { let _ = Some(1).unwrap(); }\n}\n",
    );
    fs.writeFileSync(
      path.join(dir, "src", "sqli.ts"),
      "export async function run(req: { params: { id: string } }, db: { query: (s: string) => Promise<void> }) {\n  const q = `SELECT * FROM u WHERE id = ${req.params.id}`;\n  await db.query(q);\n  await db.query('DELETE FROM u WHERE id = ' + req.params.id);\n}\n",
    );
    fs.writeFileSync(
      path.join(dir, "src", "sham.ts"),
      "export function h() { try { return 1; } catch (err) { console.warn({ err }); return { ok: true }; } }\n",
    );
    fs.writeFileSync(
      path.join(dir, "src", "sham.py"),
      "import logging\ndef h():\n    try:\n        return 1\n    except Exception as e:\n        logging.warning(e)\n        return True\n",
    );
    fs.writeFileSync(
      path.join(dir, "src", "Sham.cs"),
      "public class S { public object H() { try { return 1; } catch (Exception) { return Results.Ok(new { accepted = true }); } } }\n",
    );
    fs.writeFileSync(path.join(dir, "src", "stubs.pyi"), "from typing import Any\ndef parse(x: dict[str, Any]) -> Any: ...\n");
    fs.writeFileSync(path.join(dir, "src", "sync.ts"), "import fs from 'node:fs';\nexport async function r(p: string) { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } }\n");
    fs.writeFileSync(path.join(dir, "src", "mcp", "http-client.ts"), "export async function ping(u: string) { const r = await fetch(u); console.log(r.status); }\n");
    fs.writeFileSync(path.join(dir, "src", "app", "api", "auth", "session", "route.ts"), "export async function GET() { return Response.json({ user: 1 }); }\n");
    fs.writeFileSync(path.join(dir, "src", "a.ts"), "export * from './b.ts';\n");
    fs.writeFileSync(path.join(dir, "src", "b.ts"), "export * from './a.ts';\n");
    fs.writeFileSync(path.join(dir, "src", "Worker.cs"), "builder.Services.AddDbContext<AppDbContext>();\nbuilder.Services.AddHostedService<SyncWorker>();\npublic class SyncWorker { public SyncWorker(AppDbContext db) {} }\n");
    fs.writeFileSync(path.join(dir, "src", "cell.rs"), "pub fn f(cell: &RefCell<Vec<i32>>, callback: fn(usize)) { let n = { let items = cell.borrow(); items.len() }; callback(n); }\n");

    const rep = scanRepo(dir);
    const byFile = (f: string) => rep.findings.filter((x) => x.file === f).map((x) => x.rule);
    assert.deepEqual(byFile("src/lib.rs"), []);
    assert.equal(byFile("src/sqli.ts").filter((r) => r === "ast-taint-to-sink").length, 2);
    assert.ok(byFile("src/sham.ts").includes("no-silent-catch-return"));
    assert.ok(byFile("src/sham.py").includes("no-silent-catch-return"));
    assert.ok(byFile("src/Sham.cs").includes("no-silent-catch-return"));
    assert.deepEqual(byFile("src/stubs.pyi"), []);
    assert.equal(byFile("src/sync.ts").includes("ast-missing-await-in-try"), false);
    assert.equal(byFile("src/mcp/http-client.ts").includes("mcp-stdio-stdout-pollution"), false);
    assert.ok(byFile("src/app/api/auth/session/route.ts").includes("auth-get-missing-no-store"));
    assert.ok(rep.findings.some((x) => x.rule === "graph-circular-module-dependency"));
    assert.ok(byFile("src/Worker.cs").includes("arch-dotnet-di-captive-or-unvalidated-scope"));
    assert.equal(byFile("src/cell.rs").includes("rust-reentrant-callback-under-borrow"), false);
  });

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "packages", "empty"), { recursive: true });
    fs.mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "root", scripts: { test: "bun test" } }));
    fs.writeFileSync(path.join(dir, "packages", "empty", "package.json"), JSON.stringify({ name: "empty" }));
    fs.writeFileSync(path.join(dir, ".github", "workflows", "ci.yml"), "on: [pull_request]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - working-directory: packages/empty\n        run: bun run test\n");
    const repo = discoverRepo(dir);
    assert.equal(repo.ci.runsUnitTests, false);
  });
});
