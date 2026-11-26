import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { extractSfcScript } from "../../src/discover.ts";
import { executeHookEvent } from "../../src/hooks/runtime.ts";
import { scanRepo } from "../../src/ladder.ts";
import { lintNoComments } from "../../src/no-comments.ts";
import { parseAndValidateCommandArgv, scrubChildEnv } from "../../src/rungs/command-audit.ts";
import { runPlantedFaultCanary } from "../../src/rungs/mutation-probe.ts";
import { runTwoSidedOracleCheck } from "../../src/rungs/oracle-check.ts";
import { evaluateCrapForCoverageFile } from "../../src/rungs/reports.ts";
import { parseRunnerTestCounts } from "../../src/rungs/runner-metrics.ts";
import { parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";
import { maskCode } from "../../src/test-lexical.ts";
import { auditDiffAntiEvasion, auditManifestDowngrade } from "../../src/zero-defect/anti-evasion.ts";
import { fitEmpiricalBigO } from "../../src/zero-defect/big-o.ts";
import { inferDynamicInvariants } from "../../src/zero-defect/daikon-invariants.ts";
import { evaluateSpcSeries } from "../../src/zero-defect/index.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-r6-"));
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

test("R6 Arch-1: total fail-closed hooks block nesting bombs, self-modification, Codex apply_patch slop, and VSTACK_HOOK_DISABLED on control-plane", () => {
  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.mkdirSync(path.join(dir, "node_modules", "veristack", "dist"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "hooks.json"), JSON.stringify({ enabled: true, tier: "immediate", harnesses: ["claude", "codex", "cursor"] }));

    const selfMod = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_input: { file_path: path.join(dir, "node_modules/veristack/dist/cli.mjs"), content: "process.exit(0);" } }), { repoRoot: dir, harness: "claude" });
    assert.equal(selfMod.exitCode, 2);
    assert.ok(selfMod.findings.some((f) => f.rule === "hook-protected-control-plane"));

    const envBypass = spawnSync(process.execPath, [binPath, "hook", "pre-edit", "--harness", "claude", "--repo", dir], {
      input: JSON.stringify({ cwd: dir, tool_input: { file_path: path.join(dir, ".verification/rungs.json"), content: "{}" } }),
      encoding: "utf8",
      env: { ...process.env, VSTACK_HOOK_DISABLED: "1" },
    });
    assert.equal(envBypass.status, 2);

    const bomb = `export const d = ${"!".repeat(3000)}x;\n`;
    const bombRes = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_input: { file_path: path.join(dir, "src/bomb.ts"), content: bomb } }), { repoRoot: dir, harness: "claude" });
    assert.equal(bombRes.exitCode, 2);
    assert.ok(bombRes.findings.some((f) => f.rule === "syntax-nesting-bomb"));

    const codexPatch = "*** Begin Patch\n*** Add File: src/slop.ts\n+export const x = (1 as any);\n*** End Patch\n";
    const codexRes = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_input: { input: codexPatch } }), { repoRoot: dir, harness: "codex" });
    assert.equal(codexRes.exitCode, 2);
    assert.equal(codexRes.stdout, "");
    assert.ok(codexRes.findings.some((f) => f.rule === "no-chained-or-any-cast"));

    const indentedPatch = "  *** Update File: .verification/rungs.json\n";
    const indRes = executeHookEvent("pre-edit", JSON.stringify({ cwd: dir, tool_input: { patch: indentedPatch } }), { repoRoot: dir, harness: "codex" });
    assert.equal(indRes.exitCode, 2);
    assert.ok(indRes.findings.some((f) => f.rule === "hook-protected-control-plane"));
  });
});

test("R6 Arch-2 & Arch-4: HEAD~1 downgrade lock defeats git-remote-remove, real TOML bunfig/cargo/pytest audit, pnpm -F & bun --cwd scripts, and scrubChildEnv", () => {
  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "a.test.ts"), 'import { expect, test } from "bun:test";\ntest("a", () => { expect(1).toBe(1); });\n');
    fs.writeFileSync(path.join(dir, "tests", "b.test.ts"), 'import { expect, test } from "bun:test";\ntest("b", () => { expect(2).toBe(2); });\n');
    const cleanManifest = { schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test ./tests/a.test.ts ./tests/b.test.ts", required: true } } };
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify(cleanManifest));
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "clean"], { cwd: dir });

    const guttedManifest = { schemaVersion: 1, archetype: "library", rungs: { R2: { command: "bun test ./tests/a.test.ts", required: true } } };
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify(guttedManifest));
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "gut r2"], { cwd: dir });

    const localVerify = spawnSync(process.execPath, [binPath, "verify", dir, "--strict"], { encoding: "utf8" });
    assert.equal(localVerify.status, 1);
    assert.match(localVerify.stderr, /diff-manifest-downgrade/);

    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ scripts: { pytest: "printf '=== 42 passed in 0.01s ===\\n'" } }));
    assert.ok(parseAndValidateCommandArgv("R2", "pnpm -F . pytest", dir).error);
    fs.mkdirSync(path.join(dir, "packages", "sub"), { recursive: true });
    fs.writeFileSync(path.join(dir, "packages", "sub", "package.json"), JSON.stringify({ scripts: { test: "printf ' 7 pass\\n 0 fail\\n'" } }));
    assert.ok(parseAndValidateCommandArgv("R2", "bun --cwd packages/sub test", dir).error);

    assert.ok(parseAndValidateCommandArgv("R6", "vstack no-comments . --fail", dir).error);
    assert.ok(parseAndValidateCommandArgv("R5", "vstack canary . --test-cmd \"bun test\" --max-mutants 1 --fail", dir).error);
    assert.ok(parseAndValidateCommandArgv("R5", "gremlins unleash --threshold-efficacy 0", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "dotnet test --results-directory /tmp/evil", dir).error);
    assert.ok(parseAndValidateCommandArgv("R2", "vitest run --reporter evil-pkg", dir).error);

    fs.writeFileSync(path.join(dir, "bunfig.toml"), 'test = { preload = ["./evil.ts"], root = "tests/fake" }\n');
    assert.ok(parseAndValidateCommandArgv("R2", "bun test", dir).error);
    fs.rmSync(path.join(dir, "bunfig.toml"));

    fs.mkdirSync(path.join(dir, ".cargo"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".cargo", "config.toml"), '[target."cfg(all())"]\nrunner = ["sh", "-c", "true"]\n');
    assert.ok(parseAndValidateCommandArgv("R2", "cargo test", dir).error);
    fs.rmSync(path.join(dir, ".cargo"), { recursive: true, force: true });

    const env = scrubChildEnv({ NODE_OPTIONS: "--require ./x.cjs", PYTEST_ADDOPTS: "-k x", CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER: "sh", RUSTFLAGS: "-A", PATH: "/usr/bin" });
    assert.equal(env.NODE_OPTIONS, undefined);
    assert.equal(env.PYTEST_ADDOPTS, undefined);
    assert.equal(env.RUSTFLAGS, undefined);
    assert.equal(env.CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER, undefined);

    const wfBadPaths = parseGitHubWorkflow({ abs: "/tmp/ci.yml", rel: ".github/workflows/ci.yml", content: "on:\n  pull_request:\n    paths-ignore: ['src/**']\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bun test\n", lines: 7, isTest: false, isWorkflow: true });
    assert.equal(wfBadPaths.isPrBlocking, false);

    assert.equal(auditManifestDowngrade(dir, "HEAD~1", { downgradeOnly: true }).length > 0, true);
  });
});

test("R6 Arch-3 & Arch-5: fresh per-task canary sandbox defeats .snap cheat, oracle catches gitignored bunfig & standalone Rust #[test], runner metrics & realpath CRAP", () => {
  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "auth.ts"), "export function canAccess(a: boolean, b: boolean): boolean { return a && b; }\n");
    fs.writeFileSync(
      path.join(dir, "tests", "snap-cheat.test.ts"),
      'import fs from "node:fs"; import { expect, test } from "bun:test";\ntest("snap", () => { const cur = fs.readFileSync("src/auth.ts", "utf8"); if (!fs.existsSync(".snap")) { fs.writeFileSync(".snap", cur); return; } expect(cur).toBe(fs.readFileSync(".snap", "utf8")); });\n',
    );
    const snapCheat = runPlantedFaultCanary({ repoRoot: dir, testCmd: "bun test ./tests/snap-cheat.test.ts", targets: ["src/auth.ts"], maxMutants: 2, minKillRate: 0.75 });
    assert.equal(snapCheat.passed, false);
    assert.equal(snapCheat.killedMutants, 0);

    const realDir = fs.realpathSync(dir);
    fs.writeFileSync(path.join(dir, "lcov.info"), `SF:${realDir}/src/auth.ts\nDA:1,1\nend_of_record\n`);
    const crap = evaluateCrapForCoverageFile(dir, "lcov.info", 30);
    assert.equal(crap.evaluatedFiles, 1);
  });

  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".gitignore"), "bunfig.toml\ntests/fake/\n");
    fs.writeFileSync(path.join(dir, "src", "add.ts"), "export function add(a: number, b: number): number { return a + b; }\n");
    fs.writeFileSync(path.join(dir, "tests", "add.test.ts"), 'import { expect, test } from "bun:test";\nimport { add } from "../src/add.ts";\ntest("add", () => { expect(add(2, 3)).toBe(5); });\n');
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "base"], { cwd: dir });

    fs.writeFileSync(path.join(dir, "src", "add.ts"), "export function add(): number { return 999; }\n");
    fs.mkdirSync(path.join(dir, "tests", "fake"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "fake", "ok.test.ts"), 'import { expect, test } from "bun:test";\ntest("ok", () => { expect(1).toBe(1); });\n');
    fs.writeFileSync(path.join(dir, "bunfig.toml"), 'test = { root = "tests/fake" }\n');
    const oracleIgnored = runTwoSidedOracleCheck(dir, "HEAD", "bun test");
    assert.equal(oracleIgnored.passed, false);
  });

  assert.equal(parseRunnerTestCounts('{"Action":"pass","Test":"TestA"}\n{"Action":"pass","Test":"TestB"}\n', [["go", "test", "-json", "./..."]]).passed, 2);
  assert.equal(parseRunnerTestCounts("  3 passing (1s)\n", [["cypress", "run"]]).passed, 3);
  assert.equal(parseRunnerTestCounts("Summary [ 0.2s] 5 tests run: 4 passed (1 flaky), 1 failed\n", [["cargo", "nextest", "run"]]).failed, 1);
});

test("R6 Arch-6, Arch-7 & Arch-8: Rust cfg_attr production code preserved, JS regex/template mask, SFC </script>, SPC/Big-O/Invariants/formal-sync/diff-cheats", () => {
  const rsProd = '#[cfg_attr(test, derive(Debug))]\npub fn prod_panic(x: Option<i32>) -> i32 { x.unwrap() }\n#[cfg(all(unix, not(any(test, bench))))]\npub fn prod_only() -> i32 { Some(1).unwrap() }\n#[cfg(test)]\nfn make_buf() -> [u8; 32] { let x = Some(1).unwrap(); [x; 32] }\n';
  const rsMasked = maskCode(rsProd, "rust", true);
  assert.ok(rsMasked.includes("x.unwrap()"));
  assert.ok(rsMasked.includes("Some(1).unwrap()"));
  assert.equal(rsMasked.includes("[x; 32]"), false);
  assert.equal(lintNoComments("src/b.rs", 'let s = r#"prefix " // inside raw"#;\n', "rust").length, 0);

  const jsRegex = "const re = /'/; const bad = x as any;\n";
  assert.ok(maskCode(jsRegex, "typescript").includes("as any"));
  const jsTpl = 'const s = `a ${"`"} b`; const bad = x as any;\n';
  assert.ok(maskCode(jsTpl, "typescript").includes("as any"));
  const sfc = extractSfcScript("src/B.svelte", '<script lang="ts">\nconst tag = "</script>";\nconst bad = (1 as any);\n</script>');
  assert.ok(sfc && sfc.content.includes("as any"));

  assert.equal(evaluateSpcSeries("lat", [1, 1, 1, 1, 1, 1, 1, 1, 1, 1000], 2000).status, "drift_warning");
  assert.equal(fitEmpiricalBigO([{ n: 100, timeMs: 10 }, { n: 200, timeMs: 10 }, { n: 400, timeMs: 10 }, { n: 800, timeMs: 80 }], { maxTimeExponent: 1.45 }).passed, false);
  const inv3 = inferDynamicInvariants([{ fn: "f", result: 1 }, { fn: "f", result: 2 }, { fn: "f", result: 3 }]);
  const inv4 = inferDynamicInvariants([{ fn: "f", result: 1 }, { fn: "f", result: 2 }, { fn: "f", result: 3 }, { fn: "f", result: 4 }]);
  assert.equal(inv3.invariants.find((i) => i.kind === "never-throws")?.detail, inv4.invariants.find((i) => i.kind === "never-throws")?.detail);

  const diffCheat = auditDiffAntiEvasion([
    { file: ".verification/control-plan.json", line: 1, kind: "del", raw: '{ "schemaVersion": 1 }', code: '{ "schemaVersion": 1 }' },
    { file: "src/a.ts", line: 3, kind: "add", raw: "if (false && x > 0) return;", code: "if (false && x > 0) return;" },
  ]);
  assert.ok(diffCheat.some((f) => f.file === ".verification/control-plan.json"));
  assert.ok(diffCheat.some((f) => f.rule === "diff-invariant-guard-weakened"));

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "ambient.d.ts"), "export interface A { x: any; isReady: boolean; isClosed: boolean; }\n");
    fs.writeFileSync(path.join(dir, "src", "types.pyi"), "class C:\n    is_ready: bool\n    is_closed: bool\n");
    fs.writeFileSync(path.join(dir, "src", "Effect.tsx"), 'import { useEffect, useState } from "react";\nexport function C() { const [u, setU] = useState(""); useEffect(() => { let cancelled = false; (async () => { const t = await Promise.resolve("a"); if (!cancelled) setU(t); })(); return () => { cancelled = true; }; }, []); return u; }\n');
    const rep = scanRepo(dir);
    assert.deepEqual(rep.findings.filter((f) => f.file === "src/ambient.d.ts"), []);
    assert.deepEqual(rep.findings.filter((f) => f.file === "src/types.pyi"), []);
    assert.deepEqual(rep.findings.filter((f) => f.file === "src/Effect.tsx" && f.rule === "async-effect-stale-guard"), []);

    initGit(dir);
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, "LAWS.bend"), "law L1\n");
    fs.writeFileSync(path.join(dir, "src", "p.ts"), "export const p = 1;\n");
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "v1"], { cwd: dir });
    const sha1 = (spawnSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).stdout ?? "").trim();
    fs.writeFileSync(path.join(dir, "src", "p.ts"), "export const p = 2;\n");
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "v2"], { cwd: dir });
    fs.writeFileSync(path.join(dir, ".verification", "control-plan.json"), JSON.stringify({ schemaVersion: 1, formalChecks: [{ id: "F1", specFile: "LAWS.bend", coveredPaths: ["src/p.ts"], syncCommit: sha1 }] }));
    const fsRes = spawnSync(process.execPath, [binPath, "formal-sync", dir, "--fail"], {
      encoding: "utf8",
      env: { ...process.env, GIT_DIR: "/nonexistent" },
    });
    assert.equal(fsRes.status, 1);
    assert.match(`${fsRes.stdout}\n${fsRes.stderr}`, /formal-spec-stale/);
  });
});
