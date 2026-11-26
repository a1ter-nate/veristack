import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { discoverRepo } from "../../src/discover.ts";
import { lintNoComments } from "../../src/no-comments.ts";
import { discoverWorkspaces } from "../../src/rungs/manifest.ts";
import { insertSemanticNoOp, runPlantedFaultCanary } from "../../src/rungs/mutation-probe.ts";
import { runTwoSidedOracleCheck } from "../../src/rungs/oracle-check.ts";
import { runRungAndWriteReceipt } from "../../src/rungs/receipts.ts";
import { evaluateBranchProtectionJson } from "../../src/rungs/workflow-audit.ts";

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-core-inv-"));
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

test("branch protection JSON enforces every required check, approval count >= 1, dismiss stale, codeowners, admins, and no force push", () => {
  const full = {
    required_status_checks: { contexts: ["self-verify-vstack-strict"] },
    required_pull_request_reviews: {
      require_code_owner_reviews: true,
      required_approving_review_count: 1,
      dismiss_stale_reviews: true,
    },
    enforce_admins: { enabled: true },
    allow_force_pushes: { enabled: false },
  };
  assert.equal(evaluateBranchProtectionJson("main", JSON.stringify(full)).passed, true);

  const zeroApprovals = {
    ...full,
    required_pull_request_reviews: { ...full.required_pull_request_reviews, required_approving_review_count: 0 },
  };
  assert.equal(evaluateBranchProtectionJson("main", JSON.stringify(zeroApprovals)).passed, false);

  const noCodeowners = {
    ...full,
    required_pull_request_reviews: { ...full.required_pull_request_reviews, require_code_owner_reviews: false },
  };
  assert.equal(evaluateBranchProtectionJson("main", JSON.stringify(noCodeowners)).passed, false);

  const noAdmins = { ...full, enforce_admins: { enabled: false } };
  assert.equal(evaluateBranchProtectionJson("main", JSON.stringify(noAdmins)).passed, false);

  const forcePush = { ...full, allow_force_pushes: { enabled: true } };
  assert.equal(evaluateBranchProtectionJson("main", JSON.stringify(forcePush)).passed, false);

  const wrongCheck = { ...full, required_status_checks: { contexts: ["random-ci"] } };
  assert.equal(evaluateBranchProtectionJson("main", JSON.stringify(wrongCheck)).passed, false);

  assert.equal(evaluateBranchProtectionJson("main", "{bad").passed, false);
});

test("no-comments regex literal character classes treat [/] as class content, not regex terminator", () => {
  const withComment = "const re = /[/]a/; // trailing comment\n";
  const found = lintNoComments("src/re.ts", withComment, "typescript");
  assert.equal(found.length, 1);
  assert.equal(found[0]?.line, 1);

  const noComment = "const re = /[//]/;\nconst ok = 1;\n";
  assert.equal(lintNoComments("src/re2.ts", noComment, "typescript").length, 0);
});

test("insertSemanticNoOp handles C#, Rust, Go, Python, and TS variants cleanly", () => {
  const csBlock = "public class A { public int Run(int x) { return x + 1; } }\n";
  const csV0 = insertSemanticNoOp("src/A.cs", csBlock, 0);
  const csV1 = insertSemanticNoOp("src/A.cs", csBlock, 1);
  assert.match(csV0, /if \(false\) \{\}/);
  assert.match(csV1, /var [a-z][a-z0-9]+ = 0; _ = [a-z][a-z0-9]+;/);
  assert.notEqual(csV0, csV1);

  const csExpr = "public class B { public int Run(int x) => x + 1; }\n";
  assert.equal(insertSemanticNoOp("src/B.cs", csExpr, 0), `${csExpr}\n`);

  const rsFn = "pub fn add(a: i32, b: i32) -> i32 { a + b }\n";
  assert.match(insertSemanticNoOp("src/lib.rs", rsFn, 1), /let _[a-z][a-z0-9]+ = \(\);/);
  assert.doesNotMatch(insertSemanticNoOp("src/lib.rs", rsFn, 1), /var [a-z]/);

  const pyFuture = "from __future__ import (\n    annotations,\n)\ndef f(x):\n    return x\n";
  const pyNoOp = insertSemanticNoOp("src/a.py", pyFuture, 0);
  assert.ok(pyNoOp.indexOf("annotations") < pyNoOp.indexOf("if False:"));
});

test("discoverWorkspaces partitions nested monorepo workspaces without leaking child prod files to empty parent", () => {
  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "packages", "parent", "child", "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "root" }));
    fs.writeFileSync(path.join(dir, "packages", "parent", "package.json"), JSON.stringify({ name: "parent" }));
    fs.writeFileSync(path.join(dir, "packages", "parent", "child", "package.json"), JSON.stringify({ name: "child" }));
    fs.writeFileSync(path.join(dir, "packages", "parent", "child", "src", "index.ts"), "export const v = 1;\n");
    const ws = discoverWorkspaces(discoverRepo(dir), undefined);
    assert.deepEqual(ws.map((w) => w.path), ["packages/parent/child"]);
  });
});

test("receipts record real git HEAD commit SHA in git repos and 'no-git' outside git", () => {
  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "ok.test.ts"), 'import { expect, test } from "bun:test";\ntest("ok", () => { expect(1).toBe(1); });\n');
    const manifest = { schemaVersion: 1 as const, archetype: "library" as const, rungs: { R2: { command: "bun test ./tests/ok.test.ts", required: true } } };
    const noGit = runRungAndWriteReceipt(discoverRepo(dir), "R2", manifest, "k");
    assert.equal(noGit.commitSha, "no-git");

    initGit(dir);
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: dir });
    const headSha = (spawnSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).stdout ?? "").trim();
    const withGit = runRungAndWriteReceipt(discoverRepo(dir), "R2", manifest, "k");
    assert.equal(withGit.commitSha, headSha);
    assert.equal(withGit.commitSha.length, 40);
  });
});

test("oracle-check catches missing baseRef, baseRanZero, and Rust inline #[cfg(test)] rewrites; canary symlinks .venv", () => {
  withTempDir((dir) => {
    const missing = runTwoSidedOracleCheck(dir, "", "bun test");
    assert.equal(missing.passed, false);
    assert.equal(missing.baseRef, "<missing>");

    initGit(dir);
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "src", "lib.rs"),
      "pub fn add(a: i32, b: i32) -> i32 { a + b }\n#[cfg(test)]\nmod tests {\n  #[test]\n  fn checks_sum() { assert_eq!(super::add(2, 2), 4); }\n}\n",
    );
    fs.writeFileSync(
      path.join(dir, "tests", "verify-rs.test.ts"),
      'import fs from "node:fs"; import { expect, test } from "bun:test";\ntest("rs", () => { const s = fs.readFileSync("src/lib.rs", "utf8"); expect(s).not.toContain("checks_sum"); });\n',
    );
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "base"], { cwd: dir });

    fs.writeFileSync(
      path.join(dir, "src", "lib.rs"),
      "pub fn add(a: i32, b: i32) -> i32 { a - b }\n#[cfg(test)]\nmod tests {\n  #[test]\n  fn gutted() { assert_eq!(1, 1); }\n}\n",
    );
    const rsRes = runTwoSidedOracleCheck(dir, "HEAD", "bun test ./tests/verify-rs.test.ts");
    assert.equal(rsRes.passed, false);
  });

  withTempDir((dir) => {
    initGit(dir);
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "x.ts"), "export const x = 1;\n");
    spawnSync("git", ["add", "-A"], { cwd: dir });
    spawnSync("git", ["commit", "-q", "-m", "empty-tests"], { cwd: dir });

    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "tests", "new.test.ts"), 'import { expect, test } from "bun:test";\ntest("n", () => { expect(1).toBe(1); });\n');
    const zeroBase = runTwoSidedOracleCheck(dir, "HEAD", "bun test");
    assert.equal(zeroBase.passed, false);
  });

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, ".venv"), { recursive: true });
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".venv", "marker.txt"), "ok");
    fs.writeFileSync(path.join(dir, "src", "calc.ts"), "export function ok(a: number): boolean { return a > 0; }\n");
    fs.writeFileSync(
      path.join(dir, "tests", "calc.test.ts"),
      'import fs from "node:fs"; import { expect, test } from "bun:test"; import { ok } from "../src/calc.ts";\ntest("calc", () => { expect(fs.existsSync(".venv/marker.txt")).toBe(true); expect(ok(1)).toBe(true); expect(ok(0)).toBe(false); });\n',
    );
    const res = runPlantedFaultCanary({
      repoRoot: dir,
      testCmd: "bun test ./tests/calc.test.ts",
      targets: ["src/calc.ts"],
      maxMutants: 2,
      minKillRate: 0.75,
    });
    assert.equal(res.passed, true);
  });
});
