import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { analyzeTsAstGuards, hasPathologicalNesting } from "../../src/ast/ts-ast.ts";
import { executeHookEvent } from "../../src/hooks/runtime.ts";
import { scanRepo } from "../../src/ladder.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

function withTempDir(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-pin-"));
  try { fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test("gate-pin matrix: EVERY protected control-plane path and self-import closure denies with exit 2", () => {
  const protectedPaths = [
    ".verification/rungs.json",
    ".verification/hooks.json",
    ".verification/control-plan.json",
    ".github/workflows/ci.yml",
    ".github/CODEOWNERS",
    ".claude/settings.local.json",
    ".codex/hooks.json",
    ".cursor/hooks.json",
    ".git/config",
    ".gitattributes",
    ".gitignore",
    ".vstackignore",
    ".vstack.json",
    "package.json",
    "bun.lock",
    "bunfig.toml",
    "tsconfig.json",
    ".oxlintrc.json",
    "lefthook.yml",
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config.toml",
    "pyproject.toml",
    "pytest.ini",
    "conftest.py",
    "node_modules/veristack/dist/cli.mjs",
    "dist/cli.mjs",
    "bin/vstack.mjs",
    "scripts/check-perf-budget.mjs",
    "src/hooks/runtime.ts",
    "examples/go/manifest.json",
    "src/cli.ts",
    "src/ast/ts-ast.ts",
    "src/discover.ts",
  ];

  for (const rel of protectedPaths) {
    const res = executeHookEvent(
      "pre-edit",
      JSON.stringify({ cwd: repoRoot, tool_name: "Write", tool_input: { file_path: path.join(repoRoot, rel), content: "x\n" } }),
      { repoRoot, harness: "claude" },
    );
    assert.equal(res.exitCode, 2, `Expected exit 2 deny for protected path '${rel}'`);
    assert.ok(res.findings.some((f) => f.rule === "hook-protected-control-plane"), `Expected hook-protected-control-plane for '${rel}'`);
  }

  const bashDeny = executeHookEvent(
    "pre-edit",
    JSON.stringify({ cwd: repoRoot, tool_name: "Bash", tool_input: { command: "echo '{}' > .verification/hooks.json" } }),
    { repoRoot, harness: "claude" },
  );
  assert.equal(bashDeny.exitCode, 2);

  const bashGitDeny = executeHookEvent(
    "pre-edit",
    JSON.stringify({ cwd: repoRoot, tool_name: "Bash", tool_input: { command: "git remote remove origin" } }),
    { repoRoot, harness: "claude" },
  );
  assert.equal(bashGitDeny.exitCode, 2);

  const bashAllow = executeHookEvent(
    "pre-edit",
    JSON.stringify({ cwd: repoRoot, tool_name: "Bash", tool_input: { command: "bun test ./tests/no-comments.test.ts" } }),
    { repoRoot, harness: "claude" },
  );
  assert.equal(bashAllow.exitCode, 0);
});

test("gate-pin matrix: nesting-bomb caps, non-bomb string literal, syntax parse errors, and unknown write payloads", () => {
  assert.equal(hasPathologicalNesting(`const x = ${"(".repeat(140)}1${")".repeat(140)};`), true);
  assert.equal(hasPathologicalNesting(`const x = ${"!".repeat(140)}y;`), true);
  assert.equal(hasPathologicalNesting(`const x = ${"\\".repeat(270)};`), true);
  assert.equal(hasPathologicalNesting("a".repeat(2_100_000)), true);

  const benignStringWithParens = `export const s = "${"(".repeat(150)}";\nexport function bad(x: string) { return eval(x); }\n`;
  assert.equal(hasPathologicalNesting(benignStringWithParens), false);
  const astFindings = analyzeTsAstGuards({ rel: "src/a.ts", abs: "/tmp/a.ts", language: "typescript", isTest: false, isWorkflow: false, content: benignStringWithParens, lines: 2 });
  assert.ok(astFindings.some((f) => f.rule === "ast-unsafe-eval-or-function"));

  const brokenSyntax = "export function bad(x: string) { eval(x); const = ; }\n";
  const errFindings = analyzeTsAstGuards({ rel: "src/broken.ts", abs: "/tmp/broken.ts", language: "typescript", isTest: false, isWorkflow: false, content: brokenSyntax, lines: 1 });
  assert.ok(errFindings.some((f) => f.rule === "ts-syntax-parse-error"));

  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    const f = path.join(dir, "src", "ok.ts");
    fs.writeFileSync(f, "export const ok = 1;\n");
    const unknownKey = executeHookEvent(
      "pre-edit",
      JSON.stringify({ cwd: dir, tool_name: "Write", tool_input: { file_path: f, new_file_contents: "export const bad = (1 as any);\n" } }),
      { repoRoot: dir, harness: "claude" },
    );
    assert.equal(unknownKey.exitCode, 2);
    assert.ok(unknownKey.findings.some((x) => x.rule === "hook-unextractable-write"));

    fs.writeFileSync(f, "export function run() { try { return 1; } catch (e) {\n  throw e;\n} }\n");
    const delPatch = "*** Begin Patch\n*** Update File: src/ok.ts\n@@\n-  throw e;\n*** End Patch\n";
    const codexDel = executeHookEvent(
      "pre-edit",
      JSON.stringify({ cwd: dir, tool_name: "apply_patch", tool_input: { command: delPatch } }),
      { repoRoot: dir, harness: "codex" },
    );
    assert.equal(codexDel.exitCode, 2);
    assert.equal(codexDel.stdout, "");
    assert.ok(codexDel.findings.some((x) => x.rule === "no-swallowing-catch"));
  });
});

test("gate-pin matrix: hooks.json enabled=false is flagged by scanRepo and still denies control-plane edits", () => {
  withTempDir((dir) => {
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, ".verification", "hooks.json"), JSON.stringify({ enabled: false, tier: "immediate", harnesses: ["claude"] }));
    assert.ok(scanRepo(dir).findings.some((f) => f.rule === "hooks-disabled-in-config"));
    const cpStillDenied = executeHookEvent(
      "pre-edit",
      JSON.stringify({ cwd: dir, tool_name: "Write", tool_input: { file_path: path.join(dir, ".verification", "rungs.json"), content: "{}" } }),
      { repoRoot: dir, harness: "claude" },
    );
    assert.equal(cpStillDenied.exitCode, 2);
  });
});
