import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanRepo } from "@veristack/core";
import {
  buildReviewBrief,
  formatReviewBriefMarkdown,
  formatReviewBriefTerminal,
} from "@veristack/plugin-review-brief";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");

function initTempGitRepo(prefix: string): string {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  spawnSync("git", ["init", "-q"], { cwd: tmp });
  spawnSync("git", ["config", "user.email", "dev@test.local"], { cwd: tmp });
  spawnSync("git", ["config", "user.name", "Dev"], { cwd: tmp });
  return tmp;
}

test("review-brief detects slop-asymmetry breaches, workarounds, and ranks high-stakes files first", () => {
  const tmp = initTempGitRepo("vstack-brief-red-");
  try {
    fs.mkdirSync(path.join(tmp, "src", "auth"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "docs"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "src", "auth", "guard.ts"), "export const ok = (x: number) => x > 0;\n");
    fs.writeFileSync(path.join(tmp, "docs", "notes.md"), "# Notes\n");
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    fs.writeFileSync(
      path.join(tmp, "src", "auth", "guard.ts"),
      [
        "export const ok = (x: number) => {",
        "  try { return x > 0; } catch { return true; }",
        "};",
      ].join("\n") + "\n",
    );
    for (let i = 1; i <= 5; i++) {
      const dir = path.join(tmp, "src", `mod${i}`);
      fs.mkdirSync(dir, { recursive: true });
      const body = Array.from({ length: 70 }, (_, n) => `export const v${i}_${n} = ${n};`).join("\n");
      fs.writeFileSync(path.join(dir, `f${i}.ts`), `${body}\n`);
    }
    fs.writeFileSync(
      path.join(tmp, "docs", "notes.md"),
      Array.from({ length: 270 }, (_, i) => `Generated prose paragraph ${i}`).join("\n") + "\n",
    );
    spawnSync("git", ["add", "."], { cwd: tmp });

    const report = buildReviewBrief(tmp, { baseRef: "HEAD", maxLines: 500, maxDirs: 4, maxDocLines: 200 });
    assert.equal(report.passed, false);
    const breachRules = new Set(report.budgetBreaches.map((b) => b.rule));
    assert.ok(breachRules.has("review-budget-diff-size"));
    assert.ok(breachRules.has("review-budget-shotgun-spread"));
    assert.ok(breachRules.has("review-budget-doc-dump"));
    assert.ok(breachRules.has("review-budget-addition-bias"));
    assert.ok(breachRules.has("review-budget-workarounds"));
    assert.equal(report.reviewQueue.mustReview[0]?.file, "src/auth/guard.ts");
    assert.ok(report.blindSpots.length >= 3);
    assert.match(formatReviewBriefTerminal(report), /MUST REVIEW FIRST/);
    assert.match(formatReviewBriefMarkdown(report), /### Where Linters & Tests Are Blind/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("review-brief passes on a focused subtractive refactor and works via CLI", () => {
  const tmp = initTempGitRepo("vstack-brief-green-");
  try {
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, "src", "calc.ts"),
      Array.from({ length: 30 }, (_, i) => `export const unused${i} = ${i};`).join("\n") + "\n",
    );
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    fs.writeFileSync(path.join(tmp, "src", "calc.ts"), "export const sum = (a: number, b: number) => a + b;\n");

    const cliRes = spawnSync(process.execPath, [binPath, "review-brief", tmp, "--base", "HEAD", "--json", "--fail"], {
      encoding: "utf8",
    });
    assert.equal(cliRes.status, 0, cliRes.stderr);
    const parsed = JSON.parse(cliRes.stdout);
    assert.equal(parsed.passed, true);
    assert.ok(parsed.metrics.netLines < 0);
    assert.ok(parsed.metrics.deletionRatio > 0.9);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("agent-doc hygiene catches bloated instruction files, stale paths, and unpromoted prose rules without FPs on valid paths or fences", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-agentdoc-"));
  try {
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "src", "real.ts"), "export const real = 1;\n");
    const longFiller = Array.from({ length: 405 }, (_, i) => `- Guidance note ${i}`).join("\n");
    fs.writeFileSync(
      path.join(tmp, "AGENTS.md"),
      [
        "# Agent Instructions",
        "1. Keep `src/real.ts` clean.",
        "2. Check `src/deleted-legacy.ts` before shipping.",
        "3. Never use raw SQL queries.",
        "4. Do not import internal helpers directly.",
        "5. Must not commit skipped tests.",
        "6. Never disable strict compiler flags.",
        "```ts",
        "// example `src/fenced-example.ts` should never trigger",
        "```",
        longFiller,
      ].join("\n") + "\n",
    );

    const report = scanRepo(tmp);
    const agentFindings = report.findings.filter((f) => f.rule.startsWith("agent-doc-"));
    const rules = new Set(agentFindings.map((f) => f.rule));
    assert.ok(rules.has("agent-doc-bloat"));
    assert.ok(rules.has("agent-doc-stale-path"));
    assert.ok(rules.has("agent-doc-unpromoted-rules"));
    const staleMsgs = agentFindings.filter((f) => f.rule === "agent-doc-stale-path").map((f) => f.message);
    assert.equal(staleMsgs.length, 1);
    assert.match(staleMsgs[0] ?? "", /src\/deleted-legacy\.ts/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
