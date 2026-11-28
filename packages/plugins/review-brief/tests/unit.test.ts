import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isVeristackPlugin, runGitClean } from "@veristack/plugin";
import { buildReviewBrief, formatReviewBriefTerminal, reviewBriefPlugin } from "@veristack/plugin-review-brief";

test("review-brief plugin defines valid Veristack plugin and registers into commands", () => {
  assert.equal(isVeristackPlugin(reviewBriefPlugin), true);
  assert.equal(reviewBriefPlugin.id, "veristack.plugin.review-brief");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [reviewBriefPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.commands().length >= 1);
});

test("review-brief computes Kamei/Hotspot empirical risk and Livshits Soundiness Ledger with No fence yet", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-rb-emp-"));
  try {
    runGitClean(dir, ["init", "-q", "-b", "main"]);
    runGitClean(dir, ["config", "user.name", "Alice"]);
    runGitClean(dir, ["config", "user.email", "alice@test.local"]);
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "a.ts"), "export const a = 1;\n");
    fs.writeFileSync(path.join(dir, "src", "b.ts"), "export const b = 1;\n");
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "init"]);
    fs.writeFileSync(path.join(dir, "src", "a.ts"), "export const a = 2;\n");
    runGitClean(dir, ["add", "."]);
    runGitClean(dir, ["commit", "-q", "-m", "fix: bug in a"]);

    fs.writeFileSync(path.join(dir, "src", "a.ts"), "export function run(code: string, x: unknown): unknown { return eval(code) ?? (x as any); }\n");
    fs.writeFileSync(path.join(dir, "src", "b.ts"), "export function b(n: number): number { return n > 0 ? n : -n; }\n");
    const brief = buildReviewBrief(dir, { baseRef: "HEAD" });
    assert.ok((brief.empiricalRisk?.changeEntropy ?? 0) > 0);
    assert.ok((brief.empiricalRisk?.totalNfix ?? 0) >= 1);
    assert.ok((brief.soundinessLedger?.length ?? 0) >= 2);
    const out = formatReviewBriefTerminal(brief);
    assert.ok(out.includes("Empirical JIT Risk:"));
    assert.ok(out.includes("SOUNDINESS LEDGER"));
    assert.ok(out.includes("No fence yet"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
