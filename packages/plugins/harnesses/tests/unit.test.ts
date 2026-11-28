import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { formatInitReport, formatSingleFileReport, harnessesPlugin, initVeristackRepo, manageHooks, runDoctor, scanSingleFile } from "@veristack/plugin-harnesses";

test("harnesses plugin defines valid Veristack plugin and registers into harnesses", () => {
  assert.equal(isVeristackPlugin(harnessesPlugin), true);
  assert.equal(harnessesPlugin.id, "veristack.plugin.harnesses");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [harnessesPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.harnesses().length >= 1);
});

test("initVeristackRepo and manageHooks honor dryRun without mutating disk", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-dryrun-"));
  try {
    fs.writeFileSync(path.join(dir, "index.ts"), "export const ready = true;\n");
    const initRes = initVeristackRepo(dir, { dryRun: true });
    assert.equal(initRes.dryRun, true);
    assert.equal(initRes.manifestCreated, true);
    assert.equal(initRes.hooksEnabled, true);
    assert.ok(initRes.touchedFiles.includes(".verification/rungs.json"));
    assert.ok(initRes.touchedFiles.includes(".gitignore"));
    assert.ok(initRes.touchedFiles.includes(".verification/hooks.json"));
    assert.match(formatInitReport(initRes), /dry-run/i);
    assert.deepEqual(fs.readdirSync(dir), ["index.ts"]);

    const hooksOnRes = manageHooks(dir, "on", { dryRun: true, harnesses: ["claude", "cursor"] });
    assert.equal(hooksOnRes.dryRun, true);
    assert.deepEqual(hooksOnRes.touchedManifests, [".claude/settings.local.json", ".cursor/hooks.json"]);
    assert.deepEqual(fs.readdirSync(dir), ["index.ts"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Tricorder effective FP tracking in doctor and compositional summary cache + AutoFix in check-file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-tricorder-"));
  try {
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".verification", "escapes.json"),
      JSON.stringify({
        escapes: [],
        ruleFeedback: [
          { rule: "noisy-rule", dismissed: 3, fixed: 4 },
          { rule: "clean-rule", dismissed: 0, fixed: 10 },
        ],
      }),
    );
    fs.writeFileSync(path.join(dir, "src.ts"), "export const v = (1 as any);\n");
    const doc = runDoctor(dir);
    assert.equal(doc.findings.some((f) => f.id === "DOC:high-fp-rule:noisy-rule"), true);
    assert.equal(doc.findings.some((f) => f.id === "DOC:high-fp-rule:clean-rule"), false);

    const first = scanSingleFile(path.join(dir, "src.ts"), { repoRoot: dir });
    const second = scanSingleFile(path.join(dir, "src.ts"), { repoRoot: dir });
    assert.equal(first.findings[0]?.soundness, "incorrectness-witness");
    assert.ok(first.findings[0]?.suggestedFix);
    assert.equal(second.findings.length, first.findings.length);
    assert.ok(formatSingleFileReport(first).includes("AutoFix"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
