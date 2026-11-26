import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanRepo } from "../src/ladder.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("self-scan passes with zero cheats, zero prose comments, zero errors, zero warnings, zero push-downs, and zero rung holes", () => {
  const report = scanRepo(repoRoot);
  assert.equal(report.config, undefined);
  assert.equal(report.summary.totalFindings, 0);
  assert.equal(report.summary.cheatCount, 0);
  assert.equal(report.summary.noCommentCount, 0);
  assert.equal(report.summary.errorCount, 0);
  assert.equal(report.summary.warnCount, 0);
  assert.equal(report.summary.pushDownCount, 0);
  assert.equal(report.summary.holeCount, 0);
  assert.equal(report.summary.poorlyCoveredCount, 0);
  assert.equal(report.summary.unexecutedRungCount, 0);
  assert.equal(report.summary.wellCoveredCount, 6);
  assert.equal(report.summary.applicableRungCount, 6);
  assert.equal(report.summary.overallCoverageScore, 100);
  assert.equal(report.rungs.length, 9);
});

test("detects holes, structural slop, no-comments, and push-down opportunities in synthetic app", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-test-"));
  try {
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "e2e"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, "package.json"),
      JSON.stringify({ dependencies: { react: "^19.0.0", express: "^5.0.0" } }),
    );
    fs.writeFileSync(
      path.join(tmp, "src", "order-create.ts"),
      "// excuse comment\nexport function createOrderForTesting(x: unknown) { return x as unknown as string; }\n",
    );
    fs.writeFileSync(path.join(tmp, "src", "order-delete.ts"), "export const del = () => true;\n");
    fs.writeFileSync(path.join(tmp, "src", "order-list.ts"), "export const list = () => [];\n");
    fs.writeFileSync(
      path.join(tmp, "e2e", "orders.e2e.ts"),
      [
        "import { test, expect } from '@playwright/test';",
        "test('list', async ({ page }) => {",
        "  await page.route('/api/orders', r => r.fulfill({ json: [] }));",
        "  await page.goto('/orders');",
        "  await page.waitForTimeout(300);",
        "  await expect(page.getByRole('heading')).toHaveText('Orders');",
        "});",
      ].join("\n"),
    );

    const report = scanRepo(tmp);
    assert.equal(report.archetype, "fullstack");
    assert.ok(report.summary.noCommentCount >= 1);
    assert.ok(report.summary.cheatCount >= 1);
    assert.ok(report.summary.pushDownCount >= 1);
    assert.ok(report.findings.some((f) => f.rule === "no-prefix-cluster"));
    assert.ok(report.findings.some((f) => f.rule === "no-test-only-production-seam"));
    assert.ok(report.findings.some((f) => f.rule === "no-chained-or-any-cast"));
    assert.ok(report.pushDownOpportunities.some((p) => p.pattern === "e2e-with-mocked-network"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
