import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createPluginHostSync, scanRepo } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { auditCodeownersPerimeter, auditExtendedCiRules, ciAuditorPlugin } from "@veristack/plugin-ci-auditor";

test("ci-auditor plugin defines valid Veristack plugin and registers into signals", () => {
  assert.equal(isVeristackPlugin(ciAuditorPlugin), true);
  assert.equal(ciAuditorPlugin.id, "veristack.plugin.ci-auditor");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [ciAuditorPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.signals().length >= 1);
});

test("bun:sqlite and better-sqlite3 real-engine tests classify as R4 without integration-without-real-engine push-downs", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-sqlite-r4-"));
  try {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests", "integration"), { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "svc", dependencies: { express: "^5.0.0" } }));
    fs.writeFileSync(path.join(dir, "src", "db.ts"), "export function schemaSql(): string { return 'CREATE TABLE t(id INT)'; }\n");
    fs.writeFileSync(
      path.join(dir, "tests", "integration", "sqlite-engine.integration.test.ts"),
      [
        'import { Database } from "bun:sqlite";',
        'import { test, expect } from "bun:test";',
        'import { schemaSql } from "../../src/db.ts";',
        'test("runs ddl", () => {',
        '  const db = new Database(":memory:");',
        '  db.exec(schemaSql());',
        '  expect(db.query("SELECT 1").get()).toBeDefined();',
        '});',
      ].join("\n"),
    );
    fs.writeFileSync(
      path.join(dir, "tests", "integration", "sqlite-migration.integration.test.ts"),
      [
        'import Database from "better-sqlite3";',
        'import { test, expect } from "bun:test";',
        'import { schemaSql } from "../../src/db.ts";',
        'test("migrates", () => {',
        '  const db = new Database(":memory:");',
        '  db.exec(schemaSql());',
        '  expect(db.prepare("SELECT 1").get()).toBeDefined();',
        '});',
      ].join("\n"),
    );
    const report = scanRepo(dir);
    const r4 = report.testInventory.filter((t) => t.rung === "R4");
    assert.equal(r4.length, 2);
    assert.equal(r4.every((t) => t.hasRealDb), true);
    assert.equal(report.pushDownOpportunities.some((p) => p.pattern === "integration-without-real-engine"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Azure Pipelines with template expressions credits active CI and exempts GitHub-only CODEOWNERS", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-ado-ci-"));
  try {
    fs.mkdirSync(path.join(dir, "ci"), { recursive: true });
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "app.ts"), "export const v = 1;\n");
    fs.writeFileSync(
      path.join(dir, "ci", "azure-pipelines.yml"),
      [
        "trigger:",
        "  - main",
        "pool:",
        "  vmImage: ubuntu-latest",
        "steps:",
        "  - ${{ if eq(variables['Build.Reason'], 'PullRequest') }}:",
        "    - bash: bun run typecheck && bun test",
      ].join("\n"),
    );
    const report = scanRepo(dir);
    const r0 = report.rungs.find((r) => r.rung === "R0");
    assert.equal(r0?.checks.find((c) => c.id === "r0-codeowners")?.passed, true);
    assert.equal(auditCodeownersPerimeter([], ["ci/azure-pipelines.yml", "src/app.ts"]).passed, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("ci-hardcoded-service-port detects port 18080 as info on ephemeral hosted pools and warn on self-hosted", () => {
  const hosted = auditExtendedCiRules({
    rel: ".github/workflows/ci.yml", abs: "/tmp/ci.yml", isTest: false, isWorkflow: true, lines: 5,
    content: "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl http://127.0.0.1:18080/health\n",
  });
  const selfHosted = auditExtendedCiRules({
    rel: ".github/workflows/ci.yml", abs: "/tmp/ci.yml", isTest: false, isWorkflow: true, lines: 5,
    content: "jobs:\n  test:\n    runs-on: self-hosted\n    steps:\n      - run: curl http://127.0.0.1:18080/health\n",
  });
  assert.equal(hosted.find((f) => f.rule === "ci-hardcoded-service-port")?.severity, "info");
  assert.equal(selfHosted.find((f) => f.rule === "ci-hardcoded-service-port")?.severity, "warn");
});
