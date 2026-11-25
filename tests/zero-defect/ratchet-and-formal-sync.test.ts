import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { auditCiWorkflows } from "../../src/ci-auditor.ts";
import { discoverRepo, isTestFilePath } from "../../src/discover.ts";
import { buildRatchetBaseline, evaluateRatchet, writeRatchetBaseline } from "../../src/ratchet.ts";
import type { Finding } from "../../src/types.ts";
import { auditFormalSync } from "../../src/zero-defect/formal-sync.ts";

function makeFinding(rule: string, severity: Finding["severity"] = "error"): Finding {
  return {
    id: `T:${rule}`,
    rule,
    category: "test-smell",
    rung: "R0",
    severity,
    file: "src/a.ts",
    line: 1,
    message: rule,
    fix: "fix",
  };
}

test("auto-shrinking ratchet passes on exact match, fails on regression, and flags tighten opportunities", () => {
  const initial = [makeFinding("no-test-doubles"), makeFinding("no-test-doubles"), makeFinding("wide-directory", "warn")];
  const baseline = buildRatchetBaseline(initial);
  assert.deepEqual(baseline, { version: 1, rules: { "no-test-doubles": 2, "wide-directory": 1 } });

  const same = evaluateRatchet(initial, baseline);
  assert.equal(same.passed, true);
  assert.equal(same.regressions.length, 0);
  assert.equal(same.tightenAvailable.length, 0);

  const regressed = evaluateRatchet([...initial, makeFinding("no-test-doubles")], baseline);
  assert.equal(regressed.passed, false);
  assert.equal(regressed.regressions.length, 1);
  assert.equal(regressed.regressions[0]?.rule, "no-test-doubles");
  assert.equal(regressed.regressions[0]?.delta, 1);

  const improved = evaluateRatchet([makeFinding("no-test-doubles"), makeFinding("wide-directory", "warn")], baseline);
  assert.equal(improved.passed, false);
  assert.equal(improved.regressions.length, 0);
  assert.equal(improved.tightenAvailable.length, 1);
  assert.equal(improved.tightenAvailable[0]?.delta, -1);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-ratchet-"));
  try {
    const outFile = path.join(tmp, ".verification", "ratchet.json");
    writeRatchetBaseline(outFile, baseline);
    const loaded = JSON.parse(fs.readFileSync(outFile, "utf8"));
    assert.deepEqual(loaded, baseline);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("formal-sync detects stale formal specs when covered production files change after syncCommit", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-formal-sync-"));
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "Test"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "test@example.com"], { cwd: tmp });

    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "formal"), { recursive: true });
    fs.mkdirSync(path.join(tmp, ".verification"), { recursive: true });

    fs.writeFileSync(path.join(tmp, "src", "machine.ts"), "export const step = 1;\n");
    fs.writeFileSync(path.join(tmp, "formal", "machine.qnt"), "module machine {}\n");
    spawnSync("git", ["add", "-A"], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "initial"], { cwd: tmp });
    const syncSha = (spawnSync("git", ["rev-parse", "HEAD"], { cwd: tmp, encoding: "utf8" }).stdout ?? "").trim();

    fs.writeFileSync(
      path.join(tmp, ".verification", "control-plan.json"),
      JSON.stringify({
        service: "demo",
        controls: [],
        formalChecks: [
          {
            id: "FM-01",
            specFile: "formal/machine.qnt",
            coveredPaths: ["src/machine.ts"],
            syncCommit: syncSha,
          },
        ],
      }),
    );

    const freshRepo = discoverRepo(tmp);
    assert.deepEqual(auditFormalSync(freshRepo), []);

    fs.writeFileSync(path.join(tmp, "src", "machine.ts"), "export const step = 2;\n");
    spawnSync("git", ["add", "src/machine.ts"], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "mutate covered code"], { cwd: tmp });

    const staleRepo = discoverRepo(tmp);
    const staleFindings = auditFormalSync(staleRepo);
    assert.equal(staleFindings.length, 1);
    assert.equal(staleFindings[0]?.rule, "formal-spec-stale");
    assert.equal(staleFindings[0]?.rung, "R5");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("ci-missing-timeout warns on workflows without timeout-minutes and test discovery skips config/contracts", () => {
  assert.equal(isTestFilePath("tests/dashboard-e2e/playwright.tooling.config.ts"), false);
  assert.equal(isTestFilePath("tests/dashboard-ui/contracts/studio-roles.ts"), false);
  assert.equal(isTestFilePath("tests/dashboard-ui/unit/table.test.ts"), true);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-ci-timeout-"));
  try {
    fs.mkdirSync(path.join(tmp, ".github", "workflows"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, ".github", "workflows", "ci.yml"),
      "name: CI\non: [push]\nconcurrency:\n  group: ci-${{ github.ref }}\n  cancel-in-progress: true\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
    );
    const repo = discoverRepo(tmp);
    const findings = auditCiWorkflows(repo);
    assert.ok(findings.some((f) => f.rule === "ci-missing-timeout"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
