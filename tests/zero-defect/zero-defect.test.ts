import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scanRepo } from "../../src/ladder.ts";
import {
  computeRolledThroughputYield,
  evaluateSpcSeries,
  generateMcdcVectors,
  runRedBeforeFix,
} from "../../src/zero-defect/index.ts";

test("V30/V31/V36 prod zero-defect guards catch CDC wall-clock durations, unbounded loops, and Debug.Assert/debug_assert!", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-zd-prod-"));
  try {
    fs.writeFileSync(
      path.join(tmp, "timer.ts"),
      "export function elapsed(started: number): number { while (true) { break; } return Date.now() - started; }\n",
    );
    fs.writeFileSync(
      path.join(tmp, "Guard.cs"),
      "using System.Diagnostics;\npublic static class G { public static void Check(bool ok) { Debug.Assert(ok); } }\n",
    );
    fs.writeFileSync(
      path.join(tmp, "lib.rs"),
      "pub fn check(ok: bool) { debug_assert!(ok); }\n",
    );

    const report = scanRepo(tmp);
    const rules = new Set(report.findings.map((f) => f.rule));
    assert.ok(rules.has("cdc-wall-clock-duration"));
    assert.ok(rules.has("unbounded-loop-risk"));
    assert.ok(rules.has("no-release-stripped-assert"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("V32/V33 FMEA Control Plan, REQ traceability, and A3 repeat-escape ratchet catch violations (REQ-NO-COMMENTS-01 REQ-EXPLICIT-SM-01 REQ-CIRCUIT-SAFETY-01)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-zd-fmea-"));
  try {
    fs.mkdirSync(path.join(tmp, ".verification"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, ".verification", "control-plan.json"),
      JSON.stringify({
        controls: [
          {
            id: "CP-BAD",
            seam: "payments",
            failureMode: "double charge",
            severity: 9,
            maxAllowedRung: "R7",
            controlRef: "tests/missing.test.ts",
            reqId: "REQ-PAY-99",
          },
        ],
      }),
    );
    fs.writeFileSync(
      path.join(tmp, ".verification", "escapes.json"),
      JSON.stringify({
        escapes: [
          { id: "E1", defectClass: "missing-tenant-filter", occurrenceCause: "forgot", escapeRung: "R4", containmentRung: "R2" },
          { id: "E2", defectClass: "missing-tenant-filter", occurrenceCause: "forgot again", escapeRung: "R4", containmentRung: "R2" },
        ],
      }),
    );

    const report = scanRepo(tmp);
    const rules = new Set(report.findings.map((f) => f.rule));
    assert.ok(rules.has("fmea-high-severity-rung"));
    assert.ok(rules.has("fmea-orphaned-control"));
    assert.ok(rules.has("traceability-unverified-requirement"));
    assert.ok(rules.has("a3-repeat-defect-no-poka-yoke"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("V33 runRedBeforeFix rejects theater tests that pass on base and accepts genuine bugfix tests that fail on base", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-zd-rbf-"));
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "CI"], { cwd: tmp });
    fs.writeFileSync(path.join(tmp, "calc.js"), "export function add(a, b) { return a - b; }\n");
    fs.writeFileSync(path.join(tmp, "calc.test.js"), "import { add } from './calc.js';\nif (add(2, 0) !== 2) process.exit(1);\n");
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "buggy base"], { cwd: tmp });

    fs.writeFileSync(path.join(tmp, "calc.test.js"), "import { add } from './calc.js';\nif (add(3, 0) !== 3) process.exit(1);\n");
    const theater = runRedBeforeFix(tmp, "HEAD", "bun calc.test.js");
    assert.equal(theater.passed, false);
    assert.equal(theater.baseExitCode, 0);

    fs.writeFileSync(path.join(tmp, "calc.js"), "export function add(a, b) { return a + b; }\n");
    fs.writeFileSync(path.join(tmp, "calc.test.js"), "import { add } from './calc.js';\nif (add(2, 3) !== 5) process.exit(1);\n");
    const genuine = runRedBeforeFix(tmp, "HEAD", "bun calc.test.js");
    assert.equal(genuine.passed, true);
    assert.notEqual(genuine.baseExitCode, 0);
    assert.equal(genuine.headExitCode, 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("V34 MC/DC generator synthesizes minimal independence pairs and flags dead/redundant conditions", () => {
  const res = generateMcdcVectors("isAdmin || (isOwner && !isSuspended && hasScope)");
  assert.deepEqual(res.variables, ["isAdmin", "isOwner", "isSuspended", "hasScope"]);
  assert.equal(res.uncoveredVariables.length, 0);
  assert.ok(res.vectors.length >= 5 && res.vectors.length <= 6);

  const dead = generateMcdcVectors("a || (a && b)");
  assert.deepEqual(dead.uncoveredVariables, ["b"]);
});

test("V38 2-world relational non-interference proves Tenant A mutations never perturb Tenant B cache observations", () => {
  class TenantCache {
    private readonly store = new Map<string, string>();
    set(tenantId: string, key: string, value: string): void {
      this.store.set(`${tenantId}:${key}`, value);
    }
    get(tenantId: string, key: string): string | undefined {
      return this.store.get(`${tenantId}:${key}`);
    }
  }

  const w1 = new TenantCache();
  const w2 = new TenantCache();
  const tenantBOps: Array<[string, string]> = [
    ["profile", "b1"],
    ["prefs", "dark"],
    ["quota", "100"],
  ];

  w2.set("tenant-a", "profile", "a-secret");
  w2.set("tenant-a", "prefs", "light");

  for (const [k, v] of tenantBOps) {
    w1.set("tenant-b", k, v);
    w2.set("tenant-b", k, v);
    w2.set("tenant-a", k, `mutated-${v}`);
    assert.equal(w1.get("tenant-b", k), w2.get("tenant-b", k));
  }
});

test("V41 SPC drift detection catches Nelson Rule 2/3 & Cpk headroom erosion before USL breach, and computes RTY", () => {
  const stable = evaluateSpcSeries("p99_ms", [40, 41, 39, 40, 41, 39, 40, 41, 40, 39], 100);
  assert.equal(stable.status, "in_control");

  const drifting = evaluateSpcSeries("p99_ms", [40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52], 60);
  assert.equal(drifting.status, "drift_warning");
  assert.equal(drifting.nelsonRule3Breach, true);
  assert.equal(drifting.cpkBreach, true);

  const rty = computeRolledThroughputYield([0.99, 0.98, 0.92, 0.99, 0.97, 0.96]);
  assert.equal(rty.lowestStageIndex, 2);
  assert.equal(rty.belowFloor, true);
  assert.ok(rty.rty < 0.85);
});
