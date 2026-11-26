import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { discoverRepo } from "../../src/discover.ts";
import { runPrecisionBench } from "../../src/zero-defect/bench.ts";
import { auditLaws } from "../../src/zero-defect/laws.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function withTempRepo(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-v2-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content, "utf8");
    }
    fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("Bend 2 LAWS.bend audit enforces CODEOWNERS lock, constructive witnesses, and zero proof escapes", () => {
  withTempRepo(
    {
      ".github/CODEOWNERS": "docs/ @owners\n",
      "LAWS.bend": [
        "law balance_non_negative(n: U32):",
        "  {n == n : U32}",
        "def cheat() -> U32:",
        "  sorry",
      ].join("\n"),
    },
    (dir) => {
      const result = auditLaws(discoverRepo(dir));
      const rules = new Set(result.findings.map((f) => f.rule));
      assert.ok(rules.has("laws-unowned-by-codeowners"));
      assert.ok(rules.has("laws-missing-witness"));
      assert.ok(rules.has("laws-bend-unsafe-escape"));
    },
  );

  withTempRepo(
    {
      ".github/CODEOWNERS": "LAWS.bend @owners\n",
      "Model.bend": fs.readFileSync(path.join(repoRoot, "templates/bend2-reference/Model.bend"), "utf8"),
      "LAWS.bend": fs.readFileSync(path.join(repoRoot, "templates/bend2-reference/LAWS.bend"), "utf8"),
      "PROOF.bend": fs.readFileSync(path.join(repoRoot, "templates/bend2-reference/PROOF.bend"), "utf8"),
    },
    (dir) => {
      const result = auditLaws(discoverRepo(dir));
      assert.equal(result.declaredLaws, 6);
      assert.deepEqual(result.findings, []);
    },
  );
});

test("vstack bench verifies 100% example recall, 0 clean FPs, and 0 adversarial comment/string-wrapped FPs", () => {
  const report = runPrecisionBench(repoRoot);
  assert.equal(
    report.totalExpectedRules,
    report.totalMatchedRules,
    `Missed rules: ${report.languages.flatMap((l) => l.missedRules).join(", ")}`,
  );
  assert.equal(
    report.totalCleanFps,
    0,
    `Clean FPs: ${report.languages.flatMap((l) => l.cleanFalsePositives).join(", ")}`,
  );
  assert.equal(
    report.totalAdversarialFps,
    0,
    `Adversarial FPs: ${report.languages.flatMap((l) => [...l.commentWrappedFps, ...l.stringWrappedFps]).join(", ")}`,
  );
  assert.equal(report.passed, true);
});
