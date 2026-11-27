import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { buildBlindAuditPrompt } from "../scripts/calibration/blind-prompt.ts";
import {
  diffAgainstVeristack,
  type GroundTruthDossier,
  mergeDossiers,
  sampleFindingsForAdjudication,
  validateDossier,
} from "../scripts/calibration/diff-dossier.ts";
import { harvestRepoEvidence } from "../scripts/calibration/harvest.ts";
import { scanRepo } from "@veristack/core";

function makeTempRepo(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-cal-harness-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  }
  return dir;
}

function makeDossier(model: string, overrides: Partial<GroundTruthDossier> = {}): GroundTruthDossier {
  const baseRung = { applicable: true, configuredTools: [], prBlockingCi: { executed: false, trustworthy: true }, independentDepth: "none" };
  return {
    auditorModel: model,
    repo: "demo-lib",
    commitSha: "abc1234",
    defaultBranch: "main",
    archetype: { value: "library", rationale: "Pure library", citations: ["package.json:1"] },
    languages: { primary: ["typescript"], auxiliary: [] },
    workspaces: [
      { path: "packages/core", role: "product", archetype: "library", hasOwnOrLinkedTests: true, testLocations: ["packages/core/src/a.test.ts"] },
      { path: "samples/demo", role: "sample-demo", archetype: "service", hasOwnOrLinkedTests: false, testLocations: [] },
    ],
    rungs: {
      R0: { ...baseRung, configuredTools: [{ tool: "oxlint", citation: "package.json:4" }], prBlockingCi: { executed: true, trustworthy: true, executionChain: "ci.yml -> oxlint" }, independentDepth: "solid" },
      R1: { ...baseRung, prBlockingCi: { executed: true, trustworthy: true, executionChain: "ci.yml -> tsc" }, independentDepth: "solid" },
      R2: { ...baseRung, prBlockingCi: { executed: true, trustworthy: false, evasionHazard: "mutates GITHUB_PATH", executionChain: "ci.yml -> bun test" }, independentDepth: "solid" },
      R3: { ...baseRung },
      R4: { ...baseRung, applicable: false },
      R5: { ...baseRung },
      R6: { ...baseRung },
      R7: { ...baseRung, applicable: false },
      R8: { ...baseRung, applicable: false },
    },
    ...overrides,
  };
}

test("harvestRepoEvidence extracts language census, linked CI artifacts, inline Rust tests, and symlinks without Veristack imports", () => {
  const dir = makeTempRepo({
    "package.json": JSON.stringify({ name: "demo", scripts: { test: "vitest run" }, devDependencies: { vitest: "^4.0.0" } }),
    "crates/core/Cargo.toml": '[package]\nname = "core"\nversion = "0.1.0"\n',
    "crates/core/src/lib.rs": "pub fn f() -> i32 { 1 }\n#[cfg(test)]\nmod tests { #[test] fn ok() { assert_eq!(super::f(), 1); } }\n",
    "scripts/ci.sh": "#!/usr/bin/env bash\nvitest run\n",
    ".github/workflows/ci.yml": "on: [pull_request]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bash scripts/ci.sh\n",
    "AGENTS.md": "# Rules\n",
  });
  fs.symlinkSync(path.join(dir, "AGENTS.md"), path.join(dir, "CLAUDE.md"));
  try {
    const packet = harvestRepoEvidence(dir);
    assert.equal(packet.languageCensus.rust, 1);
    assert.equal(packet.languageCensus.shell, 1);
    assert.equal(packet.testSurface.inlineRustTestFilesCount, 1);
    assert.equal(packet.linkedCiArtifacts.length, 1);
    assert.equal(packet.linkedCiArtifacts[0]?.path, "scripts/ci.sh");
    assert.ok(packet.symlinks.docOrAgent.includes("CLAUDE.md"));
    const prompt = buildBlindAuditPrompt("/tmp/packet.json", dir, "model-a");
    assert.ok(prompt.includes("DOUBLE-BLIND"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("mergeDossiers enforces 2-of-3 consensus and diffAgainstVeristack separates CI-FN, CI-FP, SECURITY-HOLD, and WS-FP", () => {
  const d1 = makeDossier("model-a");
  const d2 = makeDossier("model-b");
  const d3 = makeDossier("model-c", { archetype: { value: "service", rationale: "dissenter", citations: ["src/a.ts:1"] } });
  assert.equal(validateDossier(d1).length, 0);

  const consensus = mergeDossiers([d1, d2, d3]);
  assert.equal(consensus.archetype.value, "library");
  assert.equal(consensus.archetype.unanimous, false);
  assert.ok(consensus.disagreements.some((d) => d.field === "archetype"));

  const fakeScan = {
    archetype: "library",
    languages: ["typescript", "javascript"],
    workspaces: [
      { path: "packages/core", score: 0 },
      { path: "samples/demo", score: 0 },
    ],
    rungs: [
      { rung: "R0", coverageGrade: "partial", coverageScore: 70, executedInCi: true },
      { rung: "R1", coverageGrade: "partial", coverageScore: 50, executedInCi: false },
      { rung: "R2", coverageGrade: "partial", coverageScore: 50, executedInCi: false },
      { rung: "R3", coverageGrade: "hole", coverageScore: 0, executedInCi: true },
      { rung: "R4", coverageGrade: "not-applicable", coverageScore: 100, executedInCi: false },
      { rung: "R5", coverageGrade: "hole", coverageScore: 0, executedInCi: false },
      { rung: "R6", coverageGrade: "hole", coverageScore: 0, executedInCi: false },
      { rung: "R7", coverageGrade: "not-applicable", coverageScore: 100, executedInCi: false },
      { rung: "R8", coverageGrade: "not-applicable", coverageScore: 100, executedInCi: false },
    ],
    summary: { overallCoverageScore: 0 },
    findings: [],
  };

  const diff = diffAgainstVeristack(consensus, fakeScan);
  assert.equal(diff.archetype.match, true);
  assert.deepEqual(diff.languages.phantomLanguages, ["javascript"]);
  assert.equal(diff.workspaces.wsFalsePositives.length, 1);
  assert.equal(diff.workspaces.wsTestLinkFalseNegatives.length, 1);
  assert.equal(diff.ci.falseNegatives.length, 1);
  assert.equal(diff.ci.falseNegatives[0]?.rung, "R1");
  assert.equal(diff.ci.falsePositives.length, 1);
  assert.equal(diff.ci.falsePositives[0]?.rung, "R3");
  assert.equal(diff.ci.securityHolds.length, 1);
  assert.equal(diff.ci.securityHolds[0]?.rung, "R2");
});

test("sampleFindingsForAdjudication excludes no-comments and extracts source excerpts", () => {
  const dir = makeTempRepo({
    "src/a.ts": "export const x = (1 as any);\n",
  });
  try {
    const rep = scanRepo(dir);
    const sampled = sampleFindingsForAdjudication(dir, rep, 3, 5);
    assert.ok(sampled.every((s) => s.rule !== "no-comments"));
    assert.ok(sampled.some((s) => s.rule === "no-chained-or-any-cast" && s.samples[0]?.excerpt.includes("as any")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
