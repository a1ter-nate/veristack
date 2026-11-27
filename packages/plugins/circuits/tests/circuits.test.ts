import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  instructionLintPromoterCircuit,
  prRiskRouterCircuit,
  testTriageCircuit,
  type InstructionRuleInput,
  type PrRiskInput,
  type TestTriageInput,
} from "@veristack/plugin-circuits";
import { runCircuit, type System1DecisionEngine } from "@veristack/plugin-circuits";
import { listDefaultCircuits } from "@veristack/plugin-circuits";
import type { System1ModelAnswer, System1Request } from "@veristack/plugin";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const cliPath = path.join(repoRoot, "src", "cli.ts");

function mockEngine(
  name: string,
  handler: (req: System1Request) => System1ModelAnswer,
): { engine: System1DecisionEngine; calledIds: string[] } {
  const calledIds: string[] = [];
  return {
    calledIds,
    engine: {
      name,
      async decide(requests) {
        for (const r of requests) calledIds.push(r.id);
        return requests.map(handler);
      },
    },
  };
}

test("pr-risk-router handles 3-band thresholds, mid-band human escalation, and static-fact contradictions", async () => {
  const prInputs: PrRiskInput[] = [
    { file: "src/a.ts", addedLines: 20, removedLines: 5, diffSnippet: "+a()", hasCheatHit: false },
    { file: "src/b.ts", addedLines: 25, removedLines: 5, diffSnippet: "+b()", hasCheatHit: false },
    { file: "src/c.ts", addedLines: 250, removedLines: 10, diffSnippet: "+c()", hasCheatHit: false },
    { file: "src/d.ts", addedLines: 15, removedLines: 2, diffSnippet: "+d()", hasCheatHit: false },
  ];

  const { engine, calledIds } = mockEngine("custom-byo-jev", (req) => {
    if (req.id.endsWith("pr-001")) return { id: req.id, choice: "low_auto_merge", confidence: 0.91, abstained: false };
    if (req.id.endsWith("pr-002")) return { id: req.id, choice: "low_auto_merge", confidence: 0.55, abstained: false };
    if (req.id.endsWith("pr-003")) return { id: req.id, choice: "low_auto_merge", confidence: 0.95, abstained: false };
    return { id: req.id, choice: null, confidence: null, abstained: true };
  });

  const report = await runCircuit(prRiskRouterCircuit, prInputs, engine);
  assert.equal(report.provider, "custom-byo-jev");
  assert.equal(report.shortCircuitedCount, 0);
  assert.equal(report.modelCalledCount, 4);
  assert.equal(calledIds.length, 4);

  assert.equal(report.receipts[0]?.band, "high");
  assert.equal(report.receipts[0]?.action, "auto_merge_candidate");
  assert.equal(report.receipts[0]?.requiresHuman, false);
  assert.equal(report.receipts[1]?.band, "uncertain");
  assert.equal(report.receipts[1]?.requiresHuman, true);
  assert.equal(report.receipts[2]?.band, "contradicted");
  assert.equal(report.receipts[2]?.requiresHuman, true);
  assert.equal(report.receipts[3]?.band, "abstained");
  assert.equal(report.receipts[3]?.requiresHuman, true);
});

test("pr-risk-router and instruction-lint-promoter short-circuit deterministic cases before calling System 1", async () => {
  const prInputs: PrRiskInput[] = [
    { file: "ci.yml", addedLines: 2, removedLines: 0, diffSnippet: "+continue-on-error: true", hasCheatHit: true },
    { file: "README.md", addedLines: 10, removedLines: 2, diffSnippet: "+docs", hasCheatHit: false },
    { file: "src/billing/charge.ts", addedLines: 15, removedLines: 5, diffSnippet: "+charge()", hasCheatHit: false },
    { file: "src/format/date.ts", addedLines: 18, removedLines: 4, diffSnippet: "+fmt()", hasCheatHit: false },
  ];

  const prMock = mockEngine("laya-mock", (req) => ({
    id: req.id,
    choice: "low_auto_merge",
    confidence: 0.92,
    abstained: false,
  }));

  const prReport = await runCircuit(prRiskRouterCircuit, prInputs, prMock.engine);
  assert.equal(prReport.shortCircuitedCount, 3);
  assert.equal(prReport.modelCalledCount, 1);
  assert.equal(prReport.shortCircuitRate, 0.75);
  assert.equal(prReport.receipts[0]?.action, "block_merge");
  assert.equal(prReport.receipts[1]?.action, "auto_merge_candidate");
  assert.equal(prReport.receipts[2]?.action, "two_review_or_canary");
  assert.equal(prReport.receipts[3]?.action, "auto_merge_candidate");

  const ruleInputs: InstructionRuleInput[] = [
    { file: "AGENTS.md", line: 1, clause: "Never add prose comments.", alreadyEnforced: true, hasConflict: false },
    { file: "AGENTS.md", line: 2, clause: "Prefer clear naming.", alreadyEnforced: false, hasConflict: false },
    { file: "AGENTS.md", line: 3, clause: "Never call fetch directly in React components.", alreadyEnforced: false, hasConflict: false },
  ];
  const ruleMock = mockEngine("gemma4-local", (req) => ({
    id: req.id,
    choice: "promotable_deterministic_rule",
    confidence: 0.88,
    abstained: false,
  }));
  const ruleReport = await runCircuit(instructionLintPromoterCircuit, ruleInputs, ruleMock.engine);
  assert.equal(ruleReport.shortCircuitedCount, 2);
  assert.equal(ruleReport.modelCalledCount, 1);
  assert.equal(ruleReport.receipts[0]?.action, "prune_redundant_prose");
  assert.equal(ruleReport.receipts[1]?.action, "keep_as_guidance");
  assert.equal(ruleReport.receipts[2]?.action, "promote_to_linter");
});

test("test-triage circuit short-circuits clean PBTs and tautologies, calling System 1 only on ambiguous tests", async () => {
  const inputs: TestTriageInput[] = [
    {
      file: "tests/pricing.pbt.test.ts",
      snippet: "fc.property(...)",
      facts: {
        id: "s1-001",
        component: "tests",
        file: "tests/pricing.pbt.test.ts",
        kind: "test",
        context: "complete",
        lines: 40,
        testCaseCount: 3,
        observedBoundary: "unit",
        hasSutImport: true,
        coverageFarmName: false,
        literalOnlyAssertion: false,
        selfDerivedExpectation: false,
        multiStatusCount: 0,
        mockCount: 0,
        networkMock: false,
        nondeterminismCount: 0,
        hasTableOrPbt: true,
        factSummary: "clean pbt",
      },
    },
    {
      file: "tests/ambiguous.test.ts",
      snippet: "test('x', () => expect(run()).toBe(1))",
      facts: {
        id: "s1-002",
        component: "tests",
        file: "tests/ambiguous.test.ts",
        kind: "test",
        context: "complete",
        lines: 30,
        testCaseCount: 2,
        observedBoundary: "unit",
        hasSutImport: true,
        coverageFarmName: false,
        literalOnlyAssertion: false,
        selfDerivedExpectation: false,
        multiStatusCount: 0,
        mockCount: 1,
        networkMock: false,
        nondeterminismCount: 0,
        hasTableOrPbt: false,
        factSummary: "ambiguous",
      },
    },
  ];

  const mock = mockEngine("fixture-byo", (req) => ({
    id: req.id,
    choice: "BEHAVIOR",
    confidence: 0.9,
    abstained: false,
  }));
  const report = await runCircuit(testTriageCircuit, inputs, mock.engine);
  assert.equal(report.shortCircuitedCount, 1);
  assert.equal(report.modelCalledCount, 1);
  assert.equal(report.receipts[0]?.action, "keep_verified");
  assert.equal(report.receipts[1]?.action, "keep_verified");
  assert.equal(report.receipts[1]?.band, "high");
});

test("vstack circuit CLI lists all 4 default verification circuits and runs test-triage with fixture provider", () => {
  assert.equal(listDefaultCircuits().length, 4);
  const listRes = spawnSync(process.execPath, [cliPath, "circuit", "list", "--json"], { encoding: "utf8" });
  assert.equal(listRes.status, 0, listRes.stderr);
  const listed = JSON.parse(listRes.stdout) as { circuits: Array<{ id: string }> };
  assert.deepEqual(
    listed.circuits.map((c) => c.id),
    ["test-triage", "pr-risk-router", "instruction-lint-promoter", "perf-architecture-advisor"],
  );

  const runRes = spawnSync(
    process.execPath,
    [cliPath, "circuit", "run", "test-triage", repoRoot, "--provider", "fixture", "--max", "8", "--json"],
    { encoding: "utf8" },
  );
  assert.equal(runRes.status, 0, runRes.stderr);
  const report = JSON.parse(runRes.stdout) as { circuitId: string; totalInputs: number; shortCircuitRate: number };
  assert.equal(report.circuitId, "test-triage");
  assert.ok(report.totalInputs >= 1);
  assert.ok(report.shortCircuitRate >= 0 && report.shortCircuitRate <= 1);
});
