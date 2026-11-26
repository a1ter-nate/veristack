import assert from "node:assert/strict";
import test from "node:test";
import { lintNoComments } from "../../src/no-comments.ts";
import { buildRatchetBaseline, evaluateRatchet } from "../../src/ratchet.ts";
import { parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";
import type { Finding, RungStatus } from "../../src/types.ts";

function makePrng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function runSeededProperty(seed: number, iterations: number, check: (next: () => number, idx: number) => void): void {
  const next = makePrng(seed);
  for (let i = 0; i < iterations; i++) {
    check(next, i);
  }
}

function makeFinding(rule: string, idx: number, severity: Finding["severity"] = "error"): Finding {
  return {
    id: `F:${rule}:${idx}`,
    rule,
    category: "cheat",
    rung: "R0",
    severity,
    file: "src/a.ts",
    line: idx + 1,
    message: "m",
    fix: "f",
  };
}

function makeRung(
  rung: RungStatus["rung"],
  grade: RungStatus["coverageGrade"],
  score: number,
  executedInCi: boolean,
): RungStatus {
  return {
    rung,
    name: rung,
    speedBudget: "< 2s",
    targetBudget: "100%",
    status: grade === "well-covered" ? "covered" : grade === "poorly-covered" ? "partial" : grade === "not-applicable" ? "not-applicable" : "hole",
    coverageGrade: grade,
    coverageScore: score,
    executedInCi,
    receiptVerified: executedInCi,
    idealCoverage: "ideal",
    observedCoverage: "actual",
    checks: [],
    observedCount: 1,
    evidence: grade === "not-covered" ? [] : ["ev"],
    gaps: [],
  };
}

function runStatefulModelCheck(seed: number, steps: number): void {
  const next = makePrng(seed);
  const rules = ["rA", "rB", "rC"];
  let counts: Record<string, number> = { rA: 2, rB: 2, rC: 2 };
  const initialFindings = rules.flatMap((r) => Array.from({ length: counts[r] ?? 0 }, (_, i) => makeFinding(r, i)));
  const initialRungs: RungStatus[] = [
    makeRung("R0", "well-covered", 100, true),
    makeRung("R2", "poorly-covered", 60, true),
  ];
  let baseline = buildRatchetBaseline(initialFindings, initialRungs);
  let curRungs = [...initialRungs];

  for (let step = 0; step < steps; step++) {
    const op = Math.floor(next() * 4);
    const rule = rules[Math.floor(next() * rules.length)] ?? "rA";

    if (op === 0) {
      counts = { ...counts, [rule]: (counts[rule] ?? 0) + 1 };
      const curFindings = rules.flatMap((r) => Array.from({ length: counts[r] ?? 0 }, (_, i) => makeFinding(r, i)));
      const res = evaluateRatchet(curFindings, baseline, curRungs);
      assert.equal(res.passed, false);
      assert.ok(res.regressions.some((r) => r.rule === rule));
      counts = { ...counts, [rule]: (counts[rule] ?? 1) - 1 };
    } else if (op === 1 && (counts[rule] ?? 0) > 0) {
      counts = { ...counts, [rule]: (counts[rule] ?? 1) - 1 };
      const curFindings = rules.flatMap((r) => Array.from({ length: counts[r] ?? 0 }, (_, i) => makeFinding(r, i)));
      const res = evaluateRatchet(curFindings, baseline, curRungs);
      assert.equal(res.passed, false);
      assert.ok(res.tightenAvailable.some((t) => t.rule === rule));
      baseline = buildRatchetBaseline(curFindings, curRungs);
      const afterTighten = evaluateRatchet(curFindings, baseline, curRungs);
      assert.equal(afterTighten.passed, true);
    } else if (op === 2) {
      const degraded = curRungs.map((r) =>
        r.rung === "R0" ? makeRung("R0", "not-applicable", 100, false) : r,
      );
      const curFindings = rules.flatMap((r) => Array.from({ length: counts[r] ?? 0 }, (_, i) => makeFinding(r, i)));
      const res = evaluateRatchet(curFindings, baseline, degraded);
      assert.equal(res.passed, false);
      assert.ok(res.rungRegressions.some((rr) => rr.rung === "R0"));
    } else {
      const upgraded = curRungs.map((r) =>
        r.rung === "R2" ? makeRung("R2", "well-covered", 100, true) : r,
      );
      curRungs = upgraded;
      const curFindings = rules.flatMap((r) => Array.from({ length: counts[r] ?? 0 }, (_, i) => makeFinding(r, i)));
      const res = evaluateRatchet(curFindings, baseline, curRungs);
      assert.equal(res.rungRegressions.length, 0);
      baseline = buildRatchetBaseline(curFindings, curRungs);
    }
  }
}

test("seeded PBT: lintNoComments preserves zero FPs on generated clean expressions and catches every prose comment", () => {
  runSeededProperty(20261125, 100, (next, idx) => {
    const a = Math.floor(next() * 1000);
    const b = Math.floor(next() * 1000);
    const clean = `export const v_${idx} = "http://example.com/${a}" + String(${a} + ${b});\n`;
    assert.deepEqual(lintNoComments("src/gen.ts", clean, "typescript"), []);

    const dirty = `// generated prose ${a}\n${clean}`;
    const hits = lintNoComments("src/gen.ts", dirty, "typescript");
    assert.equal(hits.length, 1);
    assert.equal(hits[0]?.rule, "no-comments");
  });
});

test("seeded PBT: parseGitHubWorkflow ignores comments, echo lines, and if:false jobs across generated workflows", () => {
  runSeededProperty(9001, 60, (next, idx) => {
    const tools = ["oxlint", "vitest", "stryker", "k6", "quint"];
    const picked = tools[Math.floor(next() * tools.length)] ?? "oxlint";
    const wfText = [
      "name: Theater",
      "on: [workflow_dispatch]",
      "jobs:",
      `  j_${idx}:`,
      "    if: false",
      "    steps:",
      `      - run: echo "${picked}"`,
      `      # ${picked}`,
    ].join("\n");
    const parsed = parseGitHubWorkflow({
      rel: ".github/workflows/t.yml",
      abs: "/virtual/.github/workflows/t.yml",
      isTest: false,
      isWorkflow: true,
      content: wfText,
      lines: 8,
    });
    assert.equal(parsed.isPrBlocking, false);
    assert.deepEqual(parsed.activeCommands, []);
    assert.equal(parsed.deadJobs.length, 1);
  });
});

test("stateful MBT: ratchet monotonicity, tightening, and archetype-downgrade rejection hold across randomized sequences", () => {
  runStatefulModelCheck(424242, 80);
});

test("parseGitHubWorkflow preserves quoted # tokens and strips column-0 and inline YAML comments", () => {
  const wf = [
    "# column-0 comment",
    "name: Real CI",
    "on: [pull_request]",
    "jobs:",
    "  verify:",
    "    steps:",
    '      - run: bun test --grep "case#1 \\"quoted\\"" # inline comment',
    "      - run: oxlint . # trailing oxlint comment",
  ].join("\n");
  const parsed = parseGitHubWorkflow({
    rel: ".github/workflows/real.yml",
    abs: "/virtual/.github/workflows/real.yml",
    isTest: false,
    isWorkflow: true,
    content: wf,
    lines: 8,
  });
  assert.equal(parsed.isPrBlocking, true);
  assert.deepEqual(parsed.activeCommands, [
    'bun test --grep "case#1 \\"quoted\\""',
    "oxlint .",
  ]);
});
